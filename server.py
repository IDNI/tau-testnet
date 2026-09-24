import logging
import os
import socket
import ssl
import sys
import threading
import time
import trio
import argparse
import trio_websocket
import subprocess


from app.container import ServiceContainer
from network import NetworkListenError, NetworkService

# Project modules
import config
import json
import api_response
from commands import createblock, sendtx  # Import command handlers
from errors import ConfigurationError, TauEngineCrash, TauTestnetError
import tau_logging


logger = logging.getLogger("tau.server")

# --- NetworkService globals ---
NETWORK_THREAD = None
NETWORK_STOP_FLAG = threading.Event()
# --- Command Dispatch Table ---


SUPPORTED_HANDSHAKE_VERSIONS = {"1", "2"}


# --- RPC rate limiting -------------------------------------------------------
# One bucket pair per connection. The WebSocket loop had an inline bucket; the
# raw-TCP path had none at all, so anything exposed over TCP was unmetered.
#
# Two tiers, because the commands differ by orders of magnitude in cost:
#   general   — ordinary reads/writes
#   expensive — commands that either spawn a native compile subprocess, walk
#               the whole chain/state, or take the global Tau lock, and cost
#               the caller nothing. sendtx is deliberately NOT in this tier:
#               it consumes a sequence number, is capped by the mempool limit and
#               carries a fee_limit, so it is already self-deterring. checktx has
#               none of those brakes.
_RPC_BURST = 10.0
_RPC_REFILL_PER_SEC = 5.0
_EXPENSIVE_BURST = 2.0
_EXPENSIVE_REFILL_PER_SEC = 0.5
# getapprovalpreview enumerates up to 64 engine steps under the global Tau lock,
# and getapprovalslots is unauthenticated text inspection; both are advisory
# conveniences. getblocks/getallaccounts/gettaustate/getgovernance/history are
# cheap for the caller and hold the process-wide DB or state lock, so a poller
# can stall mining and admission.
_EXPENSIVE_COMMANDS = frozenset({
    "checktx",
    "getapprovalpreview",
    "getapprovalslots",
    "getblocks",
    "getallaccounts",
    "gettaustate",
    "getgovernance",
    "history",
})

# Global cap on heavy RPC currently inside handler.execute(). Per-connection
# token buckets still allow a burst; without this, N clients each sending
# getblocks at once serialize on _db_lock and the node looks dead.
_EXPENSIVE_RPC_CONCURRENCY = 2
_expensive_rpc_sema = threading.BoundedSemaphore(_EXPENSIVE_RPC_CONCURRENCY)

# TCP accept loop used to spawn an unbounded thread per connection.
_TCP_MAX_CONNECTIONS = 64
_tcp_conn_sema = threading.BoundedSemaphore(_TCP_MAX_CONNECTIONS)

# WebSocket listener is a single Trio thread. Unbounded accept + huge replies
# are what make a handful of dashboard pollers look like "the node is wedged".
_WS_MAX_CONNECTIONS = 32
_WS_IDLE_TIMEOUT = 120.0
_WS_CONNECT_TIMEOUT = 10.0
_WS_DISCONNECT_TIMEOUT = 5.0
# trio-websocket's default inbound max is 1 MiB; stay under that for replies
# so a client with the same default does not 1009-close the socket.
_WS_MAX_RESPONSE_BYTES = 900_000
# Bare `getblocks` over WS used to dump the whole chain. TCP/CLI keep that
# behaviour; WS pollers get a recent window and truncated=true when there is more.
_WS_DEFAULT_GETBLOCKS_LIMIT = 50


class _TokenBucket:
    """Token bucket over an injected clock.

    The clock is a parameter because the two transports measure time
    differently: the WebSocket loop runs under trio and must use
    `trio.current_time()`, while the TCP handler is a plain thread using
    `time.monotonic()`. Not thread-safe — one instance per connection.
    """

    __slots__ = ("capacity", "refill_per_second", "_tokens", "_last")

    def __init__(self, capacity: float, refill_per_second: float, now: float):
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._tokens = capacity
        self._last = now

    def take(self, now: float) -> bool:
        """Consume one token. False when the caller is over budget."""
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_second)
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True


class _RpcLimiter:
    """The general + expensive bucket pair for one connection."""

    __slots__ = ("_general", "_expensive")

    def __init__(self, now: float):
        self._general = _TokenBucket(_RPC_BURST, _RPC_REFILL_PER_SEC, now)
        self._expensive = _TokenBucket(_EXPENSIVE_BURST, _EXPENSIVE_REFILL_PER_SEC, now)

    def allow(self, command_name: str, now: float) -> bool:
        # Charge the general bucket for every command, so an expensive one cannot
        # be used to dodge the overall rate.
        if not self._general.take(now):
            return False
        if command_name in _EXPENSIVE_COMMANDS:
            return self._expensive.take(now)
        return True


def _rate_limited_response() -> str:
    return api_response.error_response(
        "rate_limit", "Rate limit exceeded", "RATE_LIMITED"
    )


def _busy_response(command_name: str) -> str:
    return api_response.error_response(
        command_name,
        "Too many heavy RPC calls in flight; retry shortly.",
        "BUSY",
    )


def _payload_too_large_response(command_name: str, size: int) -> str:
    hint = ""
    if command_name == "getblocks":
        hint = f" Pass a smaller window, e.g. getblocks {_WS_DEFAULT_GETBLOCKS_LIMIT}."
    return api_response.error_response(
        command_name,
        f"Response too large ({size} bytes).{hint}",
        "PAYLOAD_TOO_LARGE",
    )


class _IsolatingNursery:
    """`start_soon` wrapper so one connection crash cannot cancel the WS listener.

    trio.serve_listeners documents that an unhandled handler exception
    propagates out of the listener nursery and takes the whole server down.
    trio-websocket runs each TCP accept through `_handle_connection` in that
    nursery; wrapping start_soon keeps the listener alive.
    """

    def __init__(self, nursery: trio.Nursery):
        self._nursery = nursery

    def start_soon(self, fn, *args, **kwargs):
        async def _guarded():
            try:
                await fn(*args)
            except Exception:
                logger.exception("WS connection task crashed; dropping client")
            except BaseExceptionGroup as exc:
                logger.error("WS connection task group failed: %r", exc)

        self._nursery.start_soon(_guarded, **kwargs)


def process_command(raw_command: str, container: ServiceContainer, client_label: str, *, is_local: bool = False) -> tuple[bool, str]:
    """
    Process a single command string from any source (TCP or WS).

    Returns:
        (success, response_string)
        success: True if a JSON envelope was produced.
                 False for the plain-text handshake replies (hello/ok/error <code>).
        response_string: Body to forward to the client. The TCP transport adds
        ``\\r\\n`` framing; WebSocket emits it raw.
    """
    if not raw_command:
        return True, api_response.error_response(
            "", "Received empty command.", "INVALID_PARAMS"
        )

    # Handle Handshake (Virtual Command) — stays plain text.
    if raw_command.startswith("hello version="):
        try:
            version_val = raw_command.split("=", 1)[1].strip()
        except IndexError:
            return False, "error malformed_handshake"
        if version_val in SUPPORTED_HANDSHAKE_VERSIONS:
            return False, f"ok version={version_val} env={container.settings.env} node=tau-node"
        return False, f"error unsupported_version expected=1|2 got={version_val}"

    parts = raw_command.split()
    if not parts:
        return True, api_response.error_response(
            "", "Empty command.", "INVALID_PARAMS"
        )

    command_name = parts[0].lower()
    logger.debug("Processing command from %s: %s", client_label, command_name)

    # Block production must not be remotely triggerable: createblock uses the
    # node's MINER_PRIVKEY. Validators mine via the internal SoleMiner loop.
    if command_name == "createblock" and not is_local \
            and not getattr(container.settings.authority, "allow_remote_createblock", False):
        logger.warning("Refusing remote createblock from %s", client_label)
        return True, api_response.error_response(
            command_name, "createblock is not allowed from remote clients.", "FORBIDDEN"
        )

    handler = container.command_handlers.get(command_name)
    if not handler or not hasattr(handler, "execute"):
        logger.warning("Unknown command from %s: %s", client_label, command_name)
        return True, api_response.error_response(
            command_name, f"Unknown command '{command_name}'", "UNKNOWN_COMMAND"
        )

    heavy = command_name in _EXPENSIVE_COMMANDS
    if heavy and not _expensive_rpc_sema.acquire(blocking=False):
        logger.warning("Heavy RPC busy; refusing %s from %s", command_name, client_label)
        return True, _busy_response(command_name)

    try:
        resp = handler.execute(raw_command, container)
    except TauTestnetError as exc:
        logger.warning("Tau error processing %s for %s: %s", command_name, client_label, exc)
        return True, api_response.error_response(command_name, str(exc), "INTERNAL_ERROR")
    except TimeoutError:
        logger.error("Timeout while running %s for %s", command_name, client_label)
        return True, api_response.error_response(
            command_name, "Timeout communicating with Tau process.", "TIMEOUT"
        )
    except Exception as exc:
        logger.exception("Error executing local command %s for %s", command_name, client_label)
        return True, api_response.error_response(command_name, str(exc), "INTERNAL_ERROR")
    finally:
        if heavy:
            _expensive_rpc_sema.release()

    if not isinstance(resp, str):
        logger.error("Handler %s returned non-string response", command_name)
        return True, api_response.error_response(
            command_name, "Handler returned malformed response.", "INTERNAL_ERROR"
        )
    return True, resp.rstrip("\r\n")



# --- NetworkService helpers ---
# How long the main thread waits for the libp2p listener before it starts the
# WebSocket and RPC servers regardless.
_NETWORK_LISTEN_WAIT = 30.0


class _NetworkStartup:
    """How NetworkService.start() went on the network thread, for the main thread."""

    def __init__(self, configured_addrs) -> None:
        self._done = threading.Event()
        self.configured_addrs = list(configured_addrs)
        self.listen_addrs = []
        self.error = None

    def finish(self, *, listen_addrs=(), error=None) -> None:
        self.listen_addrs = list(listen_addrs)
        self.error = error
        self._done.set()

    def wait(self, timeout: float) -> bool:
        return self._done.wait(timeout)


def _start_network_background(container: ServiceContainer) -> _NetworkStartup:
    """
    Start NetworkService in a dedicated Trio thread. The returned handle says
    when start() has returned (libp2p listening) or failed.
    """
    global NETWORK_THREAD
    cfg = container.build_network_config()
    startup = _NetworkStartup(cfg.listen_addrs)

    def _runner():
        service = NetworkService(cfg)
        
        # Register service with global bus so commands (e.g. sendtx) can access it
        from network import bus
        bus.register(service)
        
        # Inject DHT manager into chain_state so it can store formulas
        if hasattr(container.chain_state, "set_dht_client"):
            container.chain_state.set_dht_client(service._dht_manager)
            
        async def main() -> None:
            try:
                await service.start()
            except NetworkListenError as exc:
                # Fatal, and reported by the main thread; nothing to unwind here.
                startup.finish(error=exc)
                return
            except BaseException as exc:
                startup.finish(error=exc)
                raise
            startup.finish(listen_addrs=service.listen_addrs())
            
            # Re-set DHT client to trigger hydration now that DHT is fully initialized
            if hasattr(container.chain_state, "set_dht_client"):
                logger.info("Re-triggering DHT hydration after NetworkService startup")
                container.chain_state.set_dht_client(service._dht_manager)
            
            try:
                while not NETWORK_STOP_FLAG.is_set():
                    await trio.sleep(0.25)
            finally:
                await service.stop()
        trio.run(main)

    t = threading.Thread(target=_runner, name="NetworkServiceThread", daemon=True)
    t.start()
    NETWORK_THREAD = t
    return startup


def _tcp_ports(addrs) -> set:
    ports = set()
    for addr in addrs:
        try:
            port = int(addr.value_for_protocol("tcp"))
        except Exception:
            continue
        if port:
            ports.add(port)
    return ports


def _await_network_listening(startup: _NetworkStartup, timeout: float = _NETWORK_LISTEN_WAIT) -> frozenset:
    """
    Block until libp2p has bound its listen addresses; return their TCP ports.

    The WebSocket and RPC servers each take the first free port upward from
    PORT+1 / PORT. Started first, either could take the p2p port: libp2p then
    had no listener, yet the node advertised that port, and every peer's dial
    reached the WebSocket server ("failed to negotiate the secure protocol").
    Binding libp2p first settles an exact collision; the scans must still skip
    these ports, because on macOS a wildcard and a specific bind of one port
    coexist.

    Raises ConfigurationError when libp2p bound none of its addresses.
    """
    if not startup.wait(timeout):
        logger.warning(
            "NetworkService did not report listening within %.0fs; starting RPC/WS anyway.",
            timeout,
        )
    elif isinstance(startup.error, NetworkListenError):
        raise ConfigurationError(
            f"{startup.error}. Point TAU_NETWORK_LISTEN at a free address."
        ) from startup.error
    elif startup.error is not None:
        logger.error("NetworkService failed to start: %r", startup.error)
    return frozenset(_tcp_ports(startup.configured_addrs) | _tcp_ports(startup.listen_addrs))


# --- WebSocket Server ---
def _ws_peer_label(request, ws=None) -> str:
    remote = getattr(ws, "remote", None) if ws is not None else None
    if remote is None:
        remote = getattr(request, "remote", None)
    return f"WS:{remote}"


async def websocket_handler(request):
    """
    Handles WebSocket connections.
    Includes Handshake, Origin Check, and Command Processing.
    """
    container = request.server_container
    slots = getattr(request, "ws_slots", None)
    slot_held = False
    if slots is not None:
        try:
            slots.acquire_nowait()
        except trio.WouldBlock:
            logger.warning("Rejected WS from %s: at capacity", _ws_peer_label(request))
            await request.reject(503, body=b"too many websocket connections")
            return
        slot_held = True

    client_label = _ws_peer_label(request)
    try:
        ws = await request.accept()
        client_label = _ws_peer_label(request, ws)

        # Origin Check (Basic)
        headers = dict(request.headers)
        origin = headers.get("Origin") or headers.get("origin")

        # Parse allowed origins from environment (comma-separated, e.g. "https://domain1.com,https://domain2.com,*")
        allowed_env = os.environ.get("TAU_WS_ALLOWED_ORIGINS", "")
        allowed_domains = [d.strip() for d in allowed_env.split(",") if d.strip()]

        # Allow missing origin (localhost tools) or localhost/file
        allowed = False
        if not origin or origin == "null":
            allowed = True
        elif "localhost" in origin or "127.0.0.1" in origin:
            allowed = True
        elif "*" in allowed_domains:
            allowed = True
        else:
            for domain in allowed_domains:
                if domain in origin:
                    allowed = True
                    break

        if not allowed:
            logger.warning(
                "Rejected WS connection from disallowed origin: %s. Use TAU_WS_ALLOWED_ORIGINS to allow it.",
                origin,
            )
            await ws.send_message("error disallowed_origin")
            await ws.aclose()
            return

        logger.info("WS Connection accepted: %s (Origin: %s)", client_label, origin)

        # Shared limiter with the TCP path (_RpcLimiter), on trio's clock.
        limiter = _RpcLimiter(trio.current_time())
        idle_timeout = getattr(request, "ws_idle_timeout", _WS_IDLE_TIMEOUT)

        while True:
            try:
                with trio.move_on_after(idle_timeout) as idle_scope:
                    message = await ws.get_message()
                if idle_scope.cancelled_caught:
                    logger.info("WS idle timeout: %s", client_label)
                    break
            except trio_websocket.ConnectionClosed:
                break

            if not isinstance(message, str):
                message = message.decode("utf-8", errors="replace")

            parts = message.split()
            command_name = parts[0].lower() if parts else ""
            # Bare getblocks over WS is how dashboards stall the node: full-chain
            # dump under _db_lock, then a multi-MB send on the Trio thread.
            if command_name == "getblocks" and len(parts) == 1:
                message = f"getblocks {_WS_DEFAULT_GETBLOCKS_LIMIT}"

            if not limiter.allow(command_name, trio.current_time()):
                logger.warning("Rate limit exceeded for %s (%s)", client_label, command_name)
                await ws.send_message(_rate_limited_response())
                continue

            # Process in a worker thread to avoid blocking the Trio event loop
            success, response = await trio.to_thread.run_sync(
                process_command, message, container, client_label
            )
            if len(response) > _WS_MAX_RESPONSE_BYTES:
                response = _payload_too_large_response(command_name, len(response))
            try:
                await ws.send_message(response)
            except trio_websocket.ConnectionClosed:
                break
    except Exception as e:
        logger.error("WS Handler Error %s: %s", client_label, e)
    except BaseExceptionGroup:
        logger.exception("WS Handler group error %s", client_label)
    finally:
        if slot_held:
            slots.release()
        logger.info("WS Client disconnected: %s", client_label)


def _start_websocket_server(container: ServiceContainer, reserved_ports=frozenset()) -> None:
    """
    Starts the Trio WebSocket server in a separate daemon thread. Its port scan
    skips `reserved_ports` (the libp2p listen ports).
    """
    def _ws_runner():
        ws_port = config.PORT + 1
        # Try to find a free port if busy, or just fail? 
        # Plan says: Handle port conflicts (start at config.PORT + 1, scan if busy).
        
        # trio-websocket handler signature is fn(request). The wrapper that
        # attaches container + the connection limiter is created inside main()
        # so it closes over the Trio-scoped CapacityLimiter.

        def _build_ws_ssl_context() -> ssl.SSLContext | None:
            cert_path = os.environ.get("TAU_WS_CERT_PATH", "").strip()
            key_path = os.environ.get("TAU_WS_KEY_PATH", "").strip()
            if not cert_path and not key_path:
                return None
            if not cert_path or not key_path:
                logger.error(
                    "WSS disabled: both TAU_WS_CERT_PATH and TAU_WS_KEY_PATH are required."
                )
                return None
            try:
                ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            except Exception:
                logger.exception("Failed to load WSS cert/key; falling back to WS.")
                return None
            return ssl_ctx

        def _log_ws_exception(prefix, exc):
            # serve_websocket runs client handlers inside an internal Trio nursery,
            # so failures arrive wrapped in an ExceptionGroup / trio.MultiError whose
            # str() is just "Exceptions from Trio nursery (N sub-exceptions)".
            # Recurse into .exceptions so the real cause + traceback are logged.
            subs = getattr(exc, "exceptions", None)
            if subs:
                logger.error("%s %r (%d sub-exception(s))", prefix, exc, len(subs))
                for idx, sub in enumerate(subs, 1):
                    _log_ws_exception(f"{prefix} [sub {idx}/{len(subs)}]", sub)
            else:
                logger.error("%s %r", prefix, exc, exc_info=exc)

        async def main():
            # Port scanning logic
            actual_ws_port = ws_port
            ssl_context = _build_ws_ssl_context()
            scheme = "wss" if ssl_context else "ws"
            ws_slots = trio.CapacityLimiter(_WS_MAX_CONNECTIONS)

            async def handler_with_container(request):
                request.server_container = container
                request.ws_slots = ws_slots
                await websocket_handler(request)

            # Simple scan: bind to the first free port, then serve until it crashes
            # or is cancelled. A non-OSError escapes this function so the outer
            # supervisor loop can log it and restart.
            # handler_nursery is isolated so one client's ExceptionGroup cannot
            # cancel the listener (the May 2026 WS-death failure mode).
            async with trio.open_nursery() as handler_n:
                for i in range(10):
                    p = actual_ws_port + i
                    if p in reserved_ports:
                        logger.warning("WS Port %s is the libp2p listen port, trying next...", p)
                        continue
                    try:
                        logger.info("Attempting to bind %s to %s:%s", scheme, config.HOST, p)
                        # serve_websocket blocks until cancelled.
                        await trio_websocket.serve_websocket(
                            handler_with_container,
                            config.HOST,
                            p,
                            ssl_context=ssl_context,
                            handler_nursery=_IsolatingNursery(handler_n),
                            connect_timeout=_WS_CONNECT_TIMEOUT,
                            disconnect_timeout=_WS_DISCONNECT_TIMEOUT,
                        )
                        # If it returns, the server shut down on its own.
                        logger.warning("WS serve returned (unexpected).")
                        return
                    except OSError as e:
                        logger.warning("WS Port %s busy, trying next... (%s)", p, e)
                        continue
            raise RuntimeError(
                f"WS server could not bind any port in {actual_ws_port}-{actual_ws_port + 9}"
            )

        # Supervisor: restart the WS server if it ever crashes, with exponential
        # backoff. Without this a single handler crash kills the daemon thread and
        # the WS endpoint stays dead until the whole node restarts.
        backoff = 1.0
        max_backoff = 30.0
        while not NETWORK_STOP_FLAG.is_set():
            started = time.monotonic()
            try:
                logger.info("WebSocket Thread running trio loop...")
                trio.run(main)
                # main() returned without raising (serve exited or stop requested).
                if NETWORK_STOP_FLAG.is_set():
                    break
                logger.warning("WS server exited cleanly; restarting in %.1fs", backoff)
            except Exception as e:
                _log_ws_exception("WS Server crashed:", e)
                logger.warning("Restarting WS server in %.1fs", backoff)

            if NETWORK_STOP_FLAG.is_set():
                break
            # Reset backoff if the server stayed up for a while (transient blip).
            if time.monotonic() - started > 60.0:
                backoff = 1.0
            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

        logger.info("WebSocket Thread stopped.")

    t = threading.Thread(target=_ws_runner, name="WebSocketServerThread", daemon=True)
    t.start()



def handle_client(conn, addr, container: ServiceContainer):
    """Handle a single client connection, supporting multiple newline-delimited commands.

    Commands are framed by newline (``\\n``, with an optional preceding ``\\r``).
    Bytes are accumulated across ``recv()`` calls so a command larger than
    ``BUFFER_SIZE`` -- e.g. a rule-deploy ``sendtx`` carrying ``bv[384]`` pubkey
    constants -- is reassembled instead of truncated mid-payload (issue #24).
    On EOF any unterminated remainder is dispatched as a final command so a legacy
    client that sends one command without a trailing newline and then closes still
    gets a response. Splitting on the ``\\n`` byte never splits a UTF-8 multibyte
    sequence, so each complete line decodes safely.
    """
    import socket

    client_label = f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) else str(addr)
    is_local = isinstance(addr, tuple) and addr[0] in ("127.0.0.1", "::1")
    logger.info("Connection accepted from %s", client_label)

    # Same limiter the WebSocket path uses. This path had none, so a pipelined
    # stream of commands on one TCP connection was unmetered.
    limiter = _RpcLimiter(time.monotonic())

    def _dispatch(line_bytes: bytes) -> bool:
        """Process one command line. Return False if the connection should close."""
        try:
            raw = line_bytes.decode('utf-8').strip()
        except UnicodeDecodeError as exc:
            logger.warning("Invalid UTF-8 from %s: %s", client_label, exc)
            err = api_response.error_response(
                "", "Invalid UTF-8 encoding", "INVALID_PARAMS"
            ) + "\r\n"
            try:
                conn.sendall(err.encode('utf-8'))
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                return False
            return True

        if not raw:
            return True  # blank line (e.g. between commands) -> ignore

        command_name = raw.split()[0].lower()
        if not limiter.allow(command_name, time.monotonic()):
            logger.warning("Rate limit exceeded for %s (%s)", client_label, command_name)
            try:
                conn.sendall((_rate_limited_response() + "\r\n").encode("utf-8"))
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                return False
            return True

        # Use shared process_command logic
        success, result_message = process_command(raw, container, client_label, is_local=is_local)

        # Append newline for TCP clients if missing (process_command returns raw response)
        if not result_message.endswith("\n"):
            result_message += "\r\n"

        try:
            conn.sendall(result_message.encode('utf-8'))
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            logger.info("Client %s disconnected during send", client_label)
            return False
        return True

    try:
        with conn:
            buffer = bytearray()
            while True:
                try:
                    data = conn.recv(config.BUFFER_SIZE)
                except (ConnectionResetError, ConnectionAbortedError):
                    # Normal client disconnect patterns (e.g. browser probes, clients closing early).
                    logger.info("Client %s reset/aborted connection", client_label)
                    break
                except socket.error:
                    logger.exception("Socket error with %s", client_label)
                    break

                if not data:
                    # EOF: flush any unterminated remainder as a final command so
                    # clients that don't newline-terminate their last command (but
                    # do close/half-close) still get a response.
                    logger.info("Client %s disconnected", client_label)
                    if buffer.strip():
                        _dispatch(bytes(buffer))
                    break

                buffer.extend(data)

                # Dispatch every complete newline-delimited command in the buffer.
                closed = False
                while True:
                    nl = buffer.find(b"\n")
                    if nl == -1:
                        break
                    line = bytes(buffer[:nl])
                    del buffer[:nl + 1]
                    if not _dispatch(line):
                        closed = True
                        break
                if closed:
                    break

                # Anti-DoS: a pending (unterminated) command must not grow without
                # bound. Once the buffered remainder exceeds the cap it cannot be a
                # single valid command, so reject and close.
                if len(buffer) > config.MAX_RPC_COMMAND_BYTES:
                    logger.warning(
                        "Client %s exceeded max RPC command size (%d bytes); closing.",
                        client_label, config.MAX_RPC_COMMAND_BYTES,
                    )
                    err = api_response.error_response(
                        "", "RPC command exceeds maximum size", "PARSE_ERROR"
                    ) + "\r\n"
                    try:
                        conn.sendall(err.encode('utf-8'))
                    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                        pass
                    break
    except Exception:
        logger.exception("Unexpected error in handle_client for %s", client_label)
    finally:
        logger.info("Closing connection to %s", client_label)


# --- Main Server Execution ---
def _start_network_and_websocket(container: ServiceContainer) -> frozenset:
    """Start the NetworkService, then the WebSocket server. Returns the libp2p
    ports, which the RPC port scan must skip as well."""
    logger.info("Starting NetworkService background thread...")
    # libp2p binds before the WebSocket and RPC servers scan for their ports.
    p2p_ports = _await_network_listening(_start_network_background(container))

    logger.info("Starting WebSocket Server background thread...")
    _start_websocket_server(container, p2p_ports)
    return p2p_ports


def _run_server(container: ServiceContainer):
    """Runs the main server loop. The caller is responsible for exception handling."""
    logger.info("Bootstrapping server in '%s' environment", container.settings.env)

    if container.settings.env == "production":
        if os.environ.get("TAU_FORCE_TEST", "0") == "1":
            raise ConfigurationError("TAU_FORCE_TEST=1 is forbidden when TAU_ENV=production.")
        if os.environ.get("TAU_FORCE_FRESH_START") == "1":
            logger.warning(
                "TAU_FORCE_FRESH_START=1 with TAU_ENV=production: persisted Tau state will be ignored this boot."
            )

    tau_module = container.tau_manager
    db_module = container.db
    chain_state_module = container.chain_state

    if not os.path.exists(config.TAU_PROGRAM_FILE):
        raise ConfigurationError(f"Tau program file '{config.TAU_PROGRAM_FILE}' not found.")

    logger.info("Using Tau program file: %s", os.path.abspath(config.TAU_PROGRAM_FILE))
    logger.info("Initializing database at %s", config.STRING_DB_PATH)
    db_module.init_db()

    # Initialize Chain State EARLY (so we can restore it on first boot if needed)
    logger.info("Initializing and loading chain state...")
    chain_state_module.initialize_persistent_state()

    # Define the State Restore Callback
    # This will be called by the Tau Manager thread whenever the process comes up (fresh or restart)
    def _restore_callback():
        restore_flag = os.environ.get("TAU_RESTORE_RULES_ON_STARTUP", "").strip().lower()
        restore_enabled = restore_flag not in {"0", "false", "no", "off"}
        use_persisted_state = restore_enabled
        latest = db_module.get_canonical_head_block()
        has_non_genesis_chain = bool(latest and int(latest.get("block_number", 0)) > 0)
        persisted_full_spec = chain_state_module.get_persisted_full_tau_spec() if has_non_genesis_chain else ""

        # Safe Mode Fallback:
        # If TAU_FORCE_FRESH_START is set (e.g. by tau_manager after a crash),
        # skip persisted dynamic state and only replay Genesis-derived updates.
        if os.environ.get("TAU_FORCE_FRESH_START") == "1":
            logger.warning("TAU_FORCE_FRESH_START=1 detected: Ignoring persisted DB state and replaying only Genesis-derived Tau updates.")
            use_persisted_state = False
        elif not restore_enabled:
            logger.info("Persisted Tau restore disabled. Replaying only Genesis-derived Tau updates.")

        try:
            if use_persisted_state:
                if persisted_full_spec:
                    logger.info("Restoring Tau spec from chain state (len=%s)...", len(persisted_full_spec))
                    tau_module.restore_full_tau_spec(persisted_full_spec)
                    logger.info("Tau restore completed via chain state snapshot.")
                    return

            restore_plan = chain_state_module.get_tau_restore_plan(use_persisted_state=use_persisted_state)
            if restore_plan:
                logger.info("Replaying %s Tau rule update(s) via i0 after bootstrap from %s...", len(restore_plan), config.TAU_PROGRAM_FILE)
                # Shared with the rebuild-from-genesis path so both reconstruct
                # an identical interpreter (consensus o6/o7 + application + builtin).
                persist_needed = chain_state_module.replay_tau_restore_plan(
                    restore_plan, source_prefix="startup"
                )

                if persist_needed:
                    latest = db_module.get_canonical_head_block()
                    latest_hash = ""
                    latest_num = 0
                    if latest:
                        latest_hash = latest.get("block_hash") or latest.get("hash") or ""
                        header = latest.get("header") or {}
                        latest_num = int(latest.get("block_number", header.get("block_number", 0)) or 0)
                    chain_state_module.commit_state_to_db(latest_hash, latest_num)
                    logger.info("Persisted replayed Tau application rules (last_block_hash=%s).", latest_hash[:16] if latest_hash else "")
            else:
                logger.info("No Tau rule updates to replay after bootstrap.")
        except Exception:
            logger.exception("Failed to replay Tau rule updates during startup callback")

    # Register the callback BEFORE starting the manager
    tau_module.set_state_restore_callback(_restore_callback)
    
    # Register Rules Handler to persist updates from Tau to DB
    tau_module.set_rules_handler(chain_state_module.save_effective_tau_spec)

    logger.info("Starting Tau Process Manager Thread...")
    manager_thread = threading.Thread(target=tau_module.start_and_manage_tau_process, daemon=True)
    manager_thread.start()

    logger.info("Waiting for Tau to signal readiness...")
    # This waits for 'tau_ready', which is set AFTER the callback completes
    if not tau_module.tau_ready.wait(timeout=config.CLIENT_WAIT_TIMEOUT):
        tau_module.request_shutdown()
        raise TauEngineCrash("Tau did not signal readiness within the expected timeout.")

    logger.info("Tau is ready.")
    
    # (Removed old restore logic block here as it's now handled by the callback)

    p2p_ports = _start_network_and_websocket(container)

    # Start Miner if configured
    if container.miner:
        logger.info("Starting Automated Miner...")
        container.miner.start()



    server_socket = None
    actual_port = config.PORT

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        max_port_attempts = 10
        for port_offset in range(max_port_attempts):
            test_port = config.PORT + port_offset
            if test_port in p2p_ports:
                logger.warning("Port %s:%s is the libp2p listen port, trying next port...", config.HOST, test_port)
                continue
            try:
                server_socket.bind((config.HOST, test_port))
                actual_port = test_port
                break
            except OSError:
                if port_offset == max_port_attempts - 1:
                    raise
                logger.warning("Port %s:%s is busy, trying next port...", config.HOST, test_port)
        else:
            raise TauEngineCrash("Failed to bind to any configured port.")

        server_socket.listen()
        logger.info("Listening on %s:%s", config.HOST, actual_port)
        logger.info("Press Ctrl+C to stop.")

        while not tau_module.server_should_stop.is_set():
            try:
                conn, addr = server_socket.accept()
                if not _tcp_conn_sema.acquire(blocking=False):
                    logger.warning("Rejected TCP from %s: at capacity", addr)
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue

                def _run_tcp_client(c=conn, a=addr):
                    try:
                        handle_client(c, a, container)
                    finally:
                        _tcp_conn_sema.release()

                client_thread = threading.Thread(target=_run_tcp_client, daemon=True)
                client_thread.start()
            except OSError:
                if tau_module.server_should_stop.is_set():
                    logger.info("Socket closed during shutdown.")
                    break
                logger.exception("Error accepting connection")
            except Exception:
                if tau_module.server_should_stop.is_set():
                    break
                logger.exception("Unexpected error accepting connection")
    finally:
        logger.info("Main server loop finished. Cleaning up...")
        if server_socket:
            try:
                server_socket.close()
            finally:
                logger.info("Server socket closed.")
        
        # Stop Miner first to prevent new blocks during shutdown
        if container.miner:
             try:
                 logger.info("Stopping Miner...")
                 container.miner.stop()
             except Exception:
                 logger.warning("Error stopping Miner", exc_info=True)

        try:
            if NETWORK_THREAD is not None:
                logger.info("Stopping NetworkService...")
                NETWORK_STOP_FLAG.set()
                NETWORK_THREAD.join(timeout=config.SHUTDOWN_TIMEOUT)
                if NETWORK_THREAD.is_alive():
                    logger.warning("NetworkService thread did not exit cleanly.")
            else:
                logger.info("NetworkService was not started or already stopped.")
        except Exception:
            logger.warning("Error during NetworkService shutdown", exc_info=True)

        logger.info("Waiting for Tau manager thread to exit...")
        if isinstance(manager_thread, threading.Thread) and manager_thread.is_alive():
            manager_thread.join(timeout=config.SHUTDOWN_TIMEOUT)
            if manager_thread.is_alive():
                logger.warning("Tau manager thread did not exit cleanly. Forcing termination.")
                tau_module.kill_tau_process()
        else:
            logger.info("Tau manager thread already finished or not started.")

        logger.info("Shutdown complete.")


def _start_watchdog():
    status_file = os.path.join(config.DATA_DIR, "tau_status.json")
    os.makedirs(config.DATA_DIR, exist_ok=True)
    
    # Clean up stale status files
    if os.path.exists(status_file):
        try:
            os.remove(status_file)
        except Exception:
            pass
            
    # Watchdog kills the server when Tau communication exceeds COMM_TIMEOUT (TAU_COMM_TIMEOUT).
    timeout = getattr(config, "COMM_TIMEOUT", 60)
    watchdog_script = os.path.join(os.path.dirname(__file__), "watchdog.py")
    watchdog_log = os.path.join(config.DATA_DIR, "watchdog.log")

    try:
        log_handle = open(watchdog_log, "a", encoding="utf-8")
        subprocess.Popen(
            [sys.executable, watchdog_script, status_file, str(timeout), str(os.getpid())],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        logger.info(
            "Watchdog started: kills server if Tau comm exceeds comm_timeout "
            "(COMM_TIMEOUT=%ss, TAU_COMM_TIMEOUT); log=%s",
            timeout,
            watchdog_log,
        )
    except Exception as e:
        logger.error("Failed to start watchdog process: %s", e)


def main():
    parser = argparse.ArgumentParser(description="Tau Testnet Server")
    parser.add_argument(
        "--ephemeral-identity",
        action="store_true",
        help="Use an ephemeral libp2p identity for this run (do not load/generate persistent key)",
    )
    args = parser.parse_args()

    tau_logging.configure(getattr(config, "LOGGING", None))
    if (
        config.settings.authority.open_governance_admission
        and config.settings.network.bootstrap_peers
    ):
        logger.warning(
            "open_governance_admission is enabled with non-empty bootstrap peers; "
            "unsafe for a networked node."
        )
    
    _start_watchdog()
    container = ServiceContainer.build(overrides={"logger": logger, "ephemeral_identity": args.ephemeral_identity})
    tau_module = container.tau_manager
    try:
        _run_server(container)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, shutting down server...")
        tau_module.request_shutdown()
    except ConfigurationError as exc:
        logger.critical("Configuration error during startup: %s", exc)
        tau_module.request_shutdown()
        sys.exit(1)
    except TauEngineCrash as exc:
        logger.critical("Tau process error: %s", exc)
        tau_module.request_shutdown()
        sys.exit(1)
    except Exception:
        logger.exception("An unexpected server error occurred.")
        tau_module.request_shutdown()
        sys.exit(1)


if __name__ == "__main__":
    main()
