import logging
import os
import socket
import ssl
import sys
import threading
import trio
import argparse
import trio_websocket


from app.container import ServiceContainer
from network import NetworkService

# Project modules
import config
import re
import json
from commands import createblock, sendtx  # Import command handlers
from errors import ConfigurationError, TauEngineCrash, TauTestnetError
import tau_logging


logger = logging.getLogger("tau.server")

# --- NetworkService globals ---
NETWORK_THREAD = None
NETWORK_STOP_FLAG = threading.Event()
# --- Command Dispatch Table ---


def process_command(raw_command: str, container: ServiceContainer, client_label: str) -> tuple[bool, str]:
    """
    Process a single command string from any source (TCP or WS).
    
    Args:
        raw_command: The full command string (e.g., "getbalance <key>")
        container: ServiceContainer instance
        client_label: Identifier for logging (IP:Port or WS ID)
        
    Returns:
        (success, response_string)
        success: True if the command was processed (even if it resulted in a Tau error).
                 False if it was a protocol level error (empty, unknown command, malformed).
        response_string: The response to send back to the client. Does NOT include trailing newline.
    """
    if not raw_command:
        return False, "ERROR: Received empty command."

    # Handle Handshake (Virtual Command)
    if raw_command.startswith("hello version="):
        # Format: hello version=1
        try:
            version_val = raw_command.split("=")[1].strip()
            if version_val == "1":
                # Return standard handshake response
                # We can inject node_id if we want, for now minimal is fine
                return True, f"ok version=1 env={container.settings.env} node=tau-node"
            else:
                return False, f"error unsupported_version expected=1 got={version_val}"
        except IndexError:
            return False, "error malformed_handshake"

    command_str = raw_command.lower()
    parts = raw_command.split()
    if not parts:
        return False, "ERROR: Empty command."
        
    command_name = parts[0].lower()
    logger.debug("Processing command from %s: %s", client_label, command_name)

    command_handlers = container.command_handlers
    handler = command_handlers.get(command_name)
    
    if not handler:
        logger.warning("Unknown command from %s: %s", client_label, command_name)
        return False, f"ERROR: Unknown command '{command_name}'"

    # 1. Local execution path
    if hasattr(handler, 'execute'):
        try:
            resp = handler.execute(raw_command, container)
            return True, resp.rstrip() # Ensure we control newlines
        except Exception as exc:
            logger.exception("Error executing local command %s for %s", command_name, client_label)
            return True, f"ERROR: {exc}"

    # 2. Tau execution path
    db_module = container.db
    tau_module = container.tau_manager
    mempool_state = container.mempool_state

    # Map parameters to IDs for Tau commands
    mapped = [parts[0]]
    # We don't really need mapped_params list for logic, just for debug if we wanted
    for param in parts[1:]:
        if re.fullmatch(r"[01]+", param) or param.isdigit():
            mapped.append(param)
        else:
            yid = db_module.get_string_id(param)
            mapped.append(yid)
    
    parts = mapped

    try:
        tau_input = handler.encode_command(parts)
    except TauTestnetError as exc:
        logger.warning("Encoding command %s failed for %s: %s", command_name, client_label, exc)
        return True, f"ERROR: {exc}"
    except Exception as exc:
        logger.exception("Encoding command %s failed for %s", command_name, client_label)
        return True, f"ERROR: {exc}"

    if not tau_module.tau_ready.wait(timeout=config.CLIENT_WAIT_TIMEOUT):
        logger.error("Tau process not ready for command %s from %s", command_name, client_label)
        return True, "ERROR: Tau process not ready."

    try:
        tau_output = tau_module.communicate_with_tau(tau_input)
        decoded = handler.decode_output(tau_output, tau_input)
        result_message = handler.handle_result(decoded, tau_input, mempool_state)
    except TimeoutError:
        logger.error("Timeout communicating with Tau for %s", client_label)
        result_message = "ERROR: Timeout communicating with Tau process."
    except TauTestnetError as e:
        logger.warning("Tau error processing %s for %s: %s", command_name, client_label, e)
        result_message = f"ERROR: {e}"
    except Exception:
        logger.exception("Internal error processing %s for %s", command_name, client_label)
        result_message = "ERROR: Internal error processing command."

    # Reverse map IDs
    try:
        result_message = re.sub(
            r"y(\\d+)",
            lambda m: db_module.get_text_by_id("y" + m.group(1)),
            result_message,
        )
    except Exception:
        logger.debug("Failed to reverse-map Tau IDs for %s", client_label)
    
    return True, result_message



# --- NetworkService helpers ---
def _start_network_background(container: ServiceContainer) -> None:
    """
    Start NetworkService in a dedicated Trio thread.
    """
    global NETWORK_THREAD
    cfg = container.build_network_config()

    def _runner():
        service = NetworkService(cfg)
        
        # Register service with global bus so commands (e.g. sendtx) can access it
        from network import bus
        bus.register(service)
        
        # Inject DHT manager into chain_state so it can store formulas
        if hasattr(container.chain_state, "set_dht_client"):
            container.chain_state.set_dht_client(service._dht_manager)
            
        async def main() -> None:
            await service.start()
            
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


# --- WebSocket Server ---
async def websocket_handler(request):
    """
    Handles WebSocket connections.
    Includes Handshake, Origin Check, and Command Processing.
    """
    container = request.server_container
    ws = await request.accept()
    
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
        logger.warning("Rejected WS connection from disallowed origin: %s. Use TAU_WS_ALLOWED_ORIGINS to allow it.", origin)
        await ws.send_message("error disallowed_origin")
        await ws.aclose()
        return

    client_label = f"WS:{id(ws)}"
    logger.info("WS Connection accepted: %s (Origin: %s)", client_label, origin)

    # Rate Limiting State (Basic Token Bucket)
    # Rate: 5 req/sec, Burst: 10
    bucket_tokens = 10.0
    last_check = trio.current_time()
    
    try:
        while True:
            try:
                message = await ws.get_message()
            except trio_websocket.ConnectionClosed:
                break
                
            # Rate Limit Check
            now = trio.current_time()
            elapsed = now - last_check
            last_check = now
            bucket_tokens = min(10.0, bucket_tokens + elapsed * 5.0)
            
            if bucket_tokens < 1.0:
                 logger.warning("Rate limit exceeded for %s", client_label)
                 await ws.send_message("error rate_limit_exceeded")
                 # Optionally close, or just drop
                 continue
            bucket_tokens -= 1.0
            
            # Process
            success, response = process_command(message, container, client_label)
            await ws.send_message(response)
            
            # Close on fatal protocol errors if desired, or keep open.
            # Here we keep open unless handshake failed fatally? 
            # process_command returns success=False for protocol errors, but we usually want to keep connection for invalid commands (typos)
            # Only close if it was a handshake failure that mandated it?
            # For now, keep open.
            
    except Exception as e:
        logger.error("WS Handler Error %s: %s", client_label, e)
    finally:
        logger.info("WS Client disconnected: %s", client_label)


def _start_websocket_server(container: ServiceContainer) -> None:
    """
    Starts the Trio WebSocket server in a separate daemon thread.
    """
    def _ws_runner():
        ws_port = config.PORT + 1
        # Try to find a free port if busy, or just fail? 
        # Plan says: Handle port conflicts (start at config.PORT + 1, scan if busy).
        
        # We need a partial to pass container to handler, or attach it to the request object wrapper?
        # trio-websocket handler signature is fn(request).
        # We can wrap it.
        
        async def handler_with_container(request):
            request.server_container = container
            await websocket_handler(request)

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

        async def main():
            # Port scanning logic
            actual_ws_port = ws_port
            ssl_context = _build_ws_ssl_context()
            scheme = "wss" if ssl_context else "ws"
            # Simple scan
            for i in range(10):
                try:
                    p = actual_ws_port + i
                    logger.info("Attempting to bind %s to 0.0.0.0:%s", scheme, p)
                    # serve_websocket blocks until cancelled.
                    # We need to run it.
                    await trio_websocket.serve_websocket(
                        handler_with_container, 
                        "0.0.0.0", 
                        p, 
                        ssl_context=ssl_context
                    )
                    # If it returns, it finished?
                    logger.warning("WS serve returned (unexpected).")
                    break 
                except OSError:
                    logger.warning("WS Port %s busy, trying next...", p)
                except Exception as e:
                    logger.error("WS Server failed to start: %s", e)
                    break
        
        try:
           logger.info("WebSocket Thread running trio loop...")
           trio.run(main)
        except Exception as e:
           logger.error("WS Thread crashed: %s", e)

    t = threading.Thread(target=_ws_runner, name="WebSocketServerThread", daemon=True)
    t.start()



def handle_client(conn, addr, container: ServiceContainer):
    """Handles a single client connection, supports multiple commands."""
    import socket

    client_label = f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) else str(addr)
    logger.info("Connection accepted from %s", client_label)

    try:
        with conn:
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
                    logger.info("Client %s disconnected", client_label)
                    break

                try:
                    raw = data.decode('utf-8').strip()
                except UnicodeDecodeError as exc:
                    logger.warning("Invalid UTF-8 from %s: %s", client_label, exc)
                    conn.sendall(b"ERROR: Invalid UTF-8 encoding\n")
                    continue

                # Use shared process_command logic
                success, result_message = process_command(raw, container, client_label)
                
                # Append newline for TCP clients if missing (process_command returns raw response)
                if not result_message.endswith("\n"):
                    result_message += "\r\n"
                
                try:
                    conn.sendall(result_message.encode('utf-8'))
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    logger.info("Client %s disconnected during send", client_label)
                    break
    except Exception:
        logger.exception("Unexpected error in handle_client for %s", client_label)
    finally:
        logger.info("Closing connection to %s", client_label)


# --- Main Server Execution ---
def _run_server(container: ServiceContainer):
    """Runs the main server loop. The caller is responsible for exception handling."""
    logger.info("Bootstrapping server in '%s' environment", container.settings.env)

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
        
        saved_rules = chain_state_module.get_rules_state()
        
        # Safe Mode Fallback:
        # If TAU_FORCE_FRESH_START is set (e.g. by tau_manager after a crash),
        # we ignore the persisted (potentially bad) state and force a fresh load of built-in rules.
        if os.environ.get("TAU_FORCE_FRESH_START") == "1":
            logger.warning("TAU_FORCE_FRESH_START=1 detected: Ignoring persisted DB state to recover with Safe Mode (Genesis + Built-ins).")
            saved_rules = None

        if saved_rules and restore_enabled:
            try:
                logger.info("Restoring persisted Tau rules/state (len=%s)...", len(saved_rules))
                # Note: communicate_with_tau checks 'tau_process_ready' which is SET before this callback runs.
                out = tau_module.communicate_with_tau(
                    rule_text=saved_rules,
                    target_output_stream_index=0,
                    wait_for_ready=False,
                )
                logger.info("Tau restore result (o0): %s", out)
            except Exception:
                logger.exception("Failed to restore persisted Tau rules/state during callback")
        else:
            if saved_rules:
                logger.info("Persisted rules found but restore is disabled. Injecting built-in rules instead.")
            # No persisted rules (or restore disabled). Load built-in rule files after Tau is up.
            try:
                builtin_rules = []
                if hasattr(chain_state_module, "load_builtin_rules_from_disk"):
                    builtin_rules = chain_state_module.load_builtin_rules_from_disk()

                if builtin_rules:
                    logger.info("Injecting %s built-in rules from disk...", len(builtin_rules))
                    for rule_text in builtin_rules:
                        logger.info("Injecting built-in rule: %s", rule_text)
                        tau_module.communicate_with_tau(
                            rule_text=rule_text,
                            target_output_stream_index=0,
                            wait_for_ready=False,
                        )

                    # Persist the resulting rules snapshot so restarts don't re-inject.
                    latest = db_module.get_latest_block()
                    latest_hash = latest["block_hash"] if latest else ""
                    chain_state_module.commit_state_to_db(latest_hash)
                    logger.info("Built-in rules injected and persisted (last_block_hash=%s).", latest_hash[:16] if latest_hash else "")
                else:
                    logger.info("No built-in rules on disk; leaving Tau spec as-is.")
            except Exception:
                logger.exception("Failed to inject built-in rules during Tau restore callback")

    # Register the callback BEFORE starting the manager
    tau_module.set_state_restore_callback(_restore_callback)
    
    # Register Rules Handler to persist updates from Tau to DB
    tau_module.set_rules_handler(chain_state_module.save_rules_state)

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

    logger.info("Starting NetworkService background thread...")
    _start_network_background(container)

    # Start WebSocket Server
    logger.info("Starting WebSocket Server background thread...")
    _start_websocket_server(container)

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
            try:
                test_port = config.PORT + port_offset
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
                client_thread = threading.Thread(target=handle_client, args=(conn, addr, container), daemon=True)
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


def main():
    parser = argparse.ArgumentParser(description="Tau Testnet Server")
    parser.add_argument(
        "--ephemeral-identity",
        action="store_true",
        help="Use an ephemeral libp2p identity for this run (do not load/generate persistent key)",
    )
    args = parser.parse_args()

    tau_logging.configure(getattr(config, "LOGGING", None))
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
