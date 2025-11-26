import logging
import os
import socket
import sys
import threading
import trio
import argparse

from app.container import ServiceContainer
from network import NetworkService

# Project modules
import config
import re
import json
from commands import createblock, sendtx  # Import command handlers
from errors import ConfigurationError, TauProcessError, TauTestnetError
import tau_logging


logger = logging.getLogger(__name__)

# --- NetworkService globals ---
NETWORK_THREAD = None
NETWORK_STOP_FLAG = threading.Event()
# --- Command Dispatch Table ---


# --- NetworkService helpers ---
def _start_network_background(container: ServiceContainer) -> None:
    """
    Start NetworkService in a dedicated Trio thread.
    """
    global NETWORK_THREAD
    cfg = container.build_network_config()

    def _runner():
        service = NetworkService(cfg)
        async def main() -> None:
            await service.start()
            try:
                while not NETWORK_STOP_FLAG.is_set():
                    await trio.sleep(0.25)
            finally:
                await service.stop()
        trio.run(main)

    t = threading.Thread(target=_runner, name="NetworkServiceThread", daemon=True)
    t.start()
    NETWORK_THREAD = t


def handle_client(conn, addr, container: ServiceContainer):
    """Handles a single client connection, supports multiple commands."""
    import datetime
    import socket

    client_label = f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) else str(addr)
    logger.info("Connection accepted from %s", client_label)

    db_module = container.db
    chain_state_module = container.chain_state
    tau_module = container.tau_manager
    mempool_state = container.mempool_state
    command_handlers = container.command_handlers

    try:
        with conn:
            while True:
                try:
                    data = conn.recv(config.BUFFER_SIZE)
                except socket.error as exc:
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

                command_str = raw.lower()
                if not command_str:
                    conn.sendall(b"ERROR: Received empty command.")
                    continue

                # Determine command name (first word)
                parts = raw.split()
                if not parts:
                    continue
                command_name = parts[0].lower()

                logger.debug("Received command from %s: %s", client_label, command_name)

                # Look up handler
                handler = command_handlers.get(command_name)
                if not handler:
                    msg = f"ERROR: Unknown command '{command_name}'\n"
                    logger.warning("Unknown command from %s: %s", client_label, command_name)
                    conn.sendall(msg.encode('utf-8'))
                    continue

                # 1. Local execution path (if handler supports it)
                if hasattr(handler, 'execute'):
                    try:
                        resp = handler.execute(raw, container)
                        conn.sendall(resp.encode('utf-8'))
                    except Exception as exc:
                        logger.exception("Error executing local command %s for %s", command_name, client_label)
                        conn.sendall(f"ERROR: {exc}\r\n".encode('utf-8'))
                    continue

                # 2. Tau execution path
                # Map parameters to IDs for Tau commands
                mapped = [parts[0]]
                mapped_params = []
                for param in parts[1:]:
                    if re.fullmatch(r"[01]+", param) or param.isdigit():
                        mapped.append(param)
                        mapped_params.append(param)
                    else:
                        yid = db_module.get_string_id(param)
                        mapped.append(yid)
                        mapped_params.append(f"{param}->{yid}")
                logger.debug("Mapped parameters for %s: %s", command_name, mapped_params)
                parts = mapped

                try:
                    tau_input = handler.encode_command(parts)
                except TauTestnetError as exc:
                    logger.warning("Encoding command %s failed for %s: %s", command_name, client_label, exc)
                    conn.sendall(f"ERROR: {exc}".encode('utf-8'))
                    continue
                except Exception as exc:
                    logger.exception("Encoding command %s failed for %s", command_name, client_label)
                    conn.sendall(f"ERROR: {exc}".encode('utf-8'))
                    continue

                if not tau_module.tau_ready.wait(timeout=config.CLIENT_WAIT_TIMEOUT):
                    logger.error("Tau process not ready for command %s from %s", command_name, client_label)
                    conn.sendall(b"ERROR: Tau process not ready.")
                    continue

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

                try:
                    result_message = re.sub(
                        r"y(\\d+)",
                        lambda m: db_module.get_text_by_id("y" + m.group(1)),
                        result_message,
                    ) + "\r\n"
                except Exception:
                    logger.debug("Failed to reverse-map Tau IDs for %s", client_label)
                    result_message = result_message + "\r\n"

                conn.sendall(result_message.encode('utf-8'))
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

    logger.info("Starting Tau Process Manager Thread...")
    manager_thread = threading.Thread(target=tau_module.start_and_manage_tau_process, daemon=True)
    manager_thread.start()

    logger.info("Waiting for Tau to signal readiness...")
    if not tau_module.tau_ready.wait(timeout=config.CLIENT_WAIT_TIMEOUT):
        tau_module.request_shutdown()
        raise TauProcessError("Tau did not signal readiness within the expected timeout.")

    logger.info("Tau is ready.")
    logger.info("Initializing and loading chain state...")
    chain_state_module.initialize_persistent_state()

    logger.info("Starting NetworkService background thread...")
    _start_network_background(container)

    saved_rules = chain_state_module.get_rules_state()
    if saved_rules:
        logger.info("Persisted rules state detected; defer injection until explicit workflow.")

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
            raise TauProcessError("Failed to bind to any configured port.")

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
    except TauProcessError as exc:
        logger.critical("Tau process error: %s", exc)
        tau_module.request_shutdown()
        sys.exit(1)
    except Exception:
        logger.exception("An unexpected server error occurred.")
        tau_module.request_shutdown()
        sys.exit(1)


if __name__ == "__main__":
    main()
