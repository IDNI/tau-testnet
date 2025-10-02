import asyncio
import logging
import os
import socket
import sys
import threading

from app.container import ServiceContainer
from network import NetworkService

# Project modules
import config
import re
import json
from commands import createblock, sendtx  # Import command handlers
from errors import ConfigurationError, TauProcessError
import tau_logging


logger = logging.getLogger(__name__)

# --- NetworkService globals ---
NETWORK_THREAD = None
NETWORK_STOP_FLAG = threading.Event()
# --- Command Dispatch Table ---


# --- NetworkService helpers ---
def _start_network_background(container: ServiceContainer) -> None:
    """
    Start NetworkService in a dedicated asyncio thread.
    """
    global NETWORK_THREAD
    cfg = container.build_network_config()

    def _runner():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        service = NetworkService(cfg)
        async def main():
            await service.start()
            # Periodically check the stop flag
            try:
                while not NETWORK_STOP_FLAG.is_set():
                    await asyncio.sleep(0.25)
            finally:
                await service.stop()
        try:
            loop.run_until_complete(main())
        finally:
            loop.stop()
            loop.close()

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

                if raw.lower().startswith('sendtx '):
                    json_blob = raw[len('sendtx '):].strip()
                    logger.debug("Received sendtx payload from %s: %s", client_label, json_blob)
                    try:
                        result_msg = sendtx.queue_transaction(json_blob)
                    except Exception as exc:
                        logger.exception("sendtx queue failed for %s", client_label)
                        result_msg = f"ERROR: {exc}"
                    conn.sendall((result_msg + "\r\n").encode('utf-8'))
                    continue

                command_str = raw.lower()
                if not command_str:
                    conn.sendall(b"ERROR: Received empty command.")
                    continue

                logger.debug("Received command from %s: %s", client_label, command_str)

                parts = command_str.split()
                if len(parts) >= 2:
                    cmd = parts[0]
                    mapped = [cmd]
                    mapped_params = []
                    for param in parts[1:]:
                        if re.fullmatch(r"[01]+", param) or param.isdigit():
                            mapped.append(param)
                            mapped_params.append(param)
                        else:
                            yid = db_module.get_string_id(param)
                            mapped.append(yid)
                            mapped_params.append(f"{param}->{yid}")
                    logger.debug("Mapped parameters for %s: %s", cmd, mapped_params)
                    parts = mapped
                command_name = parts[0]

                if command_name in ("gettimestamp", "getcurrenttimestamp"):
                    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    resp = f"Current Timestamp (UTC): {now}\r\n"
                    conn.sendall(resp.encode('utf-8'))
                    continue

                if raw.lower().startswith("getbalance "):
                    parts_raw = raw.split()
                    if len(parts_raw) != 2:
                        resp = "ERROR: Usage: getbalance <address>\r\n"
                    else:
                        bal = chain_state_module.get_balance(parts_raw[1])
                        resp = f"BALANCE: {bal}\r\n"
                    conn.sendall(resp.encode('utf-8'))
                    continue

                if raw.lower().startswith("getsequence "):
                    parts_raw = raw.split()
                    if len(parts_raw) != 2:
                        resp = "ERROR: Usage: getsequence <address>\r\n"
                    else:
                        seq = chain_state_module.get_sequence_number(parts_raw[1])
                        resp = f"SEQUENCE: {seq}\r\n"
                    conn.sendall(resp.encode('utf-8'))
                    continue

                if raw.lower().startswith("history "):
                    parts_raw = raw.split()
                    if len(parts_raw) != 2:
                        resp = "ERROR: Usage: history <address>\r\n"
                    else:
                        history_addr = parts_raw[1]
                        items = []
                        for entry in db_module.get_mempool_txs():
                            if entry.startswith("json:"):
                                try:
                                    payload = json.loads(entry[5:])
                                except Exception:
                                    logger.debug("Skipping invalid mempool json entry for history")
                                    continue
                                ops = payload.get("operations", {}).get("1", [])
                                if payload.get("sender_pubkey") == history_addr or any(isinstance(op, (list, tuple)) and history_addr in op for op in ops):
                                    items.append(json.dumps(payload, separators=(",", ":"), sort_keys=True))
                        if items:
                            resp = "HISTORY:\n" + "\n".join(items) + "\r\n"
                        else:
                            resp = "HISTORY: empty\r\n"
                    conn.sendall(resp.encode('utf-8'))
                    continue

                if raw.lower().strip() == "createblock":
                    logger.info("Create block requested by %s", client_label)
                    try:
                        block_data = createblock.create_block_from_mempool()
                        if not block_data or "block_hash" not in block_data:
                            message = block_data.get("message") if isinstance(block_data, dict) else None
                            resp = (message or "Mempool is empty. No block created.") + "\r\n"
                            logger.info("Create block skipped for %s: %s", client_label, message or "empty mempool")
                        else:
                            tx_count = len(block_data.get("transactions", []))
                            block_hash = block_data["block_hash"]
                            block_number = block_data["header"]["block_number"]
                            merkle_root = block_data["header"]["merkle_root"]
                            timestamp = block_data["header"]["timestamp"]

                            resp_lines = [
                                f"SUCCESS: Block #{block_number} created successfully!",
                                f"  - Transactions: {tx_count}",
                                f"  - Block Hash: {block_hash}",
                                f"  - Merkle Root: {merkle_root}",
                                f"  - Timestamp: {timestamp}",
                            ]
                            for idx, tx in enumerate(block_data.get("transactions", []), start=1):
                                tx_json = json.dumps(tx, sort_keys=True)
                                resp_lines.append(f"  - TX#{idx}: {tx_json}")
                            resp_lines.append("  - Mempool cleared\r\n")
                            resp = "\n".join(resp_lines)
                            logger.info("Block #%s created via client %s", block_number, client_label)
                    except Exception:
                        logger.exception("Block creation failed for %s", client_label)
                        resp = "ERROR: Failed to create block\r\n"
                    conn.sendall(resp.encode('utf-8'))
                    continue

                if raw.lower().strip() == "getblocks":
                    logger.debug("getblocks requested by %s", client_label)
                    try:
                        blocks = db_module.get_all_blocks()
                        resp = json.dumps({"blocks": blocks}, separators=(",", ":")) + "\r\n"
                    except Exception:
                        logger.exception("getblocks failed for %s", client_label)
                        resp = "ERROR: Failed to fetch blocks\r\n"
                    conn.sendall(resp.encode('utf-8'))
                    continue

                if command_name == 'sendtx':
                    logger.warning("sendtx was not parsed correctly for %s", client_label)
                    conn.sendall(b"ERROR: Invalid sendtx format. Use sendtx '{\"0\":...}'.\r\n")
                    continue

                handler = command_handlers.get(command_name)
                if not handler:
                    msg = f"ERROR: Unknown command '{command_name}'\n"
                    logger.warning("Unknown command from %s: %s", client_label, command_name)
                    conn.sendall(msg.encode('utf-8'))
                    continue

                try:
                    sbf_input = handler.encode_command(parts)
                except Exception as exc:
                    logger.exception("Encoding command %s failed for %s", command_name, client_label)
                    conn.sendall(f"ERROR: {exc}".encode('utf-8'))
                    continue

                if not tau_module.tau_ready.wait(timeout=config.CLIENT_WAIT_TIMEOUT):
                    logger.error("Tau process not ready for command %s from %s", command_name, client_label)
                    conn.sendall(b"ERROR: Tau process not ready.")
                    continue

                try:
                    sbf_output = tau_module.communicate_with_tau(sbf_input)
                    decoded = handler.decode_output(sbf_output, sbf_input)
                    result_message = handler.handle_result(decoded, sbf_input, mempool_state)
                except TimeoutError:
                    logger.error("Timeout communicating with Tau for %s", client_label)
                    result_message = "ERROR: Timeout communicating with Tau process."
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
    tau_logging.configure(getattr(config, "LOGGING", None))
    container = ServiceContainer.build(overrides={"logger": logger})
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
