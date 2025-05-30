import socket
import threading
import sys
import time
import os

# Project modules
import config
import tau_manager
import re
import json
import db
from commands import sendtx, getmempool, gettimestamp  # Import command handlers
import chain_state # Added import

MEMPOOL = []
MEMPOOL_LOCK = threading.Lock()
MEMPOOL_STATE = {'mempool': MEMPOOL, 'lock': MEMPOOL_LOCK}

# --- Command Dispatch Table ---
# Maps lowercase command names to their respective handler modules
COMMAND_HANDLERS = {
    'sendtx': sendtx,
    'getmempool': getmempool,
    'getcurrenttimestamp': gettimestamp
}


def handle_client(conn, addr):
    """Handles a single client connection, supports multiple commands."""
    import datetime
    import socket
    print(f"[INFO][Server] Connection accepted from {addr}")
    try:
        with conn:
            while True:
                try:
                    data = conn.recv(config.BUFFER_SIZE)
                except socket.error as e:
                    print(f"[ERROR][Server] Socket error with {addr}: {e}")
                    break
                if not data:
                    print(f"[INFO][Server] Client {addr} disconnected.")
                    break

                # Decode raw input string (preserve JSON casing for sendtx)
                try:
                    raw = data.decode('utf-8').strip()
                except UnicodeDecodeError as e:
                    print(f"[ERROR][Server] Invalid UTF-8 from {addr}: {e}")
                    conn.sendall(b"ERROR: Invalid UTF-8 encoding\n")
                    continue
                # Handle JSON-based sendtx: sendtx '{...}'
                if raw.lower().startswith('sendtx '):
                    json_blob = raw[len('sendtx '):].strip()
                    print(f"[INFO][Server] Received sendtx command with JSON payload: {json_blob}...")
                    try:
                        # Queue the transaction directly, bypassing Tau for now
                        result_msg = sendtx.queue_transaction(json_blob)
                    except Exception as e:
                        result_msg = f"ERROR: {e}"
                    print(f"[INFO][Server] Sending response for sendtx to {addr}: '{result_msg}'")
                    conn.sendall((result_msg + "\r\n").encode('utf-8'))
                    continue
                # For other commands, normalize to lowercase for command name lookup
                command_str = raw.lower()
                print(f"[INFO][Server] Received command from {addr}: '{command_str}'")
                if not command_str:
                    conn.sendall(b"ERROR: Received empty command.")
                    continue

                # Map string parameters to Tau IDs
                parts = command_str.split()
                if len(parts) >= 2:
                    cmd = parts[0]
                    mapped = [cmd]
                    print(f"[DEBUG][Server] Mapping parameters for command '{cmd}': {parts[1:]} ->", end=' ')
                    for p in parts[1:]:
                        if re.fullmatch(r"[01]+", p) or p.isdigit():
                            mapped.append(p)
                            print(p, end=' ')
                        else:
                            yid = db.get_string_id(p)
                            mapped.append(yid)
                            print(f"{p}=>{yid}", end=' ')
                    print()
                    parts = mapped
                command_name = parts[0]

                # Handle timestamp locally
                if command_name in ("gettimestamp", "getcurrenttimestamp"):
                    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    resp = f"Current Timestamp (UTC): {now}\r\n"
                    print(f"[INFO][Server] Sending timestamp to {addr}: '{resp}'")
                    conn.sendall(resp.encode('utf-8'))
                    continue

                if raw.lower().startswith("getbalance "):
                    parts = raw.split()
                    if len(parts) != 2:
                        resp = "ERROR: Usage: getbalance <address>\r\n"
                    else:
                        bal = chain_state.get_balance(parts[1])
                        resp = f"BALANCE: {bal}\r\n"
                    conn.sendall(resp.encode('utf-8'))
                    continue

                if raw.lower().startswith("history "):
                    parts = raw.split()
                    if len(parts) != 2:
                        resp = "ERROR: Usage: history <address>\r\n"
                    else:
                        addr = parts[1]
                        items = []
                        for entry in db.get_mempool_txs():
                            if entry.startswith("json:"):
                                try:
                                    payload = json.loads(entry[5:])
                                except Exception:
                                    continue
                                ops = payload.get("operations", {}).get("1", [])
                                if payload.get("sender_pubkey") == addr or any(isinstance(op, (list, tuple)) and addr in op for op in ops):
                                    items.append(json.dumps(payload, separators=(",", ":"), sort_keys=True))
                        if items:
                            resp = "HISTORY:\n" + "\n".join(items) + "\r\n"
                        else:
                            resp = "HISTORY: empty\r\n"
                    conn.sendall(resp.encode('utf-8'))
                    continue

                # Dispatch other commands (excluding the now-handled sendtx)
                # Ensure sendtx doesn't fall through here
                if command_name == 'sendtx':
                    print("[WARN][Server] sendtx command should have been handled earlier. Ignoring.")
                    conn.sendall(b"ERROR: Invalid sendtx format. Use sendtx '{\"0\":...}'.\r\n")
                    continue

                handler = COMMAND_HANDLERS.get(command_name)
                if not handler:
                    msg = f"ERROR: Unknown command '{command_name}'\n"
                    conn.sendall(msg.encode('utf-8'))
                    continue

                # Encode
                try:
                    sbf_input = handler.encode_command(parts)
                except Exception as e:
                    conn.sendall(f"ERROR: {e}".encode('utf-8'))
                    continue

                # Wait for Tau
                if not tau_manager.tau_ready.wait(timeout=config.CLIENT_WAIT_TIMEOUT):
                    conn.sendall(b"ERROR: Tau process not ready.")
                    continue

                # Communicate
                try:
                    sbf_output = tau_manager.communicate_with_tau(sbf_input)
                    decoded = handler.decode_output(sbf_output, sbf_input)
                    result_message = handler.handle_result(decoded, sbf_input, MEMPOOL_STATE)
                except TimeoutError:
                    result_message = "ERROR: Timeout communicating with Tau process."
                except Exception:
                    result_message = "ERROR: Internal error processing command."

                # Reverse-map Tau IDs
                try:
                    result_message = re.sub(r"y(\\d+)", lambda m: db.get_text_by_id("y" + m.group(1)),
                                            result_message) + "\r\n"
                except Exception:
                    pass

                print(f"[INFO][Server] Sending response to {addr}: '{result_message}'")
                conn.sendall(result_message.encode('utf-8'))
    except Exception as e:
        print(f"[ERROR][Server] Unexpected error in handle_client for {addr}: {e}")
    finally:
        print(f"[INFO][Server] Closing connection to {addr}")


# --- Main Server Execution ---
def main():
    """
    Starts the Tau process manager thread and then the main server loop.
    Handles graceful shutdown.
    """
    # Ensure Tau program file exists before starting manager
    if not os.path.exists(config.TAU_PROGRAM_FILE):
        print(f"[FATAL][Server] Tau program file '{config.TAU_PROGRAM_FILE}' not found!", file=sys.stderr)
        sys.exit(1)
    print(f"[INFO][Server] Using Tau program file: {os.path.abspath(config.TAU_PROGRAM_FILE)}")

    # Initialize database for string mappings
    print(f"[INFO][Server] Initializing database at {config.STRING_DB_PATH}")
    db.init_db()

    # Initialize chain state for balances
    print(f"[INFO][Server] Initializing chain state...")
    chain_state.init_chain_state()

    # Start Tau process manager thread
    print("[INFO][Server] Starting Tau Process Manager Thread...")
    manager_thread = threading.Thread(target=tau_manager.start_and_manage_tau_process, daemon=True)
    manager_thread.start()

    # Start the server socket listening
    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((config.HOST, config.PORT))
        server_socket.listen()
        print(f"[INFO][Server] Listening on {config.HOST}:{config.PORT}")
        print(f"[INFO][Server] Press Ctrl+C to stop.")

        # Main accept loop
        while not tau_manager.server_should_stop.is_set():
            try:
                conn, addr = server_socket.accept()
                client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                client_thread.start()
            except OSError as e:
                if tau_manager.server_should_stop.is_set():
                    print("[INFO][Server] Socket closed during shutdown.")
                    break
                else:
                    print(f"[ERROR][Server] Error accepting connection: {e}")
            except Exception as e:
                if not tau_manager.server_should_stop.is_set():
                    print(f"[ERROR][Server] Unexpected error accepting connection: {e}")
                else:
                    break  # Exit loop if server stopping

    # Exception handling for server setup/main loop
    except OSError as e:
        print(f"[FATAL][Server] Could not bind to {config.HOST}:{config.PORT} - {e}", file=sys.stderr)
        tau_manager.request_shutdown()  # Signal shutdown
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO][Server] KeyboardInterrupt received, shutting down server...")
        tau_manager.request_shutdown()  # Signal shutdown
    except Exception as e:
        print(f"[FATAL][Server] An unexpected server error occurred in main loop: {e}", file=sys.stderr)
        tau_manager.request_shutdown()  # Signal shutdown
    finally:
        # --- Graceful Shutdown ---
        print("[INFO][Server] Main server loop finished. Cleaning up...")
        if server_socket:
            server_socket.close()
            print("[INFO][Server] Server socket closed.")

        # Wait for Tau manager thread to exit
        print("[INFO][Server] Waiting for Tau manager thread to exit...")
        # Check if manager_thread exists and is alive before joining
        if 'manager_thread' in locals() and isinstance(manager_thread, threading.Thread) and manager_thread.is_alive():
            manager_thread.join(timeout=config.SHUTDOWN_TIMEOUT)
            if manager_thread.is_alive():
                print("[WARN][Server] Tau manager thread did not exit cleanly.")
        else:
            print("[INFO][Server] Tau manager thread already finished or not started.")

        print("[INFO][Server] Shutdown complete.")


if __name__ == "__main__":
    main()
