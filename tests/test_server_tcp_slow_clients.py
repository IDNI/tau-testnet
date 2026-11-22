"""A TCP RPC slot is taken back from a client that does not use it.

The server has 64 TCP slots. Before this change one host could hold all of
them, and a client that sent half a command and stopped (slowloris) kept its
slot forever, so a few such connections left the RPC port unanswered for every
other client until the attacker let go. Now each host has at most
_TCP_MAX_PER_HOST slots, an unfinished command is dropped after
_TCP_PARTIAL_COMMAND_SECONDS however slowly it trickles in, and an idle
connection after _TCP_IDLE_SECONDS. A client that sends whole commands is
served exactly as before.
"""
import socket
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

import server
from app.container import ServiceContainer


def _container():
    c = MagicMock(spec=ServiceContainer)
    h = MagicMock()
    h.execute.return_value = '{"status":"ok"}'
    c.command_handlers = {"ping": h}
    for attr in ("tau_manager", "db", "chain_state", "mempool_state"):
        setattr(c, attr, MagicMock())
    return c


@pytest.fixture
def fast_timeouts():
    with patch.object(server, "_TCP_POLL_SECONDS", 0.05), \
         patch.object(server, "_TCP_PARTIAL_COMMAND_SECONDS", 0.6), \
         patch.object(server, "_TCP_IDLE_SECONDS", 0.6):
        yield


def _serve_one():
    """A real connected socket pair with handle_client on the server end."""
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    client = socket.create_connection(lsock.getsockname())
    conn, addr = lsock.accept()
    lsock.close()
    done = threading.Event()

    def run():
        try:
            server.handle_client(conn, addr, _container())
        finally:
            done.set()
    threading.Thread(target=run, daemon=True).start()
    return client, done


def _read_reply(sock, timeout=5.0):
    sock.settimeout(timeout)
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def test_an_unfinished_command_loses_its_slot(fast_timeouts):
    client, done = _serve_one()
    client.sendall(b"sendtx '")
    assert done.wait(5), "a half-sent command kept its slot"
    client.close()


def test_trickling_bytes_does_not_extend_the_deadline(fast_timeouts):
    client, done = _serve_one()
    t0 = time.monotonic()
    try:
        while not done.is_set() and time.monotonic() - t0 < 5:
            client.sendall(b"x")
            time.sleep(0.03)
    except OSError:
        pass
    assert done.wait(1), "a trickle of bytes held the slot"
    assert time.monotonic() - t0 < 3
    client.close()


def test_an_idle_connection_loses_its_slot(fast_timeouts):
    client, done = _serve_one()
    assert done.wait(5)
    client.close()


def test_whole_commands_are_served_and_reset_the_idle_clock(fast_timeouts):
    client, done = _serve_one()
    for _ in range(4):
        client.sendall(b"ping\r\n")
        assert b'"ok"' in _read_reply(client)
        time.sleep(0.3)               # under the idle limit each time
    assert not done.is_set()
    client.close()
    assert done.wait(5)


def test_a_command_finished_in_time_is_served(fast_timeouts):
    client, done = _serve_one()
    client.sendall(b"pi")
    time.sleep(0.3)
    client.sendall(b"ng\r\n")
    assert b'"ok"' in _read_reply(client)
    client.close()


def test_each_host_gets_a_share_of_the_slots():
    host_a, host_b = "10.0.0.1", "10.0.0.2"
    taken = [server._tcp_host_acquire(host_a) for _ in range(server._TCP_MAX_PER_HOST)]
    try:
        assert all(taken)
        assert not server._tcp_host_acquire(host_a)
        assert server._tcp_host_acquire(host_b)
        server._tcp_host_release(host_b)
        server._tcp_host_release(host_a)
        assert server._tcp_host_acquire(host_a)
    finally:
        while server._tcp_per_host.get(host_a):
            server._tcp_host_release(host_a)
    assert host_a not in server._tcp_per_host and host_b not in server._tcp_per_host


def test_one_host_cannot_take_every_slot():
    assert server._TCP_MAX_PER_HOST * 2 <= server._TCP_MAX_CONNECTIONS
