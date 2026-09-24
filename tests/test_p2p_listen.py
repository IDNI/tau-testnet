"""The node's libp2p listener must hold the port it advertises.

Two local node processes never connected: every dial ended in "failed to
negotiate the secure protocol". The listener had never bound. A node's
WebSocket server takes the first free port from TAU_PORT+1 upward and started
alongside the network thread, so when the p2p port was TAU_PORT+1 (what two
back-to-back bind(0) calls hand out on macOS) it took that port first. libp2p
swallows a failed bind, the node logged its configured address as listening,
and every peer's dial reached the WebSocket server.
"""
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time

import multiaddr
import pytest

import server
from errors import ConfigurationError
from network import NetworkConfig, NetworkListenError, NetworkService

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _taken_port():
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock, sock.getsockname()[1]


@pytest.mark.trio
async def test_start_fails_when_the_listen_port_is_taken(caplog):
    caplog.set_level(logging.INFO, logger="network.host")
    blocker, port = _taken_port()
    svc = NetworkService(NetworkConfig(
        network_id="p2p-listen-test",
        listen_addrs=[multiaddr.Multiaddr(f"/ip4/127.0.0.1/tcp/{port}")],
        genesis_hash="p2p-listen-test",
    ))
    try:
        with pytest.raises(NetworkListenError, match=f"/ip4/127.0.0.1/tcp/{port} ") as exc:
            await svc.start()
    finally:
        blocker.close()
    assert "in use" in str(exc.value)
    assert svc.listen_addrs() == []
    assert not [r for r in caplog.records if "NetworkService listening" in r.getMessage()]


def test_a_listen_failure_stops_node_startup():
    startup = server._NetworkStartup([multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/4001")])
    startup.finish(error=NetworkListenError(
        "libp2p could not listen on any configured address: "
        "/ip4/127.0.0.1/tcp/4001 (Address already in use)"
    ))
    with pytest.raises(ConfigurationError, match="TAU_NETWORK_LISTEN"):
        server._await_network_listening(startup, timeout=1)


def test_rpc_and_ws_scans_skip_configured_and_bound_p2p_ports():
    startup = server._NetworkStartup([
        multiaddr.Multiaddr("/ip4/0.0.0.0/tcp/4001"),
        multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0"),
    ])
    startup.finish(listen_addrs=[
        multiaddr.Multiaddr("/ip4/0.0.0.0/tcp/4001"),
        multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/51234"),
    ])
    assert server._await_network_listening(startup, timeout=1) == {4001, 51234}


# A node process as far as the network is concerned: server.py's own startup of
# the network thread and the WebSocket server's port scan, minus the Tau engine.
_NODE = r'''
import json, os, socket, time
import multiaddr
import config, db, server
from network import BootstrapPeer, NetworkConfig, bus

def emit(**event):
    print(json.dumps(event), flush=True)

db.init_db()
cfg = NetworkConfig(
    network_id="p2p-listen-test",
    listen_addrs=[multiaddr.Multiaddr(os.environ["NODE_LISTEN"])],
    bootstrap_peers=[
        BootstrapPeer(p["peer_id"], [multiaddr.Multiaddr(a) for a in p["addrs"]])
        for p in json.loads(os.environ["NODE_BOOTSTRAP"])
    ],
    identity_key=os.urandom(32),
    genesis_hash="p2p-listen-test",
)

class Container:
    chain_state = None
    def build_network_config(self):
        return cfg

config.PORT = int(os.environ["NODE_RPC_PORT"])
p2p_ports = server._start_network_and_websocket(Container())
svc = bus.get()
emit(event="listening", peer_id=str(svc.get_id()),
     addrs=[str(a) for a in svc.listen_addrs()], p2p_ports=sorted(p2p_ports))

def ws_port():
    for port in range(config.PORT + 1, config.PORT + 10):
        if port in p2p_ports:
            continue
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return port
        except OSError:
            pass

deadline = time.time() + 20
while time.time() < deadline:
    port = ws_port()
    if port:
        emit(event="ws", port=port)
        break
    time.sleep(0.1)
seen = None
while True:
    peers = sorted(str(p) for p in svc.get_connected_peers())
    if peers != seen:
        seen = peers
        emit(event="peers", peers=peers)
    time.sleep(0.1)
'''


class _Node:
    def __init__(self, tmp_path, name, *, rpc_port, listen, bootstrap=()):
        workdir = tmp_path / name
        workdir.mkdir()
        script = workdir / "node.py"
        script.write_text(_NODE)
        env = dict(os.environ)
        env.update({
            "PYTHONPATH": REPO_ROOT + os.pathsep + env.get("PYTHONPATH", ""),
            "TAU_DB_PATH": str(workdir / "node.db"),
            "TAU_HEAD_REANNOUNCE_INTERVAL": "0",
            "NODE_RPC_PORT": str(rpc_port),
            "NODE_LISTEN": listen,
            "NODE_BOOTSTRAP": json.dumps(list(bootstrap)),
        })
        self.name = name
        self._stderr = open(workdir / "stderr.log", "w+")
        self.proc = subprocess.Popen(
            [sys.executable, str(script)], cwd=REPO_ROOT, env=env,
            stdout=subprocess.PIPE, stderr=self._stderr, text=True,
        )
        self.events = []
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self):
        for line in self.proc.stdout:
            try:
                self.events.append(json.loads(line))
            except ValueError:
                pass

    def wait_for(self, predicate, what, timeout=60.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            for event in list(self.events):
                if predicate(event):
                    return event
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        self._stderr.seek(0)
        pytest.fail(f"node {self.name}: no {what} (exit={self.proc.poll()})\n"
                    f"events={self.events}\nstderr tail:\n{self._stderr.read()[-4000:]}")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=10)
        self._reader.join(timeout=5)
        self.proc.stdout.close()
        self._stderr.close()


def _free_port_run(length):
    """First port of `length` consecutive free ports on 127.0.0.1."""
    for _ in range(50):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            base = probe.getsockname()[1]
        if base + length > 65535:
            continue
        try:
            for port in range(base, base + length):
                with socket.socket() as s:
                    s.bind(("127.0.0.1", port))
        except OSError:
            continue
        return base
    pytest.skip("no run of free local ports")


_WS_ONLY = r'''
import os, time
import config, server
config.PORT = int(os.environ["NODE_RPC_PORT"])
server._start_websocket_server(None, frozenset({config.PORT + 1}))
time.sleep(60)
'''


def _accepts(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        return True
    except OSError:
        return False


def test_ws_scan_skips_a_libp2p_port_even_when_it_could_bind_it(tmp_path):
    # On macOS 0.0.0.0:P and 127.0.0.1:P bind side by side, so a free-looking
    # port is no proof libp2p is not on it: the scan must skip it by number.
    base = _free_port_run(4)
    script = tmp_path / "ws.py"
    script.write_text(_WS_ONLY)
    env = dict(os.environ, NODE_RPC_PORT=str(base),
               PYTHONPATH=REPO_ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))
    proc = subprocess.Popen([sys.executable, str(script)], cwd=REPO_ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 20
        while time.time() < deadline and proc.poll() is None:
            if _accepts(base + 1) or _accepts(base + 2):
                break
            time.sleep(0.1)
        assert not _accepts(base + 1), "WebSocket server took the libp2p port"
        assert _accepts(base + 2), "WebSocket server never bound PORT+2"
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_node_processes_connect_when_the_p2p_port_is_the_ws_default(tmp_path):
    rpc_port = _free_port_run(4)
    p2p_port = rpc_port + 1  # where the WebSocket scan starts
    a = _Node(tmp_path, "a", rpc_port=rpc_port, listen=f"/ip4/127.0.0.1/tcp/{p2p_port}")
    b = None
    try:
        listening = a.wait_for(lambda e: e["event"] == "listening", "listening event")
        assert listening["addrs"] == [f"/ip4/127.0.0.1/tcp/{p2p_port}"]
        assert p2p_port in listening["p2p_ports"]
        ws = a.wait_for(lambda e: e["event"] == "ws", "WebSocket server")
        assert ws["port"] == rpc_port + 2

        b = _Node(tmp_path, "b", rpc_port=_free_port_run(4), listen="/ip4/127.0.0.1/tcp/0",
                  bootstrap=[{"peer_id": listening["peer_id"], "addrs": listening["addrs"]}])
        b_id = b.wait_for(lambda e: e["event"] == "listening", "listening event")["peer_id"]

        b.wait_for(lambda e: e["event"] == "peers" and listening["peer_id"] in e["peers"],
                   "connection to A", timeout=30)
        a.wait_for(lambda e: e["event"] == "peers" and b_id in e["peers"],
                   "connection from B", timeout=30)
    finally:
        for node in (b, a):
            if node is not None:
                node.stop()
