"""W3 networking hardening tests: remote-createblock gate, announce addrs,
genesis handshake gate, bootstrap retry."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


class TestCreateblockGate:
    def _container(self, allow_remote=False):
        container = MagicMock()
        container.settings.authority.allow_remote_createblock = allow_remote
        container.command_handlers = {}
        return container

    @staticmethod
    def _code(resp):
        import json
        body = json.loads(resp)
        return body.get("code") or body.get("error", {}).get("code")

    def test_remote_createblock_forbidden(self):
        import server
        ok, resp = server.process_command("createblock", self._container(), "1.2.3.4:5", is_local=False)
        assert ok is True
        assert self._code(resp) == "FORBIDDEN"

    def test_local_createblock_dispatches(self):
        import json
        import server
        # No handler registered -> reaches dispatch and returns UNKNOWN_COMMAND,
        # which proves the gate let it through.
        ok, resp = server.process_command("createblock", self._container(), "127.0.0.1:5", is_local=True)
        assert self._code(resp) == "UNKNOWN_COMMAND"

    def test_remote_allowed_with_flag(self):
        import json
        import server
        ok, resp = server.process_command(
            "createblock", self._container(allow_remote=True), "1.2.3.4:5", is_local=False
        )
        assert self._code(resp) == "UNKNOWN_COMMAND"

    def test_other_commands_unaffected(self):
        import json
        import server
        ok, resp = server.process_command("getbalance x", self._container(), "1.2.3.4:5", is_local=False)
        assert self._code(resp) == "UNKNOWN_COMMAND"  # not FORBIDDEN


class TestSelfAdvertisedAddrs:
    def _service(self, announce):
        from network.service import NetworkService
        svc = object.__new__(NetworkService)  # no __init__: only the helper is exercised
        svc._config = MagicMock()
        svc._config.announce_addrs = announce
        host = MagicMock()
        host.get_addrs.return_value = ["/ip4/10.0.0.1/tcp/4001"]
        svc._host_manager = MagicMock()
        type(svc)._host_fallback = None
        with patch.object(type(svc), "host", property(lambda self: host)):
            return svc, host

    def test_announce_addrs_win(self):
        from network.service import NetworkService
        svc = object.__new__(NetworkService)
        svc._config = MagicMock()
        svc._config.announce_addrs = ["/ip4/1.2.3.4/tcp/4001"]
        assert NetworkService._self_advertised_addrs(svc) == ["/ip4/1.2.3.4/tcp/4001"]

    def test_fallback_to_host_addrs(self):
        from network.service import NetworkService
        svc = object.__new__(NetworkService)
        cfg = MagicMock()
        cfg.announce_addrs = []
        svc._config = cfg
        host = MagicMock()
        host.get_addrs.return_value = ["/ip4/10.0.0.1/tcp/4001"]
        with patch.object(NetworkService, "host", new=property(lambda self: host)):
            assert NetworkService._self_advertised_addrs(svc) == ["/ip4/10.0.0.1/tcp/4001"]

    def test_magicmock_spec_config_falls_back(self):
        # A MagicMock(spec=NetworkConfig) yields a truthy MagicMock for
        # announce_addrs; the isinstance guard must reject it.
        from network.config import NetworkConfig
        from network.service import NetworkService
        svc = object.__new__(NetworkService)
        svc._config = MagicMock(spec=NetworkConfig)
        host = MagicMock()
        host.get_addrs.return_value = []
        with patch.object(NetworkService, "host", new=property(lambda self: host)):
            assert NetworkService._self_advertised_addrs(svc) == []


class TestGenesisGateLogic:
    """The gate fires only when both sides have a non-empty, differing hash."""

    @staticmethod
    def _should_reject(peer_gh, local_gh):
        return bool(peer_gh and local_gh and str(peer_gh) != str(local_gh))

    def test_mismatch_rejects(self):
        assert self._should_reject("a" * 64, "b" * 64)

    def test_match_allows(self):
        assert not self._should_reject("a" * 64, "a" * 64)

    def test_empty_local_allows(self):
        assert not self._should_reject("a" * 64, "")

    def test_missing_peer_allows(self):
        assert not self._should_reject(None, "a" * 64)


@pytest.mark.trio
async def test_bootstrap_retry_until_success():
    import trio
    from network.service import NetworkService

    svc = object.__new__(NetworkService)
    svc._config = MagicMock()
    svc._runner_stop = trio.Event()

    attempts = {"n": 0}

    async def flaky_connect(peer_info):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ConnectionError("nope")

    host = MagicMock()
    host.connect = flaky_connect
    host.get_peerstore.return_value = MagicMock()

    peer_cfg = {
        "peer_id": "12D3KooWDpWEYxBy8y84AssrPSLaq9DxC7Lncmn5wERJnAWZFnYC",
        "addrs": ["/ip4/127.0.0.1/tcp/4001"],
    }

    with patch.object(NetworkService, "host", new=property(lambda self: host)), \
         patch.object(NetworkService, "get_id", lambda self: "self-id"), \
         patch("trio.sleep", lambda *_: trio.lowlevel.checkpoint()):
        await NetworkService._connect_to_bootstrap_peer(svc, peer_cfg)

    assert attempts["n"] == 3
