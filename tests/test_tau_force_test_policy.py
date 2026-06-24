import json
import time

import config
from commands import sendtx
import tau_manager


def test_force_test_only_enabled_in_test_env(monkeypatch):
    monkeypatch.setenv("TAU_FORCE_TEST", "1")

    config.reload_settings(env="test")
    assert tau_manager.is_force_test_enabled() is True

    config.reload_settings(env="development")
    try:
        assert tau_manager.is_force_test_enabled() is False
    finally:
        config.reload_settings(env="test")


def test_sendtx_ignores_force_test_outside_test_env(monkeypatch):
    monkeypatch.setenv("TAU_FORCE_TEST", "1")
    config.reload_settings(env="development")

    try:
        sender = "a" * 96
        payload = {
            "sender_pubkey": sender,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"0": "always o1[t] := i9[t]."},
            "fee_limit": "0",
            "signature": "00" * 48,
        }

        tau_calls = []

        def mock_communicate_with_tau(**kwargs):
            tau_calls.append(kwargs)
            return "Error: syntax"

        # Crypto is mandatory now: mock signature verification instead of disabling it.
        monkeypatch.setattr(sendtx.G2Basic, "Verify", lambda *args, **kwargs: True)
        monkeypatch.setattr(sendtx, "_validate_bls12_381_pubkey", lambda *args, **kwargs: (True, None))
        monkeypatch.setattr(sendtx.chain_state, "get_sequence_number", lambda *_args, **_kwargs: 0)
        monkeypatch.setattr(sendtx.chain_state, "get_rules_state", lambda: None)
        monkeypatch.setattr(sendtx.db, "get_pending_sequence", lambda *_args, **_kwargs: None)
        # Force the live validation path (isolated compile is skipped unless the
        # engine is ready) so the mocked Tau call is the deciding gate.
        monkeypatch.setattr(sendtx.tau_manager.tau_ready, "is_set", lambda: False)
        monkeypatch.setattr(sendtx.tau_manager, "communicate_with_tau", mock_communicate_with_tau)

        result = sendtx.queue_transaction(json.dumps(payload), propagate=False)

        # Because TAU_ENV=development, TAU_FORCE_TEST must be ignored: the tx is
        # still routed through real Tau rule validation and rejected.
        assert result["ok"] is False
        assert result["code"] == "TX_REJECTED"
        assert result["message"].startswith("Transaction rejected by Tau (rule validation).")
        assert len(tau_calls) == 1
        assert tau_calls[0]["rule_text"] == payload["operations"]["0"]
    finally:
        config.reload_settings(env="test")
