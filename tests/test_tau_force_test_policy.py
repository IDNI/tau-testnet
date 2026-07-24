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

        compile_calls = []

        def mock_compile(prior_spec, revisions, timeout):
            compile_calls.append((prior_spec, revisions, timeout))
            return "syntax error in rule"  # non-None -> rejection

        # Crypto is mandatory now: mock signature verification instead of disabling it.
        monkeypatch.setattr(sendtx.G2Basic, "Verify", lambda *args, **kwargs: True)
        monkeypatch.setattr(sendtx, "_validate_bls12_381_pubkey", lambda *args, **kwargs: (True, None))
        monkeypatch.setattr(sendtx.chain_state, "get_sequence_number", lambda *_args, **_kwargs: 0)
        monkeypatch.setattr(sendtx.chain_state, "get_rules_state", lambda: None)
        monkeypatch.setattr(sendtx.db, "get_pending_sequence", lambda *_args, **_kwargs: None)
        # Op-"0" rule validation runs only via the killable isolated subprocess
        # (the sole rule-validation path). Drive it: engine ready, not in test
        # mode, and stub the subprocess compile to reject the rule.
        monkeypatch.setattr(sendtx.tau_manager.tau_ready, "is_set", lambda: True)
        monkeypatch.setattr(sendtx.tau_manager, "tau_test_mode", False, raising=False)
        import tau_native
        monkeypatch.setattr(tau_native, "compile_revisions_isolated_subprocess", mock_compile)

        result = sendtx.queue_transaction(json.dumps(payload), propagate=False)

        # Because TAU_ENV=development, TAU_FORCE_TEST must be ignored: the tx is
        # still routed through real Tau rule validation and rejected.
        assert result["ok"] is False
        assert result["code"] == "TX_REJECTED"
        assert result["message"].startswith("Transaction rejected by Tau (rule validation).")
        assert len(compile_calls) == 1
        assert compile_calls[0][1] == [payload["operations"]["0"]]
    finally:
        config.reload_settings(env="test")
