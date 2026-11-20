"""`tau-testnet policy receive`: ask a node whether an address judges the
payments made to it, and how it would judge one."""
from __future__ import annotations

from test_cli_policy import APPROVER, _ok, _run, alice  # noqa: F401 - `alice` is a fixture

PAYER = "cc" * 48
ANSWER = {"active": True, "address": APPROVER, "has_clause": True, "judges_incoming": True}


def test_it_asks_about_an_address():
    recorded = []
    rc, out, _ = _run(["policy", "receive", APPROVER], [_ok(ANSWER)], recorded)
    assert rc == 0
    assert recorded == [f"getrecipientpolicy {APPROVER}"]
    assert "judges_incoming" in out


def test_it_defaults_to_the_keys_own_address(alice):
    recorded = []
    rc, _, err = _run(["policy", "receive", "--key", "alice"], [_ok(ANSWER)], recorded)
    assert rc == 0, err
    assert recorded == [f"getrecipientpolicy {alice}"]


def test_it_probes_one_payment():
    recorded = []
    probe = dict(ANSWER, probe={"accepts_payment": True, "max_hold_seconds": 600})
    rc, out, _ = _run(
        ["policy", "receive", APPROVER, "--from", PAYER, "--amount", "25"],
        [_ok(probe)], recorded)
    assert rc == 0
    assert recorded == [f"getrecipientpolicy {APPROVER} {PAYER} 25"]
    assert "max_hold_seconds" in out


def test_a_probe_needs_both_the_sender_and_the_amount():
    recorded = []
    rc, _, err = _run(["policy", "receive", APPROVER, "--from", PAYER], [], recorded)
    assert rc != 0 and recorded == []
    assert "--from and --amount go together" in err
