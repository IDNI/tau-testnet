"""`tau-testnet policy receive`: ask a node whether an address judges the
payments made to it, and how it would judge one. `policy receive-rule`: write
the rule of such an account from numbers."""
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


# --- a payment with terms ---------------------------------------------------------

def _asked(argv):
    recorded = []
    rc, out, err = _run(["policy", "receive", APPROVER, "--from", PAYER, "--amount", "25"] + argv,
                        [_ok(ANSWER)], recorded)
    return rc, recorded, err


def test_it_asks_about_a_park():
    rc, recorded, err = _asked(["--park", "2h"])
    assert rc == 0, err
    assert recorded == [f"getrecipientpolicy {APPROVER} {PAYER} 25 seconds park=7200"]


def test_a_length_in_blocks_puts_the_payment_on_the_height_clock():
    rc, recorded, err = _asked(["--park", "100b"])
    assert rc == 0, err
    assert recorded == [f"getrecipientpolicy {APPROVER} {PAYER} 25 blocks park=100"]


def test_it_asks_about_every_term():
    rc, recorded, err = _asked(["--hold", "30d", "--recall", "1h", "--limit", "500",
                                "--period", "1w", "--refund", "90d"])
    assert rc == 0, err
    assert recorded == [
        f"getrecipientpolicy {APPROVER} {PAYER} 25 seconds hold=2592000 recall=3600 "
        f"period=604800 refund=7776000 limit=500"]


def test_refund_never_is_passed_on():
    rc, recorded, err = _asked(["--hold", "600", "--refund", "never"])
    assert rc == 0, err
    assert recorded == [f"getrecipientpolicy {APPROVER} {PAYER} 25 seconds hold=600 refund=never"]


def test_the_lengths_of_one_payment_share_a_clock():
    rc, recorded, err = _asked(["--hold", "30d", "--recall", "5b"])
    assert rc != 0 and recorded == []
    assert "one clock" in err


def test_a_limit_needs_its_period():
    rc, recorded, err = _asked(["--limit", "500"])
    assert rc != 0 and recorded == [] and "--limit and --period go together" in err


def test_terms_need_the_payment_they_belong_to():
    recorded = []
    rc, _, err = _run(["policy", "receive", APPROVER, "--park", "2h"], [], recorded)
    assert rc != 0 and recorded == []
    assert "need --from and --amount" in err


def test_a_length_that_is_none_is_refused():
    rc, recorded, err = _asked(["--park", "soon"])
    assert rc != 0 and recorded == [] and "not a length" in err


# --- writing a rule ---------------------------------------------------------------

def _write(argv):
    recorded = []
    rc, out, err = _run(["policy", "receive-rule"] + argv, [], recorded)
    assert recorded == [], "writing a rule sends nothing"
    return rc, out, err


def test_it_writes_the_rule_of_the_numbers():
    from consensus import recipient_policy

    rc, out, err = _write(["--only-from", PAYER, "--max-hold", "30d", "--max-recall", "1h",
                           "--min-allowance", "500", "--per", "1w", "--min-refund", "90d"])
    assert rc == 0, err
    assert out.strip() == recipient_policy.receive_rule(
        senders=[PAYER], max_hold_seconds=2_592_000, max_recall_seconds=3_600,
        min_allowance=500, per_seconds=604_800, min_refund_seconds=7_776_000)


def test_one_number_per_clock():
    from consensus import recipient_policy

    rc, out, err = _write(["--max-hold", "600", "--max-hold", "100b"])
    assert rc == 0, err
    assert out.strip() == recipient_policy.receive_rule(
        max_hold_seconds=600, max_hold_blocks=100)
    rc, _, err = _write(["--max-hold", "600", "--max-hold", "10m"])
    assert rc != 0 and "given twice in seconds" in err


def test_the_plain_rules():
    from consensus import recipient_policy

    for argv, numbers in (
        (["--final-only"], dict(final_only=True)),
        (["--no-limits"], dict(no_limits=True)),
        (["--no-refunds"], dict(no_refunds=True)),
        (["--only-from", PAYER, "--only-from", APPROVER], dict(senders=[PAYER, APPROVER])),
        (["--min-allowance", "500", "--per", "30d", "--average"],
         dict(min_allowance=500, per_seconds=2_592_000, average=True)),
    ):
        rc, out, err = _write(argv)
        assert rc == 0, err
        assert out.strip() == recipient_policy.receive_rule(**numbers)


def test_it_writes_to_a_file(tmp_path):
    from consensus import recipient_policy

    target = tmp_path / "policy.tau"
    rc, out, err = _write(["--final-only", "--out", str(target)])
    assert rc == 0, err
    assert target.read_text() == recipient_policy.receive_rule(final_only=True) + "\n"
    assert "wrote" in out


def test_numbers_that_contradict_are_refused_with_the_reason():
    for argv, said in (
        ([], "nothing to write"),
        (["--final-only", "--max-hold", "5"], "final only"),
        (["--min-allowance", "500"], "together with its period"),
        (["--no-limits", "--min-allowance", "5", "--per", "1w"], "exclude each other"),
        (["--only-from", "zz"], "96 hex"),
        (["--max-hold", "soon"], "not a length"),
    ):
        rc, out, err = _write(argv)
        assert rc != 0 and said in err, (argv, err)
        assert out.strip() == ""
