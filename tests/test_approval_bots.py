"""The three approver bots: TOTP, security scan, human partner.

None of this is consensus code — a misbehaving bot can only fail to sign, or sign
what its owner told it to. The sender's Tau policy decides whether a signature is
enough. So these tests cover the parts that would silently do the wrong thing:
the TOTP implementation, one-time-use, the heuristics, and the DEFER-versus-
DECLINE distinction, which matters because a decline is recorded on chain and a
defer is not.
"""
import base64
import json
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import approval_bot_common as common  # noqa: E402
import approval_bot_partner as partner_mod  # noqa: E402
import approval_bot_scan as scan_mod  # noqa: E402
import approval_bot_totp as totp_mod  # noqa: E402

A = "1a" * 48
B = "2b" * 48
AUTH = "aa" * 48
SCAN = "bb" * 48

# RFC 6238 appendix B, SHA-1: secret is the ASCII "12345678901234567890".
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
RFC_VECTORS = [
    (59, "287082"),
    (1111111109, "081804"),
    (1111111111, "050471"),
    (1234567890, "005924"),
    (2000000000, "279037"),
]


# --- TOTP -------------------------------------------------------------------

@pytest.mark.parametrize("timestamp,expected", RFC_VECTORS)
def test_totp_matches_the_rfc6238_vectors(timestamp, expected):
    """Byte-compatible with Google Authenticator, or the whole bot is theatre."""
    assert totp_mod.totp_at(RFC_SECRET, timestamp) == expected


def test_totp_accepts_one_step_of_clock_skew_either_side():
    now = 1234567890
    code = totp_mod.totp_at(RFC_SECRET, now)
    assert totp_mod.verify_totp(RFC_SECRET, code, now=now) is not None
    assert totp_mod.verify_totp(RFC_SECRET, code, now=now + 30) is not None
    assert totp_mod.verify_totp(RFC_SECRET, code, now=now - 30) is not None
    # Two steps away is outside the window.
    assert totp_mod.verify_totp(RFC_SECRET, code, now=now + 90) is None


@pytest.mark.parametrize("bad", ["000000", "12345", "abcdef", "", None, 123456])
def test_totp_rejects_junk(bad):
    assert totp_mod.verify_totp(RFC_SECRET, bad, now=1234567890) is None


def test_a_generated_secret_round_trips_through_the_uri():
    secret = totp_mod.new_secret()
    uri = totp_mod.otpauth_uri(secret, "alice")
    assert uri.startswith("otpauth://totp/")
    assert f"secret={secret}" in uri
    assert totp_mod.verify_totp(secret, totp_mod.totp_at(secret, 1000), now=1000)


# --- the enrolment store ----------------------------------------------------

def test_the_store_refuses_world_readable_secrets(tmp_path):
    """These secrets ARE the second factor: anyone who can read one mints codes
    forever, so a loose mode is a configuration error, not a warning."""
    store = totp_mod.EnrollmentStore(str(tmp_path))
    store.enroll(A)
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
    os.chmod(store.path, 0o644)
    with pytest.raises(SystemExit, match="not be group- or world-readable"):
        store.check_permissions()


def test_enrolment_round_trips(tmp_path):
    store = totp_mod.EnrollmentStore(str(tmp_path))
    secret = store.enroll(A)
    assert store.secret_for(A) == secret
    assert store.secret_for(A.upper()) == secret, "pubkeys are case-insensitive"
    assert store.secret_for(B) is None


# --- the TOTP bot's decision -------------------------------------------------

class _FakeClient:
    def __init__(self, incoming=()):
        self.incoming = list(incoming)
        self.submitted = []

    def data(self, command):
        if command.startswith("getapprovalrequests"):
            return {"incoming": self.incoming}
        if command.startswith("getsequence"):
            # A node reports the tip alongside the sequence, and the bot needs
            # it to set the vote's expire_at_height.
            return {"sequence_number": 0, "tip_height": 7}
        return {}

    def rpc(self, command):
        self.submitted.append(command)
        return {"status": "ok", "data": {}}


class _FakeSigner:
    pubkey = AUTH

    def sign(self, payload):
        payload["signature"] = "00" * 96
        return payload


def _request(request_id="ab" * 32, amount=5000, sender=A, customs=None,
             approver=AUTH, state="awaiting"):
    return {
        "request_id": request_id,
        "sender_pubkey": sender,
        "recipient_pubkey": B,
        "amount": amount,
        "expire_at_height": 900,
        "approvers": {"18": {"pubkey": approver, "state": state}},
        "custom_inputs": customs or {},
    }


def _totp_bot(tmp_path, **kwargs):
    store = totp_mod.EnrollmentStore(str(tmp_path))
    client = _FakeClient()
    return totp_mod.TotpBot(client, _FakeSigner(), store=store, **kwargs), store, client


def test_the_totp_bot_defers_until_a_code_arrives(tmp_path):
    """Deferring is not declining. A decline is recorded on chain and wastes the
    request; the code has simply not been sent yet."""
    bot, store, _ = _totp_bot(tmp_path)
    store.enroll(A)
    assert bot.decide(_request()) is None


def test_a_valid_code_makes_the_bot_approve(tmp_path):
    bot, store, _ = _totp_bot(tmp_path)
    secret = store.enroll(A)
    request = _request()
    bot.decide(request)                       # registers it as pending
    ok, detail = bot.submit_code(request["request_id"], totp_mod.totp_at(
        secret, int(__import__("time").time())))
    assert ok, detail
    assert bot.decide(request) == (True, "valid TOTP received")


def test_a_code_is_one_time_use_across_requests(tmp_path):
    """Bound to (sender, time step), so a code seen once cannot be replayed onto
    a second request inside its own validity window."""
    import time as _time

    bot, store, _ = _totp_bot(tmp_path)
    secret = store.enroll(A)
    first, second = _request("ab" * 32), _request("cd" * 32)
    bot.decide(first)
    bot.decide(second)
    code = totp_mod.totp_at(secret, int(_time.time()))
    assert bot.submit_code(first["request_id"], code)[0] is True
    ok, detail = bot.submit_code(second["request_id"], code)
    assert ok is False and "already used" in detail


def test_an_unenrolled_sender_is_refused(tmp_path):
    bot, _store, _ = _totp_bot(tmp_path)
    request = _request()
    bot.decide(request)
    ok, detail = bot.submit_code(request["request_id"], "000000")
    assert ok is False and "not enrolled" in detail


def test_a_code_for_an_unknown_request_is_refused(tmp_path):
    bot, store, _ = _totp_bot(tmp_path)
    store.enroll(A)
    ok, detail = bot.submit_code("ff" * 32, "000000")
    assert ok is False and "no such request" in detail


def test_an_onchain_code_is_ignored_unless_opted_in(tmp_path):
    """A code in a custom input is PUBLIC for its whole validity window, so
    accepting one is opt-in."""
    import time as _time

    bot, store, _ = _totp_bot(tmp_path)
    secret = store.enroll(A)
    code = totp_mod.totp_at(secret, int(_time.time()))
    request = _request(customs={"26": code})
    assert bot.decide(request) is None

    opted_in, store2, _ = _totp_bot(tmp_path, accept_onchain_code=True)
    store2.enroll(A)
    code2 = totp_mod.totp_at(store2.secret_for(A), int(_time.time()))
    approve, reason = opted_in.decide(_request(customs={"26": code2}))
    assert approve is True and "public" in reason


# --- the scan bot ------------------------------------------------------------

class _Index:
    def __init__(self, history=None):
        self._history = history or {}

    def refresh(self):
        pass

    def history(self, sender):
        return self._history.get((sender or "").lower(), [])


def _scan_bot(index, **kwargs):
    return scan_mod.ScanBot(_FakeClient(), _FakeSigner(), index=index, **kwargs)


def test_a_familiar_recipient_and_ordinary_amount_passes():
    index = _Index({A: [(1, B, 100), (10, B, 120), (25, B, 90)]})
    approve, reason = _scan_bot(index).decide(_request(amount=110))
    assert approve is True and reason == "no anomaly found"


def test_a_never_seen_recipient_is_flagged():
    index = _Index({A: [(1, "cc" * 48, 100), (2, "cc" * 48, 100)]})
    approve, reason = _scan_bot(index).decide(_request(amount=100))
    assert approve is False and "never received" in reason


def test_an_amount_far_above_the_median_is_flagged():
    index = _Index({A: [(1, B, 100), (10, B, 100), (25, B, 100)]})
    approve, reason = _scan_bot(index).decide(_request(amount=5000))
    assert approve is False and "median" in reason


def test_a_sender_with_no_history_is_flagged():
    approve, reason = _scan_bot(_Index()).decide(_request())
    assert approve is False and "no confirmed history" in reason


def test_a_burst_of_transfers_is_flagged():
    """Three inside three blocks. NOT merely two adjacent ones -- any active
    account does that routinely, and flagging it would refuse normal traffic."""
    index = _Index({A: [(8, B, 100), (9, B, 100), (10, B, 100)]})
    approve, reason = _scan_bot(index).decide(_request(amount=100))
    assert approve is False and "drain in progress" in reason


def test_ordinary_adjacent_activity_is_not_flagged():
    index = _Index({A: [(1, B, 100), (2, B, 110), (30, B, 90)]})
    approve, _reason = _scan_bot(index).decide(_request(amount=100))
    assert approve is True


def test_the_denylist_and_ceiling_are_absolute():
    index = _Index({A: [(1, B, 100), (10, B, 120), (25, B, 90)]})
    approve, reason = _scan_bot(index, denylist=[B]).decide(_request(amount=100))
    assert approve is False and "denylist" in reason
    approve, reason = _scan_bot(index, max_amount=50).decide(_request(amount=100))
    assert approve is False and "ceiling" in reason


def test_the_model_is_a_veto_not_an_authority(monkeypatch):
    """Heuristics run first; the model can only turn a pass into a refusal."""
    index = _Index({A: [(1, B, 100), (10, B, 120), (25, B, 90)]})
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    approve, reason = _scan_bot(index, use_llm=True).decide(_request(amount=110))
    assert approve is False and "ANTHROPIC_API_KEY" in reason


def test_a_model_error_refuses_rather_than_passing(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    findings = scan_mod.llm_findings(_request(), _Index(), "claude-opus-5")
    assert findings, "an unusable model must not read as approval"


# --- the partner bot ---------------------------------------------------------

def _partner(**kwargs):
    return partner_mod.PartnerBot(_FakeClient(), _FakeSigner(), **kwargs)


def test_the_partner_defers_when_there_is_no_terminal(monkeypatch, capsys):
    """Never guess on someone else's behalf: the request stays open for a human."""
    monkeypatch.setattr(partner_mod.sys, "stdin", None)
    assert _partner().decide(_request()) is None


def test_a_standing_limit_approves_small_amounts():
    approve, reason = _partner(auto_below=10000).decide(_request(amount=5000))
    assert approve is True and "standing limit" in reason


def test_a_standing_limit_does_not_cover_larger_amounts(monkeypatch):
    monkeypatch.setattr(partner_mod.sys, "stdin", None)
    assert _partner(auto_below=1000).decide(_request(amount=5000)) is None


def test_the_summary_shows_the_senders_message(capsys):
    """The comment field is the reason a human approver is in the loop."""
    _partner(assume_yes=True).decide(_request(customs={"26": "rent for Q3"}))
    assert "rent for Q3" in capsys.readouterr().out


# --- the shared client -------------------------------------------------------

def test_a_bot_only_acts_on_slots_still_awaiting_it():
    client = _FakeClient([_request(state="approved")])
    bot = scan_mod.ScanBot(client, _FakeSigner(), index=_Index())
    assert bot.tick() == 0
    assert client.submitted == []


def test_a_bot_ignores_requests_that_do_not_name_it():
    client = _FakeClient([_request(approver=SCAN)])
    bot = scan_mod.ScanBot(client, _FakeSigner(), index=_Index())
    assert bot.tick() == 0


def test_a_bot_does_not_vote_twice_on_one_request():
    client = _FakeClient([_request()])
    bot = scan_mod.ScanBot(client, _FakeSigner(), index=_Index())
    assert bot.tick() == 1
    assert bot.tick() == 0, "already acted; a second submit would just be noise"


def test_dry_run_never_submits():
    client = _FakeClient([_request()])
    bot = scan_mod.ScanBot(client, _FakeSigner(), index=_Index(), dry_run=True)
    bot.tick()
    assert client.submitted == []


def test_a_loose_key_file_is_refused(tmp_path):
    path = tmp_path / "bot.key"
    path.write_text("01" * 32)
    os.chmod(path, 0o644)

    class _Args:
        privkey_file = str(path)
        privkey = None

    with pytest.raises(SystemExit, match="must not be group- or world-readable"):
        common.load_privkey(_Args())

    os.chmod(path, 0o600)
    assert common.load_privkey(_Args()) == "01" * 32
