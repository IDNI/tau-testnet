"""Wire compatibility, recipient-only stream typing and rule-change guards."""
import json

import pytest

import tau_defs
from consensus import recipient_policy
from consensus.rule_offers import RuleOfferShapeError, clause_body_v1, clause_output_streams


def prepare(payload, *, prior=None, operations=None, active=True):
    text = recipient_policy.PREFIX + payload

    def clause_for(owner, index):
        if index == tau_defs.RECIPIENT_POLICY_INDEX and prior:
            return json.dumps(prior, sort_keys=True, separators=(",", ":"))
        return None

    return recipient_policy.prepare(text, operations or {"0": text}, "owner", clause_for,
                                    active=active)


def verdict(test):
    return f"always (({test}) ? (o5[t]:bv[24] = {{1}}:bv[24]) : (o5[t]:bv[24] = {{0}}:bv[24]))."


def test_unupgraded_node_routes_and_refuses_even_a_cap_only_unit():
    # Exactly the two pre-existing routing decisions. In particular the node
    # cannot admit this as arbitrary Tau text, even when compilation is mocked.
    text = recipient_policy.PREFIX + '{"max_hold_seconds":0}'
    assert clause_output_streams(text) == [tau_defs.USER_POLICY_STREAM_INDEX]
    with pytest.raises(RuleOfferShapeError, match="exactly one"):
        clause_body_v1(text)
    with pytest.raises(recipient_policy.PolicyError) as exc:
        prepare('{"max_hold_seconds":0}', active=False)
    assert exc.value.code == "FEATURE_INACTIVE"


@pytest.mark.parametrize("payload", [
    "[]", "null", '{"cap":12}', '{"inbound":123}', '{"inbound":"\\ud800"}',
    '{"max_hold_seconds":-1}', '{"max_hold_blocks":true}', '{"max_hold_blocks":0.5}',
    '{"max_hold_seconds":18446744073709551616}', '{"max_hold_blocks":1,"max_hold_blocks":0}',
    '{"max_hold_seconds":' + "1" * 5000 + '}',
    '{"inbound":"' + "x" * 8200 + '"}',
])
def test_invalid_wire_fields_refused(payload):
    with pytest.raises(recipient_policy.PolicyError):
        prepare(payload)


@pytest.mark.parametrize("stream", [
    "i17[t]", "i17[t]:bv[32]", "i28[t]", "i28[t]:bv[64]", "i017[t]:bv[64]",
    "i3[t-1]:bv[384]", "i3[t]:bv[24]", "i2[t]:bv[24]", "i12[t]:bv[8]",
])
def test_every_inbound_input_must_have_documented_type(stream):
    unit = verdict(f"{stream} = {{0}}:bv[64]")
    with pytest.raises(recipient_policy.PolicyError):
        prepare(json.dumps({"inbound": unit}))


def test_owner_guard_can_read_the_wallet_and_counterparty(monkeypatch):
    rule = verdict("i3[t]:bv[384] = i12[t]:bv[384]")
    update = prepare(json.dumps({"inbound": rule}))
    raw = update.changes[tau_defs.RECIPIENT_POLICY_INDEX]
    observations = []

    def evaluate(body, values, **kwargs):
        observations.append((body, values, kwargs["pool"]))
        return False, ""

    monkeypatch.setattr(recipient_policy.sender_policy, "clause_blocks", evaluate)
    result = recipient_policy.check_recipient(
        lambda *args: raw, "recipient", {1: "5", 3: "sender", 4: "recipient", 12: "sender",
                                         17: "9999", 27: "999"},
        pool="apply", timestamp=80, height=4, release_at_time=85,
    )
    assert result is None
    body, values, pool = observations[0]
    assert "i12" in body
    assert pool == "recipient-apply"
    assert (values[3], values[12]) == ("sender", "recipient")
    assert (values[17], values[27]) == ("5", "0")
    # The same unaltered sender grammar still refuses a guarded outbound unit.
    with pytest.raises(recipient_policy.PolicyError):
        prepare(json.dumps({"outbound": rule}))


def test_guard_sees_cap_loosening_as_a_revocation():
    prior = {"max_hold_seconds": 300}
    revoke = tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY
    assert revoke in prepare('{"max_hold_seconds":301}', prior=prior).guard_kinds()
    assert revoke in prepare('{"max_hold_seconds":300,"max_hold_blocks":1}', prior=prior).guard_kinds()
    assert revoke in prepare("{}", prior=prior).guard_kinds()
    assert revoke not in prepare('{"max_hold_seconds":299}', prior=prior).guard_kinds()
