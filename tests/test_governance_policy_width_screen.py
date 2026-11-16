"""A consensus revision must type every o5/o8 mention bv[24], at admission and at apply.

Stream typing is process-global and sticky, so a revision typing the shared
policy or custom-fee stream at another width would pin the shared interpreter
to it for every rule that mentions the stream afterwards.
"""
import pytest

from consensus.admission import (
    revision_policy_width_error,
    validate_consensus_rule_update_payload,
)
from test_temporal_rule_screen import (  # noqa: F401  (fixture and harness)
    ALICE,
    _apply,
    _lifecycle,
    _outcome,
    _update_tx,
    tip_view,
)

BV24_BOTH = (
    "always ( o5[t]:bv[24] = { #x000001 }:bv[24] && "
    "o8[t]:bv[24] = { #x000000 }:bv[24] )."
)
NEITHER = "always ( o6[t]:bv[16] = i10[t]:bv[16] )."

REFUSED = [
    ("o5_bv16", "always ( o5[t]:bv[16] = { #x0001 }:bv[16] ).", "o5", "bv[16]"),
    ("o8_bv16", "always ( o8[t]:bv[16] = { #x0001 }:bv[16] ).", "o8", "bv[16]"),
    ("o5_untyped", "always ( o5[t] = i1[t]:bv[24] ).", "o5", "bv[24]"),
    ("o5_bare_literal", "always ( o5[t]:bv[24] = 1 ).", "o5", "bv[24]"),
    ("o5_literal_bv16", "always ( o5[t]:bv[24] = { #x0001 }:bv[16] ).", "o5", "bv[24]"),
]


def _payload(revisions, tip_view):
    return {
        "tx_type": "consensus_rule_update",
        "sender_pubkey": ALICE,
        "rule_revisions": list(revisions),
        "activate_at_height": tip_view.next_block_height + 10,
    }


def _admit(revisions, tip_view):
    tip_view.get_update_lifecycle_state.return_value = None
    return validate_consensus_rule_update_payload(_payload(revisions, tip_view), tip_view)


@pytest.mark.parametrize("name,text,stream,width", REFUSED, ids=[r[0] for r in REFUSED])
def test_admission_refuses_a_revision_mistyping_a_policy_stream(tip_view, name, text, stream, width):
    result = _admit([text], tip_view)
    assert not result.is_valid
    assert result.code == "WIDTH_MISMATCH"
    assert stream in result.error and width in result.error


def test_admission_refuses_when_any_revision_of_several_mistypes(tip_view):
    result = _admit([NEITHER, REFUSED[0][1]], tip_view)
    assert not result.is_valid
    assert result.code == "WIDTH_MISMATCH"


def test_admission_reports_the_stream_and_found_width_as_details(tip_view):
    result = _admit([REFUSED[0][1]], tip_view)
    assert result.details == {"stream": "o5", "expected": 24, "found": 16}


@pytest.mark.parametrize("text", [BV24_BOTH, NEITHER])
def test_admission_keeps_a_correctly_typed_or_unrelated_revision(tip_view, text):
    result = _admit([text], tip_view)
    assert result.is_valid, result.error


def test_a_stream_named_only_in_a_comment_is_not_a_mistyping():
    assert revision_policy_width_error(["# o5 stays bv[16]\n" + NEITHER]) is None


def test_typed_and_unrelated_revisions_pass_the_screen_together():
    assert revision_policy_width_error([BV24_BOTH, NEITHER]) is None


@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("name,text,stream,width", REFUSED, ids=[r[0] for r in REFUSED])
def test_apply_does_not_record_a_revision_mistyping_a_policy_stream(
        name, text, stream, width, replay_mode):
    result, post, _ = _apply(_update_tx(text), _lifecycle(slots=False),
                             replay_mode=replay_mode)
    assert "update" not in result.invalid_tx_ids
    logs = " | ".join(str(x) for x in _outcome(result, "update").receipt_logs)
    assert stream in logs and width in logs
    assert post.pending_updates == set()
    assert post.update_payloads == {}


@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("text", [BV24_BOTH, NEITHER])
def test_apply_records_a_correctly_typed_or_unrelated_revision(text, replay_mode):
    result, post, _ = _apply(_update_tx(text), _lifecycle(slots=False),
                             replay_mode=replay_mode)
    assert "update" not in result.invalid_tx_ids
    assert len(post.pending_updates) == 1
