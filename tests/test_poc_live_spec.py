"""Apply must judge a block against the rules that block's parent carried,
not against whatever spec the process loaded last.

`consensus/engine.py` used to pass `spec_text=tau_manager.last_known_tau_spec`
into the guarded recipient pass. That global is the interpreter's CURRENT
spec (tau_manager.py calls it "a debug/error-state aid"), and nothing pinned
it to the block under apply: re-applying block N after the tip advanced to
block N+k judged N against N+k's rules. Replay then diverged from the
original application, which issue #47 forbids.

`recipient_policy.resolve_spec_text(snapshot)` pins the source to the state
being applied. The proof holds without the native engine: the same values
must reach the same verdict however far the live global has moved on.
"""
import types

import tau_defs
import tau_manager
from bls_keys import SK_ALICE, SK_CAROL, pubkey_hex
from consensus import recipient_policy

ALICE = pubkey_hex(SK_ALICE)
CAROL = pubkey_hex(SK_CAROL)

SPEC_WITH_CAROL = (
    "always ( (i12[t]:bv[384] = { #x" + CAROL + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
# A later block removed CAROL's unit: no occurrence of her key at all.
SPEC_WITHOUT_CAROL = (
    "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
)


def _values(sender, recipient, amount):
    return {1: str(amount), 3: "#x" + sender + ":bv[384]", 4: "#x" + recipient + ":bv[384]"}


def _step_blocking(values):
    """Stand-in for admission/apply stepping the accumulated spec."""
    return {tau_defs.USER_POLICY_STREAM_INDEX: "0"}  # block


def _snapshot(text):
    """Just the attribute `resolve_spec_text` reads off a snapshot."""
    return types.SimpleNamespace(tau_bytes=text.encode())


def test_snapshot_beats_the_live_global():
    original = tau_manager.last_known_tau_spec
    try:
        tau_manager.last_known_tau_spec = SPEC_WITHOUT_CAROL
        pinned = recipient_policy.resolve_spec_text(_snapshot(SPEC_WITH_CAROL))
    finally:
        tau_manager.last_known_tau_spec = original
    assert pinned == SPEC_WITH_CAROL


def test_same_block_same_verdict_however_the_global_moved():
    """The regression itself: moving the global must not move the verdict."""
    block = _snapshot(SPEC_WITH_CAROL)
    original = tau_manager.last_known_tau_spec
    verdicts = []
    try:
        # applied while the tip still matches the block ...
        tau_manager.last_known_tau_spec = SPEC_WITH_CAROL
        verdicts.append(recipient_policy.guarded_recipient_blocks(
            _step_blocking, _values(ALICE, CAROL, 100), ALICE, CAROL,
            spec_text=recipient_policy.resolve_spec_text(block)))
        # ... and replayed after the chain moved on past it.
        tau_manager.last_known_tau_spec = SPEC_WITHOUT_CAROL
        verdicts.append(recipient_policy.guarded_recipient_blocks(
            _step_blocking, _values(ALICE, CAROL, 100), ALICE, CAROL,
            spec_text=recipient_policy.resolve_spec_text(block)))
    finally:
        tau_manager.last_known_tau_spec = original

    assert verdicts[0][0] is True
    assert verdicts[1] == verdicts[0], "replay diverged from the original apply"


def test_falls_back_to_the_live_global_without_a_snapshot():
    """Admission's tip view and tests have no snapshot; the fallback stays."""
    original = tau_manager.last_known_tau_spec
    try:
        tau_manager.last_known_tau_spec = SPEC_WITH_CAROL
        assert recipient_policy.resolve_spec_text(None) == SPEC_WITH_CAROL
    finally:
        tau_manager.last_known_tau_spec = original
