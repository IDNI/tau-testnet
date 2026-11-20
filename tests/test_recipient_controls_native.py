"""Recipient controls against the REAL native Tau engine (no mock).

Issues #47/#76. The apply-side tests in test_recipient_controls.py prove
the gate with a scripted o5; these prove the guarded-mode second pass is
evaluated by the real engine: the recipient's guarded unit is pre-deployed
(the plan's spec is built from it as a candidate rule and the snapshot's
application-rules text is the unit itself), and the transfer is applied
through engine.apply with a real WorkerSession spawned from the router
(genesis.tau + o9 fee). No communicate_with_tau* patching anywhere: the
o5 verdicts below come out of the native interpreter.

A guarded unit cannot be deployed by a rule tx inside the block:
operations {"0"} routes o5 rules to the clause registry, which rejects
i12 guards ("a clause is evaluated only for its owner, so it must not
carry a sender guard") -- and a rule offer is screened the same way, so
an offer cannot deploy one either. The only deployment path for a
guarded unit in this codebase is genesis seeding (the unit is baked
into the genesis application_rules). What the real engine proves here
is the VERDICT of an already-deployed guarded unit.

One guarded unit per recipient: the allowlist and the hold cap combine
by NESTING into a single unit (COMBINED_UNIT). Two separate guarded
units for one recipient do NOT combine -- each `always` revision of o5
supersedes the previous one, so the last-applied unit's verdict wins
and the earlier policy is silently masked (test_native_two_separate_
guarded_units_last_wins below pins this). That is what the first
two-live-node run hit: an allowlist unit plus a cap unit seeded at
genesis, cap applied last, so the allowlist never refused anything.

Skipped when the native module is not built (same gate as
test_apply_block_abcd_native.py).
"""
import os

import pytest
from unittest.mock import MagicMock

import tau_allocator as alloc
import tau_guard
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session as ts
from bls_keys import sign_payload
from consensus.engine import TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from test_recipient_controls import (
    ALLOWLIST_UNIT,
    CAP600_UNIT,
    COMBINED_UNIT,
    RECIPIENT,
    SENDER,
    STRANGER,
)
import test_approval_apply as ap

TS = 1234567890

# The recipient allows only STRANGER; ALICE is not allowlisted. Same shape
# as ALLOWLIST_UNIT, with the allowlisted sender swapped.
STRANGER_ONLY_UNIT = (
    "always ((i12[t]:bv[384] = { #x" + RECIPIENT + " }:bv[384]) ? "
    "((i3[t]:bv[384] = { #x" + STRANGER + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24])) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]))."
)


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(),
                                reason="native tau module not built")


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A_KEY = ap.ALICE
B_KEY = ap.BOB
S_KEY = ap.STRANGER
_SK = {A_KEY: ap.SK_ALICE, B_KEY: ap.SK_BOB, S_KEY: ap.SK_STRANGER}
PROPOSER = "d4" * 48
BALANCES = {A_KEY: 5000, B_KEY: 5000, S_KEY: 5000}


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} && (o9[t]:bv[24] = {{ #x000007 }}:bv[24]) )."


def _lifecycle():
    lm = ConsensusLifecycleManager(active_validators=[A_KEY])
    lm.approval_slots_active = True
    return lm


def _proposal(lifecycle, units):
    # The guarded unit(s) are candidate rules so the plan's representation
    # knows the streams they use (i12/i3/i17/i3/o5). They are DEPLOYED into
    # the worker's evaluator here, the way rules that landed in an earlier
    # block (or at genesis) would be: the session's spec is the router plus
    # every rule applied to it, and the plan alone does not compile rules
    # into the spec. (A guarded unit cannot be deployed by a rule tx in THIS
    # block: operations {"0"} routes o5 rules to the clause registry, which
    # rejects i12 guards.) The snapshot's application-rules text carries the
    # same units, so the gate's scan and the session's spec agree --
    # exactly the post-deployment state on a live node.
    plan = tr.plan_representation(candidate_rules=list(units))
    snapshot = alloc.DbMappingSnapshot()

    def rebuild(proposal_journal, current_plan):
        session = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env(),
                                         plan=current_plan)
        session.begin_proposal(alloc.Allocator(snapshot, width=current_plan.width))
        for entry in proposal_journal.entries():
            if entry.kind == tj.REVISION:
                session.apply_rule(entry.rule_text, record=False,
                                   accumulate=entry.accumulate)
            else:
                session.evaluate(entry.inputs, multi=True, record=False)
        return session

    session = rebuild(tj.Journal(authoritative=False), plan)
    ctx = tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=plan.width, label="proposal"),
        plan=plan, rebuild=rebuild, lifecycle=lifecycle,
    )
    # Apply the units AFTER the ProposalContext is built: its __init__
    # rebinds session.allocation to the context's own allocator
    # (_bind_session), so units applied before that are interned under a
    # discarded overlay -- and the inputs, encoded under the bound
    # allocator, re-assign the same ids to different values (ALICE
    # collides with STRANGER's id 1) and the gate reads the wrong verdict.
    # Applying here interns the rules under the allocator the evaluations
    # will use, so rule literals and input values share one mapping.
    # Order matters: each `always` revision of o5 supersedes the previous
    # one, so the LAST unit applied wins the o5 verdict.
    for unit in units:
        ctx.session.apply_rule(unit, record=False, accumulate=True)
    return ctx


def _transfer_tx(tx_id, sender, recipient, amount, seq=0):
    tx = {"tx_id": tx_id, "tx_type": "user_tx", "sender_pubkey": sender,
          "sequence_number": seq, "expiration_time": 9999999999,
          "expire_at_height": 5000, "fee_limit": "100",
          "operations": {"1": [[sender, recipient, str(amount)]]}}
    return sign_payload(tx, _SK[sender])


def _park_tx(tx_id, sender, recipient, amount, seq=0, release_at_time=None,
             release_at_height=None):
    tx = {"tx_id": tx_id, "tx_type": "retractable_transfer",
          "sender_pubkey": sender, "sequence_number": seq,
          "expiration_time": 9999999999, "expire_at_height": 5000,
          "fee_limit": "100", "recipient_pubkey": recipient, "amount": amount,
          "release_at_time": release_at_time,
          "release_at_height": release_at_height}
    return sign_payload(tx, _SK[sender])


def _run(transactions, unit_or_units):
    units = (unit_or_units if isinstance(unit_or_units, (list, tuple))
             else [unit_or_units])
    lifecycle = _lifecycle()
    proposal = _proposal(lifecycle, units)
    engine = TauConsensusEngine(state_store=MagicMock())
    balances = dict(BALANCES)
    sequences = {}
    transfer_ts = {}
    watcher = tau_guard.ProposalIsolationGuard(strict=False)
    with watcher:
        result = engine.apply(
            # The unit(s) are ALREADY DEPLOYED here: their text is the
            # application-rules state (so the gate's scan finds the
            # recipient's key), and the plan's spec was built from them as
            # candidate rules. A guarded unit cannot be deployed by a rule
            # tx: operations {"0"} routes o5 rules to the clause registry,
            # which rejects i12 guards ("a clause is evaluated only for
            # its owner, so it must not carry a sender guard"), and a rule
            # offer is screened the same way -- so the only deployment path
            # for a guarded unit is genesis seeding. What the real engine
            # proves here is the VERDICT of an already-deployed guarded
            # unit, in both passes.
            TauStateSnapshot(b"hash", "\n".join(units).encode("utf-8"), {}),
            transactions, TS,
            target_balances=balances,
            target_sequences=sequences,
            target_last_transfer_ts=transfer_ts,
            target_lifecycle=lifecycle,
            proposer_pubkey=PROPOSER,
            block_height=1,
            proposal=proposal,
            session=proposal.session,
        )
    if proposal.dirty:
        proposal.reconstruct()
    return proposal, result, balances, lifecycle, watcher


def _accepted(result):
    return [t["tx_id"] for t in result.accepted_transactions]


def _rejected(result):
    return [t["tx_id"] for t in result.rejected_transactions]


def test_native_guarded_allowlist_blocks_unknown_sender(temp_database):
    tx = _transfer_tx("T", SENDER, RECIPIENT, 100)
    proposal, result, balances, lifecycle, watcher = _run([tx], STRANGER_ONLY_UNIT)
    assert _accepted(result) == [], result.receipts
    assert _rejected(result) == ["T"], result.receipts
    assert result.receipts["T"]["reason"] == "recipient_policy_block"
    # The gate scanned this text, and the real session evaluated it in the
    # second pass (i12 = recipient) before refusing.
    assert STRANGER_ONLY_UNIT in proposal.state.get("application_rules", "")
    # Nothing moved and nothing was charged: the sender keeps everything.
    assert balances[SENDER] == 5000
    assert balances[RECIPIENT] == 5000


def test_native_guarded_allowlist_allows_known_sender(temp_database):
    tx = _transfer_tx("T", SENDER, RECIPIENT, 100)
    proposal, result, balances, lifecycle, watcher = _run([tx], ALLOWLIST_UNIT)
    assert _accepted(result) == ["T"], result.receipts
    assert _rejected(result) == []
    assert ALLOWLIST_UNIT in proposal.state.get("application_rules", "")
    assert balances[RECIPIENT] == 5100
    assert balances[SENDER] == (
        5000 - 100 - result.receipts["T"]["fee_charged"])


def test_native_guarded_cap_blocks_long_park(temp_database):
    tx = _park_tx("P", SENDER, RECIPIENT, 100, release_at_time=TS + 3600)
    proposal, result, balances, lifecycle, watcher = _run([tx], CAP600_UNIT)
    assert _accepted(result) == [], result.receipts
    assert _rejected(result) == ["P"], result.receipts
    assert result.receipts["P"]["reason"] == "recipient_max_hold"
    assert lifecycle.retractable_transfers.open == {}
    assert CAP600_UNIT in proposal.state.get("application_rules", "")
    assert balances[SENDER] == 5000
    assert balances[RECIPIENT] == 5000


def test_native_guarded_cap_allows_short_park(temp_database):
    tx = _park_tx("P", SENDER, RECIPIENT, 100, release_at_time=TS + 600)
    proposal, result, balances, lifecycle, watcher = _run([tx], CAP600_UNIT)
    assert _accepted(result) == ["P"], result.receipts
    assert _rejected(result) == []
    assert len(lifecycle.retractable_transfers.open) == 1
    # The park is escrowed: the sender is debited, the recipient is not
    # credited until release.
    assert balances[SENDER] == (
        5000 - 100 - result.receipts["P"]["fee_charged"])
    assert balances[RECIPIENT] == 5000


# --- one combined unit: allowlist + cap nested -------------------------------
#
# The only way to have both policies for one recipient. The docs say "the
# two combine by nesting"; these tests prove the nested unit enforces BOTH
# refusals on the real engine, and the last-wins test below proves why two
# separate units cannot.


def test_native_combined_unit_blocks_unknown_sender(temp_database):
    tx = _transfer_tx("T", STRANGER, RECIPIENT, 100)
    proposal, result, balances, lifecycle, watcher = _run([tx], COMBINED_UNIT)
    assert _accepted(result) == [], result.receipts
    assert _rejected(result) == ["T"], result.receipts
    assert result.receipts["T"]["reason"] == "recipient_policy_block"
    assert COMBINED_UNIT in proposal.state.get("application_rules", "")
    assert balances[STRANGER] == 5000
    assert balances[RECIPIENT] == 5000


def test_native_combined_unit_allows_known_sender(temp_database):
    tx = _transfer_tx("T", SENDER, RECIPIENT, 100)
    proposal, result, balances, lifecycle, watcher = _run([tx], COMBINED_UNIT)
    assert _accepted(result) == ["T"], result.receipts
    assert _rejected(result) == []
    assert balances[RECIPIENT] == 5100
    assert balances[SENDER] == (
        5000 - 100 - result.receipts["T"]["fee_charged"])


def test_native_combined_unit_blocks_long_park_for_known_sender(temp_database):
    tx = _park_tx("P", SENDER, RECIPIENT, 100, release_at_time=TS + 3600)
    proposal, result, balances, lifecycle, watcher = _run([tx], COMBINED_UNIT)
    assert _accepted(result) == [], result.receipts
    assert _rejected(result) == ["P"], result.receipts
    assert result.receipts["P"]["reason"] == "recipient_max_hold"
    assert lifecycle.retractable_transfers.open == {}
    assert balances[SENDER] == 5000
    assert balances[RECIPIENT] == 5000


def test_native_combined_unit_allows_short_park_for_known_sender(temp_database):
    tx = _park_tx("P", SENDER, RECIPIENT, 100, release_at_time=TS + 600)
    proposal, result, balances, lifecycle, watcher = _run([tx], COMBINED_UNIT)
    assert _accepted(result) == ["P"], result.receipts
    assert _rejected(result) == []
    assert len(lifecycle.retractable_transfers.open) == 1
    assert balances[SENDER] == (
        5000 - 100 - result.receipts["P"]["fee_charged"])
    assert balances[RECIPIENT] == 5000


def test_native_two_separate_guarded_units_last_wins(temp_database):
    """Two separate guarded units for one recipient do NOT combine.

    Each `always` revision of o5 supersedes the previous one, so the
    LAST-applied unit's verdict wins and the earlier policy is silently
    masked. This is what the first two-live-node run hit: an allowlist
    unit plus a cap unit seeded at genesis, cap applied last, so a
    Stranger transfer was accepted even though the allowlist refused it.
    Deploy ONE combined unit (COMBINED_UNIT) instead -- never two.
    """
    # Allowlist first, cap last (the genesis order of the first live run):
    # the cap masks the allowlist, so the unknown sender is accepted.
    tx = _transfer_tx("T", STRANGER, RECIPIENT, 100)
    _, result, _, _, _ = _run([tx], [ALLOWLIST_UNIT, CAP600_UNIT])
    assert _accepted(result) == ["T"], result.receipts
    assert _rejected(result) == []
    # Reversed: the allowlist masks the cap, so the long park is accepted.
    park = _park_tx("P", SENDER, RECIPIENT, 100, release_at_time=TS + 3600)
    _, result, _, _, _ = _run([park], [CAP600_UNIT, ALLOWLIST_UNIT])
    assert _accepted(result) == ["P"], result.receipts
    assert _rejected(result) == []
