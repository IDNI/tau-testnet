"""Issue #42, third point: no fee for a unit the network drops.

The report: one account's o5 unit sat in the shared specification in total
form; a second account sent its own i12-guarded o5 unit, the engine found
nothing new in it, and the second account paid the fee for a rule that never
took effect.

This file pins why that cannot happen on this node:

1. An o5 unit never joins the shared specification. It is the sender's own
   clause, kept per account, so no account's o5 rule can make another's a
   no-op: each account holds its own, in the same block or in later ones.
2. The reported unit itself (an o5 rule behind `i12 = <pubkey>`) is refused at
   admission with CLAUSE_SHAPE and the way to fix it, before any fee. A block
   that carries it anyway rejects it at apply: no fee, no effect, nothing
   registered, the specification untouched.
3. The same policy without the guard lands as the sender's clause, and the
   transaction says so.

What is left of "accepted but nothing new" is an application rule the engine
already implies. It is reported as accepted and not taken, in the recorded
outcome (tests/test_tx_outcomes.py) and from the block's journal
(tests/test_rules_at_block.py), so a wallet never reads it as a change.
"""
import hashlib

import pytest

import tau_defs
from consensus.admission import validate_user_tx_reserved_domains
from consensus.facade import TipAdmissionView
from consensus.rule_offers import clause_body_v1

import test_approval_apply as ap

STREAM = tau_defs.USER_POLICY_STREAM_INDEX
FEE = 7
PARENT_SPEC = b"always (o0[t]=1)."

# The key the report's unit was guarded with.
REPORTED_KEY = ("957ce467628bf10d17ddd3eee177c1103779b08c154d3c825d7f9dd0780f3631"
                "418d2167ef71df20c6e77181ba7bdfca")


def reported_unit(key=REPORTED_KEY):
    """The unit of the report, character for character but for the key."""
    return ("always ((i12[t] = {#x" + key + "}:bv[384]) ? "
            "((i1[t] > { #x0000fa }:bv[24]) ? o5[t] = { #x0000 }:bv[16] : "
            "o5[t] = { #x0001 }:bv[16]) : o5[t] = { #x0001 }:bv[16])")


# The same policy as a clause: no more than 250 a transfer.
UNGUARDED = ("always ( (i1[t]:bv[24] > { #x0000fa }:bv[24]) "
             "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
             ": (o5[t]:bv[24] = { #x000001 }:bv[24]) ).")
# Another account's o5 rule in total form: it answers for every transfer.
TOTAL = "always ( (o5[t]:bv[24] = { #x000000 }:bv[24]) )."


def _admit(rule, sender=ap.ALICE):
    tx = {"sender_pubkey": sender, "operations": {"0": rule}}
    return validate_user_tx_reserved_domains(tx, TipAdmissionView())


def _apply(txs, lm=None, balances=None):
    funds = balances or {ap.ALICE: 1_000, ap.BOB: 1_000, ap.AUTH: 10, ap.SCAN: 10}
    result, post, _ = ap._apply(txs, lm=lm, balances=dict(funds), fee=FEE)
    rows = result.next_snapshot.metadata["tx_outcomes"]
    assert len(rows) == len(txs)
    return result, post, rows


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _bob(rule, seq=0):
    return ap.rule_tx(rule, sk=ap.SK_BOB, sender=ap.BOB, seq=seq)


# --- the reported unit ---------------------------------------------------------

@pytest.mark.parametrize("key", [REPORTED_KEY, ap.ALICE], ids=["reported-key", "own-key"])
def test_the_reported_unit_is_refused_at_admission_with_the_way_to_fix_it(key):
    verdict = _admit(reported_unit(key))
    assert not verdict.is_valid
    assert verdict.code == "CLAUSE_SHAPE"
    assert "must not reference i12" in verdict.error
    assert "UNGUARDED" in verdict.error


@pytest.mark.parametrize("key", [REPORTED_KEY, ap.ALICE], ids=["reported-key", "own-key"])
def test_a_block_that_carries_it_anyway_takes_no_fee_and_changes_nothing(key):
    tx = ap.rule_tx(reported_unit(key))
    result, post, (row,) = _apply([tx])
    assert row["status"] == "rejected" and row["reason"] == "rule_not_applied"
    assert row["fee_charged"] == 0
    assert "rule_effects" not in row
    assert any("must not reference i12" in line for line in row["logs"])
    assert tx["tx_id"] not in result.accepted_tx_ids
    assert dict(post.rule_offers.accepted_clauses) == {}
    assert result.next_snapshot.tau_bytes == PARENT_SPEC
    assert result.next_snapshot.metadata["balances"][ap.ALICE] == 1_000


def test_the_same_policy_without_the_guard_lands_as_the_senders_clause():
    verdict = _admit(UNGUARDED)
    assert verdict.is_valid, verdict.error
    assert verdict.data["o5_clause_action"] == "declare"

    tx = ap.rule_tx(UNGUARDED)
    result, post, (row,) = _apply([tx])
    body = post.rule_offers.clause_for(ap.ALICE, STREAM)
    assert row["status"] == "applied" and row["fee_charged"] == FEE
    assert row["rule_effects"] == [{
        "account": ap.ALICE, "kind": "clause", "stream": STREAM,
        "action": "registered", "sha256": _sha(body),
    }]
    # a clause, not a unit of the shared specification
    assert result.next_snapshot.tau_bytes == PARENT_SPEC


# --- another account's o5 rule takes nothing from mine ---------------------------

def test_two_accounts_each_keep_their_own_o5_rule_in_one_block():
    first, second = ap.rule_tx(TOTAL), _bob(UNGUARDED)
    result, post, rows = _apply([first, second])
    assert [row["status"] for row in rows] == ["applied", "applied"]
    assert [row["rule_effects"][0]["action"] for row in rows] == ["registered", "registered"]
    assert [row["rule_effects"][0]["account"] for row in rows] == [ap.ALICE, ap.BOB]
    mine = post.rule_offers.clause_for(ap.BOB, STREAM)
    theirs = post.rule_offers.clause_for(ap.ALICE, STREAM)
    assert mine and theirs and mine != theirs
    assert rows[1]["rule_effects"][0]["sha256"] == _sha(mine)
    assert result.next_snapshot.tau_bytes == PARENT_SPEC


def test_a_total_o5_rule_in_force_does_not_swallow_a_later_one():
    """The order of the report: the total-form rule is in force first."""
    _, lm, _ = _apply([ap.rule_tx(TOTAL)])
    theirs = lm.rule_offers.clause_for(ap.ALICE, STREAM)

    result, post, (row,) = _apply([_bob(UNGUARDED)], lm=lm)
    assert row["status"] == "applied" and row["fee_charged"] == FEE
    assert row["rule_effects"][0]["action"] == "registered"
    assert post.rule_offers.clause_for(ap.BOB, STREAM) == clause_body_v1(UNGUARDED)
    assert post.rule_offers.clause_for(ap.ALICE, STREAM) == theirs
    assert result.next_snapshot.tau_bytes == PARENT_SPEC


def test_the_same_text_from_two_accounts_is_two_clauses():
    """Even the identical rule is not "already there": each account's copy is
    its own, and each pays for a change that took effect."""
    result, post, rows = _apply([ap.rule_tx(UNGUARDED), _bob(UNGUARDED)])
    assert [(row["status"], row["fee_charged"]) for row in rows] == [("applied", FEE)] * 2
    assert post.rule_offers.clause_for(ap.ALICE, STREAM) == \
        post.rule_offers.clause_for(ap.BOB, STREAM)
    assert sorted(post.rule_offers.accepted_clauses) == sorted(
        [(ap.ALICE, STREAM), (ap.BOB, STREAM)])


def test_the_reported_unit_beside_a_good_one_costs_only_the_good_one():
    bad, good = ap.rule_tx(reported_unit(ap.ALICE)), _bob(UNGUARDED)
    result, post, rows = _apply([bad, good])
    assert [(row["status"], row["fee_charged"]) for row in rows] == [
        ("rejected", 0), ("applied", FEE)]
    balances = result.next_snapshot.metadata["balances"]
    # Alice proposes the block: she paid nothing and receives the one fee paid.
    assert balances[ap.BOB] == 1_000 - FEE and balances[ap.ALICE] == 1_000 + FEE
    assert sorted(post.rule_offers.accepted_clauses) == [(ap.BOB, STREAM)]
