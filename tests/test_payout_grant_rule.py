"""Conditional grants as a rule pattern: one rule + one o5 + one guard (#178).

There is no grant code in the node any more. A conditional grant is one
payout rule installed on a dedicated escrow account (CAROL here), one `o5`
clause locking signed transfers before the deadline, and one guard requiring
the grantee's co-signature for rule changes -- all existing machinery.
gmikeyg's case 5 on #34 is the worked example: 5,000 granted, 500 a week
from December 1, 3,800 refunded at the deadline. Every scenario runs through
the real `apply_block` with a scripted interpreter and mock policy
evaluators, and compares the FULL balance map against an oracle that only
knows the documented rules:

  * installing moves no money: the grantor funds the escrow account first,
    and the rule pays out of its spendable balance, never out of a held
    balance the node tracks;
  * weekly pacing comes from the `i49` gate in the clause, not from a cap:
    a manual draw too soon after the last paid run is refused, and a due
    point pays once (a manual draw in a point's window leaves its due run
    paying nothing);
  * at the deadline the rule's refund branch pays the remainder to the
    grantor as an ordinary settled execution -- it counts toward a shared
    cap like any other run -- and the rule ends;
  * revoking ends the rule with NO automatic refund: the remainder stays in
    the escrow account, locked by the `o5` until the deadline, and the
    guard gates the revoke itself;
  * a grant rule updates like any rule, through the guard's co-signature.

CAVEAT: the clause semantics are supplied by a scripted
MockPolicyEvaluator standing in for the native engine (which is unavailable
in this environment -- the libp2p tree is incomplete). What this proves:
terms shape, due schedule, cap windows, refund arithmetic, termination,
the `o5` lock and the guard gating. What it does NOT prove: the native
engine's interpretation of the nested ternary text (the shape screen
accepting it is proven by test_grant_rule_shape_screen_accepts_the_clause;
only the native engine can prove it evaluates it).
"""
import pytest

import tau_defs
from py_ecc.bls import G2Basic
from consensus import sender_policy
from consensus.admission import _screen_clause_domains
from consensus.approvals import STATUS_EXECUTED, screen_policy_widths
from consensus.payout import (
    PayoutBook,
    parse_payout_rule_set,
    parse_payout_rule_update,
    payout_rule_body,
    screen_payout_body,
    validate_terms_shape,
)

from consensus.policy_mock import MockPolicyEvaluator

from test_payout_guard import _parked as _guard_parked, spec as _guard_spec
from test_rule_change_release import LATE, _vote
from test_rule_change_requests import (
    ALICE as GUARD_ALICE,
    BOB as GUARD_BOB,
    GUARD_BODY,
    _request as _mk_request,
    _tx as _mk_tx,
)
from tests.chain_harness import (
    ALICE, BOB, CAROL, FAR, HEIGHT, PROPOSER, SKS, TS, Chain, Oracle, _logs, _sign,
)

TS0 = TS
WEEK, RATE, TOTAL = 3600, 500, 5000
D0 = TS0 + WEEK
DL = D0 + 3 * WEEK
DAVE = G2Basic.SkToPk(77777).hex()

_N = iter(range(10**9))


def grant_rule(total=TOTAL, rate=RATE, d0=D0, dl=DL):
    """The case-5 rule text: refund branch, weekly gate, manual/due/zero."""
    def c(x):
        return "{%d}:bv[64]" % x

    def m(x):
        return "{%d}:bv[24]" % x

    c_ref = "(i5[t]:bv[64] >= %s)" % c(dl)
    c_pay = "((i5[t]:bv[64] >= %s) && (i5[t]:bv[64] - i49[t]:bv[64] >= %s))" % (c(d0), c(WEEK))
    c_man = "(i40[t]:bv[24] > %s)" % m(0)
    refund = "((o30[t]:bv[24] = %s) && (o31[t]:bv[24] = min(i2[t]:bv[24], %s - i26[t]:bv[24])))" % (m(0), m(total))
    manual = "((o30[t]:bv[24] = min(i40[t]:bv[24], %s)) && (o31[t]:bv[24] = %s))" % (m(rate), m(0))
    due = "((o30[t]:bv[24] = %s) && (o31[t]:bv[24] = %s))" % (m(rate), m(0))
    zero = "((o30[t]:bv[24] = %s) && (o31[t]:bv[24] = %s))" % (m(0), m(0))
    pay = "%s ? %s : %s" % (c_man, manual, due)
    inner = "%s ? (%s) : %s" % (c_pay, pay, zero)
    outer = "%s ? %s : (%s)" % (c_ref, refund, inner)
    return "always ( %s )." % outer


RULE = grant_rule()
BODY = payout_rule_body(RULE)

Z384 = "#x" + "00" * 48
O5_BODY = (
    "(i4[t]:bv[384] = {%s}:bv[384] ? o5[t]:bv[24] = { #x000001 }:bv[24] : "
    "(i5[t]:bv[64] < {%d}:bv[64] ? o5[t]:bv[24] = { #x000000 }:bv[24] : o5[t]:bv[24] = { #x000001 }:bv[24]))"
    % (Z384, DL)
)


def grant_out(inputs, total=TOTAL, rate=RATE, d0=D0, dl=DL):
    """The scripted clause semantics: what the native engine should compute."""
    i5 = int(inputs.get("i5", "0"))
    i49 = int(inputs.get("i49", str(TS0)))
    i40 = int(inputs.get("i40", "0"))
    i2 = int(inputs.get("i2", "0"))
    i26 = int(inputs.get("i26", "0"))
    if i5 >= dl:
        return {"o30": "0", "o31": str(min(i2, total - i26))}
    if i5 >= d0 and i5 - i49 >= WEEK:
        if i40 > 0:
            return {"o30": str(min(i40, rate)), "o31": "0"}
        return {"o30": str(rate), "o31": "0"}
    return {"o30": "0", "o31": "0"}


def o5_verdict(inputs):
    """The corrected o5: payout executions (i4 = 0) always pass; signed
    transfers are blocked before the deadline and allowed after it."""
    if str(inputs.get("i4", "0")) in ("0", ""):
        return 1
    return 0 if int(inputs.get("i5", "0")) < DL else 1


def set_tx(sender=CAROL, seq=0, *, rule=RULE, slots=None, cap_exec=5000,
           cap_period=5000, period=4 * WEEK, clock="period_seconds",
           expires_at=DL, fee_limit="100", **extra):
    tx = {"tx_id": f"set-{next(_N)}", "tx_type": "payout_rule_set", "sender_pubkey": sender,
          "sequence_number": seq, "expiration_time": FAR, "expire_at_height": 1000,
          "fee_limit": str(fee_limit), "rule_text": rule,
          "slots": [BOB, ALICE] if slots is None else slots,
          "cap_per_execution": cap_exec, "cap_per_period": cap_period, clock: period,
          "expires_at": expires_at, "due_at": D0, "due_every": WEEK}
    tx.update(extra)
    return _sign(tx, SKS[sender])


def exec_tx(executor=BOB, seq=0, *, account=CAROL, rule_id, data=None, recipients=None,
            fee_limit="100"):
    return _sign({"tx_id": f"exec-{next(_N)}", "tx_type": "payout_execute",
                  "sender_pubkey": executor, "sequence_number": seq,
                  "expiration_time": FAR, "expire_at_height": 1000,
                  "fee_limit": str(fee_limit), "account_pubkey": account,
                  "rule_id": rule_id, "recipients": recipients or {},
                  "data": data or {}}, SKS[executor])


def revoke_tx(sender=CAROL, seq=1, *, rule_id):
    return _sign({"tx_id": f"revoke-{next(_N)}", "tx_type": "payout_rule_revoke",
                  "sender_pubkey": sender, "sequence_number": seq, "expiration_time": FAR,
                  "expire_at_height": 1000, "fee_limit": "0", "rule_id": rule_id},
                 SKS[sender])


def update_tx(old_rule_id, sender=CAROL, seq=1, **kw):
    """A payout_rule_update naming `old_rule_id`, with the rule fields of set_tx."""
    tx = set_tx(sender=sender, seq=seq, **kw)
    tx["tx_type"] = "payout_rule_update"
    tx["rule_id"] = old_rule_id
    tx["tx_id"] = f"update-{next(_N)}"
    tx.pop("signature")
    return _sign(tx, SKS[sender])


def transfer_tx(sender=CAROL, seq=0, *, to=BOB, amount=100):
    return _sign({"tx_id": f"transfer-{next(_N)}", "tx_type": "user_tx",
                  "sender_pubkey": sender, "sequence_number": seq,
                  "expiration_time": FAR, "expire_at_height": 1000,
                  "fee_limit": "100",
                  "operations": {"1": [[sender, to, amount]]}}, SKS[sender])


def rid(tx) -> str:
    return parse_payout_rule_set(tx).rule_id.hex()


def ridb(tx) -> bytes:
    """The rule id as bytes, for book.get / book.state_of."""
    return parse_payout_rule_set(tx).rule_id


@pytest.fixture
def evs():
    out = {}
    for pool in ("apply", "payout_apply"):
        out[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, out[pool])
    out["payout_apply"].set_outputs(BODY, grant_out)
    out["apply"].set_verdict(O5_BODY, o5_verdict)
    yield out
    for pool in ("apply", "payout_apply"):
        sender_policy.set_evaluator(pool, None)


@pytest.fixture
def guard_evs():
    """The guard allows a change only once slot i18 holds a pubkey."""
    evs = {}
    for pool in ("apply", "admission", "payout_apply", "payout_admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        evs[pool].set_verdict(
            GUARD_BODY, lambda inputs: "0" if inputs.get("i18", "0") == "0" else "1")
        evs[pool].set_outputs(BODY, grant_out)
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def _bal():
    return {CAROL: 5000, BOB: 0, ALICE: 0, PROPOSER: 0}


def _installed(fee=0, lock=False, **kw):
    ch, oracle = Chain(_bal(), fee=fee), Oracle(_bal())
    tx = set_tx(**kw)
    ch.block([tx])
    oracle.create(tx, fee=fee)
    if lock:
        ch.lm.rule_offers.accepted_clauses[(CAROL, 5)] = O5_BODY
    return ch, oracle, tx


def _events(ch):
    return ch.last.next_snapshot.metadata["payout_events"]


def _drawn(oracle, *, executor=BOB, fee=0, legs, ts=TS0):
    """The oracle side of a manual draw: the executor pays the fee and its
    sequence advances; the legs come out of the escrow account's balance."""
    oracle.bal[executor] -= fee
    oracle.bal[PROPOSER] += fee
    oracle.seq[executor] += 1
    for who, amount in legs:
        oracle.bal[CAROL] -= amount
        oracle.bal[who] += amount
    oracle.lts[CAROL] = ts


def _state(ch, tx):
    return ch.lm.payout_rules.state_of(CAROL, ridb(tx))


def _book(ch, tx):
    terms = ch.lm.payout_rules.get(CAROL, ridb(tx))
    st = _state(ch, tx)
    return {"due_index": st.due_index, "next_due": st.next_due(terms),
            "executions": st.executions, "paid_total": st.paid_total,
            "missed": st.missed, "due_done": st.due_done,
            "spent_in_period": st.spent_in_period}


# --- the shape ---------------------------------------------------------------------

def test_grant_rule_shape_screen_accepts_the_clause(evs):
    terms = parse_payout_rule_set(set_tx())
    assert screen_payout_body(terms.body, len(terms.slots), terms.per_sale) is None
    assert validate_terms_shape(terms, HEIGHT, TS0) is None
    assert screen_policy_widths(O5_BODY) is None
    assert _screen_clause_domains(O5_BODY) is None


# --- installing --------------------------------------------------------------------

def test_grant_rule_install_moves_no_money(evs):
    ch, oracle, tx = _installed()
    oracle.check(ch)
    terms = ch.lm.payout_rules.get(CAROL, ridb(tx))
    assert terms is not None
    assert terms.due_at == D0 and terms.due_every == WEEK and terms.expires_at == DL
    assert terms.cap_per_execution == 5000 and terms.cap_per_period == 5000
    assert _events(ch) == [{"account_pubkey": CAROL, "rule_id": rid(tx),
                            "outcome": "installed", "tx_id": tx["tx_id"]}]
    # No escrow in the book: the money sits in the escrow account's balance.
    assert ch.bal[CAROL] == 5000 and ch.bal[BOB] == 0 and ch.bal[ALICE] == 0


def test_grant_rule_install_fee_comes_from_the_escrow_account(evs):
    bal = {CAROL: 5000 + 7, BOB: 0, ALICE: 0, PROPOSER: 0}
    ch, oracle = Chain(bal, fee=7), Oracle(bal)
    tx = set_tx()
    ch.block([tx])
    oracle.create(tx, fee=7)
    oracle.check(ch)
    assert ch.bal[CAROL] == 5000
    assert ch.lm.payout_rules.get(CAROL, ridb(tx)) is not None


# --- the o5 lock ---------------------------------------------------------------------

def test_grant_rule_o5_blocks_a_signed_transfer_before_the_deadline(evs):
    ch, oracle, tx = _installed(lock=True)
    result = ch.block([transfer_tx(seq=1)], height=HEIGHT + 1, ts=TS0 + 100)
    assert ch.bal[CAROL] == 5000 and ch.bal[BOB] == 0
    assert "o5" in _logs(result)
    oracle.check(ch)  # nothing moved: no fee, no sequence
    assert evs["apply"].verdict_calls  # the o5 clause WAS consulted
    # But the weekly due run still pays: a payout execution has i4 = 0.
    ch.block([], height=HEIGHT + 2, ts=D0)
    oracle.pay(CAROL, BOB, 500, ts=D0)
    oracle.check(ch)
    assert _events(ch)[0]["outcome"] == "executed"


def test_grant_rule_o5_allows_transfers_after_the_deadline(evs):
    """After the deadline the o5 allows transfers again, so the grantor
    recovers any leftover in the escrow account by plain transfer."""
    bal = {CAROL: 6000, BOB: 0, ALICE: 0, PROPOSER: 0}  # 1,000 above the grant
    ch, oracle = Chain(bal), Oracle(bal)
    tx = set_tx()
    ch.block([tx])
    oracle.create(tx, fee=0)
    ch.lm.rule_offers.accepted_clauses[(CAROL, 5)] = O5_BODY
    ch.block([], height=HEIGHT + 1, ts=DL)
    oracle.pay(CAROL, ALICE, 5000, ts=DL)  # nothing drawn: the whole grant refunds
    oracle.check(ch)
    assert ch.bal[CAROL] == 1000
    ch.block([transfer_tx(seq=1, to=ALICE, amount=1000)],
             height=HEIGHT + 2, ts=DL + 1)
    oracle.spend(CAROL, ALICE, 1000, ts=DL + 1)
    oracle.check(ch)
    assert evs["apply"].verdict_calls  # the o5 clause WAS consulted


# --- the weekly flow: case 5 ---------------------------------------------------------

def test_grant_rule_weekly_due_run_draws_500(evs):
    ch, oracle, tx = _installed()
    ch.block([], height=HEIGHT + 1, ts=D0)
    evs_out = _events(ch)
    oracle.pay(CAROL, BOB, 500, ts=D0)
    oracle.check(ch)
    assert len(evs_out) == 1 and evs_out[0]["total"] == 500
    assert _book(ch, tx)["paid_total"] == 500


def test_grant_rule_manual_draw_too_soon_is_refused(evs):
    ch, oracle, tx = _installed()
    ch.block([], height=HEIGHT + 1, ts=D0)  # due run 1: 500
    oracle.pay(CAROL, BOB, 500, ts=D0)
    oracle.check(ch)
    bal_before = dict(ch.bal)
    exe = exec_tx(seq=ch.seq.get(BOB, 0), rule_id=rid(tx), data={"0": 200})
    result = ch.block([exe], height=HEIGHT + 2, ts=D0 + 3085)  # 6/7 of a week later
    assert ch.bal == bal_before
    assert "already paid" in _logs(result)
    assert _book(ch, tx)["executions"] == 1
    oracle.check(ch)


def test_grant_rule_second_weekly_due_run_draws_500(evs):
    ch, oracle, tx = _installed()
    ch.block([], height=HEIGHT + 1, ts=D0)
    oracle.pay(CAROL, BOB, 500, ts=D0)
    ch.block([], height=HEIGHT + 2, ts=D0 + WEEK)
    evs_out = _events(ch)
    oracle.pay(CAROL, BOB, 500, ts=D0 + WEEK)
    oracle.check(ch)
    assert len(evs_out) == 1 and evs_out[0]["total"] == 500
    b = _book(ch, tx)
    assert (b["paid_total"], b["executions"]) == (1000, 2)
    assert ch.bal[BOB] == 1000 and ch.bal[CAROL] == 4000


def test_grant_rule_manual_draw_pays_after_a_week(evs):
    ch, oracle, tx = _installed()
    ch.block([], height=HEIGHT + 1, ts=D0)
    oracle.pay(CAROL, BOB, 500, ts=D0)
    ch.block([], height=HEIGHT + 2, ts=D0 + WEEK)
    oracle.pay(CAROL, BOB, 500, ts=D0 + WEEK)
    # A manual 200 a full week after the last paid run pays; the due run for
    # that point then pays nothing (a due point pays once).
    exe = exec_tx(seq=ch.seq.get(BOB, 0), rule_id=rid(tx), data={"0": 200})
    ch.block([exe], height=HEIGHT + 3, ts=D0 + 2 * WEEK)
    _drawn(oracle, legs=[(BOB, 200)], ts=D0 + 2 * WEEK)
    oracle.check(ch)
    b = _book(ch, tx)
    assert (b["paid_total"], b["executions"]) == (1200, 3)
    assert ch.bal[BOB] == 1200 and ch.bal[CAROL] == 3800


def test_grant_rule_deadline_refund_is_3800_case_5(evs):
    """gmikeyg's case 5: 5,000 granted, 500 + 500 + 200 drawn, 3,800 refunded."""
    ch, oracle, tx = _installed()
    ch.block([], height=HEIGHT + 1, ts=D0)
    oracle.pay(CAROL, BOB, 500, ts=D0)
    ch.block([], height=HEIGHT + 2, ts=D0 + WEEK)
    oracle.pay(CAROL, BOB, 500, ts=D0 + WEEK)
    exe = exec_tx(seq=ch.seq.get(BOB, 0), rule_id=rid(tx), data={"0": 200})
    ch.block([exe], height=HEIGHT + 3, ts=D0 + 2 * WEEK)
    _drawn(oracle, legs=[(BOB, 200)], ts=D0 + 2 * WEEK)
    # The deadline block: the due retry fires the refund branch.
    ch.block([], height=HEIGHT + 4, ts=DL)
    evs_out = _events(ch)
    oracle.pay(CAROL, ALICE, 3800, ts=DL)
    oracle.check(ch)
    assert ch.bal[ALICE] == 3800 and ch.bal[BOB] == 1200 and ch.bal[CAROL] == 0
    assert any(e.get("total") == 3800 for e in evs_out)
    assert ch.lm.payout_rules.get(CAROL, ridb(tx)) is None  # refunded and expired


def test_grant_rule_terminates_after_expiry(evs):
    ch, oracle, tx = _installed()
    ch.block([], height=HEIGHT + 1, ts=D0)
    oracle.pay(CAROL, BOB, 500, ts=D0)
    ch.block([], height=HEIGHT + 2, ts=D0 + WEEK)
    oracle.pay(CAROL, BOB, 500, ts=D0 + WEEK)
    exe = exec_tx(seq=ch.seq.get(BOB, 0), rule_id=rid(tx), data={"0": 200})
    ch.block([exe], height=HEIGHT + 3, ts=D0 + 2 * WEEK)
    _drawn(oracle, legs=[(BOB, 200)], ts=D0 + 2 * WEEK)
    ch.block([], height=HEIGHT + 4, ts=DL)
    oracle.pay(CAROL, ALICE, 3800, ts=DL)
    oracle.check(ch)
    assert ch.lm.payout_rules.get(CAROL, ridb(tx)) is None  # expired at DL
    bal_before = dict(ch.bal)
    ch.block([], height=HEIGHT + 5, ts=DL + WEEK)
    assert ch.bal == bal_before and _events(ch) == []


# --- missed points and the late refund -------------------------------------------------

def test_grant_rule_manual_draw_after_a_missed_due_point_pays(evs):
    ch, oracle, tx = _installed(expires_at=D0 + 5 * WEEK)
    ch.block([], height=HEIGHT + 1, ts=D0)
    oracle.pay(CAROL, BOB, 500, ts=D0)
    oracle.check(ch)
    # Manual 200 at the next point pays; that point's due run pays nothing.
    exe = exec_tx(seq=ch.seq.get(BOB, 0), rule_id=rid(tx), data={"0": 200})
    ch.block([exe], height=HEIGHT + 2, ts=D0 + WEEK)
    _drawn(oracle, legs=[(BOB, 200)], ts=D0 + WEEK)
    oracle.check(ch)
    b = _book(ch, tx)
    assert (b["paid_total"], b["executions"]) == (700, 2)
    assert ch.bal[BOB] == 700
    # A manual 200 a week after that missed point still pays (catch-up).
    exe = exec_tx(seq=ch.seq.get(BOB, 0), rule_id=rid(tx), data={"0": 200})
    ch.block([exe], height=HEIGHT + 3, ts=D0 + 2 * WEEK)
    _drawn(oracle, legs=[(BOB, 200)], ts=D0 + 2 * WEEK)
    oracle.check(ch)
    b = _book(ch, tx)
    assert ch.bal[BOB] == 900 and b["paid_total"] == 900 and b["missed"] == 1


def test_grant_rule_refund_after_a_missed_point_is_4100(evs):
    dl2 = D0 + 5 * WEEK
    ch, oracle, tx = _installed(expires_at=dl2)
    ch.block([], height=HEIGHT + 1, ts=D0)
    oracle.pay(CAROL, BOB, 500, ts=D0)
    exe = exec_tx(seq=ch.seq.get(BOB, 0), rule_id=rid(tx), data={"0": 200})
    ch.block([exe], height=HEIGHT + 2, ts=D0 + WEEK)
    _drawn(oracle, legs=[(BOB, 200)], ts=D0 + WEEK)
    exe = exec_tx(seq=ch.seq.get(BOB, 0), rule_id=rid(tx), data={"0": 200})
    ch.block([exe], height=HEIGHT + 3, ts=D0 + 2 * WEEK)
    _drawn(oracle, legs=[(BOB, 200)], ts=D0 + 2 * WEEK)
    ch.block([], height=HEIGHT + 4, ts=dl2)
    evs_out = _events(ch)
    oracle.pay(CAROL, ALICE, 4100, ts=dl2)
    oracle.check(ch)
    assert ch.bal[ALICE] == 4100 and ch.bal[BOB] == 900 and ch.bal[CAROL] == 0
    assert any(e.get("total") == 4100 for e in evs_out)


def test_grant_rule_late_refund_fallback_expiry(evs):
    """An unaligned deadline refunds at the next weekly due point (C1)."""
    dl2 = D0 + 2 * WEEK + 1800  # mid-week, not a due point
    ch, oracle, tx = _installed(expires_at=dl2 + WEEK)
    for k in range(3):  # dues at D0, D0+WEEK, D0+2WEEK: 500 each
        ch.block([], height=HEIGHT + 1 + k, ts=D0 + k * WEEK)
        oracle.pay(CAROL, BOB, 500, ts=D0 + k * WEEK)
    oracle.check(ch)
    assert ch.bal[BOB] == 1500 and ch.bal[CAROL] == 3500
    # The next due point is past the deadline: the refund branch fires.
    ch.block([], height=HEIGHT + 4, ts=D0 + 3 * WEEK)
    evs_out = _events(ch)
    oracle.pay(CAROL, ALICE, 3500, ts=D0 + 3 * WEEK)
    oracle.check(ch)
    assert ch.bal[ALICE] == 3500 and ch.bal[CAROL] == 0
    assert any(e.get("total") == 3500 for e in evs_out)
    ch.block([], height=HEIGHT + 5, ts=dl2 + WEEK)
    assert ch.lm.payout_rules.get(CAROL, ridb(tx)) is None


def test_grant_rule_fully_drawn_refunds_zero_then_expires(evs):
    """Ten weekly 500s draw the whole grant; the deadline run computes 0."""
    dl10 = D0 + 10 * WEEK
    rule10 = grant_rule(dl=dl10)
    evs["payout_apply"].set_outputs(payout_rule_body(rule10),
                                    lambda inputs: grant_out(inputs, dl=dl10))
    ch, oracle, tx = _installed(rule=rule10, period=12 * WEEK, expires_at=dl10)
    for k in range(10):
        ch.block([], height=HEIGHT + 1 + k, ts=D0 + k * WEEK)
        oracle.pay(CAROL, BOB, 500, ts=D0 + k * WEEK)
    oracle.check(ch)
    assert ch.bal[BOB] == 5000 and ch.bal[CAROL] == 0
    assert _book(ch, tx)["paid_total"] == 5000
    ch.block([], height=HEIGHT + 11, ts=dl10)
    assert ch.bal[ALICE] == 0  # nothing to refund
    assert not any(e.get("total", 0) > 0 for e in _events(ch))
    assert ch.lm.payout_rules.get(CAROL, ridb(tx)) is None


# --- revoking and updating ----------------------------------------------------------

def test_grant_rule_revoke_ends_the_rule_without_an_automatic_refund(evs):
    ch, oracle, tx = _installed()
    ch.block([], height=HEIGHT + 1, ts=D0)  # due run 1: 500
    oracle.pay(CAROL, BOB, 500, ts=D0)
    oracle.check(ch)
    revoke = revoke_tx(seq=ch.seq.get(CAROL, 0), rule_id=rid(tx))
    ch.block([revoke], height=HEIGHT + 2)
    oracle.cancel(CAROL)
    oracle.check(ch)
    assert ch.lm.payout_rules.get(CAROL, ridb(tx)) is None
    # The remainder stays in the escrow account: no refund on revoke.
    assert ch.bal[CAROL] == 4500 and ch.bal[BOB] == 500 and ch.bal[ALICE] == 0
    assert _events(ch)[0]["outcome"] == "revoked"
    assert "refunded" not in _events(ch)[0]


def test_grant_rule_revoke_is_guard_gated(guard_evs):
    """Through a rule-change request: the revoke parks without the grantee's
    co-signature and releases on it -- and the funds stay put either way.
    The guard harness runs at a fixed timestamp 1234567890, so the rule's
    due points use times just above it (and within the 4-year window)."""
    base = 1234567890
    small = grant_rule(d0=base + 3600, dl=base + 14400)
    guard_evs["payout_apply"].set_outputs(
        payout_rule_body(small),
        lambda inputs: grant_out(inputs, d0=base + 3600, dl=base + 14400))
    chain, install = _guard_parked(
        tau_defs.RULE_CHANGE_KIND_SET_PAYOUT,
        _guard_spec(rule_text=small, slots=[GUARD_BOB, DAVE],
                    cap_per_execution=5000, cap_per_period=5000,
                    period_blocks=None, period_seconds=14400,
                    due_at=base + 3600, due_every=3600, expires_at=base + 14400),
    )
    chain.block(_vote(install.request_id))
    assert chain.entry(install).status == STATUS_EXECUTED
    terms = chain.lm.payout_rules.get(GUARD_ALICE)
    assert terms is not None
    assert chain.balances[GUARD_ALICE] == 100_000
    revoke = _mk_request(tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT, seq=1, expire=LATE)
    chain.block(_mk_tx(revoke))
    assert chain.lm.payout_rules.get(GUARD_ALICE) is not None  # still parked
    assert chain.balances[GUARD_ALICE] == 100_000
    result = chain.block(_vote(revoke.request_id, seq=1))
    assert chain.entry(revoke).status == STATUS_EXECUTED
    assert chain.lm.payout_rules.get(GUARD_ALICE) is None
    assert chain.balances[GUARD_ALICE] == 100_000  # no automatic refund
    assert [e["outcome"] for e in result.next_snapshot.metadata["payout_events"]] == [
        "revoked"]


def test_grant_rule_update_is_allowed(evs):
    """The old code banned updating a grant rule; a rule-pattern grant is an
    ordinary rule and updates like one: same lineage, version + 1, the old
    id resolves to the new one."""
    ch, oracle, tx = _installed()
    book = ch.lm.payout_rules
    upd = update_tx(rid(tx), seq=1, cap_exec=4000)
    _, _, new_terms = parse_payout_rule_update(upd)
    ok, why = book.can_admit_update(CAROL, ridb(tx), new_terms, HEIGHT + 1, TS0 + 1)
    assert ok and not why
    ch.block([upd], height=HEIGHT + 1)
    oracle.create(upd, fee=0)
    oracle.check(ch)
    book = ch.lm.payout_rules  # the block replaced the lifecycle manager
    from dataclasses import replace as _replace
    new_id = _replace(new_terms, version=2).rule_id
    assert book.get(CAROL, ridb(tx)) is None
    assert book.get(CAROL, new_id) is not None
    assert book.get(CAROL, new_id).cap_per_execution == 4000
    assert book.current_id(bytes.fromhex(rid(tx))) == new_id


# --- the book ----------------------------------------------------------------------

def test_grant_rule_restores_with_plain_rows():
    tx = set_tx()
    terms = parse_payout_rule_set(tx)
    book = PayoutBook()
    book.install(terms, HEIGHT)
    book.record(CAROL, terms.rule_id, 1200, HEIGHT + 1, TS0 + 1)
    rows = book.store_rows()
    assert len(rows[0][18]) == 14  # `more` carries the shared-cap pair (None here)
    assert rows[0][18][12:] == (None, None)  # no shared cap on this rule
    restored = PayoutBook.restore(rows, *book.resolved_state())
    assert restored.root() == book.root()
    state = restored.state_of(CAROL, terms.rule_id)
    assert (state.paid_total, state.executions) == (1200, 1)
    assert restored.get(CAROL).rule_id == terms.rule_id
    assert not hasattr(restored.get(CAROL), "grant_amount")
