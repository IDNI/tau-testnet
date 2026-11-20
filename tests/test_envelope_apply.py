"""Block-apply semantics for envelopes (spending limits).

Every scenario runs through the real `apply_block` with a scripted interpreter
and compares the FULL balance map, sequences and cooldown stamps against an
oracle that knows only the documented rules:

  * a send moves `amount` out of the sender into the envelope and costs the
    sender one transfer fee; the sender's o5 judges it as "sender pays
    recipient amount";
  * only the recipient spends, to anyone (itself included), at most cap(n) in
    period n = (clock - anchor) // period; cap(n) = caps[n], then caps[-1] when
    recurring, else no limit; nothing carries over;
  * a spend costs the recipient one transfer fee from its own balance, after the
    credit, and is judged by the recipient's o5 as a transfer it signs;
  * the sender may release the rest to the recipient at once, fee-free;
  * at expires_at the rest goes to the recipient; an envelope spent to zero
    closes on its own.

`apply_block` raises on any supply drift (balances + every escrow), so every
block here is also a conservation check.

What the feature promises, by test:
  a cap per payment and recipient .. test_each_payment_and_each_recipient_has_its_own_cap
  a schedule of caps ............... test_a_schedule_of_caps_then_free, ..._recurring
  recurring limits ................. test_a_recurring_cap_resets_every_period
  enforced at the protocol level ... the refusal section (apply refuses, not a wallet)
  recipient spends to anyone ....... test_a_spend_pays_anyone_and_the_recipient_pays_the_fee
  the end of every envelope ........ the end section
  replay ........................... test_replay_gives_the_same_state_hashes
"""
import pytest
from py_ecc.bls import G2Basic

from consensus.envelope import (
    MAX_OPEN_ENVELOPES_PER_SENDER,
    OUTCOME_ENDED,
    parse_envelope_send,
)

from tests.test_standing_apply import (
    ALICE, BOB, CAROL, CLAUSE, FAR, HEIGHT, PROPOSER, SKS, TS, Chain, Oracle, _logs,
    _sign, evaluator, spend_tx,
)

DAVE = G2Basic.SkToPk(77777).hex()
_N = iter(range(10**9))


def send_tx(sender=ALICE, recipient=BOB, amount=600, seq=0, *, caps=(100,), every=10,
            clock="period_blocks", recurring=True, ends=HEIGHT + 100, fee_limit="100",
            **extra):
    tx = {"tx_id": f"env-send-{next(_N)}", "tx_type": "envelope_send",
          "sender_pubkey": sender, "sequence_number": seq, "expiration_time": FAR,
          "expire_at_height": 10_000, "fee_limit": str(fee_limit),
          "recipient_pubkey": recipient, "amount": amount, "caps": list(caps),
          clock: every, "expires_at": ends}
    if recurring:
        tx["recurring"] = True
    tx.update(extra)
    return _sign(tx, SKS[sender])


def env_spend(eid, amount, seq, *, spender=BOB, to=CAROL, fee_limit="100"):
    return _sign({"tx_id": f"env-spend-{next(_N)}", "tx_type": "envelope_spend",
                  "sender_pubkey": spender, "sequence_number": seq,
                  "expiration_time": FAR, "expire_at_height": 10_000,
                  "fee_limit": str(fee_limit), "envelope_id": eid, "to_pubkey": to,
                  "amount": amount}, SKS[spender])


def env_release(eid, seq, *, signer=ALICE):
    return _sign({"tx_id": f"env-release-{next(_N)}", "tx_type": "envelope_release",
                  "sender_pubkey": signer, "sequence_number": seq,
                  "expiration_time": FAR, "expire_at_height": 10_000, "fee_limit": "0",
                  "envelope_id": eid}, SKS[signer])


def eid_of(tx) -> str:
    return parse_envelope_send(tx).envelope_id.hex()


def _bal():
    return {ALICE: 10_000, BOB: 50, CAROL: 0, PROPOSER: 0}


class EnvOracle(Oracle):
    """The documented rules for balances, sequences and cooldown stamps."""

    def __init__(self, balances):
        super().__init__(balances)
        self.held = {}

    def sent(self, tx, *, fee=0, ts=TS):
        sender = tx["sender_pubkey"]
        self.bal[sender] -= tx["amount"] + fee
        self.bal[PROPOSER] += fee
        self.seq[sender] += 1
        self.lts[sender] = ts
        self.held[eid_of(tx)] = tx["amount"]

    def spent(self, eid, spender, to, amount, *, fee=0, ts=TS):
        self.held[eid] -= amount
        self.bal[to] += amount
        self.bal[spender] -= fee
        self.bal[PROPOSER] += fee
        self.seq[spender] += 1
        self.lts[spender] = ts

    def released(self, eid, signer, recipient):
        self.bal[recipient] += self.held.pop(eid)
        self.seq[signer] += 1

    def ended(self, eid, recipient):
        self.bal[recipient] += self.held.pop(eid)

    def check(self, ch):
        super().check(ch)
        live = {e.hex(): s.remaining for e, s in ch.lm.envelopes.state.items()}
        assert live == {e: v for e, v in self.held.items() if v}
        assert ch.lm.envelopes.escrow_total() == sum(self.held.values())


def _sent(fee=0, **kw):
    ch, oracle = Chain(_bal(), fee=fee), EnvOracle(_bal())
    tx = send_tx(**kw)
    ch.block([tx])
    oracle.sent(tx, fee=fee)
    return ch, oracle, tx


def _events(ch):
    return ch.last.next_snapshot.metadata["envelope_events"]


def _reason(result, tx):
    return next(o for o in result.outcomes if o.tx_id == tx["tx_id"]).reason


def _accepted(result, tx):
    return tx["tx_id"] in result.accepted_tx_ids


# --- sending -----------------------------------------------------------------------

def test_a_send_escrows_the_amount_and_charges_one_fee():
    ch, oracle, tx = _sent(fee=7)
    oracle.check(ch)
    assert _events(ch) == [{"outcome": "sent", "envelope_id": eid_of(tx),
                            "sender_pubkey": ALICE, "recipient_pubkey": BOB,
                            "amount": 600, "tx_id": tx["tx_id"]}]
    terms = ch.lm.envelopes.get(bytes.fromhex(eid_of(tx)))
    assert (terms.caps, terms.period, terms.recurring) == ((100,), 10, True)
    assert ch.lm.envelopes.state_of(bytes.fromhex(eid_of(tx))).anchor == HEIGHT


def test_the_anchor_of_a_time_envelope_is_the_block_timestamp():
    ch, _, tx = _sent(clock="period_seconds", every=3600, ends=TS + 86400)
    assert ch.lm.envelopes.state_of(bytes.fromhex(eid_of(tx))).anchor == TS


@pytest.mark.parametrize("over, why", [
    ({"recipient": ALICE}, "own sender"),
    ({"amount": 0}, "amount must be in"),
    ({"caps": (0,)}, "caps[0] must be in"),
    ({"caps": ()}, "caps must be a list"),
    ({"caps": (1,) * 13}, "caps must be a list"),
    ({"every": 0}, "the period must be in"),
    ({"every": 1_000_001}, "the period must be in"),
    ({"ends": HEIGHT}, "expires_at must be in the future"),
    ({"ends": HEIGHT + 10_000_001}, "more than"),
    ({"clock": "period_seconds", "every": 31_622_401, "ends": TS + 9}, "the period"),
    ({"clock": "period_seconds", "every": 60, "ends": TS + 4 * 31_622_400 + 1}, "more than"),
])
def test_an_inadmissible_send_stays_out_and_pays_nothing(over, why):
    ch, oracle = Chain(_bal(), fee=5), EnvOracle(_bal())
    tx = send_tx(**over)
    result = ch.block([tx])
    assert not _accepted(result, tx)
    assert why in _logs(result)
    oracle.check(ch)
    assert ch.lm.envelopes.is_empty()


def test_a_send_beyond_the_balance_is_refused():
    ch, oracle = Chain(_bal()), EnvOracle(_bal())
    tx = send_tx(amount=10_001)
    result = ch.block([tx])
    assert not _accepted(result, tx)
    oracle.check(ch)


def test_a_send_that_cannot_also_pay_its_fee_is_refused():
    ch, oracle = Chain({ALICE: 600, BOB: 0, PROPOSER: 0}, fee=1), \
        EnvOracle({ALICE: 600, BOB: 0, PROPOSER: 0})
    tx = send_tx(amount=600)
    result = ch.block([tx])
    assert not _accepted(result, tx)
    oracle.check(ch)


def test_a_sender_may_hold_at_most_sixteen_open_envelopes():
    ch, oracle = Chain(_bal()), EnvOracle(_bal())
    txs = [send_tx(amount=10, seq=k) for k in range(MAX_OPEN_ENVELOPES_PER_SENDER + 1)]
    result = ch.block(txs)
    for tx in txs[:-1]:
        oracle.sent(tx)
    assert not _accepted(result, txs[-1])
    assert "open envelopes" in _logs(result)
    oracle.check(ch)


def test_no_signed_term_can_be_changed_after_signing():
    ch, oracle = Chain(_bal()), EnvOracle(_bal())
    tx = send_tx()
    tx["caps"] = [10_000]
    result = ch.block([tx])
    assert not _accepted(result, tx)
    oracle.check(ch)


def test_the_same_envelope_cannot_be_opened_twice_in_a_block():
    ch, oracle = Chain(_bal()), EnvOracle(_bal())
    tx = send_tx()
    twin = dict(tx, tx_id="twin")
    result = ch.block([tx, twin])
    oracle.sent(tx)
    assert not _accepted(result, twin)
    oracle.check(ch)


# --- spending ----------------------------------------------------------------------

def test_a_spend_pays_anyone_and_the_recipient_pays_the_fee():
    ch, oracle, tx = _sent(fee=3)
    eid = eid_of(tx)
    spend = env_spend(eid, 80, 0)
    ch.block([spend], height=HEIGHT + 1, ts=TS + 1)
    oracle.spent(eid, BOB, CAROL, 80, fee=3, ts=TS + 1)
    oracle.check(ch)
    assert _events(ch) == [{
        "outcome": "spend", "envelope_id": eid, "sender_pubkey": ALICE,
        "recipient_pubkey": BOB, "to_pubkey": CAROL, "amount": 80, "remaining": 520,
        "period_index": 0, "spent_in_period": 80, "tx_id": spend["tx_id"]}]


def test_a_recipient_with_nothing_can_spend_to_itself_and_pay_the_fee_from_it():
    ch = Chain({ALICE: 10_000, PROPOSER: 0}, fee=4)
    oracle = EnvOracle({ALICE: 10_000, PROPOSER: 0})
    tx = send_tx(fee_limit="4")
    ch.block([tx])
    oracle.sent(tx, fee=4)
    ch.block([env_spend(eid_of(tx), 100, 0, to=BOB, fee_limit="4")], height=HEIGHT + 1)
    oracle.spent(eid_of(tx), BOB, BOB, 100, fee=4)
    oracle.check(ch)
    assert ch.bal[BOB] == 96


def test_a_spend_to_someone_else_with_no_money_for_the_fee_is_refused():
    ch = Chain({ALICE: 10_000, PROPOSER: 0}, fee=4)
    oracle = EnvOracle({ALICE: 10_000, PROPOSER: 0})
    tx = send_tx(fee_limit="4")
    ch.block([tx])
    oracle.sent(tx, fee=4)
    spend = env_spend(eid_of(tx), 100, 0, fee_limit="4")
    result = ch.block([spend], height=HEIGHT + 1)
    assert not _accepted(result, spend)
    oracle.check(ch)


@pytest.mark.parametrize("signer", [ALICE, CAROL])
def test_only_the_recipient_may_spend(signer):
    ch, oracle, tx = _sent()
    spend = env_spend(eid_of(tx), 10, 1 if signer == ALICE else 0, spender=signer)
    result = ch.block([spend], height=HEIGHT + 1)
    assert _reason(result, spend) == "envelope_not_spent"
    assert "only the envelope's recipient may spend" in _logs(result)
    oracle.check(ch)


def test_a_spend_from_an_unknown_envelope_is_refused():
    ch, oracle, _ = _sent()
    spend = env_spend("cd" * 32, 10, 0)
    result = ch.block([spend], height=HEIGHT + 1)
    assert "no open envelope" in _logs(result)
    oracle.check(ch)


def test_a_spend_beyond_the_cap_is_refused_and_moves_nothing():
    ch, oracle, tx = _sent()
    spend = env_spend(eid_of(tx), 101, 0)
    result = ch.block([spend], height=HEIGHT + 1)
    assert _reason(result, spend) == "envelope_not_spent"
    assert "the cap 100 leaves 100" in _logs(result)
    oracle.check(ch)


def test_spends_in_one_block_share_the_cap():
    ch, oracle, tx = _sent()
    eid = eid_of(tx)
    first, second, third = env_spend(eid, 60, 0), env_spend(eid, 40, 1), env_spend(eid, 1, 2)
    result = ch.block([first, second, third], height=HEIGHT + 1)
    oracle.spent(eid, BOB, CAROL, 60)
    oracle.spent(eid, BOB, CAROL, 40)
    assert not _accepted(result, third)
    oracle.check(ch)


def test_each_payment_and_each_recipient_has_its_own_cap():
    # The cap is written on the payment. Two payments to Bob and one to Carol are
    # three allowances: what is spent from one takes no room from another.
    ch, oracle = Chain(_bal()), EnvOracle(_bal())
    food = send_tx(amount=600, caps=(100,), seq=0)
    rent = send_tx(amount=900, caps=(300,), seq=1)
    hers = send_tx(recipient=CAROL, amount=200, caps=(20,), seq=2)
    ch.block([food, rent, hers])
    for tx in (food, rent, hers):
        oracle.sent(tx)
    food_id, rent_id, her_id = eid_of(food), eid_of(rent), eid_of(hers)
    assert len({food_id, rent_id, her_id}) == 3

    # Each takes exactly its own cap in the same block.
    ch.block([env_spend(food_id, 100, 0), env_spend(rent_id, 300, 1),
              env_spend(her_id, 20, 0, spender=CAROL, to=BOB)], height=HEIGHT + 1)
    oracle.spent(food_id, BOB, CAROL, 100)
    oracle.spent(rent_id, BOB, CAROL, 300)
    oracle.spent(her_id, CAROL, BOB, 20)
    oracle.check(ch)

    # One more from any of them is refused against that payment's cap, although the
    # other two still hold money.
    for eid, spender, seq, cap in ((food_id, BOB, 2, 100), (rent_id, BOB, 2, 300),
                                   (her_id, CAROL, 1, 20)):
        over = env_spend(eid, 1, seq, spender=spender, to=ALICE)
        result = ch.block([over], height=HEIGHT + 2)
        assert _reason(result, over) == "envelope_not_spent"
        assert f"the cap {cap} leaves 0" in _logs(result)
    oracle.check(ch)

    # The next period renews each one at its own cap, not at a shared one.
    late = [env_spend(food_id, 101, 2), env_spend(rent_id, 300, 2)]
    result = ch.block(late, height=HEIGHT + 10)
    assert not _accepted(result, late[0]) and _accepted(result, late[1])
    oracle.spent(rent_id, BOB, CAROL, 300)
    oracle.check(ch)


def test_a_send_and_a_spend_in_the_same_block():
    ch, oracle = Chain(_bal()), EnvOracle(_bal())
    tx = send_tx()
    spend = env_spend(eid_of(tx), 100, 0)
    ch.block([tx, spend])
    oracle.sent(tx)
    oracle.spent(eid_of(tx), BOB, CAROL, 100)
    oracle.check(ch)


def _spend_series(caps, recurring, amounts_by_period, every=10):
    """Spend as much as allowed in each period; returns what each period took."""
    ch, oracle, tx = _sent(amount=5_000, caps=caps, recurring=recurring, every=every,
                           ends=HEIGHT + 1_000)
    eid, seq, taken = eid_of(tx), 0, []
    for period, want in enumerate(amounts_by_period):
        h = HEIGHT + period * every + 1
        spend = env_spend(eid, want, seq)
        result = ch.block([spend], height=h, ts=TS + h)
        if _accepted(result, spend):
            oracle.spent(eid, BOB, CAROL, want, ts=TS + h)
            seq += 1
            taken.append(want)
        else:
            taken.append(0)
        oracle.check(ch)
    return taken


def test_a_recurring_cap_resets_every_period():
    assert _spend_series((100,), True, [100, 100, 101, 100]) == [100, 100, 0, 100]


def test_a_single_cap_without_recurring_limits_only_the_first_period():
    assert _spend_series((100,), False, [101, 100, 900]) == [0, 100, 900]


def test_a_schedule_of_caps_then_free():
    assert _spend_series((300, 100), False, [300, 101, 100, 1_000]) == [300, 0, 100, 1_000]


def test_a_schedule_of_caps_recurring():
    assert _spend_series((300, 100), True, [300, 100, 101, 100]) == [300, 100, 0, 100]


def test_nothing_carries_over():
    # Nothing spent in period 0; period 1 still allows only its own cap.
    assert _spend_series((100,), True, [0, 150, 100]) == [0, 0, 100]
    ch, oracle, tx = _sent()
    spend = env_spend(eid_of(tx), 150, 0)
    result = ch.block([spend], height=HEIGHT + 15, ts=TS + 15)
    assert not _accepted(result, spend)
    oracle.check(ch)


def test_the_period_boundary_is_exact():
    ch, oracle, tx = _sent()
    eid = eid_of(tx)
    ch.block([env_spend(eid, 100, 0)], height=HEIGHT + 9)
    oracle.spent(eid, BOB, CAROL, 100)
    late = env_spend(eid, 1, 1)
    assert not _accepted(ch.block([late], height=HEIGHT + 9), late)
    ch.block([env_spend(eid, 100, 1)], height=HEIGHT + 10)
    oracle.spent(eid, BOB, CAROL, 100)
    oracle.check(ch)


def test_a_time_envelope_counts_periods_in_seconds():
    ch, oracle, tx = _sent(clock="period_seconds", every=3600, ends=TS + 86_400)
    eid = eid_of(tx)
    ch.block([env_spend(eid, 100, 0)], height=HEIGHT + 1, ts=TS + 3599)
    oracle.spent(eid, BOB, CAROL, 100, ts=TS + 3599)
    blocked = env_spend(eid, 1, 1)
    # Many blocks later, but the same hour: still the same period.
    assert not _accepted(ch.block([blocked], height=HEIGHT + 500, ts=TS + 3599), blocked)
    ch.block([env_spend(eid, 100, 1)], height=HEIGHT + 501, ts=TS + 3600)
    oracle.spent(eid, BOB, CAROL, 100, ts=TS + 3600)
    oracle.check(ch)


def test_a_spend_never_takes_more_than_the_envelope_holds():
    ch, oracle, tx = _sent(amount=150, caps=(1_000,))
    spend = env_spend(eid_of(tx), 151, 0)
    result = ch.block([spend], height=HEIGHT + 1)
    assert "the envelope holds 150" in _logs(result)
    oracle.check(ch)


def test_an_envelope_spent_to_zero_closes():
    ch, oracle, tx = _sent(amount=150, caps=(1_000,))
    eid = eid_of(tx)
    spend = env_spend(eid, 150, 0)
    ch.block([spend], height=HEIGHT + 1)
    oracle.spent(eid, BOB, CAROL, 150)
    oracle.check(ch)
    assert [e["outcome"] for e in _events(ch)] == ["spend", "emptied"]
    assert ch.lm.envelopes.open_count() == 0
    assert ch.lm.envelopes.resolved_count == 1
    again = env_spend(eid, 1, 1)
    assert not _accepted(ch.block([again], height=HEIGHT + 2), again)


def test_a_spend_stamps_the_spenders_cooldown_clock():
    ch, _, tx = _sent()
    assert BOB not in ch.lts
    ch.block([env_spend(eid_of(tx), 10, 0)], height=HEIGHT + 1, ts=TS + 77)
    assert ch.lts[BOB] == TS + 77


# --- policy (o5) -------------------------------------------------------------------

def test_the_senders_policy_judges_the_send(evaluator):
    ch, oracle = Chain(_bal()), EnvOracle(_bal())
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = CLAUSE
    evaluator.set_verdict(CLAUSE, 0)
    tx = send_tx(amount=321)
    result = ch.block([tx])
    assert _reason(result, tx) == "user_policy_block"
    oracle.check(ch)
    body, inputs = evaluator.verdict_calls[-1]
    assert inputs["i1"] == "321" and ALICE in inputs["i3"] and BOB in inputs["i4"]


def test_the_recipients_policy_judges_the_spend_as_its_own_transfer(evaluator):
    ch, oracle, tx = _sent()
    ch.lm.rule_offers.accepted_clauses[(BOB, 5)] = CLAUSE
    evaluator.set_verdict(CLAUSE, 0)
    spend = env_spend(eid_of(tx), 70, 0)
    result = ch.block([spend], height=HEIGHT + 1, ts=TS + 5)
    assert _reason(result, spend) == "user_policy_block"
    oracle.check(ch)
    body, inputs = evaluator.verdict_calls[-1]
    assert inputs["i1"] == "70"
    assert BOB in inputs["i3"] and CAROL in inputs["i4"] and BOB in inputs["i12"]
    assert inputs["i2"] == "50"          # the spender's own balance, as for any transfer
    evaluator.set_verdict(CLAUSE, None)
    ok = env_spend(eid_of(tx), 70, 0)
    ch.block([ok], height=HEIGHT + 2, ts=TS + 6)
    oracle.spent(eid_of(tx), BOB, CAROL, 70, ts=TS + 6)
    oracle.check(ch)


def test_the_senders_policy_does_not_judge_the_spend(evaluator):
    ch, oracle, tx = _sent()
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = CLAUSE
    evaluator.set_verdict(CLAUSE, 0)
    ch.block([env_spend(eid_of(tx), 70, 0)], height=HEIGHT + 1)
    oracle.spent(eid_of(tx), BOB, CAROL, 70)
    oracle.check(ch)


# --- release -----------------------------------------------------------------------

def test_the_sender_releases_the_rest_fee_free():
    ch, oracle, tx = _sent(fee=5)
    eid = eid_of(tx)
    ch.block([env_spend(eid, 100, 0)], height=HEIGHT + 1)
    oracle.spent(eid, BOB, CAROL, 100, fee=5)
    rel = env_release(eid, 1)
    ch.block([rel], height=HEIGHT + 2)
    oracle.released(eid, ALICE, BOB)
    oracle.check(ch)
    assert _events(ch) == [{"outcome": "released", "envelope_id": eid, "sender_pubkey": ALICE,
                            "recipient_pubkey": BOB, "paid_out": 500,
                            "tx_id": rel["tx_id"]}]
    assert ALICE not in ch.lts or ch.lts[ALICE] == TS


@pytest.mark.parametrize("signer", [BOB, CAROL])
def test_only_the_sender_may_release(signer):
    ch, oracle, tx = _sent()
    rel = env_release(eid_of(tx), 0, signer=signer)
    result = ch.block([rel], height=HEIGHT + 1)
    assert _reason(result, rel) == "envelope_not_released"
    oracle.check(ch)


def test_a_release_and_a_spend_in_one_block_follow_the_block_order():
    ch, oracle, tx = _sent()
    eid = eid_of(tx)
    rel, spend = env_release(eid, 1), env_spend(eid, 50, 0)
    result = ch.block([rel, spend], height=HEIGHT + 1)
    oracle.released(eid, ALICE, BOB)
    assert not _accepted(result, spend)
    oracle.check(ch)


# --- the end -----------------------------------------------------------------------

def test_at_its_end_the_rest_goes_to_the_recipient():
    ch, oracle, tx = _sent(ends=HEIGHT + 30)
    eid = eid_of(tx)
    ch.block([env_spend(eid, 100, 0)], height=HEIGHT + 1)
    oracle.spent(eid, BOB, CAROL, 100)
    ch.block([], height=HEIGHT + 29)
    assert ch.lm.envelopes.open_count() == 1
    ch.block([], height=HEIGHT + 30)
    oracle.ended(eid, BOB)
    oracle.check(ch)
    assert _events(ch) == [{"outcome": "ended", "envelope_id": eid, "sender_pubkey": ALICE,
                            "recipient_pubkey": BOB, "paid_out": 500}]
    count, _ = ch.lm.envelopes.resolved_state()
    assert count == 1


def test_no_spend_lands_in_the_block_that_ends_it():
    ch, oracle, tx = _sent(ends=HEIGHT + 30)
    spend = env_spend(eid_of(tx), 10, 0)
    result = ch.block([spend], height=HEIGHT + 30)
    assert "reached its end" in _logs(result)
    oracle.ended(eid_of(tx), BOB)
    oracle.check(ch)


def test_a_time_envelope_ends_on_the_block_timestamp():
    ch, oracle, tx = _sent(clock="period_seconds", every=60, ends=TS + 600)
    ch.block([], height=HEIGHT + 1000, ts=TS + 599)
    assert ch.lm.envelopes.open_count() == 1
    ch.block([], height=HEIGHT + 1001, ts=TS + 600)
    oracle.ended(eid_of(tx), BOB)
    oracle.check(ch)


def test_many_envelopes_end_in_one_block_in_their_order():
    ch, oracle = Chain(_bal()), EnvOracle(_bal())
    txs = [send_tx(amount=10 + k, seq=k, ends=HEIGHT + 5 + (k % 3)) for k in range(6)]
    ch.block(txs)
    for tx in txs:
        oracle.sent(tx)
    ch.block([], height=HEIGHT + 9)
    for tx in txs:
        oracle.ended(eid_of(tx), BOB)
    oracle.check(ch)
    ends = [(e["paid_out"]) for e in _events(ch)]
    assert sorted(ends) == [10, 11, 12, 13, 14, 15] and len(ends) == 6
    assert OUTCOME_ENDED == 3


# --- receive routes (#35) ----------------------------------------------------------

def _route(owner, dest, share=2000, seq=0):
    return _sign({"tx_id": f"env-route-{next(_N)}", "tx_type": "receive_route_set",
                  "sender_pubkey": owner, "sequence_number": seq, "expiration_time": FAR,
                  "expire_at_height": 10_000, "fee_limit": "100",
                  "destination_pubkey": dest, "share_bps": share}, SKS[owner])


def _splits(ch):
    return [(e["credit_class"], e["gross"], e["routed"], e["net"])
            for e in ch.last.next_snapshot.metadata["route_events"]
            if e["outcome"] == "routed"]


def test_a_spends_payee_splits_by_its_route():
    ch, oracle, tx = _sent()
    ch.block([_route(CAROL, DAVE)], height=HEIGHT + 1)
    oracle.seq[CAROL] += 1
    ch.block([env_spend(eid_of(tx), 100, 0)], height=HEIGHT + 2)
    assert _splits(ch) == [("envelope_spend", 100, 20, 80)]
    oracle.spent(eid_of(tx), BOB, CAROL, 100)
    oracle.bal[CAROL] -= 20
    oracle.bal[DAVE] += 20
    oracle.check(ch)


def test_the_release_and_the_end_split_by_the_recipients_route():
    ch, oracle = Chain(_bal()), EnvOracle(_bal())
    first, second = send_tx(seq=0), send_tx(seq=1, amount=100, ends=HEIGHT + 5)
    ch.block([first, second, _route(BOB, DAVE)])
    oracle.sent(first)
    oracle.sent(second)
    oracle.seq[BOB] += 1
    ch.block([env_release(eid_of(first), 2)], height=HEIGHT + 1)
    assert _splits(ch) == [("envelope_release", 600, 120, 480)]
    ch.block([], height=HEIGHT + 5)
    assert _splits(ch) == [("envelope_release", 100, 20, 80)]
    oracle.released(eid_of(first), ALICE, BOB)
    oracle.ended(eid_of(second), BOB)
    oracle.bal[BOB] -= 120 + 20
    oracle.bal[DAVE] += 120 + 20
    oracle.check(ch)


# --- replay and the meta hash ------------------------------------------------------

def test_replay_gives_the_same_state_hashes():
    def run(replay):
        ch = Chain(_bal(), fee=2)
        tx = send_tx(caps=(150, 50), ends=HEIGHT + 40, fee_limit="2")
        eid = eid_of(tx)
        ch.block([tx], replay=replay)
        script = {HEIGHT + 3: [env_spend(eid, 150, 0, fee_limit="2")],
                  HEIGHT + 12: [env_spend(eid, 50, 1, fee_limit="2")],
                  HEIGHT + 25: [env_spend(eid, 40, 2, to=BOB, fee_limit="2")]}
        for h in range(HEIGHT + 1, HEIGHT + 42):
            ch.block(script.get(h, []), height=h, ts=TS + h, replay=replay)
        return ch.hashes, ch.bal

    assert run(False) == run(True)


def test_an_envelope_changes_the_state_hash_and_an_empty_book_does_not():
    plain, with_env = Chain(_bal()), Chain(_bal())
    plain.block([spend_tx(ALICE, BOB, 600, 0)])
    with_env.block([send_tx()])
    assert plain.hashes != with_env.hashes
    a, b = Chain(_bal()), Chain(_bal())
    a.block([])
    b.block([])
    assert a.hashes == b.hashes
