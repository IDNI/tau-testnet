"""Random block sequences: the node against a naive reference model (#63).

The model knows nothing of the book's expiry lists, state records or
commitments. For every execution it applies the documented rules directly:

  * the rule must be installed, be the one named, and not have reached its end;
  * the period is (clock - anchor) // period, anchored where the rule was
    installed; what was paid in an earlier period does not count;
  * every slot the rule writes is paid, or nothing: an open slot needs a named
    recipient, 1 <= total <= cap per execution, period total <= cap per period,
    total <= the account's balance at that point in the block;
  * the account pays the legs; then the executor pays the fee from what it
    holds after them (an executor that is also a recipient may pay from that).

Hypothesis drives installs, revokes, executions (with random data
and named recipients), transfers and height gaps through the REAL `apply_block`
(signature checks stubbed), and after every block the node's balances and book
must equal the model's. Any divergence shrinks to a minimal program.

One account may hold several rules at once: the model keeps every rule of an
account, keyed by its id, and the strategy always aims at the account's first
(one rule per account is what the strategy exercises; the multi-rule book
itself is covered by tests/test_payout_multirule.py).
"""
import itertools
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from consensus import sender_policy
from consensus.payout import (
    PayoutShapeError, PayoutTerms, parse_payout_rule_set, parse_payout_spec,
    payout_rule_body, payout_spec_text,
)
from consensus.policy_mock import MockPolicyEvaluator

from consensus.network_binding import BOUND_TX_TYPES, chain_genesis_hash
from tests.chain_harness import ALICE, BOB, CAROL, PROPOSER, Chain, HEIGHT, TS

PEOPLE = (ALICE, BOB, CAROL)
RULES = {
    1: "always ( o30[t]:bv[24] = i40[t]:bv[24] ).",
    2: "always ( (o30[t]:bv[24] = i40[t]:bv[24]) && (o31[t]:bv[24] = i41[t]:bv[24]) ).",
}
FEE = 2
_IDS = itertools.count()


def _tx(sender, seq, height, tx_type, **fields):
    tx = {"tx_id": f"m-{next(_IDS)}", "tx_type": tx_type, "sender_pubkey": sender,
          "sequence_number": seq, "expiration_time": 9_999_999_999,
          "expire_at_height": height + 1, "fee_limit": "100", "signature": "00"}
    if tx_type in BOUND_TX_TYPES:
        tx["genesis_hash"] = chain_genesis_hash()
    tx.update(fields)
    return tx


def _scripted(inputs):
    return {f"o{30 + k}": inputs.get(f"i{40 + k}", "0") for k in range(2)}


class Model:
    def __init__(self, balances):
        self.bal = dict(balances)
        self.rules = {}     # account -> {rule_id: dict(terms, anchor, index, spent, n, paid)}

    def install(self, terms, height):
        self.rules.setdefault(terms.account_pubkey, {})[terms.rule_id] = {
            "t": terms, "anchor": height, "index": 0, "spent": 0, "n": 0, "paid": 0}

    def expire(self, height):
        """Rules whose end the block reached; the node removes them after the
        block's transactions, and no execution in that block may use them."""
        gone = {}
        for account, recs in list(self.rules.items()):
            dead = {rid: r for rid, r in recs.items() if r["t"].expires_at <= height}
            for rid in dead:
                del recs[rid]
            if dead:
                gone[account] = dead
            if not recs:
                del self.rules[account]
        return gone

    def execute(self, executor, account, rule_id, data, named, height):
        """True when the execution lands (and pays its fee)."""
        r = self.rules.get(account, {}).get(rule_id)
        if r is None or height >= r["t"].expires_at:
            return False
        t = r["t"]
        if any(k >= len(t.slots) or t.slots[k] or who == account for k, who in named.items()):
            return False
        legs = []
        for k, slot in enumerate(t.slots):
            amount = data.get(k, 0)
            if amount <= 0:
                continue
            who = slot or named.get(k)
            if not who:
                return False
            legs.append((who, amount))
        total = sum(a for _, a in legs)
        index = (height - r["anchor"]) // t.period
        spent = r["spent"] if r["index"] == index else 0
        if total <= 0 or total > t.cap_per_execution or spent + total > t.cap_per_period:
            return False
        if total > self.bal.get(account, 0):
            return False
        after = dict(self.bal)
        after[account] -= total
        for who, amount in legs:
            after[who] = after.get(who, 0) + amount
        # The fee is charged after the legs, from what the executor then holds.
        if after.get(executor, 0) < FEE:
            return False
        after[executor] -= FEE
        after["proposer"] = after.get("proposer", 0) + FEE
        self.bal = after
        r.update(index=index, spent=spent + total, n=r["n"] + 1, paid=r["paid"] + total)
        return True


# Amounts aimed at the boundaries: nothing, one, the caps, what is left in the
# period and in the account, each exactly and one over.
PICK = st.one_of(st.sampled_from(["0", "1", "cap", "cap+1", "left", "left+1", "bal",
                                  "bal+1", "half"]), st.integers(0, 130))


def _amount(pick, r, model, account, height):
    if isinstance(pick, int):
        return pick
    t = r["t"]
    index = (height - r["anchor"]) // t.period
    left = t.cap_per_period - (r["spent"] if r["index"] == index else 0)
    base = {"0": 0, "1": 1, "cap": t.cap_per_execution, "cap+1": t.cap_per_execution + 1,
            "left": left, "left+1": left + 1, "bal": model.bal.get(account, 0),
            "bal+1": model.bal.get(account, 0) + 1, "half": t.cap_per_execution // 2}
    return max(0, base[pick])


def _gap(gap, model, height, focus):
    """A fixed gap, or one that lands on (or just before) the next period
    boundary or the end of a rule: the rule the step first executes, if any."""
    if isinstance(gap, int) or not model.rules:
        return gap if isinstance(gap, int) else 1
    recs = model.rules.get(focus) or model.rules[min(model.rules)]
    r = next(iter(recs.values()))
    t = r["t"]
    if gap.startswith("edge"):
        index = (height - r["anchor"]) // t.period
        target = r["anchor"] + (index + 1) * t.period
    else:
        target = t.expires_at
    target -= 1 if gap.endswith("-1") else 0
    return max(1, target - height)


def _named(name, r, account):
    """Recipients for open slots: every open slot (mostly), or a mistake."""
    how, who = name
    if r is None or how == "none":
        return {}
    slots = r["t"].slots
    if how == "open":
        return {k: who for k, slot in enumerate(slots) if not slot}
    if how == "fixed":
        return {k: who for k, slot in enumerate(slots) if slot}
    if how == "missing":
        return {len(slots): who}
    return {k: account for k, slot in enumerate(slots) if not slot}


step = st.fixed_dictionaries({
    "gap": st.one_of(st.sampled_from([1, 1, 2, 4, 9, 10, 25]),
                     st.sampled_from(["edge-1", "edge", "end-1", "end"])),
    "install": st.one_of(st.none(), st.tuples(
        st.sampled_from(PEOPLE), st.sampled_from([1, 2]),
        st.lists(st.sampled_from(("", ALICE, BOB, CAROL)), min_size=2, max_size=2),
        st.integers(1, 120), st.sampled_from([0, 0, 1, 50, 200]), st.sampled_from([5, 10, 30]),
        st.integers(1, 60),
    )),
    "revoke": st.one_of(st.none(), st.sampled_from(PEOPLE)),
    "executions": st.lists(st.tuples(
        st.sampled_from(PEOPLE), st.sampled_from(PEOPLE),
        PICK, PICK,
        st.tuples(st.sampled_from(["open", "open", "open", "none", "fixed", "missing",
                                   "self"]), st.sampled_from(PEOPLE)),
        st.integers(0, 9),                                # 0: name a stale rule id
    ), max_size=6),
    "topup": st.one_of(st.none(), st.tuples(st.sampled_from(PEOPLE), st.sampled_from(PEOPLE),
                                            st.integers(1, 300))),
})


@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(program=st.lists(step, min_size=1, max_size=12))
def test_node_equals_the_reference_model(program):
    start = {ALICE: 500, BOB: 300, CAROL: 40}
    ch = Chain(dict(start), fee=FEE)
    model = Model(dict(start))
    evaluator = MockPolicyEvaluator(pool="payout_apply")
    for text in RULES.values():
        evaluator.set_outputs(payout_rule_body(text), _scripted)
    sender_policy.set_evaluator("payout_apply", evaluator)
    seq = {p: 0 for p in PEOPLE}
    stale = {}
    height = HEIGHT
    try:
        with patch("consensus.bls.verify", return_value=True):
            for s in program:
                focus = s["executions"][0][1] if s["executions"] else None
                height += _gap(s["gap"], model, height, focus)
                ended = model.expire(height)
                stale.update({a: next(iter(recs.values()))["t"].rule_id
                              for a, recs in ended.items()})
                txs = []
                # Installs and revokes are judged before the block in the model:
                # they land at the head of the block.
                if s["install"]:
                    who, nslots, slots, cap_e, extra, period, life = s["install"]
                    slots = slots[:nslots]
                    fixed = [x for x in slots if x]
                    tx = _tx(who, seq[who], height, "payout_rule_set", rule_text=RULES[nslots],
                             slots=slots, cap_per_execution=cap_e,
                             cap_per_period=cap_e + extra, period_blocks=period,
                             expires_at=height + life)
                    ok = who not in fixed and len(set(fixed)) == len(fixed) \
                        and model.bal.get(who, 0) >= FEE
                    if ok:
                        txs.append(tx)
                        seq[who] += 1
                        model.bal[who] -= FEE
                        model.bal["proposer"] = model.bal.get("proposer", 0) + FEE
                        model.install(parse_payout_rule_set(tx), height)
                if s["revoke"] and s["revoke"] in model.rules and not s["install"]:
                    who = s["revoke"]
                    rid = next(iter(model.rules[who]))   # the account's oldest rule
                    txs.append(_tx(who, seq[who], height, "payout_rule_revoke",
                                   fee_limit="0", rule_id=rid.hex()))
                    seq[who] += 1
                    stale[who] = rid
                    del model.rules[who][rid]
                    if not model.rules[who]:
                        del model.rules[who]
                if s["topup"]:
                    frm, to, amount = s["topup"]
                    if frm != to and model.bal.get(frm, 0) >= amount + FEE:
                        txs.append(_tx(frm, seq[frm], height, "user_tx",
                                       operations={"1": [[frm, to, amount]]}))
                        seq[frm] += 1
                        model.bal[frm] -= amount + FEE
                        model.bal[to] = model.bal.get(to, 0) + amount
                        model.bal["proposer"] = model.bal.get("proposer", 0) + FEE
                for executor, account, p0, p1, name, stale_pick in s["executions"]:
                    recs = model.rules.get(account)
                    r = next(iter(recs.values())) if recs else None
                    if (stale_pick == 0 or r is None) and account in stale:
                        rule_id = stale[account]      # revoked or ended
                    elif r is not None:
                        rule_id = r["t"].rule_id
                    else:
                        continue
                    # A rule that ended at this height still sits in the node's
                    # book during the block: aim at it as if it were live.
                    r = r or (next(iter(ended[account].values()))
                              if account in ended else None)
                    named = _named(name, r, account)
                    if r is not None:
                        d0 = _amount(p0, r, model, account, height)
                        d1 = _amount(p1, r, model, account, height) if len(r["t"].slots) > 1 \
                            else 0
                        if len(r["t"].slots) > 1 and isinstance(p1, str) and p1 != "0":
                            d0 = 0 if p0 == "0" else d0 // 2   # split the target
                            d1 = max(0, d1 - d0) if p1 in ("cap", "left", "bal") else d1
                    else:
                        d0, d1 = (p0 if isinstance(p0, int) else 5), 0
                    data = {0: min(d0, 16_777_215), 1: min(d1, 16_777_215)}
                    if model.execute(executor, account, rule_id, data, named, height):
                        txs.append(_tx(executor, seq[executor], height, "payout_execute",
                                       account_pubkey=account, rule_id=rule_id.hex(),
                                       recipients={str(k): v for k, v in named.items()},
                                       data={str(k): v for k, v in data.items()}))
                        seq[executor] += 1
                    else:
                        # A refused execution is dropped: it must not land. It is
                        # sent with the next free sequence, so if the node took it,
                        # every later transaction of that executor would fail.
                        txs.append(_tx(executor, seq[executor], height, "payout_execute",
                                       account_pubkey=account, rule_id=rule_id.hex(),
                                       recipients={str(k): v for k, v in named.items()},
                                       data={str(k): v for k, v in data.items()}))
                        refused_tx = txs[-1]
                        refused_tx["_refused"] = True

                result = ch.block([{k: v for k, v in t.items() if k != "_refused"}
                                   for t in txs], height=height, ts=TS + height)
                landed = set(result.accepted_tx_ids)
                for t in txs:
                    assert (t["tx_id"] in landed) == (not t.get("_refused")), (t, result)

                node = {k: v for k, v in ch.bal.items() if v and k != PROPOSER}
                want = {k: v for k, v in model.bal.items() if v and k != "proposer"}
                assert node == want
                assert ch.bal.get(PROPOSER, 0) == model.bal.get("proposer", 0)
                book = ch.lm.payout_rules
                assert set(book.terms) == {
                    (a, rid) for a, recs in model.rules.items() for rid in recs}
                for account, recs in model.rules.items():
                    for rid, r in recs.items():
                        state = book.state_of(account, rid)
                        assert book.get(account, rid).rule_id == r["t"].rule_id
                        assert (state.executions, state.paid_total) == (r["n"], r["paid"])
    finally:
        sender_policy.set_evaluator("payout_apply", None)


def test_sealed_and_unsealed_terms_have_different_ids():
    base = {"account_pubkey": ALICE, "sequence_number": 1, "body": "x",
            "slots": (BOB,), "cap_per_execution": 100, "cap_per_period": 250,
            "kind": 0, "period": 10, "expires_at": HEIGHT + 500}
    plain = PayoutTerms(**base)
    sealed = PayoutTerms(**base, sealed=True)
    assert plain.rule_id != sealed.rule_id
    assert plain.sealed is False and sealed.sealed is True


def test_sealed_is_part_of_the_payout_spec_text():
    fields = {"rule_text": "always ( o30[t]:bv[24] = i40[t]:bv[24] ).",
              "slots": [BOB], "cap_per_execution": 100, "cap_per_period": 250,
              "period_blocks": 10, "expires_at": HEIGHT + 500, "sealed": True}
    text = payout_spec_text(fields, 4)
    terms = parse_payout_spec(text, ALICE)
    assert terms.sealed is True and terms.sequence_number == 4
    assert payout_spec_text(fields) != payout_spec_text(
        {k: v for k, v in fields.items() if k != "sealed"})
    with pytest.raises(PayoutShapeError, match="sealed must be true or left out"):
        parse_payout_spec(payout_spec_text({**fields, "sealed": False}, 4), ALICE)
