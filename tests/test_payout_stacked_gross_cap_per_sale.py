"""Combined behaviour of the two stage-3-era bounds on one credit.

The gross-cap fix (issue #35: a credit is divided, never
multiplied) and the per-sale rules (stage 3) meet in the arrival
settlement: one credit steps every on-arrival rule of the owner
under a single shared budget of the gross credit, and a rule that
is also per_sale has the credit on its sale book, closed by the
settlement that pays it.

Scenario: the owner starts funded (an empty till would mask the
multiplication behind the staged-balance check). Two on-arrival
routes each pay 60% of the gross; the first is also per_sale. A
credit of 101 lands. The first route settles 60 (floored) -- all
the budget leaves for the second route is 41, so the second
settles nothing. The first route's sale, recorded at the credit
with amount 101, is closed by its settlement: no open sale
remains for an executor to name, and naming it is refused.
"""

from tests.test_payout_triggers import (
    ALICE, BOB, CAROL, MALLORY, PROPOSER,
    SK_ALICE, SK_BOB, Chain, _pct, transfer_tx,
)
from tests.test_payout_per_sale import _install, execute_tx
from tests.test_payout_arrival_gross_cap import _install_multi
from consensus.payouts import arrival_settlement_id, sale_settlement_id


def test_gross_budget_and_sale_closure_on_one_credit():
    ch = Chain({ALICE: 10_000, BOB: 1_000, CAROL: 0, MALLORY: 0,
                PROPOSER: 0})
    sale_terms = _install(ch, BOB, SK_BOB, height=20,
                          recipients=[CAROL],
                          extra={"per_sale": True, "on_arrival": True})
    _install_multi(ch, BOB, SK_BOB, height=20, seq=1,
                   recipients=[CAROL], extra={"on_arrival": True})
    ch.legs_fn = _pct(60)
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21)
    assert ch.accepted(tx), ch.receipt(tx)

    # The gross budget bound both routes: 60 settled in all on a
    # 101 credit, not 120 -- and the credit itself landed whole.
    assert ch.bal[CAROL] == 60
    assert ch.bal[BOB] == 1_000 + 101 - 60

    sale_state = ch.book.get_rule(BOB, sale_terms.rule_id)
    # The settling route recorded the sale and closed it in the
    # same apply: the arrival settlement and the sale marker are
    # its history, and no open sale remains.
    assert sale_state.settlements == [
        arrival_settlement_id(tx["tx_id"]),
        sale_settlement_id(sale_terms.rule_id, tx["tx_id"]),
    ]
    assert sale_state.sales == []
    assert sale_state.sales_missed == 0
    # The second route settled nothing and holds no settlement.
    others = [s for state in ch.book.rules_of(BOB)
              if state.terms.rule_id != sale_terms.rule_id
              for s in state.settlements]
    assert others == []

    # And the closed sale cannot be paid a second time by name.
    ex = execute_tx(settlement_id="late", rule_id=sale_terms.rule_id,
                    sale_id=tx["tx_id"])
    ch.block([ex], height=22)
    assert not ch.accepted(ex)
    assert ch.bal[CAROL] == 60
