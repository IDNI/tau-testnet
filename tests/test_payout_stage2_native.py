"""Payout stage 2, native evidence (Bounty 01): the six-leg #63
work escrow, the multi-rule book and the state-preserving update,
stepped by the real Tau interpreter.

Companion to tests/test_payout_stage2_apply.py (the same behaviors
against a scripted evaluator) and tests/test_payout_triggers_native.py
(stage 1's native file, whose harness this file reuses). The leg
amounts asserted here are the interpreter's own outputs on the
shipped TEMPLATE_WORK_ESCROW_CLAUSE and TEMPLATE_ROYALTY_5PCT_CLAUSE
texts, not a Python re-computation.

Gate: idiom A, as in the other native files. Locally every test
skips (the checked-in tau build targets a different Python than
the dev venv); the native CI job builds the matching module and
runs this file. Fees are the real genesis program's flat fee,
charged to each tx's sender; where a balance assertion needs a
fee it is measured off the proposer's balance, never assumed.
"""

import os

import pytest
from py_ecc.bls import G2Basic

import tau_manager
from consensus.payouts import (
    TEMPLATE_ROYALTY_5PCT_CLAUSE,
    TEMPLATE_WORK_ESCROW_CLAUSE,
    parse_payout_install,
)

from test_payout_triggers_native import (
    FAR,
    JAN1,
    NOW,
    Chain,
    _install_payout_clause,
    _key,
    _sign,
    execute_tx,
    install_tx,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENESIS_TAU = os.path.join(REPO_ROOT, "genesis.tau")
TRANSFER_RULE = os.path.join(REPO_ROOT, "rules", "04_handle_valid_transfer.tau")


def _native_available():
    try:
        import tau_native

        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built"
)


@pytest.fixture(autouse=True)
def live_tau():
    """Real engine behind tau_manager; identical seeding to the
    stage-1 native file."""
    import json

    import chain_state
    import tau_native

    iface = tau_native.TauInterface(GENESIS_TAU)
    old_iface = tau_manager.tau_direct_interface
    old_mode = tau_manager.tau_test_mode
    tau_manager.tau_direct_interface = iface
    tau_manager.tau_test_mode = False
    tau_manager.tau_ready.set()
    prev_rules_state = chain_state.get_application_rules_state()
    chain_state.save_application_rules_state("")
    with open(TRANSFER_RULE) as fh:
        tau_manager.communicate_with_tau(
            rule_text=fh.read(), target_output_stream_index=0,
            apply_rules_update=False, source="seed-transfer-rule",
        )
    with open(os.path.join(REPO_ROOT, "data", "genesis.json")) as fh:
        consensus_rules = json.load(fh)["consensus_rules"]
    tau_manager.communicate_with_tau(
        rule_text=chain_state._preprocess_tau_spec_text(consensus_rules),
        target_output_stream_index=0,
        apply_rules_update=False, source="seed-genesis-consensus",
    )
    yield iface
    tau_manager.tau_direct_interface = old_iface
    tau_manager.tau_test_mode = old_mode
    tau_manager.tau_ready.clear()
    chain_state.save_application_rules_state(prev_rules_state)


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
SK_DAVE, DAVE = _key(77777)
SK_ERIN, ERIN = _key(88888)
SK_FRANK, FRANK = _key(99999)
SK_GRACE, GRACE = _key(12121)
SK_HENRY, HENRY = _key(13131)
PROPOSER = "d4" * 48


def _balances():
    return {ALICE: 100_000, BOB: 0, CAROL: 0, DAVE: 10_000, ERIN: 0,
            FRANK: 0, GRACE: 0, HENRY: 0, PROPOSER: 0}


# --- F3: the #63 work escrow, named ---------------------------------------------


def test_the_work_escrow_pays_exactly_the_locked_price_on_every_path():
    """The #63 scenario as ONE execution of the shipped escrow
    clause: of the locked price, the worker takes 50%, each of two
    reviewers 10%, the defect bounty 10%, the poster takes back a
    15% remainder and 5% is held back. On a price divisible by 100
    the six legs sum to the price exactly; on any other price every
    leg floors and the dust stays with the poster."""
    ch = Chain(_balances())
    _install_payout_clause(ch, ALICE, TEMPLATE_WORK_ESCROW_CLAUSE)
    install = install_tx(
        owner=ALICE, sk=SK_ALICE,
        recipients=[BOB, CAROL, ERIN, FRANK, GRACE, HENRY],
        max_per_execution=10000, max_per_period=20000)
    ch.block([install], height=20, ts=NOW)
    assert ch.accepted(install), ch.receipt(install)
    install_fee = ch.bal[PROPOSER]

    ex = execute_tx(executor=DAVE, sk=SK_DAVE, seq=0,
                    settlement_id="escrow-1", gross=10000)
    ch.block([ex], height=21, ts=NOW)
    assert ch.accepted(ex), ch.receipt(ex)
    assert ch.bal[BOB] == 5000      # worker, 50%
    assert ch.bal[CAROL] == 1000    # reviewer A, 10%
    assert ch.bal[ERIN] == 1000     # reviewer B, 10%
    assert ch.bal[FRANK] == 1000    # defect bounty, 10%
    assert ch.bal[GRACE] == 1500    # poster remainder, 15%
    assert ch.bal[HENRY] == 500     # warranty holdback, 5%
    assert ch.bal[ALICE] == 100_000 - install_fee - 10000

    ex2 = execute_tx(executor=DAVE, sk=SK_DAVE, seq=1,
                     settlement_id="escrow-2", gross=999)
    ch.block([ex2], height=22, ts=NOW)
    assert ch.accepted(ex2), ch.receipt(ex2)
    assert ch.bal[BOB] == 5000 + 499
    assert ch.bal[CAROL] == 1000 + 99
    assert ch.bal[ERIN] == 1000 + 99
    assert ch.bal[FRANK] == 1000 + 99
    assert ch.bal[GRACE] == 1500 + 149
    assert ch.bal[HENRY] == 500 + 49
    # 499+99+99+99+149+49 = 994: five units of dust stayed with
    # the poster; no leg rounded up.
    assert ch.bal[ALICE] == 100_000 - install_fee - 10000 - 994


# --- F1: two rules, one account, one clause ---------------------------------------


def test_two_rules_share_a_clause_but_not_a_budget_native():
    ch = Chain(_balances())
    _install_payout_clause(ch, ALICE, TEMPLATE_ROYALTY_5PCT_CLAUSE)
    small = install_tx(owner=ALICE, sk=SK_ALICE, seq=0,
                       recipients=[BOB], max_per_execution=4)
    ch.block([small], height=20, ts=NOW)
    assert ch.accepted(small), ch.receipt(small)
    big = install_tx(owner=ALICE, sk=SK_ALICE, seq=1,
                     recipients=[BOB], max_per_execution=1000)
    ch.block([big], height=21, ts=NOW)
    assert ch.accepted(big), ch.receipt(big)
    small_id = parse_payout_install(small).rule_id
    big_id = parse_payout_install(big).rule_id
    assert small_id != big_id

    # The royalty leg on 101 is 5: over the small rule's cap,
    # inside the big rule's. Naming decides; guessing is refused.
    over = execute_tx(executor=DAVE, sk=SK_DAVE, seq=0,
                      settlement_id="s-small", gross=101,
                      extra={"rule_id": small_id})
    ch.block([over], height=22, ts=NOW)
    assert not ch.accepted(over)
    unnamed = execute_tx(executor=DAVE, sk=SK_DAVE, seq=0,
                         settlement_id="s-noname", gross=101)
    ch.block([unnamed], height=23, ts=NOW)
    assert not ch.accepted(unnamed)
    ok = execute_tx(executor=DAVE, sk=SK_DAVE, seq=0,
                    settlement_id="s-big", gross=101,
                    extra={"rule_id": big_id})
    ch.block([ok], height=24, ts=NOW)
    assert ch.accepted(ok), ch.receipt(ok)
    assert ch.bal[BOB] == 5
    book = ch.payout_book
    assert book.get_rule(ALICE, big_id).settlements == ["s-big"]
    assert book.get_rule(ALICE, small_id).settlements == []


# --- F2: the update, natively -------------------------------------------------------


def _update_tx(old_id, *, seq=1, terms_seq=2):
    tx = {
        "tx_id": "payout-update-native-0",
        "tx_type": "payout_rule_update",
        "sender_pubkey": ALICE,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "rule_id": old_id,
        "terms_sequence_number": terms_seq,
        "max_per_execution": 2000,
        "max_per_period": 2500,
        "recipients": [BOB, CAROL],
        "period_kind": 2,
        "anchor_ts": JAN1,
    }
    return _sign(tx, SK_ALICE)


def test_an_update_preserves_settlements_and_period_spend_native():
    ch = Chain(_balances())
    _install_payout_clause(ch, ALICE, TEMPLATE_ROYALTY_5PCT_CLAUSE)
    install = install_tx(owner=ALICE, sk=SK_ALICE, seq=0,
                         recipients=[BOB, CAROL])
    ch.block([install], height=20, ts=NOW)
    assert ch.accepted(install), ch.receipt(install)
    old_id = parse_payout_install(install).rule_id

    ex = execute_tx(executor=DAVE, sk=SK_DAVE, seq=0,
                    settlement_id="s1", gross=101)
    ch.block([ex], height=21, ts=NOW)
    assert ch.accepted(ex), ch.receipt(ex)
    assert ch.bal[BOB] == 5

    upd = _update_tx(old_id)
    ch.block([upd], height=22, ts=NOW)
    assert ch.accepted(upd), ch.receipt(upd)
    state = ch.payout_book.get(ALICE)
    assert state.version == 2
    assert state.lineage == [old_id]
    assert state.settlements == ["s1"]
    assert state.spent_in_period == 5
    assert state.paid_total == 5

    replay = execute_tx(executor=DAVE, sk=SK_DAVE, seq=1,
                        settlement_id="s1", gross=101)
    ch.block([replay], height=23, ts=NOW)
    assert not ch.accepted(replay)
    assert ch.bal[BOB] == 5

    ex2 = execute_tx(executor=DAVE, sk=SK_DAVE, seq=1,
                     settlement_id="s2", gross=202)
    ch.block([ex2], height=24, ts=NOW)
    assert ch.accepted(ex2), ch.receipt(ex2)
    assert ch.bal[BOB] == 5 + 10
