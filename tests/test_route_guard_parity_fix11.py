"""Bounty 01, FIX 11: receive routes judged by the rule-change guard.

The defensive audit of 2026-11-25 (AUDIT-OWN-ERRNEX-CLASS) proved the
errnex #128 class on our own FIX 9 line: a rule-change guard that
blocks every direct change refused a standing create, yet one
signature installed a 9000 bps receive route past it, a payment of
1000 credited the route destination 900, and one signature removed
the route again — install/remove never consulted the guard, because
no guard kind existed for routes. FIX 5B had closed the same class
for payout and standing (kinds 7..12) and left routes out of scope.

FIX 11 adds kinds 13 (SET_RECEIVE_ROUTE), 14 (UPDATE_RECEIVE_ROUTE)
and 15 (REMOVE_RECEIVE_ROUTE) and consults the owner's guard at
admission and at apply, mirroring the standing doors step for step.
These tests pin: the audit PoC now fails at both doors; an account
with no guard keeps the exact old lifecycle; and the guard is fed
each door's own kind, so a guard may block one door and allow
another.
"""
import hashlib
import itertools
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

import tau_defs
from block import Block
from consensus import sender_policy
from consensus.admission import (
    validate_install_receive_route_payload,
    validate_remove_receive_route_payload,
)
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.facade import TipAdmissionView
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_800_000_000
FEE = 7

_ON = "{ 1 }:bv[24]"
_OFF = "{ 0 }:bv[24]"
GUARD_TEXT = (
    "always ( (i18[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]) ? "
    f"{_ON} : {_OFF} )."
)
GUARD_BODY = GUARD_TEXT[len("always ( "):-3]


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)      # proposer / sole validator
SK_BOB, BOB = _key(44444)          # guarded account (the victim)
SK_CAROL, CAROL = _key(77777)      # payer into BOB
SK_MALLORY, MALLORY = _key(88888)  # route destination

_TX_SEQ = itertools.count()


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _lm(guard=False):
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.activate_approval_slots()
    if guard:
        lm.rule_offers.accepted_clauses[
            (BOB, tau_defs.RULE_CHANGE_GUARD_INDEX)] = GUARD_BODY
    return lm


class _Chain:
    def __init__(self, balances, lm=None, ts=TS):
        self.balances = dict(balances)
        self.sequences = {}
        self.lm = lm if lm is not None else _lm()
        self.ts = ts
        self.height = HEIGHT

    def apply(self, txs, fee=FEE):
        parent = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": dict(self.balances),
                "sequence_numbers": dict(self.sequences),
                "last_transfer_ts": {},
                "lifecycle_manager": self.lm,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )
        view = ActiveConsensusView(
            target_height=self.height,
            consensus_rules=parent.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ALICE)],
            mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
        )
        block = Block.create(
            block_number=self.height, previous_hash="00" * 32,
            transactions=txs, proposer_pubkey=ALICE, timestamp=self.ts,
        )

        def _fake_multi(**kwargs):
            vals = kwargs.get("input_stream_values") or {}
            amount = int(str(vals.get(1, "0")) or 0)
            return {1: str(amount), 8: "0", 9: str(fee), 5: "1"}

        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, block, parent)
        md = result.next_snapshot.metadata
        self.balances = md["balances"]
        self.sequences = md["sequence_numbers"]
        self.lm = md["lifecycle_manager"]
        self.height += 1
        return result


def _install_route_tx(owner, sk, destination, bps, seq, version=1):
    return _sign({
        "tx_id": f"route-{next(_TX_SEQ)}",
        "tx_type": "install_receive_route",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "route_destination_pubkey": destination,
        "route_bps": bps,
        "route_min_amount": 0,
        "route_activation_ts": 0,
        "route_expiry_ts": 0,
        "route_locked_until_ts": 0,
        "route_version": version,
    }, sk)


def _remove_route_tx(owner, sk, seq):
    return _sign({
        "tx_id": f"unroute-{next(_TX_SEQ)}",
        "tx_type": "remove_receive_route",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
    }, sk)


def _transfer(sender, sk, to, amount, seq):
    return _sign({
        "tx_id": f"tr-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"1": [[sender, to, str(amount)]]},
    }, sk)


def _receipt_reasons(result):
    reasons = []
    for outcome in result.outcomes:
        reasons.extend(str(x) for x in (outcome.receipt_logs or []))
        reason = getattr(outcome, "reason", None)
        if reason:
            reasons.append(str(reason))
    return " | ".join(reasons)


def _script_guard(verdict_fn):
    """Serve `verdict_fn(inputs) -> "0"|"1"` for the guard body in both
    pools ("0" blocks: the guard's o5 comes back 0)."""
    for pool in ("apply", "admission"):
        ev = MockPolicyEvaluator(pool=pool)
        ev.set_verdict(GUARD_BODY, verdict_fn)
        sender_policy.set_evaluator(pool, ev)


def _block_all(inputs):
    # The PoC's guard: a change is allowed only once approval slot i18
    # is filled; a direct transaction carries no vote, so it blocks.
    return "0" if inputs.get("i18", "0") == "0" else "1"


@pytest.fixture(autouse=True)
def _reset_pools():
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)


def _balances():
    return {ALICE: 0, BOB: 100000, CAROL: 100000, MALLORY: 0}


# --- apply: the audit PoC, flipped --------------------------------------


def test_guard_blocks_route_install_and_the_payment_never_splits():
    _script_guard(_block_all)
    chain = _Chain(_balances(), lm=_lm(guard=True))
    install = _install_route_tx(BOB, SK_BOB, MALLORY, 9000, seq=0)
    result = chain.apply([install])
    assert install["tx_id"] not in result.accepted_tx_ids
    assert "rule-change guard blocks" in _receipt_reasons(result)
    assert chain.lm.receive_routes.active_route(BOB, TS) is None
    # No route: a payment of 1000 to BOB stays BOB's, in full.
    pay = _transfer(CAROL, SK_CAROL, BOB, 1000, seq=0)
    result = chain.apply([pay])
    assert pay["tx_id"] in result.accepted_tx_ids
    assert chain.balances[MALLORY] == 0
    assert chain.balances[BOB] == 100000 + 1000


def test_guard_blocks_removal_of_a_route_installed_before_the_guard():
    _script_guard(_block_all)
    chain = _Chain(_balances(), lm=_lm(guard=False))
    install = _install_route_tx(BOB, SK_BOB, MALLORY, 9000, seq=0)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    # The account registers its guard afterwards; removal now judges it.
    chain.lm.rule_offers.accepted_clauses[
        (BOB, tau_defs.RULE_CHANGE_GUARD_INDEX)] = GUARD_BODY
    remove = _remove_route_tx(BOB, SK_BOB, seq=1)
    result = chain.apply([remove])
    assert remove["tx_id"] not in result.accepted_tx_ids
    assert "rule-change guard blocks" in _receipt_reasons(result)
    assert chain.lm.receive_routes.active_route(BOB, TS) is not None


def test_guard_is_fed_each_doors_own_kind():
    # A guard that blocks only REMOVE (kind 15): install lands.
    _script_guard(lambda inputs: "0" if inputs.get("i1") == "15" else "1")
    chain = _Chain(_balances(), lm=_lm(guard=True))
    install = _install_route_tx(BOB, SK_BOB, MALLORY, 9000, seq=0)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    remove = _remove_route_tx(BOB, SK_BOB, seq=1)
    result = chain.apply([remove])
    assert remove["tx_id"] not in result.accepted_tx_ids
    assert chain.lm.receive_routes.active_route(BOB, TS) is not None

    # A guard that blocks only UPDATE (kind 14): the first install
    # lands, its replacement does not.
    _script_guard(lambda inputs: "0" if inputs.get("i1") == "14" else "1")
    chain = _Chain(_balances(), lm=_lm(guard=True))
    install = _install_route_tx(BOB, SK_BOB, MALLORY, 9000, seq=0)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    replace = _install_route_tx(BOB, SK_BOB, MALLORY, 5000, seq=1, version=2)
    result = chain.apply([replace])
    assert replace["tx_id"] not in result.accepted_tx_ids
    route = chain.lm.receive_routes.active_route(BOB, TS)
    assert route is not None and route.bps == 9000


# --- apply: the unguarded lifecycle is unchanged -------------------------


def test_unguarded_route_lifecycle_is_unchanged():
    chain = _Chain(_balances(), lm=_lm(guard=False))
    install = _install_route_tx(BOB, SK_BOB, MALLORY, 9000, seq=0)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    pay = _transfer(CAROL, SK_CAROL, BOB, 1000, seq=0)
    result = chain.apply([pay])
    assert pay["tx_id"] in result.accepted_tx_ids
    assert chain.balances[MALLORY] == 900
    assert chain.balances[BOB] == 100000 - FEE + 100
    remove = _remove_route_tx(BOB, SK_BOB, seq=1)
    result = chain.apply([remove])
    assert remove["tx_id"] in result.accepted_tx_ids
    assert chain.lm.receive_routes.active_route(BOB, TS) is None


# --- admission agrees with apply ------------------------------------------


class _View(TipAdmissionView):
    def __init__(self, chain):
        self._chain = chain

    @property
    def next_block_timestamp(self):
        return self._chain.ts

    def clause_for(self, who, idx):
        return self._chain.lm.rule_offers.accepted_clauses.get((who, idx))

    def get_receive_route(self, owner_pubkey):
        entry = self._chain.lm.receive_routes.get(owner_pubkey)
        if entry is None:
            return None
        return {
            "route_id": entry.route_id.hex(),
            "owner_pubkey": entry.owner_pubkey,
            "destination_pubkey": entry.destination_pubkey,
            "bps": entry.bps,
            "min_amount": entry.min_amount,
            "activation_ts": entry.activation_ts,
            "expiry_ts": entry.expiry_ts,
            "locked_until_ts": entry.locked_until_ts,
            "version": entry.version,
            "form": entry.form,
            "clause_text": entry.clause_text,
        }


def test_admission_refuses_install_and_remove_when_the_guard_blocks():
    _script_guard(_block_all)
    chain = _Chain(_balances(), lm=_lm(guard=False))
    install = _install_route_tx(BOB, SK_BOB, MALLORY, 9000, seq=0)
    # Unguarded: admission lets the install through.
    admitted = validate_install_receive_route_payload(install, _View(chain))
    assert admitted.is_valid
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    # Guarded now: admission refuses the removal with the shared code.
    chain.lm.rule_offers.accepted_clauses[
        (BOB, tau_defs.RULE_CHANGE_GUARD_INDEX)] = GUARD_BODY
    remove = _remove_route_tx(BOB, SK_BOB, seq=1)
    admitted = validate_remove_receive_route_payload(remove, _View(chain))
    assert not admitted.is_valid
    assert admitted.code == "RULE_CHANGE_NEEDS_APPROVAL"
    # And a fresh install (a replacement, kind 14) is refused as well.
    replace = _install_route_tx(BOB, SK_BOB, MALLORY, 5000, seq=1, version=2)
    admitted = validate_install_receive_route_payload(replace, _View(chain))
    assert not admitted.is_valid
    assert admitted.code == "RULE_CHANGE_NEEDS_APPROVAL"
