"""Golden post-state of the policy-setting txs (routed o5 user_tx, rule_offer,
rule_offer_accept) and a transfer, applied to a fixed parent.

Before approval slots activate, apply trusts sender_pubkey and ACCEPTS forged
policy txs; that is the documented behavior, and the first golden pins it.
The second golden pins a block of genuine txs on an activated chain. Keys,
signatures, tx ids and the block timestamp are fixed so the hashes are stable.
"""
import hashlib

from unittest.mock import patch
from py_ecc.bls import G2Basic

from block import Block
from consensus.approvals import STATUS_FAILED, ApprovalRequest
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.rule_offers import RuleOffer
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TIER_1 = 1000          # the fake policy blocks above this without slot 18


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)        # policy owner
SK_AUTH, AUTH = _key(22222)          # ALICE's approver
SK_BOB, BOB = _key(44444)
SK_STRANGER, STRANGER = _key(55555)  # signs the forgeries
SK_MALLORY, MALLORY = _key(66666)    # offerer and block proposer
SK_CAROL, CAROL = _key(77777)

NEUTRAL_RULE = "always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
ALLOW_OFFER_RULE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
GUARDED_RULE = (
    "always ( (i12[t]:bv[384] = { #x" + ALICE + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


def tier_body(approver):
    return (
        "( (i1[t]:bv[24] > { #x0003e8 }:bv[24] && "
        "!(i18[t]:bv[384] = { #x" + approver + " }:bv[384])) "
        "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )"
    )


def _sign(tx, sk):
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def _base(tx_id, tx_type, sender, seq):
    return {
        "tx_id": tx_id,
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
    }


def rule_tx(tx_id, rule, *, sender, seq, sk):
    tx = _base(tx_id, "user_tx", sender, seq)
    tx["operations"] = {"0": rule}
    return _sign(tx, sk)


def transfer_tx(tx_id, to, amount, *, sender, seq, sk):
    tx = _base(tx_id, "user_tx", sender, seq)
    tx["operations"] = {"1": [[sender, to, str(amount)]]}
    return _sign(tx, sk)


def offer_tx(tx_id, offer, *, seq, sk):
    tx = _base(tx_id, "rule_offer", offer.offerer_pubkey, seq)
    tx.update(recipient_pubkey=offer.recipient_pubkey, rule_text=offer.rule_text,
              expire_at_height=offer.expire_at_height)
    return _sign(tx, sk)


def accept_tx(tx_id, offer, *, sender, seq, sk):
    tx = _base(tx_id, "rule_offer_accept", sender, seq)
    tx.update(offer_id=offer.offer_id_hex, rule_text=offer.rule_text)
    return _sign(tx, sk)


def _apply(txs, lm, *, replay_mode=False):
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {ALICE: 100000, AUTH: 10, BOB: 0, CAROL: 0, MALLORY: 0},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(
        target_height=HEIGHT,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(MALLORY)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block = Block.create(block_number=HEIGHT, previous_hash="00" * 32, transactions=txs,
                         proposer_pubkey=MALLORY, timestamp=1234567890)

    # The live o5 composite: seeded from the registry, then whatever the block feeds.
    fed = [lm.rule_offers.composite_for_stream(5) or ""]
    persisted = []

    def _single(**kw):
        text = str(kw.get("rule_text") or "")
        if "always" in text:
            fed.append(text)
        if text and kw.get("apply_rules_update"):
            persisted.append(text.strip())
        return "T"

    def _multi(**kw):
        vals = kw.get("input_stream_values") or {}
        amount = int(str(vals.get(1, "0")) or 0)
        guarded = ALICE in str(vals.get(12, "")) and ALICE in fed[-1]
        blocked = guarded and amount > TIER_1 and AUTH not in str(vals.get(18, "0"))
        return {1: str(amount), 8: "0", 9: "0", 5: "0" if blocked else "1"}

    with patch("tau_manager.communicate_with_tau", side_effect=_single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
         patch("chain_state.get_application_rules_state",
               side_effect=lambda: "\n".join(persisted)), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = TauConsensusEngine().apply_block(
            view, block, parent, replay_mode=replay_mode)
    return result, result.next_snapshot.metadata["lifecycle_manager"]


def _logs(result, tx_id):
    return " | ".join(
        str(line) for o in result.outcomes if o.tx_id == tx_id for line in o.receipt_logs)


_NAMES = {ALICE: "alice", AUTH: "auth", BOB: "bob", CAROL: "carol", MALLORY: "mallory"}


def _summary(result, post):
    offers = post.rule_offers
    return {
        "state_hash": result.next_snapshot.state_hash,
        "accepted": sorted(result.accepted_tx_ids),
        "skipped": sorted(result.skipped_tx_ids),
        "invalid": sorted(result.invalid_tx_ids),
        "clauses": {_NAMES[who]: body for (who, _), body in offers.accepted_clauses.items()},
        "offers": sorted(offers.terminal_status.values()),
        "balances": {_NAMES[k]: v for k, v in
                     result.next_snapshot.metadata["balances"].items()},
    }


def _pre_activation_block():
    offer = RuleOffer(offerer_pubkey=MALLORY, recipient_pubkey=ALICE,
                      rule_text=ALLOW_OFFER_RULE, expire_at_height=500)
    txs = [
        rule_tx("forged-rule", GUARDED_RULE, sender=ALICE, seq=0, sk=SK_STRANGER),
        offer_tx("offer", offer, seq=0, sk=SK_MALLORY),
        accept_tx("forged-accept", offer, sender=ALICE, seq=1, sk=SK_STRANGER),
        transfer_tx("forged-transfer", MALLORY, 5, sender=ALICE, seq=2, sk=SK_STRANGER),
    ]
    return txs, ConsensusLifecycleManager(active_validators=[MALLORY])


def _post_activation_block():
    lm = ConsensusLifecycleManager(active_validators=[MALLORY])
    lm.activate_approval_slots()
    lm.rule_offers.accepted_clauses[(ALICE, 5)] = tier_body(AUTH)
    request = ApprovalRequest(sender_pubkey=ALICE, recipient_pubkey=BOB, amount=5000,
                              sequence_number=0, expire_at_height=500,
                              approvers={18: AUTH}, custom_inputs={})
    lm.approval_requests.submit_request(request)
    offer = RuleOffer(offerer_pubkey=MALLORY, recipient_pubkey=CAROL,
                      rule_text="always ( %s )." % tier_body(AUTH), expire_at_height=500)
    txs = [
        rule_tx("bob-clause", "always ( %s )." % tier_body(AUTH),
                sender=BOB, seq=0, sk=SK_BOB),
        rule_tx("alice-revoke", NEUTRAL_RULE, sender=ALICE, seq=0, sk=SK_ALICE),
        offer_tx("offer", offer, seq=0, sk=SK_MALLORY),
        accept_tx("carol-accept", offer, sender=CAROL, seq=0, sk=SK_CAROL),
        transfer_tx("small-transfer", BOB, 500, sender=ALICE, seq=1, sk=SK_ALICE),
    ]
    return txs, lm, request


PRE_ACTIVATION_HASH = "a1ddb5917868512919d39b6348be77b8b07556f67cd68703aa89ee0760a692a3"
POST_ACTIVATION_HASH = "983bfaf7d92c1b571cf03c06adf9a2441b65f2d20d854dd25a09cd7e1ce3d44c"


def test_pre_activation_forged_policy_txs_are_accepted_live_and_on_replay():
    """Before activation apply trusts sender_pubkey, so every forgery lands."""
    for replay_mode in (False, True):
        txs, lm = _pre_activation_block()
        result, post = _apply(txs, lm, replay_mode=replay_mode)
        assert _summary(result, post) == {
            "state_hash": PRE_ACTIVATION_HASH,
            "accepted": ["forged-accept", "forged-rule", "forged-transfer", "offer"],
            "skipped": [],
            "invalid": [],
            "clauses": {"alice": "o5[t]:bv[24] = { #x000001 }:bv[24]"},
            "offers": ["accepted"],
            "balances": {"alice": 99995, "auth": 10, "bob": 0, "carol": 0, "mallory": 5},
        }
        assert "Rule applied" in _logs(result, "forged-rule")


def test_post_activation_genuine_policy_txs_are_all_accepted():
    txs, lm, request = _post_activation_block()
    result, post = _apply(txs, lm)
    assert _summary(result, post) == {
        "state_hash": POST_ACTIVATION_HASH,
        "accepted": ["alice-revoke", "bob-clause", "carol-accept", "offer", "small-transfer"],
        "skipped": [],
        "invalid": [],
        "clauses": {"bob": tier_body(AUTH), "carol": tier_body(AUTH)},
        "offers": ["accepted"],
        "balances": {"alice": 99500, "auth": 10, "bob": 500, "carol": 0, "mallory": 0},
    }
    assert post.approval_requests.terminal_status[request.request_id] == STATUS_FAILED
