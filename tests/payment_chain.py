"""Apply-block harness for programmable payments. Fee and policy are scripted."""
import hashlib
import itertools

from py_ecc.bls import G2Basic
from unittest.mock import patch

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_700_000_000
FAR = 9_999_999_999
CHAIN = "ab" * 32

_TX_SEQ = itertools.count()


def key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = key(11111)
SK_BOB, BOB = key(44444)
SK_CAROL, CAROL = key(55555)
SK_SAVE, SAVE = key(77777)
SK_REVIEW, REVIEW = key(88888)
PROPOSER = "d4" * 48


def sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def tx(tx_type: str, sender: str, seq: int, sk: int, **fields) -> dict:
    body = {
        "tx_id": f"{tx_type}-{next(_TX_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 100_000,
        "fee_limit": "0",
        "chain_id": CHAIN,
    }
    body.update(fields)
    return sign(body, sk)


class Chain:
    def __init__(self, balances, *, fee=0):
        self.bal = {PROPOSER: 0, **balances}
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.fee = fee
        self.last = None

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        return {1: str(vals.get(1, "0")), 8: "0", 9: str(self.fee), 5: "1"}

    def block(self, txs, height=HEIGHT, ts=TS, *, replay=False):
        parent = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": dict(self.bal),
                "sequence_numbers": dict(self.seq),
                "last_transfer_ts": dict(self.lts),
                "lifecycle_manager": self.lm,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
                "payments_chain_id": CHAIN,
            },
        )
        view = ActiveConsensusView(
            target_height=height,
            consensus_rules=parent.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ALICE)],
            mechanism_specific_metadata={"poa": True},
        )
        blk = Block.create(
            block_number=height, previous_hash="00" * 32, transactions=txs,
            proposer_pubkey=PROPOSER, timestamp=ts,
        )
        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=self._multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, blk, parent, replay_mode=replay)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        self.last = result
        return result

    @property
    def book(self):
        return self.lm.programmable

    def supply(self) -> int:
        return sum(self.bal.values()) + self.book.escrow_total()

    def receipt(self, index=0):
        tx_id = self.last.accepted_tx_ids[index] if self.last.accepted_tx_ids else None
        # Receipts are keyed inside the apply result's snapshot path. The
        # engine keeps them on the execution result, which apply_block folds
        # into outcomes. Prefer the outcome reason for rejections.
        return self.last.outcomes[index]
