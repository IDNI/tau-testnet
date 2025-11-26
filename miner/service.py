from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, List, Optional

import block
import chain_state
import config
import db
from poa import mempool as mempool_utils
from poa.state import StateStore, TauStateSnapshot
from poa.tau_engine import MockTauEngine, TauEngine, TauExecutionResult

logger = logging.getLogger(__name__)


class SoleMiner:
    """
    Single-authority miner that monitors the local mempool and produces PoA blocks.
    """

    def __init__(
        self,
        *,
        threshold: int = 10,
        max_block_interval: float = 30.0,
        state_store: Optional[StateStore] = None,
        tau_engine: Optional[TauEngine] = None,
        mempool_loader: Optional[Callable[[], List[Dict]]] = None,
        block_committer: Optional[Callable[[block.Block], None]] = None,
    ) -> None:
        if not config.MINER_PRIVKEY:
            raise RuntimeError("SoleMiner requires MINER_PRIVKEY to be configured.")
        self._threshold = max(1, int(threshold))
        self._max_block_interval = max(1.0, float(max_block_interval))
        self._state_store = state_store or StateStore()
        self._tau_engine = tau_engine or MockTauEngine(self._state_store)
        self._load_mempool = mempool_loader or mempool_utils.load_transactions
        self._commit_block = block_committer or db.add_block
        self._lock = threading.Lock()
        self._last_mine_time = 0.0
        self._state_store.bootstrap_from_chain_state()

    def _next_block_position(self) -> tuple[int, str]:
        latest = db.get_latest_block()
        if not latest:
            return 0, "0" * 64
        header = latest.get("header", {})
        try:
            block_number = int(header.get("block_number") or 0) + 1
        except Exception:  # pragma: no cover - defensive
            block_number = 0
        return block_number, str(latest.get("block_hash") or "0" * 64)

    def _should_mine(self, pending: int) -> bool:
        if pending == 0:
            return False
        if pending >= self._threshold:
            return True
        return (time.time() - self._last_mine_time) >= self._max_block_interval

    def _build_state_locator(self, state_hash: str) -> str:
        namespace = getattr(config, "STATE_LOCATOR_NAMESPACE", "state")
        return f"{namespace}:{state_hash}"

    def try_mine(self) -> Optional[block.Block]:
        with self._lock:
            transactions = self._load_mempool()
            pending = len(transactions)
            if not self._should_mine(pending):
                logger.debug("SoleMiner: no mining action pending=%s threshold=%s", pending, self._threshold)
                return None
            snapshot = self._state_store.current_snapshot()
            tau_result = self._tau_engine.apply(snapshot, transactions)
            accepted = tau_result.accepted_transactions
            if not accepted:
                logger.info("SoleMiner: Tau engine rejected batch of %s tx; retry later", pending)
                return None
            block_number, previous_hash = self._next_block_position()
            locator = self._build_state_locator(tau_result.snapshot.state_hash)
            new_block = block.Block.create(
                block_number=block_number,
                previous_hash=previous_hash,
                transactions=accepted,
                state_hash=tau_result.snapshot.state_hash,
                state_locator=locator,
                signing_key_hex=config.MINER_PRIVKEY,
            )
            self._persist_block(new_block, tau_result)
            self._last_mine_time = time.time()
            logger.info(
                "SoleMiner: produced block #%s txs=%s state_hash=%s",
                block_number,
                len(accepted),
                tau_result.snapshot.state_hash[:12],
            )
            return new_block

    def _persist_block(self, new_block: block.Block, tau_result: TauExecutionResult) -> None:
        self._state_store.commit(tau_result.snapshot)
        self._commit_block(new_block)
        chain_state.commit_state_to_db(new_block.block_hash)
        mempool_utils.reconcile_with_block(new_block.to_dict())

    def current_state(self) -> TauStateSnapshot:
        return self._state_store.current_snapshot()

