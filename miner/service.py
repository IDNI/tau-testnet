from __future__ import annotations

import logging
import threading
import time
from typing import Optional

import config
import db
from commands import createblock
from network import bus as network_bus

logger = logging.getLogger(__name__)


class SoleMiner:
    """
    Single-authority miner that monitors the local mempool and produces PoA blocks.
    Delegates block creation logic to commands.createblock to ensure consistency
    with manual block creation.
    """

    def __init__(
        self,
        *,
        threshold: int = 10,
        max_block_interval: float = 30.0,
    ) -> None:
        if not config.MINER_PRIVKEY:
            raise RuntimeError("SoleMiner requires MINER_PRIVKEY to be configured.")
        self._threshold = max(1, int(threshold))
        self._max_block_interval = max(1.0, float(max_block_interval))
        self._lock = threading.Lock()
        self._last_mine_time = time.time()  # Initialize to avoid immediate mine on startup

    def _should_mine(self) -> bool:
        pending = db.count_mempool_txs()
        if pending == 0:
            return False
        if pending >= self._threshold:
            return True
        return (time.time() - self._last_mine_time) >= self._max_block_interval

    def try_mine(self) -> None:
        with self._lock:
            if not self._should_mine():
                return

            try:
                # Delegate to createblock logic
                # This handles validation, execution, state locking, DB commit, and DHT publishing
                block_data = createblock.create_block_from_mempool()
                
                # Check if a block was actually created (createblock returns dict with block_hash on success)
                if isinstance(block_data, dict) and "block_hash" in block_data:
                    block_num = block_data.get("header", {}).get("block_number", "?")
                    block_hash = block_data.get("block_hash", "")[:12]
                    logger.info("SoleMiner: produced block #%s hash=%s", block_num, block_hash)
                    
                    self._last_mine_time = time.time()
                    
                    # Gossip the new block
                    svc = network_bus.get()
                    if svc:
                        logger.info("SoleMiner: broadcasting block #%s", block_num)
                        svc.broadcast_block(block_data)
                    else:
                        logger.warning("SoleMiner: network service not available; block not broadcasted.")
                else:
                    # No block created (e.g. all txs invalid). 
                    # We don't update _last_mine_time so we check again on next loop 
                    # (but invalid txs should have been removed by createblock)
                    pass

            except Exception:
                logger.exception("SoleMiner: Error during mining attempt")

    def start(self) -> None:
        """Starts the background mining loop."""
        if hasattr(self, "_mining_thread") and self._mining_thread.is_alive():
            logger.warning("SoleMiner already running.")
            return

        self._stop_event = threading.Event()
        self._mining_thread = threading.Thread(target=self._mining_loop, name="SoleMinerLoop", daemon=True)
        self._mining_thread.start()
        logger.info("SoleMiner started.")

    def stop(self) -> None:
        """Stops the background mining loop."""
        if hasattr(self, "_stop_event"):
            self._stop_event.set()
        if hasattr(self, "_mining_thread") and self._mining_thread.is_alive():
            self._mining_thread.join(timeout=5.0)
            if self._mining_thread.is_alive():
                logger.warning("SoleMiner thread did not stop gracefully.")
            else:
                logger.info("SoleMiner stopped.")

    def _mining_loop(self) -> None:
        """Internal loop that attempts to mine blocks periodically."""
        logger.info("SoleMiner background loop active. Threshold=%s, Interval=%s", self._threshold, self._max_block_interval)
        while not self._stop_event.is_set():
            try:
                self.try_mine()
            except Exception:
                logger.exception("SoleMiner: Error in mining loop")
            
            # Sleep in short bursts to allow quick shutdown
            for _ in range(10): 
                if self._stop_event.is_set(): 
                    break
                time.sleep(0.1)

