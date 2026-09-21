"""
createblock.py

Command handler for creating a new block from the current mempool.
"""

import json
import time
from typing import List, Dict
import db
import block
import chain_state
import config
from consensus.state import compute_state_hash
from consensus.lanes import TAU_EVALUATING_TX_TYPES


import tau_manager
import tau_shrink
from tau_manager import parse_tau_output
import tau_defs
import logging
import api_response

logger = logging.getLogger(__name__)

# Try import optional crypto dependencies
try:
    from py_ecc.bls import G2Basic
    _BLS_AVAILABLE = True
except ImportError:
    _BLS_AVAILABLE = False


def _validate_signature(payload: Dict) -> bool:
    """
    Validates the BLS signature of the transaction.
    """
    # Strict BLS: if library missing, cannot validate -> fail.
    # We expect _BLS_AVAILABLE to be checked by caller too, but good to be safe.
    if not _BLS_AVAILABLE:
        return False 
        
    sender_pubkey = payload.get('sender_pubkey')
    signature = payload.get('signature')
    
    if not sender_pubkey or not signature:
        return False
        
    try:
        # Reconstruct signing message
        signing_dict = {
            "sender_pubkey": sender_pubkey,
            "sequence_number": payload.get('sequence_number'),
            "expiration_time": payload.get('expiration_time'),
            "operations": payload.get('operations'),
            "fee_limit": payload.get('fee_limit'),
        }
        msg_bytes = json.dumps(signing_dict, sort_keys=True, separators=(",", ":")).encode()
        msg_hash = import_hashlib().sha256(msg_bytes).digest()
        
        pubkey_bytes = bytes.fromhex(sender_pubkey)
        sig_bytes = bytes.fromhex(signature)
        
        return G2Basic.Verify(pubkey_bytes, msg_hash, sig_bytes)
    except Exception:
        return False

def import_hashlib():
    import hashlib
    return hashlib




def execute_batch(transactions: List[Dict], reserved_ids: List[int], block_timestamp: int):
    """
    Compatibility helper used by tests to simulate a batch over the current
    in-memory chain state without persisting a block.
    """
    from copy import deepcopy
    from consensus.engine import TauConsensusEngine
    from consensus.state import TauStateSnapshot, compute_consensus_state_hash
    from chain_state import compute_accounts_hash

    latest_block = db.get_canonical_head_block()
    block_number = (latest_block['header']['block_number'] + 1) if latest_block else 0

    app_rules = (chain_state._application_rules_state or "").encode('utf-8')
    cons_rules = (chain_state._consensus_rules_state or "").encode('utf-8')
    acc_hash = compute_accounts_hash(chain_state._balances, chain_state._sequence_numbers)
    meta_hash = chain_state._lifecycle_manager.consensus_meta_hash()
    state_hash = compute_consensus_state_hash(cons_rules, app_rules, acc_hash, meta_hash)

    parent_snapshot = TauStateSnapshot(
        state_hash=state_hash,
        tau_bytes=app_rules,
        metadata={
            "source": "chain_state",
            "balances": chain_state._balances,
            "sequence_numbers": chain_state._sequence_numbers,
            "lifecycle_manager": chain_state._lifecycle_manager,
        }
    )

    working_balances = deepcopy(chain_state._balances)
    working_sequences = deepcopy(chain_state._sequence_numbers)
    working_lifecycle = deepcopy(chain_state._lifecycle_manager)

    for tx in transactions:
        operations = tx.get("operations", {}) if isinstance(tx, dict) else {}
        transfers = operations.get("1") if isinstance(operations, dict) else None
        if not isinstance(transfers, list) or not transfers:
            continue
        custom_inputs: dict[int, list[str]] = {}
        for key, value in operations.items():
            if not isinstance(key, str) or not key.isdigit():
                continue
            idx = int(key)
            if idx in (0, 1):
                continue
            if isinstance(value, (str, int)):
                custom_inputs[idx] = [str(value)]
            elif isinstance(value, (list, tuple)):
                custom_inputs[idx] = [str(item) for item in value]
        try:
            from_addr, to_addr, amount = transfers[0]
            tau_input_stream_values = {
                1: str(amount),
                2: str(working_balances.get(str(from_addr), chain_state.get_balance(str(from_addr)))),
                # Real from/to pubkeys so the interpreter's sticky per-stream bv
                # width is warmed identically to engine.apply (avoids a mid-build
                # width re-exec). Results here are discarded; apply_block is
                # authoritative.
                3: "{ #x" + str(from_addr) + " }:bv[384]",
                4: "{ #x" + str(to_addr) + " }:bv[384]",
                5: str(block_timestamp),
            }
            tau_input_stream_values.update(custom_inputs)
            tau_manager.communicate_with_tau_multi(
                input_stream_values=tau_input_stream_values,
                apply_rules_update=False,
            )
        except Exception:
            pass

    engine = TauConsensusEngine()
    exec_result = engine.apply(
        parent_snapshot,
        transactions,
        block_timestamp,
        target_balances=working_balances,
        target_sequences=working_sequences,
        target_lifecycle=working_lifecycle,
    )

    accepted = {id(tx) for tx in exec_result.accepted_transactions}
    final_txs = []
    final_reserved_ids = []
    for tx, reserved_id in zip(transactions, reserved_ids):
        if id(tx) in accepted:
            final_txs.append(tx)
            final_reserved_ids.append(reserved_id)

    final_rules = exec_result.snapshot.tau_bytes.decode('utf-8', errors='ignore')
    return final_txs, final_reserved_ids, final_rules, working_balances, working_sequences


def _drop_sequence_gap_orphans(transactions, execution_transactions, reserved_ids):
    """Remove txs whose sender has a LOWER-sequence tx still waiting outside
    this batch.

    Lane quotas make this reachable: seq 5 is rule-bearing and sits in the
    capped slow lane while seq 6 is a transfer and gets selected. The engine's
    per-sender sequence check then hard-rejects seq 6 and it is disposed with
    the block, i.e. silently destroyed rather than retried. Dropping it here
    leaves it in the mempool to be mined once its predecessor lands.

    Returns the reserved ids that were dropped, so the caller can unreserve
    them. All three lists are mutated in lockstep.
    """
    min_included: Dict[str, int] = {}
    for tx in transactions:
        if not isinstance(tx, dict):
            continue
        sender = tx.get("sender_pubkey")
        seq = tx.get("sequence_number")
        if not sender or not isinstance(seq, int):
            continue
        if sender not in min_included or seq < min_included[sender]:
            min_included[sender] = seq

    orphan_senders = set()
    for sender, included_min in min_included.items():
        try:
            pending_min = db.get_min_pending_sequence(sender)
        except Exception:
            continue
        if pending_min is not None and pending_min < included_min:
            orphan_senders.add(sender)

    if not orphan_senders:
        return []

    dropped_ids = []
    for i in range(len(transactions) - 1, -1, -1):
        tx = transactions[i]
        if isinstance(tx, dict) and tx.get("sender_pubkey") in orphan_senders:
            dropped_ids.append(reserved_ids[i])
            del transactions[i]
            del execution_transactions[i]
            del reserved_ids[i]

    if dropped_ids:
        print(
            f"[INFO][createblock] Deferred {len(dropped_ids)} tx(s) from "
            f"{len(orphan_senders)} sender(s) with an earlier sequence still queued"
        )
        try:
            db.unreserve_mempool_txs(dropped_ids)
        except Exception:
            pass
    return dropped_ids


def _restore_per_sender_sequence_order(transactions, execution_transactions, reserved_ids):
    """
    reserve_mempool_txs orders by fee priority, which can place a sender's
    later-sequence tx before an earlier one; the engine would then
    hard-reject it for sequence mismatch and it would be disposed with the
    block. Rearrange each sender's txs into ascending sequence_number
    within the slots that sender already occupies; the global fee-priority
    slot assignment is preserved. All three lists are mutated in lockstep.
    """
    by_sender: Dict[str, list] = {}
    for i, tx in enumerate(transactions):
        if isinstance(tx, dict) and tx.get("sender_pubkey"):
            by_sender.setdefault(tx["sender_pubkey"], []).append(i)
    for idxs in by_sender.values():
        if len(idxs) < 2:
            continue
        bundles = sorted(
            ((transactions[i], execution_transactions[i], reserved_ids[i]) for i in idxs),
            key=lambda b: b[0].get("sequence_number")
            if isinstance(b[0].get("sequence_number"), int) else 0,
        )
        for slot, (tx, etx, rid) in zip(idxs, bundles):
            transactions[slot] = tx
            execution_transactions[slot] = etx
            reserved_ids[slot] = rid




def _program_baseline():
    """The interpreter's starting spec: the program file the node boots from."""
    import os as _os
    path = getattr(config, "TAU_PROGRAM_FILE", None) or "genesis.tau"
    if not _os.path.isabs(path):
        path = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), path)
    try:
        with open(path) as fh:
            text = fh.read().strip()
    except Exception:
        return None
    if not text:
        return None
    return text if text.lstrip().startswith("always") else f"always ( {text} )."


def _speculative_session():
    """A disposable evaluator for the miner simulation, or None to stay in-process.

    None whenever there is nothing to isolate from -- mock mode, no native
    interface -- or when a worker cannot be built. Falling back is safe: it is
    exactly today's behaviour, including its save/restore.
    """
    try:
        import tau_manager
        import tau_session
    except Exception:
        return None
    if getattr(tau_manager, "tau_test_mode", False):
        return None
    iface = getattr(tau_manager, "tau_direct_interface", None)
    if iface is None:
        return None
    # Seeding matters more than it looks. A worker loaded with the CURRENT
    # composed spec is measurably MORE PERMISSIVE than the authoritative
    # interpreter: a stream typed by a rule that has since been superseded keeps
    # its commitment, and that commitment is invisible in the spec text. Measured
    # -- authoritative REJECTED_RULE, fresh-from-spec ACCEPTED_CHANGED for the
    # same candidate. A miner simulating on the permissive one would put a
    # transaction in a block that the authoritative re-apply then rejects, and the
    # block would fail on its state hash.
    #
    # So the worker is built by REPLAYING the accepted units in order, which
    # re-establishes the same commitments (pinned by the replay-fidelity tests),
    # rather than by loading the text they left behind.
    try:
        import chain_state as _chain_state
        plan = _chain_state.get_tau_restore_plan()
    except Exception as exc:
        logger.warning("createblock: no restore plan for the simulation worker (%s)", exc)
        return None
    units = [str(step.get("text") or "") for step in (plan or []) if str(step.get("text") or "").strip()]
    # The plan is a list of i0 updates to apply AFTER the interpreter has been
    # initialized from the program file -- it does not include the router itself.
    # Seeding from its first unit instead leaves the worker with no i0 stream at
    # all, so every revision comes back INCOMPLETE and every rule looks rejected.
    baseline = _program_baseline()
    if not baseline:
        return None
    trace = [{"kind": tau_session.RULE, "rule_text": unit} for unit in units]
    # The baseline is the RUNTIME spec, so the worker needs runtime-encoded
    # inputs: the same encoder the authoritative path uses, against the same
    # node-local intern table.
    shrunk = tau_manager.get_runtime_shrunk_streams()

    def normalize(inputs):
        return tau_manager._normalize_inputs(inputs, shrunk) or inputs

    try:
        return tau_session.WorkerSession.spawn(baseline, trace=trace, normalize=normalize)
    except Exception as exc:
        logger.warning("createblock: no simulation worker (%s); simulating in-process", exc)
        return None


def create_block_from_mempool(allow_empty: bool = False) -> Dict:
    """
    Creates a new block from all transactions currently in the mempool,
    saves it to the database, and clears the mempool.

    The whole round -- head read, eligibility, mempool reservation, Tau
    simulation, signing and persistence -- runs under `chain_state._chain_lock`.
    Two producers that each read the same head build competing blocks at one
    height, and the loser cannot persist: it collides on the block-hash primary
    key, trips the state-hash invariant, or is routed to the orphan path. The
    lock is taken with `config.BLOCK_PRODUCTION_LOCK_TIMEOUT` (0 = try-lock), so
    a second producer returns MINING_BUSY immediately instead of parking an RPC
    connection thread for the length of a round.

    `allow_empty` opts in to sealing a block with no transactions, which is how
    callers advance height to a governance activation boundary. It is off by
    default: a caller polling `createblock` would otherwise mint an unbounded
    run of empty blocks.
    """
    print(f"[INFO][createblock] Starting block creation process...")

    if not config.MINER_PRIVKEY:
        print("[ERROR][createblock] PoA mining requires MINER_PRIVKEY to be configured.")
        msg = "PoA mining requires a configured miner key."
        return {"error": msg, "message": msg}

    if not _BLS_AVAILABLE:
        print("[ERROR][createblock] BLS signing not available; cannot sign PoA block.")
        msg = "BLS signing is required for PoA blocks."
        return {"error": msg, "message": msg}

    with chain_state.chain_write_lock(
        timeout=getattr(config, "BLOCK_PRODUCTION_LOCK_TIMEOUT", 0.0)
    ) as acquired:
        if not acquired:
            msg = f"{_BUSY_PREFIX}; skipping this round."
            print(f"[INFO][createblock] {msg}")
            return {"message": msg}
        return _create_block_locked(allow_empty=allow_empty)


def _create_block_locked(allow_empty: bool = False) -> Dict:
    """`create_block_from_mempool` body. Callers must hold the chain-write lock."""
    # Ensure early turn-check and block number logic happens BEFORE reserving mempool
    latest_block = db.get_canonical_head_block()
    if latest_block:
        block_number = latest_block['header']['block_number'] + 1
        previous_hash = latest_block['block_hash']
    else:
        # Genesis block
        block_number = 0
        previous_hash = "0" * 64

    from consensus.engine import TauConsensusEngine
    engine = TauConsensusEngine()

    # PoA (validator_set): refuse to propose if our key has been removed from the
    # active set. In tau-authoritative modes (stake, tau_validator_set) the host
    # membership gate is bypassed; query_eligibility below (Tau o7) becomes the
    # gate -- on our stake (stake) or our pubkey membership in the rule
    # (tau_validator_set).
    from consensus.governance import is_tau_authoritative_eligibility_mode
    lm = chain_state._lifecycle_manager
    mode = getattr(lm, "effective_eligibility_mode", lambda: "validator_set")()
    tau_bound = is_tau_authoritative_eligibility_mode(mode)
    active = getattr(lm, "active_validators", set())
    if active and not tau_bound \
            and not getattr(config.settings.authority, "open_governance_admission", False) \
            and (config.MINER_PUBKEY or "").lower() not in active:
        msg = "Local miner pubkey is not in the active validator set; not proposing."
        print(f"[INFO][createblock] {msg}")
        return {"message": msg}

    current_time = int(time.time())
    if not engine.query_eligibility(config.MINER_PUBKEY, block_number, current_time, previous_hash):
        msg = f"Not our turn to mine block #{block_number} according to Tau consensus."
        print(f"[INFO][createblock] {msg}")
        return {"message": msg}

    # Get batch of reserved transactions from mempool. The chain-write lock is
    # already held for the whole round, so no second producer can sweep or
    # re-reserve this batch while we build on it.
    # Lane-aware selection: transfers first, then a bounded number of
    # rule-bearing transactions. The slow-lane budget is the tighter of the
    # operator's own hint and the consensus-enforced, governance-patchable
    # ceiling, so a proposer can be more conservative than consensus requires
    # but never more permissive (a block over the consensus budget is invalid).
    consensus_rule_budget = getattr(
        chain_state._lifecycle_manager, "max_rule_txs_per_block", None
    )
    # isinstance rather than a None check: a stubbed lifecycle manager hands
    # back a mock attribute, and silently comparing that against an int would
    # break the round rather than the budget.
    if not isinstance(consensus_rule_budget, int) or isinstance(consensus_rule_budget, bool):
        consensus_rule_budget = None
    slow_limit = getattr(config, "BLOCK_MAX_RULE_TXS", None)
    if not isinstance(slow_limit, int) or isinstance(slow_limit, bool):
        slow_limit = None
    if consensus_rule_budget is not None:
        slow_limit = (
            consensus_rule_budget if slow_limit is None
            else min(slow_limit, consensus_rule_budget)
        )
    reserved_txs = db.reserve_mempool_txs(limit=1000, slow_limit=slow_limit)
    print(f"[INFO][createblock] Reserved {len(reserved_txs)} entries from mempool")

    if not reserved_txs and not allow_empty:
        msg = "Mempool is empty (no pending txs); no block produced."
        print(f"[INFO][createblock] {msg}")
        return {"message": msg}

    # Extract data
    mempool_txs = [rtx['payload'] for rtx in reserved_txs]
    reserved_ids = [rtx['id'] for rtx in reserved_txs]
    reserved_hashes = [rtx.get('tx_hash') for rtx in reserved_txs]
    
    # Fix JSON alignment
    # We must filter reserved_ids and transactions in lockstep
    transactions = []
    execution_transactions = []
    filtered_reserved_ids = []
    skipped_count = 0
    
    for i, tx_data in enumerate(mempool_txs):
        r_id = reserved_ids[i]
        tx_hash = reserved_hashes[i]
        try:
            clean_data = tx_data
            if clean_data.startswith("json:"):
                clean_data = clean_data[5:]
            
            tx = json.loads(clean_data)
            # Ensure every tx has a stable identifier so the consensus engine can
            # report acceptance/rejection. Keep this synthetic ID out of the
            # persisted block body so tx_ids remains the canonical ID surface.
            execution_tx = dict(tx) if isinstance(tx, dict) else tx
            if isinstance(execution_tx, dict) and not execution_tx.get("tx_id") and tx_hash:
                execution_tx["tx_id"] = tx_hash
            transactions.append(tx)
            execution_transactions.append(execution_tx)
            filtered_reserved_ids.append(r_id)
        except json.JSONDecodeError as e:
            print(f"[WARN][createblock] Skipping invalid JSON transaction #{i+1}: {e}")
            skipped_count += 1
            # Not added to the filtered lists, so they stay aligned. Disposal
            # happens right below, not via `reserved_ids`.

    if skipped_count > 0:
        print(f"[WARN][createblock] Skipped {skipped_count} invalid transactions")

    # Drop the unparseable rows now. Unlike the engine's accept/reject verdicts
    # (which depend on the parent state and so do not survive a lost race), "this
    # payload is not JSON" is final. Left in place they would sit `reserved`,
    # recycle through the 60s stale sweep forever, and consume a slot in every
    # reservation batch. Record them first so gettxstatus reports `rejected`
    # rather than `unknown`.
    _malformed = set(reserved_ids) - set(filtered_reserved_ids)
    if _malformed:
        malformed_ids = [i for i in reserved_ids if i in _malformed]
        malformed_hashes = [
            h for i, h in zip(reserved_ids, reserved_hashes) if i in _malformed and h
        ]
        if malformed_hashes:
            db.record_dropped_txs(malformed_hashes, "rejected")
        db.remove_transactions(malformed_ids)
        reserved_ids = [i for i in reserved_ids if i not in _malformed]

    if not transactions and not allow_empty:
        msg = "Mempool is empty (no valid pending txs); no block produced."
        print(f"[INFO][createblock] {msg}")
        return {"message": msg}

    # Fee-priority reservation can reorder a sender's transactions out of
    # sequence order; restore per-sender ascending sequence within the
    # slots that sender occupies (global priority assignment preserved).
    _restore_per_sender_sequence_order(transactions, execution_transactions, filtered_reserved_ids)

    # Lane quotas can leave a sender's LOWER-numbered transaction behind while
    # including a higher one -- the fast lane takes seq 6 while seq 5 sits in
    # the capped slow lane. The engine hard-rejects the gap
    # (consensus/engine.py sequence check) and the transaction is disposed with
    # the block, so drop such orphans here and let them wait for their
    # predecessor instead.
    _drop_sequence_gap_orphans(transactions, execution_transactions, filtered_reserved_ids)

    if not transactions and not allow_empty:
        msg = "Mempool has no contiguous-sequence txs; no block produced."
        print(f"[INFO][createblock] {msg}")
        db.unreserve_mempool_txs(reserved_ids)
        return {"message": msg}

    # Fee model: the fee value is unknowable without Tau (consensus rules
    # emit it on o9). Never build a user_tx block on guessed fees.
    if any(
        isinstance(tx, dict)
        and tx.get("tx_type", "user_tx") in TAU_EVALUATING_TX_TYPES
        for tx in transactions
    ) and not tau_manager.tau_ready.wait(timeout=5):
        msg = "Tau unavailable; aborting block round (cannot evaluate fees for user transactions)."
        print(f"[ERROR][createblock] {msg}")
        import db as _db
        _db.unreserve_mempool_txs(reserved_ids)
        return {"error": msg, "message": msg}

    print(f"[INFO][createblock] Validating and Executing Batch Natively...")
    block_timestamp = int(time.time())

    # Flips once the candidate is canonical; gates the reclaim in `except`.
    persisted = False

    try:
        from consensus.engine import TauConsensusEngine
        from consensus.state import TauStateSnapshot, compute_consensus_state_hash
        from chain_state import compute_accounts_hash
        
        # 1. Load canonical parent snapshot
        app_rules = (chain_state._application_rules_state or "").encode('utf-8')
        cons_rules = (chain_state._consensus_rules_state or "").encode('utf-8')
        acc_hash = compute_accounts_hash(chain_state._balances, chain_state._sequence_numbers)
        meta_hash = chain_state._lifecycle_manager.consensus_meta_hash()
        state_hash = compute_consensus_state_hash(cons_rules, app_rules, acc_hash, meta_hash)
        
        parent_snapshot = TauStateSnapshot(
            state_hash=state_hash,
            tau_bytes=app_rules,
            metadata={
                "source": "chain_state",
                "balances": chain_state._balances,
                "sequence_numbers": chain_state._sequence_numbers,
                "lifecycle_manager": chain_state._lifecycle_manager,
                "active_consensus_id": chain_state._active_consensus_id,
                # Carry the CONSENSUS spec so derive_active_consensus/apply_block
                # propagate it (not tau_bytes, which is the application spec).
                "consensus_rules_state": chain_state._consensus_rules_state,
            }
        )
        
        engine = TauConsensusEngine()

        # 2. Derive active_view for next height
        active_view = engine.derive_active_consensus(parent_snapshot, block_number)

        # 3. Simulate Candidate using apply_block() natively
        # We need a candidate block body structure.
        candidate_block = block.Block.create(
            block_number=block_number,
            previous_hash=previous_hash,
            transactions=execution_transactions,
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=block_timestamp,
            state_hash=''
        )

        # Snapshot global Tau interpreter + application-rules state BEFORE the
        # miner-side simulation. `engine.apply_block` ultimately calls
        # `tau_manager.communicate_with_tau(..., apply_rules_update=True)` for
        # any user_tx rule op, which mutates the live `tau_direct_interface`
        # AND writes `chain_state._application_rules_state` + the db
        # `full_tau_spec` row via `_rules_handler`. We must roll those back
        # before `process_new_block` re-applies the same block; otherwise the
        # verifier path runs against an already-advanced interpreter and
        # produces a divergent `next_app_rules` / `state_hash`, manifesting as
        # "[BLOCKCHAIN] State hash mismatch for extending block #N".
        saved_app_rules = chain_state.get_application_rules_state()
        try:
            saved_db_full_spec = db.get_chain_state_value("full_tau_spec", "")
        except Exception:
            saved_db_full_spec = None
        saved_full_spec = None
        try:
            iface = tau_manager.tau_direct_interface
            if iface is not None and hasattr(iface, "get_current_spec"):
                saved_full_spec = iface.get_current_spec()
        except Exception:
            saved_full_spec = None
        if saved_full_spec is None:
            saved_full_spec = tau_manager.last_known_tau_spec
        # Snapshot the shrunk-stream set too: restoring the (shrunk) get_current_spec()
        # would otherwise re-classify nothing and leave the set empty, so a transfer
        # before process_new_block re-applies the block would feed a raw bv[384] the
        # engine rejects. Re-pin it with the restore.
        try:
            saved_shrunk_streams = tau_manager.get_runtime_shrunk_streams()
        except Exception:
            saved_shrunk_streams = None

        # Prefer a DISPOSABLE evaluator for the simulation. The save/restore
        # below exists because the simulation mutates the live interpreter, and
        # it does not actually undo that: measured, `restore_full_tau_spec` comes
        # back with time_point reset from 3 to 0 and a different interpreter
        # object, so a history-dependent rule answers differently before and
        # after -- the block is chosen under one state and applied under another.
        # A worker cannot contaminate anything, and disposal is the only rollback
        # the engine offers.
        sim_session = _speculative_session()
        # Isolating the interpreter is not enough on its own: the encoder the
        # worker shares with the authoritative path is DB-backed, and
        # `db.get_shrink_id` inserts and commits. Measured: a rejected proposal
        # that mentioned one never-before-seen address moved the committed max
        # shrink id from 0 to 1 -- permanently burning capacity and the mapping
        # epoch for a block that never existed. A private allocator mints in
        # memory and publishes nothing.
        try:
            # Call the unified path
            apply_result = engine.apply_block(
                active_view, candidate_block, parent_snapshot, session=sim_session
            )
        finally:
            if sim_session is not None:
                try:
                    sim_session.dispose()
                except Exception:
                    logger.warning("createblock: failed to dispose the simulation worker")
            # Restore the interpreter + cached rules state so `process_new_block`
            # below re-applies the block from the same baseline the miner saw.
            # Only meaningful when the simulation ran IN-PROCESS; a worker leaves
            # nothing to restore.
            try:
                if sim_session is None and saved_full_spec is not None:
                    tau_manager.restore_full_tau_spec(
                        saved_full_spec, runtime_shrunk_streams=saved_shrunk_streams
                    )
            except Exception as restore_err:
                logger.warning(
                    "createblock: failed to restore Tau spec after miner simulation: %s",
                    restore_err,
                )
            chain_state.save_application_rules_state(saved_app_rules)
            if saved_db_full_spec is not None:
                try:
                    db.set_chain_state_value("full_tau_spec", saved_db_full_spec)
                except Exception:
                    logger.warning(
                        "createblock: failed to restore db full_tau_spec after miner simulation",
                        exc_info=True,
                    )
        
        # Extract accepted/skipped outcomes
        final_txs = []
        final_reserved_ids = []
        
        rejected_hashes = []
        for i, tx in enumerate(execution_transactions):
             tx_id = tx.get('tx_id')
             if tx_id in apply_result.accepted_tx_ids or tx_id in apply_result.skipped_tx_ids:
                 final_txs.append(transactions[i])
             # Whether applied, skipped, or structurally invalid, we dispose of them from mempool!
             if tx_id in apply_result.accepted_tx_ids or tx_id in apply_result.skipped_tx_ids or tx_id in apply_result.invalid_tx_ids:
                 final_reserved_ids.append(filtered_reserved_ids[i])
             if tx_id in apply_result.invalid_tx_ids:
                 rejected_hashes.append(tx_id)

        # NOTE: the apply verdicts above are recorded/disposed only after the
        # block actually persists (step 6). They are relative to THIS parent
        # state -- if the block never lands, "invalid" is not a durable verdict.

        print(f"[INFO][createblock] Execution Result: {len(final_txs)}/{len(transactions)} logically valid")
        # Removed check to allow creation of empty block
        # 4. Form Complete Valid Block Header
        candidate_block.transactions = final_txs
        # Update IDs
        candidate_block.tx_ids = [block.compute_tx_hash(tx) for tx in final_txs]
        candidate_block.header.merkle_root = block.compute_merkle_root(candidate_block.tx_ids)
        candidate_block.header.state_hash = apply_result.next_snapshot.state_hash
        candidate_block.header.state_locator = f"{config.STATE_LOCATOR_NAMESPACE}:{apply_result.next_snapshot.state_hash}"
        candidate_block.block_hash = block.sha256_hex(candidate_block.header.canonical_bytes())
        
        # Generate Consensus Proof (PoA)
        try:
            from py_ecc.bls import G2Basic
            import hashlib
            msg_hash = hashlib.sha256(candidate_block.header.canonical_bytes()).digest()
            if not getattr(config, "MINER_PRIVKEY", None):
                raise ValueError("MINER_PRIVKEY not configured")
            sig_bytes = G2Basic.Sign(int(config.MINER_PRIVKEY, 16), msg_hash)
            candidate_block.consensus_proof = sig_bytes.hex()
        except Exception as e:
            print(f"[ERROR][createblock] Failed to generate consensus proof: {e}")
            import db as _db
            _db.unreserve_mempool_txs(reserved_ids)
            msg = f"Failed to sign block: {e}"
            return {"error": msg, "message": msg}

        # 5. Full Final Acceptance Path
        # The node runs standard process_new_block ingestion as if we imported it over network.
        # This guarantees path equivalence.
        if not chain_state.process_new_block(candidate_block):
             import db as _db
             # No block was persisted, so NOTHING may be disposed of: the batch
             # goes back to pending exactly as it was. The engine's accept/skip/
             # reject verdicts were computed against a parent that this block did
             # not extend, so they are not durable -- deleting the accepted txs
             # here (the old behaviour) destroyed valid transactions and stalled
             # their senders' sequences forever.
             _db.unreserve_mempool_txs(reserved_ids)
             msg = "Failed to persist new canonical block"
             return {"error": msg, "message": msg}

        persisted = True

        # 6. Mempool Disposition (only now that the block is canonical)
        import db as _db
        # Record before removing: a tx that is in neither `mempool` nor
        # `mempool_dropped` reads as "unknown" to gettxstatus.
        if rejected_hashes:
            _db.record_dropped_txs(rejected_hashes, "rejected")
        if final_reserved_ids:
             _db.remove_transactions(final_reserved_ids)
        # Parsed but claimed by no verdict: return them to pending instead of
        # leaving them `reserved` until the 60s stale sweep.
        leftover = [i for i in filtered_reserved_ids if i not in set(final_reserved_ids)]
        if leftover:
            _db.unreserve_mempool_txs(leftover)

        new_block = candidate_block # map for existing return variable
    except Exception as e:
        print(f"[ERROR][createblock] Block creation failed during native simulation: {e}")
        import db as _db
        # Only reclaim the batch if the block never landed. Once
        # process_new_block has committed it, its transactions belong to that
        # block; unreserving them here would re-mine them into a later one.
        if not persisted:
            _db.unreserve_mempool_txs(reserved_ids)
        msg = str(e)
        return {"error": msg, "message": msg}
        
    print(f"[INFO][createblock] Block creation process completed!")
    return new_block.to_dict()


_CONFIG_ERROR_PREFIXES = ("PoA mining requires", "BLS signing is required")
_MINING_FAILED_PREFIXES = ("Failed to sign block", "Failed to persist")
# Must not collide with the prefixes above, or a lost lock race would be
# reported as a mining failure.
_BUSY_PREFIX = "Block production already in progress"


def _classify_createblock_error(block_data: Dict) -> tuple[str, str]:
    err = block_data.get("error") or ""
    msg = block_data.get("message") or err or "Block creation failed."
    if err.startswith(_CONFIG_ERROR_PREFIXES) or msg.startswith(_CONFIG_ERROR_PREFIXES):
        return "MINING_CONFIG_ERROR", msg
    if err.startswith(_MINING_FAILED_PREFIXES) or msg.startswith(_MINING_FAILED_PREFIXES):
        return "MINING_FAILED", msg
    if msg.startswith("Not our turn"):
        return "MINING_NOT_ELIGIBLE", msg
    if msg.startswith(_BUSY_PREFIX):
        return "MINING_BUSY", msg
    if "Mempool is empty" in msg:
        return "MEMPOOL_EMPTY", msg
    if err:
        return "MINING_FAILED", msg
    return "BLOCK_NOT_CREATED", msg


def execute(raw_command: str, container):
    """
    Executes the createblock command.

    Usage: ``createblock [allow-empty]``. Without the flag an empty mempool
    yields MEMPOOL_EMPTY instead of a signed empty block; ``allow-empty`` is for
    callers that need to advance height (e.g. to a governance activation).
    """
    logger.info("Create block requested")

    args = raw_command.split()[1:]
    allow_empty = False
    for arg in args:
        if arg.lower() in ("allow-empty", "allow_empty"):
            allow_empty = True
        else:
            return api_response.error_response(
                "createblock",
                f"Unknown argument '{arg}'. Usage: createblock [allow-empty]",
                "INVALID_PARAMS",
            )

    try:
        block_data = create_block_from_mempool(allow_empty=allow_empty)
    except Exception as exc:
        logger.exception("Block creation failed")
        return api_response.error_response(
            "createblock", f"Failed to create block: {exc}", "MINING_FAILED"
        )

    if isinstance(block_data, dict) and "block_hash" in block_data:
        header = block_data.get("header", {})
        transactions = block_data.get("transactions", [])
        data = {
            "block_number": header.get("block_number"),
            "block_hash": block_data["block_hash"],
            "merkle_root": header.get("merkle_root"),
            "timestamp": header.get("timestamp"),
            "tx_count": len(transactions),
            "transactions": transactions,
        }
        logger.info("Block #%s created", header.get("block_number"))

        try:
            from network import bus
            service = bus.get()
            if service:
                service.broadcast_block(block_data)
                logger.info("Block #%s broadcasted to network", header.get("block_number"))
            else:
                logger.warning("Network service not available, block not broadcasted")
        except Exception:
            logger.exception("Failed to broadcast block")

        return api_response.success_response("createblock", data)

    if not isinstance(block_data, dict):
        return api_response.error_response(
            "createblock", "Block creation returned no data.", "BLOCK_NOT_CREATED"
        )

    code, message = _classify_createblock_error(block_data)
    logger.info("Create block skipped: %s (%s)", message, code)
    return api_response.error_response("createblock", message, code)
