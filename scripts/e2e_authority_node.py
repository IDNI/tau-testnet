#!/usr/bin/env python3
"""The production server, with named failures injectable from OUTSIDE (e2e only).

Started by scripts/e2e_authority.py in place of `python server.py`. Nothing here
changes a code path unless its control file is present: the node under test is
the production server, with at most one failure injected at a named point.

Control directory: $TAU_E2E_CONTROL

    fail_promotion     the next AuthoritativeTauOwner.promote raises -- after the
                       block is durable, before the exact worker is served
    hold_next_block    the next locally built block is held: its artifact stays
                       pending on the lent authority, and the block itself is
                       neither processed nor broadcast
    cmd-<id>.json      a probe to run inside the node -> res-<id>.json

Probes: snapshot, verify_held, reprocess_head, ingest.
"""
from __future__ import annotations

import hashlib
import json
import os
import runpy
import sys
import threading
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
CONTROL = os.environ["TAU_E2E_CONTROL"]

_held = {}


def _consume(name: str) -> bool:
    try:
        os.remove(os.path.join(CONTROL, name))
        return True
    except FileNotFoundError:
        return False


def _write(name: str, payload) -> None:
    path = os.path.join(CONTROL, name)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True, default=str)
    os.replace(tmp, path)


# --- injected failures -----------------------------------------------------------

def _install() -> None:
    import chain_state
    import tau_authority
    import tau_commit
    import commands.createblock as createblock

    real_promote = tau_authority.AuthoritativeTauOwner.promote

    def promote(self, proposal, prepared):
        if _consume("fail_promotion"):
            raise RuntimeError("e2e: injected promotion failure")
        return real_promote(self, proposal, prepared)

    tau_authority.AuthoritativeTauOwner.promote = promote

    real_create = createblock.create_block_from_mempool

    def create_block_from_mempool(*args, **kwargs):
        if not _consume("hold_next_block"):
            return real_create(*args, **kwargs)
        real_process = chain_state.process_new_block

        def held(block):
            _held["block"] = block.to_dict()
            _held["key"] = tau_commit.registry().pending
            return True

        chain_state.process_new_block = held
        try:
            out = real_create(*args, **kwargs)
        finally:
            chain_state.process_new_block = real_process
        _write("held.json", {"block": _held.get("block"), "key": _held.get("key"),
                             "result": {k: v for k, v in (out or {}).items()
                                        if k in ("error", "message")}})
        # No `block_hash`: the RPC layer broadcasts only a block it sees.
        return {"error": "held by e2e", "message": "held by e2e"}

    createblock.create_block_from_mempool = create_block_from_mempool


# --- probes ----------------------------------------------------------------------

def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str)
                          .encode()).hexdigest()[:16]


def _observe() -> dict:
    import chain_state
    import db
    import tau_authority

    owner = tau_authority.owner()
    head, seq = db.committed_journal_head()
    latest = db.latest_block_commit() or {}
    with db._db_lock:
        commits = db._db_conn.execute("SELECT COUNT(*) FROM block_commits_v1").fetchone()[0]
    return {
        "journal_head": head, "journal_sequence": seq,
        "mapping_epoch": db.shrink_mapping_epoch(),
        "max_shrink_id": db.get_max_shrink_id(),
        "balances": _digest(dict(chain_state._balances)),
        "sequences": _digest(dict(chain_state._sequence_numbers)),
        "lifecycle": chain_state._lifecycle_manager.consensus_meta_hash().hex()
        if hasattr(chain_state._lifecycle_manager.consensus_meta_hash(), "hex")
        else str(chain_state._lifecycle_manager.consensus_meta_hash()),
        "commit_records": commits,
        "latest_execution": latest.get("execution_id"),
        "authority_head": getattr(owner.descriptor, "journal_head_hash", None),
    }


def _worker_requests(session):
    spec = getattr(session, "_spec", None)
    return None if spec is None else getattr(spec, "_next_id", None)


def probe_snapshot(_args):
    import tau_admission
    import tau_authority
    import tau_commit

    owner = tau_authority.owner()
    entry = tau_commit.registry()._entry
    pending_session = entry[1].session if entry is not None else None
    return {
        "state": owner.state, "reason": owner.reason,
        "generation": owner.generation,
        "serving_worker": id(owner._session) if owner._session is not None else None,
        "pending_key": tau_commit.registry().pending,
        "held_key": _held.get("key"),
        "pending_worker": id(pending_session) if pending_session is not None else None,
        "pending_worker_requests": _worker_requests(pending_session),
        "pending_worker_alive": (pending_session._spec._proc.poll() is None
                                 if pending_session is not None else None),
        "admission": dict(tau_admission.stats),
        **_observe(),
    }


def probe_verify_held(_args):
    """Offer the held candidate's artifact against the state that has moved on."""
    import tau_authority
    import tau_commit

    key = _held.get("key")
    entry = tau_commit.registry().claim(key) if key else None
    if entry is None:
        return {"claimed": False, "pending_key": tau_commit.registry().pending,
                "held_key": key}
    prepared, proposal = entry
    worker = proposal.session
    refusal = None
    try:
        prepared.verify(proposal=proposal, execution_id=key)
    except Exception as exc:
        refusal = f"{type(exc).__name__}: {exc}"
    proposal.dispose()
    time.sleep(0.2)
    owner = tau_authority.owner()
    return {
        "claimed": True, "refusal": refusal,
        "worker_alive_after_dispose": (worker._spec._proc.poll() is None
                                       if worker is not None else None),
        "state_after": owner.state, "reason_after": owner.reason,
    }


def probe_reprocess_head(_args):
    """Feed the committed head block in again, both ways it can come back: to
    process_new_block directly, and through the network's ingestion."""
    import chain_state
    import db
    from block import Block
    from network.service import NetworkService

    before = _observe()
    head = db.get_canonical_head()
    direct = chain_state.process_new_block(Block.from_dict(head))
    after_direct = _observe()
    ingested = NetworkService._ingest_blocks([head], "e2e-redelivery")
    after_network = _observe()
    return {"block": head.get("block_hash"), "direct_returned": bool(direct),
            "network_ingested": ingested, "before": before,
            "unchanged": before == after_direct == after_network,
            "after_direct": after_direct, "after_network": after_network}


def probe_ingest(args):
    """Hand blocks to the node exactly as its network layer does after a sync:
    NetworkService._ingest_blocks -- ingestion, then fork choice."""
    import db
    from network.service import NetworkService

    started = time.time()
    count = NetworkService._ingest_blocks(list(args["blocks"]), args.get("peer", "e2e"))
    head = db.get_canonical_head() or {}
    return {"ingested": count, "head": head.get("block_hash"),
            "seconds": round(time.time() - started, 3)}


def probe_eligibility(_args):
    """What block production asks before it builds: am I the proposer?"""
    import config
    import db
    import tau_advisory
    import tau_manager
    from consensus.engine import TauConsensusEngine

    head = db.get_canonical_head() or {}
    height = int((head.get("header") or {}).get("block_number", -1)) + 1
    engine = TauConsensusEngine()
    now = int(time.time())
    inputs = engine._build_consensus_input_streams(
        proposer_pubkey=config.MINER_PUBKEY, block_number=height, timestamp=now,
        previous_hash=head.get("block_hash") or "0" * 64, proof_ok=True, claims={},
        proposer_stake=0, stake_mode=False, feed_proposer_pubkey=False,
    )
    advisory = tau_advisory.evaluator().evaluate(
        tau_manager.get_canonical_spec() or "", inputs, target=7)
    return {"height": height, "tau_ready": tau_manager.tau_ready.is_set(),
            "advisory_o7": advisory,
            "eligible": engine.query_eligibility(config.MINER_PUBKEY, height, now,
                                                 head.get("block_hash"))}


PROBES = {"snapshot": probe_snapshot, "verify_held": probe_verify_held,
          "eligibility": probe_eligibility,
          "reprocess_head": probe_reprocess_head, "ingest": probe_ingest}


def _watch() -> None:
    while True:
        try:
            names = sorted(n for n in os.listdir(CONTROL)
                           if n.startswith("cmd-") and n.endswith(".json"))
        except FileNotFoundError:
            names = []
        for name in names:
            path = os.path.join(CONTROL, name)
            try:
                with open(path) as fh:
                    cmd = json.load(fh)
                os.remove(path)
            except Exception:
                continue
            rid = name[len("cmd-"):-len(".json")]
            try:
                out = {"ok": True, "result": PROBES[cmd["probe"]](cmd.get("args"))}
            except Exception as exc:
                out = {"ok": False, "error": repr(exc),
                       "trace": traceback.format_exc()}
            _write(f"res-{rid}.json", out)
        time.sleep(0.2)


def main() -> None:
    os.makedirs(CONTROL, exist_ok=True)
    _install()
    threading.Thread(target=_watch, name="e2e-probes", daemon=True).start()
    server = os.path.join(ROOT, "server.py")
    sys.argv = [server]
    runpy.run_path(server, run_name="__main__")


if __name__ == "__main__":
    main()
