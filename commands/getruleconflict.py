"""Conflict status for a rule offer, so a recipient can decide before accepting.

ADVISORY AND NODE-LOCAL BY DESIGN. This never gates a transaction, for reasons
that are not stylistic:

  - it depends on process-local state (per-stream bitvector typing is
    process-global and sticky, and the shrink width derives from this node's own
    intern table), so two honest nodes can legitimately differ;
  - the engine build is explicitly unstable, so a verdict is not portable;
  - the cost is unbounded, and binding it to block validity would turn a heavy
    rule into a chain halt rather than a rejection.

The layers are ordered cheapest-first, and each states what it actually proves:

  L0 shape       one `always ( ... ).` unit writing one permitted stream
  L1 domains     does not write consensus-owned streams, read apply-mocked
                 inputs, or reference reserved inputs
  L2 collision   whether the acceptor ALREADY holds a clause on this stream
                 (accepting replaces it) and who else holds one
  L3 widths      the same stream declared at two bitvector widths, compared
                 statically so the live interpreter's typing is never touched
  L4 compile     the clause builds as `always ( body ).` in the policy worker
  L5 unsat       NOT AVAILABLE: sat/unsat/valid/unrealizable exist in tau-lang's
                 C++ API but are not exposed by the Python bindings, so logical
                 contradiction cannot be detected at all

Each clause is evaluated on its own for its owner, so clauses of different
accounts never conflict -- which is what makes L2 a decidable question rather
than a guess.
"""
import logging
import re
import threading

import api_response
import chain_state
import config
import db
from consensus import sender_policy
from tau_speculation import WorkerLost
from consensus.rule_offers import (
    ALLOWED_TARGET_STREAMS,
    RuleOfferShapeError,
    normalize_offer_rule_text,
    strip_clause_comments,
)

logger = logging.getLogger(__name__)

_CMD = "getruleconflict"

# One compile at a time. This is an unauthenticated read RPC that spawns a
# worker build, so without a gate it is an amplifier.
_COMPILE_GATE = threading.Semaphore(1)

# Cache keyed on everything the report actually depends on -- the offer, its
# status, the application rules, and the clause registry -- so repeated polling
# of an unchanged chain is free while any relevant change invalidates it.
# Keying on the application rules alone is not enough: a rejection changes an
# offer's status without touching them, and a clause can be registered on a
# stream the caller has not yet looked at.
_CACHE: dict = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 64

_WIDTH_RE = re.compile(r"\b([io])(\d+)\s*\[[^\]]*\]\s*:\s*bv\[\s*(\d+)\s*\]")

VERDICT_CLEAN = "clean"
VERDICT_WARN = "warn"
VERDICT_CONFLICT = "conflict"


def _stream_widths(text: str) -> dict:
    """Declared bitvector width per stream, from comment-stripped text."""
    widths: dict = {}
    for kind, index, width in _WIDTH_RE.findall(strip_clause_comments(text or "")):
        widths.setdefault(f"{kind}{index}", set()).add(int(width))
    return widths


def _layer(name, status, detail=None, **extra):
    entry = {"layer": name, "status": status}
    if detail:
        entry["detail"] = detail
    entry.update(extra)
    return entry


def _cache_get(key):
    with _CACHE_LOCK:
        return _CACHE.get(key)


def _cache_put(key, value):
    with _CACHE_LOCK:
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.clear()
        _CACHE[key] = value


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <offer_id>", "INVALID_PARAMS"
        )

    offer_id = parts[1].strip().lower()
    try:
        if len(bytes.fromhex(offer_id)) != 32:
            raise ValueError
    except ValueError:
        return api_response.error_response(
            _CMD, "offer_id must be 32 bytes (64 hex chars).", "INVALID_PARAMS"
        )

    database = getattr(container, "db", db) or db
    try:
        rows = database.load_rule_offers()
        registry = database.load_rule_clauses()
    except Exception as exc:
        return api_response.error_response(
            _CMD, f"Failed to read rule offers: {exc}", "INTERNAL_ERROR"
        )

    offer = next((r for r in rows if (r.get("offer_id") or "").lower() == offer_id), None)
    if offer is None:
        return api_response.error_response(
            _CMD, f"Unknown offer {offer_id[:16]}.", "OFFER_UNKNOWN"
        )

    acceptor = (offer.get("recipient_pubkey") or "").lower()
    rule_text = offer.get("rule_text") or ""
    app_rules = chain_state.get_rules_state() or ""

    import hashlib

    registry_fingerprint = repr(sorted(
        (
            (c.get("acceptor_pubkey") or "").lower(),
            int(c.get("target_stream", -1)),
            c.get("clause_body") or "",
        )
        for c in registry
    ))
    cache_key = (
        offer_id,
        offer.get("status"),
        hashlib.sha256(app_rules.encode("utf-8")).hexdigest(),
        hashlib.sha256(registry_fingerprint.encode("utf-8")).hexdigest(),
    )
    cached = _cache_get(cache_key)
    if cached is not None:
        return api_response.success_response(_CMD, cached)

    layers = []
    verdict = VERDICT_CLEAN

    def escalate(level):
        nonlocal verdict
        order = {VERDICT_CLEAN: 0, VERDICT_WARN: 1, VERDICT_CONFLICT: 2}
        if order[level] > order[verdict]:
            verdict = level

    # --- L0 shape ---------------------------------------------------------
    body = None
    target_stream = None
    try:
        body, target_stream = normalize_offer_rule_text(rule_text)
        layers.append(_layer("shape", "ok", target_stream=target_stream))
    except RuleOfferShapeError as exc:
        layers.append(_layer("shape", "conflict", str(exc)))
        escalate(VERDICT_CONFLICT)

    # --- L1 reserved domains ---------------------------------------------
    if body is not None:
        from consensus.admission import _screen_clause_domains

        domain_error = _screen_clause_domains(body)
        if domain_error:
            layers.append(_layer("reserved_domains", "conflict", domain_error))
            escalate(VERDICT_CONFLICT)
        else:
            layers.append(_layer("reserved_domains", "ok"))

    # --- L2 registry collision -------------------------------------------
    if target_stream is not None:
        existing_own = next(
            (c["clause_body"] for c in registry
             if (c.get("acceptor_pubkey") or "").lower() == acceptor
             and int(c.get("target_stream", -1)) == target_stream),
            None,
        )
        others = sorted(
            (c.get("acceptor_pubkey") or "").lower() for c in registry
            if int(c.get("target_stream", -1)) == target_stream
            and (c.get("acceptor_pubkey") or "").lower() != acceptor
        )
        if existing_own is not None and existing_own != body:
            layers.append(_layer(
                "registry_collision", "warn",
                f"You already have a clause on o{target_stream}; accepting "
                "REPLACES it. There is no separate retraction.",
                existing_clause=existing_own,
                other_acceptors=others,
            ))
            escalate(VERDICT_WARN)
        elif existing_own is not None:
            layers.append(_layer(
                "registry_collision", "ok",
                "This is already your active clause on this stream.",
                other_acceptors=others,
            ))
        else:
            layers.append(_layer(
                "registry_collision", "ok",
                other_acceptors=others,
            ))

    # --- L3 bitvector widths ---------------------------------------------
    # Static comparison only: probing the engine would permanently type streams
    # in the live interpreter, which serves consensus.
    if body is not None:
        offered_widths = _stream_widths(body)
        live_widths = _stream_widths(app_rules)
        clashes = []
        for stream, widths in offered_widths.items():
            if len(widths) > 1:
                clashes.append({"stream": stream, "offered": sorted(widths)})
                continue
            live = live_widths.get(stream)
            if live and widths and not (widths & live):
                clashes.append({
                    "stream": stream,
                    "offered": sorted(widths),
                    "existing": sorted(live),
                })
        if clashes:
            layers.append(_layer(
                "bv_widths", "conflict",
                "The same stream is declared at incompatible bitvector widths; "
                "the engine drops such a rule.",
                findings=clashes,
            ))
            escalate(VERDICT_CONFLICT)
        else:
            layers.append(_layer("bv_widths", "ok"))

    # --- L4 does the clause build ----------------------------------------
    if body is not None and target_stream is not None:
        if not _COMPILE_GATE.acquire(blocking=False):
            layers.append(_layer(
                "compile", "unknown",
                "Another conflict check is compiling; retry shortly.",
            ))
            escalate(VERDICT_WARN)
        else:
            try:
                from tau_native import strip_ansi

                timeout = min(getattr(config, "COMM_TIMEOUT", 60) or 60, 30)
                builds, error = sender_policy.clause_builds(
                    body, pool="admission", timeout=timeout
                )
                if builds:
                    layers.append(_layer("compile", "ok"))
                else:
                    layers.append(_layer("compile", "conflict", strip_ansi(error)))
                    escalate(VERDICT_CONFLICT)
            except (Exception, WorkerLost) as exc:  # noqa: BLE001
                logger.warning("Conflict-check compile failed", exc_info=True)
                layers.append(_layer("compile", "unknown", str(exc)))
                escalate(VERDICT_WARN)
            finally:
                _COMPILE_GATE.release()

    # --- L5 satisfiability: not reachable from Python ---------------------
    layers.append(_layer(
        "unrealizable", "unavailable",
        "Logical contradiction cannot be detected: tau-lang exposes "
        "sat/unsat/valid/unrealizable in C++ but not through its Python "
        "bindings. A clean result here means no conflict was OBSERVED, not "
        "that none exists.",
    ))

    data = {
        "offer_id": offer_id,
        "acceptor_pubkey": acceptor,
        "target_stream": target_stream,
        "status": offer.get("status"),
        "verdict": verdict,
        "advisory": True,
        "layers": layers,
        "supported_target_streams": sorted(ALLOWED_TARGET_STREAMS),
    }
    _cache_put(cache_key, data)
    return api_response.success_response(_CMD, data)
