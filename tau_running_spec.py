"""The specification the engine runs, built by the engine from the committed rules.

A rule unit can revise part of an earlier one. Sent `o26 = {7} && o27 = {9}` and
then `o26 = {3}`, the engine runs `o26 = 3 && o27 = 9`, while the stored
application rules still list both units. The stored units say what was sent;
only the engine says what is in force.

The authoritative evaluator runs in a worker whose rule text carries interned
ids, so its own `current_spec()` names private numbers. This module gives the
same engine the committed rule history in canonical (full-width) form, in a
worker of its own, and reads back `current_spec()`: the text two nodes at the
same block agree on.

Only the rule entries are replayed, not the steps between them: the revised
text depends on the order of the revisions, not on the inputs or the time point
at which they arrived (measured: the same text and hash with no steps and with
steps between). The result is cached per rule history, so a read costs one
worker only after a reset or a revision commits.
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading

logger = logging.getLogger(__name__)

ACCEPTED = ("ACCEPTED_CHANGED", "ACCEPTED_NOOP")

_lock = threading.Lock()
_cached_key = None
_cached_text = None


class RunningSpecUnavailable(RuntimeError):
    """The engine could not rebuild the specification from the committed rules."""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rule_units(entries) -> list:
    """The rule texts the specification is built from, in order: the units of the
    last reset, then every accepted revision after it. A revision the engine did
    not accept changed nothing and is left out."""
    begin = 0
    for index in range(len(entries) - 1, -1, -1):
        if entries[index]["kind"] == "reset":
            begin = index
            break
    units = []
    for entry in entries[begin:]:
        if entry["kind"] == "reset":
            units.extend(text for text, _persist in entry["units"])
        elif entry.get("outcome") in ACCEPTED and entry.get("rule_text"):
            units.append(entry["rule_text"])
    return units


def _spawn():
    import config
    import tau_speculation

    cwd = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ)
    paths = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
    if cwd not in paths:
        env["PYTHONPATH"] = os.pathsep.join([cwd] + paths)
    return tau_speculation.SpeculationSession(
        cwd=cwd, env=env, timeout=config.COMM_TIMEOUT)


def compose(baseline: str, units, *, spawn=None) -> str:
    """Build a fresh engine on `baseline`, revise it with each unit in order and
    return its `current_spec()`. Every unit must be accepted again, as it was on
    the chain; anything else is reported, never a partial text."""
    session = (spawn or _spawn)()
    try:
        session.init(baseline)
        for index, text in enumerate(units):
            receipt = session.revise(text, f"unit-{index}")
            if receipt.get("outcome") not in ACCEPTED:
                raise RunningSpecUnavailable(
                    f"unit {index} was not accepted again: {receipt.get('outcome')}")
        return session.current_spec()
    finally:
        import tau_speculation
        try:
            session.close()
        except (Exception, tau_speculation.WorkerLost):
            try:
                session.kill()
            except (Exception, tau_speculation.WorkerLost):
                pass


def _key(entries) -> str | None:
    return entries[-1]["link"] if entries else None


def at_head(store=None):
    """The running spec at the committed head, as a read returns it.

    `{"text", "sha256", "block_hash"}`, where `block_hash` is the head the rule
    history was read with (in the same read), or `{"text": None, "sha256": None,
    "block_hash": ..., "unavailable": reason}` on a node without the
    authoritative engine or when the engine could not rebuild it.
    """
    import tau_authority

    if not tau_authority.owner().enabled:
        return _unavailable(None, "this node runs without the authoritative engine")
    if store is None:
        import db as store
    return running_spec(store)


def running_spec(store, *, baseline=None, spawn=None) -> dict:
    """`at_head` for a given journal store, program baseline and worker."""
    global _cached_key, _cached_text
    import tau_authority
    import tau_speculation

    head, entries = store.committed_rule_history()
    key = _key(entries)
    with _lock:
        if key is not None and key == _cached_key:
            return _available(head, _cached_text)
        try:
            base = baseline if baseline is not None else tau_authority.program_baseline()
            if not base:
                raise RunningSpecUnavailable("no program baseline")
            text = compose(base, rule_units(entries), spawn=spawn)
        except (Exception, tau_speculation.WorkerLost) as exc:
            # A lost or timed-out worker is this node's operational trouble, never
            # a verdict on a rule: the read says the text is unavailable, and the
            # next read tries again.
            logger.warning("running spec could not be rebuilt: %r", exc)
            return _unavailable(head, f"the engine could not rebuild it: {exc!r}")
        _cached_key, _cached_text = key, text
        return _available(head, text)


def _available(head, text: str) -> dict:
    return {"text": text, "sha256": _sha256(text), "block_hash": head}


def _unavailable(head, reason: str) -> dict:
    return {"text": None, "sha256": None, "block_hash": head, "unavailable": reason}


def reset_cache() -> None:
    global _cached_key, _cached_text
    with _lock:
        _cached_key = _cached_text = None
