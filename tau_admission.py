"""Admission evaluates every request in a context of its own.

The contamination this removes. Stepping an evaluator is not read-only: each
step advances logical time, so under a history-dependent policy (`o5[t]` reading
`i1[t-1]`) the inputs one request feeds become the history the next request is
judged against. Step 5E took the authority off the shared in-process
interpreter; admission stayed on it. So a valid transaction could be refused
because of what an unrelated submission fed a moment earlier -- or admitted
under a history inclusion never sees, which is the original incident's
user-visible shape: `sendtx` says yes, inclusion says no.

The contract:

    admission request -> isolated evaluation context
                      -> reconstructed from the committed journal + allocator anchor
                      -> discarded after the request

never a stateful evaluator shared by independent submissions.

A context is a proposal without a block: the same replay of the committed
journal, the same representation planning over history plus the request's own
candidate, an allocator overlay of its own -- pinned to the committed mapping,
never published -- and no promotion. It is disposed of whatever the verdict.

What an answer means, exactly: the request was evaluated as the next thing to
run after the committed state the context was built from. Apply revalidates
against the block's actual ordered prefix, which can differ -- another
transaction may run first. That is a property of the block, not of admission.
"""
from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger(__name__)


class AdmissionUnavailable(RuntimeError):
    """No context could answer. Operational: never a verdict about the request.

    The caller reports unavailability. It does not fall back to the in-process
    interpreter -- that fallback IS the shared evaluator this module removes.
    """


class AdmissionTimeout(AdmissionUnavailable):
    """The request ran out of its end-to-end budget and its worker was killed."""


from tau_session import StepRefused  # noqa: E402 - re-exported: the engine refused
# one step's inputs. The same inputs against the same history are refused
# wherever they run, so it is about the request, not the node.


#: Contexts evaluating at once. Each is a process holding a native interpreter,
#: so a burst of submissions must queue for a slot rather than fork without bound.
MAX_CONCURRENT = 4
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)

#: Counters for diagnostics and tests: what admission actually cost.
stats = {"opened": 0, "replayed": 0, "standby_hits": 0, "disposed": 0}
_stats_lock = threading.Lock()


def _count(name, n=1):
    with _stats_lock:
        stats[name] = stats.get(name, 0) + n


def enabled() -> bool:
    """Whether admission must use isolated contexts.

    Exactly when the authority is worker-backed. Mock and unit-test
    configurations keep the in-process path: there is no native evaluator whose
    history could be contaminated.
    """
    try:
        import tau_authority
        return bool(tau_authority.owner().enabled)
    except Exception:
        return False


def default_budget() -> float:
    """One end-to-end budget per request, below the shipped client's timeout."""
    try:
        import tau_native
        return float(tau_native.admission_compile_timeout())
    except Exception:
        return 8.0


# --- the deadline ---------------------------------------------------------------

class _Deadline:
    """Kills every worker of one request when its budget runs out.

    A worker blocked inside a native call cannot be interrupted any other way,
    and the result channel has no timeout of its own. Killing the process makes
    the blocked read return, and `expired` tells the caller why.
    """

    def __init__(self, seconds: float):
        self.deadline = time.monotonic() + max(0.0, float(seconds))
        self.expired = False
        self._victims = []
        self._lock = threading.Lock()
        self._timer = threading.Timer(max(0.0, float(seconds)), self._fire)
        self._timer.daemon = True
        self._timer.start()

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def watch(self, session) -> None:
        with self._lock:
            if not self.expired:
                self._victims.append(session)
                return
        session.dispose()
        raise AdmissionTimeout("the admission budget ran out")

    def _fire(self) -> None:
        with self._lock:
            self.expired = True
            victims = list(self._victims)
        for session in victims:
            try:
                session.dispose()
            except Exception:
                pass

    def cancel(self) -> None:
        self._timer.cancel()


# --- a context --------------------------------------------------------------------

class AdmissionContext:
    """One request's evaluator. Used once, then disposed."""

    def __init__(self, session, *, anchor, plan, label, deadline, release):
        self._session = session
        self.anchor = dict(anchor)
        self.plan = plan
        self.label = label
        self._deadline = deadline
        self._release = release
        self._closed = False

    # --- evaluation ---------------------------------------------------------------

    def _operational(self, exc):
        if self._deadline is not None and self._deadline.expired:
            return AdmissionTimeout(f"{self.label}: the admission budget ran out")
        return AdmissionUnavailable(f"{self.label}: {exc}")

    def _check(self):
        if self._closed:
            raise AdmissionUnavailable(f"{self.label} was already disposed")
        if self._deadline is not None and self._deadline.expired:
            raise AdmissionTimeout(f"{self.label}: the admission budget ran out")

    def revise(self, rule_text: str) -> dict:
        """Offer a candidate revision exactly as apply would.

        Prepared under THIS context's plan and overlay -- never the node
        process's shrink state, which describes the in-process mirror and not the
        representation the authority runs under. Returns the normalized receipt
        (`accepted`, `outcome`, diagnostics).
        """
        self._check()
        try:
            self._session.apply_rule(rule_text, target=0, record=False)
        except Exception as exc:
            # Preparation that cannot represent the rule, a capacity overflow, a
            # dead worker: all node-local, none of them the author's fault.
            raise self._operational(exc) from exc
        return self._session.last_receipt() or {}

    def step(self, inputs: dict) -> dict:
        """One evaluation step; the indexed outputs, or StepRefused."""
        self._check()
        try:
            return self._session.evaluate(inputs, multi=True, record=False)
        except StepRefused:
            raise
        except Exception as exc:
            raise self._operational(exc) from exc

    # --- disposal -----------------------------------------------------------------

    def dispose(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._deadline is not None:
            self._deadline.cancel()
        try:
            self._session.dispose()
        except Exception:
            pass
        _count("disposed")
        if self._release is not None:
            release, self._release = self._release, None
            release()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.dispose()
        return False


# --- construction -----------------------------------------------------------------

def _anchor_key(anchor) -> tuple:
    return (anchor.get("journal_head"), anchor.get("journal_sequence"),
            anchor.get("epoch"))


def _conflicts(plan, candidate_rules) -> bool:
    """Whether a candidate needs PLAIN a stream this plan interns -- the same
    test that decides whether the authority can be lent."""
    if not candidate_rules:
        return False
    import tau_reconstruction
    needs = tau_reconstruction.plan_representation(candidate_rules=list(candidate_rules))
    return bool(set(needs.plain) & set(plan.interned))


def _plan_for(anchor, entries, candidate_rules):
    """The representation a block built now would run this request under.

    The committed plan -- the one the authority runs, and lends to the next
    proposal -- unless a candidate needs plain a stream it interns; then, as a
    proposal that cannot borrow the authority would, one plan over history and
    the candidate together. Semantically every plan is the same computation;
    matching apply's choice keeps admission from differing in anything else.
    """
    import tau_journal
    import tau_reconstruction

    if anchor.get("plan_json"):
        committed = tau_reconstruction.RepresentationPlan.from_json(anchor["plan_json"])
        if anchor.get("plan_id") and committed.plan_id != anchor["plan_id"]:
            raise AdmissionUnavailable(
                "the stored representation plan does not hash to its recorded id")
        if not _conflicts(committed, candidate_rules):
            return committed
    history = [e.rule_text for e in entries
               if e.kind == tau_journal.REVISION and e.rule_text]
    return tau_reconstruction.plan_representation(
        history_rules=history, candidate_rules=list(candidate_rules or ()),
    )


def _build(*, candidate_rules, label, deadline, cwd, env, store):
    """A session at the committed head: (session, anchor, plan)."""
    import tau_allocator
    import tau_authority
    import tau_journal
    import tau_session

    owner = tau_authority.owner()
    baseline = getattr(owner, "_baseline", None) or tau_authority.program_baseline()
    if not baseline:
        raise AdmissionUnavailable("no program baseline to evaluate against")
    store = store or owner.store

    anchor = store.committed_anchor()
    journal = tau_journal.journal_from_rows(anchor["rows"])
    try:
        journal.verify_chain()
    except Exception as exc:
        raise AdmissionUnavailable(f"the committed journal does not verify: {exc}") from exc
    entries = journal.entries()
    plan = _plan_for(anchor, entries, candidate_rules)
    # Pinned to the anchor it was read with: a block committing while this
    # context evaluates must not hand it bindings from a later state.
    snapshot = tau_allocator.PinnedDbMappingSnapshot(
        epoch=anchor["epoch"], high_water=anchor["high_water"], store=store,
    )
    allocator = tau_allocator.Allocator(snapshot, width=plan.width, label=label)

    def respawn():
        session = tau_session.WorkerSession.spawn(
            baseline, cwd=cwd, env=env, plan=plan, allocation=allocator,
        )
        if deadline is not None:
            deadline.watch(session)
        return session

    try:
        session = tau_session.replay_entries(
            None, entries, respawn=respawn, expected=journal.fingerprints(),
            start_at_last_reset=True,
        )
    except AdmissionUnavailable:
        raise
    except Exception as exc:
        if deadline is not None and deadline.expired:
            raise AdmissionTimeout("the admission budget ran out during replay") from exc
        raise AdmissionUnavailable(
            f"the committed journal could not be replayed: {exc}") from exc
    _count("replayed", len(entries))
    return session, {k: anchor[k] for k in ("journal_head", "journal_sequence",
                                            "epoch", "high_water")}, plan


def open_context(*, candidate_rules=(), budget=None, label="admission",
                 cwd=None, env=None, store=None) -> AdmissionContext:
    """A fresh context at the committed head, for ONE request.

    `candidate_rules` are the revisions the request will offer: the plan has to
    see them before the worker is built, or the replay pins a representation the
    candidate cannot be typed under.
    """
    deadline = _Deadline(default_budget() if budget is None else budget)
    if not _slots.acquire(timeout=deadline.remaining()):
        deadline.cancel()
        raise AdmissionUnavailable("every admission context is busy")
    release = _slots.release
    try:
        standby = _standby.take(store=store, candidate_rules=candidate_rules)
        if standby is not None:
            session, anchor, plan = standby
            try:
                deadline.watch(session)
            except AdmissionTimeout:
                raise
            _count("standby_hits")
        else:
            session, anchor, plan = _build(
                candidate_rules=candidate_rules, label=label, deadline=deadline,
                cwd=cwd, env=env, store=store,
            )
        _count("opened")
        context = AdmissionContext(session, anchor=anchor, plan=plan, label=label,
                                   deadline=deadline, release=release)
        release = None
        return context
    except BaseException:
        deadline.cancel()
        raise
    finally:
        if release is not None:
            release()
        _standby.refill(store=store, cwd=cwd, env=env)


# --- a pre-built context, waiting --------------------------------------------------

class _Standby:
    """At most one context, built at the committed head before anyone asks.

    Building a context replays the committed journal, which costs time
    proportional to the history since the last reset -- paid inside the
    request's budget, that makes admission slower as the chain grows. A standby
    moves the replay off the request path. It is still used exactly once: taken,
    evaluated, disposed; and taken only if nothing has committed since it was
    built, which is checked against the store, not remembered.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._ready = None          # (anchor_key, session, anchor, plan)
        self._building = False
        self.enabled = False

    def take(self, *, store=None, candidate_rules=()):
        if not self.enabled:
            return None
        with self._lock:
            entry, self._ready = self._ready, None
        if entry is None:
            return None
        key, session, anchor, plan = entry
        current = None
        try:
            import tau_authority
            current = _anchor_key((store or tau_authority.owner().store)
                                  .committed_anchor(rows=False))
        except Exception:
            current = None
        if current != key or _conflicts(plan, candidate_rules):
            try:
                session.dispose()
            except Exception:
                pass
            return None
        return session, anchor, plan

    def refill(self, *, store=None, cwd=None, env=None) -> None:
        if not self.enabled:
            return
        with self._lock:
            if self._building or self._ready is not None:
                return
            self._building = True

        def _run():
            try:
                session, anchor, plan = _build(
                    candidate_rules=(), label="admission-standby", deadline=None,
                    cwd=cwd, env=env, store=store,
                )
            except Exception as exc:
                logger.info("admission standby not built: %s", exc)
                with self._lock:
                    self._building = False
                return
            with self._lock:
                self._building = False
                stale, self._ready = self._ready, (_anchor_key(anchor), session,
                                                   anchor, plan)
            if stale is not None:
                try:
                    stale[1].dispose()
                except Exception:
                    pass

        threading.Thread(target=_run, name="admission-standby", daemon=True).start()

    def committed(self, *, store=None, cwd=None, env=None) -> None:
        """Committed state moved: the waiting context describes the past."""
        with self._lock:
            stale, self._ready = self._ready, None
        if stale is not None:
            try:
                stale[1].dispose()
            except Exception:
                pass
        self.refill(store=store, cwd=cwd, env=env)

    def discard(self) -> None:
        with self._lock:
            stale, self._ready = self._ready, None
        if stale is not None:
            try:
                stale[1].dispose()
            except Exception:
                pass


_standby = _Standby()


def enable_standby(on: bool = True, *, cwd=None, env=None) -> None:
    """Keep one context pre-built at the committed head (the node does)."""
    _standby.enabled = bool(on)
    if on:
        _standby.refill(cwd=cwd, env=env)
    else:
        _standby.discard()


def committed() -> None:
    """Called after a block commits. Best effort: never raises into the commit."""
    try:
        if _standby.enabled:
            _standby.committed()
    except Exception:
        logger.warning("admission standby could not be refreshed", exc_info=True)


def reset() -> None:
    """Tests and shutdown."""
    _standby.enabled = False
    _standby.discard()
    with _stats_lock:
        for key in list(stats):
            stats[key] = 0
