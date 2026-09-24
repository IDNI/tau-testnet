"""One owner of the node's authoritative Tau state.

Before this, "the authoritative evaluator" was a module global that several
paths advanced independently: the startup restore, a governance activation after
a block, the block-apply path, and the miner's save/restore dance. Each was
correct in isolation and none of them could see the others, which is how a node
ends up with two sources of evaluator truth and no way to say which one is
right.

The model is the one the commit protocol already proves in isolation:

    startup          committed snapshot + journal + allocator -> reconstruct
                     -> verify every anchor -> ACTIVE
    local mining     proposal worker -> PreparedBlockCommit -> commit -> PROMOTE
                     that exact worker -> ACTIVE
    imported block   build a proposal from the committed anchor -> same commit
                     -> same promotion -> ACTIVE

There is deliberately NO fallback to the in-process interpreter. Failing to
reconstruct or promote means UNAVAILABLE, and the node reports that rather than
quietly serving an evaluator that describes some other state. A fallback is what
recreates the second source of truth this exists to remove.

Mock execution is a different thing and stays: it runs only under explicitly
requested test configuration, where there is no native engine to be
authoritative about.
"""
from __future__ import annotations

import logging
import threading

logger = logging.getLogger(__name__)

UNINITIALIZED = "UNINITIALIZED"
ACTIVE = "ACTIVE"
#: The authoritative worker is on loan to a proposal. Not serving: it is being
#: stepped with a block that has not committed. It comes back only through
#: promotion (the block committed) or not at all (the proposal was abandoned and
#: the owner rebuilds from the journal).
LENT = "LENT"
UNAVAILABLE = "UNAVAILABLE"

#: Readiness of the AUTHORITY -- separate from tau_manager.tau_ready, which keeps
#: meaning "the in-process interpreter is up" for the admission paths that still
#: use it as an advisory mirror. Conflating the two would make every block's
#: proposal (which takes the authority out of service) stall admission.
authority_ready = threading.Event()


class AuthorityUnavailable(RuntimeError):
    """The authoritative evaluator cannot answer.

    Operational, and never a verdict about a rule, a transaction or a block. A
    caller reports unavailability; it does not substitute another evaluator.
    """


class AuthorityMismatch(RuntimeError):
    """The committed anchors disagree with each other.

    Fail closed: a node whose journal, allocator and commit record describe
    different histories cannot know which one the chain believes.
    """


#: What an operator may ask of startup (`TAU_REBUILD_JOURNAL`).
REBUILD_MISSING = "missing"      # =1: a chain from before the journal existed
REBUILD_DISCARD = "discard"      # an explicit repair of contradictory metadata
REBUILD_MODES = (None, REBUILD_MISSING, REBUILD_DISCARD)


def rebuild_mode_from_env(value):
    """`TAU_REBUILD_JOURNAL` -> a rebuild mode. An unknown value is refused
    rather than read as "no": a typo must not be the difference between a
    repair and a node that silently refuses to start for another reason."""
    text = str(value or "").strip()
    if text in ("", "0"):
        return None
    if text == "1":
        return REBUILD_MISSING
    if text == REBUILD_DISCARD:
        return REBUILD_DISCARD
    raise ValueError(
        f"TAU_REBUILD_JOURNAL={text!r} is not understood; use 1 (rebuild a chain "
        "that has no journal) or discard (replace a contradictory one)"
    )


class AuthoritativeTauOwner:
    """The only way consensus code gets the authoritative evaluator."""

    def __init__(self, *, ready=None, program_baseline=None, store=None):
        self._lock = threading.RLock()
        self._session = None
        self._ready = ready
        self._baseline = program_baseline
        self._store = store
        self.generation = 0
        self.state = UNINITIALIZED
        self.reason = None
        self.descriptor = None
        # The proposal currently holding the lent worker. Only ITS abandonment
        # takes the authority out of service: a stale proposal from an earlier
        # loan, disposed while a newer one borrows, holds a different worker.
        self._borrower = None
        # Set once, at startup, when this node's authority is worker-backed.
        # Everything that has a choice between "the owner" and "the old
        # in-process path" asks this, and once it is True there is no choice:
        # unavailability is reported, never worked around.
        self.enabled = False

    # --- availability ---------------------------------------------------------

    @property
    def store(self):
        if self._store is not None:
            return self._store
        import db
        return db

    @property
    def active(self) -> bool:
        return self.state == ACTIVE and self._session is not None

    def current(self):
        """The authoritative session, or a refusal.

        Never returns a substitute. Callers that cannot proceed without it
        report operational unavailability.
        """
        with self._lock:
            if not self.active:
                raise AuthorityUnavailable(
                    f"authoritative evaluator is {self.state}"
                    + (f": {self.reason}" if self.reason else "")
                )
            return self._session

    def mark_unavailable(self, reason: str) -> None:
        """Take the evaluator out of service. Idempotent.

        Readiness goes down first, then the generation advances, so a result
        prepared against the previous session is refused rather than published.
        """
        with self._lock:
            self.state = UNAVAILABLE
            self.reason = reason
            self._borrower = None
            # An owner that is not serving describes nothing. Keeping the old
            # descriptor would make the next start compare the committed journal
            # against the evaluator it is rebuilding precisely because that
            # evaluator is gone -- and refuse to rebuild.
            self.descriptor = None
            if self._ready is not None:
                try:
                    self._ready.clear()
                except Exception:
                    logger.error("could not clear readiness", exc_info=True)
            self.generation += 1
            logger.warning("authoritative evaluator unavailable: %s", reason)

    def _serve(self, session, descriptor=None) -> None:
        self._session = session
        self.state = ACTIVE
        self.reason = None
        self._borrower = None
        if descriptor is not None:
            self.descriptor = descriptor
        if self._ready is not None:
            try:
                self._ready.set()
            except Exception:
                logger.error("could not set readiness", exc_info=True)

    def dispose(self) -> None:
        with self._lock:
            session, self._session = self._session, None
            self.state = UNINITIALIZED
            if session is not None:
                try:
                    session.dispose()
                except Exception:
                    pass

    # --- promotion ------------------------------------------------------------

    def promote(self, proposal, prepared) -> None:
        """Take ownership of the EXACT worker that computed the committed state.

        The proposal releases it first, so a `finally` that disposes the
        proposal -- and those know nothing about whether the block committed --
        cannot kill the evaluator the node is now serving.
        """
        import tau_commit

        with self._lock:
            worker = proposal.release() if proposal is not None else prepared.worker
            if worker is None:
                raise tau_commit.CommitStateError(
                    "the proposal has already released its evaluator; promotion "
                    "is one-shot"
                )
            if prepared.worker is not None and worker is not prepared.worker:
                raise tau_commit.PreparedCommitMismatch(
                    "the proposal released a different evaluator than the one "
                    "this commit was prepared from"
                )
            old, self._session = self._session, None
            self._serve(worker, descriptor=self._descriptor_from(prepared))
            self.generation += 1
            if old is not None and old is not worker:
                try:
                    old.dispose()
                except Exception:
                    logger.warning("could not dispose the superseded evaluator",
                                   exc_info=True)

    @staticmethod
    def _descriptor_from(prepared):
        import tau_reconstruction

        return tau_reconstruction.ReconstructionDescriptor(
            committed_tip_id=prepared.execution_id,
            journal_head_hash=prepared.journal_final_head,
            journal_sequence=None,
            allocator_state_id=prepared.allocator_final_digest,
            representation_plan_id=prepared.representation_plan_id,
            native_build_id=prepared.native_build_id,
        )

    # --- reconstruction -------------------------------------------------------

    def reconstruct_from_committed(self, *, baseline=None, cwd=None, env=None,
                                   verify=True):
        """Rebuild the authoritative evaluator from committed state alone.

        The committed journal is the authority, not the specification text and
        not the restore plan: spec text was measured to come back with the
        history gone, and the restore plan cannot reproduce a type commitment
        left by a rule that has since been superseded.

        On failure the owner stays UNAVAILABLE. There is nothing else to try.
        """
        import tau_allocator
        import tau_journal
        import tau_reconstruction
        import tau_session

        with self._lock:
            store = self.store
            baseline = baseline or self._baseline
            if not baseline:
                self.mark_unavailable("no program baseline to reconstruct from")
                raise AuthorityUnavailable("no program baseline")

            rows = store.committed_journal_entries()
            journal = tau_journal.journal_from_rows(rows)
            try:
                journal.verify_chain()
            except Exception as exc:
                self.mark_unavailable(f"committed journal is corrupt: {exc}")
                raise AuthorityMismatch(f"committed journal: {exc}") from exc

            # Reconstruct under the plan the committed journal was EXECUTED
            # under. It is stored with the commit rather than re-derived: a
            # proposal plans over every candidate it considered, rejected ones
            # included, so a plan derived afterwards from committed history
            # alone can differ from the one that actually ran -- and the stored
            # contents must hash to the id they were recorded under.
            plan = self._committed_plan(store, journal)

            snapshot = tau_allocator.DbMappingSnapshot()
            try:
                session = tau_session.WorkerSession.reconstruct(
                    baseline, journal=journal, plan=plan, snapshot=snapshot,
                    cwd=cwd, env=env, verify=verify,
                )
            except Exception as exc:
                self.mark_unavailable(f"reconstruction failed: {exc}")
                raise

            old, self._session = self._session, None
            self._serve(session, descriptor=tau_reconstruction.ReconstructionDescriptor(
                journal_head_hash=journal.entries()[-1].link if len(journal) else None,
                journal_sequence=len(journal),
                allocator_state_id=snapshot.epoch,
                representation_plan_id=plan.plan_id,
                native_build_id=tau_reconstruction.native_build_id(),
            ))
            self.generation += 1
            if old is not None:
                try:
                    old.dispose()
                except Exception:
                    pass
            logger.info("authoritative evaluator reconstructed from %d committed "
                        "journal entries", len(journal))
            return session

    def _committed_plan(self, store, journal):
        import tau_journal
        import tau_reconstruction

        latest = None
        getter = getattr(store, "latest_block_commit", None)
        if getter is not None:
            latest = getter()
        if latest is None or not latest.get("plan_json"):
            # Nothing committed yet: plan over the (empty or genesis) history.
            return tau_reconstruction.plan_representation(
                history_rules=[e.rule_text for e in journal.entries()
                               if e.kind == tau_journal.REVISION and e.rule_text],
            )
        plan = tau_reconstruction.RepresentationPlan.from_json(latest["plan_json"])
        if latest.get("plan_id") and plan.plan_id != latest["plan_id"]:
            self.mark_unavailable(
                f"stored representation plan does not hash to its recorded id: "
                f"{plan.plan_id} != {latest['plan_id']}"
            )
            raise AuthorityMismatch("representation plan")
        return plan

    # --- proposals ------------------------------------------------------------

    def build_proposal(self, *, candidate_rules=(), label="proposal",
                       baseline=None, cwd=None, env=None, lend=True):
        """A proposal seeded from the COMMITTED journal.

        Not from the restore plan. The restore plan carries rules only, so a
        proposal built from it has none of the committed input history -- and if
        that proposal is then promoted, the authoritative worker's temporal state
        is not the one a restart reconstructs from the journal. Two answers for
        the same committed state is precisely what this owner exists to rule out.

        History is replayed into the PROPOSAL's own allocator, and the rebuild
        callback reuses it. A throwaway allocator for the history replay would
        let history mint id 5 for one value while the proposal later mints id 5
        for another, inside the same worker.

        One representation covers the committed history and the candidates
        together; deciding from history alone and meeting a candidate afterwards
        is how the pin conflict this design exists to avoid gets reproduced.
        """
        import tau_allocator
        import tau_journal
        import tau_proposal
        import tau_reconstruction
        import tau_session

        store = self.store
        baseline = baseline or self._baseline
        if not baseline:
            raise AuthorityUnavailable("no program baseline to build a proposal on")

        committed = tau_journal.journal_from_rows(store.committed_journal_entries())
        committed.verify_chain()
        fingerprints = committed.fingerprints()
        history = [e.rule_text for e in committed.entries()
                   if e.kind == tau_journal.REVISION and e.rule_text]

        lent = self._try_lend(committed, candidate_rules, label) if lend else None
        if lent is not None:
            plan = lent.plan
        else:
            plan = tau_reconstruction.plan_representation(
                history_rules=history, candidate_rules=list(candidate_rules),
            )
        snapshot = tau_allocator.DbMappingSnapshot()
        allocator = tau_allocator.Allocator(snapshot, width=plan.width,
                                            label="proposal")

        def _respawn(current_plan):
            return tau_session.WorkerSession.spawn(
                baseline, cwd=cwd, env=env, plan=current_plan, allocation=allocator,
            )

        def _spawn(current_plan):
            # Semantic fingerprints, so a replay under a different representation
            # still has to MEAN the same thing. A proposal built on a state the
            # committed journal does not describe is worse than no proposal.
            return tau_session.replay_entries(
                None, committed.entries(), respawn=lambda: _respawn(current_plan),
                expected=fingerprints, start_at_last_reset=True,
            )

        def rebuild(proposal_journal, current_plan):
            session = _spawn(current_plan)
            return tau_session.replay_entries(
                session, proposal_journal.entries(),
                respawn=lambda: _respawn(current_plan),
            )

        committed_entries = committed.entries()

        def _continuation():
            # The proposal journal CONTINUES the committed chain: first entry
            # links to the committed head, sequence numbers carry on.
            return tau_journal.Journal(
                authoritative=False,
                start_seq=len(committed_entries),
                start_prev=committed_entries[-1].link if committed_entries else None,
            )

        if lent is not None:
            # The exact worker that computed the committed state, not an
            # equivalent rebuilt by replay. Its history is already the committed
            # history, so there is nothing to replay and nothing to diverge.
            proposal = tau_proposal.ProposalContext(
                session=lent,
                journal=_continuation(),
                allocator=allocator,
                plan=plan, rebuild=rebuild, label=label, respawn=_respawn,
            )
            proposal.on_abandon = self._lent_abandoned
            with self._lock:
                self._borrower = proposal
            logger.info("proposal %s runs on the authoritative worker (lent)", label)
            return proposal

        return tau_proposal.ProposalContext(
            session=_spawn(plan),
            journal=_continuation(),
            allocator=allocator,
            plan=plan, rebuild=rebuild, label=label, respawn=_respawn,
        )

    def _try_lend(self, committed, candidate_rules, label):
        """Lend the authoritative worker to a proposal, or answer None.

        Only when it provably holds the committed state -- its descriptor names
        the committed journal head -- and the candidates can run under its
        representation: none of them needs a stream PLAIN that this worker has
        interned. A candidate that merely could be optimized further runs
        unoptimized, which costs time and not correctness; one that conflicts
        needs a worker planned for it from the start.
        """
        import tau_reconstruction

        with self._lock:
            if not self.active:
                return None
            session = self._session
            plan = getattr(session, "plan", None)
            if plan is None:
                return None
            head = committed.entries()[-1].link if len(committed) else None
            if self.descriptor is None or self.descriptor.journal_head_hash != head:
                return None
            if candidate_rules:
                needs = tau_reconstruction.plan_representation(
                    candidate_rules=list(candidate_rules))
                if set(needs.plain) & set(plan.interned):
                    return None
            self._session = None
            self.state = LENT
            self.reason = f"lent to {label}"
            self.generation += 1
            if self._ready is not None:
                try:
                    self._ready.clear()
                except Exception:
                    pass
            return session

    def _lent_abandoned(self, proposal) -> None:
        """The proposal holding the authoritative worker was disposed without
        being promoted. That worker has been stepped with a block that will
        never commit, and there is no undo -- so the owner stops claiming to
        serve committed state, and the next proposal rebuilds from the journal.
        """
        with self._lock:
            if self.state == LENT and proposal is self._borrower:
                self.mark_unavailable(
                    f"the lent authoritative worker was abandoned with {proposal.label}"
                )

    # --- startup --------------------------------------------------------------

    def initialize(self, *, baseline=None, cwd=None, env=None, genesis_hash=None,
                   rebuild=None):
        """Make this node's authority worker-backed, from committed state alone.

        Decided by durable state and nothing else:

        * a fresh chain (tip is genesis, nothing committed): execute the genesis
          rules in a worker and commit them as the first journal entries;
        * a chain whose commit records cover its tip: reconstruct and verify;
        * a chain with blocks and NO journal at all -- its Tau state was built by
          the in-process interpreter, before there was a journal: not ready,
          unless the operator asked for the one migration there is,
          `rebuild="missing"` (TAU_REBUILD_JOURNAL=1), a replay of the stored
          blocks through the commit protocol;
        * anything else -- a journal no record describes, a record naming a head
          or tip the journal does not have, a journal that does not reproduce
          itself: CONTRADICTORY. Never repaired implicitly, whatever the flag
          says, because nothing here can know which of the disagreeing records
          the chain believes. Only `rebuild="discard"` (TAU_REBUILD_JOURNAL=
          discard) -- a separate, explicit request -- throws the journal away and
          derives it again from the stored blocks.

        Both modes are idempotent: on a complete, consistent journal they do
        nothing destructive, so a flag left in the environment costs a log line.
        """
        if rebuild not in REBUILD_MODES:
            raise ValueError(f"unknown rebuild mode {rebuild!r}")
        with self._lock:
            self.enabled = True
            if baseline:
                self._baseline = baseline
            store = self.store
            tip = store.current_tip()
            genesis = genesis_hash or store.get_genesis_hash() or None
            latest = store.latest_block_commit()
            _, sequence = store.committed_journal_head()

            contradiction = None
            if latest is None:
                if sequence:
                    contradiction = (
                        f"the journal holds {sequence} entries but no commit "
                        "record describes them"
                    )
                elif not tip or tip == genesis:
                    return self._commit_genesis(genesis, cwd=cwd, env=env)
                elif rebuild in (REBUILD_MISSING, REBUILD_DISCARD):
                    logger.warning("the chain predates the committed journal; "
                                   "rebuilding it from the stored blocks")
                    return self._rebuild_journal(cwd=cwd, env=env)
                else:
                    self.mark_unavailable(
                        "the chain has blocks the committed journal never recorded; "
                        "its Tau state was built by the in-process interpreter. "
                        "Rebuild from genesis to use worker-backed authority "
                        "(start once with TAU_REBUILD_JOURNAL=1)."
                    )
                    raise AuthorityMismatch(self.reason)
            else:
                try:
                    self.verify_committed_anchors()
                except AuthorityMismatch as exc:
                    contradiction = f"committed anchors disagree: {exc}"
                if contradiction is None:
                    import tau_journal
                    import tau_reconstruction
                    try:
                        session = self.reconstruct_from_committed(cwd=cwd, env=env)
                    except (AuthorityMismatch, tau_journal.DivergenceError,
                            tau_reconstruction.ReconstructionMismatch) as exc:
                        # A journal that does not reproduce itself contradicts
                        # its own fingerprints -- corruption, or a different
                        # engine build. Either way nothing here can tell which.
                        # Anything ELSE (a worker that would not start) is
                        # operational and propagates as it is: offering to
                        # discard a sound journal over a spawn failure would be
                        # the worst possible advice.
                        contradiction = f"the committed journal does not reconstruct: {exc}"
                    else:
                        if rebuild is not None:
                            logger.info("TAU_REBUILD_JOURNAL=%s: the committed journal "
                                        "is complete and consistent; nothing to rebuild",
                                        rebuild)
                        return session

            if rebuild == REBUILD_DISCARD:
                logger.warning("discarding the committed journal at the operator's "
                               "request (%s); rebuilding it from the stored blocks",
                               contradiction)
                return self._rebuild_journal(cwd=cwd, env=env)
            self.mark_unavailable(
                f"{contradiction}. Contradictory committed metadata is never "
                "repaired implicitly; to discard the journal and derive it again "
                "from the stored blocks, start once with TAU_REBUILD_JOURNAL=discard"
            )
            raise AuthorityMismatch(self.reason)

    def _rebuild_journal(self, *, cwd=None, env=None):
        """Derive the committed journal by replaying the stored blocks.

        The one migration there is: explicit, requested by the operator, and
        through the same commit protocol every live block takes. Afterwards the
        anchors are verified like any other start.
        """
        import chain_state
        import db as _db

        logger.warning("rebuilding the committed journal from the stored blocks")
        result = chain_state.rebuild_state_from_blockchain(start_block=0)
        if not result.ok:
            self.mark_unavailable(
                f"journal rebuild stopped at block {result.stopped_at_block}: "
                f"{result.reason}"
            )
            raise AuthorityMismatch(self.reason)
        latest = _db.get_canonical_head_block()
        if latest:
            chain_state.commit_state_to_db(
                latest["block_hash"], int(latest["header"]["block_number"]))
        self.verify_committed_anchors()
        return self._session

    def rebuild_genesis(self, genesis_hash, *, cwd=None, env=None):
        """Re-commit genesis at the start of a full rebuild.

        The caller has already reset the committed journal and the genesis
        globals. Canonical state is NOT written here: a rebuild commits it once,
        at the end, for the head it actually replayed -- writing it now would put
        the canonical head back at genesis in the middle of the rebuild.
        """
        with self._lock:
            self.enabled = True
            self.mark_unavailable("rebuilding from genesis")
            return self._commit_genesis(genesis_hash, cwd=cwd, env=env,
                                        persist_canonical=False)

    def _commit_genesis(self, genesis_hash, *, cwd=None, env=None,
                        persist_canonical=True):
        """The genesis rules become the first committed journal entries.

        Mirrors what the in-process startup did -- the same restore plan, in the
        same order, with the same canonical accumulation of the persisted units
        -- but executed in a worker and recorded, so every later reconstruction
        starts from a history that includes them.

        Accumulation first, commit record second. Both are idempotent (the
        accumulation dedups exact units, the record is keyed on the execution),
        so a crash between them simply redoes this on the next start.
        """
        import chain_state
        import tau_allocator
        import tau_commit
        import tau_journal
        import tau_reconstruction
        import tau_session

        store = self.store
        if not self._baseline:
            self.mark_unavailable("no program baseline to build genesis on")
            raise AuthorityUnavailable("no program baseline")

        units = [u for u in chain_state.get_tau_restore_plan(use_persisted_state=True)
                 if str(u.get("text") or "").strip()]
        plan = tau_reconstruction.plan_representation(
            history_rules=[u["text"] for u in units])
        snapshot = tau_allocator.DbMappingSnapshot()
        allocator = tau_allocator.Allocator(snapshot, width=plan.width, label="genesis")
        journal = tau_journal.Journal(authoritative=False)

        try:
            session = tau_session.WorkerSession.spawn(
                self._baseline, cwd=cwd, env=env, plan=plan, allocation=allocator)
        except Exception as exc:
            self.mark_unavailable(f"could not start the genesis worker: {exc}")
            raise
        session.journal = journal

        for unit in units:
            session.apply_rule(unit["text"], target=0, record=True,
                               accumulate=bool(unit.get("persist")))
            receipt = session.last_receipt() or {}
            if not receipt.get("accepted"):
                session.dispose()
                self.mark_unavailable(
                    f"genesis rule {unit.get('label')} was not accepted: "
                    f"{receipt.get('outcome')}"
                )
                raise AuthorityUnavailable(self.reason)

        persisted = [u["text"] for u in units if u.get("persist")]
        for text in persisted:
            chain_state.save_effective_tau_spec(text)
        if persisted and persist_canonical:
            chain_state.commit_state_to_db(genesis_hash or "", 0)

        entries = journal.entries()
        delta = dict(allocator.delta())
        state = tau_commit._worker_state(session)
        store.commit_prepared_block(
            execution_id=f"genesis:{genesis_hash or ''}",
            tip=genesis_hash or "",
            parent=None,
            journal_entries=[tau_commit._entry_row(e) for e in entries],
            expected_journal_seq=0,
            allocation_delta=delta,
            expected_epoch=allocator.epoch,
            journal_head=entries[-1].link if entries else None,
            allocator_digest=tau_commit._allocator_digest(allocator.epoch, delta),
            plan_id=plan.plan_id,
            plan_json=plan.to_json(),
            spec_revision=state.get("spec_revision"),
            time_point=state.get("time_point"),
        )
        session.journal = tau_journal.Journal(authoritative=False)
        old, self._session = self._session, None
        self._serve(session, descriptor=tau_reconstruction.ReconstructionDescriptor(
            committed_tip_id=genesis_hash,
            journal_head_hash=entries[-1].link if entries else None,
            journal_sequence=len(entries),
            allocator_state_id=store.shrink_mapping_epoch(),
            representation_plan_id=plan.plan_id,
            native_build_id=tau_reconstruction.native_build_id(),
        ))
        self.generation += 1
        if old is not None:
            try:
                old.dispose()
            except Exception:
                pass
        logger.info("genesis committed to the journal: %d rule(s)", len(entries))
        return session

    # --- anchors --------------------------------------------------------------

    def verify_committed_anchors(self) -> dict:
        """Every committed anchor must agree before readiness is published.

        A mismatch means NOT READY. It does not mean "try the older restore
        mechanism" -- the whole point is that there is one authority.
        """
        store = self.store
        head, sequence = store.committed_journal_head()
        latest = None
        getter = getattr(store, "latest_block_commit", None)
        if getter is not None:
            try:
                latest = getter()
            except Exception:
                latest = None

        problems = []
        if latest is not None:
            if latest.get("journal_head") != head:
                problems.append(
                    f"commit record names journal head {latest.get('journal_head')}, "
                    f"the journal ends at {head}"
                )
            tip = None
            for name in ("current_tip", "get_canonical_head_hash"):
                fn = getattr(store, name, None)
                if fn is not None:
                    try:
                        tip = fn()
                    except Exception:
                        tip = None
                    break
            if tip is not None and latest.get("tip") and tip != latest.get("tip"):
                problems.append(
                    f"committed tip {tip} is not the one the last commit record "
                    f"names ({latest.get('tip')})"
                )
        elif sequence:
            problems.append(
                f"the journal holds {sequence} entries but no commit record "
                "describes them"
            )

        if self.descriptor is not None and latest is not None:
            if (self.descriptor.journal_head_hash is not None
                    and self.descriptor.journal_head_hash != head):
                problems.append(
                    "the serving evaluator was built from journal head "
                    f"{self.descriptor.journal_head_hash}, committed head is {head}"
                )

        if problems:
            raise AuthorityMismatch("; ".join(problems))
        return {"journal_head": head, "journal_sequence": sequence,
                "commit": latest}


def program_baseline():
    """The interpreter's starting spec: the program file the node boots from.

    One definition for everything that builds an evaluator from scratch -- the
    owner's genesis commit, its reconstruction and every proposal -- because
    two slightly different baselines would be two different starting states.
    """
    import os as _os

    import config

    path = getattr(config, "TAU_PROGRAM_FILE", None) or "genesis.tau"
    if not _os.path.isabs(path):
        path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), path)
    try:
        with open(path) as fh:
            text = fh.read().strip()
    except Exception:
        return None
    if not text:
        return None
    return text if text.lstrip().startswith("always") else f"always ( {text} )."


_owner = None


def owner() -> AuthoritativeTauOwner:
    """The process's authoritative owner."""
    global _owner
    if _owner is None:
        _owner = AuthoritativeTauOwner(ready=authority_ready)
    return _owner


def reset(new=None) -> None:
    """Replace the owner. Tests and startup only."""
    global _owner
    if _owner is not None and new is not _owner:
        _owner.dispose()
    _owner = new
