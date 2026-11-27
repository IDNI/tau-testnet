"""Production shadow replay for the shared-spec rules view (issue #42).

Step 2 of the bounty-02 design. The effective shared spec -- the spec the
engine actually runs after pointwise revision -- cannot be read truthfully
from the append-only accumulation (`chain_state._application_rules_state`
stores submitted canonical text; a later unit can displace part of an
earlier one while both stay in the text), and it must not be scraped from
the live interpreter either: that process's composed spec is eval-only,
possibly shrunk to a node-local width, and per the warnings at its
assignment sites is never hashed or persisted.

So the node keeps a second, isolated TauInterface -- the *shadow* --
genesis-booted from the same program file as the live interpreter and
advanced at block commit with the rule revisions of the committed
journal (tau_journal_v1), in journal order. The journal -- not the
accumulation -- is the feed source because the two disagree exactly
where it matters: the accumulation dedups exact units, so a unit that
is submitted, displaced, and submitted AGAIN (a resend) enters it only
once, while the engine applies the rule per transaction and ends up
running the resent unit. The journal records every application,
resends included, so a shadow fed from it tracks what the engine last
applied. After each block whose journal delta carries rule revisions,
the shadow's normalized spec is snapshotted as {height, shadow_revision,
normalized_text, sha256(normalized_text)} and persisted
(db.spec_snapshots); the `getaccountrules` view is served from those
snapshots, never from the live process and never from submitted text.

Registry-routed (clause) transactions are routed before they reach the
evaluator session, so they record no journal revision and never advance
the shadow -- the shadow's revision stream therefore also cross-checks
the routing split. A rebuild replays the committed journal from
sequence 0 through a fresh shadow and reproduces the same snapshots,
which is what makes two nodes' views comparable byte-for-byte.

The driver sits behind the same interface the node already uses for the
live engine (`TauInterface.communicate` / `get_current_spec`), so the
snapshot, persistence and view logic is testable against a scripted driver
where the native bindings are unavailable.

Step 3 (the survival ledger) reuses the same replay: `advance_journal`
records the per-unit steps of each block (the normalized text right
after each unit was fed), the commit path persists them with the
submitting tx's attribution (db.spec_unit_feeds), and the ledger is
recomputed from the canonical blocks' steps by diffing consecutive
texts at top-level conjunct granularity (`split_spec_fragments`).
Because only canonical blocks are replayed, a reorg that drops a
displacing block restores the displaced unit's status with no explicit
reversal records.
"""
import hashlib
import logging
import re
from typing import Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


# --- normalized-spec fragments (the survival ledger's diff granularity) ---

_ASSIGN_FRAGMENT_RE = re.compile(r"^(o\d+\[t\](?::[A-Za-z]+\[\d+\])?)\s*=")
_ALWAYS_LINE_RE = re.compile(r"^always\s*\((?P<body>.*)\)\s*\.\s*$", re.DOTALL)


def _split_top_level(body: str, separator: str = "&&") -> List[str]:
    """Split `body` on `separator` occurrences at bracket depth 0."""
    parts: List[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and body.startswith(separator, i):
            parts.append(body[start:i])
            i += len(separator)
            start = i
            continue
        i += 1
    parts.append(body[start:])
    return [p.strip() for p in parts if p.strip()]


def split_spec_fragments(text: str) -> List[Tuple[str, str]]:
    """Split a normalized spec text into its top-level conjunct fragments.

    Returns [(key, fragment)] in text order. A fragment that assigns one
    output stream (`oN[t]... = ...`) is keyed by its left-hand side: that
    stream assignment is the identity pointwise revision overwrites, so a
    later unit assigning the same stream displaces exactly that fragment.
    Any other fragment (a condition, an implication, ...) is keyed by its
    own text: it survives verbatim or not at all. This is the granularity
    at which the survival ledger (db.get_survival_ledger) decides what of
    a submitted unit is still in force.
    """
    fragments: List[Tuple[str, str]] = []
    for line in (text or "").split("\n"):
        line = line.strip()
        if not line:
            continue
        match = _ALWAYS_LINE_RE.match(line)
        body = match.group("body") if match else line
        for fragment in _split_top_level(body):
            assign = _ASSIGN_FRAGMENT_RE.match(fragment)
            key = assign.group(1) if assign else fragment
            fragments.append((key, fragment))
    return fragments


class TauInterfaceShadowDriver:
    """Drives a real `tau_native.TauInterface` as a shadow.

    Seeded from the node's program file exactly like the live interpreter
    (tau_manager builds `tau_direct_interface` from
    `config.TAU_PROGRAM_FILE`), then fed journal revision units through
    i0 via the interface's own `communicate` -- with
    `apply_rules_update=False`, because the shadow must not re-fire the
    rules handler (the units it is fed are already committed journal
    revisions; persisting them again is the live path's job, and the
    handler dedups anyway).
    """

    def __init__(self, program_file: Optional[str] = None):
        import config
        import tau_native

        self._tau_native = tau_native
        self._interface = tau_native.TauInterface(
            program_file or config.TAU_PROGRAM_FILE
        )
        self._revision: Optional[int] = tau_native._interpreter_spec_revision(
            self._interface.interpreter
        )

    def feed(self, unit: str) -> Optional[Dict]:
        self._interface.communicate(
            rule_text=unit,
            target_output_stream_index=0,
            apply_rules_update=False,
        )
        receipt = getattr(self._interface, "last_revision_receipt", None)
        if receipt is not None and receipt.get("spec_revision_after") is not None:
            self._revision = receipt["spec_revision_after"]
        return receipt

    def current_spec(self) -> str:
        return self._interface.get_current_spec() or ""

    def spec_revision(self) -> Optional[int]:
        if self._revision is not None:
            return self._revision
        return self._tau_native._interpreter_spec_revision(
            self._interface.interpreter
        )


class ShadowSpec:
    """An isolated spec replay plus the snapshots it produces.

    Feed discipline is the whole correctness story, and there are two
    disciplines because there are two shapes of input:

    * `advance_journal` -- the production discipline. The input is one
      block's rule revisions from the committed journal, in journal
      order, and EVERY unit is fed, resends included: the engine
      applies a rule per transaction, so a unit that was displaced and
      then submitted again must be fed again or the shadow keeps
      showing the displacing unit. `journal_cursor` tracks how far
      into the durable journal this shadow has replayed, so a commit
      path can hand it only the groups it has not consumed.
    * `advance` -- the cumulative-group discipline, retained for
      `replay`: the input is a block's FULL unit list (the accumulation
      lines), so only never-seen units are fed. Feeding a cumulative
      list journal-style would re-apply earlier blocks' units after
      later ones and end on the wrong spec.
    """

    def __init__(self, driver):
        self._driver = driver
        self._fed_units: List[str] = []
        self._fed_set = set()
        self._revision: Optional[int] = driver.spec_revision()
        self._text: str = driver.current_spec() or ""
        self._last_steps: List[Dict] = []
        self._journal_cursor: int = 0
        self._memory_cursor: int = 0
        self._journal_fed_blocks = set()

    # -- introspection ----------------------------------------------------

    @property
    def fed_units(self) -> List[str]:
        return list(self._fed_units)

    @property
    def last_steps(self) -> List[Dict]:
        """The per-unit steps of the most recent `advance`: one
        {unit, text_after, revision_after} per unit actually fed, in feed
        order. `text_after` is the shadow's normalized spec immediately
        after that unit -- the survival ledger's diff input, persisted per
        block by the commit path (db.spec_unit_feeds)."""
        return list(self._last_steps)

    @property
    def revision(self) -> Optional[int]:
        return self._revision

    @property
    def normalized_text(self) -> str:
        return self._text

    @property
    def journal_cursor(self) -> int:
        """How far into the durable committed journal this shadow has
        replayed (a tau_journal_v1 sequence number). Owned by the commit
        path: it reads the groups after the cursor, feeds them with
        `advance_journal`, and advances the cursor past each group. A
        fresh shadow starts at 0, so its first commit-path call replays
        the journal from the beginning -- the restart catch-up."""
        return self._journal_cursor

    @journal_cursor.setter
    def journal_cursor(self, value: int) -> None:
        self._journal_cursor = int(value)

    @property
    def memory_cursor(self) -> int:
        """How many of the in-process journal's accumulated revisions
        this shadow has consumed. The in-process journal carries no
        block attribution and no sequence numbers, so consumption is
        positional: the commit path identifies a block's revisions as
        the next unconsumed run matching the block's submissions and
        advances this cursor past it. Each entry is consumed at most
        once, in journal order -- a resent unit is a later entry, never
        a re-read of its first occurrence, so attribution follows the
        journal position rather than the unit text."""
        return self._memory_cursor

    @memory_cursor.setter
    def memory_cursor(self, value: int) -> None:
        self._memory_cursor = int(value)

    @property
    def journal_fed_blocks(self):
        """Block hashes whose journal revisions this shadow has already
        fed, owned by the commit path as double-record protection:
        feeding is NOT idempotent (a re-fed unit is a resend and changes
        the spec), so a block the recorder is called for twice -- a
        duplicate delivery, a rebuild re-recording a live block -- must
        feed its revisions once, unlike the old accumulation discipline
        where re-feeding was a dedup no-op."""
        return self._journal_fed_blocks

    # -- feeding ------------------------------------------------------------

    def _feed_one(self, unit: str) -> None:
        """Feed one unit and record its step (the ledger's diff input)."""
        receipt = self._driver.feed(unit)
        self._fed_units.append(unit)
        self._fed_set.add(unit)
        revision = None
        if receipt is not None:
            revision = receipt.get("spec_revision_after")
        if revision is None:
            revision = self._driver.spec_revision()
        if revision is not None:
            self._revision = revision
        elif self._revision is not None:
            self._revision += 1
        self._last_steps.append({
            "unit": unit,
            "text_after": self._driver.current_spec() or "",
            "revision_after": self._revision,
        })

    def advance_journal(
        self,
        units: Iterable[str],
        *,
        height: int,
        block_hash: str,
    ) -> Optional[Dict]:
        """Feed one block's journal rule revisions, in journal order.

        Every unit is fed, including a unit this shadow has fed before:
        that is the resend case, where the engine re-applied a displaced
        unit and the running spec is that unit again. Returns the
        snapshot for this block if at least one revision was fed, else
        None -- a block whose rules all went to the clause registry
        records no journal revision, leaves the shadow untouched and
        records nothing.
        """
        self._last_steps = []
        fed = 0
        for raw in units or []:
            unit = (raw or "").strip()
            if not unit:
                continue
            self._feed_one(unit)
            fed += 1
        if not fed:
            return None
        self._text = self._driver.current_spec() or ""
        return {
            "height": int(height),
            "block_hash": block_hash,
            "shadow_revision": self._revision,
            "normalized_text": self._text,
            "sha256": sha256_text(self._text),
        }

    def advance(
        self,
        units: Iterable[str],
        *,
        height: int,
        block_hash: str,
    ) -> Optional[Dict]:
        """Feed the accumulation units this shadow has not seen yet.

        The cumulative-group discipline, retained for `replay`: the
        input is a block's full unit list, so a unit the list already
        contained is never re-fed. The commit path does NOT use this --
        it feeds per-block journal revisions with `advance_journal`,
        where re-feeding is the whole point.

        Returns the snapshot for this block if the accumulation changed
        (at least one new unit was fed), else None -- a block whose rules
        all went to the clause registry, or that carried no rules, leaves
        the shadow untouched and records nothing.
        """
        fresh: List[str] = []
        seen = set(self._fed_set)
        for raw in units or []:
            unit = (raw or "").strip()
            if unit and unit not in seen:
                seen.add(unit)
                fresh.append(unit)
        self._last_steps = []
        if not fresh:
            return None

        for unit in fresh:
            self._feed_one(unit)

        self._text = self._driver.current_spec() or ""
        return {
            "height": int(height),
            "block_hash": block_hash,
            "shadow_revision": self._revision,
            "normalized_text": self._text,
            "sha256": sha256_text(self._text),
        }

    # -- rebuild ------------------------------------------------------------

    @classmethod
    def replay(
        cls,
        driver_factory: Callable[[], object],
        unit_groups: Iterable,
    ):
        """Rebuild from block 0: a fresh shadow fed the same unit groups.

        `unit_groups` yields (height, block_hash, units) per block, in
        chain order, each block's units being its FULL unit list (the
        accumulation lines) -- the cumulative shape `advance` is the
        discipline for. Returns (shadow, snapshots) -- the snapshots a
        node replaying the persisted accumulation produces, which must
        equal the incremental ones snapshot-for-snapshot (same text,
        same sha256); that equality is the cross-node comparability
        claim. The production rebuild (chain_state.
        rebuild_shadow_from_journal) instead replays the journal's
        per-block revision groups with `advance_journal`.
        """
        shadow = cls(driver_factory())
        snapshots: List[Dict] = []
        for height, block_hash, units in unit_groups:
            snap = shadow.advance(units, height=height, block_hash=block_hash)
            if snap is not None:
                snapshots.append(snap)
        return shadow, snapshots
