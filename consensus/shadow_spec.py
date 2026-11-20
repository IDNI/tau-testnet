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
advanced at block commit with exactly the units that entered the
application-rules accumulation (the state-committed canonical bytes, in
block order). After each block that changes the accumulation, the shadow's
normalized spec is snapshotted as {height, shadow_revision, normalized_text,
sha256(normalized_text)} and persisted (db.spec_snapshots); the
`getaccountrules` view is served from those snapshots, never from the live
process and never from submitted text.

Registry-routed (clause) transactions never enter the accumulation, so
they never advance the shadow -- the shadow's revision stream therefore
also cross-checks the routing split. A rebuild feeds the persisted
accumulation from block 0 through a fresh shadow and reproduces the same
snapshots, which is what makes two nodes' views comparable byte-for-byte.

The driver sits behind the same interface the node already uses for the
live engine (`TauInterface.communicate` / `get_current_spec`), so the
snapshot, persistence and view logic is testable against a scripted driver
where the native bindings are unavailable.
"""
import hashlib
import logging
from typing import Callable, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


class TauInterfaceShadowDriver:
    """Drives a real `tau_native.TauInterface` as a shadow.

    Seeded from the node's program file exactly like the live interpreter
    (tau_manager builds `tau_direct_interface` from
    `config.TAU_PROGRAM_FILE`), then fed accumulation units through i0 via
    the interface's own `communicate` -- with `apply_rules_update=False`,
    because the shadow must not re-fire the rules handler (the units it is
    fed are already the committed accumulation; persisting them again is
    the live path's job, and the handler dedups anyway).
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

    Feed discipline is the whole correctness story: `advance` is given the
    units of the post-block accumulation (in production, the lines of the
    committed snapshot's tau_bytes; the accumulation is append-only with
    exact-unit dedup, mirroring `save_effective_tau_spec`) and feeds only
    the ones this shadow has not seen, in order. A unit the accumulation
    already contained is never re-fed.
    """

    def __init__(self, driver):
        self._driver = driver
        self._fed_units: List[str] = []
        self._fed_set = set()
        self._revision: Optional[int] = driver.spec_revision()
        self._text: str = driver.current_spec() or ""

    # -- introspection ----------------------------------------------------

    @property
    def fed_units(self) -> List[str]:
        return list(self._fed_units)

    @property
    def revision(self) -> Optional[int]:
        return self._revision

    @property
    def normalized_text(self) -> str:
        return self._text

    # -- feeding ------------------------------------------------------------

    def advance(
        self,
        units: Iterable[str],
        *,
        height: int,
        block_hash: str,
    ) -> Optional[Dict]:
        """Feed the accumulation units this shadow has not seen yet.

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
        if not fresh:
            return None

        for unit in fresh:
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
        chain order. Returns (shadow, snapshots) -- the snapshots a node
        replaying the persisted accumulation produces, which must equal
        the incremental ones snapshot-for-snapshot (same text, same
        sha256); that equality is the cross-node comparability claim.
        """
        shadow = cls(driver_factory())
        snapshots: List[Dict] = []
        for height, block_hash, units in unit_groups:
            snap = shadow.advance(units, height=height, block_hash=block_hash)
            if snap is not None:
                snapshots.append(snap)
        return shadow, snapshots
