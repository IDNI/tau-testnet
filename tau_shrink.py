"""
Eval-only shrinking of long equality-only bitvectors for the Tau interpreter.

Long bitvectors that are only ever compared for equality (`=`) or emptiness
(`!= 0`) -- wallet pubkeys, hashes -- are expensive in the native interpreter.
This module interns each distinct long value to a small integer in the local
`tau_shrink_ids` table (db.get_shrink_id) and rewrites the formula text + input
stream values to the small `bv[64]` form *right before* the interpreter runs.

The intern table is the shrink layer's OWN dense id space. It used to share
`tau_strings` with the per-block consensus yids (proposer / parent hash / claims
json), which made the assigned ids -- and therefore the shrink width -- track the
block count rather than the address count.

CRITICAL INVARIANTS (see plan: the-problem-in-replicated-taco.md):

* Shrinking is EVAL-ONLY and NODE-LOCAL. The shrunk id is a per-node
  autoincrement value. It is safe for the consensus-critical boolean outputs
  ONLY because those depend solely on equality/emptiness relations, which are
  invariant under any injective relabeling.
* The shrunk form must NEVER reach persisted spec, the consensus state hash,
  block data, or an output stream compared across nodes. Callers persist the
  `canonical_text`, never the `runtime_text`.
* Width is NOT the classifier. A value is shrunk only when the conservative
  usage scanner proves it is used exclusively in `=`/`!=` contexts. Anything
  ambiguous fails closed (not shrunk). Prefer false negatives over false
  positives.
* Interning is width-tagged and value-canonical: equal bitvectors of the same
  declared width always map to the same id (zero-padded lowercase hex key).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import db

logger = logging.getLogger(__name__)

# Shrunk runtime width. Reuses tau_manager.DEFAULT_RULE_BV_WIDTH (64) without
# importing it (avoid an import cycle: tau_manager imports this module).
# Reserved id for the empty/zero value. tau_shrink_ids autoincrements from 1, so
# 0 is never assigned to a real value and is a safe "empty" sentinel.
RESERVED_EMPTY_ID = 0
# Only literals/streams at least this wide are shrink candidates. Arithmetic
# operands (amounts, balances, heights) are decimals well under this and never match.
MIN_SHRINK_WIDTH = 128

# --- Dynamic shrink width -----------------------------------------------------
# The OUTPUT width used for shrunk literals/streams is the SMALLEST byte-multiple
# bv that holds the current interned-address count, chosen ONCE per process (the
# native engine's per-stream bv typing is process-global and sticky -- it cannot
# change within a running process). Usable id range at width W is [1, 2^W - 2]
# (0 reserved for empty; the top value reserved as the grow boundary), so:
#   count <= 254      -> bv[8]
#   count <= 65534    -> bv[16]
#   count <= 2^24 - 2 -> bv[24] ...
# When an interned id would exceed the current width, the node must re-exec (a
# fresh process re-types at the next width); see ShrinkWidthOverflow.
DEFAULT_SHRINK_WIDTH = 8
_current_shrink_width: int = DEFAULT_SHRINK_WIDTH
# True once the width has been chosen for this process. A later recompute is
# REFUSED, not applied: the engine types each stream on first use and never
# re-types it, so widening in-process makes every subsequent rule
# (`i12[t]:bv[16]`) clash with the interpreter's existing bv[8] typing --
# "Incompatible type information in i12:untyped, expected :bv[8], found :bv[16]".
# Growth is handled by re-exec (ShrinkWidthOverflow) instead.
_width_pinned: bool = False

# Output stream indices whose values are boolean verdicts, never addresses.
# Used by the (deferred) output-expansion guard to avoid false alarms on 0/1.
_VERDICT_OUTPUT_STREAMS = frozenset({0, 1, 5, 6, 7})


def _max_usable_id(width: int) -> int:
    return (1 << width) - 2


def width_for_count(count: int) -> int:
    """Smallest byte-multiple bv width whose usable range [1, 2^W-2] holds `count`."""
    w = DEFAULT_SHRINK_WIDTH
    while count > _max_usable_id(w):
        w += 8
    return w


def current_shrink_width() -> int:
    return _current_shrink_width


def set_shrink_width(width: int, *, pin: bool = False) -> None:
    global _current_shrink_width, _width_pinned
    _current_shrink_width = max(DEFAULT_SHRINK_WIDTH, int(width))
    if pin:
        _width_pinned = True


def reset_shrink_width(width: int = DEFAULT_SHRINK_WIDTH) -> None:
    """Drop the process pin so a fresh width can be chosen. Tests only -- a live
    node grows its width by re-exec, never by resetting the pin in place."""
    global _width_pinned
    _width_pinned = False
    set_shrink_width(width)


def set_shrink_width_from_db() -> int:
    """Pick the process shrink width from the current intern-table max id.

    Call ONCE at interpreter init (process start). Later calls are REFUSED: the
    engine's per-stream bv typing is sticky, so recomputing mid-process (restores
    run per block) would emit rules at a width the live interpreter cannot type.
    A wider recomputed value only means the next NEW interned id will overflow,
    and `tau_manager._handle_width_overflow` re-execs -- the one safe way to grow.

    The max is read from the shrink id space alone (db.get_max_shrink_id), so it
    reflects the number of distinct interned addresses. It does NOT make the pin
    redundant: a process that interns its 255th address still has to re-exec.
    """
    try:
        max_id = db.get_max_shrink_id()
    except Exception:
        max_id = 0
    width = width_for_count(max_id or 0)
    if _width_pinned:
        if width != _current_shrink_width:
            logger.warning(
                "tau_shrink: refusing shrink width bv[%d] -> bv[%d] mid-process "
                "(max interned id=%s); per-stream typing is sticky, so growth "
                "waits for the next re-exec.",
                _current_shrink_width, width, max_id,
            )
        return _current_shrink_width
    set_shrink_width(width, pin=True)
    logger.info("tau_shrink: shrink width set to bv[%d] (max interned id=%s)",
                _current_shrink_width, max_id)
    return _current_shrink_width


class ShrinkUnavailable(Exception):
    """Raised internally when a value cannot be interned (DB error).

    Callers treat this as a transient, fail-closed condition: never produce a
    partially-shrunk spec, never emit an invalid literal.
    """


class ShrinkWidthOverflow(Exception):
    """Raised when an interned id no longer fits the current process shrink width.

    The id is already persisted in tau_shrink_ids, so a FRESH process will pick a
    wider width. The node must re-exec (NOT rebuild the interpreter in-process --
    the engine's per-stream bv typing is sticky). Distinct from ShrinkUnavailable
    so it is NOT swallowed by fail-closed disable paths.
    """


class ShrinkTypeConflict(Exception):
    """A rule references a stream the live process already typed at the shrunk
    width, but the classifier refuses to shrink it here -- so NEITHER form can be
    typed and there is no correct text to dispatch.

    Deliberately not a subclass of ShrinkUnavailable or ShrinkWidthOverflow:
    neither the "fall back to full width" handler nor the re-exec handler must
    swallow it. Node-local, never a consensus verdict about the rule.
    """


@dataclass(frozen=True)
class PreparedTauSpec:
    """The explicit two-representation contract handed back by prepare_rule.

    canonical_text -- full-width; the ONLY thing persisted/hashed.
    runtime_text   -- shrunk; fed to the interpreter.
    shrink_enabled -- False => runtime_text == canonical_text (no shrink applied).
    shrunk_streams -- input stream indices whose runtime values must be shrunk
                      to stay consistent with the shrunk rule literals.
    wide_streams_unshrunk -- wide input streams left at full width by this
                      preparation (fallbacks included).
    """

    canonical_text: str
    runtime_text: str
    shrink_enabled: bool
    shrunk_streams: frozenset
    # Input streams the text references at >= MIN_SHRINK_WIDTH that are NOT shrunk.
    # Populated on EVERY return path, including the fallbacks, so a caller can see
    # that a stream stayed full-width and compare that against the live process.
    wide_streams_unshrunk: frozenset = frozenset()


# --- Canonicalisation / interning ---------------------------------------------

def _hex_is_zero(hex_digits: str) -> bool:
    return len(hex_digits) > 0 and set(hex_digits) <= {"0"}


def canonical_intern_key(hex_digits: str, width: int) -> str:
    """Width-tagged, value-canonical key for the intern store.

    Lowercase, strip `#x`/whitespace, zero-pad to width/4 hex chars, prefix
    `bv<width>:`. So `{ #x01 }:bv[384]` and `{ #x000..01 }:bv[384]` map to the
    SAME key. Width is part of the key because Tau bitvectors are typed and only
    same-width equality is valid -- so equal-width values share an id, and a
    rule literal and its matching stream value (both the declared width) always
    collide on the same id.
    """
    cleaned = hex_digits.strip().lower()
    if cleaned.startswith("#x"):
        cleaned = cleaned[2:]
    pad = max(0, (width + 3) // 4)
    return f"bv{width}:{cleaned.zfill(pad)}"


# An allocator override, installed for the duration of a speculative evaluation.
# `db.get_shrink_id` inserts and COMMITS, so without this a proposal that is later
# rejected permanently burns an id and moves the mapping epoch -- the interpreter
# would be isolated while the allocator was not.
_allocator = None


class _SpeculativeAllocator:
    """Reads committed ids; mints new ones in memory only.

    Equality semantics are invariant under any injective relabeling, which is the
    property this whole module rests on, so a speculative id that never leaves the
    worker may differ from the one the authoritative path later commits.
    """

    def __init__(self, high_water: int):
        self._local = {}
        self._next = int(high_water)

    def __call__(self, key: str) -> int:
        committed = db.lookup_shrink_id(key)
        if committed is not None:
            return committed
        if key not in self._local:
            self._next += 1
            self._local[key] = self._next
        return self._local[key]

    @property
    def minted(self) -> dict:
        return dict(self._local)


class speculative_allocation:
    """Install a private allocator for the duration of a speculative evaluation."""

    def __init__(self, high_water=None):
        self._high_water = (
            db.get_max_shrink_id() if high_water is None else int(high_water)
        )
        self.allocator = None
        self._previous = None

    def __enter__(self):
        global _allocator
        self.allocator = _SpeculativeAllocator(self._high_water)
        self._previous = _allocator
        _allocator = self.allocator
        return self.allocator

    def __exit__(self, *exc):
        global _allocator
        _allocator = self._previous
        return False


def intern_value(hex_digits: str, width: int) -> int:
    """Intern a hex bitvector value to its small id. Zero -> RESERVED_EMPTY_ID.

    `width` is the ORIGINAL value width (e.g. 384) used for the canonical key.
    Raises ShrinkUnavailable on DB error; ShrinkWidthOverflow if the id no longer
    fits the current process OUTPUT shrink width (-> node must re-exec wider).
    """
    if _hex_is_zero(hex_digits):
        return RESERVED_EMPTY_ID
    key = canonical_intern_key(hex_digits, width)
    try:
        allocate = _allocator if _allocator is not None else db.get_shrink_id
        id_num = int(allocate(key))
    except Exception as exc:  # DB unavailable, malformed id, etc.
        raise ShrinkUnavailable(f"intern failed: {exc}") from exc
    if id_num < 0:
        raise ShrinkUnavailable(f"interned id {id_num} is negative")
    if id_num > _max_usable_id(_current_shrink_width):
        raise ShrinkWidthOverflow(
            f"interned id {id_num} exceeds bv[{_current_shrink_width}] usable range; "
            f"process must re-exec to widen"
        )
    return id_num


# --- Tokeniser ----------------------------------------------------------------
#
# W1: the scanner recognises a deliberately RESTRICTED fragment and consumes every
# token. Anything it cannot account for disqualifies the streams it touches -- it
# never silently classifies as NEUTRAL and keeps going.

_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<bvlit>\{[^{}]*\}\s*:\s*bv\[\s*\d+\s*\])
    | (?P<streamref>[io]\d+\s*\[[^\[\]]*\]\s*(?::\s*bv\[\s*\d+\s*\])?)
    | (?P<hexnum>\#x[0-9a-fA-F]+|\#b[01]+)
    | (?P<num>\d+)
    | (?P<op><->|->|<-|\^\^|!=|<=|>=|<<|>>|&&|\|\||'|[=<>+\-*/%&|\^!])
    | (?P<group>[()])
    | (?P<dot>\.)
    | (?P<comma>,)
    | (?P<ident>[A-Za-z_]\w*)
    | (?P<colon>:)
    | (?P<other>.)
    """,
    re.VERBOSE,
)

# A stream reference, with its time expression and optional type annotation kept as
# separate spans so a rewrite can touch the ANNOTATION ONLY and leave `[t-1]` alone.
_STREAMREF_RE = re.compile(
    r"([io])(\d+)\s*\[\s*(?P<time>t\s*[-+]\s*\d+|t|\d+)\s*\]"
    r"(?P<ann>\s*:\s*bv\[\s*(?P<width>\d+)\s*\])?"
)
_BVLIT_RE = re.compile(r"\{\s*(?P<body>[^{}]*?)\s*\}\s*:\s*bv\[\s*(?P<width>\d+)\s*\]")
# A bare `iN` / `oN` that did NOT parse as a stream reference: an occurrence the
# analyzer does not understand. It must disqualify, never disappear from the audit.
_BARE_STREAM_IDENT_RE = re.compile(r"^([io])(\d+)$")

# Operators that mean "this operand is not an equality/emptiness operand".
# `'` (postfix complement) is here deliberately: complementing an interned id
# computes over a node-local value, which is a wrong answer, not a crash.
_DISQ_OPS = frozenset(
    {"<", ">", "<=", ">=", "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", "!", "'"}
)
_EQ_OPS = frozenset({"=", "!="})
# Boolean connectives: they delimit formulas, so an operand beside one is still a
# complete comparison. They are NOT disqualifying and NOT equality operators.
_WFF_OPS = frozenset({"->", "<-", "<->", "^^", "&&", "||"})
# Temporal / quantifier keywords that legitimately precede '(' and are NOT
# function calls. Any OTHER identifier before a '(' wraps the operand in something
# this analyzer cannot reason about -> fail closed, through ANY nesting depth.
_KEYWORDS_BEFORE_PAREN = frozenset({"always", "sometimes", "all", "ex"})


@dataclass
class _Tok:
    kind: str
    text: str
    start: int
    end: int


@dataclass
class _Ref:
    """One stream occurrence, with source spans."""
    pos: int            # token index
    io: str             # "i" or "o"
    index: int
    time_expr: str      # verbatim, e.g. "t" or "t-1"
    width: int          # declared width, or -1 when unannotated
    ann_start: int      # absolute span of the ":bv[N]" annotation, -1 when absent
    ann_end: int


def _tokenize(text: str) -> list:
    toks = []
    for m in _TOKEN_RE.finditer(text):
        kind = m.lastgroup
        if kind == "ws":
            continue
        toks.append(_Tok(kind, m.group(), m.start(), m.end()))
    return toks


def _ref_of(tok: _Tok, pos: int):
    """Parse a streamref token into a _Ref, or None if it is not one."""
    m = _STREAMREF_RE.match(tok.text)
    if not m:
        return None
    width = int(m.group("width")) if m.group("width") is not None else -1
    if m.group("ann") is not None:
        ann_start = tok.start + m.start("ann")
        ann_end = tok.start + m.end("ann")
    else:
        ann_start = ann_end = -1
    time_expr = re.sub(r"\s+", "", m.group("time"))
    return _Ref(pos, m.group(1), int(m.group(2)), time_expr, width, ann_start, ann_end)


def _streamref_info(tok: _Tok):
    """Back-compat shim: (index, width_or_None) for an INPUT stream token."""
    ref = _ref_of(tok, -1)
    if ref is None or ref.io != "i":
        return None
    return ref.index, (None if ref.width < 0 else ref.width)


def _lit_of(tok: _Tok):
    """Validate a bitvector literal. Returns a dict or None.

    A literal is internable only if its body is a COMPLETE supported constant that
    is representable at its declared width -- never an arbitrary `#x`-prefixed
    string, and never an expression.
    """
    m = _BVLIT_RE.match(tok.text)
    if not m or m.end() != len(tok.text):
        return None
    body = m.group("body").strip()
    width = int(m.group("width"))
    low = body.lower()
    if low.startswith("#x"):
        digits = low[2:]
        if not digits or any(c not in "0123456789abcdef" for c in digits):
            return None
        value, hex_digits = int(digits, 16), digits
    elif low.startswith("#b"):
        bits = low[2:]
        if not bits or any(c not in "01" for c in bits):
            return None
        value = int(bits, 2)
        hex_digits = format(value, "x")
    elif low.isdigit():
        value = int(low)
        hex_digits = format(value, "x")
    else:
        return None
    if width <= 0 or value >= (1 << width):
        return None  # not representable at its declared width
    return {
        "width": width,
        "value": value,
        "hex_digits": hex_digits,
        "is_zero": value == 0,
        "body_start": tok.start + m.start("body"),
        "body_end": tok.start + m.end("body"),
    }


def _bvlit_info(tok: _Tok):
    """Back-compat shim: (hex_digits_or_None, width, is_zero)."""
    info = _lit_of(tok)
    if info is None:
        return None
    if info["is_zero"]:
        return None if info["hex_digits"] in ("", None) else info["hex_digits"], info["width"], True
    return info["hex_digits"], info["width"], False


def _enclosing_is_funccall(toks: list, idx: int) -> bool:
    """True if the operand at idx sits inside `<ident>( ... )` at ANY nesting depth.

    The old version stopped at the nearest enclosing paren, so an extra pair of
    parentheses defeated it.
    """
    depth = 0
    j = idx - 1
    while j >= 0:
        t = toks[j]
        if t.kind == "group" and t.text == ")":
            depth += 1
        elif t.kind == "group" and t.text == "(":
            if depth == 0:
                if j > 0 and toks[j - 1].kind == "ident":
                    if toks[j - 1].text.lower() not in _KEYWORDS_BEFORE_PAREN:
                        return True
                # keep walking outward -- nesting must not launder the context
                idx = j
                j = idx - 1
                continue
            depth -= 1
        j -= 1
    return False


def _neighbor_class(tok) -> str:
    """Classify an adjacent token as EQ / DISQ / NEUTRAL."""
    if tok is None:
        return "NEUTRAL"
    if tok.kind == "op":
        if tok.text in _EQ_OPS:
            return "EQ"
        if tok.text in _DISQ_OPS:
            return "DISQ"
    return "NEUTRAL"


@dataclass
class _Plan:
    """What prepare_rule intends to do, and the evidence the audit re-checks."""
    shrunk: set                 # input stream indices to shrink
    refs: list                  # every _Ref found
    unknown_streams: set        # streams with an occurrence we could not parse
    unresolved: set             # streams whose canonical width is not established
    ann_edits: list             # (start, end, replacement) for annotations
    lit_edits: list             # (tok, kind) approved literal rewrites
    edges: list                 # (left_pos, right_pos, op_text)


def _classify(text: str, exclude_streams=frozenset()):
    """Return (shrunk_streams:set[int], literal_edits:list[(tok, kind)], toks).

    Conservative supported-subset analysis. A stream is shrinkable only when every
    one of its occurrences is an operand of a supported equality/emptiness edge
    whose opposite operand carries the SAME declared canonical width, its own
    annotation is present and consistent everywhere, and nothing about it is
    unparsed. Comparing two operands of DIFFERENT canonical widths is never made
    to look well-typed by narrowing both sides.
    """
    plan = _plan(text, exclude_streams)
    return plan.shrunk, plan.lit_edits, _tokenize(text)


def _plan(text: str, exclude_streams=frozenset()) -> _Plan:
    toks = _tokenize(text)
    n = len(toks)

    refs: list = []
    occurrences: dict = {}
    unknown: set = set()
    for pos, t in enumerate(toks):
        if t.kind == "streamref":
            ref = _ref_of(t, pos)
            if ref is None:
                # a streamref-shaped token we cannot parse: disqualify loudly
                m = re.match(r"([io])(\d+)", t.text)
                if m and m.group(1) == "i":
                    unknown.add(int(m.group(2)))
                continue
            refs.append(ref)
            if ref.io == "i":
                occurrences.setdefault(ref.index, []).append(ref)
        elif t.kind == "ident":
            m = _BARE_STREAM_IDENT_RE.match(t.text)
            if m and m.group(1) == "i":
                unknown.add(int(m.group(2)))  # `i12` with no `[...]` -> not understood

    # Supported equality edges: both operands are single tokens directly adjacent
    # to the operator, and each is a COMPLETE operand -- nothing value-ish or
    # disqualifying immediately outside it. This is what rejects juxtaposition-AND
    # (`= A B`, where the right operand is really a compound) and a postfix
    # complement (`= A'`), neither of which involves an operator the scanner could
    # have enumerated.
    _VALUEISH = {"bvlit", "streamref", "num", "hexnum", "ident"}

    def _operand_complete(pos: int, outward: int) -> bool:
        j = pos + outward
        if j < 0 or j >= n:
            return True
        nb = toks[j]
        if nb.kind in _VALUEISH:
            return False
        if nb.kind == "op" and nb.text in _DISQ_OPS:
            return False
        return True

    edges = []
    for pos, t in enumerate(toks):
        if t.kind == "op" and t.text in _EQ_OPS:
            if pos - 1 < 0 or pos + 1 >= n:
                continue
            if not _operand_complete(pos - 1, -1) or not _operand_complete(pos + 1, +1):
                continue          # compound operand -> outside the supported fragment
            edges.append((pos - 1, pos + 1, t.text))

    edge_of: dict = {}
    for lpos, rpos, op in edges:
        edge_of.setdefault(lpos, []).append((rpos, op))
        edge_of.setdefault(rpos, []).append((lpos, op))

    def operand_width(pos):
        """Declared canonical width of a single-token operand, or None."""
        t = toks[pos]
        if t.kind == "streamref":
            ref = _ref_of(t, pos)
            return None if ref is None or ref.width < 0 else ref.width
        if t.kind == "bvlit":
            info = _lit_of(t)
            return None if info is None else info["width"]
        if t.kind == "num" and t.text == "0":
            return 0      # bare zero: width-agnostic emptiness operand
        return None

    def is_zero_operand(pos):
        t = toks[pos]
        if t.kind == "num" and t.text == "0":
            return True
        if t.kind == "bvlit":
            info = _lit_of(t)
            return bool(info and info["is_zero"])
        return False

    # Per-stream resolution: one consistent, explicit, wide-enough annotation.
    unresolved: set = set(unknown)
    for sidx, occ in occurrences.items():
        widths = {r.width for r in occ}
        if -1 in widths or len(widths) != 1:
            unresolved.add(sidx)          # unannotated or inconsistent -> never invent one
    candidates = set()
    for sidx, occ in occurrences.items():
        if sidx in unresolved or sidx in exclude_streams:
            continue
        if occ[0].width < MIN_SHRINK_WIDTH:
            continue
        candidates.add(sidx)

    def occurrence_ok(ref: _Ref, live: set) -> bool:
        partners = edge_of.get(ref.pos)
        if not partners:
            return False                              # not an equality operand
        if _enclosing_is_funccall(toks, ref.pos):
            return False
        for other_pos, _op in partners:
            if is_zero_operand(other_pos):
                continue                              # emptiness check: always fine
            ow = operand_width(other_pos)
            if ow is None or ow != ref.width:
                return False                          # W1.3: canonical widths must AGREE
            ot = toks[other_pos]
            if ot.kind == "bvlit":
                continue
            if ot.kind == "streamref":
                oref = _ref_of(ot, other_pos)
                if oref is None or oref.io != "i" or oref.index not in live:
                    return False
                continue
            return False
        return True

    # Dependency closure, once, to a fixpoint.
    changed = True
    while changed:
        changed = False
        for sidx in list(candidates):
            if not all(occurrence_ok(r, candidates) for r in occurrences[sidx]):
                candidates.discard(sidx)
                changed = True

    # Literal edits derive from the SETTLED set, in both orientations.
    lit_edits = []
    seen_lit = set()
    for sidx in candidates:
        for ref in occurrences[sidx]:
            for other_pos, _op in edge_of.get(ref.pos, []):
                if other_pos in seen_lit:
                    continue
                ot = toks[other_pos]
                if ot.kind == "bvlit":
                    info = _lit_of(ot)
                    if info is None:
                        continue
                    seen_lit.add(other_pos)
                    lit_edits.append((ot, "zero" if info["is_zero"] else "hex"))
                elif ot.kind == "num" and ot.text == "0":
                    seen_lit.add(other_pos)
                    lit_edits.append((ot, "zero"))

    return _Plan(
        shrunk=candidates,
        refs=refs,
        unknown_streams=unknown,
        unresolved=unresolved,
        ann_edits=[],
        lit_edits=lit_edits,
        edges=edges,
    )


def wide_input_streams(text: str) -> frozenset:
    """Input streams referenced at >= MIN_SHRINK_WIDTH, from a standalone scan.

    Used on the fallback paths so a classifier failure cannot report a falsely
    empty set.
    """
    out = set()
    try:
        for t in _tokenize(text or ""):
            if t.kind != "streamref":
                continue
            ref = _ref_of(t, -1)
            if ref is not None and ref.io == "i" and ref.width >= MIN_SHRINK_WIDTH:
                out.add(ref.index)
    except Exception:  # a scan must never break the eval path
        pass
    return frozenset(out)


# --- Rewrite ------------------------------------------------------------------

def _shrunk_streamref_text(tok: _Tok, width: int) -> str:
    """Back-compat helper. Rewrites ONLY the type annotation, preserving the time
    expression -- `i12[t-1]:bv[384]` must not become `i12[t]:bv[W]`."""
    ref = _ref_of(tok, -1)
    if ref is None:
        return tok.text
    return f"{ref.io}{ref.index}[{ref.time_expr}]:bv[{width}]"


def _apply_edits(text: str, edits: list) -> str:
    """edits: list of (start, end, replacement). Applied right-to-left."""
    for start, end, repl in sorted(edits, key=lambda e: e[0], reverse=True):
        text = text[:start] + repl + text[end:]
    return text


class ShrinkAuditFailure(Exception):
    """The rewrite did not match the plan. The classifier and the rewriter
    disagree, which is the invariant this module rests on -- never dispatch."""


def _audit(canonical: str, runtime: str, plan: _Plan, width: int, id_by_pos: dict) -> None:
    """Independent edit-coverage audit.

    Deliberately does NOT re-run the classifier on the rewritten text -- that would
    share its blind spots. It compares the tokens actually produced against the
    ORIGINAL occurrence/type information: only approved type-annotation and
    literal-payload spans may differ, every other token is identical, time
    expressions are unchanged, and each literal substitution matches the plan.
    """
    before = _tokenize(canonical)
    after = _tokenize(runtime)
    if len(before) != len(after):
        raise ShrinkAuditFailure(
            f"token count changed: {len(before)} -> {len(after)}"
        )
    approved_lit = {tok.start: kind for tok, kind in plan.lit_edits}
    covered = {s: 0 for s in plan.shrunk}
    for pos, (b, a) in enumerate(zip(before, after)):
        if b.kind != a.kind:
            approved_zero = (
                b.kind == "num" and a.kind == "bvlit"
                and approved_lit.get(b.start) == "zero"
            )
            if not approved_zero:
                raise ShrinkAuditFailure(f"token {pos} kind {b.kind} -> {a.kind}")
        if b.text == a.text:
            if b.kind in ("bvlit", "num") and b.start in approved_lit:
                raise ShrinkAuditFailure(f"planned literal at {pos} was not rewritten")
            continue
        # Changed: it must be an approved annotation or literal-payload edit.
        if b.kind == "streamref":
            rb, ra = _ref_of(b, pos), _ref_of(a, pos)
            if rb is None or ra is None:
                raise ShrinkAuditFailure(f"unparsable streamref at {pos}")
            if rb.io != ra.io or rb.index != ra.index:
                raise ShrinkAuditFailure(f"stream identity changed at {pos}")
            if rb.time_expr != ra.time_expr:
                raise ShrinkAuditFailure(
                    f"time expression changed at {pos}: {rb.time_expr} -> {ra.time_expr}"
                )
            if rb.index not in plan.shrunk:
                raise ShrinkAuditFailure(f"unplanned stream rewrite at {pos}")
            if ra.width != width:
                raise ShrinkAuditFailure(
                    f"stream {rb.index} rewritten to bv[{ra.width}], expected bv[{width}]"
                )
            covered[rb.index] = covered.get(rb.index, 0) + 1
        elif b.kind in ("bvlit", "num"):
            kind = approved_lit.get(b.start)
            if kind is None:
                raise ShrinkAuditFailure(f"unplanned literal rewrite at {pos}")
            info = _lit_of(a)
            if info is None:
                raise ShrinkAuditFailure(f"rewritten literal at {pos} is not a valid constant")
            if info["width"] != width:
                raise ShrinkAuditFailure(
                    f"literal at {pos} rewritten at bv[{info['width']}], expected bv[{width}]"
                )
            expected = 0 if kind == "zero" else id_by_pos.get(b.start)
            if expected is None or info["value"] != expected:
                raise ShrinkAuditFailure(
                    f"literal at {pos} encodes {info['value']}, plan said {expected}"
                )
        else:
            raise ShrinkAuditFailure(f"unapproved change at token {pos}: {b.text!r} -> {a.text!r}")
    # Every occurrence of a shrunk stream must have been rewritten.
    for sidx in plan.shrunk:
        want = sum(1 for r in plan.refs if r.io == "i" and r.index == sidx)
        if covered.get(sidx, 0) != want:
            raise ShrinkAuditFailure(
                f"stream {sidx}: rewrote {covered.get(sidx, 0)} of {want} occurrences"
            )


def prepare_rule(full_width_text: str, exclude_streams=frozenset()) -> PreparedTauSpec:
    """Produce the canonical/runtime split for a normalized full-width rule.

    On DB/intern failure, or on any audit failure, the whole spec falls back to
    full-width (shrink disabled, all-or-nothing -- never a partial mix). MAY raise
    ShrinkWidthOverflow if a rule literal interns to an id beyond the current
    process width -- propagated deliberately so the node can re-exec (do not swallow).
    """
    canonical = full_width_text or ""
    if not canonical.strip():
        return PreparedTauSpec(canonical, canonical, False, frozenset(), frozenset())

    width = current_shrink_width()

    try:
        plan = _plan(canonical, exclude_streams)
    except Exception as exc:  # classifier must never break the eval path
        logger.warning("tau_shrink: classify failed, disabled reason=%s", exc)
        return PreparedTauSpec(
            canonical, canonical, False, frozenset(), wide_input_streams(canonical)
        )

    if not plan.shrunk and not plan.lit_edits:
        return PreparedTauSpec(
            canonical, canonical, False, frozenset(), wide_input_streams(canonical)
        )

    # Intern ALL literals first (all-or-nothing). On DB failure: full-width.
    # ShrinkWidthOverflow is NOT caught here -- it must propagate to trigger re-exec.
    edits = []
    id_by_pos = {}
    try:
        for tok, kind in plan.lit_edits:
            if kind == "zero":
                id_by_pos[tok.start] = 0
                edits.append((tok.start, tok.end, f"{{ 0 }}:bv[{width}]"))
            else:
                info = _lit_of(tok)
                id_num = intern_value(info["hex_digits"], info["width"])
                id_by_pos[tok.start] = id_num
                edits.append((tok.start, tok.end, f"{{ {id_num} }}:bv[{width}]"))
    except ShrinkUnavailable as exc:
        logger.warning("tau_shrink: intern failed, disabled reason=%s", exc)
        return PreparedTauSpec(
            canonical, canonical, False, frozenset(), wide_input_streams(canonical)
        )

    # Annotation-only rewrites, every occurrence of every shrunk stream.
    for ref in plan.refs:
        if ref.io != "i" or ref.index not in plan.shrunk:
            continue
        if ref.ann_start < 0:
            # unannotated occurrences never reach here (they are unresolved), but
            # fail closed rather than synthesize a type.
            logger.error("tau_shrink: unannotated occurrence of shrunk i%s", ref.index)
            return PreparedTauSpec(
                canonical, canonical, False, frozenset(), wide_input_streams(canonical)
            )
        edits.append((ref.ann_start, ref.ann_end, f":bv[{width}]"))

    runtime_text = _apply_edits(canonical, edits)

    try:
        _audit(canonical, runtime_text, plan, width, id_by_pos)
    except ShrinkAuditFailure as exc:
        # NOT a fallback. Choosing an unoptimized representation is legitimate when
        # the fragment is merely unsupported; this is the implementation violating
        # its own edit plan, and the full-width text it would fall back to can be
        # incompatible with a width this process already committed to. Surface it
        # as a preparation failure and let the caller decide, rather than
        # dispatching something nobody checked.
        logger.error("tau_shrink: preparation failed its own edit audit: %s", exc)
        raise

    logger.info(
        "tau_shrink: shrunk %d literals, streams=%s, width=bv[%d]",
        len(plan.lit_edits),
        sorted(plan.shrunk),
        width,
    )
    wide_left = frozenset(
        r.index for r in plan.refs
        if r.io == "i" and r.width >= MIN_SHRINK_WIDTH and r.index not in plan.shrunk
    )
    return PreparedTauSpec(
        canonical, runtime_text, True, frozenset(plan.shrunk), wide_left
    )



# --- Stream value shrink ------------------------------------------------------


class RuntimeEncoded(str):
    """A stream value that is ALREADY in runtime (interned) form.

    W4: the adapter must never guess. Previously a bare decimal was assumed to be
    an internal id and passed through, so an externally supplied canonical `"1"`
    compared equal to whichever 384-bit address happened to hold interned id 1.
    Re-normalising an already-encoded value is a real internal need, so it gets an
    explicit, distinguishable type instead of a heuristic.
    """
    __slots__ = ()

_STREAM_LITERAL_RE = re.compile(r"^\{\s*([^{}]*?)\s*\}\s*:\s*bv\[\s*(\d+)\s*\]$")


def shrink_stream_value(value, stream_index: int, shrunk_streams) -> str:
    """Encode ONE canonical input-stream value for the runtime representation.

    The native engine expects input-stream VALUES as BARE constants (`1`, `#x..`)
    -- never the `{ .. }:bv[N]` wrapper, which is in-spec literal syntax only.

    For a stream in `shrunk_streams` the value is interned BY VALUE at the
    stream's declared canonical width. A bare decimal is a canonical value like
    any other; it is NOT accepted as an internal id, because an external caller
    can supply one (apply forwards user custom inputs here). Pass a
    `RuntimeEncoded` when the value is genuinely already encoded.

    Raises ShrinkUnavailable if a value that MUST shrink cannot be interned --
    callers fail closed rather than feed a mixed-width convention.
    """
    if isinstance(value, RuntimeEncoded):
        return str(value)
    text = "" if value is None else str(value).strip()
    if stream_index not in shrunk_streams or not text:
        return text

    m = _STREAM_LITERAL_RE.match(text)
    if m:
        inner = m.group(1).strip()
        width = int(m.group(2))
        if width < MIN_SHRINK_WIDTH:
            return text
    else:
        # bare constant: canonical value at the stream's shrink-eligible width
        inner = text
        width = None

    low = inner.lower()
    if low.startswith("#x"):
        hex_digits = low[2:]
        if not hex_digits or any(c not in "0123456789abcdef" for c in hex_digits):
            return text
    elif low.startswith("#b"):
        bits = low[2:]
        if not bits or any(c not in "01" for c in bits):
            return text
        hex_digits = format(int(bits, 2), "x")
    elif low.isdigit():
        hex_digits = format(int(low), "x")
    else:
        return text

    if width is None:
        # A bare value carries no declared width. Intern it at the width the rule
        # literals used, so the stream value and the literal collide on one id.
        width = _canonical_width_for(stream_index)
        if width is None:
            return text

    if _hex_is_zero(hex_digits):
        return "0"
    return str(intern_value(hex_digits, width))


# Canonical widths for shrink-eligible input streams. A bare stream value has no
# declared width of its own, and the intern key is width-tagged, so the adapter
# needs the stream's canonical width to land on the same id as the rule literal.
_CANONICAL_STREAM_WIDTHS = {3: 384, 4: 384, 12: 384}
for _slot in range(18, 26):
    _CANONICAL_STREAM_WIDTHS[_slot] = 384


def _canonical_width_for(stream_index: int):
    return _CANONICAL_STREAM_WIDTHS.get(stream_index)


def expand_output_value(value, output_index=None) -> str:
    """Identity.

    W4: the previous implementation guessed that an ordinary numeric output was a
    leaked interned id whenever that number happened to exist in the intern table
    -- numeric overlap is not provenance, and an ordinary fee could be diagnosed
    as a leak. The optimization is instead RESTRICTED so encoded values cannot
    reach an output at all: `_plan` only ever treats INPUT streams as candidates,
    and an equality whose opposite operand is an output stream disqualifies the
    component. So there is nothing here to expand, and nothing to guess about.
    """
    return "" if value is None else str(value).strip()