"""
Eval-only shrinking of long equality-only bitvectors for the Tau interpreter.

Long bitvectors that are only ever compared for equality (`=`) or emptiness
(`!= 0`) -- wallet pubkeys, hashes -- are expensive in the native interpreter.
This module interns each distinct long value to a small integer in the local
`tau_strings` table (db.get_string_id) and rewrites the formula text + input
stream values to the small `bv[64]` form *right before* the interpreter runs.

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
# Reserved id for the empty/zero value. tau_strings autoincrements from 1, so 0
# is never assigned to a real value and is a safe "empty" sentinel.
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


def set_shrink_width(width: int) -> None:
    global _current_shrink_width
    _current_shrink_width = max(DEFAULT_SHRINK_WIDTH, int(width))


def set_shrink_width_from_db() -> int:
    """Recompute the process shrink width from the current intern-table max id.
    Call once at interpreter init/restore (process start)."""
    try:
        max_id = db.get_max_string_id()
    except Exception:
        max_id = 0
    set_shrink_width(width_for_count(max_id or 0))
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

    The id is already persisted in tau_strings, so a FRESH process will pick a
    wider width. The node must re-exec (NOT rebuild the interpreter in-process --
    the engine's per-stream bv typing is sticky). Distinct from ShrinkUnavailable
    so it is NOT swallowed by fail-closed disable paths.
    """


@dataclass(frozen=True)
class PreparedTauSpec:
    """The explicit two-representation contract handed back by prepare_rule.

    canonical_text -- full-width; the ONLY thing persisted/hashed.
    runtime_text   -- shrunk; fed to the interpreter.
    shrink_enabled -- False => runtime_text == canonical_text (no shrink applied).
    shrunk_streams -- input stream indices whose runtime values must be shrunk
                      to stay consistent with the shrunk rule literals.
    """

    canonical_text: str
    runtime_text: str
    shrink_enabled: bool
    shrunk_streams: frozenset


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
        yid = db.get_string_id(key)
        id_num = int(yid[1:])
    except Exception as exc:  # DB unavailable, malformed yid, etc.
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

# Order matters: multi-char operators and bracketed forms before single chars.
_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<bvlit>\{[^{}]*\}\s*:\s*bv\[\s*\d+\s*\])
    | (?P<streamref>[io]\d+\s*\[\s*t\s*\]\s*(?::\s*bv\[\s*\d+\s*\])?)
    | (?P<hexnum>\#x[0-9a-fA-F]+|\#b[01]+)
    | (?P<num>\d+)
    | (?P<op>!=|<=|>=|<<|>>|&&|\|\||[=<>+\-*/%&|\^!])
    | (?P<group>[()])
    | (?P<dot>\.)
    | (?P<comma>,)
    | (?P<ident>[A-Za-z_]\w*)
    | (?P<colon>:)
    | (?P<other>.)
    """,
    re.VERBOSE,
)

_STREAMREF_RE = re.compile(
    r"([io])(\d+)\s*\[\s*t\s*\]\s*(?::\s*bv\[\s*(\d+)\s*\])?"
)
_BVLIT_RE = re.compile(r"\{\s*([^{}]*?)\s*\}\s*:\s*bv\[\s*(\d+)\s*\]")

# Operators that mean "this is not an equality/emptiness operand". A candidate
# adjacent to any of these is never shrunk.
_DISQ_OPS = frozenset(
    {"<", ">", "<=", ">=", "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", "!"}
)
_EQ_OPS = frozenset({"=", "!="})
# Temporal / quantifier keywords that legitimately precede '(' and are NOT
# function calls (`always (...)`, `all x (...)`). Any OTHER identifier before a
# '(' is treated as a function call wrapping the operand -> fail closed.
_KEYWORDS_BEFORE_PAREN = frozenset({"always", "sometimes", "all", "ex"})


@dataclass
class _Tok:
    kind: str
    text: str
    start: int
    end: int


def _tokenize(text: str) -> list:
    toks = []
    for m in _TOKEN_RE.finditer(text):
        kind = m.lastgroup
        if kind == "ws":
            continue
        toks.append(_Tok(kind, m.group(), m.start(), m.end()))
    return toks


def _streamref_info(tok: _Tok):
    """Return (index, width_or_None) for a streamref token, or None."""
    m = _STREAMREF_RE.match(tok.text)
    if not m or m.group(1) != "i":
        return None
    width = int(m.group(3)) if m.group(3) is not None else None
    return int(m.group(2)), width


def _bvlit_info(tok: _Tok):
    """Return (hex_digits_or_None, width, is_zero) for a bvlit token, or None.

    hex_digits is None for a typed decimal literal like `{ 0 }:bv[N]` (only zero
    is recognised as a decimal candidate; non-zero decimals are not addresses).
    """
    m = _BVLIT_RE.match(tok.text)
    if not m:
        return None
    inner = m.group(1).strip()
    width = int(m.group(2))
    if inner.lower().startswith("#x"):
        hex_digits = inner[2:]
        return hex_digits, width, _hex_is_zero(hex_digits)
    if inner == "0":
        return None, width, True
    return None, width, False  # non-zero decimal / binary: not an address literal


def _is_candidate_operand(tok: _Tok) -> bool:
    """A token that *could* be shrunk: wide hex/zero literal or wide stream ref."""
    if tok.kind == "bvlit":
        info = _bvlit_info(tok)
        if info is None:
            return False
        hex_digits, width, is_zero = info
        if is_zero:
            return width >= MIN_SHRINK_WIDTH
        return hex_digits is not None and width >= MIN_SHRINK_WIDTH
    if tok.kind == "streamref":
        info = _streamref_info(tok)
        if info is None:
            return False
        _idx, width = info
        return width is not None and width >= MIN_SHRINK_WIDTH
    if tok.kind == "num" and tok.text == "0":
        return True  # bare zero, only honoured opposite a shrinkable stream
    return False


def _enclosing_is_funccall(toks: list, idx: int) -> bool:
    """True if the operand at idx sits inside `<ident>( ... )` -- a function
    call we cannot reason about. Fail closed (don't shrink)."""
    depth = 0
    j = idx - 1
    while j >= 0:
        t = toks[j]
        if t.kind == "group" and t.text == ")":
            depth += 1
        elif t.kind == "group" and t.text == "(":
            if depth == 0:
                # Found the opening paren that encloses idx. Function call iff
                # the token before it is an identifier that is NOT a temporal/
                # quantifier keyword.
                if j > 0 and toks[j - 1].kind == "ident":
                    return toks[j - 1].text.lower() not in _KEYWORDS_BEFORE_PAREN
                return False
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
    return "NEUTRAL"


def _classify(text: str, exclude_streams=frozenset()):
    """Return (shrunk_streams:set[int], literal_edits:list[(tok, kind)]).

    literal kind is "hex" (intern) or "zero" (-> {0}). Conservative + fail
    closed: a stream is shrinkable only if EVERY occurrence is an equality
    operand opposite another shrink candidate, with a consistent width >=128
    explicit annotation; a literal is shrinkable only opposite a shrunk stream.
    Stream indices in exclude_streams are never shrunk (config safety override).
    """
    toks = _tokenize(text)
    n = len(toks)

    # Index every streamref occurrence and remember per-stream widths.
    stream_occurrences = {}      # idx -> list[token positions]
    stream_widths = {}           # idx -> set of declared widths (None if bare)
    for pos, t in enumerate(toks):
        if t.kind == "streamref":
            info = _streamref_info(t)
            if info is None:
                continue
            sidx, width = info
            stream_occurrences.setdefault(sidx, []).append(pos)
            stream_widths.setdefault(sidx, set()).add(width)

    def opposite_of(pos):
        """If toks[pos] is an operand of an =/!= at pos-1 or pos+1, return the
        opposite operand token + a flag for precedence-steal/funccall safety."""
        left = toks[pos - 1] if pos - 1 >= 0 else None
        right = toks[pos + 1] if pos + 1 < n else None
        lc, rc = _neighbor_class(left), _neighbor_class(right)
        # A candidate next to any disqualifying operator is never an eq operand.
        if lc == "DISQ" or rc == "DISQ":
            return None
        if _enclosing_is_funccall(toks, pos):
            return None
        if rc == "EQ":
            # operand is the LEFT side: opposite is toks[pos+2]; guard precedence
            far = toks[pos + 2] if pos + 2 < n else None
            if _neighbor_class(far) == "DISQ":
                return None
            return far
        if lc == "EQ":
            far = toks[pos - 2] if pos - 2 >= 0 else None
            if _neighbor_class(far) == "DISQ":
                return None
            return far
        return None  # not an equality operand

    # Stream candidacy: consistent explicit width >=128 and every occurrence is
    # an equality operand (structurally) opposite a candidate.
    def stream_structurally_ok(sidx) -> bool:
        widths = stream_widths.get(sidx, set())
        if None in widths or len(widths) != 1:
            return False  # bare / inconsistent annotation -> fail closed
        (w,) = tuple(widths)
        if w < MIN_SHRINK_WIDTH:
            return False
        for pos in stream_occurrences[sidx]:
            opp = opposite_of(pos)
            if opp is None or not _is_candidate_operand(opp):
                return False
        return True

    candidate_streams = {
        s
        for s in stream_occurrences
        if s not in exclude_streams and stream_structurally_ok(s)
    }

    # Fixpoint: a stream stays in S only if every occurrence's opposite is a
    # >=128 literal/zero OR a stream still in S. (Handles iN = iM chains.)
    changed = True
    while changed:
        changed = False
        for sidx in list(candidate_streams):
            ok = True
            for pos in stream_occurrences[sidx]:
                opp = opposite_of(pos)
                if opp is None:
                    ok = False
                    break
                if opp.kind == "streamref":
                    oinfo = _streamref_info(opp)
                    if oinfo is None or oinfo[0] not in candidate_streams:
                        ok = False
                        break
                elif not _is_candidate_operand(opp):
                    ok = False
                    break
            if not ok:
                candidate_streams.discard(sidx)
                changed = True

    # Literal edits: a wide hex/zero literal (or bare zero) that is an operand of
    # an =/!= opposite a shrunk stream.
    literal_edits = []
    for pos, t in enumerate(toks):
        if t.kind == "bvlit":
            info = _bvlit_info(t)
            if info is None:
                continue
            hex_digits, width, is_zero = info
            if width < MIN_SHRINK_WIDTH:
                continue
            opp = opposite_of(pos)
            if opp is None or opp.kind != "streamref":
                continue
            oinfo = _streamref_info(opp)
            if oinfo is None or oinfo[0] not in candidate_streams:
                continue
            literal_edits.append((t, "zero" if is_zero else "hex"))
        elif t.kind == "num" and t.text == "0":
            opp = opposite_of(pos)
            if opp is None or opp.kind != "streamref":
                continue
            oinfo = _streamref_info(opp)
            if oinfo is None or oinfo[0] not in candidate_streams:
                continue
            literal_edits.append((t, "zero"))

    return candidate_streams, literal_edits, toks


# --- Rewrite ------------------------------------------------------------------

def _shrunk_streamref_text(tok: _Tok, width: int) -> str:
    """Rewrite a streamref's type annotation to the current shrink width."""
    m = _STREAMREF_RE.match(tok.text)
    return f"i{m.group(2)}[t]:bv[{width}]"


def _apply_edits(text: str, edits: list) -> str:
    """edits: list of (start, end, replacement). Applied right-to-left."""
    for start, end, repl in sorted(edits, key=lambda e: e[0], reverse=True):
        text = text[:start] + repl + text[end:]
    return text


def prepare_rule(full_width_text: str, exclude_streams=frozenset()) -> PreparedTauSpec:
    """Produce the canonical/runtime split for a normalized full-width rule.

    On DB/intern failure the whole spec falls back to full-width (shrink disabled,
    all-or-nothing -- never a partial mix). MAY raise ShrinkWidthOverflow if a rule
    literal interns to an id beyond the current process width -- that is propagated
    deliberately so the node can re-exec at a wider width (do not swallow it).
    """
    canonical = full_width_text or ""
    if not canonical.strip():
        return PreparedTauSpec(canonical, canonical, False, frozenset())

    width = current_shrink_width()

    try:
        shrunk_streams, literal_edits, toks = _classify(canonical, exclude_streams)
    except Exception as exc:  # classifier must never break the eval path
        logger.warning("tau_shrink: classify failed, disabled reason=%s", exc)
        return PreparedTauSpec(canonical, canonical, False, frozenset())

    if not shrunk_streams and not literal_edits:
        return PreparedTauSpec(canonical, canonical, False, frozenset())

    # Intern ALL hex literals first (all-or-nothing). On DB failure: full-width.
    # ShrinkWidthOverflow is NOT caught here -- it must propagate to trigger re-exec.
    edits = []
    try:
        for tok, kind in literal_edits:
            if kind == "zero":
                edits.append((tok.start, tok.end, f"{{ 0 }}:bv[{width}]"))
            else:
                info = _bvlit_info(tok)
                hex_digits, vwidth, _is_zero = info
                id_num = intern_value(hex_digits, vwidth)
                if id_num == RESERVED_EMPTY_ID:
                    edits.append((tok.start, tok.end, f"{{ 0 }}:bv[{width}]"))
                else:
                    edits.append(
                        (tok.start, tok.end, f"{{ {id_num} }}:bv[{width}]")
                    )
    except ShrinkUnavailable as exc:
        logger.warning("tau_shrink: intern failed, disabled reason=%s", exc)
        return PreparedTauSpec(canonical, canonical, False, frozenset())

    # Rewrite shrunk-stream annotations to the current width (every occurrence).
    for tok in toks:
        if tok.kind != "streamref":
            continue
        info = _streamref_info(tok)
        if info is None or info[0] not in shrunk_streams:
            continue
        edits.append((tok.start, tok.end, _shrunk_streamref_text(tok, width)))

    runtime_text = _apply_edits(canonical, edits)
    logger.info(
        "tau_shrink: shrunk %d literals, streams=%s, width=bv[%d]",
        len(literal_edits),
        sorted(shrunk_streams),
        width,
    )
    return PreparedTauSpec(
        canonical, runtime_text, True, frozenset(shrunk_streams)
    )


# --- Stream value shrink ------------------------------------------------------

_STREAM_LITERAL_RE = re.compile(r"^\{\s*([^{}]*?)\s*\}\s*:\s*bv\[\s*(\d+)\s*\]$")


def shrink_stream_value(value, stream_index: int, shrunk_streams) -> str:
    """Shrink a single input-stream value, idempotently.

    The native engine expects input-stream VALUES as BARE constants (a decimal
    like `1`, or `#x..` hex) -- NOT the `{ .. }:bv[N]` literal wrapper, which is
    only valid for in-spec literals. (This mirrors the existing i3/i4 path, which
    feeds bare interned ids.) So a shrunk address value becomes the bare decimal
    id; zero becomes bare `0`.

    Only shrinks when the stream index is in shrunk_streams AND the value is a
    `{ #x.. }:bv[N]` (N>=128) literal carrying its declared width (so its intern
    key matches the rule literal's). Bare ints/decimals/already-shrunk values
    pass through unchanged (idempotent).

    Raises ShrinkUnavailable if a value that SHOULD shrink cannot be interned --
    callers must fail closed rather than feed a mixed-width convention.
    """
    text = "" if value is None else str(value).strip()
    if stream_index not in shrunk_streams or not text:
        return text
    m = _STREAM_LITERAL_RE.match(text)
    if not m:
        return text  # bare int / decimal / already shrunk -> idempotent passthrough
    inner = m.group(1).strip()
    width = int(m.group(2))
    if width < MIN_SHRINK_WIDTH:
        return text
    if inner.lower().startswith("#x"):
        hex_digits = inner[2:]
    elif inner == "0":
        return "0"
    else:
        return text  # not a hex address literal -> leave untouched
    id_num = intern_value(hex_digits, width)  # may raise ShrinkUnavailable
    return str(id_num)  # bare decimal id (0 for empty)


# --- Output expansion (deferred, with detection guard) ------------------------

def expand_output_value(value, output_index=None) -> str:
    """Identity (output expansion is deferred), but loudly flags a value that
    looks like a leaked shrunk address id on a non-verdict stream.

    Heuristic to avoid false alarms on boolean verdicts: only warns when the
    value parses as an integer > 1 (beyond the 0/1 verdict range) on a
    non-verdict stream AND that id exists in the intern store. Reserved ids 0/1
    overlap with verdict values, so they are never flagged.
    """
    text = "" if value is None else str(value).strip()
    m = _STREAM_LITERAL_RE.match(text)
    inner = m.group(1).strip() if m else text
    if inner.lstrip("#x").isdigit() or inner.isdigit():
        try:
            n = int(inner[2:], 16) if inner.lower().startswith("#x") else int(inner)
        except ValueError:
            return text
        if n > 1 and output_index not in _VERDICT_OUTPUT_STREAMS:
            try:
                stored = db.get_text_by_id(f"y{n}")
            except Exception:
                stored = None
            if stored and stored.startswith("bv"):
                logger.error(
                    "tau_shrink: output o%s value=%s looks like a shrunk address "
                    "id (interned as %s) but output expansion is not configured. "
                    "A rule may be emitting a node-local id -- this would diverge "
                    "across nodes.",
                    output_index,
                    n,
                    stored[:16],
                )
    return text
