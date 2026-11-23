"""Recipient-side o5 gate: inbound allow-list and maximum hold (#47, #76).

One account, one clause. The sender pass feeds i17 = 0. The recipient pass
runs only when that clause mentions i17, and feeds a code:

    0                  the owner's own send
    1                  a plain payment arriving (hold length 0)
    1 + seconds        a time park, seconds in 1 .. 7_776_000
    (2^63 - 1 - 100_000) + blocks
                       a height park, blocks in 1 .. 100_000

A cap of 0 is the comparison ``i17 > 1``. A cap of 600 seconds is ``i17 > 601``,
and every height park fails it. Height codes sit at the top of the
non-negative ``bv[64]`` range, so a seconds literal also fails them when the
number is longer than the 90-day window.
That refusal reports ``max_hold_blocks=0`` and, when the seconds side is itself
one cap, ``max_hold_seconds`` as well.

The number comes from the clause. When every ``i17`` mention is a direct
comparison with a ``bv[64]`` literal, or with another ``bv[64]`` input this
payment fixes, the verdict can change only at those points. The node
evaluates them and reports a number only for a single threshold. Arithmetic
is still enforced, and the refusal carries no number: searching the window
cannot prove there is no hole. Admission and apply call this same helper, so
the apply receipt carries the number ``checktx`` shows.

The recipient pass sets approval slots the transfer map already carries to 0.
Those slots are the sender's co-signers, and the sender's own clause still
sees them. A slot the map does not have is left absent.

i17 stays a sender-supplied custom stream until ``recipient_controls_active``.
The flag is consensus state, the same one-way governance switch as the
approval slots, and it is omitted from the state hash until it is turned on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import tau_defs
from consensus.retractable import (
    KIND_HEIGHT,
    KIND_TIME,
    MAX_RELEASE_WINDOW_BLOCKS,
    MAX_RELEASE_WINDOW_SECONDS,
)
from consensus.rule_offers import strip_clause_comments
from consensus import sender_policy
from tau_speculation import _SESSION_DEFAULT

STREAM = tau_defs.RECIPIENT_HOLD_STREAM_INDEX
WIDTH = tau_defs.RECIPIENT_HOLD_BV_WIDTH

CODE_OUTBOUND = 0
CODE_PLAIN = 1
# A time park of S seconds is code (1 + S). The largest legal S lands on
# TIME_CODE_MAX. Height codes occupy the top of the non-negative bv[64]
# range, the same ceiling i16 uses for "never sent". A seconds comparison
# then refuses every height park, including a literal longer than 90 days.
# Packing height codes in at the next second would let that literal admit
# every legal height park.
TIME_CODE_MAX = 1 + MAX_RELEASE_WINDOW_SECONDS
HEIGHT_CODE_MAX = (1 << 63) - 1
HEIGHT_CODE_BASE = HEIGHT_CODE_MAX - MAX_RELEASE_WINDOW_BLOCKS

SECONDS_LO = 2
BLOCKS_LO = HEIGHT_CODE_BASE + 1

POLICY_BLOCK = "recipient_policy_block"
MAX_HOLD = "RECIPIENT_MAX_HOLD"
INACTIVE = "RECIPIENT_CONTROLS_INACTIVE"

# Points one unit may be evaluated at while naming a cap. Past this the
# payment is still refused and no number is reported. A normal cap is a
# handful of comparisons, so it fits.
MAX_CAP_POINTS = 24

_LIT_BODY = r"#[xX][0-9a-fA-F]+|#[bB][01]+|\d+"
_LIT_BV = (
    r"\{\s*(" + _LIT_BODY + r")\s*\}\s*:\s*bv\s*\[\s*" + str(WIDTH) + r"\s*\]"
)
_I17_TYPED = (
    r"i" + str(STREAM) + r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*" + str(WIDTH) + r"\s*\]"
)
_CMP_OP = r"\s*(?:!=|<=|>=|=|<|>)\s*"
_DIRECT_RE = re.compile(
    r"(?:" + _I17_TYPED + _CMP_OP + _LIT_BV + r")|(?:" + _LIT_BV + _CMP_OP + _I17_TYPED + r")"
)
# The other side of a comparison with i17. i17 itself is excluded: its value
# is what the search varies, so it is not a fixed change point.
_OTHER_STREAM = (
    r"i(?!" + str(STREAM) + r"\b)(\d+)"
    r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*" + str(WIDTH) + r"\s*\]"
)
_STREAM_RE = re.compile(
    r"(?:" + _I17_TYPED + _CMP_OP + _OTHER_STREAM + r")"
    r"|(?:" + _OTHER_STREAM + _CMP_OP + _I17_TYPED + r")"
)
# Arithmetic would move the change points off the written literals. &&, ||, !
# and -> are comparisons' connectives, not arithmetic.
_ARITHMETIC_RE = re.compile(
    r"[+*/%^~]|<<|>>|(?<![&])&(?![&])|(?<![|])\|(?![|])|-(?!>)"
)

_INACTIVE_PREFIX = "recipient controls are not active"
_MENTION_RE = re.compile(r"\bi17\b")
_TYPED_RE = re.compile(r"\bi17\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*(\d+)\s*\]")
_TYPED_TAIL_RE = re.compile(r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*64\s*\]")


def controls_active(source) -> bool:
    """True only for a real ``True``. A missing attribute is off.

    A mocked view returns a truthy stand-in for any attribute it was never
    given. Treating that as activated would turn the gate on in tests and,
    worse, on any caller that forgot to thread the flag.
    """
    return getattr(source, "recipient_controls_active", False) is True


def sender_clause_inputs(values: dict, active: bool) -> dict:
    """The sender pass. i17 is 0 when the feature is on, and absent when it is off.

    Absent keeps a pre-activation evaluation byte-identical. The value is added
    only for the clause evaluator: the transfer step that prices the fee does
    not see it, so a custom use of i17 on an inactive chain is left alone.
    Every key shape is overwritten. The evaluator keeps the last one it sees,
    so a forged ``"i17"`` left beside key 17 would be the value that wins.
    """
    if not active:
        return values
    fed = dict(values or {})
    code = str(CODE_OUTBOUND)
    fed[STREAM] = code
    fed[str(STREAM)] = code
    fed[f"i{STREAM}"] = code
    return fed


def park_hold_code(kind: int, release_at: int, height: int, timestamp: int) -> int:
    """The i17 code for a park that has already cleared the release window.

    Hold length is release minus the clock the caller names. Admission passes
    ``next_block_height`` and ``next_block_timestamp``. Apply passes the height
    and timestamp of the block being applied. A non-positive hold clamps to 1
    so the code stays inside the unit the cap search understands; the shape
    check is what refuses a park that is already releasable.
    """
    if int(kind) == KIND_TIME:
        seconds = int(release_at) - int(timestamp)
        seconds = max(1, min(int(seconds), MAX_RELEASE_WINDOW_SECONDS))
        return 1 + seconds
    if int(kind) == KIND_HEIGHT:
        blocks = int(release_at) - int(height)
        blocks = max(1, min(int(blocks), MAX_RELEASE_WINDOW_BLOCKS))
        return HEIGHT_CODE_BASE + blocks
    raise ValueError(f"unknown release kind {kind}")


def clause_reads_hold_stream(body: str) -> bool:
    """Whether the recipient pass applies. An outbound-only clause never mentions i17."""
    return _MENTION_RE.search(strip_clause_comments(body or "")) is not None


def screen_hold_clause(body: str, *, active: bool) -> Optional[str]:
    """Refuse a hold clause the node will not enforce, and a width it will poison.

    While the feature is off, a ``bv[64]`` mention is a hold clause that would
    be admitted and then never fed. A ``bv[24]`` mention stays a custom input.
    Once the feature is on, every mention must be ``i17[t]:bv[64]``, because
    stream typing is process-global and the node feeds that width.
    """
    scrubbed = strip_clause_comments(body or "")
    if not _MENTION_RE.search(scrubbed):
        return None
    if not active:
        if _TYPED_RE.search(scrubbed) and any(
            int(match.group(1)) == WIDTH for match in _TYPED_RE.finditer(scrubbed)
        ):
            return (
                f"{_INACTIVE_PREFIX} on this chain. A clause that types i17 at "
                f"bv[{WIDTH}] would never be fed. Activate recipient_controls_active "
                f"before deploying it."
            )
        return None
    for match in _MENTION_RE.finditer(scrubbed):
        if _TYPED_TAIL_RE.match(scrubbed, match.end()) is None:
            found = _TYPED_RE.match(scrubbed, match.start())
            shown = f"bv[{found.group(1)}]" if found else "an untyped mention"
            return (
                f"i17 is the recipient-hold input and must be written "
                f"i17[t]:bv[{WIDTH}], found {shown}"
            )
    return None


def audit_hold_stream(spec_texts) -> list:
    """Reasons recipient controls cannot be activated. Empty means clear.

    i17 is a custom stream until the flag flips, so any deployed mention is a
    rule the node would start feeding. Per-stream typing is process-global:
    a ``bv[24]`` custom policy and a ``bv[64]`` hold clause cannot share a
    process. The audit reads only hash-bound text, so every node either
    activates or declines together.
    """
    findings = []
    for label, text in spec_texts or ():
        if not isinstance(text, str) or not text.strip():
            continue
        if _MENTION_RE.search(strip_clause_comments(text)):
            findings.append(
                f"{label} already references i17. It is a custom stream until "
                f"recipient controls activate, and feeding it at bv[{WIDTH}] "
                f"would collide with that rule."
            )
    return findings


@dataclass(frozen=True)
class RecipientRefusal:
    code: str
    message: str
    details: dict


def _unit(code: int):
    """(name, low, high, hold_of) for a park code, or None when it is not one."""
    if SECONDS_LO <= code <= TIME_CODE_MAX:
        return ("seconds", SECONDS_LO, TIME_CODE_MAX, lambda c: c - 1)
    if BLOCKS_LO <= code <= HEIGHT_CODE_MAX:
        return ("blocks", BLOCKS_LO, HEIGHT_CODE_MAX, lambda c: c - HEIGHT_CODE_BASE)
    return None


def _message(unit: str, cap: int) -> str:
    field = f"max_hold_{unit}"
    if cap == 0:
        return (
            "Recipient only accepts payments that arrive straight away "
            f"({field}=0)."
        )
    return (
        f"Recipient accepts payments held for up to {cap} {unit} ({field}={cap})."
    )


def _height_closed_message(seconds: Optional[int]) -> str:
    """A height park every height code refuses.

    ``seconds`` is the seconds cap when that side is one threshold. None means
    the seconds window is open, or not a single cap, so it is not quoted.
    """
    if seconds == 0:
        return (
            "Recipient only accepts payments that arrive straight away "
            "(max_hold_seconds=0, max_hold_blocks=0)."
        )
    if seconds is None:
        return (
            "Recipient does not accept a payment held in blocks "
            "(max_hold_blocks=0)."
        )
    return (
        f"Recipient accepts payments held for up to {seconds} seconds "
        f"(max_hold_seconds={seconds}) and does not accept a height park "
        f"(max_hold_blocks=0)."
    )


def _literal_value(text: str) -> Optional[int]:
    token = text.strip().lower()
    try:
        if token.startswith("#x"):
            return int(token[2:], 16)
        if token.startswith("#b"):
            return int(token[2:], 2)
        return int(token, 10)
    except ValueError:
        return None


def comparison_literals(body: str) -> Optional[tuple]:
    """The ``bv[64]`` literals ``i17`` is compared with, or None.

    None means the shape is not a direct comparison: arithmetic, a comparison
    with another stream, or an ``i17`` mention that is not a comparison with a
    literal. A tuple means every ``i17`` mention is such a comparison. Other
    ``bv[64]`` literals, such as a time lock on ``i5``, do not move those
    change points: every input but ``i17`` is fixed while the cap is read.
    """
    text = strip_clause_comments(body or "")
    mentions = len(_MENTION_RE.findall(text))
    if mentions == 0:
        return None
    scrubbed = re.sub(r"\{[^}]*\}", "{}", text)
    if _ARITHMETIC_RE.search(scrubbed):
        return None
    found = []
    for match in _DIRECT_RE.finditer(text):
        raw = next(group for group in match.groups() if group is not None)
        value = _literal_value(raw)
        if value is None:
            return None
        found.append(value)
    if len(found) != mentions:
        return None
    return tuple(found)


def _threshold_cap(literals, low: int, high: int, hold_of, blocked) -> Optional[int]:
    """The single threshold in ``low..high``, read off ``literals``.

    Zero means every code in the unit blocks. None means the window is open,
    the points are not one threshold, or there are too many of them to name
    a number. A hole between the points is not a cap.
    """
    points = {low, high}
    for literal in literals:
        for code in (int(literal) - 1, int(literal), int(literal) + 1):
            if low <= code <= high:
                points.add(code)
    if len(points) > MAX_CAP_POINTS:
        return None
    ordered = sorted(points)
    first_refused = None
    for index, code in enumerate(ordered):
        if blocked(code):
            if first_refused is None:
                first_refused = index
        elif first_refused is not None:
            return None
    if first_refused is None:
        return None
    if first_refused == 0:
        return 0
    boundary = ordered[first_refused] - 1
    if boundary < ordered[first_refused - 1]:
        boundary = ordered[first_refused - 1]
    if boundary < low:
        return 0
    return int(hold_of(boundary))


def _recipient_view(values: dict, hold_code: int) -> dict:
    """The map the recipient clause is stepped on.

    i17 is the hold. Approval slots already on the map become 0, whichever
    key shape the caller used. The caller's dict is not written.
    """
    trial = dict(values or {})
    code = str(int(hold_code))
    for slot in tau_defs.approval_slot_indices():
        for key in (slot, str(slot), f"i{slot}"):
            if key in trial:
                trial[key] = "0"
    present = False
    for key in (STREAM, str(STREAM), f"i{STREAM}"):
        if key in trial:
            trial[key] = code
            present = True
    if not present:
        trial[STREAM] = code
    return trial


def change_points(body: str, values: dict) -> Optional[tuple]:
    """Where an ``i17`` verdict can change for this payment, or None.

    None means the points are not known: arithmetic, a comparison with ``i17``
    itself, a stream this payment does not fix to an integer, or an ``i17``
    mention that is not a direct comparison. There is no search behind None.
    A tuple is every such point. A comparison with another ``bv[64]`` input
    uses the value the recipient pass will actually feed, including an
    approval slot zeroed because it is the sender's co-signer.
    """
    text = strip_clause_comments(body or "")
    mentions = len(_MENTION_RE.findall(text))
    if mentions == 0:
        return None
    scrubbed = re.sub(r"\{[^}]*\}", "{}", text)
    if _ARITHMETIC_RE.search(scrubbed):
        return None
    found = []
    for match in _DIRECT_RE.finditer(text):
        raw = next(group for group in match.groups() if group is not None)
        value = _literal_value(raw)
        if value is None:
            return None
        found.append(value)
    fed = sender_policy.clause_inputs(_recipient_view(values, CODE_PLAIN))
    for match in _STREAM_RE.finditer(text):
        raw = next(group for group in match.groups() if group is not None)
        seen = fed.get(f"i{int(raw)}")
        if seen is None:
            return None
        value = _literal_value(seen)
        if value is None:
            return None
        found.append(value)
    if len(found) != mentions:
        return None
    return tuple(found)


def recipient_refusal(body, values: dict, hold_code: int, *, pool: str,
                      timeout=_SESSION_DEFAULT) -> Optional[RecipientRefusal]:
    """The recipient pass. None when the clause allows the payment.

    A block at the plain-payment code is an allow-list (or anything else that
    is not a hold cap): ``recipient_policy_block``, with no invented maximum.
    A block that appears only once the hold is long enough is ``RECIPIENT_MAX_HOLD``.
    When every ``i17`` mention is a direct comparison with a literal or with
    another input this payment fixes, the cap is the single threshold those
    points draw, and a hole among them is not quoted. Anything else, including
    arithmetic, is refused with no number. A height park that every height
    code refuses also carries the seconds cap when that side is one threshold,
    so a 10-minute rule is not reported as instant-only. Past
    ``MAX_CAP_POINTS`` the refusal stands and carries no number.
    """
    if not isinstance(body, str) or not body or not clause_reads_hold_stream(body):
        return None

    cache: dict = {}

    def blocked(code: int) -> bool:
        cached = cache.get(code)
        if cached is not None:
            return cached
        verdict, _detail = sender_policy.clause_blocks(
            body, _recipient_view(values, code), pool=pool, timeout=timeout,
        )
        cache[code] = bool(verdict)
        return bool(verdict)

    if not blocked(int(hold_code)):
        return None
    if int(hold_code) <= CODE_PLAIN:
        return RecipientRefusal(
            POLICY_BLOCK,
            "rejected by recipient policy (o5)",
            {},
        )

    unit = _unit(int(hold_code))
    if unit is None or blocked(CODE_PLAIN):
        return RecipientRefusal(
            POLICY_BLOCK,
            "rejected by recipient policy (o5)",
            {},
        )

    points = change_points(body, values)

    def cap_of(low: int, high: int, hold_of) -> Optional[int]:
        """The single threshold in ``low..high``, or None when there is not one.

        The points come from the clause and from inputs this payment fixes.
        None covers an open window, a hole, a short hold refused while a longer
        one is allowed, arithmetic, and a point set larger than
        ``MAX_CAP_POINTS``. Zero is a real cap: every code in the unit blocks.
        """
        if points is None:
            return None
        return _threshold_cap(points, low, high, hold_of, blocked)

    name, low, high, hold_of = unit
    cap = cap_of(low, high, hold_of)
    if cap is None:
        return RecipientRefusal(
            POLICY_BLOCK, "rejected by recipient policy (o5)", {},
        )
    if name == "blocks" and cap == 0:
        seconds = cap_of(SECONDS_LO, TIME_CODE_MAX, lambda code: code - 1)
        details = {"max_hold_blocks": 0}
        if seconds is not None:
            details["max_hold_seconds"] = seconds
        return RecipientRefusal(MAX_HOLD, _height_closed_message(seconds), details)
    return RecipientRefusal(
        MAX_HOLD, _message(name, cap), {f"max_hold_{name}": cap},
    )
