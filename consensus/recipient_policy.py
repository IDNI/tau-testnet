"""Recipient-side policy: an account's o5 clause judging payments made TO it.

A clause that reads the receive record (`tau_defs.RECEIVE_RECORD_INDICES`: i17
and i50 to i54) is evaluated a second time for every payment whose recipient is
its owner, after the sender's own checks, on the same transfer inputs with the
approval slots emptied and the record set (see tau_defs for what each input
says). A clause that reads none of them is never asked, so a clause written
before the feature keeps its meaning.

The record describes the payment: its kind and clock (i17), how long until all
of it is within the receiver's reach (i50), how long the sender can still take
it back (i51), a spending limit on it (i52 per i53) and how soon any of it can
go back by itself (i54). The node fills it; the receiver's clause compares.

Every call site (apply, admission) goes through here so the inputs and the
failure mapping cannot drift apart, the way `sender_policy` does it for the
sender's side.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Callable, List, NamedTuple, Optional, Tuple

import tau_defs

RECIPIENT_POLICY_BLOCK_REASON = "recipient_policy_block"

_RECEIVE = tau_defs.RECEIVE_STREAM_INDEX
_RECORD = tau_defs.RECEIVE_RECORD_INDICES
_WIDTH = tau_defs.RECEIVE_STREAM_BV_WIDTH
_NEVER = tau_defs.RECEIVE_NEVER
_MENTION_RE = re.compile(r"\bi(%s)\b" % "|".join(str(i) for i in _RECORD))
_TYPED_TAIL_RE = re.compile(r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*%d\s*\]" % _WIDTH)
_RECORD_NAMES = "i%d and i%d to i%d" % (_RECORD[0], _RECORD[1], _RECORD[-1])


def recipient_policy_active(tip_view) -> bool:
    """Whether the receive record is reserved and fed at the tip.

    Requires a genuine `True`, for the reason `approval_slots_active` does: a
    partial or mocked view answers something truthy for an attribute it was
    never given, and running as if a consensus feature were on is the kind of
    thing that passes every test and then diverges on a live chain.
    """
    return getattr(tip_view, "recipient_policy_active", False) is True


@lru_cache(maxsize=1024)
def reads_receive_stream(body: str) -> bool:
    """Whether a clause body reads an input of the receive record outside a
    comment.

    This alone decides whether the clause is asked about incoming payments: a
    pure function of the registered text, so every node agrees.
    """
    from consensus.rule_offers import strip_clause_comments

    return bool(_MENTION_RE.search(strip_clause_comments(body or "")))


def screen_receive_stream_width(body: str) -> Optional[str]:
    """None when every mention of an input of the receive record is typed
    bv[64], else the reason.

    Reject-unless-annotated, like the approval slots: stream typing is
    process-global and sticky, so one clause typing i17 at another width (or not
    at all, which lets the engine infer one) would fail the build of every other
    clause that reads it.
    """
    from consensus.rule_offers import strip_clause_comments

    scrubbed = strip_clause_comments(body or "")
    for match in _MENTION_RE.finditer(scrubbed):
        if not _TYPED_TAIL_RE.match(scrubbed, match.end()):
            name = match.group(0)
            return (
                f"every mention of the receive record's input {name} must be "
                f"written {name}[t]:bv[{_WIDTH}]"
            )
    return None


_SHAPE_IDENTS = frozenset({"T", "F", "min", "max"})
_SHAPE_KINDS = frozenset({"streamref", "bvlit", "op", "group", "colon", "comma"})


def screen_receive_clause_shape(body: str) -> Optional[str]:
    """None when a clause that reads the receive record is built only from
    inputs and outputs at [t], typed constants, T, F, min, max, the ternary and
    comparison, Boolean and bit-vector operators; else the reason, naming the
    first piece that is not one of them.

    The receiver's verdict is asked again for every incoming payment, on
    whichever engine instance the node has at hand, so it must be a function of
    this step's inputs alone. A step constraint such as `[t > 3]` or `[t = 0]`,
    a temporal operator, a variable or a quantifier makes it depend on how many
    steps that instance has taken, which differs between nodes. An allowlist
    rather than a list of bad forms: what the scanner does not recognise is
    refused. A clause that does not read the record is not screened here.
    """
    if not reads_receive_stream(body):
        return None
    import tau_shrink
    from consensus.rule_offers import strip_clause_comments

    scrubbed = strip_clause_comments(body or "")
    try:
        tokens = tau_shrink._tokenize(scrubbed)
    except Exception:
        tokens = None
    found = None
    if tokens is None:
        found = "text the scanner cannot read"
    for pos, token in enumerate(tokens or ()):
        kind, text = token.kind, token.text
        if kind == "op" and text == "<":
            after = tokens[pos + 1] if pos + 1 < len(tokens) else None
            if after is not None and after.text == ">" and after.start == token.end:
                found = "<>"
                break
        if kind in _SHAPE_KINDS:
            continue
        if kind == "other" and text == "?":
            continue
        if kind == "ident" and text in _SHAPE_IDENTS:
            continue
        if kind == "other" and text == "[":
            close = scrubbed.find("]", token.start)
            found = scrubbed[token.start:close + 1 if close >= 0 else token.end]
            found = " ".join(found.split())[:40]
        else:
            found = text
        break
    if found is None:
        return None
    return (
        f"a clause that reads the receive record may hold only inputs and "
        f"outputs at [t], typed constants, T, F, min, max and comparison, "
        f"Boolean and bit-vector operators, so that its answer does not depend "
        f"on earlier steps; found '{found}'"
    )


def audit_receive_stream_collisions(spec_texts) -> List[str]:
    """Reasons the receive record cannot safely be activated. Empty means clear.

    Before activation i17 and i50 to i54 are ordinary custom input streams, so
    a deployed rule or clause may already read one. Activating over it would
    turn that clause into a receive policy its owner never wrote, or type the
    stream at a second width. `spec_texts` is the same (label, text) corpus the approval
    slot audit takes: consensus rules, builtin rules, the application-rules
    accumulation and every stored clause body.
    """
    from consensus.rule_offers import strip_clause_comments

    findings: List[str] = []
    for label, text in spec_texts or ():
        if not isinstance(text, str) or not text.strip():
            continue
        found = _MENTION_RE.search(strip_clause_comments(text))
        if found:
            findings.append(
                f"{label} already references {found.group(0)}; activating would "
                f"turn it into a receive policy or type the stream at a second "
                f"width. Replace or revoke it first"
            )
    return findings


SECONDS = "seconds"
BLOCKS = "blocks"
_KIND_OF = {SECONDS: tau_defs.RECEIVE_KIND_SECONDS, BLOCKS: tau_defs.RECEIVE_KIND_BLOCKS}
_UNIT_OF = {kind: unit for unit, kind in _KIND_OF.items()}


class ReceiveRecord(NamedTuple):
    """What the receiver's clause is told about one incoming payment.

    `kind` names the payment's clock; `hold`, `recall`, `period` and `refund`
    are lengths on that clock, `limit` an amount. The defaults are the most
    permissive value of each condition: nothing held, nothing to take back, no
    limit, nothing that goes back by itself.
    """
    kind: int = tau_defs.RECEIVE_KIND_FINAL
    hold: int = 0
    recall: int = 0
    limit: int = 0
    period: int = 0
    refund: int = _NEVER

    @property
    def unit(self) -> Optional[str]:
        """"seconds" or "blocks", or None for a payment that is final at once."""
        return _UNIT_OF.get(self.kind)

    def terms(self) -> str:
        """The record as the `<terms>` `getrecipientpolicy` takes, so that a
        payment refused in a block can be asked about again. Empty for a
        payment that is final at once."""
        if self.unit is None:
            return ""
        parts = [self.unit]
        if self.hold:
            parts.append("hold=%d" % _clamp(self.hold))
        if self.recall:
            parts.append("recall=%d" % _clamp(self.recall))
        if self.limit or self.period:
            parts.append("limit=%d period=%d" % (_clamp(self.limit), _clamp(self.period)))
        if _clamp(self.refund) < _NEVER:
            parts.append("refund=%d" % _clamp(self.refund))
        return " ".join(parts)

    def streams(self) -> dict:
        """The record as the receiver's clause reads it, by stream index."""
        return {
            tau_defs.RECEIVE_STREAM_INDEX: str(int(self.kind)),
            tau_defs.RECEIVE_HOLD_INDEX: str(_clamp(self.hold)),
            tau_defs.RECEIVE_RECALL_INDEX: str(_clamp(self.recall)),
            tau_defs.RECEIVE_LIMIT_INDEX: str(_clamp(self.limit)),
            tau_defs.RECEIVE_PERIOD_INDEX: str(_clamp(self.period)),
            tau_defs.RECEIVE_REFUND_INDEX: str(_clamp(self.refund)),
        }


def _clamp(value) -> int:
    return max(0, min(int(value), _NEVER))


# A payment that is final and spendable at once: a transfer, each leg of a
# batch, a co-signed transfer when its last vote releases it.
FINAL = ReceiveRecord()


def park_record(unit: str, length: int) -> ReceiveRecord:
    """The record of a retractable transfer released `length` (in `unit`) after
    the block that parks it.

    Until its release the money is not in the receiver's reach and the sender
    can take it back, so the hold and the recall window are the same length.
    A park has no spending limit and never goes back by itself.
    """
    length = max(0, int(length))
    return ReceiveRecord(kind=_KIND_OF[unit], hold=length, recall=length)


def record_ceiling_error(record: ReceiveRecord) -> Optional[str]:
    """Why this record may not be put to a receiver at all, or None.

    The ceilings of the limit are part of the record (see tau_defs): a payment
    whose terms lie above them is refused before the receiver is asked.
    """
    if int(record.limit) > tau_defs.RECEIVE_LIMIT_CEILING:
        return (f"a spending limit above {tau_defs.RECEIVE_LIMIT_CEILING} cannot be "
                f"described to the receiver")
    ceiling = (tau_defs.RECEIVE_PERIOD_CEILING_BLOCKS
               if record.kind == tau_defs.RECEIVE_KIND_BLOCKS
               else tau_defs.RECEIVE_PERIOD_CEILING_SECONDS)
    if int(record.period) > ceiling:
        return (f"a limit period above {ceiling} {record.unit or SECONDS} cannot be "
                f"described to the receiver")
    return None


def receive_inputs(values: dict, record: ReceiveRecord) -> dict:
    """The recipient's view of one transfer.

    The sender-pass input map, with the approval slots emptied (the sender's
    co-signers did not vote on behalf of the recipient) and the record set.
    """
    out = dict(values or {})
    for slot in tau_defs.approval_slot_indices():
        if slot in out:
            out[slot] = "0"
    out.update(record.streams())
    return out


def recipient_clause(clause_for, recipient: str) -> Optional[str]:
    """The recipient's clause body when it reads the receive record, else None."""
    body = clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX)
    if not isinstance(body, str) or not body or not reads_receive_stream(body):
        return None
    return body


_UNSET = object()


def recipient_blocks(clause_for, recipient: str, values: dict, record: ReceiveRecord,
                     *, pool: str, timeout=_UNSET) -> Tuple[bool, str]:
    """(blocked, detail) from the recipient's own clause for one incoming payment.

    (False, "") when the recipient has no clause or its clause does not read
    the record. A clause that cannot be built or stepped blocks, as on the
    sender's side, so every node reaches the same result. So does a record
    above its ceilings: it is refused before the clause is asked.
    """
    body = recipient_clause(clause_for, recipient)
    if body is None:
        return False, ""
    above = record_ceiling_error(record)
    if above:
        return True, above
    from consensus import sender_policy

    # An omitted timeout means the evaluator's own default, as on the sender's side.
    kwargs = {} if timeout is _UNSET else {"timeout": timeout}
    return sender_policy.clause_blocks(
        body, receive_inputs(values, record), pool=pool, **kwargs
    )


# --- which condition refused, and what the receiver would take ------------------
#
# The verdict is one evaluation of the clause on the whole record. Where a
# sender waits for an answer (admission and the lookup), the node also finds the
# condition that failed: it asks the clause again with every other condition at
# its most permissive value, in the order below, and names the first condition
# the clause refuses on its own. For the message a wallet prints, never for a
# verdict.

SENDER = "sender"
HOLD = "hold"
RECALL = "recall"
LIMIT = "limit"
REFUND = "refund"
COMBINED = "combined"

REFUSAL_CODES = {
    SENDER: "RECIPIENT_SENDER",
    HOLD: "RECIPIENT_HOLD",
    RECALL: "RECIPIENT_RECALL",
    LIMIT: "RECIPIENT_LIMIT",
    REFUND: "RECIPIENT_REFUND",
    COMBINED: "RECIPIENT_COMBINED",
}


def isolated(record: ReceiveRecord, condition: str) -> ReceiveRecord:
    """`record` with every condition but `condition` at its most permissive
    value. The kind stays: a length needs its clock."""
    alone = ReceiveRecord(kind=record.kind)
    if condition == HOLD:
        return alone._replace(hold=record.hold)
    if condition == RECALL:
        return alone._replace(recall=record.recall)
    if condition == LIMIT:
        return alone._replace(limit=record.limit, period=record.period)
    if condition == REFUND:
        return alone._replace(refund=record.refund)
    raise ValueError(condition)


def refused_condition(allows: Callable[[ReceiveRecord], bool],
                      record: ReceiveRecord) -> str:
    """Which condition of a payment the clause refused it refuses on its own.

    `allows(r)` answers whether the clause lets the payment through with the
    record `r`; `record` is the one it refused. First the sender: a payment
    that is refused even when final at once is refused for who sent it (or for
    something the record does not describe: the amount, a reference), and its
    sender learns nothing of the receiver's other terms. Then hold, recall,
    limit and refund, each alone. `COMBINED` when the clause refuses none of
    them alone, which is a clause that ties two together. At most five
    evaluations, and none for a payment that was final at once.
    """
    if record.kind == tau_defs.RECEIVE_KIND_FINAL or not allows(FINAL):
        return SENDER
    for condition in (HOLD, RECALL, LIMIT, REFUND):
        probe = isolated(record, condition)
        if probe == ReceiveRecord(kind=record.kind) and condition != HOLD:
            continue                      # the payment carries no such condition
        if not allows(probe):
            return condition
    return COMBINED


def _longest(allows: Callable[[int], bool], known_refused: Optional[int],
             window: int) -> int:
    """The largest N in 0..`window` that `allows`, given that it allows 0.

    `known_refused` is a length it is known to refuse, or None. Both ends of the
    answer are answers of the clause itself: N was accepted and N + 1 refused.
    A clause need not be monotone, and then this is one boundary of several.
    """
    if known_refused is None or known_refused > window:
        if allows(window):
            return window
        known_refused = window
    low, high = 0, int(known_refused)
    while high - low > 1:
        mid = (low + high) // 2
        if allows(mid):
            low = mid
        else:
            high = mid
    return low


def longest_accepted(allows: Callable[[ReceiveRecord], bool], unit: str, condition: str,
                     known_refused: Optional[int], window: int) -> Optional[int]:
    """The longest hold (or recall window) in `unit` the clause accepts with
    every other condition at its most permissive value.

    None when it accepts no payment on that clock at all, even one with nothing
    held and nothing to take back. Else the largest N in 0..`window`, found by
    bisection: at most 24 evaluations for the 90 days in seconds, 18 for the
    window in blocks.
    """
    field = {HOLD: "hold", RECALL: "recall"}[condition]
    base = ReceiveRecord(kind=_KIND_OF[unit])
    if not allows(base):
        return None
    return _longest(lambda n: allows(base._replace(**{field: n})), known_refused, window)


def accepted_instead(allows: Callable[[ReceiveRecord], bool], record: ReceiveRecord,
                     condition: str, *, seconds_window: int,
                     blocks_window: int) -> dict:
    """What a clause that refused the hold or the recall window of a payment
    would take instead, as fields for the refusal: `max_hold_seconds` /
    `max_hold_blocks` or `max_recall_seconds` / `max_recall_blocks`.

    In the payment's own unit. When the clause takes nothing on that clock (a
    rule written for seconds refuses every height release), the bound in that
    unit is 0 and, for a height release, the bound in seconds is given too, so
    the payer learns which kind of release to use.
    """
    name = "max_%s_" % condition
    unit = record.unit
    window = blocks_window if unit == BLOCKS else seconds_window
    asked = int(record.hold if condition == HOLD else record.recall)
    bound = longest_accepted(allows, unit, condition, asked, window)
    if bound is not None:
        return {name + unit: bound}
    out = {name + unit: 0}
    if unit == BLOCKS:
        seconds = longest_accepted(allows, SECONDS, condition, None, seconds_window)
        out[name + SECONDS] = seconds or 0
    return out


# --- writing a receive rule from numbers ----------------------------------------
#
# "Only Alice", "30 days" and "500 a week" are numbers in the receiver's clause.
# This writes the clause from them, so nobody has to type bitvector comparisons.
# What it writes is an ordinary o5 clause: the node treats it like one written by
# hand, and a receiver is free to write another.

_ALLOW = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
_BLOCK = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_AMOUNT_CEILING = tau_defs.RECEIVE_LIMIT_CEILING


def _record_input(index: int) -> str:
    return "i%d[t]:bv[%d]" % (index, _WIDTH)


def _number(value: int) -> str:
    return "{ %d }:bv[%d]" % (int(value), _WIDTH)


def _kind_is(kind: int) -> str:
    return "(%s = %s)" % (_record_input(_RECEIVE), _number(kind))


def _bounded(name, value, ceiling=_NEVER, least=0):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not least <= value <= ceiling:
        raise ValueError(f"{name} must be a whole number from {least} to {ceiling}")
    return value


def receive_rule(*, senders=(), final_only: bool = False,
                 max_hold_seconds: Optional[int] = None,
                 max_hold_blocks: Optional[int] = None,
                 max_recall_seconds: Optional[int] = None,
                 max_recall_blocks: Optional[int] = None,
                 min_allowance: Optional[int] = None,
                 per_seconds: Optional[int] = None,
                 per_blocks: Optional[int] = None,
                 average: bool = False, no_limits: bool = False,
                 min_refund_seconds: Optional[int] = None,
                 min_refund_blocks: Optional[int] = None,
                 no_refunds: bool = False) -> str:
    """The o5 rule of a receiver who accepts exactly the payments these numbers
    describe. What its owner sends is never restricted by it.

    - `senders`: only these accounts may pay. Empty: anyone.
    - `final_only`: only payments that are final at once.
    - `max_hold_*`, `max_recall_*`: the longest hold and the longest recall
      window, on block time (seconds) or on block height (blocks).
    - `min_allowance` per `per_seconds` / `per_blocks`: a spending limit on the
      payment must leave at least that much in every stretch of that length
      (`average`: on average over its period); a payment without a limit
      passes. `no_limits`: only payments without a limit.
    - `min_refund_*`: nothing may go back to the sender by itself earlier than
      that. `no_refunds`: nothing ever.

    Seconds and blocks are never converted: a rule with numbers for one clock
    alone accepts no payment with conditions on the other. A rule with numbers
    for neither accepts both. Raises ValueError with the reason when the
    numbers contradict each other or do not fit the record.
    """
    senders = tuple(str(s).strip().lower() for s in senders)
    for sender in senders:
        if not _PUBKEY_RE.match(sender):
            raise ValueError("a sender is a public key of 96 hex characters")
    if len(set(senders)) != len(senders):
        raise ValueError("a sender is listed twice")

    hold = {SECONDS: _bounded("the longest hold", max_hold_seconds),
            BLOCKS: _bounded("the longest hold", max_hold_blocks)}
    recall = {SECONDS: _bounded("the longest recall window", max_recall_seconds),
              BLOCKS: _bounded("the longest recall window", max_recall_blocks)}
    refund = {SECONDS: _bounded("the earliest refund", min_refund_seconds),
              BLOCKS: _bounded("the earliest refund", min_refund_blocks)}
    per = {SECONDS: _bounded("the allowance period", per_seconds,
                             tau_defs.RECEIVE_PERIOD_CEILING_SECONDS, 1),
           BLOCKS: _bounded("the allowance period", per_blocks,
                            tau_defs.RECEIVE_PERIOD_CEILING_BLOCKS, 1)}
    allowance = _bounded("the minimum allowance", min_allowance, _AMOUNT_CEILING, 1)
    if (allowance is None) != (per[SECONDS] is None and per[BLOCKS] is None):
        raise ValueError("a minimum allowance is an amount together with its period")
    if no_limits and allowance is not None:
        raise ValueError("'no limits' and a minimum allowance exclude each other")
    if no_refunds and any(value is not None for value in refund.values()):
        raise ValueError("'no refunds' and an earliest refund exclude each other")
    if average and allowance is None:
        raise ValueError("the average reading needs a minimum allowance")

    no_limit = "(%s = %s)" % (_record_input(tau_defs.RECEIVE_PERIOD_INDEX), _number(0))
    limit_input = _record_input(tau_defs.RECEIVE_LIMIT_INDEX)
    period_input = _record_input(tau_defs.RECEIVE_PERIOD_INDEX)

    def covers(length: int) -> str:
        if average:
            # on average: C * W >= X * P
            return "((%s * %s) >= (%s * %s))" % (
                limit_input, _number(length), _number(allowance), period_input)
        # strict: C >= X * ceil(P / W). Inside the ceilings of the record the
        # sum cannot wrap, and above them the receiver is not asked.
        return "(%s >= (%s * ((%s + %s) / %s)))" % (
            limit_input, _number(allowance), period_input, _number(length - 1),
            _number(length))

    def on_clock(unit: str) -> List[str]:
        terms = []
        if hold[unit] is not None:
            terms.append("(%s <= %s)" % (
                _record_input(tau_defs.RECEIVE_HOLD_INDEX), _number(hold[unit])))
        if recall[unit] is not None:
            terms.append("(%s <= %s)" % (
                _record_input(tau_defs.RECEIVE_RECALL_INDEX), _number(recall[unit])))
        if per[unit] is not None:
            terms.append("( %s || %s )" % (no_limit, covers(per[unit])))
        if refund[unit] is not None:
            terms.append("(%s >= %s)" % (
                _record_input(tau_defs.RECEIVE_REFUND_INDEX), _number(refund[unit])))
        return terms

    either_clock = []
    if no_limits:
        either_clock.append(no_limit)
    if no_refunds:
        either_clock.append("(%s = %s)" % (
            _record_input(tau_defs.RECEIVE_REFUND_INDEX), _number(_NEVER)))
    clocks = {unit: on_clock(unit) for unit in (SECONDS, BLOCKS)}
    conditional = bool(either_clock or clocks[SECONDS] or clocks[BLOCKS])
    if final_only and conditional:
        raise ValueError("'final only' accepts no payment with conditions, so it "
                         "takes no other number")

    # The payments with conditions the rule accepts, as alternatives.
    with_conditions: List[str] = []
    only_allowance = allowance is not None and not either_clock and not any(
        value is not None for numbers in (hold, recall, refund) for value in numbers.values())
    if only_allowance:
        # The allowance is the receiver's one condition, so a payment without a
        # limit carries nothing it could fail, on either clock.
        with_conditions.append(no_limit)
        for unit in (SECONDS, BLOCKS):
            if per[unit] is not None:
                with_conditions.append("( %s && %s )" % (
                    _kind_is(_KIND_OF[unit]), covers(per[unit])))
    elif clocks[SECONDS] or clocks[BLOCKS]:
        for unit in (SECONDS, BLOCKS):
            if clocks[unit]:
                with_conditions.append("( %s )" % " && ".join(
                    [_kind_is(_KIND_OF[unit])] + clocks[unit] + either_clock))
    elif either_clock:
        with_conditions.append("( %s )" % " && ".join(either_clock)
                               if len(either_clock) > 1 else either_clock[0])

    mine = _kind_is(tau_defs.RECEIVE_KIND_OWN)
    final = _kind_is(tau_defs.RECEIVE_KIND_FINAL)
    listed = " || ".join(
        "(i3[t]:bv[384] = { #x%s }:bv[384])" % sender for sender in senders)
    if len(senders) > 1:
        listed = "( %s )" % listed

    if final_only or conditional:
        if senders:
            accepted = "%s || ( %s && ( %s ) )" % (
                mine, listed, " || ".join([final] + with_conditions))
        else:
            mine_or_final = "(%s <= %s)" % (
                _record_input(_RECEIVE), _number(tau_defs.RECEIVE_KIND_FINAL))
            accepted = " || ".join([mine_or_final] + with_conditions)
    elif senders:
        accepted = "%s || %s" % (mine, listed)
    else:
        raise ValueError("nothing to write: a rule needs a sender or a condition")

    rule = "always ( ( %s ) ? %s : %s )." % (accepted, _ALLOW, _BLOCK)
    from consensus.rule_offers import clause_body_v1, screen_clause_structure

    problem = screen_clause_structure(clause_body_v1(rule))
    if problem:
        raise ValueError(f"the rule would not register: {problem}")
    return rule
