"""Reading an envelope's conditions together: when it can be spent, what each
condition does, and the same in plain words.

Nothing here is consensus. The node's checks live in consensus/envelope.py and
this module only reads terms the way those checks judge them, so a wallet can
show a sender, before signing, what the conditions add up to:

    plan(terms, sent)      the points that matter: unlock, first spend, first due
                           point and what happens there, the limit's reach
    refusal(terms, sent)   why the node would refuse it as never spendable, naming
                           the conditions that clash
    notes(terms, sent)     conditions that change nothing for this envelope
                           ("never_decides"), and combinations that may surprise
                           ("warning")
    explain(terms, ...)    the conditions as sentences

A "never_decides" note is sound: removing that condition alone would leave every
spend, refusal and close of the envelope exactly as it is (proved by exhaustive
search in tests/test_envelope_combined.py). A condition without such a note may
still never decide in practice; the note is only given when that is certain.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from consensus.envelope import (
    AT_END_REFUND,
    DAY_NAMES,
    KIND_BLOCKS,
    SECONDS_PER_DAY,
    SECONDS_PER_HOUR,
    EnvelopeState,
    EnvelopeTerms,
    first_spend_point,
    hour_of,
    offset_text,
    weekday,
)

SECONDS_PER_WEEK = 7 * SECONDS_PER_DAY

NEVER_DECIDES = "never_decides"
WARNING = "warning"
INFO = "info"


# --- Formatting --------------------------------------------------------------------


def clock_text(terms: EnvelopeTerms, value: int) -> str:
    """A point on the envelope's clock, as people read it."""
    if terms.kind == KIND_BLOCKS:
        return f"block {int(value):,}"
    moment = datetime.fromtimestamp(int(value), timezone.utc)
    if moment.second:
        return moment.strftime("%a %Y-%m-%d %H:%M:%S UTC")
    return moment.strftime("%a %Y-%m-%d %H:%M UTC")


def span_text(terms: EnvelopeTerms, value: int) -> str:
    """A length on the envelope's clock, as people read it."""
    value = int(value)
    if terms.kind == KIND_BLOCKS:
        return f"{value:,} block" + ("" if value == 1 else "s")
    for unit, name in ((SECONDS_PER_WEEK, "week"), (SECONDS_PER_DAY, "day"),
                       (SECONDS_PER_HOUR, "hour"), (60, "minute")):
        if value >= unit and value % unit == 0 and (unit >= SECONDS_PER_DAY or value // unit < 100):
            n = value // unit
            return f"{n:,} {name}" + ("" if n == 1 else "s")
    parts = []
    for unit, name in ((SECONDS_PER_DAY, "d"), (SECONDS_PER_HOUR, "h"), (60, "min"), (1, "s")):
        if value >= unit:
            parts.append(f"{value // unit} {name}")
            value %= unit
    return " ".join(parts) or "0 s"


def per_text(terms: EnvelopeTerms, value: int) -> str:
    """A period after "per": "week", "30 days", "block", "10 blocks", "1 h 40 min"."""
    text = span_text(terms, value)
    return text[2:] if text[2:] in ("week", "day", "hour", "minute", "block") and text.startswith("1 ") else text


def days_text(mask: int) -> str:
    """Weekdays as runs, Monday first: "Mon-Fri", "Mon, Wed, Fri", "Sat-Mon"."""
    on = [(mask >> d) & 1 for d in range(7)]
    runs = _cyclic_runs(on)
    if on[0] and on[6] and sum(on) < 7:
        wrapped = next(r for r in runs if r[0] + r[1] > 7)
        if wrapped[1] < 3:  # "Sun, Mon" reads better as two days in week order
            runs = [r for r in runs if r is not wrapped] + [(0, wrapped[0] + wrapped[1] - 7),
                                                            (wrapped[0], 7 - wrapped[0])]
            runs = sorted(runs)
    out = []
    for start, length in runs:
        first, last = DAY_NAMES[start], DAY_NAMES[(start + length - 1) % 7]
        if length == 1:
            out.append(first.capitalize())
        elif length == 2:
            out.append(f"{first.capitalize()}, {last.capitalize()}")
        else:
            out.append(f"{first.capitalize()}-{last.capitalize()}")
    return ", ".join(out)


def hours_text(mask: int, utc_offset: int = 0) -> str:
    """Hours as ranges with where they are read: "09:00-17:00 UTC",
    "22:00-06:00 UTC+02:00"."""
    on = [(mask >> h) & 1 for h in range(24)]
    return ", ".join(f"{start:02d}:00-{(start + length) % 24:02d}:00"
                     for start, length in _cyclic_runs(on)) + " " + offset_text(utc_offset)


def _days_at(terms: EnvelopeTerms) -> str:
    """Weekdays, with their offset when there is one: "Sat, Sun", "Sat, Sun UTC-05:00"."""
    return days_text(terms.days) + (
        f" {offset_text(terms.utc_offset)}" if terms.utc_offset else "")


def windows_text(terms: EnvelopeTerms) -> str:
    """The windows of an envelope: "Mon-Fri and 09:00-17:00 UTC+02:00", "Sat, Sun",
    "Sat, Sun UTC-05:00"."""
    if terms.days and not terms.hours:
        return _days_at(terms)
    return " and ".join(t for t in (
        days_text(terms.days) if terms.days else "",
        hours_text(terms.hours, terms.utc_offset) if terms.hours else "") if t)


def _cyclic_runs(on: List[int]) -> List[Tuple[int, int]]:
    """Runs of set entries in a cyclic list, as (start, length), first by start;
    a run that wraps past the end starts where it really starts."""
    n = len(on)
    if all(on):
        return [(0, n)]
    if not any(on):
        return []
    start = next(i for i in range(n) if not on[i])   # begin after a gap
    runs, i = [], 0
    while i < n:
        j = (start + i) % n
        if on[j]:
            length = 0
            while length < n and on[(j + length) % n]:
                length += 1
            runs.append((j, length))
            i += length
        else:
            i += 1
    return sorted(runs)


# --- The points that matter ----------------------------------------------------------


def unlock_by(terms: EnvelopeTerms, sent: int) -> List[str]:
    """Which conditions set the unlock: [] when it is the send itself."""
    unlock = terms.unlock_at(sent)
    if unlock == int(sent):
        return []
    by = []
    if terms.not_before is not None and terms.not_before == unlock:
        by.append("not_before")
    if terms.hold is not None and int(sent) + terms.hold == unlock:
        by.append("hold")
    return by


def first_due(terms: EnvelopeTerms, sent: int) -> Tuple[int, str]:
    """The due point of an envelope nobody spends from, and which condition sets it:
    "end" or "refund_idle". A tie is the end, as at apply."""
    unlock = terms.unlock_at(sent)
    state = EnvelopeState(anchor=unlock, remaining=terms.amount)
    due = state.due_point(terms)
    idle = state.idle_point(terms)
    return due, ("refund_idle" if idle is not None and idle < terms.expires_at else "end")


def limit_reach(terms: EnvelopeTerms, unlock: int) -> Tuple[int, List[int]]:
    """For a limited envelope: how many periods can hold a spend (a spend lands
    before the end), and the caps that can apply in them, first period first."""
    if not terms.limited or terms.expires_at <= unlock:
        return 0, []
    periods = (terms.expires_at - 1 - unlock) // terms.period + 1
    return periods, list(terms.caps[:min(len(terms.caps), periods)])


def window_runs(terms: EnvelopeTerms) -> List[Tuple[int, int]]:
    """The windows of one week as (start, end) seconds after Monday 00:00 at the
    envelope's offset from UTC, adjacent hours merged; a run across Sunday midnight
    wraps (end > one week)."""
    monday = _week_start() - terms.local(0)
    on = [int(terms.in_window(monday + h * SECONDS_PER_HOUR)) for h in range(7 * 24)]
    return [(start * SECONDS_PER_HOUR, (start + length) * SECONDS_PER_HOUR)
            for start, length in _cyclic_runs(on)]


def _week_start() -> int:
    """A Monday 00:00 UTC (1970-01-05)."""
    return 4 * SECONDS_PER_DAY


def longest_gap(terms: EnvelopeTerms) -> int:
    """The longest stretch, in seconds, with no window open; 0 without windows."""
    if not terms.windowed:
        return 0
    runs = window_runs(terms)
    gaps = []
    for i, (_, end) in enumerate(runs):
        nxt = runs[(i + 1) % len(runs)][0] + (SECONDS_PER_WEEK if i + 1 == len(runs) else 0)
        gaps.append(nxt - end)
    return max(gaps)


def plan(terms: EnvelopeTerms, sent: int) -> Dict[str, Any]:
    """The points that matter for an envelope sent at clock `sent`."""
    unlock = terms.unlock_at(sent)
    due, due_by = first_due(terms, sent)
    first = first_spend_point(terms, sent) if unlock < terms.expires_at else None
    periods, caps = limit_reach(terms, unlock)
    out: Dict[str, Any] = {
        "sent": int(sent),
        "unlocks_at": unlock,
        "unlocked_by": unlock_by(terms, sent) or None,
        "first_spend_at": first,
        "spendable": first is not None,
        "first_due_at": due,
        "first_due_by": due_by,
        "first_due_outcome": ("refunded_idle" if due_by == "refund_idle" else
                              "refunded" if terms.at_end == AT_END_REFUND else "ended"),
        "expires_at": terms.expires_at,
    }
    if terms.limited:
        lapses = (not terms.recurring) and periods > len(terms.caps)
        out.update({
            "limit_periods": periods,
            "limit_caps": caps,
            "most_spendable": min(terms.amount, _most_spendable(terms, periods)),
            "limit_lapses_at": unlock + len(terms.caps) * terms.period if lapses else None,
        })
    return out


def _most_spendable(terms: EnvelopeTerms, periods: int) -> int:
    """The most the limit lets through before the end, windows and refunds aside."""
    listed = len(terms.caps)
    if periods > listed and not terms.recurring:
        return terms.amount
    total = sum(terms.caps[:min(listed, periods)])
    if periods > listed:
        total += (periods - listed) * terms.caps[-1]
    return total


def refusal(terms: EnvelopeTerms, sent: int) -> Optional[str]:
    """Why an envelope sent at clock `sent` could never be spent, naming the
    conditions that clash; None when a spend could land. The node refuses such a
    send (ENVELOPE_NEVER_SPENDABLE); this says the same in plain words."""
    at = lambda v: clock_text(terms, v)
    unlock = terms.unlock_at(sent)
    by = unlock_by(terms, sent)
    cause = " and ".join(
        f"the hold of {span_text(terms, terms.hold)}" if c == "hold" else "not_before"
        for c in by)
    if unlock >= terms.expires_at:
        return (f"It would unlock at {at(unlock)} ({cause}), but it ends at "
                f"{at(terms.expires_at)}: it could never be spent.")
    if first_spend_point(terms, sent) is not None:
        return None
    due, due_by = first_due(terms, sent)
    closes = (f"the refund after {span_text(terms, terms.refund_idle)} unused"
              if due_by == "refund_idle" else "its end")
    windows = windows_text(terms)
    opened = f"it unlocks at {at(unlock)}" + (f" ({cause})" if cause else "")
    return (f"No spending window ({windows}) opens between the moment {opened} and "
            f"{at(due)} ({closes}): it could never be spent.")


# --- Conditions that change nothing, and combinations that surprise ---------------------


def notes(terms: EnvelopeTerms, sent: int) -> List[Dict[str, Any]]:
    """What to tell a sender about an envelope sent at clock `sent`.

    Every NEVER_DECIDES note is certain: that condition alone could be removed and
    the envelope would behave exactly the same. WARNING notes name combinations
    that do what they say but may not be what the sender meant.
    """
    sent = int(sent)
    out: List[Dict[str, Any]] = []
    unlock = terms.unlock_at(sent)
    if unlock >= terms.expires_at or first_spend_point(terms, sent) is None:
        return out  # refused anyway; the refusal says why
    span = lambda v: span_text(terms, v)
    at = lambda v: clock_text(terms, v)

    def add(level: str, condition: str, code: str, text: str) -> None:
        out.append({"level": level, "condition": condition, "code": code, "text": text})

    # Time locks: the later one wins, so the other changes nothing.
    held = sent + terms.hold if terms.hold is not None else sent
    if terms.not_before is not None and terms.not_before <= held:
        if terms.not_before <= sent:
            add(NEVER_DECIDES, "not_before", "NOT_BEFORE_PASSED",
                f"not_before ({at(terms.not_before)}) has passed when it arrives: it locks nothing.")
        else:
            add(NEVER_DECIDES, "not_before", "NOT_BEFORE_COVERED",
                f"not_before ({at(terms.not_before)}) changes nothing: the hold of "
                f"{span(terms.hold)} already locks it until {at(held)}.")
    if terms.hold is not None and terms.not_before is not None and held <= terms.not_before:
        add(NEVER_DECIDES, "hold", "HOLD_COVERED",
            f"hold ({span(terms.hold)}) changes nothing: not_before already locks it "
            f"until {at(terms.not_before)}.")

    # The limit: only the periods that begin before the end can matter.
    if terms.limited:
        periods, caps = limit_reach(terms, unlock)
        never_binds = bool(caps) and min(caps) >= terms.amount
        if never_binds:
            add(NEVER_DECIDES, "caps", "LIMIT_NEVER_BINDS",
                f"The spending limit changes nothing: every cap that can apply is at least "
                f"the {terms.amount:,} the envelope holds.")
        elif len(terms.caps) > periods:
            add(NEVER_DECIDES, "caps", "CAPS_UNREACHED",
                f"Only the first {periods} of the {len(terms.caps)} caps can apply: the "
                f"envelope ends at {at(terms.expires_at)}, before period {periods + 1} begins.")
        if terms.recurring and periods <= len(terms.caps):
            add(NEVER_DECIDES, "recurring", "RECURRING_UNUSED",
                "recurring changes nothing: the list of caps covers every period before the end.")
        elif terms.recurring and terms.caps[-1] >= terms.amount:
            add(NEVER_DECIDES, "recurring", "RECURRING_UNUSED",
                f"recurring changes nothing: the last cap ({terms.caps[-1]:,}) is at least "
                f"the {terms.amount:,} the envelope holds.")
        if not never_binds and not terms.recurring and periods > len(terms.caps):
            add(INFO, "caps", "LIMIT_LAPSES",
                f"The limit stops after {len(terms.caps)} period"
                f"{'' if len(terms.caps) == 1 else 's'}: from "
                f"{at(unlock + len(terms.caps) * terms.period)} the rest may be spent freely.")
        most = _most_spendable(terms, periods)
        if most < terms.amount:
            goes = "back to the sender" if terms.at_end == AT_END_REFUND else "to the recipient"
            add(INFO, "caps", "LIMIT_LEAVES_REST",
                f"The limit lets at most {most:,} of the {terms.amount:,} be spent before the "
                f"end; at least {terms.amount - most:,} goes {goes} at "
                f"{at(terms.expires_at)}, unless it is released or refunded earlier.")

    # Windows: only the stretch from the unlock to the end can matter.
    if terms.days and _covers(terms, unlock, terms.expires_at, days=True):
        add(NEVER_DECIDES, "days", "DAYS_COVER_LIFE",
            f"days ({_days_at(terms)}) changes nothing: every day from the unlock to "
            f"the end is one of them.")
    if terms.hours and _covers(terms, unlock, terms.expires_at, days=False):
        add(NEVER_DECIDES, "hours", "HOURS_COVER_LIFE",
            f"hours ({hours_text(terms.hours, terms.utc_offset)}) changes nothing: every "
            f"hour from the unlock "
            f"to the end is one of them.")

    # Refunds.
    if terms.refund_idle is not None:
        if unlock + terms.refund_idle >= terms.expires_at:
            add(NEVER_DECIDES, "refund_idle", "IDLE_NEVER_FIRES",
                f"refund_idle ({span(terms.refund_idle)}) changes nothing: the end at "
                f"{at(terms.expires_at)} comes first, and the end decides a tie.")
        elif terms.windowed and terms.refund_idle <= longest_gap(terms) + 1:
            add(WARNING, "refund_idle", "IDLE_BETWEEN_WINDOWS",
                f"refund_idle ({span(terms.refund_idle)}) is not longer than the longest time "
                f"with no window open ({span(longest_gap(terms))}): the rest may go back to "
                f"the sender while the recipient cannot spend.")
    return out


def _covers(terms: EnvelopeTerms, start: int, end: int, *, days: bool) -> bool:
    """True when every second in [start, end) lies on an allowed weekday (days) or
    in an allowed hour (hours), both read at the envelope's offset from UTC."""
    step = SECONDS_PER_DAY if days else SECONDS_PER_HOUR
    if end - start > SECONDS_PER_WEEK:
        return False  # every weekday and every hour come round; not all are allowed
    t, end = terms.local(start), terms.local(end)
    while t < end:
        if days and not (terms.days >> weekday(t)) & 1:
            return False
        if not days and not (terms.hours >> hour_of(t)) & 1:
            return False
        t = (t // step + 1) * step
    return True


# --- In plain words ----------------------------------------------------------------------


def explain(terms: EnvelopeTerms, *, unlock: int, sent: Optional[int] = None,
            sender: str = "the sender", recipient: str = "the recipient",
            remaining: Optional[int] = None) -> str:
    """The conditions as sentences. `unlock` is the envelope's unlock (an open
    envelope's anchor); `sent`, when known, names the hold by its length."""
    span = lambda v: span_text(terms, v)
    at = lambda v: clock_text(terms, v)
    held = terms.amount if remaining is None else remaining
    parts = []
    head = f"{_cap(recipient)} may spend {held:,}"
    if sent is not None and unlock <= int(sent):
        head += " at once"
    else:
        head += f" from {at(unlock)}"
        if sent is not None and unlock_by(terms, sent) == ["hold"]:
            head += f" ({span(terms.hold)} after it arrives)"
    if terms.days and terms.hours:
        head += (f", only on {days_text(terms.days)} and only "
                 f"{hours_text(terms.hours, terms.utc_offset)}")
    elif terms.days:
        head += f", only on {days_text(terms.days)} ({offset_text(terms.utc_offset)})"
    elif terms.hours:
        head += f", only {hours_text(terms.hours, terms.utc_offset)}"
    parts.append(head + ", to anyone.")
    if terms.limited:
        parts.append(_limit_sentence(terms))
    if terms.refund_idle is not None:
        parts.append(f"If {recipient} spends nothing for {span(terms.refund_idle)}, what is "
                     f"left goes back to {sender}.")
    goes = f"back to {sender}" if terms.at_end == AT_END_REFUND else f"to {recipient}"
    parts.append(f"At {at(terms.expires_at)} what is left goes {goes}.")
    parts.append(f"{_cap(sender)} cannot take it back earlier, only release the rest to "
                 f"{recipient} at once.")
    return " ".join(parts)


def _limit_sentence(terms: EnvelopeTerms) -> str:
    per = per_text(terms, terms.period)
    length = span_text(terms, terms.period)
    caps = [f"{c:,}" for c in terms.caps]
    if len(caps) == 1:
        text = f"At most {caps[0]} per {per}"
        text += ", every period" if terms.recurring else f", in the first {per} only"
    else:
        listed = ", ".join(caps[:-1]) + f" and {caps[-1]}"
        text = f"At most {listed} in the first {len(caps)} periods of {length}"
        text += f", then {caps[-1]} per {per}" if terms.recurring else ", then no limit"
    return text + "; the periods count from the unlock, and nothing carries over."


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]
