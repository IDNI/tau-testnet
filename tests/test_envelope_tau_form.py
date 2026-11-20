"""An envelope's conditions written as one Tau clause, judged by the real engine.

The node checks an envelope spend in Python (`EnvelopeBook.check_spend`). Here the
same conditions are written as the body of an `always` clause, in the form the
policy worker runs, and the real Tau engine judges random and edge-case spends.
The engine and the node must agree on every case.

The clause is built from the signed terms alone. What changes after the send
reaches it as input streams:

    i1 amount of the spend          i6 spent in that period
    i2 the envelope's clock         i7 1 when it was spent from before, else 0
    i3 block time (the windows)     i8 clock of the last spend
    i4 what the envelope holds      i9 unlock point (clock when sent, moved on by
    i5 period of the last spend        not_before / hold)

`o5 = 1` lets the spend through, `o5 = 0` refuses it, as for a sender's rule.
Time comes in as the block's clock, never as the step counter `t`, which counts
interpreter steps rather than blocks or seconds. Who may spend and whether the
envelope is still open are facts of the book, not conditions; they stay out.

Skipped where the native module is not built.
"""
import os
import random

import pytest

import tau_policy
from consensus.envelope import (
    ALL_DAYS, ALL_HOURS, AT_END_REFUND, AT_END_RELEASE, KIND_BLOCKS, KIND_SECONDS,
    SECONDS_PER_DAY, SECONDS_PER_HOUR, EnvelopeBook, EnvelopeRefused, EnvelopeSpend,
    EnvelopeState, EnvelopeTerms, validate_send_shape,
)


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SENDER, RECIPIENT, SHOP = "a" * 96, "b" * 96, "c" * 96
W = 64


def lit(value: int) -> str:
    return "{ #x%016x }:bv[%d]" % (value, W)


def s(n: int) -> str:
    return f"i{n}[t]:bv[{W}]"


AMOUNT, CLOCK, TIME, HOLDS, LAST_PERIOD, SPENT, SPENT_BEFORE, LAST_CLOCK, UNLOCK = (
    s(n) for n in range(1, 10))


def _any(parts):
    return "( " + " || ".join(parts) + " )"


def _all(parts):
    return "( " + " && ".join(parts) + " )"


def tau_form(terms: EnvelopeTerms) -> str:
    """The body of an `always` clause equal to the envelope's spend conditions."""
    parts = [
        f"{AMOUNT} <= {HOLDS}",                               # never more than it holds
        f"{CLOCK} >= {UNLOCK}",                               # locked until the unlock point
        f"{CLOCK} < {lit(terms.expires_at)}",                 # its end
    ]
    if terms.refund_idle is not None:                       # unused for refund_idle
        idle = lit(terms.refund_idle)
        parts.append(_any([
            _all([f"{SPENT_BEFORE} = {lit(1)}", f"{CLOCK} < ( {LAST_CLOCK} + {idle} )"]),
            _all([f"{SPENT_BEFORE} = {lit(0)}", f"{CLOCK} < ( {UNLOCK} + {idle} )"]),
        ]))
    # Weekdays and hours are read at the envelope's fixed offset from UTC: block
    # time plus (or minus) utc_offset quarter hours. Unsigned arithmetic is enough,
    # block time is far above twelve hours.
    local = TIME
    if terms.utc_offset > 0:
        local = f"( {TIME} + {lit(terms.utc_offset * 900)} )"
    elif terms.utc_offset < 0:
        local = f"( {TIME} - {lit(-terms.utc_offset * 900)} )"
    if terms.days:                                          # weekdays, 0 = Monday
        weekday = f"( ( ( {local} / {lit(SECONDS_PER_DAY)} ) + {lit(3)} ) % {lit(7)} )"
        parts.append(_any([f"{weekday} = {lit(d)}" for d in range(7) if terms.days >> d & 1]))
    if terms.hours:                                         # hours
        hour = f"( ( {local} % {lit(SECONDS_PER_DAY)} ) / {lit(SECONDS_PER_HOUR)} )"
        parts.append(_any([f"{hour} = {lit(h)}" for h in range(24) if terms.hours >> h & 1]))
    if terms.caps:                                          # the cap of the period now
        period = f"( ( {CLOCK} - {UNLOCK} ) / {lit(terms.period)} )"

        def within(cap):
            return _any([
                _all([f"{LAST_PERIOD} = {period}", f"( {AMOUNT} + {SPENT} ) <= {lit(cap)}"]),
                _all([f"!( {LAST_PERIOD} = {period} )", f"{AMOUNT} <= {lit(cap)}"]),
            ])

        cases = [_all([f"{period} = {lit(k)}", within(cap)]) for k, cap in enumerate(terms.caps)]
        after = f"{period} >= {lit(len(terms.caps))}"
        cases.append(_all([after, within(terms.caps[-1])]) if terms.recurring else after)
        parts.append(_any(cases))
    return (f"{_all(parts)} ? ( o5[t]:bv[24] = {{ #x000001 }}:bv[24] ) "
            f": ( o5[t]:bv[24] = {{ #x000000 }}:bv[24] )")


def inputs(terms, state, amount, clock, ts):
    return {
        "i1": str(amount), "i2": str(clock), "i3": str(ts), "i4": str(state.remaining),
        "i5": str(state.period_index), "i6": str(state.spent_in_period),
        "i7": "1" if state.spends else "0", "i8": str(state.last_clock),
        "i9": str(state.anchor),
    }


def node_verdict(terms, state, amount, height, ts):
    """(allowed, reason) from the node's own check."""
    book = EnvelopeBook()
    eid = book._insert(terms, state)
    try:
        book.check_spend(EnvelopeSpend(RECIPIENT, eid, SHOP, amount), height, ts)
    except EnvelopeRefused as exc:
        return False, str(exc)
    return True, ""


def reason_kind(reason: str) -> str:
    for key, kind in (("reached its end", "end"), ("locked until", "locked"),
                      ("outside its spending window", "window"), ("holds", "holds"),
                      ("the cap", "cap")):
        if key in reason:
            return kind
    return "allowed" if not reason else "other"


# --- random envelopes, states and spends near every edge --------------------------------

def _mask(rng, bits, full):
    while True:
        m = rng.getrandbits(bits)
        if 0 < m < full:
            return m


def random_envelope(rng):
    kind = rng.choice((KIND_BLOCKS, KIND_SECONDS))
    unit = 1 if kind == KIND_BLOCKS else rng.choice((60, SECONDS_PER_HOUR))
    sent = rng.randint(1_000, 900_000) if kind == KIND_BLOCKS else rng.randint(1_700_000_000, 1_900_000_000)
    height, ts = (sent, 1_800_000_000) if kind == KIND_BLOCKS else (5_000, sent)
    caps, period, recurring = (), 0, False
    if rng.random() < 0.7:
        caps = tuple(rng.randint(1, 1_000) for _ in range(rng.randint(1, 4)))
        period, recurring = rng.randint(1, 40) * unit, rng.random() < 0.5
    windowed = kind == KIND_SECONDS and rng.random() < 0.6
    days = _mask(rng, 7, ALL_DAYS) if windowed and rng.random() < 0.6 else 0
    hours = _mask(rng, 24, ALL_HOURS) if windowed and rng.random() < 0.7 else 0
    terms = EnvelopeTerms(
        sender_pubkey=SENDER, sequence_number=rng.randint(0, 99), recipient_pubkey=RECIPIENT,
        amount=rng.randint(1, 5_000), caps=caps, kind=kind, period=period, recurring=recurring,
        expires_at=sent + rng.randint(60, 400) * unit,
        not_before=(sent + rng.randint(0, 30) * unit) if rng.random() < 0.3 else None,
        hold=rng.randint(1, 30) * unit if rng.random() < 0.3 else None,
        days=days, hours=hours,
        refund_idle=rng.randint(1, 120) * unit if rng.random() < 0.4 else None,
        at_end=rng.choice((AT_END_RELEASE, AT_END_REFUND)),
        # Quarter hours east of UTC: none, UTC+02:00, UTC-05:30, UTC+05:45, both ends.
        utc_offset=rng.choice((0, 0, 8, -22, 23, 56, -48)) if (days or hours) else 0,
    )
    if validate_send_shape(terms, height, ts):
        return None
    return terms, sent, unit


def random_state(rng, terms, sent, unit):
    anchor = terms.unlock_at(sent)
    spends = rng.choice((0, 0, 1, 3))
    last_clock = anchor + rng.randint(0, 60) * unit if spends else 0
    period_index = rng.randint(0, 6) if terms.caps else 0
    spent = rng.randint(0, max(terms.caps or (1,))) if terms.caps and spends else 0
    return EnvelopeState(anchor=anchor, remaining=rng.randint(1, terms.amount),
                         period_index=period_index, spent_in_period=spent, spends=spends,
                         last_height=1 if spends else 0, last_clock=last_clock)


def edge_clocks(rng, terms, state, unit):
    """Clocks next to every point where a verdict can change, plus a few at random."""
    points = {state.anchor, terms.expires_at, state.due_point(terms)}
    if terms.caps:
        for k in range(len(terms.caps) + 2):
            points.add(state.anchor + k * terms.period)
        points.add(state.anchor + (state.period_index) * terms.period)
    if terms.refund_idle is not None and state.spends:
        points.add(state.last_clock + terms.refund_idle)
    if terms.windowed:                                      # a window opens, then shuts
        opens = terms.next_window(state.anchor)
        if opens is not None:
            shuts = next((opens + k * 900 for k in range(1, 4 * 24 * 7 + 1)
                          if not terms.in_window(opens + k * 900)), None)
            points.update(p for p in (opens, shuts) if p is not None)
    out = set()
    for p in points:
        out.update({p - unit, p - 1, p, p + 1})
    span = max(terms.expires_at - state.anchor, 1)
    out.update(state.anchor + rng.randint(-span // 10, span) for _ in range(6))
    return sorted(c for c in out if c > 0)


def edge_amounts(rng, terms, state, clock):
    left = state.left_at(terms, clock)
    out = {1, left, left + 1, state.remaining, state.remaining + 1, rng.randint(1, terms.amount)}
    if left > 1:
        out.add(left - 1)
    return sorted(a for a in out if a >= 1)


@pytest.fixture(scope="module")
def engine():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=env, timeout=120.0)
    yield ev
    ev.close()


def _agree(engine, terms, state, amount, clock, ts, height):
    allowed, reason = node_verdict(terms, state, amount, height, ts)
    verdict = engine.verdict(tau_form(terms), inputs(terms, state, amount, clock, ts))
    assert (not verdict.blocked) == allowed, (terms, state, amount, clock, ts, reason, verdict)
    return reason_kind(reason)


def test_the_tau_form_builds_on_the_engine(engine):
    terms = EnvelopeTerms(SENDER, 0, RECIPIENT, 900, (100, 50), KIND_SECONDS, 3_600, True,
                          1_800_100_000, not_before=1_800_000_000, days=0b0011111,
                          hours=(1 << 9) - 1 << 8, refund_idle=86_400)
    result = engine.validate(tau_form(terms))
    assert result.ok, result.error


def test_the_tau_form_and_the_node_agree_on_a_worked_example(engine):
    """100 in the first hour, then 50 per hour; weekdays 08:00-17:00 UTC; back to the
    sender if unused for a week."""
    terms = EnvelopeTerms(SENDER, 0, RECIPIENT, 900, (100, 50), KIND_SECONDS, 3_600, True,
                          1_801_000_000, days=0b0011111, hours=(1 << 9) - 1 << 8,
                          refund_idle=7 * 86_400)
    monday_9 = 1_800_230_400 + 9 * 3_600          # Monday 2027-01-18 09:00 UTC
    state = EnvelopeState(anchor=monday_9, remaining=900)
    seen = [
        _agree(engine, terms, state, 100, monday_9 + 10, monday_9 + 10, 5),     # first hour, cap 100
        _agree(engine, terms, state, 101, monday_9 + 10, monday_9 + 10, 5),     # over the cap
        _agree(engine, terms, state, 50, monday_9 + 3_700, monday_9 + 3_700, 5),  # second hour, cap 50
        _agree(engine, terms, state, 51, monday_9 + 3_700, monday_9 + 3_700, 5),
        _agree(engine, terms, state, 10, monday_9 + 9 * 3_600, monday_9 + 9 * 3_600, 5),  # 18:00
        _agree(engine, terms, state, 10, monday_9 + 5 * 86_400, monday_9 + 5 * 86_400, 5),  # Saturday
        _agree(engine, terms, state, 10, monday_9 - 1, monday_9 - 1, 5),        # before unlock
        _agree(engine, terms, state, 10, monday_9 + 7 * 86_400, monday_9 + 7 * 86_400, 5),  # unused a week
    ]
    assert seen == ["allowed", "cap", "allowed", "cap", "window", "window", "locked", "end"]


def test_the_tau_form_follows_an_offset_from_utc(engine):
    """Noon at UTC+05:45 is 06:15 to 07:15 UTC; a Thursday at UTC-05:00 runs from
    Thursday 05:00 UTC to Friday 05:00 UTC."""
    monday = 1_800_230_400                         # Monday 2027-01-18 00:00 UTC
    state = EnvelopeState(anchor=monday, remaining=900)
    noon = EnvelopeTerms(SENDER, 0, RECIPIENT, 900, (), KIND_SECONDS, 0, False,
                         monday + 30 * 86_400, hours=1 << 12, utc_offset=23)
    opens = monday + 6 * 3_600 + 900
    seen = [_agree(engine, noon, state, 10, c, c, 5)
            for c in (opens - 1, opens, opens + 3_599, opens + 3_600)]
    assert seen == ["window", "allowed", "allowed", "window"]
    thursday = EnvelopeTerms(SENDER, 0, RECIPIENT, 900, (), KIND_SECONDS, 0, False,
                             monday + 30 * 86_400, days=1 << 3, utc_offset=-20)
    starts = monday + 3 * 86_400 + 5 * 3_600
    seen = [_agree(engine, thursday, state, 10, c, c, 5)
            for c in (starts - 1, starts, starts + 86_399, starts + 86_400)]
    assert seen == ["window", "allowed", "allowed", "window"]


def test_the_tau_form_and_the_node_agree_on_every_random_case(engine):
    rng = random.Random(20261117)
    seen, cases, envelopes = {}, 0, 0
    while envelopes < 20:
        made = random_envelope(rng)
        if made is None:
            continue
        terms, sent, unit = made
        envelopes += 1
        for _ in range(2):
            state = random_state(rng, terms, sent, unit)
            for clock in edge_clocks(rng, terms, state, unit):
                height, ts = (clock, 1_800_000_000) if terms.kind == KIND_BLOCKS else (5_000, clock)
                for amount in edge_amounts(rng, terms, state, clock):
                    kind = _agree(engine, terms, state, amount, clock, ts, height)
                    seen[kind] = seen.get(kind, 0) + 1
                    cases += 1
    # Every verdict the node can give was reached, many times over.
    assert cases > 3_000, cases
    for kind in ("allowed", "end", "locked", "window", "holds", "cap"):
        assert seen.get(kind, 0) >= 20, seen
    assert "other" not in seen, seen
