"""The recipient-side rules of docs/recipient_controls.md, as clause bodies, each
with a Python model of what it decides.

The mock policy evaluator answers from the models, so the apply and admission
tests run without the engine. `test_recipient_policy_native.py` holds the two
together: the real engine must give the model's verdict for every rule on a grid
of inputs, or the mocked tests prove nothing.
"""
import tau_defs

ALLOW = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
BLOCK = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
# "This is a payment I send": the record's kind reads 0.
MINE = "(i17[t]:bv[64] = { 0 }:bv[64])"
# "Mine, or a payment that is final at once": kind 0 or 1.
FINAL = "(i17[t]:bv[64] <= { 1 }:bv[64])"
ON_TIME = "(i17[t]:bv[64] = { 2 }:bv[64])"
ON_HEIGHT = "(i17[t]:bv[64] = { 3 }:bv[64])"

NEVER = tau_defs.RECEIVE_NEVER
_DEFAULTS = {"i17": 0, "i50": 0, "i51": 0, "i52": 0, "i53": 0, "i54": 0}


def _is(stream: str, pubkey: str) -> str:
    return "(%s[t]:bv[384] = { #x%s }:bv[384])" % (stream, pubkey)


def _at_most(stream: str, bound: int) -> str:
    return "(%s[t]:bv[64] <= { %d }:bv[64])" % (stream, bound)


def _key(inputs: dict, name: str) -> str:
    value = str(inputs.get(name, "0")).strip().lower()
    return value[2:] if value.startswith("#x") else value


def _number(inputs: dict, name: str) -> int:
    return int(str(inputs.get(name, _DEFAULTS.get(name, 0))) or 0)


def _receive(inputs: dict) -> int:
    """The record's kind: 0 mine, 1 final, 2 on block time, 3 on block height."""
    return _number(inputs, "i17")


def _verdict(allowed: bool) -> str:
    return "1" if allowed else "0"


def allow_list(*senders: str) -> str:
    """Only these senders may pay me. What I send is not restricted."""
    listed = " || ".join(_is("i3", s) for s in senders)
    return "( ( %s || %s ) ? %s : %s )" % (MINE, listed, ALLOW, BLOCK)


def allow_list_model(*senders: str):
    def decide(inputs):
        if _receive(inputs) == 0:
            return "1"
        return _verdict(_key(inputs, "i3") in senders)
    return decide


def final_only() -> str:
    """Instant and final only: nothing held, nothing the sender can take back."""
    return "( %s ? %s : %s )" % (FINAL, ALLOW, BLOCK)


def final_only_model():
    return lambda inputs: _verdict(_receive(inputs) <= 1)


def max_hold(seconds: int) -> str:
    """A payment to me may be held for at most `seconds`, on block time."""
    held = "( %s && %s )" % (ON_TIME, _at_most("i50", seconds))
    return "( ( %s || %s ) ? %s : %s )" % (FINAL, held, ALLOW, BLOCK)


def max_hold_model(seconds: int):
    def decide(inputs):
        kind = _receive(inputs)
        return _verdict(kind <= 1 or (kind == 2 and _number(inputs, "i50") <= seconds))
    return decide


def max_hold_either(seconds: int, blocks: int) -> str:
    """A payment to me may be held for at most `seconds`, or released at a
    height at most `blocks` ahead."""
    timed = "( %s && %s )" % (ON_TIME, _at_most("i50", seconds))
    by_height = "( %s && %s )" % (ON_HEIGHT, _at_most("i50", blocks))
    return "( ( %s || %s || %s ) ? %s : %s )" % (FINAL, timed, by_height, ALLOW, BLOCK)


def max_hold_either_model(seconds: int, blocks: int):
    def decide(inputs):
        kind, hold = _receive(inputs), _number(inputs, "i50")
        return _verdict(kind <= 1 or (kind == 2 and hold <= seconds)
                        or (kind == 3 and hold <= blocks))
    return decide


def hold_and_recall(hold_seconds: int, recall_seconds: int) -> str:
    """Held for at most `hold_seconds`, taken back within `recall_seconds` at
    most: two conditions, each its own number."""
    held = "( %s && %s && %s )" % (
        ON_TIME, _at_most("i50", hold_seconds), _at_most("i51", recall_seconds))
    return "( ( %s || %s ) ? %s : %s )" % (FINAL, held, ALLOW, BLOCK)


def hold_and_recall_model(hold_seconds: int, recall_seconds: int):
    def decide(inputs):
        kind = _receive(inputs)
        return _verdict(kind <= 1 or (
            kind == 2 and _number(inputs, "i50") <= hold_seconds
            and _number(inputs, "i51") <= recall_seconds))
    return decide


def hold_plus_recall(total_seconds: int) -> str:
    """A clause that ties two conditions together: the hold and the recall
    window may add up to `total_seconds`. Neither is refused on its own."""
    tied = ("( %s && %s && %s && ((i50[t]:bv[64] + i51[t]:bv[64]) <= { %d }:bv[64]) )"
            % (ON_TIME, _at_most("i50", total_seconds), _at_most("i51", total_seconds),
               total_seconds))
    return "( ( %s || %s ) ? %s : %s )" % (FINAL, tied, ALLOW, BLOCK)


def hold_plus_recall_model(total_seconds: int):
    def decide(inputs):
        kind = _receive(inputs)
        hold, recall = _number(inputs, "i50"), _number(inputs, "i51")
        return _verdict(kind <= 1 or (
            kind == 2 and hold <= total_seconds and recall <= total_seconds
            and hold + recall <= total_seconds))
    return decide


def one_unit(pay_only: str, accept_only_from: str, hold_seconds: int) -> str:
    """Outbound whitelist, inbound allow-list and hold cap in ONE clause."""
    sending = "( %s && %s )" % (MINE, _is("i4", pay_only))
    final = "(i17[t]:bv[64] = { 1 }:bv[64])"
    held = "( %s && %s )" % (ON_TIME, _at_most("i50", hold_seconds))
    receiving = "( %s && ( %s || %s ) )" % (_is("i3", accept_only_from), final, held)
    return "( ( %s || %s ) ? %s : %s )" % (sending, receiving, ALLOW, BLOCK)


def one_unit_model(pay_only: str, accept_only_from: str, hold_seconds: int):
    def decide(inputs):
        kind = _receive(inputs)
        if kind == 0:
            return _verdict(_key(inputs, "i4") == pay_only)
        if _key(inputs, "i3") != accept_only_from:
            return "0"
        return _verdict(kind == 1 or (kind == 2 and _number(inputs, "i50") <= hold_seconds))
    return decide


# --- the limit, the refund and the combined rule ---------------------------------
#
# The node feeds no payment with a spending limit or a refund yet: transfers and
# parks carry neither. The rules are the receiver's side of both all the same,
# held to the engine in `test_recipient_policy_native.py`, and
# `getrecipientpolicy` answers for any terms.

_WORD = 1 << 64
NO_LIMIT = "(i53[t]:bv[64] = { 0 }:bv[64])"


def _covers(amount: int, per: int) -> str:
    """The limit leaves `amount` in every stretch of `per`: C >= X * ceil(P / W)."""
    return ("(i52[t]:bv[64] >= ({ %d }:bv[64] * ((i53[t]:bv[64] + { %d }:bv[64]) "
            "/ { %d }:bv[64])))" % (amount, per - 1, per))


def _covers_model(inputs, amount: int, per: int) -> bool:
    # as the engine computes it, in 64 bits; inside the record's ceilings
    # nothing wraps and this is the exact ceil(P / W)
    rounds = ((_number(inputs, "i53") + per - 1) % _WORD) // per
    return _number(inputs, "i52") >= (amount * rounds) % _WORD


def min_allowance(amount: int, per_seconds: int) -> str:
    """A spending limit on a payment to me leaves me at least `amount` in every
    stretch of `per_seconds`, or the payment has no limit at all."""
    limited = "( %s && %s )" % (ON_TIME, _covers(amount, per_seconds))
    return "( ( %s || %s || %s ) ? %s : %s )" % (FINAL, NO_LIMIT, limited, ALLOW, BLOCK)


def min_allowance_model(amount: int, per_seconds: int):
    def decide(inputs):
        kind = _receive(inputs)
        return _verdict(kind <= 1 or _number(inputs, "i53") == 0
                        or (kind == 2 and _covers_model(inputs, amount, per_seconds)))
    return decide


def average_allowance(amount: int, per_seconds: int) -> str:
    """The other reading of a limit: on average at least `amount` per
    `per_seconds`. 150 a week then meets 500 a month."""
    average = ("((i52[t]:bv[64] * { %d }:bv[64]) >= ({ %d }:bv[64] * i53[t]:bv[64]))"
               % (per_seconds, amount))
    limited = "( %s && %s )" % (ON_TIME, average)
    return "( ( %s || %s || %s ) ? %s : %s )" % (FINAL, NO_LIMIT, limited, ALLOW, BLOCK)


def average_allowance_model(amount: int, per_seconds: int):
    def decide(inputs):
        kind = _receive(inputs)
        limit, period = _number(inputs, "i52"), _number(inputs, "i53")
        return _verdict(kind <= 1 or period == 0 or (
            kind == 2 and (limit * per_seconds) % _WORD >= (amount * period) % _WORD))
    return decide


def no_limits() -> str:
    """Only money without a spending limit."""
    return "( ( %s || %s ) ? %s : %s )" % (FINAL, NO_LIMIT, ALLOW, BLOCK)


def no_limits_model():
    return lambda inputs: _verdict(_receive(inputs) <= 1 or _number(inputs, "i53") == 0)


def min_refund(seconds: int) -> str:
    """Nothing of a payment to me goes back by itself within `seconds`."""
    late = "( %s && (i54[t]:bv[64] >= { %d }:bv[64]) )" % (ON_TIME, seconds)
    return "( ( %s || %s ) ? %s : %s )" % (FINAL, late, ALLOW, BLOCK)


def min_refund_model(seconds: int):
    def decide(inputs):
        kind = _receive(inputs)
        return _verdict(kind <= 1 or (kind == 2 and _number(inputs, "i54") >= seconds))
    return decide


def no_refunds() -> str:
    """Nothing of a payment to me ever goes back by itself."""
    never = "(i54[t]:bv[64] = { %d }:bv[64])" % NEVER
    return "( ( %s || %s ) ? %s : %s )" % (FINAL, never, ALLOW, BLOCK)


def no_refunds_model():
    return lambda inputs: _verdict(
        _receive(inputs) <= 1 or _number(inputs, "i54") == NEVER)


def combined(sender: str, hold_seconds: int, recall_seconds: int, amount: int,
             per_seconds: int, refund_seconds: int) -> str:
    """Every condition in one rule: only `sender`; held at most `hold_seconds`;
    taken back within `recall_seconds` at most; at least `amount` per
    `per_seconds` or no limit; nothing refunded within `refund_seconds`."""
    final = "(i17[t]:bv[64] = { 1 }:bv[64])"
    terms = "( %s && %s && %s && ( %s || %s ) && (i54[t]:bv[64] >= { %d }:bv[64]) )" % (
        ON_TIME, _at_most("i50", hold_seconds), _at_most("i51", recall_seconds),
        NO_LIMIT, _covers(amount, per_seconds), refund_seconds)
    receiving = "( %s && ( %s || %s ) )" % (_is("i3", sender), final, terms)
    return "( ( %s || %s ) ? %s : %s )" % (MINE, receiving, ALLOW, BLOCK)


def combined_model(sender: str, hold_seconds: int, recall_seconds: int, amount: int,
                   per_seconds: int, refund_seconds: int):
    def decide(inputs):
        kind = _receive(inputs)
        if kind == 0:
            return "1"
        if _key(inputs, "i3") != sender:
            return "0"
        if kind == 1:
            return "1"
        return _verdict(
            kind == 2 and _number(inputs, "i50") <= hold_seconds
            and _number(inputs, "i51") <= recall_seconds
            and (_number(inputs, "i53") == 0 or _covers_model(inputs, amount, per_seconds))
            and _number(inputs, "i54") >= refund_seconds)
    return decide


def written_model(*, senders=(), final_only=False,
                  max_hold_seconds=None, max_hold_blocks=None,
                  max_recall_seconds=None, max_recall_blocks=None,
                  min_allowance=None, per_seconds=None, per_blocks=None,
                  average=False, no_limits=False,
                  min_refund_seconds=None, min_refund_blocks=None, no_refunds=False):
    """What a rule written by `recipient_policy.receive_rule` from these numbers
    must decide, written from the meaning of the numbers and not from the
    rule's text."""
    senders = tuple(s.lower() for s in senders)
    hold = {2: max_hold_seconds, 3: max_hold_blocks}
    recall = {2: max_recall_seconds, 3: max_recall_blocks}
    refund = {2: min_refund_seconds, 3: min_refund_blocks}
    per = {2: per_seconds, 3: per_blocks}
    bounded = [n for numbers in (hold, recall, refund) for n in numbers.values()
               if n is not None]

    def covers(inputs, length):
        limit, period = _number(inputs, "i52"), _number(inputs, "i53")
        if average:
            return (limit * length) % _WORD >= (min_allowance * period) % _WORD
        return limit >= (min_allowance * (((period + length - 1) % _WORD) // length)) % _WORD

    def decide(inputs):
        kind = _receive(inputs)
        if kind == 0:
            return "1"
        if senders and _key(inputs, "i3") not in senders:
            return "0"
        if kind == 1:
            return "1"
        if final_only:
            return "0"
        unlimited = _number(inputs, "i53") == 0
        everywhere = ((not no_limits or unlimited)
                      and (not no_refunds or _number(inputs, "i54") == NEVER))
        if min_allowance is None and not bounded:
            return _verdict(everywhere)      # no number for either clock
        if min_allowance is not None and not bounded and not (no_limits or no_refunds):
            # the allowance alone: a payment without a limit passes on any clock
            return _verdict(unlimited or (per.get(kind) is not None
                                          and covers(inputs, per[kind])))
        numbers = [hold.get(kind), recall.get(kind), refund.get(kind), per.get(kind)]
        if all(n is None for n in numbers):
            return "0"                       # no number for this clock
        return _verdict(
            everywhere
            and (hold[kind] is None or _number(inputs, "i50") <= hold[kind])
            and (recall[kind] is None or _number(inputs, "i51") <= recall[kind])
            and (per[kind] is None or unlimited or covers(inputs, per[kind]))
            and (refund[kind] is None or _number(inputs, "i54") >= refund[kind]))
    return decide


def needs_reference(stream: int = 30) -> str:
    """A payment to me must carry a reference on a custom input of the payer."""
    missing = "(i%d[t]:bv[24] = { #x000000 }:bv[24])" % stream
    return "( ( !%s && %s ) ? %s : %s )" % (MINE, missing, BLOCK, ALLOW)


def needs_reference_model(stream: int = 30):
    def decide(inputs):
        if _receive(inputs) == 0:
            return "1"
        value = str(inputs.get("i%d" % stream, "0")).strip()
        return "0" if value in ("", "0") else "1"
    return decide


# An ordinary sender-side clause that never mentions the receive record.
SPEND_LIMIT = (
    "( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) ? %s : %s )" % (BLOCK, ALLOW)
)


def spend_limit_model(inputs):
    value = str(inputs.get("i1", "0"))
    amount = int(value[2:], 16) if value.startswith("#x") else int(value or 0)
    return "0" if amount > 1000 else "1"
