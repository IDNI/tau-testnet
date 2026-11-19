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
# "This is a payment I send": the receive stream reads 0.
MINE = "(i17[t]:bv[64] = { 0 }:bv[64])"

UNBOUNDED = tau_defs.RECEIVE_HOLD_UNBOUNDED


def _is(stream: str, pubkey: str) -> str:
    return "(%s[t]:bv[384] = { #x%s }:bv[384])" % (stream, pubkey)


def _key(inputs: dict, name: str) -> str:
    value = str(inputs.get(name, "0")).strip().lower()
    return value[2:] if value.startswith("#x") else value


def _receive(inputs: dict) -> int:
    return int(str(inputs.get("i17", "0")) or 0)


def allow_list(*senders: str) -> str:
    """Only these senders may pay me. What I send is not restricted."""
    listed = " || ".join(_is("i3", s) for s in senders)
    return "( ( %s || %s ) ? %s : %s )" % (MINE, listed, ALLOW, BLOCK)


def allow_list_model(*senders: str):
    def decide(inputs):
        if _receive(inputs) == 0:
            return "1"
        return "1" if _key(inputs, "i3") in senders else "0"
    return decide


def max_hold(seconds: int) -> str:
    """A payment to me may be held for at most `seconds`; 0 means final at once."""
    return "( (i17[t]:bv[64] > { %d }:bv[64]) ? %s : %s )" % (seconds + 1, BLOCK, ALLOW)


def max_hold_model(seconds: int):
    def decide(inputs):
        return "0" if _receive(inputs) > seconds + 1 else "1"
    return decide


def one_unit(pay_only: str, accept_only_from: str, hold_seconds: int) -> str:
    """Outbound whitelist, inbound allow-list and hold cap in ONE clause."""
    sending_elsewhere = "( %s && !%s )" % (MINE, _is("i4", pay_only))
    stranger_pays = "( !%s && !%s )" % (MINE, _is("i3", accept_only_from))
    held_too_long = "(i17[t]:bv[64] > { %d }:bv[64])" % (hold_seconds + 1)
    return "( ( %s || %s || %s ) ? %s : %s )" % (
        sending_elsewhere, stranger_pays, held_too_long, BLOCK, ALLOW)


def one_unit_model(pay_only: str, accept_only_from: str, hold_seconds: int):
    def decide(inputs):
        receive = _receive(inputs)
        if receive == 0:
            return "1" if _key(inputs, "i4") == pay_only else "0"
        if _key(inputs, "i3") != accept_only_from:
            return "0"
        return "0" if receive > hold_seconds + 1 else "1"
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


# An ordinary sender-side clause that never mentions the receive stream.
SPEND_LIMIT = (
    "( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) ? %s : %s )" % (BLOCK, ALLOW)
)


def spend_limit_model(inputs):
    value = str(inputs.get("i1", "0"))
    amount = int(value[2:], 16) if value.startswith("#x") else int(value or 0)
    return "0" if amount > 1000 else "1"
