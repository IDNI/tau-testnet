"""Compose a recipient-policy clause (#47, #76) from plain options.

Writing the clause by hand means getting bv widths, the i17 ranges and the
sending/receiving split exactly right; one wrong width is refused at deploy and
one wrong range silently accepts what the owner meant to refuse. This builds the
same shape the docs show, from:

    allow            accept incoming money only from these senders (#47)
    max_hold_seconds accept a time-based retractable transfer held at most N s
    max_hold_blocks  accept a height-based retractable transfer held at most N blocks
    send_only_to     send only to these recipients (an outbound whitelist in the
                     same clause, #47 case 4)

Semantics of the caps (docs/recipient_policy.md): with only a seconds cap, a
height-based park is refused (a block count has no length in seconds); with
only a blocks cap, time-based parks are not limited; with both, each kind is
held to its own cap. A cap of 0 accepts only plain transfers of that kind.
"""
from __future__ import annotations

from typing import Iterable, Optional

import tau_defs

_BLOCK = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
_ALLOW = "(o5[t]:bv[24] = { #x000001 }:bv[24])"


def _u64(value: int) -> str:
    return "{ #x%016x }:bv[64]" % value


def _key(pubkey: str) -> str:
    pk = str(pubkey).strip().lower()
    if pk.startswith("0x"):
        pk = pk[2:]
    if len(pk) != 96 or any(c not in "0123456789abcdef" for c in pk):
        raise ValueError(f"not a 96-hex-digit public key: {pubkey!r}")
    return "{ #x" + pk + " }:bv[384]"


def _any_of(stream: str, keys: Iterable[str]) -> str:
    return "(" + " || ".join(f"({stream}[t]:bv[384] = {_key(k)})" for k in keys) + ")"


def compose_receive_clause(
    allow: Iterable[str] = (),
    max_hold_seconds: Optional[int] = None,
    max_hold_blocks: Optional[int] = None,
    send_only_to: Iterable[str] = (),
) -> str:
    """The `always ( ... ).` rule text for these options. Raises ValueError when
    nothing is asked for or a value is out of range."""
    allow, send_only_to = list(allow or ()), list(send_only_to or ())
    if not (allow or send_only_to or max_hold_seconds is not None or max_hold_blocks is not None):
        raise ValueError("give at least one of --allow, --max-hold-seconds, "
                         "--max-hold-blocks, --send-only-to")
    base = tau_defs.RECIPIENT_HOLD_BLOCKS_BASE
    for name, cap, limit in (("max_hold_seconds", max_hold_seconds, base - 2),
                             ("max_hold_blocks", max_hold_blocks, (1 << 63) - 1)):
        if cap is not None and not 0 <= int(cap) <= limit:
            raise ValueError(f"{name} must be between 0 and {limit}")

    i17 = "i17[t]:bv[64]"
    receiving = f"({i17} > {_u64(tau_defs.RECIPIENT_HOLD_SENDING)})"
    sending = f"({i17} = {_u64(tau_defs.RECIPIENT_HOLD_SENDING)})"

    refuse_in = []
    if allow:
        refuse_in.append("!" + _any_of("i3", allow))
    seconds_limit = None if max_hold_seconds is None else \
        tau_defs.RECIPIENT_HOLD_INSTANT + int(max_hold_seconds)
    blocks_limit = None if max_hold_blocks is None else base + int(max_hold_blocks)
    if seconds_limit is not None and blocks_limit is None:
        # Over the seconds cap, or any height-based park (above the seconds range).
        refuse_in.append(f"({i17} > {_u64(seconds_limit)})")
    elif seconds_limit is None and blocks_limit is not None:
        refuse_in.append(f"({i17} > {_u64(blocks_limit)})")
    elif seconds_limit is not None and blocks_limit is not None:
        refuse_in.append(f"(({i17} > {_u64(seconds_limit)}) && ({i17} < {_u64(base)}))")
        refuse_in.append(f"({i17} > {_u64(blocks_limit)})")

    parts = []
    if refuse_in:
        parts.append(f"({receiving} && ({' || '.join(refuse_in)}))")
    if send_only_to:
        parts.append(f"({sending} && !{_any_of('i4', send_only_to)})")
    return f"always ( ({' || '.join(parts)}) ? {_BLOCK} : {_ALLOW} )."
