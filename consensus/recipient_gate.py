"""Recipient-side policy gate (issue #47) and park hold cap (issue #76).

One implementation shared by admission (commands/sendtx.py) and block
apply (consensus/engine.py), so the two paths cannot drift: both build
the recipient's evaluation inputs with :func:`recipient_values`, read
the policy verdict with :func:`policy_blocked`, and read the hold cap
with :func:`hold_cap`.

The recipient evaluation is the ordinary transfer evaluation with the
policy owner changed: the transfer input map already carries the amount
on i1, the counterparty (sender) pubkey on i3, the recipient pubkey on
i4 and the block timestamp on i5. Setting i12 to the recipient makes the
recipient's own o5 clause fire with exactly the widths and typing the
sender side uses, and i2 becomes the recipient's balance at the parent
snapshot -- the same meaning i2 has for the sender. Two overlays are
recipient-only:

- i6 carries the current block height (its canonical consensus-ABI
  meaning; the sender map does not feed it), so a rule can compare
  height against height.
- i17 carries the park's absolute release point packed as one bv[64]
  (see tau_defs.RECIPIENT_RELEASE_PAIR_STREAM_INDEX), or 0 when the
  transfer is not a park.

Neutral default: a recipient with no o5 clause produces no o5 output
and is allowed; a recipient whose rule states no cap produces no o10
output and caps nothing. The default extends to the clause's shape:
a clause written purely for the owner's OUTBOUND transfers -- it
reads the destination stream i4, never the counterparty i3 or the
release pair i17, and states no cap on o10 -- does not mention
incoming transfers, so its verdict is not enforced against one
(:func:`clause_applies_to_inbound`). On the recipient map i4 is the
recipient himself, so such a clause judged inbound would veto
payments for a reason it was never written to give.

Activation: the gate is a governance-activated feature, like the
co-signature approval slots. Until a host-contract patch sets
`recipient_gate_active`, the gate does not run at all -- transfers
are judged exactly as they were before this feature existed, which
is also what keeps replay of pre-activation history byte-identical
-- and a clause that would deploy the feature (it targets o10, or
its body reads i17) is refused at deploy with
:data:`REASON_GATE_INACTIVE` rather than silently admitted and
never enforced. Activation is one-way: once recipient clauses are
deployed under the gate, turning it off would un-govern transfers
their authors published policies for, without any transaction of
their own.
"""

import re
from typing import Dict, Optional

import tau_defs
from consensus.rule_offers import strip_clause_comments

REASON_POLICY_BLOCK = "recipient_policy_block"
REASON_HOLD_CAP = "RECIPIENT_MAX_HOLD"
REASON_GATE_INACTIVE = "recipient_gate_inactive"

_RELEASE_PAIR_STREAM = tau_defs.RECIPIENT_RELEASE_PAIR_STREAM_INDEX
_HOLD_CAP_STREAM = tau_defs.RECIPIENT_HOLD_CAP_STREAM_INDEX
_HEIGHT_STREAM = 6
_COUNTERPARTY_STREAM = 3
_DESTINATION_STREAM = 4

_INPUT_REF = re.compile(r"\bi(\d+)\s*\[")
_OUTPUT_REF = re.compile(r"\bo(\d+)\s*\[")


def clause_applies_to_inbound(body) -> bool:
    """Whether an accepted clause's verdict may refuse an INBOUND transfer.

    The screen is textual, over the clause body the recipient
    published: the verdict applies when the clause speaks about
    incoming transfers -- it reads the counterparty (i3) or the
    release pair (i17), or it states a hold cap (o10). It also
    applies when the clause is direction-neutral: one that never
    reads the destination stream i4 (a constant verdict, an
    amount/balance rule) governs its owner as a party to a transfer
    in either direction, exactly as it does when the owner sends.

    Only the purely outbound shape is screened out: reads i4, never
    reads i3/i17, writes no o10. Such a clause is the owner's send
    whitelist; the neutral default leaves inbound transfers alone.

    The scan runs on the COMMENT-STRIPPED body (the same helper the
    codebase's own clause audits use): a stream reference that only
    appears inside a '#' comment is not a reference the clause
    makes, and must not flip the screen either way -- the same
    flaw class as the raw-substring prescreen #133's PoCs caught
    elsewhere (a key in a comment stepping the wrong recipient).
    """
    if not body:
        return True
    scrubbed = strip_clause_comments(str(body))
    reads = {int(n) for n in _INPUT_REF.findall(scrubbed)}
    writes = {int(n) for n in _OUTPUT_REF.findall(scrubbed)}
    outbound_only = (
        _DESTINATION_STREAM in reads
        and _COUNTERPARTY_STREAM not in reads
        and _RELEASE_PAIR_STREAM not in reads
        and _HOLD_CAP_STREAM not in writes
    )
    return not outbound_only


def gate_active(tip_view) -> bool:
    """Whether the recipient gate is activated at the given tip.

    Mirrors consensus.approvals.approval_slots_active: requires a
    genuine `True`, not merely a truthy value. A partial or mocked
    view returns something truthy for any attribute it was never
    given -- and silently running as if a consensus feature were
    activated is the kind of thing that passes every test and then
    diverges on a live chain. Absent or non-bool therefore reads as
    "not activated", which is also the pre-activation behaviour of
    every existing chain. The flag itself lives on the lifecycle
    manager (consensus state, one-way governance activation), so
    block apply reads it from the parent snapshot and an activation
    recorded in block H governs H+1 onward.
    """
    return getattr(tip_view, "recipient_gate_active", False) is True


def clause_uses_recipient_feature(body, target_stream=None) -> bool:
    """Whether registering this clause would deploy the recipient feature.

    True when the clause IS a hold-cap clause (its target stream is
    o10, whose only meaning is the recipient cap) or when its body
    reads the release pair i17 -- the stream the node feeds ONLY
    into the recipient-side evaluation of a park. Neither signal has
    any other meaning anywhere in the system, so a clause carrying
    one is a recipient-policy clause whatever else it also does.
    While the gate is inactive such a clause is refused at deploy
    (see REASON_GATE_INACTIVE): admitting it would leave its author
    believing inbound transfers are governed when no evaluation will
    ever read it.

    The scan runs on the COMMENT-STRIPPED body, as every other
    textual screen in this module does: a stream mentioned only in a
    '#' comment is not a reference the clause makes, and must not
    make an ordinary sender clause undeployable.
    """
    if target_stream is not None and int(target_stream) == _HOLD_CAP_STREAM:
        return True
    if not body:
        return False
    scrubbed = strip_clause_comments(str(body))
    reads = {int(n) for n in _INPUT_REF.findall(scrubbed)}
    writes = {int(n) for n in _OUTPUT_REF.findall(scrubbed)}
    return _RELEASE_PAIR_STREAM in reads or _HOLD_CAP_STREAM in writes


def pack_release_pair(release_ts: int = 0, release_height: int = 0) -> int:
    """The park's absolute release point as one bv[64] integer.

    High 32 bits are the release timestamp, low 32 bits the release
    height; the unit the park does not use is packed as 0.
    """
    return (int(release_ts) << 32) | int(release_height)


def recipient_values(base_values: Dict, recipient_pubkey: str,
                     recipient_balance, block_height: int,
                     release_pair: int = 0) -> Dict:
    """The recipient evaluation's input map for one transfer.

    `base_values` is the transfer input map the sender was judged on
    (engine `_transfer_input_map` at apply, its twin in sendtx at
    admission). Only the policy owner, the balance stream, the height
    overlay and the release pair change.
    """
    values = dict(base_values)
    values[2] = str(recipient_balance)
    values[12] = "{ #x" + str(recipient_pubkey) + " }:bv[384]"
    values[_HEIGHT_STREAM] = str(int(block_height))
    values[_RELEASE_PAIR_STREAM] = str(int(release_pair))
    return values


def policy_blocked(outputs: Dict, parse_tau_output) -> bool:
    """True when the recipient's o5 verdict blocks the transfer.

    Mirrors the sender side exactly: no o5 output means allow; an
    output that parses to the block value refuses. parse_tau_output
    maps an unparseable output to the block value, so a malformed
    recipient policy fails closed, as a malformed sender policy does.
    """
    raw = outputs.get(tau_defs.USER_POLICY_STREAM_INDEX)
    if raw is None:
        return False
    return parse_tau_output(raw) == tau_defs.USER_POLICY_BLOCK_VALUE


def hold_cap(outputs: Dict, parse_tau_output) -> Optional[int]:
    """The recipient's park hold cap from o10, or None when uncapped.

    The cap is read in the park's own unit (blocks for a height park,
    seconds for a time park). An unparseable output parses to 0 -- a
    cap of zero, instant parks only -- so a malformed cap fails closed
    for parks. Plain transfers never consult this.
    """
    raw = outputs.get(_HOLD_CAP_STREAM)
    if raw is None:
        return None
    return parse_tau_output(raw)
