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
output and caps nothing.
"""

from typing import Dict, Optional

import tau_defs

REASON_POLICY_BLOCK = "recipient_policy_block"
REASON_HOLD_CAP = "RECIPIENT_MAX_HOLD"

_RELEASE_PAIR_STREAM = tau_defs.RECIPIENT_RELEASE_PAIR_STREAM_INDEX
_HOLD_CAP_STREAM = tau_defs.RECIPIENT_HOLD_CAP_STREAM_INDEX
_HEIGHT_STREAM = 6


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
