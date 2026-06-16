"""
Fee parsing and normalization helpers (governance-votable Tau fee model).

Model (consensus-critical — every node must agree):
  * The network base fee is emitted by the ACTIVE CONSENSUS RULES on Tau
    output stream o9 (see tau_defs.CONSENSUS_FEE_STREAM_INDEX). Validators
    change the fee through the existing governance flow: propose a
    consensus_rule_update whose rule_revisions carry the full new consensus
    spec, vote, activate at height. No fee constant lives in Python.
  * User-deployed application rules may emit an EXTRA fee on output stream
    o8 (tau_defs.CUSTOM_FEE_STREAM_INDEX).
  * total_fee = sum over the transaction's Tau evaluation steps of
    (o9 + o8). A tx with transfers evaluates one step per transfer. A
    transfer-less user_tx (rule-only / custom-inputs-only) is charged via
    one dedicated fee-query step using the canonical mocked transfer inputs
    (i1 = i2 = i3 = i4 = "0", i5 = block timestamp, i12 = sender pubkey).
  * fee_limit (signed tx field) is a CAP: if total_fee > fee_limit the tx
    is hard-rejected (never included, pays nothing). The sender pays
    total_fee, not fee_limit.
  * The fee is credited to block.header.proposer_pubkey.
  * ALL transactions (governance included) must carry a syntactically valid
    fee_limit; only user_tx is charged. Governance txs are exempt so that
    validators never need funds to govern.
  * Fees are charged only for txs accepted into the block. A fee rejection
    produces no transfer writes, no fee writes, and no sequence increment.
  * Activation = o9 presence: if the active rules emit nothing on o9 the
    fee model is inactive (fee 0, byte-identical legacy behavior). Old
    blocks replay under the rules active at their height, so historical
    replay stays correct by construction.

Parse policy:
  * o9 (consensus fee) is STRICT: absent -> 0 (fee model inactive), but a
    present-yet-unparseable/negative/oversized value raises FeeRuleError —
    a voted rule that passed staged compile and emits garbage is real
    breakage; silently charging 0 would be a silent fee holiday.
  * o8 (user custom fee) is LENIENT: absent -> 0 silently; garbage,
    negative, or oversized values normalize to 0 with a loud warning —
    users must not be able to break consensus, but broken fee rules stay
    visible in logs.
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Upper bound for fee values (SQLite INTEGER is signed 64-bit; also a
# sanity cap for arithmetic on attacker-supplied values).
MAX_FEE_VALUE: int = 2**63 - 1


class FeeRuleError(Exception):
    """The active consensus rules emitted an invalid fee on o9.

    Strict by design: propagates as a consensus failure (proposer aborts
    the round, validator defers the block, admission rejects the tx)
    rather than silently charging 0.
    """


def parse_fee_limit(raw) -> Optional[int]:
    """
    Parse a tx fee_limit field. Signed payloads carry it as a decimal
    string or an int; both are accepted. Returns the integer value, or
    None if malformed, boolean, negative, fractional, or > MAX_FEE_VALUE.
    Never raises. The caller must never rewrite the payload field itself —
    the BLS signature covers the original representation.
    """
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        value = raw
    elif isinstance(raw, str):
        s = raw.strip()
        if not s:
            return None
        body = s[1:] if s[0] in "+-" else s
        if not body.isdigit():
            return None
        try:
            value = int(s)
        except ValueError:
            return None
    else:
        return None
    if value < 0 or value > MAX_FEE_VALUE:
        return None
    return value


def _parse_tau_int(raw_output) -> Optional[int]:
    """
    Decode a Tau output value to an int, or None if undecodable.

    Mirrors tau_manager.parse_tau_output's accepted literal forms
    ("result:" prefix, "{ #x0a }:bv[16]" wrappers, "#b"/"#x" radixes,
    plain decimals) but — unlike it — does NOT swallow garbage to 0:
    the strict o9 policy needs to distinguish a real 0 from breakage.
    """
    try:
        val = str(raw_output).strip()
    except Exception:
        return None
    if not val:
        return None
    if val.startswith("result:"):
        val = val[7:].strip()
    if val.startswith("{") and "}" in val:
        val = val[val.find("{") + 1: val.find("}")].strip().rstrip(",")
    try:
        if val.startswith("#b"):
            return int(val[2:], 2)
        if val.startswith("#x"):
            return int(val[2:], 16)
        return int(val)
    except Exception:
        return None


def parse_consensus_fee(raw_o9, context: str = "") -> int:
    """
    STRICT decode of the consensus fee stream (o9).
    Absent stream (None) -> 0: fee model inactive for this step.
    Present but unparseable/negative/oversized -> FeeRuleError.
    """
    if raw_o9 is None:
        return 0
    value = _parse_tau_int(raw_o9)
    if value is None or value < 0 or value > MAX_FEE_VALUE:
        raise FeeRuleError(
            f"Consensus fee rule emitted invalid o9 value {raw_o9!r}"
            f"{f' ({context})' if context else ''}"
        )
    return value


def parse_custom_fee(raw_o8, context: str = "") -> int:
    """
    LENIENT decode of the user custom fee stream (o8).
    Absent stream (None) -> 0 silently. Garbage, negative, or oversized
    values normalize to 0 with a loud warning so broken or malicious user
    fee rules are visible without affecting consensus output.
    """
    if raw_o8 is None:
        return 0
    value = _parse_tau_int(raw_o8)
    if value is None or value < 0 or value > MAX_FEE_VALUE:
        logger.warning(
            "Ignoring invalid custom fee output o8=%r%s; charging 0 for this step.",
            raw_o8, f" ({context})" if context else "",
        )
        return 0
    return value
