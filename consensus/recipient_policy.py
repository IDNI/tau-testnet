"""Signed account-local inbound rules and hold limits for incoming transfers."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re

import tau_defs
from consensus import sender_policy
from consensus.rule_offers import (
    MAX_OFFER_RULE_BYTES,
    RuleOfferShapeError,
    clause_body_v1,
    is_neutral_clause_body,
    single_unit_body,
    strip_clause_comments,
    validate_clause_target,
)
from errors import BlockchainBug
from tau_speculation import SpeculationError, WorkerLost, _SESSION_DEFAULT

# The marker deliberately includes o5[t]. Earlier nodes route every such unit
# through clause_body_v1 and reject this non-Tau envelope, including cap-only
# deployments. It also puts this operation in the existing block rule budget.
PREFIX = tau_defs.RECIPIENT_POLICY_PREFIX
_CAPS = ("max_hold_seconds", "max_hold_blocks")
_INBOUND_INPUT_WIDTHS = {1: 24, 3: 384, 4: 384, 5: 64, 12: 384, 17: 64, 27: 64}
_INPUT_NAME = re.compile(r"\bi(\d+)\b")
_INPUT = re.compile(r"\bi(\d+)\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*(\d+)\s*\]")


class PolicyError(ValueError):
    def __init__(self, message, code="RECIPIENT_POLICY_INVALID"):
        super().__init__(message)
        self.code = code


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise PolicyError(f"Duplicate recipient policy field: {key}.")
        obj[key] = value
    return obj


@dataclass(frozen=True)
class Update:
    # None deletes the entry. Missing entries remain unchanged.
    changes: dict
    builds: tuple
    removes_restriction: bool

    def guard_kinds(self):
        kinds = {
            tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY if value is None
            else tau_defs.RULE_CHANGE_KIND_SET_POLICY
            for value in self.changes.values()
        }
        if self.removes_restriction:
            kinds.add(tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY)
        return sorted(kinds)


def _loosens(previous, updated):
    """Removal and replacement cannot bypass an owner's revocation guard."""
    if previous.get("inbound") and previous["inbound"] != updated.get("inbound"):
        return True
    if not any(key in previous for key in _CAPS):
        return False
    if not any(key in updated for key in _CAPS):
        return True
    # A missing dimension when a cap exists permits no parks of that kind.
    return any(updated.get(key, 0) > previous.get(key, 0) for key in _CAPS)


def prepare(rule_text, operations, owner, clause_for, *, active):
    """Validate and plan one atomic registration, identically at admission/apply."""
    if not active:
        raise PolicyError("Recipient controls are inactive on this chain.", "FEATURE_INACTIVE")
    if set(operations) != {"0"}:
        raise PolicyError("A recipient policy deployment must be a rule-only transaction.")
    if len(rule_text) > MAX_OFFER_RULE_BYTES:
        raise PolicyError(f"Recipient policy exceeds {MAX_OFFER_RULE_BYTES} bytes.")
    try:
        if len(rule_text.encode("utf-8")) > MAX_OFFER_RULE_BYTES:
            raise PolicyError(f"Recipient policy exceeds {MAX_OFFER_RULE_BYTES} bytes.")
        obj = json.loads(rule_text[len(PREFIX):], object_pairs_hook=_unique_object)
    except PolicyError:
        raise
    except (ValueError, RecursionError) as exc:
        raise PolicyError("Recipient policy must be a UTF-8 JSON object.") from exc
    if type(obj) is not dict or not obj.keys() <= {"inbound", "outbound", *_CAPS}:
        raise PolicyError("Expected inbound, outbound, max_hold_seconds or max_hold_blocks.")
    record = {}
    for key in _CAPS:
        if key in obj:
            value = obj[key]
            if type(value) is not int or not 0 <= value < 2**64:
                raise PolicyError(f"{key} must be an unsigned 64-bit integer.")
            record[key] = value

    # Reuse the canonical grammar and screening of ordinary o5 clauses.
    from consensus.admission import _screen_clause_domains
    changes = {}
    builds = []
    for direction in ("inbound", "outbound"):
        if direction not in obj:
            continue
        unit = obj[direction]
        try:
            if not isinstance(unit, str):
                raise RuleOfferShapeError("expected one Tau unit as a string")
            unit.encode("utf-8")
            if re.search(r"\b[io]\d{11}|\bbv\s*\[\s*\d{11}", unit):
                raise RuleOfferShapeError("stream index or bit-vector width is too large")
            body = single_unit_body(unit) if direction == "inbound" else clause_body_v1(unit)
            validate_clause_target(body)
            if any(index != "5" for index in re.findall(r"\bo(\d+)\b", body)):
                raise RuleOfferShapeError("only o5 may be written")
        except (UnicodeError, RuleOfferShapeError) as exc:
            raise PolicyError(f"Invalid {direction} clause: {exc}") from exc
        error = _screen_clause_domains(body)
        if error:
            raise PolicyError(f"Invalid {direction} clause: {error}")
        if direction == "inbound":
            source = strip_clause_comments(body)
            for name in _INPUT_NAME.finditer(source):
                typed = _INPUT.match(source, name.start())
                index = int(name[1])
                expected = _INBOUND_INPUT_WIDTHS.get(index)
                if (typed is None or expected is None or int(typed[2]) != expected
                        or name[1] != str(index)):
                    raise PolicyError(f"Unsupported inbound input or width for {name[0]}.")
        if is_neutral_clause_body(body, tau_defs.USER_POLICY_STREAM_INDEX):
            body = None
        if body:
            builds.append((direction, body))
        if direction == "outbound":
            changes[tau_defs.USER_POLICY_STREAM_INDEX] = body
        elif body:
            record["inbound"] = body

    changes[tau_defs.RECIPIENT_POLICY_INDEX] = (
        json.dumps(record, sort_keys=True, separators=(",", ":")) if record else None
    )
    previous = {idx: clause_for(owner, idx) for idx in changes}
    changes = {idx: value for idx, value in changes.items() if previous[idx] != value}
    if not changes:
        raise PolicyError("This recipient policy deployment would make no change.")
    prior_record = json.loads(previous[tau_defs.RECIPIENT_POLICY_INDEX] or "{}")
    return Update(changes, tuple(builds), _loosens(prior_record, record))


@dataclass(frozen=True)
class Refusal:
    code: str
    message: str
    details: dict


def check_recipient(clause_for, recipient, inputs, *, pool, timestamp, height,
                    release_at_time=None, release_at_height=None, timeout=_SESSION_DEFAULT):
    """Return a refusal for one output, or None. Never steps the global engine."""
    raw = clause_for(recipient, tau_defs.RECIPIENT_POLICY_INDEX)
    if raw is None:
        return None
    # Only prepare() writes this committed row. Corruption must stop evaluation.
    record = json.loads(raw)
    hold_seconds = 0 if release_at_time is None else max(0, release_at_time - timestamp)
    hold_blocks = 0 if release_at_height is None else max(0, release_at_height - height)
    if release_at_time is not None or release_at_height is not None:
        dimension = "seconds" if release_at_time is not None else "blocks"
        hold = hold_seconds if release_at_time is not None else hold_blocks
        caps = {key: record[key] for key in _CAPS if key in record}
        limit = caps.get("max_hold_" + dimension)
        if caps and (limit is None or hold > limit or limit == 0):
            limits = ", ".join(f"{key}={value}" for key, value in caps.items())
            return Refusal("RECIPIENT_MAX_HOLD", f"Recipient refuses this hold ({limits}).",
                           {"recipient_pubkey": recipient, **caps, "hold_" + dimension: hold})
    if record.get("inbound"):
        # Take only documented core fields. The hold streams are host-owned in
        # this private evaluator even if the sender used the same custom indices.
        values = {idx: inputs[idx] for idx in (1, 3, 4)}
        values.update({5: str(timestamp), 12: inputs[4], 17: str(hold_seconds), 27: str(hold_blocks)})
        blocked, detail = sender_policy.clause_blocks(
            record["inbound"], values, pool="recipient-" + pool, timeout=timeout
        )
        if blocked:
            return Refusal("RECIPIENT_POLICY_BLOCKED",
                           f"Transfer rejected by recipient policy (o5={detail}).",
                           {"recipient_pubkey": recipient})
    return None


def check_at_apply(clause_for, recipient, inputs, **context):
    """Return the verdict, or abandon this proposal on unusable local state."""
    try:
        return check_recipient(clause_for, recipient, inputs, pool="apply", **context)
    except SpeculationError as exc:
        # An invalid worker reply leaves the transaction retryable.
        raise WorkerLost(f"Recipient policy evaluator failed: {exc}") from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise BlockchainBug(f"Invalid committed recipient policy for {recipient}") from exc
