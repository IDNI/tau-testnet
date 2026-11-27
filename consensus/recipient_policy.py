"""Recipient-side o5 policy gate (issues #47/#76 — Bounty 03, Recipient controls).

Until now the node evaluated exactly one account's policy per transfer: the
sender's. This module adds the second evaluation the issues ask for — the
recipient's own o5 policy, checked at admission and at block apply — so an
account can refuse incoming transfers (an inbound allow-list, "refuse
incoming above N"), and cap how long a payment to it may be held (#76).

Two modes, mirroring the sender side:

- Clause mode (this module's `recipient_clause_blocks`): the recipient's
  registered clause is stepped on the same per-transfer inputs as the
  sender pass. Direction is NOT visible to a clause body — both passes
  feed the same map, and a body may not reference i12
  (rule_offers.SENDER_STREAM bans it at registration) — so direction is
  separated by enforcement path instead: a clause that opts into
  recipient enforcement is enforced ONLY on the receive path, and the
  send path skips it (see `send_path_clause_blocks`). Without that
  separation the documented allow-list would refuse the owner's own
  sends: on the send path i3 names the owner, never an approved sender.
- Guarded mode (`guarded_recipient_blocks`): the accumulated spec is
  stepped a second time with `i12` set to the RECIPIENT's key, so the
  recipient's guarded unit — `always ((i12[t] = <me>) ? <body> : o5 =
  allow)` — is the one that can say no, exactly as the sender's unit does
  in the first pass. The counterparty is read on `i3`, which carries the
  sender's key in both passes. Callers supply the step function, so
  admission (tau_admission session) and apply (engine session) share this
  one implementation. The pass steps only when the spec carries a unit
  scoped on the recipient — a unit whose guard compares `i12` against the
  recipient's key as a full-width literal (see `spec_units` /
  `_unit_for_owner`) — so absence proves there is no unit to enforce, and
  a key that appears only in a comment, or only inside another unit's
  body, never makes the pass step. An extra step on the shared session is
  observable by history-reading rules and by the existing step accounting,
  so it is never spent speculatively.

Input contract (the documented choices the issues leave to the node): the
recipient pass feeds the SAME per-transfer input map as the sender pass
(i1 amount, i2 sender balance, i3 sender key, i4 recipient key, i5
timestamp, i12 sender key, approval slots, custom streams), plus the two
hold streams below. The counterparty is read on i3, which carries the
sender's full public key: in the sender pass i3 names the clause's owner,
in the recipient pass it names the sender. A body cannot tell the two
passes apart — every stream it may read carries the same value in both,
and the one stream whose value it could have compared (i12) is banned in
clause bodies at registration — which is exactly why enforcement, not
the body, owns the direction split (see the opt-in screen, below). An
inbound rule is therefore a plain comparison on i3, e.g. "allow only if
i3 is A or B", exactly as issue #47 requests.

Hold streams (#76): i17 carries the park's hold length in SECONDS
(release_at_time minus the block time) and i27 the hold in BLOCKS
(release_at_height minus the block height), both bv[64], host-computed by
`hold_values` — admission measures against the tip view's next-block
height/timestamp (the same clock that refuses a park which could be mined
at or after its own release), apply against the block being applied. A
plain transfer feeds 0 on both, so a cap of 0 admits plain transfers and
refuses every park; a park of one kind feeds 0 on the other kind's stream,
so a cap rule must bound both streams to bound both kinds. Both values are
FORCED into the recipient pass by this module: a sender-supplied
operations value on i17/i27 never reaches the recipient's clause. Only
parks are capped — a retract never passes this gate, and a release is
evaluated with hold 0 (the money arrives at release; nothing about the
cap is re-checked then).

Refusals: a recipient block rejects with a distinct reason so a wallet can
say which side said no. A plain policy block is `recipient_policy_block`
("rejected by recipient policy (o5)" at admission). A block of a PARK by a
clause that reads a hold stream is `recipient_max_hold`, and the refusal
carries the recipient's cap whenever the clause declares it in the
canonical form — a direct comparison of a hold stream against a literal
(`i17[t]:bv[64] <= { #x258 }:bv[64]`, or `<`, or the reversed forms); the
cap is extracted textually by `extract_hold_caps`, the same class of
textual screen the codebase already uses for stream domains. The
`:bv[...]` annotations are optional in the extraction patterns, as they
are in the language — Tau infers a literal's type from the stream it is
compared against — so a cap written `{ 600 }` reports its number too. A
cap clause in a non-canonical shape still enforces (the verdict decides);
its refusal then reports the measured hold without a numeric cap.

Opt-in screen (backwards compatibility): the recipient pass enforces only
clauses whose body reads the counterparty stream i3 or a hold stream
(i17/i27). A clause that reads neither — a pure outbound whitelist on i4,
say — is an outbound-only clause; enforcing it on inbound transfers would
silently change what a pre-existing policy means, so it is skipped here.
Every inbound rule must read the sender or the hold to work at all, so the
screen loses no expressiveness. (Comments are stripped first, as
rule_offers does for its own screens.)

The screen is symmetric, and the other half is load-bearing: the send
path does not enforce a recipient-relevant clause against the owner's
own sends (`send_path_clause_blocks`). Read on the send path, i3 can
only name the owner, so an allow-list's inbound comparison would refuse
every send the owner makes — the owner's clause would brick the owner's
wallet. A clause therefore speaks to exactly one direction, the one its
streams can actually observe: reading i3 or a hold stream makes it a
receive policy, enforced inbound only; reading neither keeps it a send
policy, enforced outbound only.

Neutral default: a recipient with no clause, or one that does not opt in,
allows everything — the same default as the sender side.

Fee model: unchanged. Admission refusal costs nothing. At apply the
sender pays the transaction fee exactly as for a sender-policy block: a
recipient block rejects the whole user_tx / park, so a batch with one
refused output fails as one transaction and no partial apply is possible.

Determinism: admission (commands/sendtx.py) and apply (consensus/
engine.py) call these functions with the same inputs, mirroring
sender_policy, so the two paths cannot drift apart. Replay runs the same
apply path, so a replayed block reaches the same verdicts. At apply the
guarded pass prescreens on the parent snapshot's rules
(`resolve_spec_text`), never on the process-global current spec, so a
block re-applied after the tip moved on is screened against the same
text that judged it the first time.

Capability: `supported()` reads tau_defs.HOST_CAPABILITIES, which
getgovernance reports to wallets. On a node built without this gate the
flags are False and the clause admission screen refuses a hold-cap clause
at deploy time with a clear reason, instead of admitting a rule that
would never run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import tau_defs
import tau_manager
from consensus import sender_policy
from consensus.retractable import KIND_HEIGHT, KIND_TIME
from consensus.rule_offers import strip_clause_comments
from tau_speculation import _SESSION_DEFAULT

#: tx_receipt["reason"] when the recipient's policy blocks a transfer.
REASON = "recipient_policy_block"

#: tx_receipt["reason"] when the recipient's hold cap blocks a park (#76).
#: The refusal text and the receipt detail carry the cap, so the payer's
#: wallet can print "accepts payments held for up to N".
REASON_MAX_HOLD = "recipient_max_hold"

#: A clause opts into recipient-side enforcement by reading the
#: counterparty stream i3 (the sender's full public key) ...
_COUNTERPARTY_STREAM = re.compile(r"\bi3\s*\[")
#: ... or a hold stream (i17 seconds / i27 blocks), which only the
#: recipient pass ever feeds meaningfully.
_HOLD_STREAM = re.compile(r"\bi(?:17|27)\s*\[")


@dataclass(frozen=True)
class RecipientRefusal:
    """Why the recipient's policy said no, with the #76 cap when known."""

    reason: str
    max_hold_seconds: Optional[int] = None
    max_hold_blocks: Optional[int] = None
    hold_seconds: int = 0
    hold_blocks: int = 0


def supported(capability: str = "recipient_policy") -> bool:
    """Whether this node enforces the recipient gate (see module docstring)."""
    return bool(tau_defs.HOST_CAPABILITIES.get(capability, False))


def clause_is_counterparty_aware(body) -> bool:
    """True when `body` reads the counterparty (i3) and so opts into
    recipient-side enforcement. False for outbound-only clauses."""
    if not isinstance(body, str) or not body:
        return False
    return bool(_COUNTERPARTY_STREAM.search(strip_clause_comments(body)))


def clause_reads_hold_stream(body) -> bool:
    """True when `body` reads i17 or i27 — the mark of a hold-cap clause."""
    if not isinstance(body, str) or not body:
        return False
    return bool(_HOLD_STREAM.search(strip_clause_comments(body)))


def clause_is_recipient_relevant(body) -> bool:
    """The opt-in screen: a clause is enforced on inbound transfers only
    when it reads the counterparty (i3) or a hold stream (i17/i27)."""
    if not isinstance(body, str) or not body:
        return False
    scrubbed = strip_clause_comments(body)
    return bool(
        _COUNTERPARTY_STREAM.search(scrubbed) or _HOLD_STREAM.search(scrubbed)
    )


def hold_values(kind, release_at, height, timestamp) -> dict:
    """The {17: seconds, 27: blocks} hold map for one park.

    `kind` is consensus.retractable's KIND_TIME / KIND_HEIGHT; the unused
    kind's stream is 0, and a non-park (kind None) is 0 on both — a plain
    transfer's hold length. Saturates at 0: admission and apply measure
    against their own block clock, and a release point already reached
    measures as no hold at all rather than a negative length.
    """
    seconds = blocks = 0
    if kind == KIND_TIME:
        seconds = max(0, int(release_at) - int(timestamp))
    elif kind == KIND_HEIGHT:
        blocks = max(0, int(release_at) - int(height))
    return {
        tau_defs.HOLD_SECONDS_STREAM_INDEX: seconds,
        tau_defs.HOLD_BLOCKS_STREAM_INDEX: blocks,
    }


_LITERAL = (r"\{\s*(?:#x(?P<hex>[0-9a-fA-F]+)|(?P<dec>\d+))\s*\}"
            r"(?:\s*:\s*bv\s*\[\s*\d+\s*\])?")
_STREAM_REF = r"i(?P<stream>17|27)\s*\[\s*t\s*\]\s*(?::\s*bv\s*\[\s*\d+\s*\])?"
_CAP_DIRECT = re.compile(_STREAM_REF + r"\s*(?P<op><=|<)\s*" + _LITERAL)
_CAP_REVERSED = re.compile(_LITERAL + r"\s*(?P<op>>=|>)\s*" + _STREAM_REF)


def _cap_value(match, strict_ops) -> int:
    raw = match.group("hex")
    value = int(raw, 16) if raw is not None else int(match.group("dec"))
    return value - 1 if match.group("op") in strict_ops else value


def extract_hold_caps(body) -> tuple[Optional[int], Optional[int]]:
    """(max_hold_seconds, max_hold_blocks) declared by a clause, or Nones.

    Reads the canonical cap comparisons (see module docstring) out of the
    comment-stripped body; when a stream is capped more than once, the
    smallest — most restrictive — cap is the one the rule enforces, so it
    is the one a refusal reports. Purely textual and deterministic: every
    node extracts the same caps from the same clause.
    """
    if not isinstance(body, str) or not body:
        return None, None
    scrubbed = strip_clause_comments(body)
    caps: dict[int, int] = {}
    for pattern, strict in ((_CAP_DIRECT, {"<"}), (_CAP_REVERSED, {">"})):
        for match in pattern.finditer(scrubbed):
            stream = int(match.group("stream"))
            cap = _cap_value(match, strict)
            if stream not in caps or cap < caps[stream]:
                caps[stream] = cap
    return (
        caps.get(tau_defs.HOLD_SECONDS_STREAM_INDEX),
        caps.get(tau_defs.HOLD_BLOCKS_STREAM_INDEX),
    )


def refusal_message(refusal: RecipientRefusal) -> str:
    """The wallet-printable refusal text, shared by admission and apply."""
    if refusal.reason != REASON_MAX_HOLD:
        return "rejected by recipient policy (o5)"
    parts = []
    if refusal.max_hold_seconds is not None:
        parts.append(f"up to {refusal.max_hold_seconds} seconds")
    if refusal.max_hold_blocks is not None:
        parts.append(f"up to {refusal.max_hold_blocks} blocks")
    cap = " or ".join(parts) if parts else "a hold cap declared in its rule"
    return (
        f"RECIPIENT_MAX_HOLD: the recipient accepts payments held for "
        f"{cap}; this payment would be held for {refusal.hold_seconds} "
        f"seconds / {refusal.hold_blocks} blocks"
    )


def send_path_clause_blocks(clause_for, sender_pubkey, values, *, pool: str,
                            timeout=_SESSION_DEFAULT) -> tuple[bool, str]:
    """(blocked, detail) for the sender's own o5 clause on the SEND path.

    The one funnel every send-path judgment of a registered clause goes
    through (admission in commands/sendtx.py, apply in
    consensus/engine.py; the approval preview mirrors the same screen in
    commands/getapprovalpreview.py). A recipient-relevant clause — one
    that reads the counterparty (i3) or a hold stream (i17/i27) — is a
    RECEIVE policy: it is not evaluated here at all, so the documented
    allow-list can never refuse the owner's own sends. On this path i3
    names the owner, never a counterparty, and a clause body may not
    reference the one stream (i12) it could have used to tell direction,
    so enforcement — not the body — owns the direction split. Any other
    clause is judged by sender_policy exactly as before.
    """
    body = clause_for(sender_pubkey, tau_defs.USER_POLICY_STREAM_INDEX)
    if not body or clause_is_recipient_relevant(body):
        return False, ""
    return sender_policy.clause_blocks(body, values, pool=pool, timeout=timeout)


def recipient_clause_blocks(clause_for, sender_pubkey, recipient_pubkey,
                            values, *, pool: str,
                            timeout=_SESSION_DEFAULT,
                            hold: Optional[dict] = None
                            ) -> tuple[bool, str, Optional[RecipientRefusal]]:
    """(blocked, detail, refusal) for the recipient's own o5 clause.

    `clause_for` is the tip view's (or the rule-offer manager's) clause
    lookup, `values` the per-transfer input map the sender pass uses, and
    `hold` the {17: seconds, 27: blocks} map from `hold_values` for a
    park (None — a plain transfer — forces both hold streams to 0).
    (False, "", None) — allow — when there is nothing to enforce: no
    recipient, a self-transfer (the sender pass already judged it), no
    clause, or a clause that never opts in.
    """
    if not recipient_pubkey or recipient_pubkey == sender_pubkey:
        return False, "", None
    body = clause_for(recipient_pubkey, tau_defs.USER_POLICY_STREAM_INDEX)
    if not body or not clause_is_recipient_relevant(body):
        return False, "", None
    hold = hold or {}
    hold_seconds = int(hold.get(tau_defs.HOLD_SECONDS_STREAM_INDEX, 0))
    hold_blocks = int(hold.get(tau_defs.HOLD_BLOCKS_STREAM_INDEX, 0))
    eval_values = dict(values or {})
    # Force the hold streams only when they can matter — a park, or a
    # clause that reads them (which must then see an explicit 0 on a
    # plain transfer). Otherwise the evaluator gets exactly the sender
    # pass's inputs, unchanged.
    if hold_seconds or hold_blocks or clause_reads_hold_stream(body):
        eval_values[tau_defs.HOLD_SECONDS_STREAM_INDEX] = str(hold_seconds)
        eval_values[tau_defs.HOLD_BLOCKS_STREAM_INDEX] = str(hold_blocks)
    blocked, detail = sender_policy.clause_blocks(
        body, eval_values, pool=pool, timeout=timeout)
    if not blocked:
        return False, "", None
    refusal = RecipientRefusal(
        reason=REASON, hold_seconds=hold_seconds, hold_blocks=hold_blocks)
    if (hold_seconds > 0 or hold_blocks > 0) and clause_reads_hold_stream(body):
        cap_seconds, cap_blocks = extract_hold_caps(body)
        refusal = RecipientRefusal(
            reason=REASON_MAX_HOLD,
            max_hold_seconds=cap_seconds,
            max_hold_blocks=cap_blocks,
            hold_seconds=hold_seconds,
            hold_blocks=hold_blocks,
        )
    return True, detail, refusal


_SPEC_KEY_LITERAL = (r"\{\s*#x(?P<key>[0-9a-fA-F]+)\s*\}"
                     r"(?:\s*:\s*bv\s*\[\s*384\s*\])?")
_UNIT_SCOPE = re.compile(
    r"\bi12\s*\[\s*t\s*\]\s*(?::\s*bv\s*\[\s*\d+\s*\])?\s*=\s*"
    + _SPEC_KEY_LITERAL)


def _normalise_key(literal: str) -> str:
    """A spec key literal normalised to the bare, lower-case, 96-hex-digit
    public key the rest of the node compares against.

    Spec text may carry a key zero-stripped or in upper case; a direct
    string compare against the canonical key would then miss the
    recipient's own unit.
    """
    return (literal or "").strip().lower().rjust(96, "0")[-96:]


def spec_units(spec_text) -> list:
    """The guarded units of a spec text, each split into (guard, body) on
    the '?' that separates them, with comments scrubbed first.

    Only chunks carrying an i12 scope comparison are kept — the canonical
    guarded shape `always ( (i12[t] = { #xKEY }) ? body : body ).` is the
    same shape the sender pass evaluates. A unit whose split fails (no
    '?') is kept as its whole scrubbed text, so an unexpected shape still
    gets evaluated rather than silently skipped.
    """
    if not spec_text or not isinstance(spec_text, str):
        return []
    scrubbed = strip_clause_comments(spec_text)
    units = []
    for chunk in scrubbed.split("always"):
        chunk = chunk.strip()
        if _UNIT_SCOPE.search(chunk):
            guard, sep, body = chunk.partition("?")
            units.append((guard, body) if sep else (chunk, ""))
    return units


def _unit_for_owner(unit_guard: str, recipient_pubkey: str):
    """The guard literal if `unit_guard` scopes on `recipient_pubkey`,
    else None.

    A guard scopes an owner by comparing i12 against that owner's key as
    a full-width literal. Matching the literal in the guard — not a
    substring of the spec — is what makes the pass judge only units that
    can actually be the recipient's: a key that appears in a comment, or
    inside a *body* (an inbound allow-list naming the key it allows), is
    not a scope and must not make an unrelated unit speak for the
    recipient.
    """
    if not unit_guard or not recipient_pubkey:
        return None
    for match in _UNIT_SCOPE.finditer(unit_guard):
        if _normalise_key(match.group("key")) == _normalise_key(
                str(recipient_pubkey)):
            return match.group("key")
    return None


def _recipient_unit(spec_text, recipient_pubkey):
    """The body of the recipient's own guarded unit, or None."""
    for guard, body in spec_units(spec_text):
        if _unit_for_owner(guard, recipient_pubkey) is not None:
            return body
    return None


def resolve_spec_text(snapshot=None, parent_snapshot=None) -> str:
    """The spec text to prescreen with, pinned to the state under apply.

    `apply` must judge a block against the rules its parent carried, not
    against whatever the process loaded last: the same block re-applied
    after the tip moved on must reach the same verdict (issue #47's
    determinism requirement, and replay). A snapshot carries the
    canonical rules as `tau_bytes`; the caller's live value
    (tau_manager.last_known_tau_spec — a debug/error-state aid in
    tau_manager's own words) is read only when no snapshot is at hand
    (tests, admission's tip view).
    """
    for source in (snapshot, parent_snapshot):
        raw = getattr(source, "tau_bytes", None) if source is not None else None
        if isinstance(raw, (bytes, bytearray)):
            text = raw.decode("utf-8", errors="ignore")
        elif isinstance(raw, str):
            text = raw
        else:
            continue
        if text:
            return text
    return tau_manager.last_known_tau_spec or ""


def guarded_recipient_blocks(evaluate, values, sender_pubkey,
                             recipient_pubkey, *, spec_text=None
                             ) -> tuple[bool, Optional[str]]:
    """(blocked, o5_raw) for the guarded-mode recipient pass.

    `evaluate` steps the accumulated spec on an input map and returns the
    output map (admission's session step at admission, the engine
    session's evaluate at apply). The recipient pass is the sender pass
    with `i12` — the policy-owner stream every guarded unit scopes on —
    set to the recipient's key; every other input, the counterparty on i3
    included, is the transfer's own. A missing o5 is the neutral default
    (allow), exactly as in the sender pass.

    Pre-screen: the pass steps only when `spec_text` carries a *unit
    scoped on the recipient* (see `_unit_for_owner`), because a step on
    the shared session is not free — history-reading rules (the cooldown
    stream, say) observe every step, and existing fee/policy accounting
    counts the main step's roundtrips. A key that is only in a comment,
    or only inside another unit's body, therefore does not make the pass
    run: the recipient is judged by her own unit or by nothing, never by
    a rule that only talks about her somewhere. An unknown or empty spec
    text also skips: no spec, no units.

    `spec_text` must be the spec of the state being judged (the block's
    parent rules at apply — see `resolve_spec_text`; the tip view at
    admission), not a live global.
    """
    if not recipient_pubkey or recipient_pubkey == sender_pubkey:
        return False, None
    if _recipient_unit(spec_text, recipient_pubkey) is None:
        return False, None
    recip_values = dict(values or {})
    recip_values[12] = "{ #x" + str(recipient_pubkey) + " }:bv[384]"
    outputs = evaluate(recip_values) or {}
    o5_raw = outputs.get(tau_defs.USER_POLICY_STREAM_INDEX)
    if o5_raw is None:
        return False, None
    blocked = (
        tau_manager.parse_tau_output(o5_raw) == tau_defs.USER_POLICY_BLOCK_VALUE
    )
    return blocked, o5_raw
