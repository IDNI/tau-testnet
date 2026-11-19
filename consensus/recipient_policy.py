"""Recipient-side o5 policy gate (issues #47/#76 — Bounty 03, recipient controls).

Until now the node evaluated exactly one account's policy per transfer: the
sender's. This module adds the second evaluation the issues ask for — the
recipient's own o5 policy, checked at admission and at block apply — so an
account can refuse incoming transfers (an inbound allow-list on i3, "refuse
incoming above N" on i1), and cap how long a payment to it may be held (#76).

Two modes, mirroring the sender side:

- Clause mode (`recipient_clause_blocks`): the recipient's registered clause
  is stepped on the same per-transfer inputs as the sender pass, with the
  hold streams forced in (below).
- Guarded mode (`guarded_recipient_blocks`): the accumulated spec is stepped
  a second time with i12 set to the RECIPIENT's key, so the recipient's
  guarded unit — `always ((i12[t] = <me>) ? <body> : o5 = allow)` — is the
  one that can say no, exactly as the sender's unit does in the first pass.
  Callers supply the step function, so admission (the admission session) and
  apply (the engine session) share this one implementation. The pass steps
  only when the recipient's key appears literally in the current spec text:
  a guarded unit scopes on its owner's key, so absence proves there is no
  unit to enforce — and an extra step on the shared session is observable by
  history-reading rules, so it is never spent speculatively.

Input contract (the documented choices the issues leave to the node): the
recipient pass feeds the SAME per-transfer input map as the sender pass
(i1 amount, i2 sender balance, i3 sender key, i4 recipient key, i5 timestamp,
i12 sender key, approval slots, custom streams), plus the two hold streams.
The counterparty is read on i3, which carries the sender's full public key
in BOTH passes: in the sender pass i3 names the clause's owner, in the
recipient pass it names the sender — the direction is visible from the
streams themselves. (i12 also carries the sender key in the clause pass, but
clause bodies may not reference it: rule_offers.SENDER_STREAM bans it at
registration.) An inbound rule is therefore a plain comparison on i3, e.g.
"allow only if i3 is A or B", exactly as issue #47 requests. In the guarded
pass i12 is re-pointed at the recipient while i3 stays the sender.

Hold streams (#76): i17 carries the park's hold length in SECONDS
(release_at_time minus the block timestamp) and i27 the hold in BLOCKS
(release_at_height minus the block height), both bv[64], host-computed by
`hold_values`. Admission measures against the tip view's next-block
height/timestamp — the same clock that refuses a park which could be mined
at or after its own release — and apply against the block being applied. A
plain transfer feeds 0 on both, so a cap of 0 admits plain transfers and
refuses every park; a park of one kind feeds 0 on the other kind's stream,
so a cap rule must bound both streams to bound both kinds. Both values are
FORCED into the recipient pass by this module: a sender-supplied operations
value on i17/i27 never reaches the recipient's clause. While the chain flag
is active the SENDER pass feeds explicit zeros on both streams (the
approval-slot precedent), so the owner's own cap clause reads 0 on its
outbound transfers and never blocks them for an unfed stream. Only parks
are capped — a retract never passes this gate, and a matured release is a
direct credit that is never re-checked (engine._release_due_retractables
stays untouched). The approval-vote release path re-runs o5 through the
shared transfer closure with hold None (final-now): the money arrives at
release, so the recipient pass sees a final payment, not the original
park's hold.

Activation: the gate runs only while the chain flag `recipient_policy_active`
is set (a one-way governance patch, mirroring approval_slots_active). Before
activation i17/i27 are ordinary custom streams and nothing here runs, so
every pre-existing policy keeps its exact meaning. Admission refuses a NEW
clause reading i17/i27 on an inactive chain (RECIPIENT_POLICY_INACTIVE)
because the rule would never be asked about incoming payments; grandfathered
clauses already on chain keep working, and the activation audit blocks the
flag until they are replaced.

Opt-in screen (backwards compatibility): the recipient pass enforces only
clauses whose comment-stripped body reads the counterparty stream i3 or a
hold stream (i17/i27). A clause that reads neither — a pure outbound
whitelist on i4, say — is an outbound-only clause; enforcing it on inbound
transfers would silently change what a pre-existing policy means, so it is
skipped here. Every inbound rule must read the sender or the hold to work at
all, so the screen loses no expressiveness.

Refusals: a recipient block rejects with a distinct reason so a wallet can
say which side said no. A plain policy block is `recipient_policy_block`
("Transaction rejected by recipient policy (o5)" at admission). A block of a
PARK with hold > 0 by a clause that reads a hold stream is
`recipient_max_hold`, and the refusal carries the recipient's cap whenever
the clause declares it in the canonical form — a direct comparison of a hold
stream against a literal (`i17[t]:bv[64] <= { #x258 }:bv[64]`, or `<`, or the
reversed `>=`/`>` forms); the cap is extracted textually by
`extract_hold_caps`, the same class of textual screen the codebase already
uses for stream domains. A cap clause in a non-canonical shape still
ENFORCES (the Tau verdict decides); its refusal then reports the measured
hold without a numeric cap.

Neutral default: a recipient with no clause, or one that does not opt in,
allows everything — the same default as the sender side.

Fee model: unchanged. An admission refusal costs nothing. At apply a
recipient block rejects the whole user_tx exactly like a sender-policy
block: staged writes never commit, the proposer filters the transaction out
of the block, and NO FEE is charged (a batch with one refused output fails
as one transaction; no partial apply is possible).

Determinism: admission (commands/sendtx.py) and apply (consensus/engine.py)
call these functions with the same inputs, mirroring sender_policy, so the
two paths cannot drift apart. Replay runs the same apply path, so a replayed
block reaches the same verdicts.

Capability: `supported()` reads tau_defs.HOST_CAPABILITIES, which
getgovernance reports to wallets beside the chain flag. On a node built
without this gate the flags are False and the clause admission screen
refuses a hold-cap clause at deploy time with a clear reason, instead of
admitting a rule that would never run.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

import tau_defs
import tau_manager
from consensus import sender_policy
from consensus.retractable import KIND_HEIGHT, KIND_TIME
from consensus.rule_offers import strip_clause_comments
from tau_speculation import _SESSION_DEFAULT

#: tx_receipt["reason"] when the recipient's policy blocks a transfer (#47).
REASON = "recipient_policy_block"

#: tx_receipt["reason"] when the recipient's hold cap blocks a park (#76).
#: The refusal text and the receipt detail carry the cap, so the payer's
#: wallet can print "accepts payments held for up to N".
REASON_MAX_HOLD = "recipient_max_hold"

#: A clause opts into recipient-side enforcement by reading the counterparty
#: stream i3 (the sender's full public key) ...
_COUNTERPARTY_STREAM = re.compile(r"\bi3\s*\[")
#: ... or a hold stream (i17 seconds / i27 blocks), which only the recipient
#: pass ever feeds meaningfully.
_HOLD_STREAM = re.compile(r"\bi(?:17|27)\s*\[")
#: Any mention of a hold stream, typed or not: the activation audit and the
#: width screen must also see untyped mentions (word-boundary, so i170/i117
#: are not false positives).
_HOLD_MENTION = re.compile(r"\bi(17|27)\b")
_HOLD_TYPED_TAIL = re.compile(
    r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*%d\s*\]" % tau_defs.HOLD_STREAM_BV_WIDTH
)


@dataclass(frozen=True)
class RecipientRefusal:
    """Why the recipient's policy said no, with the #76 cap when known."""

    reason: str
    max_hold_seconds: Optional[int] = None
    max_hold_blocks: Optional[int] = None
    hold_seconds: int = 0
    hold_blocks: int = 0


def supported(capability: str = "recipient_policy") -> bool:
    """Whether this node software enforces the named recipient capability.

    Describes the BUILD, never chain state: the chain flag wallets must check
    before deploying a rule is `recipient_policy_active` (see
    `recipient_policy_active` below and getgovernance).
    """
    return bool(tau_defs.HOST_CAPABILITIES.get(capability, False))


def recipient_policy_active(tip_view) -> bool:
    """Whether recipient-side policy is active at the tip.

    Requires a genuine `True`, for the reason `approval_slots_active` does: a
    partial or mocked view answers something truthy for an attribute it was
    never given, and running as if a consensus feature were on is the kind of
    thing that passes every test and then diverges on a live chain.
    """
    return getattr(tip_view, "recipient_policy_active", False) is True


def clause_reads_hold_stream(body) -> bool:
    """True when `body` reads i17 or i27 — the mark of a hold-cap clause."""
    if not isinstance(body, str) or not body:
        return False
    return bool(_HOLD_STREAM.search(strip_clause_comments(body)))


def clause_is_recipient_relevant(body) -> bool:
    """The opt-in screen: a clause is enforced on inbound transfers only when
    its comment-stripped body reads the counterparty (i3) or a hold stream
    (i17/i27). Outbound-only clauses keep their exact current meaning."""
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


_LITERAL = (
    r"\{\s*(?:#x(?P<hex>[0-9a-fA-F]+)|(?P<dec>\d+))\s*\}\s*:\s*bv\s*\[\s*\d+\s*\]"
)
_STREAM_REF = r"i(?P<stream>17|27)\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*\d+\s*\]"
_CAP_DIRECT = re.compile(_STREAM_REF + r"\s*(?P<op><=|<)\s*" + _LITERAL)
_CAP_REVERSED = re.compile(_LITERAL + r"\s*(?P<op>>=|>)\s*" + _STREAM_REF)


def _cap_value(match, strict_ops) -> int:
    raw = match.group("hex")
    value = int(raw, 16) if raw is not None else int(match.group("dec"))
    return value - 1 if match.group("op") in strict_ops else value


def extract_hold_caps(body) -> tuple:
    """(max_hold_seconds, max_hold_blocks) declared by a clause, or Nones.

    Reads the canonical cap comparisons (a hold stream compared against a
    literal: `<=`, `<`, or the reversed `>=`/`>`) out of the comment-stripped
    body. When a stream is capped more than once, the smallest — most
    restrictive — cap is the one the rule enforces, so it is the one a refusal
    reports. A strict inequality caps at value - 1. Purely textual and
    deterministic: every node extracts the same caps from the same clause.
    Non-canonical shapes extract nothing; the verdict still enforces them.
    """
    if not isinstance(body, str) or not body:
        return None, None
    scrubbed = strip_clause_comments(body)
    caps: dict = {}
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
    cap = " and ".join(parts) if parts else "a hold cap declared in its rule"
    return (
        f"RECIPIENT_MAX_HOLD: the recipient accepts payments held for "
        f"{cap}; this payment would be held for {refusal.hold_seconds} "
        f"seconds / {refusal.hold_blocks} blocks"
    )


def recipient_clause_blocks(clause_for, sender_pubkey, recipient_pubkey,
                            values, *, pool: str,
                            timeout=_SESSION_DEFAULT,
                            hold: Optional[dict] = None
                            ) -> tuple:
    """(blocked, detail, refusal) for the recipient's own o5 clause.

    `clause_for` is the tip view's (or the rule-offer manager's) clause
    lookup, `values` the per-transfer input map the sender pass uses, and
    `hold` the {17: seconds, 27: blocks} map from `hold_values` for a park
    (None — a plain transfer — forces both hold streams to 0).
    (False, "", None) — allow — when there is nothing to enforce: no
    recipient, a self-transfer (the sender pass already judged it), no
    clause, or a clause that never opts in. The hold streams are forced into
    a COPY of the input map, so a sender-supplied value never reaches the
    clause and the sender pass's inputs are never mutated.
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
    eval_values[tau_defs.HOLD_SECONDS_STREAM_INDEX] = str(hold_seconds)
    eval_values[tau_defs.HOLD_BLOCKS_STREAM_INDEX] = str(hold_blocks)
    blocked, detail = sender_policy.clause_blocks(
        body, eval_values, pool=pool, timeout=timeout)
    if not blocked:
        return False, "", None
    refusal = RecipientRefusal(
        reason=REASON, hold_seconds=hold_seconds, hold_blocks=hold_blocks)
    # A hold-cap refusal is distinct only when a PARK with a real hold was
    # blocked by a clause that reads a hold stream: an allow-list refusing a
    # sender refuses every hold, so there is no cap to report.
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


def guarded_recipient_blocks(evaluate, values, sender_pubkey,
                             recipient_pubkey, *, spec_text=None,
                             hold: Optional[dict] = None) -> tuple:
    """(blocked, o5_raw) for the guarded-mode recipient pass.

    `evaluate` steps the accumulated spec on an input map and returns the
    output map (the admission session's step at admission, the engine
    session's evaluate at apply). The recipient pass is the sender pass with
    i12 — the policy-owner stream every guarded unit scopes on — set to the
    recipient's key literal; every other input, the counterparty on i3
    included, is the transfer's own, and the hold streams are forced as in
    the clause pass. A missing o5 is the neutral default (allow), exactly as
    in the sender pass.

    Pre-screen: a guarded unit scopes on its owner's key as a literal in the
    spec text, so the pass steps only when the caller-supplied current spec
    text (`spec_text`, in production tau_manager.last_known_tau_spec)
    actually contains the recipient's key. Otherwise the recipient provably
    has no guarded unit and the pass is skipped without stepping — an extra
    step on the shared session is not free: history-reading rules observe
    every step. An unknown or empty spec text therefore also skips: no spec,
    no units.
    """
    if not recipient_pubkey or recipient_pubkey == sender_pubkey:
        return False, None
    if not spec_text or str(recipient_pubkey) not in spec_text:
        return False, None
    hold = hold or {}
    recip_values = dict(values or {})
    recip_values[12] = "{ #x" + str(recipient_pubkey) + " }:bv[384]"
    recip_values[tau_defs.HOLD_SECONDS_STREAM_INDEX] = str(
        int(hold.get(tau_defs.HOLD_SECONDS_STREAM_INDEX, 0)))
    recip_values[tau_defs.HOLD_BLOCKS_STREAM_INDEX] = str(
        int(hold.get(tau_defs.HOLD_BLOCKS_STREAM_INDEX, 0)))
    outputs = evaluate(recip_values) or {}
    o5_raw = outputs.get(tau_defs.USER_POLICY_STREAM_INDEX)
    if o5_raw is None:
        return False, None
    blocked = (
        tau_manager.parse_tau_output(o5_raw) == tau_defs.USER_POLICY_BLOCK_VALUE
    )
    return blocked, o5_raw


def screen_hold_stream_widths(body: str) -> Optional[str]:
    """None when every i17/i27 mention is typed bv[64], else the reason.

    Reject-unless-annotated, like the approval slots: stream typing is
    process-global and sticky, so one clause typing a hold stream at another
    width (or not at all, which lets the engine infer one) would fail the
    build of every other clause that reads it. Runs only while the chain flag
    is active — before activation the streams are ordinary custom streams a
    block may already carry at any width.
    """
    scrubbed = strip_clause_comments(body or "")
    width = tau_defs.HOLD_STREAM_BV_WIDTH
    for match in _HOLD_MENTION.finditer(scrubbed):
        idx = int(match.group(1))
        if not _HOLD_TYPED_TAIL.match(scrubbed, match.end()):
            return (
                f"every mention of the recipient hold stream i{idx} must be "
                f"written i{idx}[t]:bv[{width}]; an untyped or differently "
                f"typed mention lets the engine infer a conflicting width "
                f"process-wide"
            )
    return None


def audit_receive_stream_collisions(spec_texts) -> List[str]:
    """Reasons recipient policy cannot safely be activated. Empty means clear.

    Before activation i17/i27 are ordinary custom input streams, so a
    deployed rule or clause may already read them. Activating over one would
    reinterpret that rule as a recipient hold policy its owner never wrote,
    or type the stream at a second width. `spec_texts` is the same
    (label, text) corpus the approval-slot audit takes: consensus rules,
    builtin rules, the application-rules accumulation and every stored
    clause body. Grandfathered clauses keep working until activation; this
    audit holds the flag back until their owners replace them.
    """
    findings: List[str] = []
    for label, text in spec_texts or ():
        if not isinstance(text, str) or not text.strip():
            continue
        scrubbed = strip_clause_comments(text)
        hit = sorted({f"i{m.group(1)}" for m in _HOLD_MENTION.finditer(scrubbed)})
        if hit:
            findings.append(
                f"{label} already references recipient hold stream(s) "
                f"{', '.join(hit)}; activating would reinterpret it as a "
                f"recipient policy or type the stream at a second width. "
                f"Replace or revoke it first"
            )
    return findings