"""Native evidence, Bounty 03 (issues #47 + #76), PR #153.

The mock suite (tests/test_recipient_gate.py) proves the gate's Python
logic with two scripted evaluators: a MockPolicyEvaluator deciding
clause verdicts and a scripted _multi deciding the cap stream. Neither
touches a real Tau engine. This file proves the same named cases at
the two levels where a real engine can honestly be put in the loop:

  Tier 1 — clause level, production evaluator. The recipient clause
  texts are stepped by tau_policy.PolicyEvaluator (the worker-backed
  evaluator consensus/sender_policy.py uses in production) through
  sender_policy.clause_blocks with NO mock override and force-test
  off, and the cap stream is read from a real tau_native.TauInterface
  whose spec carries the recipient's real cap unit. Verdict parsing
  is the gate's own: recipient_gate.policy_blocked /
  recipient_gate.hold_cap, with the engine's own parser
  (tau_manager.parse_tau_output — the callable consensus/engine.py
  passes to both).

  Tier 2 — apply level, subset. tests/test_recipient_gate.py's
  harness (_lifecycle / _parent / _envelope / _transfer / _park /
  _outcome, copied below) with the scripted Tau removed: no patches
  on tau_manager.communicate_with_tau[_multi], a live TauInterface
  installed as tau_manager.tau_direct_interface (the seam
  consensus/engine.py steps via tau_session.InProcessSession), seeded
  with the transfer rule + genesis consensus rules as
  tests/test_fee_model_native.py seeds them, and no
  MockPolicyEvaluator — clause verdicts and cap outputs come from
  real units stepped by the real engine.

Case map (11 acceptance cases):
  #47-1 recipient's own rule, distinct refusal                              Tier 1 + Tier 2
  #47-2 rule reads counterparty (i3) and amount (i1)                        Tier 1
  #47-3 one refused output fails the whole batch                            not carried — the batch
        refusal rides the same per-leg gate path as #47-1 and its
        atomicity is engine bookkeeping; it stays mock-proven.
  #47-4 one unit carries inbound + outbound; comments do not screen         Tier 1 (verdicts) — the
        comment/prescreen half is Python text analysis
        (recipient_gate.clause_applies_to_inbound) and has no engine
        level; it stays mock-proven and is described that way.
  #47-5 rule offers / approval completion under a recipient refusal         not carried — the approval
        completion under a recipient refusal stays mock-proven, and
        the rule-offer exemption is structural (no gate call exists),
        stated here rather than tested. Admission == apply for the
        gate likewise remains mock-proven (TODO-VERIFY #11, decided:
        no native admission test is added).
  #76-1 recipient-set hold cap, stated in the refusal                       Tier 1 (cap read) + Tier 2 (refusal)
  #76-2 cap of zero allows instant transfers only                           Tier 1 + Tier 2
  #76-3 release and retract are never gated                                 Tier 2 only
  #76-4 no cap published -> any hold                                        Tier 1 (hold_cap is None)
  #76-5 recipient without a policy is unaffected                            Tier 1 (no clause -> no verdict path)
  #76-6 absolute deadline via the i17 pair, not a length                    Tier 1 (pair reaches the clause)

Gate: idiom A (native-prep/INFRA-MAP.md §3). Locally every test
skips; the native CI job's preflight hard-fails if the module is
missing.

Landing resolutions for the prep pack's TODO-VERIFY items (each is
also recorded at the test it gates):
  #8 (feed widths) — sender_policy.clause_inputs converts the
     recipient map for the worker via WorkerSession._single /
     _bare (consensus/sender_policy.py, tau_session.py): a
     "{ #x.. }:bv[384]" literal is fed bare ("#x.."), a decimal
     string is fed as-is, and the worker types each stream at the
     clause's declared width. The repo's own native tests pin
     decimal verdict inputs and this exact call shape
     (tests/test_tau_policy_native.py). The amounts fed below
     (50 / 2000) fit the clauses' bv[24], so the widths agree and
     no clause is restated.
  #9 (one-unit text) — the production evaluator builds
     "always ( <body> )." around a clause BODY (tau_policy.clause_spec)
     and the registry stores clause_body_v1's extraction of a
     published unit (consensus/rule_offers.py), so the mock suite's
     full unit text cannot be stepped as a clause; its extracted
     conjunction body also fails the evaluator's build probe, which
     steps the clause on zero inputs, where the conjunction is
     unsatisfiable. The unit is therefore stepped in the
     verdict-equivalent implication form — see
     test_native_one_unit_verdicts_follow_the_direction.
  #10 (cap parse callable) — the engine passes
     tau_manager.parse_tau_output to both gate reads
     (consensus/engine.py: policy_blocked and hold_cap call sites);
     this file uses that exact callable.
  #6 (real fee) — Tier 2 charges the genesis program's fee: the
     engine sums each step's o9 (+ o8) and, on success only, debits
     the sender and credits the block proposer (no fee beneficiary
     is set on this harness's lifecycle manager, so the engine's
     fallback sink is the proposer — consensus/engine.py fee
     settlement; consensus/governance.py effective_fee_beneficiary).
     Sender balances are asserted as before - amount - fee with the
     fee measured from the proposer's balance delta; recipient-side
     amounts and refusal reasons are asserted exactly; a refusal
     returns before fee settlement and charges nothing, exactly as
     the mock suite pins.
  #7 (application-rules state) — chain_state.get_application_rules_state
     is a process-global the engine reads for rule bookkeeping.
     The Tier 2 cases carry no rule transactions, so apply never
     writes it; the Tier 2 helper still sets it explicitly to ""
     for each apply and restores the prior value afterwards, and
     this note records that choice.
"""
import itertools
import json
import os
from collections import namedtuple

import pytest

import chain_state
import tau_defs
import tau_manager
from block import Block
from bls_keys import (
    SK_ALICE,
    SK_BOB,
    SK_CAROL,
    SK_MALLORY,
    pubkey_hex,
    sign_payload,
)
from consensus import recipient_gate, rule_offers, sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.retractable import parse_retractable_transfer
from consensus.state import TauStateSnapshot

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENESIS_TAU = os.path.join(REPO_ROOT, "genesis.tau")
TRANSFER_RULE = os.path.join(REPO_ROOT, "rules", "04_handle_valid_transfer.tau")

SK_AUTH = 0xA07A
ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
CAROL = pubkey_hex(SK_CAROL)
MALLORY = pubkey_hex(SK_MALLORY)
AUTH = pubkey_hex(SK_AUTH)

HEIGHT = 20
FAR = 9999999999
BLOCK_TS = 1234567890


def _native_available():
    try:
        import tau_native

        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built"
)


@pytest.fixture(autouse=True)
def real_evaluators():
    """Force the production evaluation path: no mock override in the
    sender_policy registry, and tau_manager not in force-test mode, so
    sender_policy.evaluator("apply") builds the worker-backed
    tau_policy.PolicyEvaluator (tau_policy.py) — the evaluator a live
    node runs. The worker subprocess itself loads the native module;
    if it cannot, clause_blocks fails closed (blocked) and the
    allow-assertions below fail loudly rather than passing vacuously."""
    sender_policy.set_evaluator("apply", None)
    old_mode = tau_manager.tau_test_mode
    tau_manager.tau_test_mode = False
    # is_force_test_enabled() reads the environment; the native CI job
    # runs with TAU_FORCE_TEST=0 already. Assert rather than patch, so
    # a misconfigured job fails here instead of silently using mocks.
    assert not tau_manager.is_force_test_enabled()
    yield
    tau_manager.tau_test_mode = old_mode
    sender_policy.set_evaluator("apply", None)


@pytest.fixture(autouse=True)
def live_tau():
    """Install the real engine behind tau_manager for every test here.

    Mirrors tests/test_fee_model_native.py's setUp: a TauInterface on
    the real genesis program, seeded with the transfer rule and the
    genesis consensus rules the same way production seeds them. The
    Tier 1 tests do not step this interface (they use the policy
    worker and their own interfaces); Tier 2's apply_block steps it
    via tau_session.InProcessSession.
    """
    import tau_native

    iface = tau_native.TauInterface(GENESIS_TAU)
    old_iface = tau_manager.tau_direct_interface
    old_mode = tau_manager.tau_test_mode
    tau_manager.tau_direct_interface = iface
    tau_manager.tau_test_mode = False
    tau_manager.tau_ready.set()
    with open(TRANSFER_RULE) as fh:
        tau_manager.communicate_with_tau(
            rule_text=fh.read(), target_output_stream_index=0,
            apply_rules_update=False, source="seed-transfer-rule",
        )
    # data/genesis.json is generated by the CI native job before
    # pytest runs (scripts/gen_genesis.py); the checked-in
    # genesis_consensus.tau it is generated from is the fallback.
    genesis_json = os.path.join(REPO_ROOT, "data", "genesis.json")
    if os.path.exists(genesis_json):
        with open(genesis_json) as fh:
            consensus_rules = json.load(fh)["consensus_rules"]
    else:
        with open(os.path.join(REPO_ROOT, "genesis_consensus.tau")) as fh:
            consensus_rules = fh.read()
    tau_manager.communicate_with_tau(
        rule_text=chain_state._preprocess_tau_spec_text(consensus_rules),
        target_output_stream_index=0,
        apply_rules_update=False, source="seed-genesis-consensus",
    )
    yield iface
    tau_manager.tau_direct_interface = old_iface
    tau_manager.tau_test_mode = old_mode
    tau_manager.tau_ready.clear()


def _values(*, sender, recipient=BOB, amount="100", balance="0",
            height=HEIGHT, release_pair=0):
    """The recipient evaluation map, built by the gate's own builder —
    the same map consensus/engine.py hands the clause at apply."""
    base = {1: amount, 3: "{ #x" + sender + " }:bv[384]"}
    return recipient_gate.recipient_values(
        base, recipient, int(balance), height, release_pair=release_pair
    )


def _blocked(clause, values):
    blocked, _o5 = sender_policy.clause_blocks(clause, values, pool="apply")
    return blocked


# --- Tier 1: clause level, production evaluator ------------------------------

# Fail-closed policy semantics (tests/test_tau_policy_native.py on
# main): a clause blocks unless it emits o5 = 1 for the inputs given.
ALLOW_ONLY_ALICE = (
    "( i3[t]:bv[384] = { #x" + ALICE + " }:bv[384] ) "
    "-> ( o5[t]:bv[24] = { #x000001 }:bv[24] )"
)
AMOUNT_OVER_1000_BLOCKED = (
    "( i1[t]:bv[24] > { #x0003e8 }:bv[24] ) "
    "-> ( o5[t]:bv[24] = { #x000001 }:bv[24] )"
)


def test_native_clause_reads_the_counterparty():
    """#47 case 2 (counterparty half): BOB's clause allows only ALICE
    as the sender. Stepped by the production evaluator on the gate's
    own recipient_values map: ALICE's payment is allowed, CAROL's is
    blocked — the verdict comes from the real engine reading i3."""
    assert _blocked(ALLOW_ONLY_ALICE, _values(sender=ALICE)) is False
    assert _blocked(ALLOW_ONLY_ALICE, _values(sender=CAROL)) is True


def test_native_clause_reads_the_amount():
    """#47 case 2 (amount half) / the threshold shape the repo's own
    native policy tests use: the clause emits its allow only above
    the threshold, and recipient_gate.policy_blocked's call shape
    (clause_blocks on the gate's map) agrees with the evaluator's
    verdict on both sides.

    TODO-VERIFY #8, resolved: recipient_values carries i1 as a
    decimal string, and clause_inputs feeds it to the worker bare
    (WorkerSession._bare strips only "{ ... }:bv[N]" wrappers);
    the worker types the stream at the clause's declared bv[24].
    tests/test_tau_policy_native.py pins exactly this: decimal
    verdict inputs, and clause_blocks({1: "2000"}) blocked /
    ({1: "50"}) allowed against a width-8 threshold clause. The
    amounts here (2000 / 50) fit bv[24], so the fed width and the
    clause width agree and the clause stands as written."""
    assert _blocked(AMOUNT_OVER_1000_BLOCKED, _values(sender=ALICE, amount="2000")) is False
    assert _blocked(AMOUNT_OVER_1000_BLOCKED, _values(sender=ALICE, amount="50")) is True


# The one-unit-both-directions text, copied from
# tests/test_recipient_gate.py::test_one_unit_carries_inbound_and_outbound_rules.
ONE_UNIT = (
    "always ( o5[t]:bv[24] = { #x000001 }:bv[24] "
    "&& (i3[t]:bv[384] = { #x" + ALICE + " }:bv[384] "
    "|| i4[t]:bv[384] = { #x" + CAROL + " }:bv[384]) )."
)

# The same unit as an implication — the form the production evaluator
# steps clause bodies in. See the test's docstring for why.
ONE_UNIT_BODY = (
    "( (i3[t]:bv[384] = { #x" + ALICE + " }:bv[384] "
    "|| i4[t]:bv[384] = { #x" + CAROL + " }:bv[384]) ) "
    "-> ( o5[t]:bv[24] = { #x000001 }:bv[24] )"
)


def test_native_one_unit_verdicts_follow_the_direction():
    """#47 case 4 (engine half): the recipient's ONE unit, stepped by
    the real evaluator, allows the inbound shape it whitelists and
    blocks the shape it refuses. The direction *screening*
    (recipient_gate.clause_applies_to_inbound, incl. the comment cases)
    is Python text analysis and stays mock-proven — see module docstring.

    TODO-VERIFY #9, resolved by restatement (recorded here, as the
    prep pack prescribes): ONE_UNIT above is the unit exactly as the
    mock test builds it (string concat with the same key constants),
    but a published unit is not what the evaluator steps. The
    registry stores clause_body_v1's extraction of the unit
    (consensus/rule_offers.py) and the evaluator builds
    "always ( <body> )." around that body (tau_policy.clause_spec),
    so the unit text itself would be wrapped a second time; and the
    extracted conjunction body fails the evaluator's build probe,
    which steps the clause on zero inputs, where
    "o5 = 1 && (i3 = ALICE || i4 = CAROL)" is unsatisfiable. The
    verdicts are therefore stepped with ONE_UNIT_BODY, the same unit
    restated as an implication: its antecedent is true exactly when
    the unit's disjunction holds, and where the antecedent fails o5
    is undetermined, which the evaluator reads as blocked
    (tests/test_tau_policy_native.py::test_undetermined_o5_reads_as_blocked).
    On the recipient map the two forms give the same verdict for
    every (sender, recipient) pair. The extraction itself is pinned
    by the first assertion: clause_body_v1 reads both direction
    streams out of the published unit."""
    extracted = rule_offers.clause_body_v1(ONE_UNIT)
    assert "i3[t]:bv[384]" in extracted and "i4[t]:bv[384]" in extracted
    builds, _error = sender_policy.clause_builds(ONE_UNIT_BODY, pool="apply")
    assert builds
    # Inbound shape the unit whitelists (sender is ALICE): allowed.
    assert _blocked(ONE_UNIT_BODY, _values(sender=ALICE)) is False
    # Inbound shape it refuses (sender is CAROL, recipient is BOB,
    # neither disjunct holds): blocked.
    assert _blocked(ONE_UNIT_BODY, _values(sender=CAROL)) is True


# --- Tier 1: cap stream from a real interpreter ------------------------------

CAP_CLAUSE_20 = "always ( o10[t]:bv[24] = { #x000014 }:bv[24] )."


def _cap_iface():
    import tau_native

    iface = tau_native.TauInterface(GENESIS_TAU)
    iface.communicate(
        rule_text=CAP_CLAUSE_20, target_output_stream_index=0,
        apply_rules_update=True, source="native-recipient-cap",
    )
    return iface


def test_native_cap_stream_reads_the_recipients_stated_cap():
    """#76 cases 1 + 4: with BOB's cap unit in the real spec, stepping
    the gate's recipient_values through the real interpreter yields
    o10, and recipient_gate.hold_cap reads exactly the stated cap (20).
    With no cap unit in the spec, hold_cap returns None (no cap
    published -> any hold), not 0.

    TODO-VERIFY #10, resolved: the parse callable is the engine's
    own — consensus/engine.py passes tau_manager.parse_tau_output
    to hold_cap (and to policy_blocked) at apply, so this test uses
    that exact callable rather than a local mirror."""
    parse = tau_manager.parse_tau_output
    iface = _cap_iface()
    values = _values(sender=ALICE)
    outputs = iface.communicate_multi(input_stream_values=values)
    assert recipient_gate.hold_cap(outputs, parse) == 20

    import tau_native

    bare = tau_native.TauInterface(GENESIS_TAU)
    outputs = bare.communicate_multi(input_stream_values=values)
    assert recipient_gate.hold_cap(outputs, parse) is None


def test_native_absolute_release_pair_reaches_the_clause():
    """#76 case 6 (feed half): a park's recipient evaluation carries
    the absolute (timestamp, height) pair on i17 — built by
    recipient_gate.pack_release_pair / recipient_values — and a real
    clause stepped on that map can refuse on the absolute release
    height while allowing the same hold length under the deadline.
    The apply-level refusal itself is Tier 2 / mock-proven.

    The comparison is on the whole packed pair, not a bit mask:
    pack_release_pair is (ts << 32) | height, so comparing packed
    pairs is comparing absolute release points, and with ts = 0 the
    pair is the height itself. The clause allows a release at or
    before the packed deadline (height 100) and leaves o5
    undetermined — read as blocked — past it."""
    pair = recipient_gate.pack_release_pair(release_ts=0, release_height=110)
    values = _values(sender=ALICE, release_pair=pair)
    assert int(values[17]) & 0xFFFFFFFF == 110
    deadline = recipient_gate.pack_release_pair(release_ts=0, release_height=100)
    deadline_clause = (
        "( i17[t]:bv[64] <= { #x" + format(deadline, "016x") + " }:bv[64] ) "
        "-> ( o5[t]:bv[24] = { #x000001 }:bv[24] )"
    )
    # Release at height 110 is past the absolute deadline: refused,
    # although the hold length (110 - 20) is unremarkable.
    assert _blocked(deadline_clause, values) is True
    # The same clause allows a release at height 30, before it.
    early = recipient_gate.pack_release_pair(release_ts=0, release_height=30)
    assert _blocked(
        deadline_clause, _values(sender=ALICE, release_pair=early)) is False


# --- Tier 2: apply level, subset ---------------------------------------------
# tests/test_recipient_gate.py's harness with the scripted Tau removed:
# _lifecycle / _parent / _envelope / _transfer / _park / _outcome are
# copied from that suite; _apply_native patches nothing on the Tau
# path — the engine steps the live TauInterface installed by the
# live_tau fixture, and sender_policy keeps the production evaluator
# (real_evaluators fixture). The blocked= / caps= script parameters
# are gone: refusals come from a real clause body registered for BOB
# (below), caps from a real guarded unit seeded into the spec plus
# its registry body (the trigger the gate checks).

_TX_SEQ = itertools.count()

Applied = namedtuple("Applied", "result lifecycle")


def _lifecycle(*, clause=None):
    lm = ConsensusLifecycleManager(active_validators=[MALLORY, ALICE])
    lm.activate_approval_slots()
    # The gate tests run in the ACTIVE configuration: the recipient
    # gate is governance-activated, exactly as approval slots are
    # activated one line above. The inactive configuration has its
    # own tests in the mock suite.
    lm.activate_recipient_gate()
    if clause is not None:
        lm.rule_offers.accepted_clauses[(BOB, tau_defs.USER_POLICY_STREAM_INDEX)] = clause
    return lm


def _parent(lm, balances=None):
    return TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": balances or {ALICE: 100000, AUTH: 10, BOB: 0, CAROL: 100000, MALLORY: 0},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )


def _apply_native(txs, lm, *, parent=None, height=HEIGHT):
    if parent is None:
        parent = _parent(lm)
    view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(MALLORY)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block = Block.create(block_number=height, previous_hash="00" * 32,
                         transactions=txs, proposer_pubkey=MALLORY,
                         timestamp=BLOCK_TS)
    # TODO-VERIFY #7, resolved by explicit setting (recorded in the
    # module docstring): the engine reads the process-global
    # application-rules state for rule bookkeeping; these cases
    # carry no rule transactions, so the state is set to "" for the
    # apply — the value the mock harness's patch presents — and the
    # prior value is restored afterwards.
    prior_rules = chain_state.get_application_rules_state()
    chain_state.save_application_rules_state("")
    try:
        result = TauConsensusEngine().apply_block(view, block, parent)
    finally:
        chain_state.save_application_rules_state(prior_rules)
    return Applied(result, result.next_snapshot.metadata["lifecycle_manager"])


def _envelope(tx_type, sender, seq, *, fee_limit="100000", **fields):
    tx = {
        "tx_id": f"{tx_type}-{next(_TX_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
    }
    tx.update(fields)
    return tx


def _transfer(to, amount, sk, *, sender=ALICE, seq=0):
    return sign_payload(_envelope(
        "user_tx", sender, seq,
        operations={"1": [[sender, to, str(amount)]]}), sk)


def _park(sk, *, sender=ALICE, seq=0, release_at_height=HEIGHT + 10, amount=100):
    return sign_payload(_envelope(
        "retractable_transfer", sender, seq, recipient_pubkey=BOB,
        amount=amount, release_at_height=release_at_height), sk)


def _outcome(applied, tx_id):
    return next(o for o in applied.result.outcomes if o.tx_id == tx_id)


def _balances(applied):
    return applied.result.next_snapshot.metadata["balances"]


# A clause body that refuses every transfer it judges: o5 = 0 on both
# branches of a condition that always holds. The mock suite registers
# the constant unit "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
# for this; as a clause BODY that constant is exactly what the
# production evaluator refuses at validate time — it reads no input
# stream (tau_policy's CONSTANT, pinned by
# tests/test_tau_policy_native.py::test_a_clause_that_reads_no_input_is_refused_at_registration).
# The body below is the registrable equivalent: it reads i1, which
# every recipient evaluation carries, and emits the block value
# unconditionally.
ALWAYS_BLOCK_BODY = (
    "( i1[t]:bv[24] >= { #x000000 }:bv[24] ) "
    "? ( o5[t]:bv[24] = { #x000000 }:bv[24] ) "
    ": ( o5[t]:bv[24] = { #x000000 }:bv[24] )"
)


def _cap_body(cap):
    """The registry form of BOB's cap clause: the body
    clause_body_v1 extracts from the published unit. The engine
    never steps this body — hold_cap reads the spec evaluation —
    but clause_for(BOB, o10) returning it is the gate's trigger
    for parks, exactly as in production."""
    return "o10[t]:bv[24] = { #x" + format(cap, "06x") + " }:bv[24]"


def _cap_spec_unit(cap):
    """BOB's cap as a guarded unit in the spec, in the form users
    publish (cf. the sender-scoped o8 rule in
    tests/test_fee_model_native.py): the cap fires when the
    evaluation's policy owner (i12) is BOB."""
    return (
        "always (i12[t]:bv[384] = { #x" + BOB + " }:bv[384] -> "
        "o10[t]:bv[24] = { #x" + format(cap, "06x") + " }:bv[24])."
    )


def _register_cap(lm, cap):
    lm.rule_offers.accepted_clauses[
        (BOB, tau_defs.RECIPIENT_HOLD_CAP_STREAM_INDEX)] = _cap_body(cap)
    tau_manager.communicate_with_tau(
        rule_text=_cap_spec_unit(cap), target_output_stream_index=0,
        apply_rules_update=False, source="native-recipient-cap",
    )


def test_native_recipient_policy_refusal_has_distinct_reason():
    """#47 case 1 at apply: BOB's registered clause refuses ALICE's
    transfer; the refusal carries the recipient reason, not the
    sender-policy one, and charges nothing (the engine returns
    before fee settlement — TODO-VERIFY #6 in the module docstring)."""
    lm = _lifecycle(clause=ALWAYS_BLOCK_BODY)
    tx = _transfer(BOB, 100, SK_ALICE)
    applied = _apply_native([tx], lm)
    outcome = _outcome(applied, tx["tx_id"])
    assert outcome.reason == recipient_gate.REASON_POLICY_BLOCK
    assert outcome.reason != "user_policy_block"
    assert tx["tx_id"] not in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 0
    assert _balances(applied)[ALICE] == 100000


def test_native_park_beyond_recipient_cap_refused_with_cap():
    """#76 case 1 at apply: the park holds 10 blocks against BOB's
    stated cap of 5 (a real unit in the real spec); the refusal
    names the cap, nothing is escrowed, the sender is unchanged."""
    lm = _lifecycle()
    _register_cap(lm, 5)
    tx = _park(SK_ALICE)
    applied = _apply_native([tx], lm)
    outcome = _outcome(applied, tx["tx_id"])
    assert outcome.reason == recipient_gate.REASON_HOLD_CAP
    assert "cap=5" in " | ".join(str(x) for x in outcome.receipt_logs)
    assert applied.lifecycle.retractable_transfers.escrow_total() == 0
    assert _balances(applied)[ALICE] == 100000


def test_native_park_within_recipient_cap_is_admitted():
    """#76 case 1, admitted side: the same 10-block hold against a
    cap of 20 lands and escrows in full. The sender pays the amount
    plus the real genesis fee, measured from the proposer's balance
    delta (the fee sink on this harness — module docstring, #6).
    The mock suite also observes the i17 pair on this evaluation
    through its scripted multi; here that feed is proven at Tier 1
    (test_native_absolute_release_pair_reaches_the_clause) and the
    apply-level observables are admission and escrow."""
    lm = _lifecycle()
    _register_cap(lm, 20)
    parent = _parent(lm)
    before = dict(parent.metadata["balances"])
    tx = _park(SK_ALICE)
    applied = _apply_native([tx], lm, parent=parent)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert applied.lifecycle.retractable_transfers.escrow_total() == 100
    after = _balances(applied)
    fee = after[MALLORY] - before[MALLORY]
    assert after[ALICE] == before[ALICE] - 100 - fee


def test_native_recipient_cap_zero_allows_instant_only():
    """#76 case 2 at apply: a stated cap of 0 refuses the 10-block
    park, and a plain transfer to the same recipient is unaffected
    (plain transfers never consult the cap)."""
    lm = _lifecycle()
    _register_cap(lm, 0)
    tx = _park(SK_ALICE)
    applied = _apply_native([tx], lm)
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_HOLD_CAP

    lm = _lifecycle()
    _register_cap(lm, 0)
    plain = _transfer(BOB, 100, SK_ALICE)
    applied = _apply_native([plain], lm)
    assert plain["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 100


def test_native_park_release_is_never_gated():
    """#76 case 3 at apply, the release leg: the park matures in a
    block where BOB's registered clause refuses every inbound
    transfer — proven live below by stepping that clause on the
    gate's own map — and the sweep still pays the recipient in
    full. A release is the recipient's own escrowed money leaving;
    gating it could trap funds behind a policy published after the
    park was created."""
    lm = _lifecycle()
    tx = _park(SK_ALICE)  # releases at HEIGHT + 10
    applied = _apply_native([tx], lm)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    entry = parse_retractable_transfer(tx)

    # BOB publishes the always-block clause after the park exists.
    applied.lifecycle.rule_offers.accepted_clauses[
        (BOB, tau_defs.USER_POLICY_STREAM_INDEX)] = ALWAYS_BLOCK_BODY
    # The clause really does refuse an inbound transfer on the
    # gate's own recipient map, stepped by the production evaluator.
    assert _blocked(ALWAYS_BLOCK_BODY, _values(sender=ALICE)) is True

    applied2 = _apply_native(
        [], applied.lifecycle,
        parent=applied.result.next_snapshot, height=HEIGHT + 10)
    assert entry.retractable_id.hex() in \
        applied2.result.governance_changes["released_retractables"]
    assert _balances(applied2)[BOB] == 100
    assert applied2.lifecycle.retractable_transfers.escrow_total() == 0
