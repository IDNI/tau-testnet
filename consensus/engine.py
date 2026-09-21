from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import config
import db
import tau_defs
from .tau_engine import TauEngine, TauExecutionResult, TauStateSnapshot
from .serialization import canonical_json, canonicalize_parent_hash_yid, canonicalize_proposer_yid
from .state import StateStore, compute_state_hash
from .governance import (
    DEFAULT_MAX_RULE_TXS_PER_BLOCK,
    normalize_validator_set,
    is_tau_authoritative_eligibility_mode,
)
from . import fees
from .fees import FeeRuleError
from .approvals import (
    APPROVAL_TX_TYPES,
    MAX_TIER_AUTHORS,
    STATUS_EXECUTED,
    STATUS_FAILED,
    STATUS_OPEN,
    TX_TYPE_APPROVAL_REQUEST,
    TX_TYPE_TRANSFER_VOTE,
    parse_approval_request,
    parse_transfer_vote,
    screen_policy_widths,
    screen_unsatisfiable_sender_conjunction,
)
from .rule_offers import (
    NEUTRAL_O5_CLAUSE_BODY,
    RULE_OFFER_TX_TYPES,
    RuleOfferShapeError,
    clause_body_v1,
    is_neutral_clause_body,
    TX_TYPE_RULE_OFFER,
    TX_TYPE_RULE_OFFER_ACCEPT,
    parse_rule_offer,
    parse_rule_offer_accept,
    parse_rule_offer_reject,
    clause_output_streams,
)

# Transaction types that pay a fee. Governance types are exempt so validators
# never need funds to govern; rule sharing is user-initiated and expensive, so
# exempting it would make rule spam free.
#
# `approval_request` pays because it is the ONLY charge for a parked transfer:
# executing it later is free, so there is no second fee to drift against a fee
# rule that changed while the request sat open. `transfer_vote` is exempt like a
# governance vote, so approver bots need no funding.
#
# MUST stay in step with commands.sendtx.FEE_BEARING_TX_TYPES -- the same
# constant is deliberately duplicated there to keep the admission path free of
# an engine import, and a divergence charges a different fee at admission than
# at inclusion.
FEE_BEARING_TX_TYPES = frozenset(
    {"user_tx", TX_TYPE_APPROVAL_REQUEST} | set(RULE_OFFER_TX_TYPES)
)
from consensus.tx_signing import verify_tx_signature
import tau_native
import tau_advisory
import tau_session
import tau_shrink

from errors import (
    BlockchainBug,
    TauCommunicationError,
    TauEngineBug,
    TauEngineCrash,
    TauSpecIntegrationError,
    TauSpecRejected,
)

# We need to import chain_state and tau_manager, but we must be careful about circular imports.
# We'll import them inside methods or use a lazy import pattern if needed.
import tau_manager
# chain_state will be imported inside methods to avoid circular dependency if chain_state imports this module.

logger = logging.getLogger(__name__)


def _application_rule_landed(rule_text: str) -> bool:
    """True when the preprocessed unit is in the hashed application-rules state.

    `communicate_with_tau(..., apply_rules_update=True)` is supposed to persist
    via `save_effective_tau_spec`. If the handler did not run, a success string
    from Tau is a no-op: the spec is unchanged, but a soft fail would still
    include the tx and charge a fee. Membership here is the honesty check.
    """
    import chain_state

    raw = (rule_text or "").strip()
    if not raw:
        return False
    try:
        unit = chain_state._preprocess_tau_spec_text(raw) or raw
    except Exception:
        unit = raw
    try:
        app = chain_state.get_application_rules_state() or ""
    except Exception:
        return False
    units = [u.strip() for u in app.split("\n") if u.strip()]
    if unit in units or raw in units:
        return True
    return unit in app or raw in app


from dataclasses import dataclass
from abc import ABC, abstractmethod

@dataclass
class ActiveConsensusView:
    """
    Represents the active consensus policy to be used for block validation.
    Derived purely from a parent snapshot state.
    """
    target_height: int
    consensus_rules: str
    active_validators: List[bytes]
    mechanism_specific_metadata: Optional[Dict[str, Any]] = None
    parent_balances: Optional[Dict[str, int]] = None

@dataclass
class TransactionOutcome:
    tx_id: str
    status: str # "applied", "skipped", "invalid"
    reason: Optional[str] = None
    receipt_logs: List[str] = None

@dataclass
class ApplyBlockResult:
    next_snapshot: TauStateSnapshot
    outcomes: List[TransactionOutcome]
    accepted_tx_ids: List[str]
    skipped_tx_ids: List[str]
    invalid_tx_ids: List[str]
    governance_changes: Dict[str, Any]
    mempool_hints: Dict[str, Any]


class ConsensusEngine(ABC):
    """
    Defines the contract for the Tau-driven consensus processing paths.
    Unifies mining, import, replay, and reorg behind a single interface.
    """
    
    @abstractmethod
    def derive_active_consensus(self, parent_snapshot: TauStateSnapshot, target_height: int) -> ActiveConsensusView:
        """
        Pure, read-only derivation of the active consensus view for the target height.
        MUST NOT mutate any state objects or perform archival transitions.
        """
        pass
        
    @abstractmethod
    def verify_block_header(self, active_view: ActiveConsensusView, block: Any, proof_result: Dict[str, Any]) -> bool:
        """
        Complete consensus-verdict step. Encompasses proof result consumption and 
        Tau policy evaluation yielding the final block validity (o6).
        Returns True if the block is accepted.
        """
        pass
        
    @abstractmethod
    def apply_block(
        self,
        active_view: ActiveConsensusView,
        block: Any,
        parent_snapshot: TauStateSnapshot,
        *,
        replay_mode: bool = False,
    ) -> ApplyBlockResult:
        """
        Apply the valid block payload over the active view to produce the next 
        committed snapshot. This includes archival transitions.
        """
        pass
        
    @abstractmethod
    def query_eligibility(self, active_view: ActiveConsensusView, local_pubkey: str, target_height: int, now_ts: int) -> bool:
        """
        Query whether the given identity is eligible to propose the block at the target height 
        and time, according to Tau policy (o7).
        """
        pass

def _apply_composite_rule(composite: Optional[str], tx_receipt: Dict) -> Tuple[bool, str]:
    """Route a regenerated composite rule through i0, as an op-"0" rule would.

    Returns (ok, detail). `composite` is None only when the acceptor's clause
    was the last one for that stream, which cannot happen on an accept, so a
    None here is a programming error rather than a chain condition.

    A rejection is deterministic: every node applying this block composes the
    same text from the same registry and feeds it to the same engine, so all of
    them either accept or hard-reject the transaction identically.
    """
    if not composite:
        return False, "composite is empty"

    if not tau_manager.tau_ready.is_set():
        tau_manager.tau_ready.wait(timeout=5)
    if not tau_manager.tau_ready.is_set():
        # Soft failure shape is not available here: the clause is already
        # registered in the manager, so refusing the tx is the only way to keep
        # the emitted spec and the registry consistent.
        return False, "Tau not ready"

    try:
        output = tau_manager.communicate_with_tau(
            rule_text=composite,
            target_output_stream_index=0,
            # NOT accumulated: apply_rules_update=False feeds the interpreter
            # but skips the rules handler, so the composite never enters the
            # application-rules accumulation. save_effective_tau_spec only
            # dedups EXACT units, so appending left every earlier composite in
            # place -- several per stream, net effect dependent on replay order,
            # and the spec growing with every acceptance. The clause registry is
            # the consensus-bound source of truth and chain_state's restore plan
            # rebuilds the composite from it.
            apply_rules_update=False,
        )
    except Exception as exc:  # noqa: BLE001 - deliberately broad, see below
        # A deterministic parse/compile failure surfaces as an engine error in
        # the exception text. Anything else (transient outage) is equally fatal
        # for this transaction, because the registry has already moved.
        return False, str(exc)

    tx_receipt["logs"].append(f"Tau(composite) o0: {output}")
    if "error" in str(output).lower() and "x1001" not in str(output).lower():
        return False, str(output)
    return True, ""



def _advisory_is_available() -> bool:
    """Whether a separate advisory evaluator can run at all.

    Mock mode has no interpreter to isolate from, and a node with no native
    interface has nothing to contaminate. Both keep the in-process path.
    """
    if getattr(tau_manager, "tau_test_mode", False):
        return False
    return getattr(tau_manager, "tau_direct_interface", None) is not None


class TauConsensusEngine(TauEngine, ConsensusEngine):
    """
    Legacy and transition implementation of the Tau Engine and new Consensus Engine contract.
    
    Handles:
    1. Block signature verification (PoA consensus).
    2. Transaction execution (delegating to Tau process and chain state).
    """

    def __init__(self, state_store: Optional[StateStore] = None) -> None:
        self._state_store = state_store or StateStore()
        # Validator set: strictly ordered list of public keys representing the round robin schedule
        self._validators: List[str] = list(getattr(config, "MINER_PUBKEYS", []) or [])
        if not self._validators and config.MINER_PUBKEY:
             self._validators = [config.MINER_PUBKEY]

    def _active_validator_hexes_from_snapshot(self, parent_snapshot: TauStateSnapshot) -> List[str]:
        metadata = parent_snapshot.metadata or {}
        lifecycle_manager = metadata.get("lifecycle_manager")
        if lifecycle_manager is not None and getattr(lifecycle_manager, "active_validators", None):
            return sorted(normalize_validator_set(lifecycle_manager.active_validators))
        return sorted(normalize_validator_set(self._validators))

    @staticmethod
    def _encode_bv_uint(value: Any, *, width_bits: int, field_name: str) -> str:
        parsed = int(value)
        if parsed < 0 or parsed >= (1 << width_bits):
            raise ValueError(f"{field_name} must fit within bv[{width_bits}]")
        return str(parsed)

    @staticmethod
    def _encode_yid(text: str) -> str:
        return db.get_string_id(text)

    @staticmethod
    def _encode_bv_pubkey_literal(pubkey_hex: str) -> str:
        """A 96-hex BLS pubkey as an in-spec bv[384] literal for stream i13.

        The tau_manager shrink layer interns this to the same node-local id as the
        equality literal `{ #x<hex> }:bv[384]` written into the consensus rule, so
        the membership comparison holds. RAW TauInterface callers (gen_genesis) must
        NOT use this wrapped form -- they feed the bare `#x<hex>` value instead."""
        return "{ #x" + pubkey_hex + " }:bv[384]"

    def _build_consensus_input_streams(
        self,
        *,
        proposer_pubkey: str,
        block_number: Any,
        timestamp: Any,
        previous_hash: str,
        proof_ok: bool,
        claims: Any = None,
        proposer_stake: Any = 0,
        stake_mode: bool = False,
        feed_proposer_pubkey: bool = False,
    ) -> Dict[int, str]:
        canonical_proposer = canonicalize_proposer_yid(proposer_pubkey)
        canonical_parent_hash = canonicalize_parent_hash_yid(previous_hash)
        claims_json = canonical_json(claims if claims is not None else {}).decode("utf-8")

        streams = {
            6: self._encode_bv_uint(block_number, width_bits=64, field_name="block_number"),
            7: self._encode_bv_uint(timestamp, width_bits=64, field_name="timestamp"),
            8: self._encode_yid(canonical_proposer),
            9: self._encode_yid(canonical_parent_hash),
            10: self._encode_bv_uint(1 if proof_ok else 0, width_bits=16, field_name="proof_ok"),
            11: self._encode_yid(claims_json),
            14: self._encode_bv_uint(proposer_stake, width_bits=64, field_name="proposer_stake"),
            15: self._encode_bv_uint(1 if stake_mode else 0, width_bits=16, field_name="eligibility_mode"),
        }
        # i13: proposer pubkey as bv[384], for a rule that tests set membership
        # itself (tau_validator_set). Fed ONLY when the active rule needs it:
        # feeding a bv[384] value on every eval otherwise makes each consensus
        # step pay wide-bitvector cost (~tens of seconds on a loaded host) even
        # in stake / legacy validator_set mode, where no rule references i13.
        if feed_proposer_pubkey:
            streams[13] = self._encode_bv_pubkey_literal(canonical_proposer)
        return streams

    # --- ConsensusEngine Interface Implementation ---

    def derive_active_consensus(self, parent_snapshot: TauStateSnapshot, target_height: int) -> ActiveConsensusView:
        # Skeleton implementation for Phase 1
        # In Phase 2, this will traverse the consensus_meta to build the view. 
        # For now, it delegates to PoA parameters.
        validator_hexes = self._active_validator_hexes_from_snapshot(parent_snapshot)
        # Eligibility mode comes ONLY from the parent snapshot's lifecycle manager
        # (meta-hash-bound), never from per-node config. In stake mode the host
        # membership gate is bypassed and Tau's o7 is the eligibility authority,
        # evaluated against the proposer's PARENT-state balance.
        lm = parent_snapshot.metadata.get("lifecycle_manager")
        mode = (
            lm.effective_eligibility_mode()
            if lm is not None and hasattr(lm, "effective_eligibility_mode")
            else "validator_set"
        )
        # consensus_rules is the CONSENSUS spec (o6/o7), carried in the parent
        # snapshot metadata -- NOT parent_snapshot.tau_bytes, which is the
        # APPLICATION accumulation. Using tau_bytes here meant every non-governance
        # block wrote the application spec into consensus_rules_state, which then
        # failed to parse when replayed via i0 on restart ("Unexpected 'a'").
        # The per-block rule budget travels on the view so proposer and
        # verifier read one authority -- the same governance-patchable value
        # that is bound into consensus_meta_hash.
        rule_tx_budget = getattr(lm, "max_rule_txs_per_block", None)
        if isinstance(rule_tx_budget, bool) or not isinstance(rule_tx_budget, int):
            rule_tx_budget = DEFAULT_MAX_RULE_TXS_PER_BLOCK
        return ActiveConsensusView(
            target_height=target_height,
            consensus_rules=str(parent_snapshot.metadata.get("consensus_rules_state", "") or ""),
            active_validators=[bytes.fromhex(v) for v in validator_hexes],
            mechanism_specific_metadata={
                "poa": mode != "stake",
                "eligibility_mode": mode,
                "max_rule_txs_per_block": rule_tx_budget,
                # Whether i18..i25 are reserved and fed. Read from the PARENT
                # snapshot's manager, so an activation recorded in block H
                # governs H+1 onward and never changes the meaning of the block
                # that carried it.
                "approval_slots_active": bool(
                    getattr(lm, "approval_slots_active", False)
                ),
            },
            parent_balances=parent_snapshot.metadata.get("balances"),
        )

    @staticmethod
    def _stake_mode(active_view) -> bool:
        meta = getattr(active_view, "mechanism_specific_metadata", None) or {}
        return meta.get("eligibility_mode") == "stake"

    @staticmethod
    def _view_eligibility_mode(active_view) -> str:
        meta = getattr(active_view, "mechanism_specific_metadata", None) or {}
        return meta.get("eligibility_mode") or "validator_set"

    @staticmethod
    def _view_rule_tx_budget(active_view) -> Optional[int]:
        """Per-block rule-transaction ceiling carried by the active view.

        Sourced from consensus_meta.mechanism_specific_metadata, which is the
        same place the governance-patchable value is bound into the state hash,
        so proposer and verifier read one authority. Absent means the default
        is in force; a non-integer means the view predates the field and the
        check is skipped rather than failing every block closed.
        """
        meta = getattr(active_view, "mechanism_specific_metadata", None) or {}
        if "max_rule_txs_per_block" not in meta:
            return DEFAULT_MAX_RULE_TXS_PER_BLOCK
        value = meta.get("max_rule_txs_per_block")
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            return None
        return value

    @staticmethod
    def _view_approval_slots_active(active_view) -> bool:
        meta = getattr(active_view, "mechanism_specific_metadata", None) or {}
        return meta.get("approval_slots_active") is True

    @classmethod
    def _counts_against_rule_budget(cls, tx: dict, slots_active: bool) -> bool:
        """Whether this transaction costs an interpreter rebuild.

        The rule-sharing types always do. A user_tx carrying an o5 policy rule
        does too ONCE routing is active, because it re-derives the composite --
        and not counting it would leave the flood vector wide open on the one
        path this feature adds.

        Legacy `operations["0"]` rules stay excluded, for the reason the comment
        at the call site gives: existing chains already contain blocks carrying
        many of them, and counting those retroactively would break replay of
        history. Post-activation routed rules are new, so counting them breaks
        nothing.
        """
        tx_type = tx.get("tx_type", "user_tx")
        if tx_type in RULE_OFFER_TX_TYPES:
            return True
        if not slots_active or tx_type != "user_tx":
            return False
        operations = tx.get("operations")
        if not isinstance(operations, dict):
            return False
        rule_text = operations.get("0")
        if not isinstance(rule_text, str) or not rule_text.strip():
            return False
        return tau_defs.USER_POLICY_STREAM_INDEX in clause_output_streams(rule_text)

    def verify_block_header(self, *args, **kwargs) -> bool:
        """
        Verify that the block header meets the consensus proof requirements.
        Supports both Phase 1 legacy signature and new ConsensusEngine signature.
        """
        active_view = None
        stake_mode = False
        tau_bound = False
        if len(args) > 0 and isinstance(args[0], ActiveConsensusView) or "active_view" in kwargs:
            # Phase 2+ new signature: (active_view, block, proof_result)
            proof_result = kwargs.get("proof_result") if "proof_result" in kwargs else (args[2] if len(args) > 2 else {})
            if proof_result.get("proof_ok", False) is False:
                return False
            block = kwargs.get("block") if "block" in kwargs else (args[1] if len(args) > 1 else None)
            # PoA (validator_set): the proposer must be in the active validator set
            # (skip for genesis, whose proposer is the all-zero sentinel). In
            # tau-authoritative modes (stake, tau_validator_set) the host membership
            # gate is bypassed -- Tau's o7 is the eligibility authority instead
            # (stake: evaluated on parent-state balance; tau_validator_set:
            # evaluated on the proposer pubkey i13 tested inside the rule).
            active_view = args[0] if (args and isinstance(args[0], ActiveConsensusView)) else kwargs.get("active_view")
            stake_mode = active_view is not None and self._stake_mode(active_view)
            tau_bound = active_view is not None and is_tau_authoritative_eligibility_mode(
                self._view_eligibility_mode(active_view))
            if (
                block is not None
                and getattr(block.header, "block_number", None) != 0
                and active_view is not None
                and not tau_bound
                and not getattr(config.settings.authority, "open_governance_admission", False)
            ):
                try:
                    allowed = normalize_validator_set(active_view.active_validators)
                    proposer_hex = (block.header.proposer_pubkey or "").lower()
                except (ValueError, AttributeError):
                    return False
                if allowed and proposer_hex not in allowed:
                    logger.warning(
                        "Consensus: proposer %s not in active validator set for block #%s",
                        proposer_hex[:10], block.header.block_number,
                    )
                    return False
        else:
            # Phase 1 Legacy Signature: (block)
            block = args[0] if len(args) > 0 else kwargs.get("block")
            proof_result = args[1] if len(args) > 1 and isinstance(args[1], dict) else kwargs.get("proof_result", {"proof_ok": True})

        if block and not block.consensus_proof:
            logger.warning("Consensus: Block #%s has no consensus proof", block.header.block_number)
            return False

        # Per-block rule-transaction budget. Applying a rule regenerates and
        # recompiles a composite, whose cost climbs steeply with specification
        # complexity; without a ceiling a proposer could author a block that
        # every validator times out on (COMM_TIMEOUT, then a watchdog kill).
        # This is consensus, not policy: over-budget blocks are invalid.
        #
        # Counts ONLY the rule-sharing types. Legacy operations["0"] user_tx
        # rules are deliberately excluded, because existing chains may already
        # contain blocks carrying many of them and counting those would break
        # replay of history. That flood vector is pre-existing and separate.
        if block is not None and active_view is not None:
            budget = self._view_rule_tx_budget(active_view)
            if budget is not None:
                slots_active = self._view_approval_slots_active(active_view)
                rule_txs = sum(
                    1 for tx in (getattr(block, "transactions", None) or [])
                    if isinstance(tx, dict)
                    and self._counts_against_rule_budget(tx, slots_active)
                )
                if rule_txs > budget:
                    logger.warning(
                        "Consensus: block #%s carries %d rule txs, over the "
                        "per-block budget of %d",
                        getattr(block.header, "block_number", "?"), rule_txs, budget,
                    )
                    return False

        if not tau_manager.tau_ready.is_set():
            logger.error("Consensus: Tau not ready for block verification.")
            return False
            
        try:
            proposer_stake = 0
            if stake_mode:
                balances = getattr(active_view, "parent_balances", None)
                if balances is None:
                    # Stake mode requires deterministic parent-state balances; a
                    # verify path that cannot supply them must fail closed.
                    logger.error(
                        "Consensus: stake-mode verify without parent balances for block #%s",
                        getattr(getattr(block, "header", None), "block_number", "?"),
                    )
                    return False
                proposer_stake = int(balances.get((block.header.proposer_pubkey or "").lower(), 0))
            tau_inputs = self._build_consensus_input_streams(
                proposer_pubkey=block.header.proposer_pubkey,
                block_number=block.header.block_number,
                timestamp=block.header.timestamp,
                previous_hash=block.header.previous_hash,
                proof_ok=bool(proof_result.get("proof_ok", False)),
                claims=proof_result.get("claims"),
                proposer_stake=proposer_stake,
                stake_mode=stake_mode,
                feed_proposer_pubkey=(active_view is not None
                                      and self._view_eligibility_mode(active_view) == "tau_validator_set"),
            )
            if tau_bound:
                # Tau-authoritative modes (stake, tau_validator_set): both o6
                # (validity) and o7 (eligibility) must be nonzero.
                # tau_comm_lock is taken inside communicate_with_tau_multi too; it
                # is an RLock, so this outer hold is a (harmless) wider atomic
                # region. Missing o7 parses to 0 -> fail closed (a non-member's
                # block is rejected).
                # VALIDATION, not committed execution. A header can be verified
                # more than once, verified and rejected, arrive from a peer, or be
                # checked without ever becoming the next block -- none of which
                # should move the authoritative history. Stepping is not
                # read-only, so this runs on the isolated evaluator when there is
                # one. (The shipped consensus rules carry no `[t-N]` reference, so
                # a history-free evaluator answers identically; a governance
                # update that introduced one would need this revisited.)
                outputs = None
                if _advisory_is_available():
                    outputs = tau_advisory.evaluator().evaluate_many(
                        tau_manager.get_canonical_spec() or "", tau_inputs, (6, 7)
                    )
                if outputs is None:
                    with tau_manager.tau_comm_lock:
                        outputs = tau_manager.communicate_with_tau_multi(
                            input_stream_values=tau_inputs,
                            source="consensus_verify",
                            apply_rules_update=False,
                        )
                o6_raw = outputs.get(6, "")
                o7_raw = outputs.get(7, "")
                output = str(o6_raw)
                verdict = (
                    tau_manager.parse_tau_output(str(o6_raw)) != 0
                    and tau_manager.parse_tau_output(str(o7_raw)) != 0
                )
                if verdict:
                    return True
            else:
                # Same category: validation must not mutate authoritative state.
                output = None
                if _advisory_is_available():
                    output = tau_advisory.evaluator().evaluate(
                        tau_manager.get_canonical_spec() or "", tau_inputs, target=6
                    )
                if output is None:
                    output = tau_manager.communicate_with_tau(
                        target_output_stream_index=6,
                        input_stream_values=tau_inputs,
                        apply_rules_update=False
                    )
                verdict = tau_manager.parse_tau_output(str(output)) != 0
                if verdict:
                    return True
            if "require_bls_sig" in output:
                try:
                    from py_ecc.bls import G2Basic
                    import hashlib
                    block_sig = block.consensus_proof
                    if isinstance(block_sig, dict):
                        block_sig = block_sig.get("signature")
                    if not block_sig:
                        logger.warning("Consensus: Block #%s missing cryptographic proof", block.header.block_number)
                        return False
                    msg_hash = hashlib.sha256(block.header.canonical_bytes()).digest()
                    pubkey_bytes = bytes.fromhex(block.header.proposer_pubkey)
                    sig_bytes = bytes.fromhex(block_sig)
                    if not G2Basic.Verify(pubkey_bytes, msg_hash, sig_bytes):
                        logger.warning("Consensus: Block #%s cryptographic proof failed", block.header.block_number)
                        return False
                except Exception as e:
                    logger.warning("Consensus: Block #%s cryptographic proof error: %s", block.header.block_number, e)
                    return False
                return True
            
            logger.warning("Consensus: Block #%s rejected by Tau rules (o6: %s)", block.header.block_number, output)
            return False
        except Exception as e:
            logger.error("Header verification failed: %s", e)
            return False

    def apply_block(
        self,
        active_view: ActiveConsensusView,
        block: Any,
        parent_snapshot: TauStateSnapshot,
        *,
        session=None,
        replay_mode: bool = False,
    ) -> ApplyBlockResult:
        """
        Executes a full block over the consensus boundaries.
        Unifies Rebuild, Process Block, and Mining paths.
        Pure Implementation: Operates on state passed implicitly through parent_snapshot.metadata and returns ApplyBlockResult.
        """
        import copy
        from consensus.state import compute_consensus_state_hash
        from chain_state import compute_accounts_hash
        import chain_state

        # 1. State Extraction
        metadata = parent_snapshot.metadata
        t_bals = copy.deepcopy(metadata.get('balances', {}))
        # Third per-account overlay, same commit-on-accept discipline (issue #21).
        t_lts = copy.deepcopy(metadata.get('last_transfer_ts', {}) or {})
        t_seqs = copy.deepcopy(metadata.get('sequence_numbers', {}))
        # Pre-block total supply, captured before apply mutates t_bals.
        parent_total = sum(int(v) for v in t_bals.values())

        # Make a deep copy of the lifecycle manager or instantiate a snapshot equivalent
        parent_lm = metadata.get('lifecycle_manager')
        if parent_lm:
            # Reconstruct an isolated instance 
            lm = copy.deepcopy(parent_lm)
        else:
            # Fallback if somehow not provided (tests, legacy)
            from consensus.governance import ConsensusLifecycleManager
            lm = ConsensusLifecycleManager(active_validators=[bytes.fromhex(v) for v in self._validators])
        
        # 2. Pure Transaction Simulation (Internal Layer)
        # We pass target_balances and target_sequences to self.apply which mutates them internally.
        # This acts as our pure executor since t_bals/t_seqs are local copies.
        exec_result = self.apply(
            parent_snapshot,
            block.transactions,
            block.header.timestamp,
            target_balances=t_bals,
            target_sequences=t_seqs,
            target_lifecycle=lm,
            replay_mode=replay_mode,
            proposer_pubkey=block.header.proposer_pubkey,
            block_height=block.header.block_number,
            # i2 (sender balance) is fed from the PARENT snapshot, so proposer
            # and verifier read the same map and agree exactly (issue #20).
            # metadata['balances'] is the pre-block state; t_bals above is the
            # mutable copy apply() debits, and must NOT be used for i2.
            parent_balances=metadata.get('balances'),
            parent_last_transfer_ts=metadata.get('last_transfer_ts'),
            session=session,
            target_last_transfer_ts=t_lts,
        )

        # Conservation invariant: the native fee model debits the sender and
        # credits the proposer through the same staged_writes pass, so total
        # supply is preserved across a block (no mint, no burn). A mismatch is
        # a consensus bug, not a recoverable error.
        post_total = sum(int(v) for v in t_bals.values())
        if post_total != parent_total and not getattr(config, "TESTNET_AUTO_FAUCET", False):
            raise BlockchainBug(
                f"Supply not conserved applying block #{block.header.block_number}: "
                f"parent_total={parent_total} post_total={post_total}"
            )

        # Convert internal apply result into structural outcomes
        outcomes = []
        accepted_ids = []
        skipped_ids = []
        
        for tx in block.transactions:
            tx_id = tx.get('tx_id')
            if tx in exec_result.accepted_transactions:
                # We consider all accepted ones as "applied" or "skipped/no-op"
                # Internal execution logs tell us if it was essentially a no-op 
                status = "applied"
                receipt = exec_result.receipts.get(tx_id, {})
                logs = receipt.get("logs", [])
                if any("valid no-op" in log.lower() or "ignored" in log.lower() for log in logs):
                    status = "skipped/no-op"
                    skipped_ids.append(tx_id)
                else:
                    accepted_ids.append(tx_id)
                    
                outcomes.append(TransactionOutcome(tx_id=tx_id, status=status, receipt_logs=logs))
            elif tx in exec_result.rejected_transactions:
                status = "invalid"
                receipt = exec_result.receipts.get(tx_id, {})
                outcomes.append(TransactionOutcome(tx_id=tx_id, status=status, reason=receipt.get("error"), receipt_logs=receipt.get("logs", [])))

        # 3. Post-State Materialization Layer
        
        # The rules are updated by self.apply (it returns a generic snapshot with tau_bytes).
        next_app_rules = exec_result.snapshot.tau_bytes.decode('utf-8', errors='ignore')
        
        # Governance Height Transitions.
        #
        # The effective spec is handed down so an approval-slot activation can
        # audit it before flipping the flag: reserving i18..i25 and routing o5
        # rules are consensus-visible changes, and a rule already typing a slot
        # (or a legacy raw o5 writer) would poison process-global stream typing.
        # Everything in this corpus is hash-bound state, so every node computes
        # the same verdict.
        effective_spec_texts = [
            ("consensus_rules", active_view.consensus_rules or ""),
            ("application_rules", next_app_rules or ""),
        ]
        try:
            effective_spec_texts.extend(
                ("builtin_rule_%d" % n, text)
                for n, text in enumerate(chain_state.load_builtin_rules_from_disk() or [])
            )
        except Exception:  # noqa: BLE001 - the audit is best-effort on disk reads
            logger.warning("Could not read builtin rules for the activation audit")
        effective_spec_texts.extend(
            ("clause_%s_o%d" % (acceptor[:10], stream), body)
            for (acceptor, stream), body in
            sorted(getattr(lm.rule_offers, "accepted_clauses", {}).items())
        )
        newly_active = lm.process_height_transitions(
            block.header.block_number, effective_spec_texts=effective_spec_texts
        )
        next_cons_rules = active_view.consensus_rules
        next_active_consensus_id = parent_snapshot.metadata.get("active_consensus_id", "")
        if newly_active:
            # Route every activated revision through `i0` in declaration order.
            # The genesis `i0 -> u` routing emits an `Updated specification:`
            # marker on stdout and tau_native rebuilds the interpreter from
            # that output, so the live spec advances exactly the same way it
            # does for user_tx ops['0'] application-rule changes.
            #
            # Activation revisions intentionally do NOT trigger the
            # rules-handler (`apply_rules_update=False`): consensus provenance
            # is updated via the deterministic `"\n".join(rule_revisions)` tag
            # written into `next_snapshot.metadata["consensus_rules_state"]`
            # below, not via the live spec extracted from stdout. Letting the
            # handler fire here would briefly write a partially-stripped
            # intermediate into `_application_rules_state` (the old consensus
            # prefix no longer matches the post-revision spec) and persist a
            # polluted `full_tau_spec` to the DB before the snapshot commit
            # overwrites it.
            for update in newly_active:
                tag = f"governance_activation:{update.update_id_hex[:16]}"
                for rev in update.rule_revisions:
                    if not isinstance(rev, str) or not rev.strip():
                        continue
                    try:
                        output = tau_manager.communicate_with_tau(
                            rule_text=rev,
                            target_output_stream_index=0,
                            source=tag,
                            apply_rules_update=False,
                        )
                        if output and "error" in output.lower() and "x1001" not in output.lower():
                            raise FeeRuleError(
                                f"Governance rule activation revision rejected by live Tau interpreter: {output}"
                            )
                    except (TauCommunicationError, TauEngineBug, TauEngineCrash) as e:
                        # Triggers round abort (proposer) or block deferral (validator),
                        # preventing state divergence.
                        raise FeeRuleError(
                            f"Governance rule activation rejected by live Tau interpreter "
                            f"at height {block.header.block_number}: {e}"
                        )
            last_update = newly_active[-1]
            # Provenance tag used by `compute_consensus_state_hash`. Every node
            # derives this string deterministically from `last_update.rule_revisions`,
            # so the resulting state hash is independent of the live interpreter.
            next_cons_rules = "\n".join(last_update.rule_revisions)
            next_active_consensus_id = last_update.update_id_hex[:16]
        
        # Finalize Hashes
        acc_hash = compute_accounts_hash(t_bals, t_seqs)
        meta_hash = lm.consensus_meta_hash()
        state_hash = compute_consensus_state_hash(next_cons_rules.encode('utf-8'), next_app_rules.encode('utf-8'), acc_hash, meta_hash)

        # Phase 9B instrumentation: dump the four state-hash components so a
        # mine-vs-replay divergence at a post-activation block can be pinned to
        # a single component. Zero cost unless TAU_HASH_TRACE is set.
        if os.environ.get("TAU_HASH_TRACE"):
            import hashlib as _hl
            def _h(b):
                return _hl.sha256(b if isinstance(b, bytes) else str(b).encode()).hexdigest()[:16]
            logger.warning(
                "[HASH_TRACE] blk=%s replay=%s state=%s | cons=%s app=%s acc=%s meta=%s "
                "| newly_active=%s cons_rules_len=%d app_rules_len=%d",
                block.header.block_number, replay_mode, state_hash[:16],
                _h(next_cons_rules.encode('utf-8')), _h(next_app_rules.encode('utf-8')),
                acc_hash[:16] if isinstance(acc_hash, str) else _h(acc_hash),
                meta_hash.hex()[:16] if isinstance(meta_hash, bytes) else _h(meta_hash),
                [u.update_id_hex[:12] for u in newly_active],
                len(next_cons_rules), len(next_app_rules),
            )
            if os.environ.get("TAU_HASH_TRACE") == "2":
                logger.warning(
                    "[HASH_TRACE_ACC] blk=%s replay=%s accounts=%s",
                    block.header.block_number, replay_mode,
                    sorted((a[:12], int(t_bals.get(a, 0)), int(t_seqs.get(a, 0)))
                           for a in (set(t_bals) | set(t_seqs))),
                )

        # 4. Construct Next Snapshot
        next_snapshot = TauStateSnapshot(
            state_hash=state_hash,
            tau_bytes=next_app_rules.encode('utf-8'),
            metadata={
                "source": "engine_apply_block",
                "balances": t_bals,
                "sequence_numbers": t_seqs,
                "last_transfer_ts": t_lts,
                "lifecycle_manager": lm,
                "consensus_rules_state": next_cons_rules,
                "active_consensus_id": next_active_consensus_id
            }
        )
        
        return ApplyBlockResult(
            next_snapshot=next_snapshot,
            outcomes=outcomes,
            accepted_tx_ids=accepted_ids,
            skipped_tx_ids=skipped_ids,
            invalid_tx_ids=[tx.get('tx_id') for tx in exec_result.rejected_transactions],
            governance_changes={"activated_updates": [u.update_id_hex for u in newly_active]},
            mempool_hints={"safe_to_drop": accepted_ids + skipped_ids}
        )

    @staticmethod
    def _advisory_available() -> bool:
        return _advisory_is_available()

    def query_eligibility(self, *args, **kwargs) -> bool:
        """
        Check if we are eligible to propose the next block by dry-running consensus logic.
        Supports both Phase 1 legacy signature and new ConsensusEngine signature.
        """
        if len(args) > 0 and isinstance(args[0], ActiveConsensusView) or "active_view" in kwargs:
            # new signature: (active_view, local_pubkey, target_height, now_ts)
            my_pubkey = kwargs.get("local_pubkey") if "local_pubkey" in kwargs else (args[1] if len(args) > 1 else "")
            block_number = kwargs.get("target_height") if "target_height" in kwargs else (args[2] if len(args) > 2 else 0)
            timestamp = kwargs.get("now_ts") if "now_ts" in kwargs else (args[3] if len(args) > 3 else 0)
            previous_hash = "0" * 64
        else:
            # legacy signature: (my_pubkey, block_number, timestamp, previous_hash)
            my_pubkey = args[0] if len(args) > 0 else kwargs.get("my_pubkey")
            block_number = args[1] if len(args) > 1 else kwargs.get("block_number")
            timestamp = args[2] if len(args) > 2 else kwargs.get("timestamp")
            previous_hash = args[3] if len(args) > 3 else kwargs.get("previous_hash")

        if not tau_manager.tau_ready.is_set():
            return False
            
        try:
            # Advisory dry-run only (never binds validity), so tip state is
            # acceptable here. Use committed balance (no auto-faucet shim).
            import chain_state
            lm = getattr(chain_state, "_lifecycle_manager", None)
            mode = getattr(lm, "effective_eligibility_mode", lambda: "validator_set")() if lm is not None else "validator_set"
            stake_mode = mode == "stake"
            my_stake = chain_state.get_committed_balance((my_pubkey or "").lower()) if stake_mode else 0
            tau_inputs = self._build_consensus_input_streams(
                proposer_pubkey=my_pubkey,
                block_number=block_number,
                timestamp=timestamp,
                previous_hash=previous_hash,
                proof_ok=True,
                claims={},
                proposer_stake=my_stake,
                stake_mode=stake_mode,
                feed_proposer_pubkey=(mode == "tau_validator_set"),
            )
            # ADVISORY, and isolated for it. This used to step the authoritative
            # interpreter: measured, one such query between two authoritative
            # inputs changed the next history-dependent verdict from 5 to 255,
            # because the query's own input became the following transaction's
            # `i1[t-1]`. The miner runs this every round. The advisory evaluator
            # is a separate process in canonical representation; if it cannot
            # answer, fall back to the old path rather than stop mining.
            output = None
            if _advisory_is_available():
                output = tau_advisory.evaluator().evaluate(
                    tau_manager.get_canonical_spec() or "",
                    tau_inputs,
                    target=7,
                )
            if output is None:
                output = tau_manager.communicate_with_tau(
                    target_output_stream_index=7,
                    input_stream_values=tau_inputs,
                    apply_rules_update=False
                )
            verdict = tau_manager.parse_tau_output(str(output))
            if verdict != 0:
                return True
            if "require_bls_sig" in output:
                return True
            return False
        except Exception as e:
            logger.error("Eligibility query failed: %s", e)
            return False

    def apply(
        self,
        snapshot: TauStateSnapshot,
        transactions: Sequence[Dict[str, Any]],
        block_timestamp: int | None = None,
        target_balances: Optional[Dict[str, int]] = None,
        target_sequences: Optional[Dict[str, int]] = None,
        target_lifecycle: Optional[Any] = None,
        replay_mode: bool = False,
        proposer_pubkey: Optional[str] = None,
        block_height: Optional[int] = None,
        parent_balances: Optional[Dict[str, int]] = None,
        parent_last_transfer_ts: Optional[Dict[str, int]] = None,
        target_last_transfer_ts: Optional[Dict[str, int]] = None,
        session=None,
    ) -> TauExecutionResult:
        """
        Apply transactions to the current state.

        This executes operations:
        - '0' (Rules): Sent to Tau process.
        - '1' (Transfers): Applied to chain_state balances.

        Fee model: when `proposer_pubkey` is supplied together with a
        `target_balances` overlay, every accepted user_tx is charged
        total_fee = sum over its Tau steps of (o9 consensus fee + o8 user
        custom fee), capped by the signed `fee_limit` field, and the fee is
        credited to the proposer. o9 absent -> fee 0 (model inactive).
        A FeeRuleError (invalid o9 from the voted consensus rules) is
        strict and propagates: callers must abort the proposal / defer the
        block rather than guess a fee.
        """
        import chain_state  # Import here to avoid circular dependency

        if block_timestamp is None:
            block_timestamp = 0
            
        lifecycle_mgr = target_lifecycle if target_lifecycle is not None else chain_state._lifecycle_manager
        # The evaluator this apply drives. The default binds to THIS module's
        # `tau_manager` reference rather than importing its own, so a caller that
        # substitutes the manager -- which is how much of the suite drives apply --
        # substitutes the evaluator too, exactly as before. A caller that wants
        # continuity across blocks passes its own session.
        _session = (
            session if session is not None
            else tau_session.InProcessSession(manager=tau_manager)
        )

        accepted_txs = []
        rejected_txs = []
        receipts = {}

        # Track the serialized Tau/rules snapshot bytes.
        # In production, `tau_manager` prints the normalized updated specification
        # after successful pointwise revision; `chain_state.save_rules_state(...)`
        # persists that string. When that is available, we use it to build the
        # snapshot. In tests/mocks (no rules handler), fall back to concatenating
        # rule payloads for determinism.
        current_tau_bytes = snapshot.tau_bytes

        # Fee charging requires the isolated balance overlay: there is no
        # proposer-credit primitive on the direct chain_state mutation path
        # (only legacy tests use it), and staged commit-on-accept semantics
        # depend on the overlay.
        fees_enabled = bool(proposer_pubkey) and target_balances is not None
        if bool(proposer_pubkey) and target_balances is None:
            logger.error(
                "Fee charging requested without target_balances overlay; fees skipped (legacy path)."
            )

        # Levy destination for this block. Read from the PARENT lifecycle manager,
        # which is what `lifecycle_mgr` holds during apply: height transitions run
        # after apply() returns, so a beneficiary patch activating at height H
        # governs H+1 onward and never retroactively redirects H's own fees.
        # "" means credit the proposer.
        fee_beneficiary = getattr(lifecycle_mgr, "effective_fee_beneficiary", lambda: "")()

        # i2 (sender balance) source for this block: the PARENT snapshot, frozen
        # for the whole block (issue #20). Shallow-copied because the caller's
        # dict IS chain_state._balances on every production path, and that global
        # is cleared/rebuilt under lock elsewhere — reading it lazily inside the
        # tx loop would make i2 depend on another thread's timing.
        #
        # Consequence to know: two transfers from the same sender in one block
        # both see the same pre-block balance, so a min-balance floor does not
        # compound within a block. The block-build re-check remains the backstop.
        parent_bals = dict(parent_balances or {})
        if parent_balances is None and target_balances is not None:
            # Legacy direct-apply callers (tests) that never pass a parent map.
            # Feed 0 rather than guessing from the mutable overlay, which would
            # make i2 depend on transaction order within the block.
            logger.debug("apply() without parent_balances; i2 will be fed as 0.")

        def _parent_bal(addr: Optional[str]) -> str:
            """i2 for `addr`, clamped to the width the rules declare for it.

            Applies the same TESTNET_AUTO_FAUCET substitution the debit path uses
            further down. Without it Tau would see 0 for a faucet-funded account
            while the transfer succeeded against a synthetic 100000, so a
            min-balance rule would reject a send that then went through. This does
            make i2 depend on a per-node flag — but that flag already has to match
            network-wide (it also exempts the supply-conservation invariant), and
            being inconsistent *within* one node is the worse, silent failure.
            """
            try:
                value = int(parent_bals.get(addr, 0)) if addr else 0
            except (TypeError, ValueError):
                value = 0
            if value == 0 and getattr(config, "TESTNET_AUTO_FAUCET", False):
                value = int(getattr(config, "TESTNET_AUTO_FAUCET_AMOUNT", 100000))
            return str(max(0, min(value, tau_defs.MAX_TRANSFER_VALUE)))

        # i16: seconds since this sender's previous transfer, read from the
        # PARENT snapshot like i2 (issue #21). Host-computed rather than exposing
        # the raw timestamp, so a cooldown rule is a single comparison with no bv
        # subtraction and no underflow question at "never sent".
        parent_lts = dict(parent_last_transfer_ts or {})

        cooldown_active = getattr(tau_defs, "COOLDOWN_STREAM_ACTIVE", False)

        # Co-signature approval slots. Read from the lifecycle manager this apply
        # is mutating -- which is the deep copy of the PARENT manager, so an
        # activation recorded in block H governs H+1 onward and never changes the
        # meaning of the block that carried it.
        approval_slots_on = getattr(lifecycle_mgr, "approval_slots_active", False) is True

        def _approval_slot_values(overlay=None):
            """The i18..i25 feed for one transfer, or None while inactive.

            Inactive returns None so nothing extra is fed and a pre-activation
            node evaluates byte-identical inputs. Active returns 0 on every slot
            unless `overlay` names an approver who actually voted -- and 0 equals
            no pubkey, so a co-signature clause keeps blocking until real votes
            arrive.
            """
            if not approval_slots_on:
                return None
            values = {idx: "0" for idx in tau_defs.approval_slot_indices()}
            if overlay:
                for slot, pubkey in overlay.items():
                    text = str(pubkey or "")
                    # WRAPPED literal, exactly as i3/i4/i12 are fed. tau_shrink
                    # interns the bv[384] pubkey literals inside a clause down to
                    # bv[8] ids, and it recognises a value to intern by this
                    # `{ #x.. }:bv[384]` shape. Fed as bare hex the value skips
                    # interning and a 384-bit constant lands on a bv[8] stream:
                    # "overflow in bit-vector construction", the whole block
                    # fails simulation, and block production wedges. Only a live
                    # node with shrink ON shows this -- a mocked engine does not
                    # care how the value is spelled.
                    values[int(slot)] = (
                        "{ #x" + text + " }:bv[%d]" % tau_defs.APPROVAL_SLOT_BV_WIDTH
                        if text and text != "0" else "0"
                    )
            return values

        def _since_last_transfer(addr: Optional[str]) -> str:
            """bv[64] seconds since `addr` last sent, sentinel when never."""
            try:
                previous = int(parent_lts.get(addr, 0)) if addr else 0
            except (TypeError, ValueError):
                previous = 0
            if previous <= 0:
                # Never sent: any cooldown must pass. Saturate rather than wrap.
                return str(tau_defs.COOLDOWN_NEVER_SENT)
            elapsed = int(block_timestamp or 0) - previous
            # A non-monotonic block timestamp must not produce a negative (which
            # would wrap to a huge bv value and silently satisfy the cooldown).
            return str(max(0, min(elapsed, tau_defs.COOLDOWN_NEVER_SENT)))

        for i, tx in enumerate(transactions):
            tx_id = tx.get('tx_id', str(i)) # Fallback if no ID
            operations = tx.get('operations', {})
            sender = tx.get('sender_pubkey')
            
            # By default, we consider the transaction valid for inclusion unless strictly malformed
            # (e.g. signature issues are handled in verify_block, here we might assume validity).
            # However, historically we used tx_success to mean "execution successful".
            # We now split this:
            # - accepted_in_block: True (unless we decide it's total garbage)
            # - execution_success: True/False
            
            accepted_in_block = True
            hard_reject = False
            execution_success = True
            tx_receipt = {"logs": []}

            # Expiration recheck against the deterministic block timestamp
            # (admission checks wall clock; this is the consensus-side gate).
            expiration_time = tx.get('expiration_time')
            if block_timestamp and isinstance(expiration_time, int) and block_timestamp > expiration_time:
                if not replay_mode:
                    accepted_in_block = False
                    hard_reject = True
                execution_success = False
                tx_receipt["logs"].append("Transaction expired at block timestamp")

            # The same question asked of the height, which the proposer cannot
            # choose: `block_timestamp` above is picked by whoever builds the
            # block, within the clock tolerance, so the timestamp gate alone
            # lets a proposer hold a transaction past its deadline or bury a
            # live one. Absent means a transaction written before heights
            # existed: those still replay, and admission is what refuses a new
            # one without it.
            expire_at_height = tx.get('expire_at_height')
            if (block_height is not None and isinstance(expire_at_height, int)
                    and not isinstance(expire_at_height, bool)
                    and int(block_height) >= expire_at_height):
                if not replay_mode:
                    accepted_in_block = False
                    hard_reject = True
                execution_success = False
                tx_receipt["logs"].append(
                    f"Transaction expired at height {expire_at_height} "
                    f"(block {block_height})"
                )

            # Sequence number handling: only increment if the tx is included/accepted.
            sequence_number = tx.get('sequence_number')
            should_increment_seq = False
            if sequence_number is not None and sender:
                if target_sequences is not None:
                    current_seq = target_sequences.get(sender, 0)
                else:
                    current_seq = chain_state.get_sequence_number(sender)
                    
                if sequence_number == current_seq:
                    should_increment_seq = True
                else:
                    logger.warning(
                        "Sequence mismatch for %s: expected %s, got %s",
                        sender,
                        current_seq,
                        sequence_number,
                    )
                    accepted_in_block = False
                    hard_reject = True
                    execution_success = False
                    tx_receipt["logs"].append(
                        f"Invalid sequence number: expected {current_seq}, got {sequence_number}"
                    )

            # Process operations
            # Parse operations first to establish deterministic order:
            # 1. Rule update (key "0")
            # 2. Custom inputs (keys >= 5)
            # 3. Transfers (key "1") - applied last to state, though input validation happened upstream

            tx_type = tx.get('tx_type', 'user_tx')

            # --- Fee preamble ---
            # Governance txs are exempt by design so validators never need
            # funds to govern. The rule-sharing types are NOT exempt: they are
            # user-initiated and expensive, and exempting them would make rule
            # spam free. They carry no transfers, so the transfer-less
            # fee-query step below covers them.
            charge_fee = fees_enabled and tx_type in FEE_BEARING_TX_TYPES
            fee_limit_int: Optional[int] = None
            fee_components: List[int] = []
            staged_writes: Dict[str, int] = {}
            # An approval_request prices itself with the REAL transfer inputs, so
            # the generic transfer-less fee-query step (which feeds the canonical
            # mocked i1=i2=i3=i4=0) must not run for it as well and charge twice.
            fee_already_measured = False
            # Set when this tx parked an approval request. Parking is committed
            # in the apply branch below, but the fee is settled afterwards and
            # can still hard-reject the tx -- and hard_reject suppresses staged
            # balances and nonces without rolling lifecycle mutations back. A
            # request whose tx paid nothing must not stay parked, so it is
            # withdrawn after settlement. Deterministic: every node measures the
            # same fee against the same signed fee_limit and balance.
            parked_request_id: Optional[bytes] = None

            def _read_bal(addr: str) -> int:
                """Balance as seen through this tx's staged writes."""
                if addr in staged_writes:
                    return staged_writes[addr]
                if target_balances is not None and addr in target_balances:
                    return target_balances[addr]
                return chain_state.get_balance(addr)

            def _apply_o5_clause_routing(rule_text):
                """Register or revoke the sender's o5 clause. True when handled.

                False means "not an o5 policy rule, or routing is inactive", and
                the caller takes the ordinary accumulation path unchanged.

                Mirrors admission.validate_o5_clause_routing. A clause that does
                not land is hard-rejected: a soft no-op would let a rule-only
                tx sit in the block, pay the fee, and leave the spec unchanged.
                """
                nonlocal accepted_in_block, hard_reject, execution_success

                def _did_not_land(log_msg, reason="rule_not_applied"):
                    nonlocal accepted_in_block, hard_reject, execution_success
                    tx_receipt["logs"].append(log_msg)
                    accepted_in_block = False
                    hard_reject = True
                    execution_success = False
                    tx_receipt["reason"] = reason

                if not approval_slots_on:
                    return False
                if tau_defs.USER_POLICY_STREAM_INDEX not in clause_output_streams(rule_text):
                    return False

                if not isinstance(sender, str):
                    _did_not_land("o5 clause ignored (no sender)")
                    return True

                offers = lifecycle_mgr.rule_offers
                approvals_mgr = lifecycle_mgr.approval_requests
                sender_n = sender.lower()
                stream = tau_defs.USER_POLICY_STREAM_INDEX

                try:
                    body = clause_body_v1(rule_text)
                except RuleOfferShapeError as exc:
                    # The commonest case is the OLD guarded form: accumulated
                    # rules must carry an i12 guard, registered clauses must not.
                    _did_not_land(f"o5 clause ignored ({exc})")
                    return True

                # Same screen admission runs, so the two paths reject the same
                # clause bodies. Imported lazily: consensus.admission pulls in
                # the facade and chain_state, and chain_state imports this
                # module, so a module-level import would be a cycle.
                from consensus.admission import _screen_clause_domains, _width_mismatch_details

                domain_error = _screen_clause_domains(body)
                if domain_error:
                    reason = (
                        "width_mismatch"
                        if _width_mismatch_details(domain_error)
                        else "rule_not_applied"
                    )
                    _did_not_land(f"o5 clause ignored ({domain_error})", reason=reason)
                    return True

                key = (sender_n, stream)
                revoking = is_neutral_clause_body(body, stream)
                registered = key in offers.accepted_clauses

                if revoking and not registered:
                    _did_not_land(
                        "o5 clause revocation ignored (nothing registered)")
                    return True
                if not revoking and not registered:
                    if len(offers.clauses_for_stream(stream)) >= MAX_TIER_AUTHORS:
                        _did_not_land(
                            f"o5 clause ignored (registry full: {MAX_TIER_AUTHORS} authors)")
                        return True

                # A request snapshots its approvers but re-evaluates the CURRENT
                # clause, so changing the clause under an open request would
                # silently change what its recorded votes mean, or strand it
                # until expiry. Resolve them first, in canonical id order.
                doomed = approvals_mgr.resolve_all_for_sender(sender_n, STATUS_FAILED)
                if doomed:
                    tx_receipt["logs"].append(
                        "Policy change failed %d open approval request(s)" % len(doomed))

                if revoking:
                    offers.accepted_clauses.pop(key, None)
                else:
                    offers.accepted_clauses[key] = body

                composite = offers.composite_for_stream(stream)
                if composite is None:
                    # The registry is empty now. Feeding nothing would leave the
                    # PREVIOUS composite in force on this already-running
                    # interpreter while a restarted node -- whose restore plan
                    # emits no composite for an empty registry -- would allow the
                    # transfer. Same block, two verdicts. So feed the neutral
                    # composite explicitly: it supersedes the old one, and "o5
                    # emits allow" and "o5 is never mentioned" are the same
                    # verdict.
                    composite = "always ( %s )." % NEUTRAL_O5_CLAUSE_BODY

                ok_apply, detail = _apply_composite_rule(composite, tx_receipt)
                if not ok_apply:
                    accepted_in_block = False
                    hard_reject = True
                    execution_success = False
                    tx_receipt["logs"].append(f"Error: o5 composite rejected: {detail}")
                else:
                    tx_receipt["logs"].append(
                        "o5 clause %s for %s"
                        % ("revoked" if revoking else "registered", sender_n[:10])
                    )
                return True

            def _transfer_input_map(from_addr, to_addr, amount,
                                    slot_values=None, overrides=None):
                """The per-transfer Tau input map. ONE definition, on purpose.

                The overlay ORDER is load-bearing (tau_defs documents it): the
                same keys in the same sequence must be built at mempool
                admission and at block apply, or a rule combining a custom
                stream with the transfer fields is enforced differently on the
                two paths. Every apply-side caller -- an ordinary transfer, a
                parked-transfer fee measurement, a released transfer -- goes
                through here so there is nothing to keep in step by hand.
                """
                values = {
                    1: str(amount),
                    # i2 (balance) at the PARENT snapshot: frozen for
                    # the whole block, so proposer and verifier read
                    # the same value and a balance-reading policy rule
                    # is deterministic across both (issue #20).
                    2: _parent_bal(from_addr),
                    **({16: _since_last_transfer(from_addr)} if cooldown_active else {}),
                    # i3/i4 are the real from/to pubkeys (immutable in
                    # the transfer tuple -> identical at admission and
                    # apply), so recipient-aware policy/fee rules are
                    # deterministic across the two.
                    3: "{ #x" + str(from_addr) + " }:bv[384]",
                    4: "{ #x" + str(to_addr) + " }:bv[384]",
                }
                values[12] = "{ #x" + str(from_addr) + " }:bv[384]"
                for k, v in (overrides or {}).items():
                    values[k] = v
                # Approval slots, fed after the custom merge and before i5,
                # byte-identically to the admission overlay order in
                # commands/sendtx.py. Reserved, so a sender cannot pre-fill one.
                for slot, slot_val in (slot_values or {}).items():
                    values[slot] = slot_val
                values[5] = str(block_timestamp)
                return values

            def _measure_parked_transfer(from_addr, to_addr, amount, overrides,
                                         slot_values):
                """One Tau step for a parked transfer: (policy_allows, fee).

                Measurement only -- no balances move, nothing is recorded. Used
                twice: when a request is created, to price it and to confirm the
                sender's own policy really does gate this amount without votes;
                and when a vote arrives, to see whether the policy now allows.

                Goes through `_transfer_input_map`, so the inputs are the same
                ones an ordinary transfer would be judged on.
                """
                inputs = _transfer_input_map(
                    from_addr, to_addr, amount,
                    slot_values=slot_values, overrides=overrides,
                )
                if not _session.ready(timeout=5):
                    if replay_mode:
                        # Same concession the transfer path makes: a Tau-less
                        # replay cannot know the verdict, and the state-hash
                        # invariant catches any divergence.
                        logger.warning(
                            "Replay without Tau: parked transfer for tx %s assumed "
                            "blocked, fee 0.", tx_id,
                        )
                        return False, 0
                    raise FeeRuleError(
                        f"Tau unavailable measuring a parked transfer (tx {tx_id})"
                    )
                with tau_manager.tau_comm_lock:
                    outputs = _session.evaluate(
                        inputs, multi=True, apply_rules_update=False,
                    )
                # o5 semantics, identical to the transfer path: absent -> allow,
                # BLOCK -> block, unparseable -> 0 -> block (fails closed).
                o5_raw = outputs.get(tau_defs.USER_POLICY_STREAM_INDEX)
                allows = not (
                    o5_raw is not None
                    and tau_manager.parse_tau_output(o5_raw)
                    == tau_defs.USER_POLICY_BLOCK_VALUE
                )
                fee = fees.parse_consensus_fee(
                    outputs.get(tau_defs.CONSENSUS_FEE_STREAM_INDEX),
                    context=f"tx {tx_id} parked",
                ) + fees.parse_custom_fee(
                    outputs.get(tau_defs.CUSTOM_FEE_STREAM_INDEX),
                    context=f"tx {tx_id} parked",
                )
                return allows, fee

            def _execute_fee_era_transfer(from_addr, to_addr, amount_val,
                                          slot_values=None, overrides=None):
                """Execute ONE transfer under the fee model. True to continue.

                Extracted verbatim from the user_tx transfer loop so the
                approval-completion path can execute a parked transfer through
                exactly the same gates -- o1, o5, the fee steps and the balance
                check -- instead of a second implementation that drifts.

                Deliberately a closure rather than a module-level function: the
                body reads a dozen per-transaction locals (staged_writes,
                fee_components, tx_receipt, custom_tau_inputs, the _read_bal and
                _parent_bal helpers, the replay_mode and cooldown flags) and
                rebinds three verdict flags. Threading all of that through a
                signature would be a larger change than the one being made.

                `slot_values` overlays the co-signature approval slots
                (i18..i25). The ordinary path passes the all-zero map, so no
                approver pubkey ever matches and a policy clause keeps blocking;
                the vote path passes the pubkeys of approvers who actually voted.
                """
                nonlocal accepted_in_block, hard_reject, execution_success
                try:
                    amount = int(amount_val)

                    tau_input_stream_values = _transfer_input_map(
                        from_addr, to_addr, amount,
                        slot_values=slot_values,
                        # A parked transfer feeds the custom inputs the SENDER
                        # signed into the request, not this transaction's (a vote
                        # carries none). Defaulting to custom_tau_inputs keeps the
                        # ordinary path identical.
                        overrides=custom_tau_inputs if overrides is None else overrides,
                    )

                    if not _session.ready(timeout=5):
                        if replay_mode:
                            # Tau-less replay is supported for
                            # pre-fee chains (fee 0 matches).
                            # For fee-era chains the state-hash
                            # invariant catches the divergence.
                            logger.warning(
                                "Replay without Tau: fee step assumed 0 for tx %s.",
                                tx_id,
                            )
                            fee_components.append(0)
                        else:
                            # The fee value is unknowable without
                            # Tau; "pretend 0" would be a locally-
                            # valid divergent transition. Strict.
                            raise FeeRuleError(
                                f"Tau unavailable during fee-era transfer execution (tx {tx_id})"
                            )
                    else:
                        with tau_manager.tau_comm_lock:
                            tau_outputs = _session.evaluate(
                                tau_input_stream_values, multi=True,
                                apply_rules_update=False,
                            )
                        tx_receipt["logs"].append(
                            f"Tau(transfer) o1: {tau_outputs.get(1)}"
                        )
                        step_fee = fees.parse_consensus_fee(
                            tau_outputs.get(tau_defs.CONSENSUS_FEE_STREAM_INDEX),
                            context=f"tx {tx_id}",
                        ) + fees.parse_custom_fee(
                            tau_outputs.get(tau_defs.CUSTOM_FEE_STREAM_INDEX),
                            context=f"tx {tx_id}",
                        )
                        fee_components.append(step_fee)
                        if step_fee:
                            tx_receipt["logs"].append(f"Tau fee step: {step_fee}")

                        # --- User policy (o5) — consensus-enforced ---
                        # Read from the SAME multi result (no extra
                        # roundtrip, no perturbation), mirroring admission
                        # (commands/sendtx.py). Semantics: o5 absent -> allow;
                        # present and == BLOCK (0) -> reject the WHOLE tx
                        # (a policy block on any transfer invalidates the
                        # user_tx — staged writes never commit, so no partial
                        # execution). parse_tau_output maps unparseable -> 0,
                        # so a malformed policy output fails closed (reject).
                        o5_raw = tau_outputs.get(tau_defs.USER_POLICY_STREAM_INDEX)
                        if o5_raw is not None and \
                                tau_manager.parse_tau_output(o5_raw) == tau_defs.USER_POLICY_BLOCK_VALUE:
                            logger.info(
                                "Transfer rejected by user policy (o5) for %s->%s (o5=%s)",
                                str(from_addr)[:10], str(to_addr)[:10], o5_raw,
                            )
                            if not replay_mode:
                                accepted_in_block = False
                                hard_reject = True
                            execution_success = False
                            tx_receipt["reason"] = "user_policy_block"
                            tx_receipt["logs"].append(
                                f"Transfer rejected by user policy (o5={o5_raw})"
                            )
                            return False

                    current_from = _read_bal(from_addr)
                    if current_from == 0 and getattr(config, "TESTNET_AUTO_FAUCET", False):
                        current_from = int(getattr(config, "TESTNET_AUTO_FAUCET_AMOUNT", 100000))
                    if current_from < amount:
                        logger.error(
                            "Insufficient funds for %s to send %s. Has: %s.",
                            from_addr[:10], amount, current_from,
                        )
                        if not replay_mode:
                            accepted_in_block = False
                            hard_reject = True
                        execution_success = False
                        tx_receipt["logs"].append("Transfer balance state failed (insufficient)")
                        return False
                    staged_writes[from_addr] = current_from - amount
                    staged_writes[to_addr] = _read_bal(to_addr) + amount
                except FeeRuleError:
                    raise
                except Exception as e:
                    logger.error("Error applying transfer: %s", e)
                    if not replay_mode:
                        accepted_in_block = False
                        hard_reject = True
                    execution_success = False
                    return False
                return True

            if charge_fee:
                # Absent field -> cap 0: legacy/feeless txs stay valid while
                # the fee model is inactive (total fee 0) and are rejected
                # by the cap check once it is active. Only a PRESENT but
                # malformed value is structurally invalid.
                raw_fee_limit = tx.get('fee_limit')
                fee_limit_int = 0 if raw_fee_limit is None else fees.parse_fee_limit(raw_fee_limit)
                if fee_limit_int is None:
                    if replay_mode:
                        # Stored blocks are canonical; never re-litigate.
                        logger.error(
                            "Replay: tx %s has malformed fee_limit %r; fee skipped.",
                            tx_id, tx.get('fee_limit'),
                        )
                        tx_receipt["logs"].append("Replay: malformed fee_limit; fee skipped")
                        charge_fee = False
                    else:
                        accepted_in_block = False
                        hard_reject = True
                        execution_success = False
                        tx_receipt["reason"] = "invalid_fee_limit"
                        tx_receipt["logs"].append(
                            f"Invalid fee_limit: {tx.get('fee_limit')!r}"
                        )

            rule_op_data = None
            transfers_op_data = None
            custom_tau_inputs: dict[int, list[str]] = {}
            reserved_error = None

            from consensus.governance import parse_consensus_rule_update, parse_consensus_rule_vote
            
            if tx_type == 'consensus_rule_update':
                update = parse_consensus_rule_update(tx)
                if update:
                    # Consensus-enforced activation delay. Mirrors the mempool
                    # admission floor (admission.validate_consensus_rule_update_payload)
                    # so a crafted block — which never passed admission — cannot
                    # submit a governance update that activates before the
                    # validator set has had time to react; in the limit, reaching
                    # quorum and activating in the same block. The reference
                    # height is the inclusion height, so the floor is identical
                    # on every node applying this block. Breach is a soft no-op
                    # (block stays valid, update is simply not recorded), matching
                    # forged-vote / unknown-update handling and keeping replay
                    # deterministic.
                    min_activation = (
                        block_height + len(lifecycle_mgr.active_validators)
                        if block_height is not None else None
                    )
                    if min_activation is not None and update.activate_at_height < min_activation:
                        tx_receipt["logs"].append(
                            "Update ignored (activation delay breached): "
                            f"{update.activate_at_height} < {min_activation}"
                        )
                    elif lifecycle_mgr.can_admit_update(update, is_mempool=False):
                        if lifecycle_mgr.submit_update(update):
                            tx_receipt["logs"].append("Update submitted: " + update.update_id_hex)
                        else:
                            tx_receipt["logs"].append("Duplicate update ignored: " + update.update_id_hex)
                    else:
                        tx_receipt["logs"].append("Update rejected by strict admission")
                        accepted_in_block = False
                        hard_reject = True
                        execution_success = False
                else:
                    tx_receipt["logs"].append("Invalid update format")
                    accepted_in_block = False # Structural invalidity rejects entirely in most chains

            elif tx_type in RULE_OFFER_TX_TYPES:
                # Bounds and cap breaches are SOFT no-ops with a receipt log,
                # matching the activation-delay handling above: the block stays
                # valid and the offer simply is not recorded, so replay is
                # deterministic regardless of tip state. Only a Tau failure on
                # the composed rule hard-rejects, because that means the text
                # could not have entered the specification at all.
                offers = lifecycle_mgr.rule_offers

                if tx_type == TX_TYPE_RULE_OFFER:
                    offer = parse_rule_offer(tx)
                    if offer is None:
                        tx_receipt["logs"].append("Invalid rule offer format")
                        accepted_in_block = False
                    elif not isinstance(sender, str) or sender.lower() != offer.offerer_pubkey:
                        tx_receipt["logs"].append("Rule offer offerer is not the sender")
                        accepted_in_block = False
                    else:
                        # The reference height is the INCLUSION height, which
                        # is what admission's tip_view.next_block_height()
                        # resolved to for this same transaction. Using anything
                        # else would let admission and apply disagree about
                        # whether an offer is still in its window.
                        ok, reason = offers.can_admit_offer(
                            offer,
                            next_height=block_height if block_height is not None else 0,
                        )
                        if not ok:
                            tx_receipt["logs"].append(f"Offer ignored ({reason})")
                        elif offers.submit_offer(offer):
                            tx_receipt["logs"].append("Offer submitted: " + offer.offer_id_hex)
                        else:
                            tx_receipt["logs"].append(
                                "Duplicate offer ignored: " + offer.offer_id_hex
                            )
                else:
                    accept = tx_type == TX_TYPE_RULE_OFFER_ACCEPT
                    decision = (
                        parse_rule_offer_accept(tx) if accept
                        else parse_rule_offer_reject(tx)
                    )
                    if decision is None:
                        tx_receipt["logs"].append("Invalid rule offer decision format")
                        accepted_in_block = False
                    elif not isinstance(sender, str) or sender.lower() != decision.actor_pubkey:
                        tx_receipt["logs"].append("Rule offer decision actor is not the sender")
                        accepted_in_block = False
                    else:
                        ok, reason = offers.can_admit_decision(decision)
                        if not ok:
                            tx_receipt["logs"].append(
                                f"Offer decision ignored ({reason})"
                            )
                        else:
                            target_stream = offers.submit_decision(decision)
                            if target_stream is None:
                                tx_receipt["logs"].append(
                                    "Offer resolved: " + decision.offer_id_hex
                                )
                            else:
                                # Re-emit the whole composite for the stream.
                                # Individually guarded units cannot be appended:
                                # an unconstrained stream materializes with an
                                # arbitrary witness, and two total-form rules on
                                # one stream either fail to conjoin or supersede
                                # each other. See tests/test_rule_scoping_native.
                                if (accept and target_stream
                                        == tau_defs.USER_POLICY_STREAM_INDEX):
                                    # Accepting an offered o5 clause replaces
                                    # the acceptor's registered policy, exactly
                                    # as an op-"0" declare does. Same hazard,
                                    # same remedy: a request snapshots its
                                    # approvers but re-evaluates the CURRENT
                                    # clause, so recorded votes would come to
                                    # mean something they were never given for.
                                    book = lifecycle_mgr.approval_requests
                                    doomed = book.resolve_all_for_sender(
                                        decision.actor_pubkey, STATUS_FAILED
                                    )
                                    if doomed:
                                        tx_receipt["logs"].append(
                                            "Policy change failed %d open approval "
                                            "request(s)" % len(doomed)
                                        )
                                composite = offers.composite_for_stream(target_stream)
                                ok_apply, detail = _apply_composite_rule(
                                    composite, tx_receipt
                                )
                                if not ok_apply:
                                    accepted_in_block = False
                                    hard_reject = True
                                    execution_success = False
                                    tx_receipt["logs"].append(
                                        f"Error: composite rule rejected: {detail}"
                                    )
                                else:
                                    # current_tau_bytes deliberately unchanged:
                                    # the composite is not part of the
                                    # application-rules accumulation. What binds
                                    # it into the state hash is the clause
                                    # registry root in consensus_meta.
                                    tx_receipt["logs"].append(
                                        f"Offer accepted, o{target_stream} composite applied: "
                                        + decision.offer_id_hex
                                    )

            elif tx_type in APPROVAL_TX_TYPES:
                # Bounds and state disagreements are SOFT no-ops with a receipt
                # log, matching the rule-offer branch: the block stays valid and
                # the action simply is not recorded, so replay is deterministic
                # regardless of tip state. Only a forged signature or a Tau
                # failure hard-rejects.
                approvals = lifecycle_mgr.approval_requests

                if not approval_slots_on:
                    tx_receipt["logs"].append(
                        "Approval transaction ignored: approval slots are not active"
                    )
                    accepted_in_block = False
                else:
                    # Signatures are otherwise verified at mempool admission ONLY;
                    # neither chain_state nor this engine re-checks them. For a
                    # feature whose whole promise is independent co-signatures
                    # that is not enough: a malicious proposer could mint a vote
                    # bearing an approver's sender_pubkey and release parked funds
                    # with no approver involved. Height-gated on activation, so
                    # historical replay is untouched.
                    sig_ok, sig_reason = verify_tx_signature(tx)
                    if not sig_ok:
                        logger.error(
                            "Approval tx %s signature rejected at apply: %s",
                            tx_id, sig_reason,
                        )
                        tx_receipt["logs"].append(
                            f"Approval transaction signature invalid: {sig_reason}"
                        )
                        accepted_in_block = False
                        hard_reject = True
                        execution_success = False

                    elif tx_type == TX_TYPE_APPROVAL_REQUEST:
                        request = parse_approval_request(tx)
                        if request is None:
                            tx_receipt["logs"].append("Invalid approval request format")
                            accepted_in_block = False
                        elif not isinstance(sender, str) or sender.lower() != request.sender_pubkey:
                            tx_receipt["logs"].append("Approval request sender is not the signer")
                            accepted_in_block = False
                        else:
                            ok, reason = approvals.can_admit_request(request, int(block_height or 0))
                            if not ok:
                                tx_receipt["logs"].append(f"Approval request ignored ({reason})")
                                accepted_in_block = False
                            else:
                                # Price it, and confirm the sender's own policy
                                # really does gate this amount with no votes in.
                                allows, parked_fee = _measure_parked_transfer(
                                    request.sender_pubkey, request.recipient_pubkey,
                                    request.amount, request.custom_inputs,
                                    _approval_slot_values(),
                                )
                                if allows:
                                    # Nothing to wait for: parking it would strand
                                    # funds behind approvers the policy never asks
                                    # for. Soft, so the block stays valid.
                                    tx_receipt["logs"].append(
                                        "Approval request ignored: the sender's policy "
                                        "allows this transfer with no votes -- send it "
                                        "as an ordinary transfer"
                                    )
                                    accepted_in_block = False
                                elif approvals.submit_request(request):
                                    # This is the ONLY charge for the parked
                                    # transfer: releasing it later is free, so
                                    # there is no second fee to drift against a
                                    # fee rule that changed while it sat open.
                                    # Which is exactly why the parking has to be
                                    # withdrawn if this tx fails to pay it --
                                    # see `parked_request_id` after settlement.
                                    fee_components.append(parked_fee)
                                    fee_already_measured = True
                                    parked_request_id = request.request_id
                                    tx_receipt["logs"].append(
                                        "Approval request parked: " + request.request_id_hex
                                    )
                                else:
                                    tx_receipt["logs"].append(
                                        "Duplicate approval request ignored: "
                                        + request.request_id_hex
                                    )
                                    accepted_in_block = False

                    else:  # TX_TYPE_TRANSFER_VOTE
                        vote = parse_transfer_vote(tx)
                        if vote is None:
                            tx_receipt["logs"].append("Invalid transfer vote format")
                            accepted_in_block = False
                        elif not isinstance(sender, str) or sender.lower() != vote.voter_pubkey:
                            tx_receipt["logs"].append("Transfer vote voter is not the signer")
                            accepted_in_block = False
                        else:
                            # Covers unknown, resolved, EXPIRED, not-a-declared-
                            # approver and already-voted. The expiry check matters
                            # here specifically: process_height_transitions runs
                            # AFTER this loop, so the sweep cannot stop a vote
                            # included at exactly the expiry height.
                            ok, reason = approvals.can_admit_vote(vote, int(block_height or 0))
                            if not ok:
                                tx_receipt["logs"].append(f"Transfer vote ignored ({reason})")
                                accepted_in_block = False
                            else:
                                entry = approvals.get_request(vote.request_id)
                                # PROSPECTIVE first, commit after. hard_reject
                                # suppresses staged balances and nonces but does
                                # NOT roll back lifecycle mutations, so a Tau
                                # failure here must not leave a recorded vote
                                # behind.
                                # The manager returns raw pubkeys (the right
                                # domain value); _approval_slot_values formats
                                # them for the wire as `{ #x.. }:bv[384]`, which
                                # is the shape tau_shrink interns. Feeding the
                                # raw map straight through overflowed the
                                # interned bv[8] slot stream and wedged block
                                # production.
                                prospective_raw = approvals.prospective_slot_values(
                                    vote.request_id, vote
                                )
                                prospective = _approval_slot_values(prospective_raw)
                                allows, _released_fee = _measure_parked_transfer(
                                    entry.sender_pubkey, entry.recipient_pubkey,
                                    entry.amount, entry.custom_inputs, prospective,
                                )
                                approvals.commit_vote(vote)
                                tx_receipt["logs"].append(
                                    "Transfer vote recorded: %s %s"
                                    % (vote.request_id_hex,
                                       "approve" if vote.approve else "decline")
                                )

                                if allows:
                                    # Release it through the SAME closure an
                                    # ordinary transfer uses, so o5, the balance
                                    # check and the staged-write discipline are
                                    # one implementation. No fee is charged: the
                                    # request already paid, and `charge_fee` is
                                    # False for a vote so nothing is settled.
                                    # No sequence increment for the request's
                                    # sender either -- the request consumed one.
                                    guard = (accepted_in_block, hard_reject, execution_success)
                                    released = _execute_fee_era_transfer(
                                        entry.sender_pubkey, entry.recipient_pubkey,
                                        entry.amount,
                                        slot_values=prospective,
                                        overrides=entry.custom_inputs,
                                    )
                                    if released:
                                        approvals.resolve(vote.request_id, STATUS_EXECUTED)
                                        # Stamp the REQUEST SENDER's transfer
                                        # history, not the voter's. The generic
                                        # site below keys off `sender` (this tx's
                                        # signer, i.e. the approver) and
                                        # transfers_op_data (None for a vote), so
                                        # it would skip a released transfer
                                        # entirely -- leaving it invisible to
                                        # cooldown policies and to the
                                        # consensus-bound history state.
                                        if target_last_transfer_ts is not None:
                                            target_last_transfer_ts[entry.sender_pubkey] = int(
                                                block_timestamp or 0
                                            )
                                        tx_receipt["logs"].append(
                                            "Parked transfer executed: " + vote.request_id_hex
                                        )
                                    else:
                                        # The closure hard-rejects on its own
                                        # failure paths, which is right for an
                                        # ordinary transfer but wrong here: the
                                        # VOTE was valid and should stand, and the
                                        # request simply cannot be honoured (the
                                        # sender spent the money elsewhere, or
                                        # their policy still blocks). Restore the
                                        # verdict flags and record it terminally.
                                        accepted_in_block, hard_reject, execution_success = guard
                                        staged_writes.clear()
                                        approvals.resolve(vote.request_id, STATUS_FAILED)
                                        tx_receipt["reason"] = "parked_transfer_failed"
                                        tx_receipt["logs"].append(
                                            "Parked transfer could not be executed; "
                                            "request marked failed: " + vote.request_id_hex
                                        )
                                elif entry.all_answered():
                                    # Everyone the sender named has answered and
                                    # the policy still blocks, so it never will.
                                    approvals.resolve(vote.request_id, STATUS_FAILED)
                                    tx_receipt["logs"].append(
                                        "All declared approvers answered and the policy "
                                        "still blocks; request marked failed: "
                                        + vote.request_id_hex
                                    )

            elif tx_type == 'consensus_rule_vote':
                vote = parse_consensus_rule_vote(tx)
                if vote and sender:
                    if lifecycle_mgr.can_admit_vote(vote, sender, is_mempool=False):
                        if lifecycle_mgr.submit_vote(vote, sender):
                            tx_receipt["logs"].append(f"Vote accepted for update {vote.update_id.hex()}")
                        else:
                            tx_receipt["logs"].append("Vote ignored (valid no-op)")
                    else:
                        tx_receipt["logs"].append("Vote rejected by strict admission")
                        accepted_in_block = False
                        hard_reject = True
                        execution_success = False
                else:
                    tx_receipt["logs"].append("Invalid vote format")
                    accepted_in_block = False
            else:
                # user_tx
                rule_op_data = operations.get("0")
                transfers_op_data = operations.get("1")
                
            for k, v in operations.items():
                if k.isdigit():
                    idx = int(k)
                    if idx in (0, 1):
                        continue
                    # i12 is the sender pubkey the node sets below; a custom
                    # operations["12"] would override it in the merge at
                    # tau_input_stream_values[12] and spoof the sender-scoped
                    # o5/o8 policy stream. i14/i15 are consensus stake/mode
                    # inputs fed at consensus evaluation; a user tx typing them
                    # at another bv width poisons process-global stream typing.
                    # i13 joins them only under tau_validator_set, the one mode
                    # that feeds it — derived from the SAME helper admission and
                    # sendtx use, since a disagreement here is a consensus split.
                    # Reject them here (not in RESERVED_STREAMS, a
                    # consensus-shared constant) so apply agrees with the
                    # sendtx/admission gate. Consensus change.
                    if idx in tau_defs.RESERVED_STREAMS or idx in tau_defs.reserved_operation_keys(
                            getattr(lifecycle_mgr, "effective_eligibility_mode", lambda: "")()):
                         reserved_error = f"Operation key '{k}' matches reserved stream {idx}."
                         break
                    
                    # Normalize value
                    normalized_val = []
                    valid_type = True
                    if isinstance(v, (str, int)):
                        normalized_val.append(str(v))
                    elif isinstance(v, (list, tuple)):
                        for item in v:
                            if isinstance(item, (str, int)):
                                normalized_val.append(str(item))
                            else:
                                valid_type = False
                                break
                    else:
                        valid_type = False
                    
                    if not valid_type:
                        reserved_error = f"Invalid value type for stream {idx}."
                        break
                    
                    custom_tau_inputs[idx] = normalized_val

            # W7: the rule path writes canonical application-rules state (and the
            # hashed tau bytes) as soon as the engine accepts the text, while fee
            # settlement downstream can still reject the whole transaction. A
            # rejected transaction then kept its rule -- probe: receipt
            # fee_limit_exceeded, fee_charged 0, transaction rejected, snapshot
            # still carrying the new rule. Stage the canonical effect the way
            # balance writes are already staged, and roll it back with them if the
            # verdict goes the other way. Bound for EVERY transaction, not just the
            # ones that reach the rule path.
            _rule_prior_rules_state = None
            _rule_prior_tau_bytes = current_tau_bytes
            _rule_touched_canonical = False
            try:
                if hasattr(chain_state, "get_application_rules_state"):
                    _rule_prior_rules_state = chain_state.get_application_rules_state()
            except Exception:
                _rule_prior_rules_state = None

            if reserved_error:
                logger.error("Transaction invalid: %s", reserved_error)
                accepted_in_block = False
                hard_reject = True
                execution_success = False
                tx_receipt["logs"].append(f"Error: {reserved_error}")
            else:
                # --- Step 1: Rule Execution ---
                # W7: the routed-clause path MUTATES -- it resolves the sender's
                # open approval requests and replaces or removes their registered
                # clause -- so it must not run for a transaction an earlier check
                # already rejected. It used to be guarded only by `reserved_error`,
                # so a transaction with (say) a stale sequence number still had its
                # policy replaced and its pending approvals cancelled before the
                # verdict was applied.
                _verdict_still_open = (
                    execution_success and accepted_in_block and not hard_reject
                )
                if rule_op_data is not None:
                     if isinstance(rule_op_data, str) and rule_op_data.strip() \
                             and _verdict_still_open \
                             and _apply_o5_clause_routing(rule_op_data.strip()):
                        # Registered as this sender's policy clause; the
                        # composite was fed instead of accumulating the text.
                        pass
                     elif isinstance(rule_op_data, str) and rule_op_data.strip():
                        rule_text = rule_op_data.strip()
                        width_error = screen_policy_widths(rule_text)
                        conj_error = (
                            None if approval_slots_on
                            else screen_unsatisfiable_sender_conjunction(rule_text)
                        )
                        if (width_error or conj_error) and not replay_mode:
                            accepted_in_block = False
                            hard_reject = True
                            execution_success = False
                            tx_receipt["reason"] = (
                                "width_mismatch" if width_error
                                else "unsatisfiable_sender_conjunction"
                            )
                            tx_receipt["logs"].append(
                                f"Error: {width_error or conj_error}"
                            )
                        if execution_success and accepted_in_block and not hard_reject:
                          try:
                            # The rule goes through the evaluator SESSION rather
                            # than straight to the manager: the same code has to be
                            # able to drive a disposable worker, and the engine
                            # offers no rollback, so which evaluator runs a rule
                            # cannot be a module-level fact. Dispatch is unchanged.
                            if not _session.ready(timeout=5):
                                logger.error("Tau process not ready for rule execution")
                                execution_success = False
                                tx_receipt["logs"].append("Tau not ready")
                                if not replay_mode:
                                    accepted_in_block = False
                                    hard_reject = True
                                    tx_receipt["reason"] = "rule_not_applied"
                            else:
                                output = _session.apply_rule(rule_text, target=0)

                                tx_receipt["logs"].append(f"Tau(rule) o0: {output}")

                                # W6: prefer what the engine actually reported
                                # over parsing the formatted output. A receipt
                                # separates a genuine no-op from a rule that was
                                # never routed -- an unsatisfiable rule is
                                # evaluated into the no-revision branch, which the
                                # string heuristic reads as success.
                                receipt = _session.last_receipt()
                                if receipt is not None:
                                    tau_failed = not receipt.get("accepted", False)
                                    tx_receipt["logs"].append(
                                        f"Tau(rule) outcome: {receipt.get('outcome')}"
                                    )
                                else:
                                    tau_failed = (
                                        isinstance(output, str)
                                        and "error" in output.lower()
                                        and "x1001" not in output.lower()
                                    )
                                if tau_failed:
                                    logger.warning("Tau rejected rule: %s", output)
                                    execution_success = False
                                    tx_receipt["logs"].append(
                                        f"Error: Tau rejected rule output: {output}"
                                    )
                                    if not replay_mode:
                                        accepted_in_block = False
                                        hard_reject = True
                                        tx_receipt["reason"] = "rule_rejected"
                                elif _session.is_speculative:
                                    # A speculative session commits nothing, so
                                    # there is no persistence to check for. The
                                    # engine's own receipt is the evidence, and
                                    # the canonical write happens on acceptance,
                                    # on the authoritative path.
                                    tx_receipt["logs"].append("Rule applied (speculative)")
                                elif not _application_rule_landed(rule_text):
                                    # Live apply: the handler did not persist, so
                                    # this is a no-op that must not sit in the
                                    # block or charge a fee. Replay: TAU_FORCE_TEST
                                    # and historical blocks do not re-run the
                                    # handler; application-rules state is restored
                                    # from the snapshot, so dropping the tx would
                                    # diverge reconstruction.
                                    if not replay_mode:
                                        accepted_in_block = False
                                        hard_reject = True
                                        execution_success = False
                                        tx_receipt["reason"] = "rule_not_applied"
                                        tx_receipt["logs"].append(
                                            "Error: rule did not persist to application-rules state"
                                        )
                                    else:
                                        tx_receipt["logs"].append("Rule applied")
                                else:
                                    rules_text = None
                                    try:
                                        val = (
                                            chain_state.get_application_rules_state()
                                            if hasattr(chain_state, "get_application_rules_state")
                                            else None
                                        )
                                        if isinstance(val, str):
                                            rules_text = val
                                    except Exception:
                                        pass

                                    if rules_text is not None:
                                        current_tau_bytes = rules_text.encode("utf-8")
                                    else:
                                        current_tau_bytes += rule_op_data.encode("utf-8")
                                    _rule_touched_canonical = True
                                    tx_receipt["logs"].append("Rule applied")

                          except tau_shrink.ShrinkTypeConflict as e:
                            # W3: node-local. This process cannot represent the
                            # rule because of a width it already committed to;
                            # another node, or this one after a restart, can.
                            # Must never rewrite history on replay, and must
                            # never be reported as an invalid rule.
                            logger.error("Cannot represent rule in this process: %s", e)
                            execution_success = False
                            tx_receipt["logs"].append(f"Error: runtime type conflict: {e}")
                            if not replay_mode:
                                accepted_in_block = False
                                hard_reject = True
                                tx_receipt["reason"] = "rule_type_conflict"
                          except TauSpecRejected as e:
                            # W9: the engine refused the AUTHOR's text. Measured to
                            # be a clean no-op (no revision, no type established,
                            # interpreter still usable), so it is a deterministic
                            # per-transaction verdict every node reaches -- and it
                            # is NOT a node crash. Hard-rejects in replay too,
                            # because the verdict is a function of the text alone.
                            logger.warning("Tau rejected the submitted rule: %s", e)
                            execution_success = False
                            tx_receipt["logs"].append(f"Error: rule rejected by Tau: {e}")
                            accepted_in_block = False
                            hard_reject = True
                            tx_receipt["reason"] = "rule_rejected"
                          except TauSpecIntegrationError as e:
                            # W9: the author's rule was fine and the runtime text
                            # THIS NODE generated from it was not. Node-local
                            # integration failure: never report it as an invalid
                            # rule, and never rewrite history on replay.
                            logger.error(
                                "Node-generated runtime text was refused by Tau "
                                "(integration failure, not an invalid rule): %s", e
                            )
                            execution_success = False
                            tx_receipt["logs"].append(f"Error: runtime preparation failure: {e}")
                            if not replay_mode:
                                accepted_in_block = False
                                hard_reject = True
                                tx_receipt["reason"] = "rule_not_applied"
                          except Exception as e:
                            logger.error("Error applying rule: %s", e)
                            execution_success = False
                            tx_receipt["logs"].append(f"Error: {e}")
                            # Live apply: a rule that did not land must not sit
                            # in the block and pay a fee. Replay keeps the
                            # historical inclusion (only a deterministic Tau
                            # parse error still hard-rejects). The marker is
                            # ANSI-wrapped by the engine, so match it with the
                            # ANSI-aware helper, never a literal substring.
                            if not replay_mode or tau_native.tau_reports_error(str(e)):
                                accepted_in_block = False
                                hard_reject = True
                                tx_receipt["reason"] = "rule_not_applied"

                # --- Step 2 & 3: Unified Custom Inputs & Transfers ---
                if execution_success and transfers_op_data is not None:
                    if isinstance(transfers_op_data, list) and charge_fee:
                        # Fee-era path: o1+o8+o9 in one roundtrip per
                        # transfer, tx-atomic balance staging (writes commit
                        # only if the whole tx is accepted — a mid-tx
                        # failure must not pollute the overlay/state hash).
                        for transfer in transfers_op_data:
                            if not (isinstance(transfer, (list, tuple)) and len(transfer) == 3):
                                continue
                            from_addr, to_addr, amount_val = transfer
                            if not _execute_fee_era_transfer(
                                from_addr, to_addr, amount_val,
                                slot_values=_approval_slot_values(),
                            ):
                                break
                    elif isinstance(transfers_op_data, list):
                        for transfer in transfers_op_data:
                            if isinstance(transfer, (list, tuple)) and len(transfer) == 3:
                                from_addr, to_addr, amount_val = transfer
                                try:
                                    amount = int(amount_val)
                                    
                                    # Simulate miner unified execution parity
                                    # We don't need 'remaining' balance or 'IDs' accurately in replay
                                    # because the transaction was already accepted. But to ensure
                                    # perfect semantic parity as requested, we construct the input map.
                                    # Replay strictly mirrors mining execution logic without actually 
                                    # failing if Tau fails it (as block was already valid), but we run it
                                    # to ensure identical side-effects (if any) and identical log output.
                                    
                                    tau_input_stream_values = {
                                        1: str(amount),
                                        # Same parent-snapshot i2 as the fee-era
                                        # path above: this is the replay path for
                                        # pre-fee-era blocks, and a different value
                                        # here would diverge replay from mining.
                                        2: _parent_bal(from_addr),
                                        **({16: _since_last_transfer(from_addr)} if cooldown_active else {}),
                                        # Real from/to pubkeys for eval/width parity
                                        # with the fee-era path.
                                        3: "{ #x" + str(from_addr) + " }:bv[384]",
                                        4: "{ #x" + str(to_addr) + " }:bv[384]",
                                    }
                                    # i12: full 384-bit sender pubkey (bv[384]),
                                    # mirrors the submit path so any rule that
                                    # references i12[t] replays deterministically.
                                    tau_input_stream_values[12] = "{ #x" + str(from_addr) + " }:bv[384]"
                                    # NOTE: o5 user policy is consensus-enforced in the
                                    # fee-era loop above (the live path when fees are on,
                                    # which is the release config). This feeless legacy
                                    # path mutates balances non-atomically and is not the
                                    # consensus-determining path, so it does not enforce o5.
                                    for k, v in custom_tau_inputs.items():
                                        tau_input_stream_values[k] = v
                                    tau_input_stream_values[5] = str(block_timestamp)

                                    if _session.ready(timeout=0):
                                        tau_output_transfer = _session.evaluate(
                                            tau_input_stream_values, target=1,
                                            apply_rules_update=False,
                                        )
                                        tx_receipt["logs"].append(f"Tau(transfer) o1: {tau_output_transfer}")
                                    
                                    if target_balances is not None:
                                        # Use isolated balance tracking
                                        if from_addr in target_balances:
                                            current_from = target_balances[from_addr]
                                        else:
                                            current_from = chain_state.get_balance(from_addr)

                                        if current_from == 0 and getattr(config, "TESTNET_AUTO_FAUCET", False):
                                            current_from = int(getattr(config, "TESTNET_AUTO_FAUCET_AMOUNT", 100000))

                                        if current_from < amount:
                                            logger.error("Insufficient funds for %s to send %s. Has: %s.", from_addr[:10], amount, current_from)
                                            if not replay_mode:
                                                accepted_in_block = False
                                                hard_reject = True
                                            execution_success = False
                                            tx_receipt["logs"].append("Transfer balance state failed (insufficient)")
                                            break
                                            
                                        current_to = target_balances.get(to_addr, chain_state.get_balance(to_addr))
                                        target_balances[from_addr] = current_from - amount
                                        target_balances[to_addr] = current_to + amount
                                    else:
                                        if not chain_state.update_balances_after_transfer(from_addr, to_addr, amount):
                                            if not replay_mode:
                                                accepted_in_block = False
                                                hard_reject = True
                                            execution_success = False
                                            tx_receipt["logs"].append("Transfer balance state failed")
                                            break
                                except Exception as e:
                                    logger.error("Error applying transfer: %s", e)
                                    if not replay_mode:
                                        accepted_in_block = False
                                        hard_reject = True
                                    execution_success = False
                                    break
                        # Loop finishes, check if we broke out
                    else:
                        # logical error in tx format (should be caught by verify usually)
                        pass
                
                # --- Step 4: Unified Custom Execution (if no transfers were present) ---
                if execution_success and not transfers_op_data and (custom_tau_inputs or rule_op_data is not None):
                    try:
                         unified_inputs = {}
                         for k, v in custom_tau_inputs.items():
                             unified_inputs[k] = v
                         unified_inputs[5] = str(block_timestamp)
                         
                         if _session.ready(timeout=0):
                             res_eval = _session.evaluate(
                                 unified_inputs, target=0,
                                 apply_rules_update=False,
                             )
                             tx_receipt["logs"].append(f"Tau(custom_unified) o0: {res_eval}")
                             if "error" in res_eval.lower():
                                 tx_receipt["logs"].append(f"Custom logic error: {res_eval}")
                                 execution_success = False
                    except Exception as e:
                         logger.error("Error applying unified custom log: %s", e)
                         execution_success = False
                         tx_receipt["logs"].append(f"Error (unified custom): {e}")

            # --- Step 5: Fee settlement (charged only on inclusion) ---
            # A transfer-less user_tx is charged via one dedicated fee-query
            # step with the canonical mocked transfer inputs so governance
            # fees apply uniformly to all user transactions.
            if (charge_fee and accepted_in_block and not hard_reject
                    and not transfers_op_data and not fee_already_measured):
                try:
                    fee_query_inputs = {
                        1: "0", 2: _parent_bal(sender), 3: "0", 4: "0",
                        **({16: _since_last_transfer(sender)} if cooldown_active else {}),
                        # NOTE: key order here (5 before 12) intentionally
                        # matches commands/sendtx.py's transfer-less fee query,
                        # since insertion order is what the shrink layer sees.
                        5: str(block_timestamp),
                        12: "{ #x" + str(sender) + " }:bv[384]",
                    }
                    for k, v in custom_tau_inputs.items():
                        fee_query_inputs[k] = v
                    if not _session.ready(timeout=5):
                        if replay_mode:
                            logger.warning(
                                "Replay without Tau: fee-query step assumed 0 for tx %s.", tx_id
                            )
                        else:
                            raise FeeRuleError(
                                f"Tau unavailable during fee-query step (tx {tx_id})"
                            )
                    else:
                        with tau_manager.tau_comm_lock:
                            fee_outputs = _session.evaluate(
                                fee_query_inputs, multi=True,
                                apply_rules_update=False,
                            )
                        fee_components.append(
                            fees.parse_consensus_fee(
                                fee_outputs.get(tau_defs.CONSENSUS_FEE_STREAM_INDEX),
                                context=f"tx {tx_id} fee-query",
                            ) + fees.parse_custom_fee(
                                fee_outputs.get(tau_defs.CUSTOM_FEE_STREAM_INDEX),
                                context=f"tx {tx_id} fee-query",
                            )
                        )
                except FeeRuleError:
                    raise
                except Exception as e:
                    logger.error("Error during fee-query step for tx %s: %s", tx_id, e)
                    if not replay_mode:
                        accepted_in_block = False
                        hard_reject = True
                    execution_success = False
                    tx_receipt["logs"].append(f"Error (fee query): {e}")

            if charge_fee and accepted_in_block and not hard_reject:
                total_fee = sum(fee_components)
                if total_fee == 0:
                    pass  # fee model inactive (no o9/o8): zero writes, legacy-identical
                elif total_fee > fee_limit_int:
                    if replay_mode:
                        logger.error(
                            "Replay: tx %s total fee %s exceeds fee_limit %s; fee skipped.",
                            tx_id, total_fee, fee_limit_int,
                        )
                        tx_receipt["logs"].append("Replay: fee exceeds fee_limit; fee skipped")
                    else:
                        accepted_in_block = False
                        hard_reject = True
                        execution_success = False
                        tx_receipt["reason"] = "fee_limit_exceeded"
                        tx_receipt["logs"].append(
                            f"Fee {total_fee} exceeds fee_limit {fee_limit_int}"
                        )
                else:
                    # No faucet shim here: fee settlement reads plain
                    # balances; a 0-balance faucet sender cannot pay fees.
                    sender_bal = _read_bal(sender) if sender else 0
                    if sender is None or sender_bal < total_fee:
                        if replay_mode:
                            logger.error(
                                "Replay: tx %s sender cannot cover fee %s (has %s); fee skipped.",
                                tx_id, total_fee, sender_bal,
                            )
                            tx_receipt["logs"].append("Replay: insufficient balance for fee; fee skipped")
                        else:
                            accepted_in_block = False
                            hard_reject = True
                            execution_success = False
                            tx_receipt["reason"] = "insufficient_funds_for_fee"
                            tx_receipt["logs"].append(
                                f"Insufficient balance for fee: need {total_fee}, have {sender_bal}"
                            )
                    else:
                        # Governance may route the levy to a named account
                        # instead of the proposer (issue #25). Absent a patch
                        # this resolves to "" and the proposer is credited, which
                        # is the behaviour that shipped.
                        beneficiary = fee_beneficiary or proposer_pubkey
                        # Aliasing-safe ordering: deduct the sender first,
                        # then credit the beneficiary THROUGH the staged view —
                        # sender == beneficiary nets to zero because the credit
                        # reads the already-deducted value. That now covers three
                        # cases, not two: sender == proposer, sender ==
                        # beneficiary, and beneficiary == proposer.
                        staged_writes[sender] = sender_bal - total_fee
                        staged_writes[beneficiary] = _read_bal(beneficiary) + total_fee
                        tx_receipt["fee_charged"] = total_fee
                        tx_receipt["logs"].append(
                            f"Fee charged: {total_fee} -> "
                            f"{'beneficiary' if fee_beneficiary else 'proposer'} "
                            f"{str(beneficiary)[:10]}..."
                        )

            if parked_request_id is not None and not accepted_in_block:
                # The tx did not survive settlement (fee_limit_exceeded or
                # insufficient_funds_for_fee, both of which also set
                # hard_reject). Un-park it: otherwise the request stays in
                # consensus state having paid nothing, and a later vote releases
                # the transfer for free. Replay is unaffected -- it logs and
                # skips the fee without clearing accepted_in_block, so a request
                # parked on the mined chain stays parked.
                if lifecycle_mgr.approval_requests.withdraw_request(parked_request_id):
                    tx_receipt["logs"].append(
                        "Approval request un-parked (its fee was not paid)"
                    )

            # Commit staged balance writes only for txs that stay accepted.
            # (Replay soft-fails intentionally commit partial stages — same
            # observable behavior as the legacy immediate-write loop.)
            #
            # Gated on `staged_writes` rather than on `charge_fee`: a released
            # parked transfer stages writes from a transfer_vote, which is
            # deliberately fee-exempt so approver bots need no funding. The old
            # `charge_fee` gate silently dropped those writes -- the request
            # resolved as executed and the money never moved. Behaviour for every
            # pre-existing path is unchanged, because staged_writes was only ever
            # populated by the fee-era transfer loop, which runs only when
            # charge_fee is true; the explicit target_balances check preserves
            # what charge_fee used to imply (fees_enabled requires it).
            if (accepted_in_block and not hard_reject and staged_writes
                    and target_balances is not None):
                target_balances.update(staged_writes)

            # W7: same verdict, same moment -- a transaction that does not stay
            # accepted must not leave its rule in canonical state. Replay is
            # excluded for the same reason the landed-check is: historical blocks
            # restore application-rules state from the snapshot, so rewriting it
            # here would diverge reconstruction.
            if (_rule_touched_canonical and not replay_mode
                    and not (accepted_in_block and not hard_reject)):
                current_tau_bytes = _rule_prior_tau_bytes
                if (_rule_prior_rules_state is not None
                        and hasattr(chain_state, "save_application_rules_state")):
                    try:
                        chain_state.save_application_rules_state(_rule_prior_rules_state)
                        logger.warning(
                            "rolled back the canonical application rule of a rejected "
                            "transaction (reason=%s)", tx_receipt.get("reason")
                        )
                    except Exception as exc:
                        logger.error(
                            "could not roll back the canonical application rule of a "
                            "rejected transaction: %s", exc
                        )
                # The live interpreter still holds the rule: the engine commits a
                # stream's width on the first accepted revision and there is no
                # in-process way to undo that. Canonical state -- what is hashed,
                # persisted and replayed -- is correct again; the evaluator is
                # rebuilt from it on the next reconstruction.
                logger.warning(
                    "the live interpreter still holds the rolled-back rule until "
                    "it is next reconstructed from canonical state"
                )

            if accepted_in_block and not hard_reject:
                # Record this sender's transfer time for the cooldown stream
                # (issue #21). Only transfers count -- a rule-only user_tx is not
                # a send -- and only for txs that stay accepted, mirroring the
                # staged-balance commit rule.
                if sender and transfers_op_data and target_last_transfer_ts is not None:
                    target_last_transfer_ts[sender] = int(block_timestamp or 0)

                if should_increment_seq and sender:
                    try:
                        if target_sequences is not None:
                            target_sequences[sender] = target_sequences.get(sender, 0) + 1
                        else:
                            chain_state.increment_sequence_number(sender)
                    except Exception:
                        logger.error("Failed to increment sequence number for %s", sender, exc_info=True)
                        tx_receipt["logs"].append("Error: failed to increment sequence number")
                        # execution_success = False ? No, sequence failure is bad but processed.

            if accepted_in_block and not hard_reject:
                accepted_txs.append(tx)
                tx_receipt["status"] = "success" if execution_success else "failed"
                receipts[tx_id] = tx_receipt
            else:
                rejected_txs.append(tx)
                rejected_receipt = {"status": "failed", "logs": tx_receipt["logs"]}
                if "reason" in tx_receipt:
                    # Machine-readable fee rejection cause; a rejected tx
                    # never pays anything.
                    rejected_receipt["reason"] = tx_receipt["reason"]
                    rejected_receipt["fee_charged"] = 0
                receipts[tx_id] = rejected_receipt
                logger.error("TX REJECTED during apply: %s", tx_receipt["logs"])

        # Create new snapshot
        new_snapshot = TauStateSnapshot(
            state_hash=compute_state_hash(current_tau_bytes),
            tau_bytes=current_tau_bytes,
            metadata={**snapshot.metadata, "poa": True, "last_tx_count": len(accepted_txs)},
        )
        
        return TauExecutionResult(
            snapshot=self._state_store.commit(new_snapshot),
            accepted_transactions=accepted_txs,
            rejected_transactions=rejected_txs,
            receipts=receipts,
        )
