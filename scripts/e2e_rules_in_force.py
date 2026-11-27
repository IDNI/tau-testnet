#!/usr/bin/env python3
"""End-to-end rules in force and transaction outcomes on REAL running nodes with the native Tau engine.

tests/test_tx_outcomes.py drives the engine, the database and the two reads in
one process; this drives two live nodes (see scripts/e2e_rig.py): node A mines
and is driven through its RPC port and the `tau-testnet policy` CLI; node B
receives A's blocks only and records every outcome during its own replay.

SCENARIOS
    1. Alice installs an o5 policy: `gettxstatus` answers `applied` with the fee
       and the rule effect (`registered`, the sha256 of the stored body);
       `getaccountrules` shows the same hash with `since` naming that
       transaction; `policy show` prints it.
    2. She replaces it and revokes it: `replaced` with the new hash, `revoked`
       with none; the clause is gone and the history lists all three, newest
       first. A revoke with nothing registered never reaches a block.
    3. A plain transfer is `applied` with its fee and no rule effect.
    4. A soft no-op stays in the block and pays: Bob accepts and rejects Alice's
       offer in one block; the accept registers her rule as his, the reject is
       `skipped` with its fee and the receipt line that says why.
    5. Carol installs a guard naming co-signer Xavier with `policy guard set`:
       the release writes it and the history names the request. Two revoke
       requests park: Carol sees them as open, Xavier sees them waiting for his
       vote. He approves both in one block: the release writes the first
       (`revoked`) and records the second as `release_failed` with its reason.
    6. The probe of Sep 27 on #42: `o26 = {7} && o27 = {9}`, then `o26 = {3}`.
       `running_spec` (in `getgovernance` and `getaccountrules`) says the engine
       runs `o26 = 3` and `o27 = 9` with the hash of that text, at the head the
       answer describes, while the stored application rules still list both
       units. Each confirmed rule transaction says the engine took its
       revision (`revision.taken`) and gives the revision number after it.
    7. Node A restarts and answers the same (its running spec rebuilt from the
       journal), then applies `o27 = {4}` with that rebuilt engine: taken, its
       revision number continues, the engine runs `o26 = 3` and `o27 = 4`.
       Node B replays A's blocks with the engine it has run since block 0,
       restarts, and gives the same outcome for every transaction (the revision
       fields included), the same rules in force for every account and the same
       running spec. The reads of earlier blocks (scenario 8) are among them.
    8. Every block answers again what the tip said while it was the tip:
       `getaccountrules <address> <block>` gives the clauses, the guard, the
       account's units, the running spec and the history of that block, by
       number or by hash, complete on a node that recorded every block. The
       probe's blocks give `o26 = 7`, then `o26 = 3`. `gettxstatus` reads from
       the block's committed journal what the engine did with each rule
       (`rule_outcome`), and it agrees with the recorded revision. `policy
       show --block` prints the same. All of it after A's restart and on B.
    9. Every fee rule, and who sent it: Bob installs a fee rule (o8) for himself.
       Alice's read lists it under `fee_rules` with Bob as its sender, though it
       does not name her and is not among her own rules; Bob's read gives the
       same list and marks the rule as naming him. It is the rule in force: Bob
       pays 5 on top of the base fee, Alice the base fee alone. The block before
       it does not list it, its own block does. `policy show` prints it with its
       sender, and node B gives the same, after replay and after a restart.

USAGE
    python scripts/e2e_rules_in_force.py provision --dir .local/e2e-rules-in-force
    python scripts/e2e_rules_in_force.py run --dir .local/e2e-rules-in-force

The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import argparse
import hashlib
import os

import e2e_rig as rig_mod
from e2e_rig import BASE_FEE, FEE_LIMIT, Rig, check, say

NETWORK_ID = "tau-e2e-rules-in-force"
ACTORS = ("miner", "alice", "bob", "carol", "xavier")
POLICY_STREAM = 5
GUARD_STREAM = 0xFFFFFFFF

SPEND_LIMIT = ("always ( (i1[t]:bv[24] > { #x001388 }:bv[24]) ? "
               "( o5[t]:bv[24] = { #x000000 }:bv[24] ) : "
               "( o5[t]:bv[24] = { #x000001 }:bv[24] ) ).")
PERMISSIVE = ("always ( (i1[t]:bv[24] > { #x7fffff }:bv[24]) ? "
              "( o5[t]:bv[24] = { #x000000 }:bv[24] ) : "
              "( o5[t]:bv[24] = { #x000001 }:bv[24] ) ).")
NEUTRAL = "always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) )."


PROBE_A = "always ( o26[t]:bv[24] = { 7 }:bv[24] && o27[t]:bv[24] = { 9 }:bv[24] )."
PROBE_B = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."
RUNS_3 = "o26[t]:bv[24] = { 3 }:bv[24]"
RUNS_9 = "o27[t]:bv[24] = { 9 }:bv[24]"
PROBE_C = "always ( o27[t]:bv[24] = { 4 }:bv[24] )."
RUNS_4 = "o27[t]:bv[24] = { 4 }:bv[24]"
FEE_PLUS = 5


def own_fee_rule(pk):
    """The sender `pk` pays FEE_PLUS on top of the base fee, in the form the node
    admits: fenced to the sender's own key. o8 is on no other rule of this network."""
    return ("always ( (i12[t]:bv[384] = { #x%s }:bv[384]) -> "
            "(o8[t]:bv[24] = { #x%06x }:bv[24]) )." % (pk, FEE_PLUS))


def guard_text(cosigner_pk):
    return ("always ( (i18[t]:bv[384] = { #x%s }:bv[384]) ? "
            "(o5[t]:bv[24] = { #x000001 }:bv[24]) : "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) )." % cosigner_pk)


def tx_hash(res):
    return (res.get("data") or {}).get("tx_hash")


def outcome(rig, h, node=None):
    return rig.tx_status(h, node).get("outcome") or {}


def rules(rig, who, node=None):
    return rig.read(f"getaccountrules {rig.pk[who]}", node) or {}


def policy(rig, who):
    return next((c for c in rules(rig, who).get("clauses") or []
                 if c.get("stream") == POLICY_STREAM), None)


def rule_tx(rig, who, text):
    payload = rig.common(who)
    payload.update({"tx_type": "user_tx", "fee_limit": FEE_LIMIT, "operations": {"0": text}})
    return rig.submit(who, payload)


def revision(rig, h, node=None):
    """What the confirmed rule transaction says the engine did with its rule."""
    effects = outcome(rig, h, node).get("rule_effects") or []
    return next((e.get("revision") or {} for e in effects
                 if e.get("action") == "accumulated"), {})


def remember(rig, st, who, what):
    """Keep what the tip says about `who` now, to ask for this block again later."""
    st.setdefault("then", []).append({"who": who, "what": what, "view": rules(rig, who)})


def then_read(rig, entry):
    return f"getaccountrules {rig.pk[entry['who']]} {entry['view'].get('block_number')}"


def landed(rig, res, what):
    h = tx_hash(res)
    check(f"{what} is admitted", res.get("status") == "ok" and bool(h), res)
    rig.mine(empty=False)
    rig.settle(lambda: rig.tx_status(h).get("status") == "confirmed", f"{what} to confirm", tries=3)
    return h


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_registered(rig, st):
    say("1. A policy goes in: the outcome and the rule in force agree")
    h = landed(rig, rule_tx(rig, "alice", SPEND_LIMIT), "alice's o5 policy")
    st["txs"].append(h)
    out = outcome(rig, h)
    effects = out.get("rule_effects") or []
    check("`gettxstatus` answers applied with the fee", out.get("status") == "applied"
          and out.get("fee_charged") == BASE_FEE, out)
    check("the effect: alice's o5 clause registered, with a sha256",
          len(effects) == 1 and effects[0].get("account") == rig.pk["alice"]
          and effects[0].get("kind") == "clause" and effects[0].get("stream") == POLICY_STREAM
          and effects[0].get("action") == "registered" and len(effects[0].get("sha256") or "") == 64,
          effects)
    clause = policy(rig, "alice") or {}
    sha = (effects[0] if effects else {}).get("sha256")
    check("`getaccountrules` holds the same hash, over the body it shows",
          clause.get("sha256") == sha
          and hashlib.sha256((clause.get("body") or "").encode()).hexdigest() == sha, clause)
    check("`since` names the block and this transaction",
          (clause.get("since") or {}).get("tx_hash") == h, clause.get("since"))
    view = rules(rig, "alice")
    check("all chain fields come from the tip, with the registry root",
          view.get("block_number") == rig.a.height() and bool(view.get("rule_clauses_root")),
          {k: view.get(k) for k in ("block_number", "rule_clauses_root")})
    proc = rig.cli("policy", "show", rig.pk["alice"])
    check("`policy show` prints the clause hash and where it was set",
          proc.returncode == 0 and f"sha256 {sha}" in proc.stdout and "set at block" in proc.stdout,
          proc.stdout[-500:] + proc.stderr[-300:])
    st["sha_first"] = sha
    remember(rig, st, "alice", "alice's first policy")


def scenario_replaced_and_revoked(rig, st):
    say("2. Replaced, then revoked")
    h2 = landed(rig, rule_tx(rig, "alice", PERMISSIVE), "the replacement")
    remember(rig, st, "alice", "the replacement")
    h3 = landed(rig, rule_tx(rig, "alice", NEUTRAL), "the revoke")
    remember(rig, st, "alice", "the revoke")
    st["txs"] += [h2, h3]
    e2 = (outcome(rig, h2).get("rule_effects") or [{}])[0]
    e3 = (outcome(rig, h3).get("rule_effects") or [{}])[0]
    check("the replacement is `replaced` with a new hash",
          e2.get("action") == "replaced" and e2.get("sha256") not in (None, st["sha_first"]), e2)
    check("the revoke is `revoked`, with no hash", e3.get("action") == "revoked"
          and "sha256" not in e3, e3)
    view = rules(rig, "alice")
    check("no o5 clause is in force any more", policy(rig, "alice") is None, view.get("clauses"))
    hist = [(e.get("action"), e.get("tx_hash")) for e in view.get("history") or []]
    check("the history lists all three, newest first",
          hist[:3] == [("revoked", h3), ("replaced", h2), ("registered", st["txs"][0])], hist)
    res = rule_tx(rig, "alice", NEUTRAL)
    if res.get("status") == "ok":
        h = tx_hash(res)
        rig.mine(empty=False)
        status = rig.tx_status(h)
        check("a revoke with nothing registered stays out of the block: `rejected` with its reason",
              status.get("status") == "rejected" and not rig.in_head(h), status)
    else:
        check("a revoke with nothing registered is refused before any block",
              bool((res.get("error") or {}).get("code")), res)


def scenario_plain(rig, st):
    say("3. A plain transfer")
    h = landed(rig, rig.transfer("bob", "carol", 25), "bob's transfer")
    st["txs"].append(h)
    out = outcome(rig, h)
    check("applied, with its fee and no rule effect", out.get("status") == "applied"
          and out.get("fee_charged") == BASE_FEE and "rule_effects" not in out, out)


def scenario_skipped(rig, st):
    say("4. A decision that lost in its own block stays in the block and pays")
    from consensus.rule_offers import RuleOffer
    from tau_testnet_cli import tx as cli_tx

    offer = rig.common("alice")
    offer.update(cli_tx.build_rule_offer_tx(
        sender_pubkey=rig.pk["alice"], sequence_number=offer["sequence_number"],
        expiration_time=offer["expiration_time"], recipient_pubkey=rig.pk["bob"],
        rule_text=SPEND_LIMIT, expire_at_height=offer["expire_at_height"], fee_limit=FEE_LIMIT))
    st["txs"].append(landed(rig, rig.submit("alice", offer), "alice's offer to bob"))
    oid = RuleOffer(offerer_pubkey=rig.pk["alice"], recipient_pubkey=rig.pk["bob"],
                    rule_text=SPEND_LIMIT, expire_at_height=offer["expire_at_height"]).offer_id_hex
    check("bob sees one pending offer", rules(rig, "bob").get("pending_offers") == 1,
          rules(rig, "bob").get("pending_offers"))
    hashes = []
    for build, extra in ((cli_tx.build_rule_offer_accept_tx, {"rule_text": SPEND_LIMIT}),
                         (cli_tx.build_rule_offer_reject_tx, {})):
        payload = rig.common("bob")
        payload.update(build(sender_pubkey=rig.pk["bob"], sequence_number=payload["sequence_number"],
                             expiration_time=payload["expiration_time"],
                             expire_at_height=payload["expire_at_height"], offer_id=oid,
                             fee_limit=FEE_LIMIT, **extra))
        res = rig.submit("bob", payload)
        check(f"bob's {payload['tx_type']} is admitted", res.get("status") == "ok", res)
        hashes.append(tx_hash(res))
    rig.mine(empty=False)
    rig.mine()
    st["txs"] += hashes
    accept, reject = (outcome(rig, h) for h in hashes)
    effects = accept.get("rule_effects") or [{}]
    check("the accept is applied: bob's o5 clause registered from alice's offer",
          accept.get("status") == "applied" and effects[0].get("account") == rig.pk["bob"]
          and effects[0].get("action") == "registered", accept)
    check("the reject in the same block is `skipped`, with the fee it paid and why",
          reject.get("status") == "skipped" and reject.get("fee_charged") == BASE_FEE
          and any("ignored" in line.lower() for line in reject.get("logs") or []), reject)
    check("a skipped transaction carries no rule effect", "rule_effects" not in reject, reject)
    check("bob's policy in force is the accepted text",
          (policy(rig, "bob") or {}).get("sha256") == effects[0].get("sha256"), policy(rig, "bob"))
    remember(rig, st, "bob", "bob's accepted offer")


def scenario_guard_and_release(rig, st):
    say("5. A guard, two parked revokes, one vote each, one release fails")
    from consensus.approvals import parse_rule_change_request
    from tau_testnet_cli import tx as cli_tx
    import tau_defs

    st["txs"].append(landed(rig, rule_tx(rig, "carol", SPEND_LIMIT), "carol's o5 policy"))
    proc = rig.cli("policy", "guard", "set", "--privkey", rig.privkey("carol"),
                   "--body", guard_text(rig.pk["xavier"]), "--approver", f"18={rig.pk['xavier']}",
                   "--fee", FEE_LIMIT)
    rid = next((line.split(":", 1)[1].strip() for line in proc.stdout.splitlines()
                if line.startswith("request id:")), None)
    check("`policy guard set` submits and prints the request id", proc.returncode == 0 and rid,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.settle(lambda: (rules(rig, "carol").get("rule_change_guard") or {}).get("sha256"),
               "the guard to be written", tries=3)
    guard = rules(rig, "carol").get("rule_change_guard") or {}
    check("the guard is in force, `since` names the request (no guard yet: it ran at once)",
          guard.get("sha256") and (guard.get("since") or {}).get("request_id") == rid, guard)
    remember(rig, st, "carol", "carol's guard in force")
    hist = (rules(rig, "carol").get("history") or [{}])[0]
    check("the history records the guard as registered by that request",
          hist.get("stream") == GUARD_STREAM and hist.get("action") == "registered"
          and hist.get("request_id") == rid, hist)

    rids = []
    for _ in range(2):
        payload = rig.common("carol", expire_in=2000)
        payload.update(cli_tx.build_rule_change_request_tx(
            sender_pubkey=rig.pk["carol"], sequence_number=payload["sequence_number"],
            expiration_time=payload["expiration_time"], expire_at_height=payload["expire_at_height"],
            kind=tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY, rule_text="",
            approvers={"18": rig.pk["xavier"]}, fee_limit=FEE_LIMIT))
        res = rig.submit("carol", payload)
        check("a revoke request is admitted", res.get("status") == "ok", res)
        rids.append(parse_rule_change_request(payload).request_id.hex())
        st["txs"].append(tx_hash(res))
    rig.mine(empty=False)
    rig.mine()
    mine_open = {c.get("request_id"): c for c in rules(rig, "carol").get("open_rule_changes") or []}
    check("carol sees both requests open, not ready", set(rids) <= set(mine_open)
          and not any(mine_open[r].get("ready") for r in rids if r in mine_open), mine_open)
    waiting = {c.get("request_id") for c in rules(rig, "xavier").get("awaiting_my_vote") or []}
    check("xavier sees both waiting for his vote", set(rids) <= waiting, waiting)
    check("the policy is still in force while they wait", policy(rig, "carol") is not None)

    for r in rids:
        vote = rig.common("xavier")
        vote.update(cli_tx.build_transfer_vote_tx(
            sender_pubkey=rig.pk["xavier"], sequence_number=vote["sequence_number"],
            expiration_time=vote["expiration_time"], expire_at_height=vote["expire_at_height"],
            request_id=r, approve=True))
        res = rig.submit("xavier", vote)
        check("xavier's approval is admitted", res.get("status") == "ok", res)
        st["txs"].append(tx_hash(res))
    rig.mine(empty=False)
    rig.mine()
    view = rules(rig, "carol")
    by_request = {e.get("request_id"): e for e in view.get("history") or [] if e.get("request_id")}
    first, second = sorted(rids)
    check("the release writes the first request: the policy is revoked",
          policy(rig, "carol") is None and (by_request.get(first) or {}).get("action") == "revoked",
          by_request)
    failed = by_request.get(second) or {}
    check("the second is recorded `release_failed` with its reason",
          failed.get("action") == "release_failed" and bool(failed.get("detail")), failed)
    say(f"   release_failed detail: {failed.get('detail')!r}")
    remember(rig, st, "carol", "the release")
    check("nothing is left open", not view.get("open_rule_changes"), view.get("open_rule_changes"))


def scenario_running_spec(rig, st):
    say("6. The probe of Sep 27: what the engine runs, next to what was sent")
    before = (rig.read("getgovernance") or {}).get("running_spec") or {}
    check("before the probe the running spec has a text and no o26",
          bool(before.get("text")) and "o26" not in before["text"], before)
    st["txs"].append(landed(rig, rule_tx(rig, "bob", PROBE_A), "`o26 = 7 && o27 = 9`"))
    remember(rig, st, "bob", "the probe's first rule")
    st["txs"].append(landed(rig, rule_tx(rig, "bob", PROBE_B), "`o26 = 3`"))
    remember(rig, st, "bob", "the probe's second rule")
    st["probe"] = st["txs"][-2:]
    took_a, took_b = revision(rig, st["txs"][-2]), revision(rig, st["txs"][-1])
    check("each confirmed rule transaction says the engine took its revision",
          took_a.get("taken") is True and took_b.get("taken") is True
          and took_a.get("engine_outcome") == took_b.get("engine_outcome") == "ACCEPTED_CHANGED",
          (took_a, took_b))
    check("and gives the engine's revision number after it, in order",
          isinstance(took_a.get("spec_revision"), int)
          and took_b.get("spec_revision", -1) > took_a["spec_revision"], (took_a, took_b))
    st["last_revision"] = took_b.get("spec_revision")
    gov = rig.read("getgovernance") or {}
    running = gov.get("running_spec") or {}
    text = running.get("text") or ""
    check("the engine runs o26 = 3 and o27 = 9, and the 7 is gone",
          RUNS_3 in text and RUNS_9 in text and "{ 7 }" not in text, text[-300:] or running)
    check("its sha256 is the hash of that text",
          running.get("sha256") == hashlib.sha256(text.encode()).hexdigest(), running.get("sha256"))
    check("it names the head the rest of the answer describes",
          running.get("block_hash") == gov.get("head_hash"),
          (running.get("block_hash"), gov.get("head_hash")))
    stored = gov.get("application_rules") or ""
    check("the stored application rules still list both units, the 7 included",
          "{ 7 }" in stored and "{ 3 }" in stored and "{ 9 }" in stored, stored[-300:])
    mine = rules(rig, "bob").get("running_spec") or {}
    check("`getaccountrules` gives the same running spec",
          (mine.get("sha256"), mine.get("block_hash")) == (running.get("sha256"), running.get("block_hash")),
          mine.get("sha256"))
    st["running_sha"] = running.get("sha256")


def scenario_restart_and_follower(rig, st):
    say("7. Node A restarts; node B replays A's blocks, restarts, and agrees")
    reads = [f"gettxstatus {h}" for h in st["txs"] if h]
    reads += [f"getaccountrules {rig.pk[n]}" for n in ACTORS if n != "miner"]
    reads += [then_read(rig, entry) for entry in st.get("then") or []]
    before = {cmd: rig_mod.stable(rig.read(cmd)) for cmd in reads}
    if rig.restart_a():
        after = {cmd: rig_mod.stable(rig.read(cmd)) for cmd in reads}
        check("after A's restart every outcome and every account reads the same",
              before == after, [c for c in reads if before[c] != after[c]][:3])
    # a rule applied by A's engine as rebuilt after the restart; B applies the
    # same block with the engine it has run since block 0, and the agreement
    # below compares both answers
    h = landed(rig, rule_tx(rig, "bob", PROBE_C), "`o27 = 4` after the restart")
    took = revision(rig, h)
    check("after the restart the engine takes it and its revision number continues",
          took.get("taken") is True and st.get("last_revision") is not None
          and took.get("spec_revision", -1) > st["last_revision"], took)
    reads.append(f"gettxstatus {h}")
    st["txs"].append(h)
    st["probe"].append(h)
    running = (rig.read("getgovernance") or {}).get("running_spec") or {}
    check("the engine now runs o26 = 3 and o27 = 4",
          RUNS_3 in (running.get("text") or "") and RUNS_4 in (running.get("text") or "")
          and RUNS_9 not in (running.get("text") or ""), (running.get("text") or "")[-300:])
    st["running_sha"] = running.get("sha256")
    rig.mine()
    rig.follower_agrees(reads)
    on_b = (rig.read("getgovernance", rig.b) or {}).get("running_spec") or {}
    check("node B, rebuilt from its own journal, runs the same spec",
          on_b.get("sha256") == st.get("running_sha") and RUNS_4 in (on_b.get("text") or ""),
          on_b.get("sha256"))


def _shape(view):
    """The parts of an answer that an earlier block has to give again."""
    def since(item):
        return item.get("since") or None
    return {
        "block_hash": view.get("block_hash"),
        "clauses": [(c.get("stream"), c.get("body"), c.get("sha256")) for c in view.get("clauses") or []],
        "guard": (view.get("rule_change_guard") or {}).get("sha256"),
        "units": [u.get("sha256") for u in view.get("application_rules") or []],
        "running": ((view.get("running_spec") or {}).get("sha256"),
                    (view.get("running_spec") or {}).get("text")),
        "history": [(e.get("block_number"), e.get("action"), e.get("tx_hash"),
                     e.get("request_id"), e.get("sha256")) for e in view.get("history") or []],
        "since": [since(c) for c in view.get("clauses") or []]
                 + [since(view.get("rule_change_guard") or {})],
    }


def scenario_earlier_blocks(rig, st):
    say("8. Every block answers again what the tip said while it was the tip")
    head = rig.a.height()
    for entry in st.get("then") or []:
        tip = entry["view"]
        number = tip.get("block_number")
        now = rig.read(then_read(rig, entry)) or {}
        want, got = _shape(tip), _shape(now)
        # the tip names where a text was set only within its newest history rows
        want["since"] = [a if a is not None else b for a, b in zip(want["since"], got["since"])]
        check(f"block {number} ({entry['what']}): the same clauses, guard, units, running spec "
              f"and history, complete", want == got and now.get("at_block") is True
              and now.get("complete") is True and now.get("head_block_number") == head
              and bool(got["running"][0]),
              {k: (want[k], got[k]) for k in want if want[k] != got[k]}
              or {k: now.get(k) for k in ("at_block", "complete", "head_block_number")})
    first, second = [e for e in st["then"] if e["who"] == "bob" and "probe" in e["what"]]
    text_1 = (first["view"].get("running_spec") or {}).get("text") or ""
    text_2 = (second["view"].get("running_spec") or {}).get("text") or ""
    at_1 = (rig.read(then_read(rig, first)) or {}).get("running_spec") or {}
    at_2 = (rig.read(then_read(rig, second)) or {}).get("running_spec") or {}
    check("the probe's first block ran o26 = 7, its second o26 = 3, and the tip runs o27 = 4",
          "{ 7 }" in (at_1.get("text") or "") and RUNS_3 not in (at_1.get("text") or "")
          and RUNS_3 in (at_2.get("text") or "") and "{ 7 }" not in (at_2.get("text") or "")
          and (at_1.get("text"), at_2.get("text")) == (text_1, text_2)
          and at_2.get("sha256") != st.get("running_sha"),
          (at_1.get("sha256"), at_2.get("sha256"), st.get("running_sha")))
    check("the revision counter of the two blocks is one apart",
          isinstance(at_1.get("spec_revision"), int)
          and at_2.get("spec_revision") == at_1["spec_revision"] + 1,
          (at_1.get("spec_revision"), at_2.get("spec_revision")))

    by_hash = rig.read(f"getaccountrules {rig.pk['bob']} {first['view'].get('block_hash')}")
    by_number = rig.read(then_read(rig, first))
    check("asked by the block's hash, the same answer as by its number",
          by_hash is not None and rig_mod.stable(by_hash) == rig_mod.stable(by_number),
          (by_hash or {}).get("block_number"))
    tip = rules(rig, "bob")
    at_tip = rig.read(f"getaccountrules {rig.pk['bob']} {head}") or {}
    check("the tip asked for by its number gives what the plain read gives",
          {k: v for k, v in _shape(at_tip).items() if k != "since"}
          == {k: v for k, v in _shape(tip).items() if k != "since"} and at_tip.get("complete") is True,
          (at_tip.get("block_hash"), tip.get("block_hash")))
    above = rig.a.rpc(f"getaccountrules {rig.pk['bob']} {head + 5}")
    check("a block above the head is refused, not answered from the tip",
          above.get("status") == "error"
          and (above.get("error") or {}).get("code") == "INVALID_PARAMS", above)

    counters = []
    for h in st.get("probe") or []:
        out = outcome(rig, h)
        from_journal, recorded = out.get("rule_outcome") or {}, revision(rig, h)
        counters.append(from_journal.get("spec_revision"))
        check("`gettxstatus` reads the rule's outcome from the committed journal, and it agrees "
              "with the recorded revision",
              from_journal.get("source") == "committed_journal"
              and from_journal.get("accepted") is True and from_journal.get("taken") is True
              and from_journal.get("engine_outcome") == recorded.get("engine_outcome")
              and from_journal.get("spec_revision") == recorded.get("spec_revision"),
              (from_journal, recorded))
    check("the three revisions are in order, the third by the engine as rebuilt after the restart",
          len(counters) == 3 and all(isinstance(n, int) for n in counters)
          and counters[0] < counters[1] < counters[2], counters)
    clause_tx = outcome(rig, st["txs"][0])
    check("a clause is kept in the registry: its transaction names no revision of the engine",
          clause_tx.get("status") == "applied" and "rule_outcome" not in clause_tx, clause_tx)

    number = first["view"].get("block_number")
    proc = rig.cli("policy", "show", rig.pk["bob"], "--block", str(number))
    check("`policy show --block` prints the block, the head it read at and the running spec",
          proc.returncode == 0 and f"read at head {head}" in proc.stdout
          and f"running spec: sha256 {at_1.get('sha256')}" in proc.stdout
          and "NOT COMPLETE" not in proc.stdout, proc.stdout[-600:] + proc.stderr[-300:])
    on_b = rig.read(then_read(rig, first), rig.b) or {}
    check("node B, which only replayed A's blocks, gives the same text for that block",
          ((on_b.get("running_spec") or {}).get("sha256"), on_b.get("complete"))
          == (at_1.get("sha256"), True), (on_b.get("running_spec") or {}).get("sha256"))


def _fees(view):
    """The fee rules of a read, by hash, in the order the read gives them."""
    return {u.get("sha256"): u for u in view.get("fee_rules") or []}


def _fee_rows(view):
    """What every account's read has to give alike: all but `names_this_account`."""
    return [(u.get("sha256"), u.get("unit"), u.get("sent_by"), u.get("since"))
            for u in view.get("fee_rules") or []]


def scenario_fee_rules(rig, st):
    say("9. Every fee rule, and who sent it")
    before = rules(rig, "alice")
    check("the read lists the fee rules (o8) in force", isinstance(before.get("fee_rules"), list),
          before.get("fee_rules"))
    h = landed(rig, rule_tx(rig, "bob", own_fee_rule(rig.pk["bob"])), "bob's fee rule")
    st["txs"].append(h)
    effect = next((e for e in outcome(rig, h).get("rule_effects") or []
                   if e.get("action") == "accumulated"), {})
    sha = effect.get("sha256")
    alice, bob = rules(rig, "alice"), rules(rig, "bob")
    row = _fees(alice).get(sha) or {}
    check("Alice's read lists Bob's fee rule with Bob as its sender, though it does not name her",
          bool(sha) and row.get("sent_by") == [rig.pk["bob"]]
          and row.get("names_this_account") is False
          and (row.get("since") or {}).get("tx_hash") == h
          and sha not in _fees(before), {"sha": sha, "row": row})
    check("it is not among her own application rules, it is among Bob's",
          sha not in [u.get("sha256") for u in alice.get("application_rules") or []]
          and sha in [u.get("sha256") for u in bob.get("application_rules") or []],
          ([u.get("sha256") for u in alice.get("application_rules") or []],
           [u.get("sha256") for u in bob.get("application_rules") or []]))
    check("Bob's read gives the same fee rules and marks his as naming him",
          _fee_rows(bob) == _fee_rows(alice)
          and (_fees(bob).get(sha) or {}).get("names_this_account") is True,
          (_fee_rows(bob), _fee_rows(alice)))

    fee_b = rig.transfer("bob", "carol", 7)
    fee_a = rig.transfer("alice", "carol", 7)
    hb, ha = landed(rig, fee_b, "bob's transfer"), tx_hash(fee_a)
    rig.settle(lambda: rig.tx_status(ha).get("status") == "confirmed", "alice's transfer to confirm",
               tries=3)
    st["txs"] += [hb, ha]
    paid_b, paid_a = outcome(rig, hb).get("fee_charged"), outcome(rig, ha).get("fee_charged")
    check(f"it is the rule in force: Bob pays {FEE_PLUS} on top of the base fee, Alice the base fee",
          paid_b == BASE_FEE + FEE_PLUS and paid_a == BASE_FEE, {"bob": paid_b, "alice": paid_a})

    then = rig.read(f"getaccountrules {rig.pk['alice']} {before.get('block_number')}") or {}
    its_block = rig.read(f"getaccountrules {rig.pk['alice']} {alice.get('block_number')}") or {}
    check("the block before it does not list it, its own block does, with its sender",
          then.get("complete") is True and _fee_rows(then) == _fee_rows(before)
          and sha not in _fees(then)
          and _fee_rows(its_block) == _fee_rows(alice), (_fee_rows(then), _fee_rows(its_block)))

    proc = rig.cli("policy", "show", rig.pk["alice"])
    check("`policy show` prints the fee rules of every account and who sent each",
          proc.returncode == 0 and "fee rules (o8) of every account" in proc.stdout
          and f"sha256 {sha}  sent by {rig.pk['bob'][:12]}..." in proc.stdout,
          proc.stdout[-700:] + proc.stderr[-300:])
    rig.mine()
    rig.follower_agrees([f"getaccountrules {rig.pk['alice']}",
                         f"getaccountrules {rig.pk['bob']}",
                         f"getaccountrules {rig.pk['alice']} {alice.get('block_number')}",
                         f"gettxstatus {h}", f"gettxstatus {hb}"], label="B (fee rules)")


def run(root: str) -> int:
    rig = Rig(root)
    st: dict = {"txs": []}
    try:
        if rig.start():
            rig.mine()
            scenario_registered(rig, st)
            scenario_replaced_and_revoked(rig, st)
            scenario_plain(rig, st)
            scenario_skipped(rig, st)
            scenario_guard_and_release(rig, st)
            scenario_running_spec(rig, st)
            scenario_restart_and_follower(rig, st)
            scenario_earlier_blocks(rig, st)
            scenario_fee_rules(rig, st)
    except Exception:
        import traceback
        check("the run completed", False, traceback.format_exc()[-1500:])
    finally:
        rig.stop()
    return rig.finish()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["provision", "run"])
    parser.add_argument("--dir", default=os.path.join(rig_mod.REPO, ".local",
                                                      "e2e-rules-in-force"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS, approval_slots=True)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
