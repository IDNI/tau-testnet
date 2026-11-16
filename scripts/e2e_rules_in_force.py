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
    6. Node A restarts and answers the same; node B replays A's blocks,
       restarts, and gives the same outcome for every transaction and the same
       rules in force for every account.

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


def scenario_replaced_and_revoked(rig, st):
    say("2. Replaced, then revoked")
    h2 = landed(rig, rule_tx(rig, "alice", PERMISSIVE), "the replacement")
    h3 = landed(rig, rule_tx(rig, "alice", NEUTRAL), "the revoke")
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
    check("nothing is left open", not view.get("open_rule_changes"), view.get("open_rule_changes"))


def scenario_restart_and_follower(rig, st):
    say("6. Node A restarts; node B replays A's blocks, restarts, and agrees")
    reads = [f"gettxstatus {h}" for h in st["txs"] if h]
    reads += [f"getaccountrules {rig.pk[n]}" for n in ACTORS if n != "miner"]
    before = {cmd: rig_mod.stable(rig.read(cmd)) for cmd in reads}
    if rig.restart_a():
        after = {cmd: rig_mod.stable(rig.read(cmd)) for cmd in reads}
        check("after A's restart every outcome and every account reads the same",
              before == after, [c for c in reads if before[c] != after[c]][:3])
    rig.mine()
    rig.follower_agrees(reads)


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
            scenario_restart_and_follower(rig, st)
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
