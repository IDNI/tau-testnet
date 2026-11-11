"""Clause registration on the real policy worker, through the real block apply.

Three authors (more than the former cap of two) register different clauses, each
one's transfers are judged by its own clause only, another sender is unaffected,
and a clause the engine cannot build is rejected at registration. The main
interpreter is stubbed to allow everything, so every verdict seen here comes
from a per-account clause.
"""
import os

import pytest

import tau_policy
from bls_keys import pubkey_hex
from consensus import sender_policy
from consensus.rule_offers import clause_body_v1


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

import test_clause_registration as reg  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMEOUT = 120.0

# Blocks every positive amount; reads i1, which a clause needs to be stepped.
BLOCKER_RULE = (
    "always ( (i1[t]:bv[24] > { #x000000 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)

# Stream i30 is typed bv[8] by the first clause that mentions it, so a constant
# of another width cannot build.
UNBUILDABLE_RULE = (
    "always ( (i30[t]:bv[8] = { #x0001 }:bv[16]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture
def policy_worker():
    evaluator = tau_policy.PolicyEvaluator(pool="apply", cwd=REPO, env=_env(),
                                           timeout=TIMEOUT)
    sender_policy.set_evaluator("apply", evaluator)
    yield evaluator
    sender_policy.set_evaluator("apply", None)
    evaluator.close()


def test_three_authors_are_each_judged_by_their_own_clause(policy_worker):
    names = ("blocker", "limited", "opener", "bystander")
    keys = {name: (8100 + i, pubkey_hex(8100 + i)) for i, name in enumerate(names)}
    chain = reg.Chain(list(keys.values()))
    rules = {"blocker": BLOCKER_RULE, "limited": reg.LIMIT_RULE, "opener": reg.OPEN_RULE}

    registrations = [
        reg.routed_tx(*keys["blocker"], rules["blocker"]),
        reg.routed_tx(*keys["limited"], rules["limited"]),
        reg.accept_tx(keys["opener"][0], reg.offer_to(chain, keys["opener"][1],
                                                      rules["opener"])),
    ]
    (result,) = chain.apply_in_budget(registrations)
    assert not result.invalid_tx_ids, result.outcomes
    for name, rule in rules.items():
        assert chain.clause(keys[name][1]) == clause_body_v1(rule)

    transfers = {
        "blocker": reg.transfer_tx(*keys["blocker"], 500, seq=1),
        "limited_small": reg.transfer_tx(*keys["limited"], 500, seq=1),
        "limited_large": reg.transfer_tx(*keys["limited"], 2000, seq=2),
        "opener": reg.transfer_tx(*keys["opener"], 2000, seq=1),
        "bystander": reg.transfer_tx(*keys["bystander"], 2000, seq=0),
    }
    result = chain.apply(list(transfers.values()))
    rejected = {name for name, tx in transfers.items()
                if tx["tx_id"] in result.invalid_tx_ids}
    assert rejected == {"blocker", "limited_large"}, result.outcomes


def test_a_clause_the_engine_cannot_build_is_rejected_at_registration(policy_worker):
    key = (8200, pubkey_hex(8200))
    chain = reg.Chain([key])

    ok, error = sender_policy.clause_builds(
        clause_body_v1(UNBUILDABLE_RULE), pool="apply", timeout=TIMEOUT)
    assert ok is False and error, "the engine must refuse this body"

    tx = reg.routed_tx(*key, UNBUILDABLE_RULE)
    (result,) = chain.apply_in_budget([tx])
    assert tx["tx_id"] in result.invalid_tx_ids, result.outcomes
    assert chain.clause(key[1]) is None
