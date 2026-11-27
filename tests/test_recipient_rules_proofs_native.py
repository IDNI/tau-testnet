"""The receiver's rules, decided by the engine for every input.

`test_recipient_policy_native.py` samples: each rule against its model on a
grid of records. This file asks the engine's own `valid`, which decides a
statement for every value of every input, and `sat`, which says a rule has an
answer whatever it is fed. The rules are the ones `recipient_policy.receive_rule`
writes from the numbers of the documentation: only Alice, instant and final,
30 days and 1 hour, 500 a week, no limits, 90 days, no refunds, and all of
them in one rule.

Thirty statements. Five of them must answer False: a bound moved by one
second, one rule left out of the conjunction, the ceiling of the period
dropped. A proof file whose every statement answers True proves little about
the file.

Each statement names its expected answer. The three marked slow take from
seconds to minutes on the engine and run only with TAU_SLOW_PROOFS=1.
"""
import json
import os
import subprocess
import sys

import pytest

from consensus import recipient_policy
from consensus.rule_offers import clause_body_v1

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SLOW = os.environ.get("TAU_SLOW_PROOFS") == "1"
DAY, WEEK = 86_400, 604_800
ALICE = "8f" * 48


def _native_python():
    return os.environ.get("TAU_NATIVE_PYTHON") or sys.executable


def _child_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["TAU_ENV"] = "test"
    env["TAU_FORCE_TEST"] = "0"
    return env


def _native_available():
    try:
        proc = subprocess.run(
            [_native_python(), "-c",
             "import tau_native; assert tau_native.load_tau_module() is not None"],
            capture_output=True, text=True, env=_child_env(), timeout=120,
        )
        return proc.returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(),
                                reason="native tau module not importable")

# One engine process per run of statements: stream typing is process-wide, and
# the statements type every input the way the rules do.
_CHILD = r'''
import json, sys, time
import tau_native
tau = tau_native.load_tau_module()
answers = []
for kind, spec in json.load(sys.stdin):
    started = time.time()
    result = getattr(tau, kind)(spec)
    answers.append({"value": result.value, "seconds": round(time.time() - started, 2)})
print("\nPROOFS " + json.dumps(answers))
'''


def _ask(statements, timeout):
    proc = subprocess.run(
        [_native_python(), "-c", _CHILD], input=json.dumps(statements),
        capture_output=True, text=True, env=_child_env(), timeout=timeout,
    )
    lines = [line for line in proc.stdout.splitlines() if line.startswith("PROOFS ")]
    assert lines, (proc.returncode, proc.stderr[-800:])
    return json.loads(lines[-1][len("PROOFS "):])


# --- the rules, as the writer writes them ---------------------------------------

NUMBERS = [
    dict(senders=[ALICE]),                                              # c1
    dict(final_only=True),                                              # c2
    dict(max_hold_seconds=30 * DAY, max_recall_seconds=3_600),          # c3
    dict(min_allowance=500, per_seconds=WEEK),                          # c4
    dict(no_limits=True),                                               # c5
    dict(min_refund_seconds=90 * DAY),                                  # c6
    dict(no_refunds=True),                                              # c7
    dict(senders=[ALICE], max_hold_seconds=30 * DAY, max_recall_seconds=3_600,
         min_allowance=500, per_seconds=WEEK, min_refund_seconds=90 * DAY),   # c8
]
RULES = [recipient_policy.receive_rule(**numbers) for numbers in NUMBERS]
BODY = [clause_body_v1(rule) for rule in RULES]


def _in(index, width=64):
    return "i%d[t]:bv[%d]" % (index, width)


def _n(value, width=64):
    return "{ %d }:bv[%d]" % (value, width)


ACCEPT = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
REFUSE = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
IS_ALICE = "(i3[t]:bv[384] = { #x%s }:bv[384])" % ALICE
OWN = "(%s = %s)" % (_in(17), _n(0))
FINAL = "(%s = %s)" % (_in(17), _n(1))
TIMED = "(%s = %s)" % (_in(17), _n(2))
OWN_OR_FINAL = "(%s < %s)" % (_in(17), _n(2))
PERIOD_IN_CEILING = "(%s <= %s)" % (_in(53), _n(31_622_400))
LIMIT_IN_CEILING = "(%s <= %s)" % (_in(52), _n(16_777_215))
NO_LIMIT = "(%s = %s)" % (_in(53), _n(0))
HOLD_OK = "(!(%s > %s))" % (_in(50), _n(30 * DAY))
RECALL_OK = "(!(%s > %s))" % (_in(51), _n(3_600))
REFUND_OK = "(!(%s < %s))" % (_in(54), _n(90 * DAY))
NEVER_REFUNDED = "((%s + %s) = %s)" % (_in(54), _n(1), _n(0))
# The cap meets 500 a week: there is a whole number q of weeks, the least that
# covers the period (q weeks cover it, q - 1 do not), with cap >= 500 * q.
MEETS_500_A_WEEK = (
    "(ex q:bv[64] ( (q:bv[64] > %s) && (q:bv[64] <= %s) && ((q:bv[64] * %s) >= %s)"
    " && (((q:bv[64] - %s) * %s) < %s) && (%s >= (%s * q:bv[64])) ))"
    % (_n(0), _n(53), _n(WEEK), _in(53), _n(1), _n(WEEK), _in(53), _in(52), _n(500)))
# The same without a quantifier: the whole 500s in the cap, times a week, cover
# the period.
WHOLE_500S_COVER = "(((%s / %s) * %s) >= %s)" % (_in(52), _n(500), _n(WEEK), _in(53))
ANY = "(T)"

STATEMENTS = []     # (name, expected, kind, spec, slow)


def _valid(rule, name, expected, given, then, slow=False):
    spec = "always ( (%s) -> ( %s -> ( %s ) ) )." % (BODY[rule], given, then)
    STATEMENTS.append((name, expected, "valid", spec, slow))


_valid(0, "c1 accepts exactly: own send, or the sender is Alice", True, ANY,
       "%s <-> (%s || %s)" % (ACCEPT, OWN, IS_ALICE))
_valid(0, "c1 control: accepts exactly own sends", False, ANY, "%s <-> %s" % (ACCEPT, OWN))
_valid(1, "c2 accepts exactly: own send or final payment", True, ANY,
       "%s <-> (%s || %s)" % (ACCEPT, OWN, FINAL))
_valid(2, "c3 accepts exactly: own or final, or block time with hold <= 30 d and recall <= 1 h",
       True, ANY, "%s <-> (%s || (%s && %s && %s))" % (
           ACCEPT, OWN_OR_FINAL, TIMED, HOLD_OK, RECALL_OK))
_valid(2, "c3 control: the hold bound one second longer", False, ANY,
       "%s <-> (%s || (%s && (!(%s > %s)) && %s))" % (
           ACCEPT, OWN_OR_FINAL, TIMED, _in(50), _n(30 * DAY + 1), RECALL_OK))
_valid(3, "c4 accepts exactly: own or final, no limit, or a cap of 500 times the weeks "
          "rounded up (period <= 366 d)", True, PERIOD_IN_CEILING,
       "%s <-> (%s || %s || (%s && %s))" % (
           ACCEPT, OWN_OR_FINAL, NO_LIMIT, TIMED, MEETS_500_A_WEEK), slow=True)
_valid(3, "c4 the same without a quantifier (cap <= 2^24 - 1)", True,
       "(%s && %s)" % (PERIOD_IN_CEILING, LIMIT_IN_CEILING),
       "%s <-> (%s || %s || (%s && %s))" % (
           ACCEPT, OWN_OR_FINAL, NO_LIMIT, TIMED, WHOLE_500S_COVER), slow=True)
_valid(3, "c4 control: without the ceiling of the period the sum wraps", False, ANY,
       "%s <-> (%s || %s || (%s && %s))" % (
           ACCEPT, OWN_OR_FINAL, NO_LIMIT, TIMED, WHOLE_500S_COVER))
_valid(4, "c5 accepts exactly: own or final, or no limit", True, ANY,
       "%s <-> (%s || %s)" % (ACCEPT, OWN_OR_FINAL, NO_LIMIT))
_valid(5, "c6 accepts exactly: own or final, or block time and nothing refunded within 90 d",
       True, ANY, "%s <-> (%s || (%s && %s))" % (ACCEPT, OWN_OR_FINAL, TIMED, REFUND_OK))
_valid(6, "c7 accepts exactly: own or final, or never refunded", True, ANY,
       "%s <-> (%s || %s)" % (ACCEPT, OWN_OR_FINAL, NEVER_REFUNDED))
_valid(7, "c8 own sends always pass", True, OWN, ACCEPT)
_valid(7, "c8 an accepted incoming payment is from Alice", True,
       "(%s && !%s)" % (ACCEPT, OWN), IS_ALICE)
_valid(7, "c8 accepted with conditions: block time, hold <= 30 d", True,
       "(%s && !%s)" % (ACCEPT, OWN_OR_FINAL), "%s && %s" % (TIMED, HOLD_OK))
_valid(7, "c8 accepted with conditions: recall <= 1 h", True,
       "(%s && !%s)" % (ACCEPT, OWN_OR_FINAL), RECALL_OK)
_valid(7, "c8 accepted with conditions: nothing refunded within 90 d", True,
       "(%s && !%s)" % (ACCEPT, OWN_OR_FINAL), REFUND_OK)
_valid(7, "c8 accepted with a limit: the cap meets 500 a week (period <= 366 d)", True,
       "(%s && !%s && !%s && %s)" % (ACCEPT, OWN_OR_FINAL, NO_LIMIT, PERIOD_IN_CEILING),
       MEETS_500_A_WEEK, slow=True)
_valid(7, "c8 every condition met: accepted, so it refuses only when one fails", True,
       "(%s && %s && %s && %s && %s && (%s || (%s && %s)))" % (
           IS_ALICE, TIMED, HOLD_OK, RECALL_OK, REFUND_OK, NO_LIMIT, PERIOD_IN_CEILING,
           MEETS_500_A_WEEK), ACCEPT)
_valid(7, "c8 control: accepted with conditions means hold <= 29 d", False,
       "(%s && !%s)" % (ACCEPT, OWN_OR_FINAL), "(!(%s > %s))" % (_in(50), _n(29 * DAY)))
_valid(7, "c8 the answer is always 0 or 1", True, ANY, "%s || %s" % (ACCEPT, REFUSE))


def _renamed(body, output):
    return body.replace("o5[t]", "o%d[t]" % output)


_SINGLE = ((0, 41), (2, 43), (3, 44), (5, 46))     # sender, hold and recall, limit, refund
_EACH = " && ".join("(%s)" % _renamed(BODY[rule], out) for rule, out in _SINGLE)


def _all_accept(outputs):
    return " && ".join("(o%d[t]:bv[24] = { #x000001 }:bv[24])" % out for out in outputs)


STATEMENTS.append((
    "c8 accepts exactly when each single rule (sender, hold and recall, limit, refund) accepts",
    True, "valid", "always ( ((%s) && %s) -> ( %s <-> (%s) ) )." % (
        BODY[7], _EACH, ACCEPT, _all_accept(out for _rule, out in _SINGLE)), False))
STATEMENTS.append((
    "c8 control: the same without the refund rule", False, "valid",
    "always ( ((%s) && %s) -> ( %s <-> (%s) ) )." % (
        BODY[7], _EACH, ACCEPT, _all_accept((41, 43, 44))), False))
for _index, _rule in enumerate(RULES):
    STATEMENTS.append(("c%d has an answer for every input" % (_index + 1), True, "sat",
                       " ".join(_rule.split()), False))

FAST = [s for s in STATEMENTS if not s[4]]
SLOWER = [s for s in STATEMENTS if s[4]]


def test_there_are_thirty_statements_and_five_must_fail():
    assert len(STATEMENTS) == 30
    assert sum(1 for s in STATEMENTS if s[1] is False) == 5
    assert len({s[0] for s in STATEMENTS}) == 30
    assert len(SLOWER) == 3


def test_the_engine_answers_every_statement_as_expected():
    answers = _ask([(kind, spec) for _n, _e, kind, spec, _s in FAST], timeout=900)
    assert len(answers) == len(FAST)
    wrong = [(name, expected, answer["value"])
             for (name, expected, _k, _spec, _s), answer in zip(FAST, answers)
             if answer["value"] is not expected]
    assert wrong == []


@pytest.mark.skipif(not SLOW, reason="takes minutes; run with TAU_SLOW_PROOFS=1")
@pytest.mark.parametrize("statement", SLOWER, ids=[s[0][:40] for s in SLOWER])
def test_the_engine_answers_the_slow_statements_as_expected(statement):
    name, expected, kind, spec, _slow = statement
    (answer,) = _ask([(kind, spec)], timeout=3_600)
    assert answer["value"] is expected, name
