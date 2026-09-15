"""Real-engine characterization of the co-signature approval slots (no mocks).

These pin the engine facts the design rests on. All were measured before any
schema was frozen, and two of them contradicted the first draft of the plan.

1. AN UNFED SLOT READS 0, DETERMINISTICALLY. `_fallback_value_for_stream`
   returns "0" for every stream but i0, and supplying streams the spec does not
   reference is ignored. 0 never equals an approver pubkey, so a co-signature
   clause blocks until a real vote lands -- there is no "absent means allow"
   hole.

2. THE FLAT DISJUNCTION FORM IS EQUIVALENT TO THE NESTED CASCADE, and about
   2.5x cheaper to build. The tier table below is the actual semantics, verified
   at both sides of every boundary.

3. A bv-WIDTH CLASH FAILS CLOSED. One clause typing i18 at bv[384] and another
   at bv[24] leaves `get_interpreter` returning None -- for everyone, until the
   process restarts. This is why the clause screen is reject-unless-annotated
   rather than reject-on-mismatch.

4. THE COST CEILING IS REAL. Two policy authors build inside COMM_TIMEOUT; four
   do not (measured ~110s against a 60s timeout with a watchdog kill past it).
   MAX_TIER_AUTHORS = 2 comes from this measurement, not from taste.

Run these individually: the full native suite has a pre-existing teardown crash.
Set TAU_NATIVE_PYTHON when the venv and the built `tau.cpython-3XX-*.so` disagree
on ABI, or every case silently skips.
"""
import json
import os
import subprocess
import sys

import pytest

import tau_defs

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _native_python():
    return os.environ.get("TAU_NATIVE_PYTHON") or sys.executable


def _child_env(extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    if extra:
        env.update(extra)
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


_NATIVE = _native_available()
requires_native = pytest.mark.skipif(not _NATIVE, reason="native tau module not importable")

# Hex-LETTER keys on purpose: `_normalize_assignment_value` only prefixes "#x"
# when the value contains a hex letter, so an all-digit pubkey like "11"*48 is
# read as a decimal number, the i12 guard silently never matches, and every
# policy reads as "allow". That cost real debugging time.
ALICE = "1a" * 48
BOB = "2b" * 48
AUTH = "aa" * 48
SCAN = "bb" * 48
PARTNER = "cc" * 48
WRONG = "de" * 48

_PREAMBLE = r'''
import json, os, sys, tempfile, time
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "false"
# Deliberately no config/db import: with shrink off these cases exercise
# TauInterface at the raw layer, which never reaches the intern table, so the
# child needs only the nanobind module on PYTHONPATH.
import tau_native

SENTINEL = "SLOTS_RESULT "
ROUTER = "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)"
BASE = "o1[t]:bv[24] = i1[t]:bv[24]"

ALICE = "1a" * 48
BOB = "2b" * 48
AUTH = "aa" * 48
SCAN = "bb" * 48
PARTNER = "cc" * 48
WRONG = "de" * 48

T1, T2, T3 = 1000, 10000, 100000


def bv24(n):
    return "{ #x" + format(n, "06x") + " }:bv[24]"


def bv384(h):
    return "{ #x" + h + " }:bv[384]"


def guard(pk):
    return "(i12[t]:bv[384] = " + bv384(pk) + ")"


def o5(v):
    return "(o5[t]:bv[24] = " + bv24(v) + ")"


def flat_tier(auth=AUTH, scan=SCAN, partner=PARTNER, t1=T1, t2=T2, t3=T3):
    """The shipped clause shape: ONE conditional over a 3-term disjunction."""
    blocked = (
        " (i1[t]:bv[24] > " + bv24(t3) + " && !(i20[t]:bv[384] = " + bv384(partner) + "))"
        " || (i1[t]:bv[24] > " + bv24(t2) + " && !(i19[t]:bv[384] = " + bv384(scan) + "))"
        " || (i1[t]:bv[24] > " + bv24(t1) + " && !(i18[t]:bv[384] = " + bv384(auth) + ")) "
    )
    return "( (" + blocked + ") ? " + o5(0) + " : " + o5(1) + " )"


def cascade_tier(auth=AUTH, scan=SCAN, partner=PARTNER, t1=T1, t2=T2, t3=T3):
    """The nested equivalent, kept only to prove the two agree."""
    return (
        "( (i1[t]:bv[24] > " + bv24(t3) + " && !(i20[t]:bv[384] = " + bv384(partner) + ")) ? " + o5(0) +
        " : ((i1[t]:bv[24] > " + bv24(t2) + " && !(i19[t]:bv[384] = " + bv384(scan) + ")) ? " + o5(0) +
        " : ((i1[t]:bv[24] > " + bv24(t1) + " && !(i18[t]:bv[384] = " + bv384(auth) + ")) ? " + o5(0) +
        " : " + o5(1) + " )))"
    )


def compose(clauses):
    """Mirror consensus.rule_offers.compose_stream_rule: sorted by raw key."""
    expr = o5(1)
    for pk, body in sorted(clauses.items(), reverse=True):
        expr = "(" + guard(pk) + " ? ( " + body + " ) : " + expr + ")"
    return expr


def iface_from(*bodies):
    """Build directly from a boot file holding ONE conjoined always() unit.

    A spec is one `always ( ... ).`; multiple always() sentences joined by
    newlines or spaces make get_interpreter return None, even for the four
    shipped rules/*.tau.
    """
    spec = "always ( " + " && ".join("(" + b + ")" for b in bodies) + " )."
    f = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
    f.write(spec + "\n")
    f.close()
    t0 = time.time()
    iface = tau_native.TauInterface(f.name)
    return iface, round(time.time() - t0, 2)


def new_iface():
    f = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
    f.write(ROUTER + "\n")
    f.close()
    return tau_native.TauInterface(f.name)


def feed(iface, body):
    iface.communicate(rule_text="always ( " + body + " ).",
                      target_output_stream_index=0)


def step(iface, sender, amount, slots=None):
    vals = {"12": sender, "1": str(amount)}
    for k, v in (slots or {}).items():
        vals[str(k)] = v
    return iface.communicate_multi(input_stream_values=vals)


def emit(obj):
    # Leading newline: the engine writes to fd 1 directly and can leave a
    # partial line, which would otherwise swallow the sentinel's line start.
    print("\n" + SENTINEL + json.dumps(obj))
    sys.stdout.flush()
    # The engine segfaults on interpreter teardown (known, pre-existing). The
    # result is already computed; hard-exit before any destructor runs so the
    # child reports a clean exit code.
    os._exit(0)
'''


def _run_child(tmp_path, name, body, timeout=600):
    script = tmp_path / (name + ".py")
    script.write_text(_PREAMBLE + "\n" + body)
    # The tier table lives in the parent so the expectations and the probes
    # cannot drift; the child reads it back as JSON.
    cases = json.dumps([[label, amount, names, expected]
                        for label, amount, names, expected in TIER_TABLE])
    proc = subprocess.run(
        [_native_python(), str(script)],
        capture_output=True, text=True,
        env=_child_env({"SLOT_CASES": cases}), timeout=timeout,
    )
    marker = "SLOTS_RESULT "
    line = next((l for l in proc.stdout.splitlines() if marker in l), None)
    parsed = json.loads(line[line.index(marker) + len(marker):]) if line else None
    return proc, parsed


def _assert_ok(proc, parsed):
    assert proc.returncode == 0, (
        f"child exited {proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert parsed is not None, (
        f"child produced no result line\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


# ---------------------------------------------------------------------------
# 1. The tier table, on the real engine
# ---------------------------------------------------------------------------

# (label, amount, slots filled, expected o5). "1" = allow, "0" = block.
TIER_TABLE = [
    ("below tier 1",              500,    [],                       "1"),
    ("exactly tier 1 (> strict)", 1000,   [],                       "1"),
    ("over tier 1, no votes",     1001,   [],                       "0"),
    ("over tier 1, auth",         1001,   ["auth"],                 "1"),
    ("over tier 1, WRONG key",    1001,   ["wrong"],                "0"),
    ("exactly tier 2",            10000,  ["auth"],                 "1"),
    ("over tier 2, auth only",    10001,  ["auth"],                 "0"),
    ("over tier 2, auth+scan",    10001,  ["auth", "scan"],         "1"),
    ("exactly tier 3",            100000, ["auth", "scan"],         "1"),
    ("over tier 3, missing one",  100001, ["auth", "scan"],         "0"),
    ("over tier 3, partner only", 100001, ["partner"],              "0"),
    ("over tier 3, all three",    100001, ["auth", "scan", "partner"], "1"),
]


@requires_native
def test_the_tier_table_holds_and_unfed_slots_read_zero(tmp_path):
    proc, parsed = _run_child(tmp_path, "tier_table", r'''
res = {}
body = compose({ALICE: flat_tier()})
iface, build_s = iface_from(BASE, body)
res["build_s"] = build_s

def sl(names):
    m = {}
    if "auth" in names: m[18] = AUTH
    if "scan" in names: m[19] = SCAN
    if "partner" in names: m[20] = PARTNER
    if "wrong" in names: m[18] = WRONG
    return m

CASES = json.loads(os.environ["SLOT_CASES"])
res["table"] = []
for label, amount, names, _expected in CASES:
    out = step(iface, ALICE, amount, sl(names))
    res["table"].append([label, str(out.get(5)), str(out.get(1))])

# A third party with no policy of their own, well over every tier.
res["third_party"] = str(step(iface, BOB, 200000, {}).get(5))
emit(res)
''')
    _assert_ok(proc, parsed)

    got = {row[0]: row[1] for row in parsed["table"]}
    for label, amount, _names, expected in TIER_TABLE:
        assert got[label] == expected, (
            f"{label} (amount {amount}): expected o5={expected}, got {got[label]}"
        )
    assert parsed["third_party"] == "1", (
        "a sender with no clause of their own must be unaffected; got "
        f"o5={parsed['third_party']}"
    )


@requires_native
def test_the_flat_form_matches_the_nested_cascade(tmp_path):
    """The flat disjunction is what ships, because it is ~2.5x cheaper to build.
    It is only safe to prefer it if it means the same thing."""
    proc, parsed = _run_child(tmp_path, "flat_vs_cascade", r'''
res = {}
CASES = json.loads(os.environ["SLOT_CASES"])

def sl(names):
    m = {}
    if "auth" in names: m[18] = AUTH
    if "scan" in names: m[19] = SCAN
    if "partner" in names: m[20] = PARTNER
    if "wrong" in names: m[18] = WRONG
    return m

for form, fn in (("flat", flat_tier), ("cascade", cascade_tier)):
    iface, build_s = iface_from(BASE, compose({ALICE: fn()}))
    rows = []
    for label, amount, names, _e in CASES:
        rows.append([label, str(step(iface, ALICE, amount, sl(names)).get(5))])
    rows.append(["third_party", str(step(iface, BOB, 200000, {}).get(5))])
    res[form] = rows
    res[form + "_build_s"] = build_s
emit(res)
''')
    _assert_ok(proc, parsed)
    assert parsed["flat"] == parsed["cascade"], (
        "the flat and nested forms disagree; the cheaper one is not a drop-in\n"
        f"flat:    {parsed['flat']}\ncascade: {parsed['cascade']}"
    )


@requires_native
def test_i0_replay_matches_a_conjoined_build(tmp_path):
    """A replaying node feeds units through i0; a fresh one builds them
    conjoined. If those disagree, a restart changes the chain's verdicts."""
    proc, parsed = _run_child(tmp_path, "replay_equiv", r'''
res = {}
body = compose({ALICE: flat_tier()})
probes = [("over_t1_bare", 1001, {}), ("over_t1_auth", 1001, {18: AUTH}),
          ("below_t1", 500, {}), ("over_t3_all", 100001, {18: AUTH, 19: SCAN, 20: PARTNER})]

direct, _ = iface_from(BASE, body)
res["direct"] = {k: str(step(direct, ALICE, amt, s).get(5)) for k, amt, s in probes}
res["direct_o1"] = str(step(direct, ALICE, 777, {}).get(1))

fed = new_iface()
feed(fed, BASE)
feed(fed, body)
res["i0_fed"] = {k: str(step(fed, ALICE, amt, s).get(5)) for k, amt, s in probes}
res["i0_fed_o1"] = str(step(fed, ALICE, 777, {}).get(1))
emit(res)
''')
    _assert_ok(proc, parsed)
    assert parsed["direct"] == parsed["i0_fed"], (
        f"replay diverges: direct={parsed['direct']} i0={parsed['i0_fed']}"
    )
    # The unrelated base rule still applies, so the clause did not supersede it.
    assert parsed["direct_o1"] == parsed["i0_fed_o1"] == "777"


# ---------------------------------------------------------------------------
# 2. The width clash, and why the screen is reject-unless-annotated
# ---------------------------------------------------------------------------

@requires_native
def test_a_slot_width_clash_fails_closed(tmp_path):
    proc, parsed = _run_child(tmp_path, "width_clash", r'''
res = {}
tau_mod = tau_native.load_tau_module()
good = compose({ALICE: flat_tier()})
# Another principal typing the SAME slot at a different width.
narrow = ("(" + guard(BOB) + " ? ((i18[t]:bv[24] = { #x000001 }:bv[24])"
          " ? (o12[t]:bv[24] = { #x000001 }:bv[24])"
          " : (o12[t]:bv[24] = { #x000000 }:bv[24]))"
          " : (o12[t]:bv[24] = { #x000000 }:bv[24]))")

for label, bodies in (("consistent", [BASE, good]),
                      ("clashing", [BASE, good, narrow])):
    spec = "always ( " + " && ".join("(" + b + ")" for b in bodies) + " )."
    built = tau_mod.get_interpreter(
        tau_native.TauInterface.preprocess_spec_text(spec))
    res[label] = bool(built)
    res[label + "_err"] = tau_native.report_errors(built.report)[-300:]
emit(res)
''')
    _assert_ok(proc, parsed)
    assert parsed["consistent"] is True, (
        f"the consistent spec should build: {parsed['consistent_err']}"
    )
    assert parsed["clashing"] is False, (
        "a bv[384]/bv[24] clash on the same approval slot now builds; the "
        "reject-unless-annotated clause screen may no longer be necessary -- "
        "re-measure before relaxing it"
    )


# ---------------------------------------------------------------------------
# 3. The cost ceiling that sets MAX_TIER_AUTHORS
# ---------------------------------------------------------------------------

@requires_native
def test_two_policy_authors_stay_isolated_and_the_build_cost_stays_bounded(tmp_path):
    """Two guards in one child, because the build is the expensive part.

    ISOLATION is the strict assertion: both authors' policies must still be in
    force. A composite that loses one author is the exact regression it exists to
    prevent, and it is what a second appended rule unit would cause.

    COST is asserted loosely, and deliberately so. These children run with
    `TAU_SHRINK_ENABLED=false`, which makes the build roughly SIX TIMES dearer
    than production: tau_shrink interns the bv[384] pubkey literals down to
    bv[8], and two authors measured 13-22s with shrink on versus ~122s with it
    off. So the production headroom against the 60s COMM_TIMEOUT cannot be
    checked from here; what can be checked is that nobody has made a clause
    dramatically dearer -- reintroducing the nested cascade, for instance, was
    ~2.5x the flat form. The ceiling below is that regression alarm, not a
    production budget.
    """
    proc, parsed = _run_child(tmp_path, "cost_two_authors", r'''
res = {}
authors = {ALICE: flat_tier(), BOB: flat_tier(auth=SCAN, scan=PARTNER, partner=AUTH)}
iface, build_s = iface_from(BASE, compose(authors))
res["build_s"] = build_s
res["alice_blocked"] = str(step(iface, ALICE, 1001, {}).get(5))
res["alice_allowed"] = str(step(iface, ALICE, 1001, {18: AUTH}).get(5))
res["bob_blocked"] = str(step(iface, BOB, 1001, {}).get(5))
res["bob_allowed"] = str(step(iface, BOB, 1001, {18: SCAN}).get(5))
emit(res)
''')
    _assert_ok(proc, parsed)

    assert parsed["alice_blocked"] == "0" and parsed["alice_allowed"] == "1", parsed
    assert parsed["bob_blocked"] == "0" and parsed["bob_allowed"] == "1", (
        "the second author's policy is not in force; a composite that loses one "
        f"author is the regression it exists to prevent: {parsed}"
    )

    # Shrink-off reference: ~122s measured 2026-09-01 for two flat-form authors.
    # Production (shrink on) was 13-22s for the same shape.
    SHRINK_OFF_CEILING = 300
    assert parsed["build_s"] < SHRINK_OFF_CEILING, (
        f"two authors took {parsed['build_s']}s to build with shrink off, over "
        f"the {SHRINK_OFF_CEILING}s regression ceiling (reference: ~122s). A "
        f"clause shape has become much dearer; re-measure with shrink ON before "
        f"trusting MAX_TIER_AUTHORS."
    )


def test_the_cap_matches_what_the_measurement_supports():
    """Pure unit: a cap above 2 has never been measured as safe."""
    from consensus.approvals import MAX_TIER_AUTHORS

    assert MAX_TIER_AUTHORS <= 2, (
        "raising MAX_TIER_AUTHORS needs a fresh measurement: four authors was "
        "~110s against a 60s COMM_TIMEOUT"
    )


def test_the_slot_block_is_what_the_native_cases_assume():
    """The children hardcode i18/i19/i20, so a moved slot base must fail here
    rather than silently testing nothing."""
    assert tau_defs.APPROVAL_SLOT_BASE == 18
    assert tau_defs.APPROVAL_SLOT_COUNT >= 3
    assert tau_defs.APPROVAL_SLOT_BV_WIDTH == 384
