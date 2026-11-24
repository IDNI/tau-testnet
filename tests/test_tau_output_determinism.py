import json
import os
import pathlib
import subprocess
import sys

import pytest

_REPO = pathlib.Path(__file__).resolve().parent.parent
GENESIS_TAU = str(_REPO / "genesis.tau")

SENTINEL = "TAU_DETERMINISM_RESULT "
FRESH_INSTANCES = 3
REPEATED_STEPS = 3

KEY = "11" * 48
OTHER_KEY = "22" * 48

# Process-global per-stream bv-width typing forces one child per rule; the
# native engine also segfaults on teardown, so the child os._exit()s after
# emitting its result.
_CHILD_SRC = r'''
import json, os, sys
os.environ["TAU_FORCE_TEST"] = "0"
import tau_native

SENTINEL = %(sentinel)r
spec = json.loads(sys.argv[1])


def build():
    iface = tau_native.TauInterface(spec["genesis"])
    iface.communicate(
        rule_text=iface.preprocess_spec_text(spec["rule"]),
        target_output_stream_index=0,
        apply_rules_update=False,
    )
    return iface


def step(iface, row):
    values = {int(k): v for k, v in row.items()}
    out = iface.communicate_multi(
        rule_text=None, input_stream_values=values, apply_rules_update=False)
    return {str(k): v for k, v in out.items()}


fresh = []
for _ in range(spec["fresh"]):
    iface = build()
    fresh.append([step(iface, row) for row in spec["rows"]])

iface = build()
repeated = [step(iface, spec["rows"][0]) for _ in range(spec["repeats"])]

print(SENTINEL + json.dumps({"fresh": fresh, "repeated": repeated}))
sys.stdout.flush()
os._exit(0)
''' % {"sentinel": SENTINEL}


def _child_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(_REPO), env.get("PYTHONPATH", "")])
    return env


def _native_available():
    try:
        proc = subprocess.run(
            [sys.executable, "-c",
             "import tau_native; assert tau_native.load_tau_module() is not None"],
            capture_output=True, text=True, env=_child_env(), timeout=120,
        )
        return proc.returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not available")


def _run_case(rule, rows):
    spec = {
        "genesis": GENESIS_TAU,
        "rule": rule,
        "rows": rows,
        "fresh": FRESH_INSTANCES,
        "repeats": REPEATED_STEPS,
    }
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD_SRC, json.dumps(spec)],
        capture_output=True, text=True, env=_child_env(), timeout=300,
        cwd=str(_REPO),
    )
    for line in proc.stdout.splitlines():
        if line.startswith(SENTINEL):
            return json.loads(line[len(SENTINEL):])
    pytest.fail(
        f"child produced no result (rc={proc.returncode})\n"
        f"stdout:\n{proc.stdout[-2000:]}\nstderr:\n{proc.stderr[-2000:]}")


def _stream(result_rows, index):
    return [row.get(str(index)) for row in result_rows]


def _assert_identical(result, index, expected):
    for run in result["fresh"]:
        assert _stream(run, index) == expected
    for row in result["repeated"]:
        assert row.get(str(index)) == expected[0]


O1_RULE = (
    "always ((i1[t]:bv[24] > i2[t]:bv[24]) -> "
    "o1[t]:bv[24] = { #x000001 }:bv[24])."
)

O5_RULE = (
    f"always ((i3[t]:bv[384] = {{ #x{KEY} }}:bv[384] && "
    "i1[t]:bv[24] > { #x0003e8 }:bv[24]) ? "
    "o5[t]:bv[24] = { #x000000 }:bv[24] : "
    "o5[t]:bv[24] = { #x000001 }:bv[24])."
)

O9_RULE = "always (o9[t]:bv[24] = { #x00000a }:bv[24])."


def test_determinism_same_instance_repeated_inputs():
    result = _run_case(O1_RULE, [{"1": ["100"], "2": ["50"]}])
    assert len(result["repeated"]) == REPEATED_STEPS
    assert {row["1"] for row in result["repeated"]} == {"1"}


def test_determinism_fresh_instances_identical_inputs():
    result = _run_case(
        O1_RULE,
        [{"1": ["100"], "2": ["50"]}, {"1": ["50"], "2": ["100"]}],
    )
    assert len(result["fresh"]) == FRESH_INSTANCES
    for run in result["fresh"]:
        assert _stream(run, 1) == ["1", "0"]


def test_determinism_o5_user_policy():
    rows = [
        {"1": ["2000"], "3": [f"#x{KEY}"]},
        {"1": ["2000"], "3": [f"#x{OTHER_KEY}"]},
        {"1": ["10"], "3": [f"#x{KEY}"]},
    ]
    result = _run_case(O5_RULE, rows)
    _assert_identical(result, 5, ["0", "1", "1"])


def test_determinism_o9_consensus_fee():
    result = _run_case(O9_RULE, [{"1": ["100"], "5": ["1700000000"]}])
    _assert_identical(result, 9, ["10"])
