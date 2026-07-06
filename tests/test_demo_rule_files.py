"""Phase 4: demo rule-text files + threshold templating (pure text + one native smoke)."""
import json
import os
import subprocess
import sys
import tempfile

import pytest

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_DEMO = os.path.join(_REPO, "demo")


def _read(name):
    with open(os.path.join(_DEMO, name), encoding="utf-8") as f:
        return f.read()


def test_demo_genesis_consensus_text():
    text = _read("genesis_consensus_demo.tau")
    assert "i15[t]:bv[16]" in text
    assert "o6[t]:bv[16] = i10[t]:bv[16]" in text


def _render(threshold):
    return subprocess.run(
        [sys.executable, os.path.join(_DEMO, "render_revision.py"),
         "--stake-threshold", str(threshold)],
        capture_output=True, text=True,
    )


def test_render_revision_threshold_100000():
    r = _render(100000)
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert "{ 100000 }:bv[64] <= i14[t]:bv[64]" in out
    assert "__THRESHOLD__" not in out


def test_render_revision_threshold_zero_rejected():
    r = _render(0)
    assert r.returncode != 0
    assert "stake-threshold" in r.stderr.lower()


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _native_available(), reason="native tau module not built")
def test_demo_genesis_consensus_validates_and_builds():
    """Native smoke: gen_genesis with the demo consensus rule + --base-fee 0
    passes validate_consensus_rules (incl. the i15=0 -> o7=1 check) and produces
    an artifact. Runs gen_genesis in a subprocess (it calls os._exit)."""
    script = os.path.join(_REPO, "scripts", "gen_genesis.py")
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "genesis.json")
        result = subprocess.run(
            [sys.executable, script,
             "--validator-key", "a" * 96,
             "--genesis-rules-path", "genesis.tau",
             "--genesis-consensus-path", os.path.join(_DEMO, "genesis_consensus_demo.tau"),
             "--base-fee", "0",
             "--out", out_path],
            capture_output=True, text=True, env=os.environ, cwd=_REPO,
        )
        assert result.returncode == 0, f"gen_genesis failed:\n{result.stderr}\n{result.stdout}"
        assert os.path.exists(out_path)
        with open(out_path) as f:
            data = json.load(f)
        # Demo genesis is fee-less: no o9 term.
        assert "o9" not in data.get("consensus_rules", "")
