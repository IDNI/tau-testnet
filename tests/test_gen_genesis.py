import os
import json
import sys
import tempfile
import pytest
from unittest.mock import patch

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts import gen_genesis

import os
import json
import sys
import tempfile
import subprocess

def test_gen_genesis_fee_injection():
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "gen_genesis.py"))
    
    # Use temporary output files
    with tempfile.TemporaryDirectory() as tmpdir:
        # Base fee 10
        out_path_10 = os.path.join(tmpdir, "genesis_10.json")
        test_argv_10 = [
            "--validator-key", "a" * 96,
            "--genesis-rules-path", "genesis.tau",
            "--genesis-consensus-path", "genesis_consensus.tau",
            "--out", out_path_10,
            "--base-fee", "10"
        ]
        
        result_10 = subprocess.run(
            [sys.executable, script_path] + test_argv_10,
            capture_output=True,
            text=True,
            env=os.environ
        )
        assert result_10.returncode == 0, f"gen_genesis failed: {result_10.stderr}"

        assert os.path.exists(out_path_10)
        with open(out_path_10, "r") as f:
            genesis_data = json.load(f)
        consensus_rules = genesis_data.get("consensus_rules", "")
        assert "o9" in consensus_rules
        assert "#x000a" in consensus_rules

        # Base fee 0
        out_path_0 = os.path.join(tmpdir, "genesis_0.json")
        test_argv_0 = [
            "--validator-key", "a" * 96,
            "--genesis-rules-path", "genesis.tau",
            "--genesis-consensus-path", "genesis_consensus.tau",
            "--out", out_path_0,
            "--base-fee", "0"
        ]
        
        result_0 = subprocess.run(
            [sys.executable, script_path] + test_argv_0,
            capture_output=True,
            text=True,
            env=os.environ
        )
        assert result_0.returncode == 0, f"gen_genesis failed: {result_0.stderr}"

        assert os.path.exists(out_path_0)
        with open(out_path_0, "r") as f:
            genesis_data = json.load(f)
        consensus_rules_0 = genesis_data.get("consensus_rules", "")
        assert "o9" not in consensus_rules_0
        assert "#x000a" not in consensus_rules_0


def test_derive_pubkey_privkey_leading_zero():
    """Regression: a privkey whose hex starts with '0' must not have its leading
    zero stripped. The old lstrip("0x") stripped any leading '0'/'x' chars, making
    the key odd-length and raising "Private key contains non-hex characters"."""
    G2Basic = pytest.importorskip("py_ecc.bls").G2Basic

    # 64 hex chars, leading "00". Value is far below the BLS12-381 curve order
    # (r = 0x73ed...), so it is a valid scalar.
    privkey_hex = "00" + "11" * 31
    assert len(privkey_hex) == 64

    # Must not raise.
    derived = gen_genesis.derive_pubkey_from_privkey(privkey_hex)

    expected = G2Basic.SkToPk(int.from_bytes(bytes.fromhex(privkey_hex), "big")).hex()
    assert derived == expected
    # Leading-zero byte preserved -> derivation used the full 32-byte key.
    assert derived != gen_genesis.derive_pubkey_from_privkey("11" * 31 + "11")


def test_derive_pubkey_strips_0x_prefix():
    """A literal "0x" prefix is stripped; an embedded leading 0 is not."""
    G2Basic = pytest.importorskip("py_ecc.bls").G2Basic
    body = "00" + "11" * 31
    expected = G2Basic.SkToPk(int.from_bytes(bytes.fromhex(body), "big")).hex()
    assert gen_genesis.derive_pubkey_from_privkey("0x" + body) == expected


def test_derive_pubkey_rejects_wrong_length():
    with pytest.raises(ValueError, match="64 hex chars"):
        gen_genesis.derive_pubkey_from_privkey("00" + "11" * 30)  # 62 chars

