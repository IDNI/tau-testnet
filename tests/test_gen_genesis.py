import os
import json
import sys
import tempfile
import pytest
from unittest.mock import patch

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts import gen_genesis

def test_gen_genesis_fee_injection():
    # Use temporary output files
    with tempfile.TemporaryDirectory() as tmpdir:
        # Base fee 10
        out_path_10 = os.path.join(tmpdir, "genesis_10.json")
        test_argv_10 = [
            "gen_genesis.py",
            "--validator-key", "a" * 96,
            "--genesis-rules-path", "genesis.tau",
            "--genesis-consensus-path", "genesis_consensus.tau",
            "--out", out_path_10,
            "--base-fee", "10"
        ]
        with patch("sys.argv", test_argv_10):
            try:
                gen_genesis.main()
            except SystemExit as e:
                assert e.code == 0 or e.code is None

        assert os.path.exists(out_path_10)
        with open(out_path_10, "r") as f:
            genesis_data = json.load(f)
        consensus_rules = genesis_data.get("consensus_rules", "")
        assert "o9" in consensus_rules
        assert "#x000a" in consensus_rules

        # Base fee 0
        out_path_0 = os.path.join(tmpdir, "genesis_0.json")
        test_argv_0 = [
            "gen_genesis.py",
            "--validator-key", "a" * 96,
            "--genesis-rules-path", "genesis.tau",
            "--genesis-consensus-path", "genesis_consensus.tau",
            "--out", out_path_0,
            "--base-fee", "0"
        ]
        with patch("sys.argv", test_argv_0):
            try:
                gen_genesis.main()
            except SystemExit as e:
                assert e.code == 0 or e.code is None

        assert os.path.exists(out_path_0)
        with open(out_path_0, "r") as f:
            genesis_data = json.load(f)
        consensus_rules_0 = genesis_data.get("consensus_rules", "")
        assert "o9" not in consensus_rules_0
        assert "#x000a" not in consensus_rules_0
