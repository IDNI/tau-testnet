"""A fixture that fails in its setup stops every patch that it started.

A patch left active after a failed setup changes the module globals of all
later tests in the same process.
"""
import inspect
import os
from unittest.mock import patch

import pytest

import tau_manager
from tests import test_checktx_estimate
from tests import test_fee_admission_lifecycle_types
from tests import test_retractable_admission


class _RaisingMonkeypatch:
    """Fails on the first setup line that runs after the patches start."""

    def setitem(self, *args, **kwargs):
        raise RuntimeError("setup failed")


@pytest.mark.parametrize("module", [
    test_checktx_estimate,
    test_fee_admission_lifecycle_types,
    test_retractable_admission,
], ids=lambda m: m.__name__.rsplit(".", 1)[-1])
def test_a_failed_setup_stops_the_started_patches(module):
    original_ready = tau_manager.tau_ready
    original_force = os.environ.get("TAU_FORCE_TEST")
    fixture = module.node.__wrapped__
    kwargs = {"temp_database": None, "monkeypatch": _RaisingMonkeypatch()}
    if "mock_policy_evaluators" in inspect.signature(fixture).parameters:
        kwargs["mock_policy_evaluators"] = None
    try:
        with pytest.raises(RuntimeError, match="setup failed"):
            next(fixture(**kwargs))
        assert tau_manager.tau_ready is original_ready
        assert os.environ.get("TAU_FORCE_TEST") == original_force
    finally:
        patch.stopall()
