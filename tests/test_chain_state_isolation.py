"""Direct writes to the shared chain-state maps must not outlive the test."""
import chain_state
from conftest import chain_state_maps_restored

ADDRESS = "b" * 96


def _maps():
    return {name: dict(getattr(chain_state, name))
            for name in ("_balances", "_sequence_numbers", "_last_transfer_ts")}


def test_every_test_runs_under_the_restoring_fixture(request):
    assert "restore_chain_state_maps" in request.fixturenames


def test_a_direct_credit_is_undone_by_the_helper():
    before = _maps()
    with chain_state_maps_restored():
        chain_state._balances[ADDRESS] = 500
        chain_state._sequence_numbers[ADDRESS] = 3
        chain_state._last_transfer_ts[ADDRESS] = 7
    assert _maps() == before


def test_a_failing_body_still_restores_the_maps():
    before = _maps()
    try:
        with chain_state_maps_restored():
            chain_state._balances[ADDRESS] = 500
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert _maps() == before


def test_a_block_apply_leaves_the_shared_balances_as_it_found_them():
    import test_approval_apply as ap

    before = _maps()
    with chain_state_maps_restored():
        chain_state._balances[ap.BOB] = 500
        ap._apply([ap.rule_tx("always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).")])
    assert _maps() == before
