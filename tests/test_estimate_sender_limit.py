"""A sender key cannot hold the one estimate slot with a loop of estimates.

Each call goes through `checktx.execute` with no connection limiter, as a client
that opens a new connection for each estimate does. The clock is injected, so an
estimate takes as long as the test says.
"""
from unittest.mock import patch

import pytest

import tau_admission
from commands import sendtx
from rate_limit import KeyedBuckets
from tests.test_checktx_estimate import _check, _payload, node  # noqa: F401

ESTIMATE_TAKES = 2.0


class _Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock(node, monkeypatch):
    """Each request that reaches the admission step takes ESTIMATE_TAKES seconds."""
    clock = _Clock()
    buckets = sendtx._estimate_buckets
    monkeypatch.setattr(sendtx, "_estimate_buckets", KeyedBuckets(
        buckets.capacity, buckets.refill_per_second, buckets.max_keys, clock=clock))
    close = sendtx._AdmissionTau.close

    def slow_close(self):
        # A request closes its context after the Tau steps and again at its end.
        if not getattr(self, "_took_its_time", False):
            self._took_its_time = True
            clock.now += ESTIMATE_TAKES
        close(self)

    monkeypatch.setattr(sendtx._AdmissionTau, "close", slow_close)
    return clock


def _estimate(kind="rule_offer"):
    return _check(_payload(kind, fee_limit="1000"))


def _refused_before_the_slot(kind="rule_offer"):
    with patch("tau_admission._estimate_slot.acquire",
               side_effect=AssertionError("the estimate slot was taken")):
        env = _estimate(kind)
    return env.get("error", {}).get("code") == "ESTIMATE_BUSY"


def test_a_key_pays_for_the_time_it_held_the_slot(clock):
    # A full bucket holds 0.5 s. One estimate of 2 s leaves -1.5 s, and the
    # refill of 0.25 s each second brings it above 0 six seconds later.
    env = _estimate()
    assert "error" not in env, env
    assert clock.now == 2.0
    assert _refused_before_the_slot()

    # rule_offer_accept is signed by the second key.
    env = _estimate("rule_offer_accept")
    assert "error" not in env, env
    assert clock.now == 4.0
    assert _refused_before_the_slot()

    clock.now = 7.99
    assert _refused_before_the_slot()
    clock.now = 8.01
    env = _estimate()
    assert "error" not in env, env


def test_a_busy_slot_costs_the_key_nothing(clock):
    assert tau_admission._estimate_slot.acquire(blocking=False)
    try:
        for _ in range(10):
            env = _estimate()
            assert env["error"]["code"] == "ESTIMATE_BUSY", env
    finally:
        tau_admission._estimate_slot.release()
    assert clock.now == 10 * ESTIMATE_TAKES
    env = _estimate()
    assert "error" not in env, env


def test_the_key_used_least_recently_leaves_the_map_first():
    buckets = KeyedBuckets(1.0, 0.0, max_keys=3)
    for key in ("a", "b", "c", "a", "d"):
        assert buckets.admit(key)
    assert len(buckets) == 3
    assert "b" not in buckets
    assert all(key in buckets for key in ("a", "c", "d"))
