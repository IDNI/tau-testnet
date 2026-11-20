"""Tests for consensus.sweep (Bounty 01, Stage 1).

The framework is tested with stub handlers: ordering, the per-block cap with
overflow carried to the next run, failure isolation (one item never fails the
block), and the empty no-op. No book is registered in Stage 1, so the engine
hook must also be a no-op.
"""
import pytest

from consensus.sweep import (
    MAX_SWEEP_ACTIONS_PER_BLOCK,
    SweepContext,
    SweepDue,
    SweepRegistry,
    run_programmable_sweep,
)


class StubHandler:
    """A book that reports a fixed list and executes by removing items."""

    def __init__(self, items, fail_on=None):
        self._items = list(items)
        self.fail_on = fail_on
        self.executed = []

    def collect_due(self, lm, height, ts):
        return list(self._items)

    def execute(self, item, ctx):
        if self.fail_on is not None and item.object_id == self.fail_on:
            raise RuntimeError("boom")
        self._items.remove(item)
        self.executed.append(item)
        return "executed"


def _ctx():
    return SweepContext(lm=None, balances={}, sequences={}, height=1, timestamp=100)


def test_empty_registry_is_a_noop():
    report = SweepRegistry().run(_ctx())
    assert report.executed == [] and report.failed == [] and report.deferred == []
    assert report.summary() == {"executed": [], "failed": [], "deferred": []}


def test_deterministic_order_is_due_ts_then_object_id():
    registry = SweepRegistry()
    registry.register(
        "g",
        StubHandler(
            [
                SweepDue(100, b"\x02", "g"),
                SweepDue(50, b"\x01", "g"),
                SweepDue(50, b"\x03", "g"),
            ]
        ),
    )
    report = registry.run(_ctx(), cap=10)
    assert [item.object_id for item, _ in report.executed] == [b"\x01", b"\x03", b"\x02"]
    assert [outcome for _, outcome in report.executed] == ["executed"] * 3


def test_cap_defers_overflow_and_next_run_carries_it():
    handler = StubHandler(
        [SweepDue(10, b"\x01", "g"), SweepDue(20, b"\x02", "g"), SweepDue(30, b"\x03", "g")]
    )
    registry = SweepRegistry()
    registry.register("g", handler)
    first = registry.run(_ctx(), cap=2)
    assert [item.object_id for item, _ in first.executed] == [b"\x01", b"\x02"]
    assert [item.object_id for item in first.deferred] == [b"\x03"]
    # The deferred item is still due in its book, so the next block runs it.
    second = registry.run(_ctx(), cap=10)
    assert [item.object_id for item, _ in second.executed] == [b"\x03"]
    assert second.deferred == []


def test_default_cap_is_the_module_constant():
    assert MAX_SWEEP_ACTIONS_PER_BLOCK == 256
    handler = StubHandler([SweepDue(0, i.to_bytes(2, "big"), "g") for i in range(300)])
    registry = SweepRegistry()
    registry.register("g", handler)
    report = registry.run(_ctx())
    assert len(report.executed) == 256
    assert len(report.deferred) == 44


def test_one_failure_does_not_fail_the_block():
    registry = SweepRegistry()
    registry.register(
        "g",
        StubHandler(
            [SweepDue(10, b"\x01", "g"), SweepDue(20, b"\x02", "g"), SweepDue(30, b"\x03", "g")],
            fail_on=b"\x02",
        ),
    )
    report = registry.run(_ctx(), cap=10)
    assert [item.object_id for item, _ in report.executed] == [b"\x01", b"\x03"]
    assert len(report.failed) == 1
    assert report.failed[0][0].object_id == b"\x02"
    assert "RuntimeError: boom" in report.failed[0][1]
    assert report.deferred == []


def test_duplicate_registration_and_bad_cap_raise():
    registry = SweepRegistry()
    registry.register("g", StubHandler([]))
    with pytest.raises(ValueError, match="already registered"):
        registry.register("g", StubHandler([]))
    with pytest.raises(ValueError):
        registry.run(_ctx(), cap=-1)


def test_sweep_due_validation():
    with pytest.raises(ValueError):
        SweepDue(-1, b"\x01", "g")
    with pytest.raises(ValueError):
        SweepDue(0, b"", "g")
    with pytest.raises(ValueError):
        SweepDue(0, b"\x01", "")


def test_engine_hook_is_a_noop_with_no_handlers():
    # An empty registry (what the default registry is in Stage 1) runs nothing.
    report = run_programmable_sweep(
        None, {}, {}, height=20, timestamp=1234567890, registry=SweepRegistry()
    )
    assert report.executed == [] and report.failed == [] and report.deferred == []
