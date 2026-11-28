"""`tau-testnet blocks` reads a chain larger than one answer in pages."""

from __future__ import annotations

import io
import json
import types
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import pytest

from commands import getblocks
from tau_testnet_cli import cli
from tau_testnet_cli import rpc as rpc_mod


def _rows(heights, fork_heights=()):
    rows = []
    for i in range(heights):
        rows.append({"block_hash": f"{i:064x}", "header": {"block_number": i}})
        if i in fork_heights:
            rows.append({"block_hash": f"f{i:063x}", "header": {"block_number": i}})
    return rows


def _paged_db(rows):
    def in_range(start, count):
        page = [r for r in rows if start <= r["header"]["block_number"] < start + count]
        above = [r["header"]["block_number"] for r in rows
                 if r["header"]["block_number"] >= start + count]
        return page, (min(above) if above else None)

    return types.SimpleNamespace(
        get_all_blocks=lambda: list(rows),
        get_block_count=lambda: len(rows),
        get_recent_blocks=lambda n: list(rows[-n:]),
        get_blocks_in_height_range=in_range,
    )


def _run(argv, db, *, cap=None, recorded=None):
    """Run the CLI against a node that answers with the real getblocks handler.

    ``cap`` stands in for the read cap of rpc.send_command, in bytes.
    """
    container = types.SimpleNamespace(db=db)

    def fake_send(command, host, port, *, timeout=10.0, max_bytes=None):
        if recorded is not None:
            recorded.append(command)
        response = getblocks.execute(command, container)
        if cap is not None and len(response) > cap:
            raise rpc_mod.RpcSizeLimitError(f"exceeded {cap} bytes")
        return response

    out, err = io.StringIO(), io.StringIO()
    with patch("tau_testnet_cli.rpc.send_command", side_effect=fake_send), \
         redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


def _numbers(out):
    return [b["header"]["block_number"] for b in json.loads(out)["data"]["blocks"]]


def test_blocks_reads_a_chain_larger_than_one_page():
    heights = 2 * cli.BLOCK_PAGE_HEIGHTS + 7
    rows = _rows(heights, fork_heights={cli.BLOCK_PAGE_HEIGHTS - 1})
    recorded = []
    rc, out, err = _run(["blocks"], _paged_db(rows), recorded=recorded)
    assert rc == 0, err
    assert recorded == [
        f"getblocks {cli.BLOCK_PAGE_HEIGHTS} 0",
        f"getblocks {cli.BLOCK_PAGE_HEIGHTS} {cli.BLOCK_PAGE_HEIGHTS}",
        f"getblocks {cli.BLOCK_PAGE_HEIGHTS} {2 * cli.BLOCK_PAGE_HEIGHTS}",
    ]
    data = json.loads(out)["data"]
    assert [b["block_hash"] for b in data["blocks"]] == [r["block_hash"] for r in rows]
    assert data["total"] == len(rows)
    assert data["truncated"] is False


def test_blocks_halves_the_page_when_an_answer_exceeds_the_cap():
    rows = _rows(cli.BLOCK_PAGE_HEIGHTS + 5)
    one_page = len(getblocks.execute(f"getblocks {cli.BLOCK_PAGE_HEIGHTS} 0",
                                     types.SimpleNamespace(db=_paged_db(rows))))
    recorded = []
    rc, out, err = _run(["blocks"], _paged_db(rows), cap=one_page - 1, recorded=recorded)
    assert rc == 0, err
    half = cli.BLOCK_PAGE_HEIGHTS // 2
    assert recorded[:2] == [f"getblocks {cli.BLOCK_PAGE_HEIGHTS} 0", f"getblocks {half} 0"]
    assert _numbers(out) == list(range(len(rows)))


def test_blocks_gives_up_when_one_height_exceeds_the_cap():
    recorded = []
    rc, _, err = _run(["blocks"], _paged_db(_rows(3)), cap=10, recorded=recorded)
    assert rc == cli.EXIT_NETWORK
    assert "exceeded 10 bytes" in err
    assert recorded[-1] == "getblocks 1 0"


def test_large_limit_reads_the_most_recent_rows_in_pages():
    rows = _rows(3 * cli.BLOCK_PAGE_HEIGHTS, fork_heights={250})
    limit = cli.BLOCK_PAGE_HEIGHTS + 20
    recorded = []
    rc, out, err = _run(["blocks", "--limit", str(limit)], _paged_db(rows), recorded=recorded)
    assert rc == 0, err
    assert recorded[0] == "getblocks 1"
    tip = 3 * cli.BLOCK_PAGE_HEIGHTS - 1
    assert recorded[1] == f"getblocks {cli.BLOCK_PAGE_HEIGHTS} {tip - limit + 1}"
    data = json.loads(out)["data"]
    # The same rows as one `getblocks <limit>` answer.
    assert [b["block_hash"] for b in data["blocks"]] == [r["block_hash"] for r in rows[-limit:]]
    assert data["total"] == len(rows)
    assert data["truncated"] is True


def test_small_limit_sends_one_window_request():
    recorded = []
    rc, out, err = _run(["blocks", "--limit", "10"], _paged_db(_rows(50)), recorded=recorded)
    assert rc == 0, err
    assert recorded == ["getblocks 10"]
    assert _numbers(out) == list(range(40, 50))


def test_large_limit_over_a_gap_gives_the_rows_of_one_window_request():
    # An orphan far above the chain makes `getblocks 1` report height 5000.
    rows = _rows(300) + [{"block_hash": "e" * 64, "header": {"block_number": 5000}}]
    db = _paged_db(rows)
    window = json.loads(getblocks.execute("getblocks 120", types.SimpleNamespace(db=db)))
    recorded = []
    rc, out, err = _run(["blocks", "--limit", "120"], db, recorded=recorded)
    assert rc == 0, err
    data = json.loads(out)["data"]
    assert [b["block_hash"] for b in data["blocks"]] == [
        b["block_hash"] for b in window["data"]["blocks"]
    ]
    assert len(data["blocks"]) == 120
    assert data["total"] == len(rows)
    assert data["truncated"] is True
    # Empty pages of the gap double in size, so the gap costs few requests.
    assert len(recorded) < 15, recorded


def test_large_limit_above_the_chain_length_stops_at_height_zero():
    rows = _rows(150)
    rc, out, err = _run(["blocks", "--limit", "500"], _paged_db(rows))
    assert rc == 0, err
    assert _numbers(out) == list(range(150))
    assert json.loads(out)["data"]["truncated"] is False


def test_page_below_halves_when_an_answer_exceeds_the_cap():
    # The read below the first height meets the cap too.
    rows = _rows(300) + [{"block_hash": "e" * 64, "header": {"block_number": 1000}}]
    db = _paged_db(rows)
    one_page = len(getblocks.execute(f"getblocks {cli.BLOCK_PAGE_HEIGHTS} 0",
                                     types.SimpleNamespace(db=db)))
    recorded = []
    rc, out, err = _run(["blocks", "--limit", "150"], db, cap=one_page - 1, recorded=recorded)
    assert rc == 0, err
    assert [b["block_hash"] for b in json.loads(out)["data"]["blocks"]] == [
        r["block_hash"] for r in rows[-150:]
    ]
    # A halving asks again for the same end height with fewer heights.
    ranges = [tuple(int(x) for x in c.split()[1:]) for c in recorded if len(c.split()) == 3]
    assert any(
        a[0] + a[1] == b[0] + b[1] and b[0] < a[0]
        for a, b in zip(ranges, ranges[1:])
    ), recorded


# With the orphan at 1869, the first page below with rows holds only 50 of
# the 119 rows that are still needed, so more pages follow it.
@pytest.mark.parametrize("orphan", [5000, 1869])
def test_page_below_returns_to_the_normal_size_after_a_gap(orphan):
    rows = _rows(300) + [{"block_hash": "e" * 64, "header": {"block_number": orphan}}]
    db = _paged_db(rows)
    window = json.loads(getblocks.execute("getblocks 120", types.SimpleNamespace(db=db)))
    recorded = []
    rc, out, err = _run(["blocks", "--limit", "120"], db, recorded=recorded)
    assert rc == 0, err
    assert [b["block_hash"] for b in json.loads(out)["data"]["blocks"]] == [
        b["block_hash"] for b in window["data"]["blocks"]
    ]
    pages = [tuple(int(x) for x in c.split()[1:]) for c in recorded if len(c.split()) == 3]

    def holds_rows(page):
        heights, start = page
        return any(start <= r["header"]["block_number"] < start + heights
                   for r in rows if r["header"]["block_number"] != orphan)

    first_with_rows = next(i for i, p in enumerate(pages) if holds_rows(p))
    assert all(h <= cli.BLOCK_PAGE_HEIGHTS for h, _ in pages[first_with_rows + 1:]), recorded


# 111 orphan rows above the gap leave 9 rows to read below. A trim to the
# needed rows inside the gap would stop the doubling.
@pytest.mark.parametrize("top", [5000, 100000])
def test_gap_with_few_rows_needed_below_costs_few_requests(top):
    orphans = [{"block_hash": f"e{n:063x}", "header": {"block_number": n}}
               for n in range(top - 110, top + 1)]
    rows = _rows(300) + orphans
    db = _paged_db(rows)
    window = json.loads(getblocks.execute("getblocks 120", types.SimpleNamespace(db=db)))
    recorded = []
    rc, out, err = _run(["blocks", "--limit", "120"], db, recorded=recorded)
    assert rc == 0, err
    assert [b["block_hash"] for b in json.loads(out)["data"]["blocks"]] == [
        b["block_hash"] for b in window["data"]["blocks"]
    ]
    assert len(recorded) <= 25, recorded


def test_page_below_gives_up_when_one_height_exceeds_the_cap():
    # Height 250 alone is over the cap. The forward read from 851 skips it.
    rows = _rows(300) + [{"block_hash": "e" * 64, "header": {"block_number": 1000}}]
    rows[250]["payload"] = "x" * 50_000
    recorded = []
    rc, _, err = _run(["blocks", "--limit", "150"], _paged_db(rows), cap=40_000,
                      recorded=recorded)
    assert rc == cli.EXIT_NETWORK
    assert "exceeded 40000 bytes" in err
    assert recorded[-1] == "getblocks 1 250"
    assert all(int(c.split()[2]) < 851 for c in recorded[3:]), recorded


def _run_canned(argv, answer, recorded=None):
    def fake_send(command, *a, **k):
        if recorded is not None:
            recorded.append(command)
        return answer(command)

    out, err = io.StringIO(), io.StringIO()
    with patch("tau_testnet_cli.rpc.send_command", side_effect=fake_send), \
         redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


_OLD_USAGE = json.dumps({
    "status": "error", "command": "getblocks",
    "error": {"code": "INVALID_PARAMS", "message": "Usage: getblocks [limit]"},
})


def _full_chain(rows):
    return json.dumps({"status": "ok", "command": "getblocks",
                       "data": {"blocks": rows, "total": len(rows), "truncated": False}})


def test_old_node_that_rejects_the_start_gets_one_bare_request():
    full = _full_chain(_rows(5))
    recorded = []
    rc, out, err = _run_canned(
        ["blocks"], lambda c: full if c == "getblocks" else _OLD_USAGE, recorded
    )
    assert rc == 0, err
    assert recorded == [f"getblocks {cli.BLOCK_PAGE_HEIGHTS} 0", "getblocks"]
    assert out.strip() == full


def test_old_node_with_a_chain_over_the_cap_keeps_exit_code_3():
    def answer(command):
        if command == "getblocks":
            raise rpc_mod.RpcSizeLimitError("exceeded 4194304 bytes")
        return _OLD_USAGE

    rc, out, err = _run_canned(["blocks"], answer)
    assert rc == cli.EXIT_NETWORK
    assert out == ""
    assert "exceeded 4194304 bytes" in err


def test_old_node_that_ignores_the_start_gets_one_bare_request():
    # A node that ignores every argument sends the chain with no next_start.
    full = json.dumps({"status": "ok", "command": "getblocks",
                       "data": {"blocks": _rows(5)}})
    recorded = []
    rc, out, err = _run_canned(["blocks"], lambda c: full, recorded)
    assert rc == 0, err
    assert recorded == [f"getblocks {cli.BLOCK_PAGE_HEIGHTS} 0", "getblocks"]
    assert out.strip() == full


def test_old_node_with_a_large_limit_gets_one_window_request():
    window = _full_chain(_rows(150))
    tip = _full_chain(_rows(150)[-1:])
    recorded = []
    rc, out, err = _run_canned(
        ["blocks", "--limit", "150"],
        lambda c: {"getblocks 1": tip, "getblocks 150": window}.get(c, _OLD_USAGE),
        recorded,
    )
    assert rc == 0, err
    assert recorded == ["getblocks 1", f"getblocks {cli.BLOCK_PAGE_HEIGHTS} 0", "getblocks 150"]
    assert out.strip() == window


def test_node_error_on_a_page_is_passed_through():
    failure = json.dumps({
        "status": "error", "command": "getblocks",
        "error": {"code": "INTERNAL_ERROR", "message": "Failed to fetch blocks: disk gone"},
    })
    rc, out, _ = _run_canned(["blocks"], lambda c: failure)
    assert rc == cli.EXIT_APP_ERROR
    assert out.strip() == failure


def test_next_start_that_does_not_advance_stops_the_read():
    stuck = json.dumps({"status": "ok", "command": "getblocks",
                        "data": {"blocks": [], "total": 0, "next_start": 0}})
    rc, out, _ = _run_canned(["blocks"], lambda c: stuck)
    assert rc == cli.EXIT_APP_ERROR
    assert json.loads(out)["error"]["code"] == "BAD_RESPONSE"
