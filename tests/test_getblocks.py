"""getblocks limit windowing.

The CLI has always sent `getblocks <N>` for `blocks --limit N`; the handler
used to ignore it and return the whole chain.
"""
import json
import types

import pytest

from commands import getblocks


def _container(count):
    blocks = [
        {"block_hash": f"{i:064x}", "header": {"block_number": i}}
        for i in range(count)
    ]

    def get_all_blocks():
        return list(blocks)

    return types.SimpleNamespace(db=types.SimpleNamespace(get_all_blocks=get_all_blocks))


def _run(command, count=25):
    return json.loads(getblocks.execute(command, _container(count)))


def _numbers(data):
    return [b["header"]["block_number"] for b in data["blocks"]]


def test_bare_getblocks_returns_everything():
    resp = _run("getblocks")
    assert resp["status"] == "ok", resp
    assert _numbers(resp["data"]) == list(range(25))
    assert resp["data"]["total"] == 25
    assert resp["data"]["truncated"] is False


def test_limit_returns_the_most_recent_n_in_ascending_order():
    resp = _run("getblocks 10")
    assert resp["status"] == "ok", resp
    # The tail of the chain, still oldest -> newest.
    assert _numbers(resp["data"]) == list(range(15, 25))
    assert resp["data"]["total"] == 25
    assert resp["data"]["truncated"] is True


def test_limit_of_one_returns_the_tip():
    resp = _run("getblocks 1")
    assert _numbers(resp["data"]) == [24]
    assert resp["data"]["truncated"] is True


def test_limit_above_chain_length_returns_everything_untruncated():
    resp = _run("getblocks 500")
    assert _numbers(resp["data"]) == list(range(25))
    assert resp["data"]["total"] == 25
    assert resp["data"]["truncated"] is False


def test_limit_on_an_empty_chain():
    resp = _run("getblocks 10", count=0)
    assert resp["status"] == "ok", resp
    assert resp["data"] == {"blocks": [], "total": 0, "truncated": False}


@pytest.mark.parametrize("arg", ["0", "-1", "abc", "1.5", "", "10x"])
def test_bad_limit_is_invalid_params(arg):
    resp = _run(f"getblocks {arg}")
    # "" splits away entirely and is the bare form; everything else rejects.
    if arg == "":
        assert resp["status"] == "ok", resp
        return
    assert resp["status"] == "error", resp
    assert resp["error"]["code"] == "INVALID_PARAMS"
    assert "getblocks [limit]" in resp["error"]["message"]


def test_extra_arguments_rejected():
    resp = _run("getblocks 10 20 30")
    assert resp["status"] == "error", resp
    assert resp["error"]["code"] == "INVALID_PARAMS"
    assert "getblocks [limit] [start]" in resp["error"]["message"]


def _add_chain(heights, fork_heights=()):
    """Blocks 0..heights-1, plus a second row at each height in fork_heights."""
    import db
    from block import Block

    prev = "00" * 32
    for i in range(heights):
        blk = Block.create(
            block_number=i,
            previous_hash=prev,
            transactions=[],
            proposer_pubkey="a" * 96,
            timestamp=1_700_000_000 + i,
        )
        db.add_block(blk)
        if i in fork_heights:
            db.add_block(Block.create(
                block_number=i,
                previous_hash=prev,
                transactions=[],
                proposer_pubkey="b" * 96,
                timestamp=1_700_000_500 + i,
            ))
        prev = blk.block_hash


def _run_db(command):
    import db

    return json.loads(getblocks.execute(command, types.SimpleNamespace(db=db)))


def test_page_from_start_returns_limit_heights_and_next_start(temp_database):
    _add_chain(10)
    resp = _run_db("getblocks 4 0")
    assert resp["status"] == "ok", resp
    assert _numbers(resp["data"]) == [0, 1, 2, 3]
    assert resp["data"]["start"] == 0
    assert resp["data"]["next_start"] == 4
    assert resp["data"]["total"] == 10
    assert resp["data"]["truncated"] is True


def test_last_page_has_no_next_start(temp_database):
    _add_chain(10)
    resp = _run_db("getblocks 4 8")
    assert _numbers(resp["data"]) == [8, 9]
    assert resp["data"]["next_start"] is None
    assert resp["data"]["truncated"] is False


def test_start_above_the_head_is_an_empty_last_page(temp_database):
    _add_chain(3)
    resp = _run_db("getblocks 4 50")
    assert resp["status"] == "ok", resp
    assert resp["data"]["blocks"] == []
    assert resp["data"]["next_start"] is None
    assert resp["data"]["total"] == 3


def test_page_keeps_both_rows_of_a_forked_height_at_its_edge(temp_database):
    _add_chain(6, fork_heights={3})
    first = _run_db("getblocks 4 0")
    assert _numbers(first["data"]) == [0, 1, 2, 3, 3]
    assert first["data"]["next_start"] == 4
    second = _run_db("getblocks 4 4")
    assert _numbers(second["data"]) == [4, 5]
    assert second["data"]["next_start"] is None
    assert first["data"]["total"] == 7


def test_page_next_start_crosses_a_gap_in_the_heights(temp_database):
    import db
    from block import Block

    _add_chain(5)
    db.add_block(Block.create(
        block_number=40,
        previous_hash="11" * 32,
        transactions=[],
        proposer_pubkey="c" * 96,
        timestamp=1_700_001_000,
    ))
    first = _run_db("getblocks 3 3")
    assert _numbers(first["data"]) == [3, 4]
    assert first["data"]["next_start"] == 40
    second = _run_db("getblocks 3 40")
    assert _numbers(second["data"]) == [40]
    assert second["data"]["next_start"] is None


@pytest.mark.parametrize("command", [
    "getblocks 1 9223372036854775808",
    "getblocks 9223372036854775808 0",
    "getblocks 9223372036854775808",
])
def test_argument_above_the_sqlite_range_is_invalid_params(temp_database, command):
    _add_chain(2)
    resp = _run_db(command)
    assert resp["status"] == "error", resp
    assert resp["error"]["code"] == "INVALID_PARAMS"
    assert "must be <= 9223372036854775807" in resp["error"]["message"]


def test_page_at_the_top_of_the_sqlite_range(temp_database):
    _add_chain(2)
    resp = _run_db("getblocks 9223372036854775807 9223372036854775807")
    assert resp["status"] == "ok", resp
    assert resp["data"]["blocks"] == []
    assert resp["data"]["next_start"] is None
    resp = _run_db("getblocks 9223372036854775807 1")
    assert _numbers(resp["data"]) == [1]


def test_page_does_not_load_the_full_chain():
    def boom():
        raise AssertionError("should not load the full chain")

    db = types.SimpleNamespace(
        get_all_blocks=boom,
        get_block_count=lambda: 100,
        get_blocks_in_height_range=lambda start, count: (
            [{"header": {"block_number": i}} for i in range(start, start + count)],
            start + count,
        ),
    )
    resp = json.loads(getblocks.execute("getblocks 5 20", types.SimpleNamespace(db=db)))
    assert resp["status"] == "ok", resp
    assert _numbers(resp["data"]) == list(range(20, 25))
    assert resp["data"]["next_start"] == 25


@pytest.mark.parametrize("arg", ["-1", "abc", "1.5", "3x"])
def test_bad_start_is_invalid_params(arg):
    resp = _run(f"getblocks 10 {arg}")
    assert resp["status"] == "error", resp
    assert resp["error"]["code"] == "INVALID_PARAMS"
    assert resp["error"]["message"].startswith("start must be")
    assert "getblocks [limit] [start]" in resp["error"]["message"]


def test_bad_limit_with_a_start_is_invalid_params():
    resp = _run("getblocks 0 5")
    assert resp["status"] == "error", resp
    assert resp["error"]["message"].startswith("limit must be >= 1")


def test_page_db_failure_is_internal_error():
    def boom(start, count):
        raise RuntimeError("disk gone")

    db = types.SimpleNamespace(get_blocks_in_height_range=boom, get_block_count=lambda: 0)
    resp = json.loads(getblocks.execute("getblocks 5 0", types.SimpleNamespace(db=db)))
    assert resp["status"] == "error", resp
    assert resp["error"]["code"] == "INTERNAL_ERROR"


def test_limited_getblocks_uses_recent_window_not_full_scan():
    """A windowed query must not parse the whole chain (that's what stalled the node)."""

    def boom():
        raise AssertionError("should not load the full chain")

    db = types.SimpleNamespace(
        get_all_blocks=boom,
        get_block_count=lambda: 100,
        get_recent_blocks=lambda n: [
            {"header": {"block_number": i}} for i in range(100 - n, 100)
        ],
    )
    resp = json.loads(
        getblocks.execute("getblocks 10", types.SimpleNamespace(db=db))
    )
    assert resp["status"] == "ok", resp
    assert _numbers(resp["data"]) == list(range(90, 100))
    assert resp["data"]["total"] == 100
    assert resp["data"]["truncated"] is True


def test_get_recent_blocks_sql_limit(temp_database):
    import db
    from block import Block

    prev = "00" * 32
    for i in range(5):
        blk = Block.create(
            block_number=i,
            previous_hash=prev,
            transactions=[],
            proposer_pubkey="a" * 96,
            timestamp=1_700_000_000 + i,
        )
        db.add_block(blk)
        prev = blk.block_hash
    assert db.get_block_count() == 5
    assert [b["header"]["block_number"] for b in db.get_recent_blocks(2)] == [3, 4]
    assert [b["header"]["block_number"] for b in db.get_all_blocks()] == list(range(5))


def test_db_failure_is_internal_error():
    def boom():
        raise RuntimeError("disk gone")

    container = types.SimpleNamespace(
        db=types.SimpleNamespace(get_all_blocks=boom)
    )
    resp = json.loads(getblocks.execute("getblocks", container))
    assert resp["status"] == "error", resp
    assert resp["error"]["code"] == "INTERNAL_ERROR"
    assert "disk gone" in resp["error"]["message"]
