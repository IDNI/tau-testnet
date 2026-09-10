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
    resp = _run("getblocks 10 20")
    assert resp["status"] == "error", resp
    assert resp["error"]["code"] == "INVALID_PARAMS"


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
