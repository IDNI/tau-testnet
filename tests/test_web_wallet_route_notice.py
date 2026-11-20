"""Issue #35: the web wallet warns about a route on the open account.

The chain cannot tell the owner from someone holding the owner's key, so the
wallet shows any route `getreceiveroute` reports and warns loudly about a locked
route still in its notice period, the only time it can still be cleared. These
tests feed the node's own `to_dict` output to the wallet's receiveRouteNotice
(run in node) and check that the wallet offers to clear a route exactly when the
node would still let the owner clear it.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from consensus.receive_routes import LOCK_NOTICE_SECONDS, ReceiveRoute

APP_JS = Path(__file__).resolve().parent.parent / "web-wallet/app.js"
INDEX_HTML = Path(__file__).resolve().parent.parent / "web-wallet/index.html"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")

OWNER = "a" * 96
DEST = "b" * 96
TS = 1_900_000_000
DAY = 86_400


def _function_source(src: str, name: str) -> str:
    m = re.search(rf"^function {name}\(.*?^\}}\n", src, re.S | re.M)
    assert m, f"function {name} not found in app.js"
    return m.group(0)


def _notices(cases):
    """receiveRouteNotice for each (route dict or None, now) pair."""
    src = APP_JS.read_text(encoding="utf-8")
    script = (
        _function_source(src, "formatUnixTimeUtc")
        + _function_source(src, "receiveRouteNotice")
        + "const fs = require('fs');\n"
        + "const cases = JSON.parse(fs.readFileSync(0, 'utf8'));\n"
        + "process.stdout.write(JSON.stringify(cases.map(([r, now]) => receiveRouteNotice(r, now))));\n"
    )
    res = subprocess.run(["node", "-e", script], input=json.dumps(cases).encode(),
                         capture_output=True, check=True, timeout=60)
    return json.loads(res.stdout)


def _route(**kw):
    base = dict(owner_pubkey=OWNER, destination_pubkey=DEST, bps=2000, version=1, installed_at=TS)
    base.update(kw)
    return ReceiveRoute(**base)


def test_wallet_notice_constant_is_the_node_constant():
    src = APP_JS.read_text(encoding="utf-8")
    m = re.search(r"^const ROUTE_LOCK_NOTICE_SECONDS = (\d+);", src, re.M)
    assert m and int(m.group(1)) == LOCK_NOTICE_SECONDS


def test_wallet_page_has_the_notice_elements():
    html = INDEX_HTML.read_text(encoding="utf-8")
    for element_id in ("route-notice", "route-notice-text", "btn-route-clear"):
        assert f'id="{element_id}"' in html


def test_wallet_offers_to_clear_exactly_when_the_node_allows_it():
    locked = _route(locked=True, expires_at=TS + 365 * DAY)
    scheduled_lock = _route(locked=True, active_from=TS + 30 * DAY, expires_at=TS + 365 * DAY)
    plain = _route(expires_at=TS + 30 * DAY)
    later = _route(active_from=TS + 2 * DAY)
    moments = [
        (locked, TS),                                   # just installed: notice period
        (locked, TS + LOCK_NOTICE_SECONDS - 3600),      # last hour of the notice
        (locked, TS + LOCK_NOTICE_SECONDS),             # the lock holds
        (scheduled_lock, TS + LOCK_NOTICE_SECONDS + DAY),  # notice over, start still ahead
        (scheduled_lock, TS + 31 * DAY),                # started: the lock holds
        (plain, TS),
        (later, TS),
    ]
    cases = [[r.to_dict(now), now] for r, now in moments]
    notices = _notices(cases)
    for (route, now), notice in zip(moments, notices):
        assert notice is not None
        assert notice["clearable"] is (not route.lock_holds(now)), (route, now)
        loud = route.locked and not route.lock_holds(now)
        assert (notice["level"] == "danger") is loud, (route, now, notice)


def test_pending_lock_warning_says_when_it_binds_and_what_to_do():
    route = _route(locked=True, expires_at=TS + 365 * DAY)
    [fresh, last_hour] = _notices([
        [route.to_dict(TS), TS],
        [route.to_dict(TS + LOCK_NOTICE_SECONDS - 3600), TS + LOCK_NOTICE_SECONDS - 3600],
    ])
    assert "20% of incoming payments to bbbbbbbbbbbb" in fresh["text"]
    assert "2030-03-24 17:46 UTC" in fresh["text"]  # TS + 7 days
    assert "in about 7 days" in fresh["text"]
    assert "clear the route now" in fresh["text"]
    assert "in under a day" in last_hour["text"]


def test_no_notice_without_a_live_route():
    expired = _route(expires_at=TS + DAY)
    assert _notices([[None, TS], [expired.to_dict(TS + DAY), TS + DAY]]) == [None, None]
