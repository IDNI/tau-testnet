"""RPC getters for Bounty 01 programmable payments (Step 5).

Each getter is driven against the REAL chain: a native test mines the
create tx through real blocks, then the getter's execute() is called with
a plain container (db + chain_state modules) exactly as the server calls
it, and the returned rows are asserted. A restart check proves the
getters read state that survives a reload (the persistence fix in
560b736), not just warm memory.
"""
import json
import types

import chain_state
import db
from bls_keys import SK_ALICE, pubkey_hex, sign_payload
from commands import (
    getgrants,
    getpayoutrule,
    getreceiveroute,
    getstandingpayments,
)
from consensus.periods import PERIOD_DAY, PERIOD_WEEK
from test_grants_native import ALICE, NativeChainCase, _fresh
from test_payouts_native import CLAUSE
from test_reorg_deep_chain import BASE_TS

DAY = 86400
FAR_FUTURE = 9999999999


def _container():
    return types.SimpleNamespace(db=db, chain_state=chain_state)


def _call(module, line):
    return json.loads(module.execute(line, _container()))


class _RpcBase(NativeChainCase):
    """NativeChainCase + the minimal create-tx builders the getters need.

    The builders are copied from the *_native test files (same tx shapes);
    this file deliberately does NOT subclass those test classes: subclassing
    them would make pytest re-collect their tests here, and the __test__
    flag used to suppress that leaks onto the shared class objects and
    silently drops the parents from the full-suite collection.
    """

    def _grant_create_tx(self, granter_sk, grantee, amount=5000, seq=None,
                         start_at=BASE_TS, expires_at=BASE_TS + 28 * DAY,
                         spend_cap=500, per_payment_cap=500):
        granter = pubkey_hex(granter_sk)
        if seq is None:
            seq = self._next_seq(granter)
        tx = {
            "tx_id": self._tx_id("grant-create"),
            "tx_type": "grant_create",
            "sender_pubkey": granter,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "grantee_pubkey": grantee,
            "refund_to": granter,
            "amount": amount,
            "period_kind": PERIOD_WEEK,
            "period_anchor": 0,
            "spend_cap": spend_cap,
            "per_payment_cap": per_payment_cap,
            "start_at": start_at,
            "expires_at": expires_at,
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, granter_sk)

    def _standing_create_tx(self, payer_sk, payee, amount=100, seq=None,
                            period_kind=PERIOD_DAY, start_at=BASE_TS,
                            max_fee=10):
        payer = pubkey_hex(payer_sk)
        if seq is None:
            seq = self._next_seq(payer)
        tx = {
            "tx_id": self._tx_id("standing-create"),
            "tx_type": "standing_payment",
            "sender_pubkey": payer,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "payee_pubkey": payee,
            "amount": amount,
            "period_kind": period_kind,
            "period_anchor": 0,
            "max_fee_per_execution": max_fee,
            "start_at": start_at,
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, payer_sk)

    def _route_set_tx(self, account_sk, destination, bps=2500, seq=None,
                      min_incoming=0, activate_at=BASE_TS,
                      expires_at=BASE_TS + 30 * DAY, locked_until=None):
        account = pubkey_hex(account_sk)
        if seq is None:
            seq = self._next_seq(account)
        tx = {
            "tx_id": self._tx_id("route-set"),
            "tx_type": "route_set",
            "sender_pubkey": account,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "destination_pubkey": destination,
            "bps": bps,
            "min_incoming": min_incoming,
            "activate_at": activate_at,
            "expires_at": expires_at,
            "locked_until": locked_until,
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, account_sk)

    def _payout_create_tx(self, payer_sk, recipients, seq=None,
                          clause=CLAUSE, max_per_execution=1000,
                          max_per_period=1000, start_at=BASE_TS,
                          locked_until=None):
        payer = pubkey_hex(payer_sk)
        if seq is None:
            seq = self._next_seq(payer)
        tx = {
            "tx_id": self._tx_id("payout-create"),
            "tx_type": "payout_create",
            "sender_pubkey": payer,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "recipients": list(recipients),
            "clause": clause,
            "max_per_execution": max_per_execution,
            "max_per_period": max_per_period,
            "period_kind": PERIOD_WEEK,
            "period_length": None,
            "period_anchor": 0,
            "start_at": start_at,
            "expires_at": start_at + 30 * DAY,
            "locked_until": locked_until,
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, payer_sk)


class TestGrantsRpc(_RpcBase):
    def test_getgrants_lists_open_grants_and_filters(self):
        self.assertEqual(_call(getgrants, "getgrants")["data"], {"grants": []})
        grantee = _fresh(4242)
        other = _fresh(4343)
        self._mine({1: [self._grant_create_tx(SK_ALICE, grantee)]})
        self._mine({2: [self._grant_create_tx(SK_ALICE, other)]})
        rows = _call(getgrants, "getgrants")["data"]["grants"]
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["grantee_pubkey"] for r in rows}, {grantee, other})
        self.assertTrue(all(r["amount"] == 5000 for r in rows))
        self.assertTrue(all(r["granter_pubkey"] == ALICE for r in rows))

        by_granter = _call(getgrants, f"getgrants {ALICE}")["data"]["grants"]
        self.assertEqual(len(by_granter), 2)
        by_grantee = _call(getgrants, f"getgrants {ALICE} {grantee}")["data"]["grants"]
        self.assertEqual(len(by_grantee), 1)
        self.assertEqual(by_grantee[0]["grantee_pubkey"], grantee)
        nobody = _call(getgrants, f"getgrants {_fresh(4444)}")["data"]["grants"]
        self.assertEqual(nobody, [])

    def test_getgrants_rejects_too_many_args(self):
        res = _call(getgrants, "getgrants a b c")
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["error"]["code"], "INVALID_PARAMS")

    def test_getgrants_survives_restart(self):
        grantee = _fresh(4242)
        self._mine({1: [self._grant_create_tx(SK_ALICE, grantee)]})
        before = _call(getgrants, "getgrants")["data"]["grants"]
        self._restart()
        after = _call(getgrants, "getgrants")["data"]["grants"]
        self.assertEqual(after, before)


class TestStandingRpc(_RpcBase):
    def test_getstandingpayments_lists_open_schedules_and_filters(self):
        self.assertEqual(
            _call(getstandingpayments, "getstandingpayments")["data"],
            {"standing_payments": []})
        payee = _fresh(4242)
        self._mine({1: [self._standing_create_tx(SK_ALICE, payee, amount=100)]})
        rows = _call(getstandingpayments, "getstandingpayments")["data"]["standing_payments"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["payer_pubkey"], ALICE)
        self.assertEqual(row["payee_pubkey"], payee)
        self.assertEqual(row["amount"], 100)
        # The create block's sweep executed the first period already.
        self.assertEqual(row["executions"], 1)

        by_payer = _call(
            getstandingpayments, f"getstandingpayments {ALICE}")["data"]["standing_payments"]
        self.assertEqual(len(by_payer), 1)
        by_payee = _call(
            getstandingpayments,
            f"getstandingpayments {ALICE} {payee}")["data"]["standing_payments"]
        self.assertEqual(len(by_payee), 1)
        nobody = _call(
            getstandingpayments,
            f"getstandingpayments {ALICE} {_fresh(4444)}")["data"]["standing_payments"]
        self.assertEqual(nobody, [])

    def test_getstandingpayments_rejects_too_many_args(self):
        res = _call(getstandingpayments, "getstandingpayments a b c")
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["error"]["code"], "INVALID_PARAMS")

    def test_getstandingpayments_survives_restart(self):
        payee = _fresh(4242)
        self._mine({1: [self._standing_create_tx(SK_ALICE, payee, amount=100)]})
        before = _call(getstandingpayments, "getstandingpayments")["data"]["standing_payments"]
        self._restart()
        after = _call(getstandingpayments, "getstandingpayments")["data"]["standing_payments"]
        self.assertEqual(after, before)


class TestRoutesRpc(_RpcBase):
    def test_getreceiveroute_returns_one_route_or_null(self):
        account = _fresh(4242)
        dest = _fresh(4343)
        self.assertEqual(
            _call(getreceiveroute, f"getreceiveroute {account}")["data"],
            {"route": None})
        self._mine({1: [self._route_set_tx(4242, dest, bps=2500)]})
        row = _call(getreceiveroute, f"getreceiveroute {account}")["data"]["route"]
        self.assertIsNotNone(row)
        self.assertEqual(row["account_pubkey"], account)
        self.assertEqual(row["destination_pubkey"], dest)
        self.assertEqual(row["bps"], 2500)
        self.assertEqual(
            _call(getreceiveroute, f"getreceiveroute {_fresh(4444)}")["data"],
            {"route": None})

    def test_getreceiveroute_without_args_lists_all_routes(self):
        account = _fresh(4242)
        dest = _fresh(4343)
        self.assertEqual(_call(getreceiveroute, "getreceiveroute")["data"], {"routes": []})
        self._mine({1: [self._route_set_tx(4242, dest, bps=2500)]})
        rows = _call(getreceiveroute, "getreceiveroute")["data"]["routes"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["account_pubkey"], account)

    def test_getreceiveroute_rejects_too_many_args(self):
        res = _call(getreceiveroute, "getreceiveroute a b")
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["error"]["code"], "INVALID_PARAMS")

    def test_getreceiveroute_survives_restart(self):
        account = _fresh(4242)
        dest = _fresh(4343)
        self._mine({1: [self._route_set_tx(4242, dest, bps=2500)]})
        before = _call(getreceiveroute, "getreceiveroute")["data"]["routes"]
        self._restart()
        after = _call(getreceiveroute, "getreceiveroute")["data"]["routes"]
        self.assertEqual(after, before)


class TestPayoutsRpc(_RpcBase):
    def test_getpayoutrule_lists_rules_and_reads_one_by_id(self):
        self.assertEqual(
            _call(getpayoutrule, "getpayoutrule")["data"], {"payout_rules": []})
        r1, r2 = _fresh(4242), _fresh(4343)
        self._mine({1: [self._payout_create_tx(SK_ALICE, [r1, r2])]})
        rows = _call(getpayoutrule, "getpayoutrule")["data"]["payout_rules"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["payer_pubkey"], ALICE)
        self.assertEqual(row["recipients"], [r1, r2])
        self.assertEqual(row["clause"], CLAUSE)

        pid = row["payout_id"]
        one = _call(getpayoutrule, f"getpayoutrule {pid}")["data"]["payout_rule"]
        self.assertEqual(one, row)
        self.assertEqual(
            _call(getpayoutrule, "getpayoutrule " + "00" * 32)["data"],
            {"payout_rule": None})

    def test_getpayoutrule_rejects_too_many_args(self):
        res = _call(getpayoutrule, "getpayoutrule a b")
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["error"]["code"], "INVALID_PARAMS")

    def test_getpayoutrule_survives_restart(self):
        r1, r2 = _fresh(4242), _fresh(4343)
        self._mine({1: [self._payout_create_tx(SK_ALICE, [r1, r2])]})
        before = _call(getpayoutrule, "getpayoutrule")["data"]["payout_rules"]
        self._restart()
        after = _call(getpayoutrule, "getpayoutrule")["data"]["payout_rules"]
        self.assertEqual(after, before)


class TestGettersRegistered(_RpcBase):
    """The four getters are wired into the server's command table."""

    def test_all_four_names_are_registered(self):
        from app.container import ServiceContainer

        handlers = ServiceContainer.build().command_handlers
        for name in ("getgrants", "getstandingpayments",
                     "getreceiveroute", "getpayoutrule"):
            self.assertIn(name, handlers)
