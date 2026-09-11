"""Shared client for the co-signature approver bots.

An approver bot is an ordinary account that watches its inbox and signs. It needs
no funding: `transfer_vote` is fee-exempt precisely so a bot can run without a
treasury and without a fee strategy.

Nothing here is consensus code. A bot that misbehaves can only fail to sign, or
sign something its own policy owner told it to sign; it cannot move funds on its
own, because the sender's Tau policy is what decides whether a vote is enough.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import socket
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

logger = logging.getLogger("approval_bot")

# Blocks a vote stays valid for. Short: a vote is only meaningful while the
# request it answers is still open, and a stale one should die on its own.
VOTE_EXPIRY_BLOCKS = 500


class RpcError(RuntimeError):
    pass


class NodeClient:
    """Newline-framed JSON over the node's TCP RPC port."""

    def __init__(self, host="127.0.0.1", port=65432, timeout=60.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def rpc(self, command: str):
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        try:
            sock.sendall((command + "\r\n").encode())
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                buf = sock.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
        finally:
            sock.close()
        text = b"".join(chunks).decode(errors="replace").strip()
        if not text:
            raise RpcError(f"empty response to {command.split()[0]}")
        try:
            return json.loads(text)
        except ValueError as exc:
            raise RpcError(f"unparseable response to {command.split()[0]}: {exc}")

    def data(self, command: str):
        res = self.rpc(command)
        if res.get("status") != "ok":
            raise RpcError(json.dumps(res.get("error") or res)[:400])
        return res.get("data") or {}


class Signer:
    """A bot's key, and the one canonical way to sign with it."""

    def __init__(self, privkey_hex: str):
        from py_ecc.bls import G2Basic

        self._bls = G2Basic
        self.sk = int(privkey_hex, 16)
        self.pubkey = G2Basic.SkToPk(self.sk).hex()

    def sign(self, payload: dict) -> dict:
        # The node's own preimage function, imported rather than reimplemented:
        # a bot that computed its own would silently fail to verify the moment a
        # field was added.
        from consensus.tx_signing import signing_message_bytes

        digest = hashlib.sha256(signing_message_bytes(payload)).digest()
        payload["signature"] = self._bls.Sign(self.sk, digest).hex()
        return payload


class ApproverBot:
    """Poll the inbox, decide, vote. Subclasses implement `decide`."""

    name = "approver"

    def __init__(self, client: NodeClient, signer: Signer, *, dry_run=False,
                 poll_seconds=5.0):
        self.client = client
        self.signer = signer
        self.dry_run = dry_run
        self.poll_seconds = poll_seconds
        # Requests already acted on, so a slow block does not cause a double
        # submit (the node would reject it, but the log noise hides real issues).
        self._acted: set[str] = set()

    # -- to implement -------------------------------------------------------

    def decide(self, request: dict):
        """Return (approve: bool, reason: str), or None to defer this round.

        Deferring is normal and is NOT a decline: an auth bot waits until a code
        arrives, and a scanner may want another block of history first.
        """
        raise NotImplementedError

    # -- machinery ----------------------------------------------------------

    def inbox(self) -> list:
        data = self.client.data(f"getapprovalrequests {self.signer.pubkey} in")
        return data.get("incoming") or []

    def my_slot(self, request: dict):
        for slot, info in (request.get("approvers") or {}).items():
            if str(info.get("pubkey", "")).lower() == self.signer.pubkey:
                return int(slot), info.get("state")
        return None, None

    def vote(self, request_id: str, approve: bool, reason: str = ""):
        from tau_testnet_cli.tx import build_transfer_vote_tx

        if self.dry_run:
            logger.info("[dry-run] would %s %s (%s)",
                        "approve" if approve else "decline", request_id[:16], reason)
            return None
        seq_data = self.client.data(f"getsequence {self.signer.pubkey}")
        sequence = seq_data["sequence_number"]
        # getsequence carries the tip, which is what the height deadline counts
        # from. A bot votes within blocks, so the window only has to be long
        # enough to survive a slow miner.
        tip = seq_data.get("tip_height")
        if not isinstance(tip, int) or isinstance(tip, bool):
            raise RuntimeError("node did not report tip_height; cannot set expire_at_height")
        payload = build_transfer_vote_tx(
            sender_pubkey=self.signer.pubkey,
            sequence_number=int(sequence),
            expiration_time=int(time.time()) + 3600,
            expire_at_height=tip + VOTE_EXPIRY_BLOCKS,
            request_id=request_id,
            approve=approve,
            reason=reason[:256],
        )
        self.signer.sign(payload)
        res = self.client.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")
        if res.get("status") != "ok":
            logger.error("vote on %s rejected: %s", request_id[:16],
                         json.dumps(res.get("error") or res)[:300])
            return res
        logger.info("%s %s (%s)", "approved" if approve else "declined",
                    request_id[:16], reason or "no reason given")
        return res

    def tick(self) -> int:
        """One poll. Returns how many votes were cast."""
        try:
            requests = self.inbox()
        except RpcError as exc:
            logger.warning("inbox unavailable: %s", exc)
            return 0

        cast = 0
        for request in requests:
            request_id = request.get("request_id")
            if not request_id or request_id in self._acted:
                continue
            slot, state = self.my_slot(request)
            if slot is None or state != "awaiting":
                continue
            try:
                decision = self.decide(request)
            except Exception:
                logger.exception("decide() failed for %s; deferring", request_id[:16])
                continue
            if decision is None:
                continue
            approve, reason = decision
            self.vote(request_id, approve, reason)
            self._acted.add(request_id)
            cast += 1
        return cast

    def run(self):
        logger.info("%s bot watching as %s", self.name, self.signer.pubkey[:16])
        while True:
            self.tick()
            time.sleep(self.poll_seconds)


def base_arg_parser(description: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--host", default="127.0.0.1", help="Node RPC host")
    parser.add_argument("--port", type=int, default=65432, help="Node RPC port")
    parser.add_argument(
        "--privkey", help="Bot private key (hex). Prefer --privkey-file.")
    parser.add_argument(
        "--privkey-file",
        help="File containing the bot private key, 0600 and owner-only.")
    parser.add_argument("--poll", type=float, default=5.0,
                        help="Seconds between inbox polls")
    parser.add_argument("--once", action="store_true",
                        help="Poll once and exit (for tests and cron)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Decide and log, but never submit a vote")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser


def load_privkey(args) -> str:
    """Prefer a file, and refuse a world-readable one.

    A bot's key can sign away someone else's transfer gate, so a loose mode is
    treated as a configuration error rather than a warning.
    """
    if args.privkey_file:
        path = os.path.expanduser(args.privkey_file)
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o077:
            raise SystemExit(
                f"{path} is mode {mode:03o}; a bot key must not be group- or "
                f"world-readable. chmod 600 it."
            )
        with open(path) as handle:
            return handle.read().strip()
    if args.privkey:
        return args.privkey.strip()
    env = os.environ.get("TAU_APPROVAL_BOT_PRIVKEY")
    if env:
        return env.strip()
    raise SystemExit("no key: pass --privkey-file, --privkey, or set "
                     "TAU_APPROVAL_BOT_PRIVKEY")


def configure_logging(verbose: bool):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def run_bot(bot: ApproverBot, once: bool):
    if once:
        cast = bot.tick()
        logger.info("single poll complete, %d vote(s) cast", cast)
        return 0
    try:
        bot.run()
    except KeyboardInterrupt:
        logger.info("stopping")
    return 0
