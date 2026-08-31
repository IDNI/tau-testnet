#!/usr/bin/env python3
"""Security-scan bot: signs a parked transfer if it does not look anomalous.

Deterministic heuristics by default, so a test run reproduces exactly. `--llm`
additionally asks a Claude model and requires BOTH to pass, which makes the model
a veto rather than an authority — a language model should not be the only thing
between someone and their money.

CHAIN HISTORY
-------------
The heuristics need CONFIRMED history, and no RPC serves it: `history <addr>`
walks the mempool only. So this bot builds its own index by walking `getblocks`
from its last-seen height and caching to disk. That gap is a candidate follow-up
RPC on the node side; until then the index is here and its staleness is visible
in the logs.
"""
from __future__ import annotations

import json
import logging
import os
import statistics
import time

from approval_bot_common import (
    ApproverBot,
    NodeClient,
    RpcError,
    Signer,
    base_arg_parser,
    configure_logging,
    load_privkey,
    logger,
    run_bot,
)

DEFAULT_INDEX_PATH = os.path.expanduser("~/.tau-approval-bot/scan_index.json")
DEFAULT_MODEL = "claude-opus-5"


class ChainIndex:
    """Confirmed transfer history per sender, walked from `getblocks`."""

    def __init__(self, client: NodeClient, path=DEFAULT_INDEX_PATH):
        self.client = client
        self.path = os.path.expanduser(path)
        self.height = 0
        # sender -> [(height, recipient, amount), ...]
        self.transfers: dict[str, list] = {}
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path) as handle:
                blob = json.load(handle)
            self.height = int(blob.get("height", 0))
            self.transfers = {k: [tuple(t) for t in v]
                              for k, v in (blob.get("transfers") or {}).items()}
        except Exception:
            logger.warning("could not read %s; starting a fresh index", self.path)

    def save(self):
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as handle:
            json.dump({"height": self.height, "transfers": self.transfers}, handle)
        os.replace(tmp, self.path)

    def refresh(self):
        """Walk any blocks we have not seen. Cheap after the first pass."""
        try:
            data = self.client.data("getblocks")
        except RpcError as exc:
            logger.warning("cannot refresh the chain index: %s", exc)
            return
        blocks = data.get("blocks") or []
        highest = self.height
        for block in blocks:
            try:
                number = int(block["header"]["block_number"])
            except (KeyError, TypeError, ValueError):
                continue
            if number <= self.height:
                continue
            for tx in block.get("transactions") or []:
                if not isinstance(tx, dict):
                    continue
                for transfer in ((tx.get("operations") or {}).get("1") or []):
                    if not (isinstance(transfer, (list, tuple)) and len(transfer) == 3):
                        continue
                    sender, recipient, amount = transfer
                    try:
                        amount = int(amount)
                    except (TypeError, ValueError):
                        continue
                    self.transfers.setdefault(str(sender).lower(), []).append(
                        (number, str(recipient).lower(), amount))
            highest = max(highest, number)
        if highest != self.height:
            self.height = highest
            self.save()
        logger.debug("chain index at height %d, %d senders known",
                     self.height, len(self.transfers))

    def history(self, sender: str) -> list:
        return self.transfers.get((sender or "").lower(), [])


def heuristic_findings(request: dict, index: ChainIndex) -> list:
    """Reasons to refuse. Empty means nothing looked wrong."""
    sender = str(request.get("sender_pubkey", "")).lower()
    recipient = str(request.get("recipient_pubkey", "")).lower()
    amount = int(request.get("amount") or 0)
    history = index.history(sender)
    findings = []

    seen_recipients = {r for _h, r, _a in history}
    if history and recipient not in seen_recipients:
        findings.append("recipient has never received from this sender before")
    if not history:
        findings.append("no confirmed history for this sender to compare against")

    amounts = [a for _h, _r, a in history]
    if len(amounts) >= 3:
        typical = statistics.median(amounts)
        if typical > 0 and amount > typical * 10:
            findings.append(
                f"amount {amount} is more than 10x this sender's median "
                f"transfer ({typical})")

    # A BURST, not merely two adjacent blocks: any active account transfers in
    # consecutive blocks routinely, and flagging that would refuse most ordinary
    # traffic. Three or more inside a three-block window is what a drain looks
    # like.
    BURST_COUNT, BURST_WINDOW = 3, 3
    if len(history) >= BURST_COUNT:
        heights = sorted(h for h, _r, _a in history)
        recent = heights[-BURST_COUNT:]
        if recent[-1] - recent[0] < BURST_WINDOW:
            findings.append(
                f"{BURST_COUNT} transfers inside {BURST_WINDOW} blocks "
                f"(possible drain in progress)")

    return findings


def llm_findings(request: dict, index: ChainIndex, model: str) -> list:
    """Ask a model. Any error is a REFUSAL, never a pass.

    Only structured, non-secret facts are sent: pubkeys are truncated and custom
    inputs are omitted entirely, since a sender may have put a code there.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return ["--llm requested but ANTHROPIC_API_KEY is not set"]
    try:
        import anthropic
    except ImportError:
        return ["--llm requested but the anthropic package is not installed"]

    sender = str(request.get("sender_pubkey", ""))
    summary = {
        "amount": request.get("amount"),
        "sender_prefix": sender[:12],
        "recipient_prefix": str(request.get("recipient_pubkey", ""))[:12],
        "sender_confirmed_transfer_count": len(index.history(sender)),
        "sender_recent_amounts": [a for _h, _r, a in index.history(sender)][-10:],
        "recipient_seen_before": str(request.get("recipient_pubkey", "")).lower()
                                 in {r for _h, r, _a in index.history(sender)},
    }
    prompt = (
        "You are reviewing a blockchain transfer that is waiting on approvals. "
        "Reply with a single JSON object: "
        '{"approve": true|false, "reason": "<one short sentence>"}. '
        "Approve unless something in the data looks genuinely anomalous.\n\n"
        + json.dumps(summary, indent=2)
    )
    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model, max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(getattr(block, "text", "") for block in response.content)
        verdict = json.loads(text[text.index("{"):text.rindex("}") + 1])
    except Exception as exc:
        return [f"model check failed ({type(exc).__name__}); refusing rather than "
                f"assuming it passed"]
    if not verdict.get("approve"):
        return [f"model flagged it: {verdict.get('reason', 'no reason given')}"]
    return []


class ScanBot(ApproverBot):
    name = "scan"

    def __init__(self, *args, index: ChainIndex, use_llm=False, model=DEFAULT_MODEL,
                 denylist=(), max_amount=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.index = index
        self.use_llm = use_llm
        self.model = model
        self.denylist = {d.lower() for d in denylist}
        self.max_amount = max_amount

    def decide(self, request: dict):
        self.index.refresh()
        recipient = str(request.get("recipient_pubkey", "")).lower()
        amount = int(request.get("amount") or 0)

        if recipient in self.denylist:
            return False, "recipient is on this scanner's denylist"
        if self.max_amount is not None and amount > self.max_amount:
            return False, f"amount {amount} exceeds this scanner's ceiling"

        findings = heuristic_findings(request, self.index)
        if not findings and self.use_llm:
            findings = llm_findings(request, self.index, self.model)

        if findings:
            # A decline does not cancel the request: it records a refusal to fill
            # this slot, and the sender can see why.
            return False, "; ".join(findings)[:256]
        return True, "no anomaly found"


def main(argv=None):
    parser = base_arg_parser(__doc__.splitlines()[0])
    parser.add_argument("--index-path", default=DEFAULT_INDEX_PATH)
    parser.add_argument("--llm", action="store_true",
                        help="Also require a model to pass (needs ANTHROPIC_API_KEY)")
    parser.add_argument("--model", default=os.environ.get(
        "TAU_APPROVAL_SCAN_MODEL", DEFAULT_MODEL),
        help="Model id (default: %(default)s)")
    parser.add_argument("--deny", action="append", default=[],
                        metavar="PUBKEY", help="Always refuse this recipient")
    parser.add_argument("--max-amount", type=int,
                        help="Always refuse above this amount")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    signer = Signer(load_privkey(args))
    client = NodeClient(args.host, args.port)
    index = ChainIndex(client, args.index_path)
    bot = ScanBot(client, signer, dry_run=args.dry_run, poll_seconds=args.poll,
                  index=index, use_llm=args.llm, model=args.model,
                  denylist=args.deny, max_amount=args.max_amount)
    return run_bot(bot, args.once)


if __name__ == "__main__":
    raise SystemExit(main())
