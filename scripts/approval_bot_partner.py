#!/usr/bin/env python3
"""Human-in-the-loop signer: surfaces a parked transfer and signs on confirmation.

The third approver in the tiered example is a person, so this is a watcher rather
than a decision engine: it shows what the sender attached — the comment field is
the point — and waits. `--webhook` posts the same summary to a chat or desktop
notifier so the partner does not have to sit at a terminal.

Nothing is signed without an explicit yes. `--auto-approve-below` exists for the
demo case where a partner wants a standing rule for small amounts, and it is off
by default.
"""
from __future__ import annotations

import json
import sys
import urllib.request

from approval_bot_common import (
    ApproverBot,
    NodeClient,
    Signer,
    base_arg_parser,
    configure_logging,
    load_privkey,
    logger,
    run_bot,
)


def _describe(request: dict) -> str:
    customs = request.get("custom_inputs") or {}
    comment = " | ".join(f"i{k}={v}" for k, v in sorted(customs.items())) or "(none)"
    awaiting = [slot for slot, info in (request.get("approvers") or {}).items()
                if info.get("state") == "awaiting"]
    return (
        f"request  {request.get('request_id', '')[:24]}\n"
        f"  from     {str(request.get('sender_pubkey', ''))[:24]}...\n"
        f"  to       {str(request.get('recipient_pubkey', ''))[:24]}...\n"
        f"  amount   {request.get('amount')}\n"
        f"  expires  at height {request.get('expire_at_height')}\n"
        f"  message  {comment}\n"
        f"  awaiting slots {sorted(awaiting)}"
    )


class PartnerBot(ApproverBot):
    name = "partner"

    def __init__(self, *args, webhook=None, auto_below=None, assume_yes=False,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self.webhook = webhook
        self.auto_below = auto_below
        self.assume_yes = assume_yes
        self._notified: set[str] = set()

    def _notify(self, text: str):
        if not self.webhook:
            return
        try:
            body = json.dumps({"text": text}).encode()
            req = urllib.request.Request(
                self.webhook, data=body,
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as exc:
            logger.warning("webhook post failed: %s", exc)

    def decide(self, request: dict):
        request_id = request["request_id"]
        summary = _describe(request)

        if request_id not in self._notified:
            print("\n" + summary, flush=True)
            self._notify(summary)
            self._notified.add(request_id)

        amount = int(request.get("amount") or 0)
        if self.auto_below is not None and amount < self.auto_below:
            return True, f"under this partner's standing limit of {self.auto_below}"

        if self.assume_yes:
            return True, "approved non-interactively (--yes)"

        if not sys.stdin or not sys.stdin.isatty():
            # No terminal and no standing rule: defer rather than guess. The
            # request stays open, and a person can approve it later.
            logger.info("no terminal to prompt on; deferring %s", request_id[:16])
            return None

        answer = input("  approve? [y]es / [n]o / [s]kip: ").strip().lower()
        if answer.startswith("y"):
            return True, "approved by the partner"
        if answer.startswith("n"):
            reason = input("  reason (optional): ").strip()
            return False, reason or "declined by the partner"
        return None


def main(argv=None):
    parser = base_arg_parser(__doc__.splitlines()[0])
    parser.add_argument("--webhook", help="POST {\"text\": ...} here on a new request")
    parser.add_argument("--auto-approve-below", type=int, dest="auto_below",
                        help="Standing approval under this amount (off by default)")
    parser.add_argument("--yes", action="store_true", dest="assume_yes",
                        help="Approve without prompting (for scripted demos)")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    signer = Signer(load_privkey(args))
    client = NodeClient(args.host, args.port)
    bot = PartnerBot(client, signer, dry_run=args.dry_run, poll_seconds=args.poll,
                     webhook=args.webhook, auto_below=args.auto_below,
                     assume_yes=args.assume_yes)
    return run_bot(bot, args.once)


if __name__ == "__main__":
    raise SystemExit(main())
