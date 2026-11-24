#!/usr/bin/env python3
"""Alice sends Bob 5,000. He may spend 500 a week from 1 December.

Anything still unspent on 1 January returns to Alice. The clock is the block
timestamp, so the demo does not wait for December: each block is sealed at the
moment the story needs.

Run from the repository root:

    python scripts/demo_programmable_payments.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from consensus.payments import TX_ALLOWANCE_DRAW, TX_ALLOWANCE_OPEN
from consensus.periods import WEEK, civil_to_unix
from tests.payment_chain import ALICE, BOB, CAROL, SK_ALICE, SK_BOB, Chain, tx

DEC1 = civil_to_unix(2026, 12, 1)
JAN1 = civil_to_unix(2027, 1, 1)


def main() -> None:
    chain = Chain({ALICE: 5000, BOB: 0, CAROL: 0})
    print("Alice funds a 5,000 allowance for Bob.")
    print("  spend at most 500 a week, only from 1 December 2026,")
    print("  and whatever is left on 1 January 2027 returns to Alice.")
    chain.block([tx(
        TX_ALLOWANCE_OPEN, ALICE, 0, SK_ALICE,
        grantee_pubkey=BOB, amount=5000, start_at=DEC1, hold_seconds=0,
        spend_cap=500, cap_period="week", cap_length=0, per_draw_cap=0,
        weekday_mask=0, hour_mask=0, utc_offset_quarters=0,
        expires_at=JAN1, refund_idle=0, shared_key="", shared_cap=0,
        shared_period="", shared_length=0, shared_anchor=0,
    )], ts=DEC1 - 86400)
    aid = next(iter(chain.book.allowances))
    print(f"  escrow {chain.book.escrow_total()}  Alice {chain.bal[ALICE]}")

    def draw(seq, amount, ts, height, label):
        chain.block([tx(
            TX_ALLOWANCE_DRAW, BOB, seq, SK_BOB,
            allowance_id=aid, recipient_pubkey=CAROL, amount=amount,
        )], height=height, ts=ts)
        reason = chain.last.outcomes[0].reason
        print(f"  {label}: amount {amount} -> {reason or 'paid'}  "
              f"Carol {chain.bal[CAROL]}  escrow {chain.book.escrow_total()}")

    draw(0, 100, DEC1 - 3600, 21, "30 November")
    draw(0, 300, DEC1 + 3600, 22, "1 December")
    draw(1, 200, DEC1 + 3 * 86400, 23, "4 December")
    draw(2, 201, DEC1 + 3 * 86400 + 10, 24, "4 December, over the weekly cap")
    draw(2, 500, DEC1 + WEEK + 1, 25, "8 December, new week")
    draw(3, 200, DEC1 + 2 * WEEK + 1, 26, "15 December")
    print("1 January, no transaction: the remainder returns to Alice.")
    chain.block([], height=27, ts=JAN1)
    print(f"  Alice {chain.bal[ALICE]}  Carol {chain.bal[CAROL]}  "
          f"escrow {chain.book.escrow_total()}  supply {chain.supply()}")
    if chain.bal[ALICE] != 3800 or chain.bal[CAROL] != 1200 or chain.book.escrow_total() != 0:
        raise SystemExit("demo did not return 3,800")
    print("Remainder 3,800 returned once.")


if __name__ == "__main__":
    main()
