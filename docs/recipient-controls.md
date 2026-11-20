# Recipient controls: policy gate (#47) and park hold cap (#76)

A transfer is judged by two policies, not one. The sender's o5 clause
has always decided whether the sender may send; the recipient's o5
clause now also decides whether the recipient accepts — and a
recipient may cap how long an incoming park may hold its funds.

## The gate

The check lives in the one place every value movement passes through:
the fee-era transfer execution in block apply. Ordinary transfers,
park creations and approval completions are all gated, because all of
them execute there. Transfers the engine creates itself — an approval
completion pays out there, never as a transaction output — are covered
for the same reason. Releases and retracts never pass through that
path and are never gated: a release is the recipient's own escrowed
money leaving, and gating it could trap funds behind a policy written
after the park.

Admission (sendtx, and checktx as its dry run) runs the identical
check with the identical helper (`consensus/recipient_gate.py`), so
admission and apply cannot disagree about a recipient.

## How the recipient is judged

The recipient evaluation reuses the transfer input map unchanged —
amount on i1, counterparty (sender) pubkey on i3, recipient pubkey on
i4, block timestamp on i5 — with three changes:

- i12 is the recipient's pubkey, so the recipient's own clause fires,
  with the same widths and typing the sender side uses;
- i2 is the recipient's balance at the parent snapshot, the same
  meaning i2 carries for the sender;
- i6 carries the current block height (its canonical meaning), so a
  rule can compare height against height.

The verdict is read from o5 exactly as the sender's is: no output
means allow, an output of 0 refuses. The refusal reason is
`recipient_policy_block`, distinct from the sender's
`user_policy_block`, and in a batched transaction one refused output
fails the whole transaction — no partial movement. A recipient with
no policy, or a policy that does not mention incoming transfers, is
the neutral default and allows everything. Rule offers are not
transfers and are never gated.

## The hold cap

A park carries exactly one release point, in one unit: a height or a
time. For a park creation, and only there, the recipient evaluation
also receives i17: the park's absolute release point packed as one
bv[64] — high 32 bits the release timestamp, low 32 bits the release
height, the unused unit packed as 0. On any other evaluation i17 is 0
("no hold"). Feeding the absolute point, rather than the hold length,
lets a rule express deadlines a length cannot: "nothing that releases
after height H" refuses even a short park whose release lands past H.

The recipient states its cap as a duration on o10. The node computes
the hold as release − now in the park's own unit (blocks for a height
park, seconds for a time park) and refuses when the hold exceeds the
cap, with reason `RECIPIENT_MAX_HOLD` and the cap value recorded. Cap
0 means instant transfers only. No o10 output means no cap. A
malformed cap output parses to 0, so it fails closed for parks and
never affects plain transfers.

A rule expresses its cap or deadline in one unit. A park whose release
is stated in the other unit packs that half of i17 as 0, and a
deadline rule that cannot verify its unit refuses the park — a
deadline that cannot be proven is not assumed.

## Fees

A recipient refusal at apply behaves like a sender-policy block: the
transaction fails, no funds move, and the sender pays the fee steps
measured for the transfers that were evaluated. A refusal at admission
pays nothing.

## Capability reporting

checktx reports `recipient_policy_gate: "enforced"` and
`recipient_hold_cap: "enforced"` in its result data, and a refusal in
the dry run carries sendtx's reason verbatim, so a client can tell a
recipient refusal from a sender one before broadcasting.
