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

The gate is clause-triggered: it runs only when the recipient has
published a policy — an accepted clause on o5, or (for a park) on the
hold-cap stream o10. Per-account policy enters the specification
only through accepted clauses, so the trigger misses no policy that
exists; and a neutral recipient costs exactly what it cost before
this feature — one evaluation per transfer, the same fed streams,
the same fee. The fee model's one-evaluation-per-transfer contract
is preserved for every transfer whose recipient has not opted in.

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

A recipient refusal costs exactly what a sender-policy block costs:
nothing. A transaction refused by either policy is rejected before
any fee is charged — no funds move and `fee_charged` is 0 — at apply
and at admission alike. The fee is paid only by transactions that
execute.

## Activation

The gate is a governance-activated feature, in the same shape as
approval slots. A chain whose governance has never set the host
contract patch key `recipient_gate_active` does not run the gate:
recipient clauses judge nobody, and transfers behave exactly as they
did before the feature. The patch accepts only `true` — activation
is one-way, because switching the gate off would silently un-govern
recipient clauses that are already deployed.

While the gate is inactive, deploying the feature is refused rather
than silently admitted: a clause that targets the hold-cap stream
o10 or whose body reads the release-pair stream i17 is rejected at
admission and at apply — on every surface that registers a clause —
with reason `recipient_gate_inactive` (code `FEATURE_INACTIVE`).
Ordinary o5 clauses — sender policies the chain already enforces —
deploy exactly as they always have. Accumulated spec units are not
refused: o10 is a free output stream for user rules with
pre-existing uses, and the deploy refusal covers the surfaces that
register recipient policy, not the general spec. The flag enters
the consensus mechanism metadata only once set, so a chain that
never activates hashes exactly as it did before the feature existed.

## Capability reporting

checktx reports the activation state the dry run actually judged
under: `recipient_policy_gate` and `recipient_hold_cap` are
`"enforced"` once the gate is active and `"inactive"` before it, so
a wallet can detect the feature's state before offering an inbound
rule. A refusal in the dry run carries sendtx's reason verbatim, so
a client can tell a recipient refusal from a sender one before
broadcasting.
