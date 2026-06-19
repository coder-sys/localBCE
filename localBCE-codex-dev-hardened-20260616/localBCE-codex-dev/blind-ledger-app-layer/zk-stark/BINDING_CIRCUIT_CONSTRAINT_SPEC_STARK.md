# STARK Binding Circuit Constraint Spec

Status: field-neutral design spec for the Cairo/STARK production lane. This is
not an implemented or audited circuit.

## Scope

This spec defines the native STARK-field production target and closes gaps that
must not be carried forward from deleted prototype lanes.

## Public Inputs

The Cairo circuit public inputs must include:

- batch commitment
- claim source root
- oracle facts root
- fee schedule root
- address book root
- ruleset root
- data availability root
- denial attestation root
- forced inclusion root
- accumulator root before and after
- nullifier root before and after
- payment root
- value conservation commitment
- governed root epoch
- verifier version commitment

Every root must be a Poseidon field element with the domain tags defined in
`../../LANE_DECISION_V2.md`.

## Required Constraints

### Governed Roots

The prover must not choose policy or fact roots freely. Claim source, oracle
facts, fee schedule, address book, ruleset, accumulator, nullifier, and payment
roots must equal on-chain governed values or values signed by governance keys
that the circuit verifies.

Acceptance vector: a claim with internally consistent but self-built fabricated
oracle roots is rejected.

### Claim-Derived Facts

Gate facts must be derived from the committed claim-source leaf and signed
oracle facts. Free boolean witness flags are forbidden.

Acceptance vector: a valid claim commitment with fabricated passing flags is
rejected.

### Position-Bound Membership

Membership paths must bind both value and position. Path indices are constrained
to the leaf identity for claim source, oracle, fee, address book, ruleset, and
payment leaves.

Acceptance vector: substituting a richer fee row from the same tree is rejected.

### Nullifier Transition

The circuit must prove either:

- the insert slot held the canonical zero leaf in `nullifierRootBefore`; or
- the sorted-tree predecessor and successor are both in `nullifierRootBefore`,
  the predecessor points to the successor, and the new nullifier lies strictly
  between them.

`nullifierRootBefore` must equal the live governed nullifier root.

Acceptance vectors: replayed nullifier and occupied-slot insertion are rejected.

### Range Checks

All amounts, counters, dates, lengths, packed limbs, and service units must be
range constrained before arithmetic. Amounts use cents and must be below `2^59`.
Dates use day counts and must be below `2^32`.

Acceptance vector: field wraparound in amount or date comparison is rejected.

### Multi-Line Claims

The circuit must support multiple service lines:

- each line is committed with a line id and procedure code;
- each line proves membership against the matching fee row;
- total charge equals the sum of line charges;
- payable amount equals the sum of allowed amounts for approved lines;
- rejected lines contribute zero to payment.

Acceptance vector: a decomposed or unbundled multi-line claim cannot pass by
pretending it is a single-line claim.

### Value Conservation

For each batch:

`sum(payments_out) <= sum(approved_allowed_amounts)`

The batch must maintain a running on-chain balance or equivalent governed
state so cumulative payouts cannot exceed cumulative legitimate approvals.

Acceptance vector: minting a payment without a matching approved claim is
rejected.

### Padding Inertness

If the circuit uses fixed-width batches, every unused slot must be the canonical
zero leaf and `claimed_count` must equal the actual number of nonzero claims.

Acceptance vector: padding slots cannot carry hidden payments, nullifiers, or
claims.

## Required Adversarial Corpus

The production test suite must reject:

- fabricated governed roots
- fabricated claim facts
- fee-row substitution
- replayed spent nullifier
- non-empty nullifier slot insertion
- field wraparound amounts or dates
- multi-line total mismatch
- payment root with extra output
- batch with payment count different from approved claim count
- nonzero padding slot
- legacy proof wrapper anchor presented as production

The honest vector must prove and verify end to end through the native STARK
anchor before production readiness can pass.
