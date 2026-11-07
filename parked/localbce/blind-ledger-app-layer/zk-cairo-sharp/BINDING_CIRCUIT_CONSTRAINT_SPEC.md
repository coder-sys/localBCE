# Cairo/STARK Batch Binding Circuit Constraint Spec

Status: production constraint spec. Not implemented, not audited, and not a
security claim. This document is the build target for the canonical Cairo/STARK
production lane.

## Purpose

Prove one whole batch, not one claim at a time.

The proof must say:

> Given committed raw claims, external fact roots, ruleset/fee roots, current
> nullifier and accumulator roots, and private witnesses, the batch adjudication,
> duplicate prevention, payment netting, and state transitions are correct.

## Field Strategy

Production must choose exactly one:

1. STARK_FIELD_END_TO_END.
   - Duplicate keys, nullifiers, claim/result/payment roots, fee roots, ruleset
     roots, accumulator roots, and proof commitments all live in the Cairo/STARK
     field.
   - Preferred for the Cairo-native production lane.

2. BN254_OR_SHA_BRIDGED_TO_CAIRO.
   - Existing BN254/SHA roots are represented in Cairo as limbs.
   - The circuit proves range-checked non-lossy reconstruction.
   - No modular reduction from BN254/bytes32 into felt252 is allowed.

Modulo reduction between fields is forbidden.

## Public Inputs

The production batch proof public input layout must include:

- `schema_version`
- `proof_lane_id`
- `batch_id`
- `claim_count`
- `payment_count`
- `raw_claim_root`
- `normalized_claim_root`
- `result_root`
- `payment_root`
- `nullifier_root_before`
- `nullifier_root_after`
- `accumulator_root_before`
- `accumulator_root_after`
- `ruleset_timeline_root`
- `fee_schedule_root`
- `provider_status_root`
- `eligibility_root`
- `prior_auth_root`
- `oracle_key_root`
- `adjudicator_code_hash`
- `ruleset_code_hash`
- `combined_batch_commitment`

The contract-side combined commitment must bind every public input above.

## Per-Claim Private Witness

For each real claim index `i < claim_count`, the witness must include:

- raw claim leaf data or inclusion path to raw claim root,
- normalized claim facts,
- member identifier field,
- provider NPI field,
- service date,
- service lines with procedure, units, line charge, and PA references,
- diagnosis list commitment,
- external fact inclusion proofs,
- fee schedule inclusion proofs,
- nullifier non-membership witness,
- accumulator pre-state witness,
- adjudication result leaf,
- payment contribution witness.

For each padding index `i >= claim_count`, all contribution constraints must be
inert and the leaf must be the canonical padding leaf.

## Required Constraints

### C1. Raw-to-Normalized Derivation

The circuit must derive, or verify a committed and code-hash-bound derivation of:

- member ID present,
- eligibility active on service date,
- provider NPI present,
- provider enrolled and not suspended on service date,
- service line count,
- diagnosis count,
- PA requirement and PA validity,
- total charge cents,
- min service line charge cents,
- max service line charge cents,
- program-integrity hold status.

Free normalized flags are forbidden.

### C2. Effective-Dated External Facts

Every external fact must be tied to the claim service date:

- eligibility,
- provider enrollment/suspension,
- death/not-deceased status,
- prior authorization,
- fee schedule.

Inclusion proofs must prove the fact was effective for `service_date`.

### C3. Fee Schedule And Charge Logic

For each service line:

- procedure code and modifier select the fee schedule row,
- service date is inside the row effective range,
- line charge is positive,
- line charge is within the allowed amount,
- total charge equals the sum of line charges,
- min/max line charges are derived from actual lines.

Hard-coded prototype thresholds are forbidden in production.

### C4. Nullifier Non-Membership And Transition

For every approved claim:

- derive duplicate nullifier from committed claim facts and domain parameters,
- prove non-membership against `nullifier_root_before` or the rolling in-batch
  root,
- insert the nullifier exactly once,
- output the final `nullifier_root_after`.

For every denied claim:

- no payable nullifier insertion unless policy explicitly requires denied-claim
  replay tracking.

Free spent-nullifier slots are forbidden.

### C5. Accumulator Transition

For every approved claim, update accumulator state for:

- member benefit period,
- benefit cap,
- visit count,
- units,
- deductible/out-of-pocket state where applicable,
- prior-authorization consumption.

The proof must show the transition from `accumulator_root_before` to
`accumulator_root_after`.

### C6. Result Leaf Correctness

For every claim:

- gate vector matches derived facts,
- first failed gate matches gate order,
- approval bit is one only if all gates pass,
- denial reason/CARC/RARC match the ratified mapping,
- result leaf is included in `result_root`.

### C7. Payment Root Correctness

For approved claims:

- payable amount is the allowed amount from the adjudication result,
- per-provider payments are summed exactly,
- payment leaves commit to provider alias, approved count, net amount, rail, and
  reconciliation commitment.

For denied claims:

- payable contribution is zero.

Payment root cannot contain a payee absent from approved results.
For EVM settlement, the payment Merkle leaf must be the same object checked by
the Solidity payment trigger:

`sha256(abi.encodePacked(recipient_address, payment_record))`

The private `payment_record` must still bind the provider payment key,
recipient commitment, approved result commitment, reconciliation commitment,
amount, and rail. The public payment root must bind the payee record, not only
the internal payment record, so an operator cannot pair a valid payment amount
with a different recipient address at settlement time.

### C8. Padding Inertness

All padded slots must:

- use canonical zero/padding leaves,
- contribute zero to counts and sums,
- not affect nullifier or accumulator roots,
- fail inclusion checks when index is outside `claim_count` or `payment_count`.

### C9. Public Input Binding

The public `combined_batch_commitment` must be a collision-resistant commitment
over all public inputs, including `batch_id`, roots, counts, verifier key, code
hashes, and schema version.

### C10. Verifier Key And Governance Binding

The verifier key ID and adjudicator code hash must be tied to governance roots.
The contract must reject proofs for unapproved verifier keys, ruleset roots,
code hashes, and schema versions.

## Required Negative Tests

The implementation is not complete until these all fail to prove or fail to
verify:

- normalized member/provider/eligibility flags do not match raw/external facts,
- duplicate nullifier omitted from witness,
- same nullifier inserted twice in one batch,
- fee schedule row for wrong procedure,
- fee schedule row outside service-date effective range,
- total charge differs from line sum,
- payment root includes denied claim,
- payment amount exceeds approved sum,
- padding leaf included as real claim,
- high-bit Merkle index aliases a valid index,
- proof public inputs swapped across batches,
- proof generated under retired verifier key,
- ruleset root not approved for service date,
- accumulator cap exceeded by many individually-valid claims.

## Required Positive Tests

- all gates pass and payment is produced,
- each gate G1-G10 fails with correct first failure code,
- multi-claim batch with mixed approvals/denials,
- per-provider netting across multiple approved claims,
- accumulator state advances,
- nullifier root advances,
- service-date-specific fee schedule selects correct row,
- appeal inclusion proof verifies for one claim inside a batch.

## Audit Gate

Before production:

- independent ZK audit signs off the circuit,
- domain reviewer signs off rules and remittance mapping,
- governance records exact circuit hash, verifier key, ruleset root, and schema
  version,
- reproducible witness/proof generation is documented,
- the app refuses production operation unless these hashes are configured:
  audited binding-circuit hash, verifier key hash, raw-837 derivation circuit,
  nullifier transition circuit, payment reconciliation circuit, native STARK
  verifier, accumulator root, effective-dated ruleset timeline, fee schedule
  root, eligibility/provider/prior-auth oracle roots, in-circuit oracle key
  root, settlement-address-book root, data-availability root, governance
  multisig, governance timelock, and verifier trust root.
