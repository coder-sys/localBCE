# Cairo / SHARP Lane Security Attack Notes

Security label: soundness-checkable prototype, PENDING CRYPTOGRAPHIC AUDIT.

## What Was Attacked

This pass attacked the new Cairo/S-two adjudication lane from first principles:

- malformed normalized witnesses,
- non-canonical boolean values,
- commitment binding,
- duplicate-claim assumptions,
- raw-claim-to-normalized-input trust boundaries,
- cents conversion and range limits,
- policy/ruleset version binding,
- batch attribution binding,
- local proof-generation status.

## Fixed During This Pass

### F1. Non-canonical boolean witnesses accepted

Previous behavior:

- `member_id_present = 2`
- `provider_npi_present = 999`
- otherwise clean inputs

The Cairo executable treated those values as truthy and approved the claim.

Why that matters:

Even if the decision is the same as a canonical `1`, the witness is malleable.
The same semantic claim can have multiple commitments/proofs. That can damage
deduplication, auditing, and replay logic.

Fix:

`validate_input()` now rejects malformed boolean fields unless they are exactly
`0` or `1`.

Evidence:

- `scarb test`: 7 passed / 0 failed.
- `scripts/run_attack_cases.sh`: noncanonical truthy witness now panics with
  `bad member flag` and is marked `REJECTED_AS_EXPECTED`.

### F2. Toy commitment hash

Previous behavior:

The commitment used a home-grown cube-mix hash inherited from the earlier PoC.

Why that matters:

Custom cryptographic hashing is not acceptable for a production proof binding.
Even if it is convenient inside a field, it has no reviewed security parameters.

Fix:

The commitment now uses Cairo's native Poseidon hash:

- `core::poseidon::PoseidonTrait`
- `core::hash::{HashStateExTrait, HashStateTrait}`

Evidence:

- `scarb build`: PASS.
- `scarb test`: 7 passed / 0 failed.
- `scripts/run_cases.sh`: all four normal cases still execute with expected
  decisions and failure codes.
- execution resources now include `poseidon_builtin: 7`.

### F3. Raw claim, ruleset, version, and nullifier state were not bound

Previous behavior:

The public commitment only covered the normalized adjudication summary.

Fix:

The Cairo input/output now binds:

- `raw_claim_leaf`
- `raw_claim_root`
- `ruleset_root`
- `adjudicator_version`
- `claim_nullifier`
- `spent_nullifier_root`
- `new_nullifier_root`

Evidence:

- `scarb test`: 10 passed / 0 failed.
- `commitment_changes_when_ruleset_root_changes`: PASS.
- `commitment_changes_when_raw_claim_leaf_changes`: PASS.
- `missing_raw_claim_root_is_rejected`: PASS.
- `scripts/run_cases.sh`: normal adjudication cases still produce expected decisions.

### F4. Duplicate gate was a naked trusted flag

Previous behavior:

The Cairo lane accepted `duplicate_claim` as a direct input flag.

Fix:

The `duplicate_claim` flag has been removed. G9 is now derived from:

- nonzero `claim_nullifier`
- fixed spent-nullifier witness slots `spent_nullifier_0..7`

If the claim nullifier appears in the spent witness set, G9 fails with failure
code `10`.

Evidence:

- `duplicate_claim_denies_with_code_ten`: PASS.
- `scripts/run_attack_cases.sh`: `spent_nullifier_replay_denied` denies with
  decision `0`, failure code `10`.

### F5. Batch ID was not bound into the Cairo public commitment

Previous behavior:

The Cairo commitment bound the normalized claim, raw claim root, ruleset root,
version, and nullifier state, but did not include the batch identity.

Why that matters:

If an operator can observe a valid proof and public values before final
submission, they can copy the proof-shaped payload, change only the batch ID,
and try to land first. That does not redirect money when the payment root is
identical, but it can create attribution and gas griefing.

Fix:

`batch_id` is now a nonzero field in the Cairo input and output, and it is
included in the Poseidon commitment through the derived `Hash` implementation.

Evidence:

- `commitment_changes_when_batch_id_changes`: PASS.
- `missing_batch_id_is_rejected`: PASS.
- `scripts/run_attack_cases.sh`: `missing_batch_id` rejects.

## Remaining Findings

### R0. Cairo/STARK field mismatch with current app/nullifier stack

Severity: CRITICAL DESIGN BLOCKER.

This is not a live drain today because the Cairo lane is not wired as the active
on-chain verifier. It is, however, the main architectural blocker before Cairo
can become the production lane.

Current state:

- `app/batch/poseidon.py` and the indexed nullifier tree use the BN254 scalar
  field through `pso-poseidon`.
- `zk-cairo-sharp/src/lib.cairo` uses Cairo `felt252` values and Cairo native
  Poseidon over the STARK field.
- Existing batch/contract roots are `bytes32` SHA-256-style values.

Why this matters:

The STARK field is smaller than the BN254 field. A valid BN254 nullifier greater
than the STARK field cannot be represented in Cairo without decomposition or
lossy modular reduction. For example, `STARK_FIELD + 12345` and `12345` are
different BN254/application values but collide if a bridge simply reduces them
modulo the STARK field.

Evidence:

- `tests/attacks/test_new_architecture_security_hunt.py` demonstrates the field
  mismatch and collision shape numerically.

Required decision:

Choose one production path and make it explicit:

- migrate nullifier tree, duplicate-key derivation, claim/result/payment roots,
  and proof commitments into the STARK field end-to-end, or
- keep BN254/SHA roots and prove a non-lossy limb-decomposition bridge inside
  Cairo.

Until this is resolved, Cairo is a strategically correct prototype lane, not an
interoperable replacement for the current app/nullifier state.

### R1. Normalized witness derivation is still the biggest risk

Severity: HIGH.

The Cairo program proves decisions over normalized fields like:

- `member_id_present`
- `provider_npi_present`
- `prior_auth_ok`
- `claim_nullifier` and bounded spent-nullifier slots
- `max_service_line_charge_cents`

It now binds the proof to a raw claim leaf/root and ruleset/version roots, but
it still does not prove that the normalized fields were honestly derived from
the raw 837 claim, provider record, eligibility record, PA record, or fee
schedule.

Attack shape:

A dishonest or compromised adapter can feed clean normalized values and obtain
an approval proof even if the raw claim was missing a member ID, missing NPI,
lacked prior authorization, or was actually a duplicate.

Evidence:

`scripts/run_attack_cases.sh` includes `adapter_lies_clean_flags`, which approves
because a malicious adapter can still supply clean normalized fields. The proof
is now tied to a raw claim root, but it does not parse or derive from the raw
claim bytes inside Cairo yet.

Required fix:

Move from "prove precomputed flags" to "prove the normalization path":

- commit to raw/batched claim leaves,
- commit to provider/eligibility/PA/duplicate data roots,
- derive the normalized gate values inside Cairo,
- bind the proof to the ruleset root and adapter code hash.

### R2. Duplicate prevention is bounded and not anchored to production state

Severity: MEDIUM-HIGH.

The Cairo lane no longer accepts a naked `duplicate_claim` flag. It derives G9
from a fixed-size spent-nullifier witness set.

That is materially better, but still not the final production construction. The
current witness set is fixed at eight prover-supplied slots and does not yet
verify a sparse or indexed Merkle non-membership proof against a chain-stored
nullifier root. A malicious prover can omit the already-spent nullifier from the
eight slots unless the witness is tied to authoritative nullifier state.

Required fix:

Integrate the nullifier non-membership design into this Cairo/SHARP lane:

- claim nullifier,
- spent-nullifier root,
- non-membership proof,
- output updated nullifier root or batch-nullifier delta.

Until that is wired, duplicate prevention is bounded prototype checking, not
production nullifier-tree checking.

### R3. Commitment is now Poseidon and root-bound, but raw derivation is still external

Severity: MEDIUM-HIGH.

Poseidon fixes the hash primitive, and the data model now includes raw claim
root, ruleset root, adjudicator version, and nullifier state.

The remaining issue is derivation. The Cairo program still does not parse the
actual raw claim fields:

- member ID value,
- provider NPI value,
- service date,
- procedure codes,
- diagnosis codes,
- line IDs,
- units,
- PA artifact.

Required fix:

Define a production claim leaf and batch schema. The public commitment should
bind to the raw claim leaf/root plus ruleset/adjudicator version, and the Cairo
program should derive gate fields from that committed data or from committed
external data roots.

### R4. Local proof generation is still blocked

Severity: HIGH until solved.

The Cairo executable runs, and bootloader execution emits `prover_input.json`,
but local `scarb prove` was killed by WSL out-of-memory at about 7.2 GiB RSS.

Required fix:

Run proving on a larger Linux machine or managed S-two/SHARP proving service,
then verify proof artifacts and connect the verifier path.

### R5. Cents conversion and u32 bounds need fail-closed adapter rules

Severity: MEDIUM.

The Cairo executable accepts `u32` cents. That caps values at `4,294,967,295`
cents, or `$42,949,672.95`.

Required fix:

The adapter must reject values outside the Cairo range and must use exact cents
conversion. No float truncation, wrapping, or silent rounding.

### R6. Allowable charge threshold is hard-coded

Severity: MEDIUM.

`MAX_ALLOWABLE_LINE_CHARGE_CENTS = 500000` is a prototype rule.

Required fix:

Bind allowable charge logic to the versioned ruleset and fee schedule. This is
both a correctness and auditability requirement.

### R6b. Charge gate operands are normalized inputs, not derived line facts

Severity: HIGH.

The Cairo executable receives `total_charge_cents`,
`min_service_line_charge_cents`, and `max_service_line_charge_cents` as free
normalized inputs. It checks that total/min are nonzero and max is below the
prototype threshold, but it does not derive those values from committed service
lines.

Attack shape:

A dishonest adapter can set total/min/max to low valid values while the payment
or raw claim data represents a different amount. The current app layer rejects
CLM/SV1 mismatches before batching, but Cairo itself does not prove that
relationship.

Required fix:

The Cairo lane must either derive total/min/max from committed service-line
leaves or prove inclusion of those values from a committed normalization record
whose code hash and ruleset root are also bound.

### R7. Public output privacy is not finalized

Severity: MEDIUM.

The executable currently outputs decision, failure code, and all gate bits.
That is useful for testing, but may reveal more than the final privacy product
should reveal.

Required fix:

Decide whether production public outputs are:

- decision only,
- decision plus first failure code,
- full gate vector,
- roots only plus selective disclosure for appeals.

## Clean Results From This Pass

- Valid approved case still approves.
- Ineligible case denies with failure code `2`.
- Duplicate case denies with failure code `10`.
- Excessive charge case denies with failure code `9`.
- `u32::MAX` charge denies as excessive, not approved.
- zero service lines with positive total denies first at G5.
- non-canonical boolean witness is now rejected.
- missing raw claim root is now rejected.
- changing ruleset root changes the commitment.
- changing raw claim leaf changes the commitment.
- duplicate replay against the bounded spent-nullifier witness denies with
  failure code `10`.

## Bottom Line

The Cairo lane is stronger after this pass, but it is not production-safe yet.

The malformed-witness, toy-hash, root/version binding, and naked duplicate-flag
issues were fixed or materially reduced. The remaining risk is architectural:
the proof must derive normalized fields from committed raw claim data and
external eligibility/provider/PA/nullifier/ruleset roots. Until then, a clean
Cairo proof proves that a root-bound normalized summary was adjudicated
correctly, not yet that the summary was honestly derived from a real Medi-Cal
claim.
