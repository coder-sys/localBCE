# Production Binding And Oracle-In-Proof V0

Status: compiled Circom production-binding circuit plus executable app harness. Soundness-checked by local witness tests, PENDING CRYPTO AUDIT.

This lane is the first concrete build of the production proof statement. It does not claim production security yet, but it turns the previously-written binding/oracle requirements into executable checks and a standalone arithmetic circuit.

## What It Binds

- Raw 837 payload digest.
- Reparsed raw 837 -> normalized claim context.
- Signed Ed25519 oracle attestations for eligibility/provider/death/suspension facts.
- Oracle fact roots:
  - eligibility root,
  - provider status root,
  - prior authorization root,
  - oracle public-key root.
- Fee schedule root and effective-date row selection.
- Gate vector, first-failed reason, CARC/RARC, and payable amount.
- Claim root, result root, payment root.
- Settlement recipient address book root.
- Nullifier root before/after.
- Combined batch commitment over all public roots/counts/verifier identity.

## Code

- `circuits/production_binding_v0.circom`
  - compiles as a standalone Circom circuit,
  - binds raw claim digest, oracle fact root, fee row root, claim/result/payment roots, nullifier before/after roots, ruleset root, verifier identity, and combined commitment,
  - enforces G1-G10 plus the G8 invalid-charge/excessive-charge split for one normalized claim.
- `circuits/production_binding_v1.circom`
  - closes the v0 prover-chosen-root holes,
  - requires oracle fact Merkle membership under `oracleFactsRoot`,
  - requires fee/prior-auth policy Merkle membership under `feeScheduleRoot`,
  - requires recipient Merkle membership under `addressBookRoot`,
  - derives the nullifier from claim facts and proves an empty-slot sparse insertion,
  - pays the governed allowed amount instead of the billed amount,
  - range-checks amount/date fields.
- `circuits/production_binding_v2.circom`
  - closes the v1 free-claim-story gap,
  - requires normalized claim facts to be included under a trusted
    `claimSourceRoot`,
  - derives the nullifier from the claim-source leaf plus member/provider/service
    identity,
  - rejects raw-hash double-pay attempts, member-swap collision attempts, and
    procedure-substitution attempts.
- `scripts/make_production_binding_inputs.js`
  - produces matching positive and adversarial witness inputs.
- `scripts/run_production_binding_checks.ps1`
  - compiles the circuit,
  - checks accepted witnesses,
  - checks that tampered oracle roots, forced approval over fee limit, and recipient swaps fail.
- `scripts/run_production_binding_groth16_smoke.ps1`
  - generates a local Groth16 smoke proof over the compiled circuit,
  - verifies an approved proof,
  - confirms the same proof is rejected if the public decision bit is tampered.
- `scripts/run_production_binding_v1_checks.ps1`
  - compiles the v1 circuit,
  - checks approved and denied witnesses,
  - confirms fabricated oracle facts, fake fee ceilings, recipient redirects,
    prior-auth bypass, replayed nullifier state, and over-wide amounts reject.
- `scripts/run_production_binding_v1_groth16_smoke.ps1`
  - generates/verifies a local Groth16 smoke proof over the v1 circuit.
- `scripts/run_production_binding_v2_checks.ps1`
  - compiles the v2 circuit,
  - checks approved and denied witnesses,
  - confirms fabricated oracle facts, fake fee ceilings, raw-hash double-pay,
    member collision/grief, procedure substitution, recipient redirects,
    prior-auth bypass, replayed nullifier state, and over-wide amounts reject.
- `scripts/run_production_binding_v2_groth16_smoke.ps1`
  - generates/verifies a local Groth16 smoke proof over the v2 circuit.
- `app/production_binding.py`
  - builds and verifies the production binding statement,
  - validates signed oracle facts,
  - recomputes raw-837-derived context,
  - recomputes fee, gate, payment, and root commitments.
- `tests/test_production_binding.py`
  - proves happy path,
  - rejects missing oracle fact,
  - rejects mismatched oracle value,
  - rejects raw EDI swap,
  - rejects fee schedule mismatch / bad effective date,
  - rejects tampered result amount,
  - rejects public oracle root swap,
  - rejects settlement recipient swap,
  - rejects approved payment without nullifier-root advance.

## What It Still Is Not

Still pending:

- port the v2 constraints into the chosen native STARK/Cairo production circuit,
- verify oracle signatures inside the proof; v2 proves membership against governed roots but does not verify Ed25519 signatures directly,
- externally audit the v2 nullifier sparse insertion construction,
- prove payment sum reconciliation in-circuit,
- run the production prover/verifier path after a real ceremony or native-STARK migration,
- external cryptographic audit.

V2 still does not parse raw 837 bytes inside Circom. It proves membership against
a trusted parsed-claim `claimSourceRoot`; production must make that root a governed
ingestion artifact and pin it in the verifier/contract state.
