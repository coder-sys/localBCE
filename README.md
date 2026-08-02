# Blind Ledger - ZK Claims Adjudication Prototype

Blind Ledger is a local prototype for privacy-preserving healthcare claims adjudication using:

- Rust
- Circom
- Groth16
- Winterfell STARK
- Solidity
- Foundry

The system validates claims off-chain, generates zero-knowledge proofs for approved claims, and records approved adjudications on-chain.

Groth16 remains the default compatibility path. An opt-in `stark_attested`
backend now generates and locally verifies a real Winterfell proof and settles
through controlled-attestation Solidity contracts. See `STARK_RUNTIME.md` for
the exact trust boundary and operating commands.

---

# Current Workflows

Default Groth16 backend:

claim_input.json
-> Rust adjudication
-> denial_reason validation
-> zk/input.json
-> witness generation
-> Groth16 proof
-> Solidity verifier
-> ClaimsRegistry
-> adjudication_result.json

Opt-in STARK backend:

claim_input.json
-> Rust adjudication
-> StarkBridgeInput
-> persistent nullifier transition
-> Winterfell proof and local verification
-> controlled-attestation envelope
-> StarkClaimsRegistry
-> adjudication_result.json

---

# Validation

Run the full local health check from the repository root:

```bash
bash scripts/validate_localbce.sh
```

This runs:

- `python3 scripts/validate_ops_scaffold.py`
- `bash scripts/validate_rules_pipeline.sh`
- `cargo test` and `cargo check` in `rust-engine/`
- `cargo test` and `cargo check` in `stark-engine/`
- `forge test` and `forge build` in `blind-ledger/`

Set `RUN_STARK_RUNTIME_SETTLEMENT=1` to add the disposable-Anvil live STARK
settlement gate.

Foundry may print lint notes for generated verifier constants and deployment
JSON smoke-test file cheatcodes. Those notes are not failures when the test and
build commands exit successfully.

---

# Architecture Alignment

The repository is aligned to the broader hardened technical architecture through
an explicit staging model:

- default Groth16 path: `rust-engine/`, `zk/`, `blind-ledger/`
- opt-in STARK runtime: `rust-engine/`, `stark-engine/`, `blind-ledger/`
- imported app/audit reference lane: `blind-ledger-app-layer/`
- imported hardened reference bundle: `localBCE-codex-dev-hardened-20260616/`
- rules discovery/review lane: `gov-rules-kg-prototype/`
- ops/governance planning scaffold: `ops/`

See `ARCHITECTURE_ALIGNMENT.md` for the maturity-tagged map between the
technical reference architecture and what is active, scaffolded, reference-only,
or deferred in this repo.

See `ROADMAP_TO_TARGET_ARCHITECTURE.md` for the phased implementation roadmap
from the active Groth16 prototype toward deterministic rules, STARK bridge
hardening, batch roots, native STARK settlement, app-layer integration, and
production ops.

See `STARK_PHASE4_CHECKPOINT.md` for the completed Phase 4 STARK bridge
checkpoint and initial smoke-test summary.

See `STARK_PHASE6_CHECKPOINT.md` for the feature-gated Winterfell proof-preview
checkpoint that preceded the current production AIR.

See `STARK_SOLIDITY_PREVIEW_CHECKPOINT.md` for the preview-only Solidity STARK
verifier and ClaimsRegistry adapter interface history. The current opt-in
contracts are documented in `STARK_RUNTIME.md`.

See `STARK_RUNTIME.md` for the implemented controlled-attestation runtime and
`STARK_TRANSITION_REMAINING.md` for production-hardening gates.

See `STARK_VERIFIER_ABI_CANDIDATE.md` for the current preview-only production
STARK verifier ABI candidate and public-input expectations.

See `STARK_PHASE8_PROVER_BOUNDARY.md` for implementation history and the
production G1-G10 Winterfell AIR boundary.

See `RULES_ENGINE.md` for the hash-pinned G1-G10 JSON evaluator and the
non-runtime Claude candidate shadow boundary.

---

# Project Structure

```text
localBCE/
  ARCHITECTURE_ALIGNMENT.md
                  maturity-tagged alignment to the technical reference
  ROADMAP_TO_TARGET_ARCHITECTURE.md
                  phased roadmap from active prototype to target architecture
  blind-ledger/   Solidity + Foundry
  blind-ledger-app-layer/
                  imported standalone app/audit layer
  zk/             Circom + snarkjs artifacts
  zk-prover/      future/dedicated proof service
  rust-engine/    Rust adjudication engine
  stark-engine/   first-class STARK bridge crate
  gov-rules-kg-prototype/
                  Claude web-grounded rules KG prototype
  localBCE-codex-dev-hardened-20260616/
                  imported hardened reference bundle
```

---

# Current Features

## Rust Adjudication Engine

- Claim parsing
- Claim hashing
- Structured denial reasons
- G1-G10 rule validation
- adjudication_result.json generation
- tx_hash extraction
- runtime config via config.json
- structured proof-stage logging
- Rust unit tests
- Typed, hash-pinned G1-G10 JSON ruleset with opt-in exact-parity evaluation
- Rust validation of the 51-program Claude shadow bundle

## ZK Layer

- Circom circuits
- Witness generation
- Groth16 proving
- Solidity verifier generation
- Optional STARK sidecar artifact generation from rust-engine dry-run path
- Feature-gated Winterfell G1-G10 proofs with a constrained Rescue-Prime
  claim-to-fact commitment and `publicInputRoot`

## STARK Bridge

- stark-engine/ is the first-class localBCE STARK proving and settlement crate.
- blind-ledger-app-layer/zk-stark/ remains the imported Winterfell reference/audit source.
- rust-engine/ defaults to Groth16 and supports explicit `stark_attested` routing.
- A feature-gated Winterfell PoC proof preview exists in stark-engine/ and is
  covered by the STARK smoke chain.
- The production G1-G10 AIR packages real Winterfell proof bytes and its exact
  38-element public-input vector into a versioned JSON artifact.
- The AIR constrains canonical claim-source, verified-oracle-facts,
  verified-fee-schedule, persistent nullifier, public-input, and batch-root
  semantics.
- The production artifact validator deserializes the saved proof bytes and
  re-verifies them locally; it does not trust a stored success flag.
- The atomic executor reconciles persistent local nullifier state with the
  on-chain registry, submits settlement, and applies state only after receipt
  confirmation.
- `StarkAttestationVerifier` and `StarkClaimsRegistry` provide the opt-in
  controlled-attestation settlement path.
- Solidity verifies a secp256k1 attestation over the exact inputs and proof
  commitment; it does not natively verify the full Winterfell proof.

Current STARK artifact and compatibility workflow:

```bash
bash scripts/validate_stark_bridge_chain.sh
```

This chain validates bridge schemas, root inputs, mock traces, production
proof artifacts, verifier handoffs, attestation envelopes, and persistent
state transitions. The separate runtime validator exercises live settlement.

The script writes temporary artifacts under `/tmp`, removes generated runtime
artifacts on exit, and is the source of truth for command ordering.

Feature-gated production proof artifact path:

```bash
cd rust-engine
cargo run -- stark-bridge-input-dry-run

cd ../stark-engine
cargo run --features production-air-winterfell \
  --bin generate_production_stark_proof_artifact -- \
  ../rust-engine/stark_bridge_input.json production_stark_proof_artifact.json

cargo run --features production-air-winterfell \
  --bin validate_production_stark_proof_artifact -- \
  production_stark_proof_artifact.json

cargo run --features production-air-winterfell \
  --bin generate_production_stark_verifier_handoff -- \
  production_stark_proof_artifact.json production_stark_verifier_handoff.json

cargo run --features production-air-winterfell \
  --bin validate_production_stark_verifier_handoff -- \
  production_stark_verifier_handoff.json

cargo run --features production-air-winterfell \
  --bin generate_production_claim_source_root -- \
  ../rust-engine/stark_bridge_input.json production_claim_source_root.json

cargo run --features production-air-winterfell \
  --bin validate_production_claim_source_root -- \
  production_claim_source_root.json

cargo run --features production-air-winterfell \
  --bin generate_production_oracle_facts_root -- \
  ../rust-engine/stark_bridge_input.json production_oracle_facts_root.json

cargo run --features production-air-winterfell \
  --bin validate_production_oracle_facts_root -- \
  production_oracle_facts_root.json

cargo run --features production-air-winterfell \
  --bin generate_production_fee_schedule_root -- \
  ../rust-engine/stark_bridge_input.json production_fee_schedule_root.json

cargo run --features production-air-winterfell \
  --bin validate_production_fee_schedule_root -- \
  production_fee_schedule_root.json

cargo run --features production-air-winterfell \
  --bin generate_production_nullifier_root_transition -- \
  ../rust-engine/stark_bridge_input.json production_nullifier_root_transition.json

cargo run --features production-air-winterfell \
  --bin validate_production_nullifier_root_transition -- \
  production_nullifier_root_transition.json
```

The proof binds the 32-byte claim hash, G1-G10 facts, decision, failure code,
all seven public roots, and the locked 38-element input vector. Root values are
canonically packed from four big-endian 64-bit field elements into Solidity
`bytes32`. Source labels and references are committed by the proof, while
external truth, governance approval, and attestor custody remain operational
trust responsibilities.

The verifier handoff and 129-byte settlement envelope bind the proof
commitment, target registry, and claim amount to the exact Solidity inputs.
The complete Winterfell proof remains in the audit artifact and is reverified
locally before the attestor authorizes the on-chain transition.

The claim-source command independently materializes the same canonical
depth-10 `Rp64_256` Merkle opening from bridge-supplied member, provider,
service-line, diagnosis, charge, and service-date facts. The production AIR
now consumes that opening, constrains its leaf and path, and exposes the root
through the proof artifact and verifier handoff. The root is consumed by the
opt-in STARK runtime; governance approval remains external.

Schema details for the STARK bridge artifacts are documented in:

```text
stark-engine/SCHEMA.md
```

## Smart Contracts

- Verifier.sol
- ClaimsRegistry.sol
- On-chain approved claim recording
- Active Foundry tests for ClaimsRegistry.sol
- Deployment JSON smoke test for deployment.json
- Preview-only STARK verifier and adapter interfaces/tests
- Preview-only STARK verifier V1 ABI candidate
- Controlled-attestation STARK verifier and ClaimsRegistry
- STARK deployment script and approved/denied/replay Foundry tests

---

# Active Files

## Rust

- rust-engine/src/main.rs
- rust-engine/config.json
- rust-engine/claim_input.json
- rust-engine/adjudication_result.json

## Solidity and Foundry

- blind-ledger/src/ClaimsRegistry.sol
- blind-ledger/src/Verifier.sol
- blind-ledger/script/Counter.s.sol
- blind-ledger/test/ClaimsRegistry.t.sol
- blind-ledger/test/DeploymentJson.t.sol
- blind-ledger/foundry.toml

## ZK

- zk/claim.circom

## STARK

- stark-engine/Cargo.toml
- stark-engine/SCHEMA.md
- stark-engine/src/lib.rs
- stark-engine/src/production_air.rs
- stark-engine/src/production_air_winterfell.rs
- stark-engine/src/production_proof_artifact.rs
- stark-engine/src/production_verifier_handoff.rs
- stark-engine/src/bin/generate_production_stark_proof_artifact.rs
- stark-engine/src/bin/validate_production_stark_proof_artifact.rs
- stark-engine/src/bin/generate_production_stark_verifier_handoff.rs
- stark-engine/src/bin/validate_production_stark_verifier_handoff.rs
- stark-engine/src/bin/validate_bridge_input.rs
- stark-engine/src/bin/generate_claim_source_root_input.rs
- stark-engine/src/bin/validate_claim_source_root_input.rs
- stark-engine/src/bin/generate_oracle_facts_root_input.rs
- stark-engine/src/bin/validate_oracle_facts_root_input.rs
- stark-engine/src/bin/generate_fee_schedule_root_input.rs
- stark-engine/src/bin/validate_fee_schedule_root_input.rs
- stark-engine/src/bin/generate_nullifier_root_transition_input.rs
- stark-engine/src/bin/validate_nullifier_root_transition_input.rs
- stark-engine/src/bin/generate_batch_root_plan.rs
- stark-engine/src/bin/validate_batch_root_plan.rs
- stark-engine/src/bin/generate_batch_root_gap_report.rs
- stark-engine/src/bin/generate_proof_intent.rs
- stark-engine/src/bin/generate_witness_plan.rs
- stark-engine/src/bin/validate_witness_plan.rs
- stark-engine/src/bin/generate_mock_trace.rs
- stark-engine/src/bin/validate_mock_trace.rs
- stark-engine/src/bin/generate_winterfell_compat_report.rs
- stark-engine/src/bin/generate_winterfell_gap_plan.rs
- stark-engine/tests/compatibility.rs
- stark-engine/tests/phase4_claim_source_root_input.rs
- stark-engine/tests/phase4_oracle_facts_root_input.rs
- stark-engine/tests/phase4_fee_schedule_root_input.rs
- stark-engine/tests/phase4_nullifier_root_transition_input.rs

## Imported App and Audit Layer

- blind-ledger-app-layer/README.md
- blind-ledger-app-layer/COFOUNDER_HANDOFF_README.md
- blind-ledger-app-layer/app/
- blind-ledger-app-layer/contracts/
- blind-ledger-app-layer/tests/
- blind-ledger-app-layer/zk-production-binding/
- blind-ledger-app-layer/zk-stark/
- blind-ledger-app-layer/zk-sp1/

Note: blind-ledger-app-layer is imported as a standalone cofounder handoff and
audit/research lane. It is not wired into the active Rust -> Groth16 ->
ClaimsRegistry workflow yet.

## Rules Knowledge Graph

- gov-rules-kg-prototype/README.md
- gov-rules-kg-prototype/src/gov_rules_kg/
- gov-rules-kg-prototype/tests/

Note: gov-rules-kg-prototype is a rules discovery, Claude web-grounded candidate, review, and export prototype. Its outputs are not active Rust adjudication rules until reviewed and explicitly bridged into rust-engine.

## Hardened Reference Bundle

- localBCE-codex-dev-hardened-20260616/
- localBCE-codex-dev-hardened-20260616/localBCE-codex-dev/ops/
- localBCE-codex-dev-hardened-20260616/localBCE-codex-dev/blind-ledger-app-layer/
- localBCE-codex-dev-hardened-20260616/localBCE-codex-dev/gov-rules-kg-prototype/
- localBCE-codex-dev-hardened-20260616/localBCE-codex-dev/tooling/

Note: this folder is tracked as an imported hardened reference bundle. It is not active runtime code unless a later task explicitly ports a file or behavior into the active project folders.

---

# Current Gate Coverage

- G1 Eligibility
- G2 Aid code validation
- G3 Date range validation
- G4 Share-of-cost validation
- G5 Provider validation
- G6 Billing validation
- G7 Duplicate detection
- G8 Disability determination
- G9 Recipient deceased validation
- G10 Physician certification

---

# Current Output

Approved claim:

```json
{
  "claim_id": "CLAIM-DEMO-010",
  "claim_hash": "0x97a2edc417f16993e07f860e1f52cc3d86f8adfe66ab5c4d21369ef5c2ff58c5",
  "status": "APPROVED",
  "reason": null,
  "tx_submitted": true,
  "tx_hash": "0xc2a2ee618bebfd2de66ea982a1b4f4c0566a12a27746382eafcfd43b330852dd"
}
```

Denied claim:

```json
{
  "claim_id": "CLAIM-DEMO-009",
  "claim_hash": "0x470b16112aff0e4ef85c47f50c21695e8eedbac749eeda1c7dd42320300c4eff",
  "status": "DENIED",
  "reason": "G9_RECIPIENT_DECEASED",
  "tx_submitted": false,
  "tx_hash": null
}
```

---

# Current Status

Prototype is functional end-to-end.

Working components:

- Rust -> ZK integration
- Groth16 proof generation
- Solidity verification
- ClaimsRegistry recording
- structured adjudication outputs
- Rust unit tests
- Foundry ClaimsRegistry tests
- Foundry deployment.json smoke test

---

# Active ClaimsRegistry

0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e

Configured in:

```text
rust-engine/config.json
```

---

# Current Rules Files

- rules.json - current/simple working rules
- rules_v9.json - future target architecture

Current Rust engine still reads:

```text
claim_input.json
```

Runtime submission config is read from:

```text
config.json
```

rules_v9.json is not yet active.

---

# Important Constraints

- main.rs must continue reading claim_input.json
- denial_reason() must remain
- approved claims require unique claim_id
- adjudication_result.json must continue working
- rules.json and rules_v9.json must remain parallel
- rust-engine/config.json must hold the active ClaimsRegistry address

If claim.circom changes:

1. Recompile circuit
2. Regenerate zkey
3. Regenerate Verifier.sol
4. Redeploy contracts
5. Update claims_registry_address in rust-engine/config.json

---

# Verification

Rust:

```bash
cd rust-engine
cargo test
cargo check
```

Solidity:

```bash
cd blind-ledger
forge test
forge build
```

Redeploy workflow:

```text
REDEPLOY_WORKFLOW.md
```

---

# Future Goals

- rules_v9.json integration
- recursive proofs
- policy registries
- Merkle commitments
- nullifier trees
- Plonky3 migration

Near-term next steps:

- Keep Groth16 green as the default backend.
- Independently audit the controlled-attestation STARK path and formalize key
  custody, root governance, monitoring, and recovery.
- Consider native or recursively wrapped on-chain STARK verification as a
  separate trust-model upgrade.
- Use ARCHITECTURE_ALIGNMENT.md as the boundary map before porting reference components.
- Use ROADMAP_TO_TARGET_ARCHITECTURE.md to choose the next safe integration phase.
- Port hardened/app-layer assets only through explicit reviewed integration steps.
- Bridge reviewed deterministic rule candidates into a versioned Rust shadow
  bundle, prove G1-G10 parity, and gate runtime activation explicitly.
- oracle attestations
- off-circuit rules engine
- ZK Bouncer architecture
