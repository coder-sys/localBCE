# Deployment Runbook

Status: local and pilot-prep runbook. This is not production approval.

The active demo deployment path is still the existing Groth16 flow:

```text
claim_input.json
-> rust-engine adjudication
-> zk/input.json
-> Groth16 proof
-> Solidity verifier
-> ClaimsRegistry
-> adjudication_result.json
```

## Local Preflight

1. Confirm the working tree is clean.
2. Run Rust checks from `rust-engine/`.
3. Run Foundry checks from `blind-ledger/`.
4. Confirm no filled production secrets are present in the repo.
5. Confirm `rust-engine/config.json` points to the intended local
   `ClaimsRegistry` address.

## STARK Pilot Preflight

The opt-in STARK path now generates and locally verifies real Winterfell proofs.
The governed pilot settles a controlled secp256k1 attestation over the verified
proof commitment and public inputs; it does not verify Winterfell natively in
Solidity.

Before a Sepolia pilot:

1. Run `bash scripts/validate_stark_bridge_chain.sh`.
2. Run `bash scripts/validate_stark_v2_anvil.sh` on disposable Anvil.
3. Validate the policy manifest and all deployment pins.
4. Create the 2-of-3 Safe and deploy its 72-hour `TimelockController`.
5. Enroll an approved MPC key ID and remove local-key mode from pilot config.
6. Deploy V2 on chain `11155111`, verify bytecode, and timelock the registry
   allowlist operation.
7. Execute approved and denied canaries and wait for RPC `finalized` coverage.
8. Reconcile the journal and require a clean pilot report before changing the
   release profile.

The earlier compatibility pipeline remains available with:

```text
rust-engine:
  cargo run -- stark-bridge-input-dry-run

stark-engine:
  validate_bridge_input
  generate_proof_intent
  generate_witness_plan
  validate_witness_plan
  generate_mock_trace
  generate_winterfell_compat_report
  generate_winterfell_gap_plan
```

These compatibility commands do not themselves submit on-chain.

## Release And Recovery

- `ops/stark_v2_release_profile.example.json` keeps Groth16 current until every
  pilot gate is approved.
- A failed STARK settlement must never be retried through Groth16 automatically.
- Emergency pause is immediate through the Safe; unpause and configuration
  changes are timelocked.
- Rollback is a manual governed action after journal reconciliation.
- Local nullifier state is committed only after finalized-chain confirmation.

## Production Deployment Gate

Do not deploy production contracts until:

- The controlled-attestation proof and settlement path passes all local gates.
- Safe, timelock, MPC, policy, deployment pins, and finalized canaries are owned
  and approved by their external operators.
- Public input schemas are signed off.
- Governance and manual rollback procedures have passed dry-run tests.
- Monitoring for settlement, roots, verifier artifacts, and rule ratification is
  active.
- The isolated native verifier candidate remains inactive until transcript,
  bytecode, gas, adversarial, and independent-audit gates all pass.
