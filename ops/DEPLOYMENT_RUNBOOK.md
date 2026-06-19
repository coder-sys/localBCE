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

## STARK Planning Preflight

The STARK path is currently planning/pre-prover only. It may be checked with:

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

These commands do not generate a real STARK proof and do not submit on-chain.

## Production Deployment Gate

Do not deploy production contracts until:

- Native STARK proof generation is real and externally reviewed.
- A native STARK verifier strategy is selected and audited.
- Public input schemas are signed off.
- Governance multisig and timelock configuration have passed dry-run upgrade
  and rollback tests.
- Monitoring for settlement, roots, verifier artifacts, and rule ratification is
  active.

