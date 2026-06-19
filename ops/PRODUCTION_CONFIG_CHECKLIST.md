# Production Config Checklist

Status: operational checklist, not production approval.

Before any production deployment, private environment values must replace every
placeholder with real audited roots, hashes, addresses, or keys. Never commit a
filled production environment file.

## Required Checks

1. Confirm the active Groth16 demo path still passes its Rust and Foundry tests.
2. Confirm the STARK path is still labeled pre-prover until a real proof exists.
3. Confirm no production secrets are present in the repo.
4. Confirm native STARK verifier artifacts are real before enabling any native
   STARK settlement path.
5. Confirm governance multisig and timelock addresses match deployed contracts.
6. Confirm launch blockers are closed or formally accepted by the named owner.
7. Confirm monitoring/audit event expectations are documented before pilot use.
8. Confirm rule candidates are reviewed and deterministic before runtime use.

## Current Local Prototype Status

- `BL_PROOF_LANE` style production config is not active.
- Native STARK verifier config is not active.
- Batch settlement config is not active.
- The active `ClaimsRegistry` address remains in `rust-engine/config.json`.

