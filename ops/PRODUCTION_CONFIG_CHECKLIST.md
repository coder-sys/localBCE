# Production Config Checklist

Status: operational checklist, not production approval.

Before any production deployment, private environment values must replace every
placeholder with real audited roots, hashes, addresses, or keys. Never commit a
filled production environment file.

## Required Checks

1. Confirm the active Groth16 demo path still passes its Rust and Foundry tests.
2. Confirm real Winterfell proofs verify locally and that Solidity settlement is
   still explicitly labeled controlled attestation, not native verification.
3. Confirm no production secrets are present in the repo.
4. Confirm the native STARK verifier candidate remains inactive unless every
   transcript, EIP-170, gas, adversarial, and audit gate has passed.
5. Confirm governance multisig and timelock addresses match deployed contracts.
6. Confirm launch blockers are closed or formally accepted by the named owner.
7. Confirm monitoring/audit event expectations are documented before pilot use.
8. Confirm rule candidates are reviewed and deterministic before runtime use.
9. Confirm the external signer command, fixed arguments, approved key IDs, MPC
   owner, and timeout are pinned without committing credentials.
10. Confirm `chain_id=11155111`, Safe, timelock, attestor, registry, verifier,
    policy hash, bytecode hashes, proof parameters, Cargo lockfile, and
    deployment transaction all match the deployment pin.
11. Confirm the settlement journal has no conflicting or unfinalized entries.
12. Confirm `automatic_fallback=false` and `rollback_mode=manual_governed`.

## Current Local Prototype Status

- `BL_PROOF_LANE` style production config is not active.
- Governed V2 and native STARK verifier configs are not active by default.
- Batch settlement config is not active.
- The active `ClaimsRegistry` address remains in `rust-engine/config.json`.
