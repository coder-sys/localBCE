# Deployment Runbook

Status: local and pilot-prep runbook. Real production still requires the launch
blockers in `ops/launch_blockers.json` to close.

## Preflight

1. Confirm the release zip was built by `scripts/build_clean_release_zip.ps1`.
2. Run `scripts/run_buildable_checks.ps1`.
3. Run `python scripts/validate_operational_readiness.py`.
4. Confirm no filled production secrets are present in the repo.
5. Confirm `ops/verifier_artifact_pin.example.json` is replaced by a production
   verifier pin manifest before any live deployment.

## Production Deployment Gate

Do not deploy production contracts until:

- Native STARK verifier artifact is real and externally reviewed.
- Verifier artifact hash is pinned by governance.
- Public input schema in `ops/native_stark_public_inputs_v1.json` is signed off.
- Multisig/timelock config has passed a dry-run upgrade and rollback test.
- Monitoring for `StarkBatchSubmitted` and nullifier root advancement is active.
