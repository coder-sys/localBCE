# Blind Ledger Ops Scaffolding

Status: planning scaffold, not production approval.

This directory contains operational documentation ported from the hardened
reference bundle. These files describe deployment, monitoring, custody, risk,
and production-readiness expectations for future production work.

They do not change the active local prototype:

- Groth16 remains the active compatibility/demo path.
- `rust-engine/`, `zk/`, and `blind-ledger/` remain the active runtime flow.
- `stark-engine/` contains both compatibility tooling and a feature-gated real
  Winterfell prover that is opt-in and locally verified.
- No native Solidity Winterfell verifier is active; governed V2 is an inactive
  controlled-attestation pilot candidate.

The following machine-readable JSON files are included as inactive scaffolding:

- `launch_blockers.json`
- `monitoring_events.json`
- `governance_config.example.json`
- `oracle_source_manifest.example.json`
- `verifier_artifact_pin.example.json`

These files are examples and planning inputs only. They are not active runtime
configuration, do not enable production mode, and do not replace
`rust-engine/config.json`.

Validate the inactive JSON scaffolding with:

```bash
python3 scripts/validate_ops_scaffold.py
python3 scripts/validate_policy_manifest.py ops/policy_manifest.example.json
```

`policy_manifest.example.json`, `stark_v2_deployment_pin.example.json`, and
`stark_v2_release_profile.example.json` are inactive Sepolia pilot scaffolds.
The release profile prohibits automatic fallback and requires manual governed
rollback. The policy hash binds the controlled
attestation but does not establish the legal validity or source authenticity of
claim and oracle facts. Replace every example address and placeholder pin only
through an approved release process.

After a governed deployment, generate the operational reconciliation report
with real deployment, journal, receipt, state, pin, and RPC inputs:

```bash
python3 scripts/generate_stark_pilot_reconciliation_report.py \
  --deployment blind-ledger/stark_v2_deployment.json \
  --deployment-pin ops/stark_v2_deployment_pin.json \
  --journal stark-engine/runtime-artifacts/settlement_journal.json \
  --receipt stark-engine/runtime-artifacts/settlement_receipt.json \
  --state stark-engine/runtime-state/nullifier_state.json \
  --rpc-url "$SEPOLIA_RPC_URL" \
  --output stark_pilot_reconciliation_report.json
```

The validator checks file presence, JSON parsing, `schema_version` fields,
example/demo governance addresses, required-source HTTPS/official flags, and
that the verifier artifact pin remains marked non-production. It does not
import app-layer code and does not validate production readiness.

Production environment templates, native STARK public input schemas, and
production automation scripts are intentionally not ported yet. They should be
added only through later explicit integration tasks.
