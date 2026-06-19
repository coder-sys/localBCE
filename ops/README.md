# Blind Ledger Ops Scaffolding

Status: planning scaffold, not production approval.

This directory contains operational documentation ported from the hardened
reference bundle. These files describe deployment, monitoring, custody, risk,
and production-readiness expectations for future production work.

They do not change the active local prototype:

- Groth16 remains the active compatibility/demo path.
- `rust-engine/`, `zk/`, and `blind-ledger/` remain the active runtime flow.
- `stark-engine/` remains a pre-prover planning and compatibility crate.
- No real STARK proof or native STARK verifier is active yet.

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
```

The validator checks file presence, JSON parsing, `schema_version` fields,
example/demo governance addresses, required-source HTTPS/official flags, and
that the verifier artifact pin remains marked non-production. It does not
import app-layer code and does not validate production readiness.

Production environment templates, native STARK public input schemas, and
production automation scripts are intentionally not ported yet. They should be
added only through later explicit integration tasks.
