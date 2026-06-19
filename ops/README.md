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

Machine-readable ops JSON configs and validation scripts are intentionally not
ported in this step. They should be added only through later explicit
integration tasks.

