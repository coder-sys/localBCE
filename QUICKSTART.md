# Quickstart

For a new Codex chat in the full workspace, first read `AGENTS.md`, the newest `STATE.md` entry,
`CONTINUATION_MANDATE.md`, and then the four architecture files in the mandated recovery order.
The published source archive intentionally omits `STATE.md` and `WAVE2_HANDOFF_2026-07-26.md`; when
starting from that archive, use the current root documents and `RELEASE_FILE_MANIFEST.json` instead.
The current next implementation is the LB-006 transactional database boundary in
`docs/IMPLEMENTATION_ROADMAP.md`; do not infer a next action from historical `STATE.md` entries.

From the repository root:

```powershell
py -3.14 -B -m pytest -q -p no:cacheprovider
cargo test --manifest-path experiments/bl_pq512_crypto_core/Cargo.toml --lib --tests
cargo test --manifest-path rules-engine-rust/Cargo.toml --lib --tests
```

Useful focused checks:

```powershell
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_production_boundary.py tests/test_production_readiness.py tests/test_operational_readiness.py
py -3.14 -B -m experiments.bl_pq512_crypto_foundation.internal_completion
```

The internal receipt must report `internal_complete=33`, `internal_open=48`, `proofSuiteId=null`, and `production_usable=false`. These commands verify local source behavior. They do not authorize production, PHI, payments, or Ethereum settlement.
