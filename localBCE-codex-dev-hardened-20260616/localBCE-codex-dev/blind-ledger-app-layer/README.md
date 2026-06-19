# Blind Ledger App Layer

This app layer now targets native STARK settlement only.

## Contents

- `app/`: ingestion, rules adapter, batch orchestration, nullifier roots,
  STARK-field Poseidon helpers, production readiness, operational validators,
  and the Medi-Cal operator portal API.
- `operator_portal/`: static employee-facing batch review interface.
- `contracts/`: batch registry/payment contracts, native STARK settlement
  contracts, and tests.
- `rules-engine-rust/`: Rust adjudication engine.
- `zk-stark/`: local STARK proof-core work.
- `zk-cairo-sharp/`: Cairo-native binding prototype and constraint notes.
- `tests/`: Python security, batch, readiness, and app-layer tests.

## Production Position

The app can build and test the fail-closed architecture locally. Production is
blocked until a real audited native STARK prover/verifier, pinned verifier
artifact, governed source manifests, and key custody procedures are supplied.

## Checks

From the repo root:

```powershell
.\scripts\run_buildable_checks.ps1
```

## Operator Portal

From `blind-ledger-app-layer`:

```powershell
python -m uvicorn app.operator_portal:app --host 127.0.0.1 --port 8042
```

Open `http://127.0.0.1:8042`.
