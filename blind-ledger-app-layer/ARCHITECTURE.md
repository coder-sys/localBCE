# Architecture

## Pipeline

```text
claim_input
  -> ingestion API / 837 parser
  -> shared context builder
  -> rules engine
  -> ZK_PROVER_STUB
  -> VERIFIER_STUB
  -> claims registry
  -> PAYMENT_TRIGGER_STUB
  -> 835 generator
  -> appeal router
  -> dashboard state
```

## Real Components Built

- 837 ingestion parser and validator.
- Shared context schema.
- Rules-engine gate logic, with Rust source/tests and Python fallback for local demo.
- 835 generator.
- Appeal router.
- Local claims registry.
- Static dashboard.
- End-to-end orchestrator.
- Solidity claims registry, verifier interface/stub, payment trigger, bridge stubs, governance registry, and Foundry tests.

## Stubs

- `ZK_PROVER_STUB`: returns a mock proof object with `proof`, `public_inputs`, and `context_hash`.
- `VERIFIER_STUB`: validates mock proof shape and returns true for well-formed stub proofs.
- `CIRCLE_BRIDGE_STUB` / `FEDNOW_BRIDGE_STUB`: return mock settlement references only.
- Local dev chain only: contracts are written for Anvil/Foundry local deployment, not a production L2.

## Careful-Track Remaining

- Real ZK circuits and prover.
- Generated verifier contract from circuits.
- Real L2 operations.
- Real Circle/FedNow bridge integrations.
- PQ migration and cryptographic hardening.

## Shared Context Schema

```json
{
  "claim_id": "string",
  "transaction_set": "837",
  "payer_id": "string",
  "member_id": "string",
  "patient": {"name": "string", "id": "string"},
  "provider": {"npi": "string", "name": "string"},
  "service_date": "YYYYMMDD",
  "diagnoses": ["string"],
  "service_lines": [
    {
      "line_id": "string",
      "procedure_code": "string",
      "charge_amount": "number",
      "units": "number",
      "prior_authorization": "string|null"
    }
  ],
  "total_charge": "number",
  "flags": {
    "eligibility_active": "boolean",
    "provider_enrolled": "boolean",
    "duplicate_claim": "boolean",
    "program_integrity_hold": "boolean"
  }
}
```

## API

`app/api.py` exposes:

- `GET /health`
- `POST /claims/ingest`
- `POST /claims/adjudicate`
- `GET /dashboard/state`

Run with:

```powershell
python -m uvicorn app.api:app --host 127.0.0.1 --port 8037
```

## Drop-In Interfaces

- Replace `app/stubs.py::ZKProverStub` with a real Plonky3 prover adapter that returns the same `ProofBundle`.
- Replace `VerifierStub` with a verifier client or generated verifier contract call.
- Replace `CircleBridgeStub` and `FedNowBridgeStub` with real payment bridge clients that satisfy `PaymentBridge`.
- Replace local JSON `ClaimsRegistry` with the Solidity `ClaimsRegistry` contract adapter.

