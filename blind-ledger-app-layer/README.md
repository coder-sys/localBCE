# Blind Ledger App Layer

Fresh standalone application and contract layer for a Medicaid claims adjudication stack.

This codebase is intentionally separate from any existing Blind Ledger, localBCE, gov-rules, or rule-corpus repositories. It does not import from or modify those repos.

## What Runs Here

- Python ingestion API and local orchestrator.
- 837 claim parser into a shared context schema.
- Rules-engine adapter with a Python fallback for this environment.
- Rust rules-engine crate source and unit tests, ready for `cargo test` where Rust is installed.
- 835 remittance/denial generator.
- Appeal router.
- Static dashboard generated from local pipeline state.
- Solidity contracts and Foundry tests, ready for `forge test` where Foundry is installed.
- ZK lanes:
  - frozen Groth16 adjudication circuit source,
  - Winterfell STARK proof-of-concept source/report,
  - Cairo/STARK research lane,
  - production-binding Circom v2 circuit that compiles locally and rejects
    unpinned claim facts,
    fabricated oracle facts, fake fee ceilings, recipient redirects,
    prior-auth bypass, raw-hash double-pay attempts, member collision attempts,
    procedure substitution, duplicate replay, over-wide amounts, and tampered
    public outputs.

## Demo

```powershell
python -m app.orchestrator --input sample_claim_input.json --out demo_output
python -m unittest discover -s tests
```

Open `dashboard/index.html` after the demo to view the local dashboard state.

## Trust Label

Locally tested and soundness-checked where executable, PENDING CRYPTOGRAPHIC AUDIT.
The production-binding v2 circuit now compiles and has a local Groth16 smoke proof,
but it is not a production-audited or end-to-end post-quantum verifier path yet.
