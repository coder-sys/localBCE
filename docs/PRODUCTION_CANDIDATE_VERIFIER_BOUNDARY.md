# Production-candidate verifier boundary

Updated: 2026-08-08

The Rust candidate verifier is exposed through a narrow `NativeVerifierPort`. It receives a canonical proof envelope and returns an exact receipt bound to the proof, statement, suite, schema, program, and verifier artifact. The application must never accept a caller-supplied boolean or mock receipt.

`app/production_boundary.py` then recomputes the Privacy V2 statement and applies the state transition only after native receipt validation. Verification and state mutation are one fail-closed atomic database boundary. A stale root, reused nullifier, mismatched identity, conflicting retry, or failed commit changes no state.

This is local, synthetic, nonactivating evidence. It does not select `proofSuiteId`, qualify a production database or HSM, pass an independent audit, authorize PHI/payments, or establish Ethereum settlement.

Focused checks:

```powershell
py -3.14 -B -m pytest -q -p no:cacheprovider tests/test_bl_pq512_public_input_projection.py tests/test_bl_pq512_production_boundary.py tests/test_bl_pq512_production_candidate.py -k 'not real_rust'
```
