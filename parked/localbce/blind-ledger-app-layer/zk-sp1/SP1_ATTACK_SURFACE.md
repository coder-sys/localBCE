# SP1 Attack Surface

Status: attack-surface inventory for the parallel SP1/Plonky3 path. This path is not live-wired into the app layer. Ceiling: soundness-checked where locally executable, PENDING CRYPTO AUDIT.

Patch status appended 2026-06-14: the local-now holes from the prior attack run were patched in the SP1 guest/glue. Public values now include a raw claim-identity commitment plus a batch-context commitment, public output decoding rejects out-of-range decision/failure values, and `expected_gates` delegates to the canonical Rust rules engine instead of using attacker-controlled max-charge input.

## What Was Tested Locally

1. Guest execute-mode public outputs
   - Ran the SP1 guest executable in execute mode twice.
   - Cases: approved, ineligible_denied, duplicate_denied, excessive_charge_denied.
   - Public outputs were stable: decision bit plus first-failed-gate code.
   - Cycle counts were stable across both runs.

2. Native Rust engine vs SP1 guest logic
   - The SP1 guest calls the existing `blind_ledger_rules_engine::adjudicate` library.
   - Boundary tests covered all-zero/all-fail input, zero charge, charge at native limit, excessive charge, duplicate, and approved.
   - Result: guest public values matched the native Rust engine for those normalized inputs.

3. Guest input compression
   - The SP1 guest input is a compact `ClaimInput`, not the raw 837/shared-context object.
   - It now binds a 32-byte raw claim-identity commitment and a 32-byte batch-context commitment into public values.
   - This blocks proof-output reuse across claim identities or ruleset/payment/batch contexts when consumers check both commitments.
   - Remaining audit question: the preprocessing layer must define exactly how raw 837/shared-context bytes and batch/ruleset/payment context bytes are canonicalized into those commitments.

4. Public value decoding
   - The local decoder rejects decision values outside `{0,1}` and rejects inconsistent failure codes.
   - Tested: decision `2`, approved-with-failure-code, and failure code `11` are rejected.

5. Stale helper risk
   - `expected_gates` now reads gate status from the canonical Rust engine path.
   - Tested: attacker-controlled `max_charge_cents` no longer makes the helper pass G8 when the native engine denies.

## What Was Not Testable Locally

1. SP1 core proof soundness
   - Local proof generation is RAM-walled on this machine.
   - Prior local proof attempt reached setup and exited before producing a proof.
   - Needs SP1 prover-network credentials or a larger Linux prover machine.

2. Tampered-proof rejection
   - Requires a real generated proof artifact.
   - Not tested locally because no proof was produced.

3. Wrapped EVM verifier
   - Requires real Groth16/PLONK wrapped SP1 proof generation.
   - No real wrapped proof was produced, so no real Forge gas number exists.

4. End-to-end PQ claim
   - SP1 proving is Plonky3/STARK and PQ-aligned off-chain.
   - SP1's normal EVM verifier path is Groth16/PLONK-wrapped, pairing-based, and not post-quantum at the on-chain anchor.
   - Native STARK/FRI on-chain verification remains future audit-track work.

## Findings To Carry Into Audit

1. Raw-claim binding
   - The SP1 proof currently proves normalized gate inputs plus public raw-identity and batch-context commitments, not raw claim parsing.
   - Audit question: what exact commitment binds raw 837/shared context to `ClaimInput`, what exact commitment binds ruleset/payment/batch context, and do they include all fields needed for claim identity, settlement, and appeal replay resistance?

2. Proof-path provenance
   - The app registry now stores proof system, verifier key, proof hash, and public inputs.
   - Audit question: how does the combined system enforce a policy decision about which proof systems are acceptable for which workflow?

3. Public-output range checks
   - Local decoder enforces decision in `{0,1}` and failure code consistency. External consumers still need to call the checked decoder or reproduce the same checks.

4. Stale helper removal
   - Local helper is now aligned to the canonical Rust rules engine. Keep it that way; do not reintroduce a parallel hand-coded gate table.

5. Proving DoS
   - Execute-mode cycle counts are stable for the tested fixed-size inputs, but real proof resource usage is not locally measured.
   - Audit question: what are the maximum accepted input sizes once raw claim binding is added?

## Additional Harder-Hunt Notes

See `zk-sp1/CIRCUIT_AUDIT_NOTES.md` for the 2026-06-14 app-layer/SP1 deeper hunt. Current highlights: claim count is now bound into app/contract batch public inputs, ruleset roots are content-addressed for the main Rust policy bundle, SP1 public values include a batch-context commitment, and keyed provider aliases are in place. Remaining findings include a missing-secret dev-key fallback, Python fallback omission from the policy manifest, quarantine metadata/audit identity ambiguity, and governance revocation footguns. Ceiling remains soundness-checked where locally executable, PENDING CRYPTOGRAPHIC AUDIT.
