# STARK Transition Status

## Technical Migration

The Groth16-to-STARK technical migration is complete for the selected
controlled-attestation settlement profile.

Completed phases:

1. typed Rust-to-STARK bridge input
2. proof intent, witness plan, mock trace, and compatibility validation
3. source-root and batch-root planning
4. production claim, oracle, fee, nullifier, and batch root semantics
5. Winterfell witness and adapter boundary
6. production G1-G10 Winterfell AIR and real local proof verification
7. versioned proof artifact, verifier handoff, and Solidity ABI alignment
8. persistent concurrency-safe nullifier state and atomic settlement executor
9. controlled-attestation Solidity verifier and STARK ClaimsRegistry
10. opt-in `rust-engine` runtime routing with Groth16 preserved as default

The selected profile verifies a secp256k1 attestation on-chain over the exact
public inputs and a commitment to the locally verified Winterfell proof. It
does not claim native on-chain Winterfell verification.

## What Remains

The remaining work is production hardening and trust-model evolution:

- independent cryptographic, Rust, and Solidity audits
- production attestor key custody, rotation, quorum, and emergency revocation
- governed claim-source, oracle, and fee-schedule root approval
- monitoring, reconciliation, reorg, retry, and disaster-recovery procedures
- adversarial load, concurrency, gas, and failure-injection testing
- deployment artifact pinning and release change control
- optional native or recursively wrapped on-chain STARK verification

These gates determine whether the system is production approved; they are not
missing links in the implemented controlled-attestation runtime.

## Validation Gates

```bash
bash scripts/validate_stark_bridge_chain.sh
bash scripts/validate_stark_runtime_settlement.sh
RUN_STARK_RUNTIME_SETTLEMENT=1 bash scripts/validate_localbce.sh
```

The STARK runtime validator must continue to prove that:

- approved and denied claims both produce real locally verified proofs
- approved settlement advances nullifier state
- denied settlement preserves nullifier state
- chain and local state roots agree
- replay is rejected
- Groth16 is not invoked by the STARK backend
- Groth16 remains green as the default backend

## Next Workstream

The next engineering workstream is the deterministic rules engine bridge. No
Claude web candidate becomes executable merely because it is promotion-ready.
Runtime activation requires a deterministic mapping, provenance validation,
G1-G10 parity tests, a versioned ruleset, and explicit configuration.
