# Architecture Alignment

Reference used: the supplied `ARCHITECTURE_TECHNICAL.md` document.

## Maturity Tags

- `[BUILT+TESTED]`: active code exists and has focused local validation.
- `[BUILT-CONTROLLED]`: active code exists behind an explicit trust or config
  boundary and is not production approved.
- `[SCAFFOLDED]`: a planning or compatibility surface exists but is not active.
- `[REFERENCE]`: imported material exists only for audit and selective porting.
- `[DEFERRED]`: named future work is intentionally absent.

## Active Proof Paths

Default compatibility path:

```text
rust-engine adjudication
-> Circom/Groth16
-> Verifier.sol
-> ClaimsRegistry.sol
```

Status: `[BUILT+TESTED]`.

Opt-in STARK path:

```text
rust-engine adjudication
-> StarkBridgeInput
-> persistent indexed nullifier state
-> Winterfell G1-G10 proof
-> local proof verification
-> controlled secp256k1 attestation
-> StarkAttestationVerifier
-> StarkClaimsRegistry
```

Status: `[BUILT-CONTROLLED]`.

The STARK path is a complete technical runtime for the selected controlled-
attestation profile. It does not claim native on-chain Winterfell verification
or production approval. See `STARK_RUNTIME.md`.

## Reference-To-Repo Map

| Architecture area | Active location | Status | Boundary |
| --- | --- | --- | --- |
| Claim adjudication | `rust-engine/` | `[BUILT+TESTED]` | G1-G10 `denial_reason()` remains runtime policy. |
| Groth16 compatibility | `rust-engine/`, `zk/`, `blind-ledger/` | `[BUILT+TESTED]` | Default backend; preserved unchanged. |
| Winterfell AIR/prover | `stark-engine/` | `[BUILT+TESTED]` | Real proofs are generated, serialized, and locally reverified. |
| Claim/oracle/fee roots | `stark-engine/` | `[BUILT+TESTED]` | AIR-bound; external source truth and governance remain operational trust. |
| Nullifier state | `stark-engine/` | `[BUILT+TESTED]` | Persistent indexed tree with lock, CAS generation, atomic writes, and replay rejection. |
| Batch/public-input roots | `stark-engine/` | `[BUILT+TESTED]` | AIR-bound and included in the 38-element verifier handoff. |
| STARK settlement | `blind-ledger/` | `[BUILT-CONTROLLED]` | Authorized attestation over inputs and proof commitment; not native STARK verification. |
| Runtime selection | `rust-engine/config.json` | `[BUILT+TESTED]` | `groth16` default; `stark_attested` explicit opt-in. |
| Ops/governance | `ops/` | `[SCAFFOLDED]` | Planning scaffolds and validator; not production approval. |
| Rules discovery | `gov-rules-kg-prototype/` | `[SCAFFOLDED]` | Promotion-ready candidates are not active policy. |
| 837 ingestion/app orchestration | `blind-ledger-app-layer/` | `[REFERENCE]` | Imported cofounder lane, not silently wired. |
| Hardened bundle | `localBCE-codex-dev-hardened-20260616/` | `[REFERENCE]` | Selective reviewed ports only. |
| Native Solidity STARK verifier | none | `[DEFERRED]` | Optional trust-model upgrade. |
| Cairo path | imported reference folders | `[REFERENCE]` | Winterfell is the selected active STARK implementation. |

## Validation

```bash
bash scripts/validate_stark_bridge_chain.sh
bash scripts/validate_stark_runtime_settlement.sh
RUN_STARK_RUNTIME_SETTLEMENT=1 bash scripts/validate_localbce.sh
```

The live STARK validator deploys disposable contracts and checks approved and
denied settlement, local/on-chain root agreement, replay rejection, and that
Groth16 is not executed by the STARK backend.

## Remaining Architecture Work

- deterministic reviewed rules bridge and versioned runtime rulesets
- independent audits of AIR, proof packaging, state, executor, and contracts
- production key custody, quorum/rotation, source governance, and monitoring
- batch ingestion and payment orchestration after proof and policy controls
- optional native or recursively wrapped on-chain STARK verification

## Alignment Rule

Imported folders remain reference material until a specific reviewed change is
ported into active code and validated. A technically active component is not
automatically production approved; audit and governance gates remain explicit.
