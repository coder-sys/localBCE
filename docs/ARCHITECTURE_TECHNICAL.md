# Technical architecture

Updated: 2026-08-05

Execution checkpoint: read the newest dated section of `../STATE.md`; the original transfer record
is `../WAVE2_HANDOFF_2026-07-26.md`. The RTX 4060 path is an untrusted arithmetic accelerator inside
the existing heterogeneous topology, not a new trust boundary. Rust remains authoritative for
SHA3-512, transcript, commitments, multiproofs, public-coin replay, canonical parsing, and final
verification. The manifest-bound H4 prototype now completes the real 168-layer native-masked GKR,
Construction 8.2 PCS, and one/four-shard coordinator through independent verification in
29.974129 seconds for K128 and 120.460733 seconds for K512. Gate 2E is now sealed nonactivating;
H5 passed the exact 22-launch campaign; and H6 closed the twelve bounded candidate-evidence records.
Every activation gate remains closed, `proofSuiteId=null`, and production verifier/state/custody
work is still open. Wave 4 adapter and operations engineering is complete only at the local,
synthetic, nonactivating boundary.

The compulsory target protocol is defined in `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`: an
Ethereum-settled based validity rollup with private Blind Ledger claim proofs verified inside the
L2 and a rollup validity proof verified on Ethereum L1. The complete fork/EIP compatibility
surface is `docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`.

The completion boundary is `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`: 93 internally finishable
packages cover the proof/state core, provider-neutral external-system adapters, rollup, operations,
and release. One final independent audit follows; live credentials and authorizations are
operator-supplied activation inputs.

The current claim-proof topology is the heterogeneous construction in
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`: a sealed M31 semantic AIR, one committed
fixed-shape hash-call bus, and an Fp16 Boolean GKR SHA3 coprocessor verified atomically. The old
554-951 GB direct-SHA3-STARK layouts are negative baselines only.

The frontier addendum `docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` adds CBAM, deterministic
conflict scheduling, versioned state-topology selection, proof-carrying external evidence, and
maturity-gated Ethereum adapters inside the same 93-package plan.

For implementation, every L1 change is classified as inherited consensus behavior, mandatory
L1-interface compatibility, conditional L2 EVM/prover parity, optional adoption, or research-only.
The exact per-EIP class, activation trigger, owner and tests are in
`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`. An inherited benefit is not zero work:
the observer, timing, finality, DA, resource and recovery assumptions still require fork-specific
conformance. An optional feature is never accepted merely because a client exposes it.

`docs/BL_PQ512_COMMITTED_SPARSE_STATE_PLAN.md` makes the state selection a mandatory Wave 2 gate:
the existing SHA3-512 state proof is the control, and persistent sparse-memory, transparent-
dictionary, touched-projection-RAM, shuffle-based memory, and native-hiding PQ commitment candidates
remain replaceable production-state options. The nonactivating Gate 2E/H5/H6 evidence does not
select a production state layout; the H4 prototype and candidate ledger remain proof-engine evidence.

## Runtime boundaries

Blind Ledger separates operational concerns into six trust boundaries:

| Boundary | Main paths | Notes |
| --- | --- | --- |
| Claim processing | `app/`, `app/connectors/`, portal folders | Parses input and prepares canonical claim facts. |
| Policy adjudication | `rules-engine-rust/`, `app/rules_engine_adapter.py`, `app/rules_engine_fallback.py` | Rust engine is the intended engine path. Python fallback is local/test-only and must fail closed in production. |
| Batch/proof binding | `app/batch/`, `experiments/fixed_shape_claim_air/`, `experiments/bl_pq512_crypto_core/`, `zk-cairo-sharp/` | Produces trust-critical commitments, nullifiers, roots, and public inputs; the sealed semantic AIR and shared-bus hash coprocessor are the target, while Cairo remains a differential reference. |
| Settlement/verifier | `contracts/`, `ops/verifier_artifact_pin.example.json` | Solidity-facing verifier and pinned artifact metadata. |
| Government/oracle adapter platform | `app/wave4_adapters.py`, `app/wave4_operations.py`, `tools/wave4_conformance.py` | Wave 4's versioned provider-neutral ports, canonical proof-carrying evidence capsules, local simulators, sandbox fixtures, and conformance tests isolate vendor APIs from proof semantics; production credentials, HSM/FIPS custody, and activation remain open. |
| Containing rollup/deployment | future R01-R12 modules | L2 execution/proof, based ordering, proof/data coupling, data availability, L1 settlement, opaque forced inclusion, bridge/exits, upgrades, recovery, finality, and an optional maturity-gated native-rollup adapter. |

## Proof hierarchy

The claim proof and rollup proof are separate trust boundaries. The claim proof authenticates private adjudication, nullifiers, governed roots, and value conservation. The rollup proof authenticates the full L2 state transition, including execution of the claim verifier, to Ethereum L1. Neither proof may be substituted for the other.

The claim proof is itself an atomic composition of semantic STARK, hiding bus PCS, and masked
Boolean GKR hash proof. A verifier must reject the whole object if any module, bus opening,
authenticated challenge round, or exact 12-field/sidecar binding fails.

## Current verifier gap

The source contains an interface and a Solidity mock, not a production native STARK verifier. Cairo `batch_main` returns 12 inner values, while `StarkBatchSettlement` accepts 21 separately supplied public inputs. The mock ignores both proof and public inputs. Until a real verifier authenticates one exact ordered statement, the settlement path is not Ethereum-secured and must remain blocked.

## Privacy boundary

Public L1/L2 data contains only public state, roots, commitments, and proofs. PHI, claim documents, exact private amounts, decisions, counts, and permanently decryptable medical-record ciphertext remain outside public data availability. Government storage is bound to public state by commitments and controlled through production KMS/HSM policy.

## Path layout

This checkout is already the source root. The release builder adds only a
`Blind-Ledger-Release/` wrapper inside the ZIP; it does not create a nested app-layer root.
`ops/` is the sole canonical operational tree. Sibling copies, compatibility mirrors, symlinks,
junctions, environment overrides, and fallback paths are forbidden and are rejected by the
authority verifier.

The checkout does not include the external `forge-std` dependency expected by the Foundry
configuration. Solidity tests require an explicitly provisioned, reviewed dependency and must not
be treated as release evidence without its source identity.

## Proof and build outputs

Generated `target/` trees, proof directories, proof JSON, and external GPU build output are excluded from this source handoff. Historical local paths in older notes should not be treated as packaged artifacts.

## Dependency policy

Use already-installed toolchains when available. For Python, install package dependencies only into a local virtual environment unless explicitly instructed otherwise. Runtime imports include `fastapi`, `uvicorn`, `cryptography`, and `pqcrypto`; development tests also need `pytest` and `httpx`.

## Safety rules

- Never alter hash, commitment, nullifier, root, public-input, or proof semantics without explicit approval.
- Never weaken readiness or attack tests.
- Never edit protected paths as part of cleanup or documentation handoff work.
- Report missing artifacts or toolchain failures exactly instead of changing code paths around them.
