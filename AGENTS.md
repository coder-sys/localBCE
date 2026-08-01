# Agent instructions for Blind Ledger

This is a zero-knowledge payment-system source handoff. Treat cryptographic, settlement, and policy-binding code as trust-critical.

## Before editing

1. Work from the repository root containing this `AGENTS.md`. The authoritative local path is
   recorded in the newest `STATE.md`; do not create, extract, or silently switch to another copy.
2. Read `docs/CURRENT_TECH_STACK.md` for the exact active implementation and evidence vocabulary.
3. Read `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md` before any proof, settlement, privacy, sequencing, data-availability, bridge, or finality work.
   For containing-rollup or Ethereum-upgrade work, immediately follow it with
   `docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`.
4. Read `docs/PQ_ZK_SECURITY_ARCHITECTURE.md`, the deterministic continuation contract near the top of `docs/IMPLEMENTATION_ROADMAP.md`, and `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md` before any claim-proof, witness-hiding, nullifier, commitment, post-quantum, verifier, adapter, rollup, deployment, or proving-performance work.
5. If working context is compacted or lost, re-read `CONTINUATION_MANDATE.md` immediately after this file, then read the newest section of `STATE.md`, `docs/CURRENT_TECH_STACK.md`, and the architecture/roadmap documents above before continuing. Read `WAVE2_HANDOFF_2026-07-26.md` only as historical recovery evidence; its old next-step language is not current authority. Do not reconstruct trust-critical decisions from chat summaries.
6. Check existing tools before installing anything. Do not reinstall Python, Rust, Scarb, Foundry, or CUDA if they are already present and working.
7. Prefer a local virtual environment for Python package installs.
8. Keep generated outputs out of the source tree and out of release ZIPs.

## Protected paths

Do not edit these unless the owner explicitly authorizes that exact protected change:
- `zk-cairo-sharp/`
- `contracts/`
- `app/batch/nullifier.py`
- `app/batch/leaf.py`
- `app/batch/stark_binding.py`
- `app/batch/merkle.py`
- `app/batch/accumulators.py`
- `app/batch/batch_orchestrator.py`
- `app/oracle_attestation.py`
- `app/public_inputs.py`
- `app/canonical_encoding.py`

Reading protected files is allowed for diagnosis. Editing them is not.

## Local compatibility layout

The architecture requires two copies of operational artifacts:
- `../ops/` is the canonical sibling directory used by policy-artifact hashing in the batch code.
- `ops/` inside this app-layer directory is a compatibility mirror for readiness checks that resolve from the app-layer root.

The current authoritative workspace is missing the canonical sibling `../ops/`; only the app-root
mirror is present. Tests that require canonical bytes must fail closed. Recover `../ops/` only from
trusted authoritative material, then prove recursive byte identity. Never construct it by copying
the assumed mirror or modify policy YAML contents to make tests pass.

## Assistant handoff files

Do not add Claude, Gemini, or generic memory files. In this archive, agent instructions live in:
- `AGENTS.md`
- `CONTINUATION_MANDATE.md`
- `QUICKSTART.md`
- `PROJECT_MAP.md`
- `PROOF_PROVENANCE.md`
- `KNOWN_ISSUES.md`
- `STATE.md`
- `docs/CURRENT_TECH_STACK.md`
- `docs/REJECTED_ARCHITECTURES.md`
- `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`
- `docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`
- `docs/PQ_ZK_SECURITY_ARCHITECTURE.md`
- `docs/IMPLEMENTATION_ROADMAP.md`
- `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`

## Claims you may make

You may say the archive contains source code, tests, docs, policy artifacts, and vendored Forge support.

Do not claim a production proof was verified unless a verifier command has been run in the current environment and its raw output shows success. Proof JSON/build artifacts are not packaged.

Do not claim Ethereum-secured settlement while the repository lacks a real `INativeStarkVerifier` implementation or while Cairo output and settlement public-input schemas differ. The current Solidity verifier in tests is a mock and is not release evidence.
