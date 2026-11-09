# Cleanup proposal

Each item needs a human decision before any change. On 2026-11-07 the project owner
approved proceeding with `RIGHTRAIL_BASE_PLAN.md` (which covers items 5-7) and approved
removing tracked binaries where appropriate, with recoverability preserved. An earlier
version of this file said items 5-7 were approved on 2026-10-22; no record of that exists.
Parked items were moved with `git mv`; the only deletions are item 2's four files.

1. `rightrail/artifacts/engine-evaluator/blind_financial_worker.exe` and `rightrail/artifacts/gate-verify/gate_verify.exe`: tracked Windows binaries. DECIDED 2026-11-07: KEEP. They are RightRail's pinned workers (`artifacts/**` is protected, CONST XI.2; their SHA-256 values are pinned in `PROVENANCE.md` and `gate_verify.sha256`), and no Lean toolchain exists here to rebuild them. The self-check now accepts exactly these two files, and only while each matches its pinned SHA-256.
2. `zk/claim_0000.zkey`, `zk/claim_final.zkey`, `zk/powersOfTau28_hez_final_10.ptau`, `zk/witness.wtns`: Groth16 artifacts, parked under `parked/localbce/zk/` (item 5). DONE 2026-11-07: removed from the tree (owner approval above). Nothing active reads them. Recover any of them with `git show <commit>:<path> > <path>`, using the last commit that tracked them (named in `docs/integration/LOG.md`, 2026-11-07); blob IDs: `claim_0000.zkey` 933f425f3c48e9e84ca209d0760bf8209ca6b528 (10,372 B), `claim_final.zkey` 44a459c977e08cc557c05855b049a3e58468a610 (10,764 B), `powersOfTau28_hez_final_10.ptau` f76c6a9f6889585550fc95e755b9d3119295e333 (1,262,744 B), `witness.wtns` 88add3cadd2ba40a6be53ca7533bd42d9ab9a56a (716 B).
3. `bridge/rightrail_offchain.py` and its tests: retire in Phase 4, keep as migration fixtures. NOT approved yet.
4. `rust-engine/config.json` Anvil key: DONE (N-07). The key and all chain fields were removed from active config and code; the key remains only in parked chain tooling.
5. APPROVED (2026-11-07, with the plan), DONE: park proof and chain roots (`zk/`, `zk-prover/`, `stark-engine/`, `blind-ledger/`, `deprecated/`, app-layer `contracts/`, `l2/`, `zk*/`), the `STARK_*.md` notes, STARK/Sepolia/Anvil/OpenZeppelin scripts, ops examples and their tests under `parked/localbce/`.
6. APPROVED (2026-11-07, with the plan), DONE: remove the STARK runtime, sidecar, bridge-input and chain-settlement code from `rust-engine/src/main.rs`; park `rust-engine/src/stark_activation.rs`. The removed code is recoverable at `e746f58`.
7. APPROVED (2026-11-07, with the plan), DONE: park the handoff-evidence tools that pin evidence inside the STARK runtime (`build_rightrail_handoff_crosswalk.py`, `build_rightrail_safety_review_packet.py`, `validate_rightrail_handoff.py`, `validate_rightrail_hardening.sh`) with their tests.
