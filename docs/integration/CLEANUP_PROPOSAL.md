# Cleanup proposal (NOT approved; no deletions performed)

Each item needs a human decision before any change.

1. `rightrail/artifacts/engine-evaluator/blind_financial_worker.exe` and `rightrail/artifacts/gate-verify/gate_verify.exe`: tracked Windows binaries. Proposal: remove and rebuild in CI from `rightrail/lean`. Blocks the self-check "tracked files" check.
2. `zk/claim_0000.zkey`, `zk/claim_final.zkey`, `zk/powersOfTau28_hez_final_10.ptau`, `zk/witness.wtns`: Groth16 artifacts. Proposal: move to `deprecated/` in Phase 1 (D-01) rather than delete, then decide.
3. `bridge/rightrail_offchain.py` and its tests: retire in Phase 4, keep as migration fixtures.
4. `rust-engine/config.json` Anvil key: remove under N-07 in Phase 1.
