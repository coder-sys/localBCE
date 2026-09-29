# Provenance: blind_financial_worker.exe

`blind_financial_worker.exe` is the long-lived evaluator worker (frames: u32 big-endian length,
then one BLFIN02 input in / one outcome out; `lean/BlindLedger/Financial/Worker*.lean`). It is the
Lean/Lake executable built from this repository's `lean/` tree at commit
`1786e5c29140a21bbb8fd99d48a35ccd49fa1c62` (`git archive` of `lean/`, tree id
`e4a0ed382236dc94ba6ba190e0a3f0be58e12902`).

- Size: 5,707,776 bytes
- SHA-256: `BE5EB80EB4BD43A97846A4FB6CAA54FAF4E1DB6629B43B9705D0657C7E8AE891`
- Toolchain: `leanprover/lean4:v4.33.1` (Lake, no package dependencies).

Built in a fresh stage with `lake build blind_financial_worker blind_financial_correction
blind_financial_axioms` through the shared guarded runner (guard v7, exit 0, cleanup PASS):
`C:/Users/neers/rrb/logs/m1-stage2-a4.guard.log`. The same build reproduced
`blind_financial_correction.exe` byte for byte (`1A7A1833...D3AF`, 6,279,168 bytes), so the
correction pin is unchanged. The worker decodes with `Fast.decodeFinancialInput` (`FastDecode.lean`), proved equal to the reference decoder for every input. Axioms of that theorem and the four worker laws (`WorkerLaws.lean`): `propext`,
`Classical.choice`, `Quot.sound` only (`C:/Users/neers/rrb/logs/m1-fast-b5-a2.guard.log`).

The engine module pins this size and SHA-256. Protected change record: `docs/CORE_REDESIGN.md`.
Synthetic evidence only: `proofSuiteId=null`, `production_usable=false`, `activation=false`.
