# Provenance: blind_financial_worker.exe

`blind_financial_worker.exe` is the long-lived evaluator worker (frames: u32 big-endian length,
then one BLFIN02 input in / one outcome out; `lean/BlindLedger/Financial/Worker*.lean`). It is the
Lean/Lake executable built from this repository's `lean/` tree at commit
`c524ec0d3ea832b3e36b13a05b9e5e79bea74b24` (`git archive` of `lean/`, tree id
`8aaf480194b3f697a566434b7caddb674bff6569`).

- Size: 5,707,264 bytes
- SHA-256: `956CB88F2CCEC6ABD9DCFC13D4CE1B64E6E17B0338971C5702EB2CFE2A143816`
- Toolchain: `leanprover/lean4:v4.33.1` (Lake, no package dependencies).

Built in a fresh stage with `lake build blind_financial_worker blind_financial_correction
blind_financial_axioms` through the shared guarded runner (guard v7, exit 0, cleanup PASS):
`C:/Users/neers/rrb/logs/m1-stage1-a3.guard.log`. The same build reproduced
`blind_financial_correction.exe` byte for byte (`1A7A1833...D3AF`, 6,279,168 bytes), so the
correction pin is unchanged. Axioms of the four worker laws (`WorkerLaws.lean`): `propext`,
`Classical.choice`, `Quot.sound` only (`C:/Users/neers/rrb/logs/m1-lean-all1-a1.guard.log`).

The engine module pins this size and SHA-256. Protected change record: `docs/CORE_REDESIGN.md`.
Synthetic evidence only: `proofSuiteId=null`, `production_usable=false`, `activation=false`.
