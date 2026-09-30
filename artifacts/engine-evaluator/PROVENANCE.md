# Provenance: blind_financial_worker.exe

Lake build of `lean/` at commit `405812e6bb3e4c8c0055871abeb55ec021fe1e77` (tree
`9ee89ea35cea511c520f755b26da9541ebc98a53`), toolchain `leanprover/lean4:v4.33.1`.

- 5,709,824 bytes; SHA-256 `67C5A3980A59B7DFD621C3D183CC2D4E7DCB7AA1CA87C63705A10AE3327BBEE7`;
  the engine module pins both.
- Two guarded fresh stage builds, each in a `git archive` of that commit: `leak-stage2a` (worker,
  correction exe, axioms) and `leak-stage2b` (worker) (`C:/Users/neers/rrb/logs/`). Both workers
  are byte-identical; `blind_financial_correction.exe` was reproduced byte for byte, so that pin is unchanged.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only. Record: `docs/CORE_REDESIGN.md`
  (Lean-live M1 and M1.5).
