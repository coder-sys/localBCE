# Provenance: blind_financial_worker.exe

Lake build of `lean/` at commit `a5cd1e43cef71105010bde6ac3afceeacdfff8e2` (tree
`1f0b6ba1db039da0032030cb5e9397d2ea76ade9`), toolchain `leanprover/lean4:v4.33.1`.

- 5,709,312 bytes; SHA-256 `D4B675EE325FEABCAC98B9E0ACAFC66DDC9F5C71F7D71B1FB30834FA2B7185B4`;
  the engine module pins both.
- Guarded stage build in a `git archive` of that commit: worker `m1-stage4`, correction exe
  `m1-stage4b` (`C:/Users/neers/rrb/logs/`). It reproduced `blind_financial_correction.exe`
  byte for byte, so that pin is unchanged.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only. Record: `docs/CORE_REDESIGN.md`.
