# Provenance: blind_financial_worker.exe

Lake build of `lean/` at commit `351cfa091428b2488e84f54df55afae6be69d46d` (lean tree
`1ec582f80781bf0cb551cd5b2694022704f0024e`), toolchain `leanprover/lean4:v4.33.1`.

- 5,724,160 bytes; SHA-256 `86299A0D8925C52692F936C18C9E4A2CED7118FA32FA6B864C4A745421A1712B`;
  the engine module pins both.
- Two guarded fresh stage builds, each in a `git archive` of that commit: `prtb2-stagea`
  (guard log `prtb2-stagea-a1-L3`) and `prtb2-stageb` (`prtb2-stageb-a1-L3`), each
  `lake build blind_financial_worker blind_financial_correction gate_verify gate_axioms blind_financial_axioms`, 77 jobs, exit 0
  (`C:/Users/neers/rrb/logs/`). Both workers are byte-identical. In both stages the correction exe stayed
  `D5A06E9FFDB13C6266C40658B06AF4D93204F35159B9BE7FD4387A0613A10CBB` (6,298,624 bytes; it does not import FastEncode) and
  gate_verify stayed `B9696F2E...D171C` (4,205,056 bytes).
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only. Record: `docs/CORE_REDESIGN.md` (lean-partials-v1).
- Why it moved: commit ea42222 (cherry-picked from branch `quad` as 351cfa0) changes one line of `FastEncode.lean`: `natBEPush` now
  consumes its accumulator, which removes a quadratic copy in the canonical re-encode. No behaviour, format or digest changes; only the
  worker executable is affected. The `partials` commit B (gate) did not change any file the worker imports.

Retired pins, not deleted: `EE651742B79AA6F230E612B2088EF38C856031DFF16FC1477B022711ED067C21`, 5,727,744 bytes
(lean commit `fa53ef176439bf07bfbe9745a9fbc3ea4fdd1146`, tree `9d21e3bba45f624a885ad4c5a5ce57694fd36b24`;
stage logs `lpsm-stagea`, `lpsm-stageb`; before the `natBEPush` fix); `E95C6D52584DB987B771900EEEA2DA249F9E54097B2EE91AF1518072F28E3D97`, 5,727,744 bytes
(lean commit `b6bc6473eaaf960d339f244b5a0d5b5efd15a620`, tree `da3d331a4496af470c7871826b50bad3cf87bb86`;
stage logs `leakint-stagea`, `leakint-stageb`); `0AE566EDC056990590ECB0BEA7ED6B275B2DDC6AF025FAA6BEA7EE9FED1F9077`, 5,728,256 bytes
(lean commit `3d2c2ab744608b21689bf6d07446ec672fa4464f`, tree `181b0969861f457690a9e33a35a7bc7bfc2563a8`;
stage logs `lock-stagea`, `lock-stageb`).
