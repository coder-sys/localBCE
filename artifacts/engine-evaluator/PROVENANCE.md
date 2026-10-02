# Provenance: blind_financial_worker.exe

Lake build of `lean/` at commit `0cd7a28` (M4 L1; lean tree `29784be72a0fb7e4a843f7d3d683edb305406389`), toolchain `leanprover/lean4:v4.33.1`.

- 6,460,416 bytes; SHA-256 `5CA5A67CD5D80F4A2D0EAED7F3EDB75D21F2470F0C07C8558FC21079EBFFA097`; the engine module pins both.
- Two guarded fresh stage builds, each in a `git archive` of that commit: `m4l1-stagea` and `m4l1-stageb` (guard logs `m4l1-stagea-a1-L3`,
  `m4l1-stageb-a1-L2`), each `lake build blind_financial_worker blind_financial_correction gate_verify gate_axioms blind_financial_axioms`, 115 jobs, exit 0. Both workers are byte-identical; the correction exe (`874E2A37...`) and gate_verify (`316689F5...`) did not move.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only. Record: the XI.2 section of the `0cd7a28` commit message.
- Why it moved: the worker also answers a BLFCMD03 request as the retired exe did (`00` then the BLFCRES3 body, `01` undecodable, `03` over the size bound);
  every BLFIN02 frame still gets the evaluator. Python sends BLFCMD03 frames since M4 P1, which retired the correction exe
  and its CLI target. The old law "bare BLFCMD03 differs from the evaluator" was never true (both answer `01`); the true witness
  is the KAT request (`#guard` in `WorkerLaws.lean`: worker `00`+BLFCRES3, evaluator `01`).

Retired pins, not deleted: `36D3FE0C8CF7397808C39A808D46BF8B5206583BA01B534AE96EC8C01E1B1AEA`, 6,020,608 bytes
(lean commit `1168909`, tree `3cf4adb420ce25197fdfb7a419055e62408af34e`; stage logs `m3s2-stagea`, `m3s2-stageb`; before correction frames); `86299A0D8925C52692F936C18C9E4A2CED7118FA32FA6B864C4A745421A1712B`, 5,724,160 bytes
(lean commit `351cfa091428b2488e84f54df55afae6be69d46d`, tree `1ec582f80781bf0cb551cd5b2694022704f0024e`; stage logs `prtb2-stagea`, `prtb2-stageb`; before payment frames); `EE651742B79AA6F230E612B2088EF38C856031DFF16FC1477B022711ED067C21`, 5,727,744 bytes
(lean commit `fa53ef176439bf07bfbe9745a9fbc3ea4fdd1146`, tree `9d21e3bba45f624a885ad4c5a5ce57694fd36b24`;
stage logs `lpsm-stagea`, `lpsm-stageb`; before the `natBEPush` fix); `E95C6D52584DB987B771900EEEA2DA249F9E54097B2EE91AF1518072F28E3D97`, 5,727,744 bytes
(lean commit `b6bc6473eaaf960d339f244b5a0d5b5efd15a620`, tree `da3d331a4496af470c7871826b50bad3cf87bb86`;
stage logs `leakint-stagea`, `leakint-stageb`); `0AE566EDC056990590ECB0BEA7ED6B275B2DDC6AF025FAA6BEA7EE9FED1F9077`, 5,728,256 bytes
(lean commit `3d2c2ab744608b21689bf6d07446ec672fa4464f`, tree `181b0969861f457690a9e33a35a7bc7bfc2563a8`;
stage logs `lock-stagea`, `lock-stageb`).
