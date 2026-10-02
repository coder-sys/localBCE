# Provenance: blind_financial_worker.exe

Lake build of `lean/` at commit `c3239c0` (worker perf; lean tree `26203703021c55fa42fb3b7409dda6a519fa914d`), toolchain `leanprover/lean4:v4.33.1`.

- 6,439,936 bytes; SHA-256 `58CDA012A47B82EB23BC600E9A5CC1AFA808E491A1CE33D73379E86B15DBCFD2`; the engine module pins both.
- Two guarded fresh stage builds, each in a `git archive` of that commit: `wp-c4stagea` and `wp-c4stageb` (guard logs `wp-c4stagea-a3-L1`,
  `wp-c4stageb-a1-L1`), each `lake build blind_financial_worker gate_verify gate_axioms blind_financial_axioms`, exit 0. Both workers are byte-identical; gate_verify (`316689F5...`) is byte-identical to its pin in both.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only. Record: the XI.2 section of the re-pin commit message.
- Why it moved: payment frames (BLFPAY01) are read from the byte array (`Payment/Cursor.lean`, `paymentRespondBA_eq`), not through a
  `List UInt8` of the whole frame: held memory per 8.1 MB item was +75 MB, now flat. No decision changes: old and new workers answered
  51,539 frames identically (`wp-c3old`, `wp-c3new`).

Retired pins, not deleted: `5CA5A67CD5D80F4A2D0EAED7F3EDB75D21F2470F0C07C8558FC21079EBFFA097`, 6,460,416 bytes
(lean commit `0cd7a28`, tree `29784be72a0fb7e4a843f7d3d683edb305406389`; stage logs `m4l1-stagea`, `m4l1-stageb`; before the byte-array payment path); `36D3FE0C8CF7397808C39A808D46BF8B5206583BA01B534AE96EC8C01E1B1AEA`, 6,020,608 bytes
(lean commit `1168909`, tree `3cf4adb420ce25197fdfb7a419055e62408af34e`; stage logs `m3s2-stagea`, `m3s2-stageb`; before correction frames); `86299A0D8925C52692F936C18C9E4A2CED7118FA32FA6B864C4A745421A1712B`, 5,724,160 bytes
(lean commit `351cfa091428b2488e84f54df55afae6be69d46d`, tree `1ec582f80781bf0cb551cd5b2694022704f0024e`; stage logs `prtb2-stagea`, `prtb2-stageb`; before payment frames); `EE651742B79AA6F230E612B2088EF38C856031DFF16FC1477B022711ED067C21`, 5,727,744 bytes
(lean commit `fa53ef176439bf07bfbe9745a9fbc3ea4fdd1146`, tree `9d21e3bba45f624a885ad4c5a5ce57694fd36b24`;
stage logs `lpsm-stagea`, `lpsm-stageb`; before the `natBEPush` fix); `E95C6D52584DB987B771900EEEA2DA249F9E54097B2EE91AF1518072F28E3D97`, 5,727,744 bytes
(lean commit `b6bc6473eaaf960d339f244b5a0d5b5efd15a620`, tree `da3d331a4496af470c7871826b50bad3cf87bb86`;
stage logs `leakint-stagea`, `leakint-stageb`); `0AE566EDC056990590ECB0BEA7ED6B275B2DDC6AF025FAA6BEA7EE9FED1F9077`, 5,728,256 bytes
(lean commit `3d2c2ab744608b21689bf6d07446ec672fa4464f`, tree `181b0969861f457690a9e33a35a7bc7bfc2563a8`;
stage logs `lock-stagea`, `lock-stageb`).
