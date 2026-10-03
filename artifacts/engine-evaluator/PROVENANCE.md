# Provenance: blind_financial_worker.exe

Lake build of `lean/` at commit `662dc18` (lean tree `b64dc5cb020d172abc47be4f1c416397c36440a0`), toolchain `leanprover/lean4:v4.33.1`.

- 6,420,480 bytes; SHA-256 `8BB1C6461DA45587F2FFB9BEF22F15C856793BE1B4220C461F17D61D5DAF4309`; the engine module pins both.
- Two guarded fresh stage builds, each in a `git archive` of that tree: `m1-9a`, `m1-9b`, each `lake build` of the four pin targets, exit 0. Both workers are byte-identical; `gate_verify` is still `724de1bd...`; a warm build (`m1-10`) agrees.
- Worker laws use `propext`, `Classical.choice`, `Quot.sound` only. Record: the XI.2 section of the re-pin commit message.
- Why it moved: M1 review fix. The Lean offset rule (claim plus open requests within the shortfall, reason 23) is spec only: no worker frame serves it, so no served decision changes.

Retired pins, not deleted: `84F8DCFC618D557838D15BFF5AFCA29CDB244F80DE47A57AAE4A633F0C571CE1`, 6,421,504 bytes
(lean `6a897d8`, tree `ec7d5398648854e9f28ad3e7b434156a8d67a0b8`; before offsets count open requests); `3AEC2F5E1056E589D5D53F97189FEBA4671599A9BA5CB34D886E096EB548F41B`, 6,417,408 bytes
(lean `98df3c9`, tree `00a6f26e207dbb47e3c21468b6640dee18f67975`; before the shortfall bound); `C063E4AC3D440D9392470E4546C2D324CC93569D0778E36B86B7853FDAC1EDC9`, 6,418,432 bytes
(lean `92f34ca`; M4 L2 without the capacity fix); `8EB77363E6E89FD63F0646028D3CD2B23C99CF270AF7644CFFAE1FDE769D1080`, 6,438,400 bytes
(trunk `5e500db`; capacity fix without M4 L2); `58CDA012A47B82EB23BC600E9A5CC1AFA808E491A1CE33D73379E86B15DBCFD2`, 6,439,936 bytes
(lean commit `c3239c0`, tree `26203703021c55fa42fb3b7409dda6a519fa914d`; stage logs `wp-c4stagea`, `wp-c4stageb`; before offset authorization); `5CA5A67CD5D80F4A2D0EAED7F3EDB75D21F2470F0C07C8558FC21079EBFFA097`, 6,460,416 bytes
(lean commit `0cd7a28`, tree `29784be72a0fb7e4a843f7d3d683edb305406389`; stage logs `m4l1-stagea`, `m4l1-stageb`; before the byte-array payment path); `36D3FE0C8CF7397808C39A808D46BF8B5206583BA01B534AE96EC8C01E1B1AEA`, 6,020,608 bytes
(lean commit `1168909`, tree `3cf4adb420ce25197fdfb7a419055e62408af34e`; stage logs `m3s2-stagea`, `m3s2-stageb`; before correction frames); `86299A0D8925C52692F936C18C9E4A2CED7118FA32FA6B864C4A745421A1712B`, 5,724,160 bytes
(lean commit `351cfa091428b2488e84f54df55afae6be69d46d`, tree `1ec582f80781bf0cb551cd5b2694022704f0024e`; stage logs `prtb2-stagea`, `prtb2-stageb`; before payment frames); `EE651742B79AA6F230E612B2088EF38C856031DFF16FC1477B022711ED067C21`, 5,727,744 bytes
(lean commit `fa53ef176439bf07bfbe9745a9fbc3ea4fdd1146`, tree `9d21e3bba45f624a885ad4c5a5ce57694fd36b24`;
stage logs `lpsm-stagea`, `lpsm-stageb`; before the `natBEPush` fix); `E95C6D52584DB987B771900EEEA2DA249F9E54097B2EE91AF1518072F28E3D97`, 5,727,744 bytes
(lean commit `b6bc6473eaaf960d339f244b5a0d5b5efd15a620`, tree `da3d331a4496af470c7871826b50bad3cf87bb86`;
stage logs `leakint-stagea`, `leakint-stageb`); `0AE566EDC056990590ECB0BEA7ED6B275B2DDC6AF025FAA6BEA7EE9FED1F9077`, 5,728,256 bytes
(lean commit `3d2c2ab744608b21689bf6d07446ec672fa4464f`, tree `181b0969861f457690a9e33a35a7bc7bfc2563a8`;
stage logs `lock-stagea`, `lock-stageb`).
