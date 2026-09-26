# Provenance: blind_financial_correction.exe

`blind_financial_correction.exe` is the Lean/Lake executable built from this
repository's `lean/` source at commit `fbb06aa` (tree `lean/` =
`git archive fbb06aa lean`).

- Size: 6,237,184 bytes
- SHA-256: `88D853961AB127EE33C65A57F6E35D03244FB5CCE2067F4A0FDF592ECC730992`
- Toolchain: `leanprover/lean4:v4.33.1` (Lake, no package dependencies).

## Reproduced twice

Two clean builds, each in a fresh export under its own `<BUILD_ROOT>`, each
run through `native/guard/run_guarded_v4.ps1` (SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`):

    lake --dir <BUILD_ROOT>/lean build BlindLedger blind_semantic_kernel blind_financial_axioms blind_financial_correction blind_financial

Both produced `<BUILD_ROOT>/lean/.lake/build/bin/blind_financial_correction.exe`
with the SHA-256 above. `blind_financial --correction-transition-kat` passed
37 of 37 gates on the first build's executable.

## Vectors

- `vectors/request.bin` (BLFCMD01) SHA-256 `13F832E80B93CC55D17ADD29470A2CD789CFCED1CBCF5A055FCBA3ECB927B537`
- `vectors/result.expected.bin` (BLFCRES2) SHA-256 `6858FC3684D1243EB12F2FC038AD8D2107239E92C520C388B7D5719741FE13D2`, produced by
  the first build's executable from `request.bin` with
  `vectors/run-vectors.cmd <exe> <request> <output>` under the guard.
- `vectors/result.actual.bin`, produced the same way by the second build's
  executable, is byte-identical to `result.expected.bin`.

The request is the BLFCMD01 request of the previous pin (commit `f1de262`,
`artifacts/engine-correction-e911/`), whose format is unchanged.

## Status

Synthetic evidence only. Non-activating and non-payment:
`proofSuiteId=null`, `production_usable=false`, `activation=false`.
