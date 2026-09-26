# Provenance: blind_financial_correction.exe

`blind_financial_correction.exe` is the Lean/Lake executable built from this
repository's `lean/` source at commit `32a69ec` (tree `lean/` =
`git archive 32a69ec lean`, tree id `f40f7b6c`).

- Size: 6,266,368 bytes
- SHA-256: `349BED3194C27831C2C64F78E82D8803A1446C835125BB89240F5295AD0E7A5B`
- Toolchain: `leanprover/lean4:v4.33.1` (Lake, no package dependencies).

## Reproduced twice

Two clean builds, each in a fresh export under its own `<BUILD_ROOT>`, each
run through `native/guard/run_guarded_v4.ps1` (SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`):

    lake --dir <BUILD_ROOT>/lean build BlindLedger blind_semantic_kernel blind_financial_axioms blind_financial_correction blind_financial

Both produced `<BUILD_ROOT>/lean/.lake/build/bin/blind_financial_correction.exe`
with the SHA-256 above. `blind_financial --correction-transition-kat` passed
40 of 40 gates on the first build's executable.

## Vectors

- `vectors/request.bin` (BLFCMD01) SHA-256 `13F832E80B93CC55D17ADD29470A2CD789CFCED1CBCF5A055FCBA3ECB927B537`
- `vectors/result.expected.bin` (BLFCRES2) SHA-256 `CB6DA046ED35E6E205AD1706CC29A37DE4539F14CE1AB56E1C95B86F379063DE`, produced by
  the first build's executable from `request.bin` with
  `vectors/run-vectors.cmd <exe> <request> <output>` under the guard.
- `vectors/result.actual.bin`, produced the same way by the second build's
  executable, is byte-identical to `result.expected.bin`.

The request is unchanged since the E911 pin (commit `f1de262`); BLFCMD01 is unchanged.
Against the B2 result the only change is the action payload digest (twice:
the new action and the resulting input's copy), now the Owner's SHA3-512
digest instead of 64 zero bytes.

## Retired pins

`RETIRED_PINS` lists engines a re-pin retired, one per line: SHA-256, retire
date, retiring commit, amount rule, reason (tab-separated, append-only). A
correction follow-up already committed under one of them stays valid history,
judged by that engine's amount rule (`correction-rule-v1`: the whole claim;
`b2-v1`: min(claim, shortfall)); only the pin above decides new work. The
independent checker pins the file's SHA-256,
so appending a line means updating `RETIRED_PINS_SHA256` too.

## Status

Synthetic evidence only. Non-activating and non-payment:
`proofSuiteId=null`, `production_usable=false`, `activation=false`.
