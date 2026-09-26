# Provenance: blind_financial_correction.exe

`blind_financial_correction.exe` is the Lean/Lake executable built from this
repository's `lean/` source at commit `79b6913` (tree `lean/` =
`git archive 79b6913 lean`, tree id `3dba470d`).

- Size: 6,279,168 bytes
- SHA-256: `1A7A18333726484A0737DA7B005EC699F73E99EA0CFACFB409B000F964BED3AF`
- Toolchain: `leanprover/lean4:v4.33.1` (Lake, no package dependencies).

## Reproduced twice

Two clean builds, each in a fresh export under its own `<BUILD_ROOT>`, each
run through `native/guard/run_guarded_v4.ps1` (SHA-256
`57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`):

    lake --dir <BUILD_ROOT>/lean build BlindLedger blind_semantic_kernel blind_financial_axioms blind_financial_correction blind_financial

Both produced `<BUILD_ROOT>/lean/.lake/build/bin/blind_financial_correction.exe`
with the SHA-256 above. `blind_financial --correction-transition-kat` passed
42 of 42 gates on the first build's executable.

## Vectors

- `vectors/request.bin` (BLFCMD02) SHA-256 `B658DCEE04138FDCBA6C9D72F3D2D044E5F596AA5794B3562A8312FBB57AD067`
- `vectors/result.expected.bin` (BLFCRES3) SHA-256 `83BB53D184B0B7D9268B565B844ECE9D6943C37DD022E2D361F735A4C835E0D6`, produced by
  the first build's executable from `request.bin` with
  `vectors/run-vectors.cmd <exe> <request> <output>` under the guard.
- `vectors/result.actual.bin`, produced the same way by the second build's
  executable, is byte-identical to `result.expected.bin`.

The request is the previous BLFCMD01 vector (SHA-256 `13F832E8…`) re-framed as
BLFCMD02: new magic and version, and an empty correction-paid list (two zero
bytes) before the input length. Against the previous result the only changes
are BLFCRES3's magic and version and the same empty list in the dependency
facts. This pin replaces `349BED31…`, which was never released, so it is not
listed as retired.

## Retired pins

`RETIRED_PINS` lists engines a re-pin retired, one per line: SHA-256, retire
date, retiring commit, amount rule, reason (tab-separated, append-only). A
correction follow-up already committed under one of them stays valid history,
judged by that engine's amount rule (`correction-rule-v1`: the whole claim;
`b2-v1`: min(claim, shortfall)); only the pin above (rule `h1-v1`) decides new
work. Every correction must also stay within the unpaid shortfall no earlier
request still asks for, and an obligation's corrections never name an older
engine after a newer one. The
independent checker pins the file's SHA-256, so appending a line means
updating `RETIRED_PINS_SHA256` too.

## Status

Synthetic evidence only. Non-activating and non-payment:
`proofSuiteId=null`, `production_usable=false`, `activation=false`.
