# Provenance: blind_financial_correction.exe (E911)

## What this is

`blind_financial_correction.exe` is a Lean/Lake executable built on
2026-09-23 in the Engine checkout
(`work/lean-engine-20260913/semantic_kernel/lean/.lake/build/bin/`).

- Size: 6,245,376 bytes
- SHA-256: `E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9`
- Lake trace, response file and Lake hash copied beside it
  (`.exe.trace`, `.exe.rsp`, `.exe.hash`).

## It was built from OLDER source that is no longer recoverable

This executable was compiled from an older Engine source set. The compiled
`BlindLedger/Financial/CorrectionTransition/Transition.lean` was 25,674 bytes,
SHA-256 `342F3B1DF777095D75FD12970F29DFBC09AC06DCF48147EFF804EBA78E9021AE`.
That source is no longer recoverable: Engine's `STATE.md` (archived as
`docs/history/lean-engine-20260913-STATE.md`) records the
exact-source recovery search as `NOT_RECOVERABLE` in the accessible evidence.
The compiled `Reuse.lean` (10,902 bytes, SHA-256
`1391120ECCF022FA50B17C9BFBA9BEB15A21F658205C730228CAB17A2E2AF274`) also no
longer matches the current source.

The current source
(`lean/BlindLedger/Financial/CorrectionTransition/Transition.lean`, moved
byte-identical from `lean/engine/` on 2026-09-24; 40,732 bytes, SHA-256
`E982BA7871E45138BD6AAF72434E4F43D17105D42F60413FEB3B57816AD3F01D`) has NOT
been compiled.

**This binary must never be described as built from the current `lean/`
source.** A fresh guarded Engine build is required to replace it.

## Vectors

`vectors/` is a copy of `%TEMP%\engine-correction-vectors-20260923-r2\`:

- `request.bin` SHA-256 `13F832E80B93CC55D17ADD29470A2CD789CFCED1CBCF5A055FCBA3ECB927B537`
- `result.expected.bin` SHA-256 `312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E`
- `result.actual.bin` is byte-identical to `result.expected.bin`.
- `reuse-*.bin` are the reuse-assessment request and results.
  `reuse-result.actual.bin` is byte-identical to `reuse-result.expected.bin`.
- `run-vectors.cmd` is kept unchanged. It contains absolute paths into the
  Engine checkout and `%TEMP%`, so it does not run against this directory.

These vectors only show how this older binary behaves. They are not evidence
for the current source.

## Old build evidence

`old-build-evidence/` holds the only surviving derivatives of the lost source,
copied from the Engine checkout's `.lake/build`:

- `Transition.trace`: the Lake module trace for
  `BlindLedger.Financial.CorrectionTransition.Transition`. It records the
  Lake input hash of the source that was compiled.
- `Transition.c`: the C IR that Lean generated from the lost `Transition.lean`.
- `Reuse.trace` and `Reuse.c`: the same pair for the `Reuse` module, whose
  source also changed after the build.

## Status

This is synthetic evidence only. It is non-activating and non-payment:
`proofSuiteId=null`, `production_usable=false`, `activation=false`.
