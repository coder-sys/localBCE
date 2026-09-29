# Conformance kit

Published test vectors and format references for a second implementation.
Synthetic, non-PHI, nonpayment: `proofSuiteId=null`, `production_usable=false`,
`activation=false`. A pass is a local conformance claim, not qualification or
release.

Vectors stay in place; this dir only indexes them. `MANIFEST.sha256` pins
each one (verify from the repository root with
`sha256sum -c conformance/MANIFEST.sha256`).

## Contracts

- **Correction transition** `.../CORRECTION-TRANSITION/v1` (`BLFCMD02`→
 `BLFCRES3`): vectors `artifacts/engine-correction/vectors/{request,
 result.expected}.bin`; spec [CORRECTION_TRANSITION_WIRE.md](CORRECTION_TRANSITION_WIRE.md);
 impl `blind_financial_correction.exe --apply-correction-transition`, pins
 in [PROVENANCE.md](../artifacts/engine-correction/PROVENANCE.md).
- **Correction reuse** `.../CORRECTION-REUSE/v1` (`BLFCRU02`→`BLFCRV02`):
 vectors `.../vectors/reuse-{request,result.expected}.bin`; spec
 [§7](CORRECTION_TRANSITION_WIRE.md#7-reuse-blfcru02-request-and-blfcrv02-assessment);
 same exe, `--assess-correction-reuse` (Lean only, no Python codec).
- **Gate rules v1**: vectors `tests/gate_rules/{rules_v1,demo_zz}.vectors`;
 **no written spec** (header comment per file; digests/pins in
 `tools/gate_rules_data.py`); impl Lake exe `gate_rules`
 (`lean/BlindLedger/Gate/Rules/Run.lean`), driven by
 `tests/test_gate_rules_vectors.py`.
- **Provider pre-check v1**: vectors
 `provider_app/vectors/synthetic-vectors-v1.json`; JSON Schemas
 `provider_app/schemas/{check-request-v1,check-result-v1,rule-bundle-v1}.schema.json`
 ([README](../provider_app/vectors/README.md)); `contentDigest`
 canonicalization has **no written spec**, only `provider_app/tests/helpers.py`;
 impl `provider_app/provider_app/{evaluator,codec}.py`, Lean model
 `provider_app/lean`.
- **Continuity segments** `RR/GATE/SEGMENT/v1`: **no vectors published**;
 prose only, [CORE_REDESIGN.md](../docs/CORE_REDESIGN.md) lines 168-184;
 impl `app/right_rail_financial_owner_independent.py`,
 `tests/test_right_rail_financial_history_segments.py`.

`vectors/result.actual.bin` (build output) and `run-vectors.cmd` (launcher)
are not vectors and are not in the manifest.

## Running the binary vectors

Feed each request on stdin; stdout must match `*.expected.bin` byte-for-byte,
exit 0 (`.../vectors/run-vectors.cmd EXE REQUEST OUTPUT`). A conforming
decoder must also reject every input the wire spec marks rejected; negative
vectors aren't published yet. Report `<sha256>  <path>  PASS|FAIL` per
vector plus the implementation's name, version, SHA-256 — a result is only
meaningful against the manifest digest it names.

## Versioning

1. A published vector file is immutable; its manifest digest never changes.
2. Any byte/output/meaning change is a new file under the next contract
 version (e.g. `.../v2`, magic `BLFCMD03`), a new manifest line; the old
 file and line stay.
3. Retiring a version removes nothing; mark it retired here.
4. A wire/digest/money-rule change needs its own constitution XI.2 record;
 this kit only records what exists.
5. Suppliers report pass/fail per file digest, never per path or name.

## Known gaps

Lean/Python correction-codec differences incl. one money rule
([Open discrepancies](CORRECTION_TRANSITION_WIRE.md#open-discrepancies));
gate rules and provider `contentDigest` have no written spec; continuity
segments have no published vectors; no negative (must-reject) vectors exist.
