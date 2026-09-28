# Conformance kit

Published test vectors and format references a second implementation can be checked
against. Everything here is synthetic, non-PHI and nonpayment: `proofSuiteId=null`,
`production_usable=false`, `activation=false`. A pass is a local conformance claim, not
qualification or release.

Vector files stay where they are; this directory only indexes them. `MANIFEST.sha256`
pins every published vector by SHA-256 (verify from the repository root with
`sha256sum -c conformance/MANIFEST.sha256`).

## Contracts

| Contract | Vector files | Format reference | Reference implementation |
|---|---|---|---|
| Correction transition `RR/FINANCIAL/CORRECTION-TRANSITION/v1` (`BLFCMD02` -> `BLFCRES3`) | `artifacts/engine-correction/vectors/request.bin`, `result.expected.bin` | [CORRECTION_TRANSITION_WIRE.md](CORRECTION_TRANSITION_WIRE.md) | Pinned `blind_financial_correction.exe --apply-correction-transition`; pins and derivation in [PROVENANCE.md](../artifacts/engine-correction/PROVENANCE.md) |
| Correction reuse `RR/FINANCIAL/CORRECTION-REUSE/v1` (`BLFCRU02` -> `BLFCRV02`) | `artifacts/engine-correction/vectors/reuse-request.bin`, `reuse-result.expected.bin` | [CORRECTION_TRANSITION_WIRE.md §7](CORRECTION_TRANSITION_WIRE.md#7-reuse-blfcru02-request-and-blfcrv02-assessment) | Same executable, `--assess-correction-reuse` (Lean only; no Python codec) |
| Gate rules v1 (released/unresolved/snapshot digests) | `tests/gate_rules/rules_v1.vectors`, `tests/gate_rules/demo_zz.vectors` | **No written spec.** Line format is only the header comment of each vector file; digest domains and pins are in `tools/gate_rules_data.py` | Lake exe `gate_rules` (`lean/BlindLedger/Gate/Rules/Run.lean`), driven by `tests/test_gate_rules_vectors.py` |
| Provider pre-check v1 | `provider_app/vectors/synthetic-vectors-v1.json` | JSON Schemas `provider_app/schemas/{check-request-v1,check-result-v1,rule-bundle-v1}.schema.json`; [vectors README](../provider_app/vectors/README.md). **No written spec** for the `contentDigest` canonicalization; it exists only in `provider_app/tests/helpers.py` | `provider_app/provider_app/evaluator.py`, `codec.py`; Lean model in `provider_app/lean` |
| Continuity segments `RR/GATE/SEGMENT/v1` | **None published** | Prose only, [CORE_REDESIGN.md](../docs/CORE_REDESIGN.md) lines 168-184 | `app/right_rail_financial_owner_independent.py`; exercised by `tests/test_right_rail_financial_history_segments.py` |

`artifacts/engine-correction/vectors/result.actual.bin` (build output) and
`run-vectors.cmd` (launcher) are not vectors and are not in the manifest.

## How a supplier runs the binary vectors

Feed each request file on stdin and compare stdout byte-for-byte with its
`*.expected.bin`; exit code must be 0. The launcher is
`artifacts/engine-correction/vectors/run-vectors.cmd EXE REQUEST OUTPUT`.
A conforming decoder must also reject every input the wire spec marks as rejected;
negative vectors are not yet published.

Report one line per vector file: `<sha256>  <path>  PASS|FAIL`, plus the implementation
identity (name, version, and its own SHA-256). A result is only meaningful against the
manifest digest it names.

## Versioning

1. A published vector file is immutable. Its digest in `MANIFEST.sha256` never changes.
2. Any change to bytes, expected output or meaning is a new file under the next
   contract version (for example `.../v2`, a new magic such as `BLFCMD03`), added as
   a new manifest line. The old file and line stay.
3. Retiring a contract version removes nothing; mark it retired here.
4. Changing a wire format, digest or money rule is a protected change and needs its
   own constitution XI.2 record; this kit only records what exists.
5. Suppliers report pass/fail per file digest, never per path or per contract name.

## Known gaps

- Lean vs Python differences in the correction codec, including one money-rule
  difference: [Open discrepancies](CORRECTION_TRANSITION_WIRE.md#open-discrepancies).
- Gate rules and the provider `contentDigest` have no written spec (table above).
- Continuity segments have no published vectors.
- No negative (must-reject) vectors for any contract.
