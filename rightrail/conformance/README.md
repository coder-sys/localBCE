# Conformance kit

Published test vectors and format references for a second implementation.
Synthetic, non-PHI, nonpayment: `proofSuiteId=null`, `production_usable=false`,
`activation=false`. A pass is a local conformance claim, not qualification or
release.

Vectors stay in place; this dir only indexes them. `MANIFEST.sha256` pins
each vector and every specification here; this README, an index, is the one
file not pinned (verify from the repository root with
`sha256sum -c conformance/MANIFEST.sha256`).

## Contracts

- **Correction transition** `.../CORRECTION-TRANSITION/v1` (`BLFCMD03`→
 `BLFCRES3`): vectors `artifacts/engine-correction/vectors/{request,
 result.expected}.bin`; spec [CORRECTION_TRANSITION_WIRE.md](CORRECTION_TRANSITION_WIRE.md);
 impl the evaluator worker, pins in
 [PROVENANCE.md](../artifacts/engine-evaluator/PROVENANCE.md).
- **Correction reuse** `.../CORRECTION-REUSE/v1` (`BLFCRU02`→`BLFCRV02`):
 retired 2026-10-02 with the one-shot exe (vectors in git 99ec957); spec
 [§7](CORRECTION_TRANSITION_WIRE.md#7-reuse-blfcru02-request-and-blfcrv02-assessment).
- **Gate rules v1**: spec [GATE_RULES_V1.md](GATE_RULES_V1.md); vectors
 `tests/gate_rules/{rules_v1,demo_zz}.vectors` and must-reject
 `rules_v1_negative.vectors` (pins in `tools/gate_rules_data.py`); impl Lake exe
 `gate_rules` (`lean/BlindLedger/Gate/Rules/Run.lean`), driven by
 `tests/test_gate_rules_vectors.py`; independent checker
 `gate_rules_v1_ref.py` (from the spec alone), `tests/test_gate_rules_v1_spec.py`.
 G6 (5fa47fa6, anchored batches) rewrote `rules_v1.vectors` in place; the pre-G6 bytes were deleted (RETIRED 2026-10-02; git keeps them).
- **Provider pre-check v1**: vectors
 `provider_app/vectors/synthetic-vectors-v1.json`; JSON Schemas
 `provider_app/schemas/{check-request-v1,check-result-v1,rule-bundle-v1}.schema.json`
 ([README](../provider_app/README.md)); `contentDigest`
 canonicalization: [PROVIDER_CONTENT_DIGEST_V1.md](PROVIDER_CONTENT_DIGEST_V1.md), vectors
 `conformance/vectors/provider_digest_v1/` (14 positive, 32 must-reject, `cases.json`), generator
 `tools/gen_provider_digest_v1_vectors.py`, test `tests/test_provider_digest_v1_conformance.py`;
 impl `provider_app/provider_app/{evaluator,codec}.py`, Lean model
 `provider_app/lean`.
- **Continuity segments** `RR/GATE/SEGMENT/v1`: spec [SEGMENT_V1.md](SEGMENT_V1.md); vectors
 `conformance/vectors/segment_v1/` (3 positive chains, 37 must-reject overlays, `index.json`); generator
 `tools/gen_segment_v1_vectors.py`, test `tests/test_segment_v1_conformance.py`; impl
 `app/right_rail_financial_owner_independent.py`. v1 covers the segment layer only: event id/head
 content and the 4,096-event boundary are out of scope.
- **Engine frames** `RRDQ` v2 / `RRDA` v4: spec [FRAME_V1.md](FRAME_V1.md); normative model `lean/BlindLedger/Gate/Frame/`;
 draft, no vectors yet.
- **Combined history engine** (revision 2 of the history store): spec [ENGINE_V3.md](ENGINE_V3.md); normative model
 `lean/BlindLedger/Gate/Engine3/`; draft, no vectors yet.
- **Obligations records** v1: spec [OBLIGATIONS_V1.md](OBLIGATIONS_V1.md) (layouts, tags, vectors); normative model
 `lean/BlindLedger/Gate/Obligations/Format/`; second reader [obligations_v1_ref.py](obligations_v1_ref.py); test
 `tests/test_obligations_format.py` (vectors, fuzzing, module table).
- **History index** `RR/GATE/CHAIN/v1` and `RR/GATE/{FLAT/FRAME,STORE/CHUNK,STORE/LEAF,STORE/NODE,STORE/PAGE,STORE/STATE3,INDEX/TAIL}/v1` (draft): spec
 [FLAT_V1.md](FLAT_V1.md); normative model `lean/BlindLedger/Gate/Flat/` (statements in `Theorems.lean`); no
 vectors yet.
- **Signed rule set** `RR/GATE/RULESET/v1` (draft): spec [RULESET_V1.md](RULESET_V1.md); normative model
 `lean/BlindLedger/Gate/RuleSet/Spec.lean`; frozen codec tests `tests/test_ruleset_v1_codec.py` (must-reject cases,
 round trips), `tests/test_ruleset_admission.py` (admission and selection).
- **Signed rule set** `RR/GATE/RULESET/v2` (draft; the eligibility source, aid table and reasons 24-28): spec
 [RULESET_V2.md](RULESET_V2.md); normative model `lean/BlindLedger/Gate/RuleSet/Spec.lean`; reference evaluator
 [ruleset_v2_ref.py](ruleset_v2_ref.py); test `tests/test_ruleset_v2.py` (codec, golden digests, Lean against the
 reference).
- **Eligibility system extract**, synthetic state layout v1: spec [ELIG_EXTRACT_V1.md](ELIG_EXTRACT_V1.md); vectors
 `tests/elig_vectors/` (3 golden files with their fact rows and receipts in `golden.json`, 40 must-refuse cases in
 `hostile.json`); generator `tools/gen_elig_extract_v1_vectors.py`, test `tests/test_reader_elig.py`; impl
 `app/right_rail_reader_elig.py`, independent verifier `app/right_rail_reader_elig_independent.py`.
- **State death file**, synthetic state layout v1: spec [STATE_DEATH_V1.md](STATE_DEATH_V1.md); vectors
 `tests/death_vectors/` (3 golden files in `golden.json`, 28 must-refuse cases in `hostile.json`); generator
 `tools/gen_state_death_v1_vectors.py`, test `tests/test_reader_state_death.py`; impl
 `app/right_rail_reader_state_death.py`, independent verifier `app/right_rail_reader_state_death_independent.py`.
 The state layouts share `app/right_rail_reader_fixed.py` and, for the verifiers, `app/right_rail_reader_fixed_independent.py`.
- **Provider death list**, synthetic state layout v1: spec [PROVIDER_DEATH_V1.md](PROVIDER_DEATH_V1.md); vectors
 `tests/provdeath_vectors/` (3 golden files in `golden.json`, 38 must-refuse cases in `hostile.json`); generator
 `tools/gen_provider_death_v1_vectors.py`, test `tests/test_reader_provider_death.py`; impl
 `app/right_rail_reader_provider_death.py`, independent verifier `app/right_rail_reader_provider_death_independent.py`.
- **Exclusion lists** (state list, synthetic state layout v1; federal list, the published CSV): spec
 [EXCLUSION_V1.md](EXCLUSION_V1.md); vectors `tests/excl_vectors/` (3 state and 3 federal golden files with their fact
 rows, set-aside entries and receipts in `golden.json`, 28 state and 23 federal must-refuse cases in `hostile.json`);
 generator `tools/gen_exclusion_v1_vectors.py`, test `tests/test_reader_exclusion.py`; impl
 `app/right_rail_reader_state_exclusion.py` and `app/right_rail_reader_federal_exclusion.py`, independent verifiers
 `app/right_rail_reader_state_exclusion_independent.py` and `app/right_rail_reader_federal_exclusion_independent.py`.

## Running the binary vectors

Feed each request as one worker frame; the answer, after tag 00, must match
`*.expected.bin` byte-for-byte. A conforming
decoder must also reject every input the wire spec marks rejected. Report `<sha256>  <path>  PASS|FAIL` per
vector plus the implementation's name, version, SHA-256 — a result is only
meaningful against the manifest digest it names.

## Versioning

1. A published vector file is immutable; its manifest digest never changes.
2. Any byte/output/meaning change is a new file under the next contract
 version (e.g. `.../v2`, magic `BLFCMD03`), a new manifest line; the old
 file and line stay until the version is retired.
3. Retiring a version deletes its vector files and manifest lines (git keeps them); mark it retired here.
4. A wire/digest/money-rule change needs its own constitution XI.2 record;
 this kit only records what exists.
5. Suppliers report pass/fail per file digest, never per path or name.

Known gaps: must-reject vectors cover gate rules, segments and provider digest, not the
correction wire; Lean/Python correction-codec
differences are in
[Open discrepancies](CORRECTION_TRANSITION_WIRE.md#open-discrepancies).
