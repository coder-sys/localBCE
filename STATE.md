# Blind Ledger current state

Updated: 2026-09-05

## Candidate and release closure

This documentation-only candidate starts from sealed commit `0607a275bb5158dd4b4c70dfcd95d0967c80b839`
(tree `4571c47be35dd782045aa4f9ed35a9fb31413a2c`). The sealed checkout is not modified. The
executable release policy at that baseline is:

| Lane | Count | Selection |
| --- | ---: | --- |
| Current source | 192 | selected |
| Retained compatibility | 3 | selected only by explicit closure |
| Source-only | 3 | unselected |
| Excluded generated/private | 26 | unselected |
| Unknown/retired/legacy | 0 | fail-closed if introduced |
| Tracked total | 224 | — |
| Default selection | 195 | 192 current + 3 retained |
| Unselected total | 29 | — |

The retained closure is exactly `app/batch/__init__.py`, `app/batch/poseidon.py`, and
`app/batch/stark_encoding.py`. Prefix membership is only a classification hint. Deleted
compatibility entries and the obsolete legacy registry are not release inputs. Source-only privacy
fixtures, generated evidence, private build metadata, and Profile 11 host files remain excluded.
The executable classifier reports these counts for the current candidate; no release-policy bytes
were changed by this documentation cleanup.

## Verified evidence

- Cleanup commit `d9220535a68d652dd491fdcaa184b04068014016` is the rebased eight-file reduction from
  immutable input `52b441c138b9577122303aaf1d1769fca2d82e4b`. It removes five unreachable legacy
  money-chain modules and two obsolete money tests; the surviving proof-primitives test retains
  top-level and nested float rejection, and repository caller search found no remaining references.
- The direct-state candidate owns schema version 4. A schema-3 database or backup is rejected before
  schema creation with `database_schema_version_mismatch`, while source and backup bytes remain
  identical and recovery creates no output. V4 retry, restart, backup/restore, identity,
  concurrency, rollback, and post-commit-indeterminate paths remain synthetic evidence.
- Mirror/Provider Trust Graph and continuity are synthetic, local/current-Windows, observation-only
  evidence. They have no authenticated real source, production persistence, PHI, payment, or
  activation claim. The operational export bridge selects independently reconstructed Core
  `SOURCE_OBSERVATION`, not the Provider Trust Graph path.
- Recorded sealed-baseline gates include release-policy `21 passed, 34 subtests passed`,
  active-core/security/qualification `19 passed`, proof primitives `24 passed`, and operations
  authority `ops_authority=verified`. The qualification inspection reported
  `proofSuiteId=null`, `production_usable=false`, `qualification_state=NOT_QUALIFIED`,
  `activation_state=INACTIVE`, and `selection_state=UNSELECTED`.
- On clean disposable staging of commit `e2e9ae428e82841f1a18a6fcdecd0b7d2679e26e`, the
  release-manifest gate selected 195 paths and emitted manifest-v2 SHA-256
  `c09bdd34c67522c47063f69bb9290038b0cd52c0d8d3900209c59395769cb715` (29,247 bytes). The
  create-only builder completed canonical ZIP/CRC readback with 196 entries, 3,346,819 archive
  bytes, and archive SHA-256
  `322e9493fbcd1923d26123d42661b45d1a9827aeeecea2aa592e7ca99a2d52cf`; no publication target was
  refreshed.

## Unresolved trust-critical blocker

The Native-v3 trust-boundary profile remains blocked by a source-provenance mismatch. The three
known failing tests are `test_compiled_parameter_report_rejects_exactly_seven_categories`,
`test_manifest_is_explicit_and_nonactivating`, and
`test_symbolic_ledger_rejects_zero_or_complete_placeholders`; each returns
`ledger:provenance-source-mismatch`. `experiments/native_v3_trust_boundary/profile.py` pins
`UPSTREAM_MANIFEST_SHA256=A677B8A6BEA7DCA87E4370E8FA07FDFD17F345276B581629BE230022B8C0BB5D`,
while the committed `experiments/longfellow_v09_native_v3/upstream_manifest.json` is 2633 bytes
with SHA-256 `466A704DD9CE3F812FB19A73EABC44EB922113922C805B7AD17DEEB29D52A1DD`. This is an
unresolved source identity, not a predicate to weaken; no native-v3 source fix or repin was made.

## Security and nonclaims

The strict chronology is `rule_effective < event < observation < decision`; one decision and exactly
two ordered accesses (`[0,1]`, READ then WRITE) are admitted with matching `decision_id`. Reads use
observation time and the state write uses decision time. Authoritative completeness is required
before absence can affect policy; unknown, stale, malformed, replayed, reordered, duplicated,
conflicting, or cleanup-failed input fails closed.

No production proof backend is selected. DP24 remains an ideal-vector/oracle record with six numeric
inputs `UNKNOWN`; no numeric epsilon/security-bit claim follows. `proofSuiteId=null`,
`production_usable=false`, and `activation=false` remain fixed. No Lean implementation or deployed
formal-verification claim exists. Real PHI, live credentials, payment movement, HSM/FIPS custody,
official receiver, and Ethereum settlement remain outside the evidence.

Operations bytes were not edited. `tools.ops_authority verify` remains the byte-identity gate, and
the independent `docs/DESIGN_IDEOLOGY.md` contract remains intact.

## Archive and next dependency

No source archive was refreshed or published. Any disposable archive is only for internal
builder/readback verification and is not a retained publication artifact. `STATE.md` and
`CURRENT_TASK.md` remain workspace-only and excluded from source archives. A future refresh must
start from a clean reviewed manifest and independently verify builder receipt, canonical ZIP/CRC
readback, three retained targets, equal hashes, and zero publication artifacts. After this
documentation/release-integrity work, the next authorized semantic dependency is the Lean workstream;
a model, differential test, or generated vector cannot replace it.
