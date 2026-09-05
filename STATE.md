# Blind Ledger current state

Updated: 2026-09-05

## Integrated candidate

The reviewed integration base is Cleanup commit `f53b4230bfa61a5fc87c17964d49e4c70cb92c12`
(tree `65a2cbfa316fde4e6da968abf31e65df7b26de0b`), plus the operator-equivalent policy and
governance lineage `d4261c70798654484e8c3dfb327b24bcc16a2fe0` / `653999300d4d974bbe7ddce28cda7ff0ef3bbcd6`
and pointer refresh `e15045ef8b7e7eb76a3781201c1b99c63c0e89f2` / `f5eb205962ec8285b4b5764429535b9f506041ff`.
The final authority delta is the Git successor that records this file; no standalone handoff or
archive publication is implied.

The current release map is executable and rooted in the actual integrated tree:

| Lane | Count | Selection |
| --- | ---: | --- |
| Current source | 186 | selected |
| Retained compatibility | 3 | selected only by explicit closure |
| Source-only | 3 | unselected |
| Excluded generated/private | 26 | unselected |
| Unknown/retired/legacy | 0 | fail-closed if introduced |
| Tracked total | 218 | — |
| Default selection | 189 | 186 current + 3 retained |
| Unselected total | 29 | — |

The retained compatibility closure is exactly `app/batch/__init__.py`, `app/batch/poseidon.py`,
and `app/batch/stark_encoding.py`. The 17 deleted entries formerly named by the policy are gone;
the obsolete legacy registry is gone as well. Prefix membership is only a classification hint, not
a release decision. The shared privacy helper remains a selected runtime dependency, and source-only
privacy fixtures, generated evidence, private build metadata, and Profile 11 host files remain
excluded.

## Product and authority boundary

Blind Ledger is the state-side payment-clearance layer. The incumbent adjudicates the claim; the
official state system and payment rails move money. Blind Ledger owns only the state-local directive
`CLEAR`, `HOLD`, `HUMAN_REVIEW`, `BLOCK`, or `EXCEPTION_APPROVED` and never treats proof or signature
acceptance as `CLEAR`.

Mirror is the read-only evidence, reconciliation, responsibility, remediation, and continuity
product. Provider Trust Graph is its narrow first wedge. Mirror cannot emit a Blind Ledger receipt,
authorize payment, or create an economic state transition. The five-directive continuity code is an
internal conformance harness, not the Mirror API.

The verifier-owned control set fixes mode, evaluator, rule order, conflict handling, scope, and
effective interval before admission. The three modes are `DIRECT_STATE_OWNED`,
`AUTHORITATIVE_ASSERTION`, and `PRIVATE_ZK`; there is no caller-selected downgrade or runtime
fallback. State owns `policyResult`, `effectiveDirective`, exceptions, chronology, replay/retry,
state mutation, and the outbox. Native-v3 owns private-proof identity, source binding, privacy/PQ,
resource, and complete-profile gates. The database owns atomic state mutation, concurrency,
durability, and recovery. Lean is the authorized future semantic/state-transition authority, not
current evidence.

## Verified implementation evidence

- Native-v3 Phase-0 and plaintext/trust-boundary paths preserve the five directives, strict public
  fields, authoritative absence, exact times, decision/access join, roots, retry identity, and
  independent mutation rejection. They are synthetic interface evidence, not a private proof.
- The Mirror/Provider Trust Graph and continuity lifecycle remain synthetic, local/current-Windows,
  observation-only evidence. They have no authenticated real source, production persistence, PHI,
  payment, or activation claim.
- The direct-state candidate keeps payment state separate from clearance state: non-clear directives
  advance replay/audit state only; only `CLEAR` and valid `EXCEPTION_APPROVED` advance clearance
  state. Exact retry, concurrency, rollback, restart, backup/restore, root binding, and corruption
  paths remain fail closed.
- The release-policy correction retains explicit dependency closure and the shared privacy detector.
  The focused release-policy gate passed `21 passed, 34 subtests passed` after the stale classifier
  removal. Active-core/security/qualification passed `19 passed`; operations authority reported
  `ops_authority=verified` with `proofSuiteId=null`, `production_usable=false`,
  `qualification_state=NOT_QUALIFIED`, `activation_state=INACTIVE`, and
  `selection_state=UNSELECTED`.
- The final native-v3 trust-boundary rerun reached `59 passed, 3 failed, 7 subtests passed in 6.92s`.
  The three failures are profile manifest/ledger tests and all return
  `ledger:provenance-source-mismatch`: `profile.py` pins
  `UPSTREAM_MANIFEST_SHA256=A677B8A6BEA7DCA87E4370E8FA07FDFD17F345276B581629BE230022B8C0BB5D`,
  while the committed `experiments/longfellow_v09_native_v3/upstream_manifest.json` is 2633 bytes
  with SHA-256 `466A704DD9CE3F812FB19A73EABC44EB922113922C805B7AD17DEEB29D52A1DD`. This is an
  unresolved trust-critical source identity, not a failed predicate to weaken; no protected
  native-v3 source fix was applied.
- The integrated source-reduction successor `d9220535a68d652dd491fdcaa184b04068014016` removes
  five unreachable legacy money-chain modules and two obsolete money tests from immutable Cleanup
  input `52b441c138b9577122303aaf1d1769fca2d82e4b`. The surviving proof-primitives test retains
  both top-level and nested float rejection; repository-wide caller search found no remaining
  imports or references to the deleted modules. The executable release map is now 218 tracked,
  186 current source, 3 retained compatibility, 3 source-only, 26 excluded generated/private,
  and 189 selected.

## Database V4 clean break

The integrated source owns a transactional database schema version 4. The current direct-state test
builds a schema-3 image, and opening it fails with `database_schema_version_mismatch` before schema
creation or PRAGMA work. The source and copied backup remain byte-identical; recovery creates no
output. There is no automatic migration, deletion, fallback, or compatibility reader. Current V4
retry, restart, backup/restore, identity, concurrency, rollback, and post-commit-indeterminate
paths remain the required integration evidence. This is synthetic, nonactivating storage evidence,
not a cross-version upgrade or production persistence claim.

## Security and nonclaims

The strict chronology is `rule_effective < event < observation < decision`. One decision and exactly
two ordered accesses (`[0,1]`, READ then WRITE) are admitted, with matching `decision_id`; reads use
observation time and the state write uses decision time. Authoritative completeness is required before
absence can affect policy. Unknown, stale, malformed, replayed, reordered, duplicated, conflicting,
or cleanup-failed input fails closed.

No production proof backend is selected. DP24 remains an ideal-vector/oracle record with six numeric
inputs `UNKNOWN`; no numeric epsilon/security-bit claim follows. `proofSuiteId=null`,
`production_usable=false`, and `activation=false` remain fixed. No Lean implementation or deployed
formal-verification claim exists. Real PHI, live credentials, payment movement, HSM/FIPS custody,
official receiver, and Ethereum settlement are outside the current evidence.

Operations bytes were not edited by this authority delta. `tools.ops_authority verify` remains the
byte-identity gate; the current operations documents are canonical and no policy byte may change to
make a test pass. The independent `docs/DESIGN_IDEOLOGY.md` contract remains intact.

## Archive and next dependency

No source archive was refreshed or published. A bounded disposable archive may be built solely for
this phase's internal builder/readback verification; it is not a retained publication artifact.
`STATE.md` and `CURRENT_TASK.md` are workspace-only records and remain excluded from any source
archive. A future archive refresh must start from a clean, final manifest selection and independently
verify the builder receipt, canonical ZIP/CRC readback, three retained targets, equal hashes, and
zero publication artifacts.

Current authority is `AGENTS.md`, `CURRENT_TASK.md`, `STATE.md`, `ARCHITECTURE.md`,
`README.md`, `docs/NATIVE_V3_ARCHITECTURE.md`, `docs/DATABASE_ZK_ARCHITECTURE.md`,
`docs/LEAN_FORMAL_KERNEL.md`, `docs/DESIGN_IDEOLOGY.md`, the other named `docs/` owners, and
canonical `ops/` bytes. The next authorized semantic dependency after this integrated integrity
phase is the Lean workstream; it cannot be replaced by a model, differential test, or generated
vector.
