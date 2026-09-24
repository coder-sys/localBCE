# Blind Ledger current state

Updated: 2026-09-24

## 2026-09-24 local PTG browser view and finite socket timeout — source-only

Repository checkpoint: detached HEAD `43052285078bd1eed2ee9b11eddad1ef9513eb72`, tree
`040d4c6a2002a6fc19bd7c36a3228a11f068ac72`. All pre-existing dirty and untracked work was
preserved. This follow-up changes the already authorized local-view server and focused view test,
plus the current handoff sections of `CURRENT_TASK.md` and this file. No source read-model, exporter,
Core, Ingress, verifier, profile, or operations file was changed. Work remains unstaged and
uncommitted.

### Current source identities

| Path | Lines | Bytes | SHA-256 |
| --- | ---: | ---: | --- |
| `app/mirror/provider_trust_graph_read_model_v1.py` | 717 | 27,451 | `E9A4D56060CFB76D675BA39AC3C486264819782D7C0439D48BC82B0AF2AFBFFF` |
| `tests/test_mirror_provider_trust_graph_read_model_v1.py` | 317 | 14,528 | `D2B906DF08A0CFCC0FD2EDAE4D6F3AE3B391C2C67F3A70E0637D4F4D3280304B` |
| `tools/provider_trust_graph_view.py` | 338 | 12,787 | `0A2866B36736340B3A9090F489C1E157678B9CF5C3F178DCE8D96EBCE60A5815` |
| `tools/provider_trust_graph_view.html` | 102 | 4,335 | `785F857538E4BC56359D0A924E7A6E37DC78DB58E9AEC97A01B1B87327F179C4` |
| `tools/provider_trust_graph_view.css` | 108 | 3,794 | `3C974598079B8B99CA239F3CFD97EEF8C3539A8D18F27A5C2678EA768AABA3DD` |
| `tools/provider_trust_graph_view.js` | 217 | 8,609 | `2FED1C095BA23DE7838788D020C8617C7BD59925AC2F3E2E27AFC65664206B01` |
| `tests/test_provider_trust_graph_view.py` | 171 | 8,555 | `4E2C4969CC0FF21E13C98AA660431AA9510886AC55907B30F6651A92063C27B4` |

The prior handoff contained obsolete read-model identities (`6AFF…` and `F555…`); the actual
unchanged files are the `E9A4…` and `D2B9…` entries above. The three browser assets retain their
previous hashes. The socket repair changes the view server from its reviewed input hash
`B939F427F8538272D03E435DF34CBF598622788A4601ED31947FC83C86589A21` to the current identity in
the table; the focused test changes from `B1A628B28E8D50C047CF6010B8D4A5084BA50503CE6BC830F2DA7D66D102A1DC`
to the current identity above.

`app/mirror/provider_trust_graph_read_model_v1.py` now exposes a base view, bounded `PAGE`, ephemeral
`DETAIL`, and `COMPARE` service functions and a local `python -m` CLI. Each supplied selection runs
through the existing independent PTG artifact verifier, V1 evidence-export producer, and independent
export verifier. The CLI accepts explicit artifact/request files and expected operation reference(s),
uses the existing bounded local file reader, writes canonical JSON only to stdout, and has no network,
storage, cache, ingestion, credential, or mutation path. The comparison verifies both selections
independently and requires identical verified profile version/digest; it reports role/coverage,
finding, and discrepancy projection deltas only. Its contract labels missing evidence
`UNKNOWN_NOT_ABSENT` and absence inference `FORBIDDEN`. Identifiers, graph/profile digests, operation
references, export outcome, and complete-source count stay outside every view. Source truth remains
`NOT_ESTABLISHED`; freshness and completeness remain `UNKNOWN`; durability is caller-supplied and
transient; financial, clearance, payment, economic, production, and activation powers remain false.

The exporter currently accepts only its synthetic NC Medicaid profile and fixed synthetic selection
authorization. Non-synthetic “approved observation” support is not implemented; it requires a
separately authorized exporter/profile contract change. No State-authenticated staff route, State
identity/policy integration, server-side role/scope authorization, accessibility review, or
human-review acceptance exists in this checkout. The local CLI and unauthenticated loopback browser
view are available only as synthetic previews. Canonical §5.3 staff exposure remains gated on a
State-owned authenticated route with server-side role/scope authorization and accessibility/
human-review acceptance. No authorized observation is treated as a financial determination,
clearance, source-completeness claim, or action.

The local-view test module has six authored methods, including a focused timeout regression that
opens accepted silent and incomplete-header sockets, then expects a later valid GET to complete
within the 0.25-second test timeout plus one second and the stalled peer to read EOF. The existing
read-model test module has six authored methods. These are source assertions only. No test, Python
invocation, build, compiler, checker, preflight, guard, memory poll, or `git diff --check` ran; no
runtime or success receipt exists. The old `STATE_PREFLIGHT=PASS` snapshot is for the separate
financial checkout at HEAD `8f75f527ae6717001978ac7401853c2aaae55f2b`, so it is not applicable. There
is no direct finite Mirror v4 lane grant or fresh Mirror-targeted preflight.

Next evidence action: obtain a fresh safe Mirror-targeted v4 preflight and direct finite lane return;
then run and retain the focused timeout/route/privacy and read-model output before claiming
verification.

---
Historical record last updated: 2026-09-13

## Candidate and release closure

This candidate starts from immutable commit `0607a275bb5158dd4b4c70dfcd95d0967c80b839` (tree
`4571c47be35dd782045aa4f9ed35a9fb31413a2c`) in this separate child. The state of the separate v2
evidence checkout is outside this phase. The executable release policy in this integrated child is:

| Lane | Count | Selection |
| --- | ---: | --- |
| Current source | 188 | selected |
| Retained compatibility | 3 | selected only by explicit closure |
| Source-only | 3 | unselected |
| Excluded generated/private | 24 | unselected |
| Unknown/retired/legacy | 0 | fail-closed if introduced |
| Tracked total | 218 | — |
| Default selection | 191 | 188 current + 3 retained |
| Unselected total | 27 | — |

The retained closure is exactly `app/batch/__init__.py`, `app/batch/poseidon.py`, and
`app/batch/stark_encoding.py`. Prefix membership is only a classification hint. Deleted
compatibility entries and the obsolete legacy registry are not release inputs. Source-only privacy
fixtures, generated evidence, private build metadata, and Profile 11 host files remain excluded.
The executable classifier reports these counts for the current integrated child. The release-policy
changes are removal of the orphan classifications for the deleted external-source test and the
deleted Native throughput test; unknown and retired path rejection remains unchanged.

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
- The reviewed Mirror cleanup is the exact source commit `46a4c965464ea2cd72a3205d82652ddbf8ae51f6`
  (local integration `57e5f1f938ff7346880c6fd6a01138cecd575712`): the unused external adapters and
  their fixture test are deleted, source admission retains the active NC source path, and the
  state-source contract tests cover the remaining boundary. The exact deleted module/test paths
  have no remaining file or import references. The separate source-only cleanup is
  `6df4578aa5c98ca23ba38b563b74a075a504c483` (local `47eb2309e08d17913bb2fc99ffb33e02dc9bffaa`).
- The release-policy orphan entry for the deleted external-source test was removed from
  `tools/release_manifest_gate.py`; the stale orphan entry for the deleted Native throughput test
  was removed in the same bounded reconciliation. No other classification or unknown-path guard
  was changed.
- The approved source-only deletion `d50f0f28134e40fc5a6a04028ef401f801d6596e`, integrated locally
  as `c230aa518f95397f2dac0af8592aae93796c2b53`, removes exactly the two obsolete Native
  throughput/runner wrappers and their obsolete test. Replacement Queue/runtime, source-auth,
  and Profile 11 files remain present.
- Recorded sealed-baseline gates include release-policy `21 passed, 34 subtests passed`,
  active-core/security/qualification `19 passed`, proof primitives `24 passed`, and operations
  authority `ops_authority=verified`. The qualification inspection reported
  `proofSuiteId=null`, `production_usable=false`, `qualification_state=NOT_QUALIFIED`,
  `activation_state=INACTIVE`, and `selection_state=UNSELECTED`.
- On clean disposable staging of the integrated source/policy commit
  `c29d39ff796bb7056b42095dec5bc10a4a959342`, the release-manifest gate selected 193 paths and
  emitted manifest-v2 SHA-256 `2d54c478a4c5eb45736118e6ccfba726a9ad24922f085d141c012d4948979729`
  (28,959 bytes). The create-only builder completed canonical ZIP/CRC readback with 194 entries,
  3,305,354 archive bytes, payload 3,234,361 bytes, and archive SHA-256
  `ba3533641b07907255d238492906739dad1aa8e085b0d6c50a43f75cd77c47cf`; no publication target was
  refreshed.
  The earlier internal note naming `cc953b2fbb226fdcbe03a55fcb2367c26fde9ba0` for this receipt
  was a documentation error; the raw receipt is bound to `c29d39ff796bb7056b42095dec5bc10a4a959342`.
- On clean disposable staging of the final source/policy/docs commit
  `5989bb47d72b08a8e6345130e7c3f38b9757a33e` (tree
  `e3bcb94ca692fcb771a17cd6c71c67afe23bab8f`), the release-manifest gate selected 191 paths and
  emitted manifest-v2 SHA-256 `86b0c01631156ef088302ea34633f3b6c9b31e5cde1fd5a2426fbda14eba8832`
  (28,575 bytes). The create-only builder completed canonical ZIP/CRC readback with 192 entries,
  3,284,299 archive bytes, payload 3,214,292 bytes, and archive SHA-256
  `40a15ccf73c52397c586a0a34758d6bc4606c05c48534e5ca6a5957f9ea160a4`; no publication target was
  refreshed. Independent extracted readback matched every manifest hash and size, found all three
  deleted paths absent, and found the release helper present. The extracted positive helper exited
  0 with a 530-byte archive receipt; the negative helper exited 0 with
  `EXTRACTED_NEGATIVE_REJECTION=pass reason=release payload failed the structural privacy gate`.

## NC Medicaid directory observation adapter — 2026-09-12

Driver accepted the retained metadata facts and the observation-only semantic boundary for a
synthetic implementation phase. Source/test commit
`df80e6123042d3bcbe132888c4977e055a59fac2` (tree
`af6472c69ffb488e52a910e0654ab6cee0e340b1`, parent
`7a3eb2a9b4a461dd10397f87d11491555c4a5b85`) adds only
`app/mirror/nc_medicaid_directory_profile_v1.py`,
`app/mirror/nc_medicaid_directory_v1.py`,
`app/mirror/nc_medicaid_directory_v1_independent.py`, and
`tests/test_nc_medicaid_directory_v1.py`. The existing synthetic NC profile/producer/verifier,
SourceRole, SourceAdmission, Ingress, Core, Recovery, graph, exporter, and authority paths are
unchanged.

The new profile binds the production CapabilityStatement URL and retained SHA-256 identity as
contract evidence, but exposes no live client. The adapter accepts only a caller-supplied
synthetic transport port and runs a bounded Practitioner `_id` search, exact PractitionerRole
reference search, and same-base Location reads from matching roles. It canonicalizes a transient
capture, follows returned opaque next links, rejects unsupported include/modifier semantics,
independently validates resource identity, URL, page, response, retry, byte, node, string, and
resource bounds, and releases every response. The independent parser does not import the
producer.

Only a versioned aggregate observation and opaque verification-at-time receipt cross the public
boundary. Raw response bodies, URLs, queries, fullUrls, source identifiers, operation references,
raw-source digests, exception text, and stable-person/provider fingerprints do not. Every assigned
result is read-only, observation-only, synthetic-only, `production_usable=false`,
`activation=false`, `proofSuiteId=null`, and false for payment/clearance/source-truth/enrollment/
license authority; freshness and completeness remain `UNKNOWN`. The result is not admitted to the
existing Ingress/Core continuity grammar. No source record, credential, registration, persistence,
archive, publication, qualification, activation, PHI, payment, or production claim followed.

Raw decisive verification output:

```text
python -m unittest tests.test_nc_medicaid_directory_v1 -v
----------------------------------------------------------------------
Ran 16 tests in 0.040s

OK

python -m unittest tests.test_nc_medicaid_fhir_source tests.test_mirror_state_source_contract -q
----------------------------------------------------------------------
Ran 30 tests in 0.252s

OK
```

Targeted `python -m py_compile` for the three new modules and focused test exited `0`; staged
`git diff --check` exited `0`. The optional linter probe was unavailable (`ruff` was not found;
`python -m pyflakes ...` returned `No module named pyflakes`) and was not treated as a gate.
Remaining production dependencies are unchanged: source-owner authorization/terms, authentication,
versioned field/reference semantics, rate/retry/error behavior, cadence/snapshot consistency,
completeness, authoritative enrollment/licensure, production persistence, and activation evidence
are still required before any live or qualification lane.

## NC Medicaid directory acceptance correction — 2026-09-13

The read-only adapter review identified three acceptance defects: present `Location.status` was
not constrained to the required R4 code set; Bundle `self` was checked only for host/resource/
filter grammar rather than bound to the current request page; and exact `.`/`..` Location IDs
could enter read-path construction. Driver assigned the correction to a new exclusive child from
the exact clean input `e0773be11c6d21cca8ae38e5497bcd68b16c6ee9`/tree
`05e57096de0ec0754d7db64719cdb260127949f7`. The original input checkout was not modified.

Immutable source/test correction commit `013d2f566aabdefd3f32728f09ece2b6b768cb68` has tree
`e77f0dc899e289996230a07586d66225459f58af` and parent
`e0773be11c6d21cca8ae38e5497bcd68b16c6ee9`. It changes only the existing profile, producer,
independent verifier, and focused test module. Present Location status remains optional but now
accepts only `active`, `suspended`, or `inactive`; self/request query maps are compared after
strict validation, with query ordering tolerated and cursor/count/filter keys retained; and
exact dot-segment Location IDs are rejected by profile construction, producer references, and
independent returned-reference/resource/read-path validation while ordinary dotted IDs remain
valid. The public output, synthetic-only/nonactivating flags, and existing Ingress/Core boundary
are unchanged.

Raw correction gates:

```text
python -m unittest tests.test_nc_medicaid_directory_v1 -v
----------------------------------------------------------------------
Ran 19 tests in 0.065s

OK

python -m unittest tests.test_nc_medicaid_fhir_source tests.test_mirror_state_source_contract -q
----------------------------------------------------------------------
Ran 30 tests in 0.259s

OK
```

Targeted `python -m py_compile` exited `0`; `git diff --check` exited `0`; the two test runs had
no warnings, failures, or skips. Optional `ruff` remained unavailable (`ruff` was not recognized)
and `python -m pyflakes ...` returned `No module named pyflakes`; neither was a gate. The first
commit command exited `1` for missing child-local author identity; after matching the source
repository's local identity, the immutable commit succeeded. No live source, PHI, credentials,
network transport, persistence, qualification, activation, or archive action followed.

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

## 2026-09-13 documentation reconciliation

- The accepted source-admission ownership record is commit `1306e38901b73790dfb2a973b4ac44daf2ff6869`,
  tree `1d04b16d29b2b298dc93817375cd258c9762b7ef`. It is synthetic and nonactivating; it is not
  Lean-integrated or PQ-qualified.
- The reviewed native source correspondence is commit `ab1e39b1a7daf3b6afd915c8e48106ec0602902e`,
  tree `66ca11373c7385504bf33faa88eb6dc7277394ef`, over `ca9dba3`. The original guards are
  recovered, but historical invocation-to-current-binary hash provenance is missing. Preserve the
  source/binary pins and treat production/PQ custody and qualification as unresolved.
- The arithmetic record at `14deec37b1ab08f403598972b24f8328c6e77ab4` is conditional arithmetic,
  not concrete PQ qualification. Directory commit `122a395` and correction `013d2f566` are
  synthetic and do not establish source truth or custody.
- The Pro authenticated-private-output proposal is not implemented. It remains blocked on an
  actual signing/setup/source-validation privacy model and source-to-accepted-commitment equality;
  this record assigns no active crypto implementation work.
- Earlier semantic checkouts contain Lean source at `eb29b18a` and an adapter at `21528c55`. The
  current runtime still uses a synthetic State port, so formal linkage and deployed formal
  authority are not established.
- Pagefile evidence remains unavailable, and the documentation-governance warning remains
  `11` tests / `2` errors. Preserve those warnings and all failed or superseded history; no
  production, PQ, formal, custody, or activation claim follows.

## Security and nonclaims

The strict chronology is `rule_effective < event < observation < decision`; one decision and exactly
two ordered accesses (`[0,1]`, READ then WRITE) are admitted with matching `decision_id`. Reads use
observation time and the state write uses decision time. Authoritative completeness is required
before absence can affect policy; unknown, stale, malformed, replayed, reordered, duplicated,
conflicting, or cleanup-failed input fails closed.

No production proof backend is selected. DP24 remains an ideal-vector/oracle record with six numeric
inputs `UNKNOWN`; no numeric epsilon/security-bit claim follows. `proofSuiteId=null`,
`production_usable=false`, and `activation=false` remain fixed. Earlier semantic checkouts contain
Lean source and an adapter, but the current runtime still uses a synthetic State port and formal
linkage is not established; no deployed formal-verification claim exists. Real PHI, live
credentials, payment movement, HSM/FIPS custody, official receiver, and Ethereum settlement remain
outside the evidence.

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

## Mirror V5 Recovery identity correction — 2026-09-12

The bounded correction started from immutable checkpoint `114ba6010357f61f324de42142cd6e36c917b949`
(tree `b5735efa1b36d66c3d30162822edba3b8d4be79f`, parent `4dd95683c23f019d15a0c31f783f463b75b890d4`)
and produced source correction commit `1e3d259bd01ef9111495a5f4d20d4f5a46bf6291` (tree
`2ecfa3eefd3f561a2709583b366c3e1c02432d1e`). The prior checkpoint was not amended and the final
worktree after that commit was clean.

The exact authorized source/test delta is four files: `app/mirror/operational_owner.py`,
`app/mirror/recovery_v2.py`, `app/mirror/recovery_v2_independent.py`, and
`tests/test_mirror_profile_governance_v5.py`. Operational V5 reconciliation now filters Core
observation bindings by the configured profile id/version before suppressing Ingress pending
work. Recovery V5 now creates a fresh versioned three-table grammar: V5 metadata stores canonical
sanitized config material and canonical public profile-registry descriptors plus explicit
Core/schema/registry identity; points and transitions carry a V5 storage-id digest rather than a
raw storage id; V5 event/point/publication/bootstrap identities use a V5 digest domain; and the
independent verifier reconstructs V5 metadata, registry, PREPARE, transitions, publication claims,
point rows, roots, and empty/nonempty snapshots independently. Existing V3 columns, event grammar,
digest domain, and parser remain unchanged and reject V5; V5 rejects V3, including empty catalogs;
no migration or relabeling is performed. Expected identities are constraints only. V5 recovery
bytes contain no raw custody/storage port identifiers, paths, or private source material.

Raw decisive verification output:

```text
python -m unittest tests.test_mirror_profile_governance_v5 -v
----------------------------------------------------------------------
Ran 12 tests in 4.583s

OK

python -m unittest tests.test_mirror_v2_consolidation -v
----------------------------------------------------------------------
Ran 70 tests in 41.002s

OK (skipped=1)

python -m unittest discover -s tests -p "test_mirror*.py" -q
----------------------------------------------------------------------
Ran 184 tests in 54.833s

OK (skipped=2)
```

The one V2-consolidation skip and the second complete-gate skip are the existing filesystem
capability cases: `test_recovery_bounded_image_rejects_hardlinks_symlinks_and_all_sidecars` was
skipped for `symlink capability unavailable: OSError`, and
`test_alias_hardlink_and_symlink_paths_fail_closed` was skipped for
`directory symlink unavailable: OSError`. The complete gate ran with no failures; these checks were
not weakened. Touched modules also passed `python -m py_compile` with exit status 0 and `git diff
--check` with exit status 0. The prior checkpoint's raw verbose transcript was unavailable after
context compaction; the retained exact prior summary is `Ran 142 tests in 54.175s`, `OK
(skipped=2)`. No archive, publication, activation, production, PHI, payment, or qualification
state changed.

## Mirror V5 stored configuration enforcement correction — 2026-09-12

This bounded correction started from immutable checkpoint
`0ec45fdfebfcdb03d8e394ae28151be1e1159d98` (tree
`5509fc20a0f17387ac757a84e7ee66ca42a8844d`) and produced source/test correction commit
`c4daefcbbf69ebbadd188e8027d0b716e9ea5170` (tree
`aab1809e3e3a705aa52a9636953666cb90cea92b`, parent
`0ec45fdfebfcdb03d8e394ae28151be1e1159d98`). The source worktree was clean after that commit.
Only `app/mirror/recovery_v2_independent.py` and the existing
`tests/test_mirror_profile_governance_v5.py` changed. No shared V3 or owner implementation
changed, so the containing V3/owner gates were not replayed.

The independent V5 verifier now passes the verified stored `config_material` from metadata
verification into `_v5_verify_snapshot`, `_v5_verify_event`, `_v5_prepare_point`, and persisted
point-shape validation. It rejects a PREPARE whose ingress/core configuration digest disagrees
with stored metadata and rejects a persisted point whose component digests or bundle length
disagrees with stored configuration. Both PREPARE and point size checks enforce stored
`max_bundle_bytes`, not only the global ceiling. V3 code and its compatibility boundary are
unchanged. The A/B/A test no longer invokes private `_ingest_core_artifacts`; it uses public
`owner_b.run(recovery_generation=1)` to recover B, asserts `core_recovered=1` and
`core_ingested=0` with no new source calls, verifies B-selected export and A preservation, and
verifies A reopen has zero Core/Recovery effects and an identical Core verification result.

The corruption test uses synthetic copies only. It pins the valid metadata and expected config,
changes one PREPARE component digest at a time, rehashes event material/IDs/roots/receipts and
optionally the persisted projection, and tests both V5 verification entry points. It also creates
a legitimate V5 catalog with a configured cap below `MAX_BUNDLE_BYTES`, then performs the same
event-only and projection-synced oversized-point checks. All four mismatch/cap variants are
rejected with their specific boundary codes and each rejected database remains byte-identical.

Raw decisive output from the newly required V5 gate:

```text
test_all_governance_lifecycle_artifacts_are_independent_and_identity_free (tests.test_mirror_profile_governance_v5.CoreV5ProfileGovernanceTests.test_all_governance_lifecycle_artifacts_are_independent_and_identity_free) ... ok
test_fresh_head_requires_candidate_and_rejects_standalone_terminal_artifacts (tests.test_mirror_profile_governance_v5.CoreV5ProfileGovernanceTests.test_fresh_head_requires_candidate_and_rejects_standalone_terminal_artifacts) ... ok
test_independent_image_verifier_rejects_tampering_without_mutating_current_store (tests.test_mirror_profile_governance_v5.CoreV5ProfileGovernanceTests.test_independent_image_verifier_rejects_tampering_without_mutating_current_store) ... ok
test_observation_session_retry_restart_expiry_and_slot_bound (tests.test_mirror_profile_governance_v5.CoreV5ProfileGovernanceTests.test_observation_session_retry_restart_expiry_and_slot_bound) ... ok
test_two_profiles_have_isolated_heads_and_cross_profile_rejection (tests.test_mirror_profile_governance_v5.CoreV5ProfileGovernanceTests.test_two_profiles_have_isolated_heads_and_cross_profile_rejection) ... ok
test_v4_file_is_rejected_before_mutation_and_v5_surfaces_are_sanitized (tests.test_mirror_profile_governance_v5.CoreV5ProfileGovernanceTests.test_v4_file_is_rejected_before_mutation_and_v5_surfaces_are_sanitized) ... ok
test_v5_rejects_wrong_registry_and_config_without_mutating_current_store (tests.test_mirror_profile_governance_v5.CoreV5ProfileGovernanceTests.test_v5_rejects_wrong_registry_and_config_without_mutating_current_store) ... ok
test_withdrawal_pauses_a_live_session_and_rejection_is_byte_stable (tests.test_mirror_profile_governance_v5.CoreV5ProfileGovernanceTests.test_withdrawal_pauses_a_live_session_and_rejection_is_byte_stable) ... ok
test_owner_v5_composes_profiles_retry_recovery_restore_export_and_privacy (tests.test_mirror_profile_governance_v5.OperationalOwnerV5CompositionTests.test_owner_v5_composes_profiles_retry_recovery_restore_export_and_privacy) ... ok
test_owner_v5_core_pending_retry_and_tamper_fail_closed (tests.test_mirror_profile_governance_v5.OperationalOwnerV5CompositionTests.test_owner_v5_core_pending_retry_and_tamper_fail_closed) ... ok
test_owner_v5_reopen_profile_filter_recovery_export_and_no_duplicate (tests.test_mirror_profile_governance_v5.OperationalOwnerV5CompositionTests.test_owner_v5_reopen_profile_filter_recovery_export_and_no_duplicate) ... ok
test_recovery_v5_binds_components_to_stored_config_and_cap (tests.test_mirror_profile_governance_v5.OperationalOwnerV5CompositionTests.test_recovery_v5_binds_components_to_stored_config_and_cap) ... ok
test_recovery_v5_empty_cross_version_identity_and_sanitized_material (tests.test_mirror_profile_governance_v5.OperationalOwnerV5CompositionTests.test_recovery_v5_empty_cross_version_identity_and_sanitized_material) ... ok

----------------------------------------------------------------------
Ran 13 tests in 5.606s

OK
```

This run had no warnings, failures, or skips. The exact commands
`python -m py_compile app/mirror/recovery_v2_independent.py tests/test_mirror_profile_governance_v5.py`
and `git diff --check` each exited `0`. The initial read-only root probe exited nonzero only
because a Windows backslash path was compared literally with Git's forward-slash output; a
normalized rerun passed with `RESOLVED` equal to `GIT_ROOT`, HEAD
`0ec45fdfebfcdb03d8e394ae28151be1e1159d98`, tree
`5509fc20a0f17387ac757a84e7ee66ca42a8844d`, parent
`1e3d259bd01ef9111495a5f4d20d4f5a46bf6291`, and empty status/diff sections. No mutation resulted.

Retained prior gate evidence, not replayed:

```text
python -m unittest tests.test_mirror_profile_governance_v5 -v
----------------------------------------------------------------------
Ran 12 tests in 4.583s

OK

python -m unittest tests.test_mirror_v2_consolidation -v
----------------------------------------------------------------------
Ran 70 tests in 41.002s

OK (skipped=1)

python -m unittest discover -s tests -p "test_mirror*.py" -q
----------------------------------------------------------------------
Ran 184 tests in 54.833s

OK (skipped=2)
```

The two retained filesystem capability skips are
`test_recovery_bounded_image_rejects_hardlinks_symlinks_and_all_sidecars`
(`symlink capability unavailable: OSError`) and
`test_alias_hardlink_and_symlink_paths_fail_closed`
(`directory symlink unavailable: OSError`). The older verbose transcript was unavailable after
context compaction; its retained exact summary remains `Ran 142 tests in 54.175s`,
`OK (skipped=2)`. These skips and the missing transcript were not converted to passes. No
`recovery_v2.py` or `operational_owner.py` correction, Core/Ingress/source/graph/exporter change,
archive, publication, activation, production, PHI, payment, or qualification state changed.

## NC Medicaid Provider Directory real-source contract investigation — 2026-09-12

This bounded source-contract investigation follows the accepted V5 synthetic composition. It
used retained repository evidence and current primary official documentation only. No individual
or bulk provider/patient record query, source capture, credential, account, registration, data
ingestion, archive, publication, activation, or test execution occurred.

Decision: evidence is sufficient to define an implementation-enabling transport/schema seam for
one observation-only NC directory lane, but insufficient to claim source truth, completeness,
freshness, enrollment, licensure, production qualification, or activation. The next phase, only
after Driver acceptance, is one clean-break versioned directory-observation profile/verifier and
versioned admission binding. It must preserve the existing synthetic profile and must not reuse
the existing CREDENTIAL/ENROLLMENT source-role semantics for a directory projection.

Retained code evidence: `app/mirror/nc_medicaid_fhir_profile.py:30-38` fixes the official
hostname, FHIR `4.0.1`, `official-hostname-over-tls-unverified`, `record_authentication=undocumented`,
and an unbound CapabilityStatement identity; `:64-67` uses the synthetic identifier query; and
`:80-86` forbids live transport, nonmembership, enrollment, license, and completeness
qualification. `app/mirror/source_admission.py:54-55` accepts only CREDENTIAL and ENROLLMENT
record kinds; `:335-426` forces the sanitized aggregate to synthetic-only; and
`app/mirror/ingress_v2.py:126-140` plus `app/mirror/ingress_v2_independent.py:57-68` pin the
current Ingress contract to the synthetic profile and flags. This is a clean-break requirement,
not a reason to relabel the existing fixture.

Primary source evidence and locators:

- NCDHHS developer page, `https://connect.medicaid.ncdhhs.gov/developer`, sections Provider
  Directory API, Public APIs, Sandbox APIs, and API Specs: FHIR-based API; provider-oriented
  administrative/contact data; public access guidance without credentials or registration within
  reasonable limits; sandbox described as a provider-data clone; production metadata link.
- NCDHHS quarterly update dated 2026-04-16,
  `https://medicaid.ncdhhs.gov/blog/2026/04/16/quarterly-provider-update-spring-2026`: public
  network-provider directory for Managed Care and NC Medicaid Direct; same data as the lookup
  tool; data sourced from NCTracks provider records and health-plan contract data.
- NCDHHS provider enrollment, `https://medicaid.ncdhhs.gov/providers/provider-enrollment`,
  and NCTracks enrolled-practitioner help,
  `https://www.nctracks.nc.gov/help/GeneralPublic/Content/GeneralPublic/Build_5-Provider-GeneralPublic/P_PS_01_Enrolled_Practitioner_Search.htm`:
  NCTracks enrollment/credentialing and public enrolled-provider search are separate authority
  surfaces. The 2026 NC Medicaid provider-record notice at
  `https://medicaid.ncdhhs.gov/blog/2026/03/04/providers-risks-not-accurately-reporting-your-nctracks-provider-record`
  ties accurate NCTracks records and licensure/accreditation/certification requirements to
  participation, so directory observation does not prove them.
- CMS Provider Directory API FAQ,
  `https://www.cms.gov/initiatives/burden-reduction/overview/interoperability/frequently-asked-questions/provider-directory-api`,
  current page last modified 2026-09-01: the public API requirement covers network contract
  data and says user authentication/authorization cannot be required for public access, while
  developer registration or an API key may still be required. This is a regulatory bound, not
  evidence of this API's completeness or cadence.
- HL7 R4 HTTP, search, Bundle, and CapabilityStatement specifications at
  `https://hl7.org/fhir/R4/http.html`, `https://hl7.org/fhir/R4/search.html`,
  `https://hl7.org/fhir/R4/bundle.html`, and
  `https://hl7.org/fhir/R4/capabilitystatement.html`: GET search grammar and searchset Bundle;
  FHIR JSON media/version grammar; OperationOutcome errors; fullUrl; Bundle.total match count;
  opaque next-link pagination; `_count` as a server-controlled page hint; possible page staleness;
  and capability-declared interactions/search parameters.
- Current US Core reference pages at
  `https://hl7.org/fhir/us/core/StructureDefinition-us-core-practitioner.html`,
  `https://hl7.org/fhir/us/core/StructureDefinition-us-core-practitionerrole.html`, and
  `https://hl7.org/fhir/us/core/StructureDefinition-us-core-location.html` are v9.0.0 pages.
  The endpoint advertises unversioned R4/US Core URLs, so the supported release is not pinned.

Bounded metadata-only retrieval, with `Accept: application/fhir+json`, produced the following
actual non-personal CapabilityStatement facts:

- Sandbox metadata URL
  `https://sandbox.provider-directory-api.connect.medicaid.ncdhhs.gov/fhir/metadata`: HTTP 200,
  Content-Type `application/fhir+json`, 30,346 body bytes, SHA-256
  `d446bb91807752f165fd6368535e4ee2fb83ec7e5ff94b0dfa4944e269647e9e`,
  `fhirVersion=4.0.1`, `format=json`, `date=2025-06-12`.
- Production metadata URL
  `https://provider-directory-api.connect.medicaid.ncdhhs.gov/fhir/metadata`: HTTP 200,
  Content-Type `application/fhir+json`, 30,346 body bytes, SHA-256
  `6bf2d579cc42a87087d0636ad59fc4fdb71ec08044cc854238fcac85754efd03`,
  `fhirVersion=4.0.1`, `format=json`, `date=2026-03-02`.
- Both statements advertise security services `Certificates` and `SMART-on-FHIR`. Both list
  `Location`, `Practitioner`, and `PractitionerRole` with only `read` and `search-type`.
  `Location` parameters are `_id:token`, `identifier:token`, `address:string`,
  `address-city:string`, `address-postalcode:string`, `address-state:string`,
  `endpoint:reference`, `organization:reference`, `partof:reference`, `type:token`.
- `Practitioner` parameters are `_id:token`, `identifier:token`, `given:string`,
  `name:string`, `family:string`, `period:date`. `PractitionerRole` parameters are
  `_id:token`, `endpoint:reference`, `identifier:token`, `location:reference`,
  `organization:reference`, `practitioner:reference`, `role:token`, `service:reference`,
  `specialty:token`, `network:reference`, `period:date`.
- No include or reverse-include is advertised for those three resources; the only relevant
  include observed is `Organization.location`. The three resource profile/supported-profile
  URLs are unversioned R4 and US Core URLs. The endpoint metadata dates are CapabilityStatement
  publication dates, not directory observation timestamps.

The documented source grammar supports only a conservative plan: GET approved resource types
with approved advertised parameters, negotiate `application/fhir+json`/FHIR R4, validate a
searchset Bundle, retain the self link, and follow returned `link` relation `next` URLs as opaque
continuations constrained by the approved host. The synthetic `_include` and synthetic
identifier/page grammar cannot be reused. Separate resource searches and a policy-pinned local
reference join are required unless a future CapabilityStatement explicitly advertises an include.
`Bundle.total` does not establish completeness; `_count` may return fewer resources; pages may be
stale; and the source has not documented cadence, snapshot consistency, nonmembership, rate
limits, retry classes, or error behavior for this lane.

Implementation packet for Driver approval:

1. Keep `app/mirror/nc_medicaid_fhir_profile.py`, the synthetic adapter, independent verifier,
   fixtures, and existing Ingress defaults unchanged.
2. Add a proposed sibling contract with a new profile/schema identity, pinned capability digest,
   state-owned base host/path, resolved auth mode, authorization/terms digests, approved exact
   per-resource query plan, and conservative local bounds. The adapter receives only opaque
   in-memory locator context and verifier-owned times; it cannot receive arbitrary caller URLs,
   queries, identities, profile digests, or completeness claims.
3. Add an independent verifier for the advertised FHIR grammar and a versioned
   directory-observation admission binding. The verifier may use source identifiers transiently
   for reference checks but emits only aggregate counts/status/freshness/completeness state and
   an opaque receipt. No raw response, URL, query, fullUrl, provider/NPI/license identity,
   credential/enrollment identity, page identity, or raw source digest may enter durable Core,
   Ingress, or logical output.
4. Keep the existing SourceRole restriction and continuity graph semantics. If the current graph
   requires credential/enrollment records, stop at the observation boundary rather than treating
   directory data as either authority. Real-lane flags are observation-only,
   `synthetic_only=false`, `production_usable=false`, `activation=false`, and
   `proofSuiteId=null`. Ingress remains the sole sanitized durable observation owner; Core,
   Recovery, export selection, qualification, and activation are outside this phase.
5. Acceptance requires exact capability/host/auth/terms binding, GET-only supported interactions,
   media/version validation, approved query/reference grammar, no unsupported include, safe
   next-link traversal, local bounds, explicit unknown/stale/partial outcomes, independent
   verification, byte-stable rejection, no identity/raw-byte leakage, and preserved synthetic
   regression checks. Existing synthetic limits of 131,072-byte pages, 196,197-byte envelopes,
   four pages, two retries, 30-second Retry-After, and five-second timeout are proposed local
   bounds only, not source facts.

External facts still required before implementation approval are: state/source-owner authorization
and terms including retention, redistribution, rate/support and sandbox-to-production boundary;
resolution of public no-auth guidance versus the CapabilityStatement security services; canonical
identifier and per-resource query/reference semantics; a versioned profile/field contract;
freshness/cadence/snapshot/completeness/pagination/throttling/retry/error behavior; and a separate
authoritative enrollment/licensure source if continuity remains in scope.

Warnings, failures, and skips are retained explicitly: two browser metadata fetches failed because
the web tool rejected `application/fhir+json` as an unsupported content type (direct unsafe opens
were not used); one initial PowerShell extraction printed response bytes as decimal lines before
a UTF-8 decoding rerun produced the hashes above; individual-record queries executed `0`, bulk
enumeration queries `0`, credentials/accounts/registrations `0`, and source captures/ingestion
`0` (each intentionally not attempted). A historical 2021 daily-refresh reference and a 2023
RFP were not used as current source facts. No V5, Mirror, native, PQ, Lean, or recovery tests
were run; only Git identity, status, and diff checks are in scope for this record phase.
