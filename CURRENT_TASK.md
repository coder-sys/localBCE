# Blind Ledger current task

Updated: 2026-09-07

Immutable input base commit: `c29d39ff796bb7056b42095dec5bc10a4a959342` (historical reviewed
integrated evidence, not the current child identity).
Input base tree: `4ad77eef67acb0d5019ac0520d42849330bd6d21` (historical input tree).
Reviewed integration baseline commit: `9c0586f4303a504dee48730c4525c93277511e94` (the exact
clean candidate before this bounded portability and authority-reconciliation correction).
Reviewed integration baseline tree: `ecd85c04af106cfdde19c07c495f570cce6db399`.
PHASE: Project-wide obsolete-material reachability and authority cleanup.

Cleanup input commit: `5fe29fad1f44df961ea20f8e3397c8d2e02783d0` (tree
`c963c8d489b5295ab0a4679953161a84a624567b`), clean before this bounded cleanup.

Cleanup implementation commit: `960352a8829d426b98053306fba6a2f323c7c896` (tree
`0dfdaf7eaeef48d9673750f9eafc3827c287aeb8`).

Next bounded action: cleanup is complete; the next authorized semantic dependency is the Lean
workstream. Do not publish an archive, activate a profile, mutate the separate v2 evidence checkout,
or resurrect shelved SHAKE/control-export work without a new bounded task.

## Objective

Keep one current, nonactivating authority set that future agents can follow without reconstructing
superseded task pointers or repeated ownership prose. `AGENTS.md` owns execution and safety;
`STATE.md` owns verified evidence and nonclaims; `ARCHITECTURE.md` owns cross-product boundaries;
the named `docs/` owners own their technical contracts; and this file owns only this bounded work
and unresolved blockers.

Remove only demonstrably obsolete tracked material and stale authority references while preserving
every trust boundary, fail-closed rule, custody restriction, negative-test requirement,
qualification consequence, and nonactivation claim. Git history remains the record of completed
implementation and prior authority decisions. This cleanup reviews the full current tree after
the reviewed Mirror/source, release-policy, and portability corrections; it creates no archive or
activation change.

## Blockers and unresolved identity

- The Native-v3 trust-boundary profile remains blocked by an unresolved source-provenance mismatch,
  not by a relaxed predicate. `experiments/native_v3_trust_boundary/profile.py` pins
  `A677B8A6BEA7DCA87E4370E8FA07FDFD17F345276B581629BE230022B8C0BB5D`, while the committed
  `experiments/longfellow_v09_native_v3/upstream_manifest.json` is 2633 bytes with SHA-256
  `466A704DD9CE3F812FB19A73EABC44EB922113922C805B7AD17DEEB29D52A1DD`. The three known failures
  return `ledger:provenance-source-mismatch`; no native-v3 source fix or repin is authorized here.
- Cleanup disposition: the current tree has 198 tracked files (170 current source, 2 retained
  compatibility, 3 source-only, and 23 excluded generated/private; 172 selected by default).
  Consumer and build-graph review found the five-file SPHINCS/public-input island and nine generic
  18-endpoint Native source files unused. Commit `960352a8829d426b98053306fba6a2f323c7c896`
  removes their 2,214 source lines, seven CMake targets, and sole three-package production
  dependency closure. The operation-scoped source-assertion and minimal-clearance Native families
  remain because current code validates and consumes their implementation attestation.
- The pre-cleanup deleted-path history scan found 1,335 historical deletions. The corrected current
  scan found 29 reference occurrences covering 24 distinct deleted paths; these are intentional
  governance negative-list/test references. The protected
  Queue V6 metadata comment remains unchanged and requires a separately scoped driver decision;
  it is not evidence for deleting active Queue or Native-v3 code.
- The semantic assurance tests require the explicit external `BLIND_LEDGER_SEMANTIC_CANDIDATE`
  environment seam. Missing configuration, dirty state, wrong HEAD/tree, source drift, artifact
  drift, theorem drift, or checker failure remains fail-closed; there is no personal-path fallback.
- At cleanup commit `960352a8829d426b98053306fba6a2f323c7c896`, the executable release
  classifier reports 198 tracked files: 170 current source, 2 retained compatibility, 3
  source-only, and 23 excluded generated/private, with 172 selected by default. The older
  218/191 and 212/186 numbers are historical evidence and must not be presented as current.
- Whole-suite verification from clean record commit
  `8ffe6ff02e7608665085e8cb481f42c03b215ecb` completed with `3 failed, 552 passed,
  4 skipped, 557 subtests passed`. The only failures are the same three
  `ledger:provenance-source-mismatch` tests named above; no new cleanup regression was observed.
- The Windows verifier workspace snapshot now compares only stable directory/reparse attribute
  bits; volatile `st_file_attributes` provider bits no longer turn an unchanged workspace into a
  false `verifier_workspace_changed` failure. The Profile 11 source-binding manifest pins the
  reviewed runtime blob `6c48f2428ef5fe391eeb24ab566b4c2ecc680445` and final verifier-process blob
  `2002036f2e0be3266ff4827bb01a24b13657b2cd`.

## Nonclaims and scope

`proofSuiteId=null`, `production_usable=false`, `activation=false`, and
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED` remain authoritative. No Lean kernel is implemented or
linked, no private-proof backend is selected, and no real PHI, credentials, payment movement,
production persistence, or official receiver is in scope. Mirror remains read-only and
nonpayment. The reviewed integration baseline above is the current child input; the separate v2
checkout and any other working-tree state are outside this child’s scope, and current edits are
confined here.
