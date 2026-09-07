# Blind Ledger current task

Updated: 2026-09-07

Immutable input base commit: `c29d39ff796bb7056b42095dec5bc10a4a959342` (historical reviewed
integrated evidence, not the current child identity).
Input base tree: `4ad77eef67acb0d5019ac0520d42849330bd6d21` (historical input tree).
Reviewed integration baseline commit: `9c0586f4303a504dee48730c4525c93277511e94` (the exact
clean candidate before this bounded portability and authority-reconciliation correction).
Reviewed integration baseline tree: `ecd85c04af106cfdde19c07c495f570cce6db399`.
PHASE: Portable semantic candidate input and release-authority reconciliation.

Final source correction commit: `365536cc344889e4d111e7dc996cdd17c8f76d8f` (tree
`ba2b86b9a3447bfdf81f3e9300c423fed20a65e9`), clean after the bounded correction and disposable
release readback.

Next bounded action: preserve the verified handoff and do not publish an archive, activate a
profile, or mutate the separate v2 evidence checkout.

## Objective

Keep one current, nonactivating authority set that future agents can follow without reconstructing
superseded task pointers or repeated ownership prose. `AGENTS.md` owns execution and safety;
`STATE.md` owns verified evidence and nonclaims; `ARCHITECTURE.md` owns cross-product boundaries;
the named `docs/` owners own their technical contracts; and this file owns only this bounded work
and unresolved blockers.

Remove stale candidate/phase/lineage records and duplicate explanations while preserving every
trust boundary, fail-closed rule, custody restriction, negative-test requirement, qualification
consequence, and nonactivation claim. Git history remains the record of completed implementation
and prior authority decisions. This child includes the reviewed Mirror/source commits, the exact
resulting orphan release-policy removals described in `STATE.md`, and this separately authorized
portable-input/authority-count correction; it creates no archive or activation change.

## Blockers and unresolved identity

- The Native-v3 trust-boundary profile remains blocked by an unresolved source-provenance mismatch,
  not by a relaxed predicate. `experiments/native_v3_trust_boundary/profile.py` pins
  `A677B8A6BEA7DCA87E4370E8FA07FDFD17F345276B581629BE230022B8C0BB5D`, while the committed
  `experiments/longfellow_v09_native_v3/upstream_manifest.json` is 2633 bytes with SHA-256
  `466A704DD9CE3F812FB19A73EABC44EB922113922C805B7AD17DEEB29D52A1DD`. The three known failures
  return `ledger:provenance-source-mismatch`; no native-v3 source fix or repin is authorized here.
- A source-owned version discrepancy remains visible for separate cleanup: the current-lane
  `app/minimal_clearance_verification_profile.py` names a V6 queue/profile domain, while the active
  `app/minimal_clearance_verification_queue.py` and its tests freeze Profile 11. This child does
  not normalize either implementation or its tests; documentation must not describe the mismatch
  as resolved.
- The semantic assurance tests require the explicit external `BLIND_LEDGER_SEMANTIC_CANDIDATE`
  environment seam. Missing configuration, dirty state, wrong HEAD/tree, source drift, artifact
  drift, theorem drift, or checker failure remains fail-closed; there is no personal-path fallback.
- At the reviewed integration baseline, the executable release classifier reports 212 tracked
  files: 183 current source, 3 retained compatibility, 3 source-only, and 23 excluded
  generated/private, with 186 selected by default. The older 218-tracked/191-selected numbers
  are historical evidence and must not be presented as current.
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
