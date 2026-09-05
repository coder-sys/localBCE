# Blind Ledger current task

Updated: 2026-09-05

Current candidate commit: `0607a275bb5158dd4b4c70dfcd95d0967c80b839` (sealed review baseline;
this child is its documentation-only successor).
Current candidate tree: `4571c47be35dd782045aa4f9ed35a9fb31413a2c` (sealed baseline tree).
PHASE: Authority and documentation cleanup.

Next bounded action: finish the Markdown authority consolidation in this isolated child, run only
the gates affected by the changed Markdown, and report the resulting clean candidate. Do not edit
application source, tests, dependencies, operations bytes, protected paths, or archive targets.

## Objective

Keep one current, nonactivating authority set that future agents can follow without reconstructing
superseded task pointers or repeated ownership prose. `AGENTS.md` owns execution and safety;
`STATE.md` owns verified evidence and nonclaims; `ARCHITECTURE.md` owns cross-product boundaries;
the named `docs/` owners own their technical contracts; and this file owns only this bounded work
and unresolved blockers.

Remove stale candidate/phase/lineage records and duplicate explanations while preserving every
trust boundary, fail-closed rule, custody restriction, negative-test requirement, qualification
consequence, and nonactivation claim. Git history remains the record of completed implementation
and prior authority decisions; this phase creates no archive or activation change.

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

## Nonclaims and scope

`proofSuiteId=null`, `production_usable=false`, `activation=false`, and
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED` remain authoritative. No Lean kernel is implemented or
linked, no private-proof backend is selected, and no real PHI, credentials, payment movement,
production persistence, or official receiver is in scope. Mirror remains read-only and
nonpayment. The sealed 0607 checkout is not modified; all edits are confined to this child.
