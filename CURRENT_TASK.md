# Blind Ledger current task

Updated: 2026-09-05

Current candidate commit: `e15045ef8b7e7eb76a3781201c1b99c63c0e89f2` (integrated review base for
this final authority delta).
Current candidate tree: `f236018647872b2fc0d2dd5891b88ab1554a449c` (integrated review base tree).
PHASE: Integrated source-closure, release-policy, and authority consolidation.

Next bounded action: finish the final policy, privacy, manifest, extraction, and readback checks on
the clean candidate, with no archive publication. If every required gate passes, this phase is
complete; later work starts with the authorized Lean dependency.

## Objective

Maintain one current, nonactivating product authority set after integrating Cleanup's source
closure with the operator release/privacy/governance delta. The release manifest is an explicit
dependency closure, not a retained-prefix keep map. Documentation records current ownership and
claims; Git preserves superseded source and evidence.

Integrated source lineage is Cleanup commit `f53b4230bfa61a5fc87c17964d49e4c70cb92c12` (tree
`65a2cbfa316fde4e6da968abf31e65df7b26de0b`), followed by the operator-equivalent policy commit
`d4261c70798654484e8c3dfb327b24bcc16a2fe0` (equivalent to operator commit
`653999300d4d974bbe7ddce28cda7ff0ef3bbcd6`) and pointer refresh `e15045e` (equivalent to
operator commit `f5eb205962ec8285b4b5764429535b9f506041ff`).

## Current release closure

The integrated tracked tree contains 225 paths. The executable policy classifies 193 as current
source, 3 as retained compatibility, 3 as source-only, and 26 as excluded generated/private;
unknown, retired, and legacy lanes are empty. The default selection is 196 paths (193 current +
the following three reviewed compatibility modules), leaving 29 unselected:

- `app/batch/__init__.py`
- `app/batch/poseidon.py`
- `app/batch/stark_encoding.py`

Cleanup deleted the formerly listed compatibility inputs. The policy now contains no stale deleted
dependency entries and no obsolete `LEGACY_NONCURRENT` registry; retained-prefix hints never select
by themselves, and unknown or retired paths still fail closed.

## Verified integration work

- The shared privacy detector, release builder/scanner, manifest policy, and documentation registry
  remain in one operator delta. The runtime helper remains in the selected release closure.
- The direct-state V4 database boundary and current direct-state tests are the source of truth for
  the clean break; old V3 databases/backups are rejected before writable open and preserved byte-for-
  byte. There is no migration or compatibility reader.
- The authority set is consolidated in `AGENTS.md`, `CURRENT_TASK.md`, `STATE.md`,
  `ARCHITECTURE.md`, `README.md`, and the named `docs/`/`ops/` owners. `docs/DESIGN_IDEOLOGY.md` remains
  an independent design contract and is not rewritten here.

## Required final evidence

Run and report the exact results for the release-manifest, documentation-governance, privacy,
builder, active-core/security/qualification, direct-state/native boundary, operations-authority,
strict-compilation, structural-privacy, and extracted-builder/readback gates. A clean CLI exit is
not sufficient: selected counts, manifest/archive identities, rejection evidence, warnings, and
skips must be retained. Do not refresh or publish the three external source archives.

The native-v3 trust-boundary profile gate is currently blocked by a source-provenance mismatch,
not by a relaxed predicate: `experiments/native_v3_trust_boundary/profile.py` pins
`UPSTREAM_MANIFEST_SHA256=A677B8A6BEA7DCA87E4370E8FA07FDFD17F345276B581629BE230022B8C0BB5D`,
while the committed `experiments/longfellow_v09_native_v3/upstream_manifest.json` is 2633 bytes
with SHA-256 `466A704DD9CE3F812FB19A73EABC44EB922113922C805B7AD17DEEB29D52A1DD`. The failing
tests are `test_compiled_parameter_report_rejects_exactly_seven_categories`,
`test_manifest_is_explicit_and_nonactivating`, and
`test_symbolic_ledger_rejects_zero_or_complete_placeholders`; each fails with
`ledger:provenance-source-mismatch`. No protected native-v3 source path is changed in this phase.

## Nonclaims and protected scope

`proofSuiteId=null`, `production_usable=false`, `activation=false`, and qualification
`NOT_QUALIFIED`/`INACTIVE`/`UNSELECTED` remain authoritative. No Lean kernel is implemented or
linked, no private-proof backend is selected, and no real PHI, credentials, payment movement,
production persistence, or official receiver is in scope. Native-v3 remains the exact private-proof
and resource authority; the database document owns the verifier-to-state transaction; Mirror remains
read-only and nonpayment.

Do not edit protected verifier, oracle, public-input, canonical-encoding, native queue/composition,
or Mirror paths without their owner. Do not edit `docs/DESIGN_IDEOLOGY.md`, operations bytes,
publication targets, or generated/private artifacts in this phase.
