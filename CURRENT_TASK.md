# Blind Ledger current task

Updated: 2026-09-05

Current candidate commit: `be4f1d565033dd57e0101af6f5bfcb0868bb1db6` (source base for this
operator delta).
Current candidate tree: `746fcbbd314e16bed96e50b52a1f586bfa8ec50a` (source-base tree; the
operator-owned documentation/toolchain delta is now committed and the worktree is clean).

PHASE: Operator-owned privacy, release-manifest, documentation-governance, and authority-record
consolidation. Cleanup separately owns the authorized source extraction and closure-qualified
legacy-code/test deletions.

Next bounded action: hand the verified operator delta, exact test/Git output, and
provisional-to-final rooted release map to Cleanup for source integration; then re-run the
release-policy checks against Cleanup's clean integrated source tree.

## Objective

Make the current candidate's release and documentation boundary executable and honest. The
operator-owned change may touch the shared privacy primitives, release builder/scanner, release
manifest policy and tests, Markdown authority records and their governance checker, and evidence
outside the source tree. It must preserve the current nonactivating application semantics and must
not turn a source checkout into an extracted-release runtime.

The release selection remains an explicit dependency closure. Prefix membership alone is not a
release decision. Cleanup's completed constant relocation and any behavior-preserving deletions
must be reconciled against the policy before a final manifest is generated.

## Verified candidate evidence

- The README now separates source-checkout commands from extracted-release use, identifies the
  operations-authority and qualification smoke, and labels Profile 11 as source-only.
- The privacy primitive factoring is locally verified by `tests/test_privacy_artifact_scan.py`:
  `21 passed, 5 subtests passed`. The builder, scanner, and shared helper use the same detector,
  duplicate-key rejection, JSON walk, and text-category primitives. `py_compile` passed for the
  changed Python modules.
- The combined operator suite (`tests/test_privacy_artifact_scan.py`,
  `tests/test_build_release_archive.py`, `tests/test_release_manifest_gate.py`, and
  `tests/test_documentation_governance.py`) passed `60 passed, 100 subtests passed`.
  The current committed default selection passed the structural privacy check with
  `STRUCTURAL_PRIVACY_SELECTED=248` and `STRUCTURAL_PRIVACY_FAILURES=0`; the shared detector
  helper is included as a runtime release dependency, with its path-regex vocabulary assembled
  without self-triggering source literals.
- The final operator commit `653999300d4d974bbe7ddce28cda7ff0ef3bbcd6` passed the extracted-source
  dependency gate: the manifest selected 248 payload files and the archive contained
  `tools/privacy_primitives.py`; an extracted builder built a benign archive and rejected an
  encoded-container payload without creating an output archive.
- Documentation governance returned 21 registered/live Markdown files, five root authorities,
  and zero protected-compatibility root files. The active-core/security/qualification command
  passed 19 tests; operations authority is verified; qualification remains NOT_QUALIFIED,
  INACTIVE, and UNSELECTED.
- The direct-state lane remains live and non-dispositive. `DIRECT_STATE_OWNED` is not replaced by
  Queue 11, and the dynamic Poseidon helper build/invocation remains part of the dependency review.
- Cleanup has been asked to retain only paths justified by completed source reachability and the
  protected application boundary. `app/oracle_attestation.py` and all other protected paths remain
  untouched.

## Blockers and nonclaims

- The release-policy closure is not final until Cleanup's approved governance-constant extraction
  and rooted source cleanup are present in the reviewed source state. No blanket experiment-tree
  retention or deletion is authorized by this record.
- Cleanup's pending source-review input at commit `bdba7c3bee27a33147fb06506225995984a45206`
  intentionally changes the transactional database boundary from schema 3 to schema 4. Existing V3
  direct-state-owned databases and backups are rejected with `database_schema_version_mismatch`;
  no cross-version storage compatibility or automatic data migration is claimed. V3 byte-preservation
  on rejection and V4 retry/recovery remain integration gates.
- No archive publication, three-target refresh, activation, or production claim is made by this
  phase. An internal archive build is conditional on a clean final source state and reconciled
  manifest; a privacy-gated or otherwise incomplete run cannot enter the archive-refresh lifecycle.
- `proofSuiteId=null`, `production_usable=false`, and `activation=false` remain authoritative.
  No Lean kernel is implemented or linked, no private-proof backend is selected, and no real PHI,
  live credentials, payment movement, HSM/FIPS custody, or official receiver is in scope.

## Authority and protected scope

`AGENTS.md` owns execution and safety. This file owns only the current bounded work and blockers;
`STATE.md` owns verified evidence and nonclaims; `ARCHITECTURE.md` owns cross-product boundaries;
the active `docs/` authorities own their technical domains; and `docs/DESIGN_IDEOLOGY.md` remains
an independent design contract and is not substantively rewritten here.

Protected application paths, operations bytes, wheels, source-only Profile 11 harnesses, and
publication targets are outside this phase. No verifier, privacy, qualification, or activation gate
may be weakened to make a run pass. Historical evidence stays labeled as historical and cannot
silently become current capability.
