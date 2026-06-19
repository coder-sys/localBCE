# Tasks

## Launch Blockers

- Audit and pin a real native STARK prover/verifier.
- Add production verifier deployment only after audited artifacts are pinned.
- Ratify oracle/source manifests and governed ruleset roots.
- Complete key custody, rotation, monitoring, and incident-response signoff.
- Run `scripts/run_buildable_checks.ps1`.
- Build the clean release zip with `scripts/build_clean_release_zip.ps1`.

## Forbidden

- Reintroduce deleted proof lanes, generated verifier adapters, or setup ceremony
  artifacts.
- Move test doubles into production source or deployment scripts.
- Ship a zip with caches, generated proof outputs, or stale handoff manifests.
