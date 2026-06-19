# Agent Notes

The active architecture is native STARK settlement only.

Do:

- Keep app-layer batch commitments, nullifier roots, payment roots, governed
  roots, and public inputs bound end to end.
- Keep production readiness fail-closed unless every required artifact and
  governance root is explicit.
- Use `scripts/run_buildable_checks.ps1` before release.
- Use `scripts/build_clean_release_zip.ps1` for deliverable zips.

Do not:

- Reintroduce deleted proof lanes, generated verifier adapters, or source-level
  test verifier doubles.
- Treat test-local verifier doubles as production artifacts.
- Bypass verifier artifact pin checks.
- Package build caches, generated proof artifacts, or stale handoff manifests.
