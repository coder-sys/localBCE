# Parked work

`parked/private_zk/` holds the private zero-knowledge evidence track (Profile 11/12
clearance queue, composition and runtime, direct-mask contract and complete path,
`lean/queue`, `lean/security`, `rust/queue`, the Profile 11 source host) and its tests.
Its architecture documents are in `parked/private_zk/docs/` (`NATIVE_V3_ARCHITECTURE.md`,
`DATABASE_ZK_ARCHITECTURE.md`); they are frozen as written and may cite retired files.
The direct-mask C sources are in `parked/private_zk/native/tools/` (described by its
`README.md`), except `native/tools/direct_mask_fixture/`: the protected guard
(`native/guard/run_guarded_v4.ps1`, line 56) refuses every mode, including the live
`Command` mode, if that directory is missing, so it stays. The guard's
`Configure`/`Build`/`CTest` lanes build this parked fixture and now point at moved
sibling paths (`tools\direct_mask_vole`, `tools\direct_mask_pipeline`), so they fail
closed until the track is unparked; `Command` mode is unaffected.
`parked/mirror_legacy/` holds the NC Medicaid directory v1 adapter (and its independent
checker and test), moved out of `app/mirror/`.
`parked/state_clearance/` holds the State BLSDRQ01 direct clearance route
(`direct_state_owned_clearance_v1`, `semantic_kernel_binding`,
`transactional_database_boundary`, `governance_authority_v2`), the whole former
`experiments/` tree it imports (native_v3 continuity/trust-boundary/phase0 and the
longfellow evidence and patches) and their tests. Nothing in the financial product imports
them; the route never had a production pin. It still imports `app/batch/poseidon.py` and
`app/minimal_clearance_*`, which stay in `app/`.
The private-ZK track is parked under Constitution IX.4: the plan marks the private zero-knowledge mode
as conditional, so it stays off the critical path until a customer need selects it.
The default `pytest` run excludes this directory; run it explicitly with `pytest parked`.
Parked is not hidden: failures, skips and stale external pins here are still reported (VI.3).
