# Parked work

`parked/private_zk/` holds the private zero-knowledge evidence track (Profile 11/12
clearance queue, composition and runtime, direct-mask contract and complete path,
`lean/queue`, `lean/security`, `rust/queue`, the Profile 11 source host) and its tests.
Its architecture documents are in `parked/private_zk/docs/` (`NATIVE_V3_ARCHITECTURE.md`,
`DATABASE_ZK_ARCHITECTURE.md`); they are frozen as written and may cite retired files.
The C sources in `native/tools/direct_mask_*` belong to the same track but stay in
`native/` because the guard (`native/guard/run_guarded_v4.ps1`) builds from there;
`native/tools/README.md` describes them.
`parked/mirror_legacy/` holds the NC Medicaid directory v1 adapter (and its independent
checker and test), moved out of `app/mirror/`.
The private-ZK track is parked under Constitution IX.4: the plan marks the private zero-knowledge mode
as conditional, so it stays off the critical path until a customer need selects it.
The default `pytest` run excludes this directory; run it explicitly with `pytest parked`.
Parked is not hidden: failures, skips and stale external pins here are still reported (VI.3).
