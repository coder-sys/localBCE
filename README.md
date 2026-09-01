# Blind Ledger

Blind Ledger is RightRail's state-side payment-clearance layer. It answers whether an already
proposed payment satisfies state-approved deterministic controls; the incumbent adjudicates the
claim and the official state system and payment rails move money.

Mirror is RightRail's umbrella read-only evidence, reconciliation, and operational-visibility
product, and one of its three customer-facing products. Provider Trust Graph is Mirror's current
narrow first wedge, not the whole Mirror product. Mirror's eight capability views are internal
views, not separate products. It reports only evidence-backed source coverage, findings,
discrepancies, remediation/retest, parity, responsibility, money, and transition artifacts; it
does not expose a Blind Ledger clearance receipt or authorize an economic mutation. The
five-directive clearance harness remains internal.

Read [`ARCHITECTURE.md`](ARCHITECTURE.md) for Mirror's six-question contract, visibility levels,
capability map, and separation from Blind Ledger and broad `Continuity State`. Read
[`docs/IMPLEMENTATION_ROADMAP.md`](docs/IMPLEMENTATION_ROADMAP.md) for the dependency ladder and
claim levels; this README is the entry route, not a readiness record.

When an undisclosed payment-relevant assertion crosses the clearance boundary and affects
automation, a verifier-owned native proof must be accepted before the database applies the exact
transition atomically. Lawfully state-owned plaintext may use the verifier-owned deterministic
control set without a purposeless ZK wrapper. Proof/session acceptance never means `CLEAR`, and
`policyResult` remains distinct from `effectiveDirective`.

This repository is a production-shaped, integration-ready candidate. Current evidence is synthetic,
local/current-Windows, and nonactivating: `proofSuiteId=null`, `production_usable=false`, activation
is false, and no real PHI, payment data, production proof backend, or deployed Lean kernel is
authorized. Productionization is qualification and narrow adapter substitution, not a semantic
rewrite.

## Read in this order

1. [`AGENTS.md`](AGENTS.md) — execution rules and document precedence.
2. [`CURRENT_TASK.md`](CURRENT_TASK.md) — the current bounded objective and blockers.
3. [`STATE.md`](STATE.md) — verified implementation evidence and nonclaims.
4. [`ARCHITECTURE.md`](ARCHITECTURE.md) — whole-system ownership and component map.
5. [`docs/MIRROR_ARCHITECTURE.md`](docs/MIRROR_ARCHITECTURE.md) — Mirror source, custody, reconciliation, and recovery boundary.
6. [`docs/DATABASE_ZK_ARCHITECTURE.md`](docs/DATABASE_ZK_ARCHITECTURE.md) — transaction boundary.
7. [`docs/NATIVE_V3_ARCHITECTURE.md`](docs/NATIVE_V3_ARCHITECTURE.md) — private-proof target.
8. [`docs/LEAN_FORMAL_KERNEL.md`](docs/LEAN_FORMAL_KERNEL.md) — later mandatory formal gate.
9. [`docs/IMPLEMENTATION_ROADMAP.md`](docs/IMPLEMENTATION_ROADMAP.md) — dependency order.

Supporting authorities are [`docs/NATIVE_V3_PLAINTEXT_CONTINUITY.md`](docs/NATIVE_V3_PLAINTEXT_CONTINUITY.md),
[`docs/NATIVE_V3_TRUST_BOUNDARY_PROFILE.md`](docs/NATIVE_V3_TRUST_BOUNDARY_PROFILE.md),
[`docs/PYTHON_DEPENDENCY_LOCKING.md`](docs/PYTHON_DEPENDENCY_LOCKING.md),
[`docs/RARC_PENDING_DECISION.md`](docs/RARC_PENDING_DECISION.md),
[`docs/REJECTED_ARCHITECTURES.md`](docs/REJECTED_ARCHITECTURES.md), and the independent
[`docs/DESIGN_IDEOLOGY.md`](docs/DESIGN_IDEOLOGY.md). Git history and retained source archives
preserve superseded source and narrative; the rejected-architectures record is the only live
place for concise prohibitions against restarting those directions.

## Local verification

Run from the repository root with the existing offline toolchains. Use a new empty session
directory for every trust-boundary run.

```powershell
py -3.14 -B -m unittest tests.test_native_v3_plaintext_continuity
py -3.14 -B -m unittest tests.test_native_v3_trust_boundary_profile
py -3.14 -B experiments/native_v3_phase0/native_v3_fixture.py kat
py -3.14 -B experiments/native_v3_phase0/native_v3_fixture.py negatives
cargo run --manifest-path experiments/native_v3_phase0_rust/Cargo.toml --locked --offline -- kat
cargo run --manifest-path experiments/native_v3_phase0_rust/Cargo.toml --locked --offline -- negatives
py -3.14 -B -m pytest -q tests/test_active_core_contract.py tests/test_security_freeze_spec.py tests/test_qualification_gate.py
py -3.14 -B -m tools.qualification_gate inspect
py -3.14 -B -m pytest -q tests/test_documentation_governance.py
git diff --check
```

These checks exercise bounded candidate seams. They do not close the private-proof theorem ledger,
authorize deployment, move money, authorize PHI, select a backend, or publish an archive.

Dependency installation is explicit and offline through `tools.locked_python_dependencies`; the
checked-in locks and wheelhouse, not network resolution, are the installation authority.

## Retained component references

The concise component-local documents linked from [`ARCHITECTURE.md`](ARCHITECTURE.md) are exact
operations, custody, monitoring, or licensing notes. They cannot select a backend or supply
production credit.

## Source authority

Git is the history for retired source and narrative. A retained source archive is a reviewed
publication artifact, not a substitute for the live authority hierarchy. Archive selection is
controlled by the deterministic release-manifest gate and builder; this documentation stage does
not rebuild or publish archives.

## Profile 11 complete-path screen

This is a nonactivating, test-only preparation harness. Per warmup/measured sample it enforces one
Profile 11 Range100 proof and one source-auth frame for one ordered batch of 100 operations, one
contained C verification batch, one atomic State/outbox batch, and 100 acknowledgements. Proof
acceptance is not CLEAR; State owns policy, directive, chronology, exceptions, disposition, recovery,
and outbox.

The pinned source boundary is repository `0027e9048471dde0b86bf08d3b7cf6b20db234d4` (tree
`5073d194aa6adb721903eb6084f19479ff8efaa4`) with source-host executable SHA-256
`C205CEBEA6C84B94D710F240D13808920980DF9CA2FC3AF2FCCAF900CACD3369` and size 471,552 bytes.
The underlying Rust producer pin is repository `2bfabac2738d546e75063fd77081cbfd8ff604b3` (tree
`9689987cf6854c7553f5792c9d6f15bddf13446a`) with release executable SHA-256
`C4BD6BC6D5399149010E100D5F9737412F4CC5EF6AAAC2B187486BE0DEEBFB4E` and size 423,936 bytes.
The pinned C repository is `9ca1ba2ccb6fa78384e3c3e21cfd3dfd0cb38eb2` (tree
`178a5f20c6738f7272cd38f77315da83650bbac0`); its verifier is 52,736 bytes, SHA-256
`4834D0A6A7E198A98EA0018F1009F6C180C510680EE61F2757E8342EF8B4032C`. The Queue pin is
`412b53e68091561657106345a22a772699761945` (tree `72746eb68e667698fdb0a72c8aea7c9bf027076a`).
The manifest also pins both C libraries and the synthetic public-key fixture; no production key is used.

The outer coordinator is placed in a Windows Job before resume. The complete tree is capped below
5,000,000,000 bytes (requested cap 4,999,999,999, with page-floor readback), and component admission
is 4,500,000,000 bytes. Timeouts terminate and reap the Job. Missing containment or descendant
accounting is a failure. The native file-write observer is capability-based: without complete
ETW/provider, privilege, PID-lineage, loss, and stop evidence it reports `observer_unavailable` or
`observer_incomplete`; directory snapshots are never treated as complete filesystem-write observation.

The native implementation uses a realtime, memory-only `StartTraceW`/`OpenTraceW`/`ProcessTrace`
session for the registered Kernel-File and Kernel-Process providers; it supplies no ETL/PML/log
filename. It remains fail-closed here because the installed Kernel-File schema does not provide a
decodable directory-only metadata mutation event, and file-name correlation can be lost. Provider
presence alone therefore cannot establish complete observation: until an independently verified
schema and external trace/isolation evidence cover every required event class, the backend must not
report `observer_ready` or support a complete-path run. See Microsoft's [system provider]
documentation for the provider/session boundary.

[system provider]: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers

Only the selected State DB, configured SQLite DELETE journal, State runtime lock, and necessary
State-directory metadata are authorized. Proof, signature, frame, statement, digest, PHI, temporary,
witness/nonce, spill, stdout/stderr log, crash-dump, and core writes—including files later deleted—are forbidden.

The schedule is one untimed warmup followed by exactly five measured samples; nearest-rank p95 is the
maximum of those five samples. The aggregate contains only fixed counts, timings, peak bytes, fixed
codes, and qualification flags. `proofSuiteId` is null, `production_usable` is false, and `activation`
is false; the harness makes no production or performance qualification claim.

Each retained sample keeps the complete `verify_state_ms` boundary: handoff, frame read, IPC preparation,
an inclusive contained-verifier/process/Job/C-wall/output-drain proxy, post-verifier Queue/State work,
integrity, close, and an explicit unbucketed residual. `total_unbucketed_ms` reconciles total time with
source, verify/state, and acknowledgement stages. The contained-verifier value is not a C-internal
timer, and p95 substage fields are component-wise maxima of the five measured samples.

Run from this directory with Python 3.14:

```powershell
py -3.14 -B -m py_compile profile11_complete_path.py tests\test_profile11_complete_path.py
py -3.14 -B -m unittest -v tests.test_profile11_complete_path
py -3.14 -B -m unittest -v tests.test_profile11_source_boundary
py -3.14 -B -m unittest -v -k stream tests.test_minimal_clearance_verifier_process
py -3.14 -B -m profile11_complete_path --prepare
py -3.14 -B -m profile11_complete_path --screen
```

`--prepare` launches nothing and reports every missing dependency. `--screen` first requires a ready
complete file-write observer; otherwise it returns a zero-sample failed aggregate without launching
the coordinator. With that gate open, it uses the already pinned source/C binaries and never compiles
them.
