# Blind Ledger

Blind Ledger is RightRail's state-side payment-clearance layer. It evaluates state-approved
deterministic controls; the incumbent adjudicates the claim and the official state system moves
money.

Mirror is RightRail's read-only evidence, reconciliation, and operational-visibility product.
Provider Trust Graph is its narrow first wedge. Mirror reports evidence-backed coverage, findings,
discrepancies, remediation/retest, parity, responsibility, money, and transition artifacts; it does
not expose a Blind Ledger receipt or authorize an economic mutation. The five-directive harness is
internal.

When an undisclosed payment-relevant assertion crosses the clearance boundary and affects
automation, a verifier-owned native proof must be accepted before the database applies the exact
transition atomically. Lawfully state-owned plaintext may use the verifier-owned deterministic
control set without a purposeless ZK wrapper. Proof or signature acceptance is never `CLEAR`, and
`policyResult` remains distinct from `effectiveDirective`.

This is a production-shaped candidate, but current evidence is synthetic, local/current-Windows,
and nonactivating: `proofSuiteId=null`, `production_usable=false`, and
`activation=false`. No real PHI, live credentials, payment movement, production proof backend, or
deployed Lean kernel is authorized. Productionization is qualification and adapter substitution,
not a semantic rewrite.

## Read in this order

1. [`AGENTS.md`](AGENTS.md) — execution rules and precedence.
2. [`CURRENT_TASK.md`](CURRENT_TASK.md) — current bounded objective and blockers.
3. [`STATE.md`](STATE.md) — verified evidence and nonclaims.
4. [`ARCHITECTURE.md`](ARCHITECTURE.md) — whole-system ownership and product separation.
5. [`docs/MIRROR_ARCHITECTURE.md`](docs/MIRROR_ARCHITECTURE.md) — read-only source, custody, reconciliation, and recovery.
6. [`docs/DATABASE_ZK_ARCHITECTURE.md`](docs/DATABASE_ZK_ARCHITECTURE.md) — verifier-to-database transaction boundary.
7. [`docs/NATIVE_V3_ARCHITECTURE.md`](docs/NATIVE_V3_ARCHITECTURE.md) — private-proof and resource target.
8. [`docs/LEAN_FORMAL_KERNEL.md`](docs/LEAN_FORMAL_KERNEL.md) — later formal semantic gate.
9. [`docs/IMPLEMENTATION_ROADMAP.md`](docs/IMPLEMENTATION_ROADMAP.md) — dependency order.

Supporting authorities are [`docs/NATIVE_V3_PLAINTEXT_CONTINUITY.md`](docs/NATIVE_V3_PLAINTEXT_CONTINUITY.md),
[`docs/NATIVE_V3_TRUST_BOUNDARY_PROFILE.md`](docs/NATIVE_V3_TRUST_BOUNDARY_PROFILE.md),
[`docs/PYTHON_DEPENDENCY_LOCKING.md`](docs/PYTHON_DEPENDENCY_LOCKING.md),
[`docs/RARC_PENDING_DECISION.md`](docs/RARC_PENDING_DECISION.md),
[`docs/REJECTED_ARCHITECTURES.md`](docs/REJECTED_ARCHITECTURES.md), and the independent
[`docs/DESIGN_IDEOLOGY.md`](docs/DESIGN_IDEOLOGY.md). Git preserves superseded source and narrative;
the rejected-architectures record is the only live place for concise prohibitions against revival.

## Local verification

Run from the repository root with existing offline toolchains. Use a new empty session directory for
each trust-boundary run.

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
authorize deployment, move money, authorize PHI, select a backend, or publish an archive. Dependency
installation is explicit and offline through `tools.locked_python_dependencies`.

## Profile 11 complete-path screen

Profile 11 is a source-only, nonactivating preparation harness. It exercises one state-generated
ordered batch, an external verifier boundary, one atomic State/outbox batch, and acknowledgements;
State owns policy, directives, chronology, exceptions, recovery, and outbox. Exact pins, fixed
envelope/frame/IPC sizes, native file-write observation, Windows containment, resource ceilings,
qualification predicates, and zero-PHI exclusions are owned by
[`docs/NATIVE_V3_ARCHITECTURE.md`](docs/NATIVE_V3_ARCHITECTURE.md), not duplicated here.

```powershell
py -3.14 -B -m py_compile profile11_complete_path.py tests\test_profile11_complete_path.py
py -3.14 -B -m unittest -v tests.test_profile11_complete_path
py -3.14 -B -m unittest -v tests.test_profile11_source_boundary
py -3.14 -B -m unittest -v -k stream tests.test_minimal_clearance_verifier_process
py -3.14 -B profile11_complete_path.py --prepare
py -3.14 -B profile11_complete_path.py --screen
```

`--screen` requires a complete file-write observer and returns a zero-sample failed aggregate when
that gate is unavailable. This harness makes no production, performance, proof, PHI, payment, or
activation claim.

## Source and release authority

Git is the history for retired source and narrative. The deterministic release-manifest gate uses
an explicit rooted dependency closure; prefix membership alone never selects a release input. A
retained source archive is a reviewed publication artifact, not live authority. This documentation
phase does not rebuild or publish archives.
