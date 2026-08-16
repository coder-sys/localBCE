# Blind Ledger

Blind Ledger is RightRail's state-side payment-clearance layer. It answers whether an already
proposed payment satisfies state-approved deterministic controls; the incumbent adjudicates the
claim and the official state system and payment rails move money.

Mirror / Provider Trust Graph is a separate read-only evidence and continuity product. It reports
source coverage, findings, discrepancies, remediation/retest, parity, and transition artifacts.
It does not expose a Blind Ledger clearance receipt or authorize an economic mutation. The
five-directive clearance harness remains internal.

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
5. [`docs/DATABASE_ZK_ARCHITECTURE.md`](docs/DATABASE_ZK_ARCHITECTURE.md) — transaction boundary.
6. [`docs/NATIVE_V3_ARCHITECTURE.md`](docs/NATIVE_V3_ARCHITECTURE.md) — private-proof target.
7. [`docs/LEAN_FORMAL_KERNEL.md`](docs/LEAN_FORMAL_KERNEL.md) — later mandatory formal gate.
8. [`docs/IMPLEMENTATION_ROADMAP.md`](docs/IMPLEMENTATION_ROADMAP.md) — dependency order.

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
py -3.14 -B -m pytest -q tests/test_active_core_contract.py tests/test_security_freeze_spec.py
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
