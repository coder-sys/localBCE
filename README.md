# RightRail financial workflow

RightRail's first concrete responsibility in this checkout is a synthetic, state-local financial
workflow. It keeps five logical responsibilities explicit: State Control Pack, Blind Ledger,
Mirror, Continuity State, and Switch. The official processor/payment system remains the authority
for funds movement. This repository records obligations, evidence, evaluations, determinations,
authorized actions, delivery state, and descriptive cash/reporting evidence; it does not move money
or authorize a live payment.

The financial owner is the sole writer for the durable workflow. Mirror commands and queries that
owner, and Continuity exports/restores a bounded versioned view of the same records. Evidence,
official determination, action authorization, dispatch/acknowledgment, and cash completion are
separate facts. An acknowledgment is never cash evidence. A synthetic trusted authority is injected
for local tests; missing, stale, or unauthorized authority fails closed.

The fictional fixture is fixed: twenty hospitals and $1,000,000 total; H is owed $100,000 and the
other nineteen total $900,000. All inputs, canaries, reports, and acceptance data are synthetic.
Expected values are manually derived constants. Current claims remain nonactivating:
`proofSuiteId=null`, `production_usable=false`, and `activation=false`.

The fixed cents are H `10,000,000`, eighteen other items `4,700,000` each, and one other item
`5,400,000`; the other-item total is `90,000,000` cents and the program total is `100,000,000`.
The acceptance branches use reviewer-supplied expectations for `9,700,000` cash, a `300,000`
claimed offset, unique correction payment `P2`, reversal, and distinct replacement `P3`.

The retained direct-clearance V1, queue/source ownership and reservation rules, queue/State/outbox
atomicity, exact 100-reference protocol, non-`CLEAR` economic guard, cryptographic/native paths,
and Lean/formal research remain separate generations. This financial slice does not change their
bytes, security parameters, artifacts, operations policy, archives, or production status.

## Integration baseline — 2026-09-13

The implementation checkout is branch `rightrail-financial-workflow-20260913` at
`be712f56117ee71f2f2477f139a9894a209a2985`, tree
`11191daf7d1604969649262300efb6a62b25fcff`, parent
`1306e38901b73790dfb2a973b4ac44daf2ff6869`. Before the documentation checkpoint, tracked status
was clean and only the driver-supplied `build-performance/` evidence directory was untracked.
The request hash and reference-plan PDF hash are recorded in `CURRENT_TASK.md` and `STATE.md`.

The work is staged as: governing documentation and pins; focused seam checks and baseline
reproductions; a durable financial owner with an independent checker; same-owner Mirror queries/
commands and bounded shadow Continuity export/restore; then the twelve acceptance cases, separate
native regressions, and guarded bounded measurements. Numerical financial SLAs are not supplied by
the reference plan, so measurements must report provisional budgets and unknown targets honestly.

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

Supporting authorities are [`docs/PYTHON_DEPENDENCY_LOCKING.md`](docs/PYTHON_DEPENDENCY_LOCKING.md),
[`docs/RARC_PENDING_DECISION.md`](docs/RARC_PENDING_DECISION.md),
[`docs/REJECTED_ARCHITECTURES.md`](docs/REJECTED_ARCHITECTURES.md), and the independent
[`docs/DESIGN_IDEOLOGY.md`](docs/DESIGN_IDEOLOGY.md). The source-only continuity and session
fixtures are owned by [`docs/NATIVE_V3_ARCHITECTURE.md`](docs/NATIVE_V3_ARCHITECTURE.md) and their
executable sources/tests. Git preserves superseded source and narrative; the rejected-architectures
record is the only live place for concise prohibitions against revival.

## Current financial-workflow verification

Run from this checkout with the existing Python toolchain and the existing guarded wrapper for any
build, checker, test, or native batch. The current gate sequence is: focused source seam checks and
reported-defect reproductions; independent financial schema/history checks; all twelve synthetic
acceptance cases through real persistence; same-owner Mirror and Continuity checks; separate native
regressions; then a bounded measurement run. Never use a formula under test to generate an expected
financial answer. Record exact commands, raw trust-critical output, skipped counts/reasons, and
resource limits in `STATE.md`.

## Retained Blind Ledger verification

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

The semantic assurance gate requires an explicitly configured, external, clean Git checkout. It has
no personal-path fallback: a missing, dirty, or identity-mismatched candidate fails closed. Set the
existing environment seam to the separately verified candidate before running the negative-fixture
tests or the executable gate; the checked-in manifest binds the required HEAD and tree.

```powershell
$env:BLIND_LEDGER_SEMANTIC_CANDIDATE = '<absolute path to the verified external candidate checkout>'
py -3.14 -B -m pytest -q tests/test_semantic_assurance_gate.py
py -3.14 -B -m tools.semantic_assurance_gate --candidate-root $env:BLIND_LEDGER_SEMANTIC_CANDIDATE
```

The semantic gate reads `tools/semantic_assurance_manifest.json` and remains synthetic,
nonactivating evidence; it does not establish refinement to Rust, database durability,
cryptographic soundness, deployment, payment movement, or activation.

## Retained Profile 11 complete-path screen

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

Profile 11 direct execution binds the local clean checkout through the manifest's
`python_source_binding.required_modules` Git-blob map. It does not select an external Queue path,
HEAD, or tree, and it does not fall back to ambient imports or generated bytecode.

The retained direct-mask tool descriptions are registered component records, not active financial
owners: [`authenticated proof`](tools/direct_mask_authenticated_proof/README.md),
[`fixture`](tools/direct_mask_fixture/README.md), [`pipeline`](tools/direct_mask_pipeline/README.md),
[`source auth`](tools/direct_mask_source_auth/README.md), [`source proof`](tools/direct_mask_source_proof/README.md),
and [`wire`](tools/direct_mask_wire/README.md). Their code, binaries, and proof/security meanings
remain under the separate retained native boundary.
