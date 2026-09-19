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

## Current source/checkpoint — 2026-09-19

The documentation/source batch started from branch
`rightrail-financial-workflow-20260913` at HEAD
`de495141ad2b7c5b910bf6dd6459b7b1120eaea6`, tree
`4ea7838728ba1322d2a50edb5ede0c3deedc3a97`. The preceding source/docs
checkpoint is parent commit
`1effa625800c778367579416cb15a07555264754`, tree
`85bd334d002446c598cde41dd61283736c1e006e`. The follow-on source/test/harness
implementation is committed at
`691d3965f37e935889782215415368d83a9b0b25`, tree
`b50853d20935e28616e87e51c478ee398d4e3f3c`; this maintained-document state is
post-commit. The owner is explicitly versioned as
`RR/FINANCIAL/OWNER/v3`; Continuity is
`RR/FINANCIAL/CONTINUITY/v3`. v3 binds event header fields into event IDs and
heads and reconstructs population lifecycle order independently. The
follow-on binds reconstructed imported counts to persisted population state,
adds an explicit non-live TEST restore/continuation mode, and keeps
dispatch/egress disabled.

The final guarded affected source/test result is:

```text
Ran 46 tests in 14.878s
OK
```

The follow-on measurement series completed at
`work/financial-measurements-v4-r1` with 3 measured samples plus 1 warmup at
each of sizes 5, 10, and 20 (12 owner databases and 12 TEST restore
databases). All measured owner and TEST restarts independently verified, and
all 9 measured restores left source bytes unchanged. Total-ms medians were
329.150, 440.241, and 590.361 ms. Lock wait-to-acquire/transaction-held
medians were 20.024/9.507, 15.852/9.710, and 15.148/9.661 ms. Each measured
sample used one holder statement, one waiter attempt, and one successful
acquisition. This is a bounded observation, not a financial SLA; native
metrics remain pending and queue wait/age is not applicable. The prior v2/v3
measurement databases/logs remain historical evidence. Separate older
financial suites were not present beyond the three named RightRail financial
test modules, so no additional older financial suite was run; unrelated
repository suites remain outside this bounded verification. Whole-system,
native/Lean, independent-audit, and production qualification remain open;
this candidate remains synthetic, nonactivating, nonpayment, and non-PHI.

## Read in this order

1. [`../../AGENTS.md`](../../AGENTS.md) — Driver execution rules and precedence.
2. [`../../WORKSPACE_MAP.md`](../../WORKSPACE_MAP.md) — current roots and ownership map.
3. [`AGENTS.md`](AGENTS.md) — financial-child rules.
4. [`CURRENT_TASK.md`](CURRENT_TASK.md) — current bounded objective and blockers.
5. [`STATE.md`](STATE.md) — verified evidence and nonclaims.
6. [`ARCHITECTURE.md`](ARCHITECTURE.md) — whole-system ownership and product separation.
7. [`docs/MIRROR_ARCHITECTURE.md`](docs/MIRROR_ARCHITECTURE.md) — read-only source, custody, reconciliation, and recovery.
8. [`docs/DATABASE_ZK_ARCHITECTURE.md`](docs/DATABASE_ZK_ARCHITECTURE.md) — verifier-to-database transaction boundary.
9. [`docs/NATIVE_V3_ARCHITECTURE.md`](docs/NATIVE_V3_ARCHITECTURE.md) — private-proof and resource target.
10. [`docs/LEAN_FORMAL_KERNEL.md`](docs/LEAN_FORMAL_KERNEL.md) — later formal semantic gate.
11. [`docs/IMPLEMENTATION_ROADMAP.md`](docs/IMPLEMENTATION_ROADMAP.md) — dependency order.

Supporting authorities are [`docs/PYTHON_DEPENDENCY_LOCKING.md`](docs/PYTHON_DEPENDENCY_LOCKING.md),
[`docs/RARC_PENDING_DECISION.md`](docs/RARC_PENDING_DECISION.md),
[`docs/REJECTED_ARCHITECTURES.md`](docs/REJECTED_ARCHITECTURES.md), and the independent
[`docs/DESIGN_IDEOLOGY.md`](docs/DESIGN_IDEOLOGY.md). The source-only continuity and session
fixtures are owned by [`docs/NATIVE_V3_ARCHITECTURE.md`](docs/NATIVE_V3_ARCHITECTURE.md) and their
executable sources/tests. Git preserves superseded source and narrative; the rejected-architectures
record is the only live place for concise prohibitions against revival.

## Current financial-workflow verification

Future source-phase runs must use the existing Python toolchain and guarded
wrapper. The sequence is focused source seam checks and reported-defect
reproductions; independent schema/history checks; all twelve synthetic
acceptance cases through real persistence; same-owner Mirror and Continuity
checks; separate native regressions; then a bounded measurement run. Never use
a formula under test to generate an expected financial answer. Record exact
commands, raw trust-critical output, skipped counts/reasons, and resource
limits in `STATE.md`.

The final affected source/test run used the existing guarded wrapper with the
absolute child `tests` path and Python unittest discovery; its exact result and
resource evidence are recorded in `STATE.md`. Earlier v3-r4 and v3-r2 logs
remain retained historical evidence, as does the earlier pre-launch mutex
stop. The maintained financial boundary still requires guarded execution for
any future test/build/checker/native command.

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
