# Quickstart

Current truth: Wave 1 is sealed synthetic/nonactivating; Wave 2 is active; 6 of 93 packages are
complete; `proofSuiteId` is null; real PHI/payments are forbidden. Read
`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` after the throughput and heterogeneous-proof
contracts. Its projections are prospective and must not be reported as benchmarks.

Run commands from `blind-ledger-app-layer/` unless a command says otherwise.

Before treating any successful command as release progress, read
`docs/IMPLEMENTATION_ROADMAP.md`, `docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`, and
`docs/BL_PQ512_THROUGHPUT_RECOVERY_PLAN.md`, then
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. The current state is 6 of 93 internal packages
complete, proof suite `UNSELECTED`, and not deployment-ready. Current Wave 1 (historical Wave 1A)
is the sealed nonactivating relation; current Wave 2 (historical Wave 1B) owns strict-PQ proof and
throughput recovery. Local test success is not the final independent audit and never authorizes real
PHI or payments.

## Do not reinstall tools blindly

An agent does not need to install Python, Rust, Scarb, Foundry, or CUDA if they are already installed and working. Check first:

```powershell
python --version
python -m pip --version
cargo --version
scarb --version
forge --version
```

Python dependencies are supported only on the reviewed CPython 3.14.4 targets: Windows x86-64 and
Linux x86-64 with glibc 2.28 or newer. Obtain the exact pre-provisioned wheelhouse through the
reviewed release-artifact channel; routine installation never resolves or downloads packages.
Use a fresh local virtual environment instead of changing global Python:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
$wheelhouse = "C:\reviewed-artifacts\cp314-win_amd64-development"
$auditDir = "..\proof-runs\python-install-audit"
New-Item -ItemType Directory -Force -Path $auditDir | Out-Null
python -m tools.locked_python_dependencies install `
  --profile development `
  --wheelhouse $wheelhouse `
  --attestation-out "$auditDir\development-install.json"
```

The installer fails before pip on a wrong interpreter, platform, pip version, lock or manifest
drift, missing/extra/renamed/symlinked/tampered wheels, an sdist, a non-fresh environment, or any
SHA-256/SHA3-512 mismatch. Pip is then forced to use the verified local wheels with `--no-index`,
`--require-hashes`, `--only-binary=:all:`, and `--no-deps`. See
`docs/PYTHON_DEPENDENCY_LOCKING.md` for the review and rotation contract.

If a tool is missing, report the exact missing tool and stop unless the owner asks you to install it.

## Python tests

```powershell
python -m pytest -q --ignore=tests/attacks --ignore=tests/test_risc0_complete_claim_differential.py
$runId = Get-Date -Format 'yyyyMMddTHHmmssZ'
$env:BL_RISC0_MODEL_TARGET_DIR = Join-Path $PWD "cache\quickstart-risc0-$runId"
python -m pytest -q -s tests/test_risc0_complete_claim_differential.py::Risc0CompleteClaimDifferentialTests::test_python_rust_cairo_and_risc0_agree_on_complete_synthetic_claim
python -m pytest -q tests/attacks
```

R30 remains the reviewed offline Python supply-chain baseline. R34 is the corrected historical Wave 1A
semantic-reference rollback point: 768 ordinary non-attack tests, two exact differentials, 181 attack tests, and 174 native
entries, or 1,125 unique Python/native entries. The 2026-07-21 Wave 1A executable-relation seal is
current Wave 1's nonactivating boundary. The broad non-attack command includes the physical-
dimension differential and has one explicit Windows account-capability skip because the account
cannot create symlinks; R30's locked Linux qualification passes that capability case.
Treat the counts as lower bounds for successor work: reject unexplained decreases, but
do not hard-code them to suppress new tests. Run focused affected tests during development and the
three complete lanes at a convergence milestone. Any Python/Rust/Cairo/RISC semantic mismatch is a
hard stop.

The historical Wave 1A structural/authenticated-reference slice can still be checked independently.
It does not substitute for the selected executable-relation seal:

```powershell
python -m pytest -q `
  tests/test_poseidon_bulk_chunking.py `
  tests/test_pq_tree_reference.py `
  tests/test_pq_sparse_tree_reference.py `
  tests/test_pq_membership_reference.py `
  tests/test_pq_strong_nullifier_reference.py `
  tests/test_a12_nullifier_derivation.py `
  tests/test_governed_attempt_nullifier.py `
  tests/test_r25_claim_truth_reference.py `
  tests/test_r25_witness_schema_reference.py `
  tests/test_wave1a_authenticated_payment_reference.py `
  tests/test_wave1a_authenticated_payment_maps_reference.py `
  tests/test_wave1a_relation_reference.py `
  tests/test_wave1a_physical_air_reference.py `
  tests/test_privacy_v2_abi.py
```

These historical tests use synthetic data. A passing result validates the parser, independently recomputed
dense/sparse paths, uniform reference replay transitions, scoped authenticated payment state, and
the composed host plus historical metadata-inventory KAT and A12-derived attempt/cover keys. It does
not by itself validate the sealed executable polynomial constraints. The current relation requires
`nullifier_derivations_authenticated=true`; current Wave 1 still does not
instantiate the concrete theorem-matched proof backend, select a qualified PQ suite, or authorize
activation.

The current focused Wave 1A closure gates additionally cover the executable application components,
global boundary composition, master-input adapter, exact global SHA3 schedule, and Rust parity. See
`docs/WAVE1A_EXECUTABLE_AIR_SPEC.md` for the authoritative test inventory and commitments; do not
replace a failed gate with a smaller historical subset.

## Rust rules engine

```powershell
cargo test --manifest-path rules-engine-rust/Cargo.toml --lib --tests -q
```

## Solidity tests

Forge support is vendored at `../third_party/forge-std/`.

```powershell
forge test
```

## Cairo circuit checks

```powershell
cd zk-cairo-sharp
scarb build
scarb test
```

## Local proof measurement

The measurement script builds synthetic batch witness inputs and then calls the installed prover toolchain. It does not package proof artifacts.

```powershell
python -m tools.measure_proving --claim-count 1
python -m tools.measure_proving --claim-count 100 --witness-only
python -m tools.measure_poseidon --rows 256 --iterations 20
```

The currently available S-two measurements are validity-only. Wave 1 has since sealed the complete
synthetic fixed-shape semantic AIR, but the shared-bus Boolean SHA3 coprocessor, native hiding,
authoritative durable SHA3-512 state, and selected strict-PQ suite remain incomplete. Use synthetic
data only and never interpret a fast calibration proof as a complete private claim proof.

If `scarb`, CUDA, or an external prover is missing, report the exact tool output. Do not guess flags or rewrite trust-critical code to force a pass.

## Serialized verifier-clean proof jobs

Use the job runner when proof attempts need immutable requests, exclusive execution,
heartbeats, bounded timeout retries, and machine-readable terminal status. Keep the
queue and generated artifacts outside this app-layer source tree.

```powershell
$queue = "..\..\proof-runs\local-prover-queue"
python -m tools.proving_job_runner enqueue --queue-root $queue --job-id batch-0001 --claim-count 1
python -m tools.proving_job_runner run-next --queue-root $queue
python -m tools.proving_job_runner status --queue-root $queue --job-id batch-0001
```

The runner invokes the supported simple-bootloader proof path and accepts success
only when verification, semantic output matching, proof-file hashing, and protected
Cairo source-manifest checks all pass. This local synthetic-claim path is not a
production adjudication input service, and it does not establish compatibility with
the pinned Solidity settlement verifier.
