# Quickstart

Current truth: H4 has complete one-run K128/K512 prototypes through independent verification;
Gate 2E state selection, H5 repeated p95, and H6 qualification remain open. Wave 1 is sealed
synthetic/nonactivating; Wave 2 is active; 6 of 93 packages are complete; `proofSuiteId` is null;
real PHI/payments are forbidden. Read `docs/CURRENT_TECH_STACK.md`, then
`docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md` after the throughput and heterogeneous-proof
contracts. Before any containing-rollup work, also read
`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md`. Its compulsory based-validity invariants
and the frontier projections must not be confused with implemented or measured evidence. For each
fork/EIP, read its impact class, activation trigger, package owners and required tests; never infer
that “inherited from L1” means no compatibility work or that “available” means enabled.

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
py -3.14 -m pytest -q --ignore=tests/attacks
py -3.14 -m pytest -q tests/attacks
```

R30 remains the reviewed offline Python supply-chain baseline. R34 counts are historical and include
the now-removed RISC Zero/Stwo suites. Current 2026-07-31 collection found 1,093 ordinary Python
tests before the known missing canonical `../ops` tree stopped collection, plus 396 attack tests
collected cleanly. Run focused affected tests during development and both complete Python lanes at a
convergence milestone. Any current Python/Rust/Cairo semantic mismatch is a hard stop.

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

The standalone Stwo and RISC Zero experiments are retired and absent from the active tree. The H4
shared-bus Boolean GKR/Construction-8.2 prototype is complete for one K128 and K512 run, but the
authoritative state selection, full composition/simulator ledger, H5 p95 campaign, and H6 suite
qualification remain incomplete. Use synthetic data only and never interpret a component or one-run
prototype result as production qualification.

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
