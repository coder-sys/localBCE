# Local verification

Run from the repository root with the existing offline toolchains.

```powershell
py -3.14 -B -m unittest tests.test_native_v3_plaintext_continuity
py -3.14 -B -m unittest tests.test_native_v3_trust_boundary_profile

py -3.14 -B experiments/native_v3_phase0/native_v3_fixture.py kat
py -3.14 -B experiments/native_v3_phase0/native_v3_fixture.py negatives
cargo run --manifest-path experiments/native_v3_phase0_rust/Cargo.toml --locked --offline -- kat
cargo run --manifest-path experiments/native_v3_phase0_rust/Cargo.toml --locked --offline -- negatives

$sessionDir = Join-Path (Get-Location) 'work/quickstart-trust-boundary-session'
py -3.14 -B -m experiments.native_v3_trust_boundary.session create $sessionDir
py -3.14 -B -m experiments.native_v3_trust_boundary.session challenge $sessionDir
py -3.14 -B -m experiments.native_v3_trust_boundary.session respond $sessionDir
cargo run --manifest-path experiments/native_v3_trust_boundary_rust/Cargo.toml --locked --offline -- verify $sessionDir

py -3.14 -B -m pytest -q tests/test_active_core_contract.py tests/test_security_freeze_spec.py
git diff --check
```

Use a new empty trust-boundary session directory for each run. These checks exercise bounded
candidate seams; current qualification and nonactivation status is authoritative in `STATE.md` and
`CURRENT_TASK.md`. They do not by themselves close the unresolved private-proof theorem ledger or
authorize deployment, payment, PHI, activation, or archive publication.
