# Security arithmetic verification evidence

Updated: 2026-09-23

## Scope and production blocker

This child addresses the narrow arithmetic-evidence gap where the accepted v2
conditional rational arithmetic had been calculated in Python without a
compiled, independently checkable Lean result at the certificate boundary.
The change adds a package-free Lean arithmetic kernel, a deterministic
executable, and a fail-closed Python adapter. The adapter consumes exact Lean
results for the cap, runtime-counter, QROM/privacy, width-budget, and
certificate-row paths; it does not reimplement or silently fall back when
Lean is unavailable or disagrees. This is conditional arithmetic evidence and
does not qualify formal release, production use, or product activation.

The accepted scope remains conditional arithmetic only. Cryptographic
reductions, primitive security, source truth/custody, randomness, transport,
durable state, availability qualification, payment, PHI, activation, and
product selection remain outside this child.

## Historical v1 correction continuation — verification complete at the time; handoff pending

The adapter correction was prepared from accepted correction commit
`2a9b375560288234e9da9d1a95b8c547c132ecef`. The current theorem manifest has
22 entries with 22 pinned receipt source paths after splitting the row
component proofs into seven separately bounded modules. The adapter guards 16
explicit Lean source targets and now pins receipt hash
`3a0094016d1e88285c821f7a81a745ac487f2800c1e04e537cd1339f25ea4455`.

`theoremManifest_count = 22` proves the length of the declared 22-name string
list; it is not a complete inventory and does not automatically link every
emitted theorem term to a manifest name. In particular,
`width_delta_all_k_bundle` is independently checked and emitted but is not in
that list, as with the other aggregate-only terms. The adapter's explicit
theorem fields and the independent axiom/checker evidence remain the
authoritative term checks.

The active shared guard is pinned to SHA-256
`A9D3496E3789F16182D3F6946860BC7454F86AEC407FB9BFFE352D1F4FED7FE1`, with
nominal reserve `3221225472`, 20% tolerance (effective floor `2576980378`),
process-tree cap `2000000000`, and mutex
`Local\BlindLedgerDirectMaskBuild20260907`. The original parallel Lake build
and unsupported serial option are preserved below; the final build used the
supported `+Module.Name` targets sequentially with the guard and cap
unchanged.

### Final guarded build and source axiom check

Command:

```text
python -c "from tools.direct_mask_contract.lean_adapter import build_formal_arithmetic_for_test; print(build_formal_arithmetic_for_test(), end='')"
```

The fresh preflight immediately before launch was
`FREE_PHYSICAL_BYTES=5009735680` and `HEAVY_PROCESS_COUNT=0`. The decisive
outer-guard evidence was:

```text
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=64 min_free_bytes=4194361344 reserve_bytes=3221225472 peak_private_bytes=1405612032
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
```

The child built all 34 jobs and then ran the pinned Lean `--trust=0`
`BlindLedger/AxiomCheck.lean`; the decisive build lines were:

```text
✔ [34/34] Built blind_security_arithmetic:exe (2.2s)
Build completed successfully (34 jobs).
```

The complete `--trust=0` axiom output was:

```text
'BlindLedger.SecurityArithmetic.cap_counters_well_formed' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_eff_completion_accounting' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_alg_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_eff_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_hist_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.p_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.switching_counted_once_at_caps' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_alg_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.q_eff_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.q_hist_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.p_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.remaining_nonnegative_on_admissible' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.cap_qrom_bound_lt_quarter' does not depend on any axioms
'BlindLedger.SecurityArithmetic.cap_adaptive_square_lt_remaining_square' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width384_partition' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width512_partition' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_zero_max_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_one_max_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_zero_simplified' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_one_simplified' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_simplified' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.width384_cap_row_terms_le_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width512_cap_row_terms_le_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width384_delta_cap_all_k' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.width512_delta_cap_all_k' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.theoremManifest_count' does not depend on any axioms
'BlindLedger.SecurityArithmetic.cap_theorem_bundle' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width_partition_bundle' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_certificate_bundle' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.width_delta_all_k_bundle' depends on axioms: [propext, Quot.sound]
```

The final build child stderr length was `0`. The output reports only standard
Lean axioms `propext` and `Quot.sound`; it reports no `sorry` or untrusted
custom axiom. The generalized monotonicity/admissibility and all-k wrapper
terms retain those standard dependencies; the cap, accounting, QROM, width,
row-component, manifest, and most bundle terms are reported axiom-free.

### Independent checker

Command:

```text
python -c "from tools.direct_mask_contract.lean_adapter import run_independent_formal_checker_for_test; print(run_independent_formal_checker_for_test())"
```

The fresh preflight was `FREE_PHYSICAL_BYTES=4916211712` and
`HEAVY_PROCESS_COUNT=0`. The guarded checker exited `0`, with
`min_free_bytes=4395671552`, `peak_private_bytes=1297731584`,
`CLEANUP=PASS`, and mutex release. The pinned `leanchecker` child stdout and
stderr were both empty files (`length=0`); the successful exit is the checker
result. The preceding final build performed the pinned `--trust=0`
`AxiomCheck` shown above.

### Artifact receipt and identity

The worktree receipt is `formal/lean/artifact_receipt.json`; JSON parsing
returned `receipt_json=valid`. Its SHA-256 is
`3A0094016D1E88285C821F7A81A745AC487F2800C1E04E537CD1339F25EA4455`.
The receipt binds build ID `BL-SECURITY-ARITHMETIC-20260913-V1`, schema
`BLSECAR01/v1`, toolchain `leanprover/lean4:v4.33.1`, 22 source paths, the
guard hash above, and the final executable:

```text
path=formal/lean/.lake/build/bin/blind_security_arithmetic.exe
length=108998144
mtime=2026-09-19T14:18:27.7594339-04:00
sha256=588C07EC80F5BCB05DDAA0A1B00048CFD06651DEC86E28A45B68DA8229E8CD55
```

The read-only `_artifact_identity()` probe completed successfully and
returned the same receipt hash, build/schema/toolchain IDs, binary hash and
length, 22 source hashes, pinned tool hashes, and guard hash. The adapter
therefore accepts the exact artifact identity and rejects replacement or
malformed receipts through the tested negative paths.

### Adapter correction and guarded consumer verification

The prior rollout commands were unguarded outer Python processes. The first
four-test run emitted the preserved warnings and still passed:

```text
ResourceWarning: unclosed file <_io.BufferedReader name=3>
... lean_adapter.py:807 / 686 ...
....
Ran 4 tests in 15.163s
OK
```

The bounded-process pipe close correction then produced the second preserved
four-test result `Ran 4 tests in 15.505s` followed by `OK`, and the separate
two-test cache/receipt result `Ran 2 tests in 12.839s` followed by `OK`.
Those successful runs were not accepted as contained evidence because their
outer Python processes were outside the shared guard.

The adapter correction now validates exact non-Boolean natural counters and
exact Boolean flags before runtime cache lookup, keeps runtime/row caches at a
64-entry LRU bound and the cap cache at one entry, preserves artifact identity
validation on every lookup, invalidation on identity change, and deep-copy
isolation, and starts the guarded PowerShell controller in an owned process
group. A limit first sends a cooperative control signal so the existing guard
can run its `finally` cleanup; only if that owned controller fails to stop does
the bounded helper terminate the exact owned tree. The timeout/output limits
are unchanged. The timeout/overflow failure path was not executed, per the
explicit instruction not to launch or kill a failure probe.

The test class had 27 methods at this accepted checkpoint. Its setup performs
only the pinned receipt/source/binary identity check and never rebuilds. The
one accepted consumer batch ran `py_compile` and all six affected tests inside the
unchanged Command-mode guard, with no nested guard or rebuild:

```text
PHYSICAL_PREFLIGHT free_bytes=4177006592 reserve_bytes=3221225472 reserve_floor_bytes=2576980378 tolerance_percent=20
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=13 min_free_bytes=4048920576 reserve_bytes=3221225472 peak_working_set_bytes=139595776 peak_private_bytes=85774336 reserve_floor_bytes=2576980378 tolerance_percent=20
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
```

The guarded child stdout file length was `0`; stderr contained exactly:

```text
......
----------------------------------------------------------------------
Ran 6 tests in 6.894s

OK
```

At that checkpoint, the six selected tests covered exact constants, runtime/counter rejection, row
maximum and simplification, the v3 residual-resource boundary, copy-safe
bounded-cache identity/eviction and warm/cold type rejection, malformed or
replaced receipt rejection, and the owned-process-group contract. Therefore
21 of the 27 methods remained unselected. No Lean source, binary, receipt, or
formal checker inputs changed in that Python-only correction, so no formal
build or checker rerun was performed.

### Post-checkpoint bounded cancellation correction

After checkpoint `8833f5385e5b701f4a084526fdc892059e23ecfc`, source review
identified two remaining adapter defects. A fast-exiting child could fill
stdout or stderr after the monitor loop had observed process exit, so the
post-reader path now rechecks both capture overflow flags and both final byte
lengths. Separately, stop/escalation errors could escape before `wait`, reader
join, and pipe close. The bounded state machine now records stop, wait,
owned-tree escalation, reader join, and pipe-close failures and completes
finalization before raising the combined failure.

The exact owned-tree contract decision is adapter-local and does not change the
shared guard or add another controller: every owned `_run_bounded` call must
provide an identity-bound cleanup-receipt checker. The only current owned
caller, `_guarded_power_shell`, supplies `_guarded_cleanup_contract`, which
requires both exact receipts below in the captured output:

```text
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
```

Missing or failed receipt evidence is a hard
`owned_process_tree_cleanup_unverified` failure. A root PID exit is never
treated as independent proof that descendants were cleaned. No real timeout,
overflow, taskkill, or descendant-failure probe was launched.

The direct Engine handoff then ran exactly the seven requested tests under the
unchanged Command-mode guard. The successful run used suffix
`lean-security-seven-20260919-b`. The inner command was `py -3.14 -B -m
py_compile tools/direct_mask_contract/lean_adapter.py
tools/direct_mask_contract/test_calculator_v2.py`, followed by
`py -3.14 -B -m unittest` for these seven methods:

```text
test_lean_batch_accepts_runtime_and_caps_and_rejects_invalid_counters
test_filtered_constants_are_exact_and_e3_dominates
test_row_bound_is_maximum_not_union_and_simplifies
test_v3_endpoint_residual_resources_and_shake_boundary_are_explicit
test_lean_adapter_cache_is_copy_safe_and_identity_checked
test_lean_adapter_rejects_receipt_replacement_and_malformed_output
test_lean_adapter_bounded_output_and_finalization_faults
```

The child stdout was empty and its stderr was exactly:

```text
.......
----------------------------------------------------------------------
Ran 7 tests in 6.488s

OK
```

The exact decisive outer-guard output was:

```text
PHYSICAL_PREFLIGHT free_bytes=6031036416 reserve_bytes=3221225472 reserve_floor_bytes=2576980378 tolerance_percent=20
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=14 min_free_bytes=5948071936 reserve_bytes=3221225472 peak_working_set_bytes=167010304 peak_private_bytes=90034176 reserve_floor_bytes=2576980378 tolerance_percent=20
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
```

The guard SHA-256 was
`A9D3496E3789F16182D3F6946860BC7454F86AEC407FB9BFFE352D1F4FED7FE1`; no
warning or test failure appeared. The new source/test paths were also checked
with the following bounded local batch, which uses only mocked process objects:

```text
python -m py_compile tools/direct_mask_contract/lean_adapter.py tools/direct_mask_contract/test_calculator_v2.py
python -m unittest tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_lean_adapter_rejects_receipt_replacement_and_malformed_output tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_lean_adapter_bounded_output_and_finalization_faults
```

The exact local result was:

```text
..
----------------------------------------------------------------------
Ran 2 tests in 0.218s

OK
```

The local command exited `0`; it did not rebuild Lean, invoke the formal
checker, or launch a real process. The new test covers fast-exit stdout and
stderr overflow, signal failure plus cleanup-tool exception, root-exit
unresolved descendants, and reader completion after escalation failure. The
guarded seven-test result is the authoritative affected verification; the local
two-test result is supplemental and overlaps on the receipt negative-path test.

### Final owned-wait exception correction

Source review found one remaining owned lifecycle branch: after a limit-triggered
cooperative stop, a non-`TimeoutExpired` exception from the first `process.wait()`
was recorded but did not invoke owned-tree escalation. The adapter now routes
that branch through the existing identity-bound `_terminate_owned_process_tree`
helper, attempts the bounded second wait, preserves both the original wait error
and any cleanup/escalation error, and then completes reader and pipe
finalization. No root-only kill or shared-guard change was introduced.

The direct Engine handoff reran the exact seven affected tests through the
unchanged guard, with run suffix `lean-security-seven-20260919-c`. Child stdout
was empty and child stderr was exactly:

```text
.......
----------------------------------------------------------------------
Ran 7 tests in 7.066s

OK
```

The exact decisive outer-guard output was:

```text
PHYSICAL_PREFLIGHT free_bytes=4206432256 reserve_bytes=3221225472 reserve_floor_bytes=2576980378 tolerance_percent=20
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=14 min_free_bytes=4089335808 reserve_bytes=3221225472 peak_working_set_bytes=162717696 peak_private_bytes=89358336 reserve_floor_bytes=2576980378 tolerance_percent=20
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
```

The guard SHA-256 remained
`A9D3496E3789F16182D3F6946860BC7454F86AEC407FB9BFFE352D1F4FED7FE1`; no
warning or failure appeared. No Lean rebuild, leanchecker run, native compile,
unsafe probe, shared-guard change, or other-repository change occurred.

### Preserved failed attempts and intermediate evidence

No failure was suppressed or weakened. The guarded component passes before the
whole build were exit `0`, with no warnings and cleanup/mutex release:

```text
RowBoundsSupport.lean  min_free_bytes=5159051264 peak_private_bytes=1337819136
RowBoundsTerms.lean   min_free_bytes=5033996288 peak_private_bytes=1294839808
RowBoundsH0.lean      min_free_bytes=5142151168 peak_private_bytes=1268146176
RowBoundsH1.lean      min_free_bytes=4897935360 peak_private_bytes=1294036992
RowBoundsH1Outer.lean min_free_bytes=4711469056 peak_private_bytes=1282719744
RowBoundsFS1.lean     min_free_bytes=4260872192 peak_private_bytes=1294700544
RowBoundsFS2.lean     min_free_bytes=4392054784 peak_private_bytes=1294643200
RowBoundsFS3.lean     min_free_bytes=4357140480 peak_private_bytes=1303052288
RowBoundsZero.lean    min_free_bytes=3926990848 peak_private_bytes=1286918144
RowBounds.lean        min_free_bytes=4295266304 peak_private_bytes=1294467072
WidthBoundsDefinitions.lean min_free_bytes=4341641216 peak_private_bytes=1267245056
WidthBoundsCaps.lean  min_free_bytes=4442386432 peak_private_bytes=1295298560
WidthBounds.lean      min_free_bytes=4462698496 peak_private_bytes=1295790080
```

The helper-heavy RowBoundsTerms version reached the fixed process cap with
minimum free `4133990400` and peak private `2035912704`; earlier RowBounds
attempts reached it with peak private `2013884416` and `2024583168`. The first
WidthBoundsCaps source pass reported:

```text
WidthBoundsCaps.lean:9:48: error: unexpected token '∧'; expected ':=', 'where' or '|'
WidthBoundsCaps.lean:18:48: error: unexpected token '∧'; expected ':=', 'where' or '|'
```

The first WidthBounds pass reported unknown `pow2Frac` at lines 14 and 88 and
four `fs3Bound` type mismatches at lines 53, 68, 127, and 142. These were
corrected with `open ExactFrac` and definitional `change` steps; the corrected
modules passed.

Two Theorems attempts did not launch and returned exactly:

```text
RUNNER_FAILURE reason=mutex is already held: Local\BlindLedgerDirectMaskBuild20260907
```

The authorized retry also returned the same condition after preflight
`FREE_PHYSICAL_BYTES=5020553216` and `HEAVY_PROCESS_COUNT=0`; the read-only
process inventory found no runner, Lean, Lake, checker, or compiler process to
terminate. After the engine owner released the lane, the first whole parallel
Lake build reached the unchanged process cap with
`min_free_bytes=4279042048` and `peak_private_bytes=2332090368`, returning:

```text
GUARD_STOP label=Command reason=owned process tree reached memory cap during Command
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
```

The attempted `lake build -j 1` correction launched no child and returned:

```text
error: unknown short option '-j'
```

The adapter was then changed to the explicit sequential `+Module.Name`
targets used by the successful 34-job build. The guard, reserve, process cap,
mutex, and trust checks were not weakened.

## Immutable identities

- Read-only input base commit: `14deec37b1ab08f403598972b24f8328c6e77ab4`
- Read-only input base tree: `05f3cc1fc5cf79e704bcb4843ff0b4d6fb1eca69`
- Writable child: `work/lean-security-20260913`
- Pre-commit child HEAD: `b844c5cab68964f0d09d72653dbe9aa79273d9be`
- Pre-commit child HEAD tree: `2fa148fee6e58d0f4a4f01a8fa103f8a7e1f574f`
- Lean toolchain: `leanprover/lean4:v4.33.1`
- Build ID: `BL-SECURITY-ARITHMETIC-20260913-V1`
- Schema ID: `BLSECAR01/v1`
- Historical baseline theorem manifest count: `19`

Final Lean source SHA-256 values before this evidence file was added:

```text
9681D6AC383245540082DF96D162AC8FCDC1BCFB7E22B7E5D0E318F09085E631  formal/lean/BlindLedger.lean
7F9172F7150490233C1340EF49F371BF9D4DA1E691ACB9D7AA1069B48B86AE6D  formal/lean/BlindLedger/Arithmetic.lean
E546E69C8E64A6F0C63BA30DED3B3FDC86831C8BDCA205AAFCB5D00363F847FD  formal/lean/BlindLedger/AxiomCheck.lean
9FB055B1BC9A3F3A190335ADADE2B686C3E714EF795F5E18BE2D4306DA95686B  formal/lean/BlindLedger/SecurityExecutable.lean
2E116A2F6BCE440A2C342376A291360B8088A1AD3F53ABFF3C765B09512F070A  formal/lean/BlindLedger/Theorems.lean
080C51C9BB3A6167EE1EFE6ABE6DB2DD8353881368E8E343E5C67D5A0D11A68A  tools/direct_mask_contract/calculator_v2.py
5525FBE74A70BDD1CD436E1D75727E0550F92B88E4AD0E66CCAE8FD8FACC0659  tools/direct_mask_contract/lean_adapter.py
6E3B96057A32018BD2663CF27DDCDACE5D2A1889237727549F8FE556361D6F5B  tools/direct_mask_contract/test_calculator_v2.py
```

Final executable identity:

```text
path=formal/lean/.lake/build/bin/blind_security_arithmetic.exe
length=108988928
mtime=2026-09-13T12:24:32.3716494-04:00
sha256=453E4AE16519B6184F1A1FF5B178506E4DB4B57EC1C02ED0AF6ECDDE9DB44E1B
```

The executable mtime is later than the newest Lean source mtime
(`Arithmetic.lean`, `2026-09-13T12:13:13.0853553-04:00`). The adapter rejects
missing, stale, wrong-toolchain, malformed, nonzero-exit, or theorem-receipt-
mismatched artifacts.

## Guarded build and source axiom check

Command:

```text
python -c "from tools.direct_mask_contract.lean_adapter import build_formal_arithmetic_for_test; print(build_formal_arithmetic_for_test(), end='')"
```

The helper uses the existing guarded runner
`work/pq-wide-seed-native-20260913/build-filter-native/run_guarded_v3.ps1`,
mutex `Local\BlindLedgerDirectMaskBuild20260907`, a 1,073,741,824-byte
physical reserve, exact child-tree cleanup, pinned Lake/Lean 4.33.1, and the
exact child-local generated executable as its only removable target. The final
outer evidence was:

```text
PHYSICAL_PREFLIGHT free_bytes=5098143744 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=9 min_free_bytes=4332503040 reserve_bytes=1073741824 peak_working_set_bytes=762281984 peak_private_bytes=1294708736
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
```

The complete final child log was:

```text
✔ [10/10] Built blind_security_arithmetic:exe (2.2s)
Build completed successfully (10 jobs).
'BlindLedger.SecurityArithmetic.cap_counters_well_formed' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_eff_completion_accounting' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_alg_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_eff_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_hist_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.p_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.switching_counted_once_at_caps' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_alg_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.q_eff_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.q_hist_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.p_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.remaining_nonnegative_on_admissible' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.cap_qrom_bound_lt_quarter' does not depend on any axioms
'BlindLedger.SecurityArithmetic.cap_adaptive_square_lt_remaining_square' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width384_partition' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width512_partition' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_zero_max_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_one_max_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_zero_simplified' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_one_simplified' does not depend on any axioms
'BlindLedger.SecurityArithmetic.theoremManifest_count' does not depend on any axioms
'BlindLedger.SecurityArithmetic.cap_theorem_bundle' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width_partition_bundle' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_certificate_bundle' does not depend on any axioms
```

The final build child stderr was empty. The standard Lean axioms
`propext` and `Quot.sound` occur only in the monotonicity/admissibility terms;
the cap, accounting, QROM, width, row, manifest, and bundle terms are
axiom-free in the trust-0 scan.

## Independent final verifier

The final guarded command ran both checks sequentially against the final binary:

```text
Set-Location -LiteralPath 'formal/lean'
$env:LEAN_PATH = 'formal/lean/.lake/build/lib/lean'
& '.../leanchecker.exe' 'BlindLedger.Theorems'
& '.../lean.exe' '--trust=0' 'BlindLedger/AxiomCheck.lean'
```

The complete child stdout was:

```text
CHECK=leanchecker
CHECK_EXIT=0
CHECK=axiomcheck
'BlindLedger.SecurityArithmetic.cap_counters_well_formed' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_eff_completion_accounting' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_alg_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_eff_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_hist_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.p_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.switching_counted_once_at_caps' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_alg_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.q_eff_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.q_hist_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.p_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.remaining_nonnegative_on_admissible' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.cap_qrom_bound_lt_quarter' does not depend on any axioms
'BlindLedger.SecurityArithmetic.cap_adaptive_square_lt_remaining_square' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width384_partition' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width512_partition' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_zero_max_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_one_max_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_zero_simplified' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_one_simplified' does not depend on any axioms
'BlindLedger.SecurityArithmetic.theoremManifest_count' does not depend on any axioms
'BlindLedger.SecurityArithmetic.cap_theorem_bundle' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width_partition_bundle' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_certificate_bundle' does not depend on any axioms
AXIOM_EXIT=0
```

The final verifier outer guard exited 0 with
`CLEANUP=PASS label=Command owned_process_tree=empty` and
`MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907`; its stderr
was empty.

## Focused consumer verification

Command and result:

```text
python -m py_compile tools/direct_mask_contract/lean_adapter.py
python -m unittest tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_lean_batch_accepts_runtime_and_caps_and_rejects_invalid_counters tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_filtered_constants_are_exact_and_e3_dominates tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_row_bound_is_maximum_not_union_and_simplifies tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_v3_endpoint_residual_resources_and_shake_boundary_are_explicit
```

```text
Ran 4 tests in 11.594s
OK
```

The tested consumer behavior includes:

- Lean `cap` PASS with manifest count `19`, theorem-term receipts, both width
  rows, and external-premise receipt.
- Valid Lean runtime counters PASS with `q=121`.
- Invalid runtime `R2=4097` REJECT with
  `error=counters-not-well-formed`.
- Lean row mode PASS for `j=0`, with maximum row bound `3/2^263` and the
  simplified-bound predicate true; the row test also exercises `j=1`,
  `j=2^32`, and `j=2^128`.
- Exact Python/Lean equality for `e0`, `eKOS`, `e2`, `e3`, the direct maximum,
  v3 width identities, and the v3 residual-resource boundary.

## Corrected intermediate failures

No failure was suppressed or weakened. The preserved intermediate results were:

- The first fresh build exited 0 but emitted four warnings that exponent `2112`
  exceeded the configured threshold `2048` at the four row theorem decisions.
  The arithmetic-kernel threshold was raised narrowly to `4096`; the final
  build emitted no warnings.
- The adapter then correctly rejected a stale executable with the exact error
  `formal_binary_stale_against_sources` because Lake did not relink after that
  non-semantic option-only edit. The test-build helper was corrected to remove
  only the exact generated executable before rebuilding.
- A retry using unsupported `lake build -R` did not relink; pinned Lake help
  confirmed no rebuild option. The helper now uses ordinary `lake build` after
  the exact target removal and typechecks `AxiomCheck.lean` under the guard.
- One corrected-build attempt stopped before launching a child with the exact
  error `RUNNER_FAILURE reason=mutex is already held: Local\\BlindLedgerDirectMaskBuild20260907`.
  No foreign process was killed. The next owner-released retry passed.
- The first parser pass found `TypeError: unsupported operand type(s) for |:
  'tuple' and 'set'`; the boolean field union was normalized.
- The next pass found `AttributeError: 'dict' object has no attribute
  'numerator'`; formal fraction payloads were returned directly at the
  certificate boundary.
- The following pass found missing boolean schema field
  `certificate.row.simplified_bound_holds`; the field was added and the final
  focused batch passed.
- One seven-test handoff command-construction attempt (`lean-security-seven-20260919-a`)
  did not run the test body: the child exited `1` with exact stderr
  `The filename, directory name, or volume label syntax is incorrect.` The
  unchanged outer guard still reported `CLEANUP=PASS` and
  `MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907`. The command
  was corrected to the successful `-b` run above; no source, native, or Lean
  changes occurred during the failed attempt.

Earlier shared-host resource incidents remain historical evidence and are not
claimed as successful gates: an Engine lane was stopped after its measured
working set exceeded its 4.5-GB native cap, and two accidental no-argument
`leanchecker` probes were stopped after hanging. The final checks used the
module-specific checker invocation only.

## Explicit skips and remaining gates

- The full 28-test `test_calculator_v2` execution was not run; 21 methods
  remain unselected after the six guarded methods and one new mocked fault-state
  method are counted uniquely. This preserves the instruction not to rerun the
  large availability calculation. No selected test invoked the large
  availability loops. The prior 27-method count applied before the new
  cancellation test; the current class count is `28`.
- No crypto/proof-suite, native protocol, source-custody, database, activation,
  deployment, PHI, payment, or production-selection gate was rerun or claimed.
- The generated child-local `tools/direct_mask_contract/__pycache__` remains
  untracked with `7` `.pyc` files (711,101 bytes), including both CPython 3.11
  and 3.14 test outputs. It is preserved and not staged.
- The guarded Lean build tree `formal/lean/.lake` remains untracked with `188`
  files in `7` directories totaling `113,248,929` bytes, including the verified
  executable. It is retained as build/checker evidence and is not staged; no
  generated build tree was deleted.
- `proofSuiteId=null`, `production_usable=false`, activation false, and
  selection false remain unchanged.
- The four external premises remain explicit: crypto reduction, primitive
  security, source custody/independence, and operations/RNG.
- The result is verified conditional arithmetic and a checked consumer binding,
  not whole-product qualification or production authorization.

## V2 theorem-manifest contract — verification complete (2026-09-22)

The 2026-09-22 change introduces a separate v2 executable and receipt
contract. Its build ID is BL-SECURITY-ARITHMETIC-20260922-V2, output header is
BL-SECURITY-ARITHMETIC/2, and schema ID is BLSECAR02/v2. The adapter reads only
formal/lean/artifact_receipt.v2.json and the v2 binary at
formal/lean/.lake/build-v2/bin/blind_security_arithmetic_v2.exe. The v1 binary,
artifact_receipt.json, and earlier v1 raw evidence remain historical; the v2
adapter rejects v1 protocol and receipt bytes.

The canonical inventory is the exact union of the 22 v1 manifest entries and
the 30 names previously printed by AxiomCheck.lean, with 20 names in common.
The two v1-manifest-only terms are width384_direct_constant_gate and
width512_direct_constant_gate; the ten checker-only terms are the row bound
components, two cap-row terms, theoremManifest_count, and three aggregate
bundles. The resulting ordered list has 32 unique names. Arithmetic.lean,
AxiomCheck.lean, SecurityExecutable.lean, the adapter, and the v2 receipt bind
the same ordered sequence. V2 output carries the count and comma-separated
names; the consumer rejects missing, reordered, duplicate, extra, malformed,
or wrong names. The receipt writer runs only after the guarded build and
Lean --trust=0 source check succeed.

### Guarded build and trust-0 source check

Command from the Security checkout root:

~~~text
python.exe -B -c "from tools.direct_mask_contract.lean_adapter import build_formal_arithmetic_for_test; print(build_formal_arithmetic_for_test(), end='')"
~~~

The unchanged shared guard had SHA-256
55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D,
nominal reserve 3,221,225,472 bytes, effective free floor 2,190,433,321 bytes,
32% tolerance, 2,000,000,000-byte process-tree cap, and mutex
Local\BlindLedgerDirectMaskBuild20260907. The physical preflight reported
free_bytes=4,460,814,336. The build child completed all 34 jobs and the
--trust=0 AxiomCheck; its stdout was 5,272 bytes and stderr was 0 bytes. The
complete child stdout is retained at
../pq-wide-seed-native-20260913/build-filter-native/guarded-command-lean-security-arithmetic-1790131158114285100.stdout.log.
Guard evidence: CHILD_EXIT_CHECK exit7=7 exit0=0;
CHILD_EXIT_STATUS label=Command exit=0; LIVE_PHYSICAL_SUMMARY samples=207
min_free_bytes=3,780,608,000 peak_working_set_bytes=780,910,592
peak_private_bytes=1,411,237,144; CLEANUP=PASS; MUTEX=RELEASED; outer command
exit=0. The receipt was written after these checks.

The complete trust-0 axiom output was:

~~~text
'BlindLedger.SecurityArithmetic.cap_adaptive_square_lt_remaining_square' does not depend on any axioms
'BlindLedger.SecurityArithmetic.cap_counters_well_formed' does not depend on any axioms
'BlindLedger.SecurityArithmetic.cap_qrom_bound_lt_quarter' does not depend on any axioms
'BlindLedger.SecurityArithmetic.cap_theorem_bundle' does not depend on any axioms
'BlindLedger.SecurityArithmetic.p_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.p_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.q_alg_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_alg_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.q_eff_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_eff_completion_accounting' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_eff_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.q_hist_cap_exact' does not depend on any axioms
'BlindLedger.SecurityArithmetic.q_hist_mono' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.remaining_nonnegative_on_admissible' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.row_bounds_certificate_bundle' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.row_bounds_one_max_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_one_simplified' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_simplified' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.row_bounds_zero_max_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.row_bounds_zero_simplified' does not depend on any axioms
'BlindLedger.SecurityArithmetic.switching_counted_once_at_caps' does not depend on any axioms
'BlindLedger.SecurityArithmetic.theoremManifest_count' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width384_cap_row_terms_le_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width384_delta_cap_all_k' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.width384_direct_constant_gate' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width384_partition' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width512_cap_row_terms_le_e3' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width512_delta_cap_all_k' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.width512_direct_constant_gate' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width512_partition' does not depend on any axioms
'BlindLedger.SecurityArithmetic.width_delta_all_k_bundle' depends on axioms: [propext, Quot.sound]
'BlindLedger.SecurityArithmetic.width_partition_bundle' does not depend on any axioms
~~~

Thus, all 32 declared names were printed by the source checker. The only
reported axioms are Lean's propext and Quot.sound; the output reports no
untrusted custom axiom.

The v2 receipt has SHA-256
2e1bde1e70e3492e361a4d725bafa23e48053f9804ec510566234886cbaa3367.
It records receipt version 2, toolchain leanprover/lean4:v4.33.1, 22 hashed
source paths, the exact 32-name manifest, and the shared guard identity. The
binary is 109,004,288 bytes and has SHA-256
bc4ada66767b817c6ad2f1fda6169731a4815a9c4ddb09e260593f4928e766d0. V1
binary and receipt identities are unchanged.

### Independent checker

Command from the Security checkout root:

~~~text
python.exe -B -c "from tools.direct_mask_contract.lean_adapter import run_independent_formal_checker_for_test; print(run_independent_formal_checker_for_test(), end='')"
~~~

The child and outer exits were 0. The pinned leanchecker child stdout and
stderr were both empty files (0 bytes each), which is its successful result.
Guard evidence: physical preflight free_bytes=4,452,040,704;
CHILD_EXIT_CHECK exit7=7 exit0=0; CHILD_EXIT_STATUS label=Command exit=0;
LIVE_PHYSICAL_SUMMARY samples=10 min_free_bytes=4,268,032,000
peak_working_set_bytes=220,917,760 peak_private_bytes=1,242,914,816;
CLEANUP=PASS; MUTEX=RELEASED. No guard or checker process remained afterward.

### Focused positive and negative consumer tests

The first test invocation used python -m unittest while the shared guard set
the child working directory to its own acceleration-correction directory.
The child exited 1 before entering any test body: unittest reported five
loader errors, each caused by
ModuleNotFoundError: No module named 'tools.direct_mask_contract'. The
complete 3,178-byte stderr remains at
../pq-wide-seed-native-20260913/build-filter-native/guarded-command-lean-security-v2-consumer-contract-20260922-1790131524825.stderr.log.
This was an invocation/import-root failure, not a failing assertion. The repo
root was then inserted into sys.path and the same five methods passed; the
suite was run twice after correction.

The corrected focused method set was:

- test_v2_manifest_source_and_axiom_checker_share_exact_inventory
- test_v2_manifest_consumer_rejects_identity_defects
- test_v2_consumer_rejects_v1_protocol_and_receipt_bytes
- test_lean_batch_accepts_runtime_and_caps_and_rejects_invalid_counters
- test_qrom_cap_and_half_success_probe_are_exact

The final run's complete raw child output was:

~~~text
test_v2_manifest_source_and_axiom_checker_share_exact_inventory (tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_v2_manifest_source_and_axiom_checker_share_exact_inventory) ... ok
test_v2_manifest_consumer_rejects_identity_defects (tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_v2_manifest_consumer_rejects_identity_defects) ... ok
test_v2_consumer_rejects_v1_protocol_and_receipt_bytes (tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_v2_consumer_rejects_v1_protocol_and_receipt_bytes) ... ok
test_lean_batch_accepts_runtime_and_caps_and_rejects_invalid_counters (tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_lean_batch_accepts_runtime_and_caps_and_rejects_invalid_counters) ... ok
test_qrom_cap_and_half_success_probe_are_exact (tools.direct_mask_contract.test_calculator_v2.FilteredContractV2Tests.test_qrom_cap_and_half_success_probe_are_exact) ... ok

----------------------------------------------------------------------
Ran 5 tests in 6.685s

OK
~~~

Final corrected-run guard evidence: physical preflight
free_bytes=4,410,290,176; CHILD_EXIT_CHECK exit7=7 exit0=0;
CHILD_EXIT_STATUS label=Command exit=0; LIVE_PHYSICAL_SUMMARY samples=14
min_free_bytes=4,334,731,264 peak_working_set_bytes=65,761,280
peak_private_bytes=60,538,880; CLEANUP=PASS; MUTEX=RELEASED;
OUTER_GUARD_EXIT=0. The final child logs are
../pq-wide-seed-native-20260913/build-filter-native/guarded-command-lean-security-v2-consumer-contract-final-20260922-1790131870665.stdout.log
(0 bytes) and
../pq-wide-seed-native-20260913/build-filter-native/guarded-command-lean-security-v2-consumer-contract-final-20260922-1790131870665.stderr.log
(1,077 bytes).

Final safety boundary: no lake, lean, leanchecker, or related guard process
remained, and a nonblocking probe acquired the shared mutex after the guard
reported release. The final tracked diff passed git diff --check with exit 0.
The v1 cache and receipt remain unchanged; no source was staged or committed.

This verifies the v2 conditional arithmetic executable, source axiom
inventory, independent checker result, receipt identity, and the selected
positive/negative consumer behavior. It does not qualify cryptographic
reductions, primitive security, source custody, randomness, transport,
durable state, availability, payment, PHI, activation, deployment, or product
selection. The nonclaims remain proofSuiteId=null,
production_usable=false, activation=false, and selection=false; the external
crypto, primitive, source-custody, and operations/RNG premises remain open.


## Independent checker executable identity verification (2026-09-23)

The v2 independent-checker invocation now holds read-only Windows handles for
the checker file and each directory from Path.home() through the checker path
while it hashes, invokes, and rechecks the executable identity. The returned
PINNED_LEANCHECKER_IDENTITY record includes checker SHA-256, size, receipt
SHA-256, run suffix, child exit, and outer guard exit. No v2 receipt/schema,
guard, theorem/axiom, v1 binary, or v1 receipt was changed.

Source identities after the implementation and test edits:
- tools/direct_mask_contract/lean_adapter.py: 73,884 bytes,
  SHA-256 753E7C60532D0E7533716FFB9D47FDF882BC51D1DF9C1E3EC3F5283A0829825D
- tools/direct_mask_contract/test_calculator_v2.py: 80,646 bytes,
  SHA-256 B04E77029F07CF05A0EE994D41373996E19983E79F71BF6A659B65757183AD97

Fresh checker preflight recorded checker size 115,200 and SHA-256
31B506F83737B7D629FD11699DF5AAF88C3B50BE23C28219E6B283F0DE98F85C; v2
receipt size 5,401 and SHA-256
2E1BDE1E70E3492E361A4D725BAFA23E48053F9804EC510566234886CBAA3367; v2
binary size 109,004,288 and SHA-256
BC4ADA66767B817C6AD2F1FDA6169731A4815A9C4DDB09E260593F4928E766D0; guard
size 15,327 and SHA-256
55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D.
Initial preflight free memory was 4,107,403,264 bytes, above the floor of
2,190,433,321; the mutex probe acquired and released; relevant process count
was 0. The guarded checker reported preflight free memory 4,218,249,216,
CHILD_EXIT_CHECK exit7=7 exit0=0, checker child exit 0, 9 live samples,
minimum free memory 4,114,972,672, peak working set 270,770,176, peak
private bytes 1,244,758,016, CLEANUP=PASS, MUTEX=RELEASED, and outer guard
exit 0. The parent driver exited 0. Post-run free memory was 4,308,205,568;
the mutex probe acquired and released; relevant process count was 0.

The exact guarded checker command was:
python.exe -B -c "from tools.direct_mask_contract.lean_adapter import run_independent_formal_checker_for_test; print(run_independent_formal_checker_for_test(), end='')"

Its returned identity record was:
PINNED_LEANCHECKER_IDENTITY run_suffix=lean-security-independent-checker-1790136340521635900 child_exit=0 outer_guard_exit=0 path=C:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\bin\leanchecker.exe sha256=31b506f83737b7d629fd11699df5aaf88c3b50be23c28219e6b283f0de98f85c size=115200 receipt_sha256=2e1bde1e70e3492e361a4d725bafa23e48053f9804ec510566234886cbaa3367

Checker child stdout and stderr logs are both 0 bytes, each SHA-256
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855:
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-lean-security-independent-checker-1790136340521635900.stdout.log
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-lean-security-independent-checker-1790136340521635900.stderr.log

The first guarded focused test attempt exposed a test-only mock target error.
The run had 5 tests, 1 error, child and outer guard exit 1; guard cleanup
passed and the mutex was released. Guard telemetry: 3 live samples, minimum
free memory 4,093,292,544, peak working set 117,977,088, peak private bytes
45,801,472. Post-failure free memory was 4,248,522,752; mutex probe acquired
and released; relevant process count was 0. The complete child stderr was:

~~~text
E....
======================================================================
ERROR: test_checker_command_quotes_path_components (tools.direct_mask_contract.test_calculator_v2.IndependentCheckerIdentityTests.test_checker_command_quotes_path_components)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\lean-security-20260913\tools\direct_mask_contract\test_calculator_v2.py", line 115, in test_checker_command_quotes_path_components
    with (
  File "C:\Users\neers\AppData\Roaming\uv\python\cpython-3.11-windows-x86_64-none\Lib\unittest\mock.py", line 1446, in __enter__
    original, local = self.get_original()
                      ^^^^^^^^^^^^^^^^^^^
  File "C:\Users\neers\AppData\Roaming\uv\python\cpython-3.11-windows-x86_64-none\Lib\unittest\mock.py", line 1419, in get_original
    raise AttributeError(
AttributeError: <module 'tools.direct_mask_contract.lean_adapter' from 'C:\\Users\\neers\\Documents\\Codex\\2026-09-04\\blind-ledger-astra-driver-v1\\work\\lean-security-20260913\\tools\\direct_mask_contract\\lean_adapter.py'> does not have the attribute 'Path.home'

----------------------------------------------------------------------
Ran 5 tests in 0.067s

FAILED (errors=1)
~~~

The failure log is 1,353 bytes with SHA-256
3B65CB79AB1FFE7E7F2E329711753B14D80033837E40B54CFB1A64FB533A3FD4;
the matching child stdout log is 0 bytes with SHA-256
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855.
The mock was corrected to patch lean_adapter.Path.home. A new fresh preflight
then recorded free memory 4,243,161,088 bytes (above the same floor), unchanged
checker/receipt/guard identities, mutex acquired and released, and relevant
process count 0.

The corrected guarded test command was:
python.exe -B -m unittest tools.direct_mask_contract.test_calculator_v2.IndependentCheckerIdentityTests tools.direct_mask_contract.test_calculator_v2.NativeFileIdentityLockTests

The corrected run had child exit 0, outer guard exit 0, 3 live samples,
minimum free memory 4,106,776,576, peak working set 118,407,168, peak private
bytes 46,821,376, CLEANUP=PASS, MUTEX=RELEASED, and test driver exit 0. The
complete child stderr was:

~~~text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.030s

OK
~~~

There were no warnings or skips on the corrected run. Child stdout was 0
bytes (SHA-256
E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855); child
stderr was 108 bytes (SHA-256
714F29415A01B3DC098655F670EDEDA6A83A69A59D0CC42DD4E2D8BB8D9B4148).
Post-test free memory was 4,217,266,176 bytes; mutex probe acquired and
released; relevant process count was 0. Logs:
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-lean-security-checker-identity-tests-1790136450120395000.stdout.log
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-lean-security-checker-identity-tests-1790136450120395000.stderr.log
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-lean-security-checker-identity-tests-1790136544095752300.stdout.log
- ../pq-wide-seed-native-20260913/build-filter-native/guarded-command-lean-security-checker-identity-tests-1790136544095752300.stderr.log

This verifies executable identity stability around the v2 checker run and the
focused identity and native lock tests. It does not prove the provenance or
identity of the .olean inputs: the v2 receipt does not hash those files.

## Source-level OLean and native-artifact provenance gate (2026-09-23)

This is a source-only gate definition. No `module_provenance.v1.json` receipt
was created, no provenance hash was pinned, and no new checker or build was
run. The adapter currently has
`EXPECTED_MODULE_PROVENANCE_SHA256 = None`; it fails closed while the sidecar
is absent or unpinned. The v2 receipt remains unchanged at SHA-256
`2e1bde1e70e3492e361a4d725bafa23e48053f9804ec510566234886cbaa3367`, and the
retained v2 executable remains size 109,004,288 bytes with SHA-256
`bc4ada66767b817c6ad2f1fda6169731a4815a9c4ddb09e260593f4928e766d0`.

The previous guarded checker invocation completed with exit 0, but the
checker target was only `BlindLedger.Theorems`. Its project import closure is
15 local modules. LeanChecker loads imported module environments and replays
constants from the selected target; it does not independently replay each
imported module. The executable links 16 project modules, including
`BlindLedger.SecurityExecutable`. The two direct external import roots are
`Std` and `Lean.Elab.Tactic.Omega`. A read-only inventory of the installed
toolchain currently finds 2,485 main `.olean` files (353,835,856 bytes),
2,483 `.olean.server` files (31,806,176 bytes), and 2,483
`.olean.private` files (1,346,539,128 bytes), 7,451 files totaling
1,732,181,160 bytes. It finds zero `.olean.hash` files. The full external
closure actually loaded by the checker has not been derived and hash-bound.

The following are raw hashes and sizes read from the retained
`formal/lean/.lake/build-v2` tree on 2026-09-23. They are unpinned snapshots,
not evidence that these files were built from the receipt's sources or used
to create the pinned executable. The table contains all 16 main project
`.olean` files, generated C files, and native `.c.o.noexport` objects:

Each main project `.olean` also has a `.olean.hash` cache file. The inspected
project tree has no `.olean.server` or `.olean.private` files. Lake's `.olean.hash`
fingerprints are not content attestations and are not accepted by this gate.

| Module | OLean bytes / SHA-256 | Generated C bytes / SHA-256 | Native object bytes / SHA-256 |
|---|---|---|---|
| `BlindLedger.Arithmetic` | 1,285,288 / `e4bc494696dc102632893715b5cc79d657fd6600e8cfd422e0b773c654cf7b91` | 209,506 / `60d4b868fd863fb29bdd4af403c77fdc04eda819aa1b427225175e33ee7dfa73` | 172,071 / `f4190ab44b26fb7560e9a58088c0f66141a0a49d840bcf5ce1c215d9c5fd4c96` |
| `BlindLedger.RowBounds` | 9,384 / `031696db6107833f0cbfc2464195125b09b05a8af72e86712bff6e29ee069d76` | 3,201 / `7b60477c9c57369a94aff95d7bf270bbb2133bbcea3b85e8ca0145bb30b466f8` | 3,364 / `b707aa7e0cc0d7f7e4be0587ae6bc8cd2ea1cd2f758ce33ff61a1274f88a22d4` |
| `BlindLedger.RowBoundsFS1` | 8,560 / `d711252dd9aec44efe63b781cee719dc01d0306a8773693351178b706eedbe8a` | 1,434 / `5f81ef118e9441fb136c73c038b4055841973ba8b4008940fdc9791b5084b10b` | 1,822 / `e5786c737af06035c037dadc0aafb2619501ade8c5caab4a01416e57d99fc339` |
| `BlindLedger.RowBoundsFS2` | 8,560 / `a0bcb2a8c37579276af3c280b7d4bab31998702305b655210d071f008bb8b71f` | 1,434 / `270f2ff98525203438bf0e5cd6c0c14d87ff5b9a270fde63d839563b6bc7d14f` | 1,822 / `bd7f0125d0dc18074096711860c937c6a37c0f75dd63c9da45b335ebd8be3292` |
| `BlindLedger.RowBoundsFS3` | 7,768 / `635f98dc5f73fe941ce55d2753f279e63f54a53579dc0b0c4c2e92fd07827b47` | 1,434 / `2b6d5f965643aadb41851ee3318099552019463e52ca65142aa581d596db979a` | 1,822 / `571717d88c12ffaf7cb1a096d715dc00e92a8f339bd5da2961443f25e13c7271` |
| `BlindLedger.RowBoundsH0` | 8,248 / `6bdc6f613255d17a715b09bd9186dced3535e40bf5adb25e4e924093af3fde60` | 1,432 / `67feeb666faf74f49789d102c5281fd92ab152df053b902a841c2f4d7b5fa7f0` | 1,819 / `877ece3f3eedec23f82a46d4b146e5aaa552db5ed2a7da1f1a9784d67ddb7b1a` |
| `BlindLedger.RowBoundsH1` | 10,000 / `1b21827d5fd3a3256334f2b92fdc68abbc32d96cb935a2c520329e320319be3d` | 1,432 / `70333fe30863b272111569ef908f0374df2419d9a8ae0bb921e17f14de70344c` | 1,819 / `7924a6dd0152717cd3dfd77529885766854d45069c962e4d3b57478695818bb6` |
| `BlindLedger.RowBoundsH1Outer` | 10,016 / `c51ad6d8c53bb5b0dc1d04428851da1334d4c9983ac1391044b4b23ba8bf440a` | 1,442 / `ca428238671bdcd9407e9d218df0e578854ae7fd3f93290547f5ac438bbf0f3a` | 1,834 / `5f283bb6258727f187a40367136ef2ec5f1072d74b960256ab970ec0f03df6cf` |
| `BlindLedger.RowBoundsSupport` | 199,208 / `02aca185d65fe3c1e268ddc8df138d060e9eddfa73087542b2c6f25201d3a808` | 1,430 / `30f8c159376ce94b2f9d3feeeb1e3e0c04c0a1425a4bc4951ec1de9bf36108bf` | 1,830 / `498962d001f6882de3e61fe67dc66dfaef0073830490e7c4e1d1bd982e724edc` |
| `BlindLedger.RowBoundsTerms` | 71,504 / `2ceb098f1a9e0608637bdf0b03b7cfeba683f0cddee244fa8cf7f2d01f07fe8e` | 1,444 / `ba96606b09f5408b8ec4266af02af97fa251dce8878c945954726b8de5a76ec9` | 1,830 / `b7c5f0d1f3282f57213b1714c637bd16f2ac7afe343424571bb1cc3f6771c2fe` |
| `BlindLedger.RowBoundsZero` | 7,568 / `0bdaefd1de5236c68b7b24e80e7d302987c6c6ca5aed42d888084bd51a42ad8b` | 1,430 / `bcf3c1c5aa126a020908ccb400cd2408c2c67985590dc71a4cd96554ba4641c9` | 1,823 / `52efe0e8e98636035f8cdb5107c550e284f54e1e356db982f6b3c07b87074d68d` |
| `BlindLedger.SecurityExecutable` | 865,672 / `29193ec24b9803d39d89c905b1d5a970293450d9131d61b2667a26b7ade36731` | 466,963 / `94c5920f711c83816668cce8f44d46e0f8da73194267d005a8c22f5bf527cc10` | 305,561 / `b3aa84e03519eae94458329b76d37b18e041dae8154af5b3ec48e63c3d64a16a` |
| `BlindLedger.Theorems` | 47,920 / `6806a2f182e109ca84bc7a7a4112da75eac061de2b95b37346015a6c58ce4844` | 7,445 / `23a94cee14ce481775e4427c0c425247cd3d8d2e5a7b4b17a2aa163730f61f8b` | 4,951 / `989771f52b3cad727b42f2983b2a6ca3c790803dc9b758fb28f36dcced585d4a` |
| `BlindLedger.WidthBounds` | 80,672 / `520b371cadae0572697ab0efd10bdf6ba1d985ad7f0bf35027dd8723d09b25ee` | 1,435 / `286f6e83066f856b749eb7a134f8fd2765042661778f8239b913e234e003e17a` | 1,820 / `4a7975c378aae8d6347a4bbbc9d9de5b8abd18d164e393a8aeba64c8bbb4fc8f` |
| `BlindLedger.WidthBoundsCaps` | 13,248 / `ad34eb775bfc86c717f254080a076b3f89eec3517fcc1e51e02cb18352a6dcc9` | 1,464 / `17eb585f37cbd7f83cb8a427fa42a0ccbe92ef33511a925b09fa27c351081bc2` | 1,839 / `223b3bc1e41d52701e918978fbc8feaafcccb78f5011001e6767f61bbdb5d9c2` |
| `BlindLedger.WidthBoundsDefinitions` | 47,856 / `b49b5f43497ba75d380dd2c6db5685dd633746c5581f74575c13f38f919b7c1d` | 16,470 / `e6c0e5fe5864abcbfc089ca3ef8c6538b60b15d53b8a9dfb73ef0bd698f8a6a7` | 19,730 / `48a2d45b141b83f9652dc3f5c4bcd5e2e6e1684872eb0d85cd7973bb0c55dac7` |

The retained response file is 3,915 bytes with SHA-256
`771e229d7952679bff6633a8d3484ff02aaaa280c354a1090fa8ea182e66f609`; the
Lake link trace is 4,632 bytes with SHA-256
`553aff20757bf85fa147c200fc172ade5c9ba0e466308bb0df33a48aa724476b`; and
the toolchain `clang.exe` is 217,600 bytes with SHA-256
`1aea18dca98f91a6a7c65532adc2567efc775904d2a4bd28bf06731bc2c3778c`. The
current raw response file names all 16 project object files in link order and
includes `-Wl,--no-insert-timestamp`; it also names additional system
libraries. Their resolved file identities are not bound by the v2 receipt or
the new source-only schema.

The adapter now requires a separate v1 sidecar descriptor to bind each
retained module OLean/C/object to the corresponding artifact in a fresh,
isolated build directory. It compares OLean roles, sizes, and hashes; compares
generated C and object hashes; checks both response files for the same
normalized argument vector and project-object order; checks both link traces
for the exact 16 project objects and target triple; and requires the
reproduced executable's hash and size to equal the v2 receipt. The independent
checker invocation locks the v2 receipt, provenance sidecar, and exact
retained OLean inputs against replacement, then hashes the described output
inventory before and after the checker run. The sidecar schema also requires a
separate checker-run record containing the exact checker path/hash/size,
arguments, working directory, `LEAN_PATH`, run suffix, child and guard exits,
cleanup/mutex status, and guard stdout/stderr hashes. It binds that run to both
the complete described output inventory and a stable manifest hash. The
manifest hash excludes only the run record itself, avoiding a self-referential
sidecar hash while binding the build, source, checker scope, and artifact
descriptors. The checker helper emits a `CHECKER_RUN_JSON=` line whose parsed
value uses the exact typed `checker.run` schema, so it can be copied without
manual field coercion.

The sidecar stores hashes of the guarded wrapper's stdout and stderr, not the
raw wrapper transcript, and it does not record hashes of the checker child's
stdout or stderr. Preserve the complete helper output and wrapper/child logs
outside the sidecar for later audit. The trace parser rejects duplicate JSON
keys and validates object fingerprints as nonempty strings, the target-triple
fingerprint as the pinned Lean 4.33.1 canonical 16-character lowercase
hexadecimal `Hash` encoding, and the trace structure and project-object paths.
It does not compare object fingerprints with artifact content hashes or
compare object/target fingerprints between retained and rebuild traces.

Physical OLean/C/object/link-input hashing occurs in the independent-checker
helper. The v2 runtime and provenance qualification are separate contracts.
Default `_artifact_identity()` returns the existing ten-field identity for the
pinned v2 receipt, binary, theorem manifest, sources, tools, and guard; it does
not load the module-provenance sidecar. Ordinary cap/runtime/row calls retain
their existing v2 arithmetic behavior and receive no module-provenance,
formal-release, or production-qualification credit. The checker path opts in
with `require_module_provenance=True`; a missing or unpinned sidecar fails
before the checker process starts.

`_invoke` holds read-only Windows handles to the executable and its parent
directories across the locked identity check, process launch and wait, and
post-run identity check. The file handle denies write/delete sharing, binding
the executable path used by the child to the verified file and blocking a
swap-and-restore ABA during execution. A prelaunch mismatch, process failure,
post-run mismatch, or lock-release error prevents a result from returning to
the caller or its cache. Parallel readers remain permitted by the handle's
read sharing. The new negative fixture attempts write and replacement during
launch while the lock is held; it has not been run in this source-only stage.

The existing `build_formal_arithmetic_for_test()` helper rebuilds in the
retained `.lake/build-v2` tree. Its failure rollback restores only the v2
executable; it does not restore OLean/C/object outputs. It must not be used for
a provenance rebuild. No isolated provenance rebuild was performed or
qualified here; the next owner must use an isolated build directory while
preserving the retained tree and receipt, or leave the rebuild unverified and
the sidecar pin unset. New source fixtures cover missing and swapped OLeans,
divergent rebuild outputs, malformed link-trace input and object entries,
duplicate trace JSON keys, invalid target-triple hash encodings, checker-run
JSON serialization, checker-run inventory and manifest mismatches, the mocked
symlink/reparse rejection branch, stale receipts, orphaned private OLeans,
runtime identity without provenance, a pinned v2 operation with an absent
sidecar, explicit checker-side sidecar failure, and the executable
swap-and-restore attempt. None has been executed in this stage.
The role gate rejects a `.olean.private` file without `.olean.server` as a
fail-closed schema policy; this is not asserted as a general Lean artifact
dependency. The retained project tree currently has zero server/private
sidecars.

This does not yet establish the complete provenance chain. The safe-lane
handoff must generate the sidecar from a fresh Lake rebuild while preserving
the retained `.lake/build-v2` tree, then independently review the full
toolchain OLean import closure and every resolved linker library/runtime input
before any receipt hash can be pinned. The `toolchain_modules` walk and
external OLean import graph are declared by the sidecar; neither is an
independent derivation of the exact checker-loaded closure. That closure must
be derived from the pinned checker/toolchain behavior, compared as an exact
module set, and each loaded artifact hashed before pinning. The response file
can carry non-project link arguments, and its `-l` entries are not resolved to
and hashed as files. Project object trace fingerprints are only checked as
nonempty strings; the target-triple fingerprint is shape-checked but not
matched to an expected value or compared across retained/rebuild traces.
Object/target fingerprints are not reconciled across those traces. Resolve and
hash the actual external linker inputs and compare verified trace fingerprints
before pinning. No source-to-OLean-to-C/object-to-binary provenance claim is
made before those gaps are closed and the output hashes match.

The independent checker helper explicitly requires a pinned sidecar. After the
dependency gaps are closed, the safe lane must exercise the two-step record lifecycle:
pin a reviewed provisional sidecar, run the independent checker, copy its
`CHECKER_RUN_JSON` object into `checker.run`, then compute and review the final
sidecar hash. The manifest fingerprint excludes `checker.run`, so this update
does not change the checker input manifest or output inventory. This bootstrap
sequence has not been run or verified in the source-only stage; the final pin
remains unset.

Static checks only: `python -B` AST parsing reported `AST_PARSE=PASS files=2`
(exit 0); `git diff --check` exited 0 and emitted these line-ending warnings:

~~~text
warning: in the working copy of 'formal/lean/ARITHMETIC_EVIDENCE.md', LF will be replaced by CRLF the next time Git touches it
warning: in the working copy of 'tools/direct_mask_contract/lean_adapter.py', LF will be replaced by CRLF the next time Git touches it
warning: in the working copy of 'tools/direct_mask_contract/test_calculator_v2.py', LF will be replaced by CRLF the next time Git touches it
~~~

Not run under the source-only stage restriction: all 59 test methods in
`tools/direct_mask_contract/test_calculator_v2.py`, 0 Lean builds, 0
`--trust=0` checks, and 0 leanchecker invocations. The shared guarded lane is
unavailable for this stage. No test, build, or checker result is claimed.
Required next action: guarded isolated rebuild and independent receipt review,
followed by pinning only after all outputs and dependency closures are
verified.
