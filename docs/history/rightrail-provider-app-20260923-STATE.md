# Provider App child state

Updated: 2026-09-23

## Identity and boundary

- Root: `work/rightrail-provider-app-20260923`
- Branch: `rightrail-provider-app-20260923`.
- Initial commit author identity: `Codex Agent <codex-agent@invalid.local>` via per-command Git config; local placeholder, not a mailbox.
- Scope: local, in-memory synthetic pre-submission core only. The initial source packet is restricted to the 23 paths named in the verified staging manifest; `work/` scratch remains untracked.
- Bundle: `RR-SYNTHETIC-PREFLIGHT/v1`, provenance `UNAPPROVED_SYNTHETIC_FIXTURE`.
- Product state: not deployable; no adoption, approval, or operational claim.

## Implemented source

- Closed typed request, fictional claim facts, source binding, fixed rule set, bundle provenance/lifecycle, result, and outcome types.
- Strict JSON byte adapter with duplicate-key and float rejection, closed schemas, 16,384-byte input/output bounds, depth limit 8, UTC/date validation, content digest validation, rule parameter validation, and publication/expiry/withdrawal chronology checks.
- Oversized integer parser `ValueError` maps to a fixed `InputError` code. The focused rejection case uses a 5,000-digit integer under the byte cap.
- Pure Python evaluator returns ordered `PASS`, `MISSING`, and `HUMAN_CHECK` results with explicit missing facts, rule citations, fixed reason codes, exact bundle binding, and a limitation string. The only bundle is unapproved and is blocked for `REAL_USE`.
- In-memory `preflight_bytes` adapter has no network, storage, logging, telemetry, support export, submission, payment, or State financial-owner path.
- Independent standard-library checker reconstructs request/bundle/result meaning without importing `provider_app`; tests exercise reconstruction and a deliberate result mutation.
- Request, rule-bundle, and result JSON Schemas; result rules use Draft 2020-12 `prefixItems` for the exact ordered five rule IDs and `items: false`. Optional `test` dependency provides `jsonschema`.
- 26 manually specified synthetic outcome vectors; 9 parser-rejection methods; vector, checker, schema, and lifecycle tests.
- Lean 4.33.1 pure decision source and narrow normalization/refinement contract. Source compiles with `--trust=0`; no executable linkage, theorem/axiom audit, or Python-to-Lean refinement claim.

All names, facts, amounts, categories, source labels, references, and effective periods are fictional. No real rule catalog or PHI is present. User-provided evaluation time is not a trusted clock.

## Verification and evidence

Checks ran only after Driver's direct shared-lane handoff. Guard: `C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\run_guarded_v3.ps1`, SHA-256 `55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`. Effective free-memory floor 2,190,433,321 bytes; private-memory cap 2,000,000,000 bytes; mutex `Local\BlindLedgerDirectMaskBuild20260907`. The inner command set cwd to this child.

### Python

Command: `python -B -m unittest discover -s tests -t . -v`.

- First run, before adding the schema negative: fresh free-memory estimate 3,877,687,296 bytes; 512 MiB expected workload headroom; floor plus headroom 2,727,304,233 bytes; mutex absent and relevant process count 0. Guard preflight 3,756,511,232 bytes. Child/outer exit 0/0; wrapper self-tests `exit7=7 exit0=0`; cleanup PASS; mutex released. Live minimum free memory 3,673,948,160 bytes; peak working set/private 65,957,888 / 44,027,904 bytes; process count 2 to 0. `Ran 12 tests in 0.047s` / `OK`; no failures or skips.
- Final run, including schema positive, duplicate, and shuffle checks: fresh free-memory estimate 3,837,575,168 bytes; 512 MiB expected workload headroom; floor plus headroom 2,727,304,233 bytes; mutex absent and relevant process count 0. Guard preflight 3,820,937,216 bytes. Child/outer exit 0/0; wrapper self-tests `exit7=7 exit0=0`; cleanup PASS; mutex released. Live minimum free memory 3,731,845,120 bytes; peak working set/private 109,969,408 / 75,870,208 bytes; process count 2 to 4 to 0. `Ran 13 tests in 0.051s` / `OK`; no failures or skips.
- Final Python stdout log: 0 bytes, SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.
- Final Python stderr: `C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-provider_app_python_20260923_02_schema.stderr.log`; 1,936 bytes, SHA-256 `50051B1D9212F7CEBEA7DA7C19F6D56F88F9A0AA100EA11B3D5303426B840EDC`. Contains all 13 `... ok` lines and ends with `Ran 13 tests in 0.051s` and `OK`.
- Earlier Python stderr: same guard directory, `guarded-command-provider_app_python_20260923_01.stderr.log`; 1,759 bytes, SHA-256 `F708A0DE661BCB32B826BFEA285DB31D48BC52F0DCCF4EC3B719682EA16E5A94`.

The final 13 methods comprise 9 parser rejection methods and 4 vector/checker/schema/lifecycle methods. The vector test checks all 26 expected outcomes and independent result reconstruction. The schema test checks Draft 2020-12 validity, one valid generated result, and rejection of duplicate and shuffled rule IDs.

### Lean

Toolchain pin `leanprover/lean4:v4.33.1`; compiler `C:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\bin\lean.exe`, SHA-256 `AF49BACFABAA1FEA71332CA0FEAE0FA1A60912219D5902291ADC79F905BFFB8D`. Reported version: `Lean (version 4.33.1, x86_64-w64-windows-gnu, commit 819816b2e0a3bf405af45ae5c7af2491d8f5bee6, Release)`. Guarded invocation used `--trust=0` on `lean/ProviderApp/Semantics.lean` with pinned sysroot and Lean library path.

- First attempt failed: fresh preflight free-memory estimate 3,838,193,664 bytes with 1 GiB workload margin; mutex absent and relevant process count 0. Child/outer exit 1/1; cleanup PASS; mutex released. Source at that attempt SHA-256 `77FDA8C6C31A2E088527716D09169B49C69874B29DCD1BC074B485D4B446933D`.
- Cause: `partial` at line 34 was parsed as a reserved keyword and caused cascading parser/type errors. The sole correction renamed the unused constructor to `partialFixture`; corrected source SHA-256 `744B03D2D73BD78C26F924DB1FD9F65819B861C643ABECCF82A09F0A82105C8B`.
- Complete failed diagnostics remain in `C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-provider_app_lean_20260923_01.stdout.log`, 3,494 bytes, SHA-256 `F46A7EFDB771386FBA17B4414D844A405C9255E07D62932F6F6DE38B8C430997`. This is the retained raw record; the task handoff includes the diagnostics.
- Corrected guarded compile: fresh free-memory estimate 3,777,441,792 bytes; 1 GiB workload margin; floor plus margin 3,264,175,145 bytes; mutex absent and relevant process count 0. Child/outer exit 0/0; wrapper self-tests `exit7=7 exit0=0`; cleanup PASS; mutex released. Minimum sampled free memory 3,259,305,984 bytes, 4,869,161 bytes below the preflight floor-plus-margin estimate and 1,068,872,663 bytes above the guard's effective floor. Peak working set/private 557,756,416 / 947,044,352 bytes; process count 2 to 3 to 0. Compile passed; it did not check a theorem or runtime link.
- Corrected Lean stdout log: `C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-provider_app_lean_20260923_02.stdout.log`; 104 bytes, SHA-256 `89C79D9C5B24343255F93BB0203AE89E6B8715C652DEF77008A34F37656C9C82`; contains only the version line. Both Lean stderr logs are empty with SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.
- Lean outputs were only in the guard build area: `.olean` 2,057,968 bytes, SHA-256 `94B4981B1313FCFA4B4EC918C6C7608010CE0576749D1FBDCF916998531737BD`; `.ilean` 52,914 bytes, SHA-256 `7FD0F0022C5DD09720478220F41AC127C9E967A4CE44B3FEFB2DDFC3AB4D7C6F`.

### Key source hashes

- `provider_app/codec.py`: `75912CA69D9FC55E8BE95460A37E941B2C15A9EAD617224B4C21E2F77D752673`
- `tests/test_input_rejections.py`: `6E6771202C9019D7F021A35B7FE9A70A2F287CD0518F057BD8CD9F9F1FCE4832`
- `lean/ProviderApp/Semantics.lean`: `744B03D2D73BD78C26F924DB1FD9F65819B861C643ABECCF82A09F0A82105C8B`
- `schemas/check-result-v1.schema.json`: `9BF4E567F0BDB3B659B3108CB62B6BBDB1A5BBF2C1107CEAD84C41E95605A24C`
- `tests/test_provider_vectors.py`: `72A1665AC10BEB0C61CF8A28E64A7B09412CFFEEEEB3BA664DCA5BAC7D054287`
- `pyproject.toml`: `87E166B813B320FC037F67C3ECAD6B04429FFD5211CE17984DF1E541446C55C2`
- `README.md`: `AF4F4D543F24AEA240DA2832945B2B029487FE6BB3EA681310F81DC391C1E34D`

## Skipped gates and remaining work

No Python method was skipped. Six broader checks remain unverified: package/build validation; Lean theorem and axiom review; executable Lean linkage; Python-to-Lean refinement or differential checking; benchmark; and selected-provider-profile resource measurement. No deployment, adoption, security/privacy, issuer, or production acceptance gate was run.

See `docs/PRODUCTION_BACKLOG.md`. Real issuer and provider decisions, approved rule provenance/scope, trusted source/time integration, use-specific security/privacy review, environment acceptance and recovery controls, selected-profile resource evidence, full Lean refinement/linkage review, and independent owner acceptance remain outstanding.

## Path incident and preserved artifacts

The initial patch operation resolved under the wrong base because the task working directory was nested one level deeper than assumed. Driver stopped writes, inventoried the result, collision-checked and SHA-verified the 11 intended files, and moved them into the authorized child before authorizing source-only continuation. I did not move files. I had no pre-write inventory of the unintended base and cannot certify that it was empty before the incident.

Two malformed unintended tiny artifacts remain untouched at `C:\Users\neers\Documents\Codex\2026-09-22\2026-09-04\blind-ledger-astra-driver-20260923-tmp\` because exact deletion was blocked by automatic review. Do not retry through another shell or interface:

- `schemas\rule-bundle-v1.schema.json`: 4 bytes, SHA-256 `E5E61FED291CEFE8BD2C2B895B3001E679931C3D93F3597FB5E27B5BCAE8F825` (literal `***` followed by newline).
- `STATE.md`: 0 bytes, SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.

Both are outside this repository and outside this child's write scope. No cleanup or further mutation was performed there.

## Nonclaims

This source does not establish issuer authority, rule rights, source truth, completeness, trusted time, provider identity, legal/privacy/security compliance, custody or retention, provider adoption, claim acceptance, coverage, clinical judgment, payer authorization, payment, operational capacity, deployment readiness, or safe provider operation. It is not integrated with a user interface, billing system, real provider source, or financial service.

## Safe-boundary handoff

After the corrected Lean run, Driver's fresh check reported the shared mutex absent, relevant workload process count 0, and shell exit 0, then transferred the lane directly to State for pending C05 correction tests. No further guarded work is authorized in this child.

## Bounded Lean comparison extension (in progress)

Assignment scope: add a nonactivating executable path over the normalized
synthetic facts and compare it with the existing Python evaluator, independent
checker, and 26 manually specified vectors. This extension does not transfer
application runtime authority from Python to Lean.

Source additions/edits currently present:

- `lean/ProviderApp/InputProtocol.lean`: closed, 2,048-byte-bounded
  `RRPA-LEAN-COMPARE/v1` argument parser; `Main.lean` now contains only the
  `RRPA-LEAN-RESULT/v1` projection serializer and executable entrypoint.
- `lean/ProviderApp/lakefile.lean` and `lean/ProviderApp/lean-toolchain`:
  Lake library/executable package pinned to Lean 4.33.1, with `-j1` passed to
  Lean module compilation. The executable depends on library roots `Semantics`
  and `InputProtocol`.
- `provider_app/lean_compare.py`: strict Python normalization, independent
  checker gate, source/toolchain/manifest/executable hash checks, a two-second
  child deadline, bounded input/output capture, bounded post-kill wait,
  fail-closed projection comparison, and refusal of non-UTC or fractional
  timestamps that the integer-second Lean protocol cannot represent exactly.
- `tests/test_lean_compare.py`: all-vector comparison plus malformed,
  oversize, wrong-version, divergence, timeout, retry, and zero-mutation
  cases, plus non-UTC/fractional timestamp rejection. The zero-mutation
  snapshot includes SHA-256 for each file.
- `lean/AdapterContract.md`, `README.md`, and
  `docs/PRODUCTION_BACKLOG.md`: protocol fields, omissions, limits, and
  assurance boundaries.

The guarded lane was handed directly to this child. A fresh preflight at
`2026-09-23T07:09:08.0778637Z` observed free physical memory
`3529695232` bytes, zero Lean/Lake/Provider executable/Python processes, the
shared mutex absent, guard SHA-256
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`, and
Lean/Lake executable hashes matching the pins below. The guard's own preflight
then reported `free_bytes=3522039808`, above its `2190433321`-byte floor.

### First guarded build attempt (failed; dependent tests stopped)

Command: guard `run_guarded_v3.ps1 -Mode Command`, suffix
`provider-lean-build-20260923t0710z`; its child changed directory to this
package and ran `lake.exe build providerAppLean` with Lean 4.33.1 first on
`PATH` and `ELAN_HOME=C:\Users\neers\.elan`. Guard SHA-256 was
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`.
Child exit was 1; the guarded outer command exit was 1. Guarded samples:
31; minimum free physical bytes `2899828736` (above floor
`2190433321`); peak working set `615108608`; peak private bytes
`1407475712` (below `2000000000`); maximum process count 4. Both guard exit
self-tests passed (`exit7=7 exit0=0`), child process cleanup passed, and the
mutex was released. No dependent Python tests were run.

Raw child stdout:

```text
✖ [2/4] Building Main (720ms)
trace: .> LEAN_PATH=C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\lib\lean c:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\bin\lean.exe C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\Main.lean -o C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\lib\lean\Main.olean -i C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\lib\lean\Main.ilean -c C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\ir\Main.c --setup C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\ir\Main.setup.json --json
error: Main.lean:1:0: unknown module prefix 'Semantics'

No directory 'Semantics' or file 'Semantics.olean' in the search path entries:
C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\lib\lean
c:\Users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\lib\lean
error: Lean exited with code 1
Some required targets logged failures:
- Main
```

Raw child stderr:

```text
info: providerApp: no previous manifest, creating one from scratch
info: toolchain not updated; already up-to-date
error: build failed
```

The preserved guard child logs are
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-provider-lean-build-20260923t0710z.stdout.log`
(SHA-256 `A1E5A4054B1C9B58610D06E6124F0E34C1E160A227E728C95319CF4DDDC5FD7B`)
and `.stderr.log` (SHA-256
`FE21609FD8CEEAE74A033CBBB7616711CA26CE36E3C51C4A656C9449879EEF44`).
Lake created `lake-manifest.json` with no dependency packages; the adapter
now includes that manifest in its identity gate. The source correction adds
an explicit Lean library root and executable dependency. No test result,
executable linkage, Python-to-Lean agreement, or resource profile is claimed.

### Second guarded build attempt (resource stop; dependent tests stopped)

After a fresh preflight at `2026-09-23T07:14:45.6523039Z` (free physical
`3683123200` bytes, no relevant processes, mutex absent, same pinned guard
and compiler hashes), `lake build providerAppLean` ran under the same guard.
The guard's preflight was `3662442496` bytes. It built `Semantics`, then
terminated the process tree when aggregate private bytes exceeded the
unchanged cap: observed peak `2009321472`, cap `2000000000`; minimum free
physical memory was `2841001984`, still above the `2190433321` floor.
There were 12 live samples, peak working set `1065672704`, and maximum process
count 5. Exit self-tests passed; child cleanup passed and the mutex was
released. The guarded outer exit was 1. No dependent tests were run.

Raw child stdout was exactly:

```text
✔ [2/6] Built Semantics (3.2s)
```

Raw child stderr was empty. Preserved child logs:
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-provider-lean-build-r2-20260923t0712z.stdout.log`
(SHA-256 `FAD96F55B3CF03C0305EDDC3AC7EE0146308639E67E5AA1924FDF0876FCE6E16`)
and `.stderr.log` (SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`).
Local pinned Lean 4.33.1 source documents `-j/--threads`; Lake exposes
`moreLeanArgs` for module compilation. The `-j1` setting constrains Lean
threads per compiler process, not Lake-wide jobs or aggregate memory. The
following measured retry still reached the cap.

### Third guarded build attempt (resource stop; dependent tests stopped)

Fresh preflight at `2026-09-23T07:18:56.1157780Z` reported free physical
memory `3567165440` bytes, zero relevant processes, mutex absent, and the
unchanged guard/tool/source hashes. The guard preflight was
`3552661504` bytes. This build used documented `-j1`. It again built
`Semantics`, then the guard terminated the process tree at peak private bytes
`2000666624`, which exceeded the unchanged `2000000000` cap by `6666624`.
Minimum free physical memory was `2703597568`, above floor `2190433321`;
peak working set was `1068089344`, maximum process count 5, and there were 13
samples. Guard exit self-tests passed; process cleanup passed and the mutex
was released. The guarded outer exit was 1. No dependent tests were run.

Raw child stdout was exactly:

```text
✔ [2/6] Built Semantics (3.7s)
```

Raw child stderr was empty. Preserved logs:
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-provider-lean-build-r3-20260923t0720z.stdout.log`
(SHA-256 `CBBC5045577AB40DB923C5613312BD8075EF0ED9FD7AC72CDCF7742C2F363CA2`)
and `.stderr.log` (SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`).

### Fourth guarded build attempt (Lean internal panic; dependent tests stopped)

Fresh preflight at `2026-09-23T07:22:43.8845796Z` reported free physical
memory `3498868736` bytes, zero relevant processes, and the shared mutex
absent. The guard preflight reported `3495428096` bytes. Guard, compiler, and
tool hashes matched the pinned identities. The build used `-j0` as a trial
thread setting. Lean failed while building `Semantics` with an internal panic;
this was not a resource-cap termination. There were 8 live samples; minimum
free physical memory was `2714755072` bytes, peak working set
`822173696`, peak private bytes `1895211008` (below the unchanged
`2000000000` cap), and maximum process count 4. Guard self-tests passed,
child cleanup passed, the mutex was released, and child/outer exits were 1/1.
No dependent tests were run.

Raw child stdout:

```text
✖ [2/6] Building Semantics (1.6s)
trace: .> LEAN_PATH=C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\lib\lean c:\users\neers\.elan\toolchains\leanprover--lean4---v4.33.1\bin\lean.exe -j0 C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\Semantics.lean -o C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\lib\lean\Semantics.olean -i C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\ir\Semantics.ilean -c C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\ir\Semantics.c --setup C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\rightrail-provider-app-20260923\lean\ProviderApp\.lake\build\ir\Semantics.setup.json --json
info: stderr:
INTERNAL PANIC: `IO.Promise.new` called before the task manager is running; this typically happens when called (directly or transitively, e.g. via `IO.CancelToken.new`) from an `initialize` block. Construct lazily on first use instead.
error: Lean exited with code 1
Some required targets logged failures:
- Semantics
```

Raw child stderr:

```text
error: build failed
```

Preserved logs:
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-provider-lean-build-r4-20260923t0724z.stdout.log`
(SHA-256 `BDC9D659298FE4B7DA4E8CCE45155FA0341C02C77749BD7A8BA2243C622B12F0`)
and `.stderr.log` (SHA-256
`C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F`).
`-j0` is rejected and is no longer configured.

The parser was split into `InputProtocol.lean`; `Main.lean` was reduced from
264 lines to the serializer and entrypoint, and the package is restored to
`-j1`. The previous whole-package `-j1` measurement remains the only workload
estimate: peak private bytes `2000666624`, exceeding the cap by `6666624`.
The split changes compilation into `Semantics`, `InputProtocol`, and `Main`
modules but does not support a lower peak estimate until measured.

### Fifth guarded build attempt (post-split resource stop; dependent tests stopped)

The parent directly returned the execution lane. Fresh source/tool/host
preflight at `2026-09-23T07:40:21.4719969Z` confirmed the expected root,
branch, HEAD, and tree; free physical memory was `3360518144` bytes. The
required conservative headroom was floor `2190433321` plus 1 GiB, or
`3264175145` bytes; this check passed. Relevant process count was 0, mutex
absent, guard SHA-256
`55A9655FFD4F4CB4EA779D1E6FE67507CC875D7BAD0AC52DB128E964B5581E3D`,
Lean SHA-256
`AF49BACFABAA1FEA71332CA0FEAE0FA1A60912219D5902291ADC79F905BFFB8D`, Lake
SHA-256 `565C3976275D79E104421014B6229F4FCF4A8C8EDFE164A43B344C91AF6F496C`,
and package toolchain pin `leanprover/lean4:v4.33.1`. The three Lean source
files total `24131` bytes versus `24004` bytes before the split, so the
historical `-j1` peak was retained without assuming a lower workload. The
guard's own preflight reported free bytes `3403264000`, reserve bytes
`3221225472`, reserve floor `2190433321`, and tolerance 32%.

Command: guarded `-Mode Command`, suffix
`provider-lean-build-r5-20260923t0741z`, intended child action
`lake.exe build providerAppLean` in the package with Lean 4.33.1 on `PATH`.
The nested PowerShell command had a quoting error: the outer PowerShell
expanded `$ErrorActionPreference` before child invocation, so the child
reported `Stop=Stop` as an unknown command. The remaining semicolon-separated
commands continued and Lake built `Semantics`; the guard then stopped the
owned process tree at the unchanged private-memory cap. Child/outer exit was
not a normal pair because the guard terminated the process tree; the guarded
outer exit was 1. The wrapper self-tests passed (`exit7=7 exit0=0`), cleanup
passed, and the mutex was released. No executable hash was pinned and no
dependent tests were run. The cap trip is the stop condition; no retry setting
or further build/test wrapper is authorized in this packet.

Complete guarded wrapper output:

```text
PHYSICAL_PREFLIGHT free_bytes=3403264000 reserve_bytes=3221225472 reserve_floor_bytes=2190433321 tolerance_percent=32
LAUNCH label=child-exit-7 pid=17588 command=cmd.exe
LIVE_SAMPLE label=child-exit-7 index=1 free_bytes=3408162816 working_set_bytes=0 private_bytes=0 process_count=0
CHILD_EXIT_STATUS label=child-exit-7 exit=7
LIVE_PHYSICAL_SUMMARY label=child-exit-7 samples=1 min_free_bytes=3408162816 reserve_bytes=3221225472 peak_working_set_bytes=0 peak_private_bytes=0 reserve_floor_bytes=2190433321 tolerance_percent=32
CLEANUP=PASS label=child-exit-7 owned_process_tree=empty
LAUNCH label=child-exit-0 pid=25508 command=cmd.exe
LIVE_SAMPLE label=child-exit-0 index=1 free_bytes=3397976064 working_set_bytes=0 private_bytes=0 process_count=0
CHILD_EXIT_STATUS label=child-exit-0 exit=0
LIVE_PHYSICAL_SUMMARY label=child-exit-0 samples=1 min_free_bytes=3397976064 reserve_bytes=3221225472 peak_working_set_bytes=0 peak_private_bytes=0 reserve_floor_bytes=2190433321 tolerance_percent=32
CLEANUP=PASS label=child-exit-0 owned_process_tree=empty
CHILD_EXIT_CHECK exit7=7 exit0=0
LAUNCH label=Command pid=39208 command=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
LIVE_SAMPLE label=Command index=1 free_bytes=3378425856 working_set_bytes=68059136 private_bytes=44613632 process_count=2
LIVE_SAMPLE label=Command index=2 free_bytes=3350892544 working_set_bytes=93634560 private_bytes=73490432 process_count=2
LIVE_SAMPLE label=Command index=3 free_bytes=3310223360 working_set_bytes=106278912 private_bytes=84688896 process_count=2
LIVE_SAMPLE label=Command index=4 free_bytes=3263279104 working_set_bytes=169508864 private_bytes=320110592 process_count=3
LIVE_SAMPLE label=Command index=5 free_bytes=3139575808 working_set_bytes=200495104 private_bytes=1023057920 process_count=3
LIVE_SAMPLE label=Command index=6 free_bytes=2791206912 working_set_bytes=550170624 private_bytes=1107582976 process_count=3
LIVE_SAMPLE label=Command index=7 free_bytes=2733666304 working_set_bytes=655933440 private_bytes=1348341760 process_count=4
LIVE_SAMPLE label=Command index=8 free_bytes=2701860864 working_set_bytes=682803200 private_bytes=1851400192 process_count=4
LIVE_SAMPLE label=Command index=9 free_bytes=2581422080 working_set_bytes=993628160 private_bytes=1982304256 process_count=4
LIVE_SAMPLE label=Command index=10 free_bytes=2570579968 working_set_bytes=1051623424 private_bytes=1979736064 process_count=4
LIVE_SAMPLE label=Command index=11 free_bytes=2563629056 working_set_bytes=1065664512 private_bytes=1991782400 process_count=4
LIVE_SAMPLE label=Command index=12 free_bytes=2560024576 working_set_bytes=1078341632 private_bytes=2028584960 process_count=4
GUARD_STOP label=Command reason=owned process tree reached memory cap during Command
LIVE_PHYSICAL_SUMMARY label=Command samples=12 min_free_bytes=2560024576 reserve_bytes=3221225472 peak_working_set_bytes=1078341632 peak_private_bytes=2028584960 reserve_floor_bytes=2190433321 tolerance_percent=32
CLEANUP=PASS label=Command owned_process_tree=empty
RUNNER_FAILURE reason=owned process tree reached memory cap during Command
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
GUARD_OUTER_EXIT=1
```

Raw child stdout, 33 bytes, SHA-256
`D04D8C8B44EEEFC8C224DC6615FD6C512D8E3E040D97A3EA63AD66DB80E47D35`;
guard log:
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-provider-lean-build-r5-20260923t0741z.stdout.log`:

```text
✔ [1/3] Built Semantics (3.6s)
```

Raw child stderr, 493 bytes, SHA-256
`FE863476B5F0C7AE2439F9950DEB5C7BFC0A26BEC43819F5142855B193863434`;
guard log:
`C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\guarded-command-provider-lean-build-r5-20260923t0741z.stderr.log`.
The following JSON string is the exact file contents, with `\r\n` encoding
the file's line breaks and its final blank-line space:

```json
"Stop=Stop : The term 'Stop=Stop' is not recognized as the name of a cmdlet, function, script file, or operable \r\nprogram. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.\r\nAt line:1 char:1\r\n+ Stop='Stop'; Set-Location -LiteralPath 'C:\\Users\\neers\\Documents\\Code ...\r\n+ ~~~~~~~~~~~\r\n    + CategoryInfo          : ObjectNotFound: (Stop=Stop:String) [], CommandNotFoundException\r\n    + FullyQualifiedErrorId : CommandNotFoundException\r\n \r\n"
```

After stop, fresh boundary query at `2026-09-23T07:41:53.3729786Z` reported
free physical memory `3376865280` bytes, relevant process count 0, exact mutex
absent, and the same guard hash. Safe-boundary check passed and the lane was
returned directly to Driver.

Static checks on the final source revision: Python AST parse passed for both
adapter/test files; six Lean source/toolchain/manifest pins matched their
file hashes; 12 Lean module/protocol shape checks passed; Markdown line-ending
and trailing-whitespace checks passed for four files; and `git diff --check`
exited 0. The executable hash remains `PENDING`, which fails closed. All seven
new focused test methods, including the 26 vector cases and their 104 expected
result-field comparisons, remain unrun because the guarded build stopped
before producing a verified executable. The original 13-method baseline was
run earlier and passed; it does not verify this extension. This source
extension does not introduce network, persistence, application logging,
telemetry, claims, PHI, production usability, or activation.

## Lean semantic-module segmentation (source-only; lane handoff pending)

On 2026-09-23 the typed normalized-fact semantics were divided along the
original definition boundaries into six importable modules. The former
14,132-byte `Semantics.lean` source was restored and SHA-256 verified as
`744B03D2D73BD78C26F924DB1FD9F65819B861C643ABECCF82A09F0A82105C8B`
before segmentation; it is now a 28-byte facade importing
`Semantics.Properties`. The split preserves the original definitions and
namespace boundaries; it changes module organization, not the Python
application authority.

| Module | Bytes | SHA-256 |
| --- | ---: | --- |
| `Semantics/Model.lean` | 2,894 | `99098C22327038F99E04AE9A16B8B27749C3095678472204E2CBE0FD19F2EA01` |
| `Semantics/Codes.lean` | 1,022 | `E48E0D7EF16962CBE84841B29CC1DEAB3F111F78AF619F45362FB45292722709` |
| `Semantics/Rules.lean` | 4,572 | `8F4828A4F950F7C6CEB0C567B99AD3BE02FD43F3750615B17FC97AA51F8F8BB4` |
| `Semantics/RuleEvaluation.lean` | 4,154 | `C0364A4BF766A538EC9474E8E682CEAB216802100D300D4E51538710B903533A` |
| `Semantics/Result.lean` | 1,114 | `BC64DEB2D19CF1073AD358F123D8B1D1DEE92622066B10E713A4A360E1994212` |
| `Semantics/Properties.lean` | 803 | `5876940158CAFEE511447B8635997C6369192470E545B6BF617083DE946883D6` |

The parser modules import `Semantics.Model` directly. Static source inspection
confirmed the adapter emits a 21-field fixed prefix followed by nine fields
per rule, and the Lean parser checks `fields.size == 21 + ruleCount * 9`,
validates the declared rule count and rule IDs, and bounds each rule interval
within the bundle interval. The comparison adapter uses only normalized
synthetic fields; the REAL_USE path blanks facts before Lean input and remains
blocked by the unapproved fixture. The parser remains a local diagnostic path
and makes no activation, payment, PHI, or formal-refinement claim.

`lakefile.lean` pins Lean module jobs at `-j1` and directs this revision to
`.lake/provider-lean-split-r7`; its SHA-256 is
`920671B6929BA574FAD5C427C0B2A3A70FC4277E67A0B5E4173A1E17288D588F`.
The adapter pins all 13 Lean modules and three package identity files: 16
source-map entries matched their exact file hashes. A source-only import-graph
check found 13 modules, 19 local import edges, and no cycles. The matching
field-layout source check passed. The executable SHA remains `PENDING`, so the
adapter fails closed; no executable or compile success is claimed.

One initial pin-inventory script reported `SOURCE_MAP_ENTRIES=16
LEAN_PINS=14 PENDING_ARTIFACT=True`, then stopped at
`unexpected source pin map shape`: its file-extension counter had included
`lakefile.lean` as a module. The 16 pin comparisons themselves had passed.
The corrected inventory excludes that Lake configuration file from module
counting and passed with `SOURCE_MAP_ENTRIES=16 LEAN_MODULE_PINS=13
PACKAGE_IDENTITY_PINS=3 PENDING_ARTIFACT=True`,
`SOURCE_PINS=PASS`, `LEAN_MODULES=13 LOCAL_IMPORT_EDGES=19 ACYCLIC=True`,
and `FIELD_LAYOUT=PASS fixed_prefix=21 rule_width=9; matching
decoder/encoder source checks present`. No repository file changed during
the initial script assertion.

No Lean compiler, Lake build, executable, test, checker, guarded command,
native tool, or benchmark ran during this continuation. The seven focused
comparison test methods remain unrun because there is no pinned executable.
The r1-r5 failure records above, including their raw output and historical
resource data, were left intact.

### Next action after direct lane handoff

After Driver has completed the Queue, State, Engine, and Security lane and
directly hands this child the execution lane, verify the current v4 guard,
pinned Lean/Lake identities, package/source pins, process/mutex boundary, and
a fresh target-specific start-memory threshold. Then run only
`lake.exe build providerAppLean` in `lean/ProviderApp` under the current v4
guard, with the child environment pinned to Lean 4.33.1 and the output kept
under `.lake/provider-lean-split-r7`. Use a quoting-safe child invocation
(for example a Base64-encoded PowerShell command) to avoid repeating the r5
outer-variable interpolation error. Preserve complete guard and child output.
If the split build completes, record its exact artifact hash before authorizing
the seven focused tests; do not run those tests if build, artifact identity,
or the guard fails. Stop on any source/tool/hash mismatch, unsafe fresh
preflight, guard stop, nonzero exit, or loss of the direct handoff. This plan
does not relax the v4 resource floor, mutex, cleanup, or raw-log requirements.

### Final source-only checks (2026-09-23)

The final read-only preservation check matched the recorded SHA-256 values
for all ten r1-r5 guarded child stdout/stderr logs. The module pin map
matched 16 of 16 source/package entries; the import graph had 13 modules,
19 local edges, and no cycles. Static Markdown checks passed on README.md,
STATE.md, lean/AdapterContract.md, and docs/PRODUCTION_BACKLOG.md with no
bare LF or trailing spaces.

`git diff --check` exited 0 and emitted this Git line-ending warning:
`warning: in the working copy of 'lean/ProviderApp/Semantics.lean', LF will be replaced by CRLF the next time Git touches it`.
No compiler, build, test, checker, guard, native command, or benchmark ran.

## Versioned Lean protocol hardening (source-only; v5 lane pending)

The Lean normalized-input parser now requires the REAL_USE fields at positions
5–11 to use the hyphen sentinel. The Python adapter already emits that shape;
this closes the direct executable input path too. The fixed v1 header, ASCII
byte bound, canonical decimal tokens, closed tag parsing, separator-count validation, exact 21 + 9n field
count, and deterministic v1 output layout remain explicit. The adapter still
pins the executable as PENDING and returns a fixed failure before invocation;
there is no Python fallback acceptance.

The focused negative coverage now includes unknown mode/scope/rule/semantic
tags, unsupported input and output versions, noncanonical counts, wrong rule
count, empty/missing/extra fields, trailing separators, a populated REAL_USE fact token, and output rule
tag rejection. The eight focused methods remain unrun.

| Path | SHA-256 before | SHA-256 after |
| --- | --- | --- |
| lean/ProviderApp/InputProtocol.lean | DC42B3547BBB3C2D1C4C3E273AD1E0B6767F9C0C1E4F68445040FFE977341744 | 573016427EE74B06092A9F885AACCAFDB025D834AF932F61F7EA3A1212630807 |
| provider_app/lean_compare.py | 9884978816B513CF095CB5FB59E93AB476D9643B1306D7E3467ACB35EAD02E1D | 6E622397986DA84B235414AA2478FE44831A713508B43D19F27C64EDD124C50D |
| tests/test_lean_compare.py | 0F30E57C64CEAD631E3930F4AC5FDBAB843BB08ECDC1C77118607660D9B01844 | F662B1C358A3A4BFA97D3DA9E3D077792478D9ABC844DA56F581CAF79E18E653 |
| README.md | 81496DEF026B1A5E5DA39709A0172AFE71C550350A15856737E69DBEBB40CDEC | D8A166F3247E1B8BC07B07EB3185E6D4E8F7F6EB98A0E8B4685BD08CEDDC3483 |
| lean/AdapterContract.md | 2FC6129EDD870719666CE8650373998AC0E88EDEF66094661E5D08CF2E19F8D0 | 5D48E827A4B29DCED0AC6632EA62E1D7BF40C479DCC14D55AE4163390627865E |

Source-only pin inventory: PIN_ENTRIES=16 PIN_MATCHES=16 ARTIFACT_SHA256=PENDING; STATIC_PIN_CHECK=PASS. The focused test source contains 8 methods. Markdown checks: README.md LF=30 CRLF=30 bareLF=0 trailing=0; lean/AdapterContract.md LF=127 CRLF=127 bareLF=0 trailing=0.

An initial diff check emitted this warning:
warning: in the working copy of 'lean/AdapterContract.md', LF will be replaced by CRLF the next time Git touches it
The inserted paragraphs were normalized to CRLF and rechecked; bareLF=0.

The final git diff --check exited 0 and emitted this warning:
warning: in the working copy of 'lean/ProviderApp/Semantics.lean', LF will be replaced by CRLF the next time Git touches it

No compiler, Lake build, test method, checker, guard, native tool, or benchmark ran in this continuation. Skipped execution gates: Lean executable build=1; focused comparison methods=8; standalone checker=0 runs; native/benchmark=0 runs. The assignment reports that the current v4 guard CIM preflight receives Access denied; this continuation did not retry v4 or start v5 because Driver has not handed off a reviewed lane. The r1–r5 raw records and all work/ scratch files were left untouched. Source remains synthetic, nonactivating, nonpayment, and non-PHI; Python remains the application authority.

## CLI diagnostic and identity pin completion (source-only; v5 lane pending)

`Main.lean` now maps parser failures through a closed fixed-code set, writes a
single diagnostic line to stderr, flushes it, emits no stdout, and exits with
status 2. Unknown internal parser codes reduce to `LEAN_PROTOCOL_MALFORMED`;
input is never echoed. The focused malformed-input test now requires an exact
one-line diagnostic of at most 64 bytes and empty stdout for every rejection
case. The successful CLI path still calls the Lean evaluator directly and
serializes only its deterministic fixed-code projection.

The exact Lake target was already present and is unchanged: package build
directory `.lake/provider-lean-split-r7`, Lean module argument `-j1`, library
roots `Semantics` and `InputProtocol`, and executable target `providerAppLean`
with root `Main` depending on `providerAppSemantics`. The adapter's Main source
identity pin now matches the updated executable source. The built executable
pin remains `PENDING`; Python comparison still fails closed and has no
semantic fallback.

| Path | SHA-256 before | SHA-256 after |
| --- | --- | --- |
| lean/ProviderApp/Main.lean | 4CC1B7F9292B21A3028860A386CAF67604E048FCBC7CAE0E97567DC4B49F89E7 | EE7AFDED9CB823044180E86226E810A494C9121000894A24F76C8139E5C6B829 |
| provider_app/lean_compare.py | 6E622397986DA84B235414AA2478FE44831A713508B43D19F27C64EDD124C50D | DF86B6EF8C3897DA5992B875B8FF05DAA2C10AE1AA3DFA640591993160555C60 |
| tests/test_lean_compare.py | F662B1C358A3A4BFA97D3DA9E3D077792478D9ABC844DA56F581CAF79E18E653 | 0B0380848D8A028682995AFB1525A9F176BEDA5B0474D3A3CAE19DB27E7C478F |
| lean/AdapterContract.md | 5D48E827A4B29DCED0AC6632EA62E1D7BF40C479DCC14D55AE4163390627865E | 0EDAC4EEA0EE0760F484E35370F96F566EAEDF7687BD1066B076578B5271E9A5 |

Static source identity inventory: PIN_ENTRIES=16 PIN_MATCHES=16
MAIN_PIN=PASS ARTIFACT_SHA256=PENDING STATIC_PIN_CHECK=PASS. Formatting
counts: Main LF=51 CRLF=0, adapter LF=629 CRLF=0, tests LF=329 CRLF=0,
AdapterContract LF=131 CRLF=131; all five checked files have zero bare LF
and zero trailing whitespace. git diff --check exited 0 and emitted only:
warning: in the working copy of 'lean/ProviderApp/Semantics.lean', LF will be replaced by CRLF the next time Git touches it.

No execution gate ran in this continuation; the eight focused methods remain unrun until Driver directly hands this child a finite reviewed lane.
The previous v4 CIM preflight Access denied is not retried here. All r1-r5 raw
records and work scratch remain untouched. Product state remains
`proofSuiteId=null`, inactive, nonpayment, non-PHI, and
`production_usable=false`.
