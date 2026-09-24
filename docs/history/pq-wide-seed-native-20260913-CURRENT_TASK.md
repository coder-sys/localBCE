# Completed DMV3 native evidence closure — 2026-09-13

## Objective and authority

This continuation reconciles the completed native run with its original guarded CommandExecution
records and records the current artifact identities. It is documentation-only: no native executable,
build, CTest, calculation, or new guard run is authorized.

The retained native source identity is commit
`ca9dba3f61374810d6677be1f7d1dd9f7ab761ad`, tree
`eccf7ac50e32068164b8ec802f78a597566d58aa`, parent
`45784ce6c317afb9e9e83e483a398c14a1715f54` / tree
`3a292ce7e24efda8df2a67533b17ce7e6ccb8cc6`. The accepted mathematical input is contract commit
`82f0cd3ad9b71e426aaee8410708c9bfab92992b`, tree
`3330c23ef976c34ec78d2b869ef398255dffe1ea`, specifically `bounded_generator_feasibility_proposal_v3`.
The separate privacy-certificate correction `14deec37b1ab08f403598972b24f8328c6e77ab4` /
`05f3cc1fc5cf79e704bcb4843ff0b4d6fb1eca69` changed only the contract calculator/test lane and
was not a native rerun input.

The current record head is `ab1e39b1a7daf3b6afd915c8e48106ec0602902e`, tree
`66ca11373c7385504bf33faa88eb6dc7277394ef`, parent `ca9dba3`. This head records
the recovered run and source-correspondence review only. It does not establish a
historical invocation-to-current-binary hash pairing; the original guard outcomes and
all failed or superseded predecessor evidence remain retained below.

## Current DMV3 identity

Fixed `w=512`, 64-byte seeds, `r=1312`, `nu=1823` bits serialized as 228 bytes, H0 squeeze 230
bytes, commitment 164 bytes, `m4=20068`, frame `544074`, signed `challenge_mode=3`, and transcript
prefix `BL/DMV/FAEST-256F/v3`. The final wire statement is 1147 bytes; nonces are 192 bytes,
`m1=506416`, `m2=15887`, and `m3=96`.

## Recovered original-run evidence

The original records were read from
`C:/Users/neers/.codex/sessions/2026/08/31/rollout-2026-08-31T15-44-50-01a0595a-5fc0-7430-be75-71a72e9a4ca5.jsonl`
with `FileShare.ReadWrite`. The exact invocation commands and call IDs are recorded in `STATE.md`.
The final guarded commands were:

```text
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'vole-build-clean-abs' -CommandPath 'C:\Program Files\CMake\bin\cmake.exe' -CommandArguments @('--build','C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\vole','--config','Release','--target','direct_mask_vole_probe','--','/m:1','/nologo')
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'vole-probe-v3-clean' -CommandPath 'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\vole\Release\direct_mask_vole_probe.exe'
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Configure -RunSuffix 'pipeline-configure-v3-normalized'
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Build -RunSuffix 'pipeline-build-v3'
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'transcript-oracle-v3-standalone' -CommandPath 'C:\Users\neers\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe' -CommandArguments @('C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\tools\direct_mask_vole\transcript_oracle.py','C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\vole\Release\direct_mask_vole_probe.exe')
& '.\build-filter-native\run_guarded_v3.ps1' -Mode CTest -RunSuffix 'fixture-ctest-v3'
```

The three final result lines are a `CHILD_EXIT_STATUS ... exit=0` line with the operation’s label,
cleanup PASS, and mutex release for each successful command. The final wire CTest outer record is
additionally retained in
full at the original call and wait records: `PHYSICAL_PREFLIGHT free_bytes=3181486080
reserve_bytes=1073741824`, `CHILD_EXIT_CHECK exit7=7 exit0=0`,
`LIVE_PHYSICAL_SUMMARY label=Command samples=121 min_free_bytes=2958135296
reserve_bytes=1073741824 peak_working_set_bytes=53800960 peak_private_bytes=34922496`,
`CLEANUP=PASS label=Command owned_process_tree=empty`, and
`MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907`.

The retained child results are:

- VOLE: `DIRECT_MASK_PROBE_COUNTS passed=71 failed=0`, `DIRECT_MASK_PROBE_STATUS=PASS`,
  `E2E_WIRE_SIZE bytes=543999 written=543999`, `E2E_VERIFY_STATUS status=0`, and
  `SOURCE_BOUND_COUNTS ... prover_calls=1 verifier_calls=1 counts_equal=1`.
- Oracle: `TRANSCRIPT_ORACLE status=PASS kat=3 mutation_vectors=3 h0_vendor=1 cache_vectors=1
  prefix=BL/DMV/FAEST-256F/v3 encoding=uint32le_length_delimited_parts`.
- Pipeline CTest: `100% tests passed, 0 tests failed out of 8`, 0 skips; probe checks
  `116/96/58/86 FAILED=0`, each `ALL_TESTS=PASS`, and all four real-symbol gates passed.
- Fixture CTest: `1/1 Test #1 ... Passed`, `100% tests passed, 0 tests failed out of 1`, and
  `NON_ACTIVATING_DIRECT_MASK_FIXTURE_PROBE cases=20 failures=0`.
- Wire CTest: `100% tests passed, 0 tests failed out of 3`,
  `WIRE_FRAME bytes=544074 written=544074 statement=1147 nu=228 nonces=192 m1=506416 m2=15887
  m3=96 m4=20068`, `PROCESS_REQUEST ... matches_prover_statement=true`, positive verifier exit 0,
  and `PROCESS_PIPELINE status=PASS cases=12 skips=0`.

The verifier is a separate process/link boundary with full transcript reconstruction, no
source-producer/source-proof dependency, and `witness_bytes_to_verifier=0`. It shares the
`direct_mask_vole.c` cryptographic implementation, so this is not a claim of independently
implemented cryptography.

## Artifact identity and limitations

The following are current filesystem hashes of retained binaries, not hashes recorded at runtime:

```text
build-filter-native/acceleration-correction/Release/direct_mask_fixture_probe.exe  length=41472  sha256=959151FF4FC2038608DC365D06297C30C29D63445394B4B1243321D99CE23B22
build-filter-native/vole/Release/direct_mask_vole_probe.exe                         length=282624 sha256=6F195A963C1E5BDC50D65095D7DA919DAAF74E210680CA251D4DDCBF8C04D5E7
build-filter-native/pipeline-v3/Release/dm_pipeline_probe.exe                       length=316928 sha256=03760E1066FDF445FAFE7B179917A932F46DE0E29729D49B3E93FD8BFCD163C1
build-filter-native/pipeline-v3/Release/dm_pipeline_source_cli.exe                  length=262656 sha256=2BCC0A5B78B493DBCCF53A9DE8638001FA643159DCAAA254745D6EE83BE3622C
build-filter-native/pipeline-v3/Release/dm_pipeline_verifier_cli.exe                length=232448 sha256=A4B27C04DC949C07F464983DCE24A8A90D6A433A8750AB79FB300961FF57EA94
build-filter-native/pipeline-v3/sp/Release/dm_source_proof_probe.exe                length=314368 sha256=E87B5F01F46A45DA8954AD084EFB0BFE4F6FCB4E59B8C9E1E7521F92B1BA9DBB
build-filter-native/pipeline-v3/sp/ap/Release/dm_authenticated_proof_probe.exe     length=309760 sha256=6D5E4E6FCB8CA9D6B248EFE95F0027F2EF1803F4DFE0D8AB7598B6773321AC2C
build-filter-native/pipeline-v3/sp/ap/sa/Release/dm_source_auth_probe.exe           length=189952 sha256=B2C2FC51CD7D29AFC4EE378BD9497FE020CAAD417B152C570CEB4FE59C184BA6
build-filter-native/wire-v3-command/Release/direct_mask_driver.exe                   length=17408  sha256=65EA83FA73987485E75926C8A5FFDA3F0E681010588E4A5C94A64F3C65E3FAEF
build-filter-native/wire-v3-command/Release/direct_mask_process_harness.exe          length=27648  sha256=1993B1B5099D86FFD14E6ECDA63D09DD7E8BA4138F20B8A7E30F79AB7DE6E7A6
build-filter-native/wire-v3-command/Release/direct_mask_wire_probe.exe               length=253952 sha256=D3767EE0EE7F1744BEFA21DF43DF3BE05B3D04601B737470F084D5373273A335
build-filter-native/wire-v3-command/Release/direct_mask_wire_prover.exe             length=233984 sha256=A69CC8BCBA56A3A079043FD500F5C2464E2BB0CBD0FFE332551EB225A4EA1998
build-filter-native/wire-v3-command/Release/direct_mask_wire_verifier.exe           length=206848 sha256=336F71B9F33B7466674EA7898FA493FF48B523B7FEECC8965F6085F0751B80C7
```

Current retained child-log identities are recorded in `STATE.md`. The final successful build logs
reported 112/917/1017/720 warning lines for VOLE/full fixture/standalone pipeline/wire builds,
respectively, with categories preserved there; no build error or failure marker was found. The
wire configure stderr contains the complete non-fatal CMake warning that `BUILD_TESTING` was not
used. Final successful probe/test stderr logs are zero bytes. These are retained-file checks, not
new native execution.

The original records prove the exact command paths and guard/child outcomes, while current CMake
caches prove the final build directories’ source paths. They do not prove a runtime pairing between
each original invocation, a Git HEAD/tree snapshot, and the current binary hash. That provenance
claim remains intentionally open.

## Historical evidence and nonclaims

All old DMV2/mode-2 text and failed v3 attempts remain preserved in `STATE.md` under explicit
historical headings and are superseded by this DMV3 record. Preserve, do not relabel, the missing-`nu`
C2198 compile, early `0xC0000409` stack overruns, retry-RNG/root misclassification and first 67/4
probe, CRLF identity mismatch, missing subordinate probes and `MSB1009` path attempt, wrong-path
oracle exit 2, wrong standalone `Mode Configure`, fixed-IV wire retry failures, and wire v3c’s
`matches_prover_statement=false` result before challenge mode 3/v3d.

The finite theorem, global counter persistence/admission, exact availability/work bound, QROM/PQ
security, Lean semantics, zero-PHI deployed recoverability, production custody, product integration,
activation, publication, real data, payments, and qualification remain open.

The retained performance evidence includes one unmatched FS3 observation of `4568.689ms`.
It is not a p95 measurement, and the earlier `41.75%` attribution is withdrawn. Pagefile
evidence was unavailable; physical-free-memory samples do not establish pagefile or commit
headroom. The current DMV3 wire exposes public `T` and `C`; the proposed authenticated
private-output slots are absent. For any future constant-only 624-bit seed port, the
unprocessed remainder is `624 mod 64 = 48` bits, not 16; the current 512-bit path is
unaffected. The prior FX candidate is superseded and unqualified.

## Cross-lane dependency status

The accepted source-admission/ownership correction is commit
`1306e38901b73790dfb2a973b4ac44daf2ff6869`, tree
`1d04b16d29b2b298dc93817375cd258c9762b7ef`. It is synthetic and nonactivating;
it is not Lean-integrated, PQ-qualified, or evidence of real-source custody. The
conditional arithmetic correction at `14deec37b1ab08f403598972b24f8328c6e77ab4`
is likewise not concrete PQ security evidence. Existing Lean semantic source and
adapter material are known to exist in earlier semantic checkouts, but this native
runtime still uses a synthetic State port and formal linkage to the current candidate
is open. The separate authenticated private-output proposal is not implemented and
remains blocked on its justified signing/setup/source-validation privacy model and
source-to-accepted-commitment equality; no native implementation assignment follows.
