# Filtered direct-mask native candidate state

This workspace-only record is continuation evidence, not product authority or a release artifact.

## Current authoritative DMV3 closure — 2026-09-13

This section is the current authority and supersedes the preserved historical material below. It
records a completed native run and a documentation-only evidence reconciliation. No native
executable, build, CTest, calculation, or new guard run was performed for this closure.

### Repository and input identity

- Writable child:
  C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-wide-seed-native-20260913
- Retained native source identity at the completed run boundary: commit
  ca9dba3f61374810d6677be1f7d1dd9f7ab761ad, tree
  eccf7ac50e32068164b8ec802f78a597566d58aa, parent
  45784ce6c317afb9e9e83e483a398c14a1715f54 / tree
  3a292ce7e24efda8df2a67533b17ce7e6ccb8cc6.
- Exact accepted mathematical input: contract commit
  82f0cd3ad9b71e426aaee8410708c9bfab92992b, tree
  3330c23ef976c34ec78d2b869ef398255dffe1ea, specifically
  bounded_generator_feasibility_proposal_v3.
- Separate privacy-certificate correction: commit
  14deec37b1ab08f403598972b24f8328c6e77ab4, tree
  05f3cc1fc5cf79e704bcb4843ff0b4d6fb1eca69, parent f008901b. It changed only the contract
  calculator/test lane and was not a native rerun input.
- Before this record-only edit, the native child had HEAD ca9dba3..., tree eccf7ac..., clean
  tracked status, and only build-filter-native/ untracked. Native source, math input, and generated
  binaries are immutable for this closure.
- The current record head is commit
  ab1e39b1a7daf3b6afd915c8e48106ec0602902e, tree
  66ca11373c7385504bf33faa88eb6dc7277394ef, parent ca9dba3. This is a
  documentation-only evidence closure. The reviewed source correspondence and recovered guard
  outcomes do not prove that an original invocation used the current binary hash; that historical
  source/build/runtime provenance remains open.

### Current DMV3 geometry

The completed native candidate is fixed w=512 with 64-byte seeds, r=1312, nu=1823 bits serialized
as 228 bytes, H0 squeeze 230 bytes, commitment 164 bytes, m4=20068, frame 544074, signed
challenge_mode=3, and transcript prefix BL/DMV/FAEST-256F/v3. The final wire statement is 1147
bytes; nonces are 192 bytes, m1=506416, m2=15887, and m3=96.

### Original CommandExecution recovery

The original records were read with FileShare.ReadWrite from:

    C:/Users/neers/.codex/sessions/2026/08/31/rollout-2026-08-31T15-44-50-01a0595a-5fc0-7430-be75-71a72e9a4ca5.jsonl

The following are the exact guarded cmd values from the original final invocations. The call IDs
and continuation call IDs bind the command records to their original output records:

~~~text
call_zs4TaKsbifwb9eo7iTU1KUsS
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'vole-build-clean-abs' -CommandPath 'C:\Program Files\CMake\bin\cmake.exe' -CommandArguments @('--build','C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\vole','--config','Release','--target','direct_mask_vole_probe','--','/m:1','/nologo')

call_hw6nHamGDvcV1yKJBXp7sqgw; continuation call_SF3ZltIJkY5ys2kcAKfeu9m4, call_kDjslqk6hkSsjNvt6uYYTzfz; nested session 14493
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'vole-probe-v3-clean' -CommandPath 'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\vole\Release\direct_mask_vole_probe.exe'

call_UtJFNHrtf0kYjCz5G2nZie01
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Configure -RunSuffix 'pipeline-configure-v3-normalized'

call_cFoc5GIww7JsDVVcDzhOyQ5g; continuation call_kdTZsTUyCqRW4eoPnmvccIX9; nested session 55565
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Build -RunSuffix 'pipeline-build-v3'

call_smCYmb7hmx73hTbegIv2ZJoN; continuations call_qAyTM9ZOEnoCoHlpPib4o203, call_hoGEfUwwcXhGCueWlWUrwGCV; nested session 34436
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'transcript-oracle-v3-standalone' -CommandPath 'C:\Users\neers\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe' -CommandArguments @('C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\tools\direct_mask_vole\transcript_oracle.py','C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\vole\Release\direct_mask_vole_probe.exe')

call_WcctyTk3Mffi6ZbSYqJDYUXv
& '.\build-filter-native\run_guarded_v3.ps1' -Mode CTest -RunSuffix 'fixture-ctest-v3'

call_oit9g1oikZ1DEY3ZDOJBeH2V
$child='C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913'; $build=Join-Path $child 'build-filter-native\pipeline-v3'; & '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'pipeline-standalone-configure-v3' -CommandPath 'C:\Program Files\CMake\bin\cmake.exe' -CommandArguments @('-S',(Join-Path $child 'tools\direct_mask_pipeline'),'-B',$build,'-G','Visual Studio 17 2022','-A','x64',('-DFAEST_REF_DIR='+'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-direct-mask-source-auth-20260908\vendor\faest-ref'),('-DDMV_SOURCE_DIR='+(Join-Path $child 'tools\direct_mask_vole')),('-DMLDSA_ROOT='+'C:\Users\neers\Documents\Codex\2026-08-31\blind-zkbpp-c-profile11-extmu-v1'),'-DBUILD_TESTING=ON')

call_Njbyx79LVDBZogULHRTTOqjy; continuations call_S0NO7R5uZyw3Ow2zIHjZ1gOl, call_Xr0VzIfIoy8vssAoabotaAbu; nested session 50634
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'pipeline-standalone-build-v3' -CommandPath 'C:\Program Files\CMake\bin\cmake.exe' -CommandArguments @('--build','C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\pipeline-v3','--config','Release','--target','dm_pipeline_probe','dm_pipeline_source_cli','dm_pipeline_verifier_cli','--','/m:1','/nologo')

call_ltBNAF9KI1TMIhjAqQE5s8Mt; continuations call_TbxrgLqY6afUjERw8naY1mIT, call_vX57RWAe0nG92gDbz4oob1y4, call_tUgUO10b6qV3h2hOsOGLgKlf; nested session 74061
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'pipeline-ctest-v3b' -CommandPath 'C:\Program Files\CMake\bin\ctest.exe' -CommandArguments @('--test-dir','C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\pipeline-v3','-C','Release','-R','^(direct_mask_pipeline_probe|direct_mask_pipeline_real_symbol_gate|direct_mask_source_proof_probe|direct_mask_source_proof_real_symbol_gate|direct_mask_authenticated_proof_probe|direct_mask_authenticated_proof_real_symbol_gate|direct_mask_source_auth_probe|direct_mask_source_auth_real_symbol_gate)$','-V','--output-on-failure')

call_J79KFs7SxsJ2XhrYVrZaPiUU
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'wire-configure-v3-command' -CommandPath 'C:\Program Files\CMake\bin\cmake.exe' -CommandArguments @('-S','C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\tools\direct_mask_wire','-B','C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\wire-v3-command','-G','Visual Studio 17 2022','-A','x64','-DFAEST_REF_DIR=C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-direct-mask-source-auth-20260908\vendor\faest-ref','-DDMV_SOURCE_DIR=C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\tools\direct_mask_vole','-DDMN_SOURCE_DIR=C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\tools\direct_mask_native','-DBUILD_TESTING=ON')

call_MRLwrsgXrSueV0ABE2MOZ9Ih; continuation call_jqXMtVNYvCqlCHuZEfbjfli1; nested session 12075
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'wire-build-v3' -CommandPath 'C:\Program Files\CMake\bin\cmake.exe' -CommandArguments @('--build','C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\wire-v3-command','--config','Release','--target','ALL_BUILD','--','/m:1','/nologo')

call_LvdAXed95cOXQ8af5Zff3Xrj; continuations call_xYWG4y4KyKs65VxcVlD4cjhy, call_kTy1ROeCBJ51g1pFOr7esTTp; nested session 31180
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'wire-probe-v3' -CommandPath 'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\wire-v3-command\Release\direct_mask_wire_probe.exe' -CommandArguments @()

call_J3yCmYsZ6PeIw1d0HuYOOHPk; wait records call_5nADwTCZ3OfqVKGWGdnlPzDV and call_0whjpwSiVCWoZAjoBrI1ncVD; outer cell 656
& '.\build-filter-native\run_guarded_v3.ps1' -Mode Command -RunSuffix 'wire-ctest-v3d' -CommandPath 'C:\Program Files\CMake\bin\ctest.exe' -CommandArguments @('--test-dir','C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\wire-v3-command','-C','Release','-V','--output-on-failure')
~~~

For the completed direct calls, the final nested CommandExecution result carried exit_code=0;
long-running calls reached exit_code=0 in their final continuation record. The wire CTest outer cell
completed through the two wait records; those wait blocks carry the guard's final command status
rather than a separate nested JSON exit_code. The raw guard line CHILD_EXIT_STATUS label=Command
exit=0 is therefore the command-exit evidence for that record.

### Recovered outer-guard decision lines

The records below are selected decision lines from the original outputs. Some PTY control sequences
split a reserve_bytes token across terminal-wrapped lines; the data is rejoined only to make the
verbatim token readable. The complete original session records, including all LIVE_SAMPLE lines,
remain available at the session path above.

~~~text
vole-build-clean-abs:
PHYSICAL_PREFLIGHT free_bytes=3560378368 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=6 min_free_bytes=3474419712 reserve_bytes=1073741824 peak_working_set_bytes=251641856 peak_private_bytes=198385664
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

vole-probe-v3-clean:
PHYSICAL_PREFLIGHT free_bytes=3706519552 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=71 min_free_bytes=3530473472 reserve_bytes=1073741824 peak_working_set_bytes=26341376 peak_private_bytes=25333760
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

pipeline-configure-v3-normalized:
PHYSICAL_PREFLIGHT free_bytes=1909944320 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Configure exit=0
LIVE_PHYSICAL_SUMMARY label=Configure samples=4 min_free_bytes=1885884416 reserve_bytes=1073741824 peak_working_set_bytes=39424000 peak_private_bytes=45510656
CLEANUP=PASS label=Configure owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

pipeline-build-v3:
PHYSICAL_PREFLIGHT free_bytes=1907154944 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Build exit=0
LIVE_PHYSICAL_SUMMARY label=Build samples=41 min_free_bytes=1617952768 reserve_bytes=1073741824 peak_working_set_bytes=199229440 peak_private_bytes=154542080
CLEANUP=PASS label=Build owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

transcript-oracle-v3-standalone:
PHYSICAL_PREFLIGHT free_bytes=2827276288 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=66 min_free_bytes=2579587072 reserve_bytes=1073741824 peak_working_set_bytes=50171904 peak_private_bytes=35610624
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

fixture-ctest-v3:
PHYSICAL_PREFLIGHT free_bytes=2383417344 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=CTest exit=0
LIVE_PHYSICAL_SUMMARY label=CTest samples=2 min_free_bytes=2300960768 reserve_bytes=1073741824 peak_working_set_bytes=22106112 peak_private_bytes=7364608
CLEANUP=PASS label=CTest owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

pipeline-standalone-configure-v3:
PHYSICAL_PREFLIGHT free_bytes=2489487360 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=9 min_free_bytes=2342158336 reserve_bytes=1073741824 peak_working_set_bytes=122896384 peak_private_bytes=77705216
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

pipeline-standalone-build-v3:
PHYSICAL_PREFLIGHT free_bytes=2728267776 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=45 min_free_bytes=2465189888 reserve_bytes=1073741824 peak_working_set_bytes=204173312 peak_private_bytes=165171200
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

pipeline-ctest-v3b:
PHYSICAL_PREFLIGHT free_bytes=3044720640 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=68 min_free_bytes=2788524032 reserve_bytes=1073741824 peak_working_set_bytes=66961408 peak_private_bytes=36188160
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

wire-configure-v3-command:
PHYSICAL_PREFLIGHT free_bytes=2808819712 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=6 min_free_bytes=2718216192 reserve_bytes=1073741824 peak_working_set_bytes=142606336 peak_private_bytes=250548224
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

wire-build-v3:
PHYSICAL_PREFLIGHT free_bytes=2797641728 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=35 min_free_bytes=2609176576 reserve_bytes=1073741824 peak_working_set_bytes=198180864 peak_private_bytes=161656832
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

wire-probe-v3:
PHYSICAL_PREFLIGHT free_bytes=3059961856 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=43 min_free_bytes=2928832512 reserve_bytes=1073741824 peak_working_set_bytes=27738112 peak_private_bytes=26841088
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907

wire-ctest-v3d:
PHYSICAL_PREFLIGHT free_bytes=3181486080 reserve_bytes=1073741824
CHILD_EXIT_CHECK exit7=7 exit0=0
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=121 min_free_bytes=2958135296 reserve_bytes=1073741824 peak_working_set_bytes=53800960 peak_private_bytes=34922496
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
~~~

### Retained child outputs

The complete retained child stdout/stderr files are under build-filter-native/. Their current
filesystem identities are:

~~~text
guarded-command-vole-probe-v3-clean.stdout.log length=7415 sha256=390B42A445C2ABDECE44E85D1855FAA7A683841C50E5A4B2CD8E9B99881225BF
guarded-command-vole-probe-v3-clean.stderr.log length=0 sha256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
guarded-command-transcript-oracle-v3-standalone.stdout.log length=7568 sha256=8E2CE6685E225D4F9B8A327AFC8D4D5F5A83225AA67265DA30BC7B5247B94504
guarded-command-transcript-oracle-v3-standalone.stderr.log length=0 sha256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
guarded-ctest-fixture-ctest-v3.stdout.log length=2434 sha256=E597F12296E0F26EF2DB813ACE209EEB49B143094232FBE57045F9066FEBA59D
guarded-ctest-fixture-ctest-v3.stderr.log length=0 sha256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
guarded-command-pipeline-ctest-v3b.stdout.log length=24846 sha256=2FF469BE63B97AEC52D454F6CD8160F36794CBDADEF5B1EDC2135251CE623202
guarded-command-pipeline-ctest-v3b.stderr.log length=0 sha256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
guarded-command-wire-ctest-v3d.stdout.log length=7726 sha256=BD720F9B257EF9044B9B7DB046B4DC24F1E3A62A64E9E528BAB1BD8A0BA520D5
guarded-command-wire-ctest-v3d.stderr.log length=0 sha256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
guarded-command-vole-build-clean-abs.stdout.log length=50446 sha256=136E9C4B7C9CE1DDBA52B9A8F113ABD8C89D61036EBB2AD4EEF783BDCF7818FF
guarded-command-vole-build-clean-abs.stderr.log length=0 sha256=E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
guarded-build-pipeline-build-v3.stdout.log length=455995 sha256=42E54EF358EF3407771B3FE3F2275C8FBB6DD58FEEC9346879ACC0165B1D2EB2
guarded-command-pipeline-standalone-build-v3.stdout.log length=482545 sha256=F4F2699068433E9769DC6C424C93F6E614FE535334ED11F6DED8411BDC70C638
guarded-command-wire-build-v3.stdout.log length=332034 sha256=1CE3CEAE600E7FC4EB6418D8EF13AD1CF3D54E396901F3BF6D21C2A3CAA9B5AE
~~~

All final successful build/probe/CTest stderr files are zero bytes with the E3B0... empty-file
SHA-256 shown above, except the successful wire configure stderr, which is 97 bytes,
SHA-256 B3B8740DB5D5CA52C4DA6D4FB47C41B4F90663C25C2ADC941D4B22109E4F333E, and contains:

~~~text
CMake Warning:
  Manually-specified variables were not used by the project:

    BUILD_TESTING
~~~

Warning audit of the retained final build stdout files found zero build errors and zero failure
markers. Exact warning counts are:

- VOLE rebuild: 112 warning text lines, C4141=98, C4146=10, C4324=4.
- Full fixture build: 917 warning text lines, C4090=1, C4141=833, C4146=59, C4244=5, C4267=1,
  C4324=18.
- Standalone pipeline build: 1017 warning text lines, C4090=1, C4141=929, C4146=59, C4244=5,
  C4267=1, C4324=22.
- Wire build: 720 warning text lines, C4090=1, C4141=642, C4146=59, C4244=5, C4267=1,
  C4324=12.

### Decision-relevant child output

The final VOLE raw output includes:

~~~text
VOLE_IDENTITY rows=1792 mismatches=0 delta_zero=0
TRANSCRIPT_CACHE_DERIVED fs2_fixed_prefix_bytes=8176 fs3_fixed_prefix_bytes=8452 fresh_queries_unchanged=1 final_nonce_length_word_preserved=1 fs2_multi_nonce=1 fs3_multi_nonce=1 reinit_changed_input=1 cache_clear_zeroed=1
H0_RETRY_CAP_STATUS status=-9 reserved=1 queries=1 accepted=0 rejected=1 aborted=0 rng_failures=0 root_calls=0 prover_delta=0 zeroed=1
DMV_RETRY_COUNTERS h0=1/1/1/0/0/0 fs2=8/8/1/7/0/0 fs3=21629/21629/1/21628/0/0
E2E_WIRE_SIZE bytes=543999 written=543999 statement=1072 nu=228 nonces=192 m1=506416 m2=15887 m3=96 m4=20068
E2E_VERIFY_STATUS status=0 clock_ticks=4776 ticks_per_second=1000
SOURCE_BOUND_COUNTS ell=125048 m=172232 bitness=125048 inverse=26192 equality=7424 tag=768 range=12800 sboxes=13096 aes_blocks=58 key_schedules=2 prover_calls=1 verifier_calls=1 counts_equal=1
DIRECT_MASK_PROBE_COUNTS passed=71 failed=0
DIRECT_MASK_PROBE_STATUS=PASS
~~~

The oracle raw result is:

~~~text
TRANSCRIPT_ORACLE status=PASS kat=3 mutation_vectors=3 h0_vendor=1 cache_vectors=1 prefix=BL/DMV/FAEST-256F/v3 encoding=uint32le_length_delimited_parts
~~~

Pipeline CTest raw result:

~~~text
1/8 Test #1: direct_mask_pipeline_probe .........................   Passed    9.02 sec
2/8 Test #2: direct_mask_pipeline_real_symbol_gate ..............   Passed   12.56 sec
3/8 Test #3: direct_mask_source_proof_probe .....................   Passed    9.38 sec
4/8 Test #4: direct_mask_source_proof_real_symbol_gate ..........   Passed    0.43 sec
5/8 Test #5: direct_mask_authenticated_proof_probe ..............   Passed    9.12 sec
6/8 Test #6: direct_mask_authenticated_proof_real_symbol_gate ...   Passed    0.37 sec
7/8 Test #7: direct_mask_source_auth_probe ......................   Passed    0.11 sec
8/8 Test #8: direct_mask_source_auth_real_symbol_gate ...........   Passed    0.31 sec
100% tests passed, 0 tests failed out of 8
~~~

Its four probe summaries are CHECK_COUNT=116 FAILED=0 ALL_TESTS=PASS,
CHECK_COUNT=96 FAILED=0 ALL_TESTS=PASS, CHECK_COUNT=58 FAILED=0 ALL_TESTS=PASS, and
CHECK_COUNT=86 FAILED=0 ALL_TESTS=PASS. All four real-symbol gates passed and the CTest run had
zero skips.

Fixture CTest raw result:

~~~text
1: STATUS NON_ACTIVATING_DIRECT_MASK_FIXTURE_PROBE cases=20 failures=0
1/1 Test #1: direct_mask_fixture_probe ........   Passed    0.07 sec
100% tests passed, 0 tests failed out of 1
~~~

Wire CTest raw result:

~~~text
1: NATIVE_MATERIALIZER status=0 byte_count=15631 bit_count=125048 expected_bytes=15631
1: WIRE_PROVE_STATUS status=0 name=ok final_nonce_calls=32032
1: WIRE_FRAME bytes=544074 written=544074 statement=1147 nu=228 nonces=192 m1=506416 m2=15887 m3=96 m4=20068
1: WIRE_VERIFY status=0 name=ok
1: DIRECT_MASK_WIRE_PROBE status=PASS proof_verification=PASS skips=0
2: DM_DRIVER phase=process status=PASS exit_code=0 timed_out=false output_limited=false
3: PROCESS_ROLE role=verifier_positive launch=true exit_code=0 timed_out=false output_limited=false timer_error=false io_error=false resource_error=false
3: PROCESS_REQUEST source=independent_state_constant request_bytes=1147 frame_bytes=544074 matches_prover_statement=true witness_bytes_to_verifier=0
3: PROCESS_CASE name=retry_failure status=PASS expected_exit=41 exit_code=41
3: PROCESS_CLEANUP private_buffers_cleared=true proof_buffer_released=true statement_buffer_released=true child_output_forwarded=false persisted_private_artifacts=false
3: PROCESS_PIPELINE status=PASS cases=12 skips=0 child_output_forwarded=false persisted_private_artifacts=false
100% tests passed, 0 tests failed out of 3
~~~

The final native process verifier is a separate prover/verifier executable and link/process
boundary. It reconstructs the full transcript from the request/frame and receives zero witness
bytes; it does not link the source producer or source-proof executable. It shares the
direct_mask_vole.c cryptographic implementation with the producer, so no independently implemented
cryptography claim is made.

### Current artifact identity (not runtime provenance)

Current filesystem hashes of the retained final binaries are:

~~~text
build-filter-native/acceleration-correction/Release/direct_mask_fixture_probe.exe length=41472 sha256=959151FF4FC2038608DC365D06297C30C29D63445394B4B1243321D99CE23B22
build-filter-native/vole/Release/direct_mask_vole_probe.exe length=282624 sha256=6F195A963C1E5BDC50D65095D7DA919DAAF74E210680CA251D4DDCBF8C04D5E7
build-filter-native/pipeline-v3/Release/dm_pipeline_probe.exe length=316928 sha256=03760E1066FDF445FAFE7B179917A932F46DE0E29729D49B3E93FD8BFCD163C1
build-filter-native/pipeline-v3/Release/dm_pipeline_source_cli.exe length=262656 sha256=2BCC0A5B78B493DBCCF53A9DE8638001FA643159DCAAA254745D6EE83BE3622C
build-filter-native/pipeline-v3/Release/dm_pipeline_verifier_cli.exe length=232448 sha256=A4B27C04DC949C07F464983DCE24A8A90D6A433A8750AB79FB300961FF57EA94
build-filter-native/pipeline-v3/sp/Release/dm_source_proof_probe.exe length=314368 sha256=E87B5F01F46A45DA8954AD084EFB0BFE4F6FCB4E59B8C9E1E7521F92B1BA9DBB
build-filter-native/pipeline-v3/sp/ap/Release/dm_authenticated_proof_probe.exe length=309760 sha256=6D5E4E6FCB8CA9D6B248EFE95F0027F2EF1803F4DFE0D8AB7598B6773321AC2C
build-filter-native/pipeline-v3/sp/ap/sa/Release/dm_source_auth_probe.exe length=189952 sha256=B2C2FC51CD7D29AFC4EE378BD9497FE020CAAD417B152C570CEB4FE59C184BA6
build-filter-native/wire-v3-command/Release/direct_mask_driver.exe length=17408 sha256=65EA83FA73987485E75926C8A5FFDA3F0E681010588E4A5C94A64F3C65E3FAEF
build-filter-native/wire-v3-command/Release/direct_mask_process_harness.exe length=27648 sha256=1993B1B5099D86FFD14E6ECDA63D09DD7E8BA4138F20B8A7E30F79AB7DE6E7A6
build-filter-native/wire-v3-command/Release/direct_mask_wire_probe.exe length=253952 sha256=D3767EE0EE7F1744BEFA21DF43DF3BE05B3D04601B737470F084D5373273A335
build-filter-native/wire-v3-command/Release/direct_mask_wire_prover.exe length=233984 sha256=A69CC8BCBA56A3A079043FD500F5C2464E2BB0CBD0FFE332551EB225A4EA1998
build-filter-native/wire-v3-command/Release/direct_mask_wire_verifier.exe length=206848 sha256=336F71B9F33B7466674EA7898FA493FF48B523B7FEECC8965F6085F0751B80C7
~~~

These hashes were computed during this closure and establish current file identity only. The
original session records do not contain final executable SHA-256 values or a runtime Git HEAD/tree
snapshot. Current CMake caches bind the final build directories to this child’s VOLE, wire, and
pipeline source paths, but that is path/configuration evidence, not a runtime source/binary pair.
Therefore the claim that each particular original invocation used the binary represented by each
current hash remains unproven and is intentionally not made.

The current CMake cache path bindings are:

~~~text
build-filter-native/vole/CMakeCache.txt:
CMAKE_HOME_DIRECTORY=C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-wide-seed-native-20260913/tools/direct_mask_vole
build-filter-native/pipeline-v3/CMakeCache.txt:
CMAKE_HOME_DIRECTORY=C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-wide-seed-native-20260913/tools/direct_mask_pipeline
DMV_SOURCE_DIR=C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-wide-seed-native-20260913/tools/direct_mask_vole
build-filter-native/wire-v3-command/CMakeCache.txt:
CMAKE_HOME_DIRECTORY=C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-wide-seed-native-20260913/tools/direct_mask_wire
DMV_SOURCE_DIR=C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-wide-seed-native-20260913/tools/direct_mask_vole
DMN_SOURCE_DIR=C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-wide-seed-native-20260913/tools/direct_mask_native
~~~

All three caches use Visual Studio 17 2022. The retained FAEST and ML-DSA paths are the exact
read-only inputs shown in the original commands and caches; no vendor source was edited.

### Historical failed and superseded v3 predecessors

The following failures remain preserved evidence and are not current passes:

- Initial missing-nu compile failed with MSVC C2198.
- Early native runs exited 0xC0000409 from a stack overrun caused by the H1 64-byte hash-buffer
  issue.
- Retry RNG/root accounting was initially misclassified; the first direct probe was 67 passed and
  4 failed before correction.
- The first pipeline CMake identity check reported expected
  08923E5B... but actual a302... because CRLF was included; only CRLF normalization before hashing
  was corrected.
- The first selective pipeline CTest build lacked subordinate probes; a root target-name attempt
  failed with MSB1009. Nested projects were then built directly before the final v3b 8/8 result.
- A wrong-path transcript oracle invocation exited 2 with missing_executable.
- A standalone wire configure was first sent through Mode Configure and routed to the
  acceleration-correction path; the final standalone wire build used the correct Command mode.
- Wire CTest v3 and v3b each failed all 3 tests with
  WIRE_PROVE_STATUS status=-10 name=retry final_nonce_calls=0 because the request used a fixed IV.
- Wire v3c passed 2/3 but its process case reported matches_prover_statement=false because the
  independent request used challenge_mode=1. The request was corrected to challenge_mode=3 and
  the final v3d run passed 3/3.

### Closure nonclaims

This child remains a synthetic, non-activating engineering candidate. No finite theorem, QROM/PQ
security result, availability/work bound, global counter persistence/admission, zero-PHI deployed
recoverability, production custody, product integration, activation, publication, real-data,
payment, or qualification claim follows. No private witness, seed, signature, proof, or source
material was written to logs or disk.

## Historical preserved DMV2/native predecessor state (superseded)

All material below this heading is retained historical DMV2 and prior-correction evidence. It is not
current contract or authority; the current DMV3 closure is the section above.

### Historical DMV2 verified before edits (superseded)

- Writable root: `C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-direct-mask-filter-native-20260912`.
- Base HEAD/tree: `530e880ef6cbd5fa4e023f42d3aa66a0d213d9e2` /
  `e1119b850c3a886a4df09f375fd50d9ac81e94d7`; detached and clean before dependency copies.
- Six tracked VOLE files and ten tracked fixture files were copied; source-to-child SHA-256
  verification reported `VERIFY_VOLE_COUNT=6 MISMATCHES=0` and
  `VERIFY_FIXTURE_COUNT=10 MISMATCHES=0`.
- Final finite contract input: `e464ba5d2272bd4df223d4ff0b4033fcd62bb138` /
  `d438d32a5421df5d4feda7727990651ba7fc7fa7`. The committed tree is the only contract input
  consumed here. Its final grouped v2 correction suite exited 0 with `Ran 20 tests in 27.994s`,
  `OK`, and the raw handoff reports `REPORT_EXIT=0 REPORT_SECONDS=2.495122`; the parent correction's 29-test output is preserved evidence, not a
  rerun of this grouped commit. The checkout currently retains only the separate lane's untracked
  Python cache; this child does not edit it. The corrected decoded-choice denominator is 2^248;
  the separate eight grinding bits are separate.
- Input identities verified before checkout: pipeline `530e880…`/`e1119b…`, VOLE
  `392e53e…`/`34dc61…`, fixture `5473dd…`/`1ec1a0…`, FAEST vendor
  `ebefcb…`/`f0c2e6…`, ML-DSA `9ca1ba…`/`178a5f…`, AES/circuit
  `0bce17…`/`0a0872…`, and v1 contract `798508…`/`5267b4…`. Their untracked build/cache
  material was not copied or modified.

### Historical DMV2 status (superseded)

The filtered native source, wire/source-auth version separation, cache path, bounded local retry
counters, fixture request-cap checks, and contained guard are implemented only in this child. The
copied VOLE and fixture files matched their pinned inputs before edits (`MISMATCHES=0`). The
standalone probe rebuild exited 0 with 0 build errors and 527 warning lines (inherited
MSVC/vendor warnings). Guarded `direct-mask-probe-r3` exited 0 with 86 samples, minimum free
physical memory `2321858560` bytes against reserve `1073741824`, peak private memory `22302720`
bytes, cleanup pass, and mutex release. Its raw output reports `DIRECT_MASK_PROBE_COUNTS
passed=62 failed=0`, `DIRECT_MASK_PROBE_STATUS=PASS`, source proof status 0, and
`DMV_RETRY_COUNTERS h0=1/1/1/0/0/0 fs2=18/18/1/17/0/0 fs3=28359/28359/1/28358/0/0`.
The guarded Python oracle also exited 0: `TRANSCRIPT_ORACLE status=PASS kat=3
mutation_vectors=3 prefix=BL/DMV/FAEST-256F/v2 encoding=uint32le_length_delimited_parts`.

The final pipeline CTest run after the final CMake regeneration was guarded and exited 0 with all
8 tests passed, 0 failed, 0 skips, stderr empty, and total test time `69.70 sec`. The guard
recorded 101 samples, minimum free physical memory `1672011776` bytes against reserve
`1073741824`, peak working set `70868992`, peak private memory `35909632`, cleanup pass, and
mutex release. The final direct pipeline probe reports `CHECK_COUNT=116 FAILED=0`,
`MIXED_VERSION_REJECTED=TRUE`; source-proof, authenticated-proof, and source-auth probes report
`CHECK_COUNT=96/58/86 FAILED=0`. The final fixture probe reports
`STATUS NON_ACTIVATING_DIRECT_MASK_FIXTURE_PROBE cases=20 failures=0`; its guarded run exited 0
with cleanup pass and mutex release. After correcting the embedded CTest registry boundary, the
fixture's registered CTest run is `1/1 Test #1: direct_mask_fixture_probe Passed 0.03 sec`,
`100% tests passed, 0 tests failed out of 1`, total `0.04 sec`, guarded exit 0, cleanup pass,
and mutex release. Pipeline ALL_BUILD exited 0 with 0 build errors and 1028 warning lines;
fixture ALL_BUILD exited 0 with 0 build errors and 916 warning lines.

Earlier corrected failures remain evidence: the first standalone run used an arbitrary IV and hit
the H0 rejection cap; a second used an intentionally too-small FS3 cap and exhausted at 1024
attempts; the first selective CTest build lacked TrackFileAccess link-input logs and three
subordinate executables, and a root target-name build attempt used a nonexistent project path.
The first fixture CTest attempt (`fixture-ctest-r18`) also exited 8: its registry incorrectly
contained nine tests, with the direct fixture probe passing but six nested pipeline entries
missing/unbuilt (four Not Run and two symbol-gate failures). The explicit `DM_EMBEDDED_NO_TESTS`
boundary was then added to the four embedded CMake test blocks; reconfigure r22 produced one
fixture test and guarded `fixture-ctest-r23` passed. These runs were not treated as passes; the
corrected tlog build and final 8-test CTest run passed.
The generated `KeccakP-1600-opt64.obj` was exactly moved under `build-filter-native/` with SHA-256
`210141A9972F7C2C1202FD603A1CF5B6BBFF9FE754E6805AAB6548085DD0E928` unchanged.

The finite-contract input remains `e464ba5d2272bd4df223d4ff0b4033fcd62bb138` /
`d438d32a5421df5d4feda7727990651ba7fc7fa7`, with its grouped v2 gate `Ran 20 tests in
27.994s`, `OK`. The driver's review caveat is preserved: its new security derivation is not
accepted because the stated event omits explicit suffix gates, its H1 table omits the 256-leaf
forms, and its exact FS encoding table omits the literal FS domain bytes. The native candidate
keeps the actual vendor geometry and native `BL/DMV/FAEST-256F/v2` length-delimited encoding; no
theorem or production claim follows.

After the native handoff, the separate contract lane committed the superseding correction
`f291ee05a7cc90e6fbb448568f7bec4e799a09fa` / tree
`59c444bdbb518c78e66cb6310c7a19774fd0a597`, changing only CONTRACT_V2.md, calculator_v2.py,
and manifest_v2.json. Its focused raw gate reports `Ran 6 tests in 1.691s`, `OK`; its checkout
now has only the pre-existing untracked `__pycache__/`. The native implementation and native
evidence in this child were produced against committed contract `e464ba5d...` / tree
`d438d32a...`; no native rerun or source change consumed the superseding PQ commit. Future
contract/profile review must use f291ee05... and preserve its stated conditional premises.

Any generated build must remain under `build-filter-native/` and must not be committed.

### Historical DMV2 nonclaims (superseded)

This child is a synthetic, nonactivating engineering candidate. It does not qualify a proof suite,
state transition, production profile, privacy/custody boundary, PQ security theorem, availability,
or payment path. Existing product authorities remain unchanged and the old unfiltered E2E lane is
outside this checkout.

### Historical filtered-native correction phase (superseded) — 2026-09-12

The read-only contract lane changed after the earlier handoff: its actual tip is
`d81d84ad1acf50cea2248a008ff106fd54950f31` / tree
`1ceca80f7867417082cbdb5f9884372e5c1d572c`, with `bbff48b` and `f291ee0` in its ancestry.
The tip changes exactly four contract-lane files (`CONTRACT_V2.md`, `calculator_v2.py`,
`manifest_v2.json`, `test_calculator_v2.py`) to record a bounded, non-qualifying concrete PQ
feasibility blocker. It does not change native bytes, filters, caps, or wire geometry. No PQ
calculation was rerun here; this discrepancy is preserved rather than silently treating the earlier
`f291ee0`/`bbff48b` handoff as current.

The driver’s six native corrections were applied only in the allowlisted VOLE probe path:

- `direct_mask_vole.c` now uses the pinned vendor `H0_init`/`H0_update`/`H0_final` API for
  `iv || 00`, and separates 105-byte FS2 scratch from 33-byte FS3 scratch on every proof path.
- `direct_mask_vole_probe.c` emits a public H0 KAT, checks the vendor leaf prefix, exercises
  multiple cache nonces plus frozen-input reinitialization and owned-context zeroing, and records
  stage-specific cap/RNG failures with reservation/query/outcome partitions, proof zeroing, one-root
  and relation-call deltas. The final staged fixtures reached FS2 and FS3; no full 2^22 negative
  search was run.
- `transcript_oracle.py` independently checks literal
  `hashlib.shake_256(h0_iv + bytes([0])).digest(98)` correspondence and cache evidence.

The generated guarded runner is
`build-filter-native/run_guarded_correction_20260912.ps1`, SHA-256
`43910DBA2012B019A257A6F4E8807D6B2B962DBCE1A134A1B90825B8AC303534`, length 14907 bytes. It is
an adapted copy of the verified read-only runner, with actual child exit propagation, process-tree
cleanup/evidence, physical-memory sampling, mutex hold-on-unresolved-cleanup behavior, and an
additional command mode for the child’s native gates. The tracked wrapper in
`tools/direct_mask_fixture/` was not used. The sampling evidence is process-tree sampling, not a
claim of Job Object enforcement.

Correction evidence (all guarded runs exited 0 unless stated otherwise):

- VOLE rebuild: 527 warning lines, 0 error lines, 0 failure markers. Probe guard: 107 samples,
  minimum free physical memory `2523951104` bytes vs reserve `1073741824`, peak private
  `22220800` bytes, cleanup pass, mutex released. Raw probe: `DIRECT_MASK_PROBE_COUNTS passed=70
  failed=0`; `DIRECT_MASK_PROBE_STATUS=PASS`; `H0_KAT` vendor/raw/leaf check passed;
  `FS2_CAP_STATUS cap=5 ... reserved=5 queries=5 accepted=0 rejected=5 ... root_calls=1
  prover_delta=0 zeroed=1`; `FS3_CAP_STATUS cap=7 ... reserved=7 queries=7 accepted=0 rejected=7
  ... root_calls=1 prover_delta=1 zeroed=1`; H0/FS2/FS3 RNG statuses each report one abort,
  one RNG failure, zero queries, zeroed proof, and downstream deltas `0/0/1` respectively.
- Python oracle guard: 106 samples, minimum free physical memory `2508652544` bytes, peak
  private `32153600` bytes, cleanup pass, mutex released. Raw result:
  `TRANSCRIPT_ORACLE status=PASS kat=3 mutation_vectors=3 h0_vendor=1 cache_vectors=1
  prefix=BL/DMV/FAEST-256F/v2 encoding=uint32le_length_delimited_parts`.
- Fixture configure: 8 samples, minimum free physical memory `2652028928` bytes, cleanup pass,
  mutex released, build-log failure gate false. Fixture build: 916 warning lines, 0 error lines,
  0 failure markers. Actual fixture CTest: `1/1` passed, `0` failed, `0.17 sec`, stderr empty,
  cleanup pass, mutex released.
- Pipeline incremental corrected rebuild: 56 warning lines, 0 error lines, 0 failure markers.
  Full pipeline CTest: `8/8` passed, `0` failed, `0` skips, stderr empty, `92` guard samples,
  minimum free physical memory `2440232960` bytes, peak private `35864576` bytes, cleanup pass,
  mutex released. Raw probe gates report `CHECK_COUNT=116/96/58/86 FAILED=0` for pipeline,
  source-proof, authenticated-proof, and source-auth respectively; all report `ALL_TESTS=PASS`.

The generated logs and binaries remain untracked under `build-filter-native/`. The child was at
HEAD `caf10a1a119e86dc1462e2f866192a8a1d4912dd` / tree
`7d71da2b7914a7451a0bc716bd27f0b8da54c7eb` before this correction commit; old rejected evidence
and prior commit history are preserved. This correction remains synthetic, nonactivating, and does
not close any open PQ, availability, product, custody, or production-qualification claim.

### Historical shared-mutex containment repair (superseded) — 2026-09-12

The prior correction commit 8d3aaf21dcb2329a255fa34491718a048d18ef67 / tree
77afa0793c161baf1dc40f42f9fdba25b4e2bd17 remains unchanged. The generated runner had been
recorded above at its pre-repair identity (43910DBA2012B019A257A6F4E8807D6B2B962DBCE1A134A1B90825B8AC303534,
14907 bytes) and used the distinct mutex name Local\BlindLedgerDirectMaskFilterNative20260912.
That identity and every prior guard transcript are historical evidence; they are not
retroactively treated as common-mutex coordinated, and no old log was rewritten or deleted.

The only generated-runner change in this phase is the mutex literal. The current generated
build-filter-native/run_guarded_correction_20260912.ps1 uses the shared name
Local\BlindLedgerDirectMaskBuild20260907, is 14900 bytes, and has SHA-256
6A0D031724818C4971CD0E64033055B4397D51DFB1544F3272E4A0F2D86AEC1B.
It remains generated, untracked output and is not release payload.

The first self-check invocation was rejected by PowerShell before the runner executed because
-File treated the three command arguments as extra positional script arguments. Its preserved
transcript is build-filter-native/guarded-command-shared-mutex-selfcheck-20260912.transcript.log.
The corrected -Command invocation was the only runner verification after the mutex edit. Its
preserved transcript is build-filter-native/guarded-command-shared-mutex-selfcheck-20260912b.transcript.log
(1394 bytes, SHA-256 CD2F1AF1A35A5128BFF6A324114C6C4D3FB8C468421395A4E697AA143D6B1729). Its raw
decision lines are CHILD_EXIT_CHECK exit7=7 exit0=0, CHILD_EXIT_STATUS label=Command exit=0,
CLEANUP=PASS label=Command owned_process_tree=empty, and
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907. The runner-generated command
stdout and stderr are both zero bytes. No proof/build/test suite was replayed for this scheduling-only
repair.

The three nonempty failed correction-configure stderr artifacts remain preserved, each exactly 962
bytes with SHA-256 89B15301695E2A50BA1FB6B9D4779AFF608FDAB2138477E11342B9A8AE017524:

- build-filter-native/guarded-configure-fixture-configure-correction-20260912.stderr.log
- build-filter-native/guarded-configure-fixture-correction-configure-20260912.stderr.log
- build-filter-native/guarded-configure-fixture-correction-configure-debug-20260912.stderr.log

They are byte-identical. Their complete preserved stderr is:

~~~text
CMake Warning:
  Ignoring extra path from command line:

   "C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-direct-mask-pipeline-20260908/tools/direct_mask_pipeline"


CMake Warning:
  Ignoring extra path from command line:

   "C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-direct-mask-filter-native-20260912/tools/direct_mask_vole"


CMake Warning:
  Ignoring extra path from command line:

   "C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-direct-mask-source-auth-20260908\vendor\faest-ref"


CMake Error: The source "C:/Users/neers/Documents/Codex/2026-08-31/blind-zkbpp-c-profile11-extmu-v1/CMakeLists.txt" does not match the source "C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-direct-mask-pipeline-20260908/tools/direct_mask_pipeline/CMakeLists.txt" used to generate cache.  Re-run cmake with a different source directory.
~~~

The final configure succeeded in the fresh build-filter-native/fixture-correction directory;
the three failed attempts above remain explicit evidence and were not relabeled as passes.

Warning audit of the preserved guarded build stdout logs used every warning C####: diagnostic,
stripped only the trailing MSBuild project path for distinct-text grouping, and found zero
error C####: matches and zero failure markers in each log. Complete category/text counts are:

- VOLE rebuild (527 warnings; log SHA-256
  B353394A284D57AA568CE9A5C4C057C9B6C0D33F0775416E45EA6C7AEB5EDFB3): C4090 1 —
  'function': different 'const' qualifiers; C4141 449 — 'inline': used more than once;
  C4146 67 — unary minus operator applied to unsigned type, result still unsigned; C4244 5 —
  '=': conversion from 'uint64_t' to 'uint8_t', possible loss of data (1),
  'function': conversion from 'const uint64_t' to 'uint32_t', possible loss of data (3),
  'initializing': conversion from 'uint64_t' to 'const uint8_t', possible loss of data (1);
  C4267 1 — 'initializing': conversion from 'size_t' to 'const ULONG', possible loss of data;
  C4324 4 — 'KeccakWidth1600_12rounds_SpongeInstanceStruct': structure was padded due to alignment specifier
  (2) and 'KeccakWidth1600_SpongeInstanceStruct': structure was padded due to alignment specifier
  (2).
- Fixture build (916 warnings; log SHA-256
  8A41216B8E1580F144E46EF1B34D1F129F22647F0128F816D2D5EA7B64E47272): C4090 1 —
  'function': different 'const' qualifiers; C4141 792 — 'inline': used more than once;
  C4146 99 — unary minus operator applied to unsigned type, result still unsigned; C4244 5 —
  the same three complete texts and counts 1/3/1 listed above; C4267 1 — the same complete
  size_t to const ULONG text listed above; C4324 18 — the two complete struct-padding texts
  listed above, with counts 9/9.
- Pipeline incremental rebuild (56 warnings; log SHA-256
  4D6EF5FEEFF2C9D1469EFF3063A5E79C84FEE76E2CDA8F33A9E34B04ED19A775): C4141 49 —
  'inline': used more than once; C4146 5 — unary minus operator applied to unsigned type, result still unsigned;
  C4324 2 — the two complete struct-padding texts listed above, with counts 1/1.

These warnings are retained inherited MSVC/vendor diagnostics, not newly asserted defects. The
repair remains synthetic, nonactivating, and does not close any open PQ, availability, product,
custody, or production-qualification claim.

### Historical bf256 acceleration integration (superseded) — 2026-09-12

This phase integrates the accepted native bf256 acceleration into the filtered containing paths.
The accepted read-only performance input was
C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-direct-mask-performance-20260912
at HEAD 48268072892afe4db41d3acc50a62e555f0f2f4b, tree
3b720ca35b9943bb7b7be4f27f7c4cd0e8b20d46. The accepted acceleration source commit is
4dd3ea2ece80b43e29befe63c644e3b6b46eea61, tree
3061d6b77e60bb28f92ea4667bdbe72fcd7c2e50, parent
f73378a3bf33f5356887ba1e46b758a544392507. The imported files are byte-identical to that
accepted source: direct_mask_bf256_accel.c is 6013 bytes with SHA-256
08923E5EB209FFBFB89CC489D2C21770769F0AB45F31984BBC075DDDDCF52399; direct_mask_bf256_accel.h
is 830 bytes with SHA-256 00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2.
The child input before this phase was HEAD 28fb538521482289b2cfc9a13cc7960326600cd5, tree
1795502f3b259b499ce93a5756393e292be54ca4.

Graph wiring is deliberately narrow. The pinned FAEST fields.c source is compiled with only
bf256_mul and bf256_mul_inplace renamed to direct_mask_bf256_mul_portable and
direct_mask_bf256_mul_inplace_portable. The accepted accelerator is compiled into
faest_primitives, faest_direct_mask_primitives, and dm_faest_public; public callers retain
bf256_mul and bf256_mul_inplace and therefore use the accelerator's public dispatcher. The final
fixture keeps its child-local embedded pipeline and sets DM_EMBEDDED_NO_TESTS, so it has one
fixture test rather than importing duplicate pipeline tests. The independent pipeline remains a
separate eight-test graph. No vendor, product, runtime, adapter, PQ, Profile13, or original
protocol implementation file was edited.

The exact imported source and graph records are in tools/direct_mask_vole/CANDIDATE_PROVENANCE.txt.
The child source-auth CMake gate checks the two imported file hashes and the accepted input head,
tree, source commit, source tree, and parent. The adapted generated guard is
build-filter-native/run_guarded_acceleration_20260912.ps1, 14905 bytes, SHA-256
BD5D39E0B96A0FE85B6E253C5C62740B09FE378BCAA02D45DB956421EF053E1A. Its only semantic diff from
the accepted build-filter-native/run_guarded_correction_20260912.ps1 is the default build
directory fixture-correction -> acceleration-correction. The accepted runner is 14900 bytes,
SHA-256 6A0D031724818C4971CD0E64033055B4397D51DFB1544F3272E4A0F2D86AEC1B. Both use mutex
Local\BlindLedgerDirectMaskBuild20260907, child exit checks 7 and 0, a 1 GiB reserve, process-tree
cleanup, and mutex release. All native configure, build, test, dumpbin, and probe invocations in
this phase used the adapted runner. Generated logs and build trees remain under build-filter-native
and are not release payload.

Arithmetic correspondence gates:

- Normal kernel configure/build/run used fresh kernel-normal-r4 with
  CMAKE_VS_GLOBALS=TrackFileAccess=false and CMAKE_TRY_COMPILE_PLATFORM_VARIABLES=CMAKE_VS_GLOBALS.
  The raw probe output was:

  BF256_ARITHMETIC_BEGIN
  BF256_ARITHMETIC_MODE=normal_dispatch
  BF256_ARITHMETIC_BACKEND=pclmul PCLMUL_AVAILABLE=1
  BF256_ARITHMETIC_BASIS_PAIRS=65536 BOUNDARY_VECTORS=17 BOUNDARY_PAIRS=289 CHECKS=460775 MISMATCHES=0
  BF256_ARITHMETIC_STATUS=PASS
  FIELD_IDENTITY delta_case=0 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  ACTUAL_COUNTS ell=125048 m=172232 bitness=125048 inverse=26192 equality=7424 tag=768 range=12800 sboxes=13096 aes_blocks=58 key_schedules=2
  FIELD_IDENTITY delta_case=1 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  FIELD_IDENTITY delta_case=2 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  FIELD_IDENTITY delta_case=3 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  NEGATIVE name=root status=0 rows=172232 nonzero_leading=274
  NEGATIVE name=inverse status=0 rows=172232 nonzero_leading=325
  NEGATIVE name=g0 status=0 rows=172232 nonzero_leading=2077
  NEGATIVE name=value status=0 rows=172232 nonzero_leading=2
  NEGATIVE name=borrow_first status=0 rows=172232 nonzero_leading=2
  NEGATIVE name=borrow_last status=0 rows=172232 nonzero_leading=1
  NEGATIVE name=tag_T status=0 rows=172232 nonzero_leading=1
  NEGATIVE name=tag_U status=0 rows=172232 nonzero_leading=120
  NEGATIVE name=ciphertext_C status=0 rows=172232 nonzero_leading=1
  RANGE_NATIVE boundary=0 status=1 out_of_range=1
  NEGATIVE name=lower_minus_one status=0 rows=172232 nonzero_leading=1
  RANGE_NATIVE boundary=1 status=1 out_of_range=1
  NEGATIVE name=upper_plus_one status=0 rows=172232 nonzero_leading=1
  API_REJECTIONS callback=-91 non_boolean=-7 dimension=-3 context=-2 zero_U=-2
  DIRECT_MASK_KERNEL status=PASS skips=0 fixture_rng=deterministic cpu_seconds=22.826

- Forced arithmetic-only configure/build/run used fresh kernel-forced-r4 with
  DIRECT_MASK_BF256_FORCE_PORTABLE=ON and DIRECT_MASK_BF256_ARITHMETIC_ONLY=ON. The forced
  CMake cache contains CMAKE_VS_GLOBALS=TrackFileAccess=false,
  CMAKE_TRY_COMPILE_PLATFORM_VARIABLES=CMAKE_VS_GLOBALS, and both forced options ON. Raw output:

  BF256_ARITHMETIC_BEGIN
  BF256_ARITHMETIC_MODE=forced_capability_false
  BF256_ARITHMETIC_BACKEND=portable PCLMUL_AVAILABLE=0
  BF256_ARITHMETIC_BASIS_PAIRS=65536 BOUNDARY_VECTORS=17 BOUNDARY_PAIRS=289 CHECKS=460775 MISMATCHES=0
  BF256_ARITHMETIC_STATUS=PASS
  DIRECT_MASK_KERNEL_ARITHMETIC_ONLY status=PASS

Each arithmetic pair checks seven public API cases: out-of-place, destination=l.h.s. alias,
destination=r.h.s. alias, in-place l.h.s., in-place r.h.s., self alias, and self in-place. The
probe therefore reports 65,825 input pairs and 460,775 checks in each mode, including the
corrected portable destination=r.h.s. alias case. Normal run transcript:
build-filter-native/acceleration-kernel-normal-r4-run-20260912.transcript.log, 7060 bytes,
SHA-256 82FAE8BBB1501CD26E49DB6E62F344A8AC74DDB49D07E2BB66A4F8CDB27E8ECF. Forced run
transcript: build-filter-native/acceleration-kernel-forced-r4-run-20260912.transcript.log, 2100
bytes, SHA-256 0224B45E570827F911B3DA22E166D7EA9D69FF02AE3C958D329B0B163389895A.

Containing filtered VOLE gate:

The fresh vole-r4 configure/build/run completed with runner exit 0 and the existing probe
reported DIRECT_MASK_PROBE_COUNTS passed=70 failed=0 and DIRECT_MASK_PROBE_STATUS=PASS. Its raw
trust-critical output also included CHECK_PASS h0_vendor_raw_matches_leaf, CHECK_PASS commit,
CHECK_PASS reconstruct, CHECK_PASS reconstructed_commitment_matches, VOLE_IDENTITY rows=1792
mismatches=0 delta_zero=0, CHECK_PASS q_equals_v_plus_delta_u_all_rows,
CHECK_PASS tampered_correction_changes_q, CHECK_PASS leaf_uhash, CHECK_PASS fs1, CHECK_PASS fs2_raw,
CHECK_PASS fs3_raw, CHECK_PASS fs2_filter_predicate, CHECK_PASS fs3_filter_predicate,
CHECK_PASS fs1_binds_full_statement, CHECK_PASS fs2_binds_full_statement,
CHECK_PASS fs3_binds_full_statement, CHECK_PASS fs2_cache_full_replay_byte_equivalence,
CHECK_PASS fs3_cache_full_replay_byte_equivalence, CHECK_PASS cache_clear_zeroes_owned_contexts,
CHECK_PASS h0_retry_cap_fails_closed, CHECK_PASS canonical_wire_roundtrip,
CHECK_PASS explicit_nu_tamper_rejected, CHECK_PASS vh_tamper_rejected,
CHECK_PASS three_coefficient_tamper_rejected, CHECK_PASS full_statement_mismatch_rejected,
CHECK_PASS failed_decode_clears_destination, CHECK_PASS failed_decode_cannot_verify,
CHECK_PASS decode_valid_recovery, CHECK_PASS live_proof_reuse_succeeds,
CHECK_PASS failed_prove_clears_destination, CHECK_PASS failed_prove_cannot_verify,
CHECK_PASS prove_valid_recovery, CHECK_PASS retry_negative_fixture_found,
CHECK_PASS fs2_cap_reaches_stage_and_fails_closed, CHECK_PASS fs3_cap_reaches_stage_and_fails_closed,
CHECK_PASS h0_rng_failure_fails_closed_and_counts_abort,
CHECK_PASS fs2_rng_failure_fails_closed_and_counts_abort,
CHECK_PASS fs3_rng_failure_fails_closed_and_counts_abort. The exact full probe output is retained in
build-filter-native/guarded-command-vole-r4-run-20260912.stdout.log (6865 bytes, SHA-256
F98F33E629BCB17D3C6C6F424A6CBF79EFF2288285E110D3B1D5272A577E675F) and the guard transcript is
build-filter-native/acceleration-vole-r4-run-20260912.transcript.log (7296 bytes, SHA-256
0F018CC926BC2A6B2C17DED1881C19DB64A3B7EE19032424C6EAF57B20560DA2).

The native probe's exact stage evidence was:

  DMV_STAGE_CLOCK ticks_per_second=1000 h0=0 commitment=1284 construction=57 fs2=2 relation=1626 fs3=145
  E2E_VERIFY_STATUS status=0 clock_ticks=2613 ticks_per_second=1000
  DMV_RETRY_COUNTERS h0=1/1/1/0/0/0 fs2=6/6/1/5/0/0 fs3=93610/93610/1/93609/0/0
  TRANSCRIPT_CACHE_DERIVED fs2_fixed_prefix_bytes=8044 fs3_fixed_prefix_bytes=8320 fresh_queries_unchanged=1 final_nonce_length_word_preserved=1 fs2_multi_nonce=1 fs3_multi_nonce=1 reinit_changed_input=1 cache_clear_zeroed=1
  SOURCE_BOUND_COUNTS ell=125048 m=172232 bitness=125048 inverse=26192 equality=7424 tag=768 range=12800 sboxes=13096 aes_blocks=58 key_schedules=2 prover_calls=1 verifier_calls=1 counts_equal=1
  E2E_WIRE_SIZE bytes=534295 written=534295 statement=1072 nu=96 nonces=192 m1=506416 m2=15887 m3=96 m4=10496

Final fixture gate:

The corrected fresh final fixture configure/build/CTest completed with one registered test and
runner exit 0. Its verbatim CTest result was:

  1: STATUS NON_ACTIVATING_DIRECT_MASK_FIXTURE_PROBE cases=20 failures=0
  1/1 Test #1: direct_mask_fixture_probe ........   Passed    0.06 sec
  100% tests passed, 0 tests failed out of 1
  Total Test time (real) = 0.10 sec

The 20 preceding lines were all PASS checks, including exact request parsing, epoch/retry-cap/U
validation, fixed-seed key derivation and frozen public-key matching, DMSI source-input
construction/offset/encoding checks, one-callback matching-key behavior, and wrong-key rejection
before the producer callback. The fixture CTest stdout is 2479 bytes, SHA-256
AC8C9B22B30CAEF5668B5DCA2FDBCC4D9427EBAFBD6D4CCBA859A768310CB5D5, and its guard transcript is 1413 bytes, SHA-256
BBC5F132156934D1159D728B5FD67911A1C18899D2E84298C9C758AD196D4E05.

Independent containing pipeline gate:

The fresh short-path build-filter-native/tr4 graph used TrackFileAccess=true and completed the
MSVC compiler detection, root targets, and three nested probe projects through the adapted guard.
CTest registry output was exactly:

  Test #1: direct_mask_pipeline_probe
  Test #2: direct_mask_pipeline_real_symbol_gate
  Test #3: direct_mask_source_proof_probe
  Test #4: direct_mask_source_proof_real_symbol_gate
  Test #5: direct_mask_authenticated_proof_probe
  Test #6: direct_mask_authenticated_proof_real_symbol_gate
  Test #7: direct_mask_source_auth_probe
  Test #8: direct_mask_source_auth_real_symbol_gate
  Total Tests: 8

The completed full CTest output was:

  CHECK_COUNT=116 FAILED=0
  ALL_TESTS=PASS

  REAL_PIPELINE_CODEC_SYMBOL_GATE=PASS checked=3
  REAL_PIPELINE_SOURCE_SYMBOL_GATE=PASS checked=1
  REAL_PIPELINE_VERIFIER_SYMBOL_GATE=PASS checked=1
  REAL_PIPELINE_VERIFIER_NO_PRODUCER_DEPENDENCY_GATE=PASS checked=5
  REAL_PIPELINE_RELEASE_LINK_INPUT_GATE=PASS actual_non_system=8 expected_non_system=8 main_object=direct_mask_pipeline_verifier_main.obj
  REAL_PIPELINE_LINK_CLOSURE_GATE=PASS verifier_edges=29 source_edges=34 signer_allowance=dm_source_auth
  REAL_SOURCE_PROOF_SYMBOL_GATE=PASS checked=3
  REAL_NATIVE_PROOF_SYMBOL_GATE=PASS checked=2
  REAL_SOURCE_PROOF_CLOSURE_GATE=PASS forbidden=9
  REAL_AUTHENTICATED_PROOF_SYMBOL_GATE=PASS checked=3
  REAL_AUTHENTICATED_PROOF_CLOSURE_GATE=PASS forbidden=7
  REAL_SYMBOL_GATE=PASS checked=6
  WIRE_REAL_SYMBOL_GATE=PASS checked=4
  FAEST_REAL_SYMBOL_GATE=PASS checked=3
  MLDSA_REAL_SYMBOL_GATE=PASS checked=3
  SOURCE_CLOSURE_GATE=PASS forbidden=7
  100% tests passed, 0 tests failed out of 8
  Total Test time (real) = 31.22 sec

The full CTest stdout is 24637 bytes, SHA-256
10568F4C99F6B127E0ED2513AF68ABF6770668DAC75A184837F38DE3843B47C1; stderr is zero bytes with
SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855; guard transcript is
8250 bytes, SHA-256 F706A98D310E489ABFDE896766C7EFD3D75205C893AD54136ECA507E86C48B56.

Archive/source evidence was collected under the guard. dm_faest_public.vcxproj includes the
accepted child-local direct_mask_bf256_accel.c and fields.c with the two portable renames. The
normal containing archives' /linkermember:1 output showed:

  faest_primitives.lib: A450 bf256_mul, A450 bf256_mul_inplace, A450 direct_mask_bf256_backend_name, A450 direct_mask_bf256_pclmul_available; C046 direct_mask_bf256_mul_inplace_portable, C046 direct_mask_bf256_mul_portable
  faest_direct_mask_primitives.lib: 2F9D8 bf256_mul, 2F9D8 bf256_mul_inplace, 2F9D8 direct_mask_bf256_backend_name, 2F9D8 direct_mask_bf256_pclmul_available; 315D2 direct_mask_bf256_mul_inplace_portable, 315D2 direct_mask_bf256_mul_portable
  dm_faest_public.lib: 2F6B0 bf256_mul, 2F6B0 bf256_mul_inplace, 2F6B0 direct_mask_bf256_backend_name, 2F6B0 direct_mask_bf256_pclmul_available; 3128A direct_mask_bf256_mul_inplace_portable, 3128A direct_mask_bf256_mul_portable
  fixture pipeline_build dm_faest_public.lib: 2F77C bf256_mul, 2F77C bf256_mul_inplace, 2F77C direct_mask_bf256_backend_name, 2F77C direct_mask_bf256_pclmul_available; 3137A direct_mask_bf256_mul_inplace_portable, 3137A direct_mask_bf256_mul_portable

The dm_faest_public /symbols output counted one defined external bf256_mul, one defined external
bf256_mul_inplace, one defined external direct_mask_bf256_mul_portable, and one defined external
direct_mask_bf256_mul_inplace_portable; no production archive dump contained a
DIRECT_MASK_BF256_TEST_SEAM or direct_mask_bf256_test symbol line. The archive evidence transcript
is build-filter-native/acceleration-symbols-all-containing-archives-20260912.transcript.log, 1503
bytes, SHA-256 2CDC19678FCFBF44C7085C65F529B4DFD6927C4879DB228B9F85AA32DB42F4E8. The fixture
archive evidence transcript is 1504 bytes, SHA-256
99F129797D51125A65171C2769F621A5D7AB2CA07F6310342141283F3553C392.

Successful guarded build warning audit used exact warning-code matches. No successful build log
contained an error diagnostic; runner stderr was zero for each successful build. Counts were:

  kernel normal: 301 = C4090:1, C4141:300
  kernel forced: 343 = C4090:1, C4141:300, C4702:42
  VOLE: 575 = C4090:1, C4141:497, C4146:67, C4244:5, C4267:1, C4324:4
  final fixture: 1020 = C4090:1, C4141:889, C4146:104, C4244:5, C4267:1, C4324:20
  independent root target batch: 1076 = C4090:1, C4141:938, C4146:109, C4244:5, C4267:1, C4324:22
  nested source-proof probe: 112 = C4141:98, C4146:10, C4324:4
  nested authenticated-proof probe: 210 = C4141:196, C4146:10, C4324:4
  nested source-auth probe: 112 = C4141:98, C4146:10, C4324:4

The warnings are inherited MSVC/vendor diagnostics; no warning was suppressed or relabeled. Key
successful build log sizes/hashes are retained at the exact names above and in the generated
directory. The following produced artifact identities were verified after the final runs:

  kernel normal probe: 68608 bytes, SHA-256 A962BB826052C2261DB01BAE6ECAB112F94B5396E40FD2007FCDFDAD7BB2AF75
  kernel forced probe: 16384 bytes, SHA-256 7933173D709BFB5A62B71FE505A93509F61EECDD0BD74AD002D61E74F4745443
  VOLE probe: 284160 bytes, SHA-256 C4EF4CFC9CCAE9E58D23FC5FA938880E5C132614CA29FD1B28DEEF2D176D3851
  final fixture probe: 41472 bytes, SHA-256 F711C2D408ABC3C2C778F7AE50791B64D292E19135133DE9CA9135A0E0B1F6D5
  independent dm_pipeline_probe: 319488 bytes, SHA-256 C2E077F0E7B753CA119FA8548C0C68EEF9341BC806277E52865839ACBD3466A6
  independent dm_pipeline_verifier_cli: 242176 bytes, SHA-256 C85868219B6878573B741129E8084D75D1F24083055B831C092A0135EAD24780
  independent dm_faest_public.lib: 334556 bytes, SHA-256 54EDA128F63435640461026DD06C3C94761D22CFD4CF2D34A61E84F64D0DDE29

Retained failures and corrections (none are silently skipped):

- Initial kernel normal configure, r2, and r3 failed only at MSVC FileTracker try-compile setup,
  respectively with 9, 2, and 9 FTK1011 errors. Their complete stderr/transcripts remain
  acceleration-kernel-normal-configure-20260912 (2472 bytes, SHA-256 579F57AFD33DEC9AE77AF938B5C81D989FE938C3AD5CFDAE728FF20F926E7C48),
  acceleration-kernel-normal-r2-configure-20260912 (2347 bytes, SHA-256
  7348A91C3F1FD000DD736E85E5708B75FB8CDE1CDC5CC0F7A8BE57A18C773959), and
  acceleration-kernel-normal-r3-configure-20260912 (2351 bytes, SHA-256
  78EC1FDC642C53DF4966B3263E6390D8DDC16629BFF68BF4736870C66712890C). The r4 configure
  succeeded after forwarding the tracking variable into try-compile with a fresh build path.
- The first final-fixture configure omitted the leading hyphen on DFAEST_REF_DIR and then reached
  the expected case-sensitive hash check, which reported expected uppercase
  08923E5EB209FFBFB89CC489D2C21770769F0AB45F31984BBC075DDDDCF52399 but got lowercase
  08923e5eb209ffbfb89cc489d2c21770769f0ab45f31984bbc075ddddcf52399. The complete failed transcript is
  acceleration-final-fixture-r4-configure-20260912.transcript.log, 2102 bytes, SHA-256
  0A89F5B8929D1D6CEB53DDD07171AC5A04D1831D8A6FDF19A47DFED776768867. The CMake comparison was
  corrected to normalize actual file hashes to uppercase; the accepted source bytes were not
  changed.
- The first independent r4 CTest batch returned exit 1: test 2 failed because it found zero
  current Release link.read tlogs where one was required, and tests 3, 5, and 7 were Not Run
  because their EXCLUDE_FROM_ALL nested executables had not been explicitly built. The preserved
  transcript is 3954 bytes, SHA-256 17FD05B8E94502982812043BF541B399880CABA873790B93C4BE126FB15BC68F.
- The first corrective r4 build with TrackFileAccess=true returned exit 1 with two FTK1011
  errors creating Lib-link.read.1.tlog and Lib-link.write.1.tlog under the nested
  mldsa_source_auth_wrapper project; transcript 5245 bytes, SHA-256
  9B791E499934417E4F81AEB4806656EA2BD7B717A2EFEC35BB4816F461B44420. A malformed outer command
  with doubled CMake path backslashes and two fresh long-path tlog configurations also failed;
  all guard cleanup/mutex checks passed and all complete logs remain under build-filter-native.
- A combined short-path build returned MSB1009 after successfully producing every root target,
  because CMake's root Visual Studio project did not expose nested target names. The nested
  projects were then built directly by their generated paths through the guard; all three
  completed with exit 0 and no error diagnostics. The final tr4 CTest batch had no Not Run tests.
- One early configure transcript was initially created at the parent work directory by the outer
  shell and was immediately moved into build-filter-native; the final child-boundary file is
  acceleration-kernel-normal-r3-configure-20260912.transcript.log, 2351 bytes, SHA-256
  78EC1FDC642C53DF4966B3263E6390D8DDC16629BFF68BF4736870C66712890C. No parent stray file
  remains.

This phase proves only native arithmetic correspondence and the existing synthetic,
non-activating filtered probes/graph checks. It makes no product activation, availability,
custody, PQ security, protocol rollout, payment, or production-qualification claim, and no
private bytes were written to logs or disk. The narrow record commit for this phase has parent
28fb538521482289b2cfc9a13cc7960326600cd5; the resulting commit/tree and clean tracked status are
reported by the final handoff.

### Historical real forbidden-producer link-gate correction (superseded) — 2026-09-12

The native acceleration record above remains based at commit
1544339ec15b8d61fc537a190dce29d3fbd16bdb, tree
f2f1e2f3bf7ec26434463e805ff5aff25fba8e30. A retained real-symbol CTest run exposed that
the direct forbidden-library negative was a false pass: the fixture supplied the missing
relative path `dm_source_proof_build\\Release\\dm_source_proof.lib`, while the real producer
archive was under the configured `sp` output. The old raw line was:

  REAL_PIPELINE_FORBIDDEN_DIRECT_LIBRARY_NEGATIVE=PASS reason=controlled direct forbidden-dependency input closure: missing or non-file input c:/users/neers/documents/codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-direct-mask-filter-native-20260912/build-filter-native/tr4/dm_source_proof_build/release/dm_source_proof.lib

That prior result is preserved as failed evidence and is not relabeled as a valid gate.
The correction edits only `tools/direct_mask_pipeline/verify_real_symbols.cmake` and
`tools/direct_mask_pipeline/verifier_forbidden_direct_dependency_fixture.vcxproj`. The
fixture now requires the exact `@REAL_SOURCE_PROOF_LIBRARY@` placeholder, and the gate
requires the supplied normalized producer archive to exist as a file, to be present in the
materialized clone, to be in the expected input set, and to be rejected from the actual
verifier input set for the exact producer/materializer-symbol reason. The actual archive
used by the corrected run was
`build-filter-native/tr4/sp/Release/dm_source_proof.lib`, length 18582, SHA-256
E54ED7E74DED9C38B9AB8480A16136E28573369EE82EDF6A25FD04AE3F78F055.

The first guarded correction attempt was intentionally retained as a failed correction. Its
raw CTest error was:

  CMake Error at .../tools/direct_mask_pipeline/verify_real_symbols.cmake:964 (if):
    if given arguments:
      "direct_input_ok" "OR" "direct_expected_index" "EQUAL" "-1" "OR" "direct_actual_index" "NOT" "EQUAL" "-1" "OR" "direct_symbol_reason_index" "EQUAL" "-1"
    Unknown arguments specified

The syntax was corrected to `NOT direct_actual_index EQUAL -1`. The second guarded run used
the retained acceleration guard and ran only
`^direct_mask_pipeline_real_symbol_gate$`: CTest reported `1/1 ... Passed 12.32 sec`,
`100% tests passed, 0 tests failed out of 1`, and `Total Test time (real) = 12.34 sec`.
Its child stdout is 359 bytes, SHA-256
7E2F419EAFDF83937EC091319697938A773A5539681538E555435B11FBFA5A1A; stderr is zero bytes,
SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855. The decisive
raw gate evidence was:

  REAL_PIPELINE_FORBIDDEN_DIRECT_LIBRARY_NEGATIVE=PASS reason=actual producer archive forbidden-symbol rejection; expected_index=8; actual_index=-1; evidence=controlled direct forbidden-dependency input closure: non-system link input contains forbidden producer/materializer symbol: c:/users/neers/documents/codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-direct-mask-filter-native-20260912/build-filter-native/tr4/sp/release/dm_source_proof.lib
  REAL_PIPELINE_RELEASE_LINK_INPUT_GATE=PASS actual_non_system=8 expected_non_system=8 main_object=direct_mask_pipeline_verifier_main.obj
  REAL_PIPELINE_LINK_CLOSURE_GATE=PASS ... verifier_edges=29 ... source_edges=34 ... signer_allowance=dm_source_auth

The corrected run also retained PASS evidence for all existing malformed, duplicate,
conflicting, nested, disabled, commented, oversized, forbidden-edge, and missing-evidence
negative fixtures. The guard reported `CHILD_EXIT_CHECK exit7=7 exit0=0`,
`CHILD_EXIT_STATUS label=Command exit=0`,
`LIVE_PHYSICAL_SUMMARY label=Command samples=19 min_free_bytes=2231169024 reserve_bytes=1073741824 peak_working_set_bytes=65409024 peak_private_bytes=34312192`,
`CLEANUP=PASS label=Command owned_process_tree=empty`, and
`MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907`. No native computation,
relation/field arithmetic, wire data, or accepted acceleration bytes changed in this
gate-only correction. The full independent eight-test batch was not rerun for this repair;
only the affected real-symbol CTest was run under the accepted guard. A separate immutable
correction commit and its resulting tree are reported by the handoff.

### Historical rejected direct VOLE byte-pass fusion (superseded) — 2026-09-12

After the gate correction, the candidate base was commit
94b66f820b042449a89d734b100fea86c3add843, tree
a8832a7502143dd7dccd07158c7e6dd4294b7121. One bounded native latency candidate changed
only `tools/direct_mask_vole/direct_mask_vole.c` in `direct_convert_to_vole`: the existing
per-pair `v` accumulation pass and next-row XOR pass were fused into one byte loop using
the same left/right/next pointers, loop order, byte order, and XOR operations. No field,
relation, source-G0/G1, wire, filter, retry, transcript, opening, or secret-dependent
control-flow material changed.

The candidate build command was:

  cmake --build build-filter-native/acceleration-correction/vole-r4 --config Release --target direct_mask_vole_probe -- /m:1 /nologo

It exited 0 and produced `direct_mask_vole_probe.exe`. The guarded build raw evidence was:

  PHYSICAL_PREFLIGHT free_bytes=2083389440 reserve_bytes=1073741824
  CHILD_EXIT_CHECK exit7=7 exit0=0
  CHILD_EXIT_STATUS label=Command exit=0
  LIVE_PHYSICAL_SUMMARY label=Command samples=27 min_free_bytes=1893167104 reserve_bytes=1073741824 peak_working_set_bytes=255627264 peak_private_bytes=196509696
  CLEANUP=PASS label=Command owned_process_tree=empty
  MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907

The build child stdout is 285656 bytes, SHA-256
D06FB0FE917DE4C76432D5F23B910FA45E8A649DB97922FBAA4FAFDE8883AAE9; stderr is zero bytes,
SHA-256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855. Its warning
count was 575: C4090:1, C4141:497, C4146:67, C4244:5, C4267:1, C4324:4. No build
failure marker occurred.

The same deterministic VOLE probe then passed all checks. Decisive raw lines were:

  VOLE_IDENTITY rows=1792 mismatches=0 delta_zero=0
  TRANSCRIPT_CACHE_DERIVED fs2_fixed_prefix_bytes=8044 fs3_fixed_prefix_bytes=8320 fresh_queries_unchanged=1 final_nonce_length_word_preserved=1 fs2_multi_nonce=1 fs3_multi_nonce=1 reinit_changed_input=1 cache_clear_zeroed=1
  DMV_RETRY_COUNTERS h0=1/1/1/0/0/0 fs2=6/6/1/5/0/0 fs3=93610/93610/1/93609/0/0
  DMV_STAGE_CLOCK ticks_per_second=1000 h0=0 commitment=1352 construction=63 fs2=3 relation=1726 fs3=171
  E2E_WIRE_SIZE bytes=534295 written=534295 statement=1072 nu=96 nonces=192 m1=506416 m2=15887 m3=96 m4=10496
  E2E_VERIFY_STATUS status=0 clock_ticks=2887 ticks_per_second=1000
  SOURCE_BOUND_COUNTS ell=125048 m=172232 bitness=125048 inverse=26192 equality=7424 tag=768 range=12800 sboxes=13096 aes_blocks=58 key_schedules=2 prover_calls=1 verifier_calls=1 counts_equal=1
  DIRECT_MASK_PROBE_COUNTS passed=70 failed=0
  DIRECT_MASK_PROBE_STATUS=PASS

The guarded probe raw evidence was:

  PHYSICAL_PREFLIGHT free_bytes=1675628544 reserve_bytes=1073741824
  CHILD_EXIT_CHECK exit7=7 exit0=0
  CHILD_EXIT_STATUS label=Command exit=0
  LIVE_PHYSICAL_SUMMARY label=Command samples=38 min_free_bytes=1900539904 reserve_bytes=1073741824 peak_working_set_bytes=23175168 peak_private_bytes=22392832
  CLEANUP=PASS label=Command owned_process_tree=empty
  MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907

The retained before sample from `build-filter-native/guarded-command-vole-r4-run-20260912.stdout.log`
was 6865 bytes, SHA-256 F98F33E629BCB17D3C6C6F424A6CBF79EFF2288285E110D3B1D5272A577E675F,
with:

  DMV_STAGE_CLOCK ticks_per_second=1000 h0=0 commitment=1284 construction=57 fs2=2 relation=1626 fs3=145
  E2E_VERIFY_STATUS status=0 clock_ticks=2613 ticks_per_second=1000

Thus the candidate measured +68 ms commitment, +100 ms relation, and +274 ms verification
on the one-sample clock, rather than a containing-path improvement. The retained baseline
guard observed 47 samples with minimum free bytes 3309027328, while the candidate probe
observed 38 samples with minimum free bytes 1900539904; the differing host load is a
measurement limitation, not evidence of a speedup. The candidate was therefore removed
with an explicit patch. The restored source blob is
970a3dd15b46dd36c4c7e83791edf60812ee7691, equal to `HEAD:tools/direct_mask_vole/direct_mask_vole.c`;
no latency candidate commit was created. Candidate logs and generated binaries remain only
under `build-filter-native/` as rejected-candidate evidence and are not release payload.

The candidate-only pipeline, malformed, link, kernel, standalone-field, and forced-fallback
runs were not performed after the candidate was removed: count 1 pipeline/malformed/link
batch skipped because the final source bytes were restored, and count 4 unchanged kernel/
field/fallback checks skipped because no kernel, arithmetic, or build-wiring source changed.
The corrected real-symbol gate and its malformed/link fixtures remain covered by the
separate gate-repair run above. Accepted acceleration C/H bytes remain unchanged at their
recorded hashes. No production activation or qualification claim follows from this rejected
latency attempt.

### Historical kernel byte-embedding accelerated dispatch (superseded) — 2026-09-12

Driver assigned a bounded native candidate for the measured hotspot in
`tools/direct_mask_kernel/direct_mask_kernel.c:125-132`. The vendor byte-combine path
uses seven `bf256_mul` calls per byte and the kernel invokes it twice for each of 13096
S-boxes. The kernel CMake intentionally compiles the pinned vendor `fields.c` with
`bf256_mul=direct_mask_bf256_mul_portable`, so the existing byte-combine call bypassed
the accepted public accelerated dispatch. This candidate routes the same fixed-basis
seven products through the public `bf256_mul` entry point, while preserving the vendor
and accepted acceleration sources byte-for-byte.

The candidate base before these edits was commit
`0c8f8fdc775e07202163a58d13d3a63853b411bf`, tree
`689102e24e851d2b63cbdbc46a70a9f90f4e217f`. The candidate source edits touched only
`tools/direct_mask_kernel/direct_mask_kernel.c` and the existing
`tools/direct_mask_kernel/direct_mask_kernel_probe.c`. No CMake file,
vendor file, accepted acceleration C/H file, protocol/wire/filter/retry/transcript
path, native materializer, runtime, adapter, or product State/Profile13 file changed.
The candidate source hashes before commit are:

  tools/direct_mask_kernel/direct_mask_kernel.c length 17495 SHA-256 23CE8AE880305931E526568E1E49329E10B097764696E3E818D7BDC8D07E3050
  tools/direct_mask_kernel/direct_mask_kernel_probe.c length 16612 SHA-256 CC0AEE1A77E7BFF720C63D6B3893671ED830363B8334FDD6702C16C76995B88D
  tools/direct_mask_vole/direct_mask_bf256_accel.c SHA-256 08923E5EB209FFBFB89CC489D2C21770769F0AB45F31984BBC075DDDDCF52399
  tools/direct_mask_vole/direct_mask_bf256_accel.h SHA-256 00E1D9C1E078BD35BCCA95AE76865590ED1B78969DAFBD89D85EBB7C09FF21E2
  pinned vendor fields.c SHA-256 6F3ED9280D56958F342790132357AB9D13517996B0B1ECE7F9D8E44DA78FD560

The implementation initializes `byte_basis[8]` once per kernel invocation using
`bf256_byte_combine_bits(&basis[i], 1 << i)`, then starts each embedding with bit 0 and
adds the seven products `bf256_mul(byte->bits[i], basis[i])` for i=1..7. The basis is
public, the loop bounds and order are fixed, no secret-indexed table or secret-dependent
branch is introduced, and the basis is covered by the existing state zeroization at
`direct_mask_kernel.c:390`. The probe now compares the vendor reference against the
same public-dispatch product expansion over four vectors (bit-valued, single-basis,
XOR-basis, and arbitrary four-word field values):

  BYTE_EMBEDDING_CORRESPONDENCE vectors=4 products=28 mismatches=0 status=PASS

The rejected fused VOLE candidate was restored before this kernel change. Its retained
binary is `build-filter-native/rejected-latency-vole-probe-fused-20260912.exe`, length
285184, SHA-256 `E77AE55B848A36DC8C432B1E46803789F3E1C0BE4028A5EE08318A5AAAFD3CFF`.
The restored pre-change VOLE baseline raw output was 6865 bytes, SHA-256
`99084319C64C7630F11225EDE0E485A88B3B303BD7A279DF1600164296BA3D47`, with:

  VOLE_IDENTITY rows=1792 mismatches=0 delta_zero=0
  DMV_STAGE_CLOCK ticks_per_second=1000 h0=0 commitment=1465 construction=67 fs2=2 relation=1685 fs3=174
  E2E_WIRE_SIZE bytes=534295 written=534295 statement=1072 nu=96 nonces=192 m1=506416 m2=15887 m3=96 m4=10496
  E2E_VERIFY_STATUS status=0 clock_ticks=2927 ticks_per_second=1000
  SOURCE_BOUND_COUNTS ell=125048 m=172232 bitness=125048 inverse=26192 equality=7424 tag=768 range=12800 sboxes=13096 aes_blocks=58 key_schedules=2 prover_calls=1 verifier_calls=1 counts_equal=1
  DIRECT_MASK_PROBE_COUNTS passed=70 failed=0
  DIRECT_MASK_PROBE_STATUS=PASS

Candidate standalone kernel, forced-portable kernel, VOLE, pipeline, nested probe, and
eight-test independent CTest runs were all executed through
`build-filter-native/run_guarded_acceleration_20260912.ps1` with mutex
`Local\\BlindLedgerDirectMaskBuild20260907`, child exit 7/0 checks, one heavy job,
physical reserve >=1073741824 bytes, and checked cleanup. All successful candidate
build/probe/CTest runner stderr logs were zero bytes with SHA-256
`E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.

Normal kernel candidate build command:

  cmake --build build-filter-native/acceleration-correction/kernel-normal-r4 --config Release --target direct_mask_kernel_probe -- /m:1 /nologo

The build exited 0; stdout length 150970, SHA-256
`071CD3324803384683D35BFDA56173393128B3C361A6E4DC2029E3D18F9B76CA`; warnings were
`C4090:1,C4141:300` and no failure marker occurred. Guard evidence was:

  PHYSICAL_PREFLIGHT free_bytes=2808442880 reserve_bytes=1073741824
  CHILD_EXIT_CHECK exit7=7 exit0=0
  CHILD_EXIT_STATUS label=Command exit=0
  LIVE_PHYSICAL_SUMMARY label=Command samples=9 min_free_bytes=2673893376 reserve_bytes=1073741824 peak_working_set_bytes=185696256 peak_private_bytes=144465920
  CLEANUP=PASS label=Command owned_process_tree=empty
  MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907

The normal probe stdout was length 1800, SHA-256
`CC9DECFA65AF0CE6A3CCF7BBDB68B46540A382B7DFAF83F88AC86BEE03D5578B`. Its complete
decision-relevant raw results were:

  BF256_ARITHMETIC_MODE=normal_dispatch
  BF256_ARITHMETIC_BACKEND=pclmul PCLMUL_AVAILABLE=1
  BF256_ARITHMETIC_BASIS_PAIRS=65536 BOUNDARY_VECTORS=17 BOUNDARY_PAIRS=289 CHECKS=460775 MISMATCHES=0
  BF256_ARITHMETIC_STATUS=PASS
  BYTE_EMBEDDING_CORRESPONDENCE vectors=4 products=28 mismatches=0 status=PASS
  FIELD_IDENTITY delta_case=0 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  FIELD_IDENTITY delta_case=1 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  FIELD_IDENTITY delta_case=2 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  FIELD_IDENTITY delta_case=3 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  ACTUAL_COUNTS ell=125048 m=172232 bitness=125048 inverse=26192 equality=7424 tag=768 range=12800 sboxes=13096 aes_blocks=58 key_schedules=2
  NEGATIVE name=root status=0 rows=172232 nonzero_leading=274
  NEGATIVE name=inverse status=0 rows=172232 nonzero_leading=325
  NEGATIVE name=g0 status=0 rows=172232 nonzero_leading=2077
  NEGATIVE name=value status=0 rows=172232 nonzero_leading=2
  NEGATIVE name=borrow_first status=0 rows=172232 nonzero_leading=2
  NEGATIVE name=borrow_last status=0 rows=172232 nonzero_leading=1
  NEGATIVE name=tag_T status=0 rows=172232 nonzero_leading=1
  NEGATIVE name=tag_U status=0 rows=172232 nonzero_leading=120
  NEGATIVE name=ciphertext_C status=0 rows=172232 nonzero_leading=1
  RANGE_NATIVE boundary=0 status=1 out_of_range=1
  NEGATIVE name=lower_minus_one status=0 rows=172232 nonzero_leading=1
  RANGE_NATIVE boundary=1 status=1 out_of_range=1
  NEGATIVE name=upper_plus_one status=0 rows=172232 nonzero_leading=1
  API_REJECTIONS callback=-91 non_boolean=-7 dimension=-3 context=-2 zero_U=-2
  DIRECT_MASK_KERNEL status=PASS skips=0 fixture_rng=deterministic cpu_seconds=2.311

The forced-portable layout was reconfigured with
`DIRECT_MASK_BF256_ARITHMETIC_ONLY=OFF` so it exercised the actual changed kernel. The
first reconfigure invocation had one malformed `-D` spelling; CMake exited 0 but emitted
the raw warning `Ignoring extra path from command line: DNATIVE_ORACLE_DIR=...`. It was
immediately corrected with the exact `-DNATIVE_ORACLE_DIR=...` spelling; corrected
stdout length 341, SHA-256
`6243F444FF3C85A1E5137769B2CCAF81DB92DBACF3DAB6BFB33C99A2837A896`, stderr zero.
The corrected full forced build exited 0; stdout length 150970, SHA-256
`F1FA022903AE45B071F73D7C3F314A8675BD04BC1979F812399548F68BA97E99`; warnings were
`C4090:1,C4141:300`; no failure marker occurred. Its guard evidence was:

  PHYSICAL_PREFLIGHT free_bytes=2922729472 reserve_bytes=1073741824
  CHILD_EXIT_CHECK exit7=7 exit0=0
  CHILD_EXIT_STATUS label=Command exit=0
  LIVE_PHYSICAL_SUMMARY label=Command samples=9 min_free_bytes=2808193024 reserve_bytes=1073741824 peak_working_set_bytes=151568384 peak_private_bytes=123305984
  CLEANUP=PASS label=Command owned_process_tree=empty
  MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907

The forced probe exited 0 and produced stdout length 1811, SHA-256
`9010A338AF1BD33E8BCB0739C7FD500F5C0DDED2B2F78222E4346DFB39AD3D7C`:

  BF256_ARITHMETIC_MODE=forced_capability_false
  BF256_ARITHMETIC_BACKEND=portable PCLMUL_AVAILABLE=0
  BF256_ARITHMETIC_BASIS_PAIRS=65536 BOUNDARY_VECTORS=17 BOUNDARY_PAIRS=289 CHECKS=460775 MISMATCHES=0
  BF256_ARITHMETIC_STATUS=PASS
  BYTE_EMBEDDING_CORRESPONDENCE vectors=4 products=28 mismatches=0 status=PASS
  FIELD_IDENTITY delta_case=0 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  FIELD_IDENTITY delta_case=1 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  FIELD_IDENTITY delta_case=2 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  FIELD_IDENTITY delta_case=3 prover=0 verifier=0 rows=172232 nonzero_leading=0 mismatches=0
  ACTUAL_COUNTS ell=125048 m=172232 bitness=125048 inverse=26192 equality=7424 tag=768 range=12800 sboxes=13096 aes_blocks=58 key_schedules=2
  NEGATIVE name=root status=0 rows=172232 nonzero_leading=274
  NEGATIVE name=inverse status=0 rows=172232 nonzero_leading=325
  NEGATIVE name=g0 status=0 rows=172232 nonzero_leading=2077
  NEGATIVE name=value status=0 rows=172232 nonzero_leading=2
  NEGATIVE name=borrow_first status=0 rows=172232 nonzero_leading=2
  NEGATIVE name=borrow_last status=0 rows=172232 nonzero_leading=1
  NEGATIVE name=tag_T status=0 rows=172232 nonzero_leading=1
  NEGATIVE name=tag_U status=0 rows=172232 nonzero_leading=120
  NEGATIVE name=ciphertext_C status=0 rows=172232 nonzero_leading=1
  RANGE_NATIVE boundary=0 status=1 out_of_range=1
  NEGATIVE name=lower_minus_one status=0 rows=172232 nonzero_leading=1
  RANGE_NATIVE boundary=1 status=1 out_of_range=1
  NEGATIVE name=upper_plus_one status=0 rows=172232 nonzero_leading=1
  API_REJECTIONS callback=-91 non_boolean=-7 dimension=-3 context=-2 zero_U=-2
  DIRECT_MASK_KERNEL status=PASS skips=0 fixture_rng=deterministic cpu_seconds=53.948

The forced run guard reported `PHYSICAL_PREFLIGHT free_bytes=2944192512 reserve_bytes=1073741824`,
`CHILD_EXIT_CHECK exit7=7 exit0=0`, `CHILD_EXIT_STATUS label=Command exit=0`,
`LIVE_PHYSICAL_SUMMARY label=Command samples=88 min_free_bytes=2812801024 reserve_bytes=1073741824 peak_working_set_bytes=25493504 peak_private_bytes=16003072`,
`CLEANUP=PASS label=Command owned_process_tree=empty`, and
`MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907`.

The candidate VOLE build command was the existing standalone target:

  cmake --build build-filter-native/acceleration-correction/vole-r4 --config Release --target direct_mask_vole_probe -- /m:1 /nologo

It exited 0 with stdout length 285656, SHA-256
`D06FB0FE917DE4C76432D5F23B910FA45E8A649DB97922FBAA4FAFDE8883AAE9`, stderr zero,
warnings `C4090:1,C4141:497,C4146:67,C4244:5,C4267:1,C4324:4`, and no failure marker.
Build guard evidence was:

  PHYSICAL_PREFLIGHT free_bytes=3424337920 reserve_bytes=1073741824
  CHILD_EXIT_CHECK exit7=7 exit0=0
  CHILD_EXIT_STATUS label=Command exit=0
  LIVE_PHYSICAL_SUMMARY label=Command samples=27 min_free_bytes=3197681664 reserve_bytes=1073741824 peak_working_set_bytes=196739072 peak_private_bytes=151777280
  CLEANUP=PASS label=Command owned_process_tree=empty
  MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907

The candidate VOLE probe exited 0; stdout length 6864, SHA-256
`8A2B4428BE9961A3CAEDAE9FF7E1D01D82C098759B41B8541B794EA68109B9E2`, stderr zero.
Decision-relevant raw results were:

  VOLE_IDENTITY rows=1792 mismatches=0 delta_zero=0
  TRANSCRIPT_CACHE_DERIVED fs2_fixed_prefix_bytes=8044 fs3_fixed_prefix_bytes=8320 fresh_queries_unchanged=1 final_nonce_length_word_preserved=1 fs2_multi_nonce=1 fs3_multi_nonce=1 reinit_changed_input=1 cache_clear_zeroed=1
  DMV_RETRY_COUNTERS h0=1/1/1/0/0/0 fs2=6/6/1/5/0/0 fs3=93610/93610/1/93609/0/0
  DMV_STAGE_CLOCK ticks_per_second=1000 h0=0 commitment=1264 construction=56 fs2=2 relation=543 fs3=158
  E2E_WIRE_SIZE bytes=534295 written=534295 statement=1072 nu=96 nonces=192 m1=506416 m2=15887 m3=96 m4=10496
  E2E_VERIFY_STATUS status=0 clock_ticks=1636 ticks_per_second=1000
  SOURCE_BOUND_COUNTS ell=125048 m=172232 bitness=125048 inverse=26192 equality=7424 tag=768 range=12800 sboxes=13096 aes_blocks=58 key_schedules=2 prover_calls=1 verifier_calls=1 counts_equal=1
  DIRECT_MASK_PROBE_COUNTS passed=70 failed=0
  DIRECT_MASK_PROBE_STATUS=PASS

Against the restored baseline, this one-sample run measured commitment 1465->1264,
construction 67->56, FS2 2->2, relation 1685->543, FS3 174->158, and end-to-end
verification 2927->1636 ticks at 1000 ticks/second. These are bounded host measurements,
not a performance qualification: the candidate probe guard observed 30 samples with
minimum free bytes 3347324928, while the baseline guard observed 41 samples with
minimum free bytes 2224844800. The candidate VOLE run guard reported
`PHYSICAL_PREFLIGHT free_bytes=3398123520 reserve_bytes=1073741824`,
`LIVE_PHYSICAL_SUMMARY label=Command samples=30 min_free_bytes=3347324928 reserve_bytes=1073741824 peak_working_set_bytes=23322624 peak_private_bytes=22380544`,
child exit 7/0, cleanup PASS, and mutex RELEASED.

The existing independent pipeline was rebuilt against the current kernel. Root build
command:

  cmake --build build-filter-native/tr4 --config Release --target dm_pipeline_probe dm_pipeline_source_cli dm_pipeline_verifier_cli -- /m:1 /nologo

It exited 0; stdout length 53650, SHA-256
`688490CBC508FC57EF254A8A3303B669CEA443E54EE27ADC7954D5E160B15594`; stderr zero;
warnings exactly `C4141:97,C4146:5,C4324:2`; no failure marker. The excluded nested
source-proof, authenticated-proof, and source-auth probe projects were each rebuilt
directly through the same guard, each reported `Build succeeded. 0 Warning(s) 0 Error(s)`,
and their stdout hashes were respectively
`A0123E95AFD35B426C17D95C13FCA3804114CAA04816C19C620DC3789618C135`,
`CB1B3B63A64AE98B0F646FF71B5591164DA6E896DF415D0A778E370640A9C4F9`, and
`BE8A8F292769EDD1E59FF1E3F77ECCA7298DFCFF6DCFAFDD3C35C4C84A18C029`.

The independent pipeline probe exited 0, stdout length 525, SHA-256
`4CFEB8FA0702CCE298133D87E9D5FD4F3E79A56331C1ECD8C9D59F9CD7F05A8F`, with:

  STATUS NON_ACTIVATING_DIRECT_MASK_PIPELINE
  SOURCE_INPUT_BYTES=5876 CAPSULE_BYTES=539013 VERIFIER_INPUT_BYTES=541781
  ONE_FRESH_SOURCE_PROOF=TRUE
  CHEAP_CASES_BEFORE_PROOF=TRUE
  OBSERVED_CONTEXT=source-auth U=source-auth KEY=source-auth EPOCH=source-auth CAPSULE_EPOCH=source-auth SIGNATURE=source-auth
  OBSERVED_HEADER=decode EMBEDDED_X=source-auth M3=proof
  MIXED_VERSION_REJECTED=TRUE
  SOURCE_OUTPUT_HAS_ONLY_SIGNATURE_AND_FRAME=TRUE
  VERIFIER_OWNS_NO_SOURCE_TRUTH_OR_STATE=TRUE
  CHECK_COUNT=116 FAILED=0
  ALL_TESTS=PASS

The final independent CTest command ran all eight tests under the guard:

  ctest --test-dir build-filter-native/tr4 -C Release -R ^(direct_mask_pipeline_probe|direct_mask_pipeline_real_symbol_gate|direct_mask_source_proof_probe|direct_mask_source_proof_real_symbol_gate|direct_mask_authenticated_proof_probe|direct_mask_authenticated_proof_real_symbol_gate|direct_mask_source_auth_probe|direct_mask_source_auth_real_symbol_gate)$ -V --output-on-failure

CTest stdout length 25114, SHA-256
`388F4FDEB697EBE0130DA848733620825DD876A9E805F054B0F593ABF205A807`, stderr zero. Raw
CTest result:

  1/8 Test #1: direct_mask_pipeline_probe .........................   Passed    3.69 sec
  2/8 Test #2: direct_mask_pipeline_real_symbol_gate ..............   Passed   12.33 sec
  3/8 Test #3: direct_mask_source_proof_probe .....................   Passed    4.06 sec
  4/8 Test #4: direct_mask_source_proof_real_symbol_gate ..........   Passed    0.38 sec
  5/8 Test #5: direct_mask_authenticated_proof_probe ..............   Passed    3.98 sec
  6/8 Test #6: direct_mask_authenticated_proof_real_symbol_gate ...   Passed    0.31 sec
  7/8 Test #7: direct_mask_source_auth_probe ......................   Passed    0.10 sec
  8/8 Test #8: direct_mask_source_auth_real_symbol_gate ...........   Passed    0.26 sec
  100% tests passed, 0 tests failed out of 8
  Total Test time (real) = 25.80 sec

The pipeline probe had `CHECK_COUNT=116 FAILED=0 ALL_TESTS=PASS`; source-proof had
`CHECK_COUNT=96 FAILED=0 ALL_TESTS=PASS`; authenticated-proof had
`CHECK_COUNT=58 FAILED=0 ALL_TESTS=PASS`; source-auth had
`CHECK_COUNT=86 FAILED=0 ALL_TESTS=PASS`. All four real-symbol gates passed. The raw
negative suite retained PASS for malformed, duplicate, conflicting, nested, disabled,
commented, oversized, forbidden-edge, and missing-evidence fixtures. The decisive
link/verifier lines were:

  REAL_PIPELINE_FORBIDDEN_DIRECT_LIBRARY_NEGATIVE=PASS reason=actual producer archive forbidden-symbol rejection; expected_index=8; actual_index=-1; evidence=controlled direct forbidden-dependency input closure: non-system link input contains forbidden producer/materializer symbol: c:/users/neers/documents/codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-direct-mask-filter-native-20260912/build-filter-native/tr4/sp/release/dm_source_proof.lib
  REAL_PIPELINE_CODEC_SYMBOL_GATE=PASS checked=3
  REAL_PIPELINE_SOURCE_SYMBOL_GATE=PASS checked=1
  REAL_PIPELINE_VERIFIER_SYMBOL_GATE=PASS checked=1
  REAL_PIPELINE_VERIFIER_NO_PRODUCER_DEPENDENCY_GATE=PASS checked=5
  REAL_PIPELINE_RELEASE_LINK_INPUT_GATE=PASS actual_non_system=8 expected_non_system=8 main_object=direct_mask_pipeline_verifier_main.obj
  REAL_PIPELINE_LINK_CLOSURE_GATE=PASS ... verifier_edges=29 ... source_edges=34 ... signer_allowance=dm_source_auth

The eight-test CTest guard reported:

  PHYSICAL_PREFLIGHT free_bytes=3165589504 reserve_bytes=1073741824
  CHILD_EXIT_CHECK exit7=7 exit0=0
  CHILD_EXIT_STATUS label=Command exit=0
  LIVE_PHYSICAL_SUMMARY label=Command samples=43 min_free_bytes=2947284992 reserve_bytes=1073741824 peak_working_set_bytes=66465792 peak_private_bytes=36622336
  CLEANUP=PASS label=Command owned_process_tree=empty
  MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907

The corrected producer archive used by the gate was
`build-filter-native/tr4/sp/Release/dm_source_proof.lib`, length 18582, SHA-256
`E54ED7E74DED9C38B9AB8480A16136E28573369EE82EDF6A25FD04AE3F78F055`. Candidate
pipeline artifacts included current `dm_wire_codec.lib` length 295812 SHA-256
`BF1C7C3305B6825937774E2F133E2E2561DD57620D188FE669D8932D32A997E1`, current kernel
object length 42928 SHA-256
`57F6EB04C61AF6DE2A0631292853F5B85D86233813764F2B468D64B777BB7AF6`, and unchanged
`dm_faest_public.lib` length 334556 SHA-256
`54EDA128F63435640461026DD06C3C94761D22CFD4CF2D34A61E84F64D0DDE29`.

Skipped or non-qualification items are explicit: final candidate CTest skipped 0 of 8;
kernel normal/forced negative and 65536-pair arithmetic coverage skipped 0; nested
probe builds skipped 0. One separate repeated performance sample was not run because
the available measurements are one-sample host-load observations and the guard's
single-heavy-job resource policy was preserved. Product activation, real data,
payments/custody, publication, and security qualification remain out of scope (five
non-actions). The malformed forced reconfigure was corrected and rerun; it is a
diagnostic recovery, not a test failure. No private witness bytes were logged or written
to disk. The candidate remains synthetic, non-activating, unselected, and unqualified.
