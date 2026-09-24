# Current task: Direct Mask calculator and adapter source reduction

Updated: 2026-09-24
Status: Source-only reductions applied. Guarded verification remains pending a direct finite-lane handoff and fresh target-specific preflight.

## Objective and boundary

Consolidate duplicated exact arithmetic and remove redundant cache-miss copying in tools/direct_mask_contract/calculator_v2.py and tools/direct_mask_contract/lean_adapter.py. The focused test_calculator_v2.py is in scope for directly affected coverage; no assertion or fixture needed a source change, so the test file is unchanged.

This increment does not edit the manifest, report contract, Lean sources or theorem statements, caps, filters, gates, Queue, State, Engine, Financial, native code, or Driver guard. The source files already had dirty work before this increment; preserve it.

## Applied source reductions

- calculator_v2.py now has one immutable _GENERATOR_SECURITY_CONSTANTS tuple. _security_constants and the v3 proposal consume the same exact eKOS, e2, and e3 formulas. The existing manifest validation, formal cap result matching, v3 formal width-row matching, rational representation, rounding, caps, output keys, and report assembly remain in their prior code paths.
- lean_adapter.py returns the freshly produced result after _cache_put has deep-copied it into the cache. The three removed deepcopy(result) calls copied that fresh result a second time. Cache hits still go through _cache_get, which deep-copies; keys, identity checks, cache invalidation, LRU bounds, and _cache_put storage isolation are unchanged.
- The focused tests were not edited. Existing test_lean_adapter_cache_is_copy_safe_and_identity_checked mutates the first cap result and checks the subsequent cache read; existing row, v3, and report tests retain independent expected values.

## Producer/consumer graph and Lean correspondence

- certificate_constants obtains the Python exact constants through _security_constants, validates the manifest, then compares each rational, maximum, maximum-name predicate, and density predicates with run_formal_cap output.
- row_bounds uses those constants to compute the seven Python rows, maximum, and simplified bound, then compares j, each rational, maximum, and simplification result with run_formal_row(j).
- concrete_feasibility calls _computational_work_model, which emits both the v2 and v3 proposals. The v3 proposal uses the shared tuple, then runs _formal_result_cap and _bind_formal_v3_rows for the exact 384- and 512-bit rows and comparisons. V3 remains an unselected proposal.
- qrom_bound and privacy_bound compute Python values and compare counters, bounds, rational fields, and predicates with _formal_result_for_counters; cap reports continue to use _formal_result_cap.
- calculate_report_v2 assembles certificate constants/rows, QROM and privacy cap output, concrete feasibility, availability, and a fail-closed static runtime_admission. Public calculate_report remains its v2 alias. admission_ledger validates caller counters, calls the same report producer, adds runtime QROM/privacy evaluations, and retains admitted=false and UNATTESTED_GLOBAL_LIFETIME.
- The Lean correspondence remains in protected formal/lean/BlindLedger/Arithmetic.lean (eKOS, e2, e3, rowEval, and v3 width evaluation) and SecurityExecutable.lean (serialized cap/runtime/row fields). The adapter’s checked artifact identity and result parser remain in place. This is a source trace; no post-edit runtime or report-byte comparison was run.

## Source identities and repository state

Security Git root: C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/lean-security-20260913.

- HEAD: 4452126284007a836c5801606bcbd713393274ed
- HEAD tree: 55d8cd9f0a07a512782113790928eb378529f633
- Detached at HEAD; 10 tracked modifications, 11 untracked paths, 0 staged paths. Existing dirty work and untracked evidence are preserved.

| File | Before this increment | After this increment |
| --- | --- | --- |
| calculator_v2.py | 227,228 bytes / 4,099 lines / 016A5D3B6A9EE7871658ED64904CCE9C121A79C7D0E90E009F7269BFE8875871 | 227,148 bytes / 4,099 lines / E856869EDCCF6A950E604BB0E32827E712C87C4ECF873991BCFC7D99FDDBF2A9 |
| lean_adapter.py | 166,908 bytes / 3,632 lines / ED80B9E2992EEB62B1D1B337A50EA4915810E54A41AA2B96821240227CFE996B | 166,878 bytes / 3,632 lines / F44AF8A0C487596C491A233C835636262C0637F855DA83A141676D619C3FD0FE |
| test_calculator_v2.py | 134,151 bytes / 2,524 lines / 4825C634E757C209AE24C149F830161AEB9864B3FD0E06FF16501CDB6CD8F9E0 | unchanged; same identity |

The two source files are 110 bytes smaller in total; their combined line count is unchanged. CONTRACT_V2.md was not edited and is 113,066 bytes / 4094853FE1ECCBEA78F0644127B7318019A3628B81FCC272FAED7527DF8F726B. manifest_v2.json was not edited and is 159,947 bytes / 52AD258EC47A3163BD884768E350B033DE37D2F92B17BB2CEF0D0330FCEFA5A7. The three protected OpportunityAccountingV1*.lean files retain their recorded identities in the prior section.

## Verification, skips, and remaining evidence

- Static source and diff inspection only. Test/build/compiler/checker invocations: 0. Fresh preflight and guarded invocations: 0. git diff --check: 0.
- Skipped target: 1 focused module (tools/direct_mask_contract/test_calculator_v2.py), 64 test methods not run, because there was no direct v4 finite-lane grant and no fresh target-specific preflight. No other test target was run.
- The earlier Lean r1-r6 failures and the successful r7 target with 30 unused-simp warnings remain recorded below with raw logs. That prior Lean build does not verify these Python edits.
- Git reported its existing line-ending warnings for calculator_v2.py, lean_adapter.py, and test_calculator_v2.py: LF will be replaced by CRLF the next time Git touches it. No line-ending normalization was run.
- The first exact replacement joined a constant assignment to the following return line and did the same at base_delta_linear_weight; static diff inspection exposed both joined forms, and targeted replacements restored their line breaks. A later separator assertion returned expected one constant block separator, got 0; it made no write, and readback showed the two blank lines were already present. No build or test was run to hide these editing errors.
- Discovery-only command issues, all corrected without source changes: the first map/architecture paths omitted the Driver work layout; one combined PowerShell inspection had Unexpected token '}' ; and an unquoted HEAD^{tree} was parsed as an invalid revision (fatal: ambiguous argument 'dAByAGUAZQA='). The corrected map, architecture, and quoted tree were read successfully.

## Next action

Obtain the direct safe-boundary v4 lane handoff to Security, verify the guard identity, and take a fresh target-specific preflight. Then run only the focused calculator v2 test module using that target’s documented start floor. Preserve full output and warnings, update the exact result here, and return the lane at a clean process/mutex boundary. Claims remain proofSuiteId=null, production_usable=false, and activation=false.

## Previous task record: local Direct Mask opportunity transition invariants

Updated: 2026-09-24
Status: the focused Lean target compiled successfully under the guarded v4 lane; Security returned the lane to Driver at a clean process/mutex boundary.

## Objective and boundary

Strengthen the Security-owned local opportunity reducer with Lean proofs over replay-accepted event sequences and reserve/finalize command traces. The proof scope is one caller-held `LedgerState` with a fixed `ScopeId`. Keep transition semantics, caps, theorem statements, and example propositions unchanged. This work does not create a global ledger, runtime admission authority, authenticated receipt, production qualification, or protection against offline QRO queries, cloned state, or rollback.

The writable paths for this increment were exactly:

- `formal/lean/BlindLedger/OpportunityAccountingV1.lean`
- `formal/lean/BlindLedger/OpportunityAccountingV1Theorems.lean`
- `formal/lean/BlindLedger/OpportunityAccountingV1Tests.lean`
- `CURRENT_TASK.md`
- `STATE.md`

All other dirty paths were preserved. No path was staged or committed.

## Implemented proof surface

`OpportunityAccountingV1.lean` defines the pure local event reducer and its bounded Nat counters, receipt encodings, structural replay, and reserve/finalize transitions. Caps, denial outcomes, receipt bytes, and transition semantics were not intentionally changed.

`OpportunityAccountingV1Theorems.lean` contains 33 theorem declarations over replay bounds/event-ID uniqueness, well-formed states, retries/conflicts, pre-admission immutability, counter monotonicity/equality, accounting-invariant preservation, and finite command traces. Eighteen `#print axioms` directives cover the named results. `OpportunityAccountingV1Tests.lean` contains 39 examples. Five receipt-string examples use a local `set_option maxRecDepth 4096 in`; their propositions and `by decide` proofs are unchanged.

## Guarded verification

Only the authorized target was run:

```text
lake build BlindLedger.OpportunityAccountingV1Tests
```

It was invoked from `formal/lean` using `leanprover/lean4:v4.33.1`, via `run_guarded_v4.ps1` SHA-256 `57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, `-Mode Command`, and `-MinimumStartFreeBytes 4190433321`. Fresh preflight free physical memory was `4325511168` bytes; the wrapper preflight was `4317765632` bytes. The v4 hard physical-free floor remained `2190433321` bytes.

Attempts r1-r6 all ran the same target and exited 1 at the child and guard. Their raw outputs are preserved as `guarded-command-security-opportunity-accounting-v1-20260924-rN.stdout.log` and corresponding `security-wrapper-...-rN.stdout.log` files in the Driver checkout's `work/pq-wide-seed-native-20260913/build-filter-native/` directory. Each matching stderr log is preserved there too.

| Run | Child/guard exit | Child error headers | Warnings | Axiom reports | Minimum sampled free bytes | Finding |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| r1 | 1 / 1 | 17 | 0 | 0 | 3907190784 | Decidable-instance synthesis and parser errors (`prefix`, then record syntax cascade). |
| r2 | 1 / 1 | 2 | 0 | 0 | 3990986752 | One record-update parse error at reducer line 501 plus generic build failure. |
| r3 | 1 / 1 | 49 | 42 | 18 | 3835994112 | Theorem elaboration failed broadly; its partial axiom output included `sorryAx` and is not valid proof evidence. |
| r4 | 1 / 1 | 10 | 30 | 18 | 3740491776 | Nine theorem proof errors plus generic build failure; partial axiom output included `sorryAx`. |
| r5 | 1 / 1 | 5 | 29 | 18 | 3656966144 | Four theorem proof errors plus generic build failure; partial axiom output included `sorryAx`. |
| r6 | 1 / 1 | 6 | 30 | 18 | 3463540736 | Five receipt examples hit the default recursion-depth limit plus generic build failure. |
| r7 | 0 / 0 | 0 | 30 | 18 | 2905444352 | Target completed successfully. |

R7 decisive raw output:

```text
CHILD_EXIT_CHECK exit7=7 exit0=0
PHYSICAL_PREFLIGHT free_bytes=4317765632 reserve_bytes=3221225472 reserve_floor_bytes=2190433321 target_start_floor_bytes=4190433321 effective_start_floor_bytes=4190433321 tolerance_percent=32
CHILD_EXIT_STATUS label=Command exit=0
LIVE_PHYSICAL_SUMMARY label=Command samples=38 min_free_bytes=2905444352 reserve_bytes=3221225472 peak_working_set_bytes=1597190144 peak_private_bytes=2270306304 reserve_floor_bytes=2190433321 tolerance_percent=32
CLEANUP=PASS label=Command owned_process_tree=empty
MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907
✔ [4/4] Built BlindLedger.OpportunityAccountingV1Tests (22s)
Build completed successfully (4 jobs).
```

R7 child stdout is 12,107 bytes / SHA-256 `2A9878E3A2FCC346087FCEC533F9054F1F36B9078CCF4300EAEDDB992B1DEDA9`; child stderr is empty / SHA-256 `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`. Guard stdout is 6,837 bytes / SHA-256 `803C2F4E217327C695416C98215AFE24178A6BA8CA20ED76A59293CEF375C7E5`; guard stderr is empty with the same empty-file hash. Full raw logs remain at the exact Driver paths above.

The 30 remaining warnings are unused `simp` arguments in `OpportunityAccountingV1Theorems.lean`; they do not disable checks or affect the passing target. All 18 r7 axiom reports are in the raw build log. They depend only on Lean's `propext`, `Quot.sound`, and, for `runOpportunityCommands_countersNeverDecrease`, `Classical.choice`; no `sorryAx` was reported. A source scan found no `sorry`, `admit`, `unsafe`, or `axiom` tokens in the three authorized Lean files. The build is local compilation evidence only, not an independent isolated-kernel or trusted-runner acceptance result.

## Source identities and repository boundary

Security Git root: `C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/lean-security-20260913`.

- HEAD: `4452126284007a836c5801606bcbd713393274ed`
- HEAD tree: `55d8cd9f0a07a512782113790928eb378529f633`
- Branch: detached at HEAD; 10 tracked modifications, 11 untracked paths, 0 staged paths. The 10 existing tracked dirties and all unrelated untracked paths remain intact.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `formal/lean/BlindLedger/OpportunityAccountingV1.lean` | 21971 | `3D86093F36376D995B804FD1BD15091C35C5E310370C7E4A4673B324F316E457` |
| `formal/lean/BlindLedger/OpportunityAccountingV1Theorems.lean` | 32906 | `E230626A8E944F17F3B386A80115AA7BBCE8458DB6D374248230FCA16BAC174D` |
| `formal/lean/BlindLedger/OpportunityAccountingV1Tests.lean` | 10176 | `875CAC38C7157101F2AF99BEC4E5175CA0A8F33A9F3A7C0B65D6DB1A79D418CE` |

## Safe boundary, skips, and claims

After r7, the target Lake/Lean process count was 0, the shared mutex was available, and free physical memory was `4401655808` bytes. Brave was not present in the process snapshot (`brave_process_count=0`); no browser/application was started or closed. The Security lane is returned to Driver at this idle process/mutex boundary.

Within the authorized scope, skipped targets: 0. Additional targets/builds and other test suites run: 0. The separate pre-existing calculator test module remains out of scope (1 module / 64 methods not run). No worker polling, broad suite, activation, or production operation was performed.

The reducer remains caller-held and unauthenticated. No external persistence/CAS, producer authentication, global event identity, rollback/clone resistance, offline-Q accounting, or per-row evaluation binding is established. Claims remain `proofSuiteId=null`, `production_usable=false`, and `activation=false`.
