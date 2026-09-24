# Security task state: DMV2 opportunity-counter provenance

Updated: 2026-09-24

The final guarded verification and current handoff state are recorded in the last section below; it supersedes earlier “Security has no direct handoff” and “verification deferred” statements in this historical log.

## Checkout and change identity

- Git root: `C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/lean-security-20260913`
- HEAD: `4452126284007a836c5801606bcbd713393274ed`
- HEAD tree: `55d8cd9f0a07a512782113790928eb378529f633`
- Branch: detached at HEAD.
- Recovery snapshot manifest SHA-256: `5BED13558A23898CACD66B579CBCB50A2C46915157106117D8B8EA75B453286F` (read-only hash).
- Guarded v4 wrapper SHA-256: `57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`; physical-free floor: `2,190,433,321` bytes. The wrapper was identity-checked, not invoked.
- At this checkpoint, Git reports 10 tracked modified paths, 7 untracked paths, and 0 staged paths. The tracked paths are `formal/lean/ARITHMETIC_EVIDENCE.md`, `formal/lean/BlindLedger/Arithmetic.lean`, `AxiomCheck.lean`, `SecurityExecutable.lean`, `formal/lean/README.md`, `formal/lean/lakefile.toml`, and `tools/direct_mask_contract/CONTRACT_V2.md`, `calculator_v2.py`, `lean_adapter.py`, and `test_calculator_v2.py`. Existing dirty changes in the calculator and test file are preserved; this record does not attribute their full diffs to this task. Untracked paths are Driver-added `AGENTS.md`, these two task records, `formal/lean/.lake/`, `formal/lean/artifact_receipt.v2.json`, `tools/direct_mask_contract/__pycache__/`, and `tools/direct_mask_contract/olean_imports.lean`. Nothing was staged. This task changed the contract, calculator, and directly affected test among the allowed source paths; it did not modify `ARITHMETIC_EVIDENCE.md`, theorem sources, Queue, State, Engine, Financial, native code, or the Driver acceptance entry point.

Current task-source identities:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `tools/direct_mask_contract/CONTRACT_V2.md` | 111,781 | `61C6D22819346C6E73D8147750678616C59A370DB33FEDC859D561EEC64172C0` |
| `tools/direct_mask_contract/calculator_v2.py` | 227,228 | `016A5D3B6A9EE7871658ED64904CCE9C121A79C7D0E90E009F7269BFE8875871` |
| `tools/direct_mask_contract/test_calculator_v2.py` | 134,151 | `4825C634E757C209AE24C149F830161AEB9864B3FD0E06FF16501CDB6CD8F9E0` |
| `formal/lean/ARITHMETIC_EVIDENCE.md` (pre-existing dirty work; untouched here) | 66,445 | `956D8A17FD90219821D3DE4D1AC516248CB1BD184C6CCC6BA9004739FF8C12E9` |
| `CURRENT_TASK.md` (this assignment boundary) | 3,586 | `634F902EACB138F719523CC19D4D77F86FA58E1F89E663CB4EBF0DC5143DFD79` |

## Findings and decision

The unchanged soundness ledger formulas are `q = Q + 35*A + 38*V + R0 + R2 + R3 + 38` and `q_hist = Q + 39*A + 41*V + R0 + R2 + R3`. Their arithmetic and theorem meaning were not changed.

`CONTRACT_V2.md:304-400` defines the counted events and enforcement boundary. `A` includes admitted attempts that fail or abort; `S` is distinct source commitments; `M` is fresh commitments; `E_U` is independent source-U issuance; `V` is backend verifier invocation; `Q` is all adversarial QRO queries, including offline work; and `R0/R2/R3` are stage-specific candidate reservations including failed, aborted, and unknown outcomes. The calculator has no authenticated global event ledger.

Queue evidence was re-anchored to Queue HEAD `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`: writer `app/minimal_clearance_verification_queue.py` is 227,531 bytes / `FD55BABFA9266A87BB859F0129E2E63BE50A575D1F3BF8E722B6A16C4CC6C10E`; independent decoder is 145,820 bytes / `3101847DE2681A105A6E9521344B332649CF76BF33B0ED082C322C3708D662CF`. It is schema 13/Profile 12, exact-100, with a local 101-unit no-refund reservation. Local source-admission ceilings are A=1, S=4096, M=100, U issuance=1; V=1 is charged before verifier execution. These are not a DMV2 global ledger, and Profile 12 does not inherit this proposal. Queue has no Q counter or separate R0/R2/R3 outcome ledger. The keyed v1 issue API retries against the same authoritative SQLite history; the legacy unkeyed API lacks a same-request retry identity. Queue’s current task states external rollback protection is not added.

State evidence was re-anchored to State HEAD `ab66da45854e3cb1c35a620b0c1aa3a3051f79ac`. `app/transactional_database_boundary.py` is 155,801 bytes / `CA5C206FC0C834EE8F1BE8B252771A6F5DBF361E788439882B8BFC45F45B8A4F`. State exposes an optional `AntiRollbackReference`; its bundled in-memory implementation is test-only. Queue counter history is not bound to that reference, and no independently durable production anchor was identified.

Lane handoff evidence: Queue HEAD is `b0e39a8e1adcfb7e8f610dae0cba75fc20e23d55`; its `CURRENT_TASK.md` is 119,838 bytes / `1AACE198468F5A255E8A1C6D3249BF28789B631AE48886B9F67CD0DBBD256604` and requires the safe-boundary handoff after Engine and State release the lane. Engine HEAD is `907e32de63ab0d8133f2a7aff1441b06a1a884e8`; its `CURRENT_TASK.md` is 7,517 bytes / `2B1CE949564AAF002F4802C8C1ED09F91377BCE49E35BA6759E126116ACA493CC` and `STATE.md` is 62,698 bytes / `6873C15C8A6ECBBD9833E64D2345D1A43BFD3BDE8E11CED3188E99135CAF8686`. The latest Engine record states the lane is with State and has not returned directly to Engine. Accordingly, this Security task has no direct release or fresh preflight.

Decision: keep global admission false for caller-supplied counters while retaining conditional arithmetic. Service reservations cannot enforce offline `Q`. The versioned opportunity-ledger shape is only a proposal; no receipt is issued or trusted. Do not claim private-proof qualification until global service-event provenance, clone/rollback resistance, producer coverage, and the offline-Q assumption are independently resolved.

## Verification, skips, and limitations

- Source inspection and targeted static reads only; no source code was executed.
- Test runs: 0. The focused calculator test module `tools/direct_mask_contract/test_calculator_v2.py` is pending; its directly affected case is `FilteredContractV2Tests.test_consistent_counters_do_not_attest_global_scope`. That case expects `q=121` with conditional arithmetic available, while global admission remains false even if a caller sets the global-accounting flag.
- Skipped target count: 1 focused test module / 64 test methods, because Security has not received the direct guarded-lane handoff and has no fresh preflight. No method ran.
- Compiler/build/guard invocations: 0. No fresh Security preflight was taken.
- After writing the task records, `git diff --check` on tracked changes exited 0. It emitted the same Git line-ending warning for each of `formal/lean/ARITHMETIC_EVIDENCE.md`, `tools/direct_mask_contract/CONTRACT_V2.md`, `calculator_v2.py`, `lean_adapter.py`, and `test_calculator_v2.py`: `LF will be replaced by CRLF the next time Git touches it`. No whitespace error was reported. The newly created task records are untracked and are not included by `git diff --check`.
- Process-only failures corrected: the supplied top-level workspace folder was a wrapper, not a Git root (`Get-Content` reported missing AGENTS.md and Git reported `fatal: not a git repository`); the Security checkout was then located under the Driver work tree. Two attachment reads first failed because paths with spaces were passed without `-LiteralPath` (`A positional parameter cannot be found that accepts argument 'text.txt'`), then succeeded. One double-quoted PowerShell replacement interpreted Markdown backticks and damaged a new handoff paragraph in STATE.md; read-back caught it and a literal here-string restored the intended text. Three identity-row searches exited before writing; the final hash-based update succeeded. No source files were affected.
- Whole-system limitation: no authenticated service-wide counter root or offline adversarial-Q bound is established. The ledger interface, if implemented, would still not constrain offline Q by itself.
- Claims remain `proofSuiteId=null`, `production_usable=false`, `activation=false`.

## Next executable task

Wait for the direct safe-boundary lane release to Security. Verify the exact v4 wrapper, take a fresh target-specific preflight, then run only the focused calculator test module under the guard. Capture raw stdout/stderr and exit status, update this record, and return the lane at the safe boundary. Do not launch broad suites or duplicate the Driver-owned acceptance entry point.

## Local Direct Mask opportunity-accounting reducer v1 — source-only — 2026-09-23

### Assignment and repository identity

The newer Security assignment supersedes the calculator-only `CURRENT_TASK.md` objective above; its completed evidence and prior dirty work are retained here. The writable increment is a local, reusable Lean transition for service-observed opportunity events, a focused Lean example module, its versioned tool-side interface note, the necessary distinction in `CONTRACT_V2.md`, and the current task/state records. Existing `calculator_v2.py`, calculator tests, Lean arithmetic/theorem sources, `lakefile.toml`, Queue, State, Engine, Financial, and native code were not edited for this increment.

Security Git root: `C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/lean-security-20260913`.

- HEAD: `4452126284007a836c5801606bcbd713393274ed`
- HEAD tree: `55d8cd9f0a07a512782113790928eb378529f633`
- Branch: detached at HEAD; no commit or staging occurred.
- Final working status: 10 tracked modified paths, 10 untracked paths, 0 staged paths. This count preserves all previously observed tracked dirties and untracked evidence/build artifacts. This task changed no pre-existing dirty file except the already-dirty `tools/direct_mask_contract/CONTRACT_V2.md`, where it added a clarifying local-reducer subsection and amended the State/Queue proposal description.

### Implemented source and decisions

`formal/lean/BlindLedger/OpportunityAccountingV1.lean` defines schema `BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1`, bounded typed scope/event/commitment IDs, typed `R0/R2/R3` stage requests, a caller-held ordered event history, pure reserve/finalize transitions, structural history replay, and stable ASCII result/reservation/terminal encodings. Reservations charge before work. Exact request retry returns the same reservation receipt and any available terminal receipt; changed input under an admitted ID conflicts. Pre-admission denial leaves the state and event ID unused. `COMPLETED`, `REJECTED`, `FAILED`, `ABORTED`, and `UNKNOWN` finalize events without refunds.

The reducer applies `A,S,E_U,V <= 2^32`, `M <= A` with at most one fresh commitment per open attempt, `R0 <= 2^16*A`, `R2 <= 2^12*A`, and `R3 <= 2^22*A`. `Nat` avoids machine wraparound and checked increments reject cap overflow. It also records stage evaluation starts in separate local counters and requires cumulative `EVAL_R0<=R0`, `EVAL_R2<=R2`, and `EVAL_R3<=R3`; these counters are not added to the soundness formulas. A stage-evaluation start is charged before evaluator work and remains charged when outcome is unknown. The aggregate invariant does not bind each evaluation to one reservation row.

`Q` is intentionally absent. Scope IDs are fixed by reducer transitions and there is no reset API, but callers can create another state, clone/restore data, or bypass the API. Structural replay is consistency checking, not an authenticated history. This code supplies no storage, transaction/CAS, producer or issuer authentication, global lifetime namespace, external monotonic authority, clone/rollback resistance, trusted/global receipt, or runtime admission. The owner adapter must serialize/CAS transitions, atomically persist state/history/receipt before work, not restart work on exact retry, and reconcile unresolved reservations/evaluation starts as `UNKNOWN`. No Python adapter was needed for the importable Lean operation; no `lakefile.toml` update was needed because the existing `BlindLedger` library discovers the new modules.

The existing State/Queue `BL/DIRECT-MASK/OPPORTUNITY-LEDGER/v1` remains a separate unimplemented owner interface. The local reducer is not connected to it, Profile 12, State's optional AntiRollbackReference, Queue, or Financial. It does not alter DMV2 algebra, theorem meaning, existing runtime admission denial, or qualification/activation claims.

### Changed-file identities

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `formal/lean/BlindLedger/OpportunityAccountingV1.lean` | 20,997 | `20194CC038640085FCDF66B377C37B604E505CE876A1F264378AD6C04C836272` |
| `formal/lean/BlindLedger/OpportunityAccountingV1Tests.lean` | 7,957 | `2826071956988635355ACBB3C00B74D8B4E6B2F175B2BF541E484705FC14FD5E` |
| `tools/direct_mask_contract/OPPORTUNITY_ACCOUNTING_V1.md` | 6,444 | `355DBD72048C99DB4C5F4F7727F4906D5DDD82E10DBBFBA5E7E1821B18959784` |
| `tools/direct_mask_contract/CONTRACT_V2.md` (pre-existing dirty file; this increment's clarification only) | 113,066 | `4094853FE1ECCBEA78F0644127B7318019A3628B81FCC272FAED7527DF8F726B` |
| `CURRENT_TASK.md` | 3,819 | `D0F3951EE1094DE4645597660E1B46C2DD92E37FFE055B261C8EF96716F7B730` |

The test source contains 32 Lean `example` declarations. The expected narrow guarded target is `lake build BlindLedger.OpportunityAccountingV1Tests` from `formal/lean`; it has not run.

### Verification, skips, and process evidence

- Source reads/review and identity/status reads only. Lean/Lake/compiler/executable/test/checker/guard invocations: 0. Fresh preflight: 0. The source-level examples have not been verified by compilation.
- Skipped target: 1 focused Lean module target / 32 source examples, because no direct safe-boundary handoff to Security or post-handoff preflight is present. No other suite was authorized in this source-only increment. `git diff --check` was not run because Security's instruction requires guarded handoff for checks as well as tests/builds.
- Latest Engine `CURRENT_TASK.md` identity is 8,662 bytes / SHA-256 `712678D5CB6C4BFDFB9BFE0628066BBBA23983486602DF4ADFE62CD90126875D`; its latest `STATE.md` says State/Driver holds the shared lane and no direct Engine return is present. Security has no direct lane handoff. Do not run the focused target, a compiler, or guard until Security receives the lane and takes fresh v4 preflight. The wrapper identity remains `57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`; floor `2,190,433,321` bytes.
- A read-only `git diff` of `CONTRACT_V2.md` emitted: `warning: in the working copy of 'tools/direct_mask_contract/CONTRACT_V2.md', LF will be replaced by CRLF the next time Git touches it`. No diff-check or line-ending normalization was attempted.
- Process-only path/patch errors were corrected without source loss. Initial task/state reads and Engine searches used parent paths missing the actual `work/lean-security-20260913` / `work/lean-engine-20260913` suffixes and returned path-not-found; the actual roots were listed and used thereafter. One PowerShell `git rev-parse HEAD^{tree}` expression was parsed incorrectly (`fatal: ambiguous argument 'dAByAGUAZQA='`); quoting `'HEAD^{tree}'` returned the recorded tree hash. A tool-side note was briefly copied to the supplied 2026-09-22 wrapper directory instead of the Security Git root; byte-identical copy SHA-256 matched at both paths, the unintended wrapper copy was removed, and `Test-Path` returned `False`. Seven patch attempts failed hunk/context/path matching and made no changes; later targeted patches succeeded. These failures did not affect pre-existing dirty files.

Claims remain `proofSuiteId=null`, `production_usable=false`, and `activation=false`.

## Local Direct Mask opportunity transition invariants — source-only — 2026-09-23

### Assignment, ownership, and repository state

This follow-on supersedes the prior source-only objective above only for the authorized increment. It strengthens the local reducer’s proof evidence and focused examples; it does not widen Security ownership. The writable paths for this increment were exactly:

- `formal/lean/BlindLedger/OpportunityAccountingV1.lean`
- `formal/lean/BlindLedger/OpportunityAccountingV1Theorems.lean`
- `formal/lean/BlindLedger/OpportunityAccountingV1Tests.lean`
- `CURRENT_TASK.md` and `STATE.md`

Security Git root: `C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/lean-security-20260913`.

- HEAD: `4452126284007a836c5801606bcbd713393274ed`
- HEAD tree: `55d8cd9f0a07a512782113790928eb378529f633`
- Branch: detached at HEAD; no commit or staging occurred.
- Current status: 10 tracked modified paths, 11 untracked paths, 0 staged paths. No pre-existing tracked dirty path was changed in this increment. The allowed Security source/test/task/state files remain untracked. Six other untracked paths are unchanged: `AGENTS.md`, `formal/lean/.lake/`, `formal/lean/artifact_receipt.v2.json`, `tools/direct_mask_contract/OPPORTUNITY_ACCOUNTING_V1.md`, `tools/direct_mask_contract/__pycache__/`, and `tools/direct_mask_contract/olean_imports.lean`. The 10 existing tracked dirty paths remain the paths enumerated in the earlier state section. No other checkout or owner path was edited.

### Implemented changes and theorem scope

`OpportunityAccountingV1.lean` now exposes deterministic lookup/replay/receipt/outcome helpers to the theorem module. `findEntry` is an explicit structural first-match recursion equivalent to the prior `List.find?` predicate. No reducer counter, cap, rejection, receipt bytes, encoding, or state transition rule was intentionally changed.

`OpportunityAccountingV1Theorems.lean` contains 33 theorem declarations. `AccountingInvariant` is componentwise counter-cap compliance, aggregate evaluation-start counts no greater than each reserved R0/R2/R3 total, and uniqueness of event IDs in the local entry list. The theorems cover:

- Replay bounds and event-ID uniqueness for arbitrary replay-accepted suffixes from a bounded/unique prefix, and those invariants for every `LedgerState.WellFormed` state.
- Per-reservation counter monotonicity, accepted-result caps/evaluation bounds, and append/fresh-ID shape for `.reserved` results.
- Exact retry returns the state and canonical reservation/terminal receipts associated with the existing entry; changed input returns `.inputConflict` and preserves the state/receipts.
- A rejected pre-admission request returns a structurally equal state and no receipt.
- Finalization leaves both counter records equal to their pre-finalization values. A repeated terminal outcome is `.exactRetry`; a different terminal outcome is `.inputConflict` with the state and prior receipt unchanged.
- Preservation of `AccountingInvariant` and componentwise counter monotonicity over an arbitrary finite list of reserve/finalize commands, including a theorem from `LedgerState.empty`.

The source-level examples now number 39. The trace example includes attempt and R0 reservation, R0 evaluation, `UNKNOWN` finalization, exact retry, and conflicting changed final outcome. Eighteen bounded `#print axioms` directives name these results: `replayEntries_preserves_bounds`, `replayEntries_arbitrarySequence_invariants`, `LedgerState.wellFormed_bounds`, `LedgerState.wellFormed_eventIdsUnique`, `LedgerState.wellFormed_invariants`, `reserveOpportunity_exactRetry`, `reserveOpportunity_changedInput_conflicts`, `reserveOpportunity_preAdmissionDenial_unchanged`, `reserveOpportunity_countersNeverDecrease`, `reserveOpportunity_success_appends`, `reserveOpportunity_preserves_accountingInvariant`, `finalizeOpportunity_preserves_accountingInvariant`, `runOpportunityCommands_preserves_accountingInvariant`, `runOpportunityCommands_countersNeverDecrease`, `runOpportunityCommands_fromEmpty_invariants`, `finalizeOpportunity_terminalOutcomeStable`, `finalizeOpportunity_countersUnchanged`, and `reserveOpportunity_acceptedState_bounds`.

These are local pure-function theorems. The theorem module states that an owner must keep one fixed scope, assign nonoverlapping scope identities, serialize writers or use CAS, and atomically persist the state/history/receipt before work. A missed commit/response recovery is only safe if retry observes that same durable result. The theorems do not authenticate the scope, event sources, issuers, or receipt; prove global scope/event-ID uniqueness; constrain offline `Q`; prevent bypass, clone, restore, or rollback; or bind every evaluation start to a specific reservation row. Those controls require an external authoritative owner/custody path. This work does not qualify a runtime authority or production use.

### Changed file identities

| File | Prior identity | Current identity |
| --- | --- | --- |
| `formal/lean/BlindLedger/OpportunityAccountingV1.lean` | 20,997 bytes / `20194CC038640085FCDF66B377C37B604E505CE876A1F264378AD6C04C836272` | 21,223 bytes / `D280A060B6F4F59A93182423A15892961D59DEA52C53170EEAFE220966EACC0A` |
| `formal/lean/BlindLedger/OpportunityAccountingV1Theorems.lean` | New file | 31,957 bytes / `213EEE4617BDC20827EECCD5B411C214B461AC52C3BAA2A8C11408350EEF9F62` |
| `formal/lean/BlindLedger/OpportunityAccountingV1Tests.lean` | 7,957 bytes / `2826071956988635355ACBB3C00B74D8B4E6B2F175B2BF541E484705FC14FD5E` | 10,021 bytes / `3757D77AEF8B9B57D117ED40E839CFE892FC4A676BF25231C53FC437BBA69581` |
| `CURRENT_TASK.md` | 3,819 bytes / `D0F3951EE1094DE4645597660E1B46C2DD92E37FFE055B261C8EF96716F7B730` | 4,152 bytes / `36939ED0AD046D3D1FAEE8A781C559627FBA20DF7B587E7D0C5DE5DB889F707C` |
| `STATE.md` | Existing untracked task record, SHA `8C593F71EC40C9C9E2F7BE906B1175533CF7C348AE1FF9DA7F4B90CC44682271` before this append | Updated by this section; self-hash is reported in the handoff message because embedding a final file hash in this file would change that hash. |

### Verification gate, skips, and process evidence

- Lean/Lake/compiler/executable/test/checker/guard invocations: 0. Fresh Security preflight: 0. No `#print axioms` output has been observed; all proof terms, imports, declarations, and examples remain uncompiled and unverified.
- Skipped target count: 1 focused target, `lake build BlindLedger.OpportunityAccountingV1Tests`; its 39 source examples and 18 axiom-report commands were not executed. Reason: no direct safe-boundary handoff to Security and no fresh target-specific v4 preflight. No worker was polled.
- `git diff --check` and all other checkers were not run because the direct handoff gate is still absent. No compiler/test failure or checker warning was produced in this increment.
- Two source-inspection command/patch errors were corrected without source loss: an unquoted PowerShell `git rev-parse HEAD^{tree}` was parsed as an invalid revision and returned a fatal argument error; quoting it produced the tree identity recorded above. Two patch hunks failed context matching and made no change; targeted patches then succeeded. No other failure, warning, or skipped executable task occurred.
- Latest recorded Engine evidence says State/Driver holds the finite guarded lane; Security has not received direct handoff. Preserve wrapper SHA-256 `57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, physical-free floor `2,190,433,321` bytes, mutex and all v4 guard rules. Do not run or poll until the direct handoff and fresh preflight.

### Next action and claims

After direct safe-boundary release to Security, verify the wrapper identity and take a fresh target-specific preflight. Run only `lake build BlindLedger.OpportunityAccountingV1Tests` under the guarded v4 wrapper using the target’s documented `-MinimumStartFreeBytes`. Preserve complete output and exit status; fix only proof/source issues within the authorized paths and rerun the affected target under the guard. Review the exact 18 axiom reports, then return the lane at a safe boundary. Claims remain `proofSuiteId=null`, `production_usable=false`, and `activation=false`.

## Local Direct Mask opportunity transition invariants — guarded verification complete — 2026-09-24

### Assignment, identity, and source state

The explicit direct safe-boundary handoff in the current user task superseded the historical no-handoff wording above. Writable paths were exactly the three `formal/lean/BlindLedger/OpportunityAccountingV1*.lean` files, `CURRENT_TASK.md`, and `STATE.md`. The only follow-up after r6 was five scoped `set_option maxRecDepth 4096 in` command wrappers in the examples at test-source lines 31, 35, 57, 64, and 125. All 39 example propositions and `by decide` proof bodies remain unchanged. Reducer cap values, transitions, denial behavior, encodings, and theorem statements were not changed to address the recursion-depth failure.

Security root: `C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/lean-security-20260913`. HEAD `4452126284007a836c5801606bcbd713393274ed`, tree `55d8cd9f0a07a512782113790928eb378529f633`, detached branch. At final status: 10 tracked modifications, 11 untracked paths, 0 staged; no unrelated dirty path was edited, staged, or committed.

| Source | Bytes | SHA-256 |
| --- | ---: | --- |
| `formal/lean/BlindLedger/OpportunityAccountingV1.lean` | 21971 | `3D86093F36376D995B804FD1BD15091C35C5E310370C7E4A4673B324F316E457` |
| `formal/lean/BlindLedger/OpportunityAccountingV1Theorems.lean` | 32906 | `E230626A8E944F17F3B386A80115AA7BBCE8458DB6D374248230FCA16BAC174D` |
| `formal/lean/BlindLedger/OpportunityAccountingV1Tests.lean` | 10176 | `875CAC38C7157101F2AF99BEC4E5175CA0A8F33A9F3A7C0B65D6DB1A79D418CE` |

### Guarded run history

Only `lake build BlindLedger.OpportunityAccountingV1Tests` was run, from `formal/lean`, using `leanprover/lean4:v4.33.1`. Each invocation used Driver `work/pq-wide-seed-native-20260913/build-filter-native/run_guarded_v4.ps1`, SHA-256 `57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB`, `-Mode Command`, and `-MinimumStartFreeBytes 4190433321`. All invocations passed the guard exit self-tests (`CHILD_EXIT_CHECK exit7=7 exit0=0`), cleanup, and mutex release; target exits are shown below. The 2,190,433,321-byte physical-free hard floor was maintained.

| Run | Child / outer exit | Error headers | Warnings | Axiom infos | Minimum sampled free bytes | Outcome |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| r1 | 1 / 1 | 17 | 0 | 0 | 3907190784 | Ten Decidable synthesis errors and six `prefix`/record parser errors, plus generic build failure. |
| r2 | 1 / 1 | 2 | 0 | 0 | 3990986752 | Record-update parse error at reducer line 501 plus generic build failure. |
| r3 | 1 / 1 | 49 | 42 | 18 | 3835994112 | Theorem elaboration failed; partial `#print axioms` included `sorryAx` and is invalid as proof evidence. |
| r4 | 1 / 1 | 10 | 30 | 18 | 3740491776 | Nine theorem proof errors plus generic failure; partial axiom output included `sorryAx`. |
| r5 | 1 / 1 | 5 | 29 | 18 | 3656966144 | Four theorem proof errors plus generic failure; partial axiom output included `sorryAx`. |
| r6 | 1 / 1 | 6 | 30 | 18 | 3463540736 | Five receipt examples hit Lean’s default recursion-depth limit plus generic failure. |
| r7 | 0 / 0 | 0 | 30 | 18 | 2905444352 | Focused target compiled successfully. |

All raw logs are preserved in `C:/Users/neers/Documents/Codex/2026-09-04/blind-ledger-astra-driver-v1/work/pq-wide-seed-native-20260913/build-filter-native/` with run-specific names `guarded-command-security-opportunity-accounting-v1-20260924-rN.stdout.log`, `guarded-command-...-rN.stderr.log`, `security-wrapper-security-opportunity-accounting-v1-20260924-rN.stdout.log`, and `security-wrapper-...-rN.stderr.log`.

| Run | Child stdout bytes / SHA-256 | Child stderr bytes / SHA-256 | Guard stdout bytes / SHA-256 | Guard stderr bytes / SHA-256 |
| --- | --- | --- | --- | --- |
| r1 | 4578 / `B026309B5AE4E974A2329AD3A1C60C74DC93ECEBE5A75C0CF152E12824C87E20` | 20 / `C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F` | 6444 / `3FD0F36B48503A68EC17A92DF3CC03EB6B89250211E2445195A3A7F5CD1C0F20` | 0 / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` |
| r2 | 1363 / `D3CD9BECB2D8E6CF9AAD0CADC3CA88AE7ADF51273E14AEC14649F161E85A0004` | 20 / `C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F` | 2923 / `21BDF18DEC4C8E7E440D90F65537747794ACFA004D9C8C7500F618C25AC651F8` | 0 / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` |
| r3 | 144752 / `08A4B9886CF7D0BA43F0E8881231759D466BB49D520013E39D31AE5525DC87E0` | 20 / `C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F` | 7362 / `6CCC4574E3BF413EAD25238DB88E4BEF394D5F329584249B7E84F99F12794921` | 0 / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` |
| r4 | 40643 / `A91836BEA82BC620069983BD1992C1252C24FED96BE626E66B98DE9DA839D7CB` | 20 / `C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F` | 3676 / `E2781309D3050CEA70842F86E706979CBDEB90645C106773A50D2DC232D0D0BB` | 0 / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` |
| r5 | 25971 / `1CC4286187F872681A84956C3B04B9C29FF19B304DEDCF7138837394BDE76BDF` | 20 / `C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F` | 2799 / `298E65D6E4936FACD7B85C8F123BC5B841A6C0DBA79BE7E2535CCC64ACBD91EA` | 0 / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` |
| r6 | 14410 / `8B3D0E24023B38AC3631F65A9948FF1921B46C1DAD6489D57A5E960D15F74B30` | 20 / `C4A27DB198C4D8632369EE6102944EF46E83C20D685F7C17A6AAFF9CFCFC710F` | 3939 / `981747AD6B37BBCF7BF8392CE495608104AA6B46979BB8CB48E877DE2AD98C51` | 0 / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` |
| r7 | 12107 / `2A9878E3A2FCC346087FCEC533F9054F1F36B9078CCF4300EAEDDB992B1DEDA9` | 0 / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` | 6837 / `803C2F4E217327C695416C98215AFE24178A6BA8CA20ED76A59293CEF375C7E5` | 0 / `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855` |

R7 exact summary evidence: fresh outer preflight `free_bytes=4325511168`; wrapper preflight `free_bytes=4317765632`; target exit `0`; 38 process/memory samples; minimum sampled free `2905444352`; peak working set `1597190144`; peak private bytes `2270306304` (the owner’s process-tree cap waiver remained effective); cleanup passed and `Local\BlindLedgerDirectMaskBuild20260907` was released. Post-run target process count was 0, mutex availability check succeeded, and current free physical bytes were `4401655808`.

The 30 r7 warnings are all unused `simp` arguments in the theorem file. Their exact locations and unused arguments, as emitted, are:

```text
236:27 eventIds
352:16 hFind
358:18 hFind; 358:25 hReject
363:22 hFind; 363:29 hReject; 363:38 hReserve
369:26 hFind; 369:33 hReject; 369:42 hReserve
403:20 hFind; 406:24 hFind; 408:55 hFind
448:16 hFind; 452:31 hFind; 452:38 hReject
455:28 hFind; 455:35 hReject; 455:44 hReserve
459:32 hFind; 459:39 hReject; 459:48 hReserve
495:28 reserveOpportunity; 495:48 hWellFormed; 495:61 hFind; 495:68 hReject
496:24 hReserve; 541:20 hFind; 544:24 hFind; 546:55 hFind
```

Each warning has the linter hint `Omit it from the simp argument list.` and note `This linter can be disabled with set_option linter.unusedSimpArgs false`. No linter was disabled. The 18 successful axiom reports in the raw r7 build output depend on `propext`, `Quot.sound`, and once `Classical.choice` (for `runOpportunityCommands_countersNeverDecrease`). No `sorryAx` appears. A source scan found no `sorry`, `admit`, `unsafe`, or `axiom` tokens in the three Lean files. This is local Lake compilation evidence, not an independent isolated-kernel/trusted-runner check.

### Skips, whole-system limits, and handoff

Skipped targets within the one-target authorization: 0. Additional target builds and other test suites run: 0. The separate existing calculator suite remains outside scope (1 module / 64 methods not run); no broad suite or independent kernel checker was requested or run. Worker polling count: 0.

The local reducer remains unauthenticated caller-held state. It proves no global event identity, producer authentication, durable CAS/storage, clone/rollback resistance, offline-Q accounting, or per-row evaluation binding. It does not connect to Queue, State, Engine, or Financial authority. Claims remain `proofSuiteId=null`, `production_usable=false`, `activation=false`; no runtime or production claim follows from this build.

Brave was absent from the process snapshot (`brave_process_count=0`); no browser/application was started or closed. Security returned the shared lane to Driver at a fresh idle process/mutex boundary.

Read-only discovery issues corrected after compaction: one stale r6 log filename lookup and one initial parent-path calculation pointed at nonexistent paths; an initial hash call also passed a path array as one `-LiteralPath` value. All were corrected by using actual workspace paths and one-path-at-a-time hashing. No source, log, guard, or process state was changed by those failed reads.

## Direct Mask calculator and adapter source reduction — source-only — 2026-09-24

### Change and call graph

In the Security checkout at HEAD 4452126284007a836c5801606bcbd713393274ed / tree 55d8cd9f0a07a512782113790928eb378529f633, this source-only increment touched tools/direct_mask_contract/calculator_v2.py and tools/direct_mask_contract/lean_adapter.py. The existing changes and all unrelated dirty paths were preserved; no file was staged or committed.

calculator_v2.py now defines _GENERATOR_SECURITY_CONSTANTS once and uses it in _security_constants and _bounded_generator_feasibility_proposal_v3. The latter still consumes the same exact eKOS, e2, and e3 rationals and feeds _bind_formal_v3_rows; certificate_constants still compares Python constants to Lean cap output. row_bounds still compares seven exact rows and two bounds with Lean row output. concrete_feasibility still produces v2 and unselected v3 proposals through _computational_work_model; QROM/privacy outputs still use the formal runtime comparison. calculate_report_v2, its public calculate_report alias, and admission_ledger were not changed. The admission result remains false and global scope remains unattested.

In lean_adapter.py, three cache-miss branches now return their newly invoked result after _cache_put has deep-copied the stored value. Cache-hit _cache_get still deep-copies. _artifact_identity, _prepare_cache, input validation order, key shape, eviction, and formal invocation are unchanged. Existing copy-safety and identity tests remain unchanged but unrun.

The formal correspondence is retained at formal/lean/BlindLedger/Arithmetic.lean (eKOS, e2, e3, rowEval, v3 widths) and SecurityExecutable.lean; no Lean file, theorem, gate, output parser, manifest, contract, or report serializer was changed.

### Identities and source delta

| File | Before | After |
| --- | --- | --- |
| calculator_v2.py | 227,228 bytes / 4,099 lines / 016A5D3B6A9EE7871658ED64904CCE9C121A79C7D0E90E009F7269BFE8875871 | 227,148 bytes / 4,099 lines / E856869EDCCF6A950E604BB0E32827E712C87C4ECF873991BCFC7D99FDDBF2A9 |
| lean_adapter.py | 166,908 bytes / 3,632 lines / ED80B9E2992EEB62B1D1B337A50EA4915810E54A41AA2B96821240227CFE996B | 166,878 bytes / 3,632 lines / F44AF8A0C487596C491A233C835636262C0637F855DA83A141676D619C3FD0FE |
| test_calculator_v2.py | 134,151 bytes / 2,524 lines / 4825C634E757C209AE24C149F830161AEB9864B3FD0E06FF16501CDB6CD8F9E0 | unchanged |

Combined source shrink: 110 bytes; source line count unchanged. Current unchanged contract identity: CONTRACT_V2.md, 113,066 bytes / 4094853FE1ECCBEA78F0644127B7318019A3628B81FCC272FAED7527DF8F726B. Current manifest identity: manifest_v2.json, 159,947 bytes / 52AD258EC47A3163BD884768E350B033DE37D2F92B17BB2CEF0D0330FCEFA5A7.

### Verification, skips, and operational evidence

Static source and diff inspection only. Build/test/compiler/checker/preflight/guard invocations: 0; git diff --check: 0. One focused test module / 64 methods was skipped because Security had no direct v4 finite-lane grant or fresh target-specific preflight. No other test module was run. The prior Lean r1-r6 failures and r7 success with 30 unused-simp warnings are preserved in this file and CURRENT_TASK.md; r7 does not verify these Python changes.

Git emitted the existing line-ending warning for all three dirty Python files (calculator_v2.py, lean_adapter.py, test_calculator_v2.py): LF will be replaced by CRLF the next time Git touches it. Source line endings were not normalized.

Source-edit recovery: the first targeted replacement joined the shared-constant assignment with the following return and base_delta_linear_weight; static diff/readback exposed it and targeted edits repaired the line breaks. A later blank-line assertion reported expected one constant block separator, got 0 and made no write; readback showed spacing was already correct. Earlier discovery commands had stale parent paths, one PowerShell brace parse error, and one unquoted tree revision (fatal: ambiguous argument 'dAByAGUAZQA='); corrected reads succeeded. No unresolved command failure remains.

### Handoff

Next executable action: receive direct safe-boundary release of the finite v4 lane to Security, verify the exact guard, and take a fresh preflight using the calculator test target’s documented start condition. Run only tools/direct_mask_contract/test_calculator_v2.py, preserve complete output/warnings, then return the lane idle. The prior Lean target’s 4190433321 start floor is not reused for this different target.

Claims remain proofSuiteId=null, production_usable=false, activation=false. No report-byte equality, broader test, independent qualification, or production property was verified by this source-only change.

