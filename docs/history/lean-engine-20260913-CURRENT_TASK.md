# Engine current task

Updated: 2026-09-24

## Active delegated producer slice — source-only (2026-09-24)

Finish the self-contained `tools/build_financial_correction_release.ps1` producer and align the
Engine task/state/formal-kernel documents with Release's frozen
`RR/LEAN-ENGINE/BUILD-RECEIPT/v2` consumer contract. The current Release consumer identity was
read from `work/rightrail-financial-workflow-20260913/tools/right_rail_financial_service_kit.py`,
SHA-256 `28E13C9AF92ABC6CC14AE08E54A4C33619B970F371D08AC967D54896794679DD`. Its release-root
inventory is exact; the staged Lean build tree must stay outside it. The producer must retain raw
child and guard logs, bind the current v4 guard and all actual tool/source identities, and create
the canonical exact-38-field success receipt only after every check succeeds.

This is a source-only consumer handoff, not a runtime lane grant. Do not parse or execute the
producer, build Lean, run vectors/tests/checkers, invoke the guard, or create a receipt until a new
direct Driver lane grant and passing fresh v4 preflight. Release's producer source is packaged
from the Engine `tools` path; the Producer's output directory must contain only the exact
artifact, source manifest, six vector files, four logs, and receipt expected by the consumer.
State's separately reported `BLSDRQ01` route requires a different
`BL-STATE-SEMANTIC-ADAPTER/1` package and remains pending; this correction-transition producer
does not satisfy or change that State pin.

## Previous source-only fixed-point lane status (2026-09-24)

State directly handed the sole v4 lane to Engine after verified postrun cleanup/release. Engine's
first fresh v4 no-op Command preflight failed with `RUNNER_FAILURE reason=Access denied` (outer
exit 1) before physical preflight or launch; it returned no physical-free measurement and launched
no target. The wrapper emitted `MUTEX=RELEASED`, but did not emit `CLEANUP=PASS`. The attempted
lane-return message to State was rejected by automatic approval review
(`MCP tool call requires approval, but approval policy is never`), so State was not notified.
Driver's later direct update takes coordination custody; it is not a new target-run grant. Driver
reported an independent external pwsh 7.6.5 sample of 4,063,748,096 bytes, 126,685,225 below the
unchanged 4,190,433,321-byte target start floor, with compiler process count 0 and mutex absent.
That sample is not an Engine guard preflight or a substitute counter. After the user reported
changing permissions and directed a fresh shell, a new PowerShell 7.6.5 process verified the
expected wrapper/source hashes and HEAD/tree but the v4 no-op preflight again failed with
`Access denied` (outer exit 1), before physical preflight or launch; details are in STATE.md. Do
source review/preparation only in this exact Engine scope until Driver issues a new direct lane
grant. On a grant, use a fresh shell with functioning CIM and the exact v4 preflight; stop on access
denial or a below-floor measurement. Earlier guarded runtime/checker/KAT receipts predate this
refinement and do not verify it. Current-source Lean/Lake/compiler/KAT/checker/vector run counts
remain 0.

## Active source-only fixed-point refinement (2026-09-24)

`CorrectionTransition/Transition.lean` now proves that updating every case to the first evaluation's `caseStatus` leaves the full evaluation unchanged, provided the updated input still passes the existing well-formedness gate. The proof covers empty case lists and every `CaseStatus`: amount-satisfied branches ignore prior case status; unsatisfied `.CORRECTION_REQUIRED` and `.AUTHORIZED` remain stable; the other unsatisfied statuses normalize to `.OPEN`, which is stable after the update. `evaluateTotals` reads only payments and claims, so the case-only update cannot alter its totals.

`buildAccepted` carries the provisional evaluator result with its equality witness, retains the resulting-input well-formedness check and `.INVALID_INPUT` rejection, and uses the fixed-point theorem to certify that same result for the resulting input. The existing after-revision check remains. The accepted mutation-link result theorem is present in `CorrectionTransition/Theorems.lean`; both proofs remain source-only and uncompiled for the current source identity. Do not edit `Evaluation.lean`, codecs, KATs, or other source paths in this refinement.

State directly handed off the lane, and Engine attempted a fresh v4 preflight with the documented 4,190,433,321-byte start floor. The wrapper returned `Access denied` before a physical reading or launch. The attempted notification returning the lane to State was rejected, so State was not notified. Driver subsequently took coordination custody. Following the user's permission-change notice, a fresh PowerShell 7.6.5 process verified wrapper/source/HEAD/tree identities but the exact v4 preflight again returned `Access denied` before physical preflight or launch. Do not retry or lower the floor; continue source review/preparation only until Driver's direct target-run grant. Then use a fresh shell with functioning CIM and the exact v4 preflight, stopping if it is denied or below the target floor. The physical floor remains 2,190,433,321 bytes and the wrapper identity is recorded in the guarded-execution section below.

## Objective

Implement and expose the Engine-owned `FinancialOwner.reject_offset_and_authorize_correction`
transition with a typed dependency record and one narrow post-acceptance reuse assessment. The Lean
operation returns a typed transition or rejection, ordered effects, structured requirements,
post-state projection, bounded query observations, and follow-up identities. Reuse reports
calculation validity, persisted human-approval equality, local synthetic follow-up eligibility, and
deadline status as separate facts.

## Scope and authority

- Engine checkout: `work/lean-engine-20260913`, current base HEAD
  `907e32de63ab0d8133f2a7aff1441b06a1a884e8`.
- Owner reference: `work/rightrail-financial-workflow-20260913`, read-only; its correction method
  currently stops at `correction_transition_unavailable` and remains the only database writer.
- State owns the transaction, event-chain persistence, concurrency/retry recovery, and downstream
  integration. Lean does not commit rows, compute the DB event-chain hash, authenticate the Owner,
  or dispatch an action.
- The accepted result identifies `RR/FINANCIAL/CORRECTION-TRANSITION/v1` and version `1`; State
  must bind the exact built executable SHA-256 externally. Lean does not self-assert that hash.
- Engine owns its additive correction/reuse modules, codecs, CLI paths, KAT source, and documentation.
  Security exclusively owns `Financial/CodecLaws.lean`, `Financial/CodecLawsCheck.lean`, and
  `Financial/CodecLaws/`; do not edit, duplicate, or re-home that proof source.
- The additive `blind_financial_correction` executable exposes only the existing correction apply
  and reuse assessment operations through shared runtime handlers. The existing `blind_financial`
  command set remains intact and continues to own its KAT/theorem imports.
- Python Owner and State remain read-only in this task. No changes to State/Queue/Mirror/native,
  security proof sources, old financial wires, theorem manifests, or existing `--kat` gates.

## Invariants

- Preserve exact `BLFIN02`/`BLFRES02` fields, order, tags, canonical bytes, and strict trailing-byte
  rejection. The new contracts are additive: input/result `BLFCMD01`/`BLFCRES1`, reuse
  `BLFCRU01`/`BLFCRV01`.
- Preserve all 30 KAT gate names/expectations and the explicit 38-name theorem/checker scope.
- Keep `ControlPack.sourceRefs` stored order and repeated values; it is an ordered text list, not a
  canonical unique-ID list.
- Do not add `sorry`, `admit`, unsafe authority, or an unlisted theorem dependency workaround.
- Python remains the sole owner writer. State must supply three complete unique-key query
  observations (`actions.action_id`, `determinations.determination_id`,
  `determinations.input_evaluation_id`) from the same event-versioned read/commit transaction.
- Input evaluation receipt must include its 64-byte opaque `input_snapshot_digest`; it is retained
  with evaluation ID/result digest/revision/time. Authority and receipt digests remain opaque
  equality bindings; the adapter/source is not cryptographically authenticated by Lean.
- Local execution eligibility is a same-snapshot predicate only. State must atomically recheck and
  consume it; `externalDispatchPermitted` is always false.
- Keep `proofSuiteId=null`, `production_usable=false`, and `activation=false`.
- Keep all existing dirty user/Security/C05 work intact. No production, PHI, payment, activation,
  native proof-acceptance, database, or adapter runtime changes.

## Prior guarded execution status (earlier source identity)

The earlier Engine preflight at 2,896,142,336 free bytes was below the documented 4,190,433,321-byte target start threshold and launched no target. After the direct State-to-Engine lane return, the target-specific threshold remained 4,190,433,321 bytes; the v4 physical floor remained 2,190,433,321 bytes. No lower target threshold was adopted.

The current v4 wrapper is C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-wide-seed-native-20260913\build-filter-native\run_guarded_v4.ps1, SHA-256 57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB. It retained its process sampling, cleanup, mutex, child-exit checks, self-tests, and fresh launch preflight. Every launched v4 run passed cleanup and released Local\BlindLedgerDirectMaskBuild20260907, including the compiler failures recorded below. Final target-specific preflights passed; no resource floor failed during a target launch.

Final theorem/checker executable preflight: 2026-09-24T03:33:15.3837286Z; physical free 5,412,425,728 bytes; target floor passed; relevant process count 0; mutex absent; HEAD 907e32de63ab0d8133f2a7aff1441b06a1a884e8; tracked diff hash b6c68bb85c913d8e903198bb4571f4d95ad28b31; git diff --check exit 0. The executable was 6,014,464 bytes, SHA-256 AB253B484CAF2E44FAF94D4DA3453EF2AF9CA8DDA94367560C61FB3B303AAE5F.

The complete run chronology, guarded telemetry, raw stdout/stderr identities, exact KAT outputs, warnings, failures, vectors, and source hashes are retained in the latest STATE.md section. Logs remain under the Driver guard directory outside this Engine checkout.

## Correction transition owner alignment and run status (2026-09-23)

The additive Lean transition/reuse API, codecs, CLI operations, and 32-gate KAT remain under semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/. Transition result magic is BLFCRES1; reuse remains RR/FINANCIAL/CORRECTION-REUSE/v1 with BLFCRU01/BLFCRV01. The current Owner method remains fail-closed for new corrections at correction_transition_unavailable. Python Owner and State were read-only.

The first 32-gate executable KAT run passed 31/32 gates and failed only owner_domain_digest_vectors. Comparison with the actual Owner module's pure canonicalization/digest helpers showed the Lean hex encoder used lowercase A–F while the Owner's _hex helper uses uppercase. The Lean encoder and the three expected digest vectors were corrected from actual Owner helper output; the idempotency key already matched. The final KAT passed all 32/32 gates. This is a narrow byte-identity correction, not a new gate or a rebaseline from Lean output.

The final guarded full CLI executable is 7,443,968 bytes, SHA-256 A592F0AFB038F83DE566AF8C02AC0C80FFAD94DF163D67BA3EB47549BC1D1540. The final guarded narrow correction executable is 6,245,376 bytes, SHA-256 E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9. Exact request/result/reuse vector identities and byte-for-byte output comparisons are in STATE.md.

## Runtime-only correction executable and import closure (2026-09-23)

The additive Lake target is blind_financial_correction, rooted at BlindLedger.Financial.CorrectionTransitionCli. Its only commands are --apply-correction-transition and --assess-correction-reuse. Both executables call the same bounded reader, decoder, semantic transition/reuse functions, result encoders, rejection codes, and error strings from CorrectionTransition.Runtime.

The entrypoint imports only CorrectionTransition.Runtime; that module directly imports CorrectionTransition.Codec and ReuseCodec. A fresh local import traversal found 14 repository-local modules in the closure. It contains no KAT, theorem, axiom-check, Financial.Executable, Financial.Cli, DecisionPackage umbrella, or DecisionPackage CLI module. It does include DecisionPackage.Types, Projection, and Codec because the transition and wire codecs depend on them. This corrects the earlier source-only note that reported 15 modules.

The narrow target built successfully in 32 jobs. The full blind_financial CLI target built successfully in 50 jobs after one repaired DecisionPackage.KAT syntax failure. Final runs passed the existing 30 KAT gates and retained 38-name theorem manifest, all 32 correction/reuse KAT gates, the checker build, and exact result-vector comparisons. Full raw evidence is in STATE.md.

## Previous source-only findings (preserved history)

The theorem proof source is split behind stable `BlindLedger.Financial.Theorems` into
`Theorems.Correspondence`, `Theorems.Vectors`, and `Theorems.Manifest`. The correspondence ledger
is in `docs/LEAN_FORMAL_KERNEL.md`. The source review aligned role/kind token syntax, case-owner
authorization, generic zero-amount evidence, and unused authority actor roles with the Python owner
contract. Engine now bounds authority epochs at the owner's signed SQLite integer ceiling and has a
source gate for the maximum and maximum-plus-one values. The empty-case owner mismatch is now closed
at source level: the Engine requires at least one case, the common OPEN fixture carries a valid case,
and the existing mutation gate verifies both decoder and evaluator rejection of an empty case list.
The late-completion gate also contains a
parser-decoded equal-time payment/determination collision: Lean identity order and the owner-mirrored
stable source order differ, but both source-level loops return the shared timestamp. The independent
specification gate now evaluates the decoded BLFIN02 fixture and compares every result projection.
These are source-only assertions; compilation, executable KATs, and a pinned Python owner snapshot
comparison remain pending.

The receipt checklist is also in `docs/LEAN_FORMAL_KERNEL.md`; current artifact identity, exact
source hashes, static counts, status, unverified work, and the next action belong in `STATE.md`.

## Prior C05 decision-package projection — source-only (2026-09-23)

The additive implementation is under `semantic_kernel/lean/BlindLedger/Financial/DecisionPackage/`
behind stable import `BlindLedger.Financial.DecisionPackage`. Its CLI paths are
`--project-decision-package` and `--decision-package-kat`; the pre-existing `--kat` output and its
30 gate names are unchanged. `BLFDCP01` and `BLFDPR01` are new bounded wrappers. The result nested
in the input envelope uses the existing strict `BLFRES02` codec. This does not change `BLFIN02`,
`BLFRES02`, `Theorems`, `Executable`, Python, the database, or runtime authority.

The source correspondence, Mirror redactions, exact supported-field crosswalk, explicit UNKNOWN
cases, hand-derived H values, omitted package sections, opaque digest limitation, and raw C05
checkout identities are in `docs/LEAN_FORMAL_KERNEL.md` and `STATE.md`. The projected output
preserves the full validated current evaluation receipt and crosschecks its bindings against the
projection. The H vector's Owner-known
business facts are source-derived; revision and opaque digests are labelled synthetic test
scaffolding and are not a captured Owner/Mirror package or byte-for-byte conformance receipt.

No Lean, Lake, compiler, CLI, KAT, Owner test, or Engine test was run. The Engine lane remains
State-owned and no direct Engine release arrived. Continue source-only work; run only the bounded
target selection after State's direct lane return and the recorded Security clearance. Then return
the lane to State at the safe boundary. Nonactivation remains
`proofSuiteId=null`, `production_usable=false`, and `activation=false`.


## Temporary tooling cleanup disposition

The exact four helper files and two vector directories under C:\Users\neers\AppData\Local\Temp were inventoried and hash-checked. One removal command failed before launch because its command line exceeded the Windows limit (os error 206); two exact-path cleanup attempts were rejected by automatic review with the reason blocked by policy. No files were removed. The read-only recheck found all 18 files and both directories still present. This cleanup is recorded as skipped; no alternate deletion method was attempted.

## Exact-source provenance recovery (2026-09-24)

Status: `NOT_RECOVERABLE` from the accessible evidence searched. The 14-file compiled manifest
matches the current worktree for 12 files; `Transition.lean` and `Reuse.lean` have different
sizes and SHA-256 values. The all-object Git scan found 0/14 expected hashes, and the corrected
scan of five retained source ZIPs found 0 Lean entries and 0 source-hash matches. The filename
search found no historical Transition or Reuse source copy. It ended with `rg_exit=2` and 55
explicit `Access is denied` directory warnings, so this is not a global absence claim. The exact
warning list, archive identities, current hashes, and search limits are recorded in STATE.md.

The existing `E911E8844130155E4615D284D6D29A597B6E441DC45101D411EE8422EAE684B9` executable
remains evidence for its older source set only. No source reconstruction, compiler, Lake, target,
checker, KAT, or vector run occurred. Keep the v4 lane stopped and wait for readable source
evidence before claiming exact provenance; any later build still requires a direct Driver lane
grant and fresh passing v4 preflight.
