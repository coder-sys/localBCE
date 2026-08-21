# Blind Ledger current state

Updated: 2026-08-21

## Product boundary

Blind Ledger is RightRail's state-side payment-clearance layer. The incumbent adjudicates the
claim, and the official state system and payment rails move money. Blind Ledger produces only one
of five state-local directives: `CLEAR`, `HOLD`, `HUMAN_REVIEW`, `BLOCK`, or
`EXCEPTION_APPROVED`.

The first commercial wedge is read-only provider credential and enrollment continuity. It has no
payment authority and does not need to wait for a production private-proof suite.

Externally, that wedge is a Mirror/Provider Trust Graph evidence and remediation product. The
current five-directive continuity code is an internal Blind Ledger conformance harness,
not the commercial product API. The broader `Continuity State` name remains reserved for the live
operational handoff package required to replace a vendor.

## Production-shaped integration posture

The current architecture is a production-shaped, integration-ready candidate. The canonical
business semantics and artifact interfaces are intended to survive bounded component substitution:
directives, result separation, control-set/order, authoritative absence, four times, joins, roots,
exception identity, state transitions, retry/recovery, and fail-closed behavior are not disposable
prototype conventions. Qualification—not redesign—is the remaining path for these seams.

The read-only provider-continuity wedge can adopt authenticated source adapters, real governance/PQ
signatures, production persistence/custody, and state-owned deployment/support without waiting for
the private-payment ZK backend. Blind Ledger's private clearance path still requires the Lean kernel,
a theorem-qualified ZK backend, and database/custody qualification. Current qualifications and
nonclaims remain centralized here and in `CURRENT_TASK.md`; the architecture docs define the fixed
patch-in interfaces and gates.

## Governed operations-byte evolution

The three changed byte-bound operation documents evolved under the gate-change procedure in
`docs/DESIGN_IDEOLOGY.md`. Old bytes, exact predicate meaning, and replacements are recorded here;
the updated SHA3-512 values are the new commit-bound authority.

| File | Old bytes / SHA3-512 | Fixed invariant and new bytes / SHA3-512 |
| --- | --- | --- |
| `ops/DEPLOYMENT_RUNBOOK.md` | 1207 / `45e902ee19516bfebccbddfd041cdaac932eff639d2ca2b7e7c8cfe580e8bb1a803e02763a617420afbab99f81f88befac1f3ad0aa487004f893239eb54c939c` | Accepted verifier receipt plus Blind Ledger clearance-state mutation are atomic; official rails move funds later; L1 anchoring is committed later with no fixed cadence. 1435 / `57a38a947d4c7d88c57403f6ad122a024bc707b3082335ab43d9029d15872b13cf067c2a14b3a61481fdbc54e8d00afdf5dce131e59d4311f4670f36f4fde0b9` |
| `ops/KEY_CUSTODY_AND_ROTATION.md` | 2375 / `a3bb1283a04a133b0f32cb8d27d1867bb0cf9543c12976fc31f0827ab9235952c06349a35a81d34972c241f32c1793e87f845a3c2668f02d60f8d9111920167c` | Algorithm-agile Category 1+ signatures; dual Category-5 only for an explicit threat model; signatures prove provenance/authority, not truth. 2700 / `76787aa22795639b4e5bd91365f3c9e8f609d739bfb98a01d5e5e2e3d9797dc0a82b3c3ff411c6cb56b30ecd0cde5ab8fd2389098611b146b30c0b3da5a639a9` |
| `ops/PRODUCTION_CONFIG_CHECKLIST.md` | 1080 / `afffeff773a00aec7471f2a8fb15d463244e025f2c8928cd76e56e43ab7d7d93938dd63b8cfd71812b38093f9f780aca593eeaf826db566d96040b8fa9842a3a` | `NATIVE_STARK_DATABASE_TRANSITION` is a disabled legacy sentinel; no verifier/evaluator/backend is selected. 1257 / `286c31e304644ad6fa23a63b7b8940dfd5294f78c3242997628253518b70f9d127b621be40cea92540d83761e19a5e6757bfbab4d237ee90ff55e33e4bd2c0b6` |
| `ops/RISK_REGISTER.md` | 1278 / `d5ad6ac4a0812292df5ea3f8cc754181cc40560831a931f493212cdfa77c52a69be6eb51eabc0907ca23e77385493086ae47e93d8c75e35ecf5d4508d4b243d8` | Risk treatment now names algorithm-agile authority signatures and makes dual-PQ conditional on the approved threat model. 1359 / `9ac9ae175f6fd1fd5ebf4b3efa95999f7e3833452e9768966c5bacca1360bdc069b5e56e9c4e1d01046a4e903a5d14514b7c043d87fbe9326705b4de6ae6ea1e` |

## Current executable evidence

Native-v3 Phase 0 fixes the five-directive business grammar and eleven identity fields. The Python
and independent Rust known-answer paths pass, including fourteen negative mutation classes.

The synthetic plaintext continuity wedge now exercises a verifier-owned
`DIRECT_STATE_OWNED` control set over canonical provider facts and authoritative
completeness/nonmembership. It preserves `policyResult` separately from
`effectiveDirective`, binds all four times, joins one logical `ClearanceDecisionRow` to ordered
chronological `StateAccessRow` records, and binds SHA3-512 before/after roots, replay identity,
and governed exception identity. Its focused test suite reports 24/24 passing and its independent
parser accepts all eight intended case bundles. Reviewed V2 regressions include producer receipt
parse/canonical round-trips for all eight `DEMO_CASES`, including NONE and governed-exception paths,
and producer/independent rejection of fact/nonmembership contradiction with
`completeness:fact-nonmembership-conflict`.

The trust-boundary profile implements canonical framing, prover commitment, authenticated
verifier-fresh challenge, prover response, independent Rust parsing, and replay/domain/order/root/
mutation negatives. It is an executable interface profile, not a private proof.

The 2026-08-20 trust-boundary hardening gives the producer one canonical decision/access join:
exactly one decision row and two access rows, with access index 0 as READ bound to the operation's
before value and access index 1 as WRITE bound to its after value. The independent verifier
recomputes the same relation without calling the producer validator; its focused raw mutation
matrix rejects 13/13 malformed or semantically altered joins. The valid 676-byte join and its
existing SHA3-512 ID remain unchanged. The DP24 ledger now binds an immutable parameter-set
identity to the pinned upstream manifest (SHA-256
`A677B8A6BEA7DCA87E4370E8FA07FDFD17F345276B581629BE230022B8C0BB5D`), labels all six numeric
parameters `UNKNOWN` with candidate literals marked `HYPOTHETICAL_CANDIDATE_INPUT`, and suppresses
numeric epsilon/security-bit output until authority-bound provenance exists.

Mirror Continuity Operational Foundation V2, Restore V1, and Withdrawal V1 are accepted as a synthetic,
nonactivating operational candidate. The focused unittest is 30/30 passing, including exact
chain-ID binding, deterministic retry and crash-recovery behavior, five restore fault seams,
same-process and cross-process convergence, deterministic export/restore round-trip, target and
sidecar rejection, and 65 sequential distinct-destination restores with an empty post-release
lock registry. Restore V1's accepted archive publication independently read back one candidate and
three retained targets as byte-identical, with two reviewed payload modifications and 959 unchanged
payload members. This is local/current-Windows candidate evidence only; no POSIX no-clobber
qualification is claimed.

The terminal Provider Continuity `WITHDRAWN_OBSERVATION_ONLY` seam is source/test-reviewed and included
in the accepted Withdrawal V1 publication. It requires a separately supplied canonical synthetic
authorization record, embeds and independently verifies the complete approved Control Pack artifact,
and has no reactivation or replacement path. It is evidence for one approved lineage, not an
operational revocation store; future consumers must consult a durable lifecycle head before treating
an approval as active. Exact focused evidence and the bounded 23,128-byte artifact telemetry are
recorded in `CURRENT_TASK.md`.

The next bounded lifecycle-head stage is now implemented in the existing operational candidate. The
store independently verifies and appends the terminal withdrawal as the next Governance V1 lineage
stage, and `ContinuityStore.provider_continuity_lifecycle_head(...)` fails closed on any database
conformance or head-binding error. Only a current `APPROVED_OBSERVATION_ONLY` head reports active;
`WITHDRAWN_OBSERVATION_ONLY` is terminal and non-active. Exact withdrawal retry and state-owned
export/restore preserve that head. This remains synthetic, local/current-Windows, observation-only
evidence with no production persistence, source authentication, payment authority, or activation.

Lean 4 is the later mandatory target for the executable clearance semantic and legal state-transition
kernel; it is not active now. It will own bounded canonical semantic decoding, control-set evaluation, authoritative
absence, chronology, exceptions, observation-only separation, replay, exact decision/access joins,
and allowed after-state. It is not implemented; the current Python/Rust KATs and parsers are not a
deployed-formal-verification claim.

## Direct-State-Owned Atomic Clearance V1 candidate

On 2026-08-15 an isolated candidate based on source commit
`ce31abeb941ce7ad5927ca67d6f23872f430ed09` composed the canonical plaintext continuity bundle,
its independent parser, and the existing serializable SQLite database boundary. The composition
root pins the source profile, `DIRECT_STATE_OWNED` mode, evaluator, control-set/rule order,
governance authority, schema/program identity, epoch, and database context. A successful independent
parse is converted into a store-sealed typed operation; the database rechecks chronology, direct
continuity state IDs/roots, policy/directive separation, exact retry identity, context, and the
allowed clear-versus-non-clear state transition before one append-only direct request, audit event,
dedicated `DIRECT_CLEARANCE` transition, and state update commit.

The settlement-separation correction gives the direct lane an explicit version-1
`direct_clearance_state` snapshot and request-column shape. Its clearance root and direct-transition
count are independently reconstructed and included in the main database state-binding chain. All
five direct directives preserve the durable payment root and `settled_batch_count`; only `CLEAR`
and `EXCEPTION_APPROVED` advance the dedicated clearance root, while every direct attempt advances
only the dedicated direct count. The existing settlement and migration lanes retain their original
payment-root, settlement-count, transition-kind, and recovery semantics. A pre-correction direct
table shape is rejected as a schema mismatch rather than silently reinterpreted.

The correction's focused evidence is 27/27 direct-state tests, 31/31 combined continuity and
trust-boundary tests, and 46/46 transactional database/production/migration plus implicated
migration-attack tests. The direct tests cover all five directives, governed exception
and sentinel paths, independently rebound semantic mutations, authority/downgrade mutations,
concurrency, exact retry, conflicting retry, stale state, rollback, post-commit indeterminate
recovery, restart, and backup/restore. The existing continuity telemetry covered 8 synthetic cases:
195,889-byte Python heap peak, 23,859,200-byte peak working set, zero pagefile growth, and
`complete_proof_resource_gate_measured=false`.

The active-core, security, documentation, release-manifest, and production-readiness gate command
passed 35 tests plus 17 subtests. The existing offline Rust Phase-0 `kat` and `negatives` commands
also passed with their original five-directive and negative-rejection statuses. These checks do not
select a proof backend or qualify a production deployment.

This remains a synthetic, nonactivating candidate. `proofSuiteId=null`,
`production_usable=false`, and activation remain false. The controlled integration did not invoke
a prover, select a proof backend, implement Lean, touch payment/PHI/Ethereum, or refresh archives.
The accepted candidate evidence does not claim production persistence, anti-rollback custody,
source authentication, formal-kernel qualification, deployment, payment movement, or production
clearance authority. The authoritative checkout is changed only by the authorized exact
non-destructive fast-forward to this corrected candidate after every required integration gate
passes.

## Controlled integration synthesis

The controlled candidate starts from the unchanged authoritative base
`458a9cc81dbf4bf3f122b74223fb5d5cf68fa970` and cherry-picks exactly the six authorized Mirror
source commits in order: `3ac97b7430cd692124f2518128802e3f2491d12c`,
`c828c526536fc994a86ff2c1a934105e1c92f50f`, `426770ca3ee865124da143c5f813c4e55b1698d6`,
`4bf2d6d9480550072e4de6cdc81579776d91ab6d`, `6567a1e159da540d3518b702c8beeea178bd9da6`,
and `1a69fb3bc6a165dd50c4101311d9335526b0e28f`. Their detached candidate commit identities are,
respectively, `3a82d9fbd571b38164530d41abe8c88ab7e59728`,
`f33e2a49476297897f1e9a9431169f96b9d4d232`, `f7c2575f453c2202e1bebb9e5158570396b6bc39`,
`b62bf312727bc1a8e5106ff25789c0e7268aa4e1`, `729ec82f8115af2bc6c4e2b24d3ebbebf0370c25`,
and `eab18d2f1ac7f59d7dce4f59a4dd2b1215afa511`. The accepted predecessor remains
`3efd3a5179a3c1c26b4b5a353b62d59488de1f34`; no authoritative fast-forward occurred.

This sequence provides the complete current synthetic Mirror rehearsal chain: fixture-only
source admission and state-side custody; Provider Trust Graph V2 and governed profile lifecycle;
independent source reconciliation, discrepancy/responsibility/remediation/retest/parity;
Contract, Denominator, Transaction, Money, Transition, and State Value evidence views;
synthetic qualification; and ContinuityStore atomic persistence, exact retry, busy recovery,
export/restore, restart, rollback, and aggregate-only support. Mirror remains read-only evidence
and continuity. It does not emit a Blind Ledger directive, authorize clearance, settle, or move
money; Provider Trust Graph remains one wedge rather than the whole product.

Direct worker-run evidence in this candidate: Python 3.11.15 compiled all 14 changed Python files
successfully. The 16 directly implicated non-rehearsal modules passed 162 tests when rerun serially
after an initial parallel scheduling probe exposed two cross-suite SQLite busy errors
(`transaction:busy` in Provider Trust Graph V2 and `money:busy` in Money Mirror); those exact
modules passed without code changes when isolated. The complete `tests.test_mirror_rehearsal`
module passed 13/13 in 930.637 seconds, including both matrix tests and the ABI regression. Its
independent ledger is `753b3588b0e5963e52396bc9eaec34db05252331888b2e16688a9ab52c4ff9fb2fa771350f9bb7f5d8d3369be33e0646ec291ab765f984499dba67331e2f24d5`, with 39 mutation,
10 fault, 12 recovery, and 2 concurrency cases; the final chain has 24 artifacts, 24 events,
24 receipts, and 24 transitions. Conflicting fixed-envelope races in both launch orders returned
`custody:fixed-envelope-conflict` for the loser and left the winner's 24-artifact chain only.
No warnings or skips were emitted.

The complete-process resource gate remains OPEN and fail-closed. The raw rehearsal result was
`JOB_OBJECT_EVIDENCE {"blocker":"job-object:exception:PermissionError","cap_bytes":5000000000,"cap_enforced":true,"counter_name":"PeakJobMemoryUsed","exit_code":null,"measured":false,"peak_bytes":null,"semantics":"job_commit_charge_bytes"}`; the matrix ledger recorded child exit `-1`, `measured=false`, and no peak. Job configuration succeeded, but this sandbox did not permit the assigned-before-resume launch/`PeakJobMemoryUsed` query. No fallback measurement was used. The documented `py -3.14` launcher was unavailable; the equivalent compile/test commands used available Python 3.11.15 and this limitation is not a production qualification.

The claim remains `SYNTHETIC_REHEARSAL_READY` only. Whole-Mirror completion, `CONTROLLED_SHADOW_READY`,
`PRODUCTION_READY`, live source authentication/authorization, legal terms, completeness/cadence/
failure qualification, state privacy approval, HSM/FIPS custody, production persistence/HA/
backup/DR/monitoring/runbooks, the measured resource gate, payment/clearance/settlement authority,
and any activation remain open or false. `proofSuiteId=null`, `production_usable=false`, and
activation remain false. No live network, real record, PHI, credential, archive, or authoritative
checkout mutation occurred.

## Verifier custody and state admission

Commit `b8947081f490fe19d7be430500f5f71e3a67648d`, parent
`efafe06448c92f95944c9ca1d72a08c9488c4557`, adds the verifier-custody/state-admission boundary in
exactly four implementation paths: `app/minimal_clearance_proof_state.py`, the new
`app/minimal_clearance_verifier_process.py`,
`experiments/longfellow_v09_native_v3/src/native_v3_minimal_clearance_verifier.cpp`, and
`tests/test_minimal_clearance_proof_state.py`.

`NativeMinimalClearanceVerifier` requires a configured 64-hex executable SHA-256 identity,
snapshots and rehashes the regular non-symlink executable before every run, and launches only a
fresh verifier-owned read-only snapshot. The combined native form reconstructs the verifier-owned
public statement in the same process as proof verification and writes exactly 3,340 statement bytes
only after proof acceptance. The Windows containment module creates and configures a Job Object
before child execution, creates the child suspended, assigns it before resume, enforces
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, a 5,000,000,000-byte job-commit cap, and active-process limit
1, bounds ASCII stdout/stderr, and has no subprocess fallback.

`MinimalClearanceStateStoreV1` schema 2 persists `expected_verifier_sha256` in the singleton row and
binds it into operation/state identities. Submit, exact retry, restart, recovery, export/restore,
and integrity checks fail closed on identity drift. The only public state-changing entrypoint is
`submit(artifact_path)`; `apply_acceptance` is absent, `_apply_verified_acceptance` is internal,
and `StaticMinimalClearanceVerifier` is not exported from application code. Rejected verification,
identity drift, containment failure, timeout, malformed output, or state mismatch cannot mutate the
proof-state tables.

The prior candidate qualification, used as accepted input rather than rerun here, performed one
retained-proof submit. It recorded artifact size 411,672, SHA-256
`69F653130822D15977BC14E450B62A5A20FF7CF12512C7BBBC79714B5A5BB38E`, `ReadOnly=True`, executable
identity `7E03EF2AE1181ED0A107ECAD577C1FDA6CB8EEB174CA4D239BB4EA74E561513B`, PeakJobMemoryUsed
1,041,915,904 bytes as job commit, cap enforcement, active-process limit 1, schema 2, restart and
integrity success, unchanged payment root and settled count, and one request/audit/transition.

This integration run did not consume the retained proof and invoked no prover. It personally ran
the verifier-only build (11/11 targets), compiled both changed application modules, passed the
cheap real/injected containment diagnostic, passed `tests.test_minimal_clearance_proof_state` 9/9,
and passed the compact active-core/security-freeze/documentation-governance/release-manifest gate
with 29 tests and 17 subtests. No warnings, failures, errors, or skips were observed in those
focused checks.

## Longfellow compiled parameter report

The cleanup retains implementation facts through one fixed
longfellow_minimal_clearance_parameter_reporter executable. It links only the verifier-side
circuit target, never invokes a prover, and emits one canonical 28-key UTF-8 JSON object. Two
runs exited 0, were byte-identical at 1,215 bytes, and have SHA-256
`0E8856979A1C1082CFA43CC92BA0AC6CD67F6B17CA1E59A151E2C6A41977B3D3`. The report is
separately validated by the Python profile gate for exact keys/types, pinned source and patch
identities, compiled dimensions, circuit ID, and nonactivating flags.

The compiled facts are field `GF2_128`, degree 128, serialized width 16 bytes, implementation
rate 4, 189 queries, transcript version 6, artifact version 1, artifact header/public-statement
sizes 68/3340, circuit dimensions `36969/26721/217/12158968`, and circuit ID
`1eaaf14f3b23db1ed02f3c378099627767f81142e0114f90448cac7c1cc66be0`. This is not an
independent native verifier or circuit-reconstruction claim. The report's implementation rate is
not DP24 `rate_R`; all six DP24 numeric mappings remain `UNKNOWN`, and no theorem,
security-bit, backend-selection, production-usability, or activation claim follows.

## Private-proof status

No production proof backend is selected. DP24 remains an ideal-vector-oracle formula record only.
Its parameter-set identity is `3a8b4c62c78efded8b26d0a428b7bad17dc338b86ba945467ec8b815b8850080ad553452ac9dfc0d300df90cce3dc85b830ac9d24d543f8957fcef2e45b9e4ac`, but the
repository bytes do not authority-bind the six DP24 numeric inputs. They are therefore UNKNOWN,
the exact-rational calculation is deferred, and numeric epsilon/security-bit precision is
suppressed. The repository still has no complete bound covering concrete SHA3-512 Merkle/BCS
binding, salted-leaf hiding, collapse-position binding, malicious-verifier zero knowledge,
semantic/state composition, atomic product proof, and abort/retry composition.

Accordingly:

- `proofSuiteId=null`
- `production_usable=false`
- activation is false
- private-proof backend selection is false
- all inputs are synthetic
- real PHI and real payments are forbidden
- no K128, K512, production-proof, or scale claim is permitted

## Security and state invariants

The verifier-owned automatic control set fixes evidence mode, evaluator identity, rule order,
conflict policy, scope, and effective interval. Callers cannot select or downgrade the mode.
Proof/session acceptance never means `CLEAR`. Authoritative completeness/nonmembership is required
before absence can be inferred. Event, observation, rule-effective, and decision times remain
distinct. Governed exceptions require a stable signed authorization identity or the exact sentinel.

Verification fails closed for corrupt or noncanonical bytes, wrong roots or control sets, stale
before-state, omission/reorder/duplicate, incomplete-feed absence, replay, strict-chronology errors,
directive/exception/economic mismatch, retry conflict, and after-state mutation.

The complete process tree, scratch, and pagefile gates for a production backend remain
unqualified. The accepted minimal engineering proof recorded an approximately 1.041 GB observed
job commit for its one synthetic proof attempt, below the 5,000,000,000-byte ceiling. This
integration did not invoke a prover and does not establish production deployment, complete
process-tree qualification for a future backend, or the full theorem/security ledger. The CPU-only
ceiling remains 5,000,000,000 bytes.

## Authority and next work

Current authority is `AGENTS.md`, `CURRENT_TASK.md`, `STATE.md`, `ARCHITECTURE.md`,
`docs/NATIVE_V3_ARCHITECTURE.md`, `docs/DATABASE_ZK_ARCHITECTURE.md`,
`docs/LEAN_FORMAL_KERNEL.md`, and the named component authorities linked from `README.md`.
Retained compatibility references are not design authority.

The next safe dependency is Sol review of the verifier-custody/state-admission controlled
integration. Separately, the six unresolved private-proof theorem/composition terms listed in
`CURRENT_TASK.md` remain open; no backend is selected and the safe implementation boundary remains
synthetic, state-owned, and nonactivating.

Current archive authority is the external publication receipt plus independent physical readback
of exactly the three retained roles: one Downloads copy, one Desktop-root copy, and one nested
Desktop source-backup copy, each checked against the Git commit recorded by that receipt. Any
source commit after a receipt makes those archives stale until republished. Verification requires
equal byte length and SHA-256 across all three roles, canonical ZIP/CRC readback, no duplicate or
unexpected entries, zero temporary publication artifacts, and `three_way_byte_identical=true`.
`STATE.md` and `CURRENT_TASK.md` are workspace-only authority records and are excluded from the
source archive. No archive identity is evidence of ZK, formal verification, production persistence,
source authentication, payment authority, PHI safety, or activation.
