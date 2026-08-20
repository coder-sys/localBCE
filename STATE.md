# Blind Ledger current state

Updated: 2026-08-20

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
matrix rejects 12/12 malformed or semantically altered joins. The valid 676-byte join and its
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

The controlled integration candidate preserves the authoritative `ce31abeb941ce7ad5927ca67d6f23872f430ed09`
base and the accepted frozen tips: Mirror `3efd3a5179a3c1c26b4b5a353b62d59488de1f34` and Blind
Ledger `784ada21fe9e21bf63f351cecbfd23f4be92ff94`. Mirror's older merge-base was reconciled by
commit/path identity; the four Native-v3 paths already newer on the authoritative base were
preserved, and rejected Mirror validator implementation files remain absent. No later Mirror work
was included.

Mirror remains a synthetic, read-only evidence/reconciliation/continuity candidate. In this
integration run its focused unittest command passed 209 tests, including state-source admission,
Provider Trust Graph, custody/reconciliation, discrepancy/denominator/contract, transaction and
money evidence, State Value Ledger, Transition, Continuity Operational Foundation, and store-owned
busy recovery. Live-source authorization, terms/completeness/cadence/failure behavior, HSM/FIPS
custody, HA/DR operations, state privacy/support approval, and shadow-pilot evidence remain open.

The accepted Blind Ledger route is the complete current minimal engineering proof route: one
610-byte, nine-block private source/registry commitment, direct semantic constraints, 12,158,968
terms, and one retained synthetic proof with approximately 1.041 GB observed job commit. The
retained proof independently accepted in this run with 34/34 copy-only verifier mutations rejected;
proof acceptance reported zero state mutations and zero CLEAR authorizations. The state-side
transaction owns clearance/replay/recovery, and the accepted candidate's direct-state evidence
keeps the payment root and `settled_batch_count` unchanged while using `DIRECT_CLEARANCE` and a
dedicated clearance root/count. This is not a comparison to the rejected 18-endpoint design.

Earlier accepted integration records report the native non-prover build, shape/evaluator/parity/
preflight outputs, retained-proof identity and acceptance, and all 34 copy-only verifier
rejections; those were not rerun in this correction. The current hardening run personally verified
the corrected join/provenance code and focused gates described above, did not invoke a prover, and
did not inspect archives. The exact seven-module direct composition gate remains earlier
worker/integration evidence rather than a result relabeled as personally rerun here.

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

The next safe dependency is Sol review of the corrected reconciled provenance. Separately, the six unresolved private-proof
theorem/composition terms listed in `CURRENT_TASK.md` remain open; no backend is selected and the
safe implementation boundary remains synthetic, state-owned, and nonactivating.

Current archive authority is the external publication receipt plus independent physical readback
of exactly the three retained roles: one Downloads copy, one Desktop-root copy, and one nested
Desktop source-backup copy, each checked against the Git commit recorded by that receipt. Any
source commit after a receipt makes those archives stale until republished. Verification requires
equal byte length and SHA-256 across all three roles, canonical ZIP/CRC readback, no duplicate or
unexpected entries, zero temporary publication artifacts, and `three_way_byte_identical=true`.
`STATE.md` and `CURRENT_TASK.md` are workspace-only authority records and are excluded from the
source archive. No archive identity is evidence of ZK, formal verification, production persistence,
source authentication, payment authority, PHI safety, or activation.
