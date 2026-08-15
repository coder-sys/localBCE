# Blind Ledger current state

Updated: 2026-08-15

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

## Current executable evidence

Native-v3 Phase 0 fixes the five-directive business grammar and eleven identity fields. The Python
and independent Rust known-answer paths pass, including fourteen negative mutation classes.

The synthetic plaintext continuity wedge now exercises a verifier-owned
`DIRECT_STATE_OWNED` control set over canonical provider facts and authoritative
completeness/nonmembership. It preserves `policyResult` separately from
`effectiveDirective`, binds all four times, joins one logical `ClearanceDecisionRow` to ordered
chronological `StateAccessRow` records, and binds SHA3-512 before/after roots, replay identity,
and governed exception identity. Its focused test suite reports 21/21 passing and its independent
parser accepts all eight intended case bundles. Reviewed V2 regressions include producer receipt
parse/canonical round-trips for all eight `DEMO_CASES`, including NONE and governed-exception paths,
and producer/independent rejection of fact/nonmembership contradiction with
`completeness:fact-nonmembership-conflict`.

The trust-boundary profile implements canonical framing, prover commitment, authenticated
verifier-fresh challenge, prover response, independent Rust parsing, and replay/domain/order/root/
mutation negatives. It is an executable interface profile, not a private proof.

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

Lean 4 is now the approved target for the executable clearance semantic and legal state-transition
kernel. It will own bounded canonical semantic decoding, control-set evaluation, authoritative
absence, chronology, exceptions, observation-only separation, replay, exact decision/access joins,
and allowed after-state. It is not implemented; the current Python/Rust KATs and parsers are not a
deployed-formal-verification claim.

## Private-proof status

No production proof backend is selected. DP24 evidence is an ideal-vector-oracle experiment only.
Its 56-instance calculator reports 128.664794844 ideal-model bits, but the repository has no
complete bound covering concrete SHA3-512 Merkle/BCS binding, salted-leaf hiding, collapse-position
binding, malicious-verifier zero knowledge, semantic/state composition, atomic product proof, and
abort/retry composition.

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
before-state, omission/reorder/duplicate, incomplete-feed absence, replay, chronology errors,
directive/exception/economic mismatch, retry conflict, and after-state mutation.

The complete process tree, scratch, and pagefile gates for a private proof remain unmeasured because
no complete backend exists. The CPU-only peak process-tree memory ceiling remains
5,000,000,000 bytes.

## Authority and next work

Current authority is `ARCHITECTURE.md`, `docs/NATIVE_V3_ARCHITECTURE.md`,
`docs/DATABASE_ZK_ARCHITECTURE.md`, `docs/LEAN_FORMAL_KERNEL.md`, and `CURRENT_TASK.md`. Legacy BL-PQ512, H4/CUDA,
Privacy V2, binary-field, Binius64, and decisive-composition documents are retired compatibility
markers, not design authority.

The next private-proof step is research and closure of the six unresolved theorem/composition terms
listed in `CURRENT_TASK.md`. Until then, the safe implementation boundary is the synthetic
read-only plaintext wedge and narrow future-proof adapter.

The accepted post-cleanup Withdrawal V1 publication contains 964 payload files plus one embedded
manifest (965 ZIP entries) in one fresh candidate and three retained byte-identical targets. Each
copy is 15,169,121 bytes with SHA-256
ACDAA4E232DED29DC666C5CA8C359E2DB1F2A48693A053EBD531324B8D81E946. The embedded
`RELEASE_FILE_MANIFEST.json` is 182,516 bytes with SHA-256
ECDEAC9A76B22F72E52E480AE24B539E7AF6CA1FB44CE1A1F4151BFF7DD1E516. The exact candidate is
`C:\Users\neers\Documents\Codex\2026-08-15\blind-ledger-mirror-workhorse\work\archive-output-deletion-pass-20260815-36da256\canonical-source.zip`; the retained targets are the Downloads copy, Desktop-root copy, and nested Desktop source-backup copy
of `Blind-Ledger-Wave2-Source-Complete-2026-08-02.zip`. Each readback consumed 14,958,887
bytes and returned CRC PASS, duplicates 0, directories 0, and zero-byte entries 0. Direct
comparison with the accepted Restore V1 archive still finds exactly 3 additions, 0 removals,
7 active-document modifications, and 954 unchanged payload members; the deleted
`experiments/binary_field_k128/generate_keccak_states.py` was not a manifest member. The fresh
stage independently checked all 964 live manifest source hashes. The three new rollback copies
remain preserved at the deletion-pass receipt directory and all pass the same ZIP readback.
The current manifest, custodian receipt, and architecture verification are retained under
`_handoff_support/retained-evidence-20260815`; STATE.md and CURRENT_TASK.md remain workspace-only
and are excluded from the ZIP. This record makes no claim of production persistence, POSIX
no-clobber behavior, source authentication, ZK, formal verification, payment authority, PHI
safety, or activation.
