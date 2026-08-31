# Native-v3 proof architecture

Updated: 2026-08-25
Status: production-shaped target architecture; current qualification status is authoritative in
`STATE.md` and `CURRENT_TASK.md`, and no backend is selected.
Owner: private-proof, security, state, privacy, and resource qualification authority. The commercial
Mirror wedge is governed by its own read-only boundary and does not inherit private-proof claims.

This document is the active proof, security, state, and resource qualification authority. The former
Privacy V2, binary-field, Binius64, and decisive-composition narratives have been retired; Git
history and retained archives preserve their exact evidence.

## Product invariant

When evidence must remain hidden across the state clearance trust boundary and affects an automated
payment directive, a future qualified `PRIVATE_ZK` verifier may accept one proof of the exact hidden
source-bound assertion/predicate. The proof relation does not own the ordered state relation, policy,
directive, exception, outbox, or ACK. Proof acceptance is only one input to the state owner, and the
state-owned result and database mutation must commit in one fail-closed atomic transaction.

The first complete `PRIVATE_ZK` scale profile may be one authoritative source producing one ordered
100-operation batch proof. The private proof owns only the exact undisclosed assertion relation, its
operation/batch binding, hiding commitment/opening, qualified source-bound root, and minimal assertion
result. The independent verifier returns only an opaque assertion-verification receipt/outcome. An exact
typed binding carries that receipt into the state transaction and later Lean semantics; the state
evaluator/transaction alone owns `policyResult`, `effectiveDirective`, chronology, exception/disposition,
and state mutation. A historical design requiring every private proof to recursively prove the entire
clearance policy/database transition is not part of this contract. Later multi-source composition may
verify `N` independent source proofs or use optional recursive aggregation, but either must satisfy the
complete product gates; replacing the proof backend does not require clearance-state migration.

ZK is not required merely because data is sensitive. If the state clearance service already
lawfully holds every required fact in plaintext, the smallest correct mechanism is inspectable
deterministic evaluation over signed governed records. Native v3 is the mandatory path when an
undisclosed payment-relevant assertion crosses the clearance boundary and affects automation, not
ceremony around evidence the verifier already owns.

No L2, rollup, sequencer, bridge, Solidity ABI, or public data-availability layer is part of this
boundary. Ethereum is not a dependency.

## Current experimental engineering boundary

The current native-v3 proof and application code are experimental engineering only. Exactly three
pre-admission modes exist: `DIRECT_STATE_OWNED` for state-owned canonical non-PHI facts,
`AUTHORITATIVE_ASSERTION` for an operation-scoped minimally disclosed derived assertion with a
qualified PQ source signature, and `PRIVATE_ZK` for a proof over a hidden source-bound assertion.
The verifier-owned control set selects one mode before admission; no runtime fallback or downgrade
exists. The current Queue integration candidate is the nonactivating Profile 10 contract: it issues a state-generated ordered set of exactly 100 opaque 32-byte operation
references and one shared immutable allowlisted statement before a volatile handoff; batch positions
and the ordered batch root are state-computed before handoff.

The Queue handoff accepts only an exact mutable `bytearray`, copies it into a bounded memory-owned
single-use buffer, clears the caller buffer after transfer, and invokes no caller-owned read or
close callback. The inactive handoff boundary uses one pre-provisioned absolute empty non-reparse verifier directory
for the volatile process call; the adapter does not create or remove that directory. The process
runner owns the empty-before check, no-entry/no-spill containment, and cleanup of child-created
entries while retaining the directory itself. The boundary does not persist proof/source/signature/
commitment, frame, statement, exact proof/source digest, PHI, temp/spill, log, acceptance, or
process-output bytes. Authorized Queue/State DB, WAL, and commit writes remain limited to state-owned
fields; an activated profile owns its exact proof envelope and complete-path resource profile under
the contract below; there is no universal input-admission allowance. A consumed, failed, expired,
restarted, or ambiguous handoff becomes `HELD` and requires a fresh state operation and fresh handoff.
These controls do not close the profile theorem, malicious-verifier/QROM, grinding, SHA3, Lean,
deployment, custody, or source-authorization gates.

### Profile 10 Queue integration candidate

The Queue checkout integrates the mechanically interoperable, nonactivating Profile 10 statement/proof
boundary as an unqualified candidate. Its exact identifiers are `PROFILE_VERSION=10`,
`BLIND-ZKBPP-RANGE100-CDG-DIRECT-V1`, the 304-byte `BL-R100-STMT-V2\0` statement with
encoding 2, circuit fingerprint
`a85a1a5f4ad3e9b777e5f9043f8b43f5c0018f8a6aab51359aedfe1264091c0c0f973c9d4e3bf9064383f0db9beb2606bad62b92677db0588006475236bd83cf`,
and Profile 10 fingerprint
`8490652f6c69feb8ac1fa2a8edadf79a45632f67a73f0d67441321afbb7369c6d2bbe71302626fb4f92eb378b8b35fe24d09f11df55f4795ffd227d27ec52f9a`.
The source-auth profile is `BLIND-MLDSA87-SOURCE-AUTH-V1-R100-CDG-DIRECT-V1-UNQUALIFIED`.
One proof covers exactly 100 Queue operations, distinct from its 1,024 cryptographic repetitions
and the Queue's 101-unit reservation. The Rust producer checkout is commit
`626d7e200407b91bcd467b3d4973eae7dcab004c` with tree
`f9631ad1dbc6a6524f8dc3b7d1fc1f38211aafc7`; its mechanical producer-content pin is 403,456 bytes
with SHA-256 `CD16BA905E8C6B9E1135A38AFE29566D22FCB039EDAC5E5018505945F022399`. This carries
no reproducibility or custody claim. The proof envelope is 16,294,348 bytes, the signed prefix is
16,297,640 bytes, the ML-DSA-87 public key is 2,592 bytes, the signature is 4,627 bytes, and
the signed source-auth frame is 16,302,267 bytes. The exact IPC is 16,308,435 bytes
(6,168 state/config bytes plus the frame). Proof, signature, frame, statement, and IPC bytes remain
volatile. The C source-auth owner tracked boundary is commit
`9bd4d8505361e472547fe59ef4c725530b606fcc` with tree
`b023af5753c48ea992560c9b6aca8d4280f2b115`; the canonical state-side executable is
`C:\Users\neers\Documents\Codex\2026-08-30\blind-zkbpp-c-cdg-direct-v1\work\build-profile10\Release\blind_source_auth_verify_process_v1.exe`,
50,176 bytes with SHA-256
`AE01234D32D622D5DCCC269AF4FFD094738865F91FF3440DE91C3A37B3522722`. The candidate remains
unselected, unqualified, `proofSuiteId=null`, `production_usable=false`, and `activation=false`.
The C process takes no arguments; exit 0 is accepted, exit 1 is a combined rejection, exit 2 is
malformed/short/extra input, and exit 3 is an internal failure. Any other exit, timeout, nonempty
output, containment failure, identity mismatch, cleanup failure, workspace change, or concurrent
call fails closed to `HELD`. Complete-path p95 and >=128-bit PQ qualification remain open. Proof
acceptance yields only an opaque scoped verification outcome and never `CLEAR`; State alone owns
chronology, `policyResult`, `effectiveDirective`, exceptions, disposition, retries, and economic
state.

## Source-auth and private representation contract

`AUTHORITATIVE_ASSERTION` signs the narrow operation-scoped assertion directly when the genuine source
contract delegates canonicalization or derivation to that source; it requires no raw digest, dual
commitment, or ZK wrapper. The signature establishes source authority, provenance, and scope, not
source truth or honesty. For `PRIVATE_ZK` with a source-attested witness, the source may sign one
fresh randomized operation-scoped proof-native hiding commitment `P`; the proof must bind its witness
and predicate to exactly `P` and the current operation reference. This establishes source-attested
witness provenance plus predicate correctness, not independent raw-record correctness. If independent
raw-record-to-assertion verification is required, the proof must include the exact canonicalization/
link relation to the authoritative source representation; a signature over two unrelated commitments
is not an equality bridge. Exact in-circuit SHA3-512 is required only when the authoritative contract
makes SHA3 the representation that must be independently linked; otherwise a qualified proof-native
representation may be contracted. `P`, the body, signature, and proof remain volatile and unlinkable,
with no stable digest. This source-attested commitment possibility is unimplemented and cannot supply
a current verifier receipt or state disposition. `proofSuiteId` belongs only to `PRIVATE_ZK` and remains
null/unactivated until the complete profile qualifies; `DIRECT_STATE_OWNED` and
`AUTHORITATIVE_ASSERTION` do not wait on a private-proof backend. Signed unrelated dual commitments,
source-signature-as-truth claims, and claims that destroyed artifacts remain independently recoverable
are rejected.

Separately from the Profile 10 private-proof/source-auth process boundary, the smallest current
standardized, nonactivating `AUTHORITATIVE_ASSERTION` candidate is
`sourceAuthProfileId=ML-DSA-44-PURE-HEDGED-V1`: FIPS 204 ML-DSA-44, pure rather than HashML-DSA,
hedged signing, and fixed context/domain `BL/SOURCE-AUTH/ASSERTION/v1`. Approved key-generation RBG
strength is at least 192 bits so the selected set retains its Category 2 claim. Its body is fixed-
length-delimited and canonical, never JSON, with no classical or algorithm fallback. It contains
only the exact state-issued 256-bit `operation_ref`, source authority/key/epoch, source profile/rule/
version, bounded delegated-assertion enum/value, and bounded validity interval. It never contains a
Blind directive, `policyResult`, `effectiveDirective`, exception, chronology, state transition,
payment amount, claimant/provider identity, raw-data digest, or stable fingerprint. This is a
nonactivating candidate requirement, not module validation, HSM/FIPS custody evidence, source truth,
or production qualification.

Blind verifies the canonical body/signature ephemerally and destroys/discards those bytes after verification;
only an opaque operation-scoped verification receipt/outcome plus qualified source-auth profile/
version/key epoch is durable. The authoritative source owns lawful original retention. State recovery
proves only that Blind recorded a valid verification at the time; it cannot reverify the original
source signature from Blind storage alone. A source-assisted later re-verification is a separate
reacquisition event, not guaranteed recovery. State audit/checkpoint PQ signatures may authenticate
opaque receipt history but do not recreate or prove the original source signature.

### Zero-PHI deployed recoverability gate

Current experimental Python/OS handling does not establish destruction. Activation is blocked until
the deployed process/module/OS configuration and adversarial evidence show that raw proof,
signature/body, source material, credentials, paths, stdout/stderr, and linkable fingerprints cannot
enter or remain recoverable from crash dumps, swap/pagefile, temp files, backups, telemetry, support
captures, or AI. The Queue-owned handoff buffer is wiped in full on close; this does not falsely
claim byte-zeroization that Python can prove.

The strict public handoff allowlist is the one-time random ordered set of 100 operation references
and batch challenge, shared assertion and profile versions, bounded validity window, ordered batch
positions/root, and approved-source registry root when needed. Names, claim numbers, provider fingerprints, raw-data hashes,
source paths, and stable cross-batch identifiers are excluded.

The current statement grammar intentionally carries only the strict public allowlist. A selected hidden
assertion may bind an amount only when that amount is itself part of the selected assertion contract;
state-held amounts remain state-owned. Policy, directive, chronology, reads/writes, exception authority,
and the state transition are likewise state/Lean/database semantics, not universal proof fields. If an
authoritative contract requires independent raw-record linkage to a SHA3 representation, the selected
relation must include that linkage; otherwise a qualified proof-native representation may be used. The
typed receipt and separately verified atomic state transition may evolve together only at a breaking,
versioned boundary. Until the selected relation and state/Lean gates qualify, proof acceptance cannot
authorize `CLEAR` or any economic action.

## Production-shaped patch-in contract

Native-v3 is the private-clearance plug-in behind a fixed business and state interface, not a
semantic rewrite. A qualified implementation must preserve the canonical five-directive grammar,
`policyResult`/`effectiveDirective` separation, governed control-set/order, authoritative
absence, four-time chronology, decision/access join, exception identity, roots, replay, and
fail-closed state transition. Productionization is qualification and substitution of the Lean
kernel, native verifier/backend, authenticated source/governance inputs, and production
database/custody adapters. Every substitution reruns the frozen KATs, independent verification,
mutation/replay/recovery, and complete resource gates. A component that changes those interfaces
is an architecture change and requires review. The current qualification record and the unresolved
private-proof terms remain in `STATE.md`; the read-only provider-continuity wedge does not wait for
this private-payment plug-in.

## Smallest complete system

1. The verifier-owned control set selects exactly one of the three evidence modes before admission.
2. `DIRECT_STATE_OWNED` evaluates state-owned canonical non-PHI facts without a re-proving wrapper.
   `AUTHORITATIVE_ASSERTION` consumes an operation-scoped derived assertion whose qualified PQ
   signature authenticates authority, provenance, and scope but not truth. `PRIVATE_ZK` receives a
   source-bound hiding commitment and proves only the narrow hidden assertion/predicate.
3. The evidence owner returns only a mode-specific, non-dispositive evidence result:
   `DIRECT_STATE_OWNED` returns the state-owned evaluation, `AUTHORITATIVE_ASSERTION` returns the
   qualified source-signature/assertion result, and `PRIVATE_ZK` returns proof acceptance plus the
   opaque ordered batch references and bounded shared assertion/profile/version/order/resource fields. For the
   current unqualified Profile 10 private handoff, the independent verifier consumes the sealed
   memory-owned handoff once; producers, transports, logs, and caller booleans have no acceptance
   authority, and the handoff is never
   refetched. None of these results contains policyResult or effectiveDirective.
4. The state owner separately resolves `PASS`/`MISSING`/`AMBIGUOUS`/`FAIL` plus state exception
   approval into exactly the five directives, then atomically applies the ordered state chain and
   opaque reference/directive outbox. The official state payment system, not the proof or Blind
   Ledger database, moves money.

The source-auth and private-representation contract above is normative for this composition sequence.
A qualified implementation may avoid repeating source signature verification inside every private
proof only under that exact contract; this moves repeat work to its natural owner and never trusts a
prover-supplied root. The resulting evidence still establishes no source truth or state disposition.

## Clearance semantics and typed receipt

Native v3 preserves five fixed state directives: `CLEAR`, `HOLD`, `HUMAN_REVIEW`, `BLOCK`, and
`EXCEPTION_APPROVED`. A future qualified proof binds only the hidden assertion; the state owner and
Lean/database relation bind the ordered state relation. The verifier returns proof acceptance only;
proof acceptance is not itself a directive and must never default to `CLEAR`.

- `CLEAR` means every selected deterministic automatic check passed.
- `HOLD` means a fixable deterministic requirement is missing.
- `HUMAN_REVIEW` means judgment, ambiguity, an unavailable authoritative fact, or additional
  evidence prevents automatic enforcement.
- `BLOCK` means a clear state-approved deterministic condition failed.
- `EXCEPTION_APPROVED` means a separately governed state official authorized a scoped override.

The state-owned operation row carries an underlying `policyResult`, an `effectiveDirective`, and
state-owned exception approval. The no-exception case uses a domain-separated sentinel. The state
owner maps `PASS` to `CLEAR`, `MISSING` to `HOLD`, `AMBIGUOUS` to `HUMAN_REVIEW`, `FAIL` without
exception to `BLOCK`, and `FAIL` with state exception approval to `EXCEPTION_APPROVED`. The proof
preserves no disposition authority, so a verifier or witness cannot erase or rewrite the state
decision trail.

The future `PRIVATE_ZK` public contract remains commitment-only and fixed-shape. Its independent
verifier returns no directive, policy result, raw proof, source identity, or exact artifact
fingerprint. `DIRECT_STATE_OWNED` and `AUTHORITATIVE_ASSERTION` have separate mode-specific
evidence results; they do not use a private-proof receipt or wait on a private-proof backend.
The state owner emits the separate state receipt and may release only the state-owned directive to
the official payment system. `HOLD`, `HUMAN_REVIEW`, and `BLOCK` do not advance economic clearance
state.

A verifier failure returns no receipt and no directive. Operational continuity may use a separately
authorized, signed, expiring human override recorded by Mirror; it is outside proof acceptance and
cannot relabel a failed proof as `CLEAR`.

## Governed rule and evidence boundary

The State Control Pack is the canonical rule source shared by Provider App, the state reference
engine, Mirror comparisons, and Blind Ledger. Blind Ledger never reauthors policy in a private proof.
Each enforceable rule artifact commits to its source authority, version, effective interval, scope,
required evidence, deterministic logic, explicit exceptions, conformance tests, state approval, and
supersession history. The registry leaf may commit to that canonical payload rather than duplicate
it, but its typed record kind and authority role must prevent a fact, rule, contract obligation, or
exception authorization from being substituted for another.

The verifier-owned governance snapshot resolves one exact `automaticControlSetId`: the ordered rule
identities, priority/conflict policy, directive mapping, transaction scope, and effective interval
that the state approved for automatic enforcement. The prover cannot omit an applicable rule,
choose a more favorable subset, or change the conflict policy. Unknown scope, overlapping rules
without a governed resolution, or a rule outside its effective interval yields `HUMAN_REVIEW` or a
fail-closed rejection according to the frozen control-set policy.

The commercial read-only provider-continuity wedge stops before this automatic-enforcement
boundary. It is a Mirror/Provider Trust Graph finding, remediation, parity, and transition product;
it does not create an operative `ClearanceDecisionRow`. The current synthetic plaintext continuity
module exercises future Blind Ledger semantics only as an internal conformance harness. A
Behavioral Twin extraction or Mirror finding is a candidate input to governance, never an approved
control merely because it describes incumbent behavior.

Mirror may supply evidence references and responsibility-boundary observations, but a Mirror label
is not truth by itself. Every fact used for automatic clearance must resolve to the selected
verifier-owned mode: state-owned canonical facts for `DIRECT_STATE_OWNED`, a qualified operation-
scoped PQ-signed derived assertion for `AUTHORITATIVE_ASSERTION`, or a source-bound commitment and
private predicate proof for `PRIVATE_ZK`. Missing or ambiguous authority yields `HUMAN_REVIEW`, never
a prover-invented fact.

Each evidence reference retains its authoritative source identity, record kind, exact subject and
scope, observation time, validity interval, population/completeness authority, provenance, and
integrity binding. Mirror may additionally retain visibility level, responsibility boundary, and
confidence for oversight, but those interpretive fields cannot supply automatic truth. Only the
verifier-owned governed source contract determines clearance eligibility.

Absence is a fact with its own authority. A missing authorization, enrollment, attachment, or other
record may produce `HOLD` or `BLOCK` only when the proof binds a complete authoritative snapshot,
bounded nonmembership proof, or signed closure/completeness assertion for the exact subject, scope,
and time. Absence from an incomplete feed yields `HUMAN_REVIEW`. The database authority owns the
strict relation `rule_effective < event < observation < decision` and exact decision/access join;
retries cannot change the bound rule or source snapshot.

## Native-v3 public statement

Native v3 uses a fixed, typed, canonical binary record. It is not the old 12-field `bytes32` ABI and
does not carry felt or Poseidon compatibility projections. The verifier-facing source/proof handoff
contains only the following strict public allowlist:

```text
operationReference            // one-time state-issued random challenge/reference
assertionIdentifier
assertionVersion
statePolicyVersion
proofProfileVersion           // PRIVATE_ZK profile metadata when selected
validFrom
validUntil                    // bounded validity window
orderedBatchPosition          // present only for an ordered batch
orderedBatchRoot              // present only for an ordered batch
approvedSourceRegistryRoot    // present only when the selected source contract requires it
```

The state-side context, governance, control-set, chronology, before/after roots, economic
commitments, and audit identities are retained only in the state-owned receipt/transaction; they
are not source/proof handoff fields. `proofSuiteId` belongs only to `PRIVATE_ZK`, remains null until
that complete profile qualifies, and is not caller-selected. A selected `PRIVATE_ZK` transcript
absorbs the exact allowlisted statement before any challenge.
Unknown versions, contexts, suites, lengths, orderings, duplicates, alternate encodings, and
trailing bytes fail before untrusted-size allocation. State sequence, chronology, policy, directive,
exception, outbox, and ACK semantics remain state-owned receipt/transaction fields; the private
proof relation does not establish them.

## Logical private tables

Keep business semantics separate from memory mechanics. Native v3 has two logical fixed-capacity
tables even if a qualified backend later fuses their physical trace after equivalence tests:

```text
ClearanceDecisionRow
  decisionIndex, decisionCount
  attemptId
  subjectCommitment
  proposedPaymentCommitment
  decisionPathCommitment       // ordered applicable rules, evidence, conflict resolution, and reasons
  authorizedAmountCommitment
  policyResult                  // state-owned disposition control result
  effectiveDirective             // resolved only by the state owner
  exceptionAuthorizationId     // governed identity or canonical no-exception sentinel

StateAccessRow
  decisionIndex, accessIndex, accessCount
  address, key
  valueBefore, valueAfter
  accessMode
```

The state owner and later Lean/database relation join every state access to exactly one decision,
enforce chronological ordering, and reject orphaned, duplicated, reordered, or omitted rows. A
`PRIVATE_ZK` proof may establish only the hidden source-bound assertion/predicate that supplies one
input to this state-owned evaluation. `decisionPathCommitment` is state-owned and selectively
auditable; it gives every automatic directive a stable link to its source rule, evidence, tests, and
decision path without putting PHI in the public statement. A physical fusion is an optimization only
and cannot erase these logical bindings or their independent mutation tests.

## Lean semantic and transition authority

The approved target places the pure five-directive evaluator and legal local state transition in
an executable Lean 4 kernel. Lean covers bounded canonical semantic decoding, control-set
selection, authoritative completeness/nonmembership, chronology, exception eligibility,
observation-only separation, replay, decision/access joins, and allowed after-state. Rust remains
the cryptographic verifier and transcript/proof-envelope authority; the database remains the
concurrency, durability, and recovery authority.

A private proof can authorize no mutation unless the Rust verifier accepts and the state owner
accepts the minimal verifier receipt plus its own state-owned disposition/transition through the
Lean kernel. A direct state-owned evaluation uses the same Lean semantic relation over canonical
governed plaintext inputs. The deployed path must execute the proved definitions or have a
reviewed refinement proof to them; KAT agreement alone is not formal-verification credit. The full
theorem and build contract is `LEAN_FORMAL_KERNEL.md`.

## State and replay design

Native v3 separates three jobs:

- the semantic relation owns the exact fixed-capacity ordered operation table, five-directive
  clearance semantics, exception-authorization checks, and money/policy rules;
- the state owner and later Lean/database relation establish chronological reads, writes, uniqueness,
  replay rejection, and the before-to-after transition; and
- SHA3-512 authenticates stable endpoint identifiers instead of being recomputed at every internal
  state access.

The state interface is:

```text
stateId = SHA3-512(
  "BL/NATIVE-V3/STATE-ID/v1" || executionContextId || sequence ||
  stateLayoutId || capacity || length(stateCommitmentBytes) || stateCommitmentBytes
)
```

`stateCommitmentBytes` must be deterministic, canonically encoded, transparently constructed,
post-quantum binding, incrementally maintainable, and verified by the state owner and later
Lean/database relation. No felt, truncated digest, host comparison, or prover-supplied unchecked
root may authorize state. The exact commitment/memory theorem remains an implementation choice and
must earn its claim with a small complete proof before scale work; a private proof does not
authorize the state relation.

## Proof-backend contract

The backend is replaceable behind one narrow interface. It must provide:

- a canonical fixed-profile statement and witness grammar;
- one complete source-bound assertion/predicate, commitment-opening, hiding, and verification
  theorem; state semantics and transition theorems remain separate Lean/database gates;
- native witness hiding for every committed/opened oracle and proof message;
- deterministic, transparent, versioned public parameters derived from reviewed standards or
  constants, with no secret or trusted setup and no elliptic-curve dependency; any activation
  profile whose soundness or privacy depends on an unverified ceremony, toxic-waste destruction,
  or hidden parameter custody is rejected;
- a transcript construction covered by the selected profile's exact post-quantum theorem, if that
  profile selects Fiat-Shamir or an interactive coin;
- an independent verifier returning typed outputs only after full verification;
- deterministic verification, bounded parsing, mutation/reorder/omission rejection, and exact
  resource telemetry; and
- streaming or bounded-frontier proving with exact source-local prover and optional-aggregator
  hardware requirements declared by the selected profile; those components have no state authority.

Every `PRIVATE_ZK` profile requires an exact zero-knowledge/privacy theorem for its actual adversary
and transcript model; profile-conditional means selecting the applicable theorem, never omitting
one. For an interactive protocol, malicious-verifier privacy plus reset, abort, retry, and session
composition is mandatory. For a noninteractive protocol, the exact NIZK or Fiat-Shamir/QROM privacy
and soundness model is mandatory instead; a separate interactive malicious-verifier property is not
required when it is inapplicable. Fiat-Shamir/QROM, grinding, separate cryptographic nullifiers,
and recursion/aggregation remain profile-conditional. If selected, each is covered by that profile's
exact finite theorem and composition ledger, including bounded attempts, fan-in, retries, aborts,
batching, recursion, and all bad events. A state-issued fresh 256-bit operation reference/challenge
plus database uniqueness is the default cross-operation replay/binding defense; it does not replace
proof soundness. Aggregation is optional and receives no product credit unless measured as part of
the complete path.

## Security target

- Every computational primitive used by an activated external-authority or private-proof profile,
  and the composed system's relevant computational primitives, must meet at least the NIST
  post-quantum Category 1 baseline for its attack model. NIST categories are broad comparison floors,
  not an exact proof-security claim or generic proof-soundness theorem.
- One qualified security-profile deployment/authorization lifetime has a hard global budget of at most
  `2^32` theorem-relevant acceptance opportunities, not merely process invocations, across all hosts,
  tenants, members, batches, retries, aborts, crashes, and every key epoch or rotation under that
  profile. A batch or aggregate containing `n` independently false-able member statements conservatively
  consumes `n` member occurrences plus any separate aggregation event unless the exact selected theorem
  proves a smaller accounting unit. The state owner reserves each opportunity atomically before
  cryptographic acceptance work. Key rotation does not refund or reset this global budget. Per-key and
  per-epoch signature, message, and query caps are nested operational limits, not fresh statistical
  soundness budgets. Retries, aborts after challenge or verification begins, malformed candidate
  verifications, crashes after reservation, and other consumed reservations are never refunded. A
  genuinely new security profile with separate requalification has a separately scoped claim; any
  cross-profile or system-lifetime claim must explicitly bound and union all such profiles and does not
  inherit the finite `2^-128` bound automatically. Exceeding the budget, overflow, cap exhaustion,
  ambiguous batch cardinality, reservation loss, or loss of trustworthy global coordination/counter
  state fails closed. Rotation or requalification under the same profile cannot restore consumed budget;
  only a genuinely new security profile may establish a separately scoped claim. This is an assurance
  accounting bound, not a throughput target.
- The exact theorem ledger must prove the union of all statistical bad events over the full globally
  reserved lifetime budget, apply the conservative member-plus-aggregation charge unless its
  exact theorem justifies less, and include proof soundness/knowledge, commitment binding where
  statistical, transcript/challenge collisions, enabled aggregation, operation-reference
  collisions, abort/retry/reset, and every other union factor. The total must be at most `2^-128`.
  Equal allocation across eight per-attempt classes requires at least 164 bits per event; use a
  192-bit per-proof/statistical engineering target unless a tighter exact ledger proves the complete
  bound.
- The complete finite proof/aggregate false-acceptance ledger is distinct from the NIST Category 1
  floor and must cover bounded attempts, fan-in, queries, repetitions, batching, recursion/
  aggregation, all bad events, and complete composition. Category 1 alone is not an exact 128-bit
  proof, and no unbounded deployment-lifetime `2^-128` probability is claimed.
- Computational PQ claims are a separate ledger. Each suite declares its adversary work/query model,
  signature/oracle counts, key lifetime, reduction loss, and whether the selected NIST category
  preserves the intended 128-bit product claim under that finite deployment/authorization-lifetime
  budget; a stronger category is used
  when the exact reduction or usage evidence requires it, without a global Category 3 mandate.
- SHA3-512 remains the authoritative external identifier and provides margin; digest width alone is
  not proof-system security.
- Signatures for activated external-authority profiles are algorithm-agile and must use a NIST-
  approved PQ profile of at least Category 1. Source, authorization, configuration, and audit
  signatures are qualified PQ trust-boundary inputs; classical-only failure never downgrades to
  plaintext or synthetic acceptance.
  Two independent Category-5 signatures are required only by a documented custody/governance threat
  model or an actual National Security System profile, not by default inside every proof.
- No production claim is allowed without executable parameter accounting, exact theorem mapping,
  independent verification, malformed-proof tests, and side-channel review.

## Privacy and resource contract

- Proof, trace, operation count, errors, and externally visible schedule are fixed per selected
  deployment profile and independent of all five directives, exception presence, padding, and
  other private values.
- Each selected verification profile owns the smallest exact proof-envelope cap that passes parser,
  leakage, and capacity tests, never above the absolute `4,500,000,000`-byte admission ceiling. There
  is no universal profile allowance; an unselected private-proof profile remains inactive.
- Fresh secret randomness is OS-CSPRNG-owned, domain-separated, never reused or logged, and zeroized
  after proving.
- The complete controlled reference path includes source-local proving, optional aggregation when
  selected, independent verification, the atomic state transaction, and outbox/ACK; its complete
  process tree must remain strictly below `5,000,000,000` bytes. A selected profile may separately
  declare exact source-local accelerator or hardware requirements, but that deployment evidence cannot
  satisfy or replace the pinned laptop product gate.
- Report source-prover, optional-aggregator, independent-verifier, state-transaction, and outbox/ACK
  stages separately, with external official-source and official-ACK latency measured and disclosed
  separately when applicable. A complete-profile measurement begins at admitted canonical input and
  ends after independent verification, the atomic state transaction, and outbox/ACK; component or
  cached timings receive only component credit.
- For product credit, that complete controlled reference path must run 100 complete operations within
  35 seconds p95 on the pinned laptop-class reference hardware, with the complete resource and
  negative-test boundary. Other source hardware may be disclosed separately but does not satisfy or
  replace this gate. This is an engineering floor inherited from the earlier campaign, not the final
  product SLA. Sustained claims/second, p95 time-to-first decision, thermal throttling, energy,
  queue/cadence leakage, and recovery are reported. A larger profile is forbidden until this boundary
  accepts and product volume actually requires it.

## Implementation order

The Lean item below is a deferred formal gate, not the current or next implementation phase. The
nonpayment commercial wedge and operational foundations come first, and Lean work begins only after
explicit phase authorization. It still must close before production clearance or payment authority.

1. Freeze the canonical native-v3 statement, typed receipt, five-directive operation table,
   source/exception-registry contract, privacy adversary, and declared laptop-class state-side
   reference profile.
2. The five cross-language KATs cover `CLEAR`, `HOLD`, `HUMAN_REVIEW`, `BLOCK`, and governed
   `EXCEPTION_APPROVED`, with wrong-directive, exception, chronology, corruption, root, statement,
   and state-mutation negatives. The exception seal is synthetic-KAT-only.
3. At the later authorized formal gate, implement the Lean kernel, canonical decoder, theorem
   manifest, independent check, and narrow fail-closed Rust adapter against the frozen KATs.
4. Implement the smallest complete narrow private fixture: one hidden assertion relation with its
   operation/batch/source-bound commitment and minimal result, an independent verifier returning the
   typed receipt, and its binding into the separately verified state transaction and later Lean
   semantics. Include SHA3 linkage only when the selected authoritative representation contract
   requires it.
5. Require rejection of corruption, wrong bindings, reorder, omission, duplicate/replay, directive,
   exception, and after-state mutations plus complete resource telemetry.
6. Add fixed-profile batching and a streaming state/memory implementation. Optimize only the
   measured dominant complete-process stage.
7. Bind the typed receipt to the existing atomic database boundary and test retry, concurrency,
   rollback, crash, and recovery.
8. Meet the 100-complete-operation/35-second-p95 state-side floor, then freeze the
   machine-verifiable security ledger and proof-package grammar. Only then consider a larger
   profile, accelerator, aggregation, or production candidate.

## Retirement and deletion boundary

The old Privacy V2, fixed-shape, binary-field, L2/Starknet/Solidity, exact-package, and
unconditional dual-signature lanes are outside the active core. Their historical proof-layout and
monolithic-launch-gate rejections are recorded once in `REJECTED_ARCHITECTURES.md`; they are not
current capability or profile gates. Deletion requires an enumerated producer/consumer and manifest
scan, replacement tests, and one bounded change; historical performance is never production credit.

## Current claim boundary

`STATE.md` owns qualification, nonactivation, resource, and private-proof status. Phase-0 KATs and
the synthetic exception seal are evidence only; no complete native-v3 proof, production signature,
or deployed formal-verification claim exists.
