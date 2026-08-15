# Native-v3 plaintext provider continuity wedge

Status: synthetic, local, read-only, nonactivating deterministic V2 boundary. This is not a proof
backend and does not select a production direct evaluator.

This module is an internal Blind Ledger conformance harness for future clearance semantics. It is
not the external contract for the first commercial provider-continuity wedge. That wedge belongs
to Mirror's Provider Trust Graph and reports evidence findings, coverage, discrepancies,
remediation/retest, parity cases, and transition artifacts without creating an operative
`ClearanceDecisionRow` or clearance directive.

The continuity wire contracts are explicitly version 2: every continuity magic and continuity
domain uses the V2 suffix and rejects V1 bytes. The frozen Phase-0 exception-authorization record
remains its own V1 record because the Phase-0 typed receipt freezes that contract; V2 carries its
exact canonical bytes, or the existing nonzero no-exception sentinel.

The wedge covers one synthetic provider, credential, enrollment, and feed identity. The fixed
verifier-owned control set has one ordered rule (`EXPECTED_RULE_ID`), priority 100,
`priority-then-human-review` conflict handling, the scope
`provider-credential-enrollment-continuity-v1`, and the effective interval `[6000, 9000)`. Its
mode is the fixed `DIRECT_STATE_OWNED` identity. No request field can select a mode, control set,
directive, fallback, economic mutation, or after-state.

The canonical path is:

```text
CredentialEnrollmentFact[] + FeedCompleteness
        -> verifier-owned deterministic rule
        -> policyResult + effectiveDirective
        -> one ClearanceDecisionRow
        -> ordered READ StateAccessRow + WRITE StateAccessRow
        -> SHA3-512 before state root / after state root
        -> typed audit-only receipt
```

The self-contained V2 bundle is bounded and ordered as `receipt, request, facts, completeness,
exception-or-sentinel, before-state, after-state`. The request bytes include all four times, the
attempt identity, and the exact expected initial before-state identifier. The independent parser
recomputes the request, chronology, replay, decision-path, decision, state, access, join, receipt,
and bundle identities without importing producer record or evaluator classes.

The absence rule is exact: `HOLD` requires `complete=true` and an exact subject-key
nonmembership entry for the same feed, provider, scope, and observation time. An incomplete feed
cannot infer absence and returns `HUMAN_REVIEW`. Multiple facts for one subject, a stale rule
interval, temporal contradictions, expired or terminated records, and a malformed/ambiguous input
fail closed. Every admitted fact has the exact synthetic identities and the same observation
snapshot as the request and completeness record. `ACTIVE`, `EXPIRED`, and `TERMINATED` are checked
against the observation time, and control-set authorization must cover decision time. A governed
exception uses the frozen Phase-0 authorization record type and nonzero authorization ID; its
deterministic seal remains synthetic-KAT-only.

Every receipt carries `proofSuiteId=null`, `proof_session_accepted=false`, and
`economic_mutation=false`. `CLEAR` is an evaluator directive, not proof acceptance and not payment
movement. The state write is a read-only continuity/audit transition; the official payment system
remains outside this wedge.

`independent.py` parses the bundle without importing the continuity record classes. It reconstructs
the exact matching-fact and absence result, policy/reason/directive, governed exception, control
set/mode/rule/profile bindings, source root, completeness ID, request and four times, decision/
chronology/replay/path IDs, exact initial and after states, access addresses and values, join ID,
receipt ID, and V2 bundle ID. This is independent deterministic-parser evidence only. It is not a
ZK, hiding, PQ, binding, semantic/state proof, production-readiness, or complete `<=2^-128`
composition claim.

The approved target replaces semantic authority with the executable Lean kernel described in
`LEAN_FORMAL_KERNEL.md`. The current producer and independent parser remain essential differential
and mutation evidence, but agreement between them is not a refinement proof or deployed formal
verification.
