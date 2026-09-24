# Direct Mask local opportunity accounting v1

Status: source implementation is present in
`formal/lean/BlindLedger/OpportunityAccountingV1.lean`. It has not been compiled
or executed in this source-only handoff. The focused Lean examples are in
`formal/lean/BlindLedger/OpportunityAccountingV1Tests.lean` and remain pending
the Security guarded-lane handoff.

## Contract

Schema: `BL/DIRECT-MASK/LOCAL-OPPORTUNITY-ACCOUNTING/v1`.

This is an importable deterministic Lean reducer for service-observed events in
one caller-held local state. Its typed IDs are unsigned values below `2^256`;
their canonical encoding is base-10 without leading zeroes. The request body
fixes the event kind and, where applicable, its parent attempt and commitment
identity. The reducer has no `Q` event or field.

| Event | Charge | Local rule |
| --- | --- | --- |
| `A` attempt | `A += 1` | Event ID is the attempt ID; failed, rejected, aborted, and unknown final outcomes stay charged. |
| `S` source commitment | `S += 1` | Commitment IDs are deduplicated; a second event ID for an already-counted commitment is rejected without charge. |
| `M` fresh commitment | `M += 1` | Requires an open admitted `A`, a unique commitment ID, and at most one fresh commitment per parent attempt. This enforces the local `M <= A` accounting shape; it does not prove the producer follows the cryptographic algorithm. |
| `E_U` source-U issuance | `E_U += 1` | Every accepted event ID charges separately. Value nonzero-ness, issuance independence, and source provenance are not observed. |
| `V` verifier invocation | `V += 1` | Every accepted event ID charges separately. The reducer cannot prove that every real invocation called it first. |
| `R0`, `R2`, `R3` stage reservation | corresponding `R += 1` | Requires an open admitted `A`; every reservation is charged before candidate work. |
| `EVAL_R0`, `EVAL_R2`, `EVAL_R3` stage evaluation start | separate local observation count | Requires an open admitted `A` and a prior reservation for that stage; each cumulative evaluation-start count must remain at most its corresponding `R` count. These counts are not terms in the DMV2 query formulas. |

Caps match the current DMV2 arithmetic caps: `A,S,E_U,V <= 2^32`, `M <= A`,
`R0 <= 2^16*A`, `R2 <= 2^12*A`, and `R3 <= 2^22*A`. `Nat` has no machine
overflow; every accepted increment is checked against these finite protocol
caps before the reducer changes state. `Q <= 2^128` is intentionally absent
because offline adversarial QRO queries cannot be observed or reserved by this
service-local primitive.

An accepted reservation or stage evaluation start is charged immediately.
`COMPLETED`, `REJECTED`, `FAILED`, `ABORTED`, and `UNKNOWN` only finalize the
event; they never refund a counter or evaluation-start count. An exact
event-ID/request retry returns the original reservation
receipt and, if already finalized, the same terminal receipt. Reusing an
admitted event ID with changed input returns `INPUT_CONFLICT`. A rejection
before admission consumes neither the counter nor the event ID. Finalizing an
event with the same outcome is an exact retry; a different outcome conflicts.

Reservation and terminal receipts use stable ASCII fields separated by `|`:

```text
schema|RESERVED|scope-id|event-id|kind-fields|A=n,S=n,M=n,E_U=n,V=n,R0=n,R2=n,R3=n|EVAL_R0=n,EVAL_R2=n,EVAL_R3=n
schema|FINAL|scope-id|event-id|kind-fields|A=n,S=n,M=n,E_U=n,V=n,R0=n,R2=n,R3=n|EVAL_R0=n,EVAL_R2=n,EVAL_R3=n|OUTCOME
```

`A`, `S`, `M`, `E_U`, `V`, stage reservation kinds, and `EVAL_R0/R2/R3` kinds
are fixed tags. All IDs and counters are canonical decimal. Result records have stable `RESERVE`/`FINALIZE` tags,
fixed status names, scope and current totals, the request event identity and
kind (or requested terminal outcome), and length-prefixed optional receipts.
The counter groups inside a receipt are the snapshots captured when that event
was admitted; only the result record carries the current state totals.
Receipt strings are identifiers for this local reducer only: they are not
signed, authenticated, or global attestations.

## Owner boundary and recovery

Producers are the honest attempt path (`A`), source commitment path (`S`), fresh
BAVC commitment path (`M`), source-U issuer (`E_U`), verifier launcher (`V`),
and retry loops at stages `R0/R2/R3`. Each stage producer first reserves its
candidate, then records a stage evaluation start before invoking the evaluator.
The reducer enforces the aggregate count inequality; it does not bind an
evaluation start to one specific reservation row.
The Lean module is only the deterministic transition they may call. It does
not make a producer call the reducer and does not verify correspondence between
claimed observations and actual work; an unresolved evaluation remains charged
as an attempt and should finalize `UNKNOWN`.

The owner adapter consuming this reducer must serialize concurrent updates or
use compare-and-swap on the exact prior state. It must atomically commit the
new counters, event history, and reservation receipt before allowing work to
start. A failed commit permits no work; a stale concurrent writer must reload
and re-evaluate instead of overwriting a newer state. Exact retry after an
accepted reservation or evaluation start returns the original receipt and does
not authorize starting work again. If recovery cannot determine whether work ran, finalize
the still-pending event as `UNKNOWN`; that charge remains. Commit finalization
and its receipt atomically so a lost response can be recovered by exact retry.

The local scope ID is fixed in each state and the reducer exposes no reset
operation, but callers can construct another state, clone or restore old data,
or bypass the reducer unless an owner authority prevents it. This artifact
validates the caller-held history's internal ordering and counts; it does not
authenticate that history or prove a terminal parent's earlier child timeline.
It does not supply atomic storage, a monotonic external reference, producer
binding, issuer provenance, clone/rollback resistance, a cross-process lifetime
namespace, a global receipt, or private-proof/runtime admission. It does not
connect to Queue, State, Financial, the calculator's admission path, or any
existing 101-unit Queue reservation. Existing algebra and theorem meanings
remain unchanged. `proofSuiteId=null`, `production_usable=false`, and
`activation=false` remain in force.
