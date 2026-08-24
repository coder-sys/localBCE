# Risk register

The machine-readable authority is `ops/launch_blockers.json`. Every blocker is fail-closed; no
open item may be accepted by waiver, caller input, or a derived readiness Boolean.

| Blocker | Classification | Gate | Control boundary |
| --- | --- | --- | --- |
| BL-PROOF-SOUNDNESS | internal_engineering | qualification | complete theorem, native hiding, and independent verification |
| BL-PROOF-THROUGHPUT | internal_engineering | qualification | bounded CPU resource and latency evidence |
| BL-CLEARANCE-STATE-OWNER | internal_engineering | qualification | one Queue/Composition state owner with exact retry/recovery |
| BL-FORMAL-KERNEL | internal_engineering | qualification | executable Lean semantic/state-transition gate |
| BL-CUSTODY-OPERATIONS | deployment_evidence | qualification | release identity, custody, rotation, backup, and restore evidence |
| BL-INDEPENDENT-AUDIT | external_assurance | qualification | independent review of the scoped release |
| BL-OFFICIAL-RECEIVER | external_integration | activation | approved receiver and acknowledgment boundary |
| BL-GOVERNMENT-CONNECTORS | external_integration | activation | authorized state source/connectors and operational terms |

dual-PQ only when the approved threat model requires it. Open proof, state, formal, custody,
audit, receiver, and connector risk remains nonqualifying.
