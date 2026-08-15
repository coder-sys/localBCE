# Native-v3 threat model

Updated: 2026-08-14

The filename is retained for compatibility; this document now describes the current Blind Ledger
boundary.

| Boundary | Adversarial condition | Required response |
| --- | --- | --- |
| Control selection | Caller selects mode, evaluator, rule order, scope, interval, or fallback | Reject; only the exact verifier-owned control set is admissible |
| Source ingestion | Forged, stale, ambiguous, omitted, or reordered facts | Verify canonical bytes, signer authority, freshness, ordering, and completeness; fail closed |
| Absence | Missing record is treated as proof of nonexistence | Require authoritative completeness plus exact nonmembership |
| Private proof | Corrupt proof, wrong statement/root/control set, replay, omission, duplicate, or mutation | Independent verification and exact transcript reconstruction; no directive on failure |
| Direct evaluator | Conflicting facts, stale rule interval, or caller-supplied result | Deterministic conflict policy or human review; never trust caller output |
| Exception | Missing, expired, out-of-scope, or prover-selected authorization | Reject or preserve underlying directive; require stable governed signed identity |
| State | Stale before-root, concurrent retry, duplicate request, partial write, recovery replay | One atomic transaction with exact replay identity and before/after verification |
| Chronology | Event, observation, rule-effective, and decision times are conflated | Bind and validate all four independently |
| Economics | Proof/session acceptance is treated as CLEAR or amount is mutated | Keep typed directive separate; verify exact economic fields; official system moves money |
| Resources | Prover exceeds memory/scratch/pagefile limits | Abort safely; never weaken the 5,000,000,000-byte process-tree cap |
| Operations | Stale docs or retained prototypes are treated as authority | Use current architecture and executable evidence; legacy material gives no activation credit |

Signatures establish provenance and authority, not real-world truth. Dual Category-5 signatures are
required only when an approved custody threat model says so; algorithm agility and the current
approved profile govern otherwise.

The repository remains synthetic and nonactivating: `proofSuiteId=null`,
`production_usable=false`, activation false, and real PHI/payments forbidden.

