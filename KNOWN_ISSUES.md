# Known issues

Updated: 2026-08-14

| Area | Current issue and consequence |
| --- | --- |
| Private-proof backend | No backend is selected and no complete native-v3 proof exists. Production, activation, K128/K512, and private-proof performance claims are blocked. |
| Security composition | Concrete SHA3-512 commitment binding/hiding, collapse-position binding, malicious-verifier ZK, semantic/state composition, abort/retry composition, and authenticated-challenge accounting do not yet have one complete finite `<=2^-128` proof. |
| Plaintext wedge | The provider continuity slice is synthetic and read-only. It is not a selected production evaluator, does not move money, and has no PHI authorization. |
| Product/API separation | The synthetic continuity harness exercises future Blind Ledger directives, but the first commercial provider-continuity wedge is a read-only Mirror/Provider Trust Graph capability. A distinct external finding/remediation contract is not implemented yet. |
| Formal kernel | The Lean semantic/state-transition kernel, canonical decoder, theorem manifest, native artifact, Rust adapter, and deployed-code correspondence are not implemented. No formal-verification production claim is allowed. |
| Continuity naming | The current narrow continuity state is an audit/assessment fixture, not the full operational `Continuity State` required for vendor handoff. Source names must be reconciled in a bounded versioned change. |
| Resource evidence | Direct-path telemetry is small, but complete proof process-tree memory, scratch, pagefile, throughput, and latency are unmeasured because no complete proof backend exists. |
| Corporate data plane | The zero-PHI target includes support, logs, crash dumps, monitoring, analytics, AI tools, contractors, and persistent linkable fingerprints. A production state-side sanitizer and enforceable corporate egress schema are not implemented. |
| Neutral metering | The commercial covered-flow meter and State Value Ledger remain architectural requirements only. They must be downstream, read-only, and unable to influence rules, directives, exceptions, or payment outcomes. |
| Production infrastructure | Production database, key custody, source governance, monitoring, independent audit, and activation review remain unselected or incomplete. |
| Frozen operations prose | Some canonical `ops/` documents still describe retired payment-transition or dual-signature assumptions. Their bytes are frozen by operational authority and require explicit governance authorization before reconciliation; they are not native-v3 architecture authority. |
| Retained code | Legacy Privacy V2, BL-PQ512/H4/CUDA, binary-field, Binius64, and Cairo code remains only for regression, differential evidence, and staged deletion. It must not be treated as the active design. |
| Archive | The current cleanup and continuity source archive has been rebuilt and independently read back at all three retained targets. Any later publishable source change requires another fresh candidate and three-way verification. |
