# Known issues

Updated: 2026-08-08

| Issue | Current boundary |
| --- | --- |
| Internal roadmap | 33 of 81 packages are complete locally; 48 remain open. Five internal blockers are release-candidate blockers; one audit gate and three operator activation inputs also block production activation, for nine total production-activation blockers. |
| Production suite | `proofSuiteId` remains null; selection and activation are forbidden. |
| Independent audit | Not started. One final external audit gate remains after internal engineering evidence. |
| Native verifier | The Rust candidate and direct local boundary exist, but the operational verifier-artifact pin is still an example placeholder and the exact release suite is not qualified. |
| Database transition | `LocalSettlementV2` is an in-memory atomic model. A transactional database port plus concurrency, retry, rollback, crash-recovery, and durable audit tests remain internal Phase 2 work. |
| Database deployment | Selecting and operating the production database engine, backup/restore service, external anti-rollback authority, and live custody remain later activation work. |
| Privacy migration | The 12-field public ABI and local mutation tests pass, but proof-bound differential/inference and database migration/rollback qualification remain open. |
| Custody operations | Software references exist; legal hold, backup/restore, crypto-erasure, provider conformance, HSM/FIPS, and external anti-rollback remain unqualified. |
| Source truth | A valid proof establishes satisfaction of encoded rules over authenticated inputs; it cannot guarantee an authorized source was honest or that policy was correct. |
| Availability | The application database remains an availability dependency. Backups, replicas, recovery, and signed append-only evidence must be operationally qualified. |
| Performance | H5 measured p95 32.360845 seconds for K128 and 148.861885 seconds for K512 on the qualified campaign. These are evidence, not production SLAs. |
| Ethereum | No Ethereum dependency exists through Phase 2. A future direct-L1 checkpoint design has not been implemented or costed from measured gas. |
| Production use | `production_usable=false`; real PHI and real payments remain forbidden. |
