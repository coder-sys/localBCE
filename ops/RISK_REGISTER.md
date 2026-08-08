# Risk register

The machine-readable authority is `ops/launch_blockers.json`.

| Risk | Required treatment |
| --- | --- |
| Invalid or privacy-leaking proof | Complete fixed-shape relation, native hiding, independent verification, audit |
| Forged/stale signed evidence | Dual-PQ authority, exact source/version/epoch/completeness binding |
| Verifier/database TOCTOU | One serializable transaction with locked roots and nullifier uniqueness |
| Duplicate/conflicting retries | Idempotency key plus exact request commitment; fail on mismatch |
| Database loss or rollback | Replication, backup/restore drills, signed append-only log, external anti-rollback |
| Custody compromise | HSM/FIPS custody, separation of duties, rotation and recovery drills |
| Build substitution | Locked offline builds, SBOM, hashes, reproducibility |
| PHI leakage | Fixed public shape, forbidden-field checks, redacted non-PHI events |
| Source dishonesty or bad policy | Governance, audit, appeals, signer accountability; ZK cannot remove this trust |
| Availability | Capacity, replicas, failover, recovery objectives, incident response |

No proof, audit, privacy, state, source-authority, or activation blocker may be downgraded to accepted risk. No L2 exists in the current threat surface.
