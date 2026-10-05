# Gate failover model (TLA+)

`gate_failover.tla` models the payment gate's primary/standby failover: epochs,
fencing, synchronous replication, solo mode, ML-DSA token signing, the payer's
fence, and the two-signature bypass with post-hoc reconciliation. It is a design
model, not the implementation; a code change that departs from it needs the model
updated and rechecked. It models one shard. Resharding is out of scope: a tenant's
shard count is fixed (Lean `installCert`), and changing it needs its own migration
spec.

## Results (2026-09-25, TLC 2.19, `-deadlock`, 1 worker, 512 MB heap, under the guard)

| Config | Model | Checked | Result |
|---|---|---|---|
| `safety.cfg` | 2 nodes, 2 payments, MaxEpoch 3 | TypeOK, NoConflictingTokens, NoFencedTokenAccepted, ReleaseRequiresTokenOrBypass, AtMostOnceRelease, NoLostDecision, StaleCannotSign, EpochMonotone | No error. 17,706,382 generated, 3,516,192 distinct, depth 24, 2 min 17 s |
| `live.cfg` | 2 nodes, 1 payment, MaxEpoch 2 | BypassEventuallyReconciled | No error. 21,214 generated, 5,152 distinct, depth 14 |
| `gate_failover.cfg` | as `safety.cfg` | all of the above | No error (2026-10-05, 3.5 GB heap). Same counts as `safety.cfg`, 37 min 42 s |

Not yet checked: 3 nodes, 3 payments, MaxEpoch 4.

## Rerun

```
java -Xmx512m -cp tla2tools.jar tlc2.TLC -workers 1 -deadlock -config safety.cfg gate_failover.tla
java -Xmx512m -cp tla2tools.jar tlc2.TLC -workers 1 -deadlock -config live.cfg gate_failover.tla
```

Run through the shared runner (`rr_guarded.ps1 -Exe java ... -MinFree 2200000000`).
tla2tools.jar v1.7.4 (SHA-256 `936A262061C914694DFD669A543BE24573C45D5AA0FF20A8B96B23D01E050E88`), Temurin JRE 21.0.12.1.
