# Cairo binding security notes

The Cairo statement is retained as a differential attack oracle, not the active release proof.

It models governed claim/oracle/ruleset/policy roots, governed facts and policy rows, per-line
authorization, nullifier transitions, cent bounds, value conservation, and state-root binding.

Regression guards cover fabricated facts, duplicate-by-omission, procedure substitution, free
ceilings, non-empty padding insertion, stale roots, denied-claim nullifier forgery, authorization
substitution, and claim-source/oracle drift.

Production remains blocked until the native verifier and parser are audited and pinned, public
inputs match the exact V2 schema, official source/custody systems are qualified, and the direct
database transition passes isolation, retry, crash, recovery, and anti-rollback review.

Cairo does not authorize payment and is not the active heterogeneous proof lane.
