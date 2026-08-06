# Wave 2 internal reference boundary

Updated: 2026-08-05

Status: local/synthetic engineering evidence only. This document does not select a production
proof suite, create a production verifier, authorize activation, or close the independent audit.

## What is now executable

`app/wave2_internal.py` is the narrow integration seam for the remaining local Wave 2 reference
work. It connects:

- fixed-shape K128 and K512 synthetic private schedules;
- the exact ordered twelve-field Privacy V2 public projection;
- the canonical 744-byte candidate sidecar;
- the bounded `BLPQPF01` proof-body grammar; and
- a fail-closed public-binding/transcript reference verifier.

The proof body contains four fixed 64-byte commitment sections and is always 696 bytes. It contains
no public-output array or sidecar bytes. The sidecar remains a separate 744-byte verifier input.
Private schedules are guarded by `BL_ENV`/`BL_DEV`/`BL_ALLOW_WAVE2_INTERNAL_REFERENCE`, are
synthetic-only, and are never written to the repository or release archive.

The reference verifier checks canonical parsing, candidate identity, the twelve public fields, the
sidecar statement digest, and the transcript digest. It does not claim semantic proof soundness,
zero-knowledge witness hiding, audited PCS security, or production constant-time behavior. Those
are intentionally still fail-closed gates.

## Verification receipt

The offline command is:

```text
py -3.14 -B tools/wave2_internal_conformance.py --repo-root .
```

The verified run produced:

```text
schema=blind_ledger_wave2_internal_conformance_receipt_v1
K128 cases=3 verified=3 private_wire_bytes=23500 proof_body_bytes=696 sidecar_bytes=744
K512 cases=3 verified=3 private_wire_bytes=93388 proof_body_bytes=696 sidecar_bytes=744
fixed_shape=true privacy_clean=true
H6 candidate controls=true
software PQ KMS roundtrip=true software_only=true hsm_backed=false fips_validated=false
network_access=false live_credentials=false proofSuiteId=null activation_allowed=false
zero_knowledge_proof_verified=false
```

Focused tests are `14 passed` for the reference and attack boundary, plus `2 passed` for the
conformance/release profile. The command does not run the expensive K128/K512 qualification
campaign; it is a structural and privacy-boundary receipt, not performance evidence.

## What remains open

The following remain outside this internal reference boundary:

- a production native STARK prover and independently audited verifier;
- a complete native witness-hiding proof and simulator with all abort/retry/artifact paths;
- final PCS/transcript/security-budget selection and a non-null production `proofSuiteId`;
- production HSM/FIPS custody, external anti-rollback authority, and operator key enrollment;
- a real Ethereum client/L2 verifier and production settlement deployment;
- whole-product release qualification and the final independent security audit.

The internal profile is therefore a useful local engineering layer, not a production activation
shortcut. `ops/wave2_internal_release_profile.json` records the same boundary in machine-readable
form.
