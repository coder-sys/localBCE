# Direct-mask native tools (parked track)

These C directories belong to the parked private zero-knowledge evidence track
(`PRIVATE_ZK`; see `parked/README.md`). `direct_mask_fixture` stays at
`native/tools/direct_mask_fixture/` because the protected guard requires that
directory to exist; its CMake finds the siblings via `../`, so building it needs
the siblings restored beside it. Default CMake paths such as `../../vendor` were
written for the original checkout layout and need overrides. None of them is on the financial critical path, and none may
authorize a clearance, state transition, payment or activation.

| Directory | What it owns |
| --- | --- |
| `direct_mask_kernel`, `direct_mask_native` | relation arithmetic and the native witness materializer |
| `direct_mask_circuit`, `direct_mask_vole` | range/tag-linear constraints and the VOLE proof engine (BF256 acceleration) |
| `direct_mask_wire` | the DMV3 proof frame codec, prover/verifier fixtures, bounded process driver |
| `direct_mask_source_auth` | ML-DSA-87 source signature over the canonical statement `x` |
| `direct_mask_source_proof` | source-side producer: `x`, witness, one wire proof and signature |
| `direct_mask_authenticated_proof` | verifier that requires both the source signature and the proof over the same `x` |
| `direct_mask_pipeline` | fixed-size source/verifier CLIs and process status classification |
| `direct_mask_fixture` | test-only public-request appliance with a fixed-seed key |

Rules shared by all of them: fixed-size inputs are checked (null, size, epoch,
range, alias) before any destructive clear, allocation or randomness; every
ordinary failure wipes owned outputs and temporaries; the canonical `x`,
signature and frame are volatile verifier evidence and must never enter State,
a WAL, receipts, logs, backups or any downstream authority. Proof acceptance and
source provenance are separate properties; success needs both for the same
statement.

## DMV3 frame

```
DMV3 header (40 bytes) || x || nu || sigma1 || sigma2 || sigma3 || m1 || m2 || m3 || m4
```

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | ASCII `DMV3` |
| 4 | 1 | version `3` |
| 5 | 3 | zero |
| 8 | 4 | witness bits, LE `125048` |
| 12 | 4 | constraints, LE `172232` |
| 16 | 1 | relation degree `3` |
| 17 | 3 | zero |
| 20 | 4 | `x` length, LE `1147` |
| 24 | 4 | `m1` length, LE `506416` |
| 28 | 4 | `m2` length, LE `15887` |
| 32 | 4 | `m3` length, LE `96` |
| 36 | 4 | `m4` length, LE `20068` |

`x` is canonical with no padding:

```
source_suite[16] || relation_id_bytes:u32le || relation_id[23] || context[64] ||
U[96] || T[96] || C[800] ||
field_bits:u32le || degree:u32le || tau:u32le || w_grind:u32le ||
short_challenge_bits:u32le || open_budget:u32le || witness_bits:u32le ||
constraints:u32le || padding_bits:u32le || mask_count:u32le ||
nonce_bits:u32le || challenge_mode:u32le
```

Relation id `direct-mask-relation-v1`; source suite `SBA1-SRC-CMT-v1` plus one
zero byte; descriptor `field_bits=256`, `degree=3`, `tau=33`, `w_grind=8`,
`short_challenge_bits=64`, `open_budget=229`, `mask_count=6`, `nonce_bits=512`,
`challenge_mode=3`, zero padding bits. Payload sizes are derived, never taken
from the header:

```
ell = 125048; bit_rows = ell + 6*256 = 126584; row_bytes = ceil(bit_rows/8) = 15823
m1 = 16 + 64 + 32*15823 = 506416;  m2 = 8*32 + ceil(ell/8) = 15887
m3 = 3*32 = 96;                    m4 = 33*164 + 229*64 = 20068
```

`nu` is 228 bytes (the 1,823-bit filtered key), recomputed from the `m1` IV and
required to match. The three nonces are 64 bytes each. FS1-FS3 are recomputed
from the full transcript and are not wire fields. The frame is exactly 544,074
bytes; decoding requires exact lengths, zero reserved bytes, canonical `x` and
`nu`, no trailing data, and the 8 MiB input bound before allocation.

## Other fixed grammars

- **Source signature message:** ASCII `BL/DM/SOURCE-AUTH/v1` (20 bytes) ||
  u64 LE positive key epoch || `x` (1,147 bytes). The signer draws its own
  randomizer from the OS CSPRNG and never accepts one from the caller.
- **Source producer inputs:** 64-byte context, 96-byte `U`, 100 LE u64 values,
  positive key epoch, positive final-retry bound, 4,896-byte ML-DSA-87 secret key.
- **Pipeline:** source CLI reads one `DMSI0001` input (5,876 bytes) and emits a
  548,717-byte `DMSP0001` capsule (key epoch, 4,627-byte signature, DMV3 frame).
  Verifier CLI reads one `DMVI0001` input (551,485 bytes) and writes nothing.
  Exit `0` accepted, `1` cryptographic rejection, `2` malformed, `3` internal.
- **Fixture request:** exactly 180 bytes on stdin: `DMSR0001`, LE `key_epoch=1`,
  LE `max_final_retries=4096`, 64-byte context, nonzero 96-byte `U`. Fixed seed
  `00 01 .. 1f`. Exit `2` malformed (no output), `3` internal.

The prover and verifier targets compile without `FAEST_TESTS` or
`DMN_NATIVE_PROBE`; only the standalone probes use test accessors. The verifier
link-closure gate forbids the source producer and native materializer in the
verifier executable.
