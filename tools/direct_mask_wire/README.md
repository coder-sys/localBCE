# Direct-mask DMV1 wire boundary

This directory contains a non-activating, degree-three direct-mask wire adapter.  It delegates
the proof body to the separately pinned primitive engine and delegates relation arithmetic to the
local direct-mask kernel.  The code is an integration candidate only; it is not a production
FAEST implementation and carries no constant-time, privacy, or security qualification.

## Canonical frame

The frame is exactly:

```
DMV1 header || x || nu || sigma1 || sigma2 || sigma3 || m1 || m2 || m3 || m4
```

The header is 40 bytes:

| Offset | Bytes | Encoding |
|---:|---:|---|
| 0 | 4 | ASCII `DMV1` |
| 4 | 1 | version `1` |
| 5 | 3 | reserved zero bytes |
| 8 | 4 | witness-bit count, little-endian `125048` |
| 12 | 4 | constraint count, little-endian `172232` |
| 16 | 1 | relation degree `3` |
| 17 | 3 | reserved zero bytes |
| 20 | 4 | `x` length, little-endian `1147` |
| 24 | 4 | `m1` length, little-endian `506416` |
| 28 | 4 | `m2` length, little-endian `15887` |
| 32 | 4 | `m3` length, little-endian `96` |
| 36 | 4 | `m4` length, little-endian `10496` |

`x` is canonical and has no host structure padding:

```
source_suite[16] || relation_id_bytes:u32le || relation_id[23] || context[64] ||
U[96] || T[96] || C[800] ||
field_bits:u32le || degree:u32le || tau:u32le || w_grind:u32le ||
short_challenge_bits:u32le || open_budget:u32le || witness_bits:u32le ||
constraints:u32le || padding_bits:u32le || mask_count:u32le ||
nonce_bits:u32le || challenge_mode:u32le
```

For this profile the relation id is `direct-mask-relation-v1`, the source suite is
`SBA1-SRC-CMT-v1` followed by one zero byte, and the descriptor is fixed to
`field_bits=256`, `degree=3`, `tau=33`, `w_grind=8`, `short_challenge_bits=64`,
`open_budget=229`, `mask_count=6`, `nonce_bits=512`, `challenge_mode=1`, with zero padding bits.

The payload sizes are derived rather than accepted from an untrusted header:

```
ell       = 125048
bit_rows  = ell + 6*256 = 126584
row_bytes = ceil(bit_rows/8) = 15823
m1        = 16 + 64 + (33-1)*15823 = 506416
m2        = 8*32 + ceil(ell/8)      = 15887
m3        = 3*32                    = 96
m4        = 33*(3*256/8) + 229*32   = 10496
```

The explicit `nu` is 96 bytes (`3*256/8`) and is retained for wire compatibility.  It is
recomputed from the `m1` IV and must match during decode and verification.  The three nonces are
64 bytes each.  No FS challenge is a wire field: FS1, FS2, and FS3 are recomputed from the full
canonical transcript, including all of `x`, `nu`, prior records, and the corresponding nonces.

The resulting frame is 534370 bytes.  Decoding requires the exact frame length, exact component
lengths, zero reserved bytes, canonical `x`, canonical `nu`, and no trailing data.  The adapter
also enforces the 8 MiB bounded-input limit before allocating payloads.

## Verification and process checks

`direct_mask_wire_prover` is a source-bound process fixture: it builds one native witness from the
immutable materializer imported under `tools/direct_mask_native`, proves it with bounded final
grinding, and writes only the canonical statement and frame.  It is compiled without
`FAEST_TESTS`, `DMN_NATIVE_PROBE`, or any verifier-only native accessor.  The separate
`direct_mask_wire_verifier` links only the wire adapter, receives the expected statement
independently from the frame, and never receives a witness.

`direct_mask_wire_probe` remains the in-process test probe.  It builds one source-bound native
witness, round-trips the canonical frame, verifies it, and checks expected-context, explicit-`nu`,
body-mutation, lifecycle, and alias rejection.  Its output distinguishes fixture construction,
exact kernel counts, wire status, and proof verification.

`direct_mask_driver` runs a requested child in a bounded process/job-tree envelope, captures and
discards child output, and reports exit status, output limits, wall time, CPU time, and memory
accounting.  It does not itself claim proof acceptance or production readiness.

The `dm_faest_public`, `direct_mask_wire`, `dm_native_fixture`, and `direct_mask_wire_prover`
targets intentionally compile without `FAEST_TESTS` or `DMN_NATIVE_PROBE`.  Only the standalone
`direct_mask_wire_probe` target uses `FAEST_TESTS`; the probe-only native accessor is not part of
the prover or verifier targets.
