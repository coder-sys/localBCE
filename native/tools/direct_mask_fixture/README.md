# Direct-mask public-request fixture

This directory contains a test-only, nonactivating source appliance for the
accepted direct-mask pipeline boundary. It is not a production interface and
does not authorize payment, clearance, deployment, or proof-suite promotion.

## Request contract

`direct_mask_fixture_source` accepts no command-line arguments and reads one
exact 180-byte binary request from standard input, followed by EOF:

- bytes `0..7`: `DMSR0001`
- bytes `8..15`: little-endian `key_epoch = 1`
- bytes `16..19`: little-endian `max_final_retries = 4096`
- bytes `20..83`: caller context; all-zero context is allowed
- bytes `84..179`: nonzero `U`

Malformed input exits with status `2` and produces no output. Internal setup or
I/O failure exits with status `3`. A valid request constructs the existing
`DMSI0001` source-input layout, derives the fixed-seed ML-DSA keypair, checks
the derived public key against `fixture_public_key.h`, and then calls the
existing source producer exactly once. An accepted capsule is the existing
548717-byte binary capsule on standard output.

The fixed seed is `00 01 ... 1f`; witness values alternate between little-
endian `0x1122334455667788` and `0xddeeff0011223344`. Secret material and
fixture buffers are cleared on every appliance exit path.

## Verification boundary

The guarded fixture build verifies eight pinned static-library identities and
builds the appliance, key exporter, and cheap probe. The previously attempted
auxiliary process-based `direct_mask_fixture_cli_test` is intentionally
unregistered and rejected; its source, binary, and logs remain preserved as
rejected evidence. Its historical `cases=12 failures=0 skipped=1` output
carries no skip or cleanup qualification. The earlier r6-r9 guarded builds
invoked four fixture targets, although only the CLI test source recompiled;
those records do not change that disposition. All ten actual malformed-input
checks belong to Queue's caller over the existing product Job Object runner
and remain pending in the product contained-runner source-boundary tests; no
synthetic skip or cleanup credit is carried forward. The authorized fixture
CTest registration retains only the parser/encoding/key-binding probe. It
deliberately does not submit a valid request to the real producer; therefore
this fixture phase provides no positive proof result or production
qualification.

The internal guarded build tree and logs belong under `build-fixture/` and are
not source artifacts.
