# Pinned S-two allocator-safety patch

## Provenance

- Upstream: `https://github.com/starkware-libs/stwo`
- Exact source commit: `aeceb74c58184d7886ebd7f34a7453fee714ca40`
- Exact source tree: `debdb3804a656654016896c4d292293fe07ccff3`
- Archived source SHA-256: `AF979C0BA6F6D1F1BCFDF4AB8D6B444E83F65FC2C6471BF404CCE5B063C329E6`
- Vendored tracked files before patch: 249
- Vendored license SHA-256: `6FC3AE0CC00EEAC4C08B33D060CE3725438DCDE152DC571E08F3D8E6F86B3B8F`

The archive was produced locally with `git archive` from the already-cached exact commit. The
vendored tree is used through local Cargo paths so the safety change never mutates or depends on a
developer's Cargo cache.

## Defect

`BaseColumn::into_cpu_vec` reconstructed a `Vec<BaseField>` from the allocation owned by a
`Vec<PackedBaseField>`. On the pinned x86-64 toolchain, `PackedBaseField` is 64-byte aligned and
`BaseField` is 4-byte aligned. `Vec::from_raw_parts` requires the allocation and deallocation
layouts to have the same alignment. Windows therefore received an interior aligned pointer when
the vector was dropped and terminated the process with `0xC0000374` (`STATUS_HEAP_CORRUPTION`).

The 16-row AIR tests reliably reached the defect through S-two's small-column prefix-sum path.
Using 64 or more rows merely bypassed the unsafe path and was rejected as a workaround.

## Patch boundary

The sole production-code change in the vendored dependency is:

```rust
pub fn into_cpu_vec(self) -> Vec<BaseField> {
    self.as_slice().to_vec()
}
```

This makes a correctly aligned CPU vector and lets the packed vector deallocate with its original
layout. It changes neither field values, AIR constraints, transcript data, public inputs, nor the
12-field Privacy V2 external ABI. The copy is limited to the under-64-element slow path.

A package-level integration regression calls the patched public method, checks every converted
value, and exercises destruction of the returned vector. Keeping this regression outside the
vendored workspace avoids introducing S-two's uncached dev-only dependencies. The custom AIR
proof/verification and negative tests remain the semantic gate.

## Trust status

This is a local reviewed patch, not an upstream release or independent audit. It may support Phase
1 experimental evidence only. Production qualification still requires independent review,
upstream disclosure, the complete Blind Ledger AIR, witness hiding, post-quantum transcript and
commitment parameters, and the production verifier.
