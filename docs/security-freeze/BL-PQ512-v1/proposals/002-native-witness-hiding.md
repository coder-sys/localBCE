# BLH-002: complete native witness hiding

Priority: critical

Status: construction plan; not a privacy claim.

Current disposition: this gate now covers both modules and their bridge. The exact implementation
contract is `docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`; an unmasked bus, GKR/sumcheck
message, terminal evaluation, or cross-module reduction fails the entire privacy claim.

## Problem

The current custom AIR commits unmasked witness-derived columns. Fixed public outputs and salts do
not make that transcript zero knowledge. A single unmasked trace, quotient, lookup, DEEP, or FRI
oracle defeats the confidentiality claim.

## Proposal

Mask every private semantic trace polynomial as `w + Z_H*r`, randomize all quotient components, and
commit an independent FRI batch mask before the batching challenge. Separately mask the shared-bus
PCS and every Boolean-GKR/sumcheck message and terminal evaluation. Inventory every explicit and
implicit opening, bridge reduction, neighbor row, extension conjugate, denominator/abort case,
decomposition piece, and repeated proof. Draw fresh domain-separated randomness from an OS CSPRNG,
prevent caller control or reuse, and destroy it after proving.

The fixed-shape claim schedule must give approval, every denial, and every cover slot identical
dimensions, state-operation counts, proof framing, and failure behavior. Host isolation and constant-
time evidence remain separate operational gates.

## Acceptance evidence

- Circle-STARK-specific interactive simulator and statistical-distance ledger;
- complete authenticated-interactive-public-coin composition argument, including retries and aborts;
- static oracle-coverage gate proving that no committed private oracle is unmasked;
- mask-reuse, deterministic-RNG, abort, crash, cancellation, and zeroization attacks;
- repeated-proof unlinkability and fixed-proof-shape campaign;
- proof-artifact and log scans; and
- independent witness-hiding, FRI, side-channel, and implementation review.
