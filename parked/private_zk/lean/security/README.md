# Security arithmetic kernel

This project is the narrow Lean owner for the finite arithmetic consumed by
`tools/direct_mask_contract/calculator_v2.py`. It does not model cryptographic
reductions, primitive security, source custody, randomness, transport, durable
state, payment, PHI, activation, or product selection. Those remain named
external premises at the certificate boundary.

The project is pinned to `leanprover/lean4:v4.33.1` and has no Lake packages.
`BlindLedger.Arithmetic` defines exact natural-number formulas and
`ExactFrac`, whose numerator is an `Int`, whose denominator is a positive
`Nat`, and whose comparisons cross-multiply in the kernel. `BlindLedger.Theorems`
contains the checked cap, completion-accounting, monotonicity, remaining-budget,
QROM, width-partition, direct-constant, and certificate-row terms.

`blind_security_arithmetic_v2` is the current deterministic executable. Its
header is `BL-SECURITY-ARITHMETIC/2`, its schema is `BLSECAR02/v2`, and its
build ID is `BL-SECURITY-ARITHMETIC-20260922-V2`. The v2 `THEOREMS` record
emits the count and the canonical comma-separated theorem-name sequence; the
adapter requires the exact 32-name inventory shared with the trust-0 axiom
checker. V1 headers and v1 receipt bytes are rejected by the v2 adapter.

The v1 executable at
`formal/lean/.lake/build/bin/blind_security_arithmetic.exe`, its receipt at
`formal/lean/artifact_receipt.json`, and the earlier v1 evidence remain
historical. V2 uses the separate clean build directory
`formal/lean/.lake/build-v2`, its executable at
`formal/lean/.lake/build-v2/bin/blind_security_arithmetic_v2.exe`, and the
receipt at `formal/lean/artifact_receipt.v2.json`.
The v2 receipt is created only after the guarded build and `--trust=0` source
check succeed; it binds the exact theorem-name sequence, source/toolchain,
binary, and current shared guard identity.

The executable has three modes:

- `cap` emits the complete cap batch, both current384/current512 width rows,
  exact constants, QROM/probe arithmetic, privacy-budget arithmetic, and the
  theorem-term receipt.
- `runtime` accepts the 24 natural counters and five required precondition
  flags. It emits a result only for `Counters.WellFormed`; malformed or
  over-cap input emits `REJECT`.
- `row <j>` emits the exact certificate row arithmetic for a natural `j`.

The Python adapter never builds or substitutes for Lean during normal
calculation. It rejects a missing, stale, wrong-toolchain, malformed,
nonzero-exit, or theorem-receipt-mismatched executable. Build and checker
evidence must use the existing shared guarded runner with the required mutex,
physical-memory reserve, live process-tree cap, exit probes, and cleanup.

The executable is intentionally not a proof-suite or activation artifact:
`proofSuiteId=null`, `production_usable=false`, and activation/selection remain
false in the surrounding contract.
