# Blind Ledger

Blind Ledger is RightRail's state-side payment-clearance system. It determines whether an already
proposed payment may proceed under selected deterministic state rules; it does not adjudicate the
entire claim or move money.

When undisclosed evidence crosses the clearance trust boundary and affects automation, the pinned
native verifier must accept the private proof before the database applies the corresponding state
transition atomically. Signed government and oracle records provide authenticated inputs. The proof
binds the underlying policy result, one of `CLEAR`, `HOLD`, `HUMAN_REVIEW`, `BLOCK`, or
`EXCEPTION_APPROVED`, governed exception authority, source, replay protection, value conservation,
and the clearance commitment. Proof acceptance alone never means `CLEAR`; the existing state
payment system remains the money mover.

This repository is a production-shaped, integration-ready candidate. Productionization is bounded
qualification and adapter substitution, not a semantic rewrite; current qualification status and
nonactivation gates are authoritative in `STATE.md` and `CURRENT_TASK.md`.

The approved target uses a small executable Lean kernel for clearance semantics, canonical semantic
decoding, and legal state transitions. Rust remains the native cryptographic verifier and database
integration shell. The Lean kernel is a deferred production plug-in behind the fixed semantics.

The first commercial wedge is read-only provider credential and enrollment continuity through the
Mirror/Provider Trust Graph and observation-only Governance seams. It can adopt authenticated source
adapters and a qualified operational store independently of the private-payment ZK backend; the
private clearance path still requires Lean, theorem-qualified ZK, and database/custody qualification.

Start with:

- `docs/DATABASE_ZK_ARCHITECTURE.md` for the system boundary.
- `docs/NATIVE_V3_ARCHITECTURE.md` for the active proof, state, security, privacy, and CPU contract.
- `docs/LEAN_FORMAL_KERNEL.md` for the formal semantic kernel, theorem gates, and Rust/database boundary.
- `docs/CURRENT_TECH_STACK.md` for implemented components.
- `docs/IMPLEMENTATION_ROADMAP.md` for the native-v3 critical path.
- `CURRENT_TASK.md` for the current bounded implementation phase in the full workspace.
- `QUICKSTART.md` for local verification.

The old Privacy V2, BL-PQ512/H4/CUDA, binary-field K128, Binius64, and decisive-composition
prose has been retired. Compatibility filenames remain only where regression code still requires
them; Git history and retained archives preserve the former bytes.

Published source archives may omit workspace-only continuation records; use the current documents
and `RELEASE_FILE_MANIFEST.json` when working from an archive.

No L2 is part of the design. Ethereum remains an optional later checkpoint adapter and is not an
automatic dependency of the read-only wedge.
