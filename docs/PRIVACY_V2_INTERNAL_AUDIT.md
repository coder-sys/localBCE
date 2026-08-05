# Privacy V2 internal audit

Date: 2026-07-12

Status: historical audit record. It is not a current implementation inventory. The removed RISC
Zero experiment and its measurements are retained here as dated evidence only; current proof and
rejection boundaries are `docs/CURRENT_TECH_STACK.md` and `docs/REJECTED_ARCHITECTURES.md`.

Scope: Privacy V2 Python construction, ordered public-input encoding, Cairo V2 statement, Solidity
V2 settlement, manifest parity, metadata leakage, and prover operations.

This is a parent-agent internal review, not the unavailable multi-worker Codex Deep Security Scan
and not an independent cryptographic audit.

Current planning addendum: every remediation below is internal engineering under
`docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`. The final independent Security Audit Gate reviews the
completed release; live government endpoints, credentials, HSM handles, signers, and accounts are
operator activation inputs.

Current topology addendum: this 2026-07-12 audit predates the sealed Wave 1 relation and the H4
shared-bus Boolean GKR/Construction-8.2 prototype. Its findings remain historical inputs. H4 now
attaches native masks and independent verification for one K128/K512 run; the later Gate 2E context
is sealed, the exact H5 campaign passed, and the bounded H6 candidate-evidence manifest closed all
twelve records without activating production. The production verifier, durable state/custody,
release identity, and final audit remain open. The later frontier addendum adds CBAM, state/
scheduler, adapter-evidence, and public-DA privacy gates; it does not retroactively change this
audit's evidence or close a production finding.

## Audit passes

| Pass | Result |
| --- | --- |
| Statement and commitment binding | Exact 12-field ordering is shared; private data, salts, totals, domain, nonce, and batch commitment affect the settlement commitment. Full adjudication migration remains open. |
| Solidity state and replay | Authorized submitter, domain, nonce replay, live root, governed roots, artifact hash, schema hash, and proof output binding are checked. A real verifier and governance rotation remain open. |
| Encoding and malleability | Noncanonical Stark-field encodings were accepted by the V2 submission boundary; Python and Solidity now reject them. |
| Privacy and inference | Public outputs omit direct amounts/counts/PHI, but proof-backend leakage, batch size, timing, root equality, and root-linkability remain. |
| Secret generation | The builder accepted arbitrary nonzero salts. An OS-CSPRNG generator is now provided; production operations must prohibit manual or reused salts. |
| Operational fail-closed behavior | S-two PHI use remains forbidden, local KMS remains simulation-only, development receipts are disabled in the RISC Zero experiment, and no external proving service is used. |

## Open high-impact findings

1. **No production claim verifier.** The L2 cannot yet authenticate a real V2 proof. The test verifier
   is only a binding mock, and `isTestVerifier()` is self-reported defense in depth, not a trust root.
2. **The full private statement is not migrated.** The RISC Zero qualification proves only the
   12-field commitment envelope, not claim parsing, policy, oracle membership, Merkle paths, or
   sequential nullifier behavior.
3. **Nullifier-root equality leaks information.** Allowing an unchanged root avoids rejecting
   no-op batches but does not hide them. The equality is public and may reveal all-denied behavior.
4. **Batch metadata leaks remain.** Variable proof work, submission timing, batch frequency, and
   public root changes may reveal volume or linkage. Fixed-size scheduling and padding are unbuilt.
5. **Payment state is not constrained.** V2 proves equality of private allowed/payment totals but
   does not prove a payment accumulator or bridge/asset state transition.
6. **Production key custody module is unbuilt.** The current KMS/HSM integration is simulated
   locally only. P11-P12/O01 must internally deliver provider-neutral PQ/hybrid custody ports,
   reference implementations, and conformance tests; live provider enrollment is an activation input.

## Changes made in this run

- Added a pinned, non-development RISC Zero 3.0.5 qualification guest.
- Added a Python-generated Poseidon KAT shared with the guest and host.
- Added OS-CSPRNG V2 salt generation.
- Added Python and Solidity canonical Stark-field checks.
- Corrected the nullifier-root privacy claim in tests and documentation.

No item above authorizes real PHI or production settlement.

## Validation evidence

- Real local RISC Zero 3.0.5 receipt: verified, development mode disabled, 12/12 public fields
  matched the independent Python Poseidon KAT.
- Real receipt proving time: `1472.797364` seconds; local verification: `0.134665` seconds.
- Python: `405 passed`, `0 failed`, plus 8 passing subtests.
- Attack suite: `64 passed`, `0 failed`.
- Solidity: full Forge suite exited successfully.
- RISC Zero model: `4 passed`, `0 failed`.
- Existing Rust rules engine under WSL: `31 passed`, `0 failed`.

The first broad Python run correctly failed because generated proof dependencies were inside the
release tree. The security gate was not weakened. Generated output was removed, the wrapper now
routes builds to a WSL cache outside the release tree, and the complete clean-tree rerun passed.
