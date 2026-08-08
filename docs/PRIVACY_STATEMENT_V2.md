# Privacy Statement V2

The external application statement is exactly the ordered 12-field manifest in `ops/native_stark_public_inputs_v2.json`. All fields are `bytes32`; the count, names, order, encoding, and forbidden-field list are trust-critical.

The proof body and authenticated sidecar are separate. The sidecar binds full-width SHA3-512 authority, proof suite, verifier artifact, schema, program, strong state roots, policy/ruleset roots, source identities, transcript/session identity, and settlement identity.

Approval/denial counts, exact amounts, diagnoses, member identifiers, documents, encrypted payloads, and other PHI are forbidden from public fields, logs, and any future L1 checkpoint. Approval, denial, and padding use a fixed public shape. Every real attempt consumes a nullifier; cover slots consume cover nullifiers.

The native verifier must authenticate the exact statement before one atomic database transaction changes state. A detached verification result, caller-supplied verdict, or database-only policy check cannot authorize payment.

Ordinary provider-app preflight is nonauthoritative and need not generate a proof. The authoritative proof is mandatory at the payment-decision boundary.

The repository is nonactivating and not approved for real PHI.
