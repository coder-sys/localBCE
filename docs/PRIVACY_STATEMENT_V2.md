# Privacy Statement V2

Updated: 2026-07-22

Status: selected 12-field external privacy boundary; not yet the active production statement. The
authoritative strict post-quantum verifier context is wider than these 12 values.

The containing rollup architecture is defined in `docs/BASED_ZK_ROLLUP_ARCHITECTURE.md`.
The selected claim-proof security profile is defined in `docs/PQ_ZK_SECURITY_ARCHITECTURE.md`.
The exact nonactivatable S07-S12 candidate context is
`docs/BL_PQ512_S07_S12_PREIMPLEMENTATION_FREEZE.md`.
The internal-build, final-audit, and operator-activation boundary is
`docs/DEPLOYMENT_READY_BUILD_CONTRACT.md`.
The current physical proof topology is
`docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`.
The cross-wave frontier contract is `docs/FRONTIER_THROUGHPUT_AND_ETHEREUM_ALIGNMENT.md`; its CBAM,
evidence capsules, scheduler, DA, and Ethereum adapters inherit every privacy prohibition here.
`docs/ETHEREUM_STRAWMAP_BASED_ROLLUP_COMPATIBILITY.md` makes the outer-chain privacy boundary
explicit: wormholes, LUCID/encrypted mempools, ephemeral keys, private ETH, privacy pools, and
zkzk frames are research or compatibility surfaces. None authorizes PHI, claim documents, exact
private amounts, decision metadata, or witnesses in public calldata, blobs, logs, tickets, or
ciphertext envelopes.

## Proof-backend blocker

Removing private values from public outputs is necessary but not sufficient. Starknet's S-two
documentation states that current S-two does not provide the zero-knowledge feature and exposes
unmasked commitments to witness values. Therefore, the current S-two proof path is validity-only for
this threat model and must not process real PHI.

The production target is now a heterogeneous proof: the sealed M31 fixed-shape semantic AIR binds
through one hiding committed bus to a masked Fp16 Boolean GKR SHA3 coprocessor. Both modules share
one PQ-authenticated interactive public-coin session and are accepted atomically. RISC Zero 3.0.5,
Cairo, direct SHA3 AIR, and upstream S-two remain semantic, differential, or validity controls; none
is the selected complete production path. No current backend is production-approved.

Reference: https://docs.starknet.io/learn/S-two-book/why-stwo

Decision record: `docs/ZK_BACKEND_DECISION.md`

## Privacy objective

No patient, member, provider-document, claim, decision, or payment amount data may be recoverable
from public chain data, proof artifacts, prover queues, logs, crash files, or public data-availability
payloads. Authorized government auditors retain selective access through government-controlled
encrypted storage.

## Public boundary

The future public statement is limited to opaque commitments, governed roots, nullifier state,
accumulator state, and a value-conservation commitment. Exact approved amounts, payment amounts,
claim counts, approval counts, denial counts, and encrypted medical-record bytes are forbidden from
the public statement and settlement events.

`ops/native_stark_public_inputs_v2.json` is the exact 12-field external application ABI implemented
by `batch_main_v2` and `StarkBatchSettlementV2`. Preserving it means preserving its field count,
order, names, types, and forbidden-field boundary. It does not require old denied-case KAT values to
remain unchanged, and it does not make twelve Stark-field values the entire strict post-quantum
security context.

`BL-PQ512-v1` adds canonical authenticated proof metadata and verifier-maintained SHA3-512 state:
strong nullifier roots before and after, strong payment-state roots before and after, a governed-root
registry commitment, a master batch commitment, full-width settlement domain, profile, suite,
schema, verifier artifact, epoch, and sequence. These values travel in a separate authenticated
744-byte sidecar and verifier state, not inside the proof body and not as added fields in the
external `Submission`. The internal verifier interface and storage must therefore change.

Legacy Poseidon roots and wide roots must be derived independently from the same raw canonical
records and constrained to the same ordered operations. Hashing an existing felt root with SHA3-512
does not improve its binding strength. The wide nullifier root and wide master batch commitment are
authoritative for replay and deduplication; legacy fields remain compatibility values.

The current ABI is parallel to V1 and must not be represented as deployed, independently audited,
or accepted by a production verifier. Exact amount and count fields are replaced by salted opaque
and value-conservation commitments.

Production package builders must obtain fresh, distinct salts from
`app.privacy_v2.generate_privacy_v2_salts()`. Entropy cannot be proven from a field value alone, so
operator controls must prevent caller-chosen or reused salts.

Accumulator/payment-state roots remain deliberately absent from the 12-field ABI. The candidate
sidecar carries composite full-width before/after roots outside that ABI, but they cannot become
authoritative until the proof relation implements and verifies their exact transition.

## Private data boundary

Raw claims and proving witnesses remain encrypted at rest with a fresh AES-256-GCM data key for each
package. The data key is currently wrapped to an RSA-3072-or-stronger public key. The target private
unwrap operation uses the internally built provider-neutral KMS/HSM port; live provider coordinates
and authorized key handles are operator activation inputs. The application never persists that
private key. Plaintext witness packages are rejected when `BL_ENV` is `prod` or `production`.

RSA-3072 is classical and is not an end-to-end post-quantum key-wrapping solution. Production must
replace or explicitly hybridize it with a pinned, approved post-quantum KEM and complete the same
inventory for oracle, governance, attestation, transport, backup, and recovery keys. The system must
not claim end-to-end post-quantum security while RSA or Ed25519 remains an authoritative surface.

Plaintext may exist only inside the isolated proving worker for the minimum time required to execute
the proof. The local simulator now exercises separate-process key custody, authenticated unwrap,
pipe transport, and WSL RAM-backed argument staging. The simulator is forbidden in production;
the release must internally provide a qualified PQ/hybrid KMS/HSM module and conformance suite,
then receive live provider configuration and final independent operational review.

## Public data availability

Public calldata and blobs must contain commitments and proofs only. Raw PHI and permanently
decryptable medical-record ciphertext are not public data-availability payloads. Encrypted claim
records remain in government-controlled storage with retention, legal hold, key rotation, and
crypto-erasure controls; Ethereum stores only their commitment.

## Release gates

1. The protected Cairo public statement and settlement contract must be redesigned in a separate
   experimental version and reviewed independently.
2. Differential known-answer tests must prove that V2 preserves every adjudication, nullifier,
   policy, oracle, payment-conservation, and accumulator rule.
3. One-claim and small-batch inference tests must show that public data reveals neither decision nor
   amount. Every real claim, approved or denied, must consume a canonical attempt nullifier. Every
   fixed padding slot must consume a domain-separated cover nullifier. Approval, denial, and padding
   must use the same trace, proof, and state-operation shape.
4. Artifact scans must find no plaintext witness, EDI, member identifiers, diagnoses, or prior
   authorization values.
5. The KMS/HSM integration, worker isolation, logging, crash recovery, backup, retention, and
   destruction behavior require independent security and privacy review.
6. The claim verifier must authenticate the exact V2 statement inside the L2, and the rollup proof
   must authenticate that L2 state transition to Ethereum L1.
7. Based sequencing, public-state reconstruction, forced inclusion, exits, bridge custody, and
   protocol upgrades must pass adversarial and independent review.
8. The production proof backend must provide independently audited zero-knowledge witness hiding;
   output commitments alone do not satisfy the privacy objective.
9. The PCS/Merkle/FRI commitments, Fiat-Shamir transcript, verifier/schema/profile identity, state
   anchors, signatures, KEMs, and multi-target analysis must meet the declared post-quantum profile
   before any strict or end-to-end post-quantum claim.
