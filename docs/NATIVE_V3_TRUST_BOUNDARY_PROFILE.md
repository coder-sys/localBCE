# Native-v3 trust-boundary profile

Status: bounded protocol-boundary evidence only; no proof backend is selected.
Owner: Native-v3 session framing and independent-parser profile. It owns framing and replay
properties, not proof soundness, payment authority, or activation.

The profile in `experiments/native_v3_trust_boundary/` freezes the smallest
session composition that must exist before a private clearance proof can be
considered. It binds the existing synthetic Phase-0 fixture, but it does not
prove the fixture's source membership, policy semantics, hiding, state
transition authorization, or payment clearance.

## Trust-boundary theorem result

Verifier-fresh public coins are useful: a live verifier can sample a challenge
after the prover commitment, so the Fiat-Shamir/QROM transform is not part of
this boundary. That does not establish vector-commitment collapse/binding,
native hiding or simulation, malicious-verifier ZK, semantic/state
composition, authenticated production authority, or abort/retry security.
The profile therefore records `complete_bound_available=false`,
`production_usable=false`, `proofSuiteId=null`, and no activation.

The machine-readable `security_ledger.json` retains the exact DP24
Construction 4.12 / Theorem 4.17 ideal-vector-oracle calculation:

- single epsilon: `0.00000000000000000000000000000000000000003310162687154428085907914929615699976420723788...`;
- 56-instance union epsilon: `0.000000000000000000000000000000000000001853691104806479728108432360584791986795605321651...`;
- corresponding ideal-oracle margins: `134.472149766...` and `128.664794844...` bits.

The ledger leaves these terms unresolved and refuses caller-supplied zeroes:
vector-commitment collapse/binding, salted-leaf hiding, malicious-verifier ZK
composition, semantic/state composition, abort/retry union, and production
challenge authentication.

## Canonical profile

`profile_manifest.json` is generated from the executable profile and includes
the field-by-field byte grammar. All integers are unsigned big-endian. The
fixed statement is 992 bytes and has a null proof-suite marker. Every frame
has `BLTBFRM1`, version, kind, role, round, a nonzero 32-byte session ID, a
64-byte domain tag, a u32 payload length, and exactly that payload.

The two vector leaves are ordered indices 0 and 1. Each leaf includes a u32
index, length-delimited value, and exactly 32 hidden salt bytes. The internal
node includes height 0, left index 0, and ordered left/right 64-byte child
hashes. A commitment binds the statement digest, vector root, and handle;
the handle is domain-separated over session ID, statement digest, and root.
The one-sibling opening must use the verifier-selected index.

The statement binds the verifier-owned profile, Phase-0 statement digest,
source root, automatic control-set identity/order/conflict policy/scope and
interval, exact decision/access join, frozen receipt, completeness evidence,
chronology, replay identity, exception ID or nonzero sentinel, and exact
before/after state IDs. It fixes the five Phase-0 directive vocabulary at the
boundary without treating verifier acceptance as `CLEAR`.

## Session state machine

1. The prover obtains a fresh session ID and fresh leaf salts from the OS
   CSPRNG, builds the fixed two-leaf commitment, and sends the commitment.
2. The verifier independently parses the statement and commitment, checks all
   verifier-owned bindings, samples a fresh nonce/scalar after that
   commitment, derives the selected index, and authenticates the challenge.
   The current tag is fixture-only HMAC-SHA3-512, not a production PQ
   signature or authorization proof.
3. The prover parses only a verifier-role challenge bound to its commitment,
   creates one ordered opening and a fresh response nonce, and emits the
   transcript.
4. The independent verifier reparses every record, checks frame roles/rounds,
   exact transcript order and digest, challenge authentication, commitment/
   response bindings, opening root, and a create-once acceptance marker.

Persistent create-once markers reject duplicate sessions, challenge replay,
accepted-transcript replay, reused random material, abort/retry grinding, and
retry counts beyond the fixed cap. Corruption, truncation, role/round/domain
mutation, wrong root/index/salt/opening, and statement or transcript mutation
fail closed.

The Rust verifier is intentionally independent: it parses the directory's
public session files and verifier key but never reads `prover_state.bin`. Its
hard-coded expected binding IDs are duplicated only as a cross-language
fixture check; they do not constitute a cryptographic reduction.

## Scope and nonclaims

The directory output is scratch-only synthetic evidence. It contains no real
PHI or payments and cannot authorize a state write or money movement. No
Merkle/BCS theorem, ZK theorem, hiding claim, PQ signature claim, complete
false-acceptance bound, production resource qualification, activation, or
proof-suite selection follows from this profile.
