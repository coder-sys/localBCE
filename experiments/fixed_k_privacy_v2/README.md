# Fixed-K Privacy V2 synthetic reference

Status: structural test reference only. It is not a proof, AIR, verifier, production sidecar, or
governed fixed-K profile. It must never process real PHI or advance settlement state.

Current role: structural shape oracle for the heterogeneous proof in
`../../docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`. The shared bus and Boolean SHA3
coprocessor must preserve this fixed-shape boundary; this reference itself supplies neither module.

`reference.py` makes the already-selected shape rules executable without choosing the unresolved
protocol parameters. A caller supplies a reviewed K, profile digest, fresh synthetic salt, and
already-derived legacy and 512-bit nullifiers. The reference then enforces exactly K fixed-width
private slots, explicit committed real/cover kinds, inert cover payloads and amounts, unique
nonzero nullifiers for every slot, and the unchanged ordered 12-field external ABI. Its synthetic
reference commitment binds the complete ordered 12-field statement as well as every private slot.

It is guarded by all three of:

- `BL_ENV` equal to `local`, `test`, `unit`, or `ci`;
- `BL_DEV=1`;
- `BL_ALLOW_SYNTHETIC_FIXED_K_REFERENCE=1`.

The guard is rechecked at construction, private serialization, commitment, and verification time;
an object created under test flags cannot later be used after those flags are removed. The caller
must separately prove the entropy and non-reuse of the supplied synthetic salt: this stateless
reference checks only its exact width and that it is nonzero.

The reference does not close A01, A04, A05, A12, A13, A15, or A16. In particular, it does not:

- govern or authenticate K;
- derive cover nullifiers or prove legacy/strong same-preimage equivalence;
- choose production domain tags, encodings, tree rules, or collision handling;
- insert nullifiers into either authoritative tree;
- constrain slot semantics in the sealed M31 semantic AIR or shared-bus hash coprocessor;
- fix the variable service-line, diagnosis, policy-row, authorization, or path capacities inside a
  real claim witness;
- authenticate the reference commitment through a production proof transcript; or
- provide witness hiding or strict post-quantum proof-system security.

Those decisions remain blocked by the open specification and cryptographic-review gates in
`docs/IMPLEMENTATION_ROADMAP.md` and `docs/PQ_ZK_SECURITY_ARCHITECTURE.md`.
