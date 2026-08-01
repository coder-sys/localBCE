# BL-PQ512 cryptographic foundation references

Current Wave 2 role: these are scalar/differential inputs to the shared-bus Boolean hash
coprocessor contract in `../../docs/BL_PQ512_HETEROGENEOUS_HASH_COPROCESSOR.md`; they are not a
monolithic direct-SHA3-STARK release design.

These modules make the current S09 algebra, theorem-interface parameter work, Circle-FRI substrate,
public-coin construction, PQ authentication, retry governance, hiding worksheet, and proof framing
testable without pretending that a proof suite exists.

- `field16_reference.py` implements the pinned M31 degree-16 tower, canonical 64-byte encoding,
  arithmetic, inversion, exact irreducibility checks, and unbiased SHA3-512 rejection sampling.
- `public_coin_reference.py` implements an immutable typed round schedule, PQ-signature verifier
  ports, commit/reveal challenge generation, exact theorem-message ordering, unbiased query
  sampling, and append-only audit evidence.
- `oods_reference.py` implements authenticated-attempt Fp8-excluding OODS sampling and the exact
  stereographic circle map.
- `circle_fri_reference.py` implements scalar Circle-FRI folds, conjugate-pair degree correction,
  mandatory independent per-domain batch masks, globally unique batching powers across variable-
  width domains, and gap-complete fold-with-insertion.
- `cross_domain_pcs_reference.py` implements typed SHA3-512 projection-consistent trees for mixed
  Circle domains, including the FRI batch-mask commitment fixed before its batching challenge.
- `unique_decoding_parameters.py` derives an exact six-candidate interface-level rate/query sweep
  from the frozen 16-table dimensions without selecting a final candidate.
- `native_hiding_parameters.py` applies the conservative trace-mask degree bound to every physical
  table, derives the exact metadata-only 16-table FRI domain/power/mask/fold schedule, and records
  every remaining simulator/final-expansion gate.
- `circle_hiding_simulator.py` constructs the direct Circle trace-evaluation map for multiple
  degree-16 extension points and base-domain queries by exact polynomial CRT. It covers the OODS
  point and its base-domain transition translate.
- `circle_quotient_masking.py` implements the canonical two-component quotient kernel mask,
  freezes the source-aligned repeated-doubling split-factor rule, and constructs the conditional
  quotient-mask distribution. The final split log-degree and prover integration remain AIR-derived.
- `sha3_512_air_reference.py` implements the byte-oriented SHA3-512/Keccak-f[1600] round witness,
  exact FIPS padding, a 1,632-column/1,024-lookup round core, and the full 1,704-column/1,096-first-
  round-lookup sponge envelope.
- `application_sha3_port_inventory.py` independently enumerates both governed source trees and
  AST-locks 79/79 SHA3 callsites: 39 `AIR_REQUIRED`, five public-precomputed, 21 host-evidence-only,
  11 Wave-1C verifier-state, and three superseded-reference sites. H0 dynamically remeasured all five
  post-R36 additions, including a separate exact 238-byte cover-v2 helper observation and the four
  K128 physical-trace payment-key observations.
  The current inventory identity is
  `618c06447efc67bca80ca9bb4c59a89970e7c42a26ea6a45a298c8dc8e1e8b2643f3c51a923d1b89ebb6a2311dc22edfffeea70471a9f97c5378b8a43fb607c2`.
  New governed files plus alias, attribute, `hashlib.new`, dynamic-import, and dynamic-`getattr` forms
  fail closed. The old `51*K` rerun remains superseded audit evidence only; current K128 bus mapping
  and resource evidence remain open.
- `application_sha3_shared_schedule.py` proves the fixed dense-tree topology for claim/oracle trees
  across K128/K256/K512. The claim tree hashes every node once; the oracle lane hashes one exact
  2,133-byte bundle per claim and one ordered execution root while its audit tree reuses the leaf
  digests outside the proof. The reversible compact claim source plus packed oracle costs
  14,322/28,644/57,288 permutations and 343,728/687,456/1,374,912 round rows. Non-dense application ports and lookup-interaction packing
  remain open and activation remains false.
- `pq_signature_adapters.py` wraps the exact locked `pqcrypto==0.4.0` ML-DSA-87 and
  SPHINCS+-SHAKE-256f-simple implementations with strict key/signature sizes and fail-closed errors.
- `public_coin_governance.py` binds an immutable epoch and statement, burns at most four attempt
  ordinals before use, quarantines missing revealers, forbids same-epoch re-enrollment, requires both
  PQ suites on every retry, and chains local audit evidence with SHA3-512.
- `proof_body_reference.py` provides an out-of-band-identity-bound `BLPQPF01` reference grammar,
  exact 88-byte header preflight, bounded header-first stream reading, fixed ordered sections, and
  strict malformed/trailing-byte rejection.
- `c0_control_fixture.py` freezes the synthetic Gate 2E-0 C0 state/payment/access control and its
  exact K128/K512 manifest identities. `c0_control_measurement.py` measures the state-only and
  complete boundaries in a fresh Windows process with explicit RSS, scratch, pagefile, and I/O
  fields; it is reference evidence, not a production proof path.
- `state_interface.py` freezes the 13 Gate 2E-1/S1 replaceable state-plane descriptors, the bounded
  `BLSI` envelope, the `BLTR` old/new transition grammar, and a SHA3-512 public identifier port.
  It intentionally has no claim, payment, settlement, or proof implementation dependency.
- `scalar_state_relation_controls.py` implements the Gate 2E-2/S2 synthetic scalar controls:
  C1 dense and touched-sparse persistent memory, C2 transparent index/value dictionary, C3
  touched-projection RAM, and C4 compact shuffle-based memory consistency.  Each control has a
  deterministic bounded witness, candidate-specific derived work counters, and an independent
  replay verifier.  `scalar_state_relation_parity.py` compares the fixed semantic/shape/money
  boundary to C0 and exercises all seven C0 negative classes for both K128 and K512.  Candidate
  roots remain differential identities; no candidate is selected or bound to H4.

The sibling `experiments/bl_pq512_crypto_core/` crate is a `no_std` Rust mirror for the frozen Fp16
tower, OODS and conjugate-pair algebra, scalar Circle-FRI, typed SHA3-512 mixed-domain trees, the
K512/beta-1 interface schedule commitment, the cross-language direct-evaluation certificate,
canonical quotient split/mask KATs, and an independent SHA3-512 permutation/shape KAT.

These are internal/nonactivating modules. The PQ adapters exercise real standardized algorithms but
are software-only reference evidence, not HSM custody, FIPS-module validation, side-channel
qualification, or production approval. The reference OODS path now rejects the embedded Fp8
subfield, and theorem-scheduled sessions reject a generic or reordered prover message before the
challenge-service commitment phase. No module here implements the final optimized fixed-capacity
hash schedule and interaction packing, complete native-hiding simulator, durable challenge-service orchestration, or production proof
prover/verifier, and none can assign `proofSuiteId`, enable activation, or authorize real data. The
normative construction and remaining gates are in
`docs/BL_PQ512_S09_INTERNAL_SOLUTION.md`.
