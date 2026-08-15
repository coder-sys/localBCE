from __future__ import annotations

from hashlib import sha3_512
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "experiments" / "bl_pq512_crypto_core"
PACKAGE_SOURCE = CORE / "src" / "h4_proof_package_v1.rs"
LIB_SOURCE = CORE / "src" / "lib.rs"
SCHEDULE_SOURCE = CORE / "src" / "fp16_relay_free_gkr_schedule.rs"
UNIFORM_GKR_SOURCE = CORE / "src" / "fp16_relay_free_gkr_uniform.rs"
STATE_RELATION_SOURCE = CORE / "src" / "state_relation_gkr.rs"
STATE_SQUAREFREE_SOURCE = CORE / "src" / "state_squarefree_gkr.rs"
INTERLEAVED_VERIFIER = CORE / "src" / "bin" / "fp16_zk_rs_interleaved_verify.rs"
SPOTCHECK_VERIFIER = CORE / "src" / "bin" / "fp16_zk_rs_spotcheck_verify.rs"
ANSWER_CODE_VERIFIER = CORE / "src" / "bin" / "fp16_zk_rs_answer_code_verify.rs"
ANSWER_TARGET_VERIFIER = CORE / "src" / "bin" / "fp16_zk_rs_answer_target.rs"
PUBLIC_COIN_BRIDGE = CORE / "src" / "bin" / "fp16_zk_rs_public_coin_bridge.rs"
THEOREM_PROVER = CORE / "cuda" / "cuda_fp16_zk_rs_theorem8_1_k128_prototype.py"
INTERLEAVED_PROVER = CORE / "cuda" / "cuda_fp16_zk_rs_interleaved_k128_prototype.py"


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _claim_record(root: bytes, capacity: int, points_and_values: bytes) -> bytes:
    assert len(root) == 64
    digest = sha3_512(
        b"BL/PQ512/WAVE2/STATE-SQUAREFREE-CLAIMS/v2\0"
        + root
        + capacity.to_bytes(2, "big")
        + (2).to_bytes(2, "big")
        + points_and_values
    ).digest()
    return b"BLSQCL02" + root + capacity.to_bytes(2, "big") + (2).to_bytes(2, "big") + digest


def test_fixed_container_and_null_suite_are_source_enforced() -> None:
    source = _source(PACKAGE_SOURCE)
    assert "pub const H4_PROOF_PACKAGE_V1_BYTES: usize = 192 << 20;" in source
    assert 'pub const H4_AGGREGATE_PACKAGE_V1_MAGIC: &[u8; 8] = b"BLH4AG01";' in source
    assert "const NULL_PROOF_SUITE_ID: [u8; 64] = [0_u8; 64];" in source
    assert "H4_DURABLE_MAX_ATTEMPTS_PER_STATEMENT: u16 = 4" in source
    assert "attempt != key.expected_attempt" in source
    assert "bundle.attempt != attempt" in source
    assert "encoded[64..128] != NULL_PROOF_SUITE_ID" in source
    assert "encoded[compact_core_length..]" in source
    assert "any(|byte| *byte != 0)" in source
    assert 'H4_K128_GOVERNED_PROFILE_LABEL: &str = "K128_CALIBRATION"' in source
    assert 'H4_K512_GOVERNED_PROFILE_LABEL: &str = "K512_CALIBRATION"' in source
    assert "pub governed_profile_code: u8" in source
    assert "pub governed_profile_label: &'static str" in source
    assert "key.governed_profile_code != profile.code()" in source
    assert "key.governed_profile_label != profile.governed_label()" in source
    assert "pub const fn profile_code(&self) -> u8" in source
    assert "pub const fn governed_profile_label(&self) -> &'static str" in source


def test_aggregate_has_one_global_chain_and_exact_ordered_fixed_shard_bodies() -> None:
    source = _source(PACKAGE_SOURCE)
    shard_body_bytes = 192 << 20
    max_bundle_bytes = 16 << 20
    assert shard_body_bytes == 201_326_592
    assert 512 + max_bundle_bytes + shard_body_bytes == 218_104_320
    assert 512 + max_bundle_bytes + 4 * shard_body_bytes == 822_084_096
    assert "H4_AGGREGATE_PACKAGE_V1_HEADER_BYTES" in source
    assert "pub fn h4_aggregate_package_v1_exact_bytes" in source
    assert "usize::from(profile.shard_count()).checked_mul(H4_PROOF_PACKAGE_V1_BYTES)?" in source
    assert "decode_chained_public_coin_bundle(&encoded[public_coin_start..shard_bodies_start])" in source
    assert "for shard_index in 0..shard_count" in source
    assert "embedded_public_coin_length != 0" in source
    assert "H4ProofPackageV1Error::StandaloneShard" in source


def test_authenticated_schedule_replay_is_library_owned() -> None:
    schedule = _source(SCHEDULE_SOURCE)
    package = _source(PACKAGE_SOURCE)
    adapter = _source(PUBLIC_COIN_BRIDGE)
    symbol = "verify_selected_state_composed_public_coin_bundle"
    assert f"pub fn {symbol}" in schedule
    assert "verify_chained_public_coin_bundle(bundle)?" in schedule
    assert "round.descriptor != descriptor" in schedule
    assert symbol in package
    assert symbol in adapter


def test_every_global_round_frame_is_bounded_and_canonical() -> None:
    source = _source(PACKAGE_SOURCE)
    maximum = ((1 << 20) - 16 - 4 * 5) // 4
    assert maximum == 262_135
    assert "H4_GLOBAL_MAX_SHARD_MESSAGE_BYTES" in source
    assert "H4_KIND801_MAX_SHARD_MESSAGE_BYTES: usize = 131_088" in source
    assert "pub fn encode_h4_global_round_frame" in source
    assert "shard_messages.len() != usize::from(profile.shard_count())" in source
    assert "message_length > governed_maximum" in source
    assert "usize::from(shard_index) != expected_shard" in source
    assert "offset != encoded.len()" in source


def test_blsqab02_embeds_the_exact_prechallenge_claim_bytes() -> None:
    root = sha3_512(b"h4-squarefree-coefficient-root").digest()
    point_value_bytes = bytearray()
    encoded_point_value_bytes = bytearray()
    for phase in range(2):
        point_value_bytes.extend((11).to_bytes(2, "big"))
        point_value_bytes.extend(bytes([phase + 1]) * (12 * 64))
        encoded_point_value_bytes.extend((11).to_bytes(2, "big"))
        encoded_point_value_bytes.extend(bytes(6))
        encoded_point_value_bytes.extend(bytes([phase + 1]) * (12 * 64))
    claims = _claim_record(root, 512, bytes(point_value_bytes))
    binding = b"BLSQAB02" + claims + bytes(encoded_point_value_bytes) + bytes(2 * 64)
    assert len(claims) == 140
    assert len(binding) == 1_828
    assert binding[8:148] == claims

    substituted = bytearray(binding)
    substituted[8 + 72] ^= 1
    assert bytes(substituted[8:148]) != claims

    source = _source(PACKAGE_SOURCE)
    assert "encoded.get(8..8 + H4_BLSQCL02_BYTES) != Some(expected_claims)" in source
    assert "mixing_challenges != expected_mixing" in source


def test_public_answer_v2_has_separate_main_ordinary_and_tensor_sections() -> None:
    main = 67_584 * 64
    ordinary = 10 * 3_266 * 64
    tensor = 64 * 512 * 64
    assert (main, ordinary, tensor, main + ordinary + tensor) == (
        4_325_376,
        2_090_240,
        2_097_152,
        8_512_768,
    )
    source = _source(PACKAGE_SOURCE)
    assert 'b"BL/PQ512/FP16-ZK-RS/ANSWERS/v2"' in source
    assert "H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES" in source
    assert "H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES" in source
    assert "let answer_tensor_root = digest64" in source


def test_corrected_producer_and_native_verifiers_share_one_tensor_grammar() -> None:
    prover = _source(THEOREM_PROVER)
    interleaved = _source(INTERLEAVED_PROVER)
    answer_code = _source(ANSWER_CODE_VERIFIER)
    answer_target = _source(ANSWER_TARGET_VERIFIER)
    public_coin = _source(PUBLIC_COIN_BRIDGE)

    assert 'b"BLRSCV07"' in prover and 'b"BLRSCV07"' in answer_code
    assert 'b"BLRSTA05"' in prover and 'b"BLRSTA05"' in answer_target
    assert 'b"BLRSTO02"' in prover and 'b"BLRSTO02"' in answer_target
    assert 'b"BLRSCV06"' not in prover and 'b"BLRSCV06"' not in answer_code
    assert 'b"BLRSTA04"' not in prover and 'b"BLRSTA04"' not in answer_target
    assert 'b"BLRSAC01"' in prover and 'b"BLRSAC01"' in answer_code
    assert 'b"BLZKRSV3"' in interleaved
    assert "SUMCHECK_BASE_WORDS = SUMCHECK_ROUNDS + NON_GKR_AUXILIARY_WORDS" in prover
    assert "BASE_GKR_MASK_KIND = 66" in prover
    assert "GKR_MASK_KIND = 67" in prover
    assert "GKR_MASK_ANSWER_KIND = 69" in prover
    assert "BASE_AUX_MASK_KIND" not in prover
    assert "base_gkr_mask_tree.root" in prover
    assert "answer_gkr_mask_root" in prover
    assert "ANSWER_GKR_TENSOR_BYTES" in public_coin
    assert "gkr_pcs_answer_tensor_root" in public_coin


def test_state_composed_producer_emits_source_rounds_before_kind143_and_binds_targets() -> None:
    prover = _source(THEOREM_PROVER)
    bridge = _source(PUBLIC_COIN_BRIDGE)
    package = _source(PACKAGE_SOURCE)

    assert "H4_SOURCE_RELATION_ROUNDS = 64" in prover
    assert "H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES = 4_560" in prover
    assert 'payload[:8] != b"BLH4SF01"' in prover
    assert "expected_source_root=self.h4_source_root" in prover
    assert "expected_mask_root=self.gkr_mask_commitment" in prover
    assert "public_coin_rounds += H4_SOURCE_RELATION_ROUNDS" in prover
    assert "public_coin_h4_masked_source_functional_binding" in prover
    assert "process.stdin.write(h4_masked_source_functional_binding)" in prover
    assert "scale(h4_masked_source_target, epsilon)" in prover

    booleanity = bridge.index("let booleanity = produce_h4_booleanity_transcript(")
    padding = bridge.index("let padding = produce_h4_padding_transcript(")
    combined = bridge.index("let complete_mask_message = gkr_mask_batch_message(")
    assert booleanity < padding < combined
    assert "state_mask_constraints.extend(booleanity.mask_constraints().iter().cloned())" in bridge
    assert "state_mask_constraints.extend(padding.mask_constraints().iter().cloned())" in bridge
    assert "H4MaskedSourceFunctionalBinding::from_verified_boundaries(" in bridge
    assert "H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES" in bridge
    assert "binding.booleanity_left_challenge" in package
    assert "binding.booleanity_right_challenge" in package
    assert "binding.booleanity_group_point[0]" not in package

    binding_start = package.index("pub struct H4MaskedSourceFunctionalBinding")
    binding_end = package.index("pub struct H4MaskedSourceFunctionalClaims", binding_start)
    binding_fields = package[binding_start:binding_end]
    assert "masked_terminal" in binding_fields
    assert "raw_terminal" not in binding_fields
    assert "raw_source" not in binding_fields
    assert "mask_coefficients" not in binding_fields


def test_raw_free_relay_gkr_is_reconstructed_from_authenticated_messages() -> None:
    package = _source(PACKAGE_SOURCE)
    uniform = _source(UNIFORM_GKR_SOURCE)
    assert "pub fn reconstruct_and_verify_public_masked_nonuniform_trace" in uniform
    assert "decode_public_polynomial_message" in uniform
    assert "verify_public_masked_nonuniform_trace(&proof" in uniform
    assert "reconstruct_and_verify_public_masked_nonuniform_trace(" in package
    assert "gkr_mask_batch.constraints.len() != H4_RELAY_GKR_MASK_CONSTRAINTS" in package


def test_gkr_statement_bindings_are_derived_from_governed_boundary_inputs() -> None:
    source = _source(PACKAGE_SOURCE)
    assert "pub expected_gkr_statement_bindings: [[u8; 64]; 4]" in source
    assert "pub gkr_statement_binding_inputs: H4GkrStatementBindingInputs" in source
    assert 'b"BL/PQ512/WAVE2/HASH-BUS-B16/GKR-STATEMENT/v1\\0"' in source
    assert "H4_HASH_BUS_BOUNDARY_BYTES_PER_SHARD: u64 = 52_428_800" in source
    assert "hash.update([profile.code(), 2_u8]);" in source
    assert "hash.update(u16::from(shard).to_be_bytes());" in source
    assert "gkr_statement_bindings != key.expected_gkr_statement_bindings" in source
    assert "expected_gkr_statement_binding" in source


def test_state_relation_source_digest_is_key_owned_and_every_round_is_replayed() -> None:
    package = _source(PACKAGE_SOURCE)
    state = _source(STATE_RELATION_SOURCE)
    assert "pub expected_state_relation_source_digest: [u8; 64]" in package
    assert "!nonzero(&source_digest)" in package
    assert "round.message != state_relation_output_message(source_digest)" in package
    assert "state_relation_round_message(" in package
    assert "reconstruct_and_verify_h4_state_relation_boundary(" in package
    assert "public_masked_state_relation_h4_input_claims(" in package
    assert "public_masked_state_relation_constraints(" in package
    assert "H4_STATE_RELATION_MASK_CONSTRAINTS: usize = 4" in package
    assert "pub const fn state_relation_source_digest(&self) -> [u8; 64]" in package
    assert "pub fn public_state_relation_transcript_digest" in state
    assert "verify_public_masked_state_relation_gkr(proof)?" in state


def test_squarefree_and_complete_mask_batch_are_reconstructed_from_public_bytes() -> None:
    package = _source(PACKAGE_SOURCE)
    squarefree = _source(STATE_SQUAREFREE_SOURCE)
    adapter = _source(PUBLIC_COIN_BRIDGE)
    assert "pub fn public_masked_state_squarefree_layer_plan" in squarefree
    assert "pub fn state_squarefree_beta_message" in squarefree
    assert "pub fn state_squarefree_point_message" in squarefree
    assert "pub fn state_squarefree_round_message" in squarefree
    assert "reconstruct_and_verify_h4_squarefree_boundary(" in package
    assert "verify_public_masked_state_squarefree_composed(&proof)" in package
    assert "public_masked_state_squarefree_constraints(&proof" in package
    assert "ordinals[1] + 3 != layout.layers.len()" in squarefree
    assert "complete_mask_round.message != gkr_mask_batch_message(&complete_mask_constraints)" in package
    assert "aggregate_gkr_mask_constraints(" in package
    assert "expected_relation_terminals != public_view.relation_terminals" in package
    assert "state_squarefree_beta_message" in adapter
    assert "state_squarefree_round_message" in adapter


def test_portable_verifier_checks_all_construction_8_2_spotcheck_families() -> None:
    source = _source(PACKAGE_SOURCE)
    assert "fn verify_construction_8_2_spotchecks" in source
    assert "openings.main_base_openings[ordinal]" in source
    assert "openings.source_main_openings[ordinal]" in source
    assert "openings.sumcheck_source_openings" in source
    assert "openings.squarefree_source_openings[ordinal]" in source
    assert "openings.ordinary_base_openings" in source
    assert "*answer != *base + combination * *mask" in source
    assert "H4_SERIALIZED_PCS_OPENING_SCALARS" in source
    assert "847_596" in source


def test_coupled_base_and_source_tensors_retain_joint_mask_freedom() -> None:
    coefficients = 64 * 512
    authenticated_queries = 1_218
    old_layout_rank = 64 * min(authenticated_queries, 512)
    source_root_only_k128_rank = 26_899 + authenticated_queries
    source_root_only_k512_rank = 28_027 + authenticated_queries
    public_answer_equation_rank = coefficients
    k128_joint_rank = (
        26_899 + public_answer_equation_rank + 2 * authenticated_queries + 1
    )
    k512_joint_rank = (
        28_027 + public_answer_equation_rank + 2 * authenticated_queries + 1
    )

    assert old_layout_rank == coefficients
    assert source_root_only_k128_rank == 28_117
    assert source_root_only_k512_rank == 29_245
    assert k128_joint_rank == 62_104
    assert k512_joint_rank == 63_232
    assert 2 * coefficients - k128_joint_rank == 3_432
    assert 2 * coefficients - k512_joint_rank == 2_304

    source = _source(SCHEDULE_SOURCE)
    assert "GKR_MASK_TENSOR_INNER_MESSAGE_VALUES: usize = 512" in source
    assert "GKR_MASK_TENSOR_OUTER_MESSAGE_VALUES: usize = 64" in source
    assert "GKR_MASK_TENSOR_PCS_OPENINGS: usize = 1_218" in source
    assert "GKR_MASK_JOINT_COEFFICIENT_DIMENSION" in source
    assert "GKR_MASK_PUBLIC_ANSWER_EQUATION_RANK" in source
    assert "complete_observation_rank >= mask_rank.joint_coefficient_dimension" in _source(
        PACKAGE_SOURCE
    )
    assert "mask_rank.residual_entropy_bits_lower_bound < 256" in _source(PACKAGE_SOURCE)


def test_booleanity_schedule_layout_and_padding_exception_are_exact() -> None:
    schedule = _source(SCHEDULE_SOURCE)
    package = _source(PACKAGE_SOURCE)
    assert "H4_BOOLEANITY_VARIABLES: u32 = 29" in schedule
    assert "H4_BOOLEANITY_PRELUDE_KIND: u16 = 144" in schedule
    assert "H4_BOOLEANITY_SUMCHECK_KIND: u16 = 145" in schedule
    assert "H4_BOOLEANITY_TERMINAL_KIND: u16 = 146" in schedule
    assert "STATE_COMPOSED_K128_ROUNDS, 6_791" in schedule
    assert "STATE_COMPOSED_K512_ROUNDS, 7_059" in schedule
    assert "let mut booleanity = vec![3; H4_BOOLEANITY_VARIABLES as usize]" in schedule
    assert "booleanity.extend([5, 5, 2])" in schedule
    assert "H4_PADDING_PRELUDE_KIND: u16 = 147" in schedule
    assert "H4_PADDING_SUMCHECK_KIND: u16 = 148" in schedule
    assert "H4_PADDING_TERMINAL_KIND: u16 = 149" in schedule
    assert "STATE_COMPOSED_K128_MASK_USED_COEFFICIENTS: usize = 28_013" in schedule
    assert "STATE_COMPOSED_K512_MASK_USED_COEFFICIENTS: usize = 29_201" in schedule

    assert 'b"BLH4BO03"' in package
    assert 'b"BLH4BR03"' in package
    assert 'b"BLH4BT03"' in package
    assert 'b"BLH4PO01"' in package
    assert 'b"BLH4PR01"' in package
    assert 'b"BLH4PT01"' in package
    assert "verify_h4_booleanity_algebra_boundary(" in package
    assert "verify_h4_padding_algebra_boundary(" in package
    assert "round_challenges" in package and "challenge.is_zero()" in package
    assert "H4_BOOLEANITY_QUINTIC_ROUND_BYTES" in package
    assert "complete_mask_constraints.extend(booleanity.mask_constraints.iter().cloned())" in package
    assert "complete_mask_constraints.extend(padding.mask_constraints.iter().cloned())" in package
    assert "(1_600..1_664).contains(&wire) && group < 4_096" in package
    assert "H4SourceCellClass::GlobalPadding" in package


def test_public_answer_tensor_needs_no_extra_multiproof_segment() -> None:
    package = _source(PACKAGE_SOURCE)
    verifier = _source(INTERLEAVED_VERIFIER)
    assert "matches!(segment_count, 21 | 37)" in package
    assert "THEOREM_8_1_COMPLETE_SEGMENT_COUNTS: [usize; 2] = [21, 37]" in verifier
    assert "let (computed_answer_tensor_root, answer_tensor_openings)" in package
    assert "answer_tensor_root_and_openings(" in package
    assert "GKR_TENSOR_ANSWER_KIND" in package
    assert "22 | 38" not in package


def test_tensor_coordinates_are_seed_bound_and_retry_bounded_in_both_verifiers() -> None:
    for path in (INTERLEAVED_VERIFIER, SPOTCHECK_VERIFIER):
        source = _source(path)
        assert "QUERY_MAX_DRAWS" in source
        assert "GKR_MASK_OUTER_QUERY_DOMAIN" in source
        assert "gkr_mask_outer_queries/v1" in source
        assert "query_seed" in source
        assert "inner_query" in source


def test_package_is_exported_as_a_boundary_not_complete_acceptance() -> None:
    library = _source(LIB_SOURCE)
    source = _source(PACKAGE_SOURCE)
    assert "pub mod h4_proof_package_v1;" in library
    assert "pub mod semantic_h4_bridge;" in library
    assert "VerifiedH4AggregatePackageV1Boundary" in source
    assert "Possessing this value is not H4 proof acceptance." in source
    assert "kind143 combined committed-mask/Construction functional" in source
    assert "committed-source Booleanity" in source
    assert "global-padding zero functional" in source
    assert "128-byte" in source
    assert "post-parent-OODS bridge" in source
    assert "pub fn verify_h4_aggregate_package_v1_boundary" in source
    assert "pub fn verify_h4_proof_package_v1_boundary" not in source


def test_public_boundary_has_no_private_coefficient_or_witness_getter() -> None:
    source = _source(PACKAGE_SOURCE)
    forbidden_getters = (
        "pub const fn coefficients(",
        "pub const fn witness(",
        "pub const fn raw_claim(",
        "pub const fn mask_coefficients(",
    )
    assert all(getter not in source for getter in forbidden_getters)
