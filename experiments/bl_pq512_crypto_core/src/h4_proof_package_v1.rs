//! Fixed-container aggregate transport and authenticated square-free boundary for H4.
//!
//! This module intentionally verifies a strict, useful prefix of the portable
//! H4 proof boundary: one authenticated global public-coin chain followed by
//! one or four exact 192 MiB shard bodies, pinned identities, the public
//! answer-coefficient commitment that precedes the query seed, corrected
//! hidden base/mask tensor geometry/rank, and
//! byte-for-byte binding of the pre-kind799 `BLSQCL02` claim record into
//! `BLSQAB02`. It also verifies the authenticated nine-round PCS row sumcheck,
//! all canonical RS Merkle multiproofs, the hidden kind66-B/kind67-N tensor
//! openings, the public kind69-A tensor encoding, `A=B+mix*N`, and the complete
//! Construction-8.2 answer functional. It reconstructs and verifies the
//! preceding raw-free relay-free GKR and state-relation public views from
//! authenticated round messages, including exact verifier-key ownership of the
//! state-source digest and the two state PCS claims. The square-free public GKR,
//! all twelve derived state PCS terminals, two public masked coefficient
//! terminals, the generic masked committed-source Booleanity GKR, the separate
//! global-padding zero functional with its state-lane exception, and the
//! kind143 combined committed-mask/Construction functional are also replayed
//! and checked. The current v1 roots remain 64-byte SHA3-512 roots, below the
//! frozen strict-PQ binding policy, and the post-parent-OODS bridge primitives
//! are not present; this module therefore does not construct `VerifiedH4`.

use alloc::{collections::BTreeSet, vec, vec::Vec};

use sha3::{Digest, Sha3_512};

use crate::{
    chained_public_coin::{
        ChainedPublicCoinBundle, ChainedRoundDescriptor, MAX_CHAIN_BUNDLE_BYTES,
        MAX_PROVER_MESSAGE_BYTES, decode_chained_public_coin_bundle,
    },
    field::{Fp16, M31},
    fp16_relay_free_gkr_schedule::{
        GKR_LAYERS, GKR_ROUNDS, GkrMaskTensorObservationRankCertificate,
        H4_BOOLEANITY_PRELUDE_KIND, H4_BOOLEANITY_SUMCHECK_KIND, H4_BOOLEANITY_TERMINAL_KIND,
        H4_BOOLEANITY_VARIABLES, H4_PADDING_PRELUDE_KIND, H4_PADDING_SUMCHECK_KIND,
        H4_PADDING_TERMINAL_KIND, H4_PADDING_VARIABLES, H4_STATE_COMPOSED_MASK_BATCH_KIND,
        H4_STATE_RELATION_GROUP_KIND, H4_STATE_RELATION_OUTPUT_KIND,
        H4_STATE_RELATION_TERMINAL_KIND, H4_STATE_RELATION_WIRE_KIND,
        H4_STATE_SQUAREFREE_BETA_KIND, H4_STATE_SQUAREFREE_GROUP_KIND,
        H4_STATE_SQUAREFREE_LEFT_KIND, H4_STATE_SQUAREFREE_MIX_KIND,
        H4_STATE_SQUAREFREE_POINT_KIND, H4_STATE_SQUAREFREE_RIGHT_KIND,
        H4_STATE_SQUAREFREE_TERMINAL_KIND, STATE_COMPOSED_K128_ROUNDS, STATE_COMPOSED_K512_ROUNDS,
        STATE_RELATION_ROUNDS, gkr_mask_tensor_observation_rank_certificate,
        selected_booleanity_mask_layer, selected_gkr_round_kind, selected_padding_mask_layer,
        selected_state_composed_mask_layout, verify_selected_state_composed_public_coin_bundle,
    },
    fp16_relay_free_gkr_uniform::{
        UniformGkrMaskConstraint, UniformGkrMaskFunctional, UniformRelayFreeClaim,
        UniformRelayFreeGkrRound, aggregate_gkr_mask_constraints, gkr_mask_batch_message,
        reconstruct_and_verify_public_masked_nonuniform_trace,
    },
    fp16_zk_rs_gkr_binding::{
        BOUNDARY_VARIABLES, GKR_CLAIM_COUNT, PackedComponentClaim, bind_gkr_boundary_claims,
        claim_main_answer_target,
    },
    gkr_sumcheck::{LayerOutputClaim, shared_group_terminal_gate_claim},
    gkr_zk_mask::boolean_vanishing,
    keccak_gkr_dag::{KeccakDagGate, KeccakDagGateKind, KeccakDagLayer, KeccakDagSource},
    merkle::RootHash,
    merkle_multiproof::{CanonicalMerkleMultiProof, canonical_frontier_positions},
    multilinear_pcs::MultilinearOpeningClaim,
    state_relation_gkr::{
        PublicMaskedStateRelationGkrProof, STATE_RELATION_GROUP_VARIABLES,
        STATE_RELATION_OUTPUT_CHALLENGE_COUNT, STATE_RELATION_TRANSCRIPT_DOMAIN,
        STATE_RELATION_WIRE_VARIABLES, h4_state_point, public_masked_state_relation_constraints,
        public_masked_state_relation_h4_input_claims, public_state_relation_transcript_digest,
        state_relation_output_message, state_relation_round_message,
        verify_public_masked_state_relation_gkr,
    },
    state_squarefree_gkr::{
        PublicMaskedStateSquarefreeGkrProof, PublicMaskedStateSquarefreeLayerProof,
        STATE_SQUAREFREE_PHASES, STATE_SQUAREFREE_TRANSCRIPT_DOMAIN, StateSquarefreeLayout,
        public_masked_state_squarefree_constraints,
        public_masked_state_squarefree_gkr_mask_functional,
        public_masked_state_squarefree_layer_plan, public_masked_state_squarefree_state_reductions,
        state_squarefree_authenticated_rounds, state_squarefree_beta_message,
        state_squarefree_layer_ordinal, state_squarefree_point_message,
        state_squarefree_round_message, verify_public_masked_state_squarefree_composed,
    },
    state_squarefree_pcs::state_squarefree_coefficient_functional,
};

pub const H4_PROOF_PACKAGE_V1_MAGIC: &[u8; 8] = b"BLH4PK01";
pub const H4_PROOF_PACKAGE_V1_VERSION: u16 = 1;
pub const H4_PROOF_PACKAGE_V1_BYTES: usize = 192 << 20;
pub const H4_PROOF_PACKAGE_V1_HEADER_BYTES: usize = 512;
pub const H4_AGGREGATE_PACKAGE_V1_MAGIC: &[u8; 8] = b"BLH4AG01";
pub const H4_AGGREGATE_PACKAGE_V1_VERSION: u16 = 1;
pub const H4_AGGREGATE_PACKAGE_V1_HEADER_BYTES: usize = 512;
pub const H4_GLOBAL_ROUND_FRAME_VERSION: u16 = 1;
pub const H4_ANSWER_MAIN_COEFFICIENT_BYTES: usize = 67_584 * 64;
pub const H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES: usize = 10 * 3_266 * 64;
pub const H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES: usize = 64 * 512 * 64;
pub const H4_ANSWER_COEFFICIENT_BYTES: usize = H4_ANSWER_MAIN_COEFFICIENT_BYTES
    + H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES
    + H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES;
pub const H4_BLSQCL02_BYTES: usize = 140;
pub const H4_BLSQAB02_BYTES: usize = 1_828;
pub const H4_DURABLE_MAX_ATTEMPTS_PER_STATEMENT: u16 = 4;
pub const H4_K128_GOVERNED_PROFILE_LABEL: &str = "K128_CALIBRATION";
pub const H4_K512_GOVERNED_PROFILE_LABEL: &str = "K512_CALIBRATION";
pub const H4_GLOBAL_ROUND_FRAME_MAGIC: &[u8; 8] = b"BLH4GR01";
pub const H4_GLOBAL_ROUND_FRAME_HEADER_BYTES: usize = 16;
pub const H4_GLOBAL_ROUND_FRAME_SHARD_HEADER_BYTES: usize = 5;
pub const H4_GLOBAL_MAX_SHARD_MESSAGE_BYTES: usize = (MAX_PROVER_MESSAGE_BYTES
    - H4_GLOBAL_ROUND_FRAME_HEADER_BYTES
    - 4 * H4_GLOBAL_ROUND_FRAME_SHARD_HEADER_BYTES)
    / 4;
pub const H4_KIND801_MAX_SHARD_MESSAGE_BYTES: usize = 131_088;
pub const H4_KIND801_MAX_K512_GLOBAL_FRAME_BYTES: usize = H4_GLOBAL_ROUND_FRAME_HEADER_BYTES
    + 4 * (H4_GLOBAL_ROUND_FRAME_SHARD_HEADER_BYTES + H4_KIND801_MAX_SHARD_MESSAGE_BYTES);
pub const H4_PUBLIC_VIEW_V1_MAGIC: &[u8; 8] = b"BLH4PV01";
pub const H4_PUBLIC_VIEW_V1_VERSION: u16 = 1;
pub const H4_PUBLIC_VIEW_V1_HEADER_BYTES: usize = 32;
pub const H4_PACKED_CLAIMS_BYTES: usize =
    GKR_CLAIM_COUNT * (4 + (3 + BOUNDARY_VARIABLES + 16) * 64);
pub const H4_GKR_RELATION_TERMINALS: usize = 64;
pub const H4_GKR_RELATION_TERMINAL_BYTES: usize = H4_GKR_RELATION_TERMINALS * 64;
pub const H4_RS_MULTIPROOF_MAGIC: &[u8; 8] = b"BLZKRSV3";
pub const H4_RS_MULTIPROOF_PREFIX_BYTES: usize = 8 + 4 + 64;
pub const H4_MAIN_CODE_VALUES: usize = 1 << 17;
pub const H4_MAIN_OPENINGS: usize = 1_600;
pub const H4_AUXILIARY_CODE_VALUES: usize = 1 << 13;
pub const H4_AUXILIARY_OPENINGS: usize = 1_218;
pub const H4_GKR_TENSOR_INNER_MESSAGE_VALUES: usize = 512;
pub const H4_GKR_TENSOR_INNER_CODE_VALUES: usize = 1 << 13;
pub const H4_GKR_TENSOR_OUTER_MESSAGE_VALUES: usize = 64;
pub const H4_GKR_TENSOR_OUTER_CODE_VALUES: usize = 1 << 7;
pub const H4_GKR_TENSOR_LEAVES: usize =
    H4_GKR_TENSOR_INNER_CODE_VALUES * H4_GKR_TENSOR_OUTER_CODE_VALUES;
pub const H4_GKR_TENSOR_DATA_BYTES: usize = H4_GKR_TENSOR_LEAVES * 64;
pub const H4_QUERY_MAX_DRAWS: u64 = 1 << 20;
pub const H4_QUERY_MAX_RETRIES_PER_DRAW: u64 = 1 << 20;
pub const H4_INITIAL_SOURCE_WORDS: usize = 512;
pub const H4_INITIAL_PCS_OPENING_SCALARS: usize = H4_INITIAL_SOURCE_WORDS * H4_MAIN_OPENINGS;
pub const H4_COMBINED_AUXILIARY_PCS_OPENING_SCALARS: usize =
    (WORD_SUMCHECK_ROUNDS + NON_GKR_AUXILIARY_WORDS) * H4_AUXILIARY_OPENINGS;
pub const H4_SERIALIZED_PCS_OPENING_SCALARS: usize = H4_INITIAL_PCS_OPENING_SCALARS
    + H4_COMBINED_AUXILIARY_PCS_OPENING_SCALARS
    + H4_AUXILIARY_OPENINGS
    + H4_MAIN_OPENINGS
    + H4_AUXILIARY_OPENINGS
    + H4_AUXILIARY_OPENINGS;
pub const H4_GKR_STATEMENT_BINDING_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/HASH-BUS-B16/GKR-STATEMENT/v1\0";
pub const H4_PADDED_PERMUTATIONS_PER_SHARD: u64 = 131_072;
pub const H4_LIVE_WIRES_PER_PERMUTATION: u16 = 1_600;
pub const H4_HASH_BUS_BOUNDARY_HEADER_BYTES: u64 = 215;
pub const H4_HASH_BUS_BOUNDARY_BYTES_PER_SHARD: u64 = 52_428_800;
pub const H4_RELAY_GKR_MASK_CONSTRAINTS: usize = 508;
pub const H4_STATE_RELATION_MASK_CONSTRAINTS: usize = 4;
pub const H4_K128_SQUAREFREE_MASK_CONSTRAINTS: usize = 110;
pub const H4_K512_SQUAREFREE_MASK_CONSTRAINTS: usize = 134;
pub const H4_BOOLEANITY_MASK_CONSTRAINTS: usize = 2;
pub const H4_PADDING_MASK_CONSTRAINTS: usize = 2;
pub const H4_K128_COMPLETE_MASK_CONSTRAINTS: usize = 626;
pub const H4_K512_COMPLETE_MASK_CONSTRAINTS: usize = 650;
pub const H4_BOOLEANITY_COMPONENT_VARIABLES: usize = 4;
pub const H4_BOOLEANITY_COEFFICIENT_VARIABLES: usize = 16;
pub const H4_BOOLEANITY_WORD_VARIABLES: usize = 9;
pub const H4_BOOLEANITY_GROUP_DEGREE: usize = 3;
pub const H4_BOOLEANITY_SOURCE_DEGREE: usize = 5;
pub const H4_BOOLEANITY_W_DEGREE: usize = 2;
pub const H4_BOOLEANITY_PRELUDE_MAGIC: &[u8; 8] = b"BLH4BO03";
pub const H4_BOOLEANITY_ROUND_MAGIC: &[u8; 8] = b"BLH4BR03";
pub const H4_BOOLEANITY_TERMINAL_MAGIC: &[u8; 8] = b"BLH4BT03";
pub const H4_BOOLEANITY_GRAMMAR_VERSION: u16 = 3;
pub const H4_BOOLEANITY_PRELUDE_BYTES: usize = 272;
pub const H4_BOOLEANITY_CUBIC_ROUND_BYTES: usize = 272;
pub const H4_BOOLEANITY_QUINTIC_ROUND_BYTES: usize = 400;
pub const H4_BOOLEANITY_TERMINAL_BYTES: usize = 600;
pub const H4_PADDING_PRELUDE_MAGIC: &[u8; 8] = b"BLH4PO01";
pub const H4_PADDING_ROUND_MAGIC: &[u8; 8] = b"BLH4PR01";
pub const H4_PADDING_TERMINAL_MAGIC: &[u8; 8] = b"BLH4PT01";
pub const H4_PADDING_GRAMMAR_VERSION: u16 = 1;
pub const H4_PADDING_PRELUDE_BYTES: usize = 272;
pub const H4_PADDING_ROUND_BYTES: usize = 208;
pub const H4_PADDING_TERMINAL_BYTES: usize = 336;
pub const H4_MASKED_SOURCE_FUNCTIONAL_BOOLEANITY_TAG: u8 = 1;
pub const H4_MASKED_SOURCE_FUNCTIONAL_PADDING_TAG: u8 = 2;
pub const H4_MASKED_SOURCE_FUNCTIONAL_BINDING_MAGIC: &[u8; 8] = b"BLH4SF01";
pub const H4_MASKED_SOURCE_FUNCTIONAL_BINDING_VERSION: u16 = 1;
pub const H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES: usize = 4_560;
pub const H4_SOURCE_COEFFICIENT_POSITIONS: usize = 1 << H4_BOOLEANITY_COEFFICIENT_VARIABLES;
pub const H4_SOURCE_GLOBAL_WORDS: usize = 1 << H4_BOOLEANITY_WORD_VARIABLES;
pub const H4_HASH_VIRTUAL_BITS: usize = 16 * 26_214_400;
pub const H4_STATE_LANE_VIRTUAL_CELLS: usize = 16 * 262_144;
pub const H4_GLOBAL_PADDING_VIRTUAL_CELLS: usize = 16 * 7_077_888;

/// Exact aggregate prefix (all integers unsigned big-endian):
///
/// ```text
/// 0   8  magic BLH4AG01          8   2  version=1
/// 10  1  profile                 11  1  shardCount (1 or 4)
/// 12  2  durable attempt         14  2  flags=0
/// 16  8  global bundle bytes     24  8  shardBodyBytes=201326592
/// 32  8  exact aggregate bytes   40  4  transcript round count
/// 44  2  global-frame version=1  46  18 reserved=0
/// 64 64  proofSuiteId=0          128 64 profile identity
/// 192 64 base program commitment 256 64 schedule commitment
/// 320 64 session id              384 64 contributor-set commitment
/// 448 64 statement commitment
/// ```
///
/// The prefix is followed by exactly `globalBundleBytes`, then exactly
/// `shardCount` ordered fixed shard bodies. There is no transcript padding and
/// no trailing byte.
pub fn h4_aggregate_package_v1_exact_bytes(
    profile: H4ProofProfile,
    public_coin_length: usize,
) -> Option<usize> {
    if public_coin_length == 0 || public_coin_length > MAX_CHAIN_BUNDLE_BYTES {
        return None;
    }
    H4_AGGREGATE_PACKAGE_V1_HEADER_BYTES
        .checked_add(public_coin_length)?
        .checked_add(usize::from(profile.shard_count()).checked_mul(H4_PROOF_PACKAGE_V1_BYTES)?)
}

const PACKAGE_HASH_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/H4-PROOF-PACKAGE/v1\0";
const AGGREGATE_PACKAGE_HASH_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/H4-AGGREGATE-PACKAGE/v1\0";
const CONTRIBUTOR_SET_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/H4-PUBLIC-COIN-CONTRIBUTORS/v1\0";
const PRECHALLENGE_BINDING_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/H4-PRECHALLENGE-BINDING/v1\0";
const SQUAREFREE_CLAIMS_DIGEST_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/STATE-SQUAREFREE-CLAIMS/v2\0";
const BOOLEANITY_LAYOUT_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/H4-SOURCE-BOOLEANITY-LAYOUT/v3\0";
const BOOLEANITY_TRANSCRIPT_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/H4-SOURCE-BOOLEANITY-TRANSCRIPT/v3\0";
const PADDING_TRANSCRIPT_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/H4-SOURCE-PADDING-TRANSCRIPT/v1\0";
const MASKED_SOURCE_FUNCTIONALS_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/H4-MASKED-SOURCE-FUNCTIONALS/v1\0";
const MASKED_SOURCE_FUNCTIONAL_BINDING_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/H4-MASKED-SOURCE-FUNCTIONAL-BINDING/v1\0";
const ANSWERS_DOMAIN: &[u8] = b"BL/PQ512/FP16-ZK-RS/ANSWERS/v2";
const BASE_MASKS_DOMAIN: &[u8] = b"BL/PQ512/FP16-ZK-RS/BASE-MASKS/v3";
const PCS_MAGIC: &[u8; 8] = b"BLPQPCS1";
const PCS_VERSION: u16 = 1;
const SEGMENT_LEAF_DOMAIN: u16 = 516;
const SEGMENT_SET_DOMAIN: u16 = 517;
const QUERY_DOMAIN: u16 = 524;
const GKR_BINDING_DOMAIN: u16 = 525;
const GKR_MASK_OUTER_QUERY_DOMAIN: u16 = 526;
const GKR_MASK_OUTER_QUERY_LABEL: &[u8] = b"gkr_mask_outer_queries/v1";
const GKR_CLAIMS_DIGEST_LABEL: &[u8] =
    b"BL/PQ512/FP16-ZK-RS/GKR-MIXED-CLAIMS/HASH-PACKED-STATE-DIRECT/v3\0";
const GKR_ROW_BINDING_LABEL: &[u8] = b"BL/PQ512/FP16-ZK-RS/ROW-BATCHED-BINDING/MIXED-v3\0";
const GKR_TENSOR_BOUNDARY: u64 = 2;
const GKR_TENSOR_BASE_KIND: u64 = 66;
const GKR_TENSOR_MASK_KIND: u64 = 67;
const GKR_TENSOR_ANSWER_KIND: u64 = 69;
const PCS_SUMCHECK_BASE_KIND: u64 = 64;
const PCS_MAIN_BASE_KIND: u64 = 65;
const PCS_SQUAREFREE_KIND: u64 = 68;
const WORD_SUMCHECK_ROUNDS: usize = 9;
const AUXILIARY_MESSAGE_VALUES: usize = 2_048;
const AUXILIARY_DIMENSION: usize = 3_266;
const NON_GKR_AUXILIARY_WORDS: usize = 10;
const ROOT25_COORDINATES: [u32; 16] = [
    1_905_033_081,
    454_651_505,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];
const COSET_COORDINATES: [u32; 16] = [2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const NULL_PROOF_SUITE_ID: [u8; 64] = [0_u8; 64];
const KIND_CLAIM_BATCH: u16 = 799;
const KIND_INITIAL_SUMCHECK: u16 = 800;
const KIND_ROW_SUMCHECK: u16 = 801;
const KIND_BASE_MASKS: u16 = 802;
const KIND_ANSWER_QUERIES: u16 = 803;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum H4ProofProfile {
    K128 = 1,
    K512 = 3,
}

impl H4ProofProfile {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn governed_label(self) -> &'static str {
        match self {
            Self::K128 => H4_K128_GOVERNED_PROFILE_LABEL,
            Self::K512 => H4_K512_GOVERNED_PROFILE_LABEL,
        }
    }

    const fn shard_count(self) -> u8 {
        match self {
            Self::K128 => 1,
            Self::K512 => 4,
        }
    }

    const fn state_capacity(self) -> u16 {
        match self {
            Self::K128 => 128,
            Self::K512 => 512,
        }
    }

    const fn transcript_rounds(self) -> usize {
        match self {
            Self::K128 => STATE_COMPOSED_K128_ROUNDS as usize,
            Self::K512 => STATE_COMPOSED_K512_ROUNDS as usize,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H4AggregatePackageV1VerificationKey {
    pub profile: H4ProofProfile,
    pub governed_profile_code: u8,
    pub governed_profile_label: &'static str,
    pub expected_attempt: u16,
    pub profile_identity: [u8; 64],
    pub program_commitment: [u8; 64],
    pub schedule_commitment: [u8; 64],
    pub session_id: [u8; 64],
    pub public_coin_contributors_commitment: [u8; 64],
    pub statement_commitment: [u8; 64],
    pub aggregate_package_commitment: [u8; 64],
    /// Digest of the typed-state source owned by the governed verification key.
    /// It is never learned from a shard or transcript message.
    pub expected_state_relation_source_digest: [u8; 64],
    pub gkr_statement_binding_inputs: H4GkrStatementBindingInputs,
    pub expected_gkr_statement_bindings: [[u8; 64]; 4],
}

/// Canonical public header inputs used to derive every per-shard GKR
/// statement binding.  These are verifier-key data, not prover-selected
/// package fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H4GkrStatementBindingInputs {
    pub semantic_program_commitment: [u8; 64],
    pub descriptor_commitment: [u8; 64],
    pub semantic_port_commitment: [u8; 64],
    pub boundary_file_sha3_512: [u8; 64],
    pub gkr_plan_commitment: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H4ProofPackageV1Error {
    Length,
    Magic,
    Version,
    Profile,
    Geometry,
    Flags,
    Identity,
    ProofSuite,
    SectionLength,
    Padding,
    Commitment,
    PublicCoin,
    ContributorSet,
    TranscriptSchedule,
    TranscriptBinding,
    AnswerCommitment,
    SquarefreeClaims,
    SquarefreeAnswerBinding,
    Rank,
    GlobalFrame,
    AggregateLength,
    StandaloneShard,
    PublicView,
    PackedClaims,
    Sumcheck,
    Multiproof,
    TensorCode,
    TensorRelation,
    Functional,
    Gkr,
    StateRelation,
    Booleanity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H4MaskedSquarefreePublicClaims {
    pub coefficient_root: [u8; 64],
    pub capacity: u16,
    pub claims_digest: [u8; 64],
    pub points: [[Fp16; 11]; 2],
    pub values: [Fp16; 2],
    pub mixing_challenges: [Fp16; 2],
    pub masked_target: Fp16,
}

/// Opaque public view of the verifier-fixed masked Booleanity GKR.
///
/// The raw source evaluation and both raw mask terminals are absent. The
/// generic nonlinear terminal correction is checked inside the degree-five
/// left/right rounds; Construction 8.2 later authenticates only the derived
/// tagged masked source functional.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedH4BooleanityAlgebraBoundary {
    source_root: [u8; 64],
    mask_tensor_root: [u8; 64],
    mask_layer: usize,
    equality_point: [Fp16; 29],
    group_point: [Fp16; 29],
    left_challenge: Fp16,
    right_challenge: Fp16,
    w_challenge: Fp16,
    masked_terminal_left: Fp16,
    masked_terminal_right: Fp16,
    transcript_commitment: [u8; 64],
    mask_constraints: Vec<UniformGkrMaskConstraint>,
}

impl VerifiedH4BooleanityAlgebraBoundary {
    pub const fn source_root(&self) -> [u8; 64] {
        self.source_root
    }

    pub const fn mask_tensor_root(&self) -> [u8; 64] {
        self.mask_tensor_root
    }

    pub const fn mask_layer(&self) -> usize {
        self.mask_layer
    }

    pub const fn masked_terminal_left(&self) -> Fp16 {
        self.masked_terminal_left
    }

    pub const fn masked_terminal_right(&self) -> Fp16 {
        self.masked_terminal_right
    }

    pub const fn transcript_commitment(&self) -> [u8; 64] {
        self.transcript_commitment
    }

    pub fn mask_constraints(&self) -> &[UniformGkrMaskConstraint] {
        &self.mask_constraints
    }
}

/// Opaque public view of the independent linear global-padding identity.
/// The verifier-fixed selector excludes only the documented state-lane cells;
/// the raw source terminal never crosses the proof boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedH4PaddingAlgebraBoundary {
    source_root: [u8; 64],
    mask_tensor_root: [u8; 64],
    mask_layer: usize,
    equality_point: [Fp16; 29],
    sumcheck_point: [Fp16; 29],
    masked_terminal: Fp16,
    functional_mixing_challenge: Fp16,
    transcript_commitment: [u8; 64],
    mask_constraints: Vec<UniformGkrMaskConstraint>,
}

impl VerifiedH4PaddingAlgebraBoundary {
    pub const fn source_root(&self) -> [u8; 64] {
        self.source_root
    }

    pub const fn mask_tensor_root(&self) -> [u8; 64] {
        self.mask_tensor_root
    }

    pub const fn mask_layer(&self) -> usize {
        self.mask_layer
    }

    pub const fn masked_terminal(&self) -> Fp16 {
        self.masked_terminal
    }

    pub const fn functional_mixing_challenge(&self) -> Fp16 {
        self.functional_mixing_challenge
    }

    pub const fn transcript_commitment(&self) -> [u8; 64] {
        self.transcript_commitment
    }

    pub fn mask_constraints(&self) -> &[UniformGkrMaskConstraint] {
        &self.mask_constraints
    }
}

/// Canonical raw-free handoff from the authenticated kinds 144--149 transcript
/// into the Construction-8.2 base/answer target workers.  Only masked public
/// terminals and verifier-derived points cross this boundary; raw source and
/// mask evaluations are intentionally unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4MaskedSourceFunctionalBinding {
    profile: H4ProofProfile,
    source_root: [u8; 64],
    mask_tensor_root: [u8; 64],
    booleanity_transcript_commitment: [u8; 64],
    booleanity_group_point: [Fp16; 29],
    booleanity_left_challenge: Fp16,
    booleanity_right_challenge: Fp16,
    booleanity_w_challenge: Fp16,
    booleanity_masked_terminal_left: Fp16,
    booleanity_masked_terminal_right: Fp16,
    padding_transcript_commitment: [u8; 64],
    padding_sumcheck_point: [Fp16; 29],
    padding_masked_terminal: Fp16,
    padding_functional_mixing_challenge: Fp16,
    complete_mask_challenge: Fp16,
}

/// The two fixed raw-free Construction source-functional ordinals. These are
/// verifier-derived objects: no raw source value, raw component evaluation, or
/// caller-selected selector is represented by this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4MaskedSourceFunctionalClaims {
    commitment: [u8; 64],
    masked_target: Fp16,
    answer_main_functional: Fp16,
    answer_mask_functional: Fp16,
}

impl H4MaskedSourceFunctionalClaims {
    pub const fn commitment(&self) -> [u8; 64] {
        self.commitment
    }

    pub const fn masked_target(&self) -> Fp16 {
        self.masked_target
    }

    pub const fn answer_main_functional(&self) -> Fp16 {
        self.answer_main_functional
    }

    pub const fn answer_mask_functional(&self) -> Fp16 {
        self.answer_mask_functional
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedH4ShardPackageV1Boundary {
    pub package_commitment: [u8; 64],
    pub source_root: [u8; 64],
    pub base_tensor_root: [u8; 64],
    pub gkr_mask_tensor_root: [u8; 64],
    pub answer_tensor_root: [u8; 64],
    pub prechallenge_binding_commitment: [u8; 64],
    pub squarefree: H4MaskedSquarefreePublicClaims,
    pub tensor_observations: usize,
    pub serialized_pcs_opening_scalars: usize,
    pub answer_functional: Fp16,
    pub source_functional: Fp16,
    pub gkr_mask_constraint_count: usize,
    pub state_relation_transcript_digest: [u8; 64],
    pub state_relation_mask_constraints: Vec<UniformGkrMaskConstraint>,
    pub squarefree_transcript_digest: [u8; 64],
    pub squarefree_mask_constraints: Vec<UniformGkrMaskConstraint>,
    pub booleanity: VerifiedH4BooleanityAlgebraBoundary,
    pub padding: VerifiedH4PaddingAlgebraBoundary,
    pub masked_source_functionals: H4MaskedSourceFunctionalClaims,
    pub complete_mask_constraint_count: usize,
}

/// Opaque evidence for the aggregate transport/public-coin/BLSQ boundary only.
///
/// Possessing this value is not H4 proof acceptance.  Private fields prevent a
/// caller from manufacturing a success-shaped boundary without running this
/// module's verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedH4AggregatePackageV1Boundary {
    profile: H4ProofProfile,
    attempt: u16,
    aggregate_package_commitment: [u8; 64],
    statement_commitment: [u8; 64],
    schedule_commitment: [u8; 64],
    session_id: [u8; 64],
    final_transcript_root: [u8; 64],
    prechallenge_binding_commitment: [u8; 64],
    query_seed: Fp16,
    shards: Vec<VerifiedH4ShardPackageV1Boundary>,
    mask_rank: GkrMaskTensorObservationRankCertificate,
    gkr_statement_bindings: [[u8; 64]; 4],
    state_relation_source_digest: [u8; 64],
}

impl VerifiedH4AggregatePackageV1Boundary {
    pub const fn profile(&self) -> H4ProofProfile {
        self.profile
    }

    pub const fn profile_code(&self) -> u8 {
        self.profile.code()
    }

    pub const fn governed_profile_label(&self) -> &'static str {
        self.profile.governed_label()
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    pub const fn attempt(&self) -> u16 {
        self.attempt
    }

    pub const fn aggregate_package_commitment(&self) -> [u8; 64] {
        self.aggregate_package_commitment
    }

    pub const fn statement_commitment(&self) -> [u8; 64] {
        self.statement_commitment
    }

    pub const fn schedule_commitment(&self) -> [u8; 64] {
        self.schedule_commitment
    }

    pub const fn session_id(&self) -> [u8; 64] {
        self.session_id
    }

    pub const fn final_transcript_root(&self) -> [u8; 64] {
        self.final_transcript_root
    }

    pub const fn prechallenge_binding_commitment(&self) -> [u8; 64] {
        self.prechallenge_binding_commitment
    }

    pub const fn query_seed(&self) -> Fp16 {
        self.query_seed
    }

    pub const fn mask_rank(&self) -> GkrMaskTensorObservationRankCertificate {
        self.mask_rank
    }

    pub const fn gkr_statement_bindings(&self) -> [[u8; 64]; 4] {
        self.gkr_statement_bindings
    }

    /// Verifier-key-owned digest that every authenticated state-relation round
    /// was checked to bind. This is not learned from the package.
    pub const fn state_relation_source_digest(&self) -> [u8; 64] {
        self.state_relation_source_digest
    }

    pub fn complete_mask_constraint_counts(&self) -> Vec<usize> {
        self.shards
            .iter()
            .map(|shard| shard.complete_mask_constraint_count)
            .collect()
    }
}

fn derive_gkr_statement_bindings(
    profile: H4ProofProfile,
    inputs: H4GkrStatementBindingInputs,
) -> Result<[[u8; 64]; 4], H4ProofPackageV1Error> {
    let public_inputs = [
        &inputs.semantic_program_commitment,
        &inputs.descriptor_commitment,
        &inputs.semantic_port_commitment,
        &inputs.boundary_file_sha3_512,
        &inputs.gkr_plan_commitment,
    ];
    if public_inputs.into_iter().any(|value| !nonzero(value)) {
        return Err(H4ProofPackageV1Error::Identity);
    }
    let shard_count = profile.shard_count();
    let file_bytes = H4_HASH_BUS_BOUNDARY_HEADER_BYTES
        .checked_add(
            H4_HASH_BUS_BOUNDARY_BYTES_PER_SHARD
                .checked_mul(u64::from(shard_count))
                .ok_or(H4ProofPackageV1Error::Geometry)?,
        )
        .ok_or(H4ProofPackageV1Error::Geometry)?;
    let mut bindings = [[0_u8; 64]; 4];
    for shard in 0..shard_count {
        let mut hash = Sha3_512::new();
        hash.update(H4_GKR_STATEMENT_BINDING_DOMAIN);
        hash.update([profile.code(), 2_u8]);
        hash.update(inputs.semantic_program_commitment);
        hash.update(inputs.descriptor_commitment);
        hash.update(inputs.semantic_port_commitment);
        hash.update(u16::from(shard_count).to_be_bytes());
        hash.update(H4_PADDED_PERMUTATIONS_PER_SHARD.to_be_bytes());
        hash.update(H4_LIVE_WIRES_PER_PERMUTATION.to_be_bytes());
        hash.update(file_bytes.to_be_bytes());
        hash.update(inputs.boundary_file_sha3_512);
        hash.update(u16::from(shard).to_be_bytes());
        hash.update(inputs.gkr_plan_commitment);
        bindings[usize::from(shard)] = hash.finalize().into();
    }
    Ok(bindings)
}

fn nonzero(value: &[u8; 64]) -> bool {
    value.iter().any(|byte| *byte != 0)
}

fn digest64(encoded: &[u8]) -> Result<[u8; 64], H4ProofPackageV1Error> {
    encoded
        .try_into()
        .map_err(|_| H4ProofPackageV1Error::SectionLength)
}

fn u16_at(encoded: &[u8], offset: usize) -> Result<u16, H4ProofPackageV1Error> {
    Ok(u16::from_be_bytes(
        encoded
            .get(offset..offset + 2)
            .ok_or(H4ProofPackageV1Error::Length)?
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::Length)?,
    ))
}

fn u32_at(encoded: &[u8], offset: usize) -> Result<u32, H4ProofPackageV1Error> {
    Ok(u32::from_be_bytes(
        encoded
            .get(offset..offset + 4)
            .ok_or(H4ProofPackageV1Error::Length)?
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::Length)?,
    ))
}

fn u64_at(encoded: &[u8], offset: usize) -> Result<u64, H4ProofPackageV1Error> {
    Ok(u64::from_be_bytes(
        encoded
            .get(offset..offset + 8)
            .ok_or(H4ProofPackageV1Error::Length)?
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::Length)?,
    ))
}

fn pcs_hash_parts(domain: u16, parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(PCS_MAGIC);
    hash.update(PCS_VERSION.to_be_bytes());
    hash.update(domain.to_be_bytes());
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn decode_fp16(
    encoded: &[u8],
    error: H4ProofPackageV1Error,
) -> Result<Fp16, H4ProofPackageV1Error> {
    let encoded: &[u8; 64] = encoded.try_into().map_err(|_| error)?;
    Fp16::decode(encoded).map_err(|_| error)
}

fn decode_fp16_values(
    encoded: &[u8],
    error: H4ProofPackageV1Error,
) -> Result<Vec<Fp16>, H4ProofPackageV1Error> {
    if !encoded.len().is_multiple_of(64) {
        return Err(error);
    }
    encoded
        .chunks_exact(64)
        .map(|value| decode_fp16(value, error))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H4SourceCellClass {
    HashBit,
    StateLaneException,
    GlobalPadding,
}

/// Classify one packed source coefficient independently of its sixteen M31
/// components.  `global_word` is canonical boundary-major order: bit eight is
/// the boundary and the low eight bits are the high group bits.  The low
/// coefficient address contains eleven wire bits followed by five low group
/// bits.  Only wire<1600 participates in Booleanity.  Boundary-one wires
/// 1600..1663 are the documented Fp16 state lane for group<4096; every other
/// non-hash cell is required to be global zero padding.
pub fn h4_source_cell_class(
    coefficient_position: usize,
    global_word: usize,
) -> Result<H4SourceCellClass, H4ProofPackageV1Error> {
    if coefficient_position >= H4_SOURCE_COEFFICIENT_POSITIONS
        || global_word >= H4_SOURCE_GLOBAL_WORDS
    {
        return Err(H4ProofPackageV1Error::Geometry);
    }
    let wire = coefficient_position & ((1 << 11) - 1);
    if wire < usize::from(H4_LIVE_WIRES_PER_PERMUTATION) {
        return Ok(H4SourceCellClass::HashBit);
    }
    let boundary = global_word >> 8;
    let group_high = global_word & 0xff;
    let group_low = coefficient_position >> 11;
    let group = (group_high << 5) | group_low;
    if boundary == 1 && (1_600..1_664).contains(&wire) && group < 4_096 {
        return Ok(H4SourceCellClass::StateLaneException);
    }
    Ok(H4SourceCellClass::GlobalPadding)
}

fn h4_booleanity_layout_commitment(
    profile: H4ProofProfile,
) -> Result<[u8; 64], H4ProofPackageV1Error> {
    if H4_BOOLEANITY_COMPONENT_VARIABLES
        + H4_BOOLEANITY_COEFFICIENT_VARIABLES
        + H4_BOOLEANITY_WORD_VARIABLES
        != H4_BOOLEANITY_VARIABLES as usize
    {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let capacity = usize::from(profile.state_capacity());
    let layout = selected_state_composed_mask_layout(capacity)
        .map_err(|_| H4ProofPackageV1Error::Booleanity)?;
    let mask_layer =
        selected_booleanity_mask_layer(capacity).map_err(|_| H4ProofPackageV1Error::Booleanity)?;
    let layer = layout
        .layers
        .get(mask_layer)
        .ok_or(H4ProofPackageV1Error::Booleanity)?;
    let mut expected_degrees = vec![H4_BOOLEANITY_GROUP_DEGREE; H4_BOOLEANITY_VARIABLES as usize];
    expected_degrees.extend([
        H4_BOOLEANITY_SOURCE_DEGREE,
        H4_BOOLEANITY_SOURCE_DEGREE,
        H4_BOOLEANITY_W_DEGREE,
    ]);
    if mask_layer + 2 != layout.layers.len()
        || layer.variable_degrees != expected_degrees
        || layout.padded_coefficients != 32_768
        || layout.used_coefficients > layout.padded_coefficients
        || mask_layer > 0 && layout.layers[mask_layer - 1].layer_offset + 9 != layer.bridge_offset
    {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let mut hash = Sha3_512::new();
    hash.update(BOOLEANITY_LAYOUT_DOMAIN);
    hash.update(H4_BOOLEANITY_GRAMMAR_VERSION.to_be_bytes());
    hash.update([profile.code()]);
    hash.update((H4_BOOLEANITY_COMPONENT_VARIABLES as u16).to_be_bytes());
    hash.update((H4_BOOLEANITY_COEFFICIENT_VARIABLES as u16).to_be_bytes());
    hash.update((H4_BOOLEANITY_WORD_VARIABLES as u16).to_be_bytes());
    hash.update(H4_LIVE_WIRES_PER_PERMUTATION.to_be_bytes());
    hash.update((1_600_u16).to_be_bytes());
    hash.update((1_664_u16).to_be_bytes());
    hash.update((4_096_u16).to_be_bytes());
    hash.update(
        u32::try_from(mask_layer)
            .map_err(|_| H4ProofPackageV1Error::Booleanity)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(layer.bridge_offset)
            .map_err(|_| H4ProofPackageV1Error::Booleanity)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(layer.sumcheck_offset)
            .map_err(|_| H4ProofPackageV1Error::Booleanity)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(layer.layer_offset)
            .map_err(|_| H4ProofPackageV1Error::Booleanity)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(layout.used_coefficients)
            .map_err(|_| H4ProofPackageV1Error::Booleanity)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(layout.padded_coefficients)
            .map_err(|_| H4ProofPackageV1Error::Booleanity)?
            .to_be_bytes(),
    );
    for degree in expected_degrees {
        hash.update([u8::try_from(degree).map_err(|_| H4ProofPackageV1Error::Booleanity)?]);
    }
    Ok(hash.finalize().into())
}

fn h4_padding_layout_commitment(
    profile: H4ProofProfile,
) -> Result<[u8; 64], H4ProofPackageV1Error> {
    if H4_BOOLEANITY_COMPONENT_VARIABLES
        + H4_BOOLEANITY_COEFFICIENT_VARIABLES
        + H4_BOOLEANITY_WORD_VARIABLES
        != H4_PADDING_VARIABLES as usize
    {
        return Err(H4ProofPackageV1Error::Padding);
    }
    let capacity = usize::from(profile.state_capacity());
    let layout = selected_state_composed_mask_layout(capacity)
        .map_err(|_| H4ProofPackageV1Error::Padding)?;
    let mask_layer =
        selected_padding_mask_layer(capacity).map_err(|_| H4ProofPackageV1Error::Padding)?;
    let layer = layout
        .layers
        .get(mask_layer)
        .ok_or(H4ProofPackageV1Error::Padding)?;
    let expected_degrees = vec![2; H4_PADDING_VARIABLES as usize];
    if mask_layer + 1 != layout.layers.len()
        || layer.variable_degrees != expected_degrees
        || layout.padded_coefficients != 32_768
        || layout.used_coefficients > layout.padded_coefficients
        || mask_layer == 0
        || layout.layers[mask_layer - 1].layer_offset + 9 != layer.bridge_offset
    {
        return Err(H4ProofPackageV1Error::Padding);
    }
    let mut hash = Sha3_512::new();
    hash.update(b"BL/PQ512/WAVE2/H4-SOURCE-PADDING-LAYOUT/v1\0");
    hash.update(H4_PADDING_GRAMMAR_VERSION.to_be_bytes());
    hash.update([profile.code()]);
    hash.update((H4_BOOLEANITY_COMPONENT_VARIABLES as u16).to_be_bytes());
    hash.update((H4_BOOLEANITY_COEFFICIENT_VARIABLES as u16).to_be_bytes());
    hash.update((H4_BOOLEANITY_WORD_VARIABLES as u16).to_be_bytes());
    hash.update(H4_LIVE_WIRES_PER_PERMUTATION.to_be_bytes());
    hash.update((1_600_u16).to_be_bytes());
    hash.update((1_664_u16).to_be_bytes());
    hash.update((2_048_u16).to_be_bytes());
    hash.update((4_096_u16).to_be_bytes());
    hash.update([1, H4_MASKED_SOURCE_FUNCTIONAL_PADDING_TAG]);
    hash.update(
        u32::try_from(mask_layer)
            .map_err(|_| H4ProofPackageV1Error::Padding)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(layer.bridge_offset)
            .map_err(|_| H4ProofPackageV1Error::Padding)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(layer.sumcheck_offset)
            .map_err(|_| H4ProofPackageV1Error::Padding)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(layer.layer_offset)
            .map_err(|_| H4ProofPackageV1Error::Padding)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(layout.used_coefficients)
            .map_err(|_| H4ProofPackageV1Error::Padding)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(layout.padded_coefficients)
            .map_err(|_| H4ProofPackageV1Error::Padding)?
            .to_be_bytes(),
    );
    hash.update([2_u8; H4_PADDING_VARIABLES as usize]);
    Ok(hash.finalize().into())
}

pub fn h4_booleanity_prelude_message(
    profile: H4ProofProfile,
    shard_index: u8,
    source_root: [u8; 64],
    mask_tensor_root: [u8; 64],
    statement_binding: [u8; 64],
) -> Result<Vec<u8>, H4ProofPackageV1Error> {
    if shard_index >= profile.shard_count()
        || !nonzero(&source_root)
        || !nonzero(&mask_tensor_root)
        || !nonzero(&statement_binding)
    {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let mut message = Vec::with_capacity(H4_BOOLEANITY_PRELUDE_BYTES);
    message.extend_from_slice(H4_BOOLEANITY_PRELUDE_MAGIC);
    message.extend_from_slice(&H4_BOOLEANITY_GRAMMAR_VERSION.to_be_bytes());
    message.extend_from_slice(&[profile.code(), shard_index]);
    message.extend_from_slice(&(H4_BOOLEANITY_VARIABLES as u16).to_be_bytes());
    message.extend_from_slice(&[
        H4_BOOLEANITY_SOURCE_DEGREE as u8,
        H4_BOOLEANITY_W_DEGREE as u8,
    ]);
    message.extend_from_slice(&source_root);
    message.extend_from_slice(&mask_tensor_root);
    message.extend_from_slice(&statement_binding);
    message.extend_from_slice(&h4_booleanity_layout_commitment(profile)?);
    debug_assert_eq!(message.len(), H4_BOOLEANITY_PRELUDE_BYTES);
    Ok(message)
}

pub fn h4_booleanity_round_message(
    round: usize,
    coefficients: &[Fp16],
) -> Result<Vec<u8>, H4ProofPackageV1Error> {
    let nonterminal_rounds = H4_BOOLEANITY_VARIABLES as usize + 2;
    if round >= nonterminal_rounds {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let (phase, degree) = if round < H4_BOOLEANITY_VARIABLES as usize {
        (0_u8, H4_BOOLEANITY_GROUP_DEGREE)
    } else if round == H4_BOOLEANITY_VARIABLES as usize {
        (1_u8, H4_BOOLEANITY_SOURCE_DEGREE)
    } else {
        (2_u8, H4_BOOLEANITY_SOURCE_DEGREE)
    };
    if coefficients.len() != degree + 1 {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let expected_bytes = if degree == H4_BOOLEANITY_SOURCE_DEGREE {
        H4_BOOLEANITY_QUINTIC_ROUND_BYTES
    } else {
        H4_BOOLEANITY_CUBIC_ROUND_BYTES
    };
    let mut message = Vec::with_capacity(expected_bytes);
    message.extend_from_slice(H4_BOOLEANITY_ROUND_MAGIC);
    message.extend_from_slice(&H4_BOOLEANITY_GRAMMAR_VERSION.to_be_bytes());
    message.extend_from_slice(
        &u16::try_from(round)
            .map_err(|_| H4ProofPackageV1Error::Booleanity)?
            .to_be_bytes(),
    );
    message.push(u8::try_from(degree).map_err(|_| H4ProofPackageV1Error::Booleanity)?);
    message.push(phase);
    message.extend_from_slice(&[0_u8; 2]);
    for coefficient in coefficients {
        message.extend_from_slice(&coefficient.encode());
    }
    debug_assert_eq!(message.len(), expected_bytes);
    Ok(message)
}

pub fn h4_booleanity_transcript_commitment(
    profile: H4ProofProfile,
    shard_index: u8,
    prelude_message: &[u8],
    prelude_outputs: &[Fp16],
    round_messages: &[&[u8]],
    round_challenges: &[Fp16],
) -> Result<[u8; 64], H4ProofPackageV1Error> {
    if prelude_outputs.len() != 1 + H4_BOOLEANITY_VARIABLES as usize
        || round_messages.len() != H4_BOOLEANITY_VARIABLES as usize + 2
        || round_challenges.len() != H4_BOOLEANITY_VARIABLES as usize + 2
    {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let mut hash = Sha3_512::new();
    hash.update(BOOLEANITY_TRANSCRIPT_DOMAIN);
    hash.update([profile.code(), shard_index]);
    hash.update(prelude_message);
    for output in prelude_outputs {
        hash.update(output.encode());
    }
    for (message, challenge) in round_messages.iter().zip(round_challenges) {
        hash.update(message);
        hash.update(challenge.encode());
    }
    Ok(hash.finalize().into())
}

pub fn h4_booleanity_gate_layer() -> KeccakDagLayer {
    KeccakDagLayer {
        left_source: KeccakDagSource::RoundInput,
        right_source: KeccakDagSource::RoundInput,
        left_width: 2,
        right_width: 2,
        raw_width: 1,
        padded_width: 1,
        gates: vec![KeccakDagGate {
            left: 0,
            right: 0,
            kind: KeccakDagGateKind::Multiply,
        }],
    }
}

pub fn h4_booleanity_terminal_message(
    profile: H4ProofProfile,
    shard_index: u8,
    source_root: [u8; 64],
    mask_tensor_root: [u8; 64],
    transcript_commitment: [u8; 64],
    w_coefficients: [Fp16; 3],
    masked_terminal_left: Fp16,
    masked_terminal_right: Fp16,
) -> Result<Vec<u8>, H4ProofPackageV1Error> {
    if shard_index >= profile.shard_count()
        || !nonzero(&source_root)
        || !nonzero(&mask_tensor_root)
        || !nonzero(&transcript_commitment)
    {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let mut message = Vec::with_capacity(H4_BOOLEANITY_TERMINAL_BYTES);
    message.extend_from_slice(H4_BOOLEANITY_TERMINAL_MAGIC);
    message.extend_from_slice(&H4_BOOLEANITY_GRAMMAR_VERSION.to_be_bytes());
    message.extend_from_slice(&[profile.code(), shard_index]);
    message.extend_from_slice(&(H4_BOOLEANITY_VARIABLES as u16).to_be_bytes());
    message.extend_from_slice(&[1, 1]);
    message.extend_from_slice(&[
        H4_BOOLEANITY_W_DEGREE as u8,
        H4_MASKED_SOURCE_FUNCTIONAL_BOOLEANITY_TAG,
    ]);
    message.extend_from_slice(&[0_u8; 6]);
    message.extend_from_slice(&source_root);
    message.extend_from_slice(&mask_tensor_root);
    message.extend_from_slice(&h4_booleanity_layout_commitment(profile)?);
    message.extend_from_slice(&transcript_commitment);
    for coefficient in w_coefficients {
        message.extend_from_slice(&coefficient.encode());
    }
    message.extend_from_slice(&masked_terminal_left.encode());
    message.extend_from_slice(&masked_terminal_right.encode());
    debug_assert_eq!(message.len(), H4_BOOLEANITY_TERMINAL_BYTES);
    Ok(message)
}

fn equality_polynomial_at(left: &[Fp16], right: &[Fp16]) -> Result<Fp16, H4ProofPackageV1Error> {
    if left.len() != right.len() || left.is_empty() {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    Ok(left
        .iter()
        .copied()
        .zip(right.iter().copied())
        .fold(Fp16::ONE, |product, (left, right)| {
            product * (left * right + (Fp16::ONE - left) * (Fp16::ONE - right))
        }))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_h4_booleanity_algebra_boundary(
    profile: H4ProofProfile,
    shard_index: u8,
    expected_source_root: [u8; 64],
    expected_mask_tensor_root: [u8; 64],
    expected_statement_binding: [u8; 64],
    prelude_message: &[u8],
    prelude_outputs: &[Fp16],
    round_messages: &[&[u8]],
    round_challenges: &[Fp16],
    terminal_message: &[u8],
    terminal_binding_challenge: Fp16,
) -> Result<VerifiedH4BooleanityAlgebraBoundary, H4ProofPackageV1Error> {
    let nonterminal_rounds = H4_BOOLEANITY_VARIABLES as usize + 2;
    if prelude_message
        != h4_booleanity_prelude_message(
            profile,
            shard_index,
            expected_source_root,
            expected_mask_tensor_root,
            expected_statement_binding,
        )?
        || prelude_outputs.len() != 1 + H4_BOOLEANITY_VARIABLES as usize
        || prelude_outputs[0].is_zero()
        || round_messages.len() != nonterminal_rounds
        || round_challenges.len() != nonterminal_rounds
        || round_challenges
            .iter()
            .any(|challenge| challenge.is_zero() || *challenge == Fp16::ONE)
        || terminal_binding_challenge.is_zero()
        || terminal_binding_challenge == Fp16::ONE
    {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let rho = prelude_outputs[0];
    let equality_point: [Fp16; 29] = prelude_outputs[1..]
        .try_into()
        .map_err(|_| H4ProofPackageV1Error::Booleanity)?;
    let group_point: [Fp16; 29] = round_challenges[..H4_BOOLEANITY_VARIABLES as usize]
        .try_into()
        .map_err(|_| H4ProofPackageV1Error::Booleanity)?;
    let left_challenge = round_challenges[H4_BOOLEANITY_VARIABLES as usize];
    let right_challenge = round_challenges[H4_BOOLEANITY_VARIABLES as usize + 1];

    let mut initial_masked_claim = None;
    let mut current = Fp16::ZERO;
    for (round, (message, challenge)) in round_messages
        .iter()
        .copied()
        .zip(round_challenges.iter().copied())
        .enumerate()
    {
        let (phase, degree) = if round < H4_BOOLEANITY_VARIABLES as usize {
            (0_u8, H4_BOOLEANITY_GROUP_DEGREE)
        } else if round == H4_BOOLEANITY_VARIABLES as usize {
            (1_u8, H4_BOOLEANITY_SOURCE_DEGREE)
        } else {
            (2_u8, H4_BOOLEANITY_SOURCE_DEGREE)
        };
        let expected_bytes = if degree == H4_BOOLEANITY_SOURCE_DEGREE {
            H4_BOOLEANITY_QUINTIC_ROUND_BYTES
        } else {
            H4_BOOLEANITY_CUBIC_ROUND_BYTES
        };
        if message.len() != expected_bytes
            || message.get(..8) != Some(H4_BOOLEANITY_ROUND_MAGIC)
            || u16_at(message, 8)? != H4_BOOLEANITY_GRAMMAR_VERSION
            || usize::from(u16_at(message, 10)?) != round
            || usize::from(message[12]) != degree
            || message[13] != phase
            || message[14..16] != [0_u8; 2]
        {
            return Err(H4ProofPackageV1Error::Booleanity);
        }
        let coefficients = decode_fp16_values(&message[16..], H4ProofPackageV1Error::Booleanity)?;
        if coefficients.len() != degree + 1 {
            return Err(H4ProofPackageV1Error::Booleanity);
        }
        let boolean_sum =
            polynomial_eval(&coefficients, Fp16::ZERO) + polynomial_eval(&coefficients, Fp16::ONE);
        if round == 0 {
            initial_masked_claim = Some(boolean_sum);
        } else if boolean_sum != current {
            return Err(H4ProofPackageV1Error::Booleanity);
        }
        current = polynomial_eval(&coefficients, challenge);
    }

    let transcript_commitment = h4_booleanity_transcript_commitment(
        profile,
        shard_index,
        prelude_message,
        prelude_outputs,
        round_messages,
        round_challenges,
    )?;
    if terminal_message.len() != H4_BOOLEANITY_TERMINAL_BYTES
        || terminal_message.get(..8) != Some(H4_BOOLEANITY_TERMINAL_MAGIC)
        || u16_at(terminal_message, 8)? != H4_BOOLEANITY_GRAMMAR_VERSION
        || terminal_message[10] != profile.code()
        || terminal_message[11] != shard_index
        || usize::from(u16_at(terminal_message, 12)?) != H4_BOOLEANITY_VARIABLES as usize
        || terminal_message[14..16] != [1, 1]
        || usize::from(terminal_message[16]) != H4_BOOLEANITY_W_DEGREE
        || terminal_message[17] != H4_MASKED_SOURCE_FUNCTIONAL_BOOLEANITY_TAG
        || terminal_message[18..24] != [0_u8; 6]
        || terminal_message[24..88] != expected_source_root
        || terminal_message[88..152] != expected_mask_tensor_root
        || terminal_message[152..216] != h4_booleanity_layout_commitment(profile)?
        || terminal_message[216..280] != transcript_commitment
    {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let w_coefficients = decode_fp16_values(
        &terminal_message[280..472],
        H4ProofPackageV1Error::Booleanity,
    )?;
    if w_coefficients.len() != H4_BOOLEANITY_W_DEGREE + 1
        || polynomial_eval(&w_coefficients, Fp16::ZERO)
            + polynomial_eval(&w_coefficients, Fp16::ONE)
            != current
    {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let masked_terminal_left = decode_fp16(
        &terminal_message[472..536],
        H4ProofPackageV1Error::Booleanity,
    )?;
    let masked_terminal_right = decode_fp16(
        &terminal_message[536..600],
        H4ProofPackageV1Error::Booleanity,
    )?;
    let topology = h4_booleanity_gate_layer();
    let terminal_gate = shared_group_terminal_gate_claim(
        &topology,
        1_usize << H4_BOOLEANITY_VARIABLES,
        &[LayerOutputClaim {
            point: equality_point.to_vec(),
            value: Fp16::ZERO,
            coefficient: Fp16::ONE,
        }],
        &group_point,
        &[left_challenge, right_challenge],
        masked_terminal_left,
        masked_terminal_right,
    )
    .map_err(|_| H4ProofPackageV1Error::Booleanity)?;
    let terminal_residual = polynomial_eval(&w_coefficients, terminal_binding_challenge)
        - (Fp16::ONE - terminal_binding_challenge) * terminal_gate;
    let mask_layer = selected_booleanity_mask_layer(usize::from(profile.state_capacity()))
        .map_err(|_| H4ProofPackageV1Error::Booleanity)?;
    let mut full_point = group_point.to_vec();
    full_point.extend([left_challenge, right_challenge, terminal_binding_challenge]);
    let mask_constraints = vec![
        UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::SumcheckBooleanSum {
                layer: mask_layer,
                scale: rho,
            }],
            residual: initial_masked_claim.ok_or(H4ProofPackageV1Error::Booleanity)?,
        },
        UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::SumcheckEvaluation {
                layer: mask_layer,
                point: full_point,
                scale: rho,
            }],
            residual: terminal_residual,
        },
    ];
    debug_assert_eq!(mask_constraints.len(), H4_BOOLEANITY_MASK_CONSTRAINTS);
    Ok(VerifiedH4BooleanityAlgebraBoundary {
        source_root: expected_source_root,
        mask_tensor_root: expected_mask_tensor_root,
        mask_layer,
        equality_point,
        group_point,
        left_challenge,
        right_challenge,
        w_challenge: terminal_binding_challenge,
        masked_terminal_left,
        masked_terminal_right,
        transcript_commitment,
        mask_constraints,
    })
}

pub fn h4_padding_prelude_message(
    profile: H4ProofProfile,
    shard_index: u8,
    source_root: [u8; 64],
    mask_tensor_root: [u8; 64],
    statement_binding: [u8; 64],
) -> Result<Vec<u8>, H4ProofPackageV1Error> {
    if shard_index >= profile.shard_count()
        || !nonzero(&source_root)
        || !nonzero(&mask_tensor_root)
        || !nonzero(&statement_binding)
    {
        return Err(H4ProofPackageV1Error::Padding);
    }
    let mut message = Vec::with_capacity(H4_PADDING_PRELUDE_BYTES);
    message.extend_from_slice(H4_PADDING_PRELUDE_MAGIC);
    message.extend_from_slice(&H4_PADDING_GRAMMAR_VERSION.to_be_bytes());
    message.extend_from_slice(&[profile.code(), shard_index]);
    message.extend_from_slice(&(H4_PADDING_VARIABLES as u16).to_be_bytes());
    message.extend_from_slice(&[2, H4_MASKED_SOURCE_FUNCTIONAL_PADDING_TAG]);
    message.extend_from_slice(&source_root);
    message.extend_from_slice(&mask_tensor_root);
    message.extend_from_slice(&statement_binding);
    message.extend_from_slice(&h4_padding_layout_commitment(profile)?);
    debug_assert_eq!(message.len(), H4_PADDING_PRELUDE_BYTES);
    Ok(message)
}

pub fn h4_padding_round_message(
    round: usize,
    coefficients: [Fp16; 3],
) -> Result<Vec<u8>, H4ProofPackageV1Error> {
    if round >= H4_PADDING_VARIABLES as usize {
        return Err(H4ProofPackageV1Error::Padding);
    }
    let mut message = Vec::with_capacity(H4_PADDING_ROUND_BYTES);
    message.extend_from_slice(H4_PADDING_ROUND_MAGIC);
    message.extend_from_slice(&H4_PADDING_GRAMMAR_VERSION.to_be_bytes());
    message.extend_from_slice(
        &u16::try_from(round)
            .map_err(|_| H4ProofPackageV1Error::Padding)?
            .to_be_bytes(),
    );
    message.extend_from_slice(&[2, H4_MASKED_SOURCE_FUNCTIONAL_PADDING_TAG, 0, 0]);
    for coefficient in coefficients {
        message.extend_from_slice(&coefficient.encode());
    }
    debug_assert_eq!(message.len(), H4_PADDING_ROUND_BYTES);
    Ok(message)
}

pub fn h4_padding_transcript_commitment(
    profile: H4ProofProfile,
    shard_index: u8,
    prelude_message: &[u8],
    prelude_outputs: &[Fp16],
    round_messages: &[&[u8]],
    round_challenges: &[Fp16],
) -> Result<[u8; 64], H4ProofPackageV1Error> {
    if prelude_outputs.len() != 1 + H4_PADDING_VARIABLES as usize
        || round_messages.len() != H4_PADDING_VARIABLES as usize
        || round_challenges.len() != H4_PADDING_VARIABLES as usize
    {
        return Err(H4ProofPackageV1Error::Padding);
    }
    let mut hash = Sha3_512::new();
    hash.update(PADDING_TRANSCRIPT_DOMAIN);
    hash.update([profile.code(), shard_index]);
    hash.update(prelude_message);
    for output in prelude_outputs {
        hash.update(output.encode());
    }
    for (message, challenge) in round_messages.iter().zip(round_challenges) {
        hash.update(message);
        hash.update(challenge.encode());
    }
    Ok(hash.finalize().into())
}

pub fn h4_padding_terminal_message(
    profile: H4ProofProfile,
    shard_index: u8,
    source_root: [u8; 64],
    mask_tensor_root: [u8; 64],
    transcript_commitment: [u8; 64],
    masked_terminal: Fp16,
) -> Result<Vec<u8>, H4ProofPackageV1Error> {
    if shard_index >= profile.shard_count()
        || !nonzero(&source_root)
        || !nonzero(&mask_tensor_root)
        || !nonzero(&transcript_commitment)
    {
        return Err(H4ProofPackageV1Error::Padding);
    }
    let mut message = Vec::with_capacity(H4_PADDING_TERMINAL_BYTES);
    message.extend_from_slice(H4_PADDING_TERMINAL_MAGIC);
    message.extend_from_slice(&H4_PADDING_GRAMMAR_VERSION.to_be_bytes());
    message.extend_from_slice(&[profile.code(), shard_index]);
    message.extend_from_slice(&(H4_PADDING_VARIABLES as u16).to_be_bytes());
    message.extend_from_slice(&[2, H4_MASKED_SOURCE_FUNCTIONAL_PADDING_TAG]);
    message.extend_from_slice(&source_root);
    message.extend_from_slice(&mask_tensor_root);
    message.extend_from_slice(&h4_padding_layout_commitment(profile)?);
    message.extend_from_slice(&transcript_commitment);
    message.extend_from_slice(&masked_terminal.encode());
    debug_assert_eq!(message.len(), H4_PADDING_TERMINAL_BYTES);
    Ok(message)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_h4_padding_algebra_boundary(
    profile: H4ProofProfile,
    shard_index: u8,
    expected_source_root: [u8; 64],
    expected_mask_tensor_root: [u8; 64],
    expected_statement_binding: [u8; 64],
    prelude_message: &[u8],
    prelude_outputs: &[Fp16],
    round_messages: &[&[u8]],
    round_challenges: &[Fp16],
    terminal_message: &[u8],
    functional_mixing_challenge: Fp16,
) -> Result<VerifiedH4PaddingAlgebraBoundary, H4ProofPackageV1Error> {
    if prelude_message
        != h4_padding_prelude_message(
            profile,
            shard_index,
            expected_source_root,
            expected_mask_tensor_root,
            expected_statement_binding,
        )?
        || prelude_outputs.len() != 1 + H4_PADDING_VARIABLES as usize
        || prelude_outputs[0].is_zero()
        || round_messages.len() != H4_PADDING_VARIABLES as usize
        || round_challenges.len() != H4_PADDING_VARIABLES as usize
        || round_challenges
            .iter()
            .any(|challenge| challenge.is_zero() || *challenge == Fp16::ONE)
        || functional_mixing_challenge.is_zero()
    {
        return Err(H4ProofPackageV1Error::Padding);
    }
    let rho = prelude_outputs[0];
    let equality_point: [Fp16; 29] = prelude_outputs[1..]
        .try_into()
        .map_err(|_| H4ProofPackageV1Error::Padding)?;
    let sumcheck_point: [Fp16; 29] = round_challenges
        .try_into()
        .map_err(|_| H4ProofPackageV1Error::Padding)?;
    let mut initial_masked_claim = None;
    let mut current = Fp16::ZERO;
    for (round, ((message, challenge), expected_message)) in round_messages
        .iter()
        .copied()
        .zip(round_challenges.iter().copied())
        .zip(0..H4_PADDING_VARIABLES as usize)
        .enumerate()
    {
        if round != expected_message
            || message.len() != H4_PADDING_ROUND_BYTES
            || message.get(..8) != Some(H4_PADDING_ROUND_MAGIC)
            || u16_at(message, 8)? != H4_PADDING_GRAMMAR_VERSION
            || usize::from(u16_at(message, 10)?) != round
            || message[12..16] != [2, H4_MASKED_SOURCE_FUNCTIONAL_PADDING_TAG, 0, 0]
        {
            return Err(H4ProofPackageV1Error::Padding);
        }
        let coefficients = decode_fp16_values(&message[16..], H4ProofPackageV1Error::Padding)?;
        if coefficients.len() != 3 {
            return Err(H4ProofPackageV1Error::Padding);
        }
        let boolean_sum =
            polynomial_eval(&coefficients, Fp16::ZERO) + polynomial_eval(&coefficients, Fp16::ONE);
        if round == 0 {
            initial_masked_claim = Some(boolean_sum);
        } else if boolean_sum != current {
            return Err(H4ProofPackageV1Error::Padding);
        }
        current = polynomial_eval(&coefficients, challenge);
    }
    let transcript_commitment = h4_padding_transcript_commitment(
        profile,
        shard_index,
        prelude_message,
        prelude_outputs,
        round_messages,
        round_challenges,
    )?;
    if terminal_message.len() != H4_PADDING_TERMINAL_BYTES
        || terminal_message.get(..8) != Some(H4_PADDING_TERMINAL_MAGIC)
        || u16_at(terminal_message, 8)? != H4_PADDING_GRAMMAR_VERSION
        || terminal_message[10] != profile.code()
        || terminal_message[11] != shard_index
        || usize::from(u16_at(terminal_message, 12)?) != H4_PADDING_VARIABLES as usize
        || terminal_message[14..16] != [2, H4_MASKED_SOURCE_FUNCTIONAL_PADDING_TAG]
        || terminal_message[16..80] != expected_source_root
        || terminal_message[80..144] != expected_mask_tensor_root
        || terminal_message[144..208] != h4_padding_layout_commitment(profile)?
        || terminal_message[208..272] != transcript_commitment
    {
        return Err(H4ProofPackageV1Error::Padding);
    }
    let masked_terminal = decode_fp16(&terminal_message[272..336], H4ProofPackageV1Error::Padding)?;
    let equality = equality_polynomial_at(&equality_point, &sumcheck_point)
        .map_err(|_| H4ProofPackageV1Error::Padding)?;
    let mask_layer = selected_padding_mask_layer(usize::from(profile.state_capacity()))
        .map_err(|_| H4ProofPackageV1Error::Padding)?;
    let mask_constraints = vec![
        UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::SumcheckBooleanSum {
                layer: mask_layer,
                scale: rho,
            }],
            residual: initial_masked_claim.ok_or(H4ProofPackageV1Error::Padding)?,
        },
        UniformGkrMaskConstraint {
            functionals: vec![
                UniformGkrMaskFunctional::SumcheckEvaluation {
                    layer: mask_layer,
                    point: sumcheck_point.to_vec(),
                    scale: rho,
                },
                UniformGkrMaskFunctional::LayerBooleanSum {
                    layer: mask_layer,
                    z_first: sumcheck_point[0],
                    scale: -equality * boolean_vanishing(&sumcheck_point),
                },
            ],
            residual: current - equality * masked_terminal,
        },
    ];
    debug_assert_eq!(mask_constraints.len(), H4_PADDING_MASK_CONSTRAINTS);
    Ok(VerifiedH4PaddingAlgebraBoundary {
        source_root: expected_source_root,
        mask_tensor_root: expected_mask_tensor_root,
        mask_layer,
        equality_point,
        sumcheck_point,
        masked_terminal,
        functional_mixing_challenge,
        transcript_commitment,
        mask_constraints,
    })
}

#[derive(Clone, Copy)]
enum H4LowSourceSelector {
    Hash,
    NonHash,
    StateLane,
}

fn h4_component_equality_weights(
    component_point: &[Fp16],
) -> Result<[Fp16; 16], H4ProofPackageV1Error> {
    let component_weights = multilinear_weights(component_point)?;
    if component_weights.len() != 1 << H4_BOOLEANITY_COMPONENT_VARIABLES {
        return Err(H4ProofPackageV1Error::Functional);
    }
    Ok(component_weights
        .try_into()
        .map_err(|_| H4ProofPackageV1Error::Functional)?)
}

fn h4_packed_node_mle(
    packed: Fp16,
    component_weights: &[Fp16; 16],
) -> Result<Fp16, H4ProofPackageV1Error> {
    packed
        .coefficients()
        .into_iter()
        .zip(component_weights.iter().copied())
        .try_fold(Fp16::ZERO, |sum, (coefficient, weight)| {
            let coefficient =
                M31::from_canonical(coefficient).map_err(|_| H4ProofPackageV1Error::Functional)?;
            Ok(sum + weight * Fp16::from_m31(coefficient))
        })
}

fn h4_low_source_answer_functional(
    main: &[Fp16],
    component_point: &[Fp16],
    coefficient_point: &[Fp16],
    selector: H4LowSourceSelector,
) -> Result<Fp16, H4ProofPackageV1Error> {
    if main.len() < H4_SOURCE_COEFFICIENT_POSITIONS
        || component_point.len() != H4_BOOLEANITY_COMPONENT_VARIABLES
        || coefficient_point.len() != H4_BOOLEANITY_COEFFICIENT_VARIABLES
    {
        return Err(H4ProofPackageV1Error::Functional);
    }
    let component_weights = h4_component_equality_weights(component_point)?;
    let coefficient_weights = multilinear_weights(coefficient_point)?;
    main[..H4_SOURCE_COEFFICIENT_POSITIONS]
        .iter()
        .copied()
        .zip(coefficient_weights)
        .enumerate()
        .try_fold(Fp16::ZERO, |sum, (position, (packed, equality))| {
            let wire = position & ((1 << 11) - 1);
            let selected = match selector {
                H4LowSourceSelector::Hash => wire < 1_600,
                H4LowSourceSelector::NonHash => wire >= 1_600,
                H4LowSourceSelector::StateLane => (1_600..1_664).contains(&wire),
            };
            if selected {
                Ok(sum + equality * h4_packed_node_mle(packed, &component_weights)?)
            } else {
                Ok(sum)
            }
        })
}

fn h4_high_cross_functional(
    row_challenges: &[Fp16],
    point: &[Fp16],
    state_lane_exception_only: bool,
) -> Result<Fp16, H4ProofPackageV1Error> {
    h4_high_cross_functional_with_complement(row_challenges, point, state_lane_exception_only, None)
}

fn h4_high_cross_functional_with_complement(
    row_challenges: &[Fp16],
    point: &[Fp16],
    state_lane_exception_only: bool,
    complement_coordinate: Option<usize>,
) -> Result<Fp16, H4ProofPackageV1Error> {
    if row_challenges.len() != H4_BOOLEANITY_WORD_VARIABLES
        || point.len() != H4_BOOLEANITY_WORD_VARIABLES
        || complement_coordinate
            .is_some_and(|coordinate| coordinate >= H4_BOOLEANITY_WORD_VARIABLES)
    {
        return Err(H4ProofPackageV1Error::Functional);
    }
    let mut mapped_row_challenges = [Fp16::ZERO; H4_BOOLEANITY_WORD_VARIABLES];
    mapped_row_challenges.copy_from_slice(row_challenges);
    if let Some(coordinate) = complement_coordinate {
        mapped_row_challenges[coordinate] = Fp16::ONE - mapped_row_challenges[coordinate];
    }
    let row_weights = multilinear_weights(&mapped_row_challenges)?;
    let point_weights = multilinear_weights(point)?;
    Ok(row_weights
        .into_iter()
        .zip(point_weights)
        .enumerate()
        .filter(|(global_word, _)| {
            !state_lane_exception_only || (*global_word >> 8 == 1 && (*global_word & 0xff) < 128)
        })
        .fold(Fp16::ZERO, |sum, (_, (row, point))| sum + row * point))
}

fn h4_booleanity_source_answer_functional(
    main: &[Fp16],
    row_challenges: &[Fp16],
    point: &[Fp16; 29],
    selected_boundary_to_canonical: bool,
) -> Result<Fp16, H4ProofPackageV1Error> {
    let complement_coordinate =
        selected_boundary_to_canonical.then_some(H4_BOOLEANITY_WORD_VARIABLES - 1);
    h4_booleanity_source_answer_functional_with_complement(
        main,
        row_challenges,
        point,
        complement_coordinate,
    )
}

fn h4_booleanity_source_answer_functional_with_complement(
    main: &[Fp16],
    row_challenges: &[Fp16],
    point: &[Fp16; 29],
    complement_coordinate: Option<usize>,
) -> Result<Fp16, H4ProofPackageV1Error> {
    let low = h4_low_source_answer_functional(
        main,
        &point[..H4_BOOLEANITY_COMPONENT_VARIABLES],
        &point[H4_BOOLEANITY_COMPONENT_VARIABLES
            ..H4_BOOLEANITY_COMPONENT_VARIABLES + H4_BOOLEANITY_COEFFICIENT_VARIABLES],
        H4LowSourceSelector::Hash,
    )?;
    let high_point =
        &point[H4_BOOLEANITY_COMPONENT_VARIABLES + H4_BOOLEANITY_COEFFICIENT_VARIABLES..];
    let high = h4_high_cross_functional_with_complement(
        row_challenges,
        high_point,
        false,
        complement_coordinate,
    )?;
    Ok(low * high)
}

fn h4_padding_source_answer_functional(
    main: &[Fp16],
    row_challenges: &[Fp16],
    point: &[Fp16; 29],
) -> Result<Fp16, H4ProofPackageV1Error> {
    h4_padding_source_answer_functional_with_complement(main, row_challenges, point, None)
}

fn h4_padding_source_answer_functional_with_complement(
    main: &[Fp16],
    row_challenges: &[Fp16],
    point: &[Fp16; 29],
    complement_coordinate: Option<usize>,
) -> Result<Fp16, H4ProofPackageV1Error> {
    let component = &point[..H4_BOOLEANITY_COMPONENT_VARIABLES];
    let coefficient = &point[H4_BOOLEANITY_COMPONENT_VARIABLES
        ..H4_BOOLEANITY_COMPONENT_VARIABLES + H4_BOOLEANITY_COEFFICIENT_VARIABLES];
    let high_point =
        &point[H4_BOOLEANITY_COMPONENT_VARIABLES + H4_BOOLEANITY_COEFFICIENT_VARIABLES..];
    let high_nonhash = h4_high_cross_functional_with_complement(
        row_challenges,
        high_point,
        false,
        complement_coordinate,
    )?;
    let nonhash = h4_low_source_answer_functional(
        main,
        component,
        coefficient,
        H4LowSourceSelector::NonHash,
    )? * high_nonhash;
    let high_exception = h4_high_cross_functional_with_complement(
        row_challenges,
        high_point,
        true,
        complement_coordinate,
    )?;
    let exception = h4_low_source_answer_functional(
        main,
        component,
        coefficient,
        H4LowSourceSelector::StateLane,
    )? * high_exception;
    Ok(nonhash - exception)
}

impl H4MaskedSourceFunctionalBinding {
    pub fn from_verified_boundaries(
        profile: H4ProofProfile,
        booleanity: &VerifiedH4BooleanityAlgebraBoundary,
        padding: &VerifiedH4PaddingAlgebraBoundary,
        complete_mask_challenge: Fp16,
    ) -> Result<Self, H4ProofPackageV1Error> {
        let capacity = usize::from(profile.state_capacity());
        if complete_mask_challenge.is_zero()
            || booleanity.source_root != padding.source_root
            || booleanity.mask_tensor_root != padding.mask_tensor_root
            || booleanity.mask_layer
                != selected_booleanity_mask_layer(capacity)
                    .map_err(|_| H4ProofPackageV1Error::Functional)?
            || padding.mask_layer
                != selected_padding_mask_layer(capacity)
                    .map_err(|_| H4ProofPackageV1Error::Functional)?
            || !nonzero(&booleanity.source_root)
            || !nonzero(&booleanity.mask_tensor_root)
            || !nonzero(&booleanity.transcript_commitment)
            || !nonzero(&padding.transcript_commitment)
        {
            return Err(H4ProofPackageV1Error::Functional);
        }
        Ok(Self {
            profile,
            source_root: booleanity.source_root,
            mask_tensor_root: booleanity.mask_tensor_root,
            booleanity_transcript_commitment: booleanity.transcript_commitment,
            booleanity_group_point: booleanity.group_point,
            booleanity_left_challenge: booleanity.left_challenge,
            booleanity_right_challenge: booleanity.right_challenge,
            booleanity_w_challenge: booleanity.w_challenge,
            booleanity_masked_terminal_left: booleanity.masked_terminal_left,
            booleanity_masked_terminal_right: booleanity.masked_terminal_right,
            padding_transcript_commitment: padding.transcript_commitment,
            padding_sumcheck_point: padding.sumcheck_point,
            padding_masked_terminal: padding.masked_terminal,
            padding_functional_mixing_challenge: padding.functional_mixing_challenge,
            complete_mask_challenge,
        })
    }

    pub const fn profile(&self) -> H4ProofProfile {
        self.profile
    }

    pub const fn source_root(&self) -> [u8; 64] {
        self.source_root
    }

    pub const fn mask_tensor_root(&self) -> [u8; 64] {
        self.mask_tensor_root
    }

    pub const fn complete_mask_challenge(&self) -> Fp16 {
        self.complete_mask_challenge
    }

    /// Diagnostic-only copies of the verifier-derived H4 points.  These
    /// accessors expose no raw source or accepting predicate state; they make
    /// the native/source and answer-target paths diffable in a bounded capture.
    pub const fn booleanity_group_point(&self) -> [Fp16; 29] {
        self.booleanity_group_point
    }

    pub const fn booleanity_left_challenge(&self) -> Fp16 {
        self.booleanity_left_challenge
    }

    pub const fn booleanity_right_challenge(&self) -> Fp16 {
        self.booleanity_right_challenge
    }

    pub const fn booleanity_w_challenge(&self) -> Fp16 {
        self.booleanity_w_challenge
    }

    pub const fn padding_sumcheck_point(&self) -> [Fp16; 29] {
        self.padding_sumcheck_point
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES);
        encoded.extend_from_slice(H4_MASKED_SOURCE_FUNCTIONAL_BINDING_MAGIC);
        encoded.extend_from_slice(&H4_MASKED_SOURCE_FUNCTIONAL_BINDING_VERSION.to_be_bytes());
        encoded.extend_from_slice(&[self.profile.code(), 2]);
        encoded.extend_from_slice(&[0_u8; 4]);
        encoded.extend_from_slice(&self.source_root);
        encoded.extend_from_slice(&self.mask_tensor_root);
        encoded.extend_from_slice(&self.booleanity_transcript_commitment);
        for coordinate in self.booleanity_group_point {
            encoded.extend_from_slice(&coordinate.encode());
        }
        for value in [
            self.booleanity_left_challenge,
            self.booleanity_right_challenge,
            self.booleanity_w_challenge,
            self.booleanity_masked_terminal_left,
            self.booleanity_masked_terminal_right,
        ] {
            encoded.extend_from_slice(&value.encode());
        }
        encoded.extend_from_slice(&self.padding_transcript_commitment);
        for coordinate in self.padding_sumcheck_point {
            encoded.extend_from_slice(&coordinate.encode());
        }
        encoded.extend_from_slice(&self.padding_masked_terminal.encode());
        encoded.extend_from_slice(&self.padding_functional_mixing_challenge.encode());
        encoded.extend_from_slice(&self.complete_mask_challenge.encode());
        let mut hash = Sha3_512::new();
        hash.update(MASKED_SOURCE_FUNCTIONAL_BINDING_DOMAIN);
        hash.update(&encoded);
        encoded.extend_from_slice(&<[u8; 64]>::from(hash.finalize()));
        debug_assert_eq!(encoded.len(), H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES);
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, H4ProofPackageV1Error> {
        if encoded.len() != H4_MASKED_SOURCE_FUNCTIONAL_BINDING_BYTES
            || encoded.get(..8) != Some(H4_MASKED_SOURCE_FUNCTIONAL_BINDING_MAGIC)
            || u16_at(encoded, 8)? != H4_MASKED_SOURCE_FUNCTIONAL_BINDING_VERSION
            || encoded[11] != 2
            || encoded[12..16] != [0_u8; 4]
        {
            return Err(H4ProofPackageV1Error::Functional);
        }
        let profile = match encoded[10] {
            1 => H4ProofProfile::K128,
            3 => H4ProofProfile::K512,
            _ => return Err(H4ProofPackageV1Error::Functional),
        };
        let expected_commitment: [u8; 64] = encoded[encoded.len() - 64..]
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::Functional)?;
        let mut hash = Sha3_512::new();
        hash.update(MASKED_SOURCE_FUNCTIONAL_BINDING_DOMAIN);
        hash.update(&encoded[..encoded.len() - 64]);
        if <[u8; 64]>::from(hash.finalize()) != expected_commitment {
            return Err(H4ProofPackageV1Error::Functional);
        }
        fn take<'a>(
            encoded: &'a [u8],
            offset: &mut usize,
            count: usize,
        ) -> Result<&'a [u8], H4ProofPackageV1Error> {
            let end = offset
                .checked_add(count)
                .ok_or(H4ProofPackageV1Error::Functional)?;
            let value = encoded
                .get(*offset..end)
                .ok_or(H4ProofPackageV1Error::Functional)?;
            *offset = end;
            Ok(value)
        }
        fn take_fp16(encoded: &[u8], offset: &mut usize) -> Result<Fp16, H4ProofPackageV1Error> {
            Fp16::decode(take(encoded, offset, 64)?).map_err(|_| H4ProofPackageV1Error::Functional)
        }
        let mut offset = 16_usize;
        let source_root: [u8; 64] = take(encoded, &mut offset, 64)?
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::Functional)?;
        let mask_tensor_root: [u8; 64] = take(encoded, &mut offset, 64)?
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::Functional)?;
        let booleanity_transcript_commitment: [u8; 64] = take(encoded, &mut offset, 64)?
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::Functional)?;
        let mut booleanity_group_point = [Fp16::ZERO; 29];
        for coordinate in &mut booleanity_group_point {
            *coordinate = take_fp16(encoded, &mut offset)?;
        }
        let booleanity_left_challenge = take_fp16(encoded, &mut offset)?;
        let booleanity_right_challenge = take_fp16(encoded, &mut offset)?;
        let booleanity_w_challenge = take_fp16(encoded, &mut offset)?;
        let booleanity_masked_terminal_left = take_fp16(encoded, &mut offset)?;
        let booleanity_masked_terminal_right = take_fp16(encoded, &mut offset)?;
        let padding_transcript_commitment: [u8; 64] = take(encoded, &mut offset, 64)?
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::Functional)?;
        let mut padding_sumcheck_point = [Fp16::ZERO; 29];
        for coordinate in &mut padding_sumcheck_point {
            *coordinate = take_fp16(encoded, &mut offset)?;
        }
        let padding_masked_terminal = take_fp16(encoded, &mut offset)?;
        let padding_functional_mixing_challenge = take_fp16(encoded, &mut offset)?;
        let complete_mask_challenge = take_fp16(encoded, &mut offset)?;
        if offset != encoded.len() - 64
            || !nonzero(&source_root)
            || !nonzero(&mask_tensor_root)
            || !nonzero(&booleanity_transcript_commitment)
            || !nonzero(&padding_transcript_commitment)
            || booleanity_left_challenge.is_zero()
            || booleanity_left_challenge == Fp16::ONE
            || booleanity_right_challenge.is_zero()
            || booleanity_right_challenge == Fp16::ONE
            || booleanity_w_challenge.is_zero()
            || booleanity_w_challenge == Fp16::ONE
            || padding_functional_mixing_challenge.is_zero()
            || complete_mask_challenge.is_zero()
        {
            return Err(H4ProofPackageV1Error::Functional);
        }
        Ok(Self {
            profile,
            source_root,
            mask_tensor_root,
            booleanity_transcript_commitment,
            booleanity_group_point,
            booleanity_left_challenge,
            booleanity_right_challenge,
            booleanity_w_challenge,
            booleanity_masked_terminal_left,
            booleanity_masked_terminal_right,
            padding_transcript_commitment,
            padding_sumcheck_point,
            padding_masked_terminal,
            padding_functional_mixing_challenge,
            complete_mask_challenge,
        })
    }
}

pub fn evaluate_h4_masked_source_functional_binding(
    binding: &H4MaskedSourceFunctionalBinding,
    main: &[Fp16],
    tensor: &[Fp16],
    row_challenges: &[Fp16],
) -> Result<H4MaskedSourceFunctionalClaims, H4ProofPackageV1Error> {
    if tensor.len() != 32_768
        || row_challenges.len() != H4_BOOLEANITY_WORD_VARIABLES
        || binding.complete_mask_challenge.is_zero()
    {
        return Err(H4ProofPackageV1Error::Functional);
    }
    let left_source_scale = Fp16::ONE - binding.booleanity_left_challenge;
    let right_source_scale = Fp16::ONE - binding.booleanity_right_challenge;
    let booleanity_source_scale =
        left_source_scale + binding.complete_mask_challenge * right_source_scale;
    if booleanity_source_scale.is_zero() || binding.padding_functional_mixing_challenge.is_zero() {
        return Err(H4ProofPackageV1Error::Functional);
    }
    let booleanity_masked_target = binding.booleanity_masked_terminal_left
        + binding.complete_mask_challenge
            * (binding.booleanity_masked_terminal_right + right_source_scale);
    let masked_target = booleanity_masked_target
        + binding.padding_functional_mixing_challenge * binding.padding_masked_terminal;
    let answer_main_functional = booleanity_source_scale
        * h4_booleanity_source_answer_functional(
            main,
            row_challenges,
            &binding.booleanity_group_point,
            true,
        )?
        + binding.padding_functional_mixing_challenge
            * h4_padding_source_answer_functional(
                main,
                row_challenges,
                &binding.padding_sumcheck_point,
            )?;

    let layout = selected_state_composed_mask_layout(usize::from(binding.profile.state_capacity()))
        .map_err(|_| H4ProofPackageV1Error::Functional)?;
    let booleanity_mask_layer =
        selected_booleanity_mask_layer(usize::from(binding.profile.state_capacity()))
            .map_err(|_| H4ProofPackageV1Error::Functional)?;
    let padding_mask_layer =
        selected_padding_mask_layer(usize::from(binding.profile.state_capacity()))
            .map_err(|_| H4ProofPackageV1Error::Functional)?;
    let mut mask_weights = vec![Fp16::ZERO; layout.padded_coefficients];
    let mut left_point = binding.booleanity_group_point.to_vec();
    left_point.push(binding.booleanity_left_challenge);
    let mut right_point = binding.booleanity_group_point.to_vec();
    right_point.push(binding.booleanity_right_challenge);
    layout
        .accumulate_layer_boolean_w_sum(
            &mut mask_weights,
            booleanity_mask_layer,
            binding.booleanity_left_challenge,
            boolean_vanishing(&left_point),
        )
        .map_err(|_| H4ProofPackageV1Error::Functional)?;
    layout
        .accumulate_layer_boolean_w_sum(
            &mut mask_weights,
            booleanity_mask_layer,
            binding.booleanity_right_challenge,
            binding.complete_mask_challenge * boolean_vanishing(&right_point),
        )
        .map_err(|_| H4ProofPackageV1Error::Functional)?;
    layout
        .accumulate_layer_boolean_w_sum(
            &mut mask_weights,
            padding_mask_layer,
            binding.padding_sumcheck_point[0],
            binding.padding_functional_mixing_challenge
                * boolean_vanishing(&binding.padding_sumcheck_point),
        )
        .map_err(|_| H4ProofPackageV1Error::Functional)?;
    let answer_mask_functional = inner_product(tensor, &mask_weights)?;

    let mut hash = Sha3_512::new();
    hash.update(MASKED_SOURCE_FUNCTIONALS_DOMAIN);
    hash.update([binding.profile.code(), 2]);
    hash.update([
        H4_BOOLEANITY_COMPONENT_VARIABLES as u8,
        H4_BOOLEANITY_COEFFICIENT_VARIABLES as u8,
        H4_BOOLEANITY_WORD_VARIABLES as u8,
    ]);
    hash.update(H4_LIVE_WIRES_PER_PERMUTATION.to_be_bytes());
    hash.update((1_600_u16).to_be_bytes());
    hash.update((1_664_u16).to_be_bytes());
    hash.update((4_096_u16).to_be_bytes());
    hash.update([0, H4_MASKED_SOURCE_FUNCTIONAL_BOOLEANITY_TAG]);
    hash.update(binding.booleanity_transcript_commitment);
    for coordinate in binding.booleanity_group_point {
        hash.update(coordinate.encode());
    }
    hash.update(binding.booleanity_left_challenge.encode());
    hash.update(binding.booleanity_right_challenge.encode());
    hash.update(binding.booleanity_w_challenge.encode());
    hash.update(binding.booleanity_masked_terminal_left.encode());
    hash.update(binding.booleanity_masked_terminal_right.encode());
    hash.update(binding.complete_mask_challenge.encode());
    hash.update(booleanity_source_scale.encode());
    hash.update([1, H4_MASKED_SOURCE_FUNCTIONAL_PADDING_TAG]);
    hash.update(binding.padding_transcript_commitment);
    for coordinate in binding.padding_sumcheck_point {
        hash.update(coordinate.encode());
    }
    hash.update(binding.padding_masked_terminal.encode());
    hash.update(binding.padding_functional_mixing_challenge.encode());
    hash.update(masked_target.encode());
    hash.update(answer_main_functional.encode());
    hash.update(answer_mask_functional.encode());
    Ok(H4MaskedSourceFunctionalClaims {
        commitment: hash.finalize().into(),
        masked_target,
        answer_main_functional,
        answer_mask_functional,
    })
}

fn derive_h4_masked_source_functional_claims(
    profile: H4ProofProfile,
    main: &[Fp16],
    tensor: &[Fp16],
    row_challenges: &[Fp16],
    booleanity: &VerifiedH4BooleanityAlgebraBoundary,
    padding: &VerifiedH4PaddingAlgebraBoundary,
    complete_mask_challenge: Fp16,
) -> Result<H4MaskedSourceFunctionalClaims, H4ProofPackageV1Error> {
    let binding = H4MaskedSourceFunctionalBinding::from_verified_boundaries(
        profile,
        booleanity,
        padding,
        complete_mask_challenge,
    )?;
    evaluate_h4_masked_source_functional_binding(&binding, main, tensor, row_challenges)
}

pub fn exact_queries(
    seed: &[u8; 64],
    label: &[u8],
    bound: usize,
    count: usize,
) -> Result<Vec<usize>, H4ProofPackageV1Error> {
    if bound == 0 || count == 0 || count > bound {
        return Err(H4ProofPackageV1Error::Geometry);
    }
    let bound_u64 = u64::try_from(bound).map_err(|_| H4ProofPackageV1Error::Geometry)?;
    let threshold = ((1_u128 << 64) - u128::from(bound_u64)) % u128::from(bound_u64);
    let mut queries = Vec::with_capacity(count);
    let mut seen = BTreeSet::new();
    let mut draw = 0_u64;
    while queries.len() < count {
        if draw >= H4_QUERY_MAX_DRAWS {
            return Err(H4ProofPackageV1Error::TranscriptSchedule);
        }
        let mut retry = 0_u64;
        loop {
            if retry >= H4_QUERY_MAX_RETRIES_PER_DRAW {
                return Err(H4ProofPackageV1Error::TranscriptSchedule);
            }
            let digest = pcs_hash_parts(
                QUERY_DOMAIN,
                &[seed, label, &draw.to_be_bytes(), &retry.to_be_bytes()],
            );
            let random_word = u64::from_le_bytes(
                digest[..8]
                    .try_into()
                    .map_err(|_| H4ProofPackageV1Error::TranscriptSchedule)?,
            );
            let product = u128::from(random_word) * u128::from(bound_u64);
            if (product & u128::from(u64::MAX)) >= threshold {
                let candidate = usize::try_from(product >> 64)
                    .map_err(|_| H4ProofPackageV1Error::TranscriptSchedule)?;
                if seen.insert(candidate) {
                    queries.push(candidate);
                    break;
                }
            }
            retry = retry
                .checked_add(1)
                .ok_or(H4ProofPackageV1Error::TranscriptSchedule)?;
        }
        draw = draw
            .checked_add(1)
            .ok_or(H4ProofPackageV1Error::TranscriptSchedule)?;
    }
    queries.sort_unstable();
    Ok(queries)
}

pub fn tensor_queries(
    seed: &[u8; 64],
    inner_queries: &[usize],
) -> Result<Vec<usize>, H4ProofPackageV1Error> {
    let mut queries = Vec::with_capacity(inner_queries.len());
    for (ordinal, inner_query) in inner_queries.iter().copied().enumerate() {
        let ordinal = u64::try_from(ordinal).map_err(|_| H4ProofPackageV1Error::Geometry)?;
        let inner_query =
            u32::try_from(inner_query).map_err(|_| H4ProofPackageV1Error::Geometry)?;
        let digest = pcs_hash_parts(
            GKR_MASK_OUTER_QUERY_DOMAIN,
            &[
                seed,
                GKR_MASK_OUTER_QUERY_LABEL,
                &ordinal.to_be_bytes(),
                &inner_query.to_be_bytes(),
            ],
        );
        let random_word = u64::from_le_bytes(
            digest[..8]
                .try_into()
                .map_err(|_| H4ProofPackageV1Error::TranscriptSchedule)?,
        );
        let outer = usize::try_from(
            (u128::from(random_word) * H4_GKR_TENSOR_OUTER_CODE_VALUES as u128) >> 64,
        )
        .map_err(|_| H4ProofPackageV1Error::TranscriptSchedule)?;
        queries.push(
            usize::try_from(inner_query)
                .map_err(|_| H4ProofPackageV1Error::TranscriptSchedule)?
                .checked_mul(H4_GKR_TENSOR_OUTER_CODE_VALUES)
                .and_then(|index| index.checked_add(outer))
                .ok_or(H4ProofPackageV1Error::TranscriptSchedule)?,
        );
    }
    if queries.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(H4ProofPackageV1Error::TranscriptSchedule);
    }
    Ok(queries)
}

fn segment_leaf_hash(
    boundary: u64,
    kind: u64,
    data_size: usize,
    leaf_size: usize,
    leaf_index: usize,
    payload: &[u8],
) -> Result<[u8; 64], H4ProofPackageV1Error> {
    if payload.len() != leaf_size {
        return Err(H4ProofPackageV1Error::Multiproof);
    }
    Ok(pcs_hash_parts(
        SEGMENT_LEAF_DOMAIN,
        &[
            &boundary.to_be_bytes(),
            &kind.to_be_bytes(),
            &u64::try_from(data_size)
                .map_err(|_| H4ProofPackageV1Error::Multiproof)?
                .to_be_bytes(),
            &u64::try_from(leaf_size)
                .map_err(|_| H4ProofPackageV1Error::Multiproof)?
                .to_be_bytes(),
            &u64::try_from(leaf_index)
                .map_err(|_| H4ProofPackageV1Error::Multiproof)?
                .to_be_bytes(),
            payload,
        ],
    ))
}

fn polynomial_eval(coefficients: &[Fp16], point: Fp16) -> Fp16 {
    coefficients
        .iter()
        .copied()
        .rev()
        .fold(Fp16::ZERO, |value, coefficient| value * point + coefficient)
}

fn multilinear_evaluate(
    values: &[Fp16],
    challenges: &[Fp16],
) -> Result<Fp16, H4ProofPackageV1Error> {
    if values.len() != 1_usize << challenges.len() {
        return Err(H4ProofPackageV1Error::Functional);
    }
    let mut layer = values.to_vec();
    let mut active = layer.len();
    for challenge in challenges {
        for index in 0..active / 2 {
            let left = layer[2 * index];
            let right = layer[2 * index + 1];
            layer[index] = left + (right - left) * *challenge;
        }
        active /= 2;
    }
    Ok(layer[0])
}

pub(crate) fn multilinear_weights(challenges: &[Fp16]) -> Result<Vec<Fp16>, H4ProofPackageV1Error> {
    let count = 1_usize
        .checked_shl(u32::try_from(challenges.len()).map_err(|_| H4ProofPackageV1Error::Geometry)?)
        .ok_or(H4ProofPackageV1Error::Geometry)?;
    let mut weights = Vec::with_capacity(count);
    for word in 0..count {
        let mut weight = Fp16::ONE;
        for (bit, challenge) in challenges.iter().copied().enumerate() {
            weight = weight
                * if word & (1_usize << bit) == 0 {
                    Fp16::ONE - challenge
                } else {
                    challenge
                };
        }
        weights.push(weight);
    }
    Ok(weights)
}

fn inner_product(left: &[Fp16], right: &[Fp16]) -> Result<Fp16, H4ProofPackageV1Error> {
    if left.len() != right.len() {
        return Err(H4ProofPackageV1Error::Functional);
    }
    Ok(left
        .iter()
        .copied()
        .zip(right)
        .fold(Fp16::ZERO, |sum, (value, weight)| sum + value * *weight))
}

fn package_commitment(encoded: &[u8]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(PACKAGE_HASH_DOMAIN);
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    hash.finalize().into()
}

fn aggregate_package_commitment(encoded: &[u8]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(AGGREGATE_PACKAGE_HASH_DOMAIN);
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    hash.finalize().into()
}

fn contributor_set_commitment(bundle: &ChainedPublicCoinBundle) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(CONTRIBUTOR_SET_DOMAIN);
    hash.update((bundle.contributors.len() as u16).to_be_bytes());
    for contributor in &bundle.contributors {
        hash.update(contributor.contributor_id);
        hash.update(contributor.key_id);
        hash.update((contributor.suite as u16).to_be_bytes());
        hash.update(
            u32::try_from(contributor.public_key.len())
                .expect("public-coin decoder bounds every contributor key")
                .to_be_bytes(),
        );
        hash.update(&contributor.public_key);
    }
    hash.finalize().into()
}

fn parse_profile(encoded: u8) -> Result<H4ProofProfile, H4ProofPackageV1Error> {
    match encoded {
        1 => Ok(H4ProofProfile::K128),
        3 => Ok(H4ProofProfile::K512),
        _ => Err(H4ProofPackageV1Error::Profile),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H4GlobalRoundFrame<'a> {
    shard_messages: Vec<&'a [u8]>,
}

struct H4PublicViewV1<'a> {
    claims: Vec<PackedComponentClaim>,
    claims_digest: [u8; 64],
    relation_terminals: Vec<Fp16>,
    relation_terminal_bytes: &'a [u8],
    pcs_multiproofs: &'a [u8],
}

pub(crate) fn parse_packed_claims(
    encoded: &[u8],
) -> Result<Vec<PackedComponentClaim>, H4ProofPackageV1Error> {
    if encoded.len() != H4_PACKED_CLAIMS_BYTES {
        return Err(H4ProofPackageV1Error::PackedClaims);
    }
    let mut offset = 0_usize;
    let mut claims = Vec::with_capacity(GKR_CLAIM_COUNT);
    for _ in 0..GKR_CLAIM_COUNT {
        let boundary = u8::try_from(u32_at(encoded, offset)?)
            .map_err(|_| H4ProofPackageV1Error::PackedClaims)?;
        offset += 4;
        let coefficient = decode_fp16(
            &encoded[offset..offset + 64],
            H4ProofPackageV1Error::PackedClaims,
        )?;
        offset += 64;
        let value = decode_fp16(
            &encoded[offset..offset + 64],
            H4ProofPackageV1Error::PackedClaims,
        )?;
        offset += 64;
        let shard_query = decode_fp16(
            &encoded[offset..offset + 64],
            H4ProofPackageV1Error::PackedClaims,
        )?;
        offset += 64;
        let mut point = Vec::with_capacity(BOUNDARY_VARIABLES);
        for _ in 0..BOUNDARY_VARIABLES {
            point.push(decode_fp16(
                &encoded[offset..offset + 64],
                H4ProofPackageV1Error::PackedClaims,
            )?);
            offset += 64;
        }
        let mut component_evaluations = [Fp16::ZERO; 16];
        for evaluation in &mut component_evaluations {
            *evaluation = decode_fp16(
                &encoded[offset..offset + 64],
                H4ProofPackageV1Error::PackedClaims,
            )?;
            offset += 64;
        }
        claims.push(PackedComponentClaim {
            boundary,
            claim: LayerOutputClaim {
                point,
                value,
                coefficient,
            },
            shard_query,
            component_evaluations,
        });
    }
    if offset != encoded.len() {
        return Err(H4ProofPackageV1Error::PackedClaims);
    }
    Ok(claims)
}

pub(crate) fn uniform_claim_from_packed(claim: &PackedComponentClaim) -> UniformRelayFreeClaim {
    UniformRelayFreeClaim {
        shard_query: claim.shard_query,
        point: claim.claim.point.clone(),
        value: claim.claim.value,
        coefficient: claim.claim.coefficient,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct H4AuthenticatedRound {
    pub descriptor: ChainedRoundDescriptor,
    pub message: Vec<u8>,
    pub outputs: Vec<Fp16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedH4StateRelationBoundary {
    pub transcript_digest: [u8; 64],
    pub mask_constraints: Vec<UniformGkrMaskConstraint>,
    pub shard_query: Fp16,
}

fn decode_state_relation_round_values(
    round: &H4AuthenticatedRound,
    source_digest: [u8; 64],
    expected_kind: u16,
    expected_local_round: usize,
    expected_values: usize,
) -> Result<Vec<Fp16>, H4ProofPackageV1Error> {
    if round.descriptor.kind != expected_kind
        || round.descriptor.output_count != 1
        || round.outputs.len() != 1
        || round.message.len()
            != STATE_RELATION_TRANSCRIPT_DOMAIN.len() + 64 + 2 + 4 + expected_values * 64
    {
        return Err(H4ProofPackageV1Error::StateRelation);
    }
    let values_start = STATE_RELATION_TRANSCRIPT_DOMAIN.len() + 64 + 2 + 4;
    let values = decode_fp16_values(
        &round.message[values_start..],
        H4ProofPackageV1Error::StateRelation,
    )?;
    if values.len() != expected_values
        || state_relation_round_message(source_digest, expected_kind, expected_local_round, &values)
            .map_err(|_| H4ProofPackageV1Error::StateRelation)?
            != round.message
    {
        return Err(H4ProofPackageV1Error::StateRelation);
    }
    Ok(values)
}

pub(crate) fn reconstruct_and_verify_h4_state_relation_boundary(
    rounds: &[H4AuthenticatedRound],
    source_digest: [u8; 64],
    packed_claims: &[PackedComponentClaim],
) -> Result<VerifiedH4StateRelationBoundary, H4ProofPackageV1Error> {
    if !nonzero(&source_digest)
        || rounds.len() != STATE_RELATION_ROUNDS as usize
        || packed_claims.len() != GKR_CLAIM_COUNT
    {
        return Err(H4ProofPackageV1Error::StateRelation);
    }
    for (index, round) in rounds.iter().enumerate() {
        if round.descriptor.ordinal != GKR_ROUNDS + index as u32 {
            return Err(H4ProofPackageV1Error::StateRelation);
        }
    }

    let output_round = &rounds[0];
    if output_round.descriptor.kind != H4_STATE_RELATION_OUTPUT_KIND
        || output_round.descriptor.output_count != STATE_RELATION_OUTPUT_CHALLENGE_COUNT
        || output_round.outputs.len() != usize::from(STATE_RELATION_OUTPUT_CHALLENGE_COUNT)
        || output_round.message != state_relation_output_message(source_digest)
    {
        return Err(H4ProofPackageV1Error::StateRelation);
    }
    let output_claim = LayerOutputClaim {
        point: output_round.outputs[1..18].to_vec(),
        value: Fp16::ZERO,
        coefficient: Fp16::ONE,
    };
    let sumcheck_rho = output_round.outputs[18];

    let mut published_rounds =
        Vec::with_capacity(STATE_RELATION_GROUP_VARIABLES + 2 * STATE_RELATION_WIRE_VARIABLES + 1);
    let mut group_challenges = Vec::with_capacity(STATE_RELATION_GROUP_VARIABLES);
    for local_round in 0..STATE_RELATION_GROUP_VARIABLES {
        let round = &rounds[1 + local_round];
        published_rounds.push(decode_state_relation_round_values(
            round,
            source_digest,
            H4_STATE_RELATION_GROUP_KIND,
            local_round,
            4,
        )?);
        group_challenges.push(round.outputs[0]);
    }

    let wire_start = 1 + STATE_RELATION_GROUP_VARIABLES;
    let mut wire_challenges = Vec::with_capacity(2 * STATE_RELATION_WIRE_VARIABLES);
    for wire_round in 0..2 * STATE_RELATION_WIRE_VARIABLES {
        let round = &rounds[wire_start + wire_round];
        let local_round = wire_round % STATE_RELATION_WIRE_VARIABLES;
        let expected_values = if local_round + 1 == STATE_RELATION_WIRE_VARIABLES {
            4
        } else {
            3
        };
        published_rounds.push(decode_state_relation_round_values(
            round,
            source_digest,
            H4_STATE_RELATION_WIRE_KIND,
            local_round,
            expected_values,
        )?);
        wire_challenges.push(round.outputs[0]);
    }

    let terminal_round = rounds.last().ok_or(H4ProofPackageV1Error::StateRelation)?;
    let terminal = decode_state_relation_round_values(
        terminal_round,
        source_digest,
        H4_STATE_RELATION_TERMINAL_KIND,
        0,
        5,
    )?;
    published_rounds.push(terminal[..3].to_vec());
    let proof = PublicMaskedStateRelationGkrProof {
        output_claim,
        sumcheck_rho,
        published_rounds,
        group_challenges,
        wire_challenges,
        masked_terminal_left: terminal[3],
        masked_terminal_right: terminal[4],
        w_challenge: terminal_round.outputs[0],
    };
    verify_public_masked_state_relation_gkr(&proof)
        .map_err(|_| H4ProofPackageV1Error::StateRelation)?;

    let raw_values = [packed_claims[5].claim.value, packed_claims[6].claim.value];
    let expected_claims =
        public_masked_state_relation_h4_input_claims(&proof, output_round.outputs[0], raw_values)
            .map_err(|_| H4ProofPackageV1Error::StateRelation)?;
    for (packed, expected) in packed_claims[5..7].iter().zip(expected_claims) {
        if packed.boundary != expected.boundary
            || packed.claim.coefficient != Fp16::ONE
            || packed.claim.point != expected.point
            || packed.claim.value != expected.value
            || packed.shard_query != expected.shard_query
            || packed
                .component_evaluations
                .iter()
                .any(|value| *value != expected.value)
        {
            return Err(H4ProofPackageV1Error::StateRelation);
        }
    }

    let mask_constraints =
        public_masked_state_relation_constraints(&proof, GKR_LAYERS as usize, raw_values)
            .map_err(|_| H4ProofPackageV1Error::StateRelation)?;
    if mask_constraints.len() != H4_STATE_RELATION_MASK_CONSTRAINTS {
        return Err(H4ProofPackageV1Error::StateRelation);
    }
    let transcript_digest =
        public_state_relation_transcript_digest(source_digest, &proof, output_round.outputs[0])
            .map_err(|_| H4ProofPackageV1Error::StateRelation)?;
    Ok(VerifiedH4StateRelationBoundary {
        transcript_digest,
        mask_constraints,
        shard_query: output_round.outputs[0],
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedH4SquarefreeBoundary {
    pub transcript_digest: [u8; 64],
    pub mask_constraints: Vec<UniformGkrMaskConstraint>,
}

#[allow(clippy::too_many_arguments)]
fn decode_squarefree_round_values(
    round: &H4AuthenticatedRound,
    source_digest: [u8; 64],
    coefficient_root: [u8; 64],
    expected_kind: u16,
    phase: usize,
    layer: usize,
    local_round: usize,
    expected_values: usize,
) -> Result<Vec<Fp16>, H4ProofPackageV1Error> {
    let prefix_bytes = STATE_SQUAREFREE_TRANSCRIPT_DOMAIN.len() + 2 * 64 + 2 + 4 * 4;
    if round.descriptor.kind != expected_kind
        || round.descriptor.output_count != 1
        || round.outputs.len() != 1
        || round.message.len() != prefix_bytes + expected_values * 64
    {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    let values = decode_fp16_values(
        &round.message[prefix_bytes..],
        H4ProofPackageV1Error::SquarefreeClaims,
    )?;
    if values.len() != expected_values
        || state_squarefree_round_message(
            source_digest,
            coefficient_root,
            expected_kind,
            phase,
            layer,
            local_round,
            &values,
        )
        .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?
            != round.message
    {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    Ok(values)
}

fn squarefree_descriptor_kind(kind: u8) -> Result<u16, H4ProofPackageV1Error> {
    match kind {
        0 => Ok(H4_STATE_SQUAREFREE_GROUP_KIND),
        1 => Ok(H4_STATE_SQUAREFREE_LEFT_KIND),
        2 => Ok(H4_STATE_SQUAREFREE_RIGHT_KIND),
        _ => Err(H4ProofPackageV1Error::SquarefreeClaims),
    }
}

fn lift_squarefree_coefficient_point(
    capacity: usize,
    phase: usize,
    point: &[Fp16],
) -> Result<[Fp16; 11], H4ProofPackageV1Error> {
    let row_variables = capacity.ilog2() as usize;
    if phase >= STATE_SQUAREFREE_PHASES || point.len() != row_variables + 1 {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    let mut lifted = [Fp16::ZERO; 11];
    lifted[..row_variables].copy_from_slice(&point[..row_variables]);
    lifted[9] = point[row_variables];
    lifted[10] = if phase == 0 { Fp16::ZERO } else { Fp16::ONE };
    Ok(lifted)
}

fn squarefree_h4_state_point(
    wire: usize,
    row_point: &[Fp16],
) -> Result<Vec<Fp16>, H4ProofPackageV1Error> {
    if row_point.len() != 12 {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    let mut local = Vec::with_capacity(STATE_RELATION_WIRE_VARIABLES + row_point.len());
    for bit in 0..STATE_RELATION_WIRE_VARIABLES {
        local.push(if (wire >> bit) & 1 == 1 {
            Fp16::ONE
        } else {
            Fp16::ZERO
        });
    }
    local.extend_from_slice(row_point);
    h4_state_point(&local).map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn reconstruct_and_verify_h4_squarefree_boundary(
    rounds: &[H4AuthenticatedRound],
    source_digest: [u8; 64],
    initial_root: [u8; 64],
    squarefree: &H4MaskedSquarefreePublicClaims,
    capacity: usize,
    shard_query: Fp16,
    packed_claims: &[PackedComponentClaim],
) -> Result<VerifiedH4SquarefreeBoundary, H4ProofPackageV1Error> {
    let expected_rounds = state_squarefree_authenticated_rounds(capacity)
        .ok_or(H4ProofPackageV1Error::SquarefreeClaims)? as usize;
    let plans = public_masked_state_squarefree_layer_plan(capacity)
        .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?;
    let squarefree_start = GKR_ROUNDS + STATE_RELATION_ROUNDS;
    if !nonzero(&source_digest)
        || !nonzero(&initial_root)
        || !nonzero(&squarefree.coefficient_root)
        || shard_query.is_zero()
        || rounds.len() != expected_rounds
        || packed_claims.len() != GKR_CLAIM_COUNT
    {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    for (index, round) in rounds.iter().enumerate() {
        if round.descriptor.ordinal != squarefree_start + index as u32 {
            return Err(H4ProofPackageV1Error::SquarefreeClaims);
        }
    }

    let beta_round = &rounds[0];
    if beta_round.descriptor.kind != H4_STATE_SQUAREFREE_BETA_KIND
        || beta_round.descriptor.output_count != 1
        || beta_round.outputs.len() != 1
        || beta_round.outputs[0].is_zero()
        || beta_round.message
            != state_squarefree_beta_message(source_digest, initial_root, capacity)
                .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?
    {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    let beta = beta_round.outputs[0];
    let point_round = &rounds[1];
    if point_round.descriptor.kind != H4_STATE_SQUAREFREE_POINT_KIND
        || usize::from(point_round.descriptor.output_count) != 1 + plans.len()
        || point_round.outputs.len() != 1 + plans.len()
        || point_round.outputs.iter().any(|value| value.is_zero())
        || point_round.message
            != state_squarefree_point_message(
                source_digest,
                initial_root,
                squarefree.coefficient_root,
                beta,
            )
    {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    let evaluation_point = point_round.outputs[0];
    let mut transcript_hash = Sha3_512::new();
    transcript_hash.update(STATE_SQUAREFREE_TRANSCRIPT_DOMAIN);
    transcript_hash.update(source_digest);
    transcript_hash.update(initial_root);
    transcript_hash.update(squarefree.coefficient_root);
    transcript_hash.update(beta.encode());
    for value in &point_round.outputs {
        transcript_hash.update(value.encode());
    }

    let mut cursor = 2_usize;
    let mut layers = Vec::with_capacity(plans.len());
    for (mask_ordinal, plan) in plans.iter().enumerate() {
        let layer = state_squarefree_layer_ordinal(plan.kind, plan.topology_index)
            .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?;
        let mut published_rounds = Vec::with_capacity(plan.expected_degrees.len());
        let mut group_challenges = Vec::with_capacity(plan.group_rounds);
        let mut wire_challenges = Vec::with_capacity(plan.left_rounds + plan.right_rounds);
        let mut polynomial_round = 0_usize;
        for (axis, axis_rounds) in [
            (0_u8, plan.group_rounds),
            (1_u8, plan.left_rounds),
            (2_u8, plan.right_rounds),
        ] {
            for local_round in 0..axis_rounds {
                let transcript_round = rounds
                    .get(cursor)
                    .ok_or(H4ProofPackageV1Error::SquarefreeClaims)?;
                let values = decode_squarefree_round_values(
                    transcript_round,
                    source_digest,
                    squarefree.coefficient_root,
                    squarefree_descriptor_kind(axis)?,
                    usize::from(plan.phase),
                    layer,
                    local_round,
                    plan.expected_degrees[polynomial_round] + 1,
                )?;
                transcript_hash.update(&transcript_round.message);
                transcript_hash.update(transcript_round.outputs[0].encode());
                published_rounds.push(values);
                if axis == 0 {
                    group_challenges.push(transcript_round.outputs[0]);
                } else {
                    wire_challenges.push(transcript_round.outputs[0]);
                }
                polynomial_round += 1;
                cursor += 1;
            }
        }
        let terminal_round = rounds
            .get(cursor)
            .ok_or(H4ProofPackageV1Error::SquarefreeClaims)?;
        let terminal_polynomial_values = plan.expected_degrees[plan
            .expected_degrees
            .len()
            .checked_sub(1)
            .ok_or(H4ProofPackageV1Error::SquarefreeClaims)?]
            + 1;
        let terminal = decode_squarefree_round_values(
            terminal_round,
            source_digest,
            squarefree.coefficient_root,
            H4_STATE_SQUAREFREE_TERMINAL_KIND,
            usize::from(plan.phase),
            layer,
            0,
            terminal_polynomial_values + 2,
        )?;
        transcript_hash.update(&terminal_round.message);
        transcript_hash.update(terminal_round.outputs[0].encode());
        let masked_terminal_left = terminal[terminal_polynomial_values];
        let masked_terminal_right = terminal[terminal_polynomial_values + 1];
        published_rounds.push(terminal[..terminal_polynomial_values].to_vec());
        cursor += 1;

        let mut terminal_coefficients = [Fp16::ZERO; 2];
        for (mix_round, coefficient) in terminal_coefficients.iter_mut().enumerate() {
            let transcript_round = rounds
                .get(cursor)
                .ok_or(H4ProofPackageV1Error::SquarefreeClaims)?;
            let values = decode_squarefree_round_values(
                transcript_round,
                source_digest,
                squarefree.coefficient_root,
                H4_STATE_SQUAREFREE_MIX_KIND,
                usize::from(plan.phase),
                layer,
                mix_round,
                2,
            )?;
            if values != [masked_terminal_left, masked_terminal_right]
                || transcript_round.outputs[0].is_zero()
            {
                return Err(H4ProofPackageV1Error::SquarefreeClaims);
            }
            transcript_hash.update(&transcript_round.message);
            transcript_hash.update(transcript_round.outputs[0].encode());
            *coefficient = transcript_round.outputs[0];
            cursor += 1;
        }
        if polynomial_round + 1 != plan.expected_degrees.len() {
            return Err(H4ProofPackageV1Error::SquarefreeClaims);
        }
        layers.push(PublicMaskedStateSquarefreeLayerProof {
            phase: plan.phase,
            kind: plan.kind,
            topology_index: plan.topology_index,
            sumcheck_rho: point_round.outputs[1 + mask_ordinal],
            published_rounds,
            group_challenges,
            wire_challenges,
            masked_terminal_left,
            masked_terminal_right,
            w_challenge: terminal_round.outputs[0],
            terminal_coefficients,
        });
    }
    if cursor != rounds.len() {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    let proof = PublicMaskedStateSquarefreeGkrProof {
        layout: StateSquarefreeLayout::new(capacity)
            .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?,
        beta,
        evaluation_point,
        layers,
    };
    let boundary = verify_public_masked_state_squarefree_composed(&proof)
        .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?;
    for (phase, claim) in boundary.coefficient_claims.iter().enumerate() {
        if lift_squarefree_coefficient_point(capacity, phase, &claim.point)?
            != squarefree.points[phase]
            || claim.masked_value != squarefree.values[phase]
        {
            return Err(H4ProofPackageV1Error::SquarefreeClaims);
        }
    }

    let zero_leaf_values = [[Fp16::ZERO; 2]; STATE_SQUAREFREE_PHASES];
    let reductions = public_masked_state_squarefree_state_reductions(&proof, zero_leaf_values)
        .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?;
    let mut raw_state_leaf_values = zero_leaf_values;
    let mut claim_ordinal = 7_usize;
    for (phase, phase_reductions) in reductions.iter().enumerate() {
        for (reduction, reduction_claim) in phase_reductions.iter().enumerate() {
            let mut raw_openings = [Fp16::ZERO; 3];
            for (opening, wire) in reduction_claim.state_wires.iter().copied().enumerate() {
                let packed = packed_claims
                    .get(claim_ordinal)
                    .ok_or(H4ProofPackageV1Error::SquarefreeClaims)?;
                let expected_point = squarefree_h4_state_point(wire, &reduction_claim.row_point)?;
                if packed.boundary != 1
                    || packed.claim.coefficient != Fp16::ONE
                    || packed.claim.point != expected_point
                    || packed.shard_query != shard_query
                    || packed
                        .component_evaluations
                        .iter()
                        .any(|value| *value != packed.claim.value)
                {
                    return Err(H4ProofPackageV1Error::SquarefreeClaims);
                }
                raw_openings[opening] = packed.claim.value;
                claim_ordinal += 1;
            }
            raw_state_leaf_values[phase][reduction] = reduction_claim.affine_coefficients[0]
                + reduction_claim.affine_coefficients[1] * raw_openings[0]
                + reduction_claim.affine_coefficients[2] * raw_openings[1]
                + reduction_claim.affine_coefficients[3] * raw_openings[2];
        }
    }
    if claim_ordinal != GKR_CLAIM_COUNT {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    let checked_reductions =
        public_masked_state_squarefree_state_reductions(&proof, raw_state_leaf_values)
            .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?;
    if checked_reductions
        .iter()
        .flatten()
        .zip(raw_state_leaf_values.iter().flatten())
        .any(|(reduction, expected)| reduction.expected_value != *expected)
    {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    let mask_constraints =
        public_masked_state_squarefree_constraints(&proof, raw_state_leaf_values)
            .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?;
    let expected_constraints = match capacity {
        128 => H4_K128_SQUAREFREE_MASK_CONSTRAINTS,
        512 => H4_K512_SQUAREFREE_MASK_CONSTRAINTS,
        _ => return Err(H4ProofPackageV1Error::SquarefreeClaims),
    };
    if mask_constraints.len() != 2 * plans.len() + 6
        || mask_constraints.len() != expected_constraints
    {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }
    Ok(VerifiedH4SquarefreeBoundary {
        transcript_digest: transcript_hash.finalize().into(),
        mask_constraints,
    })
}

fn parse_h4_public_view_v1(encoded: &[u8]) -> Result<H4PublicViewV1<'_>, H4ProofPackageV1Error> {
    if encoded.len() < H4_PUBLIC_VIEW_V1_HEADER_BYTES
        || encoded.get(..8) != Some(H4_PUBLIC_VIEW_V1_MAGIC)
        || u16_at(encoded, 8)? != H4_PUBLIC_VIEW_V1_VERSION
        || u16_at(encoded, 10)? != 0
        || usize::from(u16_at(encoded, 12)?) != GKR_CLAIM_COUNT
        || usize::from(u16_at(encoded, 14)?) != H4_GKR_RELATION_TERMINALS
        || usize::try_from(u32_at(encoded, 16)?).map_err(|_| H4ProofPackageV1Error::PublicView)?
            != H4_PACKED_CLAIMS_BYTES
        || usize::try_from(u32_at(encoded, 20)?).map_err(|_| H4ProofPackageV1Error::PublicView)?
            != H4_GKR_RELATION_TERMINAL_BYTES
    {
        return Err(H4ProofPackageV1Error::PublicView);
    }
    let pcs_length =
        usize::try_from(u64_at(encoded, 24)?).map_err(|_| H4ProofPackageV1Error::PublicView)?;
    let claims_start = H4_PUBLIC_VIEW_V1_HEADER_BYTES;
    let claims_end = claims_start
        .checked_add(H4_PACKED_CLAIMS_BYTES)
        .ok_or(H4ProofPackageV1Error::PublicView)?;
    let terminals_end = claims_end
        .checked_add(H4_GKR_RELATION_TERMINAL_BYTES)
        .ok_or(H4ProofPackageV1Error::PublicView)?;
    let pcs_end = terminals_end
        .checked_add(pcs_length)
        .ok_or(H4ProofPackageV1Error::PublicView)?;
    if pcs_length < H4_RS_MULTIPROOF_PREFIX_BYTES || pcs_end != encoded.len() {
        return Err(H4ProofPackageV1Error::PublicView);
    }
    let claims_bytes = &encoded[claims_start..claims_end];
    let claims = parse_packed_claims(claims_bytes)?;
    let claims_digest =
        pcs_hash_parts(GKR_BINDING_DOMAIN, &[GKR_CLAIMS_DIGEST_LABEL, claims_bytes]);
    let relation_terminals = decode_fp16_values(
        &encoded[claims_end..terminals_end],
        H4ProofPackageV1Error::PublicView,
    )?;
    Ok(H4PublicViewV1 {
        claims,
        claims_digest,
        relation_terminals,
        relation_terminal_bytes: &encoded[claims_end..terminals_end],
        pcs_multiproofs: &encoded[terminals_end..pcs_end],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedH4RowSumcheckBoundary {
    pub mask_functional_claim: Fp16,
    pub terminal_target: Fp16,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_authenticated_h4_row_sumcheck(
    claim_message: &[u8],
    initial_message: &[u8],
    row_messages: &[&[u8]],
    claims: &[PackedComponentClaim],
    claims_digest: [u8; 64],
    claim_challenge: Fp16,
    coordinate_challenge: Fp16,
    epsilon: Fp16,
    row_challenges: &[Fp16],
) -> Result<VerifiedH4RowSumcheckBoundary, H4ProofPackageV1Error> {
    if claim_message.len() != 392 + H4_BLSQCL02_BYTES
        || claim_message.get(..8) != Some(b"BLT8GC06")
        || claim_message.get(264..328) != Some(claims_digest.as_slice())
        || initial_message.len() != 456
        || initial_message.get(..8) != Some(b"BLT8SO06")
        || initial_message.get(8..264) != claim_message.get(8..264)
        || row_messages.len() != WORD_SUMCHECK_ROUNDS
        || row_challenges.len() != WORD_SUMCHECK_ROUNDS
        || epsilon.is_zero()
    {
        return Err(H4ProofPackageV1Error::Sumcheck);
    }
    let mask_functional_claim =
        decode_fp16(&claim_message[200..264], H4ProofPackageV1Error::Sumcheck)?;
    let claim_mask_target = decode_fp16(&claim_message[328..392], H4ProofPackageV1Error::Sumcheck)?;
    let binding = bind_gkr_boundary_claims(claims, claim_challenge, coordinate_challenge)
        .map_err(|_| H4ProofPackageV1Error::PackedClaims)?;
    let mask_scale = (0..GKR_CLAIM_COUNT).fold(Fp16::ONE, |power, _| power * claim_challenge);
    let initial_target = binding.expected_target + mask_scale * mask_functional_claim;
    let expected_binding_digest = pcs_hash_parts(
        GKR_BINDING_DOMAIN + 1,
        &[
            GKR_ROW_BINDING_LABEL,
            &claims_digest,
            &claim_challenge.encode(),
            &coordinate_challenge.encode(),
            &initial_target.encode(),
        ],
    );
    if initial_message.get(264..328) != Some(expected_binding_digest.as_slice())
        || decode_fp16(&initial_message[328..392], H4ProofPackageV1Error::Sumcheck)?
            != initial_target
        || decode_fp16(&initial_message[392..456], H4ProofPackageV1Error::Sumcheck)?
            != claim_mask_target
    {
        return Err(H4ProofPackageV1Error::Sumcheck);
    }

    let mut expected = initial_target * epsilon + claim_mask_target;
    for (round, (message, challenge)) in row_messages.iter().zip(row_challenges).enumerate() {
        if message.len() != H4_KIND801_MAX_SHARD_MESSAGE_BYTES
            || message.get(..8) != Some(b"BLT8HR04")
            || usize::try_from(u32_at(message, 8)?).map_err(|_| H4ProofPackageV1Error::Sumcheck)?
                != round
            || usize::try_from(u32_at(message, 12)?).map_err(|_| H4ProofPackageV1Error::Sumcheck)?
                != AUXILIARY_MESSAGE_VALUES * 64
        {
            return Err(H4ProofPackageV1Error::Sumcheck);
        }
        let coefficients = decode_fp16_values(&message[16..], H4ProofPackageV1Error::Sumcheck)?;
        if coefficients.len() != AUXILIARY_MESSAGE_VALUES
            || coefficients[0]
                + coefficients
                    .iter()
                    .copied()
                    .fold(Fp16::ZERO, |sum, coefficient| sum + coefficient)
                != expected
        {
            return Err(H4ProofPackageV1Error::Sumcheck);
        }
        expected = polynomial_eval(&coefficients, *challenge);
    }
    Ok(VerifiedH4RowSumcheckBoundary {
        mask_functional_claim,
        terminal_target: expected,
    })
}

pub(crate) fn verify_answer_functional(
    coefficients: &[Fp16],
    claims: &[PackedComponentClaim],
    claim_challenge: Fp16,
    coordinate_challenge: Fp16,
    row_challenges: &[Fp16],
    relation_terminals: &[Fp16],
    epsilon: Fp16,
    squarefree: &H4MaskedSquarefreePublicClaims,
    booleanity: &VerifiedH4BooleanityAlgebraBoundary,
    padding: &VerifiedH4PaddingAlgebraBoundary,
    complete_mask_challenge: Fp16,
) -> Result<(Fp16, H4MaskedSourceFunctionalClaims), H4ProofPackageV1Error> {
    let main_values = H4_ANSWER_MAIN_COEFFICIENT_BYTES / 64;
    let ordinary_values = H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES / 64;
    let tensor_values = H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES / 64;
    if coefficients.len() != main_values + ordinary_values + tensor_values
        || row_challenges.len() != WORD_SUMCHECK_ROUNDS
        || relation_terminals.len() != H4_GKR_RELATION_TERMINALS
        || epsilon.is_zero()
    {
        return Err(H4ProofPackageV1Error::Functional);
    }
    let main = &coefficients[..main_values];
    let ordinary = &coefficients[main_values..main_values + ordinary_values];
    let tensor = &coefficients[main_values + ordinary_values..];
    let binding = bind_gkr_boundary_claims(claims, claim_challenge, coordinate_challenge)
        .map_err(|_| H4ProofPackageV1Error::PackedClaims)?;
    let mut main_target = Fp16::ZERO;
    for claim_ordinal in 0..GKR_CLAIM_COUNT {
        main_target = main_target
            + claim_main_answer_target(&binding, claim_ordinal, row_challenges, main)
                .map_err(|_| H4ProofPackageV1Error::Functional)?;
    }

    let ordinary_words = ordinary
        .chunks_exact(AUXILIARY_DIMENSION)
        .collect::<Vec<_>>();
    let tensor_words = tensor
        .chunks_exact(H4_GKR_TENSOR_INNER_MESSAGE_VALUES)
        .collect::<Vec<_>>();
    if ordinary_words.len() != NON_GKR_AUXILIARY_WORDS
        || tensor_words.len() != H4_GKR_TENSOR_OUTER_MESSAGE_VALUES
    {
        return Err(H4ProofPackageV1Error::Functional);
    }
    let mut auxiliary_target = ordinary_words
        .iter()
        .take(WORD_SUMCHECK_ROUNDS)
        .zip(row_challenges)
        .fold(Fp16::ZERO, |target, (word, challenge)| {
            target + polynomial_eval(&word[..AUXILIARY_MESSAGE_VALUES], *challenge)
        });
    for ((word, relation_terminal), _) in tensor_words
        .iter()
        .zip(relation_terminals)
        .zip(0..H4_GKR_RELATION_TERMINALS)
    {
        auxiliary_target = auxiliary_target
            + multilinear_evaluate(word, row_challenges)? * *relation_terminal * epsilon;
    }

    let coefficient_claims = squarefree
        .points
        .iter()
        .cloned()
        .zip(squarefree.values)
        .map(|(point, value)| MultilinearOpeningClaim {
            point: point.to_vec(),
            value,
        })
        .collect::<Vec<_>>();
    let (coefficient_functional, coefficient_target) = state_squarefree_coefficient_functional(
        usize::from(squarefree.capacity),
        &coefficient_claims,
        &squarefree.mixing_challenges,
    )
    .map_err(|_| H4ProofPackageV1Error::Functional)?;
    let (gkr_mask_functional, masked_target) = public_masked_state_squarefree_gkr_mask_functional(
        usize::from(squarefree.capacity),
        &coefficient_claims,
        &squarefree.mixing_challenges,
    )
    .map_err(|_| H4ProofPackageV1Error::Functional)?;
    if coefficient_target != squarefree.masked_target
        || masked_target != squarefree.masked_target
        || gkr_mask_functional.len() != tensor.len()
    {
        return Err(H4ProofPackageV1Error::Functional);
    }
    let raw_coefficient_opening = inner_product(
        &ordinary_words[NON_GKR_AUXILIARY_WORDS - 1][..AUXILIARY_MESSAGE_VALUES],
        &coefficient_functional,
    )?;
    let mask_coefficient_opening = inner_product(tensor, &gkr_mask_functional)?;
    if raw_coefficient_opening + mask_coefficient_opening != squarefree.masked_target {
        return Err(H4ProofPackageV1Error::Functional);
    }
    auxiliary_target = auxiliary_target + squarefree.masked_target;
    let functional_profile = match squarefree.capacity {
        128 => H4ProofProfile::K128,
        512 => H4ProofProfile::K512,
        _ => return Err(H4ProofPackageV1Error::Functional),
    };
    let masked_source_functionals = derive_h4_masked_source_functional_claims(
        functional_profile,
        main,
        tensor,
        row_challenges,
        booleanity,
        padding,
        complete_mask_challenge,
    )?;
    main_target = main_target + masked_source_functionals.answer_main_functional;
    auxiliary_target =
        auxiliary_target + epsilon * masked_source_functionals.answer_mask_functional;
    Ok((
        main_target * epsilon + auxiliary_target,
        masked_source_functionals,
    ))
}

fn root_for_log(log_code: u32) -> Result<Fp16, H4ProofPackageV1Error> {
    if log_code == 0 || log_code > 25 {
        return Err(H4ProofPackageV1Error::TensorCode);
    }
    let mut root = Fp16::from_coefficients(ROOT25_COORDINATES)
        .map_err(|_| H4ProofPackageV1Error::TensorCode)?;
    for _ in log_code..25 {
        root = root.square();
    }
    Ok(root)
}

fn frozen_coset() -> Result<Fp16, H4ProofPackageV1Error> {
    Fp16::from_coefficients(COSET_COORDINATES).map_err(|_| H4ProofPackageV1Error::TensorCode)
}

fn transform_blocks(values: &mut [Fp16], length: usize, stage_root: Fp16) {
    for block in values.chunks_exact_mut(length) {
        let mut twiddle = Fp16::ONE;
        let half = length / 2;
        for index in 0..half {
            let left = block[index];
            let right = block[half + index] * twiddle;
            block[index] = left + right;
            block[half + index] = left - right;
            twiddle = twiddle * stage_root;
        }
    }
}

fn ntt_in_place(values: &mut [Fp16], root: Fp16) {
    let count = values.len();
    let log_size = count.ilog2();
    for index in 1..count {
        let reversed = index.reverse_bits() >> (usize::BITS - log_size);
        if index < reversed {
            values.swap(index, reversed);
        }
    }
    let mut length = 2_usize;
    while length <= count {
        let stage_log = length.ilog2();
        let mut stage_root = root;
        for _ in stage_log..log_size {
            stage_root = stage_root.square();
        }
        transform_blocks(values, length, stage_root);
        if length == count {
            break;
        }
        length *= 2;
    }
}

pub(crate) fn encode_codeword(
    coefficients: &[Fp16],
    log_code: u32,
) -> Result<Vec<Fp16>, H4ProofPackageV1Error> {
    let count = 1_usize << log_code;
    if coefficients.is_empty() || coefficients.len() > count {
        return Err(H4ProofPackageV1Error::TensorCode);
    }
    let coset = frozen_coset()?;
    let mut coset_power = Fp16::ONE;
    let mut values = vec![Fp16::ZERO; count];
    for (destination, coefficient) in values.iter_mut().zip(coefficients.iter().copied()) {
        *destination = coefficient * coset_power;
        coset_power = coset_power * coset;
    }
    ntt_in_place(&mut values, root_for_log(log_code)?);
    Ok(values)
}

fn answer_tensor_root_and_openings(
    coefficients: &[Fp16],
    tensor_query_indices: &[usize],
) -> Result<([u8; 64], Vec<Fp16>), H4ProofPackageV1Error> {
    if coefficients.len() != H4_GKR_TENSOR_OUTER_MESSAGE_VALUES * H4_GKR_TENSOR_INNER_MESSAGE_VALUES
        || tensor_query_indices.len() != H4_AUXILIARY_OPENINGS
        || tensor_query_indices
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || tensor_query_indices
            .last()
            .is_none_or(|index| *index >= H4_GKR_TENSOR_LEAVES)
    {
        return Err(H4ProofPackageV1Error::TensorCode);
    }
    let inner_codewords = coefficients
        .chunks_exact(H4_GKR_TENSOR_INNER_MESSAGE_VALUES)
        .map(|word| encode_codeword(word, H4_GKR_TENSOR_INNER_CODE_VALUES.ilog2()))
        .collect::<Result<Vec<_>, _>>()?;
    if inner_codewords.len() != H4_GKR_TENSOR_OUTER_MESSAGE_VALUES {
        return Err(H4ProofPackageV1Error::TensorCode);
    }

    let mut frontier: Vec<Option<[u8; 64]>> = vec![None; H4_GKR_TENSOR_LEAVES.ilog2() as usize + 1];
    let mut openings = Vec::with_capacity(tensor_query_indices.len());
    let mut query_ordinal = 0_usize;
    let mut outer_coefficients = vec![Fp16::ZERO; H4_GKR_TENSOR_OUTER_MESSAGE_VALUES];
    for inner in 0..H4_GKR_TENSOR_INNER_CODE_VALUES {
        for (coefficient, codeword) in outer_coefficients.iter_mut().zip(&inner_codewords) {
            *coefficient = codeword[inner];
        }
        let outer_codeword =
            encode_codeword(&outer_coefficients, H4_GKR_TENSOR_OUTER_CODE_VALUES.ilog2())?;
        for (outer, value) in outer_codeword.into_iter().enumerate() {
            let leaf = inner * H4_GKR_TENSOR_OUTER_CODE_VALUES + outer;
            if tensor_query_indices.get(query_ordinal) == Some(&leaf) {
                openings.push(value);
                query_ordinal += 1;
            }
            let mut node = segment_leaf_hash(
                GKR_TENSOR_BOUNDARY,
                GKR_TENSOR_ANSWER_KIND,
                H4_GKR_TENSOR_DATA_BYTES,
                64,
                leaf,
                &value.encode(),
            )?;
            let mut level = 0_usize;
            loop {
                if let Some(left) = frontier[level].take() {
                    node = pcs_hash_parts(514, &[&left, &node]);
                    level += 1;
                } else {
                    frontier[level] = Some(node);
                    break;
                }
            }
        }
    }
    let root_level = H4_GKR_TENSOR_LEAVES.ilog2() as usize;
    if query_ordinal != tensor_query_indices.len()
        || openings.len() != tensor_query_indices.len()
        || frontier[..root_level].iter().any(Option::is_some)
    {
        return Err(H4ProofPackageV1Error::TensorCode);
    }
    let top = frontier[root_level]
        .take()
        .ok_or(H4ProofPackageV1Error::TensorCode)?;
    let root = pcs_hash_parts(
        515,
        &[
            &u64::try_from(H4_GKR_TENSOR_LEAVES)
                .map_err(|_| H4ProofPackageV1Error::TensorCode)?
                .to_be_bytes(),
            &top,
        ],
    );
    Ok((root, openings))
}

struct H4SliceReader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> H4SliceReader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], H4ProofPackageV1Error> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(H4ProofPackageV1Error::Multiproof)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(H4ProofPackageV1Error::Multiproof)?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, H4ProofPackageV1Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| H4ProofPackageV1Error::Multiproof)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, H4ProofPackageV1Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| H4ProofPackageV1Error::Multiproof)?,
        ))
    }

    fn complete(&self) -> bool {
        self.offset == self.encoded.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedH4TensorMultiproofs {
    pub source_main_openings: Vec<Fp16>,
    pub sumcheck_source_openings: Vec<Fp16>,
    pub ordinary_base_openings: Vec<Fp16>,
    pub main_base_openings: Vec<Fp16>,
    pub squarefree_source_openings: Vec<Fp16>,
    pub base_openings: Vec<Fp16>,
    pub mask_openings: Vec<Fp16>,
}

/// Native-root PCS material for reusing the reviewed H4 algebra verifier.
/// Every opening and the public answer-tensor root must already have been
/// authenticated by the v2 BindingRoot verifier before this value is built.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeH4AlgebraBackend {
    pub openings: VerifiedH4TensorMultiproofs,
    pub answer_tensor_statement_id: [u8; 64],
    pub answer_tensor_openings: Vec<Fp16>,
}

#[allow(clippy::too_many_arguments)]
fn verify_h4_rs_multiproofs_v1(
    encoded: &[u8],
    query_seed: [u8; 64],
    fold_weights: &[Fp16],
    expected_initial_set_root: [u8; 64],
    expected_sumcheck_root: [u8; 64],
    expected_mask_tensor_root: [u8; 64],
    expected_main_base_root: [u8; 64],
    expected_base_tensor_root: [u8; 64],
    expected_squarefree_root: [u8; 64],
) -> Result<VerifiedH4TensorMultiproofs, H4ProofPackageV1Error> {
    if fold_weights.len() != H4_INITIAL_SOURCE_WORDS {
        return Err(H4ProofPackageV1Error::Multiproof);
    }
    let mut reader = H4SliceReader::new(encoded);
    if reader.take(8)? != H4_RS_MULTIPROOF_MAGIC {
        return Err(H4ProofPackageV1Error::Multiproof);
    }
    let segment_count =
        usize::try_from(reader.u32()?).map_err(|_| H4ProofPackageV1Error::Multiproof)?;
    if !matches!(segment_count, 21 | 37) || reader.take(64)? != query_seed {
        return Err(H4ProofPackageV1Error::Multiproof);
    }
    let initial_segments = segment_count - 5;
    if !matches!(initial_segments, 16 | 32) || !initial_segments.is_multiple_of(2) {
        return Err(H4ProofPackageV1Error::Multiproof);
    }
    let segments_per_boundary = initial_segments / 2;
    let interleavings_per_segment = 256 / segments_per_boundary;
    let initial_leaf_size = interleavings_per_segment * 64;
    let main_queries = exact_queries(
        &query_seed,
        b"main_queries",
        H4_MAIN_CODE_VALUES,
        H4_MAIN_OPENINGS,
    )?;
    let auxiliary_queries = exact_queries(
        &query_seed,
        b"aux_queries",
        H4_AUXILIARY_CODE_VALUES,
        H4_AUXILIARY_OPENINGS,
    )?;
    let tensor_queries = tensor_queries(&query_seed, &auxiliary_queries)?;
    let mut initial_roots = Vec::with_capacity(initial_segments);
    let mut source_main_openings = vec![Fp16::ZERO; H4_MAIN_OPENINGS];
    let mut sumcheck_source_openings = None;
    let mut ordinary_base_openings = None;
    let mut main_base_openings = None;
    let mut squarefree_source_openings = None;
    let mut base_openings = None;
    let mut mask_openings = None;

    for segment_ordinal in 0..segment_count {
        let boundary = reader.u64()?;
        let kind = reader.u64()?;
        let data_size =
            usize::try_from(reader.u64()?).map_err(|_| H4ProofPackageV1Error::Multiproof)?;
        let tree_leaves =
            usize::try_from(reader.u64()?).map_err(|_| H4ProofPackageV1Error::Multiproof)?;
        let leaf_size =
            usize::try_from(reader.u64()?).map_err(|_| H4ProofPackageV1Error::Multiproof)?;
        let opening_count =
            usize::try_from(reader.u32()?).map_err(|_| H4ProofPackageV1Error::Multiproof)?;
        let frontier_count =
            usize::try_from(reader.u32()?).map_err(|_| H4ProofPackageV1Error::Multiproof)?;
        let root: [u8; 64] = reader
            .take(64)?
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::Multiproof)?;

        let (
            expected_boundary,
            expected_kind,
            expected_leaves,
            expected_leaf_size,
            expected_openings,
        ) = if segment_ordinal < initial_segments {
            (
                u64::try_from(segment_ordinal / segments_per_boundary)
                    .map_err(|_| H4ProofPackageV1Error::Multiproof)?,
                32 + u64::try_from(segment_ordinal % segments_per_boundary)
                    .map_err(|_| H4ProofPackageV1Error::Multiproof)?,
                H4_MAIN_CODE_VALUES,
                initial_leaf_size,
                H4_MAIN_OPENINGS,
            )
        } else {
            match segment_ordinal - initial_segments {
                0 => (
                    2,
                    PCS_SUMCHECK_BASE_KIND,
                    H4_AUXILIARY_CODE_VALUES,
                    19 * 64,
                    H4_AUXILIARY_OPENINGS,
                ),
                1 => (
                    2,
                    GKR_TENSOR_MASK_KIND,
                    H4_GKR_TENSOR_LEAVES,
                    64,
                    H4_AUXILIARY_OPENINGS,
                ),
                2 => (
                    2,
                    PCS_MAIN_BASE_KIND,
                    H4_MAIN_CODE_VALUES,
                    64,
                    H4_MAIN_OPENINGS,
                ),
                3 => (
                    2,
                    GKR_TENSOR_BASE_KIND,
                    H4_GKR_TENSOR_LEAVES,
                    64,
                    H4_AUXILIARY_OPENINGS,
                ),
                4 => (
                    2,
                    PCS_SQUAREFREE_KIND,
                    H4_AUXILIARY_CODE_VALUES,
                    64,
                    H4_AUXILIARY_OPENINGS,
                ),
                _ => return Err(H4ProofPackageV1Error::Multiproof),
            }
        };
        if boundary != expected_boundary
            || kind != expected_kind
            || tree_leaves != expected_leaves
            || leaf_size != expected_leaf_size
            || data_size
                != tree_leaves
                    .checked_mul(leaf_size)
                    .ok_or(H4ProofPackageV1Error::Multiproof)?
            || opening_count != expected_openings
        {
            return Err(H4ProofPackageV1Error::Multiproof);
        }
        let expected_root = match kind {
            PCS_SUMCHECK_BASE_KIND => Some(expected_sumcheck_root),
            GKR_TENSOR_MASK_KIND => Some(expected_mask_tensor_root),
            PCS_MAIN_BASE_KIND => Some(expected_main_base_root),
            GKR_TENSOR_BASE_KIND => Some(expected_base_tensor_root),
            PCS_SQUAREFREE_KIND => Some(expected_squarefree_root),
            _ => None,
        };
        if expected_root.is_some_and(|expected| expected != root) {
            return Err(H4ProofPackageV1Error::Multiproof);
        }

        let mut indices = Vec::with_capacity(opening_count);
        for _ in 0..opening_count {
            indices.push(
                usize::try_from(reader.u32()?).map_err(|_| H4ProofPackageV1Error::Multiproof)?,
            );
        }
        let expected_indices = if segment_ordinal < initial_segments || kind == PCS_MAIN_BASE_KIND {
            &main_queries
        } else if matches!(kind, GKR_TENSOR_MASK_KIND | GKR_TENSOR_BASE_KIND) {
            &tensor_queries
        } else {
            &auxiliary_queries
        };
        if &indices != expected_indices {
            return Err(H4ProofPackageV1Error::Multiproof);
        }
        let expected_frontier = canonical_frontier_positions(tree_leaves, &indices)
            .map_err(|_| H4ProofPackageV1Error::Multiproof)?;
        if frontier_count != expected_frontier.len() {
            return Err(H4ProofPackageV1Error::Multiproof);
        }
        let leaf_bytes = opening_count
            .checked_mul(leaf_size)
            .ok_or(H4ProofPackageV1Error::Multiproof)?;
        let leaf_payloads = reader.take(leaf_bytes)?;
        for value in leaf_payloads.chunks_exact(64) {
            decode_fp16(value, H4ProofPackageV1Error::Multiproof)?;
        }
        let frontier_bytes = reader.take(
            frontier_count
                .checked_mul(64)
                .ok_or(H4ProofPackageV1Error::Multiproof)?,
        )?;
        let proof =
            CanonicalMerkleMultiProof::from_frontier_bytes(tree_leaves, &indices, frontier_bytes)
                .map_err(|_| H4ProofPackageV1Error::Multiproof)?;
        let leaf_hashes = indices
            .iter()
            .copied()
            .zip(leaf_payloads.chunks_exact(leaf_size))
            .map(|(index, payload)| {
                segment_leaf_hash(boundary, kind, data_size, leaf_size, index, payload)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !proof
            .verify_leaf_hashes(
                tree_leaves,
                &indices,
                &leaf_hashes,
                &RootHash::from_bytes(root),
            )
            .map_err(|_| H4ProofPackageV1Error::Multiproof)?
        {
            return Err(H4ProofPackageV1Error::Multiproof);
        }
        if segment_ordinal < initial_segments {
            let word_start = segment_ordinal
                .checked_mul(interleavings_per_segment)
                .ok_or(H4ProofPackageV1Error::Multiproof)?;
            let word_end = word_start
                .checked_add(interleavings_per_segment)
                .ok_or(H4ProofPackageV1Error::Multiproof)?;
            let segment_weights = fold_weights
                .get(word_start..word_end)
                .ok_or(H4ProofPackageV1Error::Multiproof)?;
            for (opening, payload) in source_main_openings
                .iter_mut()
                .zip(leaf_payloads.chunks_exact(leaf_size))
            {
                let values = decode_fp16_values(payload, H4ProofPackageV1Error::Multiproof)?;
                *opening = *opening + inner_product(&values, segment_weights)?;
            }
            initial_roots.push((boundary, kind, data_size, tree_leaves, root));
        } else if kind == PCS_SUMCHECK_BASE_KIND {
            let values = decode_fp16_values(leaf_payloads, H4ProofPackageV1Error::Multiproof)?;
            let expected_values = H4_AUXILIARY_OPENINGS
                .checked_mul(WORD_SUMCHECK_ROUNDS + NON_GKR_AUXILIARY_WORDS)
                .ok_or(H4ProofPackageV1Error::Multiproof)?;
            if values.len() != expected_values {
                return Err(H4ProofPackageV1Error::Multiproof);
            }
            let mut source = Vec::with_capacity(H4_AUXILIARY_OPENINGS * WORD_SUMCHECK_ROUNDS);
            let mut base = Vec::with_capacity(H4_AUXILIARY_OPENINGS * NON_GKR_AUXILIARY_WORDS);
            for row in values.chunks_exact(WORD_SUMCHECK_ROUNDS + NON_GKR_AUXILIARY_WORDS) {
                source.extend_from_slice(&row[..WORD_SUMCHECK_ROUNDS]);
                base.extend_from_slice(&row[WORD_SUMCHECK_ROUNDS..]);
            }
            sumcheck_source_openings = Some(source);
            ordinary_base_openings = Some(base);
        } else if kind == GKR_TENSOR_MASK_KIND {
            mask_openings = Some(decode_fp16_values(
                leaf_payloads,
                H4ProofPackageV1Error::Multiproof,
            )?);
        } else if kind == PCS_MAIN_BASE_KIND {
            main_base_openings = Some(decode_fp16_values(
                leaf_payloads,
                H4ProofPackageV1Error::Multiproof,
            )?);
        } else if kind == GKR_TENSOR_BASE_KIND {
            base_openings = Some(decode_fp16_values(
                leaf_payloads,
                H4ProofPackageV1Error::Multiproof,
            )?);
        } else if kind == PCS_SQUAREFREE_KIND {
            squarefree_source_openings = Some(decode_fp16_values(
                leaf_payloads,
                H4ProofPackageV1Error::Multiproof,
            )?);
        }
    }
    if !reader.complete() || initial_roots.len() != initial_segments {
        return Err(H4ProofPackageV1Error::Multiproof);
    }
    let mut set_hash = Sha3_512::new();
    set_hash.update(PCS_MAGIC);
    set_hash.update(PCS_VERSION.to_be_bytes());
    set_hash.update(SEGMENT_SET_DOMAIN.to_be_bytes());
    for (boundary, kind, data_size, tree_leaves, root) in initial_roots {
        set_hash.update(boundary.to_be_bytes());
        set_hash.update(kind.to_be_bytes());
        set_hash.update(
            u64::try_from(data_size)
                .map_err(|_| H4ProofPackageV1Error::Multiproof)?
                .to_be_bytes(),
        );
        set_hash.update(
            u64::try_from(tree_leaves)
                .map_err(|_| H4ProofPackageV1Error::Multiproof)?
                .to_be_bytes(),
        );
        set_hash.update(root);
    }
    if <[u8; 64]>::from(set_hash.finalize()) != expected_initial_set_root {
        return Err(H4ProofPackageV1Error::Multiproof);
    }
    let base_openings = base_openings.ok_or(H4ProofPackageV1Error::Multiproof)?;
    let mask_openings = mask_openings.ok_or(H4ProofPackageV1Error::Multiproof)?;
    let sumcheck_source_openings =
        sumcheck_source_openings.ok_or(H4ProofPackageV1Error::Multiproof)?;
    let ordinary_base_openings = ordinary_base_openings.ok_or(H4ProofPackageV1Error::Multiproof)?;
    let main_base_openings = main_base_openings.ok_or(H4ProofPackageV1Error::Multiproof)?;
    let squarefree_source_openings =
        squarefree_source_openings.ok_or(H4ProofPackageV1Error::Multiproof)?;
    if source_main_openings.len() != H4_MAIN_OPENINGS
        || sumcheck_source_openings.len() != H4_AUXILIARY_OPENINGS * WORD_SUMCHECK_ROUNDS
        || ordinary_base_openings.len() != H4_AUXILIARY_OPENINGS * NON_GKR_AUXILIARY_WORDS
        || main_base_openings.len() != H4_MAIN_OPENINGS
        || squarefree_source_openings.len() != H4_AUXILIARY_OPENINGS
        || base_openings.len() != H4_AUXILIARY_OPENINGS
        || mask_openings.len() != H4_AUXILIARY_OPENINGS
    {
        return Err(H4ProofPackageV1Error::Multiproof);
    }
    Ok(VerifiedH4TensorMultiproofs {
        source_main_openings,
        sumcheck_source_openings,
        ordinary_base_openings,
        main_base_openings,
        squarefree_source_openings,
        base_openings,
        mask_openings,
    })
}

fn verify_construction_8_2_spotchecks(
    answer_coefficients: &[Fp16],
    main_queries: &[usize],
    auxiliary_queries: &[usize],
    openings: &VerifiedH4TensorMultiproofs,
    combination: Fp16,
) -> Result<(), H4ProofPackageV1Error> {
    let main_values = H4_ANSWER_MAIN_COEFFICIENT_BYTES / 64;
    let ordinary_values = H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES / 64;
    if combination.is_zero()
        || answer_coefficients.len()
            != main_values + ordinary_values + H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES / 64
        || main_queries.len() != H4_MAIN_OPENINGS
        || auxiliary_queries.len() != H4_AUXILIARY_OPENINGS
    {
        return Err(H4ProofPackageV1Error::Functional);
    }

    let main_answer = encode_codeword(
        &answer_coefficients[..main_values],
        H4_MAIN_CODE_VALUES.ilog2(),
    )?;
    for (ordinal, query) in main_queries.iter().copied().enumerate() {
        let answer = *main_answer
            .get(query)
            .ok_or(H4ProofPackageV1Error::TensorRelation)?;
        if answer
            != openings.main_base_openings[ordinal]
                + combination * openings.source_main_openings[ordinal]
        {
            return Err(H4ProofPackageV1Error::TensorRelation);
        }
    }

    let ordinary = &answer_coefficients[main_values..main_values + ordinary_values];
    for (word, coefficients) in ordinary.chunks_exact(AUXILIARY_DIMENSION).enumerate() {
        let answer = encode_codeword(coefficients, H4_AUXILIARY_CODE_VALUES.ilog2())?;
        for (ordinal, query) in auxiliary_queries.iter().copied().enumerate() {
            let source = if word < WORD_SUMCHECK_ROUNDS {
                openings.sumcheck_source_openings[ordinal * WORD_SUMCHECK_ROUNDS + word]
            } else if word == NON_GKR_AUXILIARY_WORDS - 1 {
                openings.squarefree_source_openings[ordinal]
            } else {
                return Err(H4ProofPackageV1Error::Geometry);
            };
            let base = openings.ordinary_base_openings[ordinal * NON_GKR_AUXILIARY_WORDS + word];
            if answer
                .get(query)
                .is_none_or(|value| *value != base + combination * source)
            {
                return Err(H4ProofPackageV1Error::TensorRelation);
            }
        }
    }
    Ok(())
}

/// Encode the one canonical authenticated message for a synchronized H4 round.
/// A producer must first collect every shard's message; invoking this once per
/// child shard would create forbidden per-shard challenge chains.
pub fn encode_h4_global_round_frame(
    profile: H4ProofProfile,
    descriptor: ChainedRoundDescriptor,
    shard_messages: &[&[u8]],
) -> Result<Vec<u8>, H4ProofPackageV1Error> {
    if shard_messages.len() != usize::from(profile.shard_count()) {
        return Err(H4ProofPackageV1Error::GlobalFrame);
    }
    let governed_maximum = if descriptor.kind == KIND_ROW_SUMCHECK {
        H4_KIND801_MAX_SHARD_MESSAGE_BYTES
    } else {
        H4_GLOBAL_MAX_SHARD_MESSAGE_BYTES
    };
    let mut encoded = Vec::with_capacity(
        H4_GLOBAL_ROUND_FRAME_HEADER_BYTES
            + shard_messages
                .iter()
                .map(|message| H4_GLOBAL_ROUND_FRAME_SHARD_HEADER_BYTES + message.len())
                .sum::<usize>(),
    );
    encoded.extend_from_slice(H4_GLOBAL_ROUND_FRAME_MAGIC);
    encoded.extend_from_slice(&[profile.code(), profile.shard_count()]);
    encoded.extend_from_slice(&descriptor.kind.to_be_bytes());
    encoded.extend_from_slice(&descriptor.ordinal.to_be_bytes());
    for (shard, message) in shard_messages.iter().enumerate() {
        if message.is_empty() || message.len() > governed_maximum {
            return Err(H4ProofPackageV1Error::GlobalFrame);
        }
        encoded.push(u8::try_from(shard).map_err(|_| H4ProofPackageV1Error::GlobalFrame)?);
        encoded.extend_from_slice(
            &u32::try_from(message.len())
                .map_err(|_| H4ProofPackageV1Error::GlobalFrame)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(message);
    }
    if encoded.len() > MAX_PROVER_MESSAGE_BYTES {
        return Err(H4ProofPackageV1Error::GlobalFrame);
    }
    Ok(encoded)
}

/// Parse the one authenticated global message for a synchronized H4 round.
/// Shard indices and lengths are canonical and never supplied separately to a
/// shard verifier.
fn parse_h4_global_round_frame<'a>(
    encoded: &'a [u8],
    expected_profile: H4ProofProfile,
    expected_descriptor: ChainedRoundDescriptor,
) -> Result<H4GlobalRoundFrame<'a>, H4ProofPackageV1Error> {
    if encoded.len() < H4_GLOBAL_ROUND_FRAME_HEADER_BYTES
        || encoded.len() > MAX_PROVER_MESSAGE_BYTES
        || encoded.get(..8) != Some(H4_GLOBAL_ROUND_FRAME_MAGIC)
        || encoded[8] != expected_profile as u8
        || encoded[9] != expected_profile.shard_count()
        || u16_at(encoded, 10)? != expected_descriptor.kind
        || u32_at(encoded, 12)? != expected_descriptor.ordinal
    {
        return Err(H4ProofPackageV1Error::GlobalFrame);
    }
    let shard_count = usize::from(expected_profile.shard_count());
    let mut offset = H4_GLOBAL_ROUND_FRAME_HEADER_BYTES;
    let mut shard_messages = Vec::with_capacity(shard_count);
    for expected_shard in 0..shard_count {
        let shard_index = *encoded
            .get(offset)
            .ok_or(H4ProofPackageV1Error::GlobalFrame)?;
        offset += 1;
        let message_length = usize::try_from(u32_at(encoded, offset)?)
            .map_err(|_| H4ProofPackageV1Error::GlobalFrame)?;
        offset += 4;
        let governed_maximum = if expected_descriptor.kind == KIND_ROW_SUMCHECK {
            H4_KIND801_MAX_SHARD_MESSAGE_BYTES
        } else {
            H4_GLOBAL_MAX_SHARD_MESSAGE_BYTES
        };
        if usize::from(shard_index) != expected_shard
            || message_length == 0
            || message_length > governed_maximum
        {
            return Err(H4ProofPackageV1Error::GlobalFrame);
        }
        let end = offset
            .checked_add(message_length)
            .ok_or(H4ProofPackageV1Error::GlobalFrame)?;
        shard_messages.push(
            encoded
                .get(offset..end)
                .ok_or(H4ProofPackageV1Error::GlobalFrame)?,
        );
        offset = end;
    }
    if offset != encoded.len() {
        return Err(H4ProofPackageV1Error::GlobalFrame);
    }
    Ok(H4GlobalRoundFrame { shard_messages })
}

fn parse_fp16(encoded: &[u8]) -> Result<Fp16, H4ProofPackageV1Error> {
    let encoded: &[u8; 64] = encoded
        .try_into()
        .map_err(|_| H4ProofPackageV1Error::SquarefreeAnswerBinding)?;
    Fp16::decode(encoded).map_err(|_| H4ProofPackageV1Error::SquarefreeAnswerBinding)
}

pub(crate) fn parse_squarefree_binding(
    encoded: &[u8],
    expected_claims: &[u8],
    expected_capacity: u16,
    expected_mixing: [Fp16; 2],
) -> Result<H4MaskedSquarefreePublicClaims, H4ProofPackageV1Error> {
    if encoded.len() != H4_BLSQAB02_BYTES
        || encoded.get(..8) != Some(b"BLSQAB02")
        || expected_claims.len() != H4_BLSQCL02_BYTES
        || expected_claims.get(..8) != Some(b"BLSQCL02")
        || encoded.get(8..8 + H4_BLSQCL02_BYTES) != Some(expected_claims)
    {
        return Err(H4ProofPackageV1Error::SquarefreeAnswerBinding);
    }
    let root = digest64(&expected_claims[8..72])?;
    let capacity = u16::from_be_bytes(
        expected_claims[72..74]
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?,
    );
    let count = u16::from_be_bytes(
        expected_claims[74..76]
            .try_into()
            .map_err(|_| H4ProofPackageV1Error::SquarefreeClaims)?,
    );
    let claims_digest = digest64(&expected_claims[76..140])?;
    if !nonzero(&root) || capacity != expected_capacity || count != 2 {
        return Err(H4ProofPackageV1Error::SquarefreeClaims);
    }

    let mut offset = 8 + H4_BLSQCL02_BYTES;
    let mut points = [[Fp16::ZERO; 11]; 2];
    let mut values = [Fp16::ZERO; 2];
    let mut preimage = Vec::with_capacity(64 + 2 * (2 + 12 * 64));
    preimage.extend_from_slice(SQUAREFREE_CLAIMS_DIGEST_DOMAIN);
    preimage.extend_from_slice(&root);
    preimage.extend_from_slice(&capacity.to_be_bytes());
    preimage.extend_from_slice(&count.to_be_bytes());
    for phase in 0..2 {
        if u16_at(encoded, offset)? != 11
            || encoded
                .get(offset + 2..offset + 8)
                .ok_or(H4ProofPackageV1Error::SquarefreeAnswerBinding)?
                != [0_u8; 6]
        {
            return Err(H4ProofPackageV1Error::SquarefreeAnswerBinding);
        }
        preimage.extend_from_slice(&11_u16.to_be_bytes());
        offset += 8;
        for coordinate in &mut points[phase] {
            let bytes = encoded
                .get(offset..offset + 64)
                .ok_or(H4ProofPackageV1Error::SquarefreeAnswerBinding)?;
            *coordinate = parse_fp16(bytes)?;
            preimage.extend_from_slice(bytes);
            offset += 64;
        }
        let bytes = encoded
            .get(offset..offset + 64)
            .ok_or(H4ProofPackageV1Error::SquarefreeAnswerBinding)?;
        values[phase] = parse_fp16(bytes)?;
        preimage.extend_from_slice(bytes);
        offset += 64;
    }
    let mixing_challenges = [
        parse_fp16(
            encoded
                .get(offset..offset + 64)
                .ok_or(H4ProofPackageV1Error::SquarefreeAnswerBinding)?,
        )?,
        parse_fp16(
            encoded
                .get(offset + 64..offset + 128)
                .ok_or(H4ProofPackageV1Error::SquarefreeAnswerBinding)?,
        )?,
    ];
    offset += 128;
    if offset != encoded.len()
        || mixing_challenges != expected_mixing
        || mixing_challenges.iter().any(|value| value.is_zero())
        || <[u8; 64]>::from(Sha3_512::digest(&preimage)) != claims_digest
    {
        return Err(H4ProofPackageV1Error::SquarefreeAnswerBinding);
    }
    let masked_target = values[0] * mixing_challenges[0] + values[1] * mixing_challenges[1];
    Ok(H4MaskedSquarefreePublicClaims {
        coefficient_root: root,
        capacity,
        claims_digest,
        points,
        values,
        mixing_challenges,
        masked_target,
    })
}

pub(crate) fn verify_answer_commitment(
    message: &[u8],
    coefficients: &[u8],
) -> Result<[u8; 64], H4ProofPackageV1Error> {
    let expected_length = ANSWERS_DOMAIN.len() + 3 * (8 + 64) + 64;
    if message.len() != expected_length || !message.starts_with(ANSWERS_DOMAIN) {
        return Err(H4ProofPackageV1Error::AnswerCommitment);
    }
    let mut offset = ANSWERS_DOMAIN.len();
    let expected_section_lengths = [
        H4_ANSWER_MAIN_COEFFICIENT_BYTES,
        H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES,
        H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES,
    ];
    let mut coefficient_offset = 0_usize;
    for expected_section_length in expected_section_lengths {
        let section_length = usize::try_from(u64_at(message, offset)?)
            .map_err(|_| H4ProofPackageV1Error::AnswerCommitment)?;
        offset += 8;
        let section_digest = digest64(&message[offset..offset + 64])?;
        offset += 64;
        let section_end = coefficient_offset
            .checked_add(section_length)
            .ok_or(H4ProofPackageV1Error::AnswerCommitment)?;
        let section = coefficients
            .get(coefficient_offset..section_end)
            .ok_or(H4ProofPackageV1Error::AnswerCommitment)?;
        if section_length != expected_section_length
            || <[u8; 64]>::from(Sha3_512::digest(section)) != section_digest
        {
            return Err(H4ProofPackageV1Error::AnswerCommitment);
        }
        coefficient_offset = section_end;
    }
    let answer_tensor_root = digest64(&message[offset..offset + 64])?;
    offset += 64;
    if offset != message.len()
        || coefficient_offset != coefficients.len()
        || coefficients.len() != H4_ANSWER_COEFFICIENT_BYTES
        || !nonzero(&answer_tensor_root)
    {
        return Err(H4ProofPackageV1Error::AnswerCommitment);
    }
    Ok(answer_tensor_root)
}

/// A shard body retains the existing 512-byte `BLH4PK01` header, except offset
/// 24 is canonically zero because the aggregate owns the only public-coin
/// bundle. Offsets 16/32/40/48 contain compact-core/multiproof/public-answer/
/// BLSQAB02 byte lengths, offset 52 contains the aggregate attempt, offsets
/// 64..384 repeat the null suite and common identities, and offsets 384..512
/// contain the shard source and hidden-N tensor roots. The compact core is
/// `header || BLH4PV01 public-view/multiproof section || 8,512,768 public
/// answer bytes || 1,828 BLSQAB02 bytes`; every remaining byte through 192
/// MiB is zero. `BLH4PV01` is the exact 32-byte header documented by its
/// public constants, then 19 canonical packed claims, 64 relation-terminal
/// scalars, and one exact `BLZKRSV3` multiproof stream with no trailing byte.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_h4_shard_package_v1_boundary(
    encoded: &[u8],
    profile: H4ProofProfile,
    expected_shard_index: u8,
    attempt: u16,
    profile_identity: [u8; 64],
    program_commitment: [u8; 64],
    schedule_commitment: [u8; 64],
    session_id: [u8; 64],
    statement_commitment: [u8; 64],
    claim_message: &[u8],
    initial_message: &[u8],
    row_messages: &[&[u8]],
    base_message: &[u8],
    answer_message: &[u8],
    claim_challenge: Fp16,
    coordinate_challenge: Fp16,
    mixing: [Fp16; 2],
    epsilon: Fp16,
    row_challenges: &[Fp16],
    combination: Fp16,
    query_seed: Fp16,
    final_transcript_root: [u8; 64],
    expected_gkr_statement_binding: [u8; 64],
    gkr_rounds: Vec<UniformRelayFreeGkrRound>,
    state_relation_source_digest: [u8; 64],
    state_relation_rounds: Vec<H4AuthenticatedRound>,
    squarefree_rounds: Vec<H4AuthenticatedRound>,
    booleanity_rounds: Vec<H4AuthenticatedRound>,
    padding_rounds: Vec<H4AuthenticatedRound>,
    complete_mask_round: H4AuthenticatedRound,
    native_backend: Option<NativeH4AlgebraBackend>,
) -> Result<VerifiedH4ShardPackageV1Boundary, H4ProofPackageV1Error> {
    if native_backend.is_none() && encoded.len() != H4_PROOF_PACKAGE_V1_BYTES {
        return Err(H4ProofPackageV1Error::Length);
    }
    if encoded.get(..8) != Some(H4_PROOF_PACKAGE_V1_MAGIC) {
        return Err(H4ProofPackageV1Error::Magic);
    }
    if u16_at(encoded, 8)? != H4_PROOF_PACKAGE_V1_VERSION {
        return Err(H4ProofPackageV1Error::Version);
    }
    if parse_profile(encoded[10])? != profile
        || encoded[11] != expected_shard_index
        || encoded[12] != profile.shard_count()
        || encoded[13] != 0
        || encoded[14..16] != [0_u8; 2]
        || u16_at(encoded, 52)? != attempt
        || encoded[54..64] != [0_u8; 10]
    {
        return Err(H4ProofPackageV1Error::Geometry);
    }
    if encoded[64..128] != NULL_PROOF_SUITE_ID {
        return Err(H4ProofPackageV1Error::ProofSuite);
    }
    if encoded[128..192] != profile_identity
        || encoded[192..256] != program_commitment
        || encoded[256..320] != schedule_commitment
        || encoded[320..384] != session_id
    {
        return Err(H4ProofPackageV1Error::Identity);
    }
    let source_root = digest64(&encoded[384..448])?;
    let gkr_mask_tensor_root = digest64(&encoded[448..512])?;
    if !nonzero(&source_root) || !nonzero(&gkr_mask_tensor_root) {
        return Err(H4ProofPackageV1Error::Identity);
    }

    let compact_core_length =
        usize::try_from(u64_at(encoded, 16)?).map_err(|_| H4ProofPackageV1Error::SectionLength)?;
    let embedded_public_coin_length =
        usize::try_from(u64_at(encoded, 24)?).map_err(|_| H4ProofPackageV1Error::SectionLength)?;
    if embedded_public_coin_length != 0 {
        return Err(H4ProofPackageV1Error::StandaloneShard);
    }
    let multiproof_length =
        usize::try_from(u64_at(encoded, 32)?).map_err(|_| H4ProofPackageV1Error::SectionLength)?;
    let answer_length =
        usize::try_from(u64_at(encoded, 40)?).map_err(|_| H4ProofPackageV1Error::SectionLength)?;
    let binding_length =
        usize::try_from(u32_at(encoded, 48)?).map_err(|_| H4ProofPackageV1Error::SectionLength)?;
    let derived_core_length = H4_PROOF_PACKAGE_V1_HEADER_BYTES
        .checked_add(multiproof_length)
        .and_then(|value| value.checked_add(answer_length))
        .and_then(|value| value.checked_add(binding_length))
        .ok_or(H4ProofPackageV1Error::SectionLength)?;
    if multiproof_length == 0
        || answer_length != H4_ANSWER_COEFFICIENT_BYTES
        || binding_length != H4_BLSQAB02_BYTES
        || compact_core_length != derived_core_length
        || compact_core_length >= H4_PROOF_PACKAGE_V1_BYTES
    {
        return Err(H4ProofPackageV1Error::SectionLength);
    }
    if (native_backend.is_none() && encoded[compact_core_length..].iter().any(|byte| *byte != 0))
        || (native_backend.is_some() && encoded.len() != compact_core_length)
    {
        return Err(H4ProofPackageV1Error::Padding);
    }
    let answer_start = H4_PROOF_PACKAGE_V1_HEADER_BYTES + multiproof_length;
    let binding_start = answer_start + answer_length;
    let public_view =
        parse_h4_public_view_v1(&encoded[H4_PROOF_PACKAGE_V1_HEADER_BYTES..answer_start])?;
    let answer_coefficients = &encoded[answer_start..binding_start];
    let answer_binding = &encoded[binding_start..compact_core_length];

    if public_view.claims.len() != GKR_CLAIM_COUNT
        || public_view.claims[0].boundary != 0
        || public_view.claims[1..5]
            .iter()
            .any(|claim| claim.boundary != 1)
        || public_view.claims[..5]
            .iter()
            .any(|claim| claim.claim.point.len() != BOUNDARY_VARIABLES)
    {
        return Err(H4ProofPackageV1Error::Gkr);
    }
    let output_claim = uniform_claim_from_packed(&public_view.claims[0]);
    let input_claims = public_view.claims[1..5]
        .iter()
        .map(uniform_claim_from_packed)
        .collect::<Vec<_>>();
    let (_, gkr_mask_batch) = reconstruct_and_verify_public_masked_nonuniform_trace(
        gkr_mask_tensor_root,
        output_claim,
        input_claims,
        gkr_rounds,
        expected_gkr_statement_binding,
    )
    .map_err(|_| H4ProofPackageV1Error::Gkr)?;
    if gkr_mask_batch.constraints.len() != H4_RELAY_GKR_MASK_CONSTRAINTS {
        return Err(H4ProofPackageV1Error::Gkr);
    }
    let state_relation = reconstruct_and_verify_h4_state_relation_boundary(
        &state_relation_rounds,
        state_relation_source_digest,
        &public_view.claims,
    )?;

    if claim_message.len() != 392 + H4_BLSQCL02_BYTES
        || claim_message.get(..8) != Some(b"BLT8GC06")
        || claim_message.get(8..72) != Some(source_root.as_slice())
        || claim_message.get(136..200) != Some(gkr_mask_tensor_root.as_slice())
    {
        return Err(H4ProofPackageV1Error::TranscriptBinding);
    }
    let squarefree_claims = &claim_message[392..];
    let squarefree = parse_squarefree_binding(
        answer_binding,
        squarefree_claims,
        profile.state_capacity(),
        mixing,
    )?;
    let squarefree_boundary = reconstruct_and_verify_h4_squarefree_boundary(
        &squarefree_rounds,
        state_relation_source_digest,
        source_root,
        &squarefree,
        usize::from(profile.state_capacity()),
        state_relation.shard_query,
        &public_view.claims,
    )?;
    let booleanity_nonterminal_rounds = H4_BOOLEANITY_VARIABLES as usize + 2;
    if booleanity_rounds.len() != booleanity_nonterminal_rounds + 2
        || booleanity_rounds[0].descriptor.kind != H4_BOOLEANITY_PRELUDE_KIND
        || booleanity_rounds[0].descriptor.output_count != 1 + H4_BOOLEANITY_VARIABLES as u16
        || booleanity_rounds[0].outputs.len() != 1 + H4_BOOLEANITY_VARIABLES as usize
        || booleanity_rounds[1..1 + booleanity_nonterminal_rounds]
            .iter()
            .any(|round| {
                round.descriptor.kind != H4_BOOLEANITY_SUMCHECK_KIND
                    || round.descriptor.output_count != 1
                    || round.outputs.len() != 1
            })
        || booleanity_rounds[1 + booleanity_nonterminal_rounds]
            .descriptor
            .kind
            != H4_BOOLEANITY_TERMINAL_KIND
        || booleanity_rounds[1 + booleanity_nonterminal_rounds]
            .descriptor
            .output_count
            != 1
        || booleanity_rounds[1 + booleanity_nonterminal_rounds]
            .outputs
            .len()
            != 1
    {
        return Err(H4ProofPackageV1Error::Booleanity);
    }
    let booleanity_round_messages = booleanity_rounds[1..1 + booleanity_nonterminal_rounds]
        .iter()
        .map(|round| round.message.as_slice())
        .collect::<Vec<_>>();
    let booleanity_challenges = booleanity_rounds[1..1 + booleanity_nonterminal_rounds]
        .iter()
        .map(|round| round.outputs[0])
        .collect::<Vec<_>>();
    let booleanity_terminal = &booleanity_rounds[1 + booleanity_nonterminal_rounds];
    let booleanity = verify_h4_booleanity_algebra_boundary(
        profile,
        expected_shard_index,
        source_root,
        gkr_mask_tensor_root,
        expected_gkr_statement_binding,
        &booleanity_rounds[0].message,
        &booleanity_rounds[0].outputs,
        &booleanity_round_messages,
        &booleanity_challenges,
        &booleanity_terminal.message,
        booleanity_terminal.outputs[0],
    )?;
    if padding_rounds.len() != H4_PADDING_VARIABLES as usize + 2
        || padding_rounds[0].descriptor.kind != H4_PADDING_PRELUDE_KIND
        || padding_rounds[0].descriptor.output_count != 1 + H4_PADDING_VARIABLES as u16
        || padding_rounds[0].outputs.len() != 1 + H4_PADDING_VARIABLES as usize
        || padding_rounds[1..1 + H4_PADDING_VARIABLES as usize]
            .iter()
            .any(|round| {
                round.descriptor.kind != H4_PADDING_SUMCHECK_KIND
                    || round.descriptor.output_count != 1
                    || round.outputs.len() != 1
            })
        || padding_rounds[1 + H4_PADDING_VARIABLES as usize]
            .descriptor
            .kind
            != H4_PADDING_TERMINAL_KIND
        || padding_rounds[1 + H4_PADDING_VARIABLES as usize]
            .descriptor
            .output_count
            != 1
        || padding_rounds[1 + H4_PADDING_VARIABLES as usize]
            .outputs
            .len()
            != 1
    {
        return Err(H4ProofPackageV1Error::Padding);
    }
    let padding_round_messages = padding_rounds[1..1 + H4_PADDING_VARIABLES as usize]
        .iter()
        .map(|round| round.message.as_slice())
        .collect::<Vec<_>>();
    let padding_challenges = padding_rounds[1..1 + H4_PADDING_VARIABLES as usize]
        .iter()
        .map(|round| round.outputs[0])
        .collect::<Vec<_>>();
    let padding_terminal = &padding_rounds[1 + H4_PADDING_VARIABLES as usize];
    let padding = verify_h4_padding_algebra_boundary(
        profile,
        expected_shard_index,
        source_root,
        gkr_mask_tensor_root,
        expected_gkr_statement_binding,
        &padding_rounds[0].message,
        &padding_rounds[0].outputs,
        &padding_round_messages,
        &padding_challenges,
        &padding_terminal.message,
        padding_terminal.outputs[0],
    )?;
    let mut composed_transcript_hash = Sha3_512::new();
    composed_transcript_hash.update(STATE_RELATION_TRANSCRIPT_DOMAIN);
    composed_transcript_hash.update(state_relation.transcript_digest);
    composed_transcript_hash.update(squarefree_boundary.transcript_digest);
    composed_transcript_hash.update(squarefree.coefficient_root);
    if <[u8; 64]>::from(composed_transcript_hash.finalize()) != digest64(&claim_message[328..392])?
    {
        return Err(H4ProofPackageV1Error::TranscriptBinding);
    }

    let mut complete_mask_constraints = gkr_mask_batch.constraints.clone();
    complete_mask_constraints.extend(state_relation.mask_constraints.iter().cloned());
    complete_mask_constraints.extend(squarefree_boundary.mask_constraints.iter().cloned());
    complete_mask_constraints.extend(booleanity.mask_constraints.iter().cloned());
    complete_mask_constraints.extend(padding.mask_constraints.iter().cloned());
    let expected_complete_constraints = match profile {
        H4ProofProfile::K128 => H4_K128_COMPLETE_MASK_CONSTRAINTS,
        H4ProofProfile::K512 => H4_K512_COMPLETE_MASK_CONSTRAINTS,
    };
    if complete_mask_constraints.len() != expected_complete_constraints {
        return Err(H4ProofPackageV1Error::Gkr);
    }
    let expected_mask_ordinal = GKR_ROUNDS
        + STATE_RELATION_ROUNDS
        + state_squarefree_authenticated_rounds(usize::from(profile.state_capacity()))
            .ok_or(H4ProofPackageV1Error::SquarefreeClaims)?
        + 6
        + H4_BOOLEANITY_VARIABLES
        + H4_PADDING_VARIABLES;
    if complete_mask_round.descriptor.kind != H4_STATE_COMPOSED_MASK_BATCH_KIND
        || complete_mask_round.descriptor.ordinal != expected_mask_ordinal
        || complete_mask_round.descriptor.output_count != 1
        || complete_mask_round.outputs.len() != 1
        || complete_mask_round.outputs[0].is_zero()
        || complete_mask_round.message != gkr_mask_batch_message(&complete_mask_constraints)
    {
        return Err(H4ProofPackageV1Error::Gkr);
    }
    let mask_layout = selected_state_composed_mask_layout(usize::from(profile.state_capacity()))
        .map_err(|_| H4ProofPackageV1Error::Gkr)?;
    let (complete_mask_weights, complete_mask_opening) = aggregate_gkr_mask_constraints(
        &mask_layout,
        &complete_mask_constraints,
        complete_mask_round.outputs[0],
    )
    .map_err(|_| H4ProofPackageV1Error::Gkr)?;
    if complete_mask_opening != decode_fp16(&claim_message[200..264], H4ProofPackageV1Error::Gkr)?
        || complete_mask_weights.len() != 64 * 512
        || row_challenges.len() != WORD_SUMCHECK_ROUNDS
    {
        return Err(H4ProofPackageV1Error::Gkr);
    }
    let mask_fold_weights = multilinear_weights(row_challenges)?;
    let mut terminal_scale = Fp16::ONE;
    for _ in 0..GKR_CLAIM_COUNT {
        terminal_scale = terminal_scale * claim_challenge;
    }
    let expected_relation_terminals = complete_mask_weights
        .chunks_exact(512)
        .map(|word| inner_product(word, &mask_fold_weights).map(|value| value * terminal_scale))
        .collect::<Result<Vec<_>, _>>()?;
    if expected_relation_terminals != public_view.relation_terminals {
        return Err(H4ProofPackageV1Error::Gkr);
    }

    if base_message.len() != BASE_MASKS_DOMAIN.len() + 6 * 64
        || !base_message.starts_with(BASE_MASKS_DOMAIN)
    {
        return Err(H4ProofPackageV1Error::TranscriptBinding);
    }
    let roots = BASE_MASKS_DOMAIN.len();
    let main_base_root = digest64(&base_message[roots..roots + 64])?;
    let base_tensor_root = digest64(&base_message[roots + 64..roots + 128])?;
    let squarefree_root = digest64(&base_message[roots + 192..roots + 256])?;
    let terminal_digest = digest64(&base_message[roots + 256..roots + 320])?;
    let base_target = decode_fp16(
        &base_message[roots + 320..roots + 384],
        H4ProofPackageV1Error::Functional,
    )?;
    if base_message.get(roots + 128..roots + 192) != Some(gkr_mask_tensor_root.as_slice())
        || base_message.get(roots + 192..roots + 256)
            != Some(squarefree.coefficient_root.as_slice())
        || squarefree_root != squarefree.coefficient_root
        || terminal_digest
            != <[u8; 64]>::from(Sha3_512::digest(public_view.relation_terminal_bytes))
        || !nonzero(&main_base_root)
        || !nonzero(&base_tensor_root)
    {
        return Err(H4ProofPackageV1Error::TranscriptBinding);
    }
    let answer_tensor_root = verify_answer_commitment(answer_message, answer_coefficients)?;
    if public_view.claims_digest != digest64(&claim_message[264..328])? {
        return Err(H4ProofPackageV1Error::PackedClaims);
    }
    let row_sumcheck = verify_authenticated_h4_row_sumcheck(
        claim_message,
        initial_message,
        row_messages,
        &public_view.claims,
        public_view.claims_digest,
        claim_challenge,
        coordinate_challenge,
        epsilon,
        row_challenges,
    )?;
    if combination.is_zero() {
        return Err(H4ProofPackageV1Error::Functional);
    }
    let query_seed_bytes = query_seed.encode();
    let main_queries = exact_queries(
        &query_seed_bytes,
        b"main_queries",
        H4_MAIN_CODE_VALUES,
        H4_MAIN_OPENINGS,
    )?;
    let auxiliary_queries = exact_queries(
        &query_seed_bytes,
        b"aux_queries",
        H4_AUXILIARY_CODE_VALUES,
        H4_AUXILIARY_OPENINGS,
    )?;
    let tensor_query_indices = tensor_queries(&query_seed_bytes, &auxiliary_queries)?;
    let fold_weights = mask_fold_weights;
    let (multiproofs, native_answer) = if let Some(native) = native_backend {
        if native.answer_tensor_statement_id != answer_tensor_root
            || native.openings.source_main_openings.len() != H4_MAIN_OPENINGS
            || native.openings.sumcheck_source_openings.len()
                != H4_AUXILIARY_OPENINGS * WORD_SUMCHECK_ROUNDS
            || native.openings.ordinary_base_openings.len()
                != H4_AUXILIARY_OPENINGS * NON_GKR_AUXILIARY_WORDS
            || native.openings.main_base_openings.len() != H4_MAIN_OPENINGS
            || native.openings.squarefree_source_openings.len() != H4_AUXILIARY_OPENINGS
            || native.openings.base_openings.len() != H4_AUXILIARY_OPENINGS
            || native.openings.mask_openings.len() != H4_AUXILIARY_OPENINGS
            || native.answer_tensor_openings.len() != H4_AUXILIARY_OPENINGS
        {
            return Err(H4ProofPackageV1Error::Multiproof);
        }
        (native.openings, Some(native.answer_tensor_openings))
    } else {
        (
            verify_h4_rs_multiproofs_v1(
                public_view.pcs_multiproofs,
                query_seed_bytes,
                &fold_weights,
                source_root,
                digest64(&claim_message[72..136])?,
                gkr_mask_tensor_root,
                main_base_root,
                base_tensor_root,
                squarefree.coefficient_root,
            )?,
            None,
        )
    };
    let decoded_answer_coefficients =
        decode_fp16_values(answer_coefficients, H4ProofPackageV1Error::AnswerCommitment)?;
    verify_construction_8_2_spotchecks(
        &decoded_answer_coefficients,
        &main_queries,
        &auxiliary_queries,
        &multiproofs,
        combination,
    )?;
    let tensor_coefficient_start = decoded_answer_coefficients
        .len()
        .checked_sub(H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES / 64)
        .ok_or(H4ProofPackageV1Error::AnswerCommitment)?;
    let (computed_answer_tensor_root, answer_tensor_openings) =
        if let Some(openings) = native_answer {
            (answer_tensor_root, openings)
        } else {
            answer_tensor_root_and_openings(
                &decoded_answer_coefficients[tensor_coefficient_start..],
                &tensor_query_indices,
            )?
        };
    if computed_answer_tensor_root != answer_tensor_root
        || answer_tensor_openings.len() != H4_AUXILIARY_OPENINGS
        || multiproofs.base_openings.len() != H4_AUXILIARY_OPENINGS
        || multiproofs.mask_openings.len() != H4_AUXILIARY_OPENINGS
    {
        return Err(H4ProofPackageV1Error::TensorCode);
    }
    for ((answer, base), mask) in answer_tensor_openings
        .iter()
        .zip(&multiproofs.base_openings)
        .zip(&multiproofs.mask_openings)
    {
        if *answer != *base + combination * *mask {
            return Err(H4ProofPackageV1Error::TensorRelation);
        }
    }
    let (answer_functional, masked_source_functionals) = verify_answer_functional(
        &decoded_answer_coefficients,
        &public_view.claims,
        claim_challenge,
        coordinate_challenge,
        row_challenges,
        &public_view.relation_terminals,
        epsilon,
        &squarefree,
        &booleanity,
        &padding,
        complete_mask_round.outputs[0],
    )?;
    let source_functional = row_sumcheck.terminal_target
        + squarefree.masked_target
        + epsilon * masked_source_functionals.masked_target;
    if answer_functional != base_target + combination * source_functional {
        return Err(H4ProofPackageV1Error::Functional);
    }
    let actual_package_commitment = package_commitment(encoded);

    let mut binding_hash = Sha3_512::new();
    binding_hash.update(PRECHALLENGE_BINDING_DOMAIN);
    binding_hash.update([profile as u8, expected_shard_index, profile.shard_count()]);
    binding_hash.update(attempt.to_be_bytes());
    binding_hash.update(statement_commitment);
    binding_hash.update(session_id);
    binding_hash.update(schedule_commitment);
    binding_hash.update(actual_package_commitment);
    binding_hash.update(source_root);
    binding_hash.update(base_tensor_root);
    binding_hash.update(gkr_mask_tensor_root);
    binding_hash.update(answer_tensor_root);
    binding_hash.update(claim_message);
    binding_hash.update(base_message);
    binding_hash.update(answer_message);
    binding_hash.update(row_sumcheck.mask_functional_claim.encode());
    binding_hash.update(row_sumcheck.terminal_target.encode());
    binding_hash.update(answer_functional.encode());
    binding_hash.update(source_functional.encode());
    binding_hash.update(state_relation_source_digest);
    binding_hash.update(state_relation.transcript_digest);
    binding_hash.update(
        u32::try_from(state_relation.mask_constraints.len())
            .map_err(|_| H4ProofPackageV1Error::Rank)?
            .to_be_bytes(),
    );
    binding_hash.update(squarefree_boundary.transcript_digest);
    binding_hash.update(
        u32::try_from(squarefree_boundary.mask_constraints.len())
            .map_err(|_| H4ProofPackageV1Error::Rank)?
            .to_be_bytes(),
    );
    binding_hash.update(booleanity.transcript_commitment);
    binding_hash.update(booleanity.masked_terminal_left.encode());
    binding_hash.update(booleanity.masked_terminal_right.encode());
    binding_hash.update(booleanity.left_challenge.encode());
    binding_hash.update(booleanity.right_challenge.encode());
    binding_hash.update(booleanity.w_challenge.encode());
    binding_hash.update(
        u32::try_from(booleanity.mask_layer)
            .map_err(|_| H4ProofPackageV1Error::Rank)?
            .to_be_bytes(),
    );
    binding_hash.update(padding.transcript_commitment);
    binding_hash.update(padding.masked_terminal.encode());
    binding_hash.update(padding.functional_mixing_challenge.encode());
    binding_hash.update(
        u32::try_from(padding.mask_layer)
            .map_err(|_| H4ProofPackageV1Error::Rank)?
            .to_be_bytes(),
    );
    binding_hash.update(masked_source_functionals.commitment);
    binding_hash.update(masked_source_functionals.masked_target.encode());
    binding_hash.update(masked_source_functionals.answer_main_functional.encode());
    binding_hash.update(masked_source_functionals.answer_mask_functional.encode());
    binding_hash.update(
        u32::try_from(complete_mask_constraints.len())
            .map_err(|_| H4ProofPackageV1Error::Rank)?
            .to_be_bytes(),
    );
    binding_hash.update(query_seed.encode());
    binding_hash.update(final_transcript_root);
    let prechallenge_binding_commitment = binding_hash.finalize().into();

    Ok(VerifiedH4ShardPackageV1Boundary {
        package_commitment: actual_package_commitment,
        source_root,
        base_tensor_root,
        gkr_mask_tensor_root,
        answer_tensor_root,
        prechallenge_binding_commitment,
        squarefree,
        tensor_observations: 2 * H4_AUXILIARY_OPENINGS,
        serialized_pcs_opening_scalars: H4_SERIALIZED_PCS_OPENING_SCALARS,
        answer_functional,
        source_functional,
        gkr_mask_constraint_count: gkr_mask_batch.constraints.len(),
        state_relation_transcript_digest: state_relation.transcript_digest,
        state_relation_mask_constraints: state_relation.mask_constraints,
        squarefree_transcript_digest: squarefree_boundary.transcript_digest,
        squarefree_mask_constraints: squarefree_boundary.mask_constraints,
        booleanity,
        padding,
        masked_source_functionals,
        complete_mask_constraint_count: complete_mask_constraints.len(),
    })
}

/// Verify the exact aggregate transport, one dual-PQ authenticated global coin,
/// every synchronized round frame, and each shard's BLSQAB02/public-answer byte
/// binding. This deliberately is not H4 acceptance: the versioned 128-byte
/// strict-PQ root migration and post-parent-OODS bridge verifier remain
/// mandatory downstream.
pub fn verify_h4_aggregate_package_v1_boundary(
    encoded: &[u8],
    key: H4AggregatePackageV1VerificationKey,
) -> Result<VerifiedH4AggregatePackageV1Boundary, H4ProofPackageV1Error> {
    if encoded.len() < H4_AGGREGATE_PACKAGE_V1_HEADER_BYTES {
        return Err(H4ProofPackageV1Error::Length);
    }
    if encoded.get(..8) != Some(H4_AGGREGATE_PACKAGE_V1_MAGIC) {
        return Err(H4ProofPackageV1Error::Magic);
    }
    if u16_at(encoded, 8)? != H4_AGGREGATE_PACKAGE_V1_VERSION {
        return Err(H4ProofPackageV1Error::Version);
    }
    let profile = parse_profile(encoded[10])?;
    let shard_count = encoded[11];
    let attempt = u16_at(encoded, 12)?;
    if profile != key.profile
        || key.governed_profile_code != profile.code()
        || key.governed_profile_label != profile.governed_label()
        || shard_count != profile.shard_count()
        || attempt != key.expected_attempt
        || attempt >= H4_DURABLE_MAX_ATTEMPTS_PER_STATEMENT
        || u16_at(encoded, 14)? != 0
    {
        return Err(H4ProofPackageV1Error::Flags);
    }
    let public_coin_length = usize::try_from(u64_at(encoded, 16)?)
        .map_err(|_| H4ProofPackageV1Error::AggregateLength)?;
    let shard_body_bytes = usize::try_from(u64_at(encoded, 24)?)
        .map_err(|_| H4ProofPackageV1Error::AggregateLength)?;
    let declared_aggregate_length = usize::try_from(u64_at(encoded, 32)?)
        .map_err(|_| H4ProofPackageV1Error::AggregateLength)?;
    let transcript_rounds = usize::try_from(u32_at(encoded, 40)?)
        .map_err(|_| H4ProofPackageV1Error::AggregateLength)?;
    if public_coin_length == 0
        || public_coin_length > MAX_CHAIN_BUNDLE_BYTES
        || shard_body_bytes != H4_PROOF_PACKAGE_V1_BYTES
        || transcript_rounds != profile.transcript_rounds()
        || u16_at(encoded, 44)? != H4_GLOBAL_ROUND_FRAME_VERSION
        || u16_at(encoded, 46)? != 0
        || encoded[48..64] != [0_u8; 16]
    {
        return Err(H4ProofPackageV1Error::AggregateLength);
    }
    let expected_aggregate_length =
        h4_aggregate_package_v1_exact_bytes(profile, public_coin_length)
            .ok_or(H4ProofPackageV1Error::AggregateLength)?;
    if declared_aggregate_length != expected_aggregate_length
        || encoded.len() != expected_aggregate_length
    {
        return Err(H4ProofPackageV1Error::AggregateLength);
    }
    if encoded[64..128] != NULL_PROOF_SUITE_ID {
        return Err(H4ProofPackageV1Error::ProofSuite);
    }
    let profile_identity = digest64(&encoded[128..192])?;
    let program_commitment = digest64(&encoded[192..256])?;
    let schedule_commitment = digest64(&encoded[256..320])?;
    let session_id = digest64(&encoded[320..384])?;
    let contributors_commitment = digest64(&encoded[384..448])?;
    let statement_commitment = digest64(&encoded[448..512])?;
    let pinned = [
        &key.profile_identity,
        &key.program_commitment,
        &key.schedule_commitment,
        &key.session_id,
        &key.public_coin_contributors_commitment,
        &key.statement_commitment,
        &key.aggregate_package_commitment,
        &key.expected_state_relation_source_digest,
    ];
    if pinned.into_iter().any(|value| !nonzero(value))
        || profile_identity != key.profile_identity
        || program_commitment != key.program_commitment
        || schedule_commitment != key.schedule_commitment
        || session_id != key.session_id
        || contributors_commitment != key.public_coin_contributors_commitment
        || statement_commitment != key.statement_commitment
    {
        return Err(H4ProofPackageV1Error::Identity);
    }
    let gkr_statement_bindings =
        derive_gkr_statement_bindings(profile, key.gkr_statement_binding_inputs)?;
    if gkr_statement_bindings != key.expected_gkr_statement_bindings {
        return Err(H4ProofPackageV1Error::Identity);
    }
    let actual_aggregate_package_commitment = aggregate_package_commitment(encoded);
    if actual_aggregate_package_commitment != key.aggregate_package_commitment {
        return Err(H4ProofPackageV1Error::Commitment);
    }

    let public_coin_start = H4_AGGREGATE_PACKAGE_V1_HEADER_BYTES;
    let shard_bodies_start = public_coin_start + public_coin_length;
    let bundle = decode_chained_public_coin_bundle(&encoded[public_coin_start..shard_bodies_start])
        .map_err(|_| H4ProofPackageV1Error::PublicCoin)?;
    if bundle.session_id != session_id
        || bundle.schedule_commitment != schedule_commitment
        || bundle.attempt != attempt
        || bundle.rounds.len() != transcript_rounds
    {
        return Err(H4ProofPackageV1Error::TranscriptSchedule);
    }
    if contributor_set_commitment(&bundle) != contributors_commitment {
        return Err(H4ProofPackageV1Error::ContributorSet);
    }
    let challenges = verify_selected_state_composed_public_coin_bundle(
        &bundle,
        profile.state_capacity() as usize,
    )
    .map_err(|_| H4ProofPackageV1Error::PublicCoin)?;
    if challenges.len() != bundle.rounds.len() {
        return Err(H4ProofPackageV1Error::TranscriptSchedule);
    }
    let global_frames = bundle
        .rounds
        .iter()
        .map(|round| parse_h4_global_round_frame(&round.prover_message, profile, round.descriptor))
        .collect::<Result<Vec<_>, _>>()?;

    let unique_kind = |kind: u16| {
        bundle
            .rounds
            .iter()
            .enumerate()
            .filter(|(_, round)| round.descriptor.kind == kind)
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
    };
    let claim_batch = unique_kind(KIND_CLAIM_BATCH);
    let initial_sumcheck = unique_kind(KIND_INITIAL_SUMCHECK);
    let row_sumchecks = unique_kind(KIND_ROW_SUMCHECK);
    let base_masks = unique_kind(KIND_BASE_MASKS);
    let answer_queries = unique_kind(KIND_ANSWER_QUERIES);
    if claim_batch.len() != 1
        || initial_sumcheck.len() != 1
        || row_sumchecks.len() != WORD_SUMCHECK_ROUNDS
        || base_masks.len() != 1
        || answer_queries.len() != 1
    {
        return Err(H4ProofPackageV1Error::TranscriptSchedule);
    }
    let claim_batch = claim_batch[0];
    let initial_sumcheck = initial_sumcheck[0];
    let base_masks = base_masks[0];
    let answer_queries = answer_queries[0];
    if !(claim_batch < initial_sumcheck
        && row_sumchecks.first() == Some(&(initial_sumcheck + 1))
        && row_sumchecks.windows(2).all(|pair| pair[1] == pair[0] + 1)
        && row_sumchecks.last().is_some_and(|last| *last < base_masks)
        && base_masks < answer_queries)
        || bundle.rounds[claim_batch].descriptor.output_count != 6
        || bundle.rounds[initial_sumcheck].descriptor.output_count != 1
        || row_sumchecks
            .iter()
            .any(|round| bundle.rounds[*round].descriptor.output_count != 1)
        || bundle.rounds[base_masks].descriptor.output_count != 1
        || bundle.rounds[answer_queries].descriptor.output_count != 1
        || challenges[claim_batch].field_elements.len() != 6
        || challenges[initial_sumcheck].field_elements.len() != 1
        || row_sumchecks
            .iter()
            .any(|round| challenges[*round].field_elements.len() != 1)
        || challenges[base_masks].field_elements.len() != 1
        || challenges[answer_queries].field_elements.len() != 1
    {
        return Err(H4ProofPackageV1Error::TranscriptSchedule);
    }
    let claim_frame = &global_frames[claim_batch];
    let initial_frame = &global_frames[initial_sumcheck];
    let row_frames = row_sumchecks
        .iter()
        .map(|round| &global_frames[*round])
        .collect::<Vec<_>>();
    let base_frame = &global_frames[base_masks];
    let answer_frame = &global_frames[answer_queries];
    let mixing = [
        challenges[claim_batch].field_elements[2],
        challenges[claim_batch].field_elements[3],
    ];
    let epsilon = challenges[initial_sumcheck].field_elements[0];
    let row_challenges = row_sumchecks
        .iter()
        .map(|round| challenges[*round].field_elements[0])
        .collect::<Vec<_>>();
    let combination = challenges[base_masks].field_elements[0];
    let query_seed = challenges[answer_queries].field_elements[0];

    let mask_rank = gkr_mask_tensor_observation_rank_certificate(profile.state_capacity() as usize)
        .map_err(|_| H4ProofPackageV1Error::Rank)?;
    let enumerated_rank = mask_rank
        .state_composed_transcript_rank
        .checked_add(mask_rank.public_answer_equation_rank)
        .and_then(|rank| rank.checked_add(mask_rank.tensor_pcs_opening_scalars))
        .and_then(|rank| rank.checked_add(mask_rank.base_tensor_pcs_opening_scalars))
        .and_then(|rank| rank.checked_add(mask_rank.base_target_rank))
        .ok_or(H4ProofPackageV1Error::Rank)?;
    if enumerated_rank != mask_rank.complete_observation_rank
        || mask_rank.complete_observation_rank >= mask_rank.joint_coefficient_dimension
        || mask_rank.tensor_pcs_opening_scalars != 1_218
        || mask_rank.base_tensor_pcs_opening_scalars != 1_218
        || mask_rank.public_answer_equation_rank != 32_768
        || mask_rank.base_target_rank != 1
        || mask_rank.residual_dimension
            != mask_rank.joint_coefficient_dimension - mask_rank.complete_observation_rank
        || mask_rank.residual_entropy_bits_lower_bound != mask_rank.residual_dimension * 16 * 30
        || mask_rank.residual_entropy_bits_lower_bound < 256
        || mask_rank.tensor_leaves != 1 << 20
        || mask_rank.tensor_leaf_bytes != 64
    {
        return Err(H4ProofPackageV1Error::Rank);
    }

    let mut shards = Vec::with_capacity(usize::from(shard_count));
    for shard_index in 0..shard_count {
        let body_start = shard_bodies_start + usize::from(shard_index) * shard_body_bytes;
        let body_end = body_start + shard_body_bytes;
        let row_messages = row_frames
            .iter()
            .map(|frame| frame.shard_messages[usize::from(shard_index)])
            .collect::<Vec<_>>();
        let gkr_rounds = (0..GKR_ROUNDS as usize)
            .map(|ordinal| {
                Ok(UniformRelayFreeGkrRound {
                    kind: selected_gkr_round_kind(ordinal as u32)
                        .ok_or(H4ProofPackageV1Error::TranscriptSchedule)?,
                    message: global_frames[ordinal].shard_messages[usize::from(shard_index)]
                        .to_vec(),
                    outputs: challenges[ordinal].field_elements.clone(),
                })
            })
            .collect::<Result<Vec<_>, H4ProofPackageV1Error>>()?;
        let state_relation_start = GKR_ROUNDS as usize;
        let state_relation_end = state_relation_start + STATE_RELATION_ROUNDS as usize;
        let state_relation_rounds = (state_relation_start..state_relation_end)
            .map(|ordinal| H4AuthenticatedRound {
                descriptor: bundle.rounds[ordinal].descriptor,
                message: global_frames[ordinal].shard_messages[usize::from(shard_index)].to_vec(),
                outputs: challenges[ordinal].field_elements.clone(),
            })
            .collect::<Vec<_>>();
        let squarefree_start = state_relation_end;
        let squarefree_end = squarefree_start
            + state_squarefree_authenticated_rounds(usize::from(profile.state_capacity()))
                .ok_or(H4ProofPackageV1Error::SquarefreeClaims)? as usize;
        let squarefree_rounds = (squarefree_start..squarefree_end)
            .map(|ordinal| H4AuthenticatedRound {
                descriptor: bundle.rounds[ordinal].descriptor,
                message: global_frames[ordinal].shard_messages[usize::from(shard_index)].to_vec(),
                outputs: challenges[ordinal].field_elements.clone(),
            })
            .collect::<Vec<_>>();
        let booleanity_end = squarefree_end
            + 4
            + usize::try_from(H4_BOOLEANITY_VARIABLES)
                .map_err(|_| H4ProofPackageV1Error::Booleanity)?;
        let booleanity_rounds = (squarefree_end..booleanity_end)
            .map(|ordinal| H4AuthenticatedRound {
                descriptor: bundle.rounds[ordinal].descriptor,
                message: global_frames[ordinal].shard_messages[usize::from(shard_index)].to_vec(),
                outputs: challenges[ordinal].field_elements.clone(),
            })
            .collect::<Vec<_>>();
        let padding_end = booleanity_end
            + 2
            + usize::try_from(H4_PADDING_VARIABLES).map_err(|_| H4ProofPackageV1Error::Padding)?;
        let padding_rounds = (booleanity_end..padding_end)
            .map(|ordinal| H4AuthenticatedRound {
                descriptor: bundle.rounds[ordinal].descriptor,
                message: global_frames[ordinal].shard_messages[usize::from(shard_index)].to_vec(),
                outputs: challenges[ordinal].field_elements.clone(),
            })
            .collect::<Vec<_>>();
        let complete_mask_round = H4AuthenticatedRound {
            descriptor: bundle.rounds[padding_end].descriptor,
            message: global_frames[padding_end].shard_messages[usize::from(shard_index)].to_vec(),
            outputs: challenges[padding_end].field_elements.clone(),
        };
        shards.push(verify_h4_shard_package_v1_boundary(
            &encoded[body_start..body_end],
            profile,
            shard_index,
            attempt,
            profile_identity,
            program_commitment,
            schedule_commitment,
            session_id,
            statement_commitment,
            claim_frame.shard_messages[usize::from(shard_index)],
            initial_frame.shard_messages[usize::from(shard_index)],
            &row_messages,
            base_frame.shard_messages[usize::from(shard_index)],
            answer_frame.shard_messages[usize::from(shard_index)],
            challenges[claim_batch].field_elements[0],
            challenges[claim_batch].field_elements[1],
            mixing,
            epsilon,
            &row_challenges,
            combination,
            query_seed,
            bundle.claimed_final_transcript_root,
            gkr_statement_bindings[usize::from(shard_index)],
            gkr_rounds,
            key.expected_state_relation_source_digest,
            state_relation_rounds,
            squarefree_rounds,
            booleanity_rounds,
            padding_rounds,
            complete_mask_round,
            None,
        )?);
    }

    let mut binding_hash = Sha3_512::new();
    binding_hash.update(PRECHALLENGE_BINDING_DOMAIN);
    binding_hash.update([profile as u8, shard_count]);
    binding_hash.update(attempt.to_be_bytes());
    binding_hash.update(statement_commitment);
    binding_hash.update(session_id);
    binding_hash.update(schedule_commitment);
    binding_hash.update(contributors_commitment);
    binding_hash.update(key.expected_state_relation_source_digest);
    binding_hash.update(query_seed.encode());
    binding_hash.update(bundle.claimed_final_transcript_root);
    for shard in &shards {
        binding_hash.update(shard.package_commitment);
        binding_hash.update(shard.source_root);
        binding_hash.update(shard.base_tensor_root);
        binding_hash.update(shard.gkr_mask_tensor_root);
        binding_hash.update(shard.answer_tensor_root);
        binding_hash.update(shard.squarefree.coefficient_root);
        binding_hash.update(shard.squarefree.claims_digest);
        binding_hash.update(shard.squarefree.masked_target.encode());
        binding_hash.update(
            u32::try_from(shard.tensor_observations)
                .map_err(|_| H4ProofPackageV1Error::Rank)?
                .to_be_bytes(),
        );
        binding_hash.update(
            u32::try_from(shard.serialized_pcs_opening_scalars)
                .map_err(|_| H4ProofPackageV1Error::Rank)?
                .to_be_bytes(),
        );
        binding_hash.update(shard.answer_functional.encode());
        binding_hash.update(shard.source_functional.encode());
        binding_hash.update(
            u32::try_from(shard.gkr_mask_constraint_count)
                .map_err(|_| H4ProofPackageV1Error::Rank)?
                .to_be_bytes(),
        );
        binding_hash.update(shard.state_relation_transcript_digest);
        binding_hash.update(
            u32::try_from(shard.state_relation_mask_constraints.len())
                .map_err(|_| H4ProofPackageV1Error::Rank)?
                .to_be_bytes(),
        );
        binding_hash.update(shard.squarefree_transcript_digest);
        binding_hash.update(
            u32::try_from(shard.squarefree_mask_constraints.len())
                .map_err(|_| H4ProofPackageV1Error::Rank)?
                .to_be_bytes(),
        );
        binding_hash.update(shard.booleanity.transcript_commitment);
        binding_hash.update(shard.padding.transcript_commitment);
        binding_hash.update(shard.masked_source_functionals.commitment);
        binding_hash.update(shard.masked_source_functionals.masked_target.encode());
        binding_hash.update(
            shard
                .masked_source_functionals
                .answer_main_functional
                .encode(),
        );
        binding_hash.update(
            shard
                .masked_source_functionals
                .answer_mask_functional
                .encode(),
        );
        binding_hash.update(
            u32::try_from(shard.complete_mask_constraint_count)
                .map_err(|_| H4ProofPackageV1Error::Rank)?
                .to_be_bytes(),
        );
        binding_hash.update(shard.prechallenge_binding_commitment);
    }
    for statement_binding in gkr_statement_bindings {
        binding_hash.update(statement_binding);
    }
    let prechallenge_binding_commitment = binding_hash.finalize().into();

    Ok(VerifiedH4AggregatePackageV1Boundary {
        profile,
        attempt,
        aggregate_package_commitment: actual_aggregate_package_commitment,
        statement_commitment,
        schedule_commitment,
        session_id,
        final_transcript_root: bundle.claimed_final_transcript_root,
        prechallenge_binding_commitment,
        query_seed,
        shards,
        mask_rank,
        gkr_statement_bindings,
        state_relation_source_digest: key.expected_state_relation_source_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fp16(value: u32) -> Fp16 {
        Fp16::from_m31(crate::field::M31::from_canonical(value).unwrap())
    }

    #[test]
    fn hand_computed_three_variable_mle_matches_lsb_source_layout() {
        let values = [2_u32, 5, 7, 11, 13, 17, 19, 23]
            .into_iter()
            .map(test_fp16)
            .collect::<Vec<_>>();
        let point = [Fp16::ONE, Fp16::ZERO, Fp16::ONE];
        let expected = test_fp16(17);
        assert_eq!(multilinear_evaluate(&values, &point).unwrap(), expected);

        let weights = multilinear_weights(&point).unwrap();
        assert_eq!(weights.len(), values.len());
        assert_eq!(weights[5], Fp16::ONE);
        for (index, weight) in weights.iter().copied().enumerate() {
            if index != 5 {
                assert!(weight.is_zero(), "unexpected nonzero weight at {index}");
            }
        }
        assert_eq!(inner_product(&values, &weights).unwrap(), expected);
    }

    #[test]
    fn hand_computed_four_variable_packed_node_mle_matches_lsb_source_layout() {
        // Paper calculation: point (1,0,1,0) selects source index 0b0101 = 5.
        // The hand-written packed coefficients are 1..16, so the expected
        // result is coefficient 6 (the index is zero-based).
        let packed =
            Fp16::from_coefficients([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
                .unwrap();
        let point = [test_fp16(1), test_fp16(0), test_fp16(1), test_fp16(0)];
        let weights = h4_component_equality_weights(&point).unwrap();
        assert_eq!(h4_packed_node_mle(packed, &weights).unwrap(), test_fp16(6));
    }

    struct BooleanityFixture {
        source_root: [u8; 64],
        mask_root: [u8; 64],
        statement_binding: [u8; 64],
        prelude: Vec<u8>,
        prelude_outputs: Vec<Fp16>,
        rounds: Vec<Vec<u8>>,
        challenges: Vec<Fp16>,
        terminal: Vec<u8>,
        terminal_challenge: Fp16,
    }

    struct PaddingFixture {
        source_root: [u8; 64],
        mask_root: [u8; 64],
        statement_binding: [u8; 64],
        prelude: Vec<u8>,
        prelude_outputs: Vec<Fp16>,
        rounds: Vec<Vec<u8>>,
        challenges: Vec<Fp16>,
        terminal: Vec<u8>,
        functional_mixing_challenge: Fp16,
    }

    fn booleanity_fixture() -> BooleanityFixture {
        let profile = H4ProofProfile::K128;
        let source_root = [0x31; 64];
        let mask_root = [0x32; 64];
        let statement_binding = [0x33; 64];
        let prelude =
            h4_booleanity_prelude_message(profile, 0, source_root, mask_root, statement_binding)
                .unwrap();
        let mut prelude_outputs = vec![test_fp16(17)];
        prelude_outputs.extend((0..29).map(|index| test_fp16(101 + index)));
        let challenges = (0..31)
            .map(|index| test_fp16(211 + index))
            .collect::<Vec<_>>();
        let mut rounds = Vec::with_capacity(31);
        for round in 0..31 {
            let degree = if round < 29 {
                H4_BOOLEANITY_GROUP_DEGREE
            } else {
                H4_BOOLEANITY_SOURCE_DEGREE
            };
            let coefficients = vec![Fp16::ZERO; degree + 1];
            rounds.push(h4_booleanity_round_message(round, &coefficients).unwrap());
        }
        let round_refs = rounds.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let transcript_commitment = h4_booleanity_transcript_commitment(
            profile,
            0,
            &prelude,
            &prelude_outputs,
            &round_refs,
            &challenges,
        )
        .unwrap();
        let terminal = h4_booleanity_terminal_message(
            profile,
            0,
            source_root,
            mask_root,
            transcript_commitment,
            [Fp16::ZERO; 3],
            Fp16::ZERO,
            Fp16::ZERO,
        )
        .unwrap();
        BooleanityFixture {
            source_root,
            mask_root,
            statement_binding,
            prelude,
            prelude_outputs,
            rounds,
            challenges,
            terminal,
            terminal_challenge: test_fp16(401),
        }
    }

    fn padding_fixture() -> PaddingFixture {
        let profile = H4ProofProfile::K128;
        let source_root = [0x41; 64];
        let mask_root = [0x42; 64];
        let statement_binding = [0x43; 64];
        let prelude =
            h4_padding_prelude_message(profile, 0, source_root, mask_root, statement_binding)
                .unwrap();
        let mut prelude_outputs = vec![test_fp16(19)];
        prelude_outputs.extend((0..29).map(|index| test_fp16(501 + index)));
        let challenges = (0..29)
            .map(|index| test_fp16(601 + index))
            .collect::<Vec<_>>();
        let rounds = (0..29)
            .map(|round| h4_padding_round_message(round, [Fp16::ZERO; 3]).unwrap())
            .collect::<Vec<_>>();
        let round_refs = rounds.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let transcript_commitment = h4_padding_transcript_commitment(
            profile,
            0,
            &prelude,
            &prelude_outputs,
            &round_refs,
            &challenges,
        )
        .unwrap();
        let terminal = h4_padding_terminal_message(
            profile,
            0,
            source_root,
            mask_root,
            transcript_commitment,
            Fp16::ZERO,
        )
        .unwrap();
        PaddingFixture {
            source_root,
            mask_root,
            statement_binding,
            prelude,
            prelude_outputs,
            rounds,
            challenges,
            terminal,
            functional_mixing_challenge: test_fp16(701),
        }
    }

    fn verify_booleanity_fixture(
        fixture: &BooleanityFixture,
    ) -> Result<VerifiedH4BooleanityAlgebraBoundary, H4ProofPackageV1Error> {
        let round_refs = fixture.rounds.iter().map(Vec::as_slice).collect::<Vec<_>>();
        verify_h4_booleanity_algebra_boundary(
            H4ProofProfile::K128,
            0,
            fixture.source_root,
            fixture.mask_root,
            fixture.statement_binding,
            &fixture.prelude,
            &fixture.prelude_outputs,
            &round_refs,
            &fixture.challenges,
            &fixture.terminal,
            fixture.terminal_challenge,
        )
    }

    fn verify_padding_fixture(
        fixture: &PaddingFixture,
    ) -> Result<VerifiedH4PaddingAlgebraBoundary, H4ProofPackageV1Error> {
        let round_refs = fixture.rounds.iter().map(Vec::as_slice).collect::<Vec<_>>();
        verify_h4_padding_algebra_boundary(
            H4ProofProfile::K128,
            0,
            fixture.source_root,
            fixture.mask_root,
            fixture.statement_binding,
            &fixture.prelude,
            &fixture.prelude_outputs,
            &round_refs,
            &fixture.challenges,
            &fixture.terminal,
            fixture.functional_mixing_challenge,
        )
    }

    fn boolean_point(index: usize, variables: usize) -> Vec<Fp16> {
        (0..variables)
            .map(|bit| {
                if index & (1 << bit) == 0 {
                    Fp16::ZERO
                } else {
                    Fp16::ONE
                }
            })
            .collect()
    }

    #[test]
    fn fixed_container_and_answer_sizes_are_exact() {
        assert_eq!(H4ProofProfile::K128.code(), 1);
        assert_eq!(H4ProofProfile::K128.governed_label(), "K128_CALIBRATION");
        assert_eq!(H4ProofProfile::K512.code(), 3);
        assert_eq!(H4ProofProfile::K512.governed_label(), "K512_CALIBRATION");
        assert_eq!(H4_PROOF_PACKAGE_V1_BYTES, 201_326_592);
        assert_eq!(H4_K128_COMPLETE_MASK_CONSTRAINTS, 508 + 4 + 110 + 2 + 2);
        assert_eq!(H4_K512_COMPLETE_MASK_CONSTRAINTS, 508 + 4 + 134 + 2 + 2);
        assert_eq!(H4_ANSWER_MAIN_COEFFICIENT_BYTES, 4_325_376);
        assert_eq!(H4_ANSWER_ORDINARY_AUXILIARY_COEFFICIENT_BYTES, 2_090_240);
        assert_eq!(H4_ANSWER_GKR_TENSOR_COEFFICIENT_BYTES, 2_097_152);
        assert_eq!(H4_ANSWER_COEFFICIENT_BYTES, 8_512_768);
        assert_eq!(H4_ANSWER_COEFFICIENT_BYTES / 64, 133_012);
        assert_eq!(H4_PACKED_CLAIMS_BYTES, 52_364);
        assert_eq!(H4_GKR_RELATION_TERMINAL_BYTES, 4_096);
        assert_eq!(
            H4_PUBLIC_VIEW_V1_HEADER_BYTES
                + H4_PACKED_CLAIMS_BYTES
                + H4_GKR_RELATION_TERMINAL_BYTES,
            56_492
        );
        assert_eq!(H4_INITIAL_PCS_OPENING_SCALARS, 819_200);
        assert_eq!(H4_COMBINED_AUXILIARY_PCS_OPENING_SCALARS, 23_142);
        assert_eq!(H4_SERIALIZED_PCS_OPENING_SCALARS, 847_596);
        assert_eq!(H4_BLSQAB02_BYTES, 1_828);
        assert_eq!(
            H4_HASH_BUS_BOUNDARY_HEADER_BYTES + H4_HASH_BUS_BOUNDARY_BYTES_PER_SHARD,
            52_429_015
        );
        assert_eq!(
            H4_HASH_BUS_BOUNDARY_HEADER_BYTES + 4 * H4_HASH_BUS_BOUNDARY_BYTES_PER_SHARD,
            209_715_415
        );
        assert_eq!(H4_GLOBAL_MAX_SHARD_MESSAGE_BYTES, 262_135);
        assert_eq!(H4_KIND801_MAX_K512_GLOBAL_FRAME_BYTES, 524_388);
        assert!(H4_KIND801_MAX_K512_GLOBAL_FRAME_BYTES <= MAX_PROVER_MESSAGE_BYTES);
        assert_eq!(
            H4_AGGREGATE_PACKAGE_V1_HEADER_BYTES
                + MAX_CHAIN_BUNDLE_BYTES
                + H4_PROOF_PACKAGE_V1_BYTES,
            218_104_320
        );
        assert_eq!(
            H4_AGGREGATE_PACKAGE_V1_HEADER_BYTES
                + MAX_CHAIN_BUNDLE_BYTES
                + 4 * H4_PROOF_PACKAGE_V1_BYTES,
            822_084_096
        );
    }

    #[test]
    fn booleanity_uses_exact_hash_only_virtual_geometry_and_padding_exception() {
        assert_eq!(
            H4_BOOLEANITY_COMPONENT_VARIABLES
                + H4_BOOLEANITY_COEFFICIENT_VARIABLES
                + H4_BOOLEANITY_WORD_VARIABLES,
            29
        );
        assert_eq!(H4_HASH_VIRTUAL_BITS, 419_430_400);
        assert_eq!(H4_STATE_LANE_VIRTUAL_CELLS, 4_194_304);
        assert_eq!(H4_GLOBAL_PADDING_VIRTUAL_CELLS, 113_246_208);
        assert_eq!(
            H4_HASH_VIRTUAL_BITS + H4_STATE_LANE_VIRTUAL_CELLS + H4_GLOBAL_PADDING_VIRTUAL_CELLS,
            16 * H4_SOURCE_COEFFICIENT_POSITIONS * H4_SOURCE_GLOBAL_WORDS
        );

        // Both boundaries' wire<1600 cells are Boolean hash bits.
        assert_eq!(
            h4_source_cell_class(1_599, 0).unwrap(),
            H4SourceCellClass::HashBit
        );
        assert_eq!(
            h4_source_cell_class(1_599, 511).unwrap(),
            H4SourceCellClass::HashBit
        );
        // Boundary zero never owns an arbitrary state lane.
        assert_eq!(
            h4_source_cell_class(1_600, 0).unwrap(),
            H4SourceCellClass::GlobalPadding
        );
        // Boundary one, group<4096, wires1600..1663 are the sole exception.
        assert_eq!(
            h4_source_cell_class(1_600, 256).unwrap(),
            H4SourceCellClass::StateLaneException
        );
        assert_eq!(
            h4_source_cell_class(1_663 | (31 << 11), 383).unwrap(),
            H4SourceCellClass::StateLaneException
        );
        // group=4096 and wire=1664 are padding even on boundary one.
        assert_eq!(
            h4_source_cell_class(1_600, 384).unwrap(),
            H4SourceCellClass::GlobalPadding
        );
        assert_eq!(
            h4_source_cell_class(1_664, 256).unwrap(),
            H4SourceCellClass::GlobalPadding
        );
    }

    #[test]
    fn booleanity_algebra_accepts_generic_cubic_quintic_topology_and_two_mask_constraints() {
        let fixture = booleanity_fixture();
        let verified = verify_booleanity_fixture(&fixture).unwrap();
        assert_eq!(verified.source_root(), fixture.source_root);
        assert_eq!(verified.mask_tensor_root(), fixture.mask_root);
        assert_eq!(
            verified.mask_constraints.len(),
            H4_BOOLEANITY_MASK_CONSTRAINTS
        );
        assert_eq!(
            verified.mask_layer(),
            selected_booleanity_mask_layer(128).unwrap()
        );
        assert_eq!(
            fixture.rounds[..29]
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            vec![H4_BOOLEANITY_CUBIC_ROUND_BYTES; 29]
        );
        assert_eq!(
            fixture.rounds[29..]
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            vec![H4_BOOLEANITY_QUINTIC_ROUND_BYTES; 2]
        );
    }

    #[test]
    fn booleanity_rejects_cubic_source_round_root_transplant_and_bad_challenges() {
        let mut fixture = booleanity_fixture();
        fixture.rounds[29][12] = H4_BOOLEANITY_GROUP_DEGREE as u8;
        fixture.rounds[29].truncate(H4_BOOLEANITY_CUBIC_ROUND_BYTES);
        assert_eq!(
            verify_booleanity_fixture(&fixture),
            Err(H4ProofPackageV1Error::Booleanity)
        );

        let mut fixture = booleanity_fixture();
        fixture.terminal[16] ^= 1;
        assert_eq!(
            verify_booleanity_fixture(&fixture),
            Err(H4ProofPackageV1Error::Booleanity)
        );

        let mut fixture = booleanity_fixture();
        fixture.challenges[7] = Fp16::ONE;
        assert_eq!(
            verify_booleanity_fixture(&fixture),
            Err(H4ProofPackageV1Error::Booleanity)
        );

        let mut fixture = booleanity_fixture();
        fixture.terminal_challenge = Fp16::ZERO;
        assert_eq!(
            verify_booleanity_fixture(&fixture),
            Err(H4ProofPackageV1Error::Booleanity)
        );
    }

    #[test]
    fn padding_algebra_accepts_exact_linear_masked_identity() {
        let fixture = padding_fixture();
        let verified = verify_padding_fixture(&fixture).unwrap();
        assert_eq!(verified.source_root, fixture.source_root);
        assert_eq!(verified.mask_tensor_root, fixture.mask_root);
        assert_eq!(
            verified.mask_layer,
            selected_padding_mask_layer(128).unwrap()
        );
        assert_eq!(verified.mask_constraints.len(), H4_PADDING_MASK_CONSTRAINTS);
        assert_eq!(fixture.prelude.len(), H4_PADDING_PRELUDE_BYTES);
        assert_eq!(fixture.terminal.len(), H4_PADDING_TERMINAL_BYTES);
        assert!(
            fixture
                .rounds
                .iter()
                .all(|round| round.len() == H4_PADDING_ROUND_BYTES)
        );
    }

    #[test]
    fn padding_rejects_root_selector_terminal_and_challenge_mutations() {
        let mut fixture = padding_fixture();
        fixture.prelude[80] ^= 1;
        assert_eq!(
            verify_padding_fixture(&fixture),
            Err(H4ProofPackageV1Error::Padding)
        );

        let mut fixture = padding_fixture();
        // Offset 144 begins the verifier-derived layout commitment. This is
        // where the fixed state-lane exception and zero selector are bound.
        fixture.terminal[144] ^= 1;
        assert_eq!(
            verify_padding_fixture(&fixture),
            Err(H4ProofPackageV1Error::Padding)
        );

        let mut fixture = padding_fixture();
        // The terminal transcript digest authenticates the entire preceding
        // message/challenge chain. (The masked terminal itself is intentionally
        // free here and is bound later by kind143 plus Construction 8.2.)
        fixture.terminal[208] ^= 1;
        assert_eq!(
            verify_padding_fixture(&fixture),
            Err(H4ProofPackageV1Error::Padding)
        );

        let mut fixture = padding_fixture();
        fixture.functional_mixing_challenge = Fp16::ZERO;
        assert_eq!(
            verify_padding_fixture(&fixture),
            Err(H4ProofPackageV1Error::Padding)
        );
    }

    #[test]
    fn source_functionals_include_hash_bits_and_exclude_only_the_state_lane() {
        let component_point = boolean_point(0, H4_BOOLEANITY_COMPONENT_VARIABLES);
        let mut main = vec![Fp16::ZERO; H4_SOURCE_COEFFICIENT_POSITIONS];

        let hash_position = 1_599;
        main[hash_position] =
            Fp16::from_coefficients([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let hash_point = boolean_point(hash_position, H4_BOOLEANITY_COEFFICIENT_VARIABLES);
        let boundary_zero = boolean_point(0, H4_BOOLEANITY_WORD_VARIABLES);
        assert_eq!(
            h4_low_source_answer_functional(
                &main,
                &component_point,
                &hash_point,
                H4LowSourceSelector::Hash,
            )
            .unwrap(),
            Fp16::ONE
        );
        let mut full_hash_point = component_point.clone();
        full_hash_point.extend_from_slice(&hash_point);
        full_hash_point.extend_from_slice(&boundary_zero);
        let full_hash_point: [Fp16; 29] = full_hash_point.try_into().unwrap();
        // The source coefficient row is selected-PCS order (output boundary
        // zero, input boundary one), while the H4 binding point remains the
        // canonical input/output point.  A selected boundary-one row therefore
        // maps to the canonical boundary-zero source above.
        let selected_boundary_one = boolean_point(256, H4_BOOLEANITY_WORD_VARIABLES);
        assert_eq!(
            h4_booleanity_source_answer_functional(
                &main,
                &selected_boundary_one,
                &full_hash_point,
                true,
            )
            .unwrap(),
            Fp16::ONE
        );
        assert_eq!(
            h4_padding_source_answer_functional(&main, &boundary_zero, &full_hash_point).unwrap(),
            Fp16::ZERO
        );

        let non_boolean_component_point = [
            Fp16::from_m31(M31::from_canonical(3).unwrap()),
            Fp16::from_m31(M31::from_canonical(5).unwrap()),
            Fp16::from_m31(M31::from_canonical(7).unwrap()),
            Fp16::from_m31(M31::from_canonical(11).unwrap()),
        ];
        let raw_pattern =
            Fp16::from_coefficients([1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1]).unwrap();
        let weights = multilinear_weights(&non_boolean_component_point).unwrap();
        let expected = weights.into_iter().zip(raw_pattern.coefficients()).fold(
            Fp16::ZERO,
            |sum, (weight, coefficient)| {
                sum + weight * Fp16::from_m31(M31::from_canonical(coefficient).unwrap())
            },
        );
        assert_eq!(
            h4_packed_node_mle(
                raw_pattern,
                &h4_component_equality_weights(&non_boolean_component_point).unwrap()
            )
            .unwrap(),
            expected
        );

        main.fill(Fp16::ZERO);
        let state_position = 1_600;
        main[state_position] =
            Fp16::from_coefficients([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let state_point = boolean_point(state_position, H4_BOOLEANITY_COEFFICIENT_VARIABLES);
        let boundary_one_group_low = boolean_point(256, H4_BOOLEANITY_WORD_VARIABLES);
        let mut full_state_point = component_point;
        full_state_point.extend_from_slice(&state_point);
        full_state_point.extend_from_slice(&boundary_one_group_low);
        let full_state_point: [Fp16; 29] = full_state_point.try_into().unwrap();
        assert_eq!(
            h4_padding_source_answer_functional(&main, &boundary_one_group_low, &full_state_point,)
                .unwrap(),
            Fp16::ZERO
        );

        let boundary_zero = boolean_point(0, H4_BOOLEANITY_WORD_VARIABLES);
        let mut nonexception_point = boolean_point(0, H4_BOOLEANITY_COMPONENT_VARIABLES);
        nonexception_point.extend_from_slice(&state_point);
        nonexception_point.extend_from_slice(&boundary_zero);
        let nonexception_point: [Fp16; 29] = nonexception_point.try_into().unwrap();
        assert_eq!(
            h4_padding_source_answer_functional(&main, &boundary_zero, &nonexception_point)
                .unwrap(),
            Fp16::ONE
        );
    }

    #[test]
    fn hand_computed_four_variable_mle_uses_lsb_coordinate_order() {
        // Hand fixture: the point [1, 0, 1, 0] selects index 5 when the
        // first coordinate is bit 0.  The source vector is written here,
        // not generated from a proof or a capture, so this checks the cheap
        // algebra convention before any expensive H4 execution.
        let source = [
            test_fp16(2),
            test_fp16(3),
            test_fp16(5),
            test_fp16(7),
            test_fp16(11),
            test_fp16(13),
            test_fp16(17),
            test_fp16(19),
            test_fp16(23),
            test_fp16(29),
            test_fp16(31),
            test_fp16(37),
            test_fp16(41),
            test_fp16(43),
            test_fp16(47),
            test_fp16(53),
        ];
        let point = [test_fp16(1), test_fp16(0), test_fp16(1), test_fp16(0)];
        let weights = multilinear_weights(&point).unwrap();
        let evaluated = source
            .into_iter()
            .zip(weights)
            .fold(Fp16::ZERO, |sum, (value, weight)| sum + value * weight);
        assert_eq!(evaluated, test_fp16(13));
        assert_eq!(
            multilinear_evaluate(&source, &point).unwrap(),
            test_fp16(13)
        );
    }

    #[test]
    fn tagged_source_claim_uses_wire_first_mask_coordinate_and_serializes_no_raw_terminal() {
        let mut booleanity_fixture = booleanity_fixture();
        let right_source_scale = Fp16::ONE - booleanity_fixture.challenges[30];
        let transcript_commitment: [u8; 64] =
            booleanity_fixture.terminal[216..280].try_into().unwrap();
        booleanity_fixture.terminal = h4_booleanity_terminal_message(
            H4ProofProfile::K128,
            0,
            booleanity_fixture.source_root,
            booleanity_fixture.mask_root,
            transcript_commitment,
            [Fp16::ZERO; 3],
            Fp16::ZERO,
            -right_source_scale,
        )
        .unwrap();
        let booleanity = verify_booleanity_fixture(&booleanity_fixture).unwrap();

        let mut padding_fixture = padding_fixture();
        padding_fixture.source_root = booleanity_fixture.source_root;
        padding_fixture.mask_root = booleanity_fixture.mask_root;
        padding_fixture.statement_binding = booleanity_fixture.statement_binding;
        padding_fixture.prelude = h4_padding_prelude_message(
            H4ProofProfile::K128,
            0,
            padding_fixture.source_root,
            padding_fixture.mask_root,
            padding_fixture.statement_binding,
        )
        .unwrap();
        let round_refs = padding_fixture
            .rounds
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let padding_transcript = h4_padding_transcript_commitment(
            H4ProofProfile::K128,
            0,
            &padding_fixture.prelude,
            &padding_fixture.prelude_outputs,
            &round_refs,
            &padding_fixture.challenges,
        )
        .unwrap();
        padding_fixture.terminal = h4_padding_terminal_message(
            H4ProofProfile::K128,
            0,
            padding_fixture.source_root,
            padding_fixture.mask_root,
            padding_transcript,
            Fp16::ZERO,
        )
        .unwrap();
        let padding = verify_padding_fixture(&padding_fixture).unwrap();

        let layout = selected_state_composed_mask_layout(128).unwrap();
        let mut tensor = vec![Fp16::ZERO; layout.padded_coefficients];
        let probe = layout.layers[booleanity.mask_layer].layer_offset + 3;
        tensor[probe] = Fp16::ONE;
        let complete_mask_challenge = test_fp16(809);
        let claims = derive_h4_masked_source_functional_claims(
            H4ProofProfile::K128,
            &vec![Fp16::ZERO; H4_SOURCE_COEFFICIENT_POSITIONS],
            &tensor,
            &[Fp16::ZERO; H4_BOOLEANITY_WORD_VARIABLES],
            &booleanity,
            &padding,
            complete_mask_challenge,
        )
        .unwrap();
        assert_eq!(claims.masked_target, Fp16::ZERO);
        assert_eq!(claims.answer_main_functional, Fp16::ZERO);
        assert!(nonzero(&claims.commitment));

        let mut expected_weights = vec![Fp16::ZERO; layout.padded_coefficients];
        let mut left_point = booleanity.group_point.to_vec();
        left_point.push(booleanity.left_challenge);
        let mut right_point = booleanity.group_point.to_vec();
        right_point.push(booleanity.right_challenge);
        layout
            .accumulate_layer_boolean_w_sum(
                &mut expected_weights,
                booleanity.mask_layer,
                booleanity.left_challenge,
                boolean_vanishing(&left_point),
            )
            .unwrap();
        layout
            .accumulate_layer_boolean_w_sum(
                &mut expected_weights,
                booleanity.mask_layer,
                booleanity.right_challenge,
                complete_mask_challenge * boolean_vanishing(&right_point),
            )
            .unwrap();
        layout
            .accumulate_layer_boolean_w_sum(
                &mut expected_weights,
                padding.mask_layer,
                padding.sumcheck_point[0],
                padding.functional_mixing_challenge * boolean_vanishing(&padding.sumcheck_point),
            )
            .unwrap();
        assert_eq!(
            claims.answer_mask_functional,
            inner_product(&tensor, &expected_weights).unwrap()
        );

        // Public messages contain only masked terminals. Their exact fixed
        // widths leave no grammar slot for raw b, raw b-1, or mask deltas.
        assert_eq!(booleanity_fixture.terminal.len(), 600);
        assert_eq!(padding_fixture.terminal.len(), 336);
        assert_eq!(
            booleanity_fixture.terminal[17],
            H4_MASKED_SOURCE_FUNCTIONAL_BOOLEANITY_TAG
        );
        assert_eq!(
            padding_fixture.terminal[15],
            H4_MASKED_SOURCE_FUNCTIONAL_PADDING_TAG
        );
    }

    #[test]
    fn governed_gkr_statement_bindings_are_profile_fixed_and_zero_pad_unused_shards() {
        let inputs = H4GkrStatementBindingInputs {
            semantic_program_commitment: [11; 64],
            descriptor_commitment: [12; 64],
            semantic_port_commitment: [13; 64],
            boundary_file_sha3_512: [14; 64],
            gkr_plan_commitment: [15; 64],
        };
        let k128 = derive_gkr_statement_bindings(H4ProofProfile::K128, inputs).unwrap();
        assert!(nonzero(&k128[0]));
        assert_eq!(k128[1..], [[0_u8; 64]; 3]);
        let k512 = derive_gkr_statement_bindings(H4ProofProfile::K512, inputs).unwrap();
        assert!(k512.iter().all(nonzero));
        assert_ne!(k128[0], k512[0]);
        assert!(k512.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[cfg(feature = "std")]
    #[test]
    fn governed_gkr_statement_derivation_matches_canonical_boundary_header() {
        use crate::{
            hash_bus_b16_boundary::HashBusB16BoundaryHeader, wave1a_global_schedule::Profile,
        };

        let inputs = H4GkrStatementBindingInputs {
            semantic_program_commitment: [21; 64],
            descriptor_commitment: [22; 64],
            semantic_port_commitment: [23; 64],
            boundary_file_sha3_512: [24; 64],
            gkr_plan_commitment: [25; 64],
        };
        let header = HashBusB16BoundaryHeader {
            profile: Profile::K128Calibration,
            state_composed: true,
            semantic_program_commitment: inputs.semantic_program_commitment,
            descriptor_commitment: inputs.descriptor_commitment,
            semantic_port_commitment: inputs.semantic_port_commitment,
            coprocessor_shards: 1,
            padded_permutations: H4_PADDED_PERMUTATIONS_PER_SHARD,
            live_wires: H4_LIVE_WIRES_PER_PERMUTATION,
            file_bytes: H4_HASH_BUS_BOUNDARY_HEADER_BYTES + H4_HASH_BUS_BOUNDARY_BYTES_PER_SHARD,
            file_sha3_512: inputs.boundary_file_sha3_512,
        };
        assert_eq!(
            derive_gkr_statement_bindings(H4ProofProfile::K128, inputs).unwrap()[0],
            header
                .gkr_statement_binding(0, inputs.gkr_plan_commitment)
                .unwrap()
        );
    }

    #[test]
    fn fold_and_tensor_query_schedules_are_verifier_owned() {
        let challenges = vec![Fp16::ZERO; WORD_SUMCHECK_ROUNDS];
        let weights = multilinear_weights(&challenges).unwrap();
        assert_eq!(weights.len(), H4_INITIAL_SOURCE_WORDS);
        assert_eq!(weights[0], Fp16::ONE);
        assert!(weights[1..].iter().all(|weight| weight.is_zero()));

        let seed = Fp16::ZERO.encode();
        let inner = exact_queries(
            &seed,
            b"aux_queries",
            H4_AUXILIARY_CODE_VALUES,
            H4_AUXILIARY_OPENINGS,
        )
        .unwrap();
        let tensor = tensor_queries(&seed, &inner).unwrap();
        assert_eq!(tensor.len(), H4_AUXILIARY_OPENINGS);
        assert!(tensor.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(tensor.iter().all(|query| *query < H4_GKR_TENSOR_LEAVES));

        let mut changed_seed = seed;
        changed_seed[0] = 1;
        let changed_inner = exact_queries(
            &changed_seed,
            b"aux_queries",
            H4_AUXILIARY_CODE_VALUES,
            H4_AUXILIARY_OPENINGS,
        )
        .unwrap();
        let changed_tensor = tensor_queries(&changed_seed, &changed_inner).unwrap();
        assert_ne!(inner, changed_inner);
        assert_ne!(tensor, changed_tensor);
    }

    #[test]
    fn global_round_frame_requires_every_shard_once_in_order() {
        let descriptor = ChainedRoundDescriptor {
            kind: 801,
            ordinal: 17,
            output_count: 1,
        };
        let messages = [&[1_u8][..], &[2_u8][..], &[3_u8][..], &[4_u8][..]];
        let mut encoded =
            encode_h4_global_round_frame(H4ProofProfile::K512, descriptor, &messages).unwrap();
        let parsed =
            parse_h4_global_round_frame(&encoded, H4ProofProfile::K512, descriptor).unwrap();
        assert_eq!(
            parsed.shard_messages,
            vec![&[1][..], &[2][..], &[3][..], &[4][..]]
        );

        encoded[H4_GLOBAL_ROUND_FRAME_HEADER_BYTES] = 1;
        assert_eq!(
            parse_h4_global_round_frame(&encoded, H4ProofProfile::K512, descriptor),
            Err(H4ProofPackageV1Error::GlobalFrame)
        );
        assert_eq!(
            encode_h4_global_round_frame(H4ProofProfile::K512, descriptor, &messages[..3]),
            Err(H4ProofPackageV1Error::GlobalFrame)
        );
    }

    #[test]
    fn short_aggregate_rejects_before_inner_parsing() {
        let gkr_statement_binding_inputs = H4GkrStatementBindingInputs {
            semantic_program_commitment: [8; 64],
            descriptor_commitment: [9; 64],
            semantic_port_commitment: [10; 64],
            boundary_file_sha3_512: [11; 64],
            gkr_plan_commitment: [12; 64],
        };
        let expected_gkr_statement_bindings =
            derive_gkr_statement_bindings(H4ProofProfile::K512, gkr_statement_binding_inputs)
                .unwrap();
        let key = H4AggregatePackageV1VerificationKey {
            profile: H4ProofProfile::K512,
            governed_profile_code: 3,
            governed_profile_label: "K512_CALIBRATION",
            expected_attempt: 0,
            profile_identity: [1; 64],
            program_commitment: [2; 64],
            schedule_commitment: [3; 64],
            session_id: [4; 64],
            public_coin_contributors_commitment: [5; 64],
            statement_commitment: [6; 64],
            aggregate_package_commitment: [7; 64],
            expected_state_relation_source_digest: [13; 64],
            gkr_statement_binding_inputs,
            expected_gkr_statement_bindings,
        };
        assert_eq!(
            verify_h4_aggregate_package_v1_boundary(b"BLH4AG01", key),
            Err(H4ProofPackageV1Error::Length)
        );
    }
}
