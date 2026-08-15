//! Fixed relay-free GKR topologies for the semantic/H4 equality bridge.
//!
//! The bridge never commits a third raw hash bus.  Its round-input tables are
//! verifier-fixed sparse linear views of the already committed semantic
//! columns and H4 source.  Products and selector algebra are evaluated only
//! inside these DAGs; the resulting masked source terminals must later be
//! authenticated by Construction 8.2.

use alloc::{vec, vec::Vec};
use sha3::{Digest, Sha3_512};

use crate::{
    binding_multilinear_pcs_v2::{
        BindingMultilinearPcsProofV2, prove_binding_multilinear_opening_v2,
        verify_binding_multilinear_opening_v2,
    },
    binding_root_v2::{BindingDigestV2, BindingRoleV2, BindingRootV2, BindingRootV2Error},
    circle_lagrange_sparse_functional::{
        CircleCoefficientMleProofV3, CircleLagrangeSparseFunctionalError,
        VerifiedCircleLagrangeSparseFunctional, authenticated_circle_opening_from_verified_fri_v3,
        circle_row_functional_dual_terminal_streaming, prove_circle_coefficient_linear_v3,
        verify_circle_coefficient_linear_terminal_v3,
    },
    field::{Fp16, M31_MODULUS},
    fp16_relay_free_gkr_uniform::{
        UniformGkrMaskConstraint, UniformGkrMaskFunctional, aggregate_gkr_mask_constraints,
    },
    gkr_packed_binary_bridge_fp16::PACKED_BINARY_MESSAGE_COEFFICIENTS,
    gkr_sumcheck::{
        LayerOutputClaim, MaskedSharedGroupOracle, SharedGroupDagRoundKind,
        prove_masked_shared_group_dag_layer_interactive_internal, shared_group_terminal_gate_claim,
    },
    gkr_zk_mask::{
        CompleteGkrZkMaskCommitmentLayout, GkrZkMaskError, LibraPriorLayerCorrection,
        boolean_vanishing, polynomial_evaluation,
    },
    h4_bridge_source_response_v2::VerifiedH4BridgeSourceResponseV2,
    h4_proof_package_v2::VerifiedH4BridgeSourceTerminalV2,
    hash_bus::{
        HashBusDescriptor, build_hash_bus_descriptor_with_state, hash_bus_permutation_slot,
    },
    keccak_gkr_dag::{KeccakDagGate, KeccakDagGateKind, KeccakDagLayer, KeccakDagSource},
    master_commitments::Profile as MasterProfile,
    oracle_commitment::derive_oracle_commitment_layouts,
    strict_pq_public_coin_v2::{
        StrictPqFp16PolicyV2, StrictPqFp16RoundOutputV2, StrictPqGovernedVerifierKeyV2,
        StrictPqH4ProfileV2, StrictPqPublicCoinBundleV2, StrictPqRootUseRegistryV2,
        StrictPqRoundDescriptorV2, replay_strict_pq_fp16_public_coin_v2,
    },
    wave1a_global_schedule::Profile as ScheduleProfile,
};

use alloc::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSemanticH4CompositionV3 {
    profile: MasterProfile,
    receipt_binding: BindingDigestV2,
    public_inputs_binding: BindingDigestV2,
}

impl VerifiedSemanticH4CompositionV3 {
    pub const fn profile(&self) -> MasterProfile {
        self.profile
    }

    pub const fn receipt_binding(&self) -> BindingDigestV2 {
        self.receipt_binding
    }
    pub const fn public_inputs_binding(&self) -> BindingDigestV2 {
        self.public_inputs_binding
    }
}

/// Opaque decisive internal composition receipt. It proves that the exact
/// semantic public statement, proof-native semantic/H4 equality, portable H4
/// proof, and typed-state transition were all accepted under one governed
/// K128/K512 profile. It deliberately does not activate a production suite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDecisiveCompositionV3 {
    profile: MasterProfile,
    receipt_binding: BindingDigestV2,
}

impl VerifiedDecisiveCompositionV3 {
    pub const fn profile(&self) -> MasterProfile {
        self.profile
    }
    pub const fn receipt_binding(&self) -> BindingDigestV2 {
        self.receipt_binding
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisiveCompositionV3Error {
    Profile,
    PublicStatement,
    Binding,
}

const SEMANTIC_V3_KIND900_AUTHORITY_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/SEMANTIC-V3/KIND900-AUTHORITY/v1\0";

pub fn semantic_v3_kind900_authority_message(
    profile: MasterProfile,
    semantic_roots: &crate::oracle_commitment::BindingCommittedAirRootsV2,
    h4_pre_alpha_binding: BindingDigestV2,
    coefficient_root_inventory_binding: BindingDigestV2,
) -> Result<Vec<u8>, SemanticH4BridgeGkrError> {
    let profile_code = match profile {
        MasterProfile::K128Calibration => 1,
        MasterProfile::K512Calibration => 3,
        MasterProfile::K256DesignPoint => return Err(SemanticH4BridgeGkrError::Binding),
    };
    let mut encoded = SEMANTIC_V3_KIND900_AUTHORITY_DOMAIN.to_vec();
    encoded.push(profile_code);
    encoded.extend_from_slice(&[0_u8; 7]);
    encoded.extend_from_slice(semantic_roots.main_trace.as_bytes());
    match semantic_roots.interaction_trace {
        Some(root) => encoded.extend_from_slice(root.as_bytes()),
        None => encoded.extend_from_slice(&[0_u8; 128]),
    }
    encoded.extend_from_slice(semantic_roots.composition.as_bytes());
    encoded.extend_from_slice(h4_pre_alpha_binding.as_bytes());
    encoded.extend_from_slice(coefficient_root_inventory_binding.as_bytes());
    Ok(encoded)
}

/// Canonical ordered coefficient-root inventory fixed by kind900 before the
/// bridge alpha and OODS point are sampled.
pub fn semantic_coefficient_root_inventory_binding_v3(
    roots: &[BindingRootV2],
) -> Result<BindingDigestV2, SemanticH4BridgeGkrError> {
    if roots.is_empty() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut encoded = b"BL/PQ512/WAVE2/SEMANTIC-BRIDGE-COEFFICIENT-ROOT-INVENTORY/v1\0".to_vec();
    encoded.extend_from_slice(
        &u32::try_from(roots.len())
            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
            .to_be_bytes(),
    );
    for root in roots {
        encoded.extend_from_slice(root.as_bytes());
    }
    BindingDigestV2::hash(BindingRoleV2::Payload, &encoded).map_err(Into::into)
}

/// Canonical context for every post-parent-z bridge proof. This binds the
/// auxiliary GKR and shard response transcripts to the same selected public
/// coin, native FRI receipt, and OODS point.
pub fn semantic_h4_post_z_context_v3(
    strict: &crate::selected_public_coin_v3::VerifiedStrictSemanticV3PublicCoin,
    semantic: &crate::fri_pipeline::VerifiedFriPipelineV3,
) -> Result<BindingDigestV2, SemanticH4BridgeGkrError> {
    if semantic.query_point() != strict.oods_point() {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    semantic_h4_post_z_context_from_pre_final_v3(
        strict.pre_final_transcript_root(),
        strict.oods_point(),
        semantic,
    )
}

/// Producer-side form of the post-Z context derivation used while the strict
/// semantic transaction is paused immediately before parent round 902.
///
/// The checkpoint and OODS point are outputs of the live strict coin, while
/// `semantic` is an opaque receipt returned by native FRI replay.  This helper
/// creates no accepting receipt; the complete verifier later replays the
/// finished strict bundle and byte-compares the resulting context.
pub fn semantic_h4_post_z_context_from_pre_final_v3(
    pre_final_transcript_root: &[u8; 128],
    oods_point: crate::oods::CirclePoint,
    semantic: &crate::fri_pipeline::VerifiedFriPipelineV3,
) -> Result<BindingDigestV2, SemanticH4BridgeGkrError> {
    if semantic.query_point() != oods_point
        || !pre_final_transcript_root.iter().any(|byte| *byte != 0)
    {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let mut encoded = b"BL/PQ512/WAVE2/SEMANTIC-H4/POST-Z-CONTEXT/v2\0".to_vec();
    encoded.extend_from_slice(pre_final_transcript_root);
    encoded.extend_from_slice(semantic.receipt_binding().as_bytes());
    encoded.extend_from_slice(&oods_point.x.encode());
    encoded.extend_from_slice(&oods_point.y.encode());
    BindingDigestV2::hash(BindingRoleV2::Payload, &encoded).map_err(Into::into)
}

/// Final acceptance combiner. Both arguments are opaque verifier products;
/// there is no caller boolean, digest-pair shortcut, or legacy-root fallback.
pub fn complete_decisive_composition_v3(
    semantic_h4: VerifiedSemanticH4CompositionV3,
    typed: crate::typed_state_proof_package::VerifiedTypedStateV3,
) -> Result<VerifiedDecisiveCompositionV3, DecisiveCompositionV3Error> {
    let expected_code = match semantic_h4.profile {
        MasterProfile::K128Calibration => 1,
        MasterProfile::K512Calibration => 3,
        MasterProfile::K256DesignPoint => return Err(DecisiveCompositionV3Error::Profile),
    };
    if typed.governed_profile_code() != expected_code {
        return Err(DecisiveCompositionV3Error::Profile);
    }
    if semantic_h4.public_inputs_binding != typed.public_inputs_binding() {
        return Err(DecisiveCompositionV3Error::PublicStatement);
    }
    let mut receipt = b"BL/PQ512/WAVE2/DECISIVE-ACCEPTING-COMPOSITION/v3\0".to_vec();
    receipt.push(expected_code);
    receipt.extend_from_slice(semantic_h4.receipt_binding.as_bytes());
    receipt.extend_from_slice(typed.receipt_binding().as_bytes());
    receipt.extend_from_slice(semantic_h4.public_inputs_binding.as_bytes());
    let receipt_binding = BindingDigestV2::hash(BindingRoleV2::Payload, &receipt)
        .map_err(|_| DecisiveCompositionV3Error::Binding)?;
    Ok(VerifiedDecisiveCompositionV3 {
        profile: semantic_h4.profile,
        receipt_binding,
    })
}

/// Reachable accepting composition entry point. Every argument is an opaque
/// receipt produced by a concrete verifier in this crate. The function first
/// enforces the parent pre-z root inventory and semantic/H4 equality, then
/// binds that result to the independently verified typed-state statement.
/// Complete the accepting library-level composition from the four opaque
/// native verifier receipts. This is the coordinator authority seam; it does
/// not parse an outer envelope and it does not activate a proof suite.
pub fn complete_verified_decisive_composition_v3(
    strict: crate::selected_public_coin_v3::VerifiedStrictSemanticV3PublicCoin,
    semantic: crate::fri_pipeline::VerifiedFriPipelineV3,
    h4: crate::h4_proof_package_v2::VerifiedH4V2,
    typed: crate::typed_state_proof_package::VerifiedTypedStateV3,
) -> Result<VerifiedDecisiveCompositionV3, DecisiveCompositionV3Error> {
    let semantic_h4 = complete_semantic_h4_composition_v3(&strict, &semantic, &h4)
        .map_err(|_| DecisiveCompositionV3Error::Binding)?;
    complete_decisive_composition_v3(semantic_h4, typed)
}

/// Transactional owner for every strict-PQ one-time-root reservation used by
/// the decisive verifier. Component verifiers receive only the pending clone;
/// dropping this value or failing final composition leaves durable caller
/// state unchanged.
pub struct DecisiveCompositionTransactionV3<'a> {
    target: &'a mut StrictPqRootUseRegistryV2,
    pending: StrictPqRootUseRegistryV2,
}

impl<'a> DecisiveCompositionTransactionV3<'a> {
    pub fn begin(target: &'a mut StrictPqRootUseRegistryV2) -> Self {
        Self {
            pending: target.clone(),
            target,
        }
    }

    pub fn pending_registry(&mut self) -> &mut StrictPqRootUseRegistryV2 {
        &mut self.pending
    }

    pub fn complete(
        self,
        strict: crate::selected_public_coin_v3::VerifiedStrictSemanticV3PublicCoin,
        semantic: crate::fri_pipeline::VerifiedFriPipelineV3,
        h4: crate::h4_proof_package_v2::VerifiedH4V2,
        typed: crate::typed_state_proof_package::VerifiedTypedStateV3,
    ) -> Result<VerifiedDecisiveCompositionV3, DecisiveCompositionV3Error> {
        let verified = complete_verified_decisive_composition_v3(strict, semantic, h4, typed)?;
        *self.target = self.pending;
        Ok(verified)
    }
}

/// Final native-128 semantic/H4 composition receipt.  Both inputs are opaque
/// verifier products: the selected AIR/DEEP/FRI receipt supplies the exact
/// Circle point and roots, while `VerifiedH4V2` includes the coefficient-root
/// sparse functional, nonlinear bridge GKR, shard-summed source responses and
/// source-augmented mask PCS.
pub(crate) fn complete_semantic_h4_composition_v3(
    strict: &crate::selected_public_coin_v3::VerifiedStrictSemanticV3PublicCoin,
    semantic: &crate::fri_pipeline::VerifiedFriPipelineV3,
    h4: &crate::h4_proof_package_v2::VerifiedH4V2,
) -> Result<VerifiedSemanticH4CompositionV3, SemanticH4BridgeGkrError> {
    let expected_h4 = match strict.profile() {
        MasterProfile::K128Calibration => crate::h4_proof_package_v2::H4ProofProfileV2::K128,
        MasterProfile::K512Calibration => crate::h4_proof_package_v2::H4ProofProfileV2::K512,
        MasterProfile::K256DesignPoint => return Err(SemanticH4BridgeGkrError::Binding),
    };
    if h4.profile() != expected_h4 || semantic.query_point() != strict.oods_point() {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    if h4.semantic_fri_binding() != semantic.receipt_binding() {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    if h4.post_z_context() != semantic_h4_post_z_context_v3(strict, semantic)? {
        return Err(SemanticH4BridgeGkrError::Transcript);
    }
    let roots = semantic.oracle_roots();
    let expected_kind900_message = semantic_v3_kind900_authority_message(
        strict.profile(),
        roots,
        h4.pre_alpha_binding(),
        h4.semantic_coefficient_root_inventory_binding(),
    )?;
    let expected_kind900_binding =
        crate::selected_public_coin_v3::strict_message_binding(2, &expected_kind900_message)
            .map_err(|_| SemanticH4BridgeGkrError::Transcript)?;
    if strict.round_message_binding(2) != Some(expected_kind900_binding) {
        return Err(SemanticH4BridgeGkrError::Transcript);
    }
    let mut receipt = b"BL/PQ512/WAVE2/VERIFIED-SEMANTIC-H4-COMPOSITION/v3\0".to_vec();
    receipt.push(match strict.profile() {
        MasterProfile::K128Calibration => 1,
        MasterProfile::K512Calibration => 3,
        MasterProfile::K256DesignPoint => return Err(SemanticH4BridgeGkrError::Binding),
    });
    receipt.extend_from_slice(strict.pre_final_transcript_root());
    receipt.extend_from_slice(semantic.program_binding().as_bytes());
    receipt.extend_from_slice(semantic.public_inputs_binding().as_bytes());
    receipt.extend_from_slice(roots.main_trace.as_bytes());
    match roots.interaction_trace {
        Some(root) => receipt.extend_from_slice(root.as_bytes()),
        None => receipt.extend_from_slice(&[0_u8; 128]),
    }
    receipt.extend_from_slice(roots.composition.as_bytes());
    receipt.extend_from_slice(&strict.oods_point().x.encode());
    receipt.extend_from_slice(&strict.oods_point().y.encode());
    receipt.extend_from_slice(h4.receipt_binding().as_bytes());
    receipt.extend_from_slice(h4.source_binding().as_bytes());
    Ok(VerifiedSemanticH4CompositionV3 {
        profile: strict.profile(),
        receipt_binding: BindingDigestV2::hash(BindingRoleV2::Payload, &receipt)?,
        public_inputs_binding: semantic.public_inputs_binding(),
    })
}

pub const BRIDGE_RATE_SOURCE_WIDTH: usize = 64;
pub const BRIDGE_RATE_GROUP_LOG_K128: u8 = 23;
pub const BRIDGE_RATE_GROUP_LOG_K512: u8 = 25;
pub const BRIDGE_BLOCK_SOURCE_WIDTH: usize = 4_096;
pub const BRIDGE_BLOCK_GROUP_LOG: u8 = 19;
pub const BRIDGE_DIGEST_SOURCE_WIDTH: usize = 4_096;
pub const BRIDGE_DIGEST_GROUP_LOG: u8 = 24;
pub const BRIDGE_DIGEST_BLOCK_WIDTH: usize = 1_024;
pub const SEMANTIC_H4_BRIDGE_GKR_MAGIC: &[u8; 8] = b"BLSHBG01";
pub const SEMANTIC_H4_BRIDGE_GKR_VERSION: u16 = 1;
pub const MAX_SEMANTIC_H4_BRIDGE_GKR_BYTES: usize = 1 << 20;
pub const SEMANTIC_H4_BRIDGE_OUTPUT_KIND: u16 = 1_100;
pub const SEMANTIC_H4_BRIDGE_LAYER_KIND: u16 = 1_101;
pub const SEMANTIC_H4_BRIDGE_SUMCHECK_KIND: u16 = 1_102;

pub const RATE_LIVE: usize = 0;
pub const RATE_PREVIOUS_LIVE: usize = 1;
pub const RATE_BLOCK_ACTIVE: usize = 2;
pub const RATE_NEXT_BLOCK_ACTIVE: usize = 3;
pub const RATE_VALUE: usize = 4;
pub const RATE_FINAL_BYTE_SELECTOR: usize = 5;
pub const RATE_INPUT_BITS_START: usize = 6;
pub const RATE_PREDECESSOR_BITS_START: usize = 14;
pub const RATE_BIT_WEIGHTS_START: usize = 22;
pub const RATE_SIX: usize = 30;
pub const RATE_128: usize = 31;
pub const RATE_ONE: usize = 32;

pub const BLOCK_INPUT_BITS_START: usize = 0;
pub const BLOCK_PREDECESSOR_BITS_START: usize = 1_024;
pub const BLOCK_ACTIVE: usize = 2_048;

pub const DIGEST_ACTIVE_START: usize = 0;
pub const DIGEST_NEXT_ACTIVE_START: usize = 1_024;
pub const DIGEST_OUTPUT_BYTES_START: usize = 2_048;
pub const DIGEST_EXPECTED_BYTE: usize = 3_072;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticH4BridgeProfile {
    K128,
    K512,
}

impl SemanticH4BridgeProfile {
    pub const fn rate_group_log(self) -> u8 {
        match self {
            Self::K128 => BRIDGE_RATE_GROUP_LOG_K128,
            Self::K512 => BRIDGE_RATE_GROUP_LOG_K512,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticH4BridgeTopologies {
    pub rate: Vec<KeccakDagLayer>,
    pub inactive: Vec<KeccakDagLayer>,
    pub capacity: Vec<KeccakDagLayer>,
    pub digest: Vec<KeccakDagLayer>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticH4BridgeCircuit {
    Rate,
    Inactive,
    Capacity,
    Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticH4BridgeLayerPlan {
    pub circuit: SemanticH4BridgeCircuit,
    pub layer: usize,
    pub group_log: u8,
    pub topology: KeccakDagLayer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMaskedBridgeClaim {
    pub point: Vec<Fp16>,
    pub masked_value: Fp16,
    pub mask_layer: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMaskedBridgeLayerProof {
    pub circuit: SemanticH4BridgeCircuit,
    pub layer: usize,
    pub published_rounds: Vec<Vec<Fp16>>,
    pub masked_terminal_left: Fp16,
    pub masked_terminal_right: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticH4BridgeLayerChallenges {
    pub claim_mix: Fp16,
    pub sumcheck_rho: Fp16,
    pub group_challenges: Vec<Fp16>,
    pub wire_challenges: Vec<Fp16>,
    pub w_challenge: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMaskedSemanticH4BridgeGkrProof {
    pub profile: SemanticH4BridgeProfile,
    pub layers: Vec<PublicMaskedBridgeLayerProof>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticH4BridgePublicChallenges {
    pub output_points: [Vec<Fp16>; 4],
    pub layers: Vec<SemanticH4BridgeLayerChallenges>,
}

/// Challenge-blind accelerator boundary for a real varying semantic trace.
///
/// The oracle supplies only raw algebra. Rust owns every transcript message,
/// mask, challenge, recurrence check, wire tail, and terminal check. A caller
/// must additionally authenticate the resulting four source claims against
/// the native semantic Circle commitments before outer acceptance.
pub trait NonuniformSemanticH4BridgeOracle: MaskedSharedGroupOracle {
    fn output_claim(
        &mut self,
        circuit: SemanticH4BridgeCircuit,
        point: &[Fp16],
    ) -> Result<Fp16, SemanticH4BridgeGkrError>;

    fn begin_layer(
        &mut self,
        circuit: SemanticH4BridgeCircuit,
        layer_index: usize,
        topology: &KeccakDagLayer,
        claims: &[LayerOutputClaim],
    ) -> Result<(), SemanticH4BridgeGkrError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticH4BridgeStrictRound {
    pub descriptor: StrictPqRoundDescriptorV2,
    pub policy: StrictPqFp16PolicyV2,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedMaskedSemanticH4BridgeGkr {
    pub(crate) profile: SemanticH4BridgeProfile,
    pub(crate) source_claims: Vec<PublicMaskedBridgeClaim>,
    pub(crate) source_circuits: Vec<SemanticH4BridgeCircuit>,
    pub(crate) mask_constraints: Vec<UniformGkrMaskConstraint>,
}

/// Opaque bridge-GKR result whose challenges were replayed under the strict
/// post-z context. The algebra-only verifier result cannot enter H4
/// acceptance without this wrapper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStrictSemanticH4BridgeGkr {
    verified: VerifiedMaskedSemanticH4BridgeGkr,
    context: BindingDigestV2,
    final_transcript_root: [u8; 128],
}

impl VerifiedStrictSemanticH4BridgeGkr {
    pub fn verified_gkr(&self) -> &VerifiedMaskedSemanticH4BridgeGkr {
        &self.verified
    }

    pub const fn context(&self) -> BindingDigestV2 {
        self.context
    }

    pub const fn final_transcript_root(&self) -> &[u8; 128] {
        &self.final_transcript_root
    }
}

/// One raw round-input terminal assembled only from independently verified
/// semantic Circle adapters, H4 Construction openings, and verifier-fixed
/// constants.  The fields are private so package callers cannot substitute a
/// matching scalar for either missing commitment proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedBridgeRawSourceClaim {
    point: Vec<Fp16>,
    value: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSemanticH4BridgeSourceBinding {
    pub(crate) source_claim_count: usize,
    pub(crate) mask_constraints: Vec<UniformGkrMaskConstraint>,
    pub(crate) source_batch_binding: BindingDigestV2,
}

/// Opaque verifier-owned batch of every semantic and fixed contribution to
/// the bridge GKR round-input claims.  H4 subtracts this value from the
/// complete masked GKR batch before proving its native-root Construction
/// functional.  Consequently neither a host scalar nor an H4-only response
/// can absorb a semantic/H4 mismatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedSemanticBridgeSourceBatchV2 {
    claim_vector_binding: BindingDigestV2,
    claim_challenge: Fp16,
    batched_value: Fp16,
    claim_count: usize,
}

/// Accepting native-128 semantic source batch.  Every terminal is backed by
/// one coefficient root that was independently tied to the selected Circle
/// OODS opening; unlike v2 this type cannot be constructed from the legacy
/// algebra-only BLCLSF01/02 adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSemanticBridgeSourceBatchV3 {
    semantic_fri_binding: BindingDigestV2,
    claim_vector_binding: BindingDigestV2,
    coefficient_root_inventory_binding: BindingDigestV2,
    coefficient_roots_binding: BindingDigestV2,
    claim_challenge: Fp16,
    batched_value: Fp16,
    claim_count: usize,
    claim_values: Vec<Fp16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SemanticBridgeBaseColumnV3 {
    MessageLive = 1,
    MessageValue = 2,
    DigestValue = 3,
}

/// One verifier-derived sparse semantic source functional.  Its value is
/// authenticated from the native semantic coefficient root; the GKR point,
/// base-column tag, and gather-map binding are retained so batching cannot
/// substitute a valid opening of the wrong column or row map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSemanticBridgeFunctionalV3 {
    semantic_fri_binding: BindingDigestV2,
    source_claim_point: Vec<Fp16>,
    circuit: SemanticH4BridgeCircuit,
    column: SemanticBridgeBaseColumnV3,
    functional_binding: BindingDigestV2,
    coefficient_root: BindingRootV2,
    value: Fp16,
}

/// Public proof material for one verifier-derived semantic bridge terminal.
/// Circuit, column, claim/value ordinals and row weights are deliberately not
/// present: the verifier derives all of them from the GKR receipt and AIR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticBridgeFunctionalProofInputV3 {
    pub proof: CircleCoefficientMleProofV3,
    pub coefficient_root: BindingRootV2,
    pub functional_challenges: Vec<Fp16>,
    pub coefficient_context: BindingDigestV2,
    pub circle_completion_coin: BindingDigestV2,
    pub functional_completion_coin: BindingDigestV2,
    pub conjugate: bool,
}

/// Verifier-derived public coins for one semantic source functional.
///
/// These values are transported in the witness for codec stability, but they
/// are not proof authority: both production and replay derive them from the
/// already-authenticated semantic FRI receipt, exact GKR source point, and
/// verifier-fixed circuit/column identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticBridgeFunctionalCoinsV3 {
    pub functional_challenges: Vec<Fp16>,
    pub coefficient_context: BindingDigestV2,
    pub circle_completion_coin: BindingDigestV2,
    pub functional_completion_coin: BindingDigestV2,
}

fn semantic_coefficient_context_v3(
    profile: SemanticH4BridgeProfile,
    column: SemanticBridgeBaseColumnV3,
) -> Result<BindingDigestV2, SemanticH4BridgeGkrError> {
    let mut frame =
        b"BL/PQ512/WAVE2/SEMANTIC-BRIDGE-COEFFICIENT-CONTEXT/v2\0".to_vec();
    frame.extend_from_slice(&[profile_code(profile), column as u8]);
    BindingDigestV2::hash(BindingRoleV2::Payload, &frame)
        .map_err(|_| SemanticH4BridgeGkrError::Binding)
}

fn functional_coin_frame_v3(
    profile: SemanticH4BridgeProfile,
    circuit: SemanticH4BridgeCircuit,
    column: SemanticBridgeBaseColumnV3,
    source_claim_point: &[Fp16],
    semantic_fri_binding: BindingDigestV2,
) -> Result<Vec<u8>, SemanticH4BridgeGkrError> {
    if !expected_semantic_columns(circuit).contains(&column)
        || source_claim_point.len()
            != source_wire_log(circuit) + usize::from(circuit_group_log(profile, circuit))
    {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut frame = b"BL/PQ512/WAVE2/SEMANTIC-BRIDGE-FUNCTIONAL-COINS/v1\0".to_vec();
    frame.extend_from_slice(semantic_fri_binding.as_bytes());
    frame.extend_from_slice(&[
        profile_code(profile),
        circuit_code(circuit),
        column as u8,
        semantic_column_log(profile, column),
    ]);
    frame.extend_from_slice(
        &u16::try_from(source_claim_point.len())
            .map_err(|_| SemanticH4BridgeGkrError::Shape)?
            .to_be_bytes(),
    );
    for coordinate in source_claim_point {
        frame.extend_from_slice(&coordinate.encode());
    }
    Ok(frame)
}

fn derive_functional_field_v3(
    frame: &[u8],
    ordinal: u32,
) -> Result<Fp16, SemanticH4BridgeGkrError> {
    let mut coefficients = [0_u32; 16];
    for (index, coefficient) in coefficients.iter_mut().enumerate() {
        let mut hash = Sha3_512::new();
        hash.update(b"BL/PQ512/WAVE2/SEMANTIC-BRIDGE-FUNCTIONAL-FIELD/v1\0");
        hash.update(frame);
        hash.update(ordinal.to_be_bytes());
        hash.update((index as u32).to_be_bytes());
        let digest: [u8; 64] = hash.finalize().into();
        *coefficient =
            u32::from_be_bytes(digest[..4].try_into().expect("four-byte prefix")) % M31_MODULUS;
    }
    Fp16::from_coefficients(coefficients).map_err(|_| SemanticH4BridgeGkrError::Binding)
}

/// Derive every public coin used by one semantic Circle functional.
pub fn derive_semantic_bridge_functional_coins_v3(
    profile: SemanticH4BridgeProfile,
    circuit: SemanticH4BridgeCircuit,
    column: SemanticBridgeBaseColumnV3,
    source_claim_point: &[Fp16],
    verified_fri: &crate::fri_pipeline::VerifiedFriPipelineV3,
) -> Result<SemanticBridgeFunctionalCoinsV3, SemanticH4BridgeGkrError> {
    derive_semantic_bridge_functional_coins_from_binding_v3(
        profile,
        circuit,
        column,
        source_claim_point,
        verified_fri.receipt_binding(),
    )
}

fn derive_semantic_bridge_functional_coins_from_binding_v3(
    profile: SemanticH4BridgeProfile,
    circuit: SemanticH4BridgeCircuit,
    column: SemanticBridgeBaseColumnV3,
    source_claim_point: &[Fp16],
    semantic_fri_binding: BindingDigestV2,
) -> Result<SemanticBridgeFunctionalCoinsV3, SemanticH4BridgeGkrError> {
    let frame = functional_coin_frame_v3(
        profile,
        circuit,
        column,
        source_claim_point,
        semantic_fri_binding,
    )?;
    let count = usize::from(semantic_column_log(profile, column));
    let functional_challenges = (0..count)
        .map(|ordinal| {
            derive_functional_field_v3(
                &frame,
                u32::try_from(ordinal).map_err(|_| SemanticH4BridgeGkrError::Shape)?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let derive_binding = |label: &[u8]| {
        let mut payload = frame.clone();
        payload.extend_from_slice(label);
        BindingDigestV2::hash(BindingRoleV2::Payload, &payload)
            .map_err(|_| SemanticH4BridgeGkrError::Binding)
    };
    Ok(SemanticBridgeFunctionalCoinsV3 {
        functional_challenges,
        coefficient_context: semantic_coefficient_context_v3(profile, column)?,
        circle_completion_coin: derive_binding(b"circle-completion")?,
        functional_completion_coin: derive_binding(b"functional-completion")?,
    })
}

impl VerifiedSemanticBridgeFunctionalV3 {
    pub const fn semantic_fri_binding(&self) -> BindingDigestV2 {
        self.semantic_fri_binding
    }

    pub fn source_claim_point(&self) -> &[Fp16] {
        &self.source_claim_point
    }

    pub const fn circuit(&self) -> SemanticH4BridgeCircuit {
        self.circuit
    }

    pub const fn column(&self) -> SemanticBridgeBaseColumnV3 {
        self.column
    }

    pub const fn functional_binding(&self) -> BindingDigestV2 {
        self.functional_binding
    }

    pub const fn coefficient_root(&self) -> BindingRootV2 {
        self.coefficient_root
    }

    pub const fn value(&self) -> Fp16 {
        self.value
    }

    #[cfg(test)]
    fn synthetic_for_test(
        profile: SemanticH4BridgeProfile,
        circuit: SemanticH4BridgeCircuit,
        column: SemanticBridgeBaseColumnV3,
        source_claim_point: Vec<Fp16>,
        coefficient_root: BindingRootV2,
        value: Fp16,
    ) -> Self {
        Self {
            semantic_fri_binding: BindingDigestV2::hash(BindingRoleV2::Payload, b"synthetic-fri")
                .unwrap(),
            functional_binding: semantic_functional_binding(
                profile,
                circuit,
                column,
                &source_claim_point,
            )
            .unwrap(),
            source_claim_point,
            circuit,
            column,
            coefficient_root,
            value,
        }
    }
}

impl VerifiedSemanticBridgeSourceBatchV3 {
    pub(crate) const fn semantic_fri_binding(&self) -> BindingDigestV2 {
        self.semantic_fri_binding
    }
    pub(crate) const fn claim_vector_binding(&self) -> BindingDigestV2 {
        self.claim_vector_binding
    }
    pub(crate) const fn coefficient_roots_binding(&self) -> BindingDigestV2 {
        self.coefficient_roots_binding
    }
    pub(crate) const fn coefficient_root_inventory_binding(&self) -> BindingDigestV2 {
        self.coefficient_root_inventory_binding
    }
    pub(crate) const fn claim_challenge(&self) -> Fp16 {
        self.claim_challenge
    }
    pub(crate) const fn batched_value(&self) -> Fp16 {
        self.batched_value
    }
    pub(crate) const fn claim_count(&self) -> usize {
        self.claim_count
    }

    pub(crate) fn claim_values(&self) -> &[Fp16] {
        &self.claim_values
    }
}

impl VerifiedSemanticBridgeSourceBatchV2 {
    pub(crate) const fn claim_vector_binding(&self) -> BindingDigestV2 {
        self.claim_vector_binding
    }

    pub(crate) const fn claim_challenge(&self) -> Fp16 {
        self.claim_challenge
    }

    pub(crate) const fn batched_value(&self) -> Fp16 {
        self.batched_value
    }

    pub(crate) const fn claim_count(&self) -> usize {
        self.claim_count
    }
}

fn semantic_profile(profile: SemanticH4BridgeProfile) -> ScheduleProfile {
    match profile {
        SemanticH4BridgeProfile::K128 => ScheduleProfile::K128Calibration,
        SemanticH4BridgeProfile::K512 => ScheduleProfile::K512Calibration,
    }
}

fn semantic_column_log(profile: SemanticH4BridgeProfile, column: SemanticBridgeBaseColumnV3) -> u8 {
    match column {
        SemanticBridgeBaseColumnV3::MessageLive | SemanticBridgeBaseColumnV3::MessageValue => {
            profile.rate_group_log()
        }
        SemanticBridgeBaseColumnV3::DigestValue => match profile {
            SemanticH4BridgeProfile::K128 => 22,
            SemanticH4BridgeProfile::K512 => 24,
        },
    }
}

fn source_wire_log(circuit: SemanticH4BridgeCircuit) -> usize {
    match circuit {
        SemanticH4BridgeCircuit::Rate => 6,
        SemanticH4BridgeCircuit::Inactive
        | SemanticH4BridgeCircuit::Capacity
        | SemanticH4BridgeCircuit::Digest => 12,
    }
}

fn equality_weight(index: usize, point: &[Fp16]) -> Fp16 {
    point
        .iter()
        .copied()
        .enumerate()
        .fold(Fp16::ONE, |weight, (variable, challenge)| {
            if (index >> variable) & 1 == 1 {
                weight * challenge
            } else {
                weight * (Fp16::ONE - challenge)
            }
        })
}

fn equality_prefix_sum(count: usize, point: &[Fp16]) -> Result<Fp16, SemanticH4BridgeGkrError> {
    let size = 1usize
        .checked_shl(point.len() as u32)
        .ok_or(SemanticH4BridgeGkrError::Shape)?;
    if count > size {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    if count == size {
        return Ok(Fp16::ONE);
    }
    let mut sum = Fp16::ZERO;
    let mut equal_prefix = Fp16::ONE;
    for bit in (0..point.len()).rev() {
        let challenge = point[bit];
        if (count >> bit) & 1 == 1 {
            sum = sum + equal_prefix * (Fp16::ONE - challenge);
            equal_prefix = equal_prefix * challenge;
        } else {
            equal_prefix = equal_prefix * (Fp16::ONE - challenge);
        }
    }
    Ok(sum)
}

fn equality_interval_sum(
    start: usize,
    end: usize,
    point: &[Fp16],
) -> Result<Fp16, SemanticH4BridgeGkrError> {
    if start > end {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    Ok(equality_prefix_sum(end, point)? - equality_prefix_sum(start, point)?)
}

/// Exact weighted digit-DP for a verifier-fixed residue class.  This replaces
/// enumerating millions of fixed selector rows without changing the
/// multilinear functional being authenticated.
fn equality_residue_prefix_sum(
    count: usize,
    modulus: usize,
    residue: usize,
    point: &[Fp16],
) -> Result<Fp16, SemanticH4BridgeGkrError> {
    let size = 1usize
        .checked_shl(point.len() as u32)
        .ok_or(SemanticH4BridgeGkrError::Shape)?;
    if modulus == 0 || residue >= modulus || count > size {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut loose = vec![Fp16::ZERO; modulus];
    let mut tight = vec![Fp16::ZERO; modulus];
    if count == size {
        loose[0] = Fp16::ONE;
    } else {
        tight[0] = Fp16::ONE;
    }
    for bit in (0..point.len()).rev() {
        let bound_bit = (count >> bit) & 1;
        let mut next_loose = vec![Fp16::ZERO; modulus];
        let mut next_tight = vec![Fp16::ZERO; modulus];
        for prior in 0..modulus {
            for digit in 0..=1usize {
                let digit_weight = if digit == 1 {
                    point[bit]
                } else {
                    Fp16::ONE - point[bit]
                };
                let next = (prior * 2 + digit) % modulus;
                next_loose[next] = next_loose[next] + loose[prior] * digit_weight;
                if digit < bound_bit {
                    next_loose[next] = next_loose[next] + tight[prior] * digit_weight;
                } else if digit == bound_bit {
                    next_tight[next] = next_tight[next] + tight[prior] * digit_weight;
                }
            }
        }
        loose = next_loose;
        tight = next_tight;
    }
    Ok(loose[residue])
}

fn source_group_interval_weight(
    point: &[Fp16],
    circuit: SemanticH4BridgeCircuit,
    wire: usize,
    start: usize,
    end: usize,
) -> Result<Fp16, SemanticH4BridgeGkrError> {
    let wire_log = source_wire_log(circuit);
    if point.len() <= wire_log || wire >= 1usize << wire_log {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    Ok(equality_weight(wire, &point[..wire_log])
        * equality_interval_sum(start, end, &point[wire_log..])?)
}

fn source_cell_weight(
    point: &[Fp16],
    circuit: SemanticH4BridgeCircuit,
    wire: usize,
    group: usize,
) -> Result<Fp16, SemanticH4BridgeGkrError> {
    let wire_log = source_wire_log(circuit);
    if point.len() <= wire_log
        || wire >= 1usize << wire_log
        || group >= 1usize << (point.len() - wire_log)
    {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    Ok(equality_weight(wire, &point[..wire_log]) * equality_weight(group, &point[wire_log..]))
}

fn source_wire_weight(
    point: &[Fp16],
    circuit: SemanticH4BridgeCircuit,
    wire: usize,
) -> Result<Fp16, SemanticH4BridgeGkrError> {
    let wire_log = source_wire_log(circuit);
    if point.len() <= wire_log || wire >= 1usize << wire_log {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    Ok(equality_weight(wire, &point[..wire_log]))
}

fn expected_semantic_columns(
    circuit: SemanticH4BridgeCircuit,
) -> &'static [SemanticBridgeBaseColumnV3] {
    match circuit {
        SemanticH4BridgeCircuit::Rate => &[
            SemanticBridgeBaseColumnV3::MessageLive,
            SemanticBridgeBaseColumnV3::MessageValue,
        ],
        SemanticH4BridgeCircuit::Inactive | SemanticH4BridgeCircuit::Capacity => {
            &[SemanticBridgeBaseColumnV3::MessageLive]
        }
        SemanticH4BridgeCircuit::Digest => &[
            SemanticBridgeBaseColumnV3::MessageLive,
            SemanticBridgeBaseColumnV3::DigestValue,
        ],
    }
}

fn semantic_functional_binding(
    profile: SemanticH4BridgeProfile,
    circuit: SemanticH4BridgeCircuit,
    column: SemanticBridgeBaseColumnV3,
    point: &[Fp16],
) -> Result<BindingDigestV2, SemanticH4BridgeGkrError> {
    let descriptor = build_hash_bus_descriptor_with_state(semantic_profile(profile))
        .map_err(|_| SemanticH4BridgeGkrError::Shape)?;
    let mut encoded = b"BL/PQ512/WAVE2/SEMANTIC-BRIDGE-SPARSE-MAP/v3\0".to_vec();
    encoded.extend_from_slice(&descriptor.descriptor_commitment);
    encoded.push(match profile {
        SemanticH4BridgeProfile::K128 => 1,
        SemanticH4BridgeProfile::K512 => 3,
    });
    encoded.push(circuit_index(circuit) as u8);
    encoded.push(column as u8);
    encoded.push(semantic_column_log(profile, column));
    encoded.extend_from_slice(
        &u16::try_from(point.len())
            .map_err(|_| SemanticH4BridgeGkrError::Shape)?
            .to_be_bytes(),
    );
    for coordinate in point {
        encoded.extend_from_slice(&coordinate.encode());
    }
    BindingDigestV2::hash(BindingRoleV2::Payload, &encoded)
        .map_err(|_| SemanticH4BridgeGkrError::Binding)
}

fn semantic_row_weight(
    descriptor: &HashBusDescriptor,
    circuit: SemanticH4BridgeCircuit,
    column: SemanticBridgeBaseColumnV3,
    point: &[Fp16],
    row: usize,
) -> Result<Fp16, SemanticH4BridgeGkrError> {
    match column {
        SemanticBridgeBaseColumnV3::MessageValue => {
            if circuit != SemanticH4BridgeCircuit::Rate {
                return Err(SemanticH4BridgeGkrError::Binding);
            }
            let live_rows = usize::try_from(descriptor.total_permutations)
                .map_err(|_| SemanticH4BridgeGkrError::Shape)?
                .checked_mul(72)
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            if row >= live_rows {
                return Ok(Fp16::ZERO);
            }
            source_cell_weight(point, circuit, RATE_VALUE, row)
        }
        SemanticBridgeBaseColumnV3::DigestValue => {
            if circuit != SemanticH4BridgeCircuit::Digest {
                return Err(SemanticH4BridgeGkrError::Binding);
            }
            let digest_rows = usize::try_from(descriptor.total_calls)
                .map_err(|_| SemanticH4BridgeGkrError::Shape)?
                .checked_mul(64)
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            if row >= digest_rows {
                return Ok(Fp16::ZERO);
            }
            source_cell_weight(point, circuit, DIGEST_EXPECTED_BYTE, row)
        }
        SemanticBridgeBaseColumnV3::MessageLive => {
            let permutation = row / 72;
            let byte = row % 72;
            if permutation
                >= usize::try_from(descriptor.total_permutations)
                    .map_err(|_| SemanticH4BridgeGkrError::Shape)?
            {
                return Ok(Fp16::ZERO);
            }
            let slot = hash_bus_permutation_slot(descriptor, permutation as u64)
                .map_err(|_| SemanticH4BridgeGkrError::Shape)?
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            let mut weight = Fp16::ZERO;
            match circuit {
                SemanticH4BridgeCircuit::Rate => {
                    weight = weight + source_cell_weight(point, circuit, RATE_LIVE, row)?;
                    if byte + 1 < 72 {
                        weight = weight
                            + source_cell_weight(point, circuit, RATE_PREVIOUS_LIVE, row + 1)?;
                    } else if slot.block_index + 1 < slot.blocks_in_call {
                        weight = weight
                            + source_cell_weight(point, circuit, RATE_PREVIOUS_LIVE, row + 1)?;
                    }
                    if byte == 71 {
                        weight = weight
                            + source_group_interval_weight(
                                point,
                                circuit,
                                RATE_NEXT_BLOCK_ACTIVE,
                                permutation * 72,
                                (permutation + 1) * 72,
                            )?;
                        if slot.block_index + 1 < slot.blocks_in_call {
                            weight = weight
                                + source_group_interval_weight(
                                    point,
                                    circuit,
                                    RATE_BLOCK_ACTIVE,
                                    (permutation + 1) * 72,
                                    (permutation + 2) * 72,
                                )?;
                        }
                    }
                }
                SemanticH4BridgeCircuit::Inactive | SemanticH4BridgeCircuit::Capacity => {
                    if byte == 71 && slot.block_index + 1 < slot.blocks_in_call {
                        weight = weight
                            + source_cell_weight(point, circuit, BLOCK_ACTIVE, permutation + 1)?;
                    }
                }
                SemanticH4BridgeCircuit::Digest => {
                    if byte == 71 {
                        let start = usize::try_from(slot.call_index)
                            .map_err(|_| SemanticH4BridgeGkrError::Shape)?
                            * 64;
                        weight = weight
                            + source_group_interval_weight(
                                point,
                                circuit,
                                DIGEST_NEXT_ACTIVE_START + usize::from(slot.block_index),
                                start,
                                start + 64,
                            )?;
                        if slot.block_index + 1 < slot.blocks_in_call {
                            weight = weight
                                + source_group_interval_weight(
                                    point,
                                    circuit,
                                    DIGEST_ACTIVE_START + usize::from(slot.block_index) + 1,
                                    start,
                                    start + 64,
                                )?;
                        }
                    }
                }
            }
            Ok(weight)
        }
    }
}

fn semantic_fixed_source_value(
    profile: SemanticH4BridgeProfile,
    circuit: SemanticH4BridgeCircuit,
    point: &[Fp16],
) -> Result<Fp16, SemanticH4BridgeGkrError> {
    let descriptor = build_hash_bus_descriptor_with_state(semantic_profile(profile))
        .map_err(|_| SemanticH4BridgeGkrError::Shape)?;
    let mut result = Fp16::ZERO;
    match circuit {
        SemanticH4BridgeCircuit::Rate => {
            let group_point = &point[source_wire_log(circuit)..];
            let block_wire = source_wire_weight(point, circuit, RATE_BLOCK_ACTIVE)?;
            let mut permutation_base = 0usize;
            for run in &descriptor.runs {
                let blocks = usize::try_from(run.capacity / 72 + 1)
                    .map_err(|_| SemanticH4BridgeGkrError::Shape)?;
                let calls =
                    usize::try_from(run.count).map_err(|_| SemanticH4BridgeGkrError::Shape)?;
                for call in 0..calls {
                    let start = permutation_base
                        .checked_add(
                            call.checked_mul(blocks)
                                .ok_or(SemanticH4BridgeGkrError::Shape)?,
                        )
                        .and_then(|value| value.checked_mul(72))
                        .ok_or(SemanticH4BridgeGkrError::Shape)?;
                    result = result
                        + block_wire * equality_interval_sum(start, start + 72, group_point)?;
                }
                permutation_base = permutation_base
                    .checked_add(
                        calls
                            .checked_mul(blocks)
                            .ok_or(SemanticH4BridgeGkrError::Shape)?,
                    )
                    .ok_or(SemanticH4BridgeGkrError::Shape)?;
            }
            let live_rows = usize::try_from(descriptor.total_permutations)
                .map_err(|_| SemanticH4BridgeGkrError::Shape)?
                .checked_mul(72)
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            result = result
                + source_wire_weight(point, circuit, RATE_FINAL_BYTE_SELECTOR)?
                    * equality_residue_prefix_sum(live_rows, 72, 71, group_point)?;
            for bit in 0..8usize {
                result = result
                    + source_wire_weight(point, circuit, RATE_BIT_WEIGHTS_START + bit)?
                        * Fp16::from_m31(
                            crate::field::M31::from_canonical(1u32 << bit)
                                .map_err(|_| SemanticH4BridgeGkrError::Shape)?,
                        );
            }
            for (wire, value) in [(RATE_SIX, 6u32), (RATE_128, 128), (RATE_ONE, 1)] {
                result = result
                    + source_wire_weight(point, circuit, wire)?
                        * Fp16::from_m31(
                            crate::field::M31::from_canonical(value)
                                .map_err(|_| SemanticH4BridgeGkrError::Shape)?,
                        );
            }
        }
        SemanticH4BridgeCircuit::Inactive | SemanticH4BridgeCircuit::Capacity => {
            let group_point = &point[source_wire_log(circuit)..];
            let block_wire = source_wire_weight(point, circuit, BLOCK_ACTIVE)?;
            let mut permutation_base = 0usize;
            for run in &descriptor.runs {
                let blocks = usize::try_from(run.capacity / 72 + 1)
                    .map_err(|_| SemanticH4BridgeGkrError::Shape)?;
                let calls =
                    usize::try_from(run.count).map_err(|_| SemanticH4BridgeGkrError::Shape)?;
                for call in 0..calls {
                    let permutation = permutation_base
                        .checked_add(
                            call.checked_mul(blocks)
                                .ok_or(SemanticH4BridgeGkrError::Shape)?,
                        )
                        .ok_or(SemanticH4BridgeGkrError::Shape)?;
                    result = result + block_wire * equality_weight(permutation, group_point);
                }
                permutation_base = permutation_base
                    .checked_add(
                        calls
                            .checked_mul(blocks)
                            .ok_or(SemanticH4BridgeGkrError::Shape)?,
                    )
                    .ok_or(SemanticH4BridgeGkrError::Shape)?;
            }
        }
        SemanticH4BridgeCircuit::Digest => {
            let end = usize::try_from(descriptor.total_calls)
                .map_err(|_| SemanticH4BridgeGkrError::Shape)?
                .checked_mul(64)
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            result =
                result + source_group_interval_weight(point, circuit, DIGEST_ACTIVE_START, 0, end)?;
        }
    }
    Ok(result)
}

/// Authenticate one exact semantic column/gather functional from the same
/// native coefficient root whose Circle evaluation is selected by the v3 FRI
/// receipt.  The sparse map is derived from profile, circuit, column and GKR
/// source point; proof bytes cannot choose its weights or terminal.
#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_semantic_bridge_functional_v3(
    profile: SemanticH4BridgeProfile,
    circuit: SemanticH4BridgeCircuit,
    column: SemanticBridgeBaseColumnV3,
    source_claim_point: &[Fp16],
    verified_fri: &crate::fri_pipeline::VerifiedFriPipelineV3,
    claim_ordinal: usize,
    value_ordinal: usize,
    conjugate: bool,
    proof: &CircleCoefficientMleProofV3,
    expected_coefficient_root: BindingRootV2,
    functional_challenges: &[Fp16],
    coefficient_context: BindingDigestV2,
    circle_completion_coin: BindingDigestV2,
    functional_completion_coin: BindingDigestV2,
) -> Result<VerifiedSemanticBridgeFunctionalV3, SemanticH4BridgeGkrError> {
    if !expected_semantic_columns(circuit).contains(&column)
        || source_claim_point.len()
            != source_wire_log(circuit) + usize::from(circuit_group_log(profile, circuit))
        || functional_challenges.len() != usize::from(semantic_column_log(profile, column))
    {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let functional_binding =
        semantic_functional_binding(profile, circuit, column, source_claim_point)?;
    // Construct and validate the governed schedule once.  The dual-terminal
    // fold visits every committed row, so rebuilding the descriptor inside
    // that loop would turn a linear verifier pass into production-scale
    // repeated schedule construction.
    let descriptor = build_hash_bus_descriptor_with_state(semantic_profile(profile))
        .map_err(|_| SemanticH4BridgeGkrError::Shape)?;
    let dual_terminal = circle_row_functional_dual_terminal_streaming(
        semantic_column_log(profile, column),
        functional_challenges,
        |row| {
            semantic_row_weight(&descriptor, circuit, column, source_claim_point, row)
                .map_err(|_| CircleLagrangeSparseFunctionalError::Shape)
        },
    )
    .map_err(|_| SemanticH4BridgeGkrError::Binding)?;
    let circle = authenticated_circle_opening_from_verified_fri_v3(
        verified_fri,
        claim_ordinal,
        value_ordinal,
        conjugate,
    )
    .map_err(|_| SemanticH4BridgeGkrError::Binding)?;
    let verified = verify_circle_coefficient_linear_terminal_v3(
        proof,
        circle,
        expected_coefficient_root,
        dual_terminal,
        functional_binding,
        functional_challenges,
        coefficient_context,
        circle_completion_coin,
        functional_completion_coin,
    )
    .map_err(|_| SemanticH4BridgeGkrError::Binding)?;
    Ok(VerifiedSemanticBridgeFunctionalV3 {
        semantic_fri_binding: verified_fri.receipt_binding(),
        source_claim_point: source_claim_point.to_vec(),
        circuit,
        column,
        functional_binding: verified.functional_binding(),
        coefficient_root: verified.coefficient_root(),
        value: verified.multilinear_value(),
    })
}

/// Derive the selected DEEP-claim coordinates of one governed semantic main
/// column.  Package bytes never choose these ordinals: they follow from the
/// exact AIR program, hiding count and blowup used by the native FRI verifier.
fn semantic_main_oods_coordinates_v3(
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    table_name: &str,
    column_name: &str,
) -> Result<(usize, usize), SemanticH4BridgeGkrError> {
    let program = crate::air_ir::parse_air_program(program_encoded)
        .map_err(|_| SemanticH4BridgeGkrError::Binding)?;
    let layouts =
        derive_oracle_commitment_layouts(program_encoded, mask_coefficient_count, log_blowup)
            .map_err(|_| SemanticH4BridgeGkrError::Binding)?;
    let (table_index, table) = program
        .tables
        .iter()
        .enumerate()
        .find(|(_, table)| table._name == table_name)
        .ok_or(SemanticH4BridgeGkrError::Binding)?;
    let column_index = table
        .columns
        .iter()
        .position(|name| name == column_name)
        .ok_or(SemanticH4BridgeGkrError::Binding)?;
    if table
        .fixed_columns
        .iter()
        .any(|(fixed, _)| *fixed == column_index)
    {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let geometry = layouts
        .tables
        .get(table_index)
        .ok_or(SemanticH4BridgeGkrError::Binding)?;
    let committed_column_ordinal = (0..column_index)
        .filter(|index| !table.fixed_columns.iter().any(|(fixed, _)| fixed == index))
        .count();
    if committed_column_ordinal >= geometry.main_column_count {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let logs = layouts
        .main_trace
        .specs()
        .iter()
        .chain(
            layouts
                .interaction_trace
                .as_ref()
                .into_iter()
                .flat_map(|layout| layout.specs()),
        )
        .chain(layouts.composition.specs())
        .map(|spec| spec.log_size)
        .collect::<BTreeSet<_>>();
    let claim_ordinal = logs
        .iter()
        .position(|log| *log == geometry.evaluation_log_size)
        .ok_or(SemanticH4BridgeGkrError::Binding)?;
    Ok((
        claim_ordinal,
        geometry
            .main_column_offset
            .checked_add(committed_column_ordinal)
            .ok_or(SemanticH4BridgeGkrError::Shape)?,
    ))
}

/// Governed wrapper for the semantic bridge columns.  This removes the last
/// caller-selected DEEP claim/value coordinates from the accepting path.
#[allow(clippy::too_many_arguments)]
pub fn verify_semantic_bridge_functional_from_program_v3(
    profile: SemanticH4BridgeProfile,
    circuit: SemanticH4BridgeCircuit,
    column: SemanticBridgeBaseColumnV3,
    source_claim_point: &[Fp16],
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    verified_fri: &crate::fri_pipeline::VerifiedFriPipelineV3,
    conjugate: bool,
    proof: &CircleCoefficientMleProofV3,
    expected_coefficient_root: BindingRootV2,
    functional_challenges: &[Fp16],
    coefficient_context: BindingDigestV2,
    circle_completion_coin: BindingDigestV2,
    functional_completion_coin: BindingDigestV2,
) -> Result<VerifiedSemanticBridgeFunctionalV3, SemanticH4BridgeGkrError> {
    let derived = derive_semantic_bridge_functional_coins_v3(
        profile,
        circuit,
        column,
        source_claim_point,
        verified_fri,
    )?;
    if functional_challenges != derived.functional_challenges
        || coefficient_context != derived.coefficient_context
        || circle_completion_coin != derived.circle_completion_coin
        || functional_completion_coin != derived.functional_completion_coin
    {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let (table, semantic_column) = match column {
        SemanticBridgeBaseColumnV3::MessageLive => ("sha3_message_batch", "live"),
        SemanticBridgeBaseColumnV3::MessageValue => ("sha3_message_batch", "value"),
        SemanticBridgeBaseColumnV3::DigestValue => ("sha3_digest_byte_batch", "value"),
    };
    let (claim_ordinal, value_ordinal) = semantic_main_oods_coordinates_v3(
        program_encoded,
        mask_coefficient_count,
        log_blowup,
        table,
        semantic_column,
    )?;
    verify_semantic_bridge_functional_v3(
        profile,
        circuit,
        column,
        source_claim_point,
        verified_fri,
        claim_ordinal,
        value_ordinal,
        conjugate,
        proof,
        expected_coefficient_root,
        functional_challenges,
        coefficient_context,
        circle_completion_coin,
        functional_completion_coin,
    )
}

/// Produce one verifier-fixed semantic Circle functional proof from the
/// authenticated semantic trace column.
///
/// The caller supplies the exact logical coset rows owned by the semantic
/// producer and the strict/GKR-derived functional point.  This function owns
/// the sparse row map, Circle point, functional binding, and coefficient PCS
/// construction; it never accepts a caller-provided target or claim/value
/// ordinal.  The result is immediately replayed through the same governed
/// verifier used by the real witness path before it is returned.
#[allow(clippy::too_many_arguments)]
pub fn produce_semantic_bridge_functional_input_v3(
    profile: SemanticH4BridgeProfile,
    circuit: SemanticH4BridgeCircuit,
    column: SemanticBridgeBaseColumnV3,
    source_claim_point: &[Fp16],
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    verified_fri: &crate::fri_pipeline::VerifiedFriPipelineV3,
    logical_coset_rows: Vec<Fp16>,
    conjugate: bool,
) -> Result<SemanticBridgeFunctionalProofInputV3, SemanticH4BridgeGkrError> {
    let derived = derive_semantic_bridge_functional_coins_v3(
        profile,
        circuit,
        column,
        source_claim_point,
        verified_fri,
    )?;
    let functional_challenges = derived.functional_challenges.as_slice();
    let coefficient_context = derived.coefficient_context;
    let circle_completion_coin = derived.circle_completion_coin;
    let functional_completion_coin = derived.functional_completion_coin;
    if !expected_semantic_columns(circuit).contains(&column)
        || source_claim_point.len()
            != source_wire_log(circuit) + usize::from(circuit_group_log(profile, circuit))
        || functional_challenges.len() != usize::from(semantic_column_log(profile, column))
    {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let row_count = 1usize
        .checked_shl(
            u32::try_from(functional_challenges.len())
                .map_err(|_| SemanticH4BridgeGkrError::Shape)?,
        )
        .ok_or(SemanticH4BridgeGkrError::Shape)?;
    if logical_coset_rows.len() != row_count {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let descriptor = build_hash_bus_descriptor_with_state(semantic_profile(profile))
        .map_err(|_| SemanticH4BridgeGkrError::Shape)?;
    let mut row_weights = Vec::with_capacity(row_count);
    for row in 0..row_count {
        row_weights.push(
            semantic_row_weight(&descriptor, circuit, column, source_claim_point, row)
                .map_err(|_| SemanticH4BridgeGkrError::Binding)?,
        );
    }
    let mut circle_point = verified_fri.query_point();
    if conjugate {
        circle_point.x = circle_point.x.conjugate();
        circle_point.y = circle_point.y.conjugate();
    }
    let (proof, coefficient_root) = prove_circle_coefficient_linear_v3(
        logical_coset_rows,
        circle_point,
        row_weights,
        functional_challenges,
        coefficient_context,
        circle_completion_coin,
        functional_completion_coin,
    )
    .map_err(|_| SemanticH4BridgeGkrError::Binding)?;
    let result = SemanticBridgeFunctionalProofInputV3 {
        proof,
        coefficient_root,
        functional_challenges: functional_challenges.to_vec(),
        coefficient_context,
        circle_completion_coin,
        functional_completion_coin,
        conjugate,
    };
    verify_semantic_bridge_functional_from_program_v3(
        profile,
        circuit,
        column,
        source_claim_point,
        program_encoded,
        mask_coefficient_count,
        log_blowup,
        verified_fri,
        result.conjugate,
        &result.proof,
        result.coefficient_root,
        &result.functional_challenges,
        result.coefficient_context,
        result.circle_completion_coin,
        result.functional_completion_coin,
    )?;
    Ok(result)
}

/// Produce the complete verifier-ordered semantic functional inventory.
///
/// The callback supplies only the authenticated logical values of the column
/// requested by this module. Circuit order, column order, GKR claim points,
/// row counts, public coins, and FRI coordinates remain verifier-owned.
pub fn produce_semantic_bridge_functional_inventory_v3<E>(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    verified_fri: &crate::fri_pipeline::VerifiedFriPipelineV3,
    mut column_rows: impl FnMut(
        SemanticH4BridgeCircuit,
        SemanticBridgeBaseColumnV3,
        usize,
    ) -> Result<Vec<Fp16>, E>,
) -> Result<Vec<SemanticBridgeFunctionalProofInputV3>, SemanticH4BridgeGkrError> {
    let mut proofs = Vec::new();
    for (claim, circuit) in verified.source_claims.iter().zip(&verified.source_circuits) {
        for column in expected_semantic_columns(*circuit) {
            let row_count = 1usize
                .checked_shl(u32::from(semantic_column_log(verified.profile, *column)))
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            let rows = column_rows(*circuit, *column, row_count)
                .map_err(|_| SemanticH4BridgeGkrError::Binding)?;
            proofs.push(produce_semantic_bridge_functional_input_v3(
                verified.profile,
                *circuit,
                *column,
                &claim.point,
                program_encoded,
                mask_coefficient_count,
                log_blowup,
                verified_fri,
                rows,
                false,
            )?);
        }
    }
    Ok(proofs)
}

/// Produce the semantic functional inventory directly from the main columns
/// retained by the native AIR composition prover.  This is the smallest
/// production path: the values are neither reconstructed from a boundary nor
/// copied through a second trace builder, and the generic inventory routine
/// continues to own circuit/column ordering and all verifier-derived coins.
pub fn produce_semantic_bridge_functional_inventory_from_air_v3(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    verified_fri: &crate::fri_pipeline::VerifiedFriPipelineV3,
    composition: &crate::air_composition::AirCompositionOracle,
) -> Result<Vec<SemanticBridgeFunctionalProofInputV3>, SemanticH4BridgeGkrError> {
    let program = crate::air_ir::parse_air_program(program_encoded)
        .map_err(|_| SemanticH4BridgeGkrError::Binding)?;
    if composition.program_binary_commitment
        != crate::oracle_commitment::derive_oracle_commitment_layouts(
            program_encoded,
            mask_coefficient_count,
            log_blowup,
        )
        .map_err(|_| SemanticH4BridgeGkrError::Binding)?
        .program_binary_commitment
    {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    produce_semantic_bridge_functional_inventory_v3(
        verified,
        program_encoded,
        mask_coefficient_count,
        log_blowup,
        verified_fri,
        |_, column, row_count| {
            let (table_name, column_name) = match column {
                SemanticBridgeBaseColumnV3::MessageLive => ("sha3_message_batch", "live"),
                SemanticBridgeBaseColumnV3::MessageValue => ("sha3_message_batch", "value"),
                SemanticBridgeBaseColumnV3::DigestValue => ("sha3_digest_byte_batch", "value"),
            };
            let (table_index, table) = program
                .tables
                .iter()
                .enumerate()
                .find(|(_, table)| table._name == table_name)
                .ok_or(SemanticH4BridgeGkrError::Binding)?;
            let column_index = table
                .columns
                .iter()
                .position(|name| name == column_name)
                .ok_or(SemanticH4BridgeGkrError::Binding)?;
            if table
                .fixed_columns
                .iter()
                .any(|(fixed, _)| *fixed == column_index)
            {
                return Err(SemanticH4BridgeGkrError::Binding);
            }
            let committed = composition
                .tables
                .iter()
                .find(|candidate| candidate.table_index as usize == table_index)
                .and_then(|candidate| candidate.trace_columns.get(column_index))
                .ok_or(SemanticH4BridgeGkrError::Binding)?;
            if committed.len() != row_count {
                return Err(SemanticH4BridgeGkrError::Shape);
            }
            Ok(committed.iter().copied().map(Fp16::from_m31).collect())
        },
    )
}

/// Batch the semantic Circle-adapter terminals and verifier-fixed constants
/// in the exact verified-GKR source-claim order.  Every adapter must terminate
/// at the corresponding GKR point; the batching challenge is sampled only
/// after the GKR claims and both component roots are fixed.
pub(crate) fn authenticate_semantic_bridge_source_batch_v2(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    semantic_terms: &[Vec<VerifiedCircleLagrangeSparseFunctional>],
    verifier_fixed: &[Fp16],
    claim_challenge: Fp16,
) -> Result<VerifiedSemanticBridgeSourceBatchV2, SemanticH4BridgeGkrError> {
    if claim_challenge.is_zero()
        || verified.source_claims.is_empty()
        || verified.source_claims.len() != verified.source_circuits.len()
        || semantic_terms.len() != verified.source_claims.len()
        || verifier_fixed.len() != verified.source_claims.len()
    {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut power = Fp16::ONE;
    let mut batched_value = Fp16::ZERO;
    for ((claim, terms), fixed) in verified
        .source_claims
        .iter()
        .zip(semantic_terms)
        .zip(verifier_fixed)
    {
        if claim.point.is_empty()
            || terms
                .iter()
                .any(|term| term.multilinear_point != claim.point)
        {
            return Err(SemanticH4BridgeGkrError::Binding);
        }
        let value = terms
            .iter()
            .fold(*fixed, |sum, term| sum + term.multilinear_value);
        batched_value = batched_value + power * value;
        power = power * claim_challenge;
    }
    Ok(VerifiedSemanticBridgeSourceBatchV2 {
        claim_vector_binding: semantic_h4_bridge_claim_vector_commitment(verified)?,
        claim_challenge,
        batched_value,
        claim_count: verified.source_claims.len(),
    })
}

pub fn authenticate_semantic_bridge_source_batch_v3(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    semantic_terms: &[Vec<VerifiedSemanticBridgeFunctionalV3>],
    claim_challenge: Fp16,
) -> Result<VerifiedSemanticBridgeSourceBatchV3, SemanticH4BridgeGkrError> {
    if claim_challenge.is_zero()
        || verified.source_claims.is_empty()
        || verified.source_claims.len() != verified.source_circuits.len()
        || semantic_terms.len() != verified.source_claims.len()
    {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut ordered_roots = Vec::with_capacity(semantic_terms.iter().map(Vec::len).sum::<usize>());
    let mut roots = b"BL/PQ512/WAVE2/SEMANTIC-BRIDGE-COEFFICIENT-FUNCTIONALS/v3\0".to_vec();
    roots.extend_from_slice(
        &u32::try_from(semantic_terms.iter().map(Vec::len).sum::<usize>())
            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
            .to_be_bytes(),
    );
    let mut power = Fp16::ONE;
    let mut batched_value = Fp16::ZERO;
    let mut claim_values = Vec::with_capacity(verified.source_claims.len());
    let semantic_fri_binding = semantic_terms
        .iter()
        .flat_map(|terms| terms.iter())
        .next()
        .ok_or(SemanticH4BridgeGkrError::Shape)?
        .semantic_fri_binding;
    for ((claim, circuit), terms) in verified
        .source_claims
        .iter()
        .zip(&verified.source_circuits)
        .zip(semantic_terms)
    {
        let expected_columns = expected_semantic_columns(*circuit);
        if claim.point.is_empty()
            || terms.len() != expected_columns.len()
            || terms.iter().zip(expected_columns).any(|(term, column)| {
                term.source_claim_point != claim.point
                    || term.circuit != *circuit
                    || term.column != *column
                    || term.semantic_fri_binding != semantic_fri_binding
                    || match semantic_functional_binding(
                        verified.profile,
                        *circuit,
                        *column,
                        &claim.point,
                    ) {
                        Ok(binding) => binding != term.functional_binding,
                        Err(_) => true,
                    }
            })
        {
            return Err(SemanticH4BridgeGkrError::Binding);
        }
        let value = terms.iter().try_fold(
            semantic_fixed_source_value(verified.profile, *circuit, &claim.point)?,
            |sum, term| Ok::<_, SemanticH4BridgeGkrError>(sum + term.value),
        )?;
        claim_values.push(value);
        for term in terms {
            ordered_roots.push(term.coefficient_root);
            roots.extend_from_slice(term.coefficient_root.as_bytes());
            roots.extend_from_slice(term.functional_binding.as_bytes());
        }
        batched_value = batched_value + power * value;
        power = power * claim_challenge;
    }
    Ok(VerifiedSemanticBridgeSourceBatchV3 {
        semantic_fri_binding,
        claim_vector_binding: semantic_h4_bridge_claim_vector_commitment(verified)?,
        coefficient_root_inventory_binding: semantic_coefficient_root_inventory_binding_v3(
            &ordered_roots,
        )?,
        coefficient_roots_binding: BindingDigestV2::hash(BindingRoleV2::Payload, &roots)?,
        claim_challenge,
        batched_value,
        claim_count: verified.source_claims.len(),
        claim_values,
    })
}

/// Verify the complete ordered semantic functional inventory and return the
/// opaque batch consumed by H4. No host-selected circuit, column, OODS ordinal
/// or scalar enters the accepting path.
#[allow(clippy::too_many_arguments)]
pub fn verify_semantic_bridge_source_batch_from_program_v3(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    program_encoded: &[u8],
    mask_coefficient_count: usize,
    log_blowup: u8,
    verified_fri: &crate::fri_pipeline::VerifiedFriPipelineV3,
    proofs: &[SemanticBridgeFunctionalProofInputV3],
    claim_challenge: Fp16,
) -> Result<VerifiedSemanticBridgeSourceBatchV3, SemanticH4BridgeGkrError> {
    let expected_count = verified
        .source_circuits
        .iter()
        .map(|circuit| expected_semantic_columns(*circuit).len())
        .sum::<usize>();
    if proofs.len() != expected_count {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut cursor = 0usize;
    let mut terms = Vec::with_capacity(verified.source_claims.len());
    for (claim, circuit) in verified.source_claims.iter().zip(&verified.source_circuits) {
        let mut circuit_terms = Vec::with_capacity(expected_semantic_columns(*circuit).len());
        for column in expected_semantic_columns(*circuit) {
            let input = proofs.get(cursor).ok_or(SemanticH4BridgeGkrError::Shape)?;
            circuit_terms.push(verify_semantic_bridge_functional_from_program_v3(
                verified.profile,
                *circuit,
                *column,
                &claim.point,
                program_encoded,
                mask_coefficient_count,
                log_blowup,
                verified_fri,
                input.conjugate,
                &input.proof,
                input.coefficient_root,
                &input.functional_challenges,
                input.coefficient_context,
                input.circle_completion_coin,
                input.functional_completion_coin,
            )?);
            cursor += 1;
        }
        terms.push(circuit_terms);
    }
    if cursor != proofs.len() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    authenticate_semantic_bridge_source_batch_v3(verified, &terms, claim_challenge)
}

pub(crate) fn authenticate_bridge_raw_source_claim(
    expected_point: &[Fp16],
    semantic_terms: &[VerifiedCircleLagrangeSparseFunctional],
    h4_terms: &[VerifiedH4BridgeSourceTerminalV2],
    expected_h4_source_binding: BindingDigestV2,
    expected_h4_answer_binding: BindingDigestV2,
    verifier_fixed: Fp16,
) -> Result<AuthenticatedBridgeRawSourceClaim, SemanticH4BridgeGkrError> {
    if expected_point.is_empty()
        || semantic_terms
            .iter()
            .any(|term| term.multilinear_point != expected_point)
        || h4_terms.iter().any(|term| {
            term.point() != expected_point
                || term.source_segment_set_binding() != expected_h4_source_binding
                || term.answer_binding() != expected_h4_answer_binding
        })
    {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let value = semantic_terms
        .iter()
        .fold(verifier_fixed, |sum, term| sum + term.multilinear_value)
        + h4_terms
            .iter()
            .fold(Fp16::ZERO, |sum, term| sum + term.masked_value());
    Ok(AuthenticatedBridgeRawSourceClaim {
        point: expected_point.to_vec(),
        value,
    })
}

/// Bind every raw bridge round-input claim to the masked GKR view.  The added
/// equations are included in the same committed-mask batch as all internal
/// GKR corrections; no raw or independently adjustable mask opening is
/// serialized.
pub(crate) fn bind_semantic_h4_bridge_raw_sources(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    raw: &[AuthenticatedBridgeRawSourceClaim],
) -> Result<VerifiedSemanticH4BridgeSourceBinding, SemanticH4BridgeGkrError> {
    if raw.len() != verified.source_claims.len() || raw.is_empty() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut constraints = verified.mask_constraints.clone();
    for (masked, raw) in verified.source_claims.iter().zip(raw) {
        let layer = masked.mask_layer.ok_or(SemanticH4BridgeGkrError::Binding)?;
        if masked.point != raw.point || raw.point.is_empty() {
            return Err(SemanticH4BridgeGkrError::Binding);
        }
        constraints.push(UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::LayerBooleanSum {
                layer,
                z_first: raw.point[0],
                scale: boolean_vanishing(&raw.point),
            }],
            residual: masked.masked_value - raw.value,
        });
    }
    Ok(VerifiedSemanticH4BridgeSourceBinding {
        source_claim_count: raw.len(),
        mask_constraints: constraints,
        source_batch_binding: BindingDigestV2::hash(
            BindingRoleV2::Payload,
            &[
                b"BL/PQ512/WAVE2/SEMANTIC-H4-SOURCE-BINDING/legacy/v1\0".as_slice(),
                &u32::try_from(raw.len())
                    .map_err(|_| SemanticH4BridgeGkrError::Shape)?
                    .to_be_bytes(),
            ]
            .concat(),
        )?,
    })
}

/// Complete the proof-native semantic/H4 source equality at one verifier
/// batching challenge.  The semantic batch is built exclusively from
/// authenticated Circle adapters; the H4 batch is built exclusively from the
/// native source/base roots and its public Construction answer.  The complete
/// masked GKR claim vector must equal their sum.
pub(crate) fn bind_semantic_h4_bridge_batched_sources_v2(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    semantic: &VerifiedSemanticBridgeSourceBatchV2,
    h4: &VerifiedH4BridgeSourceResponseV2,
) -> Result<VerifiedSemanticH4BridgeSourceBinding, SemanticH4BridgeGkrError> {
    if semantic.claim_count != verified.source_claims.len()
        || semantic.claim_count == 0
        || semantic.claim_vector_binding != semantic_h4_bridge_claim_vector_commitment(verified)?
        || h4.claim_vector_binding() != semantic.claim_vector_binding
    {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let mut complete_masked = Fp16::ZERO;
    let mut power = Fp16::ONE;
    for claim in &verified.source_claims {
        complete_masked = complete_masked + power * claim.masked_value;
        power = power * semantic.claim_challenge;
    }
    if complete_masked != semantic.batched_value + h4.masked_target() {
        return Err(SemanticH4BridgeGkrError::Algebra);
    }
    let mut encoded = b"BL/PQ512/WAVE2/SEMANTIC-H4-SOURCE-BINDING/v2\0".to_vec();
    encoded.extend_from_slice(semantic.claim_vector_binding.as_bytes());
    encoded.extend_from_slice(&semantic.claim_challenge.encode());
    encoded.extend_from_slice(&semantic.batched_value.encode());
    encoded.extend_from_slice(h4.source_root().as_bytes());
    encoded.extend_from_slice(h4.base_root().as_bytes());
    encoded.extend_from_slice(h4.answer_binding().as_bytes());
    encoded.extend_from_slice(&h4.masked_target().encode());
    Ok(VerifiedSemanticH4BridgeSourceBinding {
        source_claim_count: semantic.claim_count,
        mask_constraints: verified.mask_constraints.clone(),
        source_batch_binding: BindingDigestV2::hash(BindingRoleV2::Payload, &encoded)?,
    })
}

pub(crate) fn bind_semantic_h4_bridge_batched_sources_v3(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    semantic: &VerifiedSemanticBridgeSourceBatchV3,
    h4: &VerifiedH4BridgeSourceResponseV2,
) -> Result<VerifiedSemanticH4BridgeSourceBinding, SemanticH4BridgeGkrError> {
    if semantic.claim_count != verified.source_claims.len()
        || semantic.claim_count == 0
        || semantic.claim_vector_binding != semantic_h4_bridge_claim_vector_commitment(verified)?
        || h4.claim_vector_binding() != semantic.claim_vector_binding
    {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let mut complete_masked = Fp16::ZERO;
    let mut power = Fp16::ONE;
    for claim in &verified.source_claims {
        complete_masked = complete_masked + power * claim.masked_value;
        power = power * semantic.claim_challenge;
    }
    if complete_masked != semantic.batched_value + h4.masked_target() {
        return Err(SemanticH4BridgeGkrError::Algebra);
    }
    let mask_constraints =
        source_augmented_mask_constraints(verified, semantic, core::slice::from_ref(h4))?;
    let mut encoded = b"BL/PQ512/WAVE2/SEMANTIC-H4-SOURCE-BINDING/v3\0".to_vec();
    encoded.extend_from_slice(semantic.claim_vector_binding.as_bytes());
    encoded.extend_from_slice(semantic.coefficient_roots_binding.as_bytes());
    encoded.extend_from_slice(&semantic.claim_challenge.encode());
    encoded.extend_from_slice(&semantic.batched_value.encode());
    encoded.extend_from_slice(h4.source_root().as_bytes());
    encoded.extend_from_slice(h4.base_root().as_bytes());
    encoded.extend_from_slice(h4.answer_binding().as_bytes());
    encoded.extend_from_slice(&h4.masked_target().encode());
    for value in semantic.claim_values() {
        encoded.extend_from_slice(&value.encode());
    }
    for value in h4.source_claim_values() {
        encoded.extend_from_slice(&value.encode());
    }
    Ok(VerifiedSemanticH4BridgeSourceBinding {
        source_claim_count: semantic.claim_count,
        mask_constraints,
        source_batch_binding: BindingDigestV2::hash(BindingRoleV2::Payload, &encoded)?,
    })
}

fn source_augmented_mask_constraints(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    semantic: &VerifiedSemanticBridgeSourceBatchV3,
    h4: &[VerifiedH4BridgeSourceResponseV2],
) -> Result<Vec<UniformGkrMaskConstraint>, SemanticH4BridgeGkrError> {
    if semantic.claim_values().len() != verified.source_claims.len()
        || h4.is_empty()
        || h4
            .iter()
            .any(|response| response.source_claim_values().len() != verified.source_claims.len())
    {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let mut constraints = verified.mask_constraints.clone();
    for (claim_index, masked) in verified.source_claims.iter().enumerate() {
        let h4_value = h4.iter().fold(Fp16::ZERO, |sum, response| {
            sum + response.source_claim_values()[claim_index]
        });
        let raw_value = semantic.claim_values()[claim_index] + h4_value;
        let layer = masked.mask_layer.ok_or(SemanticH4BridgeGkrError::Binding)?;
        if masked.point.is_empty() {
            return Err(SemanticH4BridgeGkrError::Binding);
        }
        constraints.push(UniformGkrMaskConstraint {
            functionals: vec![UniformGkrMaskFunctional::LayerBooleanSum {
                layer,
                z_first: masked.point[0],
                scale: boolean_vanishing(&masked.point),
            }],
            residual: masked.masked_value - raw_value,
        });
    }
    Ok(constraints)
}

/// Bind an ordered physical-shard partition of the H4 source.  The verifier
/// checks the one global masked bridge identity against the sum of all shard
/// targets; no shard is allowed to claim the complete target independently.
pub fn bind_semantic_h4_bridge_batched_sources_v3_aggregate(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    semantic: &VerifiedSemanticBridgeSourceBatchV3,
    h4: &[VerifiedH4BridgeSourceResponseV2],
) -> Result<VerifiedSemanticH4BridgeSourceBinding, SemanticH4BridgeGkrError> {
    if h4.is_empty()
        || semantic.claim_count != verified.source_claims.len()
        || semantic.claim_count == 0
        || semantic.claim_vector_binding != semantic_h4_bridge_claim_vector_commitment(verified)?
        || h4
            .iter()
            .any(|response| response.claim_vector_binding() != semantic.claim_vector_binding)
    {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let mut power = Fp16::ONE;
    let complete_masked = verified
        .source_claims
        .iter()
        .fold(Fp16::ZERO, |sum, claim| {
            let result = sum + power * claim.masked_value;
            power = power * semantic.claim_challenge;
            result
        });
    let h4_target = h4
        .iter()
        .fold(Fp16::ZERO, |sum, response| sum + response.masked_target());
    if complete_masked != semantic.batched_value + h4_target {
        return Err(SemanticH4BridgeGkrError::Algebra);
    }
    let mask_constraints = source_augmented_mask_constraints(verified, semantic, h4)?;
    let mut encoded = b"BL/PQ512/WAVE2/SEMANTIC-H4-SOURCE-BINDING/v3/AGGREGATE\0".to_vec();
    encoded.extend_from_slice(semantic.claim_vector_binding.as_bytes());
    encoded.extend_from_slice(semantic.coefficient_roots_binding.as_bytes());
    encoded.extend_from_slice(&semantic.claim_challenge.encode());
    encoded.extend_from_slice(&semantic.batched_value.encode());
    encoded.extend_from_slice(&(h4.len() as u32).to_be_bytes());
    for response in h4 {
        encoded.extend_from_slice(response.source_root().as_bytes());
        encoded.extend_from_slice(response.base_root().as_bytes());
        encoded.extend_from_slice(response.answer_binding().as_bytes());
        encoded.extend_from_slice(&response.masked_target().encode());
        for value in response.source_claim_values() {
            encoded.extend_from_slice(&value.encode());
        }
    }
    for value in semantic.claim_values() {
        encoded.extend_from_slice(&value.encode());
    }
    Ok(VerifiedSemanticH4BridgeSourceBinding {
        source_claim_count: semantic.claim_count,
        mask_constraints,
        source_batch_binding: BindingDigestV2::hash(BindingRoleV2::Payload, &encoded)?,
    })
}

/// Opaque output of the native-128 Construction verifier for the bridge mask
/// polynomial.  Its fields are private so a package caller cannot substitute a
/// matching scalar for a missing PCS opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedSemanticH4BridgeMaskOpening {
    mask_root: BindingDigestV2,
    coefficient_weights: Vec<Fp16>,
    opening: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSemanticH4BridgeMaskBatch {
    pub(crate) mask_root: BindingDigestV2,
    pub(crate) challenge: Fp16,
    pub(crate) coefficient_weights: Vec<Fp16>,
    pub(crate) opening: Fp16,
    source_batch_binding: Option<BindingDigestV2>,
}

impl VerifiedSemanticH4BridgeMaskBatch {
    pub(crate) const fn source_batch_binding(&self) -> Option<BindingDigestV2> {
        self.source_batch_binding
    }
}

impl VerifiedSemanticH4BridgeSourceBinding {
    pub(crate) const fn source_batch_binding(&self) -> BindingDigestV2 {
        self.source_batch_binding
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicBridgeInnerProductProof {
    /// Degree-two coefficient vectors in low-to-high order.
    pub rounds: Vec<[Fp16; 3]>,
}

pub const PUBLIC_BRIDGE_INNER_PRODUCT_PROOF_MAGIC: &[u8; 8] = b"BLBIPV02";
pub const PUBLIC_BRIDGE_INNER_PRODUCT_PROOF_VERSION: u16 = 2;

/// Encode the verifier-facing bridge inner-product proof.  The bytes are
/// transport material only; acceptance still requires the native PCS opening
/// and verifier-derived public weights.
pub fn encode_public_bridge_inner_product_proof(
    proof: &PublicBridgeInnerProductProof,
) -> Result<Vec<u8>, SemanticH4BridgeGkrError> {
    if proof.rounds.is_empty() || proof.rounds.len() > 32 {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut encoded = Vec::with_capacity(20 + proof.rounds.len() * 3 * 64);
    encoded.extend_from_slice(PUBLIC_BRIDGE_INNER_PRODUCT_PROOF_MAGIC);
    encoded.extend_from_slice(&PUBLIC_BRIDGE_INNER_PRODUCT_PROOF_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(proof.rounds.len())
            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&[0_u8; 4]);
    for round in &proof.rounds {
        for coefficient in round {
            encoded.extend_from_slice(&coefficient.encode());
        }
    }
    Ok(encoded)
}

/// Decode the canonical bridge inner-product proof without constructing an
/// accepting verifier receipt.
pub fn decode_public_bridge_inner_product_proof(
    encoded: &[u8],
) -> Result<PublicBridgeInnerProductProof, SemanticH4BridgeGkrError> {
    if encoded.len() < 20
        || encoded.get(..8) != Some(PUBLIC_BRIDGE_INNER_PRODUCT_PROOF_MAGIC)
        || u16::from_be_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| SemanticH4BridgeGkrError::Encoding)?,
        ) != PUBLIC_BRIDGE_INNER_PRODUCT_PROOF_VERSION
        || encoded[10..12] != [0_u8; 2]
        || encoded[16..20] != [0_u8; 4]
    {
        return Err(SemanticH4BridgeGkrError::Encoding);
    }
    let count = usize::try_from(u32::from_be_bytes(
        encoded[12..16]
            .try_into()
            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?,
    ))
    .map_err(|_| SemanticH4BridgeGkrError::Encoding)?;
    if count == 0 || count > 32 {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let expected = 20_usize
        .checked_add(
            count
                .checked_mul(3 * 64)
                .ok_or(SemanticH4BridgeGkrError::Encoding)?,
        )
        .ok_or(SemanticH4BridgeGkrError::Encoding)?;
    if encoded.len() != expected {
        return Err(SemanticH4BridgeGkrError::Encoding);
    }
    let mut offset = 20;
    let mut rounds = Vec::with_capacity(count);
    for _ in 0..count {
        let mut round = [Fp16::ZERO; 3];
        for coefficient in &mut round {
            *coefficient = Fp16::decode(
                encoded
                    .get(offset..offset + 64)
                    .ok_or(SemanticH4BridgeGkrError::Encoding)?,
            )
            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?;
            offset += 64;
        }
        rounds.push(round);
    }
    Ok(PublicBridgeInnerProductProof { rounds })
}

/// Opaque output of a component-native BindingRootV2 multilinear PCS opening.
/// Only the owning PCS verifier may construct this value in production.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedBridgeMleOpening {
    root: BindingRootV2,
    point: Vec<Fp16>,
    value: Fp16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBridgeInnerProduct {
    pub(crate) root: BindingRootV2,
    pub(crate) point: Vec<Fp16>,
    pub(crate) value: Fp16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SemanticH4BridgeGkrError {
    Shape,
    Schedule,
    Algebra,
    Encoding,
    Binding,
    Transcript,
}

impl From<BindingRootV2Error> for SemanticH4BridgeGkrError {
    fn from(_: BindingRootV2Error) -> Self {
        Self::Binding
    }
}

fn gate(left: usize, right: usize, kind: KeccakDagGateKind) -> KeccakDagGate {
    KeccakDagGate { left, right, kind }
}

fn layer(
    left_source: KeccakDagSource,
    right_source: KeccakDagSource,
    left_width: usize,
    right_width: usize,
    mut gates: Vec<KeccakDagGate>,
) -> KeccakDagLayer {
    assert!(!gates.is_empty());
    assert!(left_width.is_power_of_two() && right_width.is_power_of_two());
    assert!(
        gates
            .iter()
            .all(|value| value.left < left_width && value.right < right_width)
    );
    let raw_width = gates.len();
    let padded_width = raw_width.next_power_of_two();
    gates.resize(padded_width, gate(0, 0, KeccakDagGateKind::Zero));
    KeccakDagLayer {
        left_source,
        right_source,
        left_width,
        right_width,
        raw_width,
        padded_width,
        gates,
    }
}

fn rate_layers() -> Vec<KeccakDagLayer> {
    let mut layers = Vec::new();

    let mut first = Vec::with_capacity(16);
    for bit in 0..8 {
        first.push(gate(
            RATE_INPUT_BITS_START + bit,
            RATE_PREDECESSOR_BITS_START + bit,
            KeccakDagGateKind::Xor,
        ));
    }
    first.push(gate(
        RATE_LIVE,
        RATE_PREVIOUS_LIVE,
        KeccakDagGateKind::NotLeftAndRight,
    ));
    first.push(gate(
        RATE_NEXT_BLOCK_ACTIVE,
        RATE_BLOCK_ACTIVE,
        KeccakDagGateKind::NotLeftAndRight,
    ));
    first.push(gate(RATE_VALUE, RATE_VALUE, KeccakDagGateKind::RelayLeft));
    first.push(gate(
        RATE_BLOCK_ACTIVE,
        RATE_BLOCK_ACTIVE,
        KeccakDagGateKind::RelayLeft,
    ));
    layers.push(layer(
        KeccakDagSource::RoundInput,
        KeccakDagSource::RoundInput,
        BRIDGE_RATE_SOURCE_WIDTH,
        BRIDGE_RATE_SOURCE_WIDTH,
        first,
    ));

    let mut weighted = Vec::with_capacity(16);
    for bit in 0..8 {
        weighted.push(gate(
            bit,
            RATE_BIT_WEIGHTS_START + bit,
            KeccakDagGateKind::Multiply,
        ));
    }
    weighted.push(gate(8, RATE_SIX, KeccakDagGateKind::Multiply));
    weighted.push(gate(
        9,
        RATE_FINAL_BYTE_SELECTOR,
        KeccakDagGateKind::Multiply,
    ));
    weighted.push(gate(10, RATE_ONE, KeccakDagGateKind::Multiply));
    weighted.push(gate(11, RATE_ONE, KeccakDagGateKind::Multiply));
    layers.push(layer(
        KeccakDagSource::Layer(0),
        KeccakDagSource::RoundInput,
        16,
        BRIDGE_RATE_SOURCE_WIDTH,
        weighted,
    ));

    let mut final_weight = Vec::with_capacity(16);
    for index in 0..9 {
        final_weight.push(gate(index, index, KeccakDagGateKind::RelayLeft));
    }
    final_weight.push(gate(9, RATE_128, KeccakDagGateKind::Multiply));
    final_weight.push(gate(10, 10, KeccakDagGateKind::RelayLeft));
    final_weight.push(gate(11, 11, KeccakDagGateKind::RelayLeft));
    layers.push(layer(
        KeccakDagSource::Layer(1),
        KeccakDagSource::RoundInput,
        16,
        BRIDGE_RATE_SOURCE_WIDTH,
        final_weight,
    ));

    layers.push(layer(
        KeccakDagSource::Layer(2),
        KeccakDagSource::Layer(2),
        16,
        16,
        vec![
            gate(0, 1, KeccakDagGateKind::Add),
            gate(2, 3, KeccakDagGateKind::Add),
            gate(4, 5, KeccakDagGateKind::Add),
            gate(6, 7, KeccakDagGateKind::Add),
            gate(8, 9, KeccakDagGateKind::Add),
            gate(10, 10, KeccakDagGateKind::RelayLeft),
            gate(11, 11, KeccakDagGateKind::RelayLeft),
        ],
    ));
    layers.push(layer(
        KeccakDagSource::Layer(3),
        KeccakDagSource::Layer(3),
        8,
        8,
        vec![
            gate(0, 1, KeccakDagGateKind::Add),
            gate(2, 3, KeccakDagGateKind::Add),
            gate(4, 5, KeccakDagGateKind::Add),
            gate(6, 6, KeccakDagGateKind::RelayLeft),
        ],
    ));
    layers.push(layer(
        KeccakDagSource::Layer(4),
        KeccakDagSource::Layer(4),
        4,
        4,
        vec![
            gate(0, 1, KeccakDagGateKind::Add),
            gate(2, 2, KeccakDagGateKind::RelayLeft),
            gate(3, 3, KeccakDagGateKind::RelayLeft),
        ],
    ));
    layers.push(layer(
        KeccakDagSource::Layer(5),
        KeccakDagSource::Layer(5),
        4,
        4,
        vec![
            gate(0, 1, KeccakDagGateKind::Subtract),
            gate(2, 2, KeccakDagGateKind::RelayLeft),
        ],
    ));
    layers.push(layer(
        KeccakDagSource::Layer(6),
        KeccakDagSource::Layer(6),
        2,
        2,
        vec![gate(1, 0, KeccakDagGateKind::Multiply)],
    ));
    layers
}

fn inactive_layers() -> Vec<KeccakDagLayer> {
    let gates = (0..2_048)
        .map(|wire| {
            gate(
                BLOCK_ACTIVE,
                BLOCK_INPUT_BITS_START + wire,
                KeccakDagGateKind::NotLeftAndRight,
            )
        })
        .collect();
    vec![layer(
        KeccakDagSource::RoundInput,
        KeccakDagSource::RoundInput,
        BRIDGE_BLOCK_SOURCE_WIDTH,
        BRIDGE_BLOCK_SOURCE_WIDTH,
        gates,
    )]
}

fn capacity_layers() -> Vec<KeccakDagLayer> {
    let difference = (0..1_024)
        .map(|wire| {
            gate(
                BLOCK_INPUT_BITS_START + wire,
                BLOCK_PREDECESSOR_BITS_START + wire,
                KeccakDagGateKind::Subtract,
            )
        })
        .collect();
    let active = (0..1_024)
        .map(|wire| gate(wire, BLOCK_ACTIVE, KeccakDagGateKind::Multiply))
        .collect();
    vec![
        layer(
            KeccakDagSource::RoundInput,
            KeccakDagSource::RoundInput,
            BRIDGE_BLOCK_SOURCE_WIDTH,
            BRIDGE_BLOCK_SOURCE_WIDTH,
            difference,
        ),
        layer(
            KeccakDagSource::Layer(0),
            KeccakDagSource::RoundInput,
            1_024,
            BRIDGE_BLOCK_SOURCE_WIDTH,
            active,
        ),
    ]
}

fn digest_layers() -> Vec<KeccakDagLayer> {
    let mut layers = Vec::new();
    let actual_last = (0..BRIDGE_DIGEST_BLOCK_WIDTH)
        .map(|block| {
            gate(
                DIGEST_NEXT_ACTIVE_START + block,
                DIGEST_ACTIVE_START + block,
                KeccakDagGateKind::NotLeftAndRight,
            )
        })
        .collect();
    layers.push(layer(
        KeccakDagSource::RoundInput,
        KeccakDagSource::RoundInput,
        BRIDGE_DIGEST_SOURCE_WIDTH,
        BRIDGE_DIGEST_SOURCE_WIDTH,
        actual_last,
    ));
    let selected = (0..BRIDGE_DIGEST_BLOCK_WIDTH)
        .map(|block| {
            gate(
                block,
                DIGEST_OUTPUT_BYTES_START + block,
                KeccakDagGateKind::Multiply,
            )
        })
        .collect();
    layers.push(layer(
        KeccakDagSource::Layer(0),
        KeccakDagSource::RoundInput,
        BRIDGE_DIGEST_BLOCK_WIDTH,
        BRIDGE_DIGEST_SOURCE_WIDTH,
        selected,
    ));
    let mut width = BRIDGE_DIGEST_BLOCK_WIDTH;
    while width > 1 {
        let mut gates = (0..width / 2)
            .map(|index| gate(2 * index, 2 * index + 1, KeccakDagGateKind::Add))
            .collect::<Vec<_>>();
        // The generic masked-GKR terminal reduction requires at least one
        // source-label variable and its single-variable correction assumes a
        // two-wire counterpart. Preserve the scalar sum while retaining three
        // verifier-fixed zero padding wires at the final reduction boundary.
        if width == 2 {
            gates.extend(core::iter::repeat_n(gate(0, 0, KeccakDagGateKind::Zero), 3));
        }
        let prior = layers.len() - 1;
        layers.push(layer(
            KeccakDagSource::Layer(prior),
            KeccakDagSource::Layer(prior),
            width,
            width,
            gates,
        ));
        width /= 2;
    }
    let prior = layers.len() - 1;
    let prior_width = layers[prior].padded_width;
    layers.push(layer(
        KeccakDagSource::Layer(prior),
        KeccakDagSource::RoundInput,
        prior_width,
        BRIDGE_DIGEST_SOURCE_WIDTH,
        vec![gate(0, DIGEST_EXPECTED_BYTE, KeccakDagGateKind::Subtract)],
    ));
    layers
}

pub fn semantic_h4_bridge_topologies() -> SemanticH4BridgeTopologies {
    SemanticH4BridgeTopologies {
        rate: rate_layers(),
        inactive: inactive_layers(),
        capacity: capacity_layers(),
        digest: digest_layers(),
    }
}

pub fn semantic_h4_bridge_layer_plans(
    profile: SemanticH4BridgeProfile,
) -> Vec<SemanticH4BridgeLayerPlan> {
    let topologies = semantic_h4_bridge_topologies();
    let mut plans = Vec::with_capacity(
        topologies.rate.len()
            + topologies.inactive.len()
            + topologies.capacity.len()
            + topologies.digest.len(),
    );
    for (circuit, group_log, layers) in [
        (
            SemanticH4BridgeCircuit::Rate,
            profile.rate_group_log(),
            topologies.rate,
        ),
        (
            SemanticH4BridgeCircuit::Inactive,
            BRIDGE_BLOCK_GROUP_LOG,
            topologies.inactive,
        ),
        (
            SemanticH4BridgeCircuit::Capacity,
            BRIDGE_BLOCK_GROUP_LOG,
            topologies.capacity,
        ),
        (
            SemanticH4BridgeCircuit::Digest,
            BRIDGE_DIGEST_GROUP_LOG,
            topologies.digest,
        ),
    ] {
        let layer_count = layers.len();
        for (backward_ordinal, topology) in layers.into_iter().rev().enumerate() {
            plans.push(SemanticH4BridgeLayerPlan {
                circuit,
                layer: layer_count - 1 - backward_ordinal,
                group_log,
                topology,
            });
        }
    }
    plans
}

pub fn semantic_h4_bridge_mask_variable_degrees(
    profile: SemanticH4BridgeProfile,
) -> Vec<Vec<usize>> {
    semantic_h4_bridge_layer_plans(profile)
        .iter()
        .map(|plan| {
            let left_variables = plan.topology.left_width.trailing_zeros() as usize;
            let right_variables = plan.topology.right_width.trailing_zeros() as usize;
            let mut degrees = vec![3; usize::from(plan.group_log)];
            if left_variables != 0 {
                degrees.extend(core::iter::repeat_n(2, left_variables));
                *degrees.last_mut().expect("left variables were checked") =
                    if left_variables == 1 { 5 } else { 3 };
            }
            if right_variables != 0 {
                degrees.extend(core::iter::repeat_n(2, right_variables));
                *degrees.last_mut().expect("right variables were checked") =
                    if right_variables == 1 { 5 } else { 3 };
            }
            degrees.push(2);
            degrees
        })
        .collect()
}

pub fn semantic_h4_bridge_mask_layout(
    profile: SemanticH4BridgeProfile,
) -> Result<CompleteGkrZkMaskCommitmentLayout, GkrZkMaskError> {
    CompleteGkrZkMaskCommitmentLayout::new(
        &semantic_h4_bridge_mask_variable_degrees(profile),
        PACKED_BINARY_MESSAGE_COEFFICIENTS,
    )
}

fn evaluate_bridge_rows(
    layers: &[KeccakDagLayer],
    source: &[Fp16],
) -> Result<Vec<Vec<Fp16>>, SemanticH4BridgeGkrError> {
    let mut rows: Vec<Vec<Fp16>> = Vec::with_capacity(layers.len());
    for layer in layers {
        let left = match layer.left_source {
            KeccakDagSource::RoundInput => source,
            KeccakDagSource::Layer(index) => rows
                .get(index)
                .ok_or(SemanticH4BridgeGkrError::Schedule)?
                .as_slice(),
        };
        let right = match layer.right_source {
            KeccakDagSource::RoundInput => source,
            KeccakDagSource::Layer(index) => rows
                .get(index)
                .ok_or(SemanticH4BridgeGkrError::Schedule)?
                .as_slice(),
        };
        if left.len() < layer.left_width || right.len() < layer.right_width {
            return Err(SemanticH4BridgeGkrError::Shape);
        }
        rows.push(
            layer
                .gates
                .iter()
                .map(|gate| {
                    if gate.left >= left.len() || gate.right >= right.len() {
                        return Err(SemanticH4BridgeGkrError::Shape);
                    }
                    Ok(evaluate_gate(gate.kind, left[gate.left], right[gate.right]))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    Ok(rows)
}

fn evaluate_bridge_multilinear(
    mut values: Vec<Fp16>,
    point: &[Fp16],
) -> Result<Fp16, SemanticH4BridgeGkrError> {
    let expected = 1usize
        .checked_shl(u32::try_from(point.len()).map_err(|_| SemanticH4BridgeGkrError::Shape)?)
        .ok_or(SemanticH4BridgeGkrError::Shape)?;
    if values.len() != expected {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut active = values.len();
    for challenge in point {
        if active < 2 {
            return Err(SemanticH4BridgeGkrError::Shape);
        }
        for index in 0..active / 2 {
            values[index] =
                values[2 * index] * (Fp16::ONE - *challenge) + values[2 * index + 1] * *challenge;
        }
        active /= 2;
    }
    values
        .first()
        .copied()
        .ok_or(SemanticH4BridgeGkrError::Shape)
}

/// Produce the complete masked semantic-H4 bridge GKR from the real round
/// input vectors.  The caller owns the strict public-coin transaction and
/// supplies one callback that is invoked only after each prover message is
/// complete.  Consequently this function cannot choose output points,
/// claim-mix values, sumcheck challenges, or the final `w` challenge itself.
///
/// `source_values` are the four verifier-governed round-input tables in the
/// order Rate, Inactive, Capacity, Digest.  `mask_coefficients` is the
/// producer's private Construction-1 coefficient vector; its shape is checked
/// against the canonical layout and the returned proof is rejected if any
/// circuit's final relation is nonzero.  This is a proof producer, not a
/// verifier shortcut: the returned proof still has to be replayed by
/// [`verify_strict_semantic_h4_bridge_gkr`] and its source columns still have
/// to be authenticated by the semantic Circle adapters.
#[allow(clippy::too_many_arguments)]
pub fn produce_public_masked_semantic_h4_bridge_gkr(
    profile: SemanticH4BridgeProfile,
    context_commitment: BindingDigestV2,
    first_ordinal: u32,
    source_values: [Vec<Fp16>; 4],
    mask_coefficients: &[Fp16],
    challenge_provider: impl FnMut(
        StrictPqRoundDescriptorV2,
        StrictPqFp16PolicyV2,
        &[u8],
    ) -> Result<Vec<Fp16>, SemanticH4BridgeGkrError>,
) -> Result<
    (
        PublicMaskedSemanticH4BridgeGkrProof,
        SemanticH4BridgePublicChallenges,
    ),
    SemanticH4BridgeGkrError,
> {
    produce_public_masked_semantic_h4_bridge_gkr_internal(
        profile,
        context_commitment,
        first_ordinal,
        BridgeProducerSource::Uniform(source_values),
        mask_coefficients,
        challenge_provider,
    )
}

/// Produce the identical public proof for a varying trace without ever
/// materializing a complete group-expanded table in host memory.
#[allow(clippy::too_many_arguments)]
pub fn produce_public_masked_nonuniform_semantic_h4_bridge_gkr(
    profile: SemanticH4BridgeProfile,
    context_commitment: BindingDigestV2,
    first_ordinal: u32,
    oracle: &mut dyn NonuniformSemanticH4BridgeOracle,
    mask_coefficients: &[Fp16],
    challenge_provider: impl FnMut(
        StrictPqRoundDescriptorV2,
        StrictPqFp16PolicyV2,
        &[u8],
    ) -> Result<Vec<Fp16>, SemanticH4BridgeGkrError>,
) -> Result<
    (
        PublicMaskedSemanticH4BridgeGkrProof,
        SemanticH4BridgePublicChallenges,
    ),
    SemanticH4BridgeGkrError,
> {
    produce_public_masked_semantic_h4_bridge_gkr_internal(
        profile,
        context_commitment,
        first_ordinal,
        BridgeProducerSource::Nonuniform(oracle),
        mask_coefficients,
        challenge_provider,
    )
}

enum BridgeProducerSource<'a> {
    Uniform([Vec<Fp16>; 4]),
    Nonuniform(&'a mut dyn NonuniformSemanticH4BridgeOracle),
}

#[allow(clippy::too_many_arguments)]
fn produce_public_masked_semantic_h4_bridge_gkr_internal(
    profile: SemanticH4BridgeProfile,
    context_commitment: BindingDigestV2,
    first_ordinal: u32,
    mut source_provider: BridgeProducerSource<'_>,
    mask_coefficients: &[Fp16],
    mut challenge_provider: impl FnMut(
        StrictPqRoundDescriptorV2,
        StrictPqFp16PolicyV2,
        &[u8],
    ) -> Result<Vec<Fp16>, SemanticH4BridgeGkrError>,
) -> Result<
    (
        PublicMaskedSemanticH4BridgeGkrProof,
        SemanticH4BridgePublicChallenges,
    ),
    SemanticH4BridgeGkrError,
> {
    if context_commitment.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let topologies = semantic_h4_bridge_topologies();
    let plans = semantic_h4_bridge_layer_plans(profile);
    let layout =
        semantic_h4_bridge_mask_layout(profile).map_err(|_| SemanticH4BridgeGkrError::Shape)?;
    let (_, sumcheck_masks, layer_masks) = layout
        .decode_prefix(mask_coefficients)
        .map_err(|_| SemanticH4BridgeGkrError::Shape)?;
    let expected_widths = [
        BRIDGE_RATE_SOURCE_WIDTH,
        BRIDGE_BLOCK_SOURCE_WIDTH,
        BRIDGE_BLOCK_SOURCE_WIDTH,
        BRIDGE_DIGEST_SOURCE_WIDTH,
    ];
    if matches!(
        &source_provider,
        BridgeProducerSource::Uniform(values)
            if values.iter().zip(expected_widths).any(|(values, expected)| values.len() != expected)
    ) || plans.len() != sumcheck_masks.len()
        || plans.len() != layer_masks.len()
    {
        return Err(SemanticH4BridgeGkrError::Shape);
    }

    let ordinal = core::cell::Cell::new(first_ordinal);
    let mut strict_outputs = Vec::<Vec<Fp16>>::new();
    let next_round = core::cell::RefCell::new(
        |descriptor: StrictPqRoundDescriptorV2,
         policy: StrictPqFp16PolicyV2,
         message: &[u8],
         expected_count: usize|
         -> Result<Vec<Fp16>, SemanticH4BridgeGkrError> {
            let output = challenge_provider(descriptor, policy, message)?;
            if output.len() != expected_count
                || output.iter().any(|value| {
                    !policy.accepts(*value)
                        || (policy == StrictPqFp16PolicyV2::NonzeroNonone
                            && (*value == Fp16::ZERO || *value == Fp16::ONE))
                })
            {
                return Err(SemanticH4BridgeGkrError::Transcript);
            }
            strict_outputs.push(output.clone());
            Ok(output)
        },
    );
    let make_round =
        |kind: u16, output_count: usize, policy: StrictPqFp16PolicyV2, message: Vec<u8>| {
            let descriptor = StrictPqRoundDescriptorV2::new(
                kind,
                ordinal.get(),
                u16::try_from(output_count).map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
            )
            .map_err(|_| SemanticH4BridgeGkrError::Transcript)?;
            ordinal.set(
                ordinal
                    .get()
                    .checked_add(1)
                    .ok_or(SemanticH4BridgeGkrError::Transcript)?,
            );
            Ok::<_, SemanticH4BridgeGkrError>((descriptor, policy, message))
        };

    let mut output_points = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut public_layers = Vec::with_capacity(plans.len());
    let mut layer_challenges = Vec::with_capacity(plans.len());
    let mut proof_index = 0_usize;
    let circuit_order = [
        SemanticH4BridgeCircuit::Rate,
        SemanticH4BridgeCircuit::Inactive,
        SemanticH4BridgeCircuit::Capacity,
        SemanticH4BridgeCircuit::Digest,
    ];

    for circuit in circuit_order {
        let circuit_index = circuit_index(circuit);
        let layers = circuit_layers(&topologies, circuit);
        let group_log = circuit_group_log(profile, circuit);
        let computed_rows = match &source_provider {
            BridgeProducerSource::Uniform(values) => {
                Some(evaluate_bridge_rows(layers, &values[circuit_index])?)
            }
            BridgeProducerSource::Nonuniform(_) => None,
        };
        let output_variables = layers
            .last()
            .ok_or(SemanticH4BridgeGkrError::Shape)?
            .padded_width
            .trailing_zeros() as usize;
        let output_count = output_variables + usize::from(group_log);
        let mut output_message = b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/OUTPUT/v1\0".to_vec();
        output_message.extend_from_slice(context_commitment.as_bytes());
        output_message.extend_from_slice(&[profile_code(profile), circuit_code(circuit), 0, 0]);
        let (descriptor, policy, message) = make_round(
            SEMANTIC_H4_BRIDGE_OUTPUT_KIND,
            output_count,
            StrictPqFp16PolicyV2::Uniform,
            output_message,
        )?;
        output_points[circuit_index] =
            next_round.borrow_mut()(descriptor, policy, &message, output_count)?;
        if output_points[circuit_index].len() != output_count {
            return Err(SemanticH4BridgeGkrError::Shape);
        }

        let mut pending_masked = vec![Vec::<PublicMaskedBridgeClaim>::new(); layers.len() + 1];
        let mut pending_raw = vec![Vec::<Fp16>::new(); layers.len() + 1];
        pending_masked[layers.len()].push(PublicMaskedBridgeClaim {
            point: output_points[circuit_index].clone(),
            masked_value: Fp16::ZERO,
            mask_layer: None,
        });
        let output_claim = match &mut source_provider {
            BridgeProducerSource::Uniform(_) => evaluate_bridge_multilinear(
                computed_rows
                    .as_ref()
                    .and_then(|rows| rows.last())
                    .ok_or(SemanticH4BridgeGkrError::Shape)?
                    .clone(),
                &output_points[circuit_index][..output_variables],
            )?,
            BridgeProducerSource::Nonuniform(oracle) => {
                oracle.output_claim(circuit, &output_points[circuit_index])?
            }
        };
        pending_raw[layers.len()].push(output_claim);

        for layer_index in (0..layers.len()).rev() {
            let plan = plans
                .get(proof_index)
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            if plan.circuit != circuit || plan.layer != layer_index {
                return Err(SemanticH4BridgeGkrError::Schedule);
            }
            let layer = &layers[layer_index];
            let incoming = core::mem::take(&mut pending_masked[layer_index + 1]);
            let raw_values = core::mem::take(&mut pending_raw[layer_index + 1]);
            if incoming.is_empty() || incoming.len() != raw_values.len() || incoming.len() > 8 {
                return Err(SemanticH4BridgeGkrError::Shape);
            }

            let mut prelude_message = b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/LAYER/v1\0".to_vec();
            prelude_message.extend_from_slice(context_commitment.as_bytes());
            prelude_message.extend_from_slice(&[
                profile_code(profile),
                circuit_code(circuit),
                u8::try_from(layer_index).map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
                0,
            ]);
            prelude_message.extend_from_slice(
                &u16::try_from(proof_index)
                    .map_err(|_| SemanticH4BridgeGkrError::Transcript)?
                    .to_be_bytes(),
            );
            let (descriptor, policy, message) = make_round(
                SEMANTIC_H4_BRIDGE_LAYER_KIND,
                2,
                StrictPqFp16PolicyV2::Nonzero,
                prelude_message,
            )?;
            let prelude = next_round.borrow_mut()(descriptor, policy, &message, 2)?;
            let claim_mix = prelude[0];
            let sumcheck_rho = prelude[1];

            let mut power = Fp16::ONE;
            let effective = incoming
                .iter()
                .zip(&raw_values)
                .map(|(claim, value)| {
                    let coefficient = power;
                    power = power * claim_mix;
                    LayerOutputClaim {
                        point: claim.point.clone(),
                        value: *value,
                        coefficient,
                    }
                })
                .collect::<Vec<_>>();
            let prior = if incoming.iter().all(|claim| claim.mask_layer.is_none()) {
                LibraPriorLayerCorrection::zero()
            } else {
                let indexed = incoming
                    .iter()
                    .zip(&effective)
                    .map(|(claim, effective)| {
                        Ok::<_, SemanticH4BridgeGkrError>((
                            claim.mask_layer.ok_or(SemanticH4BridgeGkrError::Schedule)?,
                            effective.coefficient,
                            effective.point.clone(),
                        ))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                LibraPriorLayerCorrection::from_indexed_claims(&layer_masks, &indexed)
                    .map_err(|_| SemanticH4BridgeGkrError::Algebra)?
            };
            let (left, right, group_oracle): (
                &[Fp16],
                &[Fp16],
                Option<&mut dyn MaskedSharedGroupOracle>,
            ) = match (&mut source_provider, computed_rows.as_ref()) {
                (BridgeProducerSource::Uniform(values), Some(all_values)) => {
                    let source = &values[circuit_index];
                    let left = match layer.left_source {
                        KeccakDagSource::RoundInput => source.as_slice(),
                        KeccakDagSource::Layer(index) => all_values
                            .get(index)
                            .ok_or(SemanticH4BridgeGkrError::Schedule)?
                            .as_slice(),
                    };
                    let right = match layer.right_source {
                        KeccakDagSource::RoundInput => source.as_slice(),
                        KeccakDagSource::Layer(index) => all_values
                            .get(index)
                            .ok_or(SemanticH4BridgeGkrError::Schedule)?
                            .as_slice(),
                    };
                    (left, right, None)
                }
                (BridgeProducerSource::Nonuniform(oracle), None) => {
                    oracle.begin_layer(circuit, layer_index, layer, &effective)?;
                    (&[][..], &[][..], Some(&mut **oracle))
                }
                _ => return Err(SemanticH4BridgeGkrError::Shape),
            };
            let left_variables = layer.left_width.trailing_zeros() as usize;
            let right_variables = layer.right_width.trailing_zeros() as usize;
            let terminal_round_index = usize::from(group_log) + left_variables + right_variables;

            let reduction = prove_masked_shared_group_dag_layer_interactive_internal(
                layer,
                1usize << group_log,
                left,
                right,
                group_oracle,
                &effective,
                &prior,
                &sumcheck_masks[proof_index],
                &layer_masks[proof_index],
                sumcheck_rho,
                |kind, round_index, published| {
                    let mut round_message =
                        b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/SUMCHECK/v1\0".to_vec();
                    round_message.extend_from_slice(context_commitment.as_bytes());
                    let published_round_index = match kind {
                        SharedGroupDagRoundKind::Group => round_index,
                        SharedGroupDagRoundKind::LeftWire => usize::from(group_log) + round_index,
                        SharedGroupDagRoundKind::RightWire => {
                            usize::from(group_log) + left_variables + round_index
                        }
                    };
                    round_message.extend_from_slice(&[
                        profile_code(profile),
                        circuit_code(circuit),
                        u8::try_from(layer_index).map_err(|_| GkrZkMaskError::Sequence)?,
                        u8::try_from(published_round_index)
                            .map_err(|_| GkrZkMaskError::Sequence)?,
                    ]);
                    round_message.extend_from_slice(
                        &u16::try_from(published.len())
                            .map_err(|_| GkrZkMaskError::Sequence)?
                            .to_be_bytes(),
                    );
                    for value in published {
                        round_message.extend_from_slice(&value.encode());
                    }
                    let descriptor = StrictPqRoundDescriptorV2::new(
                        SEMANTIC_H4_BRIDGE_SUMCHECK_KIND,
                        ordinal.get(),
                        1,
                    )
                    .map_err(|_| GkrZkMaskError::Sequence)?;
                    ordinal.set(
                        ordinal
                            .get()
                            .checked_add(1)
                            .ok_or(GkrZkMaskError::Sequence)?,
                    );
                    let result = next_round.borrow_mut()(
                        descriptor,
                        StrictPqFp16PolicyV2::NonzeroNonone,
                        &round_message,
                        1,
                    )
                    .map_err(|_| GkrZkMaskError::Sequence)?;
                    result.first().copied().ok_or(GkrZkMaskError::Sequence)
                },
                |published, terminal_left, terminal_right| {
                    let mut round_message =
                        b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/SUMCHECK/v1\0".to_vec();
                    round_message.extend_from_slice(context_commitment.as_bytes());
                    round_message.extend_from_slice(&[
                        profile_code(profile),
                        circuit_code(circuit),
                        u8::try_from(layer_index).map_err(|_| GkrZkMaskError::Sequence)?,
                        u8::try_from(terminal_round_index).map_err(|_| GkrZkMaskError::Sequence)?,
                    ]);
                    round_message.extend_from_slice(
                        &u16::try_from(published.len())
                            .map_err(|_| GkrZkMaskError::Sequence)?
                            .to_be_bytes(),
                    );
                    for value in published {
                        round_message.extend_from_slice(&value.encode());
                    }
                    round_message.extend_from_slice(&terminal_left.encode());
                    round_message.extend_from_slice(&terminal_right.encode());
                    let descriptor = StrictPqRoundDescriptorV2::new(
                        SEMANTIC_H4_BRIDGE_SUMCHECK_KIND,
                        ordinal.get(),
                        1,
                    )
                    .map_err(|_| GkrZkMaskError::Sequence)?;
                    ordinal.set(
                        ordinal
                            .get()
                            .checked_add(1)
                            .ok_or(GkrZkMaskError::Sequence)?,
                    );
                    let result = next_round.borrow_mut()(
                        descriptor,
                        StrictPqFp16PolicyV2::NonzeroNonone,
                        &round_message,
                        1,
                    )
                    .map_err(|_| GkrZkMaskError::Sequence)?;
                    result.first().copied().ok_or(GkrZkMaskError::Sequence)
                },
            )
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;

            let outgoing = [
                (
                    layer.left_source,
                    reduction.raw_terminal_left,
                    reduction.masked_terminal_left,
                    reduction.wire_challenges[..left_variables]
                        .iter()
                        .chain(&reduction.group_challenges)
                        .copied()
                        .collect::<Vec<_>>(),
                ),
                (
                    layer.right_source,
                    reduction.raw_terminal_right,
                    reduction.masked_terminal_right,
                    reduction.wire_challenges[left_variables..]
                        .iter()
                        .chain(&reduction.group_challenges)
                        .copied()
                        .collect::<Vec<_>>(),
                ),
            ];
            for (source_kind, raw, masked, point) in outgoing {
                let claim = PublicMaskedBridgeClaim {
                    point,
                    masked_value: masked,
                    mask_layer: Some(proof_index),
                };
                match source_kind {
                    KeccakDagSource::Layer(index) if index < layer_index => {
                        pending_masked[index + 1].push(claim);
                        pending_raw[index + 1].push(raw);
                    }
                    KeccakDagSource::RoundInput => {
                        let _ = claim;
                    }
                    _ => return Err(SemanticH4BridgeGkrError::Schedule),
                }
            }
            public_layers.push(PublicMaskedBridgeLayerProof {
                circuit,
                layer: layer_index,
                published_rounds: reduction.published_rounds,
                masked_terminal_left: reduction.masked_terminal_left,
                masked_terminal_right: reduction.masked_terminal_right,
            });
            layer_challenges.push(SemanticH4BridgeLayerChallenges {
                claim_mix,
                sumcheck_rho,
                group_challenges: reduction.group_challenges,
                wire_challenges: reduction.wire_challenges,
                w_challenge: reduction.w_challenge,
            });
            proof_index += 1;
        }
        if pending_masked
            .iter()
            .skip(1)
            .any(|claims| !claims.is_empty())
            || pending_raw.iter().skip(1).any(|claims| !claims.is_empty())
        {
            return Err(SemanticH4BridgeGkrError::Schedule);
        }
    }
    if proof_index != plans.len() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let expected_rounds = semantic_h4_bridge_strict_rounds(
        &PublicMaskedSemanticH4BridgeGkrProof {
            profile,
            layers: public_layers.clone(),
        },
        context_commitment,
        first_ordinal,
    )?;
    if expected_rounds.len() != strict_outputs.len()
        || expected_rounds
            .iter()
            .zip(&strict_outputs)
            .any(|(round, output)| output.len() != usize::from(round.descriptor.output_count()))
    {
        return Err(SemanticH4BridgeGkrError::Transcript);
    }
    Ok((
        PublicMaskedSemanticH4BridgeGkrProof {
            profile,
            layers: public_layers,
        },
        SemanticH4BridgePublicChallenges {
            output_points,
            layers: layer_challenges,
        },
    ))
}

fn circuit_index(circuit: SemanticH4BridgeCircuit) -> usize {
    match circuit {
        SemanticH4BridgeCircuit::Rate => 0,
        SemanticH4BridgeCircuit::Inactive => 1,
        SemanticH4BridgeCircuit::Capacity => 2,
        SemanticH4BridgeCircuit::Digest => 3,
    }
}

fn circuit_layers(
    topologies: &SemanticH4BridgeTopologies,
    circuit: SemanticH4BridgeCircuit,
) -> &[KeccakDagLayer] {
    match circuit {
        SemanticH4BridgeCircuit::Rate => &topologies.rate,
        SemanticH4BridgeCircuit::Inactive => &topologies.inactive,
        SemanticH4BridgeCircuit::Capacity => &topologies.capacity,
        SemanticH4BridgeCircuit::Digest => &topologies.digest,
    }
}

fn circuit_group_log(profile: SemanticH4BridgeProfile, circuit: SemanticH4BridgeCircuit) -> u8 {
    match circuit {
        SemanticH4BridgeCircuit::Rate => profile.rate_group_log(),
        SemanticH4BridgeCircuit::Inactive | SemanticH4BridgeCircuit::Capacity => {
            BRIDGE_BLOCK_GROUP_LOG
        }
        SemanticH4BridgeCircuit::Digest => BRIDGE_DIGEST_GROUP_LOG,
    }
}

pub(crate) fn verify_public_masked_semantic_h4_bridge_gkr(
    proof: &PublicMaskedSemanticH4BridgeGkrProof,
    challenges: &SemanticH4BridgePublicChallenges,
) -> Result<VerifiedMaskedSemanticH4BridgeGkr, SemanticH4BridgeGkrError> {
    if proof.layers.len() != challenges.layers.len() {
        return Err(SemanticH4BridgeGkrError::Schedule);
    }
    let topologies = semantic_h4_bridge_topologies();
    let plans = semantic_h4_bridge_layer_plans(proof.profile);
    let degrees = semantic_h4_bridge_mask_variable_degrees(proof.profile);
    if proof.layers.len() != plans.len() || degrees.len() != plans.len() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }

    let mut source_claims = Vec::new();
    let mut source_circuits = Vec::new();
    let mut constraints = Vec::with_capacity(2 * plans.len());
    let mut proof_index = 0_usize;
    for circuit in [
        SemanticH4BridgeCircuit::Rate,
        SemanticH4BridgeCircuit::Inactive,
        SemanticH4BridgeCircuit::Capacity,
        SemanticH4BridgeCircuit::Digest,
    ] {
        let layers = circuit_layers(&topologies, circuit);
        let group_log = circuit_group_log(proof.profile, circuit);
        let group_count = 1_usize << group_log;
        let output_point = challenges.output_points[circuit_index(circuit)].clone();
        let output_variables = layers
            .last()
            .ok_or(SemanticH4BridgeGkrError::Shape)?
            .padded_width
            .trailing_zeros() as usize;
        if output_point.len() != output_variables + usize::from(group_log) {
            return Err(SemanticH4BridgeGkrError::Shape);
        }
        let mut pending = vec![Vec::<PublicMaskedBridgeClaim>::new(); layers.len() + 1];
        pending[layers.len()].push(PublicMaskedBridgeClaim {
            point: output_point,
            masked_value: Fp16::ZERO,
            mask_layer: None,
        });

        for layer_index in (0..layers.len()).rev() {
            let plan = plans
                .get(proof_index)
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            let layer_proof = proof
                .layers
                .get(proof_index)
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            let layer_challenges = challenges
                .layers
                .get(proof_index)
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            let topology = &layers[layer_index];
            if plan.circuit != circuit
                || plan.layer != layer_index
                || plan.group_log != group_log
                || plan.topology != *topology
                || layer_proof.circuit != circuit
                || layer_proof.layer != layer_index
                || layer_challenges.claim_mix.is_zero()
                || layer_challenges.sumcheck_rho.is_zero()
            {
                return Err(SemanticH4BridgeGkrError::Schedule);
            }
            let incoming = core::mem::take(&mut pending[layer_index + 1]);
            if incoming.is_empty() || incoming.len() > 8 {
                return Err(SemanticH4BridgeGkrError::Shape);
            }
            let mut power = Fp16::ONE;
            let effective = incoming
                .iter()
                .map(|claim| {
                    let coefficient = power;
                    power = power * layer_challenges.claim_mix;
                    LayerOutputClaim {
                        point: claim.point.clone(),
                        value: Fp16::ZERO,
                        coefficient,
                    }
                })
                .collect::<Vec<_>>();
            let left_variables = topology.left_width.trailing_zeros() as usize;
            let right_variables = topology.right_width.trailing_zeros() as usize;
            let ordinary_rounds = usize::from(group_log) + left_variables + right_variables;
            let expected_degrees = degrees
                .get(proof_index)
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            if expected_degrees.len() != ordinary_rounds + 1
                || layer_proof.published_rounds.len() != expected_degrees.len()
                || layer_challenges.group_challenges.len() != usize::from(group_log)
                || layer_challenges.wire_challenges.len() != left_variables + right_variables
                || layer_proof
                    .published_rounds
                    .iter()
                    .zip(expected_degrees)
                    .any(|(round, degree)| round.len() != degree + 1)
            {
                return Err(SemanticH4BridgeGkrError::Shape);
            }
            for round in 1..layer_proof.published_rounds.len() {
                let previous_challenge = if round <= usize::from(group_log) {
                    layer_challenges.group_challenges[round - 1]
                } else if round <= usize::from(group_log) + left_variables + right_variables {
                    layer_challenges.wire_challenges[round - 1 - usize::from(group_log)]
                } else {
                    return Err(SemanticH4BridgeGkrError::Shape);
                };
                let previous = &layer_proof.published_rounds[round - 1];
                let current = &layer_proof.published_rounds[round];
                if polynomial_evaluation(current, Fp16::ZERO)
                    + polynomial_evaluation(current, Fp16::ONE)
                    != polynomial_evaluation(previous, previous_challenge)
                {
                    return Err(SemanticH4BridgeGkrError::Algebra);
                }
            }

            let first = layer_proof
                .published_rounds
                .first()
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            let masked_initial = incoming
                .iter()
                .zip(&effective)
                .fold(Fp16::ZERO, |sum, (claim, effective)| {
                    sum + effective.coefficient * claim.masked_value
                });
            constraints.push(UniformGkrMaskConstraint {
                functionals: vec![UniformGkrMaskFunctional::SumcheckBooleanSum {
                    layer: proof_index,
                    scale: layer_challenges.sumcheck_rho,
                }],
                residual: polynomial_evaluation(first, Fp16::ZERO)
                    + polynomial_evaluation(first, Fp16::ONE)
                    - masked_initial,
            });

            let terminal_gate = shared_group_terminal_gate_claim(
                topology,
                group_count,
                &effective,
                &layer_challenges.group_challenges,
                &layer_challenges.wire_challenges,
                layer_proof.masked_terminal_left,
                layer_proof.masked_terminal_right,
            )
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
            let last = layer_proof
                .published_rounds
                .last()
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            let mut xy_point = layer_challenges.group_challenges.clone();
            xy_point.extend_from_slice(&layer_challenges.wire_challenges);
            let equality_zero = xy_point.iter().fold(Fp16::ONE, |value, coordinate| {
                value * (Fp16::ONE - *coordinate)
            });
            let mut full_point = xy_point;
            full_point.push(layer_challenges.w_challenge);
            let mut functionals = vec![UniformGkrMaskFunctional::SumcheckEvaluation {
                layer: proof_index,
                point: full_point,
                scale: layer_challenges.sumcheck_rho,
            }];
            for (claim, effective) in incoming.iter().zip(&effective) {
                if let Some(origin) = claim.mask_layer {
                    functionals.push(UniformGkrMaskFunctional::LayerEvaluation {
                        layer: origin,
                        z_first: *claim.point.first().ok_or(SemanticH4BridgeGkrError::Shape)?,
                        w: layer_challenges.w_challenge,
                        scale: equality_zero
                            * effective.coefficient
                            * boolean_vanishing(&claim.point),
                    });
                }
            }
            constraints.push(UniformGkrMaskConstraint {
                functionals,
                residual: polynomial_evaluation(last, layer_challenges.w_challenge)
                    - (Fp16::ONE - layer_challenges.w_challenge) * terminal_gate,
            });

            let points = [
                layer_challenges.wire_challenges[..left_variables]
                    .iter()
                    .chain(&layer_challenges.group_challenges)
                    .copied()
                    .collect::<Vec<_>>(),
                layer_challenges.wire_challenges[left_variables..]
                    .iter()
                    .chain(&layer_challenges.group_challenges)
                    .copied()
                    .collect::<Vec<_>>(),
            ];
            for (source, point, masked_value) in [
                (
                    topology.left_source,
                    points[0].clone(),
                    layer_proof.masked_terminal_left,
                ),
                (
                    topology.right_source,
                    points[1].clone(),
                    layer_proof.masked_terminal_right,
                ),
            ] {
                let outgoing = PublicMaskedBridgeClaim {
                    point,
                    masked_value,
                    mask_layer: Some(proof_index),
                };
                match source {
                    KeccakDagSource::Layer(index) if index < layer_index => {
                        pending[index + 1].push(outgoing)
                    }
                    KeccakDagSource::RoundInput => {
                        source_claims.push(outgoing);
                        source_circuits.push(circuit);
                    }
                    _ => return Err(SemanticH4BridgeGkrError::Schedule),
                }
            }
            proof_index += 1;
        }
        if pending.iter().any(|claims| !claims.is_empty()) {
            return Err(SemanticH4BridgeGkrError::Schedule);
        }
    }
    if proof_index != plans.len() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    Ok(VerifiedMaskedSemanticH4BridgeGkr {
        profile: proof.profile,
        source_claims,
        source_circuits,
        mask_constraints: constraints,
    })
}

fn profile_code(profile: SemanticH4BridgeProfile) -> u8 {
    match profile {
        SemanticH4BridgeProfile::K128 => 1,
        SemanticH4BridgeProfile::K512 => 3,
    }
}

fn circuit_code(circuit: SemanticH4BridgeCircuit) -> u8 {
    match circuit {
        SemanticH4BridgeCircuit::Rate => 0,
        SemanticH4BridgeCircuit::Inactive => 1,
        SemanticH4BridgeCircuit::Capacity => 2,
        SemanticH4BridgeCircuit::Digest => 3,
    }
}

fn append_field(encoded: &mut Vec<u8>, value: Fp16) {
    encoded.extend_from_slice(&value.encode());
}

pub fn encode_public_masked_semantic_h4_bridge_gkr(
    proof: &PublicMaskedSemanticH4BridgeGkrProof,
) -> Result<Vec<u8>, SemanticH4BridgeGkrError> {
    let plans = semantic_h4_bridge_layer_plans(proof.profile);
    let degrees = semantic_h4_bridge_mask_variable_degrees(proof.profile);
    if proof.layers.len() != plans.len() || proof.layers.len() != degrees.len() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(SEMANTIC_H4_BRIDGE_GKR_MAGIC);
    encoded.extend_from_slice(&SEMANTIC_H4_BRIDGE_GKR_VERSION.to_be_bytes());
    encoded.push(profile_code(proof.profile));
    encoded.extend_from_slice(&[0_u8; 5]);
    encoded.extend_from_slice(
        &u16::try_from(proof.layers.len())
            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
            .to_be_bytes(),
    );
    for ((layer, plan), expected_degrees) in proof.layers.iter().zip(&plans).zip(&degrees) {
        if layer.circuit != plan.circuit
            || layer.layer != plan.layer
            || layer.published_rounds.len() != expected_degrees.len()
        {
            return Err(SemanticH4BridgeGkrError::Shape);
        }
        encoded.push(circuit_code(layer.circuit));
        encoded.push(u8::try_from(layer.layer).map_err(|_| SemanticH4BridgeGkrError::Encoding)?);
        encoded.push(
            u8::try_from(layer.published_rounds.len())
                .map_err(|_| SemanticH4BridgeGkrError::Encoding)?,
        );
        encoded.push(0);
        for (round, degree) in layer.published_rounds.iter().zip(expected_degrees) {
            if round.len() != degree + 1 {
                return Err(SemanticH4BridgeGkrError::Shape);
            }
            for value in round {
                append_field(&mut encoded, *value);
            }
        }
        append_field(&mut encoded, layer.masked_terminal_left);
        append_field(&mut encoded, layer.masked_terminal_right);
    }
    if encoded.len() > MAX_SEMANTIC_H4_BRIDGE_GKR_BYTES {
        return Err(SemanticH4BridgeGkrError::Encoding);
    }
    Ok(encoded)
}

struct BridgeReader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> BridgeReader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], SemanticH4BridgeGkrError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(SemanticH4BridgeGkrError::Encoding)?;
        let result = self
            .encoded
            .get(self.offset..end)
            .ok_or(SemanticH4BridgeGkrError::Encoding)?;
        self.offset = end;
        Ok(result)
    }

    fn field(&mut self) -> Result<Fp16, SemanticH4BridgeGkrError> {
        Fp16::decode(self.take(64)?).map_err(|_| SemanticH4BridgeGkrError::Encoding)
    }
}

pub fn decode_public_masked_semantic_h4_bridge_gkr(
    encoded: &[u8],
) -> Result<PublicMaskedSemanticH4BridgeGkrProof, SemanticH4BridgeGkrError> {
    if encoded.len() > MAX_SEMANTIC_H4_BRIDGE_GKR_BYTES {
        return Err(SemanticH4BridgeGkrError::Encoding);
    }
    let mut reader = BridgeReader { encoded, offset: 0 };
    if reader.take(8)? != SEMANTIC_H4_BRIDGE_GKR_MAGIC
        || reader.take(2)? != SEMANTIC_H4_BRIDGE_GKR_VERSION.to_be_bytes()
    {
        return Err(SemanticH4BridgeGkrError::Encoding);
    }
    let profile = match reader.take(1)?[0] {
        1 => SemanticH4BridgeProfile::K128,
        3 => SemanticH4BridgeProfile::K512,
        _ => return Err(SemanticH4BridgeGkrError::Encoding),
    };
    if reader.take(5)? != [0_u8; 5] {
        return Err(SemanticH4BridgeGkrError::Encoding);
    }
    let layer_count = usize::from(u16::from_be_bytes(
        reader
            .take(2)?
            .try_into()
            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?,
    ));
    let plans = semantic_h4_bridge_layer_plans(profile);
    let degrees = semantic_h4_bridge_mask_variable_degrees(profile);
    if layer_count != plans.len() || layer_count != degrees.len() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut layers = Vec::with_capacity(layer_count);
    for (plan, expected_degrees) in plans.iter().zip(&degrees) {
        let header = reader.take(4)?;
        if header[0] != circuit_code(plan.circuit)
            || usize::from(header[1]) != plan.layer
            || usize::from(header[2]) != expected_degrees.len()
            || header[3] != 0
        {
            return Err(SemanticH4BridgeGkrError::Shape);
        }
        let mut published_rounds = Vec::with_capacity(expected_degrees.len());
        for degree in expected_degrees {
            let mut round = Vec::with_capacity(degree + 1);
            for _ in 0..=*degree {
                round.push(reader.field()?);
            }
            published_rounds.push(round);
        }
        layers.push(PublicMaskedBridgeLayerProof {
            circuit: plan.circuit,
            layer: plan.layer,
            published_rounds,
            masked_terminal_left: reader.field()?,
            masked_terminal_right: reader.field()?,
        });
    }
    if reader.offset != encoded.len() {
        return Err(SemanticH4BridgeGkrError::Encoding);
    }
    Ok(PublicMaskedSemanticH4BridgeGkrProof { profile, layers })
}

pub fn semantic_h4_bridge_response_commitment(
    proof: &PublicMaskedSemanticH4BridgeGkrProof,
) -> Result<BindingDigestV2, SemanticH4BridgeGkrError> {
    Ok(BindingDigestV2::hash(
        BindingRoleV2::Payload,
        &encode_public_masked_semantic_h4_bridge_gkr(proof)?,
    )?)
}

pub fn semantic_h4_bridge_claim_vector_commitment(
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
) -> Result<BindingDigestV2, SemanticH4BridgeGkrError> {
    if verified.source_claims.len() != verified.source_circuits.len() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut encoded = b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE-CLAIMS/v1\0".to_vec();
    encoded.extend_from_slice(
        &u32::try_from(verified.source_claims.len())
            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
            .to_be_bytes(),
    );
    for (claim, circuit) in verified.source_claims.iter().zip(&verified.source_circuits) {
        encoded.push(circuit_code(*circuit));
        encoded.extend_from_slice(
            &u16::try_from(claim.point.len())
                .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
                .to_be_bytes(),
        );
        for coordinate in &claim.point {
            append_field(&mut encoded, *coordinate);
        }
        append_field(&mut encoded, claim.masked_value);
        encoded.extend_from_slice(
            &u16::try_from(claim.mask_layer.ok_or(SemanticH4BridgeGkrError::Shape)?)
                .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
                .to_be_bytes(),
        );
    }
    encoded.extend_from_slice(
        &u32::try_from(verified.mask_constraints.len())
            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
            .to_be_bytes(),
    );
    for constraint in &verified.mask_constraints {
        append_field(&mut encoded, constraint.residual);
        encoded.extend_from_slice(
            &u16::try_from(constraint.functionals.len())
                .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
                .to_be_bytes(),
        );
        for functional in &constraint.functionals {
            match functional {
                UniformGkrMaskFunctional::BridgeEvaluation {
                    layer,
                    point,
                    scale,
                } => {
                    encoded.push(0);
                    encoded.extend_from_slice(
                        &u16::try_from(*layer)
                            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
                            .to_be_bytes(),
                    );
                    append_field(&mut encoded, *point);
                    append_field(&mut encoded, *scale);
                }
                UniformGkrMaskFunctional::SumcheckBooleanSum { layer, scale } => {
                    encoded.push(1);
                    encoded.extend_from_slice(
                        &u16::try_from(*layer)
                            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
                            .to_be_bytes(),
                    );
                    append_field(&mut encoded, *scale);
                }
                UniformGkrMaskFunctional::SumcheckEvaluation {
                    layer,
                    point,
                    scale,
                } => {
                    encoded.push(2);
                    encoded.extend_from_slice(
                        &u16::try_from(*layer)
                            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
                            .to_be_bytes(),
                    );
                    encoded.extend_from_slice(
                        &u16::try_from(point.len())
                            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
                            .to_be_bytes(),
                    );
                    for coordinate in point {
                        append_field(&mut encoded, *coordinate);
                    }
                    append_field(&mut encoded, *scale);
                }
                UniformGkrMaskFunctional::LayerEvaluation {
                    layer,
                    z_first,
                    w,
                    scale,
                } => {
                    encoded.push(3);
                    encoded.extend_from_slice(
                        &u16::try_from(*layer)
                            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
                            .to_be_bytes(),
                    );
                    append_field(&mut encoded, *z_first);
                    append_field(&mut encoded, *w);
                    append_field(&mut encoded, *scale);
                }
                UniformGkrMaskFunctional::LayerBooleanSum {
                    layer,
                    z_first,
                    scale,
                } => {
                    encoded.push(4);
                    encoded.extend_from_slice(
                        &u16::try_from(*layer)
                            .map_err(|_| SemanticH4BridgeGkrError::Encoding)?
                            .to_be_bytes(),
                    );
                    append_field(&mut encoded, *z_first);
                    append_field(&mut encoded, *scale);
                }
            }
        }
    }
    Ok(BindingDigestV2::hash(BindingRoleV2::Payload, &encoded)?)
}

pub(crate) fn verify_semantic_h4_bridge_mask_batch(
    profile: SemanticH4BridgeProfile,
    verified: &VerifiedMaskedSemanticH4BridgeGkr,
    challenge: Fp16,
    authenticated: AuthenticatedSemanticH4BridgeMaskOpening,
) -> Result<VerifiedSemanticH4BridgeMaskBatch, SemanticH4BridgeGkrError> {
    let layout =
        semantic_h4_bridge_mask_layout(profile).map_err(|_| SemanticH4BridgeGkrError::Shape)?;
    let (coefficient_weights, opening) =
        aggregate_gkr_mask_constraints(&layout, &verified.mask_constraints, challenge)
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
    if authenticated
        .mask_root
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
        || authenticated.coefficient_weights != coefficient_weights
        || authenticated.opening != opening
    {
        return Err(SemanticH4BridgeGkrError::Algebra);
    }
    Ok(VerifiedSemanticH4BridgeMaskBatch {
        mask_root: authenticated.mask_root,
        challenge,
        coefficient_weights,
        opening,
        source_batch_binding: None,
    })
}

pub(crate) fn verify_bridge_inner_product(
    proof: &PublicBridgeInnerProductProof,
    public_weights: &[Fp16],
    claimed_inner_product: Fp16,
    challenges: &[Fp16],
    authenticated: AuthenticatedBridgeMleOpening,
) -> Result<VerifiedBridgeInnerProduct, SemanticH4BridgeGkrError> {
    if public_weights.is_empty()
        || !public_weights.len().is_power_of_two()
        || proof.rounds.len() != public_weights.len().ilog2() as usize
        || challenges.len() != proof.rounds.len()
        || authenticated.point != challenges
        || authenticated.root.as_bytes().iter().all(|byte| *byte == 0)
    {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut current = claimed_inner_product;
    for (round, challenge) in proof.rounds.iter().zip(challenges) {
        if round[0] + round[0] + round[1] + round[2] != current {
            return Err(SemanticH4BridgeGkrError::Algebra);
        }
        current = round[0] + *challenge * (round[1] + *challenge * round[2]);
    }
    let mut folded = public_weights.to_vec();
    let mut active = folded.len();
    for challenge in challenges {
        for index in 0..active / 2 {
            folded[index] =
                folded[2 * index] * (Fp16::ONE - *challenge) + folded[2 * index + 1] * *challenge;
        }
        active /= 2;
    }
    if current != authenticated.value * folded[0] {
        return Err(SemanticH4BridgeGkrError::Algebra);
    }
    Ok(VerifiedBridgeInnerProduct {
        root: authenticated.root,
        point: authenticated.point,
        value: authenticated.value,
    })
}

/// Construct the standard degree-two product-sumcheck messages. Challenges
/// are supplied by the strict transcript; this helper never samples them.
pub fn prove_bridge_inner_product(
    mut private_values: Vec<Fp16>,
    mut public_weights: Vec<Fp16>,
    challenges: &[Fp16],
) -> Result<(PublicBridgeInnerProductProof, Fp16), SemanticH4BridgeGkrError> {
    if private_values.is_empty()
        || !private_values.len().is_power_of_two()
        || private_values.len() != public_weights.len()
        || challenges.len() != private_values.len().ilog2() as usize
    {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let claimed = private_values
        .iter()
        .zip(&public_weights)
        .fold(Fp16::ZERO, |sum, (left, right)| sum + *left * *right);
    let mut rounds = Vec::with_capacity(challenges.len());
    let mut active = private_values.len();
    for challenge in challenges {
        let mut round = [Fp16::ZERO; 3];
        for index in 0..active / 2 {
            let left_zero = private_values[2 * index];
            let left_delta = private_values[2 * index + 1] - left_zero;
            let right_zero = public_weights[2 * index];
            let right_delta = public_weights[2 * index + 1] - right_zero;
            round[0] = round[0] + left_zero * right_zero;
            round[1] = round[1] + left_zero * right_delta + left_delta * right_zero;
            round[2] = round[2] + left_delta * right_delta;
            private_values[index] = left_zero + *challenge * left_delta;
            public_weights[index] = right_zero + *challenge * right_delta;
        }
        active /= 2;
        rounds.push(round);
    }
    Ok((PublicBridgeInnerProductProof { rounds }, claimed))
}

/// Authenticate the bridge mask batch all the way to a native-128 committed
/// coefficient vector.  This is the production constructor for the otherwise
/// opaque multilinear terminal used by [`verify_bridge_inner_product`].
#[allow(clippy::too_many_arguments)]
pub fn verify_semantic_h4_bridge_mask_batch_with_pcs(
    profile: SemanticH4BridgeProfile,
    verified_gkr: &VerifiedMaskedSemanticH4BridgeGkr,
    batch_challenge: Fp16,
    inner_product_proof: &PublicBridgeInnerProductProof,
    inner_product_challenges: &[Fp16],
    pcs_proof: &BindingMultilinearPcsProofV2,
    expected_mask_root: BindingRootV2,
    expected_context: BindingDigestV2,
    completion_coin: BindingDigestV2,
) -> Result<
    (
        VerifiedSemanticH4BridgeMaskBatch,
        VerifiedBridgeInnerProduct,
    ),
    SemanticH4BridgeGkrError,
> {
    let layout =
        semantic_h4_bridge_mask_layout(profile).map_err(|_| SemanticH4BridgeGkrError::Shape)?;
    let (coefficient_weights, opening) =
        aggregate_gkr_mask_constraints(&layout, &verified_gkr.mask_constraints, batch_challenge)
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
    if coefficient_weights.len() != layout.padded_coefficients {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let terminal_value = inner_product_proof
        .rounds
        .iter()
        .zip(inner_product_challenges)
        .try_fold(opening, |current, (round, challenge)| {
            if round[0] + round[0] + round[1] + round[2] != current {
                return Err(SemanticH4BridgeGkrError::Algebra);
            }
            Ok(round[0] + *challenge * (round[1] + *challenge * round[2]))
        })?;
    let mut folded_weights = coefficient_weights.clone();
    let mut active = folded_weights.len();
    for challenge in inner_product_challenges {
        for index in 0..active / 2 {
            folded_weights[index] = folded_weights[2 * index] * (Fp16::ONE - *challenge)
                + folded_weights[2 * index + 1] * *challenge;
        }
        active /= 2;
    }
    if active != 1 || folded_weights[0].is_zero() {
        return Err(SemanticH4BridgeGkrError::Algebra);
    }
    let claimed_mle = terminal_value
        * folded_weights[0]
            .inverse()
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
    let pcs = verify_binding_multilinear_opening_v2(
        pcs_proof,
        expected_mask_root,
        inner_product_challenges,
        claimed_mle,
        expected_context,
        completion_coin,
    )
    .map_err(|_| SemanticH4BridgeGkrError::Binding)?;
    let authenticated = AuthenticatedBridgeMleOpening {
        root: pcs.root(),
        point: pcs.point().to_vec(),
        value: pcs.value(),
    };
    let inner = verify_bridge_inner_product(
        inner_product_proof,
        &coefficient_weights,
        opening,
        inner_product_challenges,
        authenticated,
    )?;
    Ok((
        VerifiedSemanticH4BridgeMaskBatch {
            mask_root: BindingDigestV2::hash(BindingRoleV2::Payload, expected_mask_root.as_bytes())
                .map_err(|_| SemanticH4BridgeGkrError::Binding)?,
            challenge: batch_challenge,
            coefficient_weights,
            opening,
            source_batch_binding: None,
        },
        inner,
    ))
}

/// Acceptance-path variant: the mask batch must include the raw source
/// equations produced by [`bind_semantic_h4_bridge_raw_sources`].
#[allow(clippy::too_many_arguments)]
pub fn verify_semantic_h4_bridge_source_mask_batch_with_pcs(
    profile: SemanticH4BridgeProfile,
    verified_gkr: &VerifiedMaskedSemanticH4BridgeGkr,
    source_binding: &VerifiedSemanticH4BridgeSourceBinding,
    batch_challenge: Fp16,
    inner_product_proof: &PublicBridgeInnerProductProof,
    inner_product_challenges: &[Fp16],
    pcs_proof: &BindingMultilinearPcsProofV2,
    expected_mask_root: BindingRootV2,
    expected_context: BindingDigestV2,
    completion_coin: BindingDigestV2,
) -> Result<
    (
        VerifiedSemanticH4BridgeMaskBatch,
        VerifiedBridgeInnerProduct,
    ),
    SemanticH4BridgeGkrError,
> {
    if profile != verified_gkr.profile
        || source_binding.source_claim_count != verified_gkr.source_claims.len()
        || source_binding.mask_constraints.len() <= verified_gkr.mask_constraints.len()
    {
        return Err(SemanticH4BridgeGkrError::Binding);
    }
    let complete = VerifiedMaskedSemanticH4BridgeGkr {
        profile,
        source_claims: verified_gkr.source_claims.clone(),
        source_circuits: verified_gkr.source_circuits.clone(),
        mask_constraints: source_binding.mask_constraints.clone(),
    };
    let (mut batch, inner) = verify_semantic_h4_bridge_mask_batch_with_pcs(
        profile,
        &complete,
        batch_challenge,
        inner_product_proof,
        inner_product_challenges,
        pcs_proof,
        expected_mask_root,
        expected_context,
        completion_coin,
    )?;
    batch.source_batch_binding = Some(source_binding.source_batch_binding);
    Ok((batch, inner))
}

/// Complete producer output for the source-augmented bridge-mask PCS stage.
/// These fields are untrusted transport material; the accepting H4 verifier
/// still reconstructs the source constraints and replays both proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducedSemanticH4BridgeSourceMaskV3 {
    pub batch_challenge: Fp16,
    pub inner_product_proof: PublicBridgeInnerProductProof,
    pub inner_product_challenges: Vec<Fp16>,
    pub pcs_proof: BindingMultilinearPcsProofV2,
    pub expected_mask_root: BindingRootV2,
    pub expected_context: BindingDigestV2,
    pub completion_coin: BindingDigestV2,
}

/// Produce the exact mask proof consumed by complete H4-v2.
///
/// The source binding is opaque and was constructed only after per-claim
/// semantic functionals and authenticated H4 source/base responses matched the
/// bridge GKR claims. The producer derives the public coefficient weights and
/// claimed opening from that receipt, commits the supplied private coefficient
/// vector, and immediately replays the result through the accepting verifier.
#[allow(clippy::too_many_arguments)]
pub fn produce_semantic_h4_bridge_source_mask_batch_with_pcs(
    profile: SemanticH4BridgeProfile,
    verified_gkr: &VerifiedMaskedSemanticH4BridgeGkr,
    source_binding: &VerifiedSemanticH4BridgeSourceBinding,
    mask_coefficients: &[Fp16],
    batch_challenge: Fp16,
    inner_product_challenges: &[Fp16],
    expected_context: BindingDigestV2,
    completion_coin: BindingDigestV2,
) -> Result<ProducedSemanticH4BridgeSourceMaskV3, SemanticH4BridgeGkrError> {
    let layout =
        semantic_h4_bridge_mask_layout(profile).map_err(|_| SemanticH4BridgeGkrError::Shape)?;
    if profile != verified_gkr.profile
        || source_binding.source_claim_count != verified_gkr.source_claims.len()
        || source_binding.mask_constraints.len() <= verified_gkr.mask_constraints.len()
        || mask_coefficients.len() != layout.padded_coefficients
        || inner_product_challenges.len() != layout.padded_coefficients.ilog2() as usize
        || batch_challenge.is_zero()
        || expected_context.as_bytes().iter().all(|byte| *byte == 0)
        || completion_coin.as_bytes().iter().all(|byte| *byte == 0)
    {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let complete = VerifiedMaskedSemanticH4BridgeGkr {
        profile,
        source_claims: verified_gkr.source_claims.clone(),
        source_circuits: verified_gkr.source_circuits.clone(),
        mask_constraints: source_binding.mask_constraints.clone(),
    };
    let (coefficient_weights, opening) =
        aggregate_gkr_mask_constraints(&layout, &complete.mask_constraints, batch_challenge)
            .map_err(|_| SemanticH4BridgeGkrError::Algebra)?;
    let (inner_product_proof, claimed) = prove_bridge_inner_product(
        mask_coefficients.to_vec(),
        coefficient_weights,
        inner_product_challenges,
    )?;
    if claimed != opening {
        return Err(SemanticH4BridgeGkrError::Algebra);
    }
    let pcs_proof = prove_binding_multilinear_opening_v2(
        mask_coefficients,
        inner_product_challenges,
        expected_context,
        completion_coin,
    )
    .map_err(|_| SemanticH4BridgeGkrError::Binding)?;
    let expected_mask_root = pcs_proof
        .roots
        .first()
        .copied()
        .ok_or(SemanticH4BridgeGkrError::Binding)?;
    verify_semantic_h4_bridge_source_mask_batch_with_pcs(
        profile,
        verified_gkr,
        source_binding,
        batch_challenge,
        &inner_product_proof,
        inner_product_challenges,
        &pcs_proof,
        expected_mask_root,
        expected_context,
        completion_coin,
    )?;
    Ok(ProducedSemanticH4BridgeSourceMaskV3 {
        batch_challenge,
        inner_product_proof,
        inner_product_challenges: inner_product_challenges.to_vec(),
        pcs_proof,
        expected_mask_root,
        expected_context,
        completion_coin,
    })
}

fn strict_round(
    kind: u16,
    ordinal: u32,
    output_count: usize,
    policy: StrictPqFp16PolicyV2,
    message: Vec<u8>,
) -> Result<SemanticH4BridgeStrictRound, SemanticH4BridgeGkrError> {
    Ok(SemanticH4BridgeStrictRound {
        descriptor: StrictPqRoundDescriptorV2::new(
            kind,
            ordinal,
            u16::try_from(output_count).map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
        )
        .map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
        policy,
        message,
    })
}

pub fn semantic_h4_bridge_strict_rounds(
    proof: &PublicMaskedSemanticH4BridgeGkrProof,
    context_commitment: BindingDigestV2,
    first_ordinal: u32,
) -> Result<Vec<SemanticH4BridgeStrictRound>, SemanticH4BridgeGkrError> {
    let plans = semantic_h4_bridge_layer_plans(proof.profile);
    if proof.layers.len() != plans.len() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let mut ordinal = first_ordinal;
    let mut rounds = Vec::new();
    for circuit in [
        SemanticH4BridgeCircuit::Rate,
        SemanticH4BridgeCircuit::Inactive,
        SemanticH4BridgeCircuit::Capacity,
        SemanticH4BridgeCircuit::Digest,
    ] {
        let topology = semantic_h4_bridge_topologies();
        let output_variables = circuit_layers(&topology, circuit)
            .last()
            .ok_or(SemanticH4BridgeGkrError::Shape)?
            .padded_width
            .trailing_zeros() as usize;
        let output_count =
            output_variables + usize::from(circuit_group_log(proof.profile, circuit));
        let mut message = b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/OUTPUT/v1\0".to_vec();
        message.extend_from_slice(context_commitment.as_bytes());
        message.extend_from_slice(&[profile_code(proof.profile), circuit_code(circuit), 0, 0]);
        rounds.push(strict_round(
            SEMANTIC_H4_BRIDGE_OUTPUT_KIND,
            ordinal,
            output_count,
            StrictPqFp16PolicyV2::Uniform,
            message,
        )?);
        ordinal = ordinal
            .checked_add(1)
            .ok_or(SemanticH4BridgeGkrError::Transcript)?;

        for (proof_index, (layer, plan)) in proof.layers.iter().zip(&plans).enumerate() {
            if plan.circuit != circuit {
                continue;
            }
            if layer.circuit != plan.circuit || layer.layer != plan.layer {
                return Err(SemanticH4BridgeGkrError::Shape);
            }
            let mut message = b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/LAYER/v1\0".to_vec();
            message.extend_from_slice(context_commitment.as_bytes());
            message.extend_from_slice(&[
                profile_code(proof.profile),
                circuit_code(circuit),
                u8::try_from(plan.layer).map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
                0,
            ]);
            message.extend_from_slice(
                &u16::try_from(proof_index)
                    .map_err(|_| SemanticH4BridgeGkrError::Transcript)?
                    .to_be_bytes(),
            );
            rounds.push(strict_round(
                SEMANTIC_H4_BRIDGE_LAYER_KIND,
                ordinal,
                2,
                StrictPqFp16PolicyV2::Nonzero,
                message,
            )?);
            ordinal = ordinal
                .checked_add(1)
                .ok_or(SemanticH4BridgeGkrError::Transcript)?;

            for (round_index, polynomial) in layer.published_rounds.iter().enumerate() {
                let mut message = b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/SUMCHECK/v1\0".to_vec();
                message.extend_from_slice(context_commitment.as_bytes());
                message.extend_from_slice(&[
                    profile_code(proof.profile),
                    circuit_code(circuit),
                    u8::try_from(plan.layer).map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
                    u8::try_from(round_index).map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
                ]);
                message.extend_from_slice(
                    &u16::try_from(polynomial.len())
                        .map_err(|_| SemanticH4BridgeGkrError::Transcript)?
                        .to_be_bytes(),
                );
                for coefficient in polynomial {
                    append_field(&mut message, *coefficient);
                }
                if round_index + 1 == layer.published_rounds.len() {
                    append_field(&mut message, layer.masked_terminal_left);
                    append_field(&mut message, layer.masked_terminal_right);
                }
                rounds.push(strict_round(
                    SEMANTIC_H4_BRIDGE_SUMCHECK_KIND,
                    ordinal,
                    1,
                    StrictPqFp16PolicyV2::NonzeroNonone,
                    message,
                )?);
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or(SemanticH4BridgeGkrError::Transcript)?;
            }
        }
    }
    Ok(rounds)
}

pub fn semantic_h4_bridge_challenges_from_strict_outputs(
    profile: SemanticH4BridgeProfile,
    outputs: &[StrictPqFp16RoundOutputV2],
    first_ordinal: u32,
) -> Result<SemanticH4BridgePublicChallenges, SemanticH4BridgeGkrError> {
    let plans = semantic_h4_bridge_layer_plans(profile);
    let degrees = semantic_h4_bridge_mask_variable_degrees(profile);
    let mut output_points = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let mut layer_challenges = Vec::with_capacity(plans.len());
    let mut cursor = 0_usize;
    let mut ordinal = first_ordinal;
    for circuit in [
        SemanticH4BridgeCircuit::Rate,
        SemanticH4BridgeCircuit::Inactive,
        SemanticH4BridgeCircuit::Capacity,
        SemanticH4BridgeCircuit::Digest,
    ] {
        let output = outputs
            .get(cursor)
            .ok_or(SemanticH4BridgeGkrError::Transcript)?;
        let batch = output.challenges();
        let descriptor = batch.descriptor();
        if descriptor.kind() != SEMANTIC_H4_BRIDGE_OUTPUT_KIND
            || descriptor.ordinal() != ordinal
            || batch.policy() != StrictPqFp16PolicyV2::Uniform
        {
            return Err(SemanticH4BridgeGkrError::Transcript);
        }
        output_points[circuit_index(circuit)] = batch
            .samples()
            .iter()
            .map(|sample| sample.element())
            .collect();
        cursor += 1;
        ordinal += 1;

        for (proof_index, plan) in plans.iter().enumerate() {
            if plan.circuit != circuit {
                continue;
            }
            let prelude = outputs
                .get(cursor)
                .ok_or(SemanticH4BridgeGkrError::Transcript)?;
            let batch = prelude.challenges();
            let descriptor = batch.descriptor();
            if descriptor.kind() != SEMANTIC_H4_BRIDGE_LAYER_KIND
                || descriptor.ordinal() != ordinal
                || descriptor.output_count() != 2
                || batch.policy() != StrictPqFp16PolicyV2::Nonzero
                || batch.samples().len() != 2
            {
                return Err(SemanticH4BridgeGkrError::Transcript);
            }
            let claim_mix = batch.samples()[0].element();
            let sumcheck_rho = batch.samples()[1].element();
            cursor += 1;
            ordinal += 1;

            let expected_degrees = degrees
                .get(proof_index)
                .ok_or(SemanticH4BridgeGkrError::Shape)?;
            let group_count = usize::from(plan.group_log);
            let wire_count = plan.topology.left_width.trailing_zeros() as usize
                + plan.topology.right_width.trailing_zeros() as usize;
            if expected_degrees.len() != group_count + wire_count + 1 {
                return Err(SemanticH4BridgeGkrError::Shape);
            }
            let mut challenges = Vec::with_capacity(expected_degrees.len());
            for _ in expected_degrees {
                let output = outputs
                    .get(cursor)
                    .ok_or(SemanticH4BridgeGkrError::Transcript)?;
                let batch = output.challenges();
                let descriptor = batch.descriptor();
                if descriptor.kind() != SEMANTIC_H4_BRIDGE_SUMCHECK_KIND
                    || descriptor.ordinal() != ordinal
                    || descriptor.output_count() != 1
                    || batch.policy() != StrictPqFp16PolicyV2::NonzeroNonone
                    || batch.samples().len() != 1
                {
                    return Err(SemanticH4BridgeGkrError::Transcript);
                }
                challenges.push(batch.samples()[0].element());
                cursor += 1;
                ordinal += 1;
            }
            layer_challenges.push(SemanticH4BridgeLayerChallenges {
                claim_mix,
                sumcheck_rho,
                group_challenges: challenges[..group_count].to_vec(),
                wire_challenges: challenges[group_count..group_count + wire_count].to_vec(),
                w_challenge: challenges[group_count + wire_count],
            });
        }
    }
    if cursor != outputs.len() || layer_challenges.len() != plans.len() {
        return Err(SemanticH4BridgeGkrError::Transcript);
    }
    Ok(SemanticH4BridgePublicChallenges {
        output_points,
        layers: layer_challenges,
    })
}

pub fn semantic_h4_bridge_strict_schedule_commitment(
    proof: &PublicMaskedSemanticH4BridgeGkrProof,
    context_commitment: BindingDigestV2,
    first_ordinal: u32,
) -> Result<[u8; 64], SemanticH4BridgeGkrError> {
    let rounds = semantic_h4_bridge_strict_rounds(proof, context_commitment, first_ordinal)?;
    let mut hash = Sha3_512::new();
    hash.update(b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/STRICT-SCHEDULE/v2\0");
    hash.update(context_commitment.as_bytes());
    hash.update([profile_code(proof.profile)]);
    hash.update(first_ordinal.to_be_bytes());
    hash.update(
        u32::try_from(rounds.len())
            .map_err(|_| SemanticH4BridgeGkrError::Transcript)?
            .to_be_bytes(),
    );
    let round_count = rounds.len();
    for round in rounds {
        hash.update(round.descriptor.encode());
        hash.update([round.policy.code()]);
    }
    let commitment: [u8; 64] = hash.finalize().into();
    let (governed, governed_round_count) =
        semantic_h4_bridge_governed_schedule(proof.profile, context_commitment, first_ordinal)?;
    if commitment != governed || usize::try_from(governed_round_count).ok() != Some(round_count) {
        return Err(SemanticH4BridgeGkrError::Transcript);
    }
    Ok(commitment)
}

/// Derive the governed descriptor/policy schedule before proof production.
///
/// Messages are intentionally excluded by the frozen schedule commitment;
/// this lets custody create a verifier key without circularly trusting a
/// prover-produced proof. The ordinary proof-derived function above remains
/// the replay check and must produce the same result.
pub fn semantic_h4_bridge_governed_schedule(
    profile: SemanticH4BridgeProfile,
    context_commitment: BindingDigestV2,
    first_ordinal: u32,
) -> Result<([u8; 64], u32), SemanticH4BridgeGkrError> {
    let plans = semantic_h4_bridge_layer_plans(profile);
    let degrees = semantic_h4_bridge_mask_variable_degrees(profile);
    if plans.len() != degrees.len() {
        return Err(SemanticH4BridgeGkrError::Shape);
    }
    let topologies = semantic_h4_bridge_topologies();
    let mut descriptors = Vec::new();
    let mut ordinal = first_ordinal;
    for circuit in [
        SemanticH4BridgeCircuit::Rate,
        SemanticH4BridgeCircuit::Inactive,
        SemanticH4BridgeCircuit::Capacity,
        SemanticH4BridgeCircuit::Digest,
    ] {
        let output_variables = circuit_layers(&topologies, circuit)
            .last()
            .ok_or(SemanticH4BridgeGkrError::Shape)?
            .padded_width
            .trailing_zeros() as usize;
        descriptors.push((
            StrictPqRoundDescriptorV2::new(
                SEMANTIC_H4_BRIDGE_OUTPUT_KIND,
                ordinal,
                u16::try_from(output_variables + usize::from(circuit_group_log(profile, circuit)))
                    .map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
            )
            .map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
            StrictPqFp16PolicyV2::Uniform,
        ));
        ordinal = ordinal
            .checked_add(1)
            .ok_or(SemanticH4BridgeGkrError::Transcript)?;
        for (plan_index, plan) in plans.iter().enumerate() {
            if plan.circuit != circuit {
                continue;
            }
            descriptors.push((
                StrictPqRoundDescriptorV2::new(SEMANTIC_H4_BRIDGE_LAYER_KIND, ordinal, 2)
                    .map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
                StrictPqFp16PolicyV2::Nonzero,
            ));
            ordinal = ordinal
                .checked_add(1)
                .ok_or(SemanticH4BridgeGkrError::Transcript)?;
            for _ in degrees
                .get(plan_index)
                .ok_or(SemanticH4BridgeGkrError::Shape)?
            {
                descriptors.push((
                    StrictPqRoundDescriptorV2::new(SEMANTIC_H4_BRIDGE_SUMCHECK_KIND, ordinal, 1)
                        .map_err(|_| SemanticH4BridgeGkrError::Transcript)?,
                    StrictPqFp16PolicyV2::NonzeroNonone,
                ));
                ordinal = ordinal
                    .checked_add(1)
                    .ok_or(SemanticH4BridgeGkrError::Transcript)?;
            }
        }
    }
    let mut hash = Sha3_512::new();
    hash.update(b"BL/PQ512/WAVE2/SEMANTIC-H4-BRIDGE/STRICT-SCHEDULE/v2\0");
    hash.update(context_commitment.as_bytes());
    hash.update([profile_code(profile)]);
    hash.update(first_ordinal.to_be_bytes());
    hash.update(
        u32::try_from(descriptors.len())
            .map_err(|_| SemanticH4BridgeGkrError::Transcript)?
            .to_be_bytes(),
    );
    for (descriptor, policy) in descriptors {
        hash.update(descriptor.encode());
        hash.update([policy.code()]);
    }
    let round_count = ordinal
        .checked_sub(first_ordinal)
        .ok_or(SemanticH4BridgeGkrError::Transcript)?;
    Ok((hash.finalize().into(), round_count))
}

/// Replay the bridge GKR's complete strict transcript transactionally and
/// verify the algebra using only challenges produced by that replay.
pub fn verify_strict_semantic_h4_bridge_gkr(
    encoded_bundle: &[u8],
    governed_key: &StrictPqGovernedVerifierKeyV2,
    proof: &PublicMaskedSemanticH4BridgeGkrProof,
    context_commitment: BindingDigestV2,
    first_ordinal: u32,
    registry: &mut StrictPqRootUseRegistryV2,
) -> Result<VerifiedStrictSemanticH4BridgeGkr, SemanticH4BridgeGkrError> {
    let rounds = semantic_h4_bridge_strict_rounds(proof, context_commitment, first_ordinal)?;
    let expected_schedule =
        semantic_h4_bridge_strict_schedule_commitment(proof, context_commitment, first_ordinal)?;
    if governed_key.schedule_commitment() != &expected_schedule
        || usize::try_from(governed_key.round_count()).ok() != Some(rounds.len())
    {
        return Err(SemanticH4BridgeGkrError::Transcript);
    }
    let bundle = StrictPqPublicCoinBundleV2::decode(encoded_bundle)
        .map_err(|_| SemanticH4BridgeGkrError::Transcript)?;
    let policies = rounds.iter().map(|round| round.policy).collect::<Vec<_>>();
    let messages = rounds
        .iter()
        .map(|round| round.message.as_slice())
        .collect::<Vec<_>>();
    let strict_profile = match proof.profile {
        SemanticH4BridgeProfile::K128 => StrictPqH4ProfileV2::K128,
        SemanticH4BridgeProfile::K512 => StrictPqH4ProfileV2::K512,
    };
    let mut pending = registry.clone();
    let outputs = replay_strict_pq_fp16_public_coin_v2(
        governed_key,
        &bundle,
        strict_profile,
        &policies,
        &messages,
        &mut pending,
    )
    .map_err(|_| SemanticH4BridgeGkrError::Transcript)?;
    let challenges =
        semantic_h4_bridge_challenges_from_strict_outputs(proof.profile, &outputs, first_ordinal)?;
    let verified = verify_public_masked_semantic_h4_bridge_gkr(proof, &challenges)?;
    let final_transcript_root = *bundle.final_transcript_root();
    *registry = pending;
    Ok(VerifiedStrictSemanticH4BridgeGkr {
        verified,
        context: context_commitment,
        final_transcript_root,
    })
}

pub fn evaluate_gate(kind: KeccakDagGateKind, left: Fp16, right: Fp16) -> Fp16 {
    match kind {
        KeccakDagGateKind::Xor => left + right - (left * right + left * right),
        KeccakDagGateKind::NotLeftAndRight => right - left * right,
        KeccakDagGateKind::XorConstant(value) => {
            if value {
                Fp16::ONE - left
            } else {
                left
            }
        }
        KeccakDagGateKind::Multiply => left * right,
        KeccakDagGateKind::Add => left + right,
        KeccakDagGateKind::RelayLeft => left,
        KeccakDagGateKind::Subtract => left - right,
        KeccakDagGateKind::Zero => Fp16::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisive_composition_accepts_only_matching_opaque_public_statement() {
        let public_inputs_binding =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"public-inputs").unwrap();
        let semantic_h4 = VerifiedSemanticH4CompositionV3 {
            profile: MasterProfile::K128Calibration,
            receipt_binding: BindingDigestV2::hash(BindingRoleV2::Payload, b"semantic-h4").unwrap(),
            public_inputs_binding,
        };
        let typed = crate::typed_state_proof_package::VerifiedTypedStateV3::synthetic_for_test(
            1,
            public_inputs_binding,
            BindingDigestV2::hash(BindingRoleV2::Payload, b"typed").unwrap(),
        );
        let verified =
            complete_decisive_composition_v3(semantic_h4.clone(), typed.clone()).unwrap();
        assert_eq!(verified.profile(), MasterProfile::K128Calibration);
        assert!(
            verified
                .receipt_binding()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
        );

        let wrong_statement =
            crate::typed_state_proof_package::VerifiedTypedStateV3::synthetic_for_test(
                1,
                BindingDigestV2::hash(BindingRoleV2::Payload, b"other-inputs").unwrap(),
                typed.receipt_binding(),
            );
        assert_eq!(
            complete_decisive_composition_v3(semantic_h4.clone(), wrong_statement),
            Err(DecisiveCompositionV3Error::PublicStatement)
        );

        let wrong_profile =
            crate::typed_state_proof_package::VerifiedTypedStateV3::synthetic_for_test(
                3,
                typed.public_inputs_binding(),
                typed.receipt_binding(),
            );
        assert_eq!(
            complete_decisive_composition_v3(semantic_h4, wrong_profile),
            Err(DecisiveCompositionV3Error::Profile)
        );
    }
    use crate::{
        field::M31, gkr_sumcheck::prove_masked_shared_group_dag_layer_interactive,
        gkr_zk_mask::LibraPriorLayerCorrection,
    };

    fn fp(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    #[test]
    fn functional_coins_are_domain_separated_and_deterministic() {
        let binding = BindingDigestV2::hash(BindingRoleV2::Payload, b"semantic-fri").unwrap();
        let point = vec![
            fp(3);
            source_wire_log(SemanticH4BridgeCircuit::Rate)
                + usize::from(circuit_group_log(
                    SemanticH4BridgeProfile::K128,
                    SemanticH4BridgeCircuit::Rate,
                ))
        ];
        let first = derive_semantic_bridge_functional_coins_from_binding_v3(
            SemanticH4BridgeProfile::K128,
            SemanticH4BridgeCircuit::Rate,
            SemanticBridgeBaseColumnV3::MessageLive,
            &point,
            binding,
        )
        .unwrap();
        let repeated = derive_semantic_bridge_functional_coins_from_binding_v3(
            SemanticH4BridgeProfile::K128,
            SemanticH4BridgeCircuit::Rate,
            SemanticBridgeBaseColumnV3::MessageLive,
            &point,
            binding,
        )
        .unwrap();
        let other_column = derive_semantic_bridge_functional_coins_from_binding_v3(
            SemanticH4BridgeProfile::K128,
            SemanticH4BridgeCircuit::Rate,
            SemanticBridgeBaseColumnV3::MessageValue,
            &point,
            binding,
        )
        .unwrap();
        assert_eq!(first, repeated);
        assert_eq!(
            first.functional_challenges.len(),
            usize::from(semantic_column_log(
                SemanticH4BridgeProfile::K128,
                SemanticBridgeBaseColumnV3::MessageLive,
            ))
        );
        assert_ne!(first, other_column);
        assert_ne!(first.coefficient_context, first.circle_completion_coin);
        assert_ne!(
            first.circle_completion_coin,
            first.functional_completion_coin
        );
    }

    fn binding_root(label: &'static [u8]) -> BindingRootV2 {
        crate::binding_root_v2::BindingMerkleTreeV2::from_payloads(&[label])
            .unwrap()
            .root()
    }

    #[test]
    fn production_bridge_gkr_producer_replays_a_noninteractive_zero_relation() {
        let profile = SemanticH4BridgeProfile::K128;
        let context =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"bridge-producer-test").unwrap();
        let source_values = [
            vec![Fp16::ZERO; BRIDGE_RATE_SOURCE_WIDTH],
            vec![Fp16::ZERO; BRIDGE_BLOCK_SOURCE_WIDTH],
            vec![Fp16::ZERO; BRIDGE_BLOCK_SOURCE_WIDTH],
            vec![Fp16::ZERO; BRIDGE_DIGEST_SOURCE_WIDTH],
        ];
        let layout = semantic_h4_bridge_mask_layout(profile).unwrap();
        let mask_coefficients = (0..layout.padded_coefficients)
            .map(|index| fp(17 + (index % 251) as u32))
            .collect::<Vec<_>>();
        let mut counter = 2_u32;
        let (proof, challenges) = produce_public_masked_semantic_h4_bridge_gkr(
            profile,
            context,
            40,
            source_values,
            &mask_coefficients,
            |descriptor, policy, _message| {
                let mut result = Vec::with_capacity(usize::from(descriptor.output_count()));
                for _ in 0..descriptor.output_count() {
                    let value = fp(2 + counter % 65_000);
                    counter = counter.wrapping_add(1);
                    if !policy.accepts(value) {
                        return Err(SemanticH4BridgeGkrError::Transcript);
                    }
                    result.push(value);
                }
                Ok(result)
            },
        )
        .unwrap();
        assert_eq!(proof.profile, profile);
        let verified = verify_public_masked_semantic_h4_bridge_gkr(&proof, &challenges).unwrap();
        assert_eq!(verified.profile, profile);
        assert_eq!(
            proof.layers.len(),
            semantic_h4_bridge_layer_plans(profile).len()
        );
    }

    #[test]
    fn production_bridge_gkr_producer_replays_a_nonzero_relation() {
        let profile = SemanticH4BridgeProfile::K128;
        let context =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"bridge-producer-nonzero-test").unwrap();
        let mut source_values = [
            vec![Fp16::ZERO; BRIDGE_RATE_SOURCE_WIDTH],
            vec![Fp16::ZERO; BRIDGE_BLOCK_SOURCE_WIDTH],
            vec![Fp16::ZERO; BRIDGE_BLOCK_SOURCE_WIDTH],
            vec![Fp16::ZERO; BRIDGE_DIGEST_SOURCE_WIDTH],
        ];
        source_values[0][0] = fp(2);
        source_values[0][1] = fp(3);
        source_values[1][0] = fp(5);
        source_values[2][10] = fp(7);
        source_values[3][100] = fp(11);
        let layout = semantic_h4_bridge_mask_layout(profile).unwrap();
        let mask_coefficients = (0..layout.padded_coefficients)
            .map(|index| fp(31 + (index % 241) as u32))
            .collect::<Vec<_>>();
        let mut counter = 101_u32;
        let (proof, challenges) = produce_public_masked_semantic_h4_bridge_gkr(
            profile,
            context,
            40,
            source_values,
            &mask_coefficients,
            |descriptor, policy, _message| {
                let mut result = Vec::with_capacity(usize::from(descriptor.output_count()));
                for _ in 0..descriptor.output_count() {
                    let value = fp(2 + counter % 65_000);
                    counter = counter.wrapping_add(1);
                    if !policy.accepts(value) {
                        return Err(SemanticH4BridgeGkrError::Transcript);
                    }
                    result.push(value);
                }
                Ok(result)
            },
        )
        .unwrap();
        assert_eq!(proof.profile, profile);
        let verified = verify_public_masked_semantic_h4_bridge_gkr(&proof, &challenges).unwrap();
        assert_eq!(verified.profile, profile);
        assert_eq!(
            proof.layers.len(),
            semantic_h4_bridge_layer_plans(profile).len()
        );
    }

    #[test]
    fn kind900_fixes_semantic_h4_and_coefficient_roots_before_z() {
        let roots = crate::oracle_commitment::BindingCommittedAirRootsV2 {
            main_trace: binding_root(b"main"),
            interaction_trace: Some(binding_root(b"interaction")),
            composition: binding_root(b"composition"),
        };
        let h4 = BindingDigestV2::hash(BindingRoleV2::Payload, b"h4-pre-alpha").unwrap();
        let coefficients = semantic_coefficient_root_inventory_binding_v3(&[
            binding_root(b"message-live"),
            binding_root(b"message-value"),
            binding_root(b"digest-value"),
        ])
        .unwrap();
        let encoded = semantic_v3_kind900_authority_message(
            MasterProfile::K128Calibration,
            &roots,
            h4,
            coefficients,
        )
        .unwrap();
        let expected = crate::selected_public_coin_v3::strict_message_binding(2, &encoded).unwrap();

        let mut changed_roots = roots;
        changed_roots.composition = binding_root(b"other-composition");
        let changed = semantic_v3_kind900_authority_message(
            MasterProfile::K128Calibration,
            &changed_roots,
            h4,
            coefficients,
        )
        .unwrap();
        assert_ne!(
            expected,
            crate::selected_public_coin_v3::strict_message_binding(2, &changed).unwrap()
        );

        let changed = semantic_v3_kind900_authority_message(
            MasterProfile::K128Calibration,
            &roots,
            BindingDigestV2::hash(BindingRoleV2::Payload, b"other-h4").unwrap(),
            coefficients,
        )
        .unwrap();
        assert_ne!(
            expected,
            crate::selected_public_coin_v3::strict_message_binding(2, &changed).unwrap()
        );

        let changed = semantic_v3_kind900_authority_message(
            MasterProfile::K128Calibration,
            &roots,
            h4,
            semantic_coefficient_root_inventory_binding_v3(&[binding_root(b"other-root")]).unwrap(),
        )
        .unwrap();
        assert_ne!(
            expected,
            crate::selected_public_coin_v3::strict_message_binding(2, &changed).unwrap()
        );
    }

    #[test]
    fn weighted_residue_prefix_matches_direct_boolean_sum() {
        let point = vec![fp(3), fp(5), fp(7), fp(11), fp(13), fp(17)];
        for count in [0usize, 1, 17, 63, 64] {
            for residue in 0..7usize {
                let direct = (0..count)
                    .filter(|index| index % 7 == residue)
                    .fold(Fp16::ZERO, |sum, index| {
                        sum + equality_weight(index, &point)
                    });
                assert_eq!(
                    equality_residue_prefix_sum(count, 7, residue, &point).unwrap(),
                    direct
                );
            }
        }
    }

    fn evaluate_rows(layers: &[KeccakDagLayer], source: &[Fp16]) -> Vec<Vec<Fp16>> {
        let mut values: Vec<Vec<Fp16>> = Vec::new();
        for layer in layers {
            let left = match layer.left_source {
                KeccakDagSource::RoundInput => source,
                KeccakDagSource::Layer(index) => &values[index],
            };
            let right = match layer.right_source {
                KeccakDagSource::RoundInput => source,
                KeccakDagSource::Layer(index) => &values[index],
            };
            values.push(
                layer
                    .gates
                    .iter()
                    .map(|gate| evaluate_gate(gate.kind, left[gate.left], right[gate.right]))
                    .collect(),
            );
        }
        values
    }

    #[test]
    fn h4_source_terminal_is_not_interchangeable_with_bridge_mask_opening() {
        let point = vec![fp(3), fp(5), fp(7)];
        let source_binding =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"h4-source-segment-set").unwrap();
        let answer_binding =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"h4-construction-answer").unwrap();
        let h4 = VerifiedH4BridgeSourceTerminalV2::synthetic_for_test(
            source_binding,
            answer_binding,
            point.clone(),
            fp(11),
        );
        let semantic = VerifiedCircleLagrangeSparseFunctional {
            circle_value: fp(13),
            multilinear_value: fp(17),
            public_lagrange_mle: fp(19),
            multilinear_point: point.clone(),
        };
        let authenticated = authenticate_bridge_raw_source_claim(
            &point,
            &[semantic.clone()],
            &[h4.clone()],
            source_binding,
            answer_binding,
            fp(23),
        )
        .unwrap();
        assert_eq!(authenticated.value, fp(23) + fp(17) + fp(11));

        let wrong_source = BindingDigestV2::hash(BindingRoleV2::Payload, b"other-source").unwrap();
        assert_eq!(
            authenticate_bridge_raw_source_claim(
                &point,
                &[semantic.clone()],
                &[h4.clone()],
                wrong_source,
                answer_binding,
                fp(23),
            ),
            Err(SemanticH4BridgeGkrError::Binding)
        );
        let wrong_answer = BindingDigestV2::hash(BindingRoleV2::Payload, b"other-answer").unwrap();
        assert_eq!(
            authenticate_bridge_raw_source_claim(
                &point,
                &[semantic],
                &[h4],
                source_binding,
                wrong_answer,
                fp(23),
            ),
            Err(SemanticH4BridgeGkrError::Binding)
        );
    }

    fn inner_product_proof(
        mut left: Vec<Fp16>,
        mut right: Vec<Fp16>,
        challenges: &[Fp16],
    ) -> (PublicBridgeInnerProductProof, Fp16, Fp16) {
        let claimed = left
            .iter()
            .zip(&right)
            .fold(Fp16::ZERO, |sum, (left, right)| sum + *left * *right);
        let mut rounds = Vec::with_capacity(challenges.len());
        let mut active = left.len();
        for challenge in challenges {
            let mut round = [Fp16::ZERO; 3];
            for index in 0..active / 2 {
                let left_zero = left[2 * index];
                let left_delta = left[2 * index + 1] - left_zero;
                let right_zero = right[2 * index];
                let right_delta = right[2 * index + 1] - right_zero;
                round[0] = round[0] + left_zero * right_zero;
                round[1] = round[1] + left_zero * right_delta + left_delta * right_zero;
                round[2] = round[2] + left_delta * right_delta;
                left[index] = left_zero + *challenge * left_delta;
                right[index] = right_zero + *challenge * right_delta;
            }
            active /= 2;
            rounds.push(round);
        }
        (PublicBridgeInnerProductProof { rounds }, claimed, left[0])
    }

    fn zero_masked_proof(
        profile: SemanticH4BridgeProfile,
    ) -> (
        PublicMaskedSemanticH4BridgeGkrProof,
        SemanticH4BridgePublicChallenges,
    ) {
        let topologies = semantic_h4_bridge_topologies();
        let plans = semantic_h4_bridge_layer_plans(profile);
        let layout = semantic_h4_bridge_mask_layout(profile).unwrap();
        let coefficients = (0..layout.padded_coefficients)
            .map(|index| fp(17 + (index % 251) as u32))
            .collect::<Vec<_>>();
        let (_, sumcheck_masks, layer_masks) = layout.decode_prefix(&coefficients).unwrap();
        let output_points = [
            vec![Fp16::ZERO; usize::from(profile.rate_group_log())],
            vec![Fp16::ZERO; 11 + usize::from(BRIDGE_BLOCK_GROUP_LOG)],
            vec![Fp16::ZERO; 10 + usize::from(BRIDGE_BLOCK_GROUP_LOG)],
            vec![Fp16::ZERO; usize::from(BRIDGE_DIGEST_GROUP_LOG)],
        ];
        let mut public_layers = Vec::with_capacity(plans.len());
        let mut public_challenges = Vec::with_capacity(plans.len());
        let mut proof_index = 0_usize;
        for circuit in [
            SemanticH4BridgeCircuit::Rate,
            SemanticH4BridgeCircuit::Inactive,
            SemanticH4BridgeCircuit::Capacity,
            SemanticH4BridgeCircuit::Digest,
        ] {
            let layers = circuit_layers(&topologies, circuit);
            let group_log = circuit_group_log(profile, circuit);
            let group_count = 1_usize << group_log;
            let source_width = match circuit {
                SemanticH4BridgeCircuit::Rate => BRIDGE_RATE_SOURCE_WIDTH,
                SemanticH4BridgeCircuit::Inactive | SemanticH4BridgeCircuit::Capacity => {
                    BRIDGE_BLOCK_SOURCE_WIDTH
                }
                SemanticH4BridgeCircuit::Digest => BRIDGE_DIGEST_SOURCE_WIDTH,
            };
            let source = vec![Fp16::ZERO; source_width];
            let values = evaluate_rows(layers, &source);
            let mut pending = vec![Vec::<PublicMaskedBridgeClaim>::new(); layers.len() + 1];
            pending[layers.len()].push(PublicMaskedBridgeClaim {
                point: output_points[circuit_index(circuit)].clone(),
                masked_value: Fp16::ZERO,
                mask_layer: None,
            });
            for layer_index in (0..layers.len()).rev() {
                let layer = &layers[layer_index];
                let incoming = core::mem::take(&mut pending[layer_index + 1]);
                let claim_mix = fp(503 + proof_index as u32);
                let sumcheck_rho = fp(877 + proof_index as u32);
                let mut power = Fp16::ONE;
                let effective = incoming
                    .iter()
                    .map(|claim| {
                        let coefficient = power;
                        power = power * claim_mix;
                        LayerOutputClaim {
                            point: claim.point.clone(),
                            value: Fp16::ZERO,
                            coefficient,
                        }
                    })
                    .collect::<Vec<_>>();
                let prior = if incoming.iter().all(|claim| claim.mask_layer.is_none()) {
                    LibraPriorLayerCorrection::zero()
                } else {
                    let indexed = incoming
                        .iter()
                        .zip(&effective)
                        .map(|(claim, effective)| {
                            (
                                claim.mask_layer.unwrap(),
                                effective.coefficient,
                                effective.point.clone(),
                            )
                        })
                        .collect::<Vec<_>>();
                    LibraPriorLayerCorrection::from_indexed_claims(&layer_masks, &indexed).unwrap()
                };
                let left = match layer.left_source {
                    KeccakDagSource::RoundInput => &source,
                    KeccakDagSource::Layer(index) => &values[index],
                };
                let right = match layer.right_source {
                    KeccakDagSource::RoundInput => &source,
                    KeccakDagSource::Layer(index) => &values[index],
                };
                let challenge_counter = core::cell::Cell::new(1_111_u32 + 64 * proof_index as u32);
                let reduction = prove_masked_shared_group_dag_layer_interactive(
                    layer,
                    group_count,
                    left,
                    right,
                    &effective,
                    &prior,
                    &sumcheck_masks[proof_index],
                    &layer_masks[proof_index],
                    sumcheck_rho,
                    |_, _, _| {
                        let next = challenge_counter.get();
                        challenge_counter.set(next + 1);
                        Ok(fp(next))
                    },
                    |_, _, _| {
                        let next = challenge_counter.get();
                        challenge_counter.set(next + 1);
                        Ok(fp(next))
                    },
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "masked bridge prover failed at {circuit:?} layer {layer_index} proof {proof_index}: {error:?}; widths=({},{},{}), point={}, degrees={:?}",
                        layer.left_width,
                        layer.right_width,
                        layer.padded_width,
                        effective[0].point.len(),
                        sumcheck_masks[proof_index].variable_degrees(),
                    )
                });
                let left_variables = layer.left_width.trailing_zeros() as usize;
                let outgoing = [
                    (
                        layer.left_source,
                        reduction.wire_challenges[..left_variables]
                            .iter()
                            .chain(&reduction.group_challenges)
                            .copied()
                            .collect::<Vec<_>>(),
                        reduction.masked_terminal_left,
                    ),
                    (
                        layer.right_source,
                        reduction.wire_challenges[left_variables..]
                            .iter()
                            .chain(&reduction.group_challenges)
                            .copied()
                            .collect::<Vec<_>>(),
                        reduction.masked_terminal_right,
                    ),
                ];
                for (source_kind, point, masked_value) in outgoing {
                    let claim = PublicMaskedBridgeClaim {
                        point,
                        masked_value,
                        mask_layer: Some(proof_index),
                    };
                    if let KeccakDagSource::Layer(index) = source_kind {
                        pending[index + 1].push(claim);
                    }
                }
                public_layers.push(PublicMaskedBridgeLayerProof {
                    circuit,
                    layer: layer_index,
                    published_rounds: reduction.published_rounds,
                    masked_terminal_left: reduction.masked_terminal_left,
                    masked_terminal_right: reduction.masked_terminal_right,
                });
                public_challenges.push(SemanticH4BridgeLayerChallenges {
                    claim_mix,
                    sumcheck_rho,
                    group_challenges: reduction.group_challenges,
                    wire_challenges: reduction.wire_challenges,
                    w_challenge: reduction.w_challenge,
                });
                proof_index += 1;
            }
        }
        (
            PublicMaskedSemanticH4BridgeGkrProof {
                profile,
                layers: public_layers,
            },
            SemanticH4BridgePublicChallenges {
                output_points,
                layers: public_challenges,
            },
        )
    }

    #[test]
    fn topology_geometry_is_exact() {
        let topology = semantic_h4_bridge_topologies();
        assert_eq!(topology.rate.len(), 8);
        assert_eq!(topology.inactive.len(), 1);
        assert_eq!(topology.capacity.len(), 2);
        assert_eq!(topology.digest.len(), 13);
        assert_eq!(topology.rate.last().unwrap().padded_width, 1);
        assert_eq!(topology.inactive.last().unwrap().padded_width, 2_048);
        assert_eq!(topology.capacity.last().unwrap().padded_width, 1_024);
        assert_eq!(topology.digest.last().unwrap().padded_width, 1);
        for profile in [SemanticH4BridgeProfile::K128, SemanticH4BridgeProfile::K512] {
            let plans = semantic_h4_bridge_layer_plans(profile);
            let layout = semantic_h4_bridge_mask_layout(profile).unwrap();
            assert_eq!(plans.len(), 24);
            assert_eq!(layout.layers.len(), plans.len());
            assert!(layout.used_coefficients < 8_192);
            assert_eq!(layout.padded_coefficients, 4_096);
            assert!(layout.leakage_budget().unwrap().total_rank < layout.padded_coefficients);
        }
    }

    #[test]
    fn rate_accepts_exact_absorb_and_rejects_input_mutation() {
        let topology = semantic_h4_bridge_topologies();
        let mut source = vec![Fp16::ZERO; BRIDGE_RATE_SOURCE_WIDTH];
        source[RATE_LIVE] = Fp16::ONE;
        source[RATE_PREVIOUS_LIVE] = Fp16::ONE;
        source[RATE_BLOCK_ACTIVE] = Fp16::ONE;
        source[RATE_NEXT_BLOCK_ACTIVE] = Fp16::ONE;
        source[RATE_VALUE] = fp(0x5a);
        source[RATE_ONE] = Fp16::ONE;
        source[RATE_SIX] = fp(6);
        source[RATE_128] = fp(128);
        for bit in 0..8 {
            source[RATE_BIT_WEIGHTS_START + bit] = fp(1 << bit);
            source[RATE_INPUT_BITS_START + bit] = fp((0x5a_u32 >> bit) & 1);
        }
        assert_eq!(
            evaluate_rows(&topology.rate, &source).last().unwrap()[0],
            Fp16::ZERO
        );
        source[RATE_INPUT_BITS_START] = Fp16::ONE - source[RATE_INPUT_BITS_START];
        assert_ne!(
            evaluate_rows(&topology.rate, &source).last().unwrap()[0],
            Fp16::ZERO
        );
    }

    #[test]
    fn digest_selects_exact_last_block_and_rejects_output_mutation() {
        let topology = semantic_h4_bridge_topologies();
        let mut source = vec![Fp16::ZERO; BRIDGE_DIGEST_SOURCE_WIDTH];
        source[DIGEST_ACTIVE_START] = Fp16::ONE;
        source[DIGEST_NEXT_ACTIVE_START] = Fp16::ONE;
        source[DIGEST_ACTIVE_START + 1] = Fp16::ONE;
        source[DIGEST_OUTPUT_BYTES_START + 1] = fp(71);
        source[DIGEST_EXPECTED_BYTE] = fp(71);
        assert_eq!(
            evaluate_rows(&topology.digest, &source).last().unwrap()[0],
            Fp16::ZERO
        );
        source[DIGEST_OUTPUT_BYTES_START + 1] = fp(70);
        assert_ne!(
            evaluate_rows(&topology.digest, &source).last().unwrap()[0],
            Fp16::ZERO
        );
    }

    #[test]
    fn raw_free_masked_proof_roundtrips_and_mutations_fail() {
        let (proof, challenges) = zero_masked_proof(SemanticH4BridgeProfile::K128);
        let verified = verify_public_masked_semantic_h4_bridge_gkr(&proof, &challenges).unwrap();
        assert!(!verified.source_claims.is_empty());
        assert_eq!(verified.mask_constraints.len(), 2 * proof.layers.len());
        let encoded = encode_public_masked_semantic_h4_bridge_gkr(&proof).unwrap();
        assert!(encoded.len() < MAX_SEMANTIC_H4_BRIDGE_GKR_BYTES);
        assert_eq!(
            decode_public_masked_semantic_h4_bridge_gkr(&encoded).unwrap(),
            proof
        );
        let response_commitment = semantic_h4_bridge_response_commitment(&proof).unwrap();
        let claim_commitment = semantic_h4_bridge_claim_vector_commitment(&verified).unwrap();
        assert_ne!(response_commitment, claim_commitment);

        let source_batch_challenge = fp(997);
        let semantic_terms = verified
            .source_claims
            .iter()
            .enumerate()
            .map(|(index, claim)| {
                vec![VerifiedCircleLagrangeSparseFunctional {
                    circle_value: fp(31 + index as u32),
                    multilinear_value: fp(101 + index as u32),
                    public_lagrange_mle: fp(211 + index as u32),
                    multilinear_point: claim.point.clone(),
                }]
            })
            .collect::<Vec<_>>();
        let fixed = (0..verified.source_claims.len())
            .map(|index| fp(307 + index as u32))
            .collect::<Vec<_>>();
        let semantic_batch = authenticate_semantic_bridge_source_batch_v2(
            &verified,
            &semantic_terms,
            &fixed,
            source_batch_challenge,
        )
        .unwrap();
        let semantic_terms_v3 = verified
            .source_claims
            .iter()
            .zip(&verified.source_circuits)
            .enumerate()
            .map(|(index, (claim, circuit))| {
                expected_semantic_columns(*circuit)
                    .iter()
                    .enumerate()
                    .map(|(column_index, column)| {
                        let mut root_bytes = [0_u8; 128];
                        root_bytes[0] = 1;
                        root_bytes[127] = u8::try_from(index + column_index + 1).unwrap();
                        VerifiedSemanticBridgeFunctionalV3::synthetic_for_test(
                            verified.profile,
                            *circuit,
                            *column,
                            claim.point.clone(),
                            BindingRootV2::decode(&root_bytes).unwrap(),
                            fp(101 + index as u32 + column_index as u32),
                        )
                    })
                    .collect()
            })
            .collect::<Vec<_>>();
        let semantic_batch_v3 = authenticate_semantic_bridge_source_batch_v3(
            &verified,
            &semantic_terms_v3,
            source_batch_challenge,
        )
        .unwrap();
        let mut expected_batch = Fp16::ZERO;
        let mut power = Fp16::ONE;
        for (index, fixed) in fixed.iter().enumerate() {
            expected_batch =
                expected_batch + power * (*fixed + semantic_terms[index][0].multilinear_value);
            power = power * source_batch_challenge;
        }
        assert_eq!(semantic_batch.batched_value(), expected_batch);
        assert_eq!(semantic_batch.claim_count(), verified.source_claims.len());
        assert_eq!(semantic_batch.claim_vector_binding(), claim_commitment);
        assert_eq!(semantic_batch_v3.claim_vector_binding(), claim_commitment);
        let mut expected_batch_v3 = Fp16::ZERO;
        let mut v3_power = Fp16::ONE;
        for ((claim, circuit), terms) in verified
            .source_claims
            .iter()
            .zip(&verified.source_circuits)
            .zip(&semantic_terms_v3)
        {
            let value = terms.iter().fold(
                semantic_fixed_source_value(verified.profile, *circuit, &claim.point).unwrap(),
                |sum, term| sum + term.value,
            );
            expected_batch_v3 = expected_batch_v3 + v3_power * value;
            v3_power = v3_power * source_batch_challenge;
        }
        assert_eq!(semantic_batch_v3.batched_value(), expected_batch_v3);
        assert!(
            !semantic_batch_v3
                .coefficient_roots_binding()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        );
        let mut complete_masked = Fp16::ZERO;
        let mut claim_power = Fp16::ONE;
        for claim in &verified.source_claims {
            complete_masked = complete_masked + claim_power * claim.masked_value;
            claim_power = claim_power * source_batch_challenge;
        }
        let h4_response = VerifiedH4BridgeSourceResponseV2::synthetic_for_test(
            claim_commitment,
            complete_masked - expected_batch,
        );
        let source_binding =
            bind_semantic_h4_bridge_batched_sources_v2(&verified, &semantic_batch, &h4_response)
                .unwrap();
        let h4_claim_values_v3 = verified
            .source_claims
            .iter()
            .zip(semantic_batch_v3.claim_values())
            .map(|(claim, semantic_value)| claim.masked_value - *semantic_value)
            .collect::<Vec<_>>();
        let h4_response_v3 = VerifiedH4BridgeSourceResponseV2::synthetic_for_test_with_claim_values(
            claim_commitment,
            complete_masked - expected_batch_v3,
            h4_claim_values_v3,
        );
        let source_binding_v3 = bind_semantic_h4_bridge_batched_sources_v3(
            &verified,
            &semantic_batch_v3,
            &h4_response_v3,
        )
        .unwrap();
        assert_eq!(
            source_binding.source_claim_count,
            verified.source_claims.len()
        );
        assert_eq!(
            source_binding_v3.source_claim_count,
            verified.source_claims.len()
        );
        assert_eq!(
            source_binding_v3.mask_constraints.len(),
            verified.mask_constraints.len() + verified.source_claims.len()
        );
        assert_ne!(
            source_binding_v3.source_batch_binding,
            source_binding.source_batch_binding
        );
        assert!(
            !source_binding
                .source_batch_binding
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        );
        let wrong_h4 = VerifiedH4BridgeSourceResponseV2::synthetic_for_test(
            claim_commitment,
            complete_masked - expected_batch + Fp16::ONE,
        );
        assert_eq!(
            bind_semantic_h4_bridge_batched_sources_v2(&verified, &semantic_batch, &wrong_h4,),
            Err(SemanticH4BridgeGkrError::Algebra)
        );
        let mut wrong_terms = semantic_terms.clone();
        wrong_terms[0][0].multilinear_point[0] = wrong_terms[0][0].multilinear_point[0] + Fp16::ONE;
        assert_eq!(
            authenticate_semantic_bridge_source_batch_v2(
                &verified,
                &wrong_terms,
                &fixed,
                source_batch_challenge,
            ),
            Err(SemanticH4BridgeGkrError::Binding)
        );
        let mut wrong_v3_terms = semantic_terms_v3.clone();
        wrong_v3_terms[0][0].column = match wrong_v3_terms[0][0].column {
            SemanticBridgeBaseColumnV3::MessageLive => SemanticBridgeBaseColumnV3::MessageValue,
            _ => SemanticBridgeBaseColumnV3::MessageLive,
        };
        assert_eq!(
            authenticate_semantic_bridge_source_batch_v3(
                &verified,
                &wrong_v3_terms,
                source_batch_challenge,
            ),
            Err(SemanticH4BridgeGkrError::Binding)
        );
        let mut retagged = verified.clone();
        retagged.source_circuits[0] = match retagged.source_circuits[0] {
            SemanticH4BridgeCircuit::Rate => SemanticH4BridgeCircuit::Capacity,
            _ => SemanticH4BridgeCircuit::Rate,
        };
        assert_ne!(
            semantic_h4_bridge_claim_vector_commitment(&retagged).unwrap(),
            claim_commitment
        );
        let strict_rounds =
            semantic_h4_bridge_strict_rounds(&proof, response_commitment, 40).unwrap();
        assert!(!strict_rounds.is_empty());
        for (offset, round) in strict_rounds.iter().enumerate() {
            assert_eq!(round.descriptor.ordinal(), 40 + offset as u32);
            assert!(!round.message.is_empty());
        }

        let batch_challenge = fp(1_009);
        let layout = semantic_h4_bridge_mask_layout(proof.profile).unwrap();
        let (weights, opening) =
            aggregate_gkr_mask_constraints(&layout, &verified.mask_constraints, batch_challenge)
                .unwrap();
        let authenticated = AuthenticatedSemanticH4BridgeMaskOpening {
            mask_root: BindingDigestV2::hash(BindingRoleV2::Payload, b"test-mask").unwrap(),
            coefficient_weights: weights,
            opening,
        };
        let batch = verify_semantic_h4_bridge_mask_batch(
            proof.profile,
            &verified,
            batch_challenge,
            authenticated.clone(),
        )
        .unwrap();
        assert_eq!(batch.opening, opening);

        let mut malformed = encoded.clone();
        malformed.push(0);
        assert_eq!(
            decode_public_masked_semantic_h4_bridge_gkr(&malformed),
            Err(SemanticH4BridgeGkrError::Encoding)
        );
        let mut malformed = encoded.clone();
        malformed[22..86].fill(0xff);
        assert_eq!(
            decode_public_masked_semantic_h4_bridge_gkr(&malformed),
            Err(SemanticH4BridgeGkrError::Encoding)
        );

        let mut mutated = proof.clone();
        mutated.layers[0].published_rounds[0][0] =
            mutated.layers[0].published_rounds[0][0] + Fp16::ONE;
        assert!(verify_public_masked_semantic_h4_bridge_gkr(&mutated, &challenges).is_err());

        let mut mutated = proof.clone();
        mutated.layers[1].masked_terminal_left = mutated.layers[1].masked_terminal_left + Fp16::ONE;
        let changed = verify_public_masked_semantic_h4_bridge_gkr(&mutated, &challenges).unwrap();
        assert_ne!(changed, verified);
        assert_eq!(
            verify_semantic_h4_bridge_mask_batch(
                proof.profile,
                &changed,
                batch_challenge,
                authenticated,
            ),
            Err(SemanticH4BridgeGkrError::Algebra)
        );

        let mut wrong_challenges = challenges.clone();
        wrong_challenges.output_points[0][0] = Fp16::ONE;
        let changed =
            verify_public_masked_semantic_h4_bridge_gkr(&proof, &wrong_challenges).unwrap();
        assert_ne!(changed, verified);

        let mut wrong_challenges = challenges.clone();
        wrong_challenges.layers[0].group_challenges[0] = Fp16::ONE;
        assert!(verify_public_masked_semantic_h4_bridge_gkr(&proof, &wrong_challenges).is_err());
    }

    #[test]
    fn inner_product_terminal_requires_authenticated_mle_opening() {
        let left = (0..16).map(|index| fp(31 + index)).collect::<Vec<_>>();
        let right = (0..16).map(|index| fp(97 + 3 * index)).collect::<Vec<_>>();
        let challenges = [fp(211), fp(223), fp(227), fp(229)];
        let (proof, claimed, terminal) = inner_product_proof(left, right.clone(), &challenges);
        let mle_root = crate::binding_root_v2::BindingMerkleTreeV2::from_payloads(&[
            b"mle-left".as_slice(),
            b"mle-right".as_slice(),
        ])
        .unwrap()
        .root();
        let authenticated = AuthenticatedBridgeMleOpening {
            root: mle_root,
            point: challenges.to_vec(),
            value: terminal,
        };
        verify_bridge_inner_product(&proof, &right, claimed, &challenges, authenticated.clone())
            .unwrap();

        let mut mutated = proof.clone();
        mutated.rounds[1][2] = mutated.rounds[1][2] + Fp16::ONE;
        assert_eq!(
            verify_bridge_inner_product(
                &mutated,
                &right,
                claimed,
                &challenges,
                authenticated.clone(),
            ),
            Err(SemanticH4BridgeGkrError::Algebra)
        );
        let wrong_opening = AuthenticatedBridgeMleOpening {
            value: terminal + Fp16::ONE,
            ..authenticated
        };
        assert_eq!(
            verify_bridge_inner_product(&proof, &right, claimed, &challenges, wrong_opening,),
            Err(SemanticH4BridgeGkrError::Algebra)
        );
    }

    #[test]
    fn bridge_mask_batch_reaches_native_committed_coefficients() {
        let profile = SemanticH4BridgeProfile::K128;
        let (gkr_proof, public_challenges) = zero_masked_proof(profile);
        let verified =
            verify_public_masked_semantic_h4_bridge_gkr(&gkr_proof, &public_challenges).unwrap();
        let layout = semantic_h4_bridge_mask_layout(profile).unwrap();
        let coefficients = (0..layout.padded_coefficients)
            .map(|index| fp(17 + (index % 251) as u32))
            .collect::<Vec<_>>();
        let batch_challenge = fp(311);
        let (weights, opening) =
            aggregate_gkr_mask_constraints(&layout, &verified.mask_constraints, batch_challenge)
                .unwrap();
        assert_eq!(
            opening,
            coefficients
                .iter()
                .zip(&weights)
                .fold(Fp16::ZERO, |sum, (left, right)| sum + *left * *right)
        );
        let challenges = (0..layout.padded_coefficients.ilog2())
            .map(|index| fp(401 + index))
            .collect::<Vec<_>>();
        let (inner_proof, claimed) =
            prove_bridge_inner_product(coefficients.clone(), weights, &challenges).unwrap();
        assert_eq!(claimed, opening);
        let context =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"bridge-mask-context").unwrap();
        let completion =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"bridge-completion").unwrap();
        let pcs_proof = crate::binding_multilinear_pcs_v2::prove_binding_multilinear_opening_v2(
            &coefficients,
            &challenges,
            context,
            completion,
        )
        .unwrap();
        verify_semantic_h4_bridge_mask_batch_with_pcs(
            profile,
            &verified,
            batch_challenge,
            &inner_proof,
            &challenges,
            &pcs_proof,
            pcs_proof.roots[0],
            context,
            completion,
        )
        .unwrap();

        let mut changed = pcs_proof;
        changed.layers[0].leaf_values[0][0] = changed.layers[0].leaf_values[0][0] + Fp16::ONE;
        assert!(
            verify_semantic_h4_bridge_mask_batch_with_pcs(
                profile,
                &verified,
                batch_challenge,
                &inner_proof,
                &challenges,
                &changed,
                changed.roots[0],
                context,
                completion,
            )
            .is_err()
        );
    }

    #[test]
    fn aggregate_h4_source_binding_requires_the_exact_shard_target_sum() {
        let verified = VerifiedMaskedSemanticH4BridgeGkr {
            profile: SemanticH4BridgeProfile::K512,
            source_claims: vec![PublicMaskedBridgeClaim {
                point: vec![fp(7)],
                masked_value: fp(10),
                mask_layer: Some(0),
            }],
            source_circuits: vec![SemanticH4BridgeCircuit::Rate],
            mask_constraints: Vec::new(),
        };
        let claim_binding = semantic_h4_bridge_claim_vector_commitment(&verified).unwrap();
        let semantic = VerifiedSemanticBridgeSourceBatchV3 {
            semantic_fri_binding: BindingDigestV2::hash(BindingRoleV2::Payload, b"semantic-fri")
                .unwrap(),
            claim_vector_binding: claim_binding,
            coefficient_root_inventory_binding: BindingDigestV2::hash(
                BindingRoleV2::Payload,
                b"coefficient-root-inventory",
            )
            .unwrap(),
            coefficient_roots_binding: BindingDigestV2::hash(
                BindingRoleV2::Payload,
                b"coefficient-roots",
            )
            .unwrap(),
            claim_challenge: fp(3),
            batched_value: fp(2),
            claim_count: 1,
            claim_values: vec![fp(2)],
        };
        let valid = [fp(1), fp(2), fp(2), fp(3)]
            .into_iter()
            .map(|target| {
                VerifiedH4BridgeSourceResponseV2::synthetic_for_test(claim_binding, target)
            })
            .collect::<Vec<_>>();
        assert!(
            bind_semantic_h4_bridge_batched_sources_v3_aggregate(&verified, &semantic, &valid)
                .is_ok()
        );
        let duplicated_global = (0..4)
            .map(|_| VerifiedH4BridgeSourceResponseV2::synthetic_for_test(claim_binding, fp(8)))
            .collect::<Vec<_>>();
        assert_eq!(
            bind_semantic_h4_bridge_batched_sources_v3_aggregate(
                &verified,
                &semantic,
                &duplicated_global,
            ),
            Err(SemanticH4BridgeGkrError::Algebra)
        );
    }
}
