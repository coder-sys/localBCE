//! Post-OODS Construction response for the semantic/H4 bridge.
//!
//! The response does not commit another raw hash bus.  After the bridge GKR
//! has fixed its masked source claims, a ten-round row sumcheck folds the
//! existing 512 packed H4 source words.  The prover publishes one masked
//! 67,584-coefficient answer.  Completion-coin-selected RS openings then bind
//! that answer to the already committed source and a pre-alpha committed base
//! tensor.  Only the masked answer functional is exposed.

use alloc::vec;
use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::{
    binding_root_v2::{BindingDigestV2, BindingRoleV2, BindingRootV2},
    field::{Fp16, M31},
    fp16_zk_rs_gkr_binding::{COEFFICIENT_VARIABLES, WORD_VARIABLES},
    h4_proof_package_v1::encode_codeword,
    h4_proof_package_v2::{
        H4_ANSWER_MAIN_COEFFICIENT_BYTES, H4_MAIN_CODE_VALUES, H4ProofProfileV2,
    },
    hash_bus::{
        PERMUTATIONS_PER_COPROCESSOR_SHARD, build_hash_bus_descriptor_with_state,
        hash_bus_permutation_slot,
    },
    semantic_h4_bridge_gkr::{
        BLOCK_INPUT_BITS_START, BLOCK_PREDECESSOR_BITS_START, DIGEST_OUTPUT_BYTES_START,
        RATE_INPUT_BITS_START, RATE_PREDECESSOR_BITS_START, SemanticH4BridgeCircuit,
        SemanticH4BridgeProfile, VerifiedMaskedSemanticH4BridgeGkr,
        VerifiedSemanticBridgeSourceBatchV3, semantic_h4_bridge_claim_vector_commitment,
    },
    strict_pq_public_coin_v2::{
        StrictPqFp16PolicyV2, StrictPqFp16RoundOutputV2, StrictPqGovernedVerifierKeyV2,
        StrictPqH4ProfileV2, StrictPqPublicCoinBundleV2, StrictPqRootUseRegistryV2,
        StrictPqRoundDescriptorV2, replay_strict_pq_fp16_public_coin_v2,
    },
    wave1a_global_schedule::Profile,
};

pub const H4_BRIDGE_SOURCE_RESPONSE_V2_MAGIC: &[u8; 8] = b"BLH4SR02";
pub const H4_BRIDGE_SOURCE_RESPONSE_V2_VERSION: u16 = 2;
pub const H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS: usize = WORD_VARIABLES + 1;
pub const H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES: usize = 3;
pub const H4_BRIDGE_SOURCE_PROJECTION_CHALLENGES: usize = WORD_VARIABLES + 1;
pub const H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_OUTPUTS: usize =
    2 + H4_BRIDGE_SOURCE_PROJECTION_CHALLENGES;
pub const H4_BRIDGE_SOURCE_RESPONSE_HEADER_BYTES: usize = 160;
pub const H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS: usize = H4_ANSWER_MAIN_COEFFICIENT_BYTES / 64;
pub const H4_BRIDGE_SOURCE_RESPONSE_LIVE_COEFFICIENTS: usize = 1 << COEFFICIENT_VARIABLES;
pub const H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES: usize = H4_BRIDGE_SOURCE_RESPONSE_HEADER_BYTES
    + H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS * H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES * 64
    + H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS * 64;
const H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/H4/BRIDGE-SOURCE-RESPONSE/PRELUDE/v2\0";
const H4_BRIDGE_SOURCE_RESPONSE_ROW_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/H4/BRIDGE-SOURCE-RESPONSE/ROW/v2\0";
const H4_BRIDGE_SOURCE_RESPONSE_ANSWER_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/H4/BRIDGE-SOURCE-RESPONSE-ANSWER/v2\0";
pub const H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_KIND: u16 = 1_103;
pub const H4_BRIDGE_SOURCE_RESPONSE_ROW_KIND: u16 = 1_104;
pub const H4_BRIDGE_SOURCE_RESPONSE_ANSWER_KIND: u16 = 1_105;
const H4_BRIDGE_SOURCE_RESPONSE_STRICT_SCHEDULE_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/H4/BRIDGE-SOURCE-RESPONSE/STRICT-SCHEDULE/v2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum H4BridgeSourceResponseV2Error {
    Shape,
    ZeroChallenge,
    Sumcheck,
    Functional,
    Code,
    Binding,
    Encoding,
    Transcript,
}

/// Opaque challenges produced only by replaying the exact response messages
/// under the governed strict-PQ key.  Keeping this type private to the crate
/// prevents package callers from substituting locally sampled field values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStrictH4BridgeSourceResponseV2 {
    challenges: H4BridgeSourceResponseChallengesV2,
    context: BindingDigestV2,
    claim_vector_binding: BindingDigestV2,
    final_transcript_root: [u8; 128],
}

impl VerifiedStrictH4BridgeSourceResponseV2 {
    pub fn challenges(&self) -> &H4BridgeSourceResponseChallengesV2 {
        &self.challenges
    }

    pub const fn final_transcript_root(&self) -> &[u8; 128] {
        &self.final_transcript_root
    }

    pub const fn claim_challenge(&self) -> Fp16 {
        self.challenges.claim_challenge
    }

    pub const fn context(&self) -> BindingDigestV2 {
        self.context
    }

    pub const fn claim_vector_binding(&self) -> BindingDigestV2 {
        self.claim_vector_binding
    }
}

/// Verifier-derived bridge relation after the thirteen canonical source
/// claims have been batched.  Its constructor is crate-private: package bytes
/// cannot choose either the initial target or the final coefficient weights.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedH4BridgeRelationV2 {
    initial_target: Fp16,
    claim_vector_binding: BindingDigestV2,
    profile: H4ProofProfileV2,
    shard_index: u8,
    source_claims: Vec<crate::semantic_h4_bridge_gkr::PublicMaskedBridgeClaim>,
    source_circuits: Vec<SemanticH4BridgeCircuit>,
    claim_challenge: Fp16,
    #[cfg(test)]
    synthetic_folded_relation_weights: Option<Vec<Fp16>>,
}

impl VerifiedH4BridgeRelationV2 {
    pub(crate) fn from_verified_gkr(
        profile: H4ProofProfileV2,
        shard_index: u8,
        verified: &VerifiedMaskedSemanticH4BridgeGkr,
        claim_challenge: Fp16,
        authenticated_non_h4_target: Fp16,
    ) -> Result<Self, H4BridgeSourceResponseV2Error> {
        if claim_challenge.is_zero()
            || shard_index >= profile.shard_count()
            || verified.source_claims.is_empty()
            || verified.source_claims.len() != verified.source_circuits.len()
            || verified
                .source_claims
                .iter()
                .any(|claim| claim.point.is_empty())
        {
            return Err(H4BridgeSourceResponseV2Error::Shape);
        }
        let claim_vector_binding = semantic_h4_bridge_claim_vector_commitment(verified)
            .map_err(|_| H4BridgeSourceResponseV2Error::Binding)?;
        let mut power = Fp16::ONE;
        let mut complete_masked_target = Fp16::ZERO;
        for claim in &verified.source_claims {
            complete_masked_target = complete_masked_target + power * claim.masked_value;
            power = power * claim_challenge;
        }
        // The bridge GKR source claims cover semantic-owned, verifier-fixed,
        // and H4-owned cells.  This Construction response authenticates only
        // the H4-owned contribution.  The non-H4 term is supplied through an
        // opaque Circle-adapter batch produced by the semantic verifier; it
        // is never a caller-selected scalar.
        let initial_target = complete_masked_target - authenticated_non_h4_target;
        Ok(Self {
            initial_target,
            claim_vector_binding,
            profile,
            shard_index,
            source_claims: verified.source_claims.clone(),
            source_circuits: verified.source_circuits.clone(),
            claim_challenge,
            #[cfg(test)]
            synthetic_folded_relation_weights: None,
        })
    }

    /// Construct one shard-local relation after the aggregate verifier has
    /// checked that the ordered shard targets sum to the complete H4-owned
    /// contribution.  This constructor is crate-private so a package caller
    /// cannot choose an independently adjustable shard target.
    pub(crate) fn from_verified_gkr_shard_target(
        profile: H4ProofProfileV2,
        shard_index: u8,
        verified: &VerifiedMaskedSemanticH4BridgeGkr,
        claim_challenge: Fp16,
        authenticated_shard_target: Fp16,
    ) -> Result<Self, H4BridgeSourceResponseV2Error> {
        if claim_challenge.is_zero()
            || shard_index >= profile.shard_count()
            || verified.source_claims.is_empty()
            || verified.source_claims.len() != verified.source_circuits.len()
            || verified
                .source_claims
                .iter()
                .any(|claim| claim.point.is_empty())
        {
            return Err(H4BridgeSourceResponseV2Error::Shape);
        }
        Ok(Self {
            initial_target: authenticated_shard_target,
            claim_vector_binding: semantic_h4_bridge_claim_vector_commitment(verified)
                .map_err(|_| H4BridgeSourceResponseV2Error::Binding)?,
            profile,
            shard_index,
            source_claims: verified.source_claims.clone(),
            source_circuits: verified.source_circuits.clone(),
            claim_challenge,
            #[cfg(test)]
            synthetic_folded_relation_weights: None,
        })
    }

    #[cfg(test)]
    fn synthetic(
        initial_target: Fp16,
        folded_relation_weights: Vec<Fp16>,
        claim_vector_binding: BindingDigestV2,
    ) -> Result<Self, H4BridgeSourceResponseV2Error> {
        if folded_relation_weights.len() != H4_BRIDGE_SOURCE_RESPONSE_LIVE_COEFFICIENTS
            || claim_vector_binding
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(H4BridgeSourceResponseV2Error::Shape);
        }
        Ok(Self {
            initial_target,
            claim_vector_binding,
            profile: H4ProofProfileV2::K128,
            shard_index: 0,
            source_claims: Vec::new(),
            source_circuits: Vec::new(),
            claim_challenge: Fp16::ONE,
            synthetic_folded_relation_weights: Some(folded_relation_weights),
        })
    }

    pub(crate) const fn claim_vector_binding(&self) -> BindingDigestV2 {
        self.claim_vector_binding
    }

    fn answer_target(
        &self,
        answer_coefficients: &[Fp16],
        row_challenges: &[Fp16],
    ) -> Result<Fp16, H4BridgeSourceResponseV2Error> {
        #[cfg(test)]
        if let Some(weights) = &self.synthetic_folded_relation_weights {
            return inner_product(
                &answer_coefficients[..H4_BRIDGE_SOURCE_RESPONSE_LIVE_COEFFICIENTS],
                weights,
            );
        }
        h4_source_answer_target(self, answer_coefficients, row_challenges)
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

fn profile(profile: H4ProofProfileV2) -> Profile {
    match profile {
        H4ProofProfileV2::K128 => Profile::K128Calibration,
        H4ProofProfileV2::K512 => Profile::K512Calibration,
    }
}

fn add_coordinate_scaled(target: &mut Fp16, coefficient: Fp16, value: Fp16, coordinate: usize) {
    if coefficient.is_zero() {
        return;
    }
    let scalar = M31::from_canonical(value.coefficients()[coordinate])
        .expect("an Fp16 coordinate is canonical M31");
    *target = *target + coefficient.mul_by_m31(scalar);
}

fn claim_weight(
    point: &[Fp16],
    wire_log: usize,
    virtual_wire: usize,
    virtual_group: usize,
) -> Result<Fp16, H4BridgeSourceResponseV2Error> {
    if point.len() < wire_log
        || virtual_wire >= 1_usize << wire_log
        || virtual_group >= 1_usize << (point.len() - wire_log)
    {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    Ok(equality_weight(virtual_wire, &point[..wire_log])
        * equality_weight(virtual_group, &point[wire_log..]))
}

/// Evaluate the exact verifier-fixed sparse map from the committed packed H4
/// source into the bridge RoundInput tables. This intentionally performs no
/// host-supplied coefficient lookup: profile, call schedule, shard, circuit,
/// points, and claim batching are all verifier-owned.
fn h4_source_answer_target(
    relation: &VerifiedH4BridgeRelationV2,
    answer: &[Fp16],
    row_challenges: &[Fp16],
) -> Result<Fp16, H4BridgeSourceResponseV2Error> {
    if answer.len() < H4_BRIDGE_SOURCE_RESPONSE_LIVE_COEFFICIENTS
        || row_challenges.len() != H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
    {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let descriptor = build_hash_bus_descriptor_with_state(profile(relation.profile))
        .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?;
    let shard_start = u64::from(relation.shard_index) * PERMUTATIONS_PER_COPROCESSOR_SHARD;
    let shard_end = shard_start + PERMUTATIONS_PER_COPROCESSOR_SHARD;
    let boundary_weights = [
        Fp16::ONE - row_challenges[WORD_VARIABLES],
        row_challenges[WORD_VARIABLES],
    ];
    let mut result = Fp16::ZERO;
    let mut claim_power = Fp16::ONE;
    for (claim, circuit) in relation.source_claims.iter().zip(&relation.source_circuits) {
        let (wire_log, expected_group_log) = match circuit {
            SemanticH4BridgeCircuit::Rate => (
                6,
                match relation.profile {
                    H4ProofProfileV2::K128 => 23,
                    H4ProofProfileV2::K512 => 25,
                },
            ),
            SemanticH4BridgeCircuit::Inactive | SemanticH4BridgeCircuit::Capacity => (12, 19),
            SemanticH4BridgeCircuit::Digest => (12, 24),
        };
        if claim.point.len() != wire_log + expected_group_log {
            return Err(H4BridgeSourceResponseV2Error::Shape);
        }
        for global_permutation in shard_start..shard_end.min(descriptor.total_permutations) {
            let slot = hash_bus_permutation_slot(&descriptor, global_permutation)
                .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?
                .ok_or(H4BridgeSourceResponseV2Error::Shape)?;
            let local = usize::try_from(global_permutation - shard_start)
                .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?;
            let lane = local & 15;
            let group = local >> 4;
            let within = group >> 5;
            let subgroup = group & 31;
            let row = equality_weight(within, &row_challenges[..WORD_VARIABLES]);
            match circuit {
                SemanticH4BridgeCircuit::Rate => {
                    for byte in 0..72_usize {
                        for bit in 0..8_usize {
                            let wire = 8 * byte + bit;
                            let position = wire + (subgroup << 11);
                            let input_weight = claim_weight(
                                &claim.point,
                                wire_log,
                                RATE_INPUT_BITS_START + bit,
                                usize::try_from(global_permutation)
                                    .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?
                                    * 72
                                    + byte,
                            )?;
                            add_coordinate_scaled(
                                &mut result,
                                claim_power * boundary_weights[0] * row * input_weight,
                                answer[position],
                                lane,
                            );
                            if slot.block_index + 1 < slot.blocks_in_call {
                                let predecessor_weight = claim_weight(
                                    &claim.point,
                                    wire_log,
                                    RATE_PREDECESSOR_BITS_START + bit,
                                    (usize::try_from(global_permutation)
                                        .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?
                                        + 1)
                                        * 72
                                        + byte,
                                )?;
                                add_coordinate_scaled(
                                    &mut result,
                                    claim_power * boundary_weights[1] * row * predecessor_weight,
                                    answer[position],
                                    lane,
                                );
                            }
                        }
                    }
                }
                SemanticH4BridgeCircuit::Inactive => {
                    for wire in 0..1_600_usize {
                        let position = wire + (subgroup << 11);
                        let weight = claim_weight(
                            &claim.point,
                            wire_log,
                            BLOCK_INPUT_BITS_START + wire,
                            usize::try_from(global_permutation)
                                .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?,
                        )?;
                        add_coordinate_scaled(
                            &mut result,
                            claim_power * boundary_weights[0] * row * weight,
                            answer[position],
                            lane,
                        );
                    }
                }
                SemanticH4BridgeCircuit::Capacity => {
                    for capacity_wire in 0..1_024_usize {
                        let wire = 576 + capacity_wire;
                        let position = wire + (subgroup << 11);
                        let input_weight = claim_weight(
                            &claim.point,
                            wire_log,
                            BLOCK_INPUT_BITS_START + capacity_wire,
                            usize::try_from(global_permutation)
                                .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?,
                        )?;
                        add_coordinate_scaled(
                            &mut result,
                            claim_power * boundary_weights[0] * row * input_weight,
                            answer[position],
                            lane,
                        );
                        if slot.block_index + 1 < slot.blocks_in_call {
                            let predecessor_weight = claim_weight(
                                &claim.point,
                                wire_log,
                                BLOCK_PREDECESSOR_BITS_START + capacity_wire,
                                usize::try_from(global_permutation)
                                    .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?
                                    + 1,
                            )?;
                            add_coordinate_scaled(
                                &mut result,
                                claim_power * boundary_weights[1] * row * predecessor_weight,
                                answer[position],
                                lane,
                            );
                        }
                    }
                }
                SemanticH4BridgeCircuit::Digest => {
                    if slot.block_index + 1 == slot.blocks_in_call {
                        for byte in 0..64_usize {
                            let virtual_group = usize::try_from(slot.call_index)
                                .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?
                                * 64
                                + byte;
                            let byte_weight = claim_weight(
                                &claim.point,
                                wire_log,
                                DIGEST_OUTPUT_BYTES_START + usize::from(slot.block_index),
                                virtual_group,
                            )?;
                            for bit in 0..8_usize {
                                let wire = 8 * byte + bit;
                                let position = wire + (subgroup << 11);
                                let bit_scale = Fp16::from_m31(
                                    M31::from_canonical(1_u32 << bit)
                                        .expect("byte bit weight is canonical"),
                                );
                                add_coordinate_scaled(
                                    &mut result,
                                    claim_power
                                        * boundary_weights[1]
                                        * row
                                        * byte_weight
                                        * bit_scale,
                                    answer[position],
                                    lane,
                                );
                            }
                        }
                    }
                }
            }
        }
        claim_power = claim_power * relation.claim_challenge;
    }
    Ok(result)
}

/// Openings produced only after native-128 multiproofs authenticate the
/// existing source segments and the bridge-base tensor at the exact same
/// completion-selected RS positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedH4BridgeResponseCodeOpeningsV2 {
    source_root: BindingRootV2,
    base_root: BindingRootV2,
    answer_binding: BindingDigestV2,
    positions: Vec<usize>,
    folded_source: Vec<Fp16>,
    folded_base: Vec<Fp16>,
}

impl VerifiedH4BridgeResponseCodeOpeningsV2 {
    pub(crate) fn from_native_multiproofs(
        source_root: BindingRootV2,
        base_root: BindingRootV2,
        answer_binding: BindingDigestV2,
        positions: Vec<usize>,
        folded_source: Vec<Fp16>,
        folded_base: Vec<Fp16>,
    ) -> Result<Self, H4BridgeSourceResponseV2Error> {
        if positions.is_empty()
            || positions.len() != folded_source.len()
            || positions.len() != folded_base.len()
            || positions.windows(2).any(|pair| pair[0] >= pair[1])
            || positions
                .last()
                .is_some_and(|position| *position >= H4_MAIN_CODE_VALUES)
            || answer_binding.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(H4BridgeSourceResponseV2Error::Shape);
        }
        Ok(Self {
            source_root,
            base_root,
            answer_binding,
            positions,
            folded_source,
            folded_base,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4BridgeSourceResponseV2 {
    pub row_sumcheck_rounds: Vec<[Fp16; H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES]>,
    pub answer_coefficients: Vec<Fp16>,
    pub answer_binding: BindingDigestV2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4BridgeSourceResponseStrictRoundV2 {
    pub descriptor: StrictPqRoundDescriptorV2,
    pub policy: StrictPqFp16PolicyV2,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct H4BridgeSourceResponseChallengesV2 {
    pub claim_challenge: Fp16,
    pub coordinate_challenge: Fp16,
    pub projection_challenges: Vec<Fp16>,
    pub row_challenges: Vec<Fp16>,
    pub response_seal_challenge: Fp16,
}

/// Opaque authority consumed by the bridge GKR source binder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedH4BridgeSourceResponseV2 {
    claim_vector_binding: BindingDigestV2,
    source_root: BindingRootV2,
    base_root: BindingRootV2,
    answer_binding: BindingDigestV2,
    masked_target: Fp16,
    row_challenges: Vec<Fp16>,
    source_claim_values: Vec<Fp16>,
}

impl VerifiedH4BridgeSourceResponseV2 {
    pub const fn claim_vector_binding(&self) -> BindingDigestV2 {
        self.claim_vector_binding
    }

    pub const fn answer_binding(&self) -> BindingDigestV2 {
        self.answer_binding
    }

    pub const fn source_root(&self) -> BindingRootV2 {
        self.source_root
    }

    pub const fn base_root(&self) -> BindingRootV2 {
        self.base_root
    }

    pub const fn masked_target(&self) -> Fp16 {
        self.masked_target
    }

    pub fn row_challenges(&self) -> &[Fp16] {
        &self.row_challenges
    }

    pub(crate) fn source_claim_values(&self) -> &[Fp16] {
        &self.source_claim_values
    }

    #[cfg(test)]
    pub(crate) fn synthetic_for_test(
        claim_vector_binding: BindingDigestV2,
        masked_target: Fp16,
    ) -> Self {
        Self::synthetic_for_test_with_claim_values(
            claim_vector_binding,
            masked_target,
            vec![masked_target],
        )
    }

    #[cfg(test)]
    pub(crate) fn synthetic_for_test_with_claim_values(
        claim_vector_binding: BindingDigestV2,
        masked_target: Fp16,
        source_claim_values: Vec<Fp16>,
    ) -> Self {
        let source_root = crate::binding_root_v2::BindingMerkleTreeV2::from_payloads(&[
            b"synthetic-h4-source".as_slice(),
        ])
        .unwrap()
        .root();
        let base_root = crate::binding_root_v2::BindingMerkleTreeV2::from_payloads(&[
            b"synthetic-h4-base".as_slice(),
        ])
        .unwrap()
        .root();
        let answer_binding =
            BindingDigestV2::hash(BindingRoleV2::Payload, b"synthetic-h4-answer").unwrap();
        Self {
            claim_vector_binding,
            source_root,
            base_root,
            answer_binding,
            masked_target,
            row_challenges: vec![Fp16::ONE; H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS],
            source_claim_values,
        }
    }
}

fn h4_source_answer_claim_values(
    relation: &VerifiedH4BridgeRelationV2,
    answer: &[Fp16],
    row_challenges: &[Fp16],
) -> Result<Vec<Fp16>, H4BridgeSourceResponseV2Error> {
    if relation.source_claims.is_empty()
        || relation.source_claims.len() != relation.source_circuits.len()
    {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let mut values = Vec::with_capacity(relation.source_claims.len());
    for (claim, circuit) in relation.source_claims.iter().zip(&relation.source_circuits) {
        let single = VerifiedH4BridgeRelationV2 {
            initial_target: Fp16::ZERO,
            claim_vector_binding: relation.claim_vector_binding,
            profile: relation.profile,
            shard_index: relation.shard_index,
            source_claims: vec![claim.clone()],
            source_circuits: vec![*circuit],
            claim_challenge: relation.claim_challenge,
            #[cfg(test)]
            synthetic_folded_relation_weights: None,
        };
        values.push(h4_source_answer_target(&single, answer, row_challenges)?);
    }
    let mut power = Fp16::ONE;
    let batched = values.iter().fold(Fp16::ZERO, |sum, value| {
        let result = sum + power * *value;
        power = power * relation.claim_challenge;
        result
    });
    if batched != h4_source_answer_target(relation, answer, row_challenges)? {
        return Err(H4BridgeSourceResponseV2Error::Functional);
    }
    Ok(values)
}

fn evaluate_quadratic(coefficients: [Fp16; 3], point: Fp16) -> Fp16 {
    coefficients[0] + point * (coefficients[1] + point * coefficients[2])
}

fn inner_product(left: &[Fp16], right: &[Fp16]) -> Result<Fp16, H4BridgeSourceResponseV2Error> {
    if left.len() != right.len() {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    Ok(left
        .iter()
        .zip(right)
        .fold(Fp16::ZERO, |sum, (left, right)| sum + *left * *right))
}

/// Build the Boolean table for the verifier-fixed H4 answer functional.
///
/// The first eleven coordinates are the row variables and the twelfth is the
/// boundary selector.  The table is accumulated directly from the sparse
/// functional rather than by repeatedly evaluating the full permutation
/// schedule.  This keeps the producer linear in the committed answer vector
/// and makes the row-sumcheck witness a derived value, not a caller-selected
/// target.
fn h4_source_answer_table(
    relation: &VerifiedH4BridgeRelationV2,
    answer: &[Fp16],
) -> Result<Vec<Fp16>, H4BridgeSourceResponseV2Error> {
    if answer.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let row_count = 1_usize << WORD_VARIABLES;
    let table_count = 1_usize << H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS;
    let mut table = vec![Fp16::ZERO; table_count];
    let descriptor = build_hash_bus_descriptor_with_state(profile(relation.profile))
        .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?;
    let shard_start = u64::from(relation.shard_index) * PERMUTATIONS_PER_COPROCESSOR_SHARD;
    let shard_end = shard_start + PERMUTATIONS_PER_COPROCESSOR_SHARD;
    let mut add = |within: usize,
                   boundary: usize,
                   coefficient: Fp16,
                   position: usize,
                   coordinate: usize|
     -> Result<(), H4BridgeSourceResponseV2Error> {
        if within >= row_count || boundary > 1 || position >= answer.len() || coordinate >= 16 {
            return Err(H4BridgeSourceResponseV2Error::Shape);
        }
        add_coordinate_scaled(
            table
                .get_mut(within | (boundary << WORD_VARIABLES))
                .ok_or(H4BridgeSourceResponseV2Error::Shape)?,
            coefficient,
            answer[position],
            coordinate,
        );
        Ok(())
    };

    let mut claim_power = Fp16::ONE;
    for (claim, circuit) in relation.source_claims.iter().zip(&relation.source_circuits) {
        let (wire_log, expected_group_log) = match circuit {
            SemanticH4BridgeCircuit::Rate => (
                6,
                match relation.profile {
                    H4ProofProfileV2::K128 => 23,
                    H4ProofProfileV2::K512 => 25,
                },
            ),
            SemanticH4BridgeCircuit::Inactive | SemanticH4BridgeCircuit::Capacity => (12, 19),
            SemanticH4BridgeCircuit::Digest => (12, 24),
        };
        if claim.point.len() != wire_log + expected_group_log {
            return Err(H4BridgeSourceResponseV2Error::Shape);
        }
        for global_permutation in shard_start..shard_end.min(descriptor.total_permutations) {
            let slot = hash_bus_permutation_slot(&descriptor, global_permutation)
                .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?
                .ok_or(H4BridgeSourceResponseV2Error::Shape)?;
            let local = usize::try_from(global_permutation - shard_start)
                .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?;
            let lane = local & 15;
            let group = local >> 4;
            let within = group >> 5;
            let subgroup = group & 31;
            let position_for = |wire: usize| wire + (subgroup << 11);
            match circuit {
                SemanticH4BridgeCircuit::Rate => {
                    for byte in 0..72_usize {
                        for bit in 0..8_usize {
                            let wire = 8 * byte + bit;
                            let position = position_for(wire);
                            let input_weight = claim_weight(
                                &claim.point,
                                wire_log,
                                RATE_INPUT_BITS_START + bit,
                                usize::try_from(global_permutation)
                                    .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?
                                    * 72
                                    + byte,
                            )?;
                            add(within, 0, claim_power * input_weight, position, lane)?;
                            if slot.block_index + 1 < slot.blocks_in_call {
                                let predecessor_weight = claim_weight(
                                    &claim.point,
                                    wire_log,
                                    RATE_PREDECESSOR_BITS_START + bit,
                                    (usize::try_from(global_permutation)
                                        .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?
                                        + 1)
                                        * 72
                                        + byte,
                                )?;
                                add(within, 1, claim_power * predecessor_weight, position, lane)?;
                            }
                        }
                    }
                }
                SemanticH4BridgeCircuit::Inactive => {
                    for wire in 0..1_600_usize {
                        let position = position_for(wire);
                        let weight = claim_weight(
                            &claim.point,
                            wire_log,
                            BLOCK_INPUT_BITS_START + wire,
                            usize::try_from(global_permutation)
                                .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?,
                        )?;
                        add(within, 0, claim_power * weight, position, lane)?;
                    }
                }
                SemanticH4BridgeCircuit::Capacity => {
                    for capacity_wire in 0..1_024_usize {
                        let wire = 576 + capacity_wire;
                        let position = position_for(wire);
                        let input_weight = claim_weight(
                            &claim.point,
                            wire_log,
                            BLOCK_INPUT_BITS_START + capacity_wire,
                            usize::try_from(global_permutation)
                                .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?,
                        )?;
                        add(within, 0, claim_power * input_weight, position, lane)?;
                        if slot.block_index + 1 < slot.blocks_in_call {
                            let predecessor_weight = claim_weight(
                                &claim.point,
                                wire_log,
                                BLOCK_PREDECESSOR_BITS_START + capacity_wire,
                                usize::try_from(global_permutation)
                                    .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?
                                    + 1,
                            )?;
                            add(within, 1, claim_power * predecessor_weight, position, lane)?;
                        }
                    }
                }
                SemanticH4BridgeCircuit::Digest => {
                    if slot.block_index + 1 == slot.blocks_in_call {
                        for byte in 0..64_usize {
                            let virtual_group = usize::try_from(slot.call_index)
                                .map_err(|_| H4BridgeSourceResponseV2Error::Shape)?
                                * 64
                                + byte;
                            let byte_weight = claim_weight(
                                &claim.point,
                                wire_log,
                                DIGEST_OUTPUT_BYTES_START + usize::from(slot.block_index),
                                virtual_group,
                            )?;
                            for bit in 0..8_usize {
                                let wire = 8 * byte + bit;
                                let position = position_for(wire);
                                let bit_scale = Fp16::from_m31(
                                    M31::from_canonical(1_u32 << bit)
                                        .expect("byte bit weight is canonical"),
                                );
                                add(
                                    within,
                                    1,
                                    claim_power * byte_weight * bit_scale,
                                    position,
                                    lane,
                                )?;
                            }
                        }
                    }
                }
            }
        }
        claim_power = claim_power * relation.claim_challenge;
    }
    Ok(table)
}

fn produce_multilinear_sumcheck(
    mut table: Vec<Fp16>,
    mut challenge_provider: impl FnMut(
        usize,
        &[Fp16; H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES],
    ) -> Result<Fp16, H4BridgeSourceResponseV2Error>,
) -> Result<
    (
        Vec<[Fp16; H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES]>,
        Vec<Fp16>,
        Fp16,
        Fp16,
    ),
    H4BridgeSourceResponseV2Error,
> {
    if table.is_empty() || !table.len().is_power_of_two() {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let initial_target = table
        .iter()
        .copied()
        .fold(Fp16::ZERO, |sum, value| sum + value);
    let rounds_count = table.len().ilog2() as usize;
    let mut rounds = Vec::with_capacity(rounds_count);
    let mut challenges = Vec::with_capacity(rounds_count);
    let mut active = table.len();
    for round_index in 0..rounds_count {
        let mut polynomial = [Fp16::ZERO; H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES];
        for pair in 0..active / 2 {
            let zero = table[2 * pair];
            let one = table[2 * pair + 1];
            polynomial[0] = polynomial[0] + zero;
            polynomial[1] = polynomial[1] + one - zero;
        }
        let challenge = challenge_provider(round_index, &polynomial)?;
        if challenge.is_zero() || challenge == Fp16::ONE {
            return Err(H4BridgeSourceResponseV2Error::ZeroChallenge);
        }
        for pair in 0..active / 2 {
            let zero = table[2 * pair];
            let one = table[2 * pair + 1];
            table[pair] = zero + challenge * (one - zero);
        }
        active /= 2;
        rounds.push(polynomial);
        challenges.push(challenge);
    }
    Ok((rounds, challenges, initial_target, table[0]))
}

/// Produce the degree-two multilinear row sumcheck for an authenticated H4
/// source/base pair.  The challenge provider is called only after each
/// polynomial is fully computed; a strict public-coin coordinator can therefore
/// absorb the exact published message before releasing its next challenge.
///
/// This function does not create roots, PCS openings, bridge-GKR receipts, or
/// strict transcript evidence.  Those remain separate verifier-owned seams.
pub(crate) fn produce_h4_bridge_source_response_v2(
    relation: &VerifiedH4BridgeRelationV2,
    source_coefficients: &[Fp16],
    base_coefficients: &[Fp16],
    construction_mix: Fp16,
    row_challenge_provider: impl FnMut(
        usize,
        &[Fp16; H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES],
    ) -> Result<Fp16, H4BridgeSourceResponseV2Error>,
) -> Result<H4BridgeSourceResponseV2, H4BridgeSourceResponseV2Error> {
    if source_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        || base_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        || construction_mix.is_zero()
    {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let answer_coefficients = source_coefficients
        .iter()
        .zip(base_coefficients)
        .map(|(source, base)| *source + construction_mix * *base)
        .collect::<Vec<_>>();
    let table = h4_source_answer_table(relation, &answer_coefficients)?;
    let (rounds, challenges, initial_target, final_target) =
        produce_multilinear_sumcheck(table, row_challenge_provider)?;
    if initial_target != relation.initial_target {
        return Err(H4BridgeSourceResponseV2Error::Functional);
    }
    let expected = h4_source_answer_target(relation, &answer_coefficients, &challenges)?;
    if final_target != expected {
        return Err(H4BridgeSourceResponseV2Error::Functional);
    }
    let answer_binding = response_answer_binding(
        relation,
        &challenges,
        construction_mix,
        &answer_coefficients,
    )?;
    Ok(H4BridgeSourceResponseV2 {
        row_sumcheck_rounds: rounds,
        answer_coefficients,
        answer_binding,
    })
}

/// Produce one shard response directly from verified bridge-GKR and semantic
/// source inputs.  The shard target is derived from the supplied source/base
/// coefficient vectors; it is never accepted as a caller scalar.  The native
/// completion path independently recomputes and authenticates that target from
/// the response, code openings, and the aggregate source binding.
#[allow(clippy::too_many_arguments)]
pub(crate) fn produce_h4_bridge_source_response_from_verified_gkr(
    profile: H4ProofProfileV2,
    shard_index: u8,
    verified_gkr: &VerifiedMaskedSemanticH4BridgeGkr,
    semantic_batch: &VerifiedSemanticBridgeSourceBatchV3,
    source_coefficients: &[Fp16],
    base_coefficients: &[Fp16],
    construction_mix: Fp16,
    row_challenge_provider: impl FnMut(
        usize,
        &[Fp16; H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES],
    ) -> Result<Fp16, H4BridgeSourceResponseV2Error>,
) -> Result<H4BridgeSourceResponseV2, H4BridgeSourceResponseV2Error> {
    let expected_profile = match verified_gkr.profile {
        SemanticH4BridgeProfile::K128 => H4ProofProfileV2::K128,
        SemanticH4BridgeProfile::K512 => H4ProofProfileV2::K512,
    };
    let claim_vector_binding = semantic_h4_bridge_claim_vector_commitment(verified_gkr)
        .map_err(|_| H4BridgeSourceResponseV2Error::Binding)?;
    if profile != expected_profile
        || semantic_batch.claim_vector_binding() != claim_vector_binding
        || semantic_batch.claim_challenge().is_zero()
        || shard_index >= profile.shard_count()
        || source_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        || base_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
    {
        return Err(H4BridgeSourceResponseV2Error::Binding);
    }
    let answer_coefficients = source_coefficients
        .iter()
        .zip(base_coefficients)
        .map(|(source, base)| *source + construction_mix * *base)
        .collect::<Vec<_>>();
    let mut relation = VerifiedH4BridgeRelationV2 {
        initial_target: Fp16::ZERO,
        claim_vector_binding,
        profile,
        shard_index,
        source_claims: verified_gkr.source_claims.clone(),
        source_circuits: verified_gkr.source_circuits.clone(),
        claim_challenge: semantic_batch.claim_challenge(),
        #[cfg(test)]
        synthetic_folded_relation_weights: None,
    };
    let table = h4_source_answer_table(&relation, &answer_coefficients)?;
    relation.initial_target = table
        .iter()
        .copied()
        .fold(Fp16::ZERO, |sum, value| sum + value);
    produce_h4_bridge_source_response_v2(
        &relation,
        source_coefficients,
        base_coefficients,
        construction_mix,
        row_challenge_provider,
    )
}

fn response_answer_binding(
    relation: &VerifiedH4BridgeRelationV2,
    row_challenges: &[Fp16],
    construction_mix: Fp16,
    coefficients: &[Fp16],
) -> Result<BindingDigestV2, H4BridgeSourceResponseV2Error> {
    if row_challenges.len() != H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
        || coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        || construction_mix.is_zero()
    {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let mut encoded = Vec::with_capacity(
        H4_BRIDGE_SOURCE_RESPONSE_ANSWER_DOMAIN.len()
            + 128
            + 64
            + row_challenges.len() * 64
            + 4
            + coefficients.len() * 64,
    );
    encoded.extend_from_slice(H4_BRIDGE_SOURCE_RESPONSE_ANSWER_DOMAIN);
    encoded.extend_from_slice(relation.claim_vector_binding.as_bytes());
    encoded.extend_from_slice(&construction_mix.encode());
    for challenge in row_challenges {
        encoded.extend_from_slice(&challenge.encode());
    }
    encoded.extend_from_slice(&(coefficients.len() as u32).to_be_bytes());
    for coefficient in coefficients {
        encoded.extend_from_slice(&coefficient.encode());
    }
    BindingDigestV2::hash(BindingRoleV2::Payload, &encoded)
        .map_err(|_| H4BridgeSourceResponseV2Error::Binding)
}

pub fn encode_h4_bridge_source_response_v2(
    response: &H4BridgeSourceResponseV2,
) -> Result<Vec<u8>, H4BridgeSourceResponseV2Error> {
    if response.row_sumcheck_rounds.len() != H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
        || response.answer_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
    {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let mut encoded = Vec::with_capacity(H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES);
    encoded.extend_from_slice(H4_BRIDGE_SOURCE_RESPONSE_V2_MAGIC);
    encoded.extend_from_slice(&H4_BRIDGE_SOURCE_RESPONSE_V2_VERSION.to_be_bytes());
    encoded.extend_from_slice(&0_u16.to_be_bytes());
    encoded.extend_from_slice(&(H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS as u32).to_be_bytes());
    encoded.extend_from_slice(&(H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS as u32).to_be_bytes());
    encoded.extend_from_slice(response.answer_binding.as_bytes());
    encoded.extend_from_slice(&[0_u8; 12]);
    for round in &response.row_sumcheck_rounds {
        for coefficient in round {
            encoded.extend_from_slice(&coefficient.encode());
        }
    }
    for coefficient in &response.answer_coefficients {
        encoded.extend_from_slice(&coefficient.encode());
    }
    if encoded.len() != H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES {
        return Err(H4BridgeSourceResponseV2Error::Encoding);
    }
    Ok(encoded)
}

pub fn decode_h4_bridge_source_response_v2(
    encoded: &[u8],
) -> Result<H4BridgeSourceResponseV2, H4BridgeSourceResponseV2Error> {
    if encoded.len() != H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES
        || encoded.get(..8) != Some(H4_BRIDGE_SOURCE_RESPONSE_V2_MAGIC)
        || u16::from_be_bytes(
            encoded[8..10]
                .try_into()
                .map_err(|_| H4BridgeSourceResponseV2Error::Encoding)?,
        ) != H4_BRIDGE_SOURCE_RESPONSE_V2_VERSION
        || encoded[10..12] != [0_u8; 2]
        || u32::from_be_bytes(
            encoded[12..16]
                .try_into()
                .map_err(|_| H4BridgeSourceResponseV2Error::Encoding)?,
        ) as usize
            != H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
        || u32::from_be_bytes(
            encoded[16..20]
                .try_into()
                .map_err(|_| H4BridgeSourceResponseV2Error::Encoding)?,
        ) as usize
            != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        || encoded[148..160] != [0_u8; 12]
    {
        return Err(H4BridgeSourceResponseV2Error::Encoding);
    }
    let answer_binding = BindingDigestV2::decode(&encoded[20..148])
        .map_err(|_| H4BridgeSourceResponseV2Error::Encoding)?;
    let mut offset = H4_BRIDGE_SOURCE_RESPONSE_HEADER_BYTES;
    let mut row_sumcheck_rounds = Vec::with_capacity(H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS);
    for _ in 0..H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS {
        let mut round = [Fp16::ZERO; 3];
        for coefficient in &mut round {
            *coefficient = Fp16::decode(&encoded[offset..offset + 64])
                .map_err(|_| H4BridgeSourceResponseV2Error::Encoding)?;
            offset += 64;
        }
        row_sumcheck_rounds.push(round);
    }
    let mut answer_coefficients = Vec::with_capacity(H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS);
    while offset < encoded.len() {
        answer_coefficients.push(
            Fp16::decode(&encoded[offset..offset + 64])
                .map_err(|_| H4BridgeSourceResponseV2Error::Encoding)?,
        );
        offset += 64;
    }
    if answer_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS {
        return Err(H4BridgeSourceResponseV2Error::Encoding);
    }
    Ok(H4BridgeSourceResponseV2 {
        row_sumcheck_rounds,
        answer_coefficients,
        answer_binding,
    })
}

fn strict_descriptor(
    kind: u16,
    ordinal: u32,
    output_count: u16,
) -> Result<StrictPqRoundDescriptorV2, H4BridgeSourceResponseV2Error> {
    StrictPqRoundDescriptorV2::new(kind, ordinal, output_count)
        .map_err(|_| H4BridgeSourceResponseV2Error::Encoding)
}

/// Build the canonical prelude message before the row sumcheck exists.
///
/// This is public so a producer can release the first governed challenge
/// before it computes the row polynomials. It is the same constructor used by
/// the serialized-response verifier; callers cannot alter its domain or
/// field ordering.
pub fn h4_bridge_source_response_strict_prelude_round_v2(
    context: BindingDigestV2,
    claim_vector_binding: BindingDigestV2,
    first_ordinal: u32,
) -> Result<H4BridgeSourceResponseStrictRoundV2, H4BridgeSourceResponseV2Error> {
    let mut message = H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_DOMAIN.to_vec();
    message.extend_from_slice(context.as_bytes());
    message.extend_from_slice(claim_vector_binding.as_bytes());
    Ok(H4BridgeSourceResponseStrictRoundV2 {
        descriptor: strict_descriptor(
            H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_KIND,
            first_ordinal,
            H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_OUTPUTS as u16,
        )?,
        policy: StrictPqFp16PolicyV2::NonzeroNonone,
        message,
    })
}

/// Build one canonical row-sumcheck message after the polynomial is known.
pub fn h4_bridge_source_response_strict_row_round_v2(
    context: BindingDigestV2,
    first_ordinal: u32,
    row_index: usize,
    polynomial: &[Fp16; H4_BRIDGE_SOURCE_RESPONSE_MESSAGE_VALUES],
) -> Result<H4BridgeSourceResponseStrictRoundV2, H4BridgeSourceResponseV2Error> {
    if row_index >= H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let ordinal = first_ordinal
        .checked_add(1 + row_index as u32)
        .ok_or(H4BridgeSourceResponseV2Error::Encoding)?;
    let mut message = H4_BRIDGE_SOURCE_RESPONSE_ROW_DOMAIN.to_vec();
    message.extend_from_slice(context.as_bytes());
    message.extend_from_slice(&(row_index as u16).to_be_bytes());
    message.extend_from_slice(&0_u16.to_be_bytes());
    for coefficient in polynomial {
        message.extend_from_slice(&coefficient.encode());
    }
    Ok(H4BridgeSourceResponseStrictRoundV2 {
        descriptor: strict_descriptor(H4_BRIDGE_SOURCE_RESPONSE_ROW_KIND, ordinal, 1)?,
        policy: StrictPqFp16PolicyV2::NonzeroNonone,
        message,
    })
}

/// Build the final answer-binding message after the response coefficients and
/// row challenges have been fixed.
pub fn h4_bridge_source_response_strict_answer_round_v2(
    response: &H4BridgeSourceResponseV2,
    context: BindingDigestV2,
    first_ordinal: u32,
) -> Result<H4BridgeSourceResponseStrictRoundV2, H4BridgeSourceResponseV2Error> {
    if response.row_sumcheck_rounds.len() != H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
        || response.answer_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
    {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let answer_ordinal = first_ordinal
        .checked_add(1 + H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS as u32)
        .ok_or(H4BridgeSourceResponseV2Error::Encoding)?;
    let mut message = H4_BRIDGE_SOURCE_RESPONSE_ANSWER_DOMAIN.to_vec();
    message.extend_from_slice(context.as_bytes());
    message.extend_from_slice(response.answer_binding.as_bytes());
    Ok(H4BridgeSourceResponseStrictRoundV2 {
        descriptor: strict_descriptor(H4_BRIDGE_SOURCE_RESPONSE_ANSWER_KIND, answer_ordinal, 1)?,
        policy: StrictPqFp16PolicyV2::Nonzero,
        message,
    })
}

/// Canonical parent-901-anchored child schedule.  Each quadratic is committed
/// before its own challenge; the answer binding is committed only after the
/// final row challenge and before the separate parent completion coin.
pub fn h4_bridge_source_response_strict_rounds_v2(
    response: &H4BridgeSourceResponseV2,
    context: BindingDigestV2,
    claim_vector_binding: BindingDigestV2,
    first_ordinal: u32,
) -> Result<Vec<H4BridgeSourceResponseStrictRoundV2>, H4BridgeSourceResponseV2Error> {
    if response.row_sumcheck_rounds.len() != H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
        || response.answer_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
    {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let mut rounds = Vec::with_capacity(H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS + 2);
    rounds.push(h4_bridge_source_response_strict_prelude_round_v2(
        context,
        claim_vector_binding,
        first_ordinal,
    )?);
    for (index, polynomial) in response.row_sumcheck_rounds.iter().enumerate() {
        rounds.push(h4_bridge_source_response_strict_row_round_v2(
            context,
            first_ordinal,
            index,
            polynomial,
        )?);
    }
    rounds.push(h4_bridge_source_response_strict_answer_round_v2(
        response,
        context,
        first_ordinal,
    )?);
    Ok(rounds)
}

pub fn h4_bridge_source_response_challenges_v2(
    outputs: &[StrictPqFp16RoundOutputV2],
    first_ordinal: u32,
) -> Result<H4BridgeSourceResponseChallengesV2, H4BridgeSourceResponseV2Error> {
    if outputs.len() != H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS + 2 {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }
    let prelude = outputs[0].challenges();
    if prelude.descriptor().kind() != H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_KIND
        || prelude.descriptor().ordinal() != first_ordinal
        || prelude.descriptor().output_count() != H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_OUTPUTS as u16
        || prelude.policy() != StrictPqFp16PolicyV2::NonzeroNonone
        || prelude.samples().len() != H4_BRIDGE_SOURCE_RESPONSE_PRELUDE_OUTPUTS
    {
        return Err(H4BridgeSourceResponseV2Error::Encoding);
    }
    let mut row_challenges = Vec::with_capacity(H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS);
    for (index, output) in outputs[1..=H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS]
        .iter()
        .enumerate()
    {
        let batch = output.challenges();
        if batch.descriptor().kind() != H4_BRIDGE_SOURCE_RESPONSE_ROW_KIND
            || batch.descriptor().ordinal() != first_ordinal + 1 + index as u32
            || batch.descriptor().output_count() != 1
            || batch.policy() != StrictPqFp16PolicyV2::NonzeroNonone
            || batch.samples().len() != 1
        {
            return Err(H4BridgeSourceResponseV2Error::Encoding);
        }
        row_challenges.push(batch.samples()[0].element());
    }
    let answer = outputs.last().expect("length checked").challenges();
    if answer.descriptor().kind() != H4_BRIDGE_SOURCE_RESPONSE_ANSWER_KIND
        || answer.descriptor().ordinal()
            != first_ordinal + 1 + H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS as u32
        || answer.descriptor().output_count() != 1
        || answer.policy() != StrictPqFp16PolicyV2::Nonzero
        || answer.samples().len() != 1
    {
        return Err(H4BridgeSourceResponseV2Error::Encoding);
    }
    Ok(H4BridgeSourceResponseChallengesV2 {
        claim_challenge: prelude.samples()[0].element(),
        coordinate_challenge: prelude.samples()[1].element(),
        projection_challenges: prelude.samples()[2..]
            .iter()
            .map(|sample| sample.element())
            .collect(),
        row_challenges,
        response_seal_challenge: answer.samples()[0].element(),
    })
}

pub fn h4_bridge_source_response_strict_schedule_commitment_v2(
    response: &H4BridgeSourceResponseV2,
    context: BindingDigestV2,
    claim_vector_binding: BindingDigestV2,
    first_ordinal: u32,
) -> Result<[u8; 64], H4BridgeSourceResponseV2Error> {
    let rounds = h4_bridge_source_response_strict_rounds_v2(
        response,
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    let mut hash = Sha3_512::new();
    hash.update(H4_BRIDGE_SOURCE_RESPONSE_STRICT_SCHEDULE_DOMAIN);
    hash.update(context.as_bytes());
    hash.update(claim_vector_binding.as_bytes());
    hash.update(first_ordinal.to_be_bytes());
    hash.update(
        u32::try_from(rounds.len())
            .map_err(|_| H4BridgeSourceResponseV2Error::Encoding)?
            .to_be_bytes(),
    );
    for round in rounds {
        hash.update(round.descriptor.encode());
        hash.update([round.policy.code()]);
    }
    Ok(hash.finalize().into())
}

/// Replay the exact post-z response transcript against its governed key.
/// Registry mutation is transactional: a malformed response or failed replay
/// cannot consume a strict-PQ root-use reservation.
#[allow(clippy::too_many_arguments)]
pub fn verify_strict_h4_bridge_source_response_v2(
    encoded_bundle: &[u8],
    governed_key: &StrictPqGovernedVerifierKeyV2,
    profile: H4ProofProfileV2,
    response: &H4BridgeSourceResponseV2,
    context: BindingDigestV2,
    claim_vector_binding: BindingDigestV2,
    first_ordinal: u32,
    registry: &mut StrictPqRootUseRegistryV2,
) -> Result<VerifiedStrictH4BridgeSourceResponseV2, H4BridgeSourceResponseV2Error> {
    let rounds = h4_bridge_source_response_strict_rounds_v2(
        response,
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    let expected_schedule = h4_bridge_source_response_strict_schedule_commitment_v2(
        response,
        context,
        claim_vector_binding,
        first_ordinal,
    )?;
    if governed_key.schedule_commitment() != &expected_schedule
        || usize::try_from(governed_key.round_count()).ok() != Some(rounds.len())
    {
        return Err(H4BridgeSourceResponseV2Error::Transcript);
    }
    let bundle = StrictPqPublicCoinBundleV2::decode(encoded_bundle)
        .map_err(|_| H4BridgeSourceResponseV2Error::Transcript)?;
    let policies = rounds.iter().map(|round| round.policy).collect::<Vec<_>>();
    let messages = rounds
        .iter()
        .map(|round| round.message.as_slice())
        .collect::<Vec<_>>();
    let strict_profile = match profile {
        H4ProofProfileV2::K128 => StrictPqH4ProfileV2::K128,
        H4ProofProfileV2::K512 => StrictPqH4ProfileV2::K512,
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
    .map_err(|_| H4BridgeSourceResponseV2Error::Transcript)?;
    let challenges = h4_bridge_source_response_challenges_v2(&outputs, first_ordinal)?;
    *registry = pending;
    Ok(VerifiedStrictH4BridgeSourceResponseV2 {
        challenges,
        context,
        claim_vector_binding,
        final_transcript_root: *bundle.final_transcript_root(),
    })
}

/// Verify the complete post-z row reduction and the completion-selected code
/// relation.  Challenges and relation weights are verifier-owned inputs; the
/// response cannot select them through its encoding.
pub(crate) fn verify_h4_bridge_source_response_v2(
    response: &H4BridgeSourceResponseV2,
    relation: &VerifiedH4BridgeRelationV2,
    row_challenges: &[Fp16],
    construction_mix: Fp16,
    openings: &VerifiedH4BridgeResponseCodeOpeningsV2,
) -> Result<VerifiedH4BridgeSourceResponseV2, H4BridgeSourceResponseV2Error> {
    if response.row_sumcheck_rounds.len() != H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
        || row_challenges.len() != H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
        || response.answer_coefficients.len() != H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        || construction_mix.is_zero()
        || row_challenges
            .iter()
            .any(|challenge| challenge.is_zero() || *challenge == Fp16::ONE)
        || response.answer_binding != openings.answer_binding
    {
        return Err(H4BridgeSourceResponseV2Error::Shape);
    }

    if response.answer_binding
        != response_answer_binding(
            relation,
            row_challenges,
            construction_mix,
            &response.answer_coefficients,
        )?
    {
        return Err(H4BridgeSourceResponseV2Error::Binding);
    }

    let mut expected = relation.initial_target;
    for (round, challenge) in response
        .row_sumcheck_rounds
        .iter()
        .copied()
        .zip(row_challenges)
    {
        if round[0] + evaluate_quadratic(round, Fp16::ONE) != expected {
            return Err(H4BridgeSourceResponseV2Error::Sumcheck);
        }
        expected = evaluate_quadratic(round, *challenge);
    }
    let answer_target = relation.answer_target(&response.answer_coefficients, row_challenges)?;
    if answer_target != expected {
        return Err(H4BridgeSourceResponseV2Error::Functional);
    }
    #[cfg(test)]
    let source_claim_values = if relation.synthetic_folded_relation_weights.is_some() {
        Vec::new()
    } else {
        h4_source_answer_claim_values(relation, &response.answer_coefficients, row_challenges)?
    };
    #[cfg(not(test))]
    let source_claim_values =
        h4_source_answer_claim_values(relation, &response.answer_coefficients, row_challenges)?;

    let answer_code = encode_codeword(&response.answer_coefficients, H4_MAIN_CODE_VALUES.ilog2())
        .map_err(|_| H4BridgeSourceResponseV2Error::Code)?;
    for ((position, source), base) in openings
        .positions
        .iter()
        .zip(&openings.folded_source)
        .zip(&openings.folded_base)
    {
        if answer_code
            .get(*position)
            .is_none_or(|answer| *answer != *source + construction_mix * *base)
        {
            return Err(H4BridgeSourceResponseV2Error::Code);
        }
    }

    Ok(VerifiedH4BridgeSourceResponseV2 {
        claim_vector_binding: relation.claim_vector_binding,
        source_root: openings.source_root,
        base_root: openings.base_root,
        answer_binding: response.answer_binding,
        masked_target: relation.initial_target,
        row_challenges: row_challenges.to_vec(),
        source_claim_values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding_root_v2::BindingRoleV2;
    use alloc::vec;

    fn fp(value: u32) -> Fp16 {
        Fp16::from_coefficients([value, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
    }

    #[test]
    fn hand_computed_four_variable_answer_target_matches_paper() {
        // Variables are least-significant-bit first.  At (1,0,1,0), index
        // 0b0101 is selected, so the hand-written source vector evaluates to
        // its sixth element: 17.
        let source = [3_u32, 5, 7, 11, 13, 17, 19, 23]
            .into_iter()
            .map(fp)
            .collect::<Vec<_>>();
        let point = [fp(1), fp(0), fp(1), fp(0)];
        let expected = fp(17);
        let weights = (0..source.len())
            .map(|index| equality_weight(index, &point))
            .collect::<Vec<_>>();
        assert_eq!(weights[5], Fp16::ONE);
        assert!(
            weights
                .iter()
                .enumerate()
                .all(|(index, weight)| index == 5 || weight.is_zero())
        );
        assert_eq!(inner_product(&source, &weights).unwrap(), expected);
    }

    #[test]
    fn hand_computed_two_variable_sumcheck_matches_all_four_rows() {
        // The table is indexed least-significant-variable first.  Its sum is
        // 3+5+7+11=26.  At challenges (13,17), folding gives
        // (10,6) then (29,30), and the final evaluation is 29+17*30=539.
        let table = [3_u32, 5, 7, 11].into_iter().map(fp).collect::<Vec<_>>();
        let challenges = [fp(13), fp(17)];
        let (rounds, observed, initial, final_value) =
            produce_multilinear_sumcheck(table, |index, _| Ok(challenges[index])).unwrap();
        assert_eq!(initial, fp(26));
        assert_eq!(rounds[0], [fp(10), fp(6), Fp16::ZERO]);
        assert_eq!(rounds[1], [fp(29), fp(30), Fp16::ZERO]);
        assert_eq!(observed, challenges);
        assert_eq!(final_value, fp(539));
    }

    fn digest(label: &[u8]) -> BindingDigestV2 {
        BindingDigestV2::hash(BindingRoleV2::Payload, label).unwrap()
    }

    fn fixture() -> (
        H4BridgeSourceResponseV2,
        VerifiedH4BridgeRelationV2,
        Vec<Fp16>,
        Fp16,
        VerifiedH4BridgeResponseCodeOpeningsV2,
    ) {
        let live = H4_BRIDGE_SOURCE_RESPONSE_LIVE_COEFFICIENTS;
        let total = H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS;
        let source = (0..total)
            .map(|index| fp((index as u32 * 17 + 3) % 1_000_003))
            .collect::<Vec<_>>();
        let base = (0..total)
            .map(|index| fp((index as u32 * 29 + 5) % 1_000_033))
            .collect::<Vec<_>>();
        let mix = fp(41);
        let answer = source
            .iter()
            .zip(&base)
            .map(|(source, base)| *source + mix * *base)
            .collect::<Vec<_>>();
        let weights = (0..live)
            .map(|index| fp((index as u32 * 7 + 11) % 1_000_037))
            .collect::<Vec<_>>();
        let answer_target = inner_product(&answer[..live], &weights).unwrap();
        let two = fp(2);
        let initial_target = (0..H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS)
            .fold(answer_target, |value, _| value * two);
        let challenges = (0..H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS)
            .map(|index| fp(101 + index as u32 * 13))
            .collect::<Vec<_>>();
        let mut expected = initial_target;
        let mut rounds = Vec::new();
        for challenge in &challenges {
            let half = expected * two.inverse().unwrap();
            let round = [half, Fp16::ZERO, Fp16::ZERO];
            expected = evaluate_quadratic(round, *challenge);
            rounds.push(round);
        }
        debug_assert_eq!(expected, answer_target);

        let relation =
            VerifiedH4BridgeRelationV2::synthetic(initial_target, weights, digest(b"claims"))
                .unwrap();
        let answer_binding = response_answer_binding(&relation, &challenges, mix, &answer).unwrap();
        let positions = vec![3, 97, 4_001];
        let source_code = encode_codeword(&source, H4_MAIN_CODE_VALUES.ilog2()).unwrap();
        let base_code = encode_codeword(&base, H4_MAIN_CODE_VALUES.ilog2()).unwrap();
        let openings = VerifiedH4BridgeResponseCodeOpeningsV2::from_native_multiproofs(
            crate::binding_root_v2::BindingMerkleTreeV2::from_payloads(&[b"source".as_slice()])
                .unwrap()
                .root(),
            crate::binding_root_v2::BindingMerkleTreeV2::from_payloads(&[b"base".as_slice()])
                .unwrap()
                .root(),
            answer_binding,
            positions.clone(),
            positions.iter().map(|index| source_code[*index]).collect(),
            positions.iter().map(|index| base_code[*index]).collect(),
        )
        .unwrap();
        (
            H4BridgeSourceResponseV2 {
                row_sumcheck_rounds: rounds,
                answer_coefficients: answer,
                answer_binding,
            },
            relation,
            challenges,
            mix,
            openings,
        )
    }

    #[test]
    fn post_z_response_accepts_and_mutations_reject() {
        let (response, relation, challenges, mix, openings) = fixture();
        assert_eq!(
            response.row_sumcheck_rounds.len(),
            H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS
        );
        assert_eq!(challenges.len(), H4_BRIDGE_SOURCE_RESPONSE_SUMCHECK_ROUNDS);
        assert_eq!(
            response.answer_coefficients.len(),
            H4_BRIDGE_SOURCE_RESPONSE_COEFFICIENTS
        );
        assert_ne!(mix, Fp16::ZERO);
        assert!(
            challenges
                .iter()
                .all(|challenge| !challenge.is_zero() && *challenge != Fp16::ONE)
        );
        assert_eq!(response.answer_binding, openings.answer_binding);
        let verified =
            verify_h4_bridge_source_response_v2(&response, &relation, &challenges, mix, &openings)
                .unwrap();
        assert_eq!(verified.masked_target(), relation.initial_target);
        let encoded = encode_h4_bridge_source_response_v2(&response).unwrap();
        assert_eq!(encoded.len(), H4_BRIDGE_SOURCE_RESPONSE_V2_BYTES);
        assert_eq!(
            decode_h4_bridge_source_response_v2(&encoded).unwrap(),
            response
        );
        let mut malformed = encoded;
        malformed[148] = 1;
        assert_eq!(
            decode_h4_bridge_source_response_v2(&malformed),
            Err(H4BridgeSourceResponseV2Error::Encoding)
        );

        let mut changed = response.clone();
        changed.answer_coefficients[29] = changed.answer_coefficients[29] + Fp16::ONE;
        assert_eq!(
            verify_h4_bridge_source_response_v2(&changed, &relation, &challenges, mix, &openings,),
            Err(H4BridgeSourceResponseV2Error::Binding)
        );

        let mut changed_openings = openings.clone();
        changed_openings.folded_source[0] = changed_openings.folded_source[0] + Fp16::ONE;
        assert_eq!(
            verify_h4_bridge_source_response_v2(
                &response,
                &relation,
                &challenges,
                mix,
                &changed_openings,
            ),
            Err(H4BridgeSourceResponseV2Error::Code)
        );

        let mut changed = response;
        changed.row_sumcheck_rounds[0][0] = changed.row_sumcheck_rounds[0][0] + Fp16::ONE;
        assert_eq!(
            verify_h4_bridge_source_response_v2(&changed, &relation, &challenges, mix, &openings,),
            Err(H4BridgeSourceResponseV2Error::Sumcheck)
        );
    }
}
