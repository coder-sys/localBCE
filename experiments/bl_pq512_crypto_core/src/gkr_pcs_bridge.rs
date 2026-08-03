//! Exact fail-closed boundary from the packed Boolean GKR terminal to MLPCS.

use core::fmt;

use crate::field::Fp16;
use crate::gkr_sumcheck::LayerOutputClaim;
use crate::multilinear_pcs::{
    MLPCS_INPUT_LOG_SIZE, MultilinearOpeningClaim, PackedGkrInputClaims, PackedGkrOutputClaim,
};
use crate::packed_boolean_sumcheck::PACK_BITS;
use crate::state_relation_gkr::{
    STATE_RELATION_WIRE_VARIABLES, StateRelationGkrProof, state_relation_input_claims,
    verify_state_relation_gkr,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GkrPcsBridgeError {
    ClaimCount,
    PointDimension,
    Coefficient,
    WireVariables,
    StateRelation,
}

impl fmt::Display for GkrPcsBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GKR-to-PCS bridge error: {self:?}")
    }
}

impl core::error::Error for GkrPcsBridgeError {}

/// Bind the two final GKR claims and shared degree-7 shard query exactly.
///
/// The first GKR layer returns two unmixed claims. Any residual coefficient,
/// missing claim, dimension drift, or impossible wire/group split is rejected.
pub fn bind_repeated_pack_gkr_terminals(
    claims: &[LayerOutputClaim],
    shard_query: Fp16,
    wire_variables: u8,
) -> Result<PackedGkrInputClaims, GkrPcsBridgeError> {
    let base_variables = usize::from(MLPCS_INPUT_LOG_SIZE) - PACK_BITS.trailing_zeros() as usize;
    if claims.len() != 2 {
        return Err(GkrPcsBridgeError::ClaimCount);
    }
    if claims
        .iter()
        .any(|claim| claim.point.len() != base_variables)
    {
        return Err(GkrPcsBridgeError::PointDimension);
    }
    if claims.iter().any(|claim| claim.coefficient != Fp16::ONE) {
        return Err(GkrPcsBridgeError::Coefficient);
    }
    if usize::from(wire_variables) > base_variables {
        return Err(GkrPcsBridgeError::WireVariables);
    }
    Ok(PackedGkrInputClaims {
        claims: core::array::from_fn(|index| MultilinearOpeningClaim {
            point: claims[index].point.clone(),
            value: claims[index].value,
        }),
        shard_query,
        wire_variables,
    })
}

/// Bind the single full-state GKR output claim to the semantic output table.
pub fn bind_repeated_pack_gkr_output(
    claim: &LayerOutputClaim,
    shard_query: Fp16,
    wire_variables: u8,
) -> Result<PackedGkrOutputClaim, GkrPcsBridgeError> {
    let base_variables = usize::from(MLPCS_INPUT_LOG_SIZE) - PACK_BITS.trailing_zeros() as usize;
    if claim.point.len() != base_variables {
        return Err(GkrPcsBridgeError::PointDimension);
    }
    if claim.coefficient != Fp16::ONE {
        return Err(GkrPcsBridgeError::Coefficient);
    }
    if usize::from(wire_variables) > base_variables {
        return Err(GkrPcsBridgeError::WireVariables);
    }
    Ok(PackedGkrOutputClaim {
        claim: MultilinearOpeningClaim {
            point: claim.point.clone(),
            value: claim.value,
        },
        shard_query,
        wire_variables,
    })
}

/// Bind the proof-native compact state relation to the exact selected PCS
/// input geometry. The relation has six wire variables and twelve fixed
/// state-row variables; the remaining three packed variables belong to the
/// shared PCS shard interpolation. The proof is verified before its
/// terminals cross this boundary, so a caller cannot turn raw terminal values
/// into a receipt field by host-side equality.
pub fn bind_state_relation_gkr_terminals(
    proof: &StateRelationGkrProof,
    shard_query: Fp16,
) -> Result<PackedGkrInputClaims, GkrPcsBridgeError> {
    verify_state_relation_gkr(proof).map_err(|_| GkrPcsBridgeError::StateRelation)?;
    let claims = state_relation_input_claims(proof, shard_query)
        .map_err(|_| GkrPcsBridgeError::StateRelation)?;
    let expected_base_variables =
        usize::from(MLPCS_INPUT_LOG_SIZE) - PACK_BITS.trailing_zeros() as usize;
    if claims.wire_variables != STATE_RELATION_WIRE_VARIABLES as u8
        || claims.claims.iter().any(|claim| {
            claim.point.len() != expected_base_variables
                || claim.point.len() != STATE_RELATION_WIRE_VARIABLES + proof.group_challenges.len()
        })
    {
        return Err(GkrPcsBridgeError::StateRelation);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn bridge_accepts_only_exact_two_unmixed_terminal_claims() {
        let claims = [
            LayerOutputClaim {
                point: vec![Fp16::ZERO; 18],
                value: Fp16::ONE,
                coefficient: Fp16::ONE,
            },
            LayerOutputClaim {
                point: vec![Fp16::ONE; 18],
                value: Fp16::ZERO,
                coefficient: Fp16::ONE,
            },
        ];
        let bound = bind_repeated_pack_gkr_terminals(&claims, Fp16::ONE, 11).unwrap();
        assert_eq!(bound.claims[0].value, Fp16::ONE);
        assert_eq!(bound.claims[1].point, vec![Fp16::ONE; 18]);

        let mut changed = claims.clone();
        changed[1].coefficient = Fp16::ZERO;
        assert_eq!(
            bind_repeated_pack_gkr_terminals(&changed, Fp16::ONE, 11),
            Err(GkrPcsBridgeError::Coefficient)
        );
        assert_eq!(
            bind_repeated_pack_gkr_terminals(&claims[..1], Fp16::ONE, 11),
            Err(GkrPcsBridgeError::ClaimCount)
        );
    }

    #[test]
    fn output_bridge_accepts_only_one_unmixed_full_state_claim() {
        let claim = LayerOutputClaim {
            point: vec![Fp16::ZERO; 18],
            value: Fp16::ONE,
            coefficient: Fp16::ONE,
        };
        let bound = bind_repeated_pack_gkr_output(&claim, Fp16::ONE, 11).unwrap();
        assert_eq!(bound.claim.value, Fp16::ONE);
        let changed = LayerOutputClaim {
            coefficient: Fp16::ZERO,
            ..claim
        };
        assert_eq!(
            bind_repeated_pack_gkr_output(&changed, Fp16::ONE, 11),
            Err(GkrPcsBridgeError::Coefficient)
        );
    }
}
