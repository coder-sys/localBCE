//! Auditable SHA3-512 Circle-FRI proof engine over the frozen Fp16 tower.
//!
//! Challenges and query positions are explicit authoritative public-coin
//! inputs.  This module enforces commitment-before-challenge structure in its
//! proof object, but the caller remains responsible for authenticating each
//! challenge receipt before invoking the prover or verifier.

use alloc::vec::Vec;

use crate::circle_fri::{
    CircleFriError, fold_circle_into_line, fold_circle_pair, fold_line, fold_line_pair,
};
use crate::field::Fp16;
use crate::merkle::{MerkleError, MerkleProof, MerkleTree, RootHash};

/// Smallest accepted evaluation domain.
pub const MIN_FRI_EVALUATIONS: usize = 4;

/// One authenticated pair opened in a committed FRI layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriPairOpening {
    /// Even member in the layer's bit-reversed pair ordering.
    pub left: Fp16,
    /// Odd member in the layer's bit-reversed pair ordering.
    pub right: Fp16,
    /// Authentication proof for `left`.
    pub left_proof: MerkleProof,
    /// Authentication proof for `right`.
    pub right_proof: MerkleProof,
}

/// All pair openings for one public query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FriQueryProof {
    /// Original query index before pair projection.
    pub initial_index: usize,
    /// One pair opening for every folded committed layer.
    pub layers: Vec<FriPairOpening>,
}

/// A complete low-degree proof relative to externally authenticated challenges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircleFriProof {
    /// Initial evaluation count.
    pub evaluation_count: usize,
    /// Strict upper bound on the polynomial coefficient count.
    pub degree_bound: usize,
    /// Commitment root before every challenge plus the final-layer root.
    pub layer_roots: Vec<RootHash>,
    /// Complete small terminal layer, required to be constant.
    pub final_layer: Vec<Fp16>,
    /// Authenticated paths for every requested query.
    pub queries: Vec<FriQueryProof>,
}

/// Strict construction or verification failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FriProofError {
    Shape,
    DegreeBound,
    ChallengeCount,
    QueryOutOfBounds,
    QueryCount,
    RootMismatch,
    Authentication,
    FoldMismatch,
    FinalLayerNotConstant,
    CircleFri(CircleFriError),
    Merkle(MerkleError),
}

impl From<CircleFriError> for FriProofError {
    fn from(value: CircleFriError) -> Self {
        Self::CircleFri(value)
    }
}

impl From<MerkleError> for FriProofError {
    fn from(value: MerkleError) -> Self {
        Self::Merkle(value)
    }
}

fn validate_shape(
    evaluation_count: usize,
    degree_bound: usize,
    challenge_count: usize,
) -> Result<usize, FriProofError> {
    if evaluation_count < MIN_FRI_EVALUATIONS || !evaluation_count.is_power_of_two() {
        return Err(FriProofError::Shape);
    }
    if degree_bound < 2 || !degree_bound.is_power_of_two() || degree_bound >= evaluation_count {
        return Err(FriProofError::DegreeBound);
    }
    let folds = degree_bound.ilog2() as usize;
    if challenge_count != folds {
        return Err(FriProofError::ChallengeCount);
    }
    Ok(folds)
}

fn tree_for_layer(values: &[Fp16]) -> Result<MerkleTree, FriProofError> {
    let encoded = values
        .iter()
        .map(|value| value.encode().to_vec())
        .collect::<Vec<_>>();
    let leaves = encoded.iter().map(Vec::as_slice).collect::<Vec<_>>();
    Ok(MerkleTree::from_leaf_payloads(&leaves)?)
}

fn fold_layer(values: &[Fp16], challenge: Fp16, first: bool) -> Result<Vec<Fp16>, FriProofError> {
    Ok(if first {
        fold_circle_into_line(values, challenge)?
    } else {
        fold_line(values, challenge)?
    })
}

/// Produce one Circle-FRI proof for the exact public-coin inputs.
pub fn prove_circle_fri(
    evaluations: &[Fp16],
    degree_bound: usize,
    fold_challenges: &[Fp16],
    query_indices: &[usize],
) -> Result<CircleFriProof, FriProofError> {
    let folds = validate_shape(evaluations.len(), degree_bound, fold_challenges.len())?;
    if query_indices.is_empty() {
        return Err(FriProofError::QueryCount);
    }
    if query_indices
        .iter()
        .any(|index| *index >= evaluations.len())
    {
        return Err(FriProofError::QueryOutOfBounds);
    }

    let mut layers = Vec::with_capacity(folds + 1);
    let mut trees = Vec::with_capacity(folds + 1);
    layers.push(evaluations.to_vec());
    trees.push(tree_for_layer(evaluations)?);
    for (round, challenge) in fold_challenges.iter().copied().enumerate() {
        let next = fold_layer(&layers[round], challenge, round == 0)?;
        trees.push(tree_for_layer(&next)?);
        layers.push(next);
    }
    let final_layer = layers.last().ok_or(FriProofError::Shape)?.clone();
    if final_layer.iter().any(|value| *value != final_layer[0]) {
        return Err(FriProofError::FinalLayerNotConstant);
    }

    let mut queries = Vec::with_capacity(query_indices.len());
    for initial_index in query_indices.iter().copied() {
        let mut index = initial_index;
        let mut openings = Vec::with_capacity(folds);
        for round in 0..folds {
            let pair_start = (index >> 1) << 1;
            openings.push(FriPairOpening {
                left: layers[round][pair_start],
                right: layers[round][pair_start + 1],
                left_proof: trees[round].proof(pair_start)?,
                right_proof: trees[round].proof(pair_start + 1)?,
            });
            index >>= 1;
        }
        queries.push(FriQueryProof {
            initial_index,
            layers: openings,
        });
    }
    Ok(CircleFriProof {
        evaluation_count: evaluations.len(),
        degree_bound,
        layer_roots: trees.iter().map(MerkleTree::root).collect(),
        final_layer,
        queries,
    })
}

/// Verify one proof against an independently obtained initial commitment root.
pub fn verify_circle_fri(
    proof: &CircleFriProof,
    expected_initial_root: RootHash,
    fold_challenges: &[Fp16],
    expected_query_indices: &[usize],
) -> Result<bool, FriProofError> {
    let folds = validate_shape(
        proof.evaluation_count,
        proof.degree_bound,
        fold_challenges.len(),
    )?;
    if proof.layer_roots.len() != folds + 1
        || proof.final_layer.len() != proof.evaluation_count >> folds
        || proof.final_layer.is_empty()
    {
        return Err(FriProofError::Shape);
    }
    if proof.layer_roots[0] != expected_initial_root {
        return Ok(false);
    }
    if proof
        .final_layer
        .iter()
        .any(|value| *value != proof.final_layer[0])
    {
        return Ok(false);
    }
    if tree_for_layer(&proof.final_layer)?.root() != proof.layer_roots[folds] {
        return Ok(false);
    }
    if proof.queries.len() != expected_query_indices.len()
        || proof
            .queries
            .iter()
            .zip(expected_query_indices)
            .any(|(query, expected)| query.initial_index != *expected)
    {
        return Err(FriProofError::QueryCount);
    }

    for query in &proof.queries {
        if query.initial_index >= proof.evaluation_count || query.layers.len() != folds {
            return Err(FriProofError::QueryOutOfBounds);
        }
        let mut index = query.initial_index;
        let mut layer_size = proof.evaluation_count;
        for (round, opening) in query.layers.iter().enumerate() {
            let pair_start = (index >> 1) << 1;
            if opening.left_proof.leaf_index() != pair_start
                || opening.right_proof.leaf_index() != pair_start + 1
                || opening.left_proof.leaf_count() != layer_size
                || opening.right_proof.leaf_count() != layer_size
                || !opening
                    .left_proof
                    .verify(&opening.left.encode(), &proof.layer_roots[round])?
                || !opening
                    .right_proof
                    .verify(&opening.right.encode(), &proof.layer_roots[round])?
            {
                return Ok(false);
            }
            let log_size = layer_size.ilog2() as u8;
            let pair = [opening.left, opening.right];
            let folded = if round == 0 {
                fold_circle_pair(&pair, index >> 1, log_size, fold_challenges[round])?
            } else {
                fold_line_pair(&pair, index >> 1, log_size, fold_challenges[round])?
            };
            index >>= 1;
            layer_size >>= 1;
            let expected = if round + 1 == folds {
                proof.final_layer[index]
            } else {
                let next = &query.layers[round + 1];
                if index & 1 == 0 {
                    next.left
                } else {
                    next.right
                }
            };
            if folded != expected {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circle_fft::evaluate_extension_circle_coefficients;
    use crate::field::M31;
    use alloc::vec;

    fn fp16(value: u32) -> Fp16 {
        Fp16::from_m31(M31::from_canonical(value).unwrap())
    }

    #[test]
    fn proves_and_verifies_strict_degree_bound() {
        let mut coefficients = vec![Fp16::ZERO; 32];
        for (index, value) in coefficients[..8].iter_mut().enumerate() {
            *value = fp16((index * index + 3 * index + 9) as u32);
        }
        let evaluations = evaluate_extension_circle_coefficients(&coefficients, 5).unwrap();
        let challenges = [fp16(5), fp16(7), fp16(11)];
        let queries = [0, 1, 7, 19, 31];
        let proof = prove_circle_fri(&evaluations, 8, &challenges, &queries).unwrap();
        assert_eq!(proof.final_layer.len(), 4);
        assert!(verify_circle_fri(&proof, proof.layer_roots[0], &challenges, &queries).unwrap());
    }

    #[test]
    fn rejects_high_degree_and_every_opening_mutation() {
        let coefficients = (0..32).map(|value| fp16(value + 1)).collect::<Vec<_>>();
        let evaluations = evaluate_extension_circle_coefficients(&coefficients, 5).unwrap();
        let challenges = [fp16(5), fp16(7), fp16(11)];
        assert_eq!(
            prove_circle_fri(&evaluations, 8, &challenges, &[3]),
            Err(FriProofError::FinalLayerNotConstant)
        );

        let mut low = coefficients;
        low[8..].fill(Fp16::ZERO);
        let evaluations = evaluate_extension_circle_coefficients(&low, 5).unwrap();
        let proof = prove_circle_fri(&evaluations, 8, &challenges, &[3]).unwrap();
        let mut forged = proof.clone();
        forged.queries[0].layers[1].left = fp16(123);
        assert!(!verify_circle_fri(&forged, proof.layer_roots[0], &challenges, &[3]).unwrap());
        let mut forged = proof.clone();
        forged.final_layer[0] = fp16(123);
        assert!(!verify_circle_fri(&forged, proof.layer_roots[0], &challenges, &[3]).unwrap());
    }
}
