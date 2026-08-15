//! Native-128 multilinear opening proof used by the semantic/H4 bridge.
//!
//! Coefficients are committed through a rate-16 multiplicative-subgroup code.
//! Folding challenges are the verifier-owned multilinear point.  Every folded
//! layer is fixed before a separate completion coin selects query positions.
//! No legacy 64-byte Merkle object is accepted by this module.

use alloc::vec::Vec;

use sha3::{Digest, Sha3_512};

use crate::{
    binding_root_v2::{
        BindingDigestV2, BindingMerkleMultiProofV2, BindingMerkleTreeV2, BindingRoleV2,
        BindingRootV2, BindingRootV2Error,
    },
    field::Fp16,
    multilinear_pcs::{
        derive_two_adic_root, evaluate_univariate_lde, fold_multiplicative_fri_layer,
        verify_multiplicative_batch_fold,
    },
};

pub const BINDING_MLPCS_V2_MAGIC: &[u8; 8] = b"BLMLPC02";
pub const BINDING_MLPCS_V2_VERSION: u16 = 2;
pub const BINDING_MLPCS_V2_RATE_LOG: u8 = 4;
pub const BINDING_MLPCS_V2_VALUES_PER_LEAF: usize = 16;
/// Frozen selected multilinear query count.  This matches the existing
/// theorem-selected MLPCS lane; smaller convenient counts are not accepted.
pub const BINDING_MLPCS_V2_QUERY_COUNT: usize = 473;
pub const BINDING_MLPCS_V2_MAX_VARIABLES: usize = 15;
pub const BINDING_MLPCS_V2_MAX_PROOF_BYTES: usize = 32 << 20;
const LEAF_DOMAIN: &[u8] = b"BL/PQ512/BINDING-MLPCS/LEAF/v2\0";
const QUERY_DOMAIN: &[u8] = b"BL/PQ512/BINDING-MLPCS/QUERY/v2\0";
const ROOTS_DOMAIN: &[u8] = b"BL/PQ512/BINDING-MLPCS/ROOTS/v2\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingMultilinearLayerOpeningV2 {
    pub leaf_indices: Vec<u64>,
    pub leaf_values: Vec<[Fp16; BINDING_MLPCS_V2_VALUES_PER_LEAF]>,
    pub multiproof: BindingMerkleMultiProofV2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingMultilinearPcsProofV2 {
    pub context: BindingDigestV2,
    pub roots: Vec<BindingRootV2>,
    pub layers: Vec<BindingMultilinearLayerOpeningV2>,
    pub terminal_values: [Fp16; BINDING_MLPCS_V2_VALUES_PER_LEAF],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBindingMultilinearOpeningV2 {
    root: BindingRootV2,
    point: Vec<Fp16>,
    value: Fp16,
    roots_commitment: BindingDigestV2,
}

impl VerifiedBindingMultilinearOpeningV2 {
    pub const fn root(&self) -> BindingRootV2 {
        self.root
    }
    pub fn point(&self) -> &[Fp16] {
        &self.point
    }
    pub const fn value(&self) -> Fp16 {
        self.value
    }
    pub const fn roots_commitment(&self) -> BindingDigestV2 {
        self.roots_commitment
    }

    #[cfg(test)]
    pub(crate) fn synthetic_for_test(root: BindingRootV2, point: Vec<Fp16>, value: Fp16) -> Self {
        Self {
            root,
            point,
            value,
            roots_commitment: BindingDigestV2::hash(BindingRoleV2::Payload, root.as_bytes())
                .expect("synthetic native root hashes"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingMultilinearPcsV2Error {
    Shape,
    Context,
    Query,
    Authentication,
    Fold,
    Terminal,
    Encoding,
    Binding(BindingRootV2Error),
}

impl From<BindingRootV2Error> for BindingMultilinearPcsV2Error {
    fn from(value: BindingRootV2Error) -> Self {
        Self::Binding(value)
    }
}

fn hypercube_values_to_monomial(
    values: &[Fp16],
) -> Result<Vec<Fp16>, BindingMultilinearPcsV2Error> {
    if values.is_empty() || !values.len().is_power_of_two() {
        return Err(BindingMultilinearPcsV2Error::Shape);
    }
    let mut coefficients = values.to_vec();
    for coordinate in 0..values.len().ilog2() {
        let half = 1usize << coordinate;
        for block in coefficients.chunks_exact_mut(2 * half) {
            for index in 0..half {
                block[half + index] = block[half + index] - block[index];
            }
        }
    }
    Ok(coefficients)
}

fn layer_leaf_payload(
    context: BindingDigestV2,
    layer: usize,
    values: &[Fp16; BINDING_MLPCS_V2_VALUES_PER_LEAF],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEAF_DOMAIN.len() + 128 + 4 + 16 * 64);
    out.extend_from_slice(LEAF_DOMAIN);
    out.extend_from_slice(context.as_bytes());
    out.extend_from_slice(&(layer as u32).to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.encode());
    }
    out
}

fn layer_payloads(
    context: BindingDigestV2,
    layer: usize,
    values: &[Fp16],
) -> Result<Vec<Vec<u8>>, BindingMultilinearPcsV2Error> {
    if values.len() < 16 || !values.len().is_power_of_two() || !values.len().is_multiple_of(16) {
        return Err(BindingMultilinearPcsV2Error::Shape);
    }
    Ok(values
        .chunks_exact(16)
        .map(|chunk| {
            let array: [Fp16; 16] = chunk.try_into().expect("exact chunk");
            layer_leaf_payload(context, layer, &array)
        })
        .collect())
}

/// Commit the first encoded layer of an already materialized multilinear
/// value table.  The returned root is exactly the first root later emitted
/// by [`prove_binding_multilinear_opening_v2`], but computing it
/// does not require a query point or completion coin.  This is the pre-Z
/// commitment boundary for reusable coefficient vectors.
pub fn binding_multilinear_root_v2(
    hypercube_values: &[Fp16],
    context: BindingDigestV2,
) -> Result<BindingRootV2, BindingMultilinearPcsV2Error> {
    if hypercube_values.len() < 8
        || !hypercube_values.len().is_power_of_two()
        || hypercube_values.len().ilog2() as usize > BINDING_MLPCS_V2_MAX_VARIABLES
    {
        return Err(BindingMultilinearPcsV2Error::Shape);
    }
    let coefficients = hypercube_values_to_monomial(hypercube_values)?;
    let values = evaluate_univariate_lde(&coefficients, BINDING_MLPCS_V2_RATE_LOG)
        .map_err(|_| BindingMultilinearPcsV2Error::Shape)?;
    Ok(BindingMerkleTreeV2::from_payloads(&layer_payloads(context, 0, &values)?)?.root())
}

fn roots_commitment(
    context: BindingDigestV2,
    roots: &[BindingRootV2],
) -> Result<BindingDigestV2, BindingMultilinearPcsV2Error> {
    let mut bytes = Vec::with_capacity(ROOTS_DOMAIN.len() + 128 + 4 + roots.len() * 128);
    bytes.extend_from_slice(ROOTS_DOMAIN);
    bytes.extend_from_slice(context.as_bytes());
    bytes.extend_from_slice(&(roots.len() as u32).to_be_bytes());
    for root in roots {
        bytes.extend_from_slice(root.as_bytes());
    }
    Ok(BindingDigestV2::hash(BindingRoleV2::Payload, &bytes)?)
}

fn query_positions(
    completion_coin: BindingDigestV2,
    roots_commitment: BindingDigestV2,
    domain_size: usize,
) -> Result<Vec<usize>, BindingMultilinearPcsV2Error> {
    if domain_size == 0 || !domain_size.is_power_of_two() {
        return Err(BindingMultilinearPcsV2Error::Shape);
    }
    Ok((0..BINDING_MLPCS_V2_QUERY_COUNT)
        .map(|draw| {
            let digest = Sha3_512::digest(
                [
                    QUERY_DOMAIN,
                    completion_coin.as_bytes(),
                    roots_commitment.as_bytes(),
                    &(draw as u32).to_be_bytes(),
                ]
                .concat(),
            );
            let low = u64::from_be_bytes(digest[56..64].try_into().expect("digest suffix"));
            low as usize & (domain_size - 1)
        })
        .collect())
}

fn selected_leaf_indices(queries: &[usize], value_count: usize) -> Vec<u64> {
    let half = value_count / 2;
    let mut indices = Vec::with_capacity(2 * queries.len());
    for query in queries {
        let base = query % half;
        indices.push((base / 16) as u64);
        indices.push(((base + half) / 16) as u64);
    }
    indices.sort_unstable();
    indices.dedup();
    indices
}

fn opened_value(
    opening: &BindingMultilinearLayerOpeningV2,
    index: usize,
) -> Result<Fp16, BindingMultilinearPcsV2Error> {
    let leaf = (index / 16) as u64;
    let position = opening
        .leaf_indices
        .binary_search(&leaf)
        .map_err(|_| BindingMultilinearPcsV2Error::Query)?;
    Ok(opening.leaf_values[position][index % 16])
}

fn take<'a>(
    encoded: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], BindingMultilinearPcsV2Error> {
    let end = offset
        .checked_add(length)
        .ok_or(BindingMultilinearPcsV2Error::Encoding)?;
    let value = encoded
        .get(*offset..end)
        .ok_or(BindingMultilinearPcsV2Error::Encoding)?;
    *offset = end;
    Ok(value)
}

pub fn encode_binding_multilinear_pcs_proof_v2(
    proof: &BindingMultilinearPcsProofV2,
) -> Result<Vec<u8>, BindingMultilinearPcsV2Error> {
    if proof.roots.is_empty()
        || proof.roots.len() > BINDING_MLPCS_V2_MAX_VARIABLES
        || proof.layers.len() != proof.roots.len()
    {
        return Err(BindingMultilinearPcsV2Error::Shape);
    }
    let mut out = Vec::new();
    out.extend_from_slice(BINDING_MLPCS_V2_MAGIC);
    out.extend_from_slice(&BINDING_MLPCS_V2_VERSION.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(proof.context.as_bytes());
    out.extend_from_slice(&(proof.roots.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    for root in &proof.roots {
        out.extend_from_slice(root.as_bytes());
    }
    for layer in &proof.layers {
        if layer.leaf_indices.is_empty() || layer.leaf_indices.len() != layer.leaf_values.len() {
            return Err(BindingMultilinearPcsV2Error::Shape);
        }
        out.extend_from_slice(&(layer.leaf_indices.len() as u32).to_be_bytes());
        for (index, values) in layer.leaf_indices.iter().zip(&layer.leaf_values) {
            out.extend_from_slice(&index.to_be_bytes());
            for value in values {
                out.extend_from_slice(&value.encode());
            }
        }
        let multiproof = layer.multiproof.encode()?;
        out.extend_from_slice(&(multiproof.len() as u32).to_be_bytes());
        out.extend_from_slice(&multiproof);
    }
    for value in proof.terminal_values {
        out.extend_from_slice(&value.encode());
    }
    if out.len() > BINDING_MLPCS_V2_MAX_PROOF_BYTES {
        return Err(BindingMultilinearPcsV2Error::Encoding);
    }
    Ok(out)
}

pub fn decode_binding_multilinear_pcs_proof_v2(
    encoded: &[u8],
) -> Result<BindingMultilinearPcsProofV2, BindingMultilinearPcsV2Error> {
    if encoded.len() > BINDING_MLPCS_V2_MAX_PROOF_BYTES || encoded.len() < 1172 {
        return Err(BindingMultilinearPcsV2Error::Encoding);
    }
    let mut offset = 0usize;
    if take(encoded, &mut offset, 8)? != BINDING_MLPCS_V2_MAGIC
        || u16::from_be_bytes(
            take(encoded, &mut offset, 2)?
                .try_into()
                .map_err(|_| BindingMultilinearPcsV2Error::Encoding)?,
        ) != BINDING_MLPCS_V2_VERSION
        || take(encoded, &mut offset, 2)? != [0u8; 2]
    {
        return Err(BindingMultilinearPcsV2Error::Encoding);
    }
    let context = BindingDigestV2::decode(take(encoded, &mut offset, 128)?)?;
    let layer_count = usize::from(u16::from_be_bytes(
        take(encoded, &mut offset, 2)?
            .try_into()
            .map_err(|_| BindingMultilinearPcsV2Error::Encoding)?,
    ));
    if layer_count == 0
        || layer_count > BINDING_MLPCS_V2_MAX_VARIABLES
        || take(encoded, &mut offset, 2)? != [0u8; 2]
    {
        return Err(BindingMultilinearPcsV2Error::Encoding);
    }
    let mut roots = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        roots.push(BindingRootV2::decode(take(encoded, &mut offset, 128)?)?);
    }
    let mut layers = Vec::with_capacity(layer_count);
    for _ in 0..layer_count {
        let count = usize::try_from(u32::from_be_bytes(
            take(encoded, &mut offset, 4)?
                .try_into()
                .map_err(|_| BindingMultilinearPcsV2Error::Encoding)?,
        ))
        .map_err(|_| BindingMultilinearPcsV2Error::Encoding)?;
        if count == 0 || count > 2 * BINDING_MLPCS_V2_QUERY_COUNT {
            return Err(BindingMultilinearPcsV2Error::Encoding);
        }
        let mut leaf_indices = Vec::with_capacity(count);
        let mut leaf_values = Vec::with_capacity(count);
        for _ in 0..count {
            leaf_indices.push(u64::from_be_bytes(
                take(encoded, &mut offset, 8)?
                    .try_into()
                    .map_err(|_| BindingMultilinearPcsV2Error::Encoding)?,
            ));
            let mut values = [Fp16::ZERO; 16];
            for value in &mut values {
                *value = Fp16::decode(take(encoded, &mut offset, 64)?)
                    .map_err(|_| BindingMultilinearPcsV2Error::Encoding)?;
            }
            leaf_values.push(values);
        }
        let proof_len = usize::try_from(u32::from_be_bytes(
            take(encoded, &mut offset, 4)?
                .try_into()
                .map_err(|_| BindingMultilinearPcsV2Error::Encoding)?,
        ))
        .map_err(|_| BindingMultilinearPcsV2Error::Encoding)?;
        let multiproof = BindingMerkleMultiProofV2::decode(take(encoded, &mut offset, proof_len)?)?;
        layers.push(BindingMultilinearLayerOpeningV2 {
            leaf_indices,
            leaf_values,
            multiproof,
        });
    }
    let mut terminal_values = [Fp16::ZERO; 16];
    for value in &mut terminal_values {
        *value = Fp16::decode(take(encoded, &mut offset, 64)?)
            .map_err(|_| BindingMultilinearPcsV2Error::Encoding)?;
    }
    if offset != encoded.len() {
        return Err(BindingMultilinearPcsV2Error::Encoding);
    }
    Ok(BindingMultilinearPcsProofV2 {
        context,
        roots,
        layers,
        terminal_values,
    })
}

/// In-memory reference prover. Production callers may replace only the tree
/// construction with an external-memory byte-identical implementation.
pub fn prove_binding_multilinear_opening_v2(
    hypercube_values: &[Fp16],
    point: &[Fp16],
    context: BindingDigestV2,
    completion_coin: BindingDigestV2,
) -> Result<BindingMultilinearPcsProofV2, BindingMultilinearPcsV2Error> {
    if hypercube_values.len()
        != 1usize
            .checked_shl(point.len() as u32)
            .ok_or(BindingMultilinearPcsV2Error::Shape)?
        || point.is_empty()
        || point.len() > BINDING_MLPCS_V2_MAX_VARIABLES
    {
        return Err(BindingMultilinearPcsV2Error::Shape);
    }
    let coefficients = hypercube_values_to_monomial(hypercube_values)?;
    let mut values = evaluate_univariate_lde(&coefficients, BINDING_MLPCS_V2_RATE_LOG)
        .map_err(|_| BindingMultilinearPcsV2Error::Shape)?;
    let mut all_values = Vec::with_capacity(point.len());
    let mut roots = Vec::with_capacity(point.len());
    for (layer, challenge) in point.iter().copied().enumerate() {
        let payloads = layer_payloads(context, layer, &values)?;
        let tree = BindingMerkleTreeV2::from_payloads(&payloads)?;
        roots.push(tree.root());
        all_values.push((values, tree));
        let root = derive_two_adic_root(
            (hypercube_values.len().ilog2() as u8 + BINDING_MLPCS_V2_RATE_LOG) - layer as u8,
        )
        .map_err(|_| BindingMultilinearPcsV2Error::Shape)?;
        values =
            fold_multiplicative_fri_layer(&all_values.last().expect("pushed").0, root, challenge)
                .map_err(|_| BindingMultilinearPcsV2Error::Fold)?;
    }
    if values.len() != 16 {
        return Err(BindingMultilinearPcsV2Error::Terminal);
    }
    let terminal_values: [Fp16; 16] = values
        .try_into()
        .map_err(|_| BindingMultilinearPcsV2Error::Terminal)?;
    let roots_binding = roots_commitment(context, &roots)?;
    let initial_queries =
        query_positions(completion_coin, roots_binding, hypercube_values.len() << 4)?;
    let mut queries = initial_queries;
    let mut layers = Vec::with_capacity(point.len());
    for (layer_values, tree) in all_values {
        let indices = selected_leaf_indices(&queries, layer_values.len());
        let leaf_values = indices
            .iter()
            .map(|index| {
                let start = *index as usize * 16;
                layer_values[start..start + 16]
                    .try_into()
                    .expect("leaf slice")
            })
            .collect::<Vec<[Fp16; 16]>>();
        let multiproof = tree.prove(&indices)?;
        layers.push(BindingMultilinearLayerOpeningV2 {
            leaf_indices: indices,
            leaf_values,
            multiproof,
        });
        queries = queries
            .into_iter()
            .map(|query| query % (layer_values.len() / 2))
            .collect();
    }
    Ok(BindingMultilinearPcsProofV2 {
        context,
        roots,
        layers,
        terminal_values,
    })
}

fn boolean_table_fold_coordinates(
    point: &[Fp16],
) -> Result<(Vec<Fp16>, Fp16), BindingMultilinearPcsV2Error> {
    if point.is_empty() || point.len() > BINDING_MLPCS_V2_MAX_VARIABLES {
        return Err(BindingMultilinearPcsV2Error::Shape);
    }
    let mut scale = Fp16::ONE;
    let mut coordinates = Vec::with_capacity(point.len());
    for coordinate in point {
        let one_minus = Fp16::ONE - *coordinate;
        if one_minus.is_zero() {
            return Err(BindingMultilinearPcsV2Error::Shape);
        }
        scale = scale * one_minus;
        coordinates.push(
            *coordinate
                * one_minus
                    .inverse()
                    .map_err(|_| BindingMultilinearPcsV2Error::Shape)?,
        );
    }
    Ok((coordinates, scale))
}

/// Commit an already materialized Boolean-hypercube table without applying a
/// second Moebius transform.  The multiplicative FRI fold computes
/// `left + t*right`; choosing `t=r/(1-r)` and tracking the product of
/// `(1-r)` makes its terminal exactly the ordinary multilinear interpolation
/// `left*(1-r)+right*r`.
///
/// This is the source-response path used when the committed RS coefficients
/// are the canonical H4 Boolean-table values themselves.  It shares the exact
/// proof grammar and Merkle domains with [`prove_binding_multilinear_opening_v2`].
pub fn prove_binding_boolean_table_opening_v2(
    table_values: &[Fp16],
    point: &[Fp16],
    context: BindingDigestV2,
    completion_coin: BindingDigestV2,
) -> Result<BindingMultilinearPcsProofV2, BindingMultilinearPcsV2Error> {
    if table_values.len()
        != 1usize
            .checked_shl(point.len() as u32)
            .ok_or(BindingMultilinearPcsV2Error::Shape)?
    {
        return Err(BindingMultilinearPcsV2Error::Shape);
    }
    let (fold_coordinates, _) = boolean_table_fold_coordinates(point)?;
    prove_binding_multilinear_coefficients_v2(
        table_values,
        &fold_coordinates,
        context,
        completion_coin,
    )
}

fn prove_binding_multilinear_coefficients_v2(
    coefficients: &[Fp16],
    fold_coordinates: &[Fp16],
    context: BindingDigestV2,
    completion_coin: BindingDigestV2,
) -> Result<BindingMultilinearPcsProofV2, BindingMultilinearPcsV2Error> {
    if coefficients.len()
        != 1usize
            .checked_shl(fold_coordinates.len() as u32)
            .ok_or(BindingMultilinearPcsV2Error::Shape)?
        || fold_coordinates.is_empty()
        || fold_coordinates.len() > BINDING_MLPCS_V2_MAX_VARIABLES
    {
        return Err(BindingMultilinearPcsV2Error::Shape);
    }
    let mut values = evaluate_univariate_lde(coefficients, BINDING_MLPCS_V2_RATE_LOG)
        .map_err(|_| BindingMultilinearPcsV2Error::Shape)?;
    let mut all_values = Vec::with_capacity(fold_coordinates.len());
    let mut roots = Vec::with_capacity(fold_coordinates.len());
    for (layer, challenge) in fold_coordinates.iter().copied().enumerate() {
        let payloads = layer_payloads(context, layer, &values)?;
        let tree = BindingMerkleTreeV2::from_payloads(&payloads)?;
        roots.push(tree.root());
        all_values.push((values, tree));
        let root = derive_two_adic_root(
            (coefficients.len().ilog2() as u8 + BINDING_MLPCS_V2_RATE_LOG) - layer as u8,
        )
        .map_err(|_| BindingMultilinearPcsV2Error::Shape)?;
        values =
            fold_multiplicative_fri_layer(&all_values.last().expect("pushed").0, root, challenge)
                .map_err(|_| BindingMultilinearPcsV2Error::Fold)?;
    }
    if values.len() != BINDING_MLPCS_V2_VALUES_PER_LEAF {
        return Err(BindingMultilinearPcsV2Error::Terminal);
    }
    let terminal_values = values
        .try_into()
        .map_err(|_| BindingMultilinearPcsV2Error::Terminal)?;
    let roots_binding = roots_commitment(context, &roots)?;
    let mut queries = query_positions(completion_coin, roots_binding, coefficients.len() << 4)?;
    let mut layers = Vec::with_capacity(fold_coordinates.len());
    for (layer_values, tree) in all_values {
        let indices = selected_leaf_indices(&queries, layer_values.len());
        let leaf_values = indices
            .iter()
            .map(|index| {
                let start = *index as usize * BINDING_MLPCS_V2_VALUES_PER_LEAF;
                layer_values[start..start + BINDING_MLPCS_V2_VALUES_PER_LEAF]
                    .try_into()
                    .expect("leaf slice")
            })
            .collect::<Vec<[Fp16; BINDING_MLPCS_V2_VALUES_PER_LEAF]>>();
        let multiproof = tree.prove(&indices)?;
        layers.push(BindingMultilinearLayerOpeningV2 {
            leaf_indices: indices,
            leaf_values,
            multiproof,
        });
        queries = queries
            .into_iter()
            .map(|query| query % (layer_values.len() / 2))
            .collect();
    }
    Ok(BindingMultilinearPcsProofV2 {
        context,
        roots,
        layers,
        terminal_values,
    })
}

/// Open one verifier-selected tensor-basis linear functional of an already
/// committed coefficient vector.  Unlike [`prove_binding_multilinear_opening_v2`],
/// this entry point does not apply a Moebius transform: `coefficients` are the
/// exact values authenticated by the first native-128 layer root and
/// `fold_coordinates` are ordered from the high tensor bit to the low tensor
/// bit, matching the recursive half-fold performed by the PCS.
pub fn prove_binding_coefficient_functional_v2(
    coefficients: &[Fp16],
    fold_coordinates: &[Fp16],
    context: BindingDigestV2,
    completion_coin: BindingDigestV2,
) -> Result<BindingMultilinearPcsProofV2, BindingMultilinearPcsV2Error> {
    prove_binding_multilinear_coefficients_v2(
        coefficients,
        fold_coordinates,
        context,
        completion_coin,
    )
}

/// Verify the direct coefficient-functional variant and return the ordinary
/// opaque native-128 opening receipt.  The first root is reusable across
/// multiple independently challenged functionals of the same coefficient
/// vector; every later fold root remains proof-local and completion-bound.
pub fn verify_binding_coefficient_functional_v2(
    proof: &BindingMultilinearPcsProofV2,
    expected_root: BindingRootV2,
    fold_coordinates: &[Fp16],
    claimed_value: Fp16,
    expected_context: BindingDigestV2,
    completion_coin: BindingDigestV2,
) -> Result<VerifiedBindingMultilinearOpeningV2, BindingMultilinearPcsV2Error> {
    verify_binding_multilinear_opening_v2(
        proof,
        expected_root,
        fold_coordinates,
        claimed_value,
        expected_context,
        completion_coin,
    )
}

pub fn verify_binding_multilinear_opening_v2(
    proof: &BindingMultilinearPcsProofV2,
    expected_root: BindingRootV2,
    point: &[Fp16],
    claimed_value: Fp16,
    expected_context: BindingDigestV2,
    completion_coin: BindingDigestV2,
) -> Result<VerifiedBindingMultilinearOpeningV2, BindingMultilinearPcsV2Error> {
    if proof.context != expected_context
        || point.is_empty()
        || point.len() > BINDING_MLPCS_V2_MAX_VARIABLES
        || proof.roots.len() != point.len()
        || proof.layers.len() != point.len()
        || proof.roots.first().copied() != Some(expected_root)
    {
        return Err(BindingMultilinearPcsV2Error::Shape);
    }
    let roots_binding = roots_commitment(expected_context, &proof.roots)?;
    let initial_size = 1usize << (point.len() + BINDING_MLPCS_V2_RATE_LOG as usize);
    let mut queries = query_positions(completion_coin, roots_binding, initial_size)?;
    let mut size = initial_size;
    let mut root_of_unity = derive_two_adic_root(size.ilog2() as u8)
        .map_err(|_| BindingMultilinearPcsV2Error::Shape)?;
    for (layer, challenge) in point.iter().copied().enumerate() {
        let opening = &proof.layers[layer];
        let expected_indices = selected_leaf_indices(&queries, size);
        if opening.leaf_indices != expected_indices
            || opening.leaf_values.len() != expected_indices.len()
            || opening.multiproof.selected_indices() != expected_indices
        {
            return Err(BindingMultilinearPcsV2Error::Query);
        }
        let payloads = opening
            .leaf_values
            .iter()
            .map(|values| layer_leaf_payload(expected_context, layer, values))
            .collect::<Vec<_>>();
        opening
            .multiproof
            .verify_payloads(&payloads, &proof.roots[layer])?;
        let half = size / 2;
        let inverse_root = root_of_unity
            .inverse()
            .map_err(|_| BindingMultilinearPcsV2Error::Fold)?;
        for query in &queries {
            let base = *query % half;
            let expected = if layer + 1 == point.len() {
                proof.terminal_values[base % 16]
            } else {
                opened_value(&proof.layers[layer + 1], base)?
            };
            if !verify_multiplicative_batch_fold(
                opened_value(opening, base)?,
                opened_value(opening, base + half)?,
                inverse_root.pow_u32(base as u32),
                challenge,
                None,
                expected,
            )
            .map_err(|_| BindingMultilinearPcsV2Error::Fold)?
            {
                return Err(BindingMultilinearPcsV2Error::Fold);
            }
        }
        queries = queries.into_iter().map(|query| query % half).collect();
        size = half;
        root_of_unity = root_of_unity.square();
    }
    if proof
        .terminal_values
        .iter()
        .any(|value| *value != claimed_value)
    {
        return Err(BindingMultilinearPcsV2Error::Terminal);
    }
    Ok(VerifiedBindingMultilinearOpeningV2 {
        root: expected_root,
        point: point.to_vec(),
        value: claimed_value,
        roots_commitment: roots_binding,
    })
}

/// Verify the direct Boolean-table variant while preserving the caller's
/// ordinary multilinear point in the opaque receipt.
pub fn verify_binding_boolean_table_opening_v2(
    proof: &BindingMultilinearPcsProofV2,
    expected_root: BindingRootV2,
    point: &[Fp16],
    claimed_value: Fp16,
    expected_context: BindingDigestV2,
    completion_coin: BindingDigestV2,
) -> Result<VerifiedBindingMultilinearOpeningV2, BindingMultilinearPcsV2Error> {
    let (fold_coordinates, scale) = boolean_table_fold_coordinates(point)?;
    let normalized = claimed_value
        * scale
            .inverse()
            .map_err(|_| BindingMultilinearPcsV2Error::Shape)?;
    let verified = verify_binding_multilinear_opening_v2(
        proof,
        expected_root,
        &fold_coordinates,
        normalized,
        expected_context,
        completion_coin,
    )?;
    Ok(VerifiedBindingMultilinearOpeningV2 {
        root: verified.root,
        point: point.to_vec(),
        value: claimed_value,
        roots_commitment: verified.roots_commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate_hypercube(mut values: Vec<Fp16>, point: &[Fp16]) -> Fp16 {
        let mut active = values.len();
        for challenge in point {
            for index in 0..active / 2 {
                values[index] = values[2 * index] * (Fp16::ONE - *challenge)
                    + values[2 * index + 1] * *challenge;
            }
            active /= 2;
        }
        values[0]
    }

    #[test]
    fn direct_boolean_table_opening_uses_normalized_fri_coordinates() {
        let table = (0..32)
            .map(|index| fp((index * index + 7) as u32))
            .collect::<Vec<_>>();
        let point = [fp(2), fp(3), fp(5), fp(7), fp(11)];
        let expected = evaluate_hypercube(table.clone(), &point);
        let context = BindingDigestV2::hash(BindingRoleV2::Payload, b"direct-table").unwrap();
        let coin = BindingDigestV2::hash(BindingRoleV2::Payload, b"completion").unwrap();
        let proof = prove_binding_boolean_table_opening_v2(&table, &point, context, coin).unwrap();
        verify_binding_boolean_table_opening_v2(
            &proof,
            proof.roots[0],
            &point,
            expected,
            context,
            coin,
        )
        .unwrap();

        assert_eq!(
            verify_binding_boolean_table_opening_v2(
                &proof,
                proof.roots[0],
                &point,
                expected + Fp16::ONE,
                context,
                coin,
            ),
            Err(BindingMultilinearPcsV2Error::Terminal)
        );
        let mut singular = point;
        singular[2] = Fp16::ONE;
        assert_eq!(
            prove_binding_boolean_table_opening_v2(&table, &singular, context, coin),
            Err(BindingMultilinearPcsV2Error::Shape)
        );
    }

    fn fp(value: u32) -> Fp16 {
        Fp16::from_coefficients([value, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap()
    }

    #[test]
    fn native_opening_accepts_and_mutations_reject() {
        let coefficients = (0..256)
            .map(|i| fp((i * 17 + 3) as u32))
            .collect::<Vec<_>>();
        let point = (0..8).map(|i| fp((i * 23 + 5) as u32)).collect::<Vec<_>>();
        let context = BindingDigestV2::hash(BindingRoleV2::Payload, b"context").unwrap();
        let coin = BindingDigestV2::hash(BindingRoleV2::Payload, b"completion").unwrap();
        let proof =
            prove_binding_multilinear_opening_v2(&coefficients, &point, context, coin).unwrap();
        let encoded = encode_binding_multilinear_pcs_proof_v2(&proof).unwrap();
        assert_eq!(
            decode_binding_multilinear_pcs_proof_v2(&encoded).unwrap(),
            proof
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_binding_multilinear_pcs_proof_v2(&trailing),
            Err(BindingMultilinearPcsV2Error::Encoding)
        );
        let value = evaluate_hypercube(coefficients.clone(), &point);
        verify_binding_multilinear_opening_v2(&proof, proof.roots[0], &point, value, context, coin)
            .unwrap();

        let mut changed = proof.clone();
        changed.layers[0].leaf_values[0][0] = changed.layers[0].leaf_values[0][0] + Fp16::ONE;
        assert!(
            verify_binding_multilinear_opening_v2(
                &changed,
                proof.roots[0],
                &point,
                value,
                context,
                coin
            )
            .is_err()
        );
        let mut changed = proof.clone();
        changed.terminal_values[0] = changed.terminal_values[0] + Fp16::ONE;
        assert!(
            verify_binding_multilinear_opening_v2(
                &changed,
                proof.roots[0],
                &point,
                value,
                context,
                coin
            )
            .is_err()
        );
        let mut changed_point = point.clone();
        changed_point[0] = changed_point[0] + Fp16::ONE;
        assert!(
            verify_binding_multilinear_opening_v2(
                &proof,
                proof.roots[0],
                &changed_point,
                value,
                context,
                coin
            )
            .is_err()
        );
    }
}
