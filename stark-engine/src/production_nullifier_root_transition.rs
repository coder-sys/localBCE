use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use winterfell::{
    crypto::{ElementHasher, Hasher, MerkleTree, hashers::Rp64_256},
    math::FieldElement,
};

use crate::{
    StarkBridgeInput,
    production_air_winterfell::{
        ProductionFelt, pack_public_input_root_bytes32, unpack_public_input_root_bytes32,
    },
};

type NullifierDigest = <Rp64_256 as Hasher>::Digest;

pub const NULLIFIER_ROOT_TRANSITION_SCHEMA_VERSION: &str = "stark-nullifier-root-transition-v2";
pub const NULLIFIER_ROOT_HASH_FUNCTION: &str = "winterfell-rp64-256";
pub const NULLIFIER_ROOT_ENCODING: &str = "bytes32-four-canonical-f64-big-endian";
pub const NULLIFIER_ROOT_TREE_DEPTH: usize = 10;
pub const NULLIFIER_ROOT_WIDTH: usize = 4;
pub const NULLIFIER_ROOT_CAPACITY: usize = 1 << NULLIFIER_ROOT_TREE_DEPTH;
pub const NULLIFIER_ROOT_LEAF_INDEX_MASK: usize = NULLIFIER_ROOT_CAPACITY - 1;
pub const NULLIFIER_PREIMAGE_LENGTH: usize = 16;
pub const NULLIFIER_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCNUL01");
pub const NULLIFIER_SCHEMA_TAG: u64 = 1;
pub const NULLIFIER_HASH_TAG: u64 = u64::from_le_bytes(*b"Rp64V1\0\0");
pub const NULLIFIER_RULESET_TAG: u64 = u64::from_le_bytes(*b"G1G10V1\0");
pub const NULLIFIER_PREIMAGE_ORDER: [&str; NULLIFIER_PREIMAGE_LENGTH] = [
    "domain_tag",
    "schema_tag",
    "hash_tag",
    "ruleset_tag",
    "claim_hash_be_u32_limb_0",
    "claim_hash_be_u32_limb_1",
    "claim_hash_be_u32_limb_2",
    "claim_hash_be_u32_limb_3",
    "claim_hash_be_u32_limb_4",
    "claim_hash_be_u32_limb_5",
    "claim_hash_be_u32_limb_6",
    "claim_hash_be_u32_limb_7",
    "reserved_0",
    "reserved_1",
    "reserved_2",
    "reserved_3",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionNullifierRootTransitionArtifactV1 {
    pub schema_version: String,
    pub source_schema_version: String,
    pub artifact_status: String,
    pub hash_function: String,
    pub root_encoding: String,
    pub bridge_input_sha256: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub decision: u8,
    pub duplicate_flag: u8,
    pub nullifier_preimage_order: Vec<String>,
    pub nullifier_preimage_decimal: Vec<String>,
    pub nullifier_digest_elements: [String; NULLIFIER_ROOT_WIDTH],
    pub nullifier_bytes32: String,
    pub empty_leaf_elements: [String; NULLIFIER_ROOT_WIDTH],
    pub tree_depth: usize,
    pub leaf_index: usize,
    pub merkle_path_elements: Vec<[String; NULLIFIER_ROOT_WIDTH]>,
    pub merkle_path_indices: Vec<u8>,
    pub nullifier_root_before_elements: [String; NULLIFIER_ROOT_WIDTH],
    pub nullifier_root_before_bytes32: String,
    pub nullifier_root_after_elements: [String; NULLIFIER_ROOT_WIDTH],
    pub nullifier_root_after_bytes32: String,
    pub state_generation_before: u64,
    pub state_generation_after: u64,
    pub transition_applied: bool,
    pub state_source_status: String,
    pub air_binding_status: String,
    pub governance_status: String,
    pub runtime_wired: bool,
    pub on_chain_verifier_wired: bool,
    pub on_chain_submission: bool,
    pub groth16_flow_unchanged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionNullifierCommittedLeafV1 {
    pub leaf_index: usize,
    pub claim_hash: String,
    pub nullifier_bytes32: String,
}

impl ProductionNullifierRootTransitionArtifactV1 {
    pub const SCHEMA_VERSION: &'static str = NULLIFIER_ROOT_TRANSITION_SCHEMA_VERSION;
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const ARTIFACT_STATUS: &'static str =
        "canonical_sparse_transition_production_air_bound_not_runtime";
    pub const BOOTSTRAP_STATE_SOURCE_STATUS: &'static str =
        "canonical_empty_tree_bootstrap_no_persistent_state_provider";
    pub const PERSISTENT_STATE_SOURCE_STATUS: &'static str =
        "persistent_file_state_compare_and_swap_v1";
    pub const AIR_BINDING_STATUS: &'static str = "production_air_v5_constrains_nullifier_derivation_indexed_empty_leaf_path_and_root_transition";
    pub const GOVERNANCE_STATUS: &'static str = "not_registered_or_approved";

    pub fn from_bridge_input(bridge: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        Self::from_bridge_input_with_committed_leaves(
            bridge,
            0,
            &[],
            Self::BOOTSTRAP_STATE_SOURCE_STATUS,
        )
    }

    pub fn from_bridge_input_with_committed_leaves(
        bridge: &StarkBridgeInput,
        state_generation: u64,
        committed_leaves: &[ProductionNullifierCommittedLeafV1],
        state_source_status: &str,
    ) -> Result<Self, Vec<String>> {
        bridge.validate()?;
        let preimage = canonical_nullifier_preimage(bridge)?;
        let nullifier = Rp64_256::hash_elements(&preimage);
        let nullifier_elements = digest_elements(&nullifier);
        let leaf_index = canonical_nullifier_leaf_index(&bridge.claim.claim_hash)?;
        let empty_leaf = empty_leaf_digest();
        let tree = build_nullifier_tree(committed_leaves)?;
        let (opened_empty_leaf, path) = tree
            .prove(leaf_index)
            .map_err(|error| vec![format!("could not open nullifier leaf: {error}")])?;
        if opened_empty_leaf != empty_leaf {
            return Err(vec![format!(
                "nullifier leaf index {leaf_index} is already occupied"
            )]);
        }
        let root_before = tree.root().clone();
        let transition_applied = bridge.adjudication.decision == 1;
        let after_leaf = if transition_applied {
            nullifier
        } else {
            empty_leaf
        };
        let root_after = compute_root(after_leaf, &path, leaf_index);
        let before_elements = digest_elements(&root_before);
        let after_elements = digest_elements(&root_after);

        let artifact = Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: Self::SOURCE_SCHEMA_VERSION.to_string(),
            artifact_status: Self::ARTIFACT_STATUS.to_string(),
            hash_function: NULLIFIER_ROOT_HASH_FUNCTION.to_string(),
            root_encoding: NULLIFIER_ROOT_ENCODING.to_string(),
            bridge_input_sha256: prefixed_sha256(
                &serde_json::to_vec(bridge)
                    .map_err(|error| vec![format!("could not serialize bridge input: {error}")])?,
            ),
            claim_id: bridge.claim.claim_id.clone(),
            claim_hash: bridge.claim.claim_hash.clone(),
            decision: bridge.adjudication.decision,
            duplicate_flag: bridge.active_rust_facts.is_duplicate,
            nullifier_preimage_order: NULLIFIER_PREIMAGE_ORDER
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            nullifier_preimage_decimal: felts_to_strings(&preimage),
            nullifier_digest_elements: digest_to_strings(&nullifier),
            nullifier_bytes32: pack_public_input_root_bytes32(&nullifier_elements),
            empty_leaf_elements: digest_to_strings(&empty_leaf),
            tree_depth: NULLIFIER_ROOT_TREE_DEPTH,
            leaf_index,
            merkle_path_elements: path.iter().map(digest_to_strings).collect(),
            merkle_path_indices: merkle_path_indices(leaf_index),
            nullifier_root_before_elements: digest_to_strings(&root_before),
            nullifier_root_before_bytes32: pack_public_input_root_bytes32(&before_elements),
            nullifier_root_after_elements: digest_to_strings(&root_after),
            nullifier_root_after_bytes32: pack_public_input_root_bytes32(&after_elements),
            state_generation_before: state_generation,
            state_generation_after: if transition_applied {
                state_generation
                    .checked_add(1)
                    .ok_or_else(|| vec!["nullifier state generation overflow".to_string()])?
            } else {
                state_generation
            },
            transition_applied,
            state_source_status: state_source_status.to_string(),
            air_binding_status: Self::AIR_BINDING_STATUS.to_string(),
            governance_status: Self::GOVERNANCE_STATUS.to_string(),
            runtime_wired: false,
            on_chain_verifier_wired: false,
            on_chain_submission: false,
            groth16_flow_unchanged: true,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub(crate) fn air_witness_components(
        &self,
    ) -> Result<ProductionNullifierWitnessComponents, Vec<String>> {
        self.validate()?;
        let preimage = strings_to_felts(
            "nullifier_preimage_decimal",
            &self.nullifier_preimage_decimal,
            NULLIFIER_PREIMAGE_LENGTH,
        )?
        .try_into()
        .expect("validated nullifier preimage length");
        let path = strings_to_digest_path("merkle_path_elements", &self.merkle_path_elements)?
            .into_iter()
            .map(|digest| digest_elements(&digest))
            .collect::<Vec<_>>()
            .try_into()
            .expect("validated nullifier path depth");
        Ok(ProductionNullifierWitnessComponents {
            preimage,
            merkle_path: path,
            root_before: digest_elements(&strings_to_digest(
                "nullifier_root_before_elements",
                &self.nullifier_root_before_elements,
            )?),
            root_after: digest_elements(&strings_to_digest(
                "nullifier_root_after_elements",
                &self.nullifier_root_after_elements,
            )?),
            leaf_index: self.leaf_index,
        })
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for (field, actual, expected) in [
            (
                "schema_version",
                self.schema_version.as_str(),
                Self::SCHEMA_VERSION,
            ),
            (
                "source_schema_version",
                self.source_schema_version.as_str(),
                Self::SOURCE_SCHEMA_VERSION,
            ),
            (
                "artifact_status",
                self.artifact_status.as_str(),
                Self::ARTIFACT_STATUS,
            ),
            (
                "hash_function",
                self.hash_function.as_str(),
                NULLIFIER_ROOT_HASH_FUNCTION,
            ),
            (
                "root_encoding",
                self.root_encoding.as_str(),
                NULLIFIER_ROOT_ENCODING,
            ),
            (
                "air_binding_status",
                self.air_binding_status.as_str(),
                Self::AIR_BINDING_STATUS,
            ),
            (
                "governance_status",
                self.governance_status.as_str(),
                Self::GOVERNANCE_STATUS,
            ),
        ] {
            if actual != expected {
                errors.push(format!("{field} must be {expected}, got {actual}"));
            }
        }
        if ![
            Self::BOOTSTRAP_STATE_SOURCE_STATUS,
            Self::PERSISTENT_STATE_SOURCE_STATUS,
        ]
        .contains(&self.state_source_status.as_str())
        {
            errors.push(format!(
                "state_source_status must be {} or {}, got {}",
                Self::BOOTSTRAP_STATE_SOURCE_STATUS,
                Self::PERSISTENT_STATE_SOURCE_STATUS,
                self.state_source_status
            ));
        }
        let expected_generation_after = if self.transition_applied {
            self.state_generation_before.checked_add(1)
        } else {
            Some(self.state_generation_before)
        };
        if expected_generation_after != Some(self.state_generation_after) {
            errors.push(
                "state_generation_after must increment exactly once for approved transitions and remain unchanged for denied transitions"
                    .to_string(),
            );
        }
        if self.state_source_status == Self::BOOTSTRAP_STATE_SOURCE_STATUS
            && self.state_generation_before != 0
        {
            errors.push("bootstrap transitions require state_generation_before = 0".to_string());
        }
        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }
        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }
        if self.decision > 1 || self.duplicate_flag > 1 {
            errors.push("decision and duplicate_flag must be boolean".to_string());
        }
        if self.decision == 1 && self.duplicate_flag != 0 {
            errors.push("approved transition requires duplicate_flag = 0".to_string());
        }
        if self.transition_applied != (self.decision == 1) {
            errors.push("transition_applied must equal decision == 1".to_string());
        }
        if self.tree_depth != NULLIFIER_ROOT_TREE_DEPTH {
            errors.push(format!(
                "tree_depth must be {NULLIFIER_ROOT_TREE_DEPTH}, got {}",
                self.tree_depth
            ));
        }
        if self.leaf_index >= (1 << NULLIFIER_ROOT_TREE_DEPTH) {
            errors.push("leaf_index is outside the nullifier tree".to_string());
        }
        if self.nullifier_preimage_order
            != NULLIFIER_PREIMAGE_ORDER
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>()
        {
            errors.push("nullifier_preimage_order is not canonical".to_string());
        }

        let preimage = strings_to_felts(
            "nullifier_preimage_decimal",
            &self.nullifier_preimage_decimal,
            NULLIFIER_PREIMAGE_LENGTH,
        );
        let nullifier =
            strings_to_digest("nullifier_digest_elements", &self.nullifier_digest_elements);
        let empty_leaf = strings_to_digest("empty_leaf_elements", &self.empty_leaf_elements);
        let path = strings_to_digest_path("merkle_path_elements", &self.merkle_path_elements);
        let before = strings_to_digest(
            "nullifier_root_before_elements",
            &self.nullifier_root_before_elements,
        );
        let after = strings_to_digest(
            "nullifier_root_after_elements",
            &self.nullifier_root_after_elements,
        );
        match (preimage, nullifier, empty_leaf, path, before, after) {
            (Ok(preimage), Ok(nullifier), Ok(empty_leaf), Ok(path), Ok(before), Ok(after)) => {
                if preimage[..4]
                    != [
                        felt(NULLIFIER_DOMAIN_TAG),
                        felt(NULLIFIER_SCHEMA_TAG),
                        felt(NULLIFIER_HASH_TAG),
                        felt(NULLIFIER_RULESET_TAG),
                    ]
                {
                    errors.push("nullifier preimage header is not canonical".to_string());
                }
                if preimage[12..] != [ProductionFelt::ZERO; 4] {
                    errors.push("nullifier reserved preimage fields must be zero".to_string());
                }
                match parse_claim_hash_limbs(&self.claim_hash) {
                    Ok(limbs) if preimage[4..12] != limbs => errors.push(
                        "nullifier preimage claim hash limbs do not match claim_hash".to_string(),
                    ),
                    Ok(_) => {}
                    Err(mut claim_errors) => errors.append(&mut claim_errors),
                }
                let expected_nullifier = Rp64_256::hash_elements(&preimage);
                if nullifier != expected_nullifier {
                    errors.push("nullifier digest does not match canonical preimage".to_string());
                }
                if empty_leaf != empty_leaf_digest() {
                    errors
                        .push("empty_leaf_elements must be the canonical zero digest".to_string());
                }
                let expected_index = match canonical_nullifier_leaf_index(&self.claim_hash) {
                    Ok(value) => value,
                    Err(mut value) => {
                        errors.append(&mut value);
                        0
                    }
                };
                if self.leaf_index != expected_index {
                    errors.push(
                        "leaf_index must equal the low tree-depth bits of the canonical claim hash"
                            .to_string(),
                    );
                }
                if path.len() != NULLIFIER_ROOT_TREE_DEPTH {
                    errors.push(format!(
                        "merkle_path_elements must contain {NULLIFIER_ROOT_TREE_DEPTH} digests"
                    ));
                } else {
                    let expected_before = compute_root(empty_leaf, &path, expected_index);
                    if before != expected_before {
                        errors.push(
                            "nullifier_root_before does not match the supplied empty-leaf Merkle path"
                                .to_string(),
                        );
                    }
                    if self.state_source_status == Self::BOOTSTRAP_STATE_SOURCE_STATUS {
                        match build_empty_nullifier_tree() {
                            Ok(tree) => {
                                let (_, expected_path) = tree
                                    .prove(expected_index)
                                    .expect("derived nullifier index is in range");
                                if path != expected_path || &before != tree.root() {
                                    errors.push(
                                        "bootstrap transition must use the canonical empty tree"
                                            .to_string(),
                                    );
                                }
                            }
                            Err(mut tree_errors) => errors.append(&mut tree_errors),
                        }
                    }
                    let expected_after_leaf = if self.transition_applied {
                        expected_nullifier
                    } else {
                        empty_leaf
                    };
                    let expected_after = compute_root(expected_after_leaf, &path, expected_index);
                    if after != expected_after {
                        errors.push(
                            "nullifier_root_after does not match the canonical transition"
                                .to_string(),
                        );
                    }
                    if self.transition_applied && after == before {
                        errors
                            .push("approved transition must change the nullifier root".to_string());
                    }
                    if !self.transition_applied && after != before {
                        errors.push(
                            "denied transition must leave the nullifier root unchanged".to_string(),
                        );
                    }
                }
                let nullifier_elements = digest_elements(&nullifier);
                if self.nullifier_bytes32 != pack_public_input_root_bytes32(&nullifier_elements) {
                    errors.push("nullifier_bytes32 does not match digest elements".to_string());
                }
                if self.nullifier_root_before_bytes32
                    != pack_public_input_root_bytes32(&digest_elements(&before))
                {
                    errors.push(
                        "nullifier_root_before_bytes32 does not match root elements".to_string(),
                    );
                }
                if self.nullifier_root_after_bytes32
                    != pack_public_input_root_bytes32(&digest_elements(&after))
                {
                    errors.push(
                        "nullifier_root_after_bytes32 does not match root elements".to_string(),
                    );
                }
            }
            (Err(mut value), _, _, _, _, _)
            | (_, Err(mut value), _, _, _, _)
            | (_, _, Err(mut value), _, _, _)
            | (_, _, _, Err(mut value), _, _)
            | (_, _, _, _, Err(mut value), _)
            | (_, _, _, _, _, Err(mut value)) => errors.append(&mut value),
        }
        if self.merkle_path_indices != merkle_path_indices(self.leaf_index) {
            errors.push("merkle_path_indices do not match leaf_index".to_string());
        }
        for (field, value) in [
            ("nullifier_bytes32", &self.nullifier_bytes32),
            (
                "nullifier_root_before_bytes32",
                &self.nullifier_root_before_bytes32,
            ),
            (
                "nullifier_root_after_bytes32",
                &self.nullifier_root_after_bytes32,
            ),
        ] {
            if unpack_public_input_root_bytes32(value).is_err() {
                errors.push(format!("{field} must use canonical f64 bytes32 encoding"));
            }
        }
        if !is_prefixed_sha256(&self.bridge_input_sha256) {
            errors.push("bridge_input_sha256 must be a 0x-prefixed SHA-256 digest".to_string());
        }
        if self.runtime_wired || self.on_chain_verifier_wired || self.on_chain_submission {
            errors.push("runtime and on-chain status flags must remain false".to_string());
        }
        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must remain true".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProductionNullifierWitnessComponents {
    pub preimage: [ProductionFelt; NULLIFIER_PREIMAGE_LENGTH],
    pub merkle_path: [[ProductionFelt; NULLIFIER_ROOT_WIDTH]; NULLIFIER_ROOT_TREE_DEPTH],
    pub root_before: [ProductionFelt; NULLIFIER_ROOT_WIDTH],
    pub root_after: [ProductionFelt; NULLIFIER_ROOT_WIDTH],
    pub leaf_index: usize,
}

pub fn canonical_nullifier_preimage(
    bridge: &StarkBridgeInput,
) -> Result<[ProductionFelt; NULLIFIER_PREIMAGE_LENGTH], Vec<String>> {
    bridge.validate()?;
    canonical_nullifier_preimage_from_claim_hash(&bridge.claim.claim_hash)
}

pub fn canonical_nullifier_digest_bytes32_from_claim_hash(
    claim_hash: &str,
) -> Result<String, Vec<String>> {
    let preimage = canonical_nullifier_preimage_from_claim_hash(claim_hash)?;
    Ok(pack_public_input_root_bytes32(
        &Rp64_256::hash_elements(&preimage)
            .as_elements()
            .try_into()
            .expect("Rp64_256 digest must contain four field elements"),
    ))
}

pub fn canonical_nullifier_leaf_index(claim_hash: &str) -> Result<usize, Vec<String>> {
    let limbs = parse_claim_hash_limbs(claim_hash)?;
    Ok((limbs[7].as_int() as usize) & NULLIFIER_ROOT_LEAF_INDEX_MASK)
}

pub fn canonical_nullifier_state_root_bytes32(
    committed_leaves: &[ProductionNullifierCommittedLeafV1],
) -> Result<String, Vec<String>> {
    let tree = build_nullifier_tree(committed_leaves)?;
    Ok(pack_public_input_root_bytes32(&digest_elements(
        tree.root(),
    )))
}

fn canonical_nullifier_preimage_from_claim_hash(
    claim_hash: &str,
) -> Result<[ProductionFelt; NULLIFIER_PREIMAGE_LENGTH], Vec<String>> {
    let claim_hash_limbs = parse_claim_hash_limbs(claim_hash)?;
    let mut preimage = [ProductionFelt::ZERO; NULLIFIER_PREIMAGE_LENGTH];
    preimage[..4].copy_from_slice(&[
        felt(NULLIFIER_DOMAIN_TAG),
        felt(NULLIFIER_SCHEMA_TAG),
        felt(NULLIFIER_HASH_TAG),
        felt(NULLIFIER_RULESET_TAG),
    ]);
    preimage[4..12].copy_from_slice(&claim_hash_limbs);
    Ok(preimage)
}

fn empty_leaf_digest() -> NullifierDigest {
    [ProductionFelt::ZERO; NULLIFIER_ROOT_WIDTH].into()
}

fn build_empty_nullifier_tree() -> Result<MerkleTree<Rp64_256>, Vec<String>> {
    MerkleTree::<Rp64_256>::new(vec![empty_leaf_digest(); NULLIFIER_ROOT_CAPACITY])
        .map_err(|error| vec![format!("could not build empty nullifier tree: {error}")])
}

fn build_nullifier_tree(
    committed_leaves: &[ProductionNullifierCommittedLeafV1],
) -> Result<MerkleTree<Rp64_256>, Vec<String>> {
    let mut errors = Vec::new();
    let mut leaves = vec![empty_leaf_digest(); NULLIFIER_ROOT_CAPACITY];
    let mut seen_claim_hashes = std::collections::BTreeSet::new();
    let mut seen_nullifiers = std::collections::BTreeSet::new();

    for (position, committed) in committed_leaves.iter().enumerate() {
        if committed.leaf_index >= NULLIFIER_ROOT_CAPACITY {
            errors.push(format!(
                "committed_leaves[{position}].leaf_index is outside the nullifier tree"
            ));
            continue;
        }
        match canonical_nullifier_leaf_index(&committed.claim_hash) {
            Ok(expected) if expected != committed.leaf_index => errors.push(format!(
                "committed_leaves[{position}].leaf_index does not match claim_hash"
            )),
            Ok(_) => {}
            Err(mut value) => errors.append(&mut value),
        }
        match canonical_nullifier_digest_bytes32_from_claim_hash(&committed.claim_hash) {
            Ok(expected) if expected != committed.nullifier_bytes32 => errors.push(format!(
                "committed_leaves[{position}].nullifier_bytes32 does not match claim_hash"
            )),
            Ok(_) => {}
            Err(mut value) => errors.append(&mut value),
        }
        if !seen_claim_hashes.insert(committed.claim_hash.clone()) {
            errors.push(format!(
                "committed_leaves[{position}] repeats claim_hash {}",
                committed.claim_hash
            ));
        }
        if !seen_nullifiers.insert(committed.nullifier_bytes32.clone()) {
            errors.push(format!(
                "committed_leaves[{position}] repeats nullifier {}",
                committed.nullifier_bytes32
            ));
        }
        if leaves[committed.leaf_index] != empty_leaf_digest() {
            errors.push(format!(
                "committed_leaves[{position}] collides at leaf index {}",
                committed.leaf_index
            ));
            continue;
        }
        match unpack_public_input_root_bytes32(&committed.nullifier_bytes32) {
            Ok(elements) => leaves[committed.leaf_index] = elements.into(),
            Err(error) => errors.push(format!(
                "committed_leaves[{position}].nullifier_bytes32: {error}"
            )),
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }
    MerkleTree::<Rp64_256>::new(leaves)
        .map_err(|error| vec![format!("could not build nullifier tree: {error}")])
}

fn compute_root(
    leaf: NullifierDigest,
    path: &[NullifierDigest],
    mut index: usize,
) -> NullifierDigest {
    let mut current = digest_elements(&leaf);
    for sibling in path {
        let sibling = digest_elements(sibling);
        let (left, right) = if index & 1 == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        current = merge_elements(left, right);
        index >>= 1;
    }
    current.into()
}

fn merge_elements(
    left: [ProductionFelt; NULLIFIER_ROOT_WIDTH],
    right: [ProductionFelt; NULLIFIER_ROOT_WIDTH],
) -> [ProductionFelt; NULLIFIER_ROOT_WIDTH] {
    let mut elements = [ProductionFelt::ZERO; 8];
    elements[..4].copy_from_slice(&left);
    elements[4..].copy_from_slice(&right);
    digest_elements(&Rp64_256::hash_elements(&elements))
}

fn parse_claim_hash_limbs(claim_hash: &str) -> Result<[ProductionFelt; 8], Vec<String>> {
    let Some(hex) = claim_hash.strip_prefix("0x") else {
        return Err(vec!["claim_hash must start with 0x".to_string()]);
    };
    if hex.len() != 64 || !hex.chars().all(|value| value.is_ascii_hexdigit()) {
        return Err(vec![
            "claim_hash must contain exactly 64 hexadecimal digits".to_string(),
        ]);
    }
    let mut limbs = [ProductionFelt::ZERO; 8];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = index * 8;
        let value = u32::from_str_radix(&hex[start..start + 8], 16)
            .map_err(|error| vec![format!("invalid claim hash limb {index}: {error}")])?;
        *limb = ProductionFelt::from(value);
    }
    Ok(limbs)
}

fn strings_to_felts(
    field: &str,
    values: &[String],
    expected_len: usize,
) -> Result<Vec<ProductionFelt>, Vec<String>> {
    let mut errors = Vec::new();
    if values.len() != expected_len {
        errors.push(format!("{field} must contain {expected_len} values"));
    }
    let mut parsed = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        match parse_canonical_felt(value) {
            Ok(value) => parsed.push(value),
            Err(error) => errors.push(format!("{field}[{index}]: {error}")),
        }
    }
    if errors.is_empty() {
        Ok(parsed)
    } else {
        Err(errors)
    }
}

fn strings_to_digest(
    field: &str,
    values: &[String; NULLIFIER_ROOT_WIDTH],
) -> Result<NullifierDigest, Vec<String>> {
    let parsed = strings_to_felts(field, values, NULLIFIER_ROOT_WIDTH)?;
    let elements: [ProductionFelt; NULLIFIER_ROOT_WIDTH] =
        parsed.try_into().expect("validated nullifier digest width");
    Ok(elements.into())
}

fn strings_to_digest_path(
    field: &str,
    values: &[[String; NULLIFIER_ROOT_WIDTH]],
) -> Result<Vec<NullifierDigest>, Vec<String>> {
    let mut errors = Vec::new();
    let mut path = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        match strings_to_digest(&format!("{field}[{index}]"), value) {
            Ok(digest) => path.push(digest),
            Err(mut value) => errors.append(&mut value),
        }
    }
    if errors.is_empty() {
        Ok(path)
    } else {
        Err(errors)
    }
}

fn parse_canonical_felt(value: &str) -> Result<ProductionFelt, String> {
    let integer = value
        .parse::<u64>()
        .map_err(|error| format!("not a decimal u64: {error}"))?;
    let felt = ProductionFelt::new(integer);
    if felt.as_int() != integer {
        return Err("value is not a canonical f64 field element".to_string());
    }
    Ok(felt)
}

fn felt(value: u64) -> ProductionFelt {
    ProductionFelt::new(value)
}

fn digest_elements(digest: &NullifierDigest) -> [ProductionFelt; NULLIFIER_ROOT_WIDTH] {
    digest
        .as_elements()
        .try_into()
        .expect("Rp64_256 digest must contain four field elements")
}

fn felts_to_strings(values: &[ProductionFelt]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_int().to_string())
        .collect()
}

fn digest_to_strings(digest: &NullifierDigest) -> [String; NULLIFIER_ROOT_WIDTH] {
    core::array::from_fn(|index| digest.as_elements()[index].as_int().to_string())
}

fn merkle_path_indices(mut index: usize) -> Vec<u8> {
    (0..NULLIFIER_ROOT_TREE_DEPTH)
        .map(|_| {
            let bit = (index & 1) as u8;
            index >>= 1;
            bit
        })
        .collect()
}

fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("0x{:x}", Sha256::digest(bytes))
}

fn is_prefixed_sha256(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn is_0x_32_byte_hex(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}
