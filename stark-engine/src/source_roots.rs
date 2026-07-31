//! Feature-gated source-root candidates for the STARK settlement boundary.
//!
//! The claim-source artifact in this module is locally generated and validated,
//! and its canonical leaf and opening are consumed by the production AIR. It is
//! not yet governed, wired into runtime execution, or accepted by an on-chain
//! verifier.

pub const TRANSFORMATION_ID: &str = "bind_source_roots";
pub const MODULE_PATH: &str = "stark-engine/src/source_roots.rs";
pub const IMPLEMENTATION_STATUS: &str = "claim_source_root_feature_gated_air_bound_not_governed";
pub const RUNTIME_WIRING_ALLOWED: bool = false;
pub const REAL_PROOF_GENERATION_ALLOWED: bool = false;
pub const REQUIRED_EVIDENCE: [&str; 4] = [
    "source_root_binding_code_path",
    "claim_oracle_fee_nullifier_root_tests",
    "source_root_fixture",
    "source_root_validation_log",
];

#[cfg(feature = "production-air-winterfell")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "production-air-winterfell")]
use sha2::{Digest, Sha256};
#[cfg(feature = "production-air-winterfell")]
use winterfell::{
    crypto::{ElementHasher, Hasher, MerkleTree, hashers::Rp64_256},
    math::FieldElement,
};

#[cfg(feature = "production-air-winterfell")]
use crate::{
    OracleFactInput, StarkBridgeInput,
    production_air_winterfell::{
        ProductionFelt, pack_public_input_root_bytes32, unpack_public_input_root_bytes32,
    },
};

#[cfg(feature = "production-air-winterfell")]
type ClaimSourceDigest = <Rp64_256 as Hasher>::Digest;

#[cfg(feature = "production-air-winterfell")]
pub const CLAIM_SOURCE_ROOT_SCHEMA_VERSION: &str = "stark-claim-source-root-v1";
#[cfg(feature = "production-air-winterfell")]
pub const CLAIM_SOURCE_ROOT_HASH_FUNCTION: &str = "winterfell-rp64-256";
#[cfg(feature = "production-air-winterfell")]
pub const CLAIM_SOURCE_ROOT_ENCODING: &str = "bytes32-four-canonical-f64-big-endian";
#[cfg(feature = "production-air-winterfell")]
pub const CLAIM_SOURCE_ROOT_TREE_DEPTH: usize = 10;
#[cfg(feature = "production-air-winterfell")]
pub const CLAIM_SOURCE_ROOT_LEAF_INDEX: usize = 5;
#[cfg(feature = "production-air-winterfell")]
pub const CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH: usize = 36;
#[cfg(feature = "production-air-winterfell")]
pub const CLAIM_SOURCE_ROOT_AMOUNT_UNIT: &str =
    "claim_amount_whole_currency_units_normalized_to_cents";
#[cfg(feature = "production-air-winterfell")]
pub const CLAIM_SOURCE_ROOT_SERVICE_DATE_UNIT: &str = "rust_engine_service_date_scalar";

#[cfg(feature = "production-air-winterfell")]
pub(crate) const CLAIM_SOURCE_ROOT_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCSR001");
#[cfg(feature = "production-air-winterfell")]
pub(crate) const CLAIM_SOURCE_ROOT_SCHEMA_TAG: u64 = 1;
#[cfg(feature = "production-air-winterfell")]
pub(crate) const CLAIM_SOURCE_ROOT_HASH_TAG: u64 = u64::from_le_bytes(*b"RP64256\0");
#[cfg(feature = "production-air-winterfell")]
pub(crate) const CLAIM_SOURCE_ROOT_UNIT_TAG: u64 = 100;
#[cfg(feature = "production-air-winterfell")]
const MEMBER_ID_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCMEM01");
#[cfg(feature = "production-air-winterfell")]
const PROVIDER_NPI_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCNPI01");
#[cfg(feature = "production-air-winterfell")]
const SERVICE_LINES_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCLINE1");
#[cfg(feature = "production-air-winterfell")]
const PROCEDURE_CODE_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCPROC1");
#[cfg(feature = "production-air-winterfell")]
const DIAGNOSES_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCDIA01");
#[cfg(feature = "production-air-winterfell")]
const DIAGNOSIS_CODE_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCDX001");
#[cfg(feature = "production-air-winterfell")]
const EMPTY_LEAF_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCEMPTY");

#[cfg(feature = "production-air-winterfell")]
pub const ORACLE_FACTS_ROOT_SCHEMA_VERSION: &str = "stark-oracle-facts-root-v1";
#[cfg(feature = "production-air-winterfell")]
pub const ORACLE_FACTS_ROOT_HASH_FUNCTION: &str = "winterfell-rp64-256";
#[cfg(feature = "production-air-winterfell")]
pub const ORACLE_FACTS_ROOT_ENCODING: &str = "bytes32-four-canonical-f64-big-endian";
#[cfg(feature = "production-air-winterfell")]
pub const ORACLE_FACTS_ROOT_TREE_DEPTH: usize = 10;
#[cfg(feature = "production-air-winterfell")]
pub const ORACLE_FACTS_ROOT_LEAF_INDEX: usize = 11;
#[cfg(feature = "production-air-winterfell")]
pub const ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH: usize = 32;

#[cfg(feature = "production-air-winterfell")]
pub(crate) const ORACLE_FACTS_ROOT_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCOR001");
#[cfg(feature = "production-air-winterfell")]
pub(crate) const ORACLE_FACTS_ROOT_SCHEMA_TAG: u64 = 1;
#[cfg(feature = "production-air-winterfell")]
pub(crate) const ORACLE_FACTS_ROOT_HASH_TAG: u64 = u64::from_le_bytes(*b"RP64256\0");
#[cfg(feature = "production-air-winterfell")]
pub(crate) const ORACLE_FACTS_ROOT_NORMALIZATION_TAG: u64 = u64::from_le_bytes(*b"ORCANON1");
#[cfg(feature = "production-air-winterfell")]
const ORACLE_MANIFEST_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCOMAN1");
#[cfg(feature = "production-air-winterfell")]
const ORACLE_FACTS_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCOFACT");
#[cfg(feature = "production-air-winterfell")]
const ORACLE_FACT_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCOF001");
#[cfg(feature = "production-air-winterfell")]
const ORACLE_ATTESTATIONS_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCOATT1");
#[cfg(feature = "production-air-winterfell")]
const ORACLE_ATTESTATION_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCOA001");
#[cfg(feature = "production-air-winterfell")]
const ORACLE_EMPTY_LEAF_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCOEMPT");

#[cfg(feature = "production-air-winterfell")]
pub const CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_ORDER: [&str; CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH] = [
    "domain_tag",
    "schema_tag",
    "hash_family_tag",
    "amount_unit_tag",
    "claim_hash_be_u32_limb_0",
    "claim_hash_be_u32_limb_1",
    "claim_hash_be_u32_limb_2",
    "claim_hash_be_u32_limb_3",
    "claim_hash_be_u32_limb_4",
    "claim_hash_be_u32_limb_5",
    "claim_hash_be_u32_limb_6",
    "claim_hash_be_u32_limb_7",
    "member_id_digest_element_0",
    "member_id_digest_element_1",
    "member_id_digest_element_2",
    "member_id_digest_element_3",
    "provider_npi_digest_element_0",
    "provider_npi_digest_element_1",
    "provider_npi_digest_element_2",
    "provider_npi_digest_element_3",
    "member_id_present",
    "provider_npi_present",
    "service_lines_present",
    "diagnoses_present",
    "service_line_count",
    "diagnosis_count",
    "total_charge_cents",
    "service_date",
    "service_lines_digest_element_0",
    "service_lines_digest_element_1",
    "service_lines_digest_element_2",
    "service_lines_digest_element_3",
    "diagnoses_digest_element_0",
    "diagnoses_digest_element_1",
    "diagnoses_digest_element_2",
    "diagnoses_digest_element_3",
];

#[cfg(feature = "production-air-winterfell")]
pub const ORACLE_FACTS_ROOT_LEAF_PREIMAGE_ORDER: [&str; ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH] = [
    "domain_tag",
    "schema_tag",
    "hash_family_tag",
    "normalization_tag",
    "claim_hash_be_u32_limb_0",
    "claim_hash_be_u32_limb_1",
    "claim_hash_be_u32_limb_2",
    "claim_hash_be_u32_limb_3",
    "claim_hash_be_u32_limb_4",
    "claim_hash_be_u32_limb_5",
    "claim_hash_be_u32_limb_6",
    "claim_hash_be_u32_limb_7",
    "source_manifest_digest_element_0",
    "source_manifest_digest_element_1",
    "source_manifest_digest_element_2",
    "source_manifest_digest_element_3",
    "facts_digest_element_0",
    "facts_digest_element_1",
    "facts_digest_element_2",
    "facts_digest_element_3",
    "attestations_digest_element_0",
    "attestations_digest_element_1",
    "attestations_digest_element_2",
    "attestations_digest_element_3",
    "source_manifest_present",
    "facts_present",
    "attestations_present",
    "fact_count",
    "attestation_count",
    "verified_fact_count",
    "reserved_zero_0",
    "reserved_zero_1",
];

#[cfg(feature = "production-air-winterfell")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionClaimSourceRootArtifactV1 {
    pub schema_version: String,
    pub source_schema_version: String,
    pub artifact_status: String,
    pub hash_function: String,
    pub root_encoding: String,
    pub empty_leaf_strategy: String,
    pub bridge_input_sha256: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub claim_amount_unit: String,
    pub service_date_unit: String,
    pub tree_depth: usize,
    pub leaf_index: usize,
    pub service_line_count: usize,
    pub diagnosis_count: usize,
    pub total_charge_cents: u64,
    pub service_date: u64,
    pub leaf_preimage_order: Vec<String>,
    pub leaf_preimage_decimal: Vec<String>,
    pub leaf_digest_elements: [String; 4],
    pub merkle_path_elements: Vec<[String; 4]>,
    pub merkle_path_indices: Vec<u8>,
    pub root_elements: [String; 4],
    pub claim_source_root_bytes32: String,
    pub governance_status: String,
    pub air_binding_status: String,
    pub runtime_wired: bool,
    pub on_chain_verifier_wired: bool,
    pub on_chain_submission: bool,
    pub groth16_flow_unchanged: bool,
}

#[cfg(feature = "production-air-winterfell")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionOracleFactsRootArtifactV1 {
    pub schema_version: String,
    pub source_schema_version: String,
    pub artifact_status: String,
    pub hash_function: String,
    pub root_encoding: String,
    pub empty_leaf_strategy: String,
    pub bridge_input_sha256: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub source_manifest_id: String,
    pub facts: Vec<OracleFactInput>,
    pub attestation_refs: Vec<String>,
    pub tree_depth: usize,
    pub leaf_index: usize,
    pub fact_count: usize,
    pub attestation_count: usize,
    pub verified_fact_count: usize,
    pub leaf_preimage_order: Vec<String>,
    pub leaf_preimage_decimal: Vec<String>,
    pub leaf_digest_elements: [String; 4],
    pub merkle_path_elements: Vec<[String; 4]>,
    pub merkle_path_indices: Vec<u8>,
    pub root_elements: [String; 4],
    pub oracle_facts_root_bytes32: String,
    pub governance_status: String,
    pub attestation_status: String,
    pub air_binding_status: String,
    pub runtime_wired: bool,
    pub on_chain_verifier_wired: bool,
    pub on_chain_submission: bool,
    pub groth16_flow_unchanged: bool,
}

#[cfg(feature = "production-air-winterfell")]
impl ProductionClaimSourceRootArtifactV1 {
    pub const SCHEMA_VERSION: &'static str = CLAIM_SOURCE_ROOT_SCHEMA_VERSION;
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const ARTIFACT_STATUS: &'static str =
        "locally_generated_candidate_not_air_bound_or_governed";
    pub const EMPTY_LEAF_STRATEGY: &'static str = "rp64_256_domain_separated_indexed_empty_leaves";
    pub const GOVERNANCE_STATUS: &'static str = "not_registered_or_approved";
    pub const AIR_BINDING_STATUS: &'static str =
        "production_air_v2_constrains_canonical_leaf_path_and_root";

    pub fn from_bridge_input(bridge: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        bridge.validate()?;
        validate_bridge_claim_source(bridge)?;

        let leaf_preimage = canonical_claim_source_leaf_preimage(bridge)?;
        let leaf_digest = Rp64_256::hash_elements(&leaf_preimage);
        let tree = build_claim_source_tree(leaf_digest)?;
        let (opened_leaf, path) = tree
            .prove(CLAIM_SOURCE_ROOT_LEAF_INDEX)
            .map_err(|error| vec![format!("could not open claim-source Merkle leaf: {error}")])?;
        debug_assert_eq!(opened_leaf, leaf_digest);
        let root: [ProductionFelt; 4] = tree
            .root()
            .as_elements()
            .try_into()
            .expect("Rp64_256 digest must contain four field elements");

        let artifact = Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: Self::SOURCE_SCHEMA_VERSION.to_string(),
            artifact_status: Self::ARTIFACT_STATUS.to_string(),
            hash_function: CLAIM_SOURCE_ROOT_HASH_FUNCTION.to_string(),
            root_encoding: CLAIM_SOURCE_ROOT_ENCODING.to_string(),
            empty_leaf_strategy: Self::EMPTY_LEAF_STRATEGY.to_string(),
            bridge_input_sha256: bridge_input_sha256(bridge)?,
            claim_id: bridge.claim.claim_id.clone(),
            claim_hash: bridge.claim.claim_hash.clone(),
            claim_amount_unit: CLAIM_SOURCE_ROOT_AMOUNT_UNIT.to_string(),
            service_date_unit: CLAIM_SOURCE_ROOT_SERVICE_DATE_UNIT.to_string(),
            tree_depth: CLAIM_SOURCE_ROOT_TREE_DEPTH,
            leaf_index: CLAIM_SOURCE_ROOT_LEAF_INDEX,
            service_line_count: bridge.claim.service_lines.len(),
            diagnosis_count: bridge.claim.diagnosis_codes.len(),
            total_charge_cents: normalized_total_charge_cents(bridge)?,
            service_date: bridge.active_rust_facts.date_of_service_from,
            leaf_preimage_order: CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_ORDER
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            leaf_preimage_decimal: felts_to_strings(&leaf_preimage),
            leaf_digest_elements: digest_to_strings(&leaf_digest),
            merkle_path_elements: path.iter().map(digest_to_strings).collect(),
            merkle_path_indices: merkle_path_indices(CLAIM_SOURCE_ROOT_LEAF_INDEX),
            root_elements: root.map(|element| element.as_int().to_string()),
            claim_source_root_bytes32: pack_public_input_root_bytes32(&root),
            governance_status: Self::GOVERNANCE_STATUS.to_string(),
            air_binding_status: Self::AIR_BINDING_STATUS.to_string(),
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
    ) -> Result<
        (
            [ProductionFelt; CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH],
            [[ProductionFelt; 4]; CLAIM_SOURCE_ROOT_TREE_DEPTH],
            [ProductionFelt; 4],
        ),
        Vec<String>,
    > {
        self.validate()?;

        let leaf_preimage = strings_to_felts(
            "leaf_preimage_decimal",
            &self.leaf_preimage_decimal,
            CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH,
        )?
        .try_into()
        .expect("validated claim-source leaf preimage length");

        let merkle_path =
            strings_to_digest_path("merkle_path_elements", &self.merkle_path_elements)?
                .into_iter()
                .map(|digest| {
                    digest
                        .as_elements()
                        .try_into()
                        .expect("Rp64_256 digest must contain four field elements")
                })
                .collect::<Vec<[ProductionFelt; 4]>>()
                .try_into()
                .expect("validated claim-source Merkle path depth");

        let root = strings_to_digest("root_elements", &self.root_elements)?
            .as_elements()
            .try_into()
            .expect("Rp64_256 digest must contain four field elements");

        Ok((leaf_preimage, merkle_path, root))
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        validate_exact(
            "schema_version",
            &self.schema_version,
            Self::SCHEMA_VERSION,
            &mut errors,
        );
        validate_exact(
            "source_schema_version",
            &self.source_schema_version,
            Self::SOURCE_SCHEMA_VERSION,
            &mut errors,
        );
        validate_exact(
            "artifact_status",
            &self.artifact_status,
            Self::ARTIFACT_STATUS,
            &mut errors,
        );
        validate_exact(
            "hash_function",
            &self.hash_function,
            CLAIM_SOURCE_ROOT_HASH_FUNCTION,
            &mut errors,
        );
        validate_exact(
            "root_encoding",
            &self.root_encoding,
            CLAIM_SOURCE_ROOT_ENCODING,
            &mut errors,
        );
        validate_exact(
            "empty_leaf_strategy",
            &self.empty_leaf_strategy,
            Self::EMPTY_LEAF_STRATEGY,
            &mut errors,
        );
        validate_exact(
            "claim_amount_unit",
            &self.claim_amount_unit,
            CLAIM_SOURCE_ROOT_AMOUNT_UNIT,
            &mut errors,
        );
        validate_exact(
            "service_date_unit",
            &self.service_date_unit,
            CLAIM_SOURCE_ROOT_SERVICE_DATE_UNIT,
            &mut errors,
        );
        validate_exact(
            "governance_status",
            &self.governance_status,
            Self::GOVERNANCE_STATUS,
            &mut errors,
        );
        validate_exact(
            "air_binding_status",
            &self.air_binding_status,
            Self::AIR_BINDING_STATUS,
            &mut errors,
        );

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }
        if parse_claim_hash_limbs(&self.claim_hash).is_err() {
            errors.push("claim_hash must be a 0x-prefixed bytes32 hex string".to_string());
        }
        if !is_prefixed_sha256(&self.bridge_input_sha256) {
            errors.push("bridge_input_sha256 must be a 0x-prefixed bytes32 hex string".to_string());
        }
        if self.tree_depth != CLAIM_SOURCE_ROOT_TREE_DEPTH {
            errors.push(format!(
                "tree_depth must be {CLAIM_SOURCE_ROOT_TREE_DEPTH}, got {}",
                self.tree_depth
            ));
        }
        if self.leaf_index != CLAIM_SOURCE_ROOT_LEAF_INDEX {
            errors.push(format!(
                "leaf_index must be {CLAIM_SOURCE_ROOT_LEAF_INDEX}, got {}",
                self.leaf_index
            ));
        }
        if self.service_line_count == 0 {
            errors.push("service_line_count must be greater than zero".to_string());
        }
        if self.diagnosis_count == 0 {
            errors.push("diagnosis_count must be greater than zero".to_string());
        }
        if self.total_charge_cents == 0 || self.total_charge_cents > u32::MAX as u64 {
            errors.push("total_charge_cents must be in 1..=u32::MAX".to_string());
        }
        if self.service_date > u32::MAX as u64 {
            errors.push("service_date must fit in u32".to_string());
        }

        let expected_order: Vec<String> = CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_ORDER
            .iter()
            .map(|value| (*value).to_string())
            .collect();
        if self.leaf_preimage_order != expected_order {
            errors.push("leaf_preimage_order does not match the canonical V1 order".to_string());
        }

        let preimage = match strings_to_felts(
            "leaf_preimage_decimal",
            &self.leaf_preimage_decimal,
            CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH,
        ) {
            Ok(values) => Some(values),
            Err(mut parse_errors) => {
                errors.append(&mut parse_errors);
                None
            }
        };
        if let Some(preimage) = &preimage {
            validate_preimage_metadata(self, preimage, &mut errors);
            let expected_leaf = Rp64_256::hash_elements(preimage);
            match strings_to_digest("leaf_digest_elements", &self.leaf_digest_elements) {
                Ok(actual_leaf) if actual_leaf != expected_leaf => {
                    errors.push(
                        "leaf_digest_elements do not match leaf_preimage_decimal".to_string(),
                    );
                }
                Err(mut parse_errors) => errors.append(&mut parse_errors),
                _ => {}
            }
        }

        let leaf = strings_to_digest("leaf_digest_elements", &self.leaf_digest_elements);
        let path = strings_to_digest_path("merkle_path_elements", &self.merkle_path_elements);
        let root = strings_to_digest("root_elements", &self.root_elements);
        match (leaf, path, root) {
            (Ok(leaf), Ok(path), Ok(root)) => {
                if path.len() != CLAIM_SOURCE_ROOT_TREE_DEPTH {
                    errors.push(format!(
                        "merkle_path_elements must contain {CLAIM_SOURCE_ROOT_TREE_DEPTH} digests"
                    ));
                } else {
                    match build_claim_source_tree(leaf) {
                        Ok(tree) => {
                            let (_, expected_path) = tree
                                .prove(CLAIM_SOURCE_ROOT_LEAF_INDEX)
                                .expect("canonical leaf index must be in range");
                            if path != expected_path {
                                errors.push(
                                    "merkle_path_elements do not match canonical indexed empty leaves"
                                        .to_string(),
                                );
                            }
                            if &root != tree.root() {
                                errors.push(
                                    "root_elements do not match the canonical claim-source tree"
                                        .to_string(),
                                );
                            }
                        }
                        Err(mut tree_errors) => errors.append(&mut tree_errors),
                    }
                    if MerkleTree::<Rp64_256>::verify(
                        root,
                        CLAIM_SOURCE_ROOT_LEAF_INDEX,
                        leaf,
                        &path,
                    )
                    .is_err()
                    {
                        errors.push(
                            "claim-source leaf does not verify under the supplied Merkle root"
                                .to_string(),
                        );
                    }
                }

                let root_elements: [ProductionFelt; 4] = root
                    .as_elements()
                    .try_into()
                    .expect("Rp64_256 digest must contain four field elements");
                if self.claim_source_root_bytes32 != pack_public_input_root_bytes32(&root_elements)
                {
                    errors
                        .push("claim_source_root_bytes32 does not match root_elements".to_string());
                }
            }
            (Err(mut parse_errors), _, _) => errors.append(&mut parse_errors),
            (_, Err(mut parse_errors), _) => errors.append(&mut parse_errors),
            (_, _, Err(mut parse_errors)) => errors.append(&mut parse_errors),
        }

        let expected_indices = merkle_path_indices(CLAIM_SOURCE_ROOT_LEAF_INDEX);
        if self.merkle_path_indices != expected_indices {
            errors.push("merkle_path_indices do not match leaf_index".to_string());
        }
        if unpack_public_input_root_bytes32(&self.claim_source_root_bytes32).is_err() {
            errors.push(
                "claim_source_root_bytes32 must use canonical f64 bytes32 encoding".to_string(),
            );
        }
        if self.runtime_wired {
            errors.push("runtime_wired must remain false".to_string());
        }
        if self.on_chain_verifier_wired {
            errors.push("on_chain_verifier_wired must remain false".to_string());
        }
        if self.on_chain_submission {
            errors.push("on_chain_submission must remain false".to_string());
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

#[cfg(feature = "production-air-winterfell")]
impl ProductionOracleFactsRootArtifactV1 {
    pub const SCHEMA_VERSION: &'static str = ORACLE_FACTS_ROOT_SCHEMA_VERSION;
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const ARTIFACT_STATUS: &'static str =
        "locally_generated_oracle_root_air_bound_not_governed";
    pub const EMPTY_LEAF_STRATEGY: &'static str =
        "rp64_256_domain_separated_indexed_oracle_empty_leaves";
    pub const GOVERNANCE_STATUS: &'static str = "not_registered_or_approved";
    pub const ATTESTATION_STATUS: &'static str =
        "references_committed_not_cryptographically_verified";
    pub const AIR_BINDING_STATUS: &'static str =
        "production_air_v3_constrains_canonical_leaf_path_and_root";

    pub fn from_bridge_input(bridge: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        bridge.validate()?;
        validate_bridge_oracle_sources(bridge)?;

        let leaf_preimage = canonical_oracle_facts_leaf_preimage(bridge)?;
        let leaf_digest = Rp64_256::hash_elements(&leaf_preimage);
        let tree = build_oracle_facts_tree(leaf_digest)?;
        let (opened_leaf, path) = tree
            .prove(ORACLE_FACTS_ROOT_LEAF_INDEX)
            .map_err(|error| vec![format!("could not open oracle-facts Merkle leaf: {error}")])?;
        debug_assert_eq!(opened_leaf, leaf_digest);
        let root: [ProductionFelt; 4] = tree
            .root()
            .as_elements()
            .try_into()
            .expect("Rp64_256 digest must contain four field elements");

        let source_manifest_id = bridge
            .claim
            .oracle_source_manifest_id
            .as_deref()
            .expect("validated oracle source manifest must be present")
            .trim()
            .to_string();
        let verified_fact_count = bridge
            .claim
            .oracle_facts
            .iter()
            .filter(|fact| {
                fact.verification_status
                    .trim()
                    .eq_ignore_ascii_case("verified")
            })
            .count();

        let artifact = Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: Self::SOURCE_SCHEMA_VERSION.to_string(),
            artifact_status: Self::ARTIFACT_STATUS.to_string(),
            hash_function: ORACLE_FACTS_ROOT_HASH_FUNCTION.to_string(),
            root_encoding: ORACLE_FACTS_ROOT_ENCODING.to_string(),
            empty_leaf_strategy: Self::EMPTY_LEAF_STRATEGY.to_string(),
            bridge_input_sha256: bridge_input_sha256(bridge)?,
            claim_id: bridge.claim.claim_id.clone(),
            claim_hash: bridge.claim.claim_hash.clone(),
            source_manifest_id,
            facts: bridge.claim.oracle_facts.clone(),
            attestation_refs: bridge.claim.oracle_attestation_refs.clone(),
            tree_depth: ORACLE_FACTS_ROOT_TREE_DEPTH,
            leaf_index: ORACLE_FACTS_ROOT_LEAF_INDEX,
            fact_count: bridge.claim.oracle_facts.len(),
            attestation_count: bridge.claim.oracle_attestation_refs.len(),
            verified_fact_count,
            leaf_preimage_order: ORACLE_FACTS_ROOT_LEAF_PREIMAGE_ORDER
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            leaf_preimage_decimal: felts_to_strings(&leaf_preimage),
            leaf_digest_elements: digest_to_strings(&leaf_digest),
            merkle_path_elements: path.iter().map(digest_to_strings).collect(),
            merkle_path_indices: merkle_path_indices(ORACLE_FACTS_ROOT_LEAF_INDEX),
            root_elements: root.map(|element| element.as_int().to_string()),
            oracle_facts_root_bytes32: pack_public_input_root_bytes32(&root),
            governance_status: Self::GOVERNANCE_STATUS.to_string(),
            attestation_status: Self::ATTESTATION_STATUS.to_string(),
            air_binding_status: Self::AIR_BINDING_STATUS.to_string(),
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
    ) -> Result<
        (
            [ProductionFelt; ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH],
            [[ProductionFelt; 4]; ORACLE_FACTS_ROOT_TREE_DEPTH],
            [ProductionFelt; 4],
        ),
        Vec<String>,
    > {
        self.validate()?;

        let leaf_preimage = strings_to_felts(
            "leaf_preimage_decimal",
            &self.leaf_preimage_decimal,
            ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH,
        )?
        .try_into()
        .expect("validated oracle-facts leaf preimage length");
        let merkle_path =
            strings_to_digest_path("merkle_path_elements", &self.merkle_path_elements)?
                .into_iter()
                .map(|digest| {
                    digest
                        .as_elements()
                        .try_into()
                        .expect("Rp64_256 digest must contain four field elements")
                })
                .collect::<Vec<[ProductionFelt; 4]>>()
                .try_into()
                .expect("validated oracle-facts Merkle path depth");
        let root = strings_to_digest("root_elements", &self.root_elements)?
            .as_elements()
            .try_into()
            .expect("Rp64_256 digest must contain four field elements");
        Ok((leaf_preimage, merkle_path, root))
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
                ORACLE_FACTS_ROOT_HASH_FUNCTION,
            ),
            (
                "root_encoding",
                self.root_encoding.as_str(),
                ORACLE_FACTS_ROOT_ENCODING,
            ),
            (
                "empty_leaf_strategy",
                self.empty_leaf_strategy.as_str(),
                Self::EMPTY_LEAF_STRATEGY,
            ),
            (
                "governance_status",
                self.governance_status.as_str(),
                Self::GOVERNANCE_STATUS,
            ),
            (
                "attestation_status",
                self.attestation_status.as_str(),
                Self::ATTESTATION_STATUS,
            ),
            (
                "air_binding_status",
                self.air_binding_status.as_str(),
                Self::AIR_BINDING_STATUS,
            ),
        ] {
            validate_exact(field, actual, expected, &mut errors);
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }
        if parse_claim_hash_limbs(&self.claim_hash).is_err() {
            errors.push("claim_hash must be a 0x-prefixed bytes32 hex string".to_string());
        }
        if !is_prefixed_sha256(&self.bridge_input_sha256) {
            errors.push("bridge_input_sha256 must be a 0x-prefixed bytes32 hex string".to_string());
        }
        if self.tree_depth != ORACLE_FACTS_ROOT_TREE_DEPTH {
            errors.push(format!(
                "tree_depth must be {ORACLE_FACTS_ROOT_TREE_DEPTH}, got {}",
                self.tree_depth
            ));
        }
        if self.leaf_index != ORACLE_FACTS_ROOT_LEAF_INDEX {
            errors.push(format!(
                "leaf_index must be {ORACLE_FACTS_ROOT_LEAF_INDEX}, got {}",
                self.leaf_index
            ));
        }
        if let Err(mut source_errors) = validate_oracle_source_parts(
            &self.source_manifest_id,
            &self.facts,
            &self.attestation_refs,
        ) {
            errors.append(&mut source_errors);
        }
        if self.fact_count != self.facts.len() {
            errors.push("fact_count does not match facts length".to_string());
        }
        if self.attestation_count != self.attestation_refs.len() {
            errors.push("attestation_count does not match attestation_refs length".to_string());
        }
        if self.verified_fact_count != self.fact_count {
            errors.push("verified_fact_count must equal fact_count".to_string());
        }

        let expected_order: Vec<String> = ORACLE_FACTS_ROOT_LEAF_PREIMAGE_ORDER
            .iter()
            .map(|value| (*value).to_string())
            .collect();
        if self.leaf_preimage_order != expected_order {
            errors.push("leaf_preimage_order does not match the canonical V1 order".to_string());
        }

        let expected_preimage = canonical_oracle_facts_leaf_preimage_from_parts(
            &self.claim_hash,
            &self.source_manifest_id,
            &self.facts,
            &self.attestation_refs,
        );
        let preimage = strings_to_felts(
            "leaf_preimage_decimal",
            &self.leaf_preimage_decimal,
            ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH,
        );
        match (expected_preimage, preimage) {
            (Ok(expected), Ok(actual)) => {
                if actual != expected {
                    errors.push(
                        "leaf_preimage_decimal does not match canonical oracle source data"
                            .to_string(),
                    );
                }
                let expected_leaf = Rp64_256::hash_elements(&expected);
                match strings_to_digest("leaf_digest_elements", &self.leaf_digest_elements) {
                    Ok(actual_leaf) if actual_leaf != expected_leaf => errors.push(
                        "leaf_digest_elements do not match leaf_preimage_decimal".to_string(),
                    ),
                    Err(mut parse_errors) => errors.append(&mut parse_errors),
                    _ => {}
                }
            }
            (Err(mut source_errors), _) => errors.append(&mut source_errors),
            (_, Err(mut parse_errors)) => errors.append(&mut parse_errors),
        }

        let leaf = strings_to_digest("leaf_digest_elements", &self.leaf_digest_elements);
        let path = strings_to_digest_path("merkle_path_elements", &self.merkle_path_elements);
        let root = strings_to_digest("root_elements", &self.root_elements);
        match (leaf, path, root) {
            (Ok(leaf), Ok(path), Ok(root)) => {
                if path.len() != ORACLE_FACTS_ROOT_TREE_DEPTH {
                    errors.push(format!(
                        "merkle_path_elements must contain {ORACLE_FACTS_ROOT_TREE_DEPTH} digests"
                    ));
                } else {
                    match build_oracle_facts_tree(leaf) {
                        Ok(tree) => {
                            let (_, expected_path) = tree
                                .prove(ORACLE_FACTS_ROOT_LEAF_INDEX)
                                .expect("canonical oracle leaf index must be in range");
                            if path != expected_path {
                                errors.push(
                                    "merkle_path_elements do not match canonical oracle empty leaves"
                                        .to_string(),
                                );
                            }
                            if &root != tree.root() {
                                errors.push(
                                    "root_elements do not match the canonical oracle-facts tree"
                                        .to_string(),
                                );
                            }
                        }
                        Err(mut tree_errors) => errors.append(&mut tree_errors),
                    }
                    if MerkleTree::<Rp64_256>::verify(
                        root,
                        ORACLE_FACTS_ROOT_LEAF_INDEX,
                        leaf,
                        &path,
                    )
                    .is_err()
                    {
                        errors.push(
                            "oracle-facts leaf does not verify under the supplied Merkle root"
                                .to_string(),
                        );
                    }
                }

                let root_elements: [ProductionFelt; 4] = root
                    .as_elements()
                    .try_into()
                    .expect("Rp64_256 digest must contain four field elements");
                if self.oracle_facts_root_bytes32 != pack_public_input_root_bytes32(&root_elements)
                {
                    errors
                        .push("oracle_facts_root_bytes32 does not match root_elements".to_string());
                }
            }
            (Err(mut parse_errors), _, _) => errors.append(&mut parse_errors),
            (_, Err(mut parse_errors), _) => errors.append(&mut parse_errors),
            (_, _, Err(mut parse_errors)) => errors.append(&mut parse_errors),
        }

        if self.merkle_path_indices != merkle_path_indices(ORACLE_FACTS_ROOT_LEAF_INDEX) {
            errors.push("merkle_path_indices do not match leaf_index".to_string());
        }
        if unpack_public_input_root_bytes32(&self.oracle_facts_root_bytes32).is_err() {
            errors.push(
                "oracle_facts_root_bytes32 must use canonical f64 bytes32 encoding".to_string(),
            );
        }
        if self.runtime_wired {
            errors.push("runtime_wired must remain false".to_string());
        }
        if self.on_chain_verifier_wired {
            errors.push("on_chain_verifier_wired must remain false".to_string());
        }
        if self.on_chain_submission {
            errors.push("on_chain_submission must remain false".to_string());
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

#[cfg(feature = "production-air-winterfell")]
pub fn canonical_oracle_facts_leaf_preimage(
    bridge: &StarkBridgeInput,
) -> Result<[ProductionFelt; ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH], Vec<String>> {
    validate_bridge_oracle_sources(bridge)?;
    canonical_oracle_facts_leaf_preimage_from_parts(
        &bridge.claim.claim_hash,
        bridge
            .claim
            .oracle_source_manifest_id
            .as_deref()
            .expect("validated oracle source manifest must be present"),
        &bridge.claim.oracle_facts,
        &bridge.claim.oracle_attestation_refs,
    )
}

#[cfg(feature = "production-air-winterfell")]
fn canonical_oracle_facts_leaf_preimage_from_parts(
    claim_hash: &str,
    source_manifest_id: &str,
    facts: &[OracleFactInput],
    attestation_refs: &[String],
) -> Result<[ProductionFelt; ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH], Vec<String>> {
    validate_oracle_source_parts(source_manifest_id, facts, attestation_refs)?;
    let claim_hash_limbs = parse_claim_hash_limbs(claim_hash)?;
    let manifest_digest = hash_text(ORACLE_MANIFEST_DOMAIN_TAG, source_manifest_id.trim());
    let facts_digest = hash_oracle_facts(facts);
    let attestations_digest = hash_oracle_attestations(attestation_refs);

    let mut preimage = [ProductionFelt::ZERO; ORACLE_FACTS_ROOT_LEAF_PREIMAGE_LENGTH];
    preimage[0] = felt(ORACLE_FACTS_ROOT_DOMAIN_TAG);
    preimage[1] = felt(ORACLE_FACTS_ROOT_SCHEMA_TAG);
    preimage[2] = felt(ORACLE_FACTS_ROOT_HASH_TAG);
    preimage[3] = felt(ORACLE_FACTS_ROOT_NORMALIZATION_TAG);
    preimage[4..12].copy_from_slice(&claim_hash_limbs);
    preimage[12..16].copy_from_slice(manifest_digest.as_elements());
    preimage[16..20].copy_from_slice(facts_digest.as_elements());
    preimage[20..24].copy_from_slice(attestations_digest.as_elements());
    preimage[24] = ProductionFelt::ONE;
    preimage[25] = ProductionFelt::ONE;
    preimage[26] = ProductionFelt::ONE;
    preimage[27] = felt(facts.len() as u64);
    preimage[28] = felt(attestation_refs.len() as u64);
    preimage[29] = felt(facts.len() as u64);
    Ok(preimage)
}

#[cfg(feature = "production-air-winterfell")]
pub fn canonical_claim_source_leaf_preimage(
    bridge: &StarkBridgeInput,
) -> Result<[ProductionFelt; CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH], Vec<String>> {
    validate_bridge_claim_source(bridge)?;
    let claim_hash_limbs = parse_claim_hash_limbs(&bridge.claim.claim_hash)?;
    let member_digest = hash_text(
        MEMBER_ID_DOMAIN_TAG,
        bridge
            .claim
            .member_id
            .as_deref()
            .expect("validated member_id must be present")
            .trim(),
    );
    let provider_digest = hash_text(
        PROVIDER_NPI_DOMAIN_TAG,
        bridge
            .claim
            .provider_npi
            .as_deref()
            .expect("validated provider_npi must be present"),
    );
    let service_lines_digest = hash_service_lines(bridge);
    let diagnoses_digest = hash_diagnoses(bridge);

    let mut preimage = [ProductionFelt::ZERO; CLAIM_SOURCE_ROOT_LEAF_PREIMAGE_LENGTH];
    preimage[0] = felt(CLAIM_SOURCE_ROOT_DOMAIN_TAG);
    preimage[1] = felt(CLAIM_SOURCE_ROOT_SCHEMA_TAG);
    preimage[2] = felt(CLAIM_SOURCE_ROOT_HASH_TAG);
    preimage[3] = felt(CLAIM_SOURCE_ROOT_UNIT_TAG);
    preimage[4..12].copy_from_slice(&claim_hash_limbs);
    preimage[12..16].copy_from_slice(member_digest.as_elements());
    preimage[16..20].copy_from_slice(provider_digest.as_elements());
    preimage[20] = ProductionFelt::ONE;
    preimage[21] = ProductionFelt::ONE;
    preimage[22] = ProductionFelt::ONE;
    preimage[23] = ProductionFelt::ONE;
    preimage[24] = felt(bridge.claim.service_lines.len() as u64);
    preimage[25] = felt(bridge.claim.diagnosis_codes.len() as u64);
    preimage[26] = felt(normalized_total_charge_cents(bridge)?);
    preimage[27] = felt(bridge.active_rust_facts.date_of_service_from);
    preimage[28..32].copy_from_slice(service_lines_digest.as_elements());
    preimage[32..36].copy_from_slice(diagnoses_digest.as_elements());
    Ok(preimage)
}

#[cfg(feature = "production-air-winterfell")]
fn validate_bridge_claim_source(bridge: &StarkBridgeInput) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    match bridge.claim.member_id.as_deref() {
        Some(value) if !value.trim().is_empty() => {}
        _ => errors.push("claim.member_id must be present for claimSourceRoot".to_string()),
    }
    match bridge.claim.provider_npi.as_deref() {
        Some(value) if value.len() == 10 && value.bytes().all(|byte| byte.is_ascii_digit()) => {}
        _ => errors.push(
            "claim.provider_npi must be a present ten-digit string for claimSourceRoot".to_string(),
        ),
    }
    if bridge.claim.service_lines.is_empty() {
        errors.push("claim.service_lines must contain at least one service line".to_string());
    }
    for (index, line) in bridge.claim.service_lines.iter().enumerate() {
        if line.procedure_code.trim().is_empty() {
            errors.push(format!(
                "claim.service_lines[{index}].procedure_code must be present"
            ));
        }
        if line.charge_cents == 0 || line.charge_cents > u32::MAX as u64 {
            errors.push(format!(
                "claim.service_lines[{index}].charge_cents must be in 1..=u32::MAX"
            ));
        }
        if line.units == 0 || line.units > u32::MAX as u64 {
            errors.push(format!(
                "claim.service_lines[{index}].units must be in 1..=u32::MAX"
            ));
        }
    }
    if bridge.claim.diagnosis_codes.is_empty() {
        errors.push("claim.diagnosis_codes must contain at least one diagnosis".to_string());
    }
    for (index, code) in bridge.claim.diagnosis_codes.iter().enumerate() {
        if code.trim().is_empty() {
            errors.push(format!("claim.diagnosis_codes[{index}] must be present"));
        }
    }
    match bridge.claim.diagnosis_count {
        Some(value) if value == bridge.claim.diagnosis_codes.len() as u64 => {}
        Some(value) => errors.push(format!(
            "claim.diagnosis_count {value} does not match diagnosis_codes length {}",
            bridge.claim.diagnosis_codes.len()
        )),
        None => {
            errors.push("claim.diagnosis_count must be present for claimSourceRoot".to_string())
        }
    }
    if bridge.active_rust_facts.date_of_service_from > u32::MAX as u64 {
        errors.push("active_rust_facts.date_of_service_from must fit in u32".to_string());
    }

    match normalized_total_charge_cents(bridge) {
        Ok(total) => {
            match bridge
                .claim
                .service_lines
                .iter()
                .try_fold(0_u64, |sum, line| sum.checked_add(line.charge_cents))
            {
                Some(line_total) if line_total == total => {}
                Some(line_total) => errors.push(format!(
                    "service line charges total {line_total} but normalized claim total is {total}"
                )),
                None => errors.push("service line charge total overflowed u64".to_string()),
            }
            if let Some(max_charge_cents) = bridge.claim.max_charge_cents
                && total > max_charge_cents
            {
                errors.push(format!(
                    "normalized claim total {total} exceeds max_charge_cents {max_charge_cents}"
                ));
            }
        }
        Err(mut total_errors) => errors.append(&mut total_errors),
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(feature = "production-air-winterfell")]
fn validate_bridge_oracle_sources(bridge: &StarkBridgeInput) -> Result<(), Vec<String>> {
    let Some(source_manifest_id) = bridge.claim.oracle_source_manifest_id.as_deref() else {
        return Err(vec![
            "claim.oracle_source_manifest_id must be present for oracleFactsRoot".to_string(),
        ]);
    };
    validate_oracle_source_parts(
        source_manifest_id,
        &bridge.claim.oracle_facts,
        &bridge.claim.oracle_attestation_refs,
    )
}

#[cfg(feature = "production-air-winterfell")]
fn validate_oracle_source_parts(
    source_manifest_id: &str,
    facts: &[OracleFactInput],
    attestation_refs: &[String],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if source_manifest_id.trim().is_empty() {
        errors.push("oracle source_manifest_id must be present".to_string());
    }
    if facts.is_empty() {
        errors.push("oracle facts must contain at least one verified fact".to_string());
    }

    let mut canonical_fact_keys = Vec::with_capacity(facts.len());
    for (index, fact) in facts.iter().enumerate() {
        let normalized = normalized_oracle_fact(fact);
        if normalized.iter().any(|value| value.is_empty()) {
            errors.push(format!(
                "oracle facts[{index}] requires fact_type, fact_key, fact_value, source_url, source_label, and verification_status"
            ));
        }
        if !normalized[3].starts_with("https://") {
            errors.push(format!("oracle facts[{index}].source_url must use https"));
        }
        if normalized[5] != "verified" {
            errors.push(format!(
                "oracle facts[{index}].verification_status must be verified"
            ));
        }
        canonical_fact_keys.push(normalized.join("\u{1f}"));
    }
    canonical_fact_keys.sort();
    if canonical_fact_keys
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        errors.push("oracle facts must not contain duplicate canonical entries".to_string());
    }

    if attestation_refs.is_empty() {
        errors.push("oracle attestation_refs must contain at least one reference".to_string());
    }
    let mut normalized_refs = attestation_refs
        .iter()
        .map(|value| value.trim().to_string())
        .collect::<Vec<_>>();
    if normalized_refs.iter().any(|value| value.is_empty()) {
        errors.push("oracle attestation_refs must be non-empty".to_string());
    }
    normalized_refs.sort();
    if normalized_refs.windows(2).any(|pair| pair[0] == pair[1]) {
        errors.push("oracle attestation_refs must not contain duplicates".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(feature = "production-air-winterfell")]
fn normalized_total_charge_cents(bridge: &StarkBridgeInput) -> Result<u64, Vec<String>> {
    match bridge.claim.claim_amount.checked_mul(100) {
        Some(value) if value > 0 && value <= u32::MAX as u64 => Ok(value),
        Some(_) => Err(vec![
            "claim.claim_amount normalized to cents must be in 1..=u32::MAX".to_string(),
        ]),
        None => Err(vec![
            "claim.claim_amount overflowed while normalizing whole currency units to cents"
                .to_string(),
        ]),
    }
}

#[cfg(feature = "production-air-winterfell")]
fn hash_service_lines(bridge: &StarkBridgeInput) -> ClaimSourceDigest {
    let mut elements = vec![
        felt(SERVICE_LINES_DOMAIN_TAG),
        felt(CLAIM_SOURCE_ROOT_SCHEMA_TAG),
        felt(bridge.claim.service_lines.len() as u64),
    ];
    for line in &bridge.claim.service_lines {
        let normalized_code = line.procedure_code.trim().to_ascii_uppercase();
        elements.extend_from_slice(
            hash_text(PROCEDURE_CODE_DOMAIN_TAG, &normalized_code).as_elements(),
        );
        elements.push(felt(line.charge_cents));
        elements.push(felt(line.units));
    }
    Rp64_256::hash_elements(&elements)
}

#[cfg(feature = "production-air-winterfell")]
fn hash_diagnoses(bridge: &StarkBridgeInput) -> ClaimSourceDigest {
    let mut elements = vec![
        felt(DIAGNOSES_DOMAIN_TAG),
        felt(CLAIM_SOURCE_ROOT_SCHEMA_TAG),
        felt(bridge.claim.diagnosis_codes.len() as u64),
    ];
    for code in &bridge.claim.diagnosis_codes {
        let normalized_code = code.trim().to_ascii_uppercase();
        elements.extend_from_slice(
            hash_text(DIAGNOSIS_CODE_DOMAIN_TAG, &normalized_code).as_elements(),
        );
    }
    Rp64_256::hash_elements(&elements)
}

#[cfg(feature = "production-air-winterfell")]
fn hash_oracle_facts(facts: &[OracleFactInput]) -> ClaimSourceDigest {
    let mut canonical_facts = facts
        .iter()
        .map(normalized_oracle_fact)
        .collect::<Vec<[String; 6]>>();
    canonical_facts.sort();

    let mut aggregate = vec![
        felt(ORACLE_FACTS_DOMAIN_TAG),
        felt(ORACLE_FACTS_ROOT_SCHEMA_TAG),
        felt(canonical_facts.len() as u64),
    ];
    for fact in canonical_facts {
        let mut fact_elements = vec![
            felt(ORACLE_FACT_DOMAIN_TAG),
            felt(ORACLE_FACTS_ROOT_SCHEMA_TAG),
        ];
        for value in fact {
            fact_elements
                .extend_from_slice(hash_text(ORACLE_FACT_DOMAIN_TAG, &value).as_elements());
        }
        let digest = Rp64_256::hash_elements(&fact_elements);
        aggregate.extend_from_slice(digest.as_elements());
    }
    Rp64_256::hash_elements(&aggregate)
}

#[cfg(feature = "production-air-winterfell")]
fn hash_oracle_attestations(attestation_refs: &[String]) -> ClaimSourceDigest {
    let mut refs = attestation_refs
        .iter()
        .map(|value| value.trim().to_string())
        .collect::<Vec<_>>();
    refs.sort();

    let mut elements = vec![
        felt(ORACLE_ATTESTATIONS_DOMAIN_TAG),
        felt(ORACLE_FACTS_ROOT_SCHEMA_TAG),
        felt(refs.len() as u64),
    ];
    for value in refs {
        elements.extend_from_slice(hash_text(ORACLE_ATTESTATION_DOMAIN_TAG, &value).as_elements());
    }
    Rp64_256::hash_elements(&elements)
}

#[cfg(feature = "production-air-winterfell")]
fn normalized_oracle_fact(fact: &OracleFactInput) -> [String; 6] {
    [
        fact.fact_type.trim().to_ascii_lowercase(),
        fact.fact_key.trim().to_ascii_lowercase(),
        fact.fact_value.trim().to_string(),
        fact.source_url
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_string(),
        fact.source_label
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_string(),
        fact.verification_status.trim().to_ascii_lowercase(),
    ]
}

#[cfg(feature = "production-air-winterfell")]
fn hash_text(domain_tag: u64, value: &str) -> ClaimSourceDigest {
    let bytes = value.as_bytes();
    let mut elements = vec![felt(domain_tag), felt(bytes.len() as u64)];
    for chunk in bytes.chunks(7) {
        let mut packed = [0_u8; 8];
        packed[..chunk.len()].copy_from_slice(chunk);
        elements.push(felt(u64::from_le_bytes(packed)));
    }
    Rp64_256::hash_elements(&elements)
}

#[cfg(feature = "production-air-winterfell")]
fn build_claim_source_tree(
    claim_leaf: ClaimSourceDigest,
) -> Result<MerkleTree<Rp64_256>, Vec<String>> {
    let leaf_count = 1_usize << CLAIM_SOURCE_ROOT_TREE_DEPTH;
    let mut leaves = (0..leaf_count).map(indexed_empty_leaf).collect::<Vec<_>>();
    leaves[CLAIM_SOURCE_ROOT_LEAF_INDEX] = claim_leaf;
    MerkleTree::<Rp64_256>::new(leaves)
        .map_err(|error| vec![format!("could not build claim-source Merkle tree: {error}")])
}

#[cfg(feature = "production-air-winterfell")]
fn build_oracle_facts_tree(
    oracle_leaf: ClaimSourceDigest,
) -> Result<MerkleTree<Rp64_256>, Vec<String>> {
    let leaf_count = 1_usize << ORACLE_FACTS_ROOT_TREE_DEPTH;
    let mut leaves = (0..leaf_count)
        .map(indexed_oracle_empty_leaf)
        .collect::<Vec<_>>();
    leaves[ORACLE_FACTS_ROOT_LEAF_INDEX] = oracle_leaf;
    MerkleTree::<Rp64_256>::new(leaves)
        .map_err(|error| vec![format!("could not build oracle-facts Merkle tree: {error}")])
}

#[cfg(feature = "production-air-winterfell")]
fn indexed_empty_leaf(index: usize) -> ClaimSourceDigest {
    Rp64_256::hash_elements(&[
        felt(EMPTY_LEAF_DOMAIN_TAG),
        felt(CLAIM_SOURCE_ROOT_SCHEMA_TAG),
        felt(index as u64),
    ])
}

#[cfg(feature = "production-air-winterfell")]
fn indexed_oracle_empty_leaf(index: usize) -> ClaimSourceDigest {
    Rp64_256::hash_elements(&[
        felt(ORACLE_EMPTY_LEAF_DOMAIN_TAG),
        felt(ORACLE_FACTS_ROOT_SCHEMA_TAG),
        felt(index as u64),
    ])
}

#[cfg(feature = "production-air-winterfell")]
fn merkle_path_indices(mut index: usize) -> Vec<u8> {
    (0..CLAIM_SOURCE_ROOT_TREE_DEPTH)
        .map(|_| {
            let bit = (index & 1) as u8;
            index >>= 1;
            bit
        })
        .collect()
}

#[cfg(feature = "production-air-winterfell")]
fn bridge_input_sha256(bridge: &StarkBridgeInput) -> Result<String, Vec<String>> {
    let bytes = serde_json::to_vec(bridge)
        .map_err(|error| vec![format!("could not serialize bridge input: {error}")])?;
    Ok(prefixed_sha256(&bytes))
}

#[cfg(feature = "production-air-winterfell")]
fn validate_preimage_metadata(
    artifact: &ProductionClaimSourceRootArtifactV1,
    preimage: &[ProductionFelt],
    errors: &mut Vec<String>,
) {
    let expected_header = [
        felt(CLAIM_SOURCE_ROOT_DOMAIN_TAG),
        felt(CLAIM_SOURCE_ROOT_SCHEMA_TAG),
        felt(CLAIM_SOURCE_ROOT_HASH_TAG),
        felt(CLAIM_SOURCE_ROOT_UNIT_TAG),
    ];
    if preimage[0..4] != expected_header {
        errors.push("leaf preimage header does not match the V1 domain".to_string());
    }
    if let Ok(claim_hash_limbs) = parse_claim_hash_limbs(&artifact.claim_hash)
        && preimage[4..12] != claim_hash_limbs
    {
        errors.push("leaf preimage claim hash limbs do not match claim_hash".to_string());
    }
    if preimage[20..24] != [ProductionFelt::ONE; 4] {
        errors.push("claim-source presence flags must all be one".to_string());
    }
    if preimage[24].as_int() != artifact.service_line_count as u64 {
        errors.push("leaf service_line_count does not match artifact metadata".to_string());
    }
    if preimage[25].as_int() != artifact.diagnosis_count as u64 {
        errors.push("leaf diagnosis_count does not match artifact metadata".to_string());
    }
    if preimage[26].as_int() != artifact.total_charge_cents {
        errors.push("leaf total_charge_cents does not match artifact metadata".to_string());
    }
    if preimage[27].as_int() != artifact.service_date {
        errors.push("leaf service_date does not match artifact metadata".to_string());
    }
}

#[cfg(feature = "production-air-winterfell")]
fn parse_claim_hash_limbs(claim_hash: &str) -> Result<[ProductionFelt; 8], Vec<String>> {
    let hex = claim_hash.strip_prefix("0x").unwrap_or(claim_hash);
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(vec![
            "claim_hash must be a 0x-prefixed bytes32 hex string".to_string(),
        ]);
    }
    let mut limbs = [ProductionFelt::ZERO; 8];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = index * 8;
        let value = u32::from_str_radix(&hex[start..start + 8], 16)
            .map_err(|error| vec![format!("invalid claim_hash limb {index}: {error}")])?;
        *limb = felt(value as u64);
    }
    Ok(limbs)
}

#[cfg(feature = "production-air-winterfell")]
fn strings_to_felts(
    field: &str,
    values: &[String],
    expected_len: usize,
) -> Result<Vec<ProductionFelt>, Vec<String>> {
    let mut errors = Vec::new();
    if values.len() != expected_len {
        errors.push(format!(
            "{field} must contain {expected_len} values, got {}",
            values.len()
        ));
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

#[cfg(feature = "production-air-winterfell")]
fn strings_to_digest(field: &str, values: &[String; 4]) -> Result<ClaimSourceDigest, Vec<String>> {
    let parsed = strings_to_felts(field, values, 4)?;
    let elements: [ProductionFelt; 4] = parsed
        .try_into()
        .expect("validated digest must contain four elements");
    Ok(elements.into())
}

#[cfg(feature = "production-air-winterfell")]
fn strings_to_digest_path(
    field: &str,
    values: &[[String; 4]],
) -> Result<Vec<ClaimSourceDigest>, Vec<String>> {
    let mut path = Vec::with_capacity(values.len());
    let mut errors = Vec::new();
    for (index, value) in values.iter().enumerate() {
        match strings_to_digest(&format!("{field}[{index}]"), value) {
            Ok(digest) => path.push(digest),
            Err(mut parse_errors) => errors.append(&mut parse_errors),
        }
    }
    if errors.is_empty() {
        Ok(path)
    } else {
        Err(errors)
    }
}

#[cfg(feature = "production-air-winterfell")]
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

#[cfg(feature = "production-air-winterfell")]
fn felts_to_strings(values: &[ProductionFelt]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_int().to_string())
        .collect()
}

#[cfg(feature = "production-air-winterfell")]
fn digest_to_strings(digest: &ClaimSourceDigest) -> [String; 4] {
    core::array::from_fn(|index| digest.as_elements()[index].as_int().to_string())
}

#[cfg(feature = "production-air-winterfell")]
fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("0x{:x}", Sha256::digest(bytes))
}

#[cfg(feature = "production-air-winterfell")]
fn is_prefixed_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(feature = "production-air-winterfell")]
fn validate_exact(field: &str, actual: &str, expected: &str, errors: &mut Vec<String>) {
    if actual != expected {
        errors.push(format!("{field} must be {expected}, got {actual}"));
    }
}

#[cfg(feature = "production-air-winterfell")]
fn felt(value: u64) -> ProductionFelt {
    ProductionFelt::new(value)
}
