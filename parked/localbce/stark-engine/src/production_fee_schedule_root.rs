//! Canonical, feature-gated fee-schedule root for the production STARK lane.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use winterfell::{
    crypto::{ElementHasher, Hasher, MerkleTree, hashers::Rp64_256},
    math::FieldElement,
};

use crate::{
    FeeScheduleEntryInput, StarkBridgeInput,
    production_air_winterfell::{
        ProductionFelt, pack_public_input_root_bytes32, unpack_public_input_root_bytes32,
    },
};

type FeeScheduleDigest = <Rp64_256 as Hasher>::Digest;

pub const FEE_SCHEDULE_ROOT_SCHEMA_VERSION: &str = "stark-fee-schedule-root-v1";
pub const FEE_SCHEDULE_ROOT_HASH_FUNCTION: &str = "winterfell-rp64-256";
pub const FEE_SCHEDULE_ROOT_ENCODING: &str = "bytes32-four-canonical-f64-big-endian";
pub const FEE_SCHEDULE_ROOT_TREE_DEPTH: usize = 10;
pub const FEE_SCHEDULE_ROOT_LEAF_INDEX: usize = 13;
pub const FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH: usize = 32;

pub(crate) const FEE_SCHEDULE_ROOT_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCFR001");
pub(crate) const FEE_SCHEDULE_ROOT_SCHEMA_TAG: u64 = 1;
pub(crate) const FEE_SCHEDULE_ROOT_HASH_TAG: u64 = u64::from_le_bytes(*b"RP64256\0");
pub(crate) const FEE_SCHEDULE_ROOT_NORMALIZATION_TAG: u64 = u64::from_le_bytes(*b"FECANON1");
const FEE_SCHEDULE_ID_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCFSID1");
const FEE_ENTRIES_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCFENTS");
const FEE_ENTRY_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCFENT1");
const FEE_TEXT_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCFTXT1");
const SERVICE_LINES_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCLINE1");
const PROCEDURE_CODE_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCPROC1");
const CLAIM_SOURCE_ROOT_SCHEMA_TAG: u64 = 1;
const FEE_EMPTY_LEAF_DOMAIN_TAG: u64 = u64::from_le_bytes(*b"LBCFEMPT");

pub const FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_ORDER: [&str; FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH] = [
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
    "fee_schedule_id_digest_element_0",
    "fee_schedule_id_digest_element_1",
    "fee_schedule_id_digest_element_2",
    "fee_schedule_id_digest_element_3",
    "entries_digest_element_0",
    "entries_digest_element_1",
    "entries_digest_element_2",
    "entries_digest_element_3",
    "service_lines_digest_element_0",
    "service_lines_digest_element_1",
    "service_lines_digest_element_2",
    "service_lines_digest_element_3",
    "fee_schedule_present",
    "entries_present",
    "all_service_lines_matched",
    "entry_count",
    "matched_service_line_count",
    "service_date",
    "total_allowed_cents",
    "total_charged_cents",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionFeeScheduleMatchV1 {
    pub procedure_code: String,
    pub units: u64,
    pub charge_cents: u64,
    pub matched_unit_amount_cents: u64,
    pub allowed_amount_cents: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionFeeScheduleRootArtifactV1 {
    pub schema_version: String,
    pub source_schema_version: String,
    pub artifact_status: String,
    pub hash_function: String,
    pub root_encoding: String,
    pub empty_leaf_strategy: String,
    pub bridge_input_sha256: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub fee_schedule_id: String,
    pub entries: Vec<FeeScheduleEntryInput>,
    pub matched_service_lines: Vec<ProductionFeeScheduleMatchV1>,
    pub tree_depth: usize,
    pub leaf_index: usize,
    pub entry_count: usize,
    pub verified_entry_count: usize,
    pub matched_service_line_count: usize,
    pub service_date: u64,
    pub total_allowed_cents: u64,
    pub total_charged_cents: u64,
    pub leaf_preimage_order: Vec<String>,
    pub leaf_preimage_decimal: Vec<String>,
    pub leaf_digest_elements: [String; 4],
    pub merkle_path_elements: Vec<[String; 4]>,
    pub merkle_path_indices: Vec<u8>,
    pub root_elements: [String; 4],
    pub fee_schedule_root_bytes32: String,
    pub governance_status: String,
    pub source_verification_status: String,
    pub air_binding_status: String,
    pub runtime_wired: bool,
    pub on_chain_verifier_wired: bool,
    pub on_chain_submission: bool,
    pub groth16_flow_unchanged: bool,
}

impl ProductionFeeScheduleRootArtifactV1 {
    pub const SCHEMA_VERSION: &'static str = FEE_SCHEDULE_ROOT_SCHEMA_VERSION;
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const ARTIFACT_STATUS: &'static str =
        "locally_generated_fee_schedule_root_air_bound_not_governed";
    pub const EMPTY_LEAF_STRATEGY: &'static str =
        "rp64_256_domain_separated_indexed_fee_schedule_empty_leaves";
    pub const GOVERNANCE_STATUS: &'static str = "not_registered_or_approved";
    pub const SOURCE_VERIFICATION_STATUS: &'static str =
        "verified_labels_and_https_references_committed_not_externally_verified";
    pub const AIR_BINDING_STATUS: &'static str =
        "production_air_v4_constrains_canonical_leaf_path_root_and_claim_source_links";

    pub fn from_bridge_input(bridge: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        bridge.validate()?;
        let schedule_id = bridge.claim.fee_schedule_id.as_deref().ok_or_else(|| {
            vec!["claim.fee_schedule_id must be present for feeScheduleRoot".to_string()]
        })?;
        let matches = validate_and_match_fee_schedule(bridge)?;
        let total_allowed_cents = checked_total(&matches, |item| item.allowed_amount_cents)?;
        let total_charged_cents = checked_total(&matches, |item| item.charge_cents)?;
        let preimage = canonical_fee_schedule_leaf_preimage_from_parts(
            &bridge.claim.claim_hash,
            schedule_id,
            &bridge.claim.fee_schedule_entries,
            &matches,
            bridge.active_rust_facts.date_of_service_from,
        )?;
        let leaf_digest = Rp64_256::hash_elements(&preimage);
        let tree = build_fee_schedule_tree(leaf_digest)?;
        let (opened_leaf, path) = tree
            .prove(FEE_SCHEDULE_ROOT_LEAF_INDEX)
            .map_err(|error| vec![format!("could not open fee-schedule Merkle leaf: {error}")])?;
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
            hash_function: FEE_SCHEDULE_ROOT_HASH_FUNCTION.to_string(),
            root_encoding: FEE_SCHEDULE_ROOT_ENCODING.to_string(),
            empty_leaf_strategy: Self::EMPTY_LEAF_STRATEGY.to_string(),
            bridge_input_sha256: prefixed_sha256(
                &serde_json::to_vec(bridge)
                    .map_err(|error| vec![format!("could not serialize bridge input: {error}")])?,
            ),
            claim_id: bridge.claim.claim_id.clone(),
            claim_hash: bridge.claim.claim_hash.clone(),
            fee_schedule_id: schedule_id.trim().to_string(),
            entries: bridge.claim.fee_schedule_entries.clone(),
            matched_service_lines: matches,
            tree_depth: FEE_SCHEDULE_ROOT_TREE_DEPTH,
            leaf_index: FEE_SCHEDULE_ROOT_LEAF_INDEX,
            entry_count: bridge.claim.fee_schedule_entries.len(),
            verified_entry_count: bridge.claim.fee_schedule_entries.len(),
            matched_service_line_count: bridge.claim.service_lines.len(),
            service_date: bridge.active_rust_facts.date_of_service_from,
            total_allowed_cents,
            total_charged_cents,
            leaf_preimage_order: FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_ORDER
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            leaf_preimage_decimal: felts_to_strings(&preimage),
            leaf_digest_elements: digest_to_strings(&leaf_digest),
            merkle_path_elements: path.iter().map(digest_to_strings).collect(),
            merkle_path_indices: merkle_path_indices(FEE_SCHEDULE_ROOT_LEAF_INDEX),
            root_elements: root.map(|element| element.as_int().to_string()),
            fee_schedule_root_bytes32: pack_public_input_root_bytes32(&root),
            governance_status: Self::GOVERNANCE_STATUS.to_string(),
            source_verification_status: Self::SOURCE_VERIFICATION_STATUS.to_string(),
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
            [ProductionFelt; FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH],
            [[ProductionFelt; 4]; FEE_SCHEDULE_ROOT_TREE_DEPTH],
            [ProductionFelt; 4],
        ),
        Vec<String>,
    > {
        self.validate()?;
        let preimage: [ProductionFelt; FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH] = strings_to_felts(
            "leaf_preimage_decimal",
            &self.leaf_preimage_decimal,
            FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH,
        )?
        .try_into()
        .expect("validated fee-schedule leaf preimage length");
        let path: [[ProductionFelt; 4]; FEE_SCHEDULE_ROOT_TREE_DEPTH] = self
            .merkle_path_elements
            .iter()
            .enumerate()
            .map(|(index, value)| {
                strings_to_digest(&format!("merkle_path_elements[{index}]"), value)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .expect("validated fee-schedule Merkle path depth");
        let root = strings_to_digest("root_elements", &self.root_elements)?;
        Ok((preimage, path, root))
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
            FEE_SCHEDULE_ROOT_HASH_FUNCTION,
            &mut errors,
        );
        validate_exact(
            "root_encoding",
            &self.root_encoding,
            FEE_SCHEDULE_ROOT_ENCODING,
            &mut errors,
        );
        validate_exact(
            "empty_leaf_strategy",
            &self.empty_leaf_strategy,
            Self::EMPTY_LEAF_STRATEGY,
            &mut errors,
        );
        validate_exact(
            "governance_status",
            &self.governance_status,
            Self::GOVERNANCE_STATUS,
            &mut errors,
        );
        validate_exact(
            "source_verification_status",
            &self.source_verification_status,
            Self::SOURCE_VERIFICATION_STATUS,
            &mut errors,
        );
        validate_exact(
            "air_binding_status",
            &self.air_binding_status,
            Self::AIR_BINDING_STATUS,
            &mut errors,
        );

        if !is_prefixed_sha256(&self.bridge_input_sha256) {
            errors.push("bridge_input_sha256 must be a 0x-prefixed SHA-256 digest".to_string());
        }
        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }
        if parse_claim_hash_limbs(&self.claim_hash).is_err() {
            errors.push("claim_hash must be a 0x-prefixed bytes32 hex string".to_string());
        }
        if self.tree_depth != FEE_SCHEDULE_ROOT_TREE_DEPTH {
            errors.push(format!("tree_depth must be {FEE_SCHEDULE_ROOT_TREE_DEPTH}"));
        }
        if self.leaf_index != FEE_SCHEDULE_ROOT_LEAF_INDEX {
            errors.push(format!("leaf_index must be {FEE_SCHEDULE_ROOT_LEAF_INDEX}"));
        }
        if self.entry_count != self.entries.len() || self.verified_entry_count != self.entries.len()
        {
            errors.push("entry counts must equal the number of verified entries".to_string());
        }
        if self.matched_service_line_count != self.matched_service_lines.len()
            || self.matched_service_lines.is_empty()
        {
            errors.push("matched_service_line_count must equal a non-empty match list".to_string());
        }
        match checked_total(&self.matched_service_lines, |item| {
            item.allowed_amount_cents
        }) {
            Ok(total) if self.total_allowed_cents == total => {}
            Ok(_) => {
                errors.push("total_allowed_cents does not match service-line matches".to_string())
            }
            Err(mut total_errors) => errors.append(&mut total_errors),
        }
        match checked_total(&self.matched_service_lines, |item| item.charge_cents) {
            Ok(total) if self.total_charged_cents == total => {}
            Ok(_) => {
                errors.push("total_charged_cents does not match service-line matches".to_string())
            }
            Err(mut total_errors) => errors.append(&mut total_errors),
        }
        if self.total_charged_cents > self.total_allowed_cents {
            errors.push("total_charged_cents must not exceed total_allowed_cents".to_string());
        }
        if let Err(mut entry_errors) =
            validate_fee_entry_parts(&self.fee_schedule_id, &self.entries)
        {
            errors.append(&mut entry_errors);
        }
        errors.extend(validate_stored_matches(
            &self.entries,
            &self.matched_service_lines,
            self.service_date,
        ));

        let expected_order = FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_ORDER
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        if self.leaf_preimage_order != expected_order {
            errors.push("leaf_preimage_order does not match the canonical V1 order".to_string());
        }

        let parsed_preimage = strings_to_felts(
            "leaf_preimage_decimal",
            &self.leaf_preimage_decimal,
            FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH,
        );
        let parsed_leaf = strings_to_digest("leaf_digest_elements", &self.leaf_digest_elements);
        let parsed_root = strings_to_digest("root_elements", &self.root_elements);
        let parsed_path = self
            .merkle_path_elements
            .iter()
            .enumerate()
            .map(|(index, value)| {
                strings_to_digest(&format!("merkle_path_elements[{index}]"), value)
            })
            .collect::<Result<Vec<_>, _>>();

        match (parsed_preimage, parsed_leaf, parsed_root, parsed_path) {
            (Ok(preimage), Ok(leaf), Ok(root), Ok(path)) => {
                let leaf_digest: FeeScheduleDigest = leaf.into();
                let root_digest: FeeScheduleDigest = root.into();
                let digest_path = path
                    .iter()
                    .copied()
                    .map(FeeScheduleDigest::from)
                    .collect::<Vec<_>>();
                if let Ok(expected) = canonical_fee_schedule_leaf_preimage_from_parts(
                    &self.claim_hash,
                    &self.fee_schedule_id,
                    &self.entries,
                    &self.matched_service_lines,
                    self.service_date,
                ) && preimage != expected
                {
                    errors.push(
                        "leaf_preimage_decimal does not match canonical fee data".to_string(),
                    );
                }
                if Rp64_256::hash_elements(&preimage) != leaf_digest {
                    errors.push(
                        "leaf_digest_elements does not hash leaf_preimage_decimal".to_string(),
                    );
                }
                if path.len() != FEE_SCHEDULE_ROOT_TREE_DEPTH {
                    errors.push(format!(
                        "merkle_path_elements must contain {FEE_SCHEDULE_ROOT_TREE_DEPTH} digests"
                    ));
                } else {
                    if let Ok(tree) = build_fee_schedule_tree(leaf_digest)
                        && *tree.root() != root_digest
                    {
                        errors.push(
                            "root_elements do not match the canonical fee-schedule tree"
                                .to_string(),
                        );
                    }
                    if MerkleTree::<Rp64_256>::verify(
                        root_digest,
                        FEE_SCHEDULE_ROOT_LEAF_INDEX,
                        leaf_digest,
                        &digest_path,
                    )
                    .is_err()
                    {
                        errors.push(
                            "fee-schedule leaf does not verify under the supplied root".to_string(),
                        );
                    }
                }
                if self.fee_schedule_root_bytes32 != pack_public_input_root_bytes32(&root) {
                    errors
                        .push("fee_schedule_root_bytes32 does not match root_elements".to_string());
                }
            }
            (Err(mut value), _, _, _) => errors.append(&mut value),
            (_, Err(mut value), _, _) => errors.append(&mut value),
            (_, _, Err(mut value), _) => errors.append(&mut value),
            (_, _, _, Err(mut value)) => errors.append(&mut value),
        }

        if self.merkle_path_indices != merkle_path_indices(FEE_SCHEDULE_ROOT_LEAF_INDEX) {
            errors.push("merkle_path_indices do not match leaf_index".to_string());
        }
        if unpack_public_input_root_bytes32(&self.fee_schedule_root_bytes32).is_err() {
            errors.push(
                "fee_schedule_root_bytes32 must use canonical f64 bytes32 encoding".to_string(),
            );
        }
        if self.runtime_wired || self.on_chain_verifier_wired || self.on_chain_submission {
            errors.push(
                "fee-schedule root must remain outside runtime and chain submission".to_string(),
            );
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

pub fn canonical_fee_schedule_leaf_preimage(
    bridge: &StarkBridgeInput,
) -> Result<[ProductionFelt; FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH], Vec<String>> {
    let schedule_id = bridge.claim.fee_schedule_id.as_deref().ok_or_else(|| {
        vec!["claim.fee_schedule_id must be present for feeScheduleRoot".to_string()]
    })?;
    let matches = validate_and_match_fee_schedule(bridge)?;
    canonical_fee_schedule_leaf_preimage_from_parts(
        &bridge.claim.claim_hash,
        schedule_id,
        &bridge.claim.fee_schedule_entries,
        &matches,
        bridge.active_rust_facts.date_of_service_from,
    )
}

fn canonical_fee_schedule_leaf_preimage_from_parts(
    claim_hash: &str,
    schedule_id: &str,
    entries: &[FeeScheduleEntryInput],
    matches: &[ProductionFeeScheduleMatchV1],
    service_date: u64,
) -> Result<[ProductionFelt; FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH], Vec<String>> {
    validate_fee_entry_parts(schedule_id, entries)?;
    if matches.is_empty() {
        return Err(vec![
            "fee schedule must match at least one service line".to_string(),
        ]);
    }
    let claim_hash_limbs = parse_claim_hash_limbs(claim_hash)?;
    let schedule_digest = hash_text(FEE_SCHEDULE_ID_DOMAIN_TAG, schedule_id.trim());
    let entries_digest = hash_fee_entries(entries);
    let service_lines_digest = hash_matched_service_lines(matches);
    let total_allowed = checked_total(matches, |item| item.allowed_amount_cents)?;
    let total_charged = checked_total(matches, |item| item.charge_cents)?;

    let mut preimage = [ProductionFelt::ZERO; FEE_SCHEDULE_ROOT_LEAF_PREIMAGE_LENGTH];
    preimage[0] = felt(FEE_SCHEDULE_ROOT_DOMAIN_TAG);
    preimage[1] = felt(FEE_SCHEDULE_ROOT_SCHEMA_TAG);
    preimage[2] = felt(FEE_SCHEDULE_ROOT_HASH_TAG);
    preimage[3] = felt(FEE_SCHEDULE_ROOT_NORMALIZATION_TAG);
    preimage[4..12].copy_from_slice(&claim_hash_limbs);
    preimage[12..16].copy_from_slice(schedule_digest.as_elements());
    preimage[16..20].copy_from_slice(entries_digest.as_elements());
    preimage[20..24].copy_from_slice(service_lines_digest.as_elements());
    preimage[24..27].copy_from_slice(&[ProductionFelt::ONE; 3]);
    preimage[27] = felt(entries.len() as u64);
    preimage[28] = felt(matches.len() as u64);
    preimage[29] = felt(service_date);
    preimage[30] = felt(total_allowed);
    preimage[31] = felt(total_charged);
    Ok(preimage)
}

fn validate_and_match_fee_schedule(
    bridge: &StarkBridgeInput,
) -> Result<Vec<ProductionFeeScheduleMatchV1>, Vec<String>> {
    let mut errors = Vec::new();
    let Some(schedule_id) = bridge.claim.fee_schedule_id.as_deref() else {
        return Err(vec![
            "claim.fee_schedule_id must be present for feeScheduleRoot".to_string(),
        ]);
    };
    if let Err(mut entry_errors) =
        validate_fee_entry_parts(schedule_id, &bridge.claim.fee_schedule_entries)
    {
        errors.append(&mut entry_errors);
    }
    if bridge.claim.service_lines.is_empty() {
        errors.push(
            "claim.service_lines must contain at least one service line for feeScheduleRoot"
                .to_string(),
        );
    }
    let service_date = bridge.active_rust_facts.date_of_service_from;
    if service_date == 0 || service_date > u32::MAX as u64 {
        errors.push("active_rust_facts.date_of_service_from must be in 1..=u32::MAX".to_string());
    }

    let mut matches = Vec::new();
    for (index, line) in bridge.claim.service_lines.iter().enumerate() {
        let code = line.procedure_code.trim().to_ascii_uppercase();
        let applicable = bridge
            .claim
            .fee_schedule_entries
            .iter()
            .filter(|entry| {
                entry.fee_code.trim().eq_ignore_ascii_case(&code)
                    && entry.effective_from <= service_date
                    && entry
                        .effective_thru
                        .is_none_or(|through| service_date <= through)
            })
            .collect::<Vec<_>>();
        if applicable.len() != 1 {
            errors.push(format!(
                "claim.service_lines[{index}] must match exactly one effective fee entry, got {}",
                applicable.len()
            ));
            continue;
        }
        let entry = applicable[0];
        let Some(allowed) = entry.unit_amount_cents.checked_mul(line.units) else {
            errors.push(format!(
                "claim.service_lines[{index}] allowed amount overflowed u64"
            ));
            continue;
        };
        if allowed == 0 || allowed > u32::MAX as u64 {
            errors.push(format!(
                "claim.service_lines[{index}] allowed amount must fit in u32"
            ));
        }
        if line.charge_cents == 0 || line.charge_cents > allowed {
            errors.push(format!(
                "claim.service_lines[{index}] charge {} exceeds fee schedule allowance {allowed}",
                line.charge_cents
            ));
        }
        matches.push(ProductionFeeScheduleMatchV1 {
            procedure_code: code,
            units: line.units,
            charge_cents: line.charge_cents,
            matched_unit_amount_cents: entry.unit_amount_cents,
            allowed_amount_cents: allowed,
        });
    }
    if checked_total(&matches, |item| item.allowed_amount_cents).is_err()
        || checked_total(&matches, |item| item.charge_cents).is_err()
    {
        errors.push("fee schedule aggregate amounts must fit in u32".to_string());
    }

    if errors.is_empty() {
        Ok(matches)
    } else {
        Err(errors)
    }
}

fn validate_stored_matches(
    entries: &[FeeScheduleEntryInput],
    matches: &[ProductionFeeScheduleMatchV1],
    service_date: u64,
) -> Vec<String> {
    let mut errors = Vec::new();
    if service_date == 0 || service_date > u32::MAX as u64 {
        errors.push("service_date must be in 1..=u32::MAX".to_string());
    }

    for (index, item) in matches.iter().enumerate() {
        let code = item.procedure_code.trim().to_ascii_uppercase();
        if code.is_empty() || item.units == 0 || item.charge_cents == 0 {
            errors.push(format!(
                "matched_service_lines[{index}] has invalid code, units, or charge"
            ));
            continue;
        }

        let applicable = entries
            .iter()
            .filter(|entry| {
                entry.fee_code.trim().eq_ignore_ascii_case(&code)
                    && entry.effective_from <= service_date
                    && entry
                        .effective_thru
                        .is_none_or(|through| service_date <= through)
            })
            .collect::<Vec<_>>();
        if applicable.len() != 1 {
            errors.push(format!(
                "matched_service_lines[{index}] must match exactly one effective fee entry, got {}",
                applicable.len()
            ));
            continue;
        }

        let entry = applicable[0];
        if item.matched_unit_amount_cents != entry.unit_amount_cents {
            errors.push(format!(
                "matched_service_lines[{index}].matched_unit_amount_cents does not match the effective fee entry"
            ));
        }
        match entry.unit_amount_cents.checked_mul(item.units) {
            Some(allowed)
                if allowed == item.allowed_amount_cents
                    && allowed <= u32::MAX as u64
                    && item.charge_cents <= allowed => {}
            Some(_) => errors.push(format!(
                "matched_service_lines[{index}] has inconsistent allowed or charged amount"
            )),
            None => errors.push(format!(
                "matched_service_lines[{index}] allowed amount overflowed u64"
            )),
        }
    }

    errors
}

fn validate_fee_entry_parts(
    schedule_id: &str,
    entries: &[FeeScheduleEntryInput],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if schedule_id.trim().is_empty() {
        errors.push("fee_schedule_id must be present".to_string());
    }
    if entries.is_empty() {
        errors.push("fee_schedule_entries must contain at least one verified entry".to_string());
    }
    let mut canonical = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let normalized = normalized_fee_entry(entry);
        if normalized.iter().any(|value| value.is_empty()) {
            errors.push(format!(
                "fee_schedule_entries[{index}] has missing required fields"
            ));
        }
        if entry.unit_amount_cents == 0 || entry.unit_amount_cents > u32::MAX as u64 {
            errors.push(format!(
                "fee_schedule_entries[{index}].unit_amount_cents must fit in u32"
            ));
        }
        if entry.currency.trim().to_ascii_uppercase() != "USD" {
            errors.push(format!(
                "fee_schedule_entries[{index}].currency must be USD in V1"
            ));
        }
        if entry.effective_from == 0 || entry.effective_from > u32::MAX as u64 {
            errors.push(format!(
                "fee_schedule_entries[{index}].effective_from must fit in u32"
            ));
        }
        if let Some(through) = entry.effective_thru
            && (through < entry.effective_from || through > u32::MAX as u64)
        {
            errors.push(format!(
                "fee_schedule_entries[{index}].effective_thru is invalid"
            ));
        }
        if !entry
            .source_url
            .as_deref()
            .unwrap_or_default()
            .trim()
            .starts_with("https://")
        {
            errors.push(format!(
                "fee_schedule_entries[{index}].source_url must use https"
            ));
        }
        if !entry
            .verification_status
            .trim()
            .eq_ignore_ascii_case("verified")
        {
            errors.push(format!(
                "fee_schedule_entries[{index}].verification_status must be verified"
            ));
        }
        canonical.push(normalized.join("\u{1f}"));
    }
    canonical.sort();
    if canonical.windows(2).any(|pair| pair[0] == pair[1]) {
        errors
            .push("fee_schedule_entries must not contain duplicate canonical entries".to_string());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn normalized_fee_entry(entry: &FeeScheduleEntryInput) -> [String; 7] {
    [
        entry.fee_code.trim().to_ascii_uppercase(),
        entry.unit_amount_cents.to_string(),
        entry.currency.trim().to_ascii_uppercase(),
        entry.effective_from.to_string(),
        entry
            .effective_thru
            .map(|value| value.to_string())
            .unwrap_or_default(),
        entry
            .source_url
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_string(),
        entry.verification_status.trim().to_ascii_lowercase(),
    ]
}

fn hash_fee_entries(entries: &[FeeScheduleEntryInput]) -> FeeScheduleDigest {
    let mut normalized = entries.iter().map(normalized_fee_entry).collect::<Vec<_>>();
    normalized.sort();
    let mut aggregate = vec![
        felt(FEE_ENTRIES_DOMAIN_TAG),
        felt(FEE_SCHEDULE_ROOT_SCHEMA_TAG),
        felt(normalized.len() as u64),
    ];
    for entry in normalized {
        let mut values = vec![
            felt(FEE_ENTRY_DOMAIN_TAG),
            felt(FEE_SCHEDULE_ROOT_SCHEMA_TAG),
        ];
        for value in entry {
            values.extend_from_slice(hash_text(FEE_TEXT_DOMAIN_TAG, &value).as_elements());
        }
        aggregate.extend_from_slice(Rp64_256::hash_elements(&values).as_elements());
    }
    Rp64_256::hash_elements(&aggregate)
}

fn hash_matched_service_lines(matches: &[ProductionFeeScheduleMatchV1]) -> FeeScheduleDigest {
    let mut elements = vec![
        felt(SERVICE_LINES_DOMAIN_TAG),
        felt(CLAIM_SOURCE_ROOT_SCHEMA_TAG),
        felt(matches.len() as u64),
    ];
    for item in matches {
        elements.extend_from_slice(
            hash_text(PROCEDURE_CODE_DOMAIN_TAG, &item.procedure_code).as_elements(),
        );
        elements.push(felt(item.charge_cents));
        elements.push(felt(item.units));
    }
    Rp64_256::hash_elements(&elements)
}

fn hash_text(domain_tag: u64, value: &str) -> FeeScheduleDigest {
    let bytes = value.as_bytes();
    let mut elements = vec![felt(domain_tag), felt(bytes.len() as u64)];
    for chunk in bytes.chunks(7) {
        let mut packed = [0_u8; 8];
        packed[..chunk.len()].copy_from_slice(chunk);
        elements.push(felt(u64::from_le_bytes(packed)));
    }
    Rp64_256::hash_elements(&elements)
}

fn build_fee_schedule_tree(leaf: FeeScheduleDigest) -> Result<MerkleTree<Rp64_256>, Vec<String>> {
    let leaf_count = 1_usize << FEE_SCHEDULE_ROOT_TREE_DEPTH;
    let mut leaves = (0..leaf_count)
        .map(|index| {
            Rp64_256::hash_elements(&[
                felt(FEE_EMPTY_LEAF_DOMAIN_TAG),
                felt(FEE_SCHEDULE_ROOT_SCHEMA_TAG),
                felt(index as u64),
            ])
        })
        .collect::<Vec<_>>();
    leaves[FEE_SCHEDULE_ROOT_LEAF_INDEX] = leaf;
    MerkleTree::<Rp64_256>::new(leaves)
        .map_err(|error| vec![format!("could not build fee-schedule Merkle tree: {error}")])
}

fn checked_total<T>(items: &[T], value: impl Fn(&T) -> u64) -> Result<u64, Vec<String>> {
    let total = items
        .iter()
        .try_fold(0_u64, |sum, item| sum.checked_add(value(item)))
        .ok_or_else(|| vec!["fee schedule aggregate amount overflowed u64".to_string()])?;
    if total == 0 || total > u32::MAX as u64 {
        Err(vec![
            "fee schedule aggregate amount must be in 1..=u32::MAX".to_string(),
        ])
    } else {
        Ok(total)
    }
}

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
        *limb = felt(
            u32::from_str_radix(&hex[start..start + 8], 16)
                .map_err(|error| vec![format!("invalid claim_hash limb {index}: {error}")])?
                as u64,
        );
    }
    Ok(limbs)
}

fn strings_to_felts(
    field: &str,
    values: &[String],
    expected: usize,
) -> Result<Vec<ProductionFelt>, Vec<String>> {
    let mut errors = Vec::new();
    if values.len() != expected {
        errors.push(format!(
            "{field} must contain {expected} values, got {}",
            values.len()
        ));
    }
    let mut parsed = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        match value.parse::<u64>() {
            Ok(integer) if ProductionFelt::new(integer).as_int() == integer => {
                parsed.push(felt(integer))
            }
            Ok(_) => errors.push(format!(
                "{field}[{index}] is not a canonical f64 field element"
            )),
            Err(error) => errors.push(format!("{field}[{index}] is not a decimal u64: {error}")),
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
    values: &[String; 4],
) -> Result<[ProductionFelt; 4], Vec<String>> {
    Ok(strings_to_felts(field, values, 4)?
        .try_into()
        .expect("four parsed values"))
}

fn felts_to_strings(values: &[ProductionFelt]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_int().to_string())
        .collect()
}

fn digest_to_strings(digest: &FeeScheduleDigest) -> [String; 4] {
    core::array::from_fn(|index| digest.as_elements()[index].as_int().to_string())
}

fn merkle_path_indices(mut index: usize) -> Vec<u8> {
    (0..FEE_SCHEDULE_ROOT_TREE_DEPTH)
        .map(|_| {
            let value = (index & 1) as u8;
            index >>= 1;
            value
        })
        .collect()
}

fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("0x{:x}", Sha256::digest(bytes))
}

fn is_prefixed_sha256(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn validate_exact(field: &str, actual: &str, expected: &str, errors: &mut Vec<String>) {
    if actual != expected {
        errors.push(format!("{field} must be {expected}, got {actual}"));
    }
}

fn felt(value: u64) -> ProductionFelt {
    ProductionFelt::new(value)
}
