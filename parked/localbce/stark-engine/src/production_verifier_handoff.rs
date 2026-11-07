use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::production_proof_artifact::ProductionStarkProofArtifactV4;

pub const STARK_VERIFIER_V1_ABI_FIELDS: [(&str, &str); 11] = [
    ("claimHash", "bytes32"),
    ("decision", "uint8"),
    ("failureCode", "uint32"),
    ("publicInputRoot", "bytes32"),
    ("claimSourceRoot", "bytes32"),
    ("oracleFactsRoot", "bytes32"),
    ("feeScheduleRoot", "bytes32"),
    ("nullifierRootBefore", "bytes32"),
    ("nullifierRootAfter", "bytes32"),
    ("batchRoot", "bytes32"),
    ("proof", "bytes"),
];

pub const STARK_VERIFIER_V1_UNRESOLVED_ROOT_FIELDS: [&str; 0] = [];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionStarkVerifierHandoffV4 {
    pub schema_version: String,
    pub source_schema_version: String,
    pub handoff_status: String,
    pub interface_name: String,
    pub function_signature: String,
    pub canonical_abi_signature: String,
    pub source_artifact_digest_encoding: String,
    pub source_artifact_sha256: String,
    pub source_artifact: ProductionStarkProofArtifactV4,
    pub abi_fields: Vec<ProductionStarkVerifierAbiFieldV4>,
    pub air_public_input_count: usize,
    pub air_public_input_order: Vec<String>,
    pub air_public_inputs_sha256: String,
    pub public_input_root: String,
    pub public_input_root_status: String,
    pub claim_source_root: String,
    pub claim_source_root_status: String,
    pub oracle_facts_root: String,
    pub oracle_facts_root_status: String,
    pub fee_schedule_root: String,
    pub fee_schedule_root_status: String,
    pub nullifier_root_before: String,
    pub nullifier_root_after: String,
    pub nullifier_root_status: String,
    pub batch_root: String,
    pub batch_root_status: String,
    pub proof_bytes_reference: String,
    pub proof_bytes_sha256: String,
    pub proof_size_bytes: usize,
    pub binding_digest_sha256: String,
    pub call_readiness: ProductionStarkVerifierCallReadinessV4,
    pub runtime_wired: bool,
    pub on_chain_verifier_wired: bool,
    pub on_chain_submission: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionStarkVerifierAbiFieldV4 {
    pub position: usize,
    pub name: String,
    pub solidity_type: String,
    pub source_path: String,
    pub value: Option<String>,
    pub value_sha256: Option<String>,
    pub binding_status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionStarkVerifierCallReadinessV4 {
    pub readiness_status: String,
    pub proof_bytes_available: bool,
    pub proof_locally_verified: bool,
    pub air_public_inputs_available: bool,
    pub air_public_input_count: usize,
    pub directly_available_abi_fields: Vec<String>,
    pub derived_candidate_abi_fields: Vec<String>,
    pub unresolved_abi_fields: Vec<String>,
    pub abi_call_ready: bool,
    pub runtime_activation_allowed: bool,
}

pub type ProductionStarkVerifierHandoffV3 = ProductionStarkVerifierHandoffV4;
pub type ProductionStarkVerifierHandoffV2 = ProductionStarkVerifierHandoffV4;
pub type ProductionStarkVerifierHandoffV1 = ProductionStarkVerifierHandoffV4;
pub type ProductionStarkVerifierAbiFieldV3 = ProductionStarkVerifierAbiFieldV4;
pub type ProductionStarkVerifierAbiFieldV2 = ProductionStarkVerifierAbiFieldV4;
pub type ProductionStarkVerifierAbiFieldV1 = ProductionStarkVerifierAbiFieldV4;
pub type ProductionStarkVerifierCallReadinessV3 = ProductionStarkVerifierCallReadinessV4;
pub type ProductionStarkVerifierCallReadinessV2 = ProductionStarkVerifierCallReadinessV4;
pub type ProductionStarkVerifierCallReadinessV1 = ProductionStarkVerifierCallReadinessV4;
pub type ProductionStarkVerifierHandoffV5 = ProductionStarkVerifierHandoffV4;
pub type ProductionStarkVerifierAbiFieldV5 = ProductionStarkVerifierAbiFieldV4;
pub type ProductionStarkVerifierCallReadinessV5 = ProductionStarkVerifierCallReadinessV4;
pub type ProductionStarkVerifierHandoffV6 = ProductionStarkVerifierHandoffV4;
pub type ProductionStarkVerifierAbiFieldV6 = ProductionStarkVerifierAbiFieldV4;
pub type ProductionStarkVerifierCallReadinessV6 = ProductionStarkVerifierCallReadinessV4;

impl ProductionStarkVerifierHandoffV4 {
    pub const SCHEMA_VERSION: &'static str = "stark-production-verifier-handoff-v7";
    pub const SOURCE_SCHEMA_VERSION: &'static str = ProductionStarkProofArtifactV4::SCHEMA_VERSION;
    pub const HANDOFF_STATUS: &'static str = "abi_aligned_call_ready_not_runtime";
    pub const INTERFACE_NAME: &'static str = "IStarkClaimsVerifierV1Candidate";
    pub const FUNCTION_SIGNATURE: &'static str = "verifyStarkClaim((bytes32,uint8,uint32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32) publicInputs,bytes proof) external view returns (bool)";
    pub const CANONICAL_ABI_SIGNATURE: &'static str = "verifyStarkClaim((bytes32,uint8,uint32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32),bytes)";
    pub const SOURCE_ARTIFACT_DIGEST_ENCODING: &'static str = "serde-json-compact-struct-order-v7";
    pub const PUBLIC_INPUT_ROOT_STATUS: &'static str = "air_constrained_rp64_256_packed_bytes32";
    pub const CLAIM_SOURCE_ROOT_STATUS: &'static str =
        "air_constrained_canonical_leaf_and_depth_10_merkle_path";
    pub const ORACLE_FACTS_ROOT_STATUS: &'static str =
        "air_constrained_canonical_verified_fact_leaf_and_depth_10_merkle_path";
    pub const FEE_SCHEDULE_ROOT_STATUS: &'static str =
        "air_constrained_canonical_verified_fee_leaf_depth_10_merkle_path_and_claim_source_links";
    pub const NULLIFIER_ROOT_STATUS: &'static str =
        "air_constrained_canonical_indexed_before_after_transition";
    pub const BATCH_ROOT_STATUS: &'static str =
        "air_constrained_single_claim_batch_hash_of_public_input_root";
    pub const PROOF_BYTES_REFERENCE: &'static str = "source_artifact.proof.bytes_hex";

    pub fn from_proof_artifact(
        artifact: &ProductionStarkProofArtifactV4,
    ) -> Result<Self, Vec<String>> {
        artifact.validate()?;

        let source_artifact_sha256 = source_artifact_sha256(artifact)?;
        let air_public_inputs_sha256 = artifact.public_inputs.canonical_bytes_sha256.clone();
        let public_input_root = artifact.public_input_root_bytes32.clone();
        let claim_source_root = artifact.claim_source_root_bytes32.clone();
        let oracle_facts_root = artifact.oracle_facts_root_bytes32.clone();
        let fee_schedule_root = artifact.fee_schedule_root_bytes32.clone();
        let nullifier_root_before = artifact.nullifier_root_before_bytes32.clone();
        let nullifier_root_after = artifact.nullifier_root_after_bytes32.clone();
        let batch_root = artifact.batch_root_bytes32.clone();
        let abi_fields = expected_abi_fields(artifact);
        let call_readiness = ProductionStarkVerifierCallReadinessV4::expected();
        let binding_digest_sha256 = binding_digest_sha256(
            &source_artifact_sha256,
            &artifact.proof.sha256,
            &air_public_inputs_sha256,
            &artifact.claim_hash,
            artifact.decision,
            artifact.failure_code,
            &public_input_root,
            &claim_source_root,
            &oracle_facts_root,
            &fee_schedule_root,
            &nullifier_root_before,
            &nullifier_root_after,
            &batch_root,
        );

        let handoff = Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: Self::SOURCE_SCHEMA_VERSION.to_string(),
            handoff_status: Self::HANDOFF_STATUS.to_string(),
            interface_name: Self::INTERFACE_NAME.to_string(),
            function_signature: Self::FUNCTION_SIGNATURE.to_string(),
            canonical_abi_signature: Self::CANONICAL_ABI_SIGNATURE.to_string(),
            source_artifact_digest_encoding: Self::SOURCE_ARTIFACT_DIGEST_ENCODING.to_string(),
            source_artifact_sha256,
            source_artifact: artifact.clone(),
            abi_fields,
            air_public_input_count: artifact.public_inputs.count,
            air_public_input_order: artifact.public_inputs.order.clone(),
            air_public_inputs_sha256,
            public_input_root,
            public_input_root_status: Self::PUBLIC_INPUT_ROOT_STATUS.to_string(),
            claim_source_root,
            claim_source_root_status: Self::CLAIM_SOURCE_ROOT_STATUS.to_string(),
            oracle_facts_root,
            oracle_facts_root_status: Self::ORACLE_FACTS_ROOT_STATUS.to_string(),
            fee_schedule_root,
            fee_schedule_root_status: Self::FEE_SCHEDULE_ROOT_STATUS.to_string(),
            nullifier_root_before,
            nullifier_root_after,
            nullifier_root_status: Self::NULLIFIER_ROOT_STATUS.to_string(),
            batch_root,
            batch_root_status: Self::BATCH_ROOT_STATUS.to_string(),
            proof_bytes_reference: Self::PROOF_BYTES_REFERENCE.to_string(),
            proof_bytes_sha256: artifact.proof.sha256.clone(),
            proof_size_bytes: artifact.proof.size_bytes,
            binding_digest_sha256,
            call_readiness,
            runtime_wired: false,
            on_chain_verifier_wired: false,
            on_chain_submission: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "The nested production artifact is independently re-verified during handoff validation."
                    .to_string(),
                "publicInputRoot is constrained by the production AIR and canonically packed into bytes32."
                    .to_string(),
                "batchRoot is AIR-constrained, so every verifier ABI field is available."
                    .to_string(),
                "The active Groth16 settlement path remains unchanged.".to_string(),
            ],
        };
        handoff.validate()?;
        Ok(handoff)
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
            "handoff_status",
            &self.handoff_status,
            Self::HANDOFF_STATUS,
            &mut errors,
        );
        validate_exact(
            "interface_name",
            &self.interface_name,
            Self::INTERFACE_NAME,
            &mut errors,
        );
        validate_exact(
            "function_signature",
            &self.function_signature,
            Self::FUNCTION_SIGNATURE,
            &mut errors,
        );
        validate_exact(
            "canonical_abi_signature",
            &self.canonical_abi_signature,
            Self::CANONICAL_ABI_SIGNATURE,
            &mut errors,
        );
        validate_exact(
            "source_artifact_digest_encoding",
            &self.source_artifact_digest_encoding,
            Self::SOURCE_ARTIFACT_DIGEST_ENCODING,
            &mut errors,
        );
        validate_exact(
            "public_input_root_status",
            &self.public_input_root_status,
            Self::PUBLIC_INPUT_ROOT_STATUS,
            &mut errors,
        );
        validate_exact(
            "claim_source_root_status",
            &self.claim_source_root_status,
            Self::CLAIM_SOURCE_ROOT_STATUS,
            &mut errors,
        );
        validate_exact(
            "oracle_facts_root_status",
            &self.oracle_facts_root_status,
            Self::ORACLE_FACTS_ROOT_STATUS,
            &mut errors,
        );
        validate_exact(
            "fee_schedule_root_status",
            &self.fee_schedule_root_status,
            Self::FEE_SCHEDULE_ROOT_STATUS,
            &mut errors,
        );
        validate_exact(
            "nullifier_root_status",
            &self.nullifier_root_status,
            Self::NULLIFIER_ROOT_STATUS,
            &mut errors,
        );
        validate_exact(
            "batch_root_status",
            &self.batch_root_status,
            Self::BATCH_ROOT_STATUS,
            &mut errors,
        );
        validate_exact(
            "proof_bytes_reference",
            &self.proof_bytes_reference,
            Self::PROOF_BYTES_REFERENCE,
            &mut errors,
        );

        if let Err(mut artifact_errors) = self.source_artifact.validate() {
            errors.extend(
                artifact_errors
                    .drain(..)
                    .map(|error| format!("source_artifact: {error}")),
            );
        }

        match source_artifact_sha256(&self.source_artifact) {
            Ok(expected) if self.source_artifact_sha256 != expected => {
                errors.push("source_artifact_sha256 does not match source_artifact".to_string());
            }
            Ok(_) => {}
            Err(mut digest_errors) => errors.append(&mut digest_errors),
        }

        if self.air_public_input_count != self.source_artifact.public_inputs.count {
            errors.push(
                "air_public_input_count does not match source artifact public input count"
                    .to_string(),
            );
        }
        if self.air_public_input_order != self.source_artifact.public_inputs.order {
            errors.push(
                "air_public_input_order does not match source artifact public input order"
                    .to_string(),
            );
        }
        if self.air_public_inputs_sha256
            != self.source_artifact.public_inputs.canonical_bytes_sha256
        {
            errors.push(
                "air_public_inputs_sha256 does not match source artifact public inputs".to_string(),
            );
        }
        if self.public_input_root != self.source_artifact.public_input_root_bytes32 {
            errors.push(
                "public_input_root must equal the AIR-constrained root packed by the source artifact"
                    .to_string(),
            );
        }
        if self.claim_source_root != self.source_artifact.claim_source_root_bytes32 {
            errors.push(
                "claim_source_root must equal the AIR-constrained claim-source root packed by the source artifact"
                    .to_string(),
            );
        }
        if self.oracle_facts_root != self.source_artifact.oracle_facts_root_bytes32 {
            errors.push(
                "oracle_facts_root must equal the AIR-constrained oracle-facts root packed by the source artifact"
                    .to_string(),
            );
        }
        if self.fee_schedule_root != self.source_artifact.fee_schedule_root_bytes32 {
            errors.push(
                "fee_schedule_root must equal the AIR-constrained fee-schedule root packed by the source artifact"
                    .to_string(),
            );
        }
        if self.nullifier_root_before != self.source_artifact.nullifier_root_before_bytes32 {
            errors.push(
                "nullifier_root_before must equal the AIR-constrained source artifact root"
                    .to_string(),
            );
        }
        if self.nullifier_root_after != self.source_artifact.nullifier_root_after_bytes32 {
            errors.push(
                "nullifier_root_after must equal the AIR-constrained source artifact root"
                    .to_string(),
            );
        }
        if self.batch_root != self.source_artifact.batch_root_bytes32 {
            errors.push(
                "batch_root must equal the AIR-constrained source artifact batch root".to_string(),
            );
        }
        if self.proof_bytes_sha256 != self.source_artifact.proof.sha256 {
            errors.push("proof_bytes_sha256 does not match source artifact proof".to_string());
        }
        if self.proof_size_bytes != self.source_artifact.proof.size_bytes {
            errors.push("proof_size_bytes does not match source artifact proof".to_string());
        }

        let expected_fields = expected_abi_fields(&self.source_artifact);
        if self.abi_fields != expected_fields {
            errors.push(
                "abi_fields do not match the exact V1 ABI order, types, values, and statuses"
                    .to_string(),
            );
        }
        if let Err(mut readiness_errors) = self.call_readiness.validate() {
            errors.append(&mut readiness_errors);
        }

        let expected_binding_digest = binding_digest_sha256(
            &self.source_artifact_sha256,
            &self.proof_bytes_sha256,
            &self.air_public_inputs_sha256,
            &self.source_artifact.claim_hash,
            self.source_artifact.decision,
            self.source_artifact.failure_code,
            &self.public_input_root,
            &self.claim_source_root,
            &self.oracle_facts_root,
            &self.fee_schedule_root,
            &self.nullifier_root_before,
            &self.nullifier_root_after,
            &self.batch_root,
        );
        if self.binding_digest_sha256 != expected_binding_digest {
            errors.push(
                "binding_digest_sha256 does not bind the artifact, proof, public inputs, and ABI root"
                    .to_string(),
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
        if self.notes.len() < 4 {
            errors.push("notes must preserve all four safety statements".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl ProductionStarkVerifierCallReadinessV4 {
    pub const READINESS_STATUS: &'static str = "abi_call_ready_runtime_activation_disabled";

    fn expected() -> Self {
        Self {
            readiness_status: Self::READINESS_STATUS.to_string(),
            proof_bytes_available: true,
            proof_locally_verified: true,
            air_public_inputs_available: true,
            air_public_input_count: 38,
            directly_available_abi_fields: vec![
                "claimHash".to_string(),
                "decision".to_string(),
                "failureCode".to_string(),
                "publicInputRoot".to_string(),
                "claimSourceRoot".to_string(),
                "oracleFactsRoot".to_string(),
                "feeScheduleRoot".to_string(),
                "nullifierRootBefore".to_string(),
                "nullifierRootAfter".to_string(),
                "batchRoot".to_string(),
                "proof".to_string(),
            ],
            derived_candidate_abi_fields: Vec::new(),
            unresolved_abi_fields: STARK_VERIFIER_V1_UNRESOLVED_ROOT_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            abi_call_ready: true,
            runtime_activation_allowed: false,
        }
    }

    fn validate(&self) -> Result<(), Vec<String>> {
        let expected = Self::expected();
        if self == &expected {
            Ok(())
        } else {
            Err(vec![
                "call_readiness must preserve the exact ABI-complete non-runtime readiness state"
                    .to_string(),
            ])
        }
    }
}

fn expected_abi_fields(
    artifact: &ProductionStarkProofArtifactV4,
) -> Vec<ProductionStarkVerifierAbiFieldV4> {
    let values = [
        Some(artifact.claim_hash.clone()),
        Some(artifact.decision.to_string()),
        Some(artifact.failure_code.to_string()),
        Some(artifact.public_input_root_bytes32.clone()),
        Some(artifact.claim_source_root_bytes32.clone()),
        Some(artifact.oracle_facts_root_bytes32.clone()),
        Some(artifact.fee_schedule_root_bytes32.clone()),
        Some(artifact.nullifier_root_before_bytes32.clone()),
        Some(artifact.nullifier_root_after_bytes32.clone()),
        Some(artifact.batch_root_bytes32.clone()),
        None,
    ];
    let source_paths = [
        "source_artifact.claim_hash",
        "source_artifact.decision",
        "source_artifact.failure_code",
        "source_artifact.public_input_root_bytes32",
        "source_artifact.claim_source_root_bytes32",
        "source_artifact.oracle_facts_root_bytes32",
        "source_artifact.fee_schedule_root_bytes32",
        "source_artifact.nullifier_root_before_bytes32",
        "source_artifact.nullifier_root_after_bytes32",
        "source_artifact.batch_root_bytes32",
        "source_artifact.proof.bytes_hex",
    ];
    let statuses = [
        "direct_air_public_input",
        "direct_air_public_input",
        "direct_air_public_input",
        "direct_air_constrained_public_input",
        "direct_air_constrained_merkle_root",
        "direct_air_constrained_merkle_root",
        "direct_air_constrained_merkle_root",
        "direct_air_constrained_nullifier_root",
        "direct_air_constrained_nullifier_root",
        "direct_air_constrained_batch_root",
        "available_locally_verified_winterfell_bytes",
    ];

    STARK_VERIFIER_V1_ABI_FIELDS
        .iter()
        .zip(values.iter())
        .enumerate()
        .map(
            |(position, ((name, solidity_type), value))| ProductionStarkVerifierAbiFieldV4 {
                position,
                name: (*name).to_string(),
                solidity_type: (*solidity_type).to_string(),
                source_path: source_paths[position].to_string(),
                value: value.clone(),
                value_sha256: if *name == "proof" {
                    Some(artifact.proof.sha256.clone())
                } else {
                    None
                },
                binding_status: statuses[position].to_string(),
            },
        )
        .collect()
}

fn source_artifact_sha256(
    artifact: &ProductionStarkProofArtifactV4,
) -> Result<String, Vec<String>> {
    let bytes = serde_json::to_vec(artifact)
        .map_err(|error| vec![format!("could not serialize source artifact: {error}")])?;
    Ok(sha256_hex(&bytes))
}

fn binding_digest_sha256(
    source_artifact_sha256: &str,
    proof_bytes_sha256: &str,
    air_public_inputs_sha256: &str,
    claim_hash: &str,
    decision: u8,
    failure_code: u32,
    public_input_root: &str,
    claim_source_root: &str,
    oracle_facts_root: &str,
    fee_schedule_root: &str,
    nullifier_root_before: &str,
    nullifier_root_after: &str,
    batch_root: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"localbce-stark-verifier-handoff-v7\0");
    update_len_prefixed(
        &mut hasher,
        ProductionStarkVerifierHandoffV4::INTERFACE_NAME,
    );
    update_len_prefixed(
        &mut hasher,
        ProductionStarkVerifierHandoffV4::CANONICAL_ABI_SIGNATURE,
    );
    update_len_prefixed(&mut hasher, source_artifact_sha256);
    update_len_prefixed(&mut hasher, proof_bytes_sha256);
    update_len_prefixed(&mut hasher, air_public_inputs_sha256);
    update_len_prefixed(&mut hasher, claim_hash);
    hasher.update([decision]);
    hasher.update(failure_code.to_be_bytes());
    update_len_prefixed(&mut hasher, public_input_root);
    update_len_prefixed(&mut hasher, claim_source_root);
    update_len_prefixed(&mut hasher, oracle_facts_root);
    update_len_prefixed(&mut hasher, fee_schedule_root);
    update_len_prefixed(&mut hasher, nullifier_root_before);
    update_len_prefixed(&mut hasher, nullifier_root_after);
    update_len_prefixed(&mut hasher, batch_root);
    for field in STARK_VERIFIER_V1_UNRESOLVED_ROOT_FIELDS {
        update_len_prefixed(&mut hasher, field);
    }
    encode_digest(hasher.finalize())
}

fn update_len_prefixed(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode_digest(Sha256::digest(bytes))
}

fn encode_digest(digest: impl AsRef<[u8]>) -> String {
    let bytes = digest.as_ref();
    let mut encoded = String::with_capacity(2 + bytes.len() * 2);
    encoded.push_str("0x");
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn validate_exact(field: &str, actual: &str, expected: &str, errors: &mut Vec<String>) {
    if actual != expected {
        errors.push(format!("{field} must be {expected}, got {actual}"));
    }
}

#[cfg(test)]
#[path = "production_verifier_handoff_tests.rs"]
mod tests;
