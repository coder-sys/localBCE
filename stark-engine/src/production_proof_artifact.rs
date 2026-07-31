use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use winterfell::Proof;

use crate::{
    StarkBridgeInput,
    production_air::ProductionAirInputV1,
    production_air_winterfell::{
        CLAIM_SOURCE_ROOT_WIDTH, FACT_COMMITMENT_HASH_FUNCTION, FACT_COMMITMENT_SCHEMA_VERSION,
        PUBLIC_INPUT_ROOT_ENCODING, PUBLIC_INPUT_ROOT_HASH_FUNCTION,
        PUBLIC_INPUT_ROOT_SCHEMA_VERSION, ProductionAirProofInputV2, ProductionAirPublicInputsV2,
        ProductionFelt, TRACE_LENGTH, TRACE_WIDTH, pack_public_input_root_bytes32,
        prove_production_air, unpack_public_input_root_bytes32, verify_production_air_result,
    },
    source_roots::{
        CLAIM_SOURCE_ROOT_ENCODING, CLAIM_SOURCE_ROOT_HASH_FUNCTION, CLAIM_SOURCE_ROOT_LEAF_INDEX,
        CLAIM_SOURCE_ROOT_SCHEMA_VERSION, CLAIM_SOURCE_ROOT_TREE_DEPTH,
    },
};

pub const PRODUCTION_STARK_PUBLIC_INPUT_ORDER: [&str; 18] = [
    "claim_hash_be_u32_limb_0",
    "claim_hash_be_u32_limb_1",
    "claim_hash_be_u32_limb_2",
    "claim_hash_be_u32_limb_3",
    "claim_hash_be_u32_limb_4",
    "claim_hash_be_u32_limb_5",
    "claim_hash_be_u32_limb_6",
    "claim_hash_be_u32_limb_7",
    "public_input_root_element_0",
    "public_input_root_element_1",
    "public_input_root_element_2",
    "public_input_root_element_3",
    "claim_source_root_element_0",
    "claim_source_root_element_1",
    "claim_source_root_element_2",
    "claim_source_root_element_3",
    "decision",
    "failure_code",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionStarkProofArtifactV3 {
    pub schema_version: String,
    pub source_schema_version: String,
    pub artifact_status: String,
    pub proof_system: String,
    pub proof_system_version: String,
    pub air_schema_version: String,
    pub fact_commitment_schema_version: String,
    pub fact_commitment_hash: String,
    pub public_input_root_schema_version: String,
    pub public_input_root_hash: String,
    pub public_input_root_encoding: String,
    pub public_input_root_bytes32: String,
    pub claim_source_root_schema_version: String,
    pub claim_source_root_hash: String,
    pub claim_source_root_encoding: String,
    pub claim_source_root_bytes32: String,
    pub claim_source_root_tree_depth: usize,
    pub claim_source_root_leaf_index: usize,
    pub claim_source_root_binding: String,
    pub claim_id: String,
    pub claim_id_binding: String,
    pub claim_hash: String,
    pub claim_hash_binding: String,
    pub ruleset_id: String,
    pub decision: u8,
    pub failure_code: u32,
    pub public_inputs: ProductionStarkPublicInputsV3,
    pub proof: ProductionStarkProofBytesV3,
    pub parameters: ProductionStarkProofParametersV3,
    pub local_verification_status: String,
    pub locally_verified: bool,
    pub runtime_wired: bool,
    pub on_chain_verifier_wired: bool,
    pub on_chain_submission: bool,
    pub groth16_flow_unchanged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionStarkPublicInputsV3 {
    pub schema_version: String,
    pub encoding: String,
    pub order: Vec<String>,
    pub values_decimal: Vec<String>,
    pub count: usize,
    pub canonical_bytes_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionStarkProofBytesV3 {
    pub encoding: String,
    pub bytes_hex: String,
    pub size_bytes: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionStarkProofParametersV3 {
    pub base_field: String,
    pub field_extension: String,
    pub trace_commitment_hash: String,
    pub trace_width: usize,
    pub trace_length: usize,
    pub public_input_count: usize,
    pub minimum_conjectured_security_bits: u32,
}

pub type ProductionStarkProofArtifactV2 = ProductionStarkProofArtifactV3;
pub type ProductionStarkProofArtifactV1 = ProductionStarkProofArtifactV3;
pub type ProductionStarkPublicInputsV2 = ProductionStarkPublicInputsV3;
pub type ProductionStarkPublicInputsV1 = ProductionStarkPublicInputsV3;
pub type ProductionStarkProofBytesV2 = ProductionStarkProofBytesV3;
pub type ProductionStarkProofBytesV1 = ProductionStarkProofBytesV3;
pub type ProductionStarkProofParametersV2 = ProductionStarkProofParametersV3;
pub type ProductionStarkProofParametersV1 = ProductionStarkProofParametersV3;

impl ProductionStarkProofArtifactV3 {
    pub const SCHEMA_VERSION: &'static str = "stark-production-proof-artifact-v3";
    pub const SOURCE_SCHEMA_VERSION: &'static str = ProductionAirProofInputV2::SCHEMA_VERSION;
    pub const ARTIFACT_STATUS: &'static str = "locally_verified_feature_gated_not_runtime";
    pub const PROOF_SYSTEM: &'static str = "winterfell";
    pub const PROOF_SYSTEM_VERSION: &'static str = "0.13.1";
    pub const CLAIM_ID_BINDING: &'static str = "metadata_only_claim_hash_is_public";
    pub const CLAIM_HASH_BINDING: &'static str = "public_input_8x_big_endian_u32";
    pub const CLAIM_SOURCE_ROOT_BINDING: &'static str =
        "air_constrained_canonical_leaf_and_depth_10_merkle_path";
    pub const LOCAL_VERIFICATION_STATUS: &'static str = "verified_from_serialized_proof_bytes";

    pub fn from_bridge_input(bridge: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        let input = ProductionAirProofInputV2::from_bridge_input(bridge)?;
        Self::from_proof_input(&input)
    }

    pub fn from_proof_input(input: &ProductionAirProofInputV2) -> Result<Self, Vec<String>> {
        input.validate()?;

        let (proof, public_inputs) = prove_production_air(input).map_err(|error| vec![error])?;
        verify_production_air_result(proof.clone(), public_inputs).map_err(|error| {
            vec![format!(
                "generated production STARK proof failed local verification: {error}"
            )]
        })?;

        let proof_bytes = proof.to_bytes();
        let public_input_root_bytes32 =
            pack_public_input_root_bytes32(&public_inputs.public_input_root);
        let claim_source_root_bytes32 =
            pack_public_input_root_bytes32(&public_inputs.claim_source_root);
        let public_inputs = ProductionStarkPublicInputsV3::from_air_public_inputs(&public_inputs);
        let adjudication = &input.adjudication;
        let artifact = Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: Self::SOURCE_SCHEMA_VERSION.to_string(),
            artifact_status: Self::ARTIFACT_STATUS.to_string(),
            proof_system: Self::PROOF_SYSTEM.to_string(),
            proof_system_version: Self::PROOF_SYSTEM_VERSION.to_string(),
            air_schema_version: adjudication.schema_version.clone(),
            fact_commitment_schema_version: FACT_COMMITMENT_SCHEMA_VERSION.to_string(),
            fact_commitment_hash: FACT_COMMITMENT_HASH_FUNCTION.to_string(),
            public_input_root_schema_version: PUBLIC_INPUT_ROOT_SCHEMA_VERSION.to_string(),
            public_input_root_hash: PUBLIC_INPUT_ROOT_HASH_FUNCTION.to_string(),
            public_input_root_encoding: PUBLIC_INPUT_ROOT_ENCODING.to_string(),
            public_input_root_bytes32,
            claim_source_root_schema_version: CLAIM_SOURCE_ROOT_SCHEMA_VERSION.to_string(),
            claim_source_root_hash: CLAIM_SOURCE_ROOT_HASH_FUNCTION.to_string(),
            claim_source_root_encoding: CLAIM_SOURCE_ROOT_ENCODING.to_string(),
            claim_source_root_bytes32,
            claim_source_root_tree_depth: CLAIM_SOURCE_ROOT_TREE_DEPTH,
            claim_source_root_leaf_index: CLAIM_SOURCE_ROOT_LEAF_INDEX,
            claim_source_root_binding: Self::CLAIM_SOURCE_ROOT_BINDING.to_string(),
            claim_id: adjudication.claim_id.clone(),
            claim_id_binding: Self::CLAIM_ID_BINDING.to_string(),
            claim_hash: adjudication.claim_hash.clone(),
            claim_hash_binding: Self::CLAIM_HASH_BINDING.to_string(),
            ruleset_id: adjudication.ruleset_id.clone(),
            decision: adjudication.expected_outcome.decision,
            failure_code: adjudication.expected_outcome.failure_code,
            public_inputs,
            proof: ProductionStarkProofBytesV3 {
                encoding: ProductionStarkProofBytesV3::ENCODING.to_string(),
                bytes_hex: encode_hex(&proof_bytes),
                size_bytes: proof_bytes.len(),
                sha256: sha256_hex(&proof_bytes),
            },
            parameters: ProductionStarkProofParametersV3::expected(),
            local_verification_status: Self::LOCAL_VERIFICATION_STATUS.to_string(),
            locally_verified: true,
            runtime_wired: false,
            on_chain_verifier_wired: false,
            on_chain_submission: false,
            groth16_flow_unchanged: true,
        };

        artifact.validate()?;
        Ok(artifact)
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
            "proof_system",
            &self.proof_system,
            Self::PROOF_SYSTEM,
            &mut errors,
        );
        validate_exact(
            "proof_system_version",
            &self.proof_system_version,
            Self::PROOF_SYSTEM_VERSION,
            &mut errors,
        );
        validate_exact(
            "air_schema_version",
            &self.air_schema_version,
            ProductionAirInputV1::SCHEMA_VERSION,
            &mut errors,
        );
        validate_exact(
            "fact_commitment_schema_version",
            &self.fact_commitment_schema_version,
            FACT_COMMITMENT_SCHEMA_VERSION,
            &mut errors,
        );
        validate_exact(
            "fact_commitment_hash",
            &self.fact_commitment_hash,
            FACT_COMMITMENT_HASH_FUNCTION,
            &mut errors,
        );
        validate_exact(
            "public_input_root_schema_version",
            &self.public_input_root_schema_version,
            PUBLIC_INPUT_ROOT_SCHEMA_VERSION,
            &mut errors,
        );
        validate_exact(
            "public_input_root_hash",
            &self.public_input_root_hash,
            PUBLIC_INPUT_ROOT_HASH_FUNCTION,
            &mut errors,
        );
        validate_exact(
            "public_input_root_encoding",
            &self.public_input_root_encoding,
            PUBLIC_INPUT_ROOT_ENCODING,
            &mut errors,
        );
        validate_exact(
            "claim_source_root_schema_version",
            &self.claim_source_root_schema_version,
            CLAIM_SOURCE_ROOT_SCHEMA_VERSION,
            &mut errors,
        );
        validate_exact(
            "claim_source_root_hash",
            &self.claim_source_root_hash,
            CLAIM_SOURCE_ROOT_HASH_FUNCTION,
            &mut errors,
        );
        validate_exact(
            "claim_source_root_encoding",
            &self.claim_source_root_encoding,
            CLAIM_SOURCE_ROOT_ENCODING,
            &mut errors,
        );
        validate_exact(
            "claim_source_root_binding",
            &self.claim_source_root_binding,
            Self::CLAIM_SOURCE_ROOT_BINDING,
            &mut errors,
        );
        if self.claim_source_root_tree_depth != CLAIM_SOURCE_ROOT_TREE_DEPTH {
            errors.push(format!(
                "claim_source_root_tree_depth must be {CLAIM_SOURCE_ROOT_TREE_DEPTH}, got {}",
                self.claim_source_root_tree_depth
            ));
        }
        if self.claim_source_root_leaf_index != CLAIM_SOURCE_ROOT_LEAF_INDEX {
            errors.push(format!(
                "claim_source_root_leaf_index must be {CLAIM_SOURCE_ROOT_LEAF_INDEX}, got {}",
                self.claim_source_root_leaf_index
            ));
        }
        validate_exact(
            "claim_id_binding",
            &self.claim_id_binding,
            Self::CLAIM_ID_BINDING,
            &mut errors,
        );
        validate_exact(
            "claim_hash_binding",
            &self.claim_hash_binding,
            Self::CLAIM_HASH_BINDING,
            &mut errors,
        );
        validate_exact(
            "local_verification_status",
            &self.local_verification_status,
            Self::LOCAL_VERIFICATION_STATUS,
            &mut errors,
        );

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }
        if self.ruleset_id != ProductionAirInputV1::RULESET_ID {
            errors.push(format!(
                "ruleset_id must be {}, got {}",
                ProductionAirInputV1::RULESET_ID,
                self.ruleset_id
            ));
        }
        if self.decision > 1 {
            errors.push(format!(
                "decision must be boolean 0 or 1, got {}",
                self.decision
            ));
        }
        if self.decision == 1 && self.failure_code != 0 {
            errors.push("approved artifact must have failure_code 0".to_string());
        }
        if self.decision == 0 && self.failure_code == 0 {
            errors.push("denied artifact must have a non-zero failure_code".to_string());
        }
        if !self.locally_verified {
            errors.push("locally_verified must be true".to_string());
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

        if let Err(mut parameter_errors) = self.parameters.validate() {
            errors.append(&mut parameter_errors);
        }
        if let Err(mut public_input_errors) =
            self.public_inputs
                .validate(&self.claim_hash, self.decision, self.failure_code)
        {
            errors.append(&mut public_input_errors);
        }
        match (
            unpack_public_input_root_bytes32(&self.public_input_root_bytes32),
            self.public_inputs.parsed_values(),
        ) {
            (Ok(packed), Ok(values))
                if values.len() == PRODUCTION_STARK_PUBLIC_INPUT_ORDER.len() =>
            {
                let public_values = packed.map(|value| value.as_int());
                if values[8..12] != public_values {
                    errors.push(
                        "public_input_root_bytes32 does not match public input root elements"
                            .to_string(),
                    );
                }
            }
            (Ok(_), Ok(_)) => {}
            (Err(error), _) => errors.push(error),
            (_, Err(_)) => {}
        }
        match (
            unpack_public_input_root_bytes32(&self.claim_source_root_bytes32),
            self.public_inputs.parsed_values(),
        ) {
            (Ok(packed), Ok(values))
                if values.len() == PRODUCTION_STARK_PUBLIC_INPUT_ORDER.len() =>
            {
                let public_values = packed.map(|value| value.as_int());
                if values[12..16] != public_values {
                    errors.push(
                        "claim_source_root_bytes32 does not match AIR public input root elements"
                            .to_string(),
                    );
                }
            }
            (Ok(_), Ok(_)) => {}
            (Err(error), _) => errors.push(error),
            (_, Err(_)) => {}
        }
        if let Err(mut proof_errors) = self.proof.validate() {
            errors.append(&mut proof_errors);
        }

        if errors.is_empty()
            && let Err(mut verification_errors) = self.verify_serialized_proof()
        {
            errors.append(&mut verification_errors);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn verify_serialized_proof(&self) -> Result<(), Vec<String>> {
        let proof_bytes = self.proof.decoded_bytes()?;
        let proof = Proof::from_bytes(&proof_bytes)
            .map_err(|error| vec![format!("invalid serialized Winterfell proof: {error}")])?;
        if proof.to_bytes() != proof_bytes {
            return Err(vec![
                "serialized Winterfell proof contains trailing or non-canonical data".to_string(),
            ]);
        }
        let public_inputs = self.public_inputs.to_air_public_inputs()?;
        verify_production_air_result(proof, public_inputs).map_err(|error| {
            vec![format!(
                "serialized production STARK proof failed local verification: {error}"
            )]
        })
    }
}

impl ProductionStarkPublicInputsV3 {
    pub const SCHEMA_VERSION: &'static str = "stark-production-public-inputs-v3";
    pub const ENCODING: &'static str = "winterfell-f64-canonical-decimal";

    fn from_air_public_inputs(public_inputs: &ProductionAirPublicInputsV2) -> Self {
        let mut values = public_inputs
            .claim_hash_limbs
            .iter()
            .map(|value| value.as_int())
            .collect::<Vec<_>>();
        values.extend(
            public_inputs
                .public_input_root
                .iter()
                .map(|value| value.as_int()),
        );
        values.extend(
            public_inputs
                .claim_source_root
                .iter()
                .map(|value| value.as_int()),
        );
        values.push(public_inputs.decision.as_int());
        values.push(public_inputs.failure_code.as_int());

        Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            encoding: Self::ENCODING.to_string(),
            order: expected_public_input_order(),
            values_decimal: values.iter().map(u64::to_string).collect(),
            count: values.len(),
            canonical_bytes_sha256: public_inputs_sha256(&values),
        }
    }

    fn validate(
        &self,
        claim_hash: &str,
        decision: u8,
        failure_code: u32,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        validate_exact(
            "public_inputs.schema_version",
            &self.schema_version,
            Self::SCHEMA_VERSION,
            &mut errors,
        );
        validate_exact(
            "public_inputs.encoding",
            &self.encoding,
            Self::ENCODING,
            &mut errors,
        );

        if self.order != expected_public_input_order() {
            errors.push(
                "public_inputs.order does not match the required 18-element order".to_string(),
            );
        }
        if self.count != PRODUCTION_STARK_PUBLIC_INPUT_ORDER.len() {
            errors.push(format!(
                "public_inputs.count must be {}, got {}",
                PRODUCTION_STARK_PUBLIC_INPUT_ORDER.len(),
                self.count
            ));
        }
        if self.values_decimal.len() != PRODUCTION_STARK_PUBLIC_INPUT_ORDER.len() {
            errors.push(format!(
                "public_inputs.values_decimal must contain {} values, got {}",
                PRODUCTION_STARK_PUBLIC_INPUT_ORDER.len(),
                self.values_decimal.len()
            ));
        }

        match self.parsed_values() {
            Ok(values) => {
                if self.canonical_bytes_sha256 != public_inputs_sha256(&values) {
                    errors.push(
                        "public_inputs.canonical_bytes_sha256 does not match values".to_string(),
                    );
                }

                match parse_claim_hash_limbs(claim_hash) {
                    Ok(expected_limbs) if values.len() >= 8 => {
                        if values[..8] != expected_limbs {
                            errors.push(
                                "public claim hash limbs do not match artifact claim_hash"
                                    .to_string(),
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(mut claim_hash_errors) => errors.append(&mut claim_hash_errors),
                }

                if values.len() == PRODUCTION_STARK_PUBLIC_INPUT_ORDER.len() {
                    if values[16] != u64::from(decision) {
                        errors.push("public decision does not match artifact decision".to_string());
                    }
                    if values[17] != u64::from(failure_code) {
                        errors.push(
                            "public failure_code does not match artifact failure_code".to_string(),
                        );
                    }
                }
            }
            Err(mut parse_errors) => errors.append(&mut parse_errors),
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn parsed_values(&self) -> Result<Vec<u64>, Vec<String>> {
        let mut values = Vec::with_capacity(self.values_decimal.len());
        let mut errors = Vec::new();
        for (index, value) in self.values_decimal.iter().enumerate() {
            match value.parse::<u64>() {
                Ok(parsed) => match ProductionFelt::try_from(parsed) {
                    Ok(_) => {
                        if value != &parsed.to_string() {
                            errors.push(format!(
                                "public_inputs.values_decimal[{index}] must use canonical decimal encoding"
                            ));
                        }
                        values.push(parsed);
                    }
                    Err(error) => errors.push(format!(
                        "public_inputs.values_decimal[{index}] is not a canonical f64 field element: {error}"
                    )),
                },
                Err(error) => errors.push(format!(
                    "public_inputs.values_decimal[{index}] is not a u64 decimal value: {error}"
                )),
            }
        }

        if errors.is_empty() {
            Ok(values)
        } else {
            Err(errors)
        }
    }

    fn to_air_public_inputs(&self) -> Result<ProductionAirPublicInputsV2, Vec<String>> {
        let values = self.parsed_values()?;
        if values.len() != PRODUCTION_STARK_PUBLIC_INPUT_ORDER.len() {
            return Err(vec![format!(
                "cannot reconstruct public inputs from {} values; expected {}",
                values.len(),
                PRODUCTION_STARK_PUBLIC_INPUT_ORDER.len()
            )]);
        }
        let field_values = values
            .into_iter()
            .map(ProductionFelt::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| vec![error])?;

        Ok(ProductionAirPublicInputsV2 {
            claim_hash_limbs: field_values[..8]
                .try_into()
                .expect("validated claim hash limb count"),
            public_input_root: field_values[8..12]
                .try_into()
                .expect("validated public input root width"),
            claim_source_root: field_values[12..12 + CLAIM_SOURCE_ROOT_WIDTH]
                .try_into()
                .expect("validated claim-source root width"),
            decision: field_values[16],
            failure_code: field_values[17],
        })
    }
}

impl ProductionStarkProofBytesV3 {
    pub const ENCODING: &'static str = "hex-lower-0x";

    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        validate_exact(
            "proof.encoding",
            &self.encoding,
            Self::ENCODING,
            &mut errors,
        );

        match self.decoded_bytes() {
            Ok(bytes) => {
                if bytes.is_empty() {
                    errors.push("proof bytes must not be empty".to_string());
                }
                if self.size_bytes != bytes.len() {
                    errors.push(format!(
                        "proof.size_bytes must be {}, got {}",
                        bytes.len(),
                        self.size_bytes
                    ));
                }
                if self.sha256 != sha256_hex(&bytes) {
                    errors.push("proof.sha256 does not match proof bytes".to_string());
                }
                if self.bytes_hex != encode_hex(&bytes) {
                    errors.push(
                        "proof.bytes_hex must use canonical lower-case 0x-prefixed encoding"
                            .to_string(),
                    );
                }
                match Proof::from_bytes(&bytes) {
                    Ok(proof) if proof.to_bytes() != bytes => errors.push(
                        "proof bytes contain trailing or non-canonical serialized data".to_string(),
                    ),
                    Ok(_) => {}
                    Err(error) => errors.push(format!(
                        "proof bytes are not a valid Winterfell proof: {error}"
                    )),
                }
            }
            Err(mut decode_errors) => errors.append(&mut decode_errors),
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn decoded_bytes(&self) -> Result<Vec<u8>, Vec<String>> {
        decode_hex(&self.bytes_hex)
    }
}

impl ProductionStarkProofParametersV3 {
    pub const BASE_FIELD: &'static str = "winterfell-f64";
    pub const FIELD_EXTENSION: &'static str = "quadratic";
    pub const TRACE_COMMITMENT_HASH: &'static str = "blake3-256";
    pub const MINIMUM_CONJECTURED_SECURITY_BITS: u32 = 80;

    fn expected() -> Self {
        Self {
            base_field: Self::BASE_FIELD.to_string(),
            field_extension: Self::FIELD_EXTENSION.to_string(),
            trace_commitment_hash: Self::TRACE_COMMITMENT_HASH.to_string(),
            trace_width: TRACE_WIDTH,
            trace_length: TRACE_LENGTH,
            public_input_count: PRODUCTION_STARK_PUBLIC_INPUT_ORDER.len(),
            minimum_conjectured_security_bits: Self::MINIMUM_CONJECTURED_SECURITY_BITS,
        }
    }

    fn validate(&self) -> Result<(), Vec<String>> {
        let expected = Self::expected();
        if self == &expected {
            Ok(())
        } else {
            Err(vec![
                "parameters do not match the production G1-G10 AIR configuration".to_string(),
            ])
        }
    }
}

fn expected_public_input_order() -> Vec<String> {
    PRODUCTION_STARK_PUBLIC_INPUT_ORDER
        .iter()
        .map(|name| (*name).to_string())
        .collect()
}

fn parse_claim_hash_limbs(claim_hash: &str) -> Result<[u64; 8], Vec<String>> {
    let Some(hex) = claim_hash.strip_prefix("0x") else {
        return Err(vec![
            "claim_hash must be a 0x-prefixed 32-byte hex string".to_string(),
        ]);
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(vec![
            "claim_hash must be a 0x-prefixed 32-byte hex string".to_string(),
        ]);
    }

    let mut limbs = [0u64; 8];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let start = index * 8;
        *limb = u64::from(
            u32::from_str_radix(&hex[start..start + 8], 16)
                .map_err(|error| vec![format!("invalid claim_hash limb {index}: {error}")])?,
        );
    }
    Ok(limbs)
}

fn public_inputs_sha256(values: &[u64]) -> String {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for value in values {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    sha256_hex(&bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    encode_hex(&digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(2 + bytes.len() * 2);
    encoded.push_str("0x");
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Vec<String>> {
    let Some(hex) = value.strip_prefix("0x") else {
        return Err(vec!["hex value must start with 0x".to_string()]);
    };
    if hex.len() % 2 != 0 {
        return Err(vec![
            "hex value must contain an even number of digits".to_string(),
        ]);
    }
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(vec![
            "hex value contains non-hexadecimal characters".to_string(),
        ]);
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[index..index + 2], 16)
            .map_err(|error| vec![format!("invalid hex byte at offset {index}: {error}")])?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn validate_exact(field: &str, actual: &str, expected: &str, errors: &mut Vec<String>) {
    if actual != expected {
        errors.push(format!("{field} must be {expected}, got {actual}"));
    }
}

#[cfg(test)]
#[path = "production_proof_artifact_tests.rs"]
mod tests;
