use serde::{Deserialize, Serialize};

use crate::production_proof_artifact::ProductionStarkProofArtifactV4;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeVerifierMutationVectorV1 {
    pub vector_id: String,
    pub mutation_kind: String,
    pub target: String,
    pub index: usize,
    pub expected_result: String,
    pub rust_winterfell_rejected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NativeVerifierActivationGatesV1 {
    pub complete_transcript_parity: bool,
    pub eip_170_bytecode_compatible: bool,
    pub verification_gas_below_half_target_block_limit: bool,
    pub adversarial_vector_suite_passed: bool,
    pub independent_cryptographic_audit_complete: bool,
    pub independent_solidity_audit_complete: bool,
    pub activation_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellNativeVerifierVectorSetV1 {
    pub schema_version: String,
    pub status: String,
    pub proof_artifact_schema_version: String,
    pub proof_system: String,
    pub proof_system_version: String,
    pub base_field: String,
    pub field_extension: String,
    pub trace_commitment_hash: String,
    pub proof_options: Vec<String>,
    pub valid_proof_sha256: String,
    pub valid_proof_size_bytes: usize,
    pub valid_public_inputs_sha256: String,
    pub valid_vector_rust_verified: bool,
    pub mutation_vectors: Vec<NativeVerifierMutationVectorV1>,
    pub activation_gates: NativeVerifierActivationGatesV1,
    pub verifier_scope: Vec<String>,
    pub explicit_limitations: Vec<String>,
}

impl WinterfellNativeVerifierVectorSetV1 {
    pub const SCHEMA_VERSION: &'static str = "winterfell-native-evm-verifier-vectors-v1";
    pub const STATUS: &'static str = "candidate_inactive_audit_and_evm_implementation_required";

    pub fn from_artifact(artifact: &ProductionStarkProofArtifactV4) -> Result<Self, Vec<String>> {
        artifact.validate()?;
        artifact.verify_serialized_proof()?;
        let mutations = mutation_cases(artifact)?;
        let value = Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            status: Self::STATUS.to_string(),
            proof_artifact_schema_version: artifact.schema_version.clone(),
            proof_system: artifact.proof_system.clone(),
            proof_system_version: artifact.proof_system_version.clone(),
            base_field: artifact.parameters.base_field.clone(),
            field_extension: artifact.parameters.field_extension.clone(),
            trace_commitment_hash: artifact.parameters.trace_commitment_hash.clone(),
            proof_options: vec![
                "num_queries=32".to_string(),
                "blowup_factor=16".to_string(),
                "grinding_factor=0".to_string(),
                "field_extension=quadratic".to_string(),
                "fri_folding_factor=8".to_string(),
                "fri_remainder_max_degree=31".to_string(),
                "constraint_batching=linear".to_string(),
                "deep_poly_batching=linear".to_string(),
            ],
            valid_proof_sha256: artifact.proof.sha256.clone(),
            valid_proof_size_bytes: artifact.proof.size_bytes,
            valid_public_inputs_sha256: artifact.public_inputs.canonical_bytes_sha256.clone(),
            valid_vector_rust_verified: true,
            mutation_vectors: mutations,
            activation_gates: NativeVerifierActivationGatesV1 {
                complete_transcript_parity: false,
                eip_170_bytecode_compatible: false,
                verification_gas_below_half_target_block_limit: false,
                adversarial_vector_suite_passed: false,
                independent_cryptographic_audit_complete: false,
                independent_solidity_audit_complete: false,
                activation_allowed: false,
            },
            verifier_scope: vec![
                "canonical Winterfell proof decoding".to_string(),
                "64-bit prime field and quadratic extension arithmetic".to_string(),
                "Blake3 transcript and Merkle authentication".to_string(),
                "FRI folding, remainder, and query checks".to_string(),
                "G1-G10 AIR and 38-element public-input binding".to_string(),
            ],
            explicit_limitations: vec![
                "This vector set is differential evidence, not an EVM verifier implementation."
                    .to_string(),
                "Proof commitment equality is never accepted as proof verification.".to_string(),
                "The governed controlled-attestation pilot remains active while this candidate is inactive."
                    .to_string(),
            ],
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!("schema_version must be {}", Self::SCHEMA_VERSION));
        }
        if self.status != Self::STATUS {
            errors.push(format!("status must be {}", Self::STATUS));
        }
        if self.proof_system != "winterfell" || !self.valid_vector_rust_verified {
            errors.push(
                "valid vector must be verified by the pinned Rust Winterfell verifier".to_string(),
            );
        }
        if self.mutation_vectors.len() < 10
            || self
                .mutation_vectors
                .iter()
                .any(|value| !value.rust_winterfell_rejected || value.expected_result != "reject")
        {
            errors.push(
                "every mutation vector must be rejected by the Rust Winterfell verifier"
                    .to_string(),
            );
        }
        if self.activation_gates.activation_allowed
            || [
                self.activation_gates.complete_transcript_parity,
                self.activation_gates.eip_170_bytecode_compatible,
                self.activation_gates
                    .verification_gas_below_half_target_block_limit,
                self.activation_gates.adversarial_vector_suite_passed,
                self.activation_gates
                    .independent_cryptographic_audit_complete,
                self.activation_gates.independent_solidity_audit_complete,
            ]
            .into_iter()
            .any(|value| value)
        {
            errors.push("native verifier candidate must remain inactive until every external gate is evidenced".to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn mutation_cases(
    artifact: &ProductionStarkProofArtifactV4,
) -> Result<Vec<NativeVerifierMutationVectorV1>, Vec<String>> {
    let proof_bytes = decode_hex(&artifact.proof.bytes_hex)?;
    if proof_bytes.len() < 256 {
        return Err(vec![
            "serialized proof is too short for mutation vectors".to_string(),
        ]);
    }
    let mut vectors = Vec::new();
    for (id, index, target) in [
        ("proof-body", 64, "proof_bytes"),
        ("transcript-region", 128, "transcript_data"),
        ("proof-middle", proof_bytes.len() / 2, "query_opening"),
        ("fri-tail", proof_bytes.len() - 1, "fri_opening"),
    ] {
        let mut mutated = artifact.clone();
        let mut bytes = proof_bytes.clone();
        bytes[index] ^= 1;
        mutated.proof.bytes_hex = encode_hex(&bytes);
        vectors.push(vector(
            id,
            "xor_proof_byte",
            target,
            index,
            mutated.verify_serialized_proof().is_err(),
        ));
    }
    for (id, index, target) in [
        ("claim-source-root", 12, "claim_source_root"),
        ("oracle-facts-root", 16, "oracle_facts_root"),
        ("fee-schedule-root", 20, "fee_schedule_root"),
        ("nullifier-root-after", 28, "nullifier_root_after"),
        ("batch-root", 32, "batch_root"),
        ("decision", 36, "decision"),
        ("failure-code", 37, "failure_code"),
    ] {
        let mut mutated = artifact.clone();
        let current = mutated.public_inputs.values_decimal[index]
            .parse::<u64>()
            .map_err(|error| vec![format!("invalid public input {index}: {error}")])?;
        mutated.public_inputs.values_decimal[index] = current.wrapping_add(1).to_string();
        vectors.push(vector(
            id,
            "increment_public_input",
            target,
            index,
            mutated.verify_serialized_proof().is_err(),
        ));
    }
    Ok(vectors)
}

fn vector(
    id: &str,
    mutation_kind: &str,
    target: &str,
    index: usize,
    rejected: bool,
) -> NativeVerifierMutationVectorV1 {
    NativeVerifierMutationVectorV1 {
        vector_id: id.to_string(),
        mutation_kind: mutation_kind.to_string(),
        target: target.to_string(),
        index,
        expected_result: "reject".to_string(),
        rust_winterfell_rejected: rejected,
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Vec<String>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() % 2 != 0 {
        return Err(vec!["proof bytes contain odd-length hex".to_string()]);
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| vec!["proof bytes contain invalid hex".to_string()])
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    let mut encoded = String::from("0x");
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String writes cannot fail");
    }
    encoded
}
