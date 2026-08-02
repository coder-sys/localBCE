use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};

use crate::{
    StarkBridgeInput,
    production_nullifier_state::{
        acquire_production_nullifier_state_lock, load_production_nullifier_state,
        write_production_nullifier_state_atomic,
    },
    production_proof_artifact::ProductionStarkProofArtifactV4,
    production_stark_attestation::ProductionStarkAttestationEnvelopeV2,
    production_verifier_handoff::ProductionStarkVerifierHandoffV4,
};

pub const SUBMIT_STARK_CLAIM_SIGNATURE: &str = "submitStarkClaim((bytes32,uint8,uint32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32),bytes,uint256)";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionStarkSettlementReceiptV1 {
    pub schema_version: String,
    pub settlement_status: String,
    pub proof_backend: String,
    pub trust_model: String,
    pub chain_id: u64,
    pub verifier_address: String,
    pub registry_address: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub decision: u8,
    pub failure_code: u32,
    pub proof_sha256: String,
    pub proof_size_bytes: usize,
    pub proof_locally_verified: bool,
    pub attestation_locally_validated: bool,
    pub transaction_hash: String,
    pub batch_root: String,
    pub batch_consumed_on_chain: bool,
    pub nullifier_root_before: String,
    pub nullifier_root_after: String,
    pub on_chain_root_after: String,
    pub local_state_generation_before: u64,
    pub local_state_generation_after: u64,
    pub local_state_committed: bool,
    pub native_on_chain_stark_verification: bool,
    pub controlled_attestation_verification: bool,
    pub groth16_executed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PendingStarkSettlementV1 {
    schema_version: String,
    status: String,
    transaction_hash: String,
    claim_hash: String,
    batch_root: String,
    nullifier_root_before: String,
    nullifier_root_after: String,
    local_state_committed: bool,
}

pub struct ProductionStarkSettlementRequest<'a> {
    pub bridge_input_path: &'a Path,
    pub nullifier_state_path: &'a Path,
    pub output_directory: &'a Path,
    pub chain_id: u64,
    pub verifier_address: &'a str,
    pub registry_address: &'a str,
    pub rpc_url: &'a str,
    pub transaction_value: &'a str,
    pub attestor_private_key: &'a str,
    pub submitter_private_key: &'a str,
}

impl ProductionStarkSettlementReceiptV1 {
    pub const SCHEMA_VERSION: &'static str = "stark-production-settlement-receipt-v1";

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!("schema_version must be {}", Self::SCHEMA_VERSION));
        }
        if self.settlement_status != "settled_on_chain_and_local_state_committed" {
            errors.push("settlement_status is not final".to_string());
        }
        if self.proof_backend != "winterfell_stark_authorized_attestation" {
            errors
                .push("proof_backend is not the production STARK attestation backend".to_string());
        }
        if !self.proof_locally_verified || !self.attestation_locally_validated {
            errors.push("proof and attestation must both be locally validated".to_string());
        }
        if self.transaction_hash.len() != 66 || !self.transaction_hash.starts_with("0x") {
            errors.push("transaction_hash must be a bytes32 hex value".to_string());
        }
        if !self.batch_consumed_on_chain || !self.local_state_committed {
            errors.push("on-chain batch and local state must both be committed".to_string());
        }
        if self.on_chain_root_after != self.nullifier_root_after {
            errors.push("on-chain root must match the committed transition root".to_string());
        }
        if self.native_on_chain_stark_verification || !self.controlled_attestation_verification {
            errors.push(
                "receipt must state the controlled-attestation trust model exactly".to_string(),
            );
        }
        if self.groth16_executed {
            errors.push("Groth16 must not execute in the STARK settlement path".to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

pub fn execute_production_stark_settlement(
    request: &ProductionStarkSettlementRequest<'_>,
) -> Result<ProductionStarkSettlementReceiptV1, Vec<String>> {
    if request.chain_id == 0 {
        return Err(vec!["chain_id must be nonzero".to_string()]);
    }
    fs::create_dir_all(request.output_directory).map_err(|error| {
        vec![format!(
            "could not create {}: {error}",
            request.output_directory.display()
        )]
    })?;
    let _state_lock = acquire_production_nullifier_state_lock(request.nullifier_state_path)?;
    let bridge = read_json::<StarkBridgeInput>(request.bridge_input_path, "bridge input")?;
    bridge.validate()?;
    let mut state = load_production_nullifier_state(request.nullifier_state_path)?;

    let on_chain_root_before = cast_call(
        request.rpc_url,
        request.registry_address,
        "currentNullifierRoot()(bytes32)",
        None,
    )?;
    if normalize_hex(&on_chain_root_before) != normalize_hex(&state.root_bytes32) {
        return Err(vec![format!(
            "on-chain nullifier root {} does not match local state root {}",
            on_chain_root_before, state.root_bytes32
        )]);
    }

    let transition = state.prepare_transition(&bridge)?;
    let proof = ProductionStarkProofArtifactV4::from_bridge_input_with_nullifier_transition(
        &bridge,
        &transition,
    )?;
    proof.verify_serialized_proof()?;
    let handoff = ProductionStarkVerifierHandoffV4::from_proof_artifact(&proof)?;
    let envelope = ProductionStarkAttestationEnvelopeV2::from_handoff(
        &handoff,
        request.chain_id,
        request.verifier_address,
        request.registry_address,
        bridge.claim.claim_amount,
        request.attestor_private_key,
    )?;

    write_json(
        request.output_directory.join("nullifier_transition.json"),
        &transition,
    )?;
    write_json(request.output_directory.join("proof_artifact.json"), &proof)?;
    write_json(
        request.output_directory.join("verifier_handoff.json"),
        &handoff,
    )?;
    write_json(
        request.output_directory.join("attestation_envelope.json"),
        &envelope,
    )?;

    let value = if envelope.public_inputs.decision == 1 {
        request.transaction_value
    } else {
        "0"
    };
    let cast_output = run_cast(&[
        "send",
        request.registry_address,
        SUBMIT_STARK_CLAIM_SIGNATURE,
        &envelope.public_inputs.cast_tuple(),
        &envelope.proof_envelope_hex,
        &bridge.claim.claim_amount.to_string(),
        "--value",
        value,
        "--private-key",
        request.submitter_private_key,
        "--rpc-url",
        request.rpc_url,
        "--json",
    ])?;
    let transaction_hash = extract_transaction_hash(&cast_output)?;

    let pending_path = request.output_directory.join("pending_settlement.json");
    write_json(
        &pending_path,
        &PendingStarkSettlementV1 {
            schema_version: "stark-production-pending-settlement-v1".to_string(),
            status: "on_chain_transaction_mined_local_state_pending".to_string(),
            transaction_hash: transaction_hash.clone(),
            claim_hash: envelope.public_inputs.claim_hash.clone(),
            batch_root: envelope.public_inputs.batch_root.clone(),
            nullifier_root_before: envelope.public_inputs.nullifier_root_before.clone(),
            nullifier_root_after: envelope.public_inputs.nullifier_root_after.clone(),
            local_state_committed: false,
        },
    )?;

    let batch_consumed = cast_call(
        request.rpc_url,
        request.registry_address,
        "consumedBatchRoots(bytes32)(bool)",
        Some(&envelope.public_inputs.batch_root),
    )?;
    if batch_consumed.trim() != "true" {
        return Err(vec![
            "STARK transaction mined but registry did not consume the batch root".to_string(),
        ]);
    }
    let on_chain_root_after = cast_call(
        request.rpc_url,
        request.registry_address,
        "currentNullifierRoot()(bytes32)",
        None,
    )?;
    if normalize_hex(&on_chain_root_after)
        != normalize_hex(&envelope.public_inputs.nullifier_root_after)
    {
        return Err(vec![
            "registry nullifier root does not match the verified STARK transition".to_string(),
        ]);
    }

    let generation_before = state.generation;
    let apply_receipt = state.apply_transition(&transition)?;
    write_production_nullifier_state_atomic(request.nullifier_state_path, &state)?;
    write_json(
        request
            .output_directory
            .join("nullifier_apply_receipt.json"),
        &apply_receipt,
    )?;

    let receipt = ProductionStarkSettlementReceiptV1 {
        schema_version: ProductionStarkSettlementReceiptV1::SCHEMA_VERSION.to_string(),
        settlement_status: "settled_on_chain_and_local_state_committed".to_string(),
        proof_backend: "winterfell_stark_authorized_attestation".to_string(),
        trust_model: ProductionStarkAttestationEnvelopeV2::TRUST_MODEL.to_string(),
        chain_id: request.chain_id,
        verifier_address: envelope.verifier_address.clone(),
        registry_address: normalize_hex(request.registry_address),
        claim_id: bridge.claim.claim_id.clone(),
        claim_hash: bridge.claim.claim_hash.clone(),
        decision: bridge.adjudication.decision,
        failure_code: bridge.adjudication.failure_code,
        proof_sha256: proof.proof.sha256.clone(),
        proof_size_bytes: proof.proof.size_bytes,
        proof_locally_verified: proof.locally_verified,
        attestation_locally_validated: envelope.locally_validated,
        transaction_hash,
        batch_root: envelope.public_inputs.batch_root.clone(),
        batch_consumed_on_chain: true,
        nullifier_root_before: transition.nullifier_root_before_bytes32.clone(),
        nullifier_root_after: transition.nullifier_root_after_bytes32.clone(),
        on_chain_root_after: normalize_hex(&on_chain_root_after),
        local_state_generation_before: generation_before,
        local_state_generation_after: state.generation,
        local_state_committed: true,
        native_on_chain_stark_verification: false,
        controlled_attestation_verification: true,
        groth16_executed: false,
    };
    receipt.validate()?;
    write_json(
        request.output_directory.join("settlement_receipt.json"),
        &receipt,
    )?;
    fs::remove_file(&pending_path).map_err(|error| {
        vec![format!(
            "could not remove {}: {error}",
            pending_path.display()
        )]
    })?;
    Ok(receipt)
}

fn cast_call(
    rpc_url: &str,
    contract: &str,
    signature: &str,
    argument: Option<&str>,
) -> Result<String, Vec<String>> {
    let mut args = vec!["call", contract, signature];
    if let Some(argument) = argument {
        args.push(argument);
    }
    args.extend(["--rpc-url", rpc_url]);
    run_cast(&args)
}

fn run_cast(args: &[&str]) -> Result<String, Vec<String>> {
    let output = Command::new("cast")
        .args(args)
        .output()
        .map_err(|error| vec![format!("could not execute cast: {error}")])?;
    if !output.status.success() {
        return Err(vec![format!(
            "cast command failed with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )]);
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|error| vec![format!("cast output was not UTF-8: {error}")])
}

fn extract_transaction_hash(output: &str) -> Result<String, Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(output)
        .map_err(|error| vec![format!("cast send did not return JSON: {error}")])?;
    value
        .get("transactionHash")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| vec!["cast send JSON did not include transactionHash".to_string()])
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
    label: &str,
) -> Result<T, Vec<String>> {
    let path = path.as_ref();
    let json = fs::read_to_string(path)
        .map_err(|error| vec![format!("could not read {}: {error}", path.display())])?;
    serde_json::from_str(&json).map_err(|error| vec![format!("invalid {label} JSON: {error}")])
}

fn write_json(path: impl Into<PathBuf>, value: &impl Serialize) -> Result<(), Vec<String>> {
    let path = path.into();
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| vec![format!("could not serialize {}: {error}", path.display())])?;
    fs::write(&path, format!("{json}\n"))
        .map_err(|error| vec![format!("could not write {}: {error}", path.display())])
}

fn normalize_hex(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}
