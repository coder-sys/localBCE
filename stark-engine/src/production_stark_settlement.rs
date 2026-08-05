use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    StarkBridgeInput,
    production_attestation_signer::ExternalCommandSigner,
    production_nullifier_root_transition::ProductionNullifierRootTransitionArtifactV1,
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
    #[serde(default)]
    pub transaction_block_number: Option<u64>,
    #[serde(default)]
    pub transaction_block_hash: Option<String>,
    #[serde(default)]
    pub finality_mode: String,
    #[serde(default)]
    pub finalized_on_chain: bool,
    #[serde(default)]
    pub policy_manifest_hash: Option<String>,
    #[serde(default)]
    pub signer_backend: String,
    #[serde(default)]
    pub signer_key_id: Option<String>,
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
pub struct ProductionStarkSettlementJournalV2 {
    pub schema_version: String,
    pub status: String,
    pub transaction_hash: Option<String>,
    pub transaction_block_number: Option<u64>,
    pub transaction_block_hash: Option<String>,
    pub finalized_block_number: Option<u64>,
    pub finalized_block_hash: Option<String>,
    pub claim_hash: String,
    pub batch_root: String,
    pub nullifier_root_before: String,
    pub nullifier_root_after: String,
    pub retry_count: u32,
    pub local_state_committed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionStarkSettlementReconciliationReportV1 {
    pub schema_version: String,
    pub status: String,
    pub journal_status_before: String,
    pub journal_status_after: String,
    pub transaction_hash: String,
    pub transaction_block_number: u64,
    pub transaction_block_hash: String,
    pub finalized_block_number: u64,
    pub claim_hash: String,
    pub batch_root: String,
    pub claim_recorded_on_chain: bool,
    pub batch_consumed_on_chain: bool,
    pub chain_root: String,
    pub local_root_before: String,
    pub local_root_after: String,
    pub local_state_committed_now: bool,
    pub retry_count: u32,
}

pub struct ProductionStarkSettlementReconciliationRequest<'a> {
    pub journal_path: &'a Path,
    pub transition_path: &'a Path,
    pub nullifier_state_path: &'a Path,
    pub report_path: &'a Path,
    pub registry_address: &'a str,
    pub rpc_url: &'a str,
    pub chain_id: u64,
    pub finality_mode: SettlementFinalityMode,
    pub finality_timeout: Duration,
    pub finality_poll_interval: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementFinalityMode {
    Mined,
    Finalized,
    TestMined,
}

pub enum ProductionAttestationSignerConfig<'a> {
    LocalPrivateKey(&'a str),
    ExternalCommand {
        signer: &'a ExternalCommandSigner,
        policy_manifest_hash: &'a str,
    },
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
    pub attestation_signer: ProductionAttestationSignerConfig<'a>,
    pub submitter_private_key: &'a str,
    pub finality_mode: SettlementFinalityMode,
    pub finality_timeout: Duration,
    pub finality_poll_interval: Duration,
}

impl ProductionStarkSettlementReceiptV1 {
    pub const SCHEMA_VERSION: &'static str = "stark-production-settlement-receipt-v1";
    pub const GOVERNED_SCHEMA_VERSION: &'static str = "stark-production-settlement-receipt-v2";
    pub const TEST_GOVERNED_SCHEMA_VERSION: &'static str =
        "stark-production-settlement-receipt-v2-test-only";

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let governed = self.schema_version == Self::GOVERNED_SCHEMA_VERSION;
        let test_governed = self.schema_version == Self::TEST_GOVERNED_SCHEMA_VERSION;
        if self.schema_version != Self::SCHEMA_VERSION && !governed && !test_governed {
            errors.push(format!(
                "schema_version must be {}, {}, or {}",
                Self::SCHEMA_VERSION,
                Self::GOVERNED_SCHEMA_VERSION,
                Self::TEST_GOVERNED_SCHEMA_VERSION
            ));
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
        if governed || test_governed {
            if self.transaction_block_number.is_none()
                || self
                    .transaction_block_hash
                    .as_deref()
                    .is_none_or(|value| value.len() != 66)
            {
                errors.push(
                    "governed receipt requires transaction block number and hash".to_string(),
                );
            }
            if governed && (!self.finalized_on_chain || self.finality_mode != "finalized") {
                errors.push("governed receipt must be finalized on chain".to_string());
            }
            if test_governed
                && (self.chain_id != 31337
                    || self.finalized_on_chain
                    || self.finality_mode != "test_mined"
                    || self.signer_backend != "mock_mpc_test_only")
            {
                errors.push(
                    "test-only governed receipt requires chain 31337, mock signer, and test_mined finality"
                        .to_string(),
                );
            }
            if self
                .policy_manifest_hash
                .as_deref()
                .is_none_or(|value| value.len() != 66)
            {
                errors.push("governed receipt requires policy_manifest_hash".to_string());
            }
            if self.signer_backend.trim().is_empty()
                || self
                    .signer_key_id
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty())
            {
                errors.push("governed receipt requires signer backend and key id".to_string());
            }
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

impl ProductionStarkSettlementJournalV2 {
    pub const SCHEMA_VERSION: &'static str = "stark-production-settlement-journal-v2";

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!("schema_version must be {}", Self::SCHEMA_VERSION));
        }
        if ![
            "prepared",
            "submitted",
            "mined",
            "finalized",
            "local_state_committed",
        ]
        .contains(&self.status.as_str())
        {
            errors.push("journal status is unsupported".to_string());
        }
        for (field, value) in [
            ("claim_hash", self.claim_hash.as_str()),
            ("batch_root", self.batch_root.as_str()),
            ("nullifier_root_before", self.nullifier_root_before.as_str()),
            ("nullifier_root_after", self.nullifier_root_after.as_str()),
        ] {
            if !is_bytes32_hex(value) {
                errors.push(format!("{field} must be a bytes32 hex value"));
            }
        }
        if self.status == "prepared" && self.transaction_hash.is_some() {
            errors.push("prepared journal must not contain a transaction hash".to_string());
        }
        if self.status != "prepared"
            && self
                .transaction_hash
                .as_deref()
                .is_none_or(|value| !is_bytes32_hex(value))
        {
            errors.push("submitted journal requires a transaction hash".to_string());
        }
        if self.local_state_committed != (self.status == "local_state_committed") {
            errors.push("local_state_committed flag must match journal status".to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

pub fn reconcile_production_stark_settlement(
    request: &ProductionStarkSettlementReconciliationRequest<'_>,
) -> Result<ProductionStarkSettlementReconciliationReportV1, Vec<String>> {
    let rpc_chain_id = run_cast(&["chain-id", "--rpc-url", request.rpc_url])?
        .parse::<u64>()
        .map_err(|error| vec![format!("cast chain-id returned an invalid value: {error}")])?;
    if rpc_chain_id != request.chain_id {
        return Err(vec![format!(
            "RPC chain ID {rpc_chain_id} does not match configured chain ID {}",
            request.chain_id
        )]);
    }
    if request.finality_mode == SettlementFinalityMode::TestMined && request.chain_id != 31337 {
        return Err(vec![
            "test_mined reconciliation is permitted only on chain ID 31337".to_string(),
        ]);
    }

    let _state_lock = acquire_production_nullifier_state_lock(request.nullifier_state_path)?;
    let mut journal = read_json::<ProductionStarkSettlementJournalV2>(
        request.journal_path,
        "settlement journal",
    )?;
    journal.validate()?;
    if journal.status == "prepared" {
        return Err(vec![
            "journal is prepared with no transaction hash; retry the original settlement command with the same claim instead of guessing a chain submission"
                .to_string(),
        ]);
    }

    let status_before = journal.status.clone();
    let transaction_hash = journal
        .transaction_hash
        .clone()
        .expect("validated transaction hash");
    journal.retry_count = journal.retry_count.saturating_add(1);
    write_json_atomic(request.journal_path, &journal)?;

    let receipt = load_chain_receipt(
        request.rpc_url,
        &transaction_hash,
        request.finality_timeout,
        request.finality_poll_interval,
    )?;
    if journal
        .transaction_block_number
        .is_some_and(|value| value != receipt.block_number)
        || journal
            .transaction_block_hash
            .as_deref()
            .is_some_and(|value| normalize_hex(value) != normalize_hex(&receipt.block_hash))
    {
        return Err(vec![
            "settlement receipt conflicts with the journal; possible reorg or wrong RPC chain"
                .to_string(),
        ]);
    }
    journal.status = "mined".to_string();
    journal.transaction_block_number = Some(receipt.block_number);
    journal.transaction_block_hash = Some(receipt.block_hash.clone());
    write_json_atomic(request.journal_path, &journal)?;

    let finalized = wait_for_finality(
        request.rpc_url,
        &receipt,
        request.finality_mode,
        request.finality_timeout,
        request.finality_poll_interval,
    )?;
    journal.status = "finalized".to_string();
    journal.finalized_block_number = Some(finalized.block_number);
    journal.finalized_block_hash = Some(finalized.block_hash);
    write_json_atomic(request.journal_path, &journal)?;

    let batch_consumed = cast_call(
        request.rpc_url,
        request.registry_address,
        "consumedBatchRoots(bytes32)(bool)",
        Some(&journal.batch_root),
    )?
    .trim()
        == "true";
    let claim_record = cast_call(
        request.rpc_url,
        request.registry_address,
        "claims(bytes32)(bool,bool,uint256,uint256,uint256,uint32,bytes32,bytes32,bytes32)",
        Some(&journal.claim_hash),
    )?;
    let claim_recorded = first_cast_bool(&claim_record)?;
    if !batch_consumed || !claim_recorded {
        return Err(vec![
            "finalized transaction does not match the expected claim and batch records".to_string(),
        ]);
    }

    let chain_root = normalize_hex(&cast_call(
        request.rpc_url,
        request.registry_address,
        "currentNullifierRoot()(bytes32)",
        None,
    )?);
    if chain_root != normalize_hex(&journal.nullifier_root_after) {
        return Err(vec![
            "finalized chain nullifier root conflicts with the journal transition".to_string(),
        ]);
    }

    let transition = read_json::<ProductionNullifierRootTransitionArtifactV1>(
        request.transition_path,
        "nullifier transition",
    )?;
    transition.validate()?;
    if normalize_hex(&transition.claim_hash) != normalize_hex(&journal.claim_hash)
        || normalize_hex(&transition.nullifier_root_before_bytes32)
            != normalize_hex(&journal.nullifier_root_before)
        || normalize_hex(&transition.nullifier_root_after_bytes32)
            != normalize_hex(&journal.nullifier_root_after)
    {
        return Err(vec![
            "nullifier transition artifact conflicts with the settlement journal".to_string(),
        ]);
    }

    let mut state = load_production_nullifier_state(request.nullifier_state_path)?;
    let local_root_before = state.root_bytes32.clone();
    let mut committed_now = false;
    if normalize_hex(&state.root_bytes32) == normalize_hex(&journal.nullifier_root_before) {
        let apply_receipt = state.apply_transition(&transition)?;
        write_production_nullifier_state_atomic(request.nullifier_state_path, &state)?;
        let apply_path = request
            .report_path
            .with_file_name("nullifier_reconciliation_apply_receipt.json");
        write_json(apply_path, &apply_receipt)?;
        committed_now = true;
    } else if normalize_hex(&state.root_bytes32) != normalize_hex(&journal.nullifier_root_after) {
        return Err(vec![
            "local nullifier state conflicts with both sides of the finalized transition"
                .to_string(),
        ]);
    }

    journal.status = "local_state_committed".to_string();
    journal.local_state_committed = true;
    write_json_atomic(request.journal_path, &journal)?;
    let report = ProductionStarkSettlementReconciliationReportV1 {
        schema_version: "stark-production-settlement-reconciliation-report-v1".to_string(),
        status: "finalized_chain_and_local_state_reconciled".to_string(),
        journal_status_before: status_before,
        journal_status_after: journal.status.clone(),
        transaction_hash,
        transaction_block_number: receipt.block_number,
        transaction_block_hash: receipt.block_hash,
        finalized_block_number: finalized.block_number,
        claim_hash: journal.claim_hash,
        batch_root: journal.batch_root,
        claim_recorded_on_chain: claim_recorded,
        batch_consumed_on_chain: batch_consumed,
        chain_root,
        local_root_before,
        local_root_after: state.root_bytes32,
        local_state_committed_now: committed_now,
        retry_count: journal.retry_count,
    };
    write_json(request.report_path, &report)?;
    Ok(report)
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
    let envelope = match &request.attestation_signer {
        ProductionAttestationSignerConfig::LocalPrivateKey(private_key) => {
            ProductionStarkAttestationEnvelopeV2::from_handoff(
                &handoff,
                request.chain_id,
                request.verifier_address,
                request.registry_address,
                bridge.claim.claim_amount,
                private_key,
            )?
        }
        ProductionAttestationSignerConfig::ExternalCommand {
            signer,
            policy_manifest_hash,
        } => ProductionStarkAttestationEnvelopeV2::from_handoff_with_external_signer(
            &handoff,
            request.chain_id,
            request.verifier_address,
            request.registry_address,
            bridge.claim.claim_amount,
            policy_manifest_hash,
            signer,
        )?,
    };
    if request.finality_mode == SettlementFinalityMode::TestMined
        && (request.chain_id != 31337 || envelope.signer_backend != "mock_mpc_test_only")
    {
        return Err(vec![
            "test_mined finality is restricted to chain 31337 with the mock MPC signer".to_string(),
        ]);
    }

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

    let journal_path = request.output_directory.join("settlement_journal.json");
    let mut journal = ProductionStarkSettlementJournalV2 {
        schema_version: "stark-production-settlement-journal-v2".to_string(),
        status: "prepared".to_string(),
        transaction_hash: None,
        transaction_block_number: None,
        transaction_block_hash: None,
        finalized_block_number: None,
        finalized_block_hash: None,
        claim_hash: envelope.public_inputs.claim_hash.clone(),
        batch_root: envelope.public_inputs.batch_root.clone(),
        nullifier_root_before: envelope.public_inputs.nullifier_root_before.clone(),
        nullifier_root_after: envelope.public_inputs.nullifier_root_after.clone(),
        retry_count: 0,
        local_state_committed: false,
    };
    write_json_atomic(&journal_path, &journal)?;

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
    journal.status = "submitted".to_string();
    journal.transaction_hash = Some(transaction_hash.clone());
    write_json_atomic(&journal_path, &journal)?;

    let transaction_receipt = load_chain_receipt(
        request.rpc_url,
        &transaction_hash,
        request.finality_timeout,
        request.finality_poll_interval,
    )?;
    journal.status = "mined".to_string();
    journal.transaction_block_number = Some(transaction_receipt.block_number);
    journal.transaction_block_hash = Some(transaction_receipt.block_hash.clone());
    write_json_atomic(&journal_path, &journal)?;

    let finalized = wait_for_finality(
        request.rpc_url,
        &transaction_receipt,
        request.finality_mode,
        request.finality_timeout,
        request.finality_poll_interval,
    )?;
    journal.status = "finalized".to_string();
    journal.finalized_block_number = Some(finalized.block_number);
    journal.finalized_block_hash = Some(finalized.block_hash);
    write_json_atomic(&journal_path, &journal)?;

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

    journal.status = "local_state_committed".to_string();
    journal.local_state_committed = true;
    write_json_atomic(&journal_path, &journal)?;

    let governed =
        envelope.schema_version == ProductionStarkAttestationEnvelopeV2::GOVERNED_SCHEMA_VERSION;
    let test_governed = governed && request.finality_mode == SettlementFinalityMode::TestMined;
    let receipt = ProductionStarkSettlementReceiptV1 {
        schema_version: if test_governed {
            ProductionStarkSettlementReceiptV1::TEST_GOVERNED_SCHEMA_VERSION.to_string()
        } else if governed {
            ProductionStarkSettlementReceiptV1::GOVERNED_SCHEMA_VERSION.to_string()
        } else {
            ProductionStarkSettlementReceiptV1::SCHEMA_VERSION.to_string()
        },
        settlement_status: "settled_on_chain_and_local_state_committed".to_string(),
        proof_backend: "winterfell_stark_authorized_attestation".to_string(),
        trust_model: envelope.trust_model.clone(),
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
        transaction_block_number: Some(transaction_receipt.block_number),
        transaction_block_hash: Some(transaction_receipt.block_hash),
        finality_mode: match request.finality_mode {
            SettlementFinalityMode::Mined => "mined".to_string(),
            SettlementFinalityMode::Finalized => "finalized".to_string(),
            SettlementFinalityMode::TestMined => "test_mined".to_string(),
        },
        finalized_on_chain: request.finality_mode == SettlementFinalityMode::Finalized,
        policy_manifest_hash: envelope.policy_manifest_hash.clone(),
        signer_backend: envelope.signer_backend.clone(),
        signer_key_id: envelope.signer_key_id.clone(),
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
    Ok(receipt)
}

#[derive(Clone, Debug)]
struct ChainBlockReference {
    transaction_hash: String,
    block_number: u64,
    block_hash: String,
}

fn load_chain_receipt(
    rpc_url: &str,
    transaction_hash: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<ChainBlockReference, Vec<String>> {
    let started = Instant::now();
    loop {
        let output = run_cast(&["receipt", transaction_hash, "--rpc-url", rpc_url, "--json"]);
        if let Ok(output) = output {
            let value: serde_json::Value = serde_json::from_str(&output)
                .map_err(|error| vec![format!("cast receipt returned invalid JSON: {error}")])?;
            let status = parse_u64(&value["status"], "receipt status")?;
            if status != 1 {
                return Err(vec!["STARK settlement transaction reverted".to_string()]);
            }
            return Ok(ChainBlockReference {
                transaction_hash: transaction_hash.to_string(),
                block_number: parse_u64(&value["blockNumber"], "receipt blockNumber")?,
                block_hash: required_hex(&value["blockHash"], 32, "receipt blockHash")?,
            });
        }
        if started.elapsed() >= timeout {
            return Err(vec![
                "timed out waiting for STARK transaction receipt".to_string(),
            ]);
        }
        thread::sleep(poll_interval);
    }
}

fn wait_for_finality(
    rpc_url: &str,
    receipt: &ChainBlockReference,
    mode: SettlementFinalityMode,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<ChainBlockReference, Vec<String>> {
    if matches!(
        mode,
        SettlementFinalityMode::Mined | SettlementFinalityMode::TestMined
    ) {
        return Ok(receipt.clone());
    }
    let started = Instant::now();
    loop {
        if let Ok(output) = run_cast(&["block", "finalized", "--rpc-url", rpc_url, "--json"]) {
            let value: serde_json::Value = serde_json::from_str(&output).map_err(|error| {
                vec![format!(
                    "cast block finalized returned invalid JSON: {error}"
                )]
            })?;
            let finalized = ChainBlockReference {
                transaction_hash: receipt.transaction_hash.clone(),
                block_number: parse_u64(&value["number"], "finalized block number")?,
                block_hash: required_hex(&value["hash"], 32, "finalized block hash")?,
            };
            if finalized.block_number >= receipt.block_number {
                let current = load_chain_receipt(
                    rpc_url,
                    &receipt.transaction_hash,
                    poll_interval,
                    poll_interval,
                );
                if let Ok(current) = current {
                    if current.block_hash != receipt.block_hash
                        || current.block_number != receipt.block_number
                    {
                        return Err(vec![
                            "STARK settlement transaction was reorganized before finality"
                                .to_string(),
                        ]);
                    }
                }
                return Ok(finalized);
            }
        }
        if started.elapsed() >= timeout {
            return Err(vec![
                "timed out waiting for finalized STARK transaction".to_string(),
            ]);
        }
        thread::sleep(poll_interval);
    }
}

fn parse_u64(value: &serde_json::Value, field: &str) -> Result<u64, Vec<String>> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    let value = value
        .as_str()
        .ok_or_else(|| vec![format!("{field} must be a number or numeric string")])?;
    if let Some(value) = value.strip_prefix("0x") {
        u64::from_str_radix(value, 16)
            .map_err(|error| vec![format!("{field} is not valid hex: {error}")])
    } else {
        value
            .parse::<u64>()
            .map_err(|error| vec![format!("{field} is not a valid number: {error}")])
    }
}

fn required_hex(
    value: &serde_json::Value,
    expected_bytes: usize,
    field: &str,
) -> Result<String, Vec<String>> {
    let value = value
        .as_str()
        .ok_or_else(|| vec![format!("{field} must be a hex string")])?
        .to_ascii_lowercase();
    if !value.starts_with("0x") || value.len() != 2 + expected_bytes * 2 {
        return Err(vec![format!("{field} must be {expected_bytes} bytes")]);
    }
    if !value[2..].bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(vec![format!("{field} contains invalid hex")]);
    }
    Ok(value)
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

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<(), Vec<String>> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| vec![format!("could not serialize {}: {error}", path.display())])?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, format!("{json}\n"))
        .map_err(|error| vec![format!("could not write {}: {error}", temporary.display())])?;
    fs::rename(&temporary, path).map_err(|error| {
        vec![format!(
            "could not atomically replace {} with {}: {error}",
            path.display(),
            temporary.display()
        )]
    })
}

fn normalize_hex(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn is_bytes32_hex(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn first_cast_bool(value: &str) -> Result<bool, Vec<String>> {
    let first = value
        .trim()
        .trim_start_matches('(')
        .split([',', ' ', '\n'])
        .find(|part| !part.is_empty())
        .ok_or_else(|| vec!["cast claim record output was empty".to_string()])?;
    match first {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(vec![
            "cast claim record output did not begin with a boolean".to_string(),
        ]),
    }
}

#[cfg(test)]
mod journal_tests {
    use super::*;

    fn sample(status: &str) -> ProductionStarkSettlementJournalV2 {
        let submitted = status != "prepared";
        ProductionStarkSettlementJournalV2 {
            schema_version: ProductionStarkSettlementJournalV2::SCHEMA_VERSION.to_string(),
            status: status.to_string(),
            transaction_hash: submitted.then(|| format!("0x{}", "11".repeat(32))),
            transaction_block_number: None,
            transaction_block_hash: None,
            finalized_block_number: None,
            finalized_block_hash: None,
            claim_hash: format!("0x{}", "22".repeat(32)),
            batch_root: format!("0x{}", "33".repeat(32)),
            nullifier_root_before: format!("0x{}", "44".repeat(32)),
            nullifier_root_after: format!("0x{}", "55".repeat(32)),
            retry_count: 0,
            local_state_committed: status == "local_state_committed",
        }
    }

    #[test]
    fn settlement_journal_accepts_every_versioned_state() {
        for status in [
            "prepared",
            "submitted",
            "mined",
            "finalized",
            "local_state_committed",
        ] {
            sample(status).validate().expect(status);
        }
    }

    #[test]
    fn settlement_journal_rejects_missing_transaction_and_inconsistent_commit() {
        let mut value = sample("submitted");
        value.transaction_hash = None;
        assert!(value.validate().is_err());
        let mut value = sample("finalized");
        value.local_state_committed = true;
        assert!(value.validate().is_err());
    }
}
