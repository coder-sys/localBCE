use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::process::Command;

const STARK_SIDECAR_OUTPUT_PATH: &str = "stark_adjudication_result.json";
const STARK_BRIDGE_INPUT_OUTPUT_PATH: &str = "stark_bridge_input.json";

#[derive(Debug, Serialize)]
enum AdjudicationStatus {
    #[serde(rename = "APPROVED")]
    Approved,
    #[serde(rename = "DENIED")]
    Denied,
}

#[derive(Debug, Serialize)]
struct AdjudicationResult {
    claim_id: String,
    claim_hash: String,
    status: AdjudicationStatus,
    reason: Option<String>,
    tx_submitted: bool,
    tx_hash: Option<String>,
}

impl AdjudicationResult {
    fn approved(claim_id: String, claim_hash: String, tx_hash: String) -> Self {
        Self {
            claim_id,
            claim_hash,
            status: AdjudicationStatus::Approved,
            reason: None,
            tx_submitted: true,
            tx_hash: Some(tx_hash),
        }
    }

    fn denied(claim_id: String, claim_hash: String, reason: &str) -> Self {
        Self {
            claim_id,
            claim_hash,
            status: AdjudicationStatus::Denied,
            reason: Some(reason.to_string()),
            tx_submitted: false,
            tx_hash: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClaimServiceLine {
    procedure_code: String,
    charge_cents: u64,
    units: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClaimOracleFact {
    fact_type: String,
    fact_key: String,
    fact_value: String,
    source_url: Option<String>,
    source_label: Option<String>,
    verification_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClaimFeeScheduleEntry {
    fee_code: String,
    unit_amount_cents: u64,
    currency: String,
    effective_from: u64,
    effective_thru: Option<u64>,
    source_url: Option<String>,
    verification_status: String,
}

#[derive(Debug, Deserialize)]
struct ClaimInput {
    claim_id: String,
    claim_amount: u64,
    member_id: Option<String>,
    provider_npi: Option<String>,
    diagnosis_count: Option<u64>,
    max_charge_cents: Option<u64>,
    #[serde(default)]
    diagnosis_codes: Vec<String>,
    #[serde(default)]
    service_lines: Vec<ClaimServiceLine>,
    #[serde(default)]
    oracle_source_manifest_id: Option<String>,
    #[serde(default)]
    oracle_facts: Vec<ClaimOracleFact>,
    #[serde(default)]
    oracle_attestation_refs: Vec<String>,
    #[serde(default)]
    fee_schedule_id: Option<String>,
    #[serde(default)]
    fee_schedule_entries: Vec<ClaimFeeScheduleEntry>,

    eligibility_active: u8,
    aid_code: u64,
    benefit_level_exists: u8,

    date_of_service_from: u64,
    eligibility_period_from: u64,
    eligibility_period_thru: u64,

    soc_amount: u64,
    soc_met: u8,

    provider_enrolled: u8,
    provider_type_valid: u8,

    billing_code_valid: u8,
    units_valid: u8,

    is_duplicate: u8,

    disability_determination_valid: u8,
    recipient_not_deceased: u8,
    physician_certification_valid: u8,
}

#[derive(Debug, Deserialize)]
struct AppConfig {
    claims_registry_address: String,
    private_key: String,
    rpc_url: String,
    transaction_value: String,
    enable_stark_sidecar_artifacts: Option<bool>,
}

impl AppConfig {
    fn stark_sidecar_enabled(&self) -> bool {
        self.enable_stark_sidecar_artifacts.unwrap_or(false)
    }
}

#[derive(Debug, Serialize)]
struct ZkCircuitInput {
    eligibility_active: u8,
    aid_code: u64,
    benefit_level_exists: u8,
    date_of_service_from: u64,
    eligibility_period_from: u64,
    eligibility_period_thru: u64,
    soc_amount: u64,
    soc_met: u8,
    provider_enrolled: u8,
    provider_type_valid: u8,
    billing_code_valid: u8,
    units_valid: u8,
    is_duplicate: u8,
    disability_determination_valid: u8,
    recipient_not_deceased: u8,
    physician_certification_valid: u8,
}

impl From<&ClaimInput> for ZkCircuitInput {
    fn from(claim: &ClaimInput) -> Self {
        Self {
            eligibility_active: claim.eligibility_active,
            aid_code: claim.aid_code,
            benefit_level_exists: claim.benefit_level_exists,
            date_of_service_from: claim.date_of_service_from,
            eligibility_period_from: claim.eligibility_period_from,
            eligibility_period_thru: claim.eligibility_period_thru,
            soc_amount: claim.soc_amount,
            soc_met: claim.soc_met,
            provider_enrolled: claim.provider_enrolled,
            provider_type_valid: claim.provider_type_valid,
            billing_code_valid: claim.billing_code_valid,
            units_valid: claim.units_valid,
            is_duplicate: claim.is_duplicate,
            disability_determination_valid: claim.disability_determination_valid,
            recipient_not_deceased: claim.recipient_not_deceased,
            physician_certification_valid: claim.physician_certification_valid,
        }
    }
}

#[derive(Debug, Serialize)]
struct StarkSidecarArtifact {
    artifact_version: &'static str,
    proof_system: &'static str,
    proof_mode: &'static str,
    runtime_status: &'static str,
    claim_id: String,
    claim_hash: String,
    decision: u8,
    failure_code: u32,
    failure_reason: Option<&'static str>,
    public_inputs: StarkSidecarPublicInputs,
    metadata: StarkSidecarMetadata,
}

#[derive(Debug, Serialize)]
struct StarkSidecarPublicInputs {
    claim_hash: String,
    decision: u8,
    failure_code: u32,
    ruleset_id: &'static str,
}

#[derive(Debug, Serialize)]
struct StarkSidecarMetadata {
    verifier_status: &'static str,
    on_chain_submission: bool,
    groth16_flow_unchanged: bool,
}

#[derive(Debug, Serialize)]
struct StarkBridgeInput {
    schema_version: &'static str,
    producer: &'static str,
    purpose: &'static str,
    runtime_mode: &'static str,
    claim: StarkBridgeClaim,
    adjudication: StarkBridgeAdjudication,
    active_rust_facts: StarkBridgeActiveRustFacts,
    winterfell_poc_mapping: StarkBridgeWinterfellPocMapping,
    public_inputs: StarkBridgePublicInputs,
    proof_status: StarkBridgeProofStatus,
}

#[derive(Debug, Serialize)]
struct StarkBridgeClaim {
    claim_id: String,
    claim_amount: u64,
    claim_hash: String,
    member_id: Option<String>,
    provider_npi: Option<String>,
    diagnosis_count: Option<u64>,
    max_charge_cents: Option<u64>,
    diagnosis_codes: Vec<String>,
    service_lines: Vec<ClaimServiceLine>,
    oracle_source_manifest_id: Option<String>,
    oracle_facts: Vec<ClaimOracleFact>,
    oracle_attestation_refs: Vec<String>,
    fee_schedule_id: Option<String>,
    fee_schedule_entries: Vec<ClaimFeeScheduleEntry>,
}

#[derive(Debug, Serialize)]
struct StarkBridgeAdjudication {
    decision: u8,
    failure_code: u32,
    failure_reason: Option<&'static str>,
    ruleset_id: &'static str,
}

#[derive(Debug, Serialize)]
struct StarkBridgeActiveRustFacts {
    eligibility_active: u8,
    aid_code: u64,
    benefit_level_exists: u8,
    date_of_service_from: u64,
    eligibility_period_from: u64,
    eligibility_period_thru: u64,
    soc_amount: u64,
    soc_met: u8,
    provider_enrolled: u8,
    provider_type_valid: u8,
    billing_code_valid: u8,
    units_valid: u8,
    is_duplicate: u8,
    disability_determination_valid: u8,
    recipient_not_deceased: u8,
    physician_certification_valid: u8,
}

#[derive(Debug, Serialize)]
struct StarkBridgeWinterfellPocMapping {
    direct: StarkBridgeDirectMapping,
    partial: StarkBridgePartialMapping,
    unmapped: StarkBridgeUnmappedMapping,
}

#[derive(Debug, Serialize)]
struct StarkBridgeDirectMapping {
    eligibility_active: u8,
    provider_enrolled: u8,
    duplicate_flag: u8,
}

#[derive(Debug, Serialize)]
struct StarkBridgePartialMapping {
    service_line_count: StarkBridgePartialEvidence,
    prior_auth_ok: StarkBridgePartialEvidence,
    charge_cents: StarkBridgePartialEvidence,
    program_integrity_hold: StarkBridgePartialEvidence,
}

#[derive(Debug, Serialize)]
struct StarkBridgePartialEvidence {
    source: Vec<&'static str>,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct StarkBridgeUnmappedMapping {
    member_id: Option<u64>,
    provider_npi: Option<u64>,
    diagnosis_count: Option<u64>,
    max_charge_cents: Option<u64>,
}

#[derive(Debug, Serialize)]
struct StarkBridgePublicInputs {
    claim_hash: String,
    decision: u8,
    failure_code: u32,
    ruleset_id: &'static str,
}

#[derive(Debug, Serialize)]
struct StarkBridgeProofStatus {
    stark_proof_generated: bool,
    winterfell_poc_compatible: bool,
    groth16_flow_unchanged: bool,
    on_chain_submission: bool,
}

impl StarkSidecarArtifact {
    fn from_claim(claim: &ClaimInput, claim_hash: &str) -> Self {
        let failure_reason = denial_reason(claim);
        let decision = bool_u8(failure_reason.is_none());
        let failure_code = failure_reason.map(stark_failure_code).unwrap_or(0);

        Self {
            artifact_version: "stark-sidecar-v0",
            proof_system: "stark",
            proof_mode: "sidecar_schema_only",
            runtime_status: "written_only_when_config_enabled",
            claim_id: claim.claim_id.clone(),
            claim_hash: claim_hash.to_string(),
            decision,
            failure_code,
            failure_reason,
            public_inputs: StarkSidecarPublicInputs {
                claim_hash: claim_hash.to_string(),
                decision,
                failure_code,
                ruleset_id: "current_g1_g10_denial_reason",
            },
            metadata: StarkSidecarMetadata {
                verifier_status: "not_selected",
                on_chain_submission: false,
                groth16_flow_unchanged: true,
            },
        }
    }
}

impl StarkBridgeInput {
    fn from_claim(claim: &ClaimInput, claim_hash: &str) -> Self {
        let failure_reason = denial_reason(claim);
        let decision = bool_u8(failure_reason.is_none());
        let failure_code = failure_reason.map(stark_failure_code).unwrap_or(0);

        Self {
            schema_version: "stark-bridge-input-v0",
            producer: "rust-engine",
            purpose: "stark_engine_compatibility_input",
            runtime_mode: "dry_run_or_optional_sidecar",
            claim: StarkBridgeClaim {
                claim_id: claim.claim_id.clone(),
                claim_amount: claim.claim_amount,
                claim_hash: claim_hash.to_string(),
                member_id: claim.member_id.clone(),
                provider_npi: claim.provider_npi.clone(),
                diagnosis_count: claim.diagnosis_count,
                max_charge_cents: claim.max_charge_cents,
                diagnosis_codes: claim.diagnosis_codes.clone(),
                service_lines: claim.service_lines.clone(),
                oracle_source_manifest_id: claim.oracle_source_manifest_id.clone(),
                oracle_facts: claim.oracle_facts.clone(),
                oracle_attestation_refs: claim.oracle_attestation_refs.clone(),
                fee_schedule_id: claim.fee_schedule_id.clone(),
                fee_schedule_entries: claim.fee_schedule_entries.clone(),
            },
            adjudication: StarkBridgeAdjudication {
                decision,
                failure_code,
                failure_reason,
                ruleset_id: "current_g1_g10_denial_reason",
            },
            active_rust_facts: StarkBridgeActiveRustFacts {
                eligibility_active: claim.eligibility_active,
                aid_code: claim.aid_code,
                benefit_level_exists: claim.benefit_level_exists,
                date_of_service_from: claim.date_of_service_from,
                eligibility_period_from: claim.eligibility_period_from,
                eligibility_period_thru: claim.eligibility_period_thru,
                soc_amount: claim.soc_amount,
                soc_met: claim.soc_met,
                provider_enrolled: claim.provider_enrolled,
                provider_type_valid: claim.provider_type_valid,
                billing_code_valid: claim.billing_code_valid,
                units_valid: claim.units_valid,
                is_duplicate: claim.is_duplicate,
                disability_determination_valid: claim.disability_determination_valid,
                recipient_not_deceased: claim.recipient_not_deceased,
                physician_certification_valid: claim.physician_certification_valid,
            },
            winterfell_poc_mapping: StarkBridgeWinterfellPocMapping {
                direct: StarkBridgeDirectMapping {
                    eligibility_active: claim.eligibility_active,
                    provider_enrolled: claim.provider_enrolled,
                    duplicate_flag: claim.is_duplicate,
                },
                partial: StarkBridgePartialMapping {
                    service_line_count: StarkBridgePartialEvidence {
                        source: vec!["billing_code_valid", "units_valid"],
                        status: "not_equivalent",
                    },
                    prior_auth_ok: StarkBridgePartialEvidence {
                        source: vec!["physician_certification_valid"],
                        status: "not_equivalent",
                    },
                    charge_cents: StarkBridgePartialEvidence {
                        source: vec!["claim_amount"],
                        status: "requires_unit_normalization",
                    },
                    program_integrity_hold: StarkBridgePartialEvidence {
                        source: vec!["disability_determination_valid", "recipient_not_deceased"],
                        status: "not_equivalent",
                    },
                },
                unmapped: StarkBridgeUnmappedMapping {
                    member_id: claim
                        .member_id
                        .as_deref()
                        .map(stable_identity_string_to_u64),
                    provider_npi: claim.provider_npi.as_deref().and_then(parse_10_digit_npi),
                    diagnosis_count: claim.diagnosis_count,
                    max_charge_cents: claim.max_charge_cents,
                },
            },
            public_inputs: StarkBridgePublicInputs {
                claim_hash: claim_hash.to_string(),
                decision,
                failure_code,
                ruleset_id: "current_g1_g10_denial_reason",
            },
            proof_status: StarkBridgeProofStatus {
                stark_proof_generated: false,
                winterfell_poc_compatible: false,
                groth16_flow_unchanged: true,
                on_chain_submission: false,
            },
        }
    }
}

fn bool_u8(value: bool) -> u8 {
    if value { 1 } else { 0 }
}

fn stable_identity_string_to_u64(value: &str) -> u64 {
    value.bytes().fold(0xcbf29ce484222325u64, |hash, byte| {
        hash ^ (byte as u64).wrapping_mul(0x100000001b3)
    })
}

fn parse_10_digit_npi(value: &str) -> Option<u64> {
    if value.len() == 10 && value.chars().all(|ch| ch.is_ascii_digit()) {
        value.parse::<u64>().ok()
    } else {
        None
    }
}

fn stark_failure_code(reason: &str) -> u32 {
    match reason {
        "G1_IDENTITY_VERIFICATION_FAILED" => 1,
        "G2_PROGRAM_ELIGIBILITY_FAILED" => 201,
        "G2_BENEFIT_LEVEL_MISSING" => 202,
        "G3_MONTH_OF_SERVICE_FAILED" => 3,
        "G4_SHARE_OF_COST_FAILED" => 4,
        "G5_PROVIDER_NOT_ENROLLED" => 501,
        "G5_PROVIDER_TYPE_INVALID" => 502,
        "G6_BILLING_CODE_INVALID" => 601,
        "G6_UNITS_INVALID" => 602,
        "G7_DUPLICATE_CLAIM" => 7,
        "G8_DISABILITY_DETERMINATION_FAILED" => 8,
        "G9_RECIPIENT_DECEASED" => 9,
        "G10_PHYSICIAN_CERTIFICATION_FAILED" => 10,
        _ => panic!("unmapped STARK sidecar failure reason: {reason}"),
    }
}

fn command_output_excerpt(output: &str) -> String {
    const MAX_LEN: usize = 500;

    match output.char_indices().nth(MAX_LEN) {
        Some((idx, _)) => format!("{}...", &output[..idx]),
        None => output.to_string(),
    }
}

fn command_failure_message(cmd: &str, status: Option<i32>, stdout: &[u8], stderr: &[u8]) -> String {
    format!(
        "command failed: {}\nexit status: {:?}\nSTDOUT:\n{}\nSTDERR:\n{}",
        cmd,
        status,
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    )
}

fn run(cmd: &str) -> Result<(), String> {
    let output = Command::new("bash")
        .arg("-lc")
        .arg(cmd)
        .output()
        .map_err(|err| format!("failed to run command '{}': {}", cmd, err))?;

    if !output.stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }

    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    if !output.status.success() {
        return Err(command_failure_message(
            cmd,
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ));
    }

    Ok(())
}

fn run_output(cmd: &str) -> Result<String, String> {
    let output = Command::new("bash")
        .arg("-lc")
        .arg(cmd)
        .output()
        .map_err(|err| format!("failed to run command '{}': {}", cmd, err))?;

    if !output.status.success() {
        return Err(command_failure_message(
            cmd,
            output.status.code(),
            &output.stdout,
            &output.stderr,
        ));
    }

    String::from_utf8(output.stdout)
        .map(|stdout| stdout.trim().to_string())
        .map_err(|err| format!("command output was not valid UTF-8 for '{}': {}", cmd, err))
}

fn claim_hash_32(claim_id: &str, claim_amount: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(claim_id.as_bytes());
    hasher.update(claim_amount.to_be_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn split_calldata(calldata: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0;
    let mut start = 0;

    for (i, ch) in calldata.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(calldata[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }

    parts.push(calldata[start..].trim().to_string());
    parts
}

fn extract_transaction_hash(cast_output: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<Value>(cast_output) {
        if let Some(tx_hash) = value.get("transactionHash").and_then(Value::as_str) {
            return Some(tx_hash.to_string());
        }
    }

    cast_output.lines().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed.starts_with("transactionHash") {
            return None;
        }

        trimmed
            .split_whitespace()
            .find(|part| part.starts_with("0x"))
            .map(|part| part.trim_matches('"').to_string())
    })
}

fn denial_reason(claim: &ClaimInput) -> Option<&'static str> {
    if claim.eligibility_active != 1 {
        return Some("G1_IDENTITY_VERIFICATION_FAILED");
    }
    if !matches!(claim.aid_code, 13 | 23 | 53 | 103 | 104) {
        return Some("G2_PROGRAM_ELIGIBILITY_FAILED");
    }
    if claim.benefit_level_exists != 1 {
        return Some("G2_BENEFIT_LEVEL_MISSING");
    }
    if claim.date_of_service_from < claim.eligibility_period_from
        || claim.date_of_service_from > claim.eligibility_period_thru
    {
        return Some("G3_MONTH_OF_SERVICE_FAILED");
    }
    if claim.soc_amount > 0 && claim.soc_met != 1 {
        return Some("G4_SHARE_OF_COST_FAILED");
    }
    if claim.provider_enrolled != 1 {
        return Some("G5_PROVIDER_NOT_ENROLLED");
    }
    if claim.provider_type_valid != 1 {
        return Some("G5_PROVIDER_TYPE_INVALID");
    }
    if claim.billing_code_valid != 1 {
        return Some("G6_BILLING_CODE_INVALID");
    }
    if claim.units_valid != 1 {
        return Some("G6_UNITS_INVALID");
    }
    if claim.is_duplicate != 0 {
        return Some("G7_DUPLICATE_CLAIM");
    }
    if claim.disability_determination_valid != 1 {
        return Some("G8_DISABILITY_DETERMINATION_FAILED");
    }
    if claim.recipient_not_deceased != 1 {
        return Some("G9_RECIPIENT_DECEASED");
    }
    if claim.physician_certification_valid != 1 {
        return Some("G10_PHYSICIAN_CERTIFICATION_FAILED");
    }

    None
}

fn write_result(result: &AdjudicationResult) -> Result<(), String> {
    let result_json = serde_json::to_string_pretty(result)
        .map_err(|err| format!("could not serialize adjudication_result.json: {}", err))?;

    fs::write("adjudication_result.json", result_json)
        .map_err(|err| format!("could not write adjudication_result.json: {}", err))
}

fn write_stark_sidecar_artifact(claim: &ClaimInput, claim_hash: &str) -> Result<(), String> {
    let artifact = StarkSidecarArtifact::from_claim(claim, claim_hash);
    let artifact_json = serde_json::to_string_pretty(&artifact).map_err(|err| {
        format!(
            "could not serialize stark_adjudication_result.json: {}",
            err
        )
    })?;

    fs::write(STARK_SIDECAR_OUTPUT_PATH, artifact_json)
        .map_err(|err| format!("could not write stark_adjudication_result.json: {}", err))
}

fn write_stark_bridge_input(claim: &ClaimInput, claim_hash: &str) -> Result<(), String> {
    let bridge_input = StarkBridgeInput::from_claim(claim, claim_hash);
    let bridge_json = serde_json::to_string_pretty(&bridge_input)
        .map_err(|err| format!("could not serialize stark_bridge_input.json: {}", err))?;

    fs::write(STARK_BRIDGE_INPUT_OUTPUT_PATH, bridge_json)
        .map_err(|err| format!("could not write stark_bridge_input.json: {}", err))
}

fn log_proof_event(stage: &str, status: &str, claim_id: &str, claim_hash: &str) {
    println!(
        "{}",
        json!({
            "event": "proof_generation",
            "stage": stage,
            "status": status,
            "claim_id": claim_id,
            "claim_hash": claim_hash,
        })
    );
}

fn read_config() -> Result<AppConfig, String> {
    let config_json = fs::read_to_string("config.json")
        .map_err(|err| format!("could not read config.json: {}", err))?;
    serde_json::from_str(&config_json).map_err(|err| format!("invalid config.json: {}", err))
}

fn read_claim_input() -> Result<ClaimInput, String> {
    let claim_json = fs::read_to_string("claim_input.json")
        .map_err(|err| format!("could not read claim_input.json: {}", err))?;

    serde_json::from_str(&claim_json).map_err(|err| format!("invalid claim_input.json: {}", err))
}

fn is_stark_sidecar_dry_run_arg(arg: Option<&str>) -> bool {
    matches!(
        arg,
        Some("stark-sidecar-dry-run") | Some("--stark-sidecar-dry-run")
    )
}

fn is_stark_bridge_input_dry_run_arg(arg: Option<&str>) -> bool {
    matches!(
        arg,
        Some("stark-bridge-input-dry-run") | Some("--stark-bridge-input-dry-run")
    )
}

fn main() {
    let arg = env::args().nth(1);
    let result = if is_stark_sidecar_dry_run_arg(arg.as_deref()) {
        run_stark_sidecar_dry_run()
    } else if is_stark_bridge_input_dry_run_arg(arg.as_deref()) {
        run_stark_bridge_input_dry_run()
    } else {
        run_app()
    };

    if let Err(err) = result {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

fn run_stark_sidecar_dry_run() -> Result<(), String> {
    let claim = read_claim_input()?;
    let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);

    write_stark_sidecar_artifact(&claim, &claim_hash)?;

    println!(
        "{}",
        json!({
            "event": "stark_sidecar_dry_run",
            "status": "completed",
            "claim_id": claim.claim_id,
            "claim_hash": claim_hash,
            "output": STARK_SIDECAR_OUTPUT_PATH,
            "groth16_executed": false,
            "chain_submission": false,
        })
    );

    Ok(())
}

fn run_stark_bridge_input_dry_run() -> Result<(), String> {
    let claim = read_claim_input()?;
    let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);

    write_stark_bridge_input(&claim, &claim_hash)?;

    println!(
        "{}",
        json!({
            "event": "stark_bridge_input_dry_run",
            "status": "completed",
            "claim_id": claim.claim_id,
            "claim_hash": claim_hash,
            "output": STARK_BRIDGE_INPUT_OUTPUT_PATH,
            "groth16_executed": false,
            "chain_submission": false,
        })
    );

    Ok(())
}

fn run_app() -> Result<(), String> {
    let config = read_config()?;
    let contract = config.claims_registry_address.as_str();
    let private_key = config.private_key.as_str();
    let rpc_url = config.rpc_url.as_str();
    let transaction_value = config.transaction_value.as_str();

    let claim = read_claim_input()?;

    let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);

    if let Some(reason) = denial_reason(&claim) {
        if config.stark_sidecar_enabled() {
            write_stark_sidecar_artifact(&claim, &claim_hash)?;
        }

        let result = AdjudicationResult::denied(claim.claim_id.clone(), claim_hash, reason);

        write_result(&result)?;

        println!("Claim denied before proof generation: {}", reason);
        println!("Wrote adjudication_result.json");
        return Ok(());
    }

    println!("Claim ID: {}", claim.claim_id);
    println!("Claim Hash: {}", claim_hash);

    let zk_input = serde_json::to_string_pretty(&ZkCircuitInput::from(&claim))
        .map_err(|err| format!("could not serialize ../zk/input.json: {}", err))?;

    fs::write("../zk/input.json", zk_input)
        .map_err(|err| format!("could not write ../zk/input.json: {}", err))?;

    log_proof_event(
        "witness_generation",
        "started",
        &claim.claim_id,
        &claim_hash,
    );
    run(
        "node ../zk/claim_js/generate_witness.js ../zk/claim_js/claim.wasm ../zk/input.json ../zk/witness.wtns",
    )?;
    log_proof_event(
        "witness_generation",
        "completed",
        &claim.claim_id,
        &claim_hash,
    );

    log_proof_event("groth16_prove", "started", &claim.claim_id, &claim_hash);
    run(
        "snarkjs groth16 prove ../zk/claim_final.zkey ../zk/witness.wtns ../zk/proof.json ../zk/public.json",
    )?;
    log_proof_event("groth16_prove", "completed", &claim.claim_id, &claim_hash);

    log_proof_event("calldata_export", "started", &claim.claim_id, &claim_hash);
    let calldata =
        run_output("cd ../zk && snarkjs zkey export soliditycalldata public.json proof.json")?
            .replace("\"", "")
            .replace(" ", "");
    log_proof_event("calldata_export", "completed", &claim.claim_id, &claim_hash);

    let parts = split_calldata(&calldata);

    if parts.len() != 4 {
        return Err(format!(
            "expected 4 calldata parts from snarkjs, got {}: {}",
            parts.len(),
            command_output_excerpt(&calldata)
        ));
    }

    let a = &parts[0];
    let b = &parts[1];
    let c = &parts[2];
    let input = &parts[3];

    println!("Proof calldata parsed dynamically.");

    log_proof_event("chain_submission", "started", &claim.claim_id, &claim_hash);
    let cast_output = run_output(&format!(
        r#"cast send {contract} \
"submitVerifiedClaim(bytes32,uint[2],uint[2][2],uint[2],uint[1],uint256)" \
{claim_hash} \
'{a}' \
'{b}' \
'{c}' \
'{input}' \
{} \
--value {transaction_value} \
--private-key {private_key} \
--rpc-url {rpc_url}"#,
        claim.claim_amount
    ))?;
    let tx_hash = extract_transaction_hash(&cast_output).ok_or_else(|| {
        format!(
            "cast send output did not include transactionHash: {}",
            command_output_excerpt(&cast_output)
        )
    })?;
    log_proof_event(
        "chain_submission",
        "completed",
        &claim.claim_id,
        &claim_hash,
    );

    println!("Dynamic proof submitted on-chain.");

    let result = AdjudicationResult::approved(claim.claim_id.clone(), claim_hash, tx_hash);

    if config.stark_sidecar_enabled() {
        write_stark_sidecar_artifact(&claim, &result.claim_hash)?;
    }

    write_result(&result)?;
    println!("Wrote adjudication_result.json");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_claim() -> ClaimInput {
        ClaimInput {
            claim_id: "CLAIM-TEST-001".to_string(),
            claim_amount: 1000,
            member_id: None,
            provider_npi: None,
            diagnosis_count: None,
            max_charge_cents: None,
            diagnosis_codes: Vec::new(),
            service_lines: Vec::new(),
            oracle_source_manifest_id: None,
            oracle_facts: Vec::new(),
            oracle_attestation_refs: Vec::new(),
            fee_schedule_id: None,
            fee_schedule_entries: Vec::new(),
            eligibility_active: 1,
            aid_code: 53,
            benefit_level_exists: 1,
            date_of_service_from: 20000,
            eligibility_period_from: 19900,
            eligibility_period_thru: 21000,
            soc_amount: 0,
            soc_met: 1,
            provider_enrolled: 1,
            provider_type_valid: 1,
            billing_code_valid: 1,
            units_valid: 1,
            is_duplicate: 0,
            disability_determination_valid: 1,
            recipient_not_deceased: 1,
            physician_certification_valid: 1,
        }
    }

    fn config_json(enable_stark_sidecar_artifacts: Option<bool>) -> String {
        let mut value = json!({
            "claims_registry_address": "0xB7f8BC63BbcaD18155201308C8f3540b07f84F5e",
            "private_key": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            "rpc_url": "http://127.0.0.1:8545",
            "transaction_value": "0.001ether",
        });

        if let Some(enabled) = enable_stark_sidecar_artifacts {
            value["enable_stark_sidecar_artifacts"] = json!(enabled);
        }

        value.to_string()
    }

    struct ShadowRule {
        reason: &'static str,
        fails: fn(&ClaimInput) -> bool,
    }

    fn shadow_rules() -> Vec<ShadowRule> {
        vec![
            ShadowRule {
                reason: "G1_IDENTITY_VERIFICATION_FAILED",
                fails: |claim| claim.eligibility_active != 1,
            },
            ShadowRule {
                reason: "G2_PROGRAM_ELIGIBILITY_FAILED",
                fails: |claim| !matches!(claim.aid_code, 13 | 23 | 53 | 103 | 104),
            },
            ShadowRule {
                reason: "G2_BENEFIT_LEVEL_MISSING",
                fails: |claim| claim.benefit_level_exists != 1,
            },
            ShadowRule {
                reason: "G3_MONTH_OF_SERVICE_FAILED",
                fails: |claim| {
                    claim.date_of_service_from < claim.eligibility_period_from
                        || claim.date_of_service_from > claim.eligibility_period_thru
                },
            },
            ShadowRule {
                reason: "G4_SHARE_OF_COST_FAILED",
                fails: |claim| claim.soc_amount > 0 && claim.soc_met != 1,
            },
            ShadowRule {
                reason: "G5_PROVIDER_NOT_ENROLLED",
                fails: |claim| claim.provider_enrolled != 1,
            },
            ShadowRule {
                reason: "G5_PROVIDER_TYPE_INVALID",
                fails: |claim| claim.provider_type_valid != 1,
            },
            ShadowRule {
                reason: "G6_BILLING_CODE_INVALID",
                fails: |claim| claim.billing_code_valid != 1,
            },
            ShadowRule {
                reason: "G6_UNITS_INVALID",
                fails: |claim| claim.units_valid != 1,
            },
            ShadowRule {
                reason: "G7_DUPLICATE_CLAIM",
                fails: |claim| claim.is_duplicate != 0,
            },
            ShadowRule {
                reason: "G8_DISABILITY_DETERMINATION_FAILED",
                fails: |claim| claim.disability_determination_valid != 1,
            },
            ShadowRule {
                reason: "G9_RECIPIENT_DECEASED",
                fails: |claim| claim.recipient_not_deceased != 1,
            },
            ShadowRule {
                reason: "G10_PHYSICIAN_CERTIFICATION_FAILED",
                fails: |claim| claim.physician_certification_valid != 1,
            },
        ]
    }

    fn shadow_denial_reason(claim: &ClaimInput) -> Option<&'static str> {
        shadow_rules()
            .into_iter()
            .find(|rule| (rule.fails)(claim))
            .map(|rule| rule.reason)
    }

    #[derive(Debug, PartialEq)]
    struct StarkCompatibleWitness {
        eligibility_active: u8,
        program_eligible: u8,
        benefit_level_exists: u8,
        month_of_service_valid: u8,
        share_of_cost_valid: u8,
        provider_enrolled: u8,
        provider_type_valid: u8,
        billing_code_valid: u8,
        units_valid: u8,
        duplicate_clear: u8,
        disability_determination_valid: u8,
        recipient_not_deceased: u8,
        physician_certification_valid: u8,
        decision: u8,
        failure_code: u32,
        failure_reason: Option<&'static str>,
    }

    #[derive(Debug, Serialize)]
    struct StarkSidecarArtifact {
        artifact_version: &'static str,
        proof_system: &'static str,
        proof_mode: &'static str,
        runtime_status: &'static str,
        claim_id: String,
        claim_hash: String,
        decision: u8,
        failure_code: u32,
        failure_reason: Option<&'static str>,
        public_inputs: StarkSidecarPublicInputs,
        metadata: StarkSidecarMetadata,
    }

    #[derive(Debug, Serialize)]
    struct StarkSidecarPublicInputs {
        claim_hash: String,
        decision: u8,
        failure_code: u32,
        ruleset_id: &'static str,
    }

    #[derive(Debug, Serialize)]
    struct StarkSidecarMetadata {
        verifier_status: &'static str,
        on_chain_submission: bool,
        groth16_flow_unchanged: bool,
    }

    #[derive(Debug, PartialEq)]
    enum ImportedStarkMappingClass {
        Direct,
        Partial,
        Unmapped,
    }

    struct ImportedStarkFieldMapping {
        imported_stark_field: &'static str,
        active_rust_source: Option<&'static str>,
        class: ImportedStarkMappingClass,
        note: &'static str,
    }

    impl StarkCompatibleWitness {
        fn from_claim(claim: &ClaimInput) -> Self {
            let failure_reason = denial_reason(claim);

            Self {
                eligibility_active: bool_u8(claim.eligibility_active == 1),
                program_eligible: bool_u8(matches!(claim.aid_code, 13 | 23 | 53 | 103 | 104)),
                benefit_level_exists: bool_u8(claim.benefit_level_exists == 1),
                month_of_service_valid: bool_u8(
                    claim.date_of_service_from >= claim.eligibility_period_from
                        && claim.date_of_service_from <= claim.eligibility_period_thru,
                ),
                share_of_cost_valid: bool_u8(claim.soc_amount == 0 || claim.soc_met == 1),
                provider_enrolled: bool_u8(claim.provider_enrolled == 1),
                provider_type_valid: bool_u8(claim.provider_type_valid == 1),
                billing_code_valid: bool_u8(claim.billing_code_valid == 1),
                units_valid: bool_u8(claim.units_valid == 1),
                duplicate_clear: bool_u8(claim.is_duplicate == 0),
                disability_determination_valid: bool_u8(claim.disability_determination_valid == 1),
                recipient_not_deceased: bool_u8(claim.recipient_not_deceased == 1),
                physician_certification_valid: bool_u8(claim.physician_certification_valid == 1),
                decision: bool_u8(failure_reason.is_none()),
                failure_code: failure_reason.map(stark_failure_code).unwrap_or(0),
                failure_reason,
            }
        }
    }

    impl StarkSidecarArtifact {
        fn from_claim(claim: &ClaimInput) -> Self {
            let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);
            let witness = StarkCompatibleWitness::from_claim(claim);

            Self {
                artifact_version: "stark-sidecar-v0-test-only",
                proof_system: "stark",
                proof_mode: "sidecar_schema_only",
                runtime_status: "not_written_by_runtime",
                claim_id: claim.claim_id.clone(),
                claim_hash: claim_hash.clone(),
                decision: witness.decision,
                failure_code: witness.failure_code,
                failure_reason: witness.failure_reason,
                public_inputs: StarkSidecarPublicInputs {
                    claim_hash,
                    decision: witness.decision,
                    failure_code: witness.failure_code,
                    ruleset_id: "current_g1_g10_shadow_rules",
                },
                metadata: StarkSidecarMetadata {
                    verifier_status: "not_selected",
                    on_chain_submission: false,
                    groth16_flow_unchanged: true,
                },
            }
        }
    }

    fn imported_winterfell_stark_field_mappings() -> Vec<ImportedStarkFieldMapping> {
        vec![
            ImportedStarkFieldMapping {
                imported_stark_field: "member_id",
                active_rust_source: Some("member_id"),
                class: ImportedStarkMappingClass::Partial,
                note: "optional string source requires deterministic numeric normalization",
            },
            ImportedStarkFieldMapping {
                imported_stark_field: "provider_npi",
                active_rust_source: Some("provider_npi"),
                class: ImportedStarkMappingClass::Partial,
                note: "optional 10-digit source requires validation and numeric parsing",
            },
            ImportedStarkFieldMapping {
                imported_stark_field: "eligibility_active",
                active_rust_source: Some("eligibility_active"),
                class: ImportedStarkMappingClass::Direct,
                note: "both models treat 1 as active/pass",
            },
            ImportedStarkFieldMapping {
                imported_stark_field: "provider_enrolled",
                active_rust_source: Some("provider_enrolled"),
                class: ImportedStarkMappingClass::Direct,
                note: "both models treat 1 as enrolled/pass",
            },
            ImportedStarkFieldMapping {
                imported_stark_field: "service_line_count",
                active_rust_source: Some("billing_code_valid, units_valid"),
                class: ImportedStarkMappingClass::Partial,
                note: "active booleans imply service-line validity, not a count",
            },
            ImportedStarkFieldMapping {
                imported_stark_field: "diagnosis_count",
                active_rust_source: Some("diagnosis_count"),
                class: ImportedStarkMappingClass::Partial,
                note: "optional source maps numerically but is not an active adjudication rule",
            },
            ImportedStarkFieldMapping {
                imported_stark_field: "prior_auth_ok",
                active_rust_source: Some("physician_certification_valid"),
                class: ImportedStarkMappingClass::Partial,
                note: "certification may support authorization but is not equivalent",
            },
            ImportedStarkFieldMapping {
                imported_stark_field: "charge_cents",
                active_rust_source: Some("claim_amount"),
                class: ImportedStarkMappingClass::Partial,
                note: "amount can map only after units/currency normalization",
            },
            ImportedStarkFieldMapping {
                imported_stark_field: "max_charge_cents",
                active_rust_source: Some("max_charge_cents"),
                class: ImportedStarkMappingClass::Partial,
                note: "optional source maps numerically but is not an active fee-schedule rule",
            },
            ImportedStarkFieldMapping {
                imported_stark_field: "duplicate_flag",
                active_rust_source: Some("is_duplicate"),
                class: ImportedStarkMappingClass::Direct,
                note: "same duplicate fact, with pass condition inverted in the gate",
            },
            ImportedStarkFieldMapping {
                imported_stark_field: "program_integrity_hold",
                active_rust_source: Some("disability_determination_valid, recipient_not_deceased"),
                class: ImportedStarkMappingClass::Partial,
                note: "active checks can contribute to integrity status but do not equal a hold flag",
            },
        ]
    }

    fn bool_u8(value: bool) -> u8 {
        if value { 1 } else { 0 }
    }

    fn stark_failure_code(reason: &str) -> u32 {
        match reason {
            "G1_IDENTITY_VERIFICATION_FAILED" => 1,
            "G2_PROGRAM_ELIGIBILITY_FAILED" => 201,
            "G2_BENEFIT_LEVEL_MISSING" => 202,
            "G3_MONTH_OF_SERVICE_FAILED" => 3,
            "G4_SHARE_OF_COST_FAILED" => 4,
            "G5_PROVIDER_NOT_ENROLLED" => 501,
            "G5_PROVIDER_TYPE_INVALID" => 502,
            "G6_BILLING_CODE_INVALID" => 601,
            "G6_UNITS_INVALID" => 602,
            "G7_DUPLICATE_CLAIM" => 7,
            "G8_DISABILITY_DETERMINATION_FAILED" => 8,
            "G9_RECIPIENT_DECEASED" => 9,
            "G10_PHYSICIAN_CERTIFICATION_FAILED" => 10,
            _ => panic!("unmapped STARK compatibility failure reason: {reason}"),
        }
    }

    fn current_gate_cases() -> Vec<(&'static str, ClaimInput)> {
        let mut cases: Vec<(&str, ClaimInput)> = vec![("valid", valid_claim())];

        let mut claim = valid_claim();
        claim.eligibility_active = 0;
        cases.push(("G1_IDENTITY_VERIFICATION_FAILED", claim));

        let mut claim = valid_claim();
        claim.aid_code = 999;
        cases.push(("G2_PROGRAM_ELIGIBILITY_FAILED", claim));

        let mut claim = valid_claim();
        claim.benefit_level_exists = 0;
        cases.push(("G2_BENEFIT_LEVEL_MISSING", claim));

        let mut claim = valid_claim();
        claim.date_of_service_from = claim.eligibility_period_thru + 1;
        cases.push(("G3_MONTH_OF_SERVICE_FAILED", claim));

        let mut claim = valid_claim();
        claim.soc_amount = 100;
        claim.soc_met = 0;
        cases.push(("G4_SHARE_OF_COST_FAILED", claim));

        let mut claim = valid_claim();
        claim.provider_enrolled = 0;
        cases.push(("G5_PROVIDER_NOT_ENROLLED", claim));

        let mut claim = valid_claim();
        claim.provider_type_valid = 0;
        cases.push(("G5_PROVIDER_TYPE_INVALID", claim));

        let mut claim = valid_claim();
        claim.billing_code_valid = 0;
        cases.push(("G6_BILLING_CODE_INVALID", claim));

        let mut claim = valid_claim();
        claim.units_valid = 0;
        cases.push(("G6_UNITS_INVALID", claim));

        let mut claim = valid_claim();
        claim.is_duplicate = 1;
        cases.push(("G7_DUPLICATE_CLAIM", claim));

        let mut claim = valid_claim();
        claim.disability_determination_valid = 0;
        cases.push(("G8_DISABILITY_DETERMINATION_FAILED", claim));

        let mut claim = valid_claim();
        claim.recipient_not_deceased = 0;
        cases.push(("G9_RECIPIENT_DECEASED", claim));

        let mut claim = valid_claim();
        claim.physician_certification_valid = 0;
        cases.push(("G10_PHYSICIAN_CERTIFICATION_FAILED", claim));

        cases
    }

    #[test]
    fn claim_hash_32_returns_stable_prefixed_32_byte_hex() {
        let hash = claim_hash_32("CLAIM-TEST-001", 1000);

        assert_eq!(hash, claim_hash_32("CLAIM-TEST-001", 1000));
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.len(), 66);
        assert!(hash[2..].chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn config_missing_stark_sidecar_flag_defaults_disabled() {
        let config: AppConfig = serde_json::from_str(&config_json(None)).unwrap();

        assert!(!config.stark_sidecar_enabled());
    }

    #[test]
    fn config_stark_sidecar_flag_can_enable_artifacts() {
        let config: AppConfig = serde_json::from_str(&config_json(Some(true))).unwrap();

        assert!(config.stark_sidecar_enabled());
    }

    #[test]
    fn stark_sidecar_dry_run_arg_is_explicit() {
        assert!(is_stark_sidecar_dry_run_arg(Some("stark-sidecar-dry-run")));
        assert!(is_stark_sidecar_dry_run_arg(Some(
            "--stark-sidecar-dry-run"
        )));
        assert!(!is_stark_sidecar_dry_run_arg(None));
        assert!(!is_stark_sidecar_dry_run_arg(Some("run")));
        assert!(!is_stark_sidecar_dry_run_arg(Some("--help")));
    }

    #[test]
    fn stark_bridge_input_dry_run_arg_is_explicit() {
        assert!(is_stark_bridge_input_dry_run_arg(Some(
            "stark-bridge-input-dry-run"
        )));
        assert!(is_stark_bridge_input_dry_run_arg(Some(
            "--stark-bridge-input-dry-run"
        )));
        assert!(!is_stark_bridge_input_dry_run_arg(None));
        assert!(!is_stark_bridge_input_dry_run_arg(Some(
            "stark-sidecar-dry-run"
        )));
        assert!(!is_stark_bridge_input_dry_run_arg(Some("--help")));
    }

    #[test]
    fn split_calldata_preserves_nested_arrays() {
        let calldata = "[1,2],[[3,4],[5,6]],[7,8],[9]";

        assert_eq!(
            split_calldata(calldata),
            vec![
                "[1,2]".to_string(),
                "[[3,4],[5,6]]".to_string(),
                "[7,8]".to_string(),
                "[9]".to_string(),
            ]
        );
    }

    #[test]
    fn zk_circuit_input_serializes_existing_schema() {
        let value = serde_json::to_value(ZkCircuitInput::from(&valid_claim())).unwrap();

        assert_eq!(value["eligibility_active"], 1);
        assert_eq!(value["aid_code"], 53);
        assert_eq!(value["benefit_level_exists"], 1);
        assert_eq!(value["date_of_service_from"], 20000);
        assert_eq!(value["eligibility_period_from"], 19900);
        assert_eq!(value["eligibility_period_thru"], 21000);
        assert_eq!(value["soc_amount"], 0);
        assert_eq!(value["soc_met"], 1);
        assert_eq!(value["provider_enrolled"], 1);
        assert_eq!(value["provider_type_valid"], 1);
        assert_eq!(value["billing_code_valid"], 1);
        assert_eq!(value["units_valid"], 1);
        assert_eq!(value["is_duplicate"], 0);
        assert_eq!(value["disability_determination_valid"], 1);
        assert_eq!(value["recipient_not_deceased"], 1);
        assert_eq!(value["physician_certification_valid"], 1);

        assert_eq!(value.as_object().unwrap().len(), 16);
    }

    #[test]
    fn approved_result_serializes_existing_schema() {
        let result = AdjudicationResult::approved(
            "CLAIM-TEST-001".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        );

        let value = serde_json::to_value(result).unwrap();

        assert_eq!(value["claim_id"], "CLAIM-TEST-001");
        assert_eq!(value["status"], "APPROVED");
        assert_eq!(value["reason"], Value::Null);
        assert_eq!(value["tx_submitted"], true);
        assert_eq!(
            value["tx_hash"],
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn denied_result_serializes_existing_schema() {
        let result = AdjudicationResult::denied(
            "CLAIM-TEST-002".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "G9_RECIPIENT_DECEASED",
        );

        let value = serde_json::to_value(result).unwrap();

        assert_eq!(value["claim_id"], "CLAIM-TEST-002");
        assert_eq!(value["status"], "DENIED");
        assert_eq!(value["reason"], "G9_RECIPIENT_DECEASED");
        assert_eq!(value["tx_submitted"], false);
        assert_eq!(value["tx_hash"], Value::Null);
    }

    #[test]
    fn extract_transaction_hash_from_plain_cast_output() {
        let output = "\
blockHash               0x1111111111111111111111111111111111111111111111111111111111111111
blockNumber             123
transactionHash         0x2222222222222222222222222222222222222222222222222222222222222222
status                  1";

        assert_eq!(
            extract_transaction_hash(output),
            Some("0x2222222222222222222222222222222222222222222222222222222222222222".to_string())
        );
    }

    #[test]
    fn extract_transaction_hash_from_json_cast_output() {
        let output = r#"{
            "blockHash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "transactionHash": "0x3333333333333333333333333333333333333333333333333333333333333333",
            "status": "0x1"
        }"#;

        assert_eq!(
            extract_transaction_hash(output),
            Some("0x3333333333333333333333333333333333333333333333333333333333333333".to_string())
        );
    }

    #[test]
    fn extract_transaction_hash_returns_none_when_missing() {
        let output = "\
blockHash               0x1111111111111111111111111111111111111111111111111111111111111111
blockNumber             123
status                  1";

        assert_eq!(extract_transaction_hash(output), None);
    }

    #[test]
    fn denial_reason_returns_none_for_valid_claim() {
        let claim = valid_claim();

        assert_eq!(denial_reason(&claim), None);
    }

    #[test]
    fn shadow_rules_match_denial_reason_for_current_gates() {
        for (case_name, claim) in current_gate_cases() {
            assert_eq!(
                shadow_denial_reason(&claim),
                denial_reason(&claim),
                "shadow rule mismatch for {case_name}"
            );
        }
    }

    #[test]
    fn stark_compatible_witness_approves_valid_claim() {
        let witness = StarkCompatibleWitness::from_claim(&valid_claim());

        assert_eq!(witness.decision, 1);
        assert_eq!(witness.failure_code, 0);
        assert_eq!(witness.failure_reason, None);
        assert_eq!(witness.eligibility_active, 1);
        assert_eq!(witness.program_eligible, 1);
        assert_eq!(witness.benefit_level_exists, 1);
        assert_eq!(witness.month_of_service_valid, 1);
        assert_eq!(witness.share_of_cost_valid, 1);
        assert_eq!(witness.provider_enrolled, 1);
        assert_eq!(witness.provider_type_valid, 1);
        assert_eq!(witness.billing_code_valid, 1);
        assert_eq!(witness.units_valid, 1);
        assert_eq!(witness.duplicate_clear, 1);
        assert_eq!(witness.disability_determination_valid, 1);
        assert_eq!(witness.recipient_not_deceased, 1);
        assert_eq!(witness.physician_certification_valid, 1);
    }

    #[test]
    fn stark_compatible_witness_matches_denial_reason_for_current_gates() {
        for (case_name, claim) in current_gate_cases() {
            let witness = StarkCompatibleWitness::from_claim(&claim);
            let denial = denial_reason(&claim);

            assert_eq!(
                witness.failure_reason, denial,
                "STARK witness reason mismatch for {case_name}"
            );

            if let Some(reason) = denial {
                assert_eq!(
                    witness.decision, 0,
                    "STARK witness decision mismatch for {case_name}"
                );
                assert_eq!(
                    witness.failure_code,
                    stark_failure_code(reason),
                    "STARK witness code mismatch for {case_name}"
                );
            } else {
                assert_eq!(
                    witness.decision, 1,
                    "STARK witness decision mismatch for {case_name}"
                );
                assert_eq!(
                    witness.failure_code, 0,
                    "STARK witness code mismatch for {case_name}"
                );
            }
        }
    }

    #[test]
    fn stark_sidecar_artifact_serializes_approved_claim_schema() {
        let claim = valid_claim();
        let value = serde_json::to_value(StarkSidecarArtifact::from_claim(&claim)).unwrap();
        let expected_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);

        assert_eq!(value["artifact_version"], "stark-sidecar-v0-test-only");
        assert_eq!(value["proof_system"], "stark");
        assert_eq!(value["proof_mode"], "sidecar_schema_only");
        assert_eq!(value["runtime_status"], "not_written_by_runtime");
        assert_eq!(value["claim_id"], "CLAIM-TEST-001");
        assert_eq!(value["claim_hash"], expected_hash);
        assert_eq!(value["decision"], 1);
        assert_eq!(value["failure_code"], 0);
        assert_eq!(value["failure_reason"], Value::Null);
        assert_eq!(value["public_inputs"]["claim_hash"], expected_hash);
        assert_eq!(value["public_inputs"]["decision"], 1);
        assert_eq!(value["public_inputs"]["failure_code"], 0);
        assert_eq!(
            value["public_inputs"]["ruleset_id"],
            "current_g1_g10_shadow_rules"
        );
        assert_eq!(value["metadata"]["verifier_status"], "not_selected");
        assert_eq!(value["metadata"]["on_chain_submission"], false);
        assert_eq!(value["metadata"]["groth16_flow_unchanged"], true);
    }

    #[test]
    fn stark_sidecar_artifact_serializes_denied_claim_schema() {
        let mut claim = valid_claim();
        claim.recipient_not_deceased = 0;

        let value = serde_json::to_value(StarkSidecarArtifact::from_claim(&claim)).unwrap();
        let expected_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);

        assert_eq!(value["artifact_version"], "stark-sidecar-v0-test-only");
        assert_eq!(value["proof_system"], "stark");
        assert_eq!(value["runtime_status"], "not_written_by_runtime");
        assert_eq!(value["claim_hash"], expected_hash);
        assert_eq!(value["decision"], 0);
        assert_eq!(value["failure_code"], 9);
        assert_eq!(value["failure_reason"], "G9_RECIPIENT_DECEASED");
        assert_eq!(value["public_inputs"]["claim_hash"], expected_hash);
        assert_eq!(value["public_inputs"]["decision"], 0);
        assert_eq!(value["public_inputs"]["failure_code"], 9);
        assert_eq!(
            value["public_inputs"]["ruleset_id"],
            "current_g1_g10_shadow_rules"
        );
        assert_eq!(value["metadata"]["verifier_status"], "not_selected");
        assert_eq!(value["metadata"]["on_chain_submission"], false);
        assert_eq!(value["metadata"]["groth16_flow_unchanged"], true);
    }

    #[test]
    fn runtime_stark_sidecar_artifact_serializes_enabled_schema() {
        let mut claim = valid_claim();
        claim.is_duplicate = 1;
        let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);

        let value =
            serde_json::to_value(super::StarkSidecarArtifact::from_claim(&claim, &claim_hash))
                .unwrap();

        assert_eq!(value["artifact_version"], "stark-sidecar-v0");
        assert_eq!(value["proof_system"], "stark");
        assert_eq!(value["proof_mode"], "sidecar_schema_only");
        assert_eq!(value["runtime_status"], "written_only_when_config_enabled");
        assert_eq!(value["claim_id"], "CLAIM-TEST-001");
        assert_eq!(value["claim_hash"], claim_hash);
        assert_eq!(value["decision"], 0);
        assert_eq!(value["failure_code"], 7);
        assert_eq!(value["failure_reason"], "G7_DUPLICATE_CLAIM");
        assert_eq!(value["public_inputs"]["claim_hash"], claim_hash);
        assert_eq!(value["public_inputs"]["decision"], 0);
        assert_eq!(value["public_inputs"]["failure_code"], 7);
        assert_eq!(
            value["public_inputs"]["ruleset_id"],
            "current_g1_g10_denial_reason"
        );
        assert_eq!(value["metadata"]["verifier_status"], "not_selected");
        assert_eq!(value["metadata"]["on_chain_submission"], false);
        assert_eq!(value["metadata"]["groth16_flow_unchanged"], true);
    }

    #[test]
    fn stark_bridge_input_serializes_approved_claim_schema() {
        let claim = valid_claim();
        let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);
        let value =
            serde_json::to_value(super::StarkBridgeInput::from_claim(&claim, &claim_hash)).unwrap();

        assert_eq!(value["schema_version"], "stark-bridge-input-v0");
        assert_eq!(value["producer"], "rust-engine");
        assert_eq!(value["purpose"], "stark_engine_compatibility_input");
        assert_eq!(value["runtime_mode"], "dry_run_or_optional_sidecar");
        assert_eq!(value["claim"]["claim_id"], "CLAIM-TEST-001");
        assert_eq!(value["claim"]["claim_amount"], 1000);
        assert_eq!(value["claim"]["claim_hash"], claim_hash);
        assert_eq!(value["claim"]["member_id"], Value::Null);
        assert_eq!(value["claim"]["provider_npi"], Value::Null);
        assert_eq!(value["claim"]["diagnosis_count"], Value::Null);
        assert_eq!(value["claim"]["max_charge_cents"], Value::Null);
        assert_eq!(value["claim"]["diagnosis_codes"], json!([]));
        assert_eq!(value["claim"]["service_lines"], json!([]));
        assert_eq!(value["adjudication"]["decision"], 1);
        assert_eq!(value["adjudication"]["failure_code"], 0);
        assert_eq!(value["adjudication"]["failure_reason"], Value::Null);
        assert_eq!(
            value["adjudication"]["ruleset_id"],
            "current_g1_g10_denial_reason"
        );
        assert_eq!(value["active_rust_facts"]["eligibility_active"], 1);
        assert_eq!(value["active_rust_facts"]["aid_code"], 53);
        assert_eq!(value["active_rust_facts"]["provider_enrolled"], 1);
        assert_eq!(value["active_rust_facts"]["is_duplicate"], 0);
        assert_eq!(
            value["winterfell_poc_mapping"]["direct"]["eligibility_active"],
            value["active_rust_facts"]["eligibility_active"]
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["direct"]["provider_enrolled"],
            value["active_rust_facts"]["provider_enrolled"]
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["direct"]["duplicate_flag"],
            value["active_rust_facts"]["is_duplicate"]
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["partial"]["charge_cents"]["source"],
            json!(["claim_amount"])
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["partial"]["charge_cents"]["status"],
            "requires_unit_normalization"
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["unmapped"]["member_id"],
            Value::Null
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["unmapped"]["provider_npi"],
            Value::Null
        );
        assert_eq!(value["public_inputs"]["claim_hash"], claim_hash);
        assert_eq!(value["public_inputs"]["decision"], 1);
        assert_eq!(value["public_inputs"]["failure_code"], 0);
        assert_eq!(value["proof_status"]["stark_proof_generated"], false);
        assert_eq!(value["proof_status"]["winterfell_poc_compatible"], false);
        assert_eq!(value["proof_status"]["groth16_flow_unchanged"], true);
        assert_eq!(value["proof_status"]["on_chain_submission"], false);
    }

    #[test]
    fn stark_bridge_input_serializes_optional_identity_source_fields() {
        let mut claim = valid_claim();
        claim.member_id = Some("MEMBER-FIXTURE-001".to_string());
        claim.provider_npi = Some("1234567893".to_string());
        claim.diagnosis_count = Some(1);
        claim.max_charge_cents = Some(150_000);
        claim.diagnosis_codes = vec!["Z00.00".to_string()];
        claim.service_lines = vec![ClaimServiceLine {
            procedure_code: "99213".to_string(),
            charge_cents: 100_000,
            units: 1,
        }];
        claim.oracle_source_manifest_id = Some("DEMO-OFFICIAL-SOURCES-V1".to_string());
        claim.oracle_facts = vec![ClaimOracleFact {
            fact_type: "eligibility".to_string(),
            fact_key: "eligibility_active".to_string(),
            fact_value: "1".to_string(),
            source_url: Some("https://example.gov/demo/oracle-facts".to_string()),
            source_label: Some("Demo source - not production".to_string()),
            verification_status: "verified".to_string(),
        }];
        claim.oracle_attestation_refs = vec!["demo-attestation:eligibility_active".to_string()];
        claim.fee_schedule_id = Some("DEMO-FEE-SCHEDULE-V1".to_string());
        claim.fee_schedule_entries = vec![ClaimFeeScheduleEntry {
            fee_code: "99213".to_string(),
            unit_amount_cents: 100_000,
            currency: "USD".to_string(),
            effective_from: 20240101,
            effective_thru: Some(20251231),
            source_url: Some("https://example.gov/demo/fee-schedule".to_string()),
            verification_status: "verified".to_string(),
        }];
        let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);
        let value =
            serde_json::to_value(super::StarkBridgeInput::from_claim(&claim, &claim_hash)).unwrap();

        assert_eq!(value["claim"]["member_id"], "MEMBER-FIXTURE-001");
        assert_eq!(value["claim"]["provider_npi"], "1234567893");
        assert_eq!(value["claim"]["diagnosis_count"], 1);
        assert_eq!(value["claim"]["max_charge_cents"], 150_000);
        assert_eq!(value["claim"]["diagnosis_codes"], json!(["Z00.00"]));
        assert_eq!(
            value["claim"]["service_lines"],
            json!([{
                "procedure_code": "99213",
                "charge_cents": 100_000,
                "units": 1
            }])
        );
        assert_eq!(
            value["claim"]["oracle_source_manifest_id"],
            "DEMO-OFFICIAL-SOURCES-V1"
        );
        assert_eq!(
            value["claim"]["oracle_facts"],
            json!([{
                "fact_type": "eligibility",
                "fact_key": "eligibility_active",
                "fact_value": "1",
                "source_url": "https://example.gov/demo/oracle-facts",
                "source_label": "Demo source - not production",
                "verification_status": "verified"
            }])
        );
        assert_eq!(
            value["claim"]["oracle_attestation_refs"],
            json!(["demo-attestation:eligibility_active"])
        );
        assert_eq!(value["claim"]["fee_schedule_id"], "DEMO-FEE-SCHEDULE-V1");
        assert_eq!(
            value["claim"]["fee_schedule_entries"],
            json!([{
                "fee_code": "99213",
                "unit_amount_cents": 100000,
                "currency": "USD",
                "effective_from": 20240101,
                "effective_thru": 20251231,
                "source_url": "https://example.gov/demo/fee-schedule",
                "verification_status": "verified"
            }])
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["unmapped"]["member_id"],
            stable_identity_string_to_u64("MEMBER-FIXTURE-001")
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["unmapped"]["provider_npi"],
            1_234_567_893
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["unmapped"]["diagnosis_count"],
            1
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["unmapped"]["max_charge_cents"],
            150_000
        );
        assert_eq!(value["proof_status"]["stark_proof_generated"], false);
        assert_eq!(value["proof_status"]["on_chain_submission"], false);
    }

    #[test]
    fn stark_bridge_input_keeps_invalid_optional_npi_out_of_numeric_poc_mapping() {
        let mut claim = valid_claim();
        claim.provider_npi = Some("not-a-npi".to_string());
        let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);
        let value =
            serde_json::to_value(super::StarkBridgeInput::from_claim(&claim, &claim_hash)).unwrap();

        assert_eq!(value["claim"]["provider_npi"], "not-a-npi");
        assert_eq!(
            value["winterfell_poc_mapping"]["unmapped"]["provider_npi"],
            Value::Null
        );
    }

    #[test]
    fn stark_bridge_input_serializes_denied_claim_schema() {
        let mut claim = valid_claim();
        claim.recipient_not_deceased = 0;
        let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);
        let value =
            serde_json::to_value(super::StarkBridgeInput::from_claim(&claim, &claim_hash)).unwrap();

        assert_eq!(value["schema_version"], "stark-bridge-input-v0");
        assert_eq!(value["claim"]["claim_hash"], claim_hash);
        assert_eq!(value["adjudication"]["decision"], 0);
        assert_eq!(value["adjudication"]["failure_code"], 9);
        assert_eq!(
            value["adjudication"]["failure_reason"],
            "G9_RECIPIENT_DECEASED"
        );
        assert_eq!(value["active_rust_facts"]["recipient_not_deceased"], 0);
        assert_eq!(value["public_inputs"]["decision"], 0);
        assert_eq!(value["public_inputs"]["failure_code"], 9);
        assert_eq!(
            value["winterfell_poc_mapping"]["partial"]["program_integrity_hold"]["source"],
            json!(["disability_determination_valid", "recipient_not_deceased"])
        );
        assert_eq!(
            value["winterfell_poc_mapping"]["partial"]["program_integrity_hold"]["status"],
            "not_equivalent"
        );
        assert_eq!(value["proof_status"]["stark_proof_generated"], false);
        assert_eq!(value["proof_status"]["on_chain_submission"], false);
    }

    #[test]
    fn imported_winterfell_stark_mapping_classifies_all_input_fields() {
        let mappings = imported_winterfell_stark_field_mappings();

        assert_eq!(mappings.len(), 11);
        assert_eq!(
            mappings
                .iter()
                .filter(|mapping| mapping.class == ImportedStarkMappingClass::Direct)
                .count(),
            3
        );
        assert_eq!(
            mappings
                .iter()
                .filter(|mapping| mapping.class == ImportedStarkMappingClass::Partial)
                .count(),
            8
        );
        assert_eq!(
            mappings
                .iter()
                .filter(|mapping| mapping.class == ImportedStarkMappingClass::Unmapped)
                .count(),
            0
        );

        for expected_field in [
            "member_id",
            "provider_npi",
            "eligibility_active",
            "provider_enrolled",
            "service_line_count",
            "diagnosis_count",
            "prior_auth_ok",
            "charge_cents",
            "max_charge_cents",
            "duplicate_flag",
            "program_integrity_hold",
        ] {
            assert!(
                mappings
                    .iter()
                    .any(|mapping| mapping.imported_stark_field == expected_field),
                "missing imported STARK field mapping for {expected_field}"
            );
        }

        let eligibility_mapping = mappings
            .iter()
            .find(|mapping| mapping.imported_stark_field == "eligibility_active")
            .unwrap();
        assert_eq!(
            eligibility_mapping.active_rust_source,
            Some("eligibility_active")
        );
        assert_eq!(
            eligibility_mapping.note,
            "both models treat 1 as active/pass"
        );
    }

    #[test]
    fn imported_winterfell_direct_mappings_match_sidecar_failures() {
        let direct_fields: Vec<&str> = imported_winterfell_stark_field_mappings()
            .into_iter()
            .filter(|mapping| mapping.class == ImportedStarkMappingClass::Direct)
            .map(|mapping| mapping.imported_stark_field)
            .collect();

        assert_eq!(
            direct_fields,
            vec!["eligibility_active", "provider_enrolled", "duplicate_flag"]
        );

        let mut claim = valid_claim();
        claim.eligibility_active = 0;
        let value = serde_json::to_value(super::StarkSidecarArtifact::from_claim(
            &claim,
            &claim_hash_32(&claim.claim_id, claim.claim_amount),
        ))
        .unwrap();
        assert_eq!(value["failure_reason"], "G1_IDENTITY_VERIFICATION_FAILED");
        assert_eq!(value["failure_code"], 1);

        let mut claim = valid_claim();
        claim.provider_enrolled = 0;
        let value = serde_json::to_value(super::StarkSidecarArtifact::from_claim(
            &claim,
            &claim_hash_32(&claim.claim_id, claim.claim_amount),
        ))
        .unwrap();
        assert_eq!(value["failure_reason"], "G5_PROVIDER_NOT_ENROLLED");
        assert_eq!(value["failure_code"], 501);

        let mut claim = valid_claim();
        claim.is_duplicate = 1;
        let value = serde_json::to_value(super::StarkSidecarArtifact::from_claim(
            &claim,
            &claim_hash_32(&claim.claim_id, claim.claim_amount),
        ))
        .unwrap();
        assert_eq!(value["failure_reason"], "G7_DUPLICATE_CLAIM");
        assert_eq!(value["failure_code"], 7);
    }

    #[test]
    fn denial_reason_returns_identity_verification_failed() {
        let mut claim = valid_claim();
        claim.eligibility_active = 0;

        assert_eq!(
            denial_reason(&claim),
            Some("G1_IDENTITY_VERIFICATION_FAILED")
        );
    }

    #[test]
    fn denial_reason_returns_program_eligibility_failed() {
        let mut claim = valid_claim();
        claim.aid_code = 999;

        assert_eq!(denial_reason(&claim), Some("G2_PROGRAM_ELIGIBILITY_FAILED"));
    }

    #[test]
    fn denial_reason_returns_benefit_level_missing() {
        let mut claim = valid_claim();
        claim.benefit_level_exists = 0;

        assert_eq!(denial_reason(&claim), Some("G2_BENEFIT_LEVEL_MISSING"));
    }

    #[test]
    fn denial_reason_returns_month_of_service_failed() {
        let mut claim = valid_claim();
        claim.date_of_service_from = claim.eligibility_period_thru + 1;

        assert_eq!(denial_reason(&claim), Some("G3_MONTH_OF_SERVICE_FAILED"));
    }

    #[test]
    fn denial_reason_returns_share_of_cost_failed() {
        let mut claim = valid_claim();
        claim.soc_amount = 100;
        claim.soc_met = 0;

        assert_eq!(denial_reason(&claim), Some("G4_SHARE_OF_COST_FAILED"));
    }

    #[test]
    fn denial_reason_returns_provider_not_enrolled() {
        let mut claim = valid_claim();
        claim.provider_enrolled = 0;

        assert_eq!(denial_reason(&claim), Some("G5_PROVIDER_NOT_ENROLLED"));
    }

    #[test]
    fn denial_reason_returns_provider_type_invalid() {
        let mut claim = valid_claim();
        claim.provider_type_valid = 0;

        assert_eq!(denial_reason(&claim), Some("G5_PROVIDER_TYPE_INVALID"));
    }

    #[test]
    fn denial_reason_returns_billing_code_invalid() {
        let mut claim = valid_claim();
        claim.billing_code_valid = 0;

        assert_eq!(denial_reason(&claim), Some("G6_BILLING_CODE_INVALID"));
    }

    #[test]
    fn denial_reason_returns_units_invalid() {
        let mut claim = valid_claim();
        claim.units_valid = 0;

        assert_eq!(denial_reason(&claim), Some("G6_UNITS_INVALID"));
    }

    #[test]
    fn denial_reason_returns_duplicate_claim() {
        let mut claim = valid_claim();
        claim.is_duplicate = 1;

        assert_eq!(denial_reason(&claim), Some("G7_DUPLICATE_CLAIM"));
    }

    #[test]
    fn denial_reason_returns_disability_determination_failed() {
        let mut claim = valid_claim();
        claim.disability_determination_valid = 0;

        assert_eq!(
            denial_reason(&claim),
            Some("G8_DISABILITY_DETERMINATION_FAILED")
        );
    }

    #[test]
    fn denial_reason_returns_recipient_deceased() {
        let mut claim = valid_claim();
        claim.recipient_not_deceased = 0;

        assert_eq!(denial_reason(&claim), Some("G9_RECIPIENT_DECEASED"));
    }

    #[test]
    fn denial_reason_returns_physician_certification_failed() {
        let mut claim = valid_claim();
        claim.physician_certification_valid = 0;

        assert_eq!(
            denial_reason(&claim),
            Some("G10_PHYSICIAN_CERTIFICATION_FAILED")
        );
    }

    #[test]
    #[ignore = "requires local Anvil, snarkjs, node, cast, config.json, and a fresh approved claim_id"]
    fn approved_claim_flow_end_to_end() {
        run_app().unwrap();
    }
}
