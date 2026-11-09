use crate::AppConfig;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::process::Command;
use std::{env, fs};

const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
const RELEASE_SCHEMA: &str = "localbce-stark-v2-release-profile-v1";
const DEPLOYMENT_PIN_SCHEMA: &str = "localbce-stark-v2-deployment-pin-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StarkRuntimeMode {
    LocalTest,
    PilotCanary,
    Production,
}

#[derive(Debug)]
pub(crate) struct StarkRuntimeActivation {
    pub(crate) mode: StarkRuntimeMode,
    pub(crate) chain_id: u64,
    pub(crate) verifier: String,
    pub(crate) registry: String,
    pub(crate) rpc_url: String,
    pub(crate) submitter_private_key: String,
    pub(crate) attestor_mode: String,
    pub(crate) signer_program: Option<String>,
    pub(crate) signer_args: Vec<String>,
    pub(crate) allowed_key_ids: Vec<String>,
    pub(crate) attestor_address: Option<String>,
    pub(crate) policy_manifest_hash: Option<String>,
    pub(crate) finality_mode: String,
}

#[derive(Debug, Deserialize)]
struct StarkReleaseProfile {
    schema_version: String,
    environment: String,
    production_usable: bool,
    chain_id: u64,
    current_backend: String,
    candidate_backend: String,
    automatic_fallback: bool,
    rollback_mode: String,
    native_verifier_active: bool,
    approved_attestor: Option<String>,
    approved_attestor_key_id: Option<String>,
    policy_manifest_hash: Option<String>,
    activation_gates: StarkActivationGates,
}

#[derive(Debug, Deserialize)]
struct StarkActivationGates {
    local_v2_validation_passed: bool,
    safe_and_timelock_deployed: bool,
    external_mpc_key_approved: bool,
    policy_manifest_approved: bool,
    deployment_pins_complete: bool,
    approved_canary_finalized: bool,
    denied_canary_finalized: bool,
    reconciliation_report_clean: bool,
    pause_recovery_rehearsed: bool,
    legal_approval_recorded: bool,
    independent_audits_complete: bool,
}

impl StarkActivationGates {
    fn pilot_ready(&self) -> bool {
        self.local_v2_validation_passed
            && self.safe_and_timelock_deployed
            && self.external_mpc_key_approved
            && self.policy_manifest_approved
            && self.deployment_pins_complete
    }

    fn all(&self) -> bool {
        self.pilot_ready()
            && self.approved_canary_finalized
            && self.denied_canary_finalized
            && self.reconciliation_report_clean
            && self.pause_recovery_rehearsed
            && self.legal_approval_recorded
            && self.independent_audits_complete
    }
}

#[derive(Debug, Deserialize)]
struct StarkDeploymentPin {
    schema_version: String,
    environment: String,
    production_usable: bool,
    chain_id: u64,
    source_commit: String,
    openzeppelin_contracts_version: String,
    cargo_lock_sha256: String,
    proof_parameters_sha256: String,
    proof_parameters: StarkProofParameters,
    deployment_transactions: Vec<String>,
    governance_safe: String,
    emergency_safe: String,
    treasury: String,
    timelock: String,
    attestor: String,
    verifier: String,
    registry: String,
    policy_manifest_hash: String,
    verifier_runtime_bytecode_sha256: String,
    registry_runtime_bytecode_sha256: String,
    native_on_chain_winterfell: bool,
}

#[derive(Debug, Deserialize)]
struct StarkProofParameters {
    schema_version: String,
    air: String,
    trace_length: u64,
    base_field: String,
    field_extension: String,
    hash_function: String,
    random_coin: String,
    merkle_tree: String,
    acceptable_min_conjectured_security_bits: u64,
    proof_options: StarkProofOptions,
    source_path: String,
    source_sha256: String,
}

#[derive(Debug, Deserialize)]
struct StarkProofOptions {
    num_queries: u64,
    blowup_factor: u64,
    grinding_factor: u64,
    fri_folding_factor: u64,
    fri_max_remainder_degree: u64,
    constraint_batching: String,
    deep_poly_batching: String,
}

pub(crate) fn validate_stark_runtime_activation(
    config: &AppConfig,
) -> Result<StarkRuntimeActivation, String> {
    let mode = runtime_mode(config)?;
    if mode == StarkRuntimeMode::LocalTest {
        return local_test_activation(config);
    }

    let release_path = configured_or_env(
        config.stark_release_profile_path.as_deref(),
        "LOCALBCE_STARK_RELEASE_PROFILE_PATH",
    )
    .ok_or_else(|| {
        "stark_release_profile_path or LOCALBCE_STARK_RELEASE_PROFILE_PATH is required".to_string()
    })?;
    let pin_path = configured_or_env(
        config.stark_deployment_pin_path.as_deref(),
        "LOCALBCE_STARK_DEPLOYMENT_PIN_PATH",
    )
    .ok_or_else(|| {
        "stark_deployment_pin_path or LOCALBCE_STARK_DEPLOYMENT_PIN_PATH is required".to_string()
    })?;
    let release_value = read_json(&release_path, "STARK release profile")?;
    let release: StarkReleaseProfile = serde_json::from_value(release_value)
        .map_err(|error| format!("invalid STARK release profile {release_path}: {error}"))?;
    validate_release_profile(&release, mode)?;

    let pin_value = read_json(&pin_path, "STARK deployment pin")?;
    let pin: StarkDeploymentPin = serde_json::from_value(pin_value.clone())
        .map_err(|error| format!("invalid STARK deployment pin {pin_path}: {error}"))?;
    validate_deployment_pin(&pin, &pin_value, mode)?;

    if config
        .stark_chain_id
        .is_some_and(|value| value != pin.chain_id)
    {
        return Err("configured stark_chain_id does not match the deployment pin".to_string());
    }
    compare_optional_address(
        config.stark_claims_registry_address.as_deref(),
        &pin.registry,
        "configured STARK registry",
    )?;
    compare_optional_address(
        config.stark_attestation_verifier_address.as_deref(),
        &pin.verifier,
        "configured STARK verifier",
    )?;

    let attestor_mode =
        configured_or_env(config.stark_attestor_mode.as_deref(), "STARK_ATTESTOR_MODE")
            .ok_or_else(|| "stark_attestor_mode is required".to_string())?;
    if attestor_mode != "external_command" {
        return Err("Sepolia STARK mode requires external_command attestation signing".to_string());
    }
    let signer_program = configured_or_env(
        config.stark_attestor_signer_program.as_deref(),
        "STARK_ATTESTOR_SIGNER_PROGRAM",
    )
    .ok_or_else(|| "approved external signer program is required".to_string())?;
    if is_placeholder(&signer_program) {
        return Err("external signer program cannot be a placeholder".to_string());
    }
    let signer_args = configured_vec_or_env(
        config.stark_attestor_signer_args.as_deref(),
        "STARK_ATTESTOR_SIGNER_ARGS_JSON",
    )?;
    let allowed_key_ids = configured_vec_or_env(
        config.stark_attestor_allowed_key_ids.as_deref(),
        "STARK_ATTESTOR_ALLOWED_KEY_IDS_JSON",
    )?;
    if allowed_key_ids.is_empty() || allowed_key_ids.iter().any(|value| is_placeholder(value)) {
        return Err("approved external signer key IDs are required".to_string());
    }

    let attestor_address = configured_or_env(
        config.stark_attestor_address.as_deref(),
        "STARK_ATTESTOR_ADDRESS",
    )
    .ok_or_else(|| "approved STARK attestor address is required".to_string())?;
    if !addresses_equal(&attestor_address, &pin.attestor) {
        return Err("configured STARK attestor does not match the deployment pin".to_string());
    }
    let release_attestor = release
        .approved_attestor
        .as_deref()
        .ok_or_else(|| "release profile is missing the approved attestor".to_string())?;
    if !addresses_equal(release_attestor, &pin.attestor) {
        return Err("release profile attestor does not match the deployment pin".to_string());
    }
    let release_key_id = release
        .approved_attestor_key_id
        .as_deref()
        .ok_or_else(|| "release profile is missing the approved attestor key ID".to_string())?;
    if !allowed_key_ids.iter().any(|value| value == release_key_id) {
        return Err(
            "configured signer key IDs do not include the release-approved key ID".to_string(),
        );
    }
    let policy_manifest_hash = configured_or_env(
        config.stark_policy_manifest_hash.as_deref(),
        "STARK_POLICY_MANIFEST_HASH",
    )
    .ok_or_else(|| "approved STARK policy manifest hash is required".to_string())?;
    if !hashes_equal(&policy_manifest_hash, &pin.policy_manifest_hash) {
        return Err(
            "configured policy manifest hash does not match the deployment pin".to_string(),
        );
    }
    let release_policy_hash = release.policy_manifest_hash.as_deref().ok_or_else(|| {
        "release profile is missing the approved policy manifest hash".to_string()
    })?;
    if !hashes_equal(release_policy_hash, &pin.policy_manifest_hash) {
        return Err("release profile policy hash does not match the deployment pin".to_string());
    }

    let finality_mode =
        configured_or_env(config.stark_finality_mode.as_deref(), "STARK_FINALITY_MODE")
            .unwrap_or_else(|| "finalized".to_string());
    if finality_mode != "finalized" || config.stark_allow_test_mined_finality == Some(true) {
        return Err(
            "Sepolia STARK mode requires finalized finality without test overrides".to_string(),
        );
    }
    let rpc_url = required_env("SEPOLIA_RPC_URL")?;
    let submitter_private_key = required_env("STARK_SUBMITTER_PRIVATE_KEY")?;
    require_finalized_rpc_support(&rpc_url)?;

    Ok(StarkRuntimeActivation {
        mode,
        chain_id: pin.chain_id,
        verifier: pin.verifier,
        registry: pin.registry,
        rpc_url,
        submitter_private_key,
        attestor_mode,
        signer_program: Some(signer_program),
        signer_args,
        allowed_key_ids,
        attestor_address: Some(attestor_address),
        policy_manifest_hash: Some(policy_manifest_hash),
        finality_mode,
    })
}

fn runtime_mode(config: &AppConfig) -> Result<StarkRuntimeMode, String> {
    let default = if config.stark_chain_id == Some(31_337)
        && config.stark_allow_test_mined_finality == Some(true)
    {
        "local_test"
    } else {
        "production"
    };
    match config.stark_runtime_mode.as_deref().unwrap_or(default) {
        "local_test" => Ok(StarkRuntimeMode::LocalTest),
        "pilot_canary" => Ok(StarkRuntimeMode::PilotCanary),
        "production" => Ok(StarkRuntimeMode::Production),
        value => Err(format!(
            "unsupported stark_runtime_mode '{value}'; expected local_test, pilot_canary, or production"
        )),
    }
}

fn local_test_activation(config: &AppConfig) -> Result<StarkRuntimeActivation, String> {
    if config.stark_chain_id != Some(31_337) {
        return Err("local_test STARK mode is restricted to chain 31337".to_string());
    }
    let finality_mode = config.stark_finality_mode.as_deref().unwrap_or("mined");
    let valid_finality = match finality_mode {
        "mined" => config.stark_allow_test_mined_finality != Some(true),
        "test_mined" => config.stark_allow_test_mined_finality == Some(true),
        _ => false,
    };
    if !valid_finality {
        return Err(
            "local_test STARK mode requires mined finality or an explicit test_mined override"
                .to_string(),
        );
    }
    let verifier = config
        .stark_attestation_verifier_address
        .clone()
        .ok_or_else(|| "stark_attestation_verifier_address is required".to_string())?;
    let registry = config
        .stark_claims_registry_address
        .clone()
        .ok_or_else(|| "stark_claims_registry_address is required".to_string())?;
    let attestor_mode = config
        .stark_attestor_mode
        .clone()
        .unwrap_or_else(|| "local_private_key".to_string());
    validate_local_attestor_mode(&attestor_mode)?;
    Ok(StarkRuntimeActivation {
        mode: StarkRuntimeMode::LocalTest,
        chain_id: 31_337,
        verifier,
        registry,
        rpc_url: config.rpc_url.clone(),
        submitter_private_key: env::var("STARK_SUBMITTER_PRIVATE_KEY")
            .unwrap_or_else(|_| config.private_key.clone()),
        attestor_mode,
        signer_program: config.stark_attestor_signer_program.clone(),
        signer_args: config
            .stark_attestor_signer_args
            .clone()
            .unwrap_or_default(),
        allowed_key_ids: config
            .stark_attestor_allowed_key_ids
            .clone()
            .unwrap_or_default(),
        attestor_address: config.stark_attestor_address.clone(),
        policy_manifest_hash: config.stark_policy_manifest_hash.clone(),
        finality_mode: finality_mode.to_string(),
    })
}

fn validate_local_attestor_mode(attestor_mode: &str) -> Result<(), String> {
    match attestor_mode {
        "local_private_key" | "external_command" => Ok(()),
        value => Err(format!(
            "unsupported local STARK attestor mode '{value}'; expected local_private_key or external_command"
        )),
    }
}

fn validate_release_profile(
    profile: &StarkReleaseProfile,
    mode: StarkRuntimeMode,
) -> Result<(), String> {
    if profile.schema_version != RELEASE_SCHEMA {
        return Err(format!(
            "release profile schema_version must be {RELEASE_SCHEMA}"
        ));
    }
    if profile.chain_id != SEPOLIA_CHAIN_ID {
        return Err("release profile must pin Sepolia chain ID 11155111".to_string());
    }
    if is_placeholder(&profile.environment) {
        return Err("release profile environment cannot be an example or placeholder".to_string());
    }
    if profile.candidate_backend != "stark_attested"
        || profile.automatic_fallback
        || profile.rollback_mode != "manual_governed"
        || profile.native_verifier_active
    {
        return Err(
            "release profile must retain stark_attested, manual rollback, no automatic fallback, and inactive native verification"
                .to_string(),
        );
    }
    if matches!(
        mode,
        StarkRuntimeMode::Production | StarkRuntimeMode::PilotCanary
    ) {
        validate_address(
            profile.approved_attestor.as_deref().unwrap_or_default(),
            "release profile approved_attestor",
        )?;
        let key_id = profile
            .approved_attestor_key_id
            .as_deref()
            .unwrap_or_default();
        if key_id.is_empty() || is_placeholder(key_id) {
            return Err(
                "release profile approved_attestor_key_id is missing or invalid".to_string(),
            );
        }
        validate_hex(
            profile.policy_manifest_hash.as_deref().unwrap_or_default(),
            64,
            true,
            "release profile policy_manifest_hash",
        )?;
    }
    match mode {
        StarkRuntimeMode::Production => {
            if !profile.production_usable
                || profile.current_backend != "stark_attested"
                || !profile.activation_gates.all()
            {
                return Err(
                    "production STARK activation requires production_usable=true, current_backend=stark_attested, and every activation gate"
                        .to_string(),
                );
            }
        }
        StarkRuntimeMode::PilotCanary => {
            if profile.production_usable
                || profile.current_backend != "groth16"
                || !profile.activation_gates.pilot_ready()
            {
                return Err(
                    "pilot canary mode requires the five pre-canary gates while production remains inactive on groth16"
                        .to_string(),
                );
            }
        }
        StarkRuntimeMode::LocalTest => unreachable!("local test does not load release profiles"),
    }
    Ok(())
}

fn validate_deployment_pin(
    pin: &StarkDeploymentPin,
    raw: &Value,
    mode: StarkRuntimeMode,
) -> Result<(), String> {
    if pin.schema_version != DEPLOYMENT_PIN_SCHEMA {
        return Err(format!(
            "deployment pin schema_version must be {DEPLOYMENT_PIN_SCHEMA}"
        ));
    }
    if pin.chain_id != SEPOLIA_CHAIN_ID || is_placeholder(&pin.environment) {
        return Err(
            "deployment pin must identify a non-placeholder Sepolia environment".to_string(),
        );
    }
    if (mode == StarkRuntimeMode::Production) != pin.production_usable {
        return Err("deployment pin production_usable does not match the runtime mode".to_string());
    }
    validate_hex(&pin.source_commit, 40, false, "source_commit")?;
    if pin.openzeppelin_contracts_version != "v5.6.1" {
        return Err("deployment pin must use OpenZeppelin v5.6.1".to_string());
    }
    for (value, label) in [
        (&pin.cargo_lock_sha256, "cargo_lock_sha256"),
        (&pin.proof_parameters_sha256, "proof_parameters_sha256"),
        (
            &pin.verifier_runtime_bytecode_sha256,
            "verifier_runtime_bytecode_sha256",
        ),
        (
            &pin.registry_runtime_bytecode_sha256,
            "registry_runtime_bytecode_sha256",
        ),
        (&pin.proof_parameters.source_sha256, "proof source_sha256"),
    ] {
        validate_hex(value, 64, false, label)?;
    }
    let proof_value = raw
        .get("proof_parameters")
        .ok_or_else(|| "deployment pin is missing proof_parameters".to_string())?;
    let canonical = serde_json::to_vec(proof_value)
        .map_err(|error| format!("could not canonicalize proof parameters: {error}"))?;
    let actual = hex::encode(Sha256::digest(canonical));
    if actual != pin.proof_parameters_sha256.to_ascii_lowercase() {
        return Err("proof_parameters_sha256 does not match proof_parameters".to_string());
    }
    validate_proof_parameters(&pin.proof_parameters)?;
    if pin.deployment_transactions.len() != 3 {
        return Err(
            "deployment pin must contain exactly three deployment transactions".to_string(),
        );
    }
    for transaction in &pin.deployment_transactions {
        validate_hex(transaction, 64, true, "deployment transaction")?;
    }
    if pin
        .deployment_transactions
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>()
        .len()
        != pin.deployment_transactions.len()
    {
        return Err("deployment transaction pins must be unique".to_string());
    }
    for (value, label) in [
        (&pin.governance_safe, "governance_safe"),
        (&pin.emergency_safe, "emergency_safe"),
        (&pin.treasury, "treasury"),
        (&pin.timelock, "timelock"),
        (&pin.attestor, "attestor"),
        (&pin.verifier, "verifier"),
        (&pin.registry, "registry"),
    ] {
        validate_address(value, label)?;
    }
    if !addresses_equal(&pin.governance_safe, &pin.emergency_safe) {
        return Err("Sepolia pilot governance and emergency Safe must match".to_string());
    }
    let distinct = [
        &pin.governance_safe,
        &pin.treasury,
        &pin.timelock,
        &pin.attestor,
        &pin.verifier,
        &pin.registry,
    ]
    .into_iter()
    .map(|value| value.to_ascii_lowercase())
    .collect::<HashSet<_>>();
    if distinct.len() != 6 {
        return Err("deployment pin reuses an address across separated roles".to_string());
    }
    validate_hex(&pin.policy_manifest_hash, 64, true, "policy_manifest_hash")?;
    if pin.native_on_chain_winterfell {
        return Err("native on-chain Winterfell verification must remain inactive".to_string());
    }
    Ok(())
}

fn validate_proof_parameters(parameters: &StarkProofParameters) -> Result<(), String> {
    let options = &parameters.proof_options;
    let valid = parameters.schema_version == "localbce-winterfell-proof-parameters-v1"
        && parameters.air == "production-g1-g10-v1"
        && parameters.trace_length == 1024
        && parameters.base_field == "f64"
        && parameters.field_extension == "quadratic"
        && parameters.hash_function == "blake3_256"
        && parameters.random_coin == "blake3_256"
        && parameters.merkle_tree == "blake3_256"
        && parameters.acceptable_min_conjectured_security_bits >= 80
        && options.num_queries == 32
        && options.blowup_factor == 16
        && options.grinding_factor == 0
        && options.fri_folding_factor == 8
        && options.fri_max_remainder_degree == 31
        && options.constraint_batching == "linear"
        && options.deep_poly_batching == "linear"
        && parameters.source_path == "stark-engine/src/production_air_winterfell.rs";
    if !valid {
        return Err("deployment pin proof parameters do not match the production AIR".to_string());
    }
    Ok(())
}

fn read_json(path: &str, label: &str) -> Result<Value, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("could not read {label} {path}: {error}"))?;
    serde_json::from_str(&content).map_err(|error| format!("invalid {label} {path}: {error}"))
}

fn require_finalized_rpc_support(rpc_url: &str) -> Result<(), String> {
    let output = Command::new("cast")
        .args([
            "rpc",
            "eth_getBlockByNumber",
            "finalized",
            "false",
            "--rpc-url",
            rpc_url,
        ])
        .output()
        .map_err(|error| format!("could not run finalized-block RPC probe: {error}"))?;
    if !output.status.success() {
        return Err("Sepolia RPC does not support the finalized block tag".to_string());
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "Sepolia RPC returned malformed finalized-block data".to_string())?;
    validate_finalized_block(&value)
}

fn validate_finalized_block(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Sepolia RPC does not support the finalized block tag".to_string())?;
    for field in ["hash", "number"] {
        let encoded = object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("finalized block response is missing {field}"))?;
        if !encoded.starts_with("0x") || encoded.len() <= 2 {
            return Err(format!("finalized block response has invalid {field}"));
        }
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required for fail-closed production STARK mode"))
}

fn configured_or_env(configured: Option<&str>, name: &str) -> Option<String> {
    configured
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| env::var(name).ok().filter(|value| !value.trim().is_empty()))
}

fn configured_vec_or_env(configured: Option<&[String]>, name: &str) -> Result<Vec<String>, String> {
    if let Some(values) = configured {
        return Ok(values.to_vec());
    }
    let Some(value) = env::var(name).ok().filter(|value| !value.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    serde_json::from_str(&value)
        .map_err(|error| format!("{name} must be a JSON string array: {error}"))
}

fn compare_optional_address(
    configured: Option<&str>,
    pinned: &str,
    label: &str,
) -> Result<(), String> {
    if configured.is_some_and(|value| !addresses_equal(value, pinned)) {
        return Err(format!("{label} does not match the deployment pin"));
    }
    Ok(())
}

fn addresses_equal(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn hashes_equal(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn validate_address(value: &str, label: &str) -> Result<(), String> {
    validate_hex(value, 40, true, label)?;
    let digits = value.trim_start_matches("0x");
    if digits
        .chars()
        .all(|character| character == digits.as_bytes()[0] as char)
    {
        return Err(format!("{label} cannot be a placeholder address"));
    }
    Ok(())
}

fn validate_hex(value: &str, digits: usize, prefixed: bool, label: &str) -> Result<(), String> {
    let body = if prefixed {
        value
            .strip_prefix("0x")
            .ok_or_else(|| format!("{label} must start with 0x"))?
    } else {
        value.strip_prefix("0x").unwrap_or(value)
    };
    if body.len() != digits
        || !body.chars().all(|character| character.is_ascii_hexdigit())
        || body.chars().all(|character| character == '0')
    {
        return Err(format!(
            "{label} must be a nonzero {digits}-digit hexadecimal value"
        ));
    }
    Ok(())
}

fn is_placeholder(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.is_empty()
        || normalized.contains("replace")
        || normalized.contains("placeholder")
        || normalized.contains("example")
        || normalized.contains("non_production")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gates(value: bool) -> Value {
        json!({
            "local_v2_validation_passed": value,
            "safe_and_timelock_deployed": value,
            "external_mpc_key_approved": value,
            "policy_manifest_approved": value,
            "deployment_pins_complete": value,
            "approved_canary_finalized": value,
            "denied_canary_finalized": value,
            "reconciliation_report_clean": value,
            "pause_recovery_rehearsed": value,
            "legal_approval_recorded": value,
            "independent_audits_complete": value,
        })
    }

    fn production_release() -> StarkReleaseProfile {
        serde_json::from_value(json!({
            "schema_version": RELEASE_SCHEMA,
            "environment": "sepolia_production",
            "production_usable": true,
            "chain_id": SEPOLIA_CHAIN_ID,
            "current_backend": "stark_attested",
            "candidate_backend": "stark_attested",
            "automatic_fallback": false,
            "rollback_mode": "manual_governed",
            "native_verifier_active": false,
            "approved_attestor": "0x1234567890123456789012345678901234567890",
            "approved_attestor_key_id": "approved-mpc-key-v1",
            "policy_manifest_hash": format!("0x{}", "ab".repeat(32)),
            "activation_gates": gates(true),
        }))
        .unwrap()
    }

    #[test]
    fn production_release_requires_every_gate() {
        let mut release = production_release();
        assert!(validate_release_profile(&release, StarkRuntimeMode::Production).is_ok());
        release.activation_gates.independent_audits_complete = false;
        assert!(
            validate_release_profile(&release, StarkRuntimeMode::Production)
                .unwrap_err()
                .contains("every activation gate")
        );
    }

    #[test]
    fn production_release_rejects_fallback_and_native_verifier() {
        let mut release = production_release();
        release.automatic_fallback = true;
        assert!(validate_release_profile(&release, StarkRuntimeMode::Production).is_err());
        release.automatic_fallback = false;
        release.native_verifier_active = true;
        assert!(validate_release_profile(&release, StarkRuntimeMode::Production).is_err());
    }

    #[test]
    fn pilot_release_requires_pre_canary_gates_only() {
        let mut release = production_release();
        release.production_usable = false;
        release.current_backend = "groth16".to_string();
        release.activation_gates.approved_canary_finalized = false;
        release.activation_gates.denied_canary_finalized = false;
        release.activation_gates.reconciliation_report_clean = false;
        release.activation_gates.pause_recovery_rehearsed = false;
        release.activation_gates.legal_approval_recorded = false;
        release.activation_gates.independent_audits_complete = false;
        assert!(validate_release_profile(&release, StarkRuntimeMode::PilotCanary).is_ok());
        release.activation_gates.external_mpc_key_approved = false;
        assert!(validate_release_profile(&release, StarkRuntimeMode::PilotCanary).is_err());
    }

    #[test]
    fn placeholder_addresses_and_hashes_are_rejected() {
        assert!(validate_address("0x1111111111111111111111111111111111111111", "safe").is_err());
        assert!(validate_hex(&format!("0x{}", "0".repeat(64)), 64, true, "hash").is_err());
    }

    #[test]
    fn finalized_block_probe_rejects_null_and_incomplete_responses() {
        assert!(validate_finalized_block(&Value::Null).is_err());
        assert!(validate_finalized_block(&json!({"hash": "0x12"})).is_err());
        assert!(validate_finalized_block(&json!({"hash": "0x12", "number": "0x1"})).is_ok());
    }

    #[test]
    fn local_attestor_mode_is_strictly_allowlisted() {
        assert!(validate_local_attestor_mode("local_private_key").is_ok());
        assert!(validate_local_attestor_mode("external_command").is_ok());
        assert!(validate_local_attestor_mode("unknown").is_err());
    }
}
