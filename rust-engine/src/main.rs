mod advanced_rules;
mod rules_engine;

use advanced_rules::{
    evaluate_promotion_queue_path, validate_canonical_bundle_path, validate_promotion_queue_path,
};
use rules_engine::{
    CURRENT_RULESET_SHA256, ClaimRuleFacts, DeterministicRuleBundle, validate_claude_shadow_bundle,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;

/// Subcommands that drove the STARK proof path. That path is parked under
/// `parked/localbce/`; the commands now fail closed instead of falling through.
const PARKED_STARK_SUBCOMMANDS: [&str; 4] = [
    "stark-sidecar-dry-run",
    "--stark-sidecar-dry-run",
    "stark-bridge-input-dry-run",
    "--stark-bridge-input-dry-run",
];

#[derive(Debug, Serialize)]
enum AdjudicationStatus {
    #[serde(rename = "APPROVED")]
    Approved,
    #[serde(rename = "DENIED")]
    Denied,
}

/// `tx_submitted` and `tx_hash` stay in the schema for compatibility with
/// existing consumers (for example `bridge/rightrail_offchain.py`); with proof
/// and chain settlement parked they are always `false` and `null`.
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
    fn approved_unsubmitted(claim_id: String, claim_hash: String) -> Self {
        Self {
            claim_id,
            claim_hash,
            status: AdjudicationStatus::Approved,
            reason: None,
            tx_submitted: false,
            tx_hash: None,
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

// Accepted for claim_input.json compatibility; not read since the STARK bridge was parked.
#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClaimServiceLine {
    procedure_code: String,
    charge_cents: u64,
    units: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ClaimOracleFact {
    fact_type: String,
    fact_key: String,
    fact_value: String,
    source_url: Option<String>,
    source_label: Option<String>,
    verification_status: String,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

impl From<&ClaimInput> for ClaimRuleFacts {
    fn from(claim: &ClaimInput) -> Self {
        Self {
            eligibility_active: u64::from(claim.eligibility_active),
            aid_code: claim.aid_code,
            benefit_level_exists: u64::from(claim.benefit_level_exists),
            date_of_service_from: claim.date_of_service_from,
            eligibility_period_from: claim.eligibility_period_from,
            eligibility_period_thru: claim.eligibility_period_thru,
            soc_amount: claim.soc_amount,
            soc_met: u64::from(claim.soc_met),
            provider_enrolled: u64::from(claim.provider_enrolled),
            provider_type_valid: u64::from(claim.provider_type_valid),
            billing_code_valid: u64::from(claim.billing_code_valid),
            units_valid: u64::from(claim.units_valid),
            is_duplicate: u64::from(claim.is_duplicate),
            disability_determination_valid: u64::from(claim.disability_determination_valid),
            recipient_not_deceased: u64::from(claim.recipient_not_deceased),
            physician_certification_valid: u64::from(claim.physician_certification_valid),
        }
    }
}

/// Runtime configuration. Unknown keys are ignored, so older configs that still
/// carry chain or STARK settings parse; those settings have no effect.
#[derive(Debug, Deserialize)]
struct AppConfig {
    proof_execution_enabled: Option<bool>,
    proof_backend: Option<String>,
    rules_backend: Option<String>,
    rules_file: Option<String>,
    rules_sha256: Option<String>,
}

impl AppConfig {
    /// Proof execution is parked. Asking for it fails closed rather than
    /// silently running adjudication only.
    fn require_adjudication_only(&self) -> Result<(), String> {
        match self.proof_backend.as_deref().unwrap_or("none") {
            "none" => {}
            "groth16" => return Err("proof_backend 'groth16' is retired".to_string()),
            "stark_attested" => {
                return Err(
                    "proof_backend 'stark_attested' is parked; RightRail is the base system"
                        .to_string(),
                );
            }
            other => {
                return Err(format!(
                    "unsupported proof_backend '{other}'; expected none"
                ));
            }
        }
        if self.proof_execution_enabled.unwrap_or(false) {
            return Err(
                "proof_execution_enabled=true is not supported; proof execution is parked"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn rules_backend(&self) -> Result<&str, String> {
        let value = self.rules_backend.as_deref().unwrap_or("hardcoded_g1_g10");
        match value {
            "hardcoded_g1_g10" | "versioned_g1_g10" => Ok(value),
            _ => Err(format!(
                "unsupported rules_backend '{value}'; expected hardcoded_g1_g10 or versioned_g1_g10"
            )),
        }
    }
}

fn claim_hash_32(claim_id: &str, claim_amount: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(claim_id.as_bytes());
    hasher.update(claim_amount.to_be_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
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

fn configured_denial_reason(
    config: &AppConfig,
    claim: &ClaimInput,
) -> Result<Option<String>, String> {
    let built_in = denial_reason(claim).map(str::to_string);
    if config.rules_backend()? == "hardcoded_g1_g10" {
        return Ok(built_in);
    }

    let rules_path = config
        .rules_file
        .as_deref()
        .ok_or_else(|| "rules_file is required for versioned_g1_g10".to_string())?;
    let configured_hash = config
        .rules_sha256
        .as_deref()
        .ok_or_else(|| "rules_sha256 is required for versioned_g1_g10".to_string())?;
    if configured_hash != CURRENT_RULESET_SHA256 {
        return Err(format!(
            "rules_sha256 must match the binary pin {CURRENT_RULESET_SHA256}, got {configured_hash}"
        ));
    }

    let bundle = DeterministicRuleBundle::from_path(Path::new(rules_path))?;
    if bundle.rules_sha256 != configured_hash {
        return Err(format!(
            "configured rules_sha256 does not match loaded bundle: expected {configured_hash}, got {}",
            bundle.rules_sha256
        ));
    }
    let versioned = bundle.evaluate(&ClaimRuleFacts::from(claim));
    if versioned != built_in {
        return Err(format!(
            "versioned G1-G10 result failed hardcoded parity: versioned={versioned:?}, hardcoded={built_in:?}"
        ));
    }
    Ok(versioned)
}

fn write_result(result: &AdjudicationResult) -> Result<(), String> {
    let result_json = serde_json::to_string_pretty(result)
        .map_err(|err| format!("could not serialize adjudication_result.json: {}", err))?;

    fs::write("adjudication_result.json", result_json)
        .map_err(|err| format!("could not write adjudication_result.json: {}", err))
}

fn read_config() -> Result<AppConfig, String> {
    let path = env::var("LOCALBCE_CONFIG_PATH").unwrap_or_else(|_| "config.json".to_string());
    let config_json =
        fs::read_to_string(&path).map_err(|err| format!("could not read {path}: {err}"))?;
    serde_json::from_str(&config_json).map_err(|err| format!("invalid {path}: {err}"))
}

fn read_claim_input() -> Result<ClaimInput, String> {
    let path =
        env::var("LOCALBCE_CLAIM_INPUT_PATH").unwrap_or_else(|_| "claim_input.json".to_string());
    let claim_json =
        fs::read_to_string(&path).map_err(|err| format!("could not read {path}: {err}"))?;

    serde_json::from_str(&claim_json).map_err(|err| format!("invalid {path}: {err}"))
}

fn main() {
    let mut args = env::args().skip(1);
    let arg = args.next();
    let result = if arg
        .as_deref()
        .is_some_and(|value| PARKED_STARK_SUBCOMMANDS.contains(&value))
    {
        Err(format!(
            "{} is parked with the STARK proof path; see parked/localbce/README.md",
            arg.as_deref().unwrap_or_default()
        ))
    } else if arg.as_deref() == Some("rules-validate") {
        args.next()
            .ok_or_else(|| "rules-validate requires a ruleset path".to_string())
            .and_then(|path| run_rules_validate(Path::new(&path)))
    } else if arg.as_deref() == Some("rules-evaluate") {
        args.next()
            .ok_or_else(|| "rules-evaluate requires a ruleset path".to_string())
            .and_then(|path| run_rules_evaluate(Path::new(&path)))
    } else if arg.as_deref() == Some("rules-shadow-validate") {
        args.next()
            .ok_or_else(|| "rules-shadow-validate requires a bundle path".to_string())
            .and_then(|path| run_rules_shadow_validate(Path::new(&path)))
    } else if arg.as_deref() == Some("rules-canonical-validate") {
        args.next()
            .ok_or_else(|| "rules-canonical-validate requires a bundle path".to_string())
            .and_then(|path| run_rules_canonical_validate(Path::new(&path)))
    } else if arg.as_deref() == Some("rules-promotion-queue-validate") {
        args.next()
            .ok_or_else(|| "rules-promotion-queue-validate requires a queue path".to_string())
            .and_then(|path| run_rules_promotion_queue_validate(Path::new(&path)))
    } else if arg.as_deref() == Some("rules-shadow-evaluate") {
        args.next()
            .ok_or_else(|| "rules-shadow-evaluate requires a queue path".to_string())
            .and_then(|queue_path| {
                args.next()
                    .ok_or_else(|| "rules-shadow-evaluate requires a facts path".to_string())
                    .and_then(|facts_path| {
                        run_advanced_rules_shadow_evaluate(
                            Path::new(&queue_path),
                            Path::new(&facts_path),
                        )
                    })
            })
    } else {
        run_app()
    };

    if let Err(err) = result {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

fn run_rules_canonical_validate(path: &Path) -> Result<(), String> {
    let (rules_sha256, rule_count) = validate_canonical_bundle_path(path)?;
    println!(
        "{}",
        json!({
            "event": "canonical_government_rules_validation",
            "status": "ok",
            "path": path,
            "rules_sha256": rules_sha256,
            "rule_count": rule_count,
            "runtime_activation": false,
            "proof_binding": false,
        })
    );
    Ok(())
}

fn run_rules_promotion_queue_validate(path: &Path) -> Result<(), String> {
    let validation = validate_promotion_queue_path(path)?;
    println!(
        "{}",
        json!({
            "event": "government_rules_promotion_queue_validation",
            "status": "ok",
            "path": path,
            "queue_id": validation.queue_id,
            "items_sha256": validation.items_sha256,
            "queue_items": validation.queue_items,
            "program_count": validation.program_count,
            "runtime_eligible": validation.runtime_eligible,
            "runtime_activation": false,
            "proof_binding": false,
        })
    );
    Ok(())
}

fn run_advanced_rules_shadow_evaluate(queue_path: &Path, facts_path: &Path) -> Result<(), String> {
    let report = evaluate_promotion_queue_path(queue_path, facts_path)?;
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("could not serialize rules shadow evaluation: {error}"))?;
    println!("{output}");
    Ok(())
}

fn run_rules_shadow_validate(path: &Path) -> Result<(), String> {
    let validation = validate_claude_shadow_bundle(path)?;
    println!(
        "{}",
        json!({
            "event": "claude_web_rust_shadow_validation",
            "status": "ok",
            "path": path,
            "bundle_id": validation.bundle_id,
            "rules_sha256": validation.rules_sha256,
            "rule_count": validation.rule_count,
            "program_count": validation.program_count,
            "runtime_activation": false,
            "proof_binding": false,
        })
    );
    Ok(())
}

fn run_rules_validate(path: &Path) -> Result<(), String> {
    let bundle = DeterministicRuleBundle::from_path(path)?;
    println!(
        "{}",
        json!({
            "event": "deterministic_rules_validation",
            "status": "ok",
            "path": path,
            "schema_version": bundle.schema_version,
            "ruleset_id": bundle.ruleset_id,
            "rules_sha256": bundle.rules_sha256,
            "rule_count": bundle.rules.len(),
            "runtime_status": bundle.runtime_status,
        })
    );
    Ok(())
}

fn run_rules_evaluate(path: &Path) -> Result<(), String> {
    let bundle = DeterministicRuleBundle::from_path(path)?;
    let claim = read_claim_input()?;
    let denial = bundle.evaluate(&ClaimRuleFacts::from(&claim));
    let built_in = denial_reason(&claim).map(str::to_string);
    if denial != built_in {
        return Err(format!(
            "versioned G1-G10 result failed hardcoded parity: versioned={denial:?}, hardcoded={built_in:?}"
        ));
    }
    println!(
        "{}",
        json!({
            "event": "deterministic_rules_evaluation",
            "status": "ok",
            "ruleset_id": bundle.ruleset_id,
            "rules_sha256": bundle.rules_sha256,
            "claim_id": claim.claim_id,
            "decision": if denial.is_none() { 1 } else { 0 },
            "denial_reason": denial,
            "hardcoded_parity": true,
            "proof_generation": false,
            "chain_submission": false,
        })
    );
    Ok(())
}

fn run_app() -> Result<(), String> {
    let config = read_config()?;
    config.require_adjudication_only()?;
    let claim = read_claim_input()?;
    let claim_hash = claim_hash_32(&claim.claim_id, claim.claim_amount);

    if let Some(reason) = configured_denial_reason(&config, &claim)?.as_deref() {
        let result = AdjudicationResult::denied(claim.claim_id.clone(), claim_hash, reason);
        write_result(&result)?;
        println!("Claim denied: {}", reason);
        println!("Wrote adjudication_result.json");
        return Ok(());
    }

    let result =
        AdjudicationResult::approved_unsubmitted(claim.claim_id.clone(), claim_hash.clone());
    write_result(&result)?;
    println!(
        "{}",
        json!({
            "event": "adjudication_only",
            "status": "completed",
            "claim_id": claim.claim_id,
            "claim_hash": claim_hash,
            "decision": "APPROVED",
            "proof_generation": false,
            "chain_submission": false,
        })
    );
    println!("Wrote adjudication_result.json");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

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


    fn config_json() -> String {
        json!({}).to_string()
    }

    fn config_with(key: &str, value: Value) -> AppConfig {
        let mut config: Value = serde_json::from_str(&config_json()).unwrap();
        config[key] = value;
        serde_json::from_value(config).unwrap()
    }

    #[test]
    fn empty_config_runs_adjudication_only() {
        let config: AppConfig = serde_json::from_str(&config_json()).unwrap();

        assert_eq!(config.require_adjudication_only(), Ok(()));
    }

    #[test]
    fn config_without_chain_fields_parses() {
        let config: AppConfig = serde_json::from_str(
            r#"{"proof_execution_enabled": false, "proof_backend": "none"}"#,
        )
        .unwrap();

        assert_eq!(config.require_adjudication_only(), Ok(()));
    }

    #[test]
    fn legacy_chain_and_stark_keys_are_ignored() {
        let config: AppConfig = serde_json::from_str(
            r#"{
                "claims_registry_address": "0x0000000000000000000000000000000000000001",
                "rpc_url": "http://127.0.0.1:8545",
                "transaction_value": "0",
                "enable_stark_sidecar_artifacts": true,
                "stark_chain_id": 31337
            }"#,
        )
        .unwrap();

        assert_eq!(config.require_adjudication_only(), Ok(()));
    }

    #[test]
    fn config_rejects_proof_execution() {
        let config = config_with("proof_execution_enabled", json!(true));

        assert!(
            config
                .require_adjudication_only()
                .unwrap_err()
                .contains("proof execution is parked")
        );
    }

    #[test]
    fn config_rejects_parked_stark_attested_backend() {
        let config = config_with("proof_backend", json!("stark_attested"));

        assert!(
            config
                .require_adjudication_only()
                .unwrap_err()
                .contains("parked")
        );
    }

    #[test]
    fn config_rejects_unknown_proof_backend() {
        let config = config_with("proof_backend", json!("mystery"));

        assert!(
            config
                .require_adjudication_only()
                .unwrap_err()
                .contains("unsupported")
        );
    }

    #[test]
    fn d_01_n_08_config_rejects_groth16_proof_backend() {
        let config = config_with("proof_backend", json!("groth16"));

        assert_eq!(
            config.require_adjudication_only(),
            Err("proof_backend 'groth16' is retired".to_string())
        );
    }

    #[test]
    fn parked_stark_subcommands_are_listed() {
        for name in [
            "stark-sidecar-dry-run",
            "--stark-sidecar-dry-run",
            "stark-bridge-input-dry-run",
            "--stark-bridge-input-dry-run",
        ] {
            assert!(PARKED_STARK_SUBCOMMANDS.contains(&name), "{name}");
        }
        assert!(!PARKED_STARK_SUBCOMMANDS.contains(&"rules-evaluate"));
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
    fn config_missing_rules_backend_preserves_hardcoded_default() {
        let config: AppConfig = serde_json::from_str(&config_json()).unwrap();

        assert_eq!(config.rules_backend(), Ok("hardcoded_g1_g10"));
    }

    #[test]
    fn versioned_rules_match_hardcoded_g1_g10_for_every_branch() {
        let mut value: Value = serde_json::from_str(&config_json()).unwrap();
        value["rules_backend"] = json!("versioned_g1_g10");
        value["rules_file"] = json!("rules_active_v1.json");
        value["rules_sha256"] = json!(CURRENT_RULESET_SHA256);
        let config: AppConfig = serde_json::from_value(value).unwrap();

        let valid = valid_claim();
        assert_eq!(configured_denial_reason(&config, &valid), Ok(None));
        for (expected, claim) in current_gate_cases().into_iter().skip(1) {
            assert_eq!(
                configured_denial_reason(&config, &claim)
                    .unwrap()
                    .as_deref(),
                Some(expected)
            );
        }
    }

    #[test]
    fn versioned_rules_require_binary_pinned_hash() {
        let mut value: Value = serde_json::from_str(&config_json()).unwrap();
        value["rules_backend"] = json!("versioned_g1_g10");
        value["rules_file"] = json!("rules_active_v1.json");
        value["rules_sha256"] = json!("00");
        let config: AppConfig = serde_json::from_value(value).unwrap();

        assert!(
            configured_denial_reason(&config, &valid_claim())
                .unwrap_err()
                .contains("binary pin")
        );
    }

    #[test]
    fn approved_unsubmitted_result_preserves_schema_without_settlement() {
        let result = AdjudicationResult::approved_unsubmitted(
            "CLAIM-TEST-001".to_string(),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );

        let value = serde_json::to_value(result).unwrap();

        assert_eq!(value["claim_id"], "CLAIM-TEST-001");
        assert_eq!(value["status"], "APPROVED");
        assert_eq!(value["reason"], Value::Null);
        assert_eq!(value["tx_submitted"], false);
        assert_eq!(value["tx_hash"], Value::Null);
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
}
