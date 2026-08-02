use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub const RULE_SCHEMA_VERSION: &str = "localbce-deterministic-rules-v1";
pub const CURRENT_RULESET_ID: &str = "current_g1_g10_denial_reason";
pub const CURRENT_RULESET_SHA256: &str =
    "95d38b6d8fc9c44b65feace024a07c22b4f11771fe6b23283ce73bbe0a7cb8e3";
pub const CLAUDE_SHADOW_SCHEMA_VERSION: &str = "claude-web-rust-shadow-bundle-v1";

#[derive(Debug, PartialEq)]
pub struct ClaudeShadowValidation {
    pub bundle_id: String,
    pub rules_sha256: String,
    pub rule_count: usize,
    pub program_count: usize,
}

pub fn validate_claude_shadow_bundle(path: &Path) -> Result<ClaudeShadowValidation, String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "could not read Claude shadow bundle {}: {error}",
            path.display()
        )
    })?;
    let bundle: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid Claude shadow bundle {}: {error}", path.display()))?;
    let mut errors = Vec::new();
    if bundle["schema_version"].as_str() != Some(CLAUDE_SHADOW_SCHEMA_VERSION) {
        errors.push("invalid Claude shadow schema_version".to_string());
    }
    if bundle["execution_status"].as_str() != Some("shadow_only_non_runtime") {
        errors.push("Claude bundle execution_status must remain shadow-only".to_string());
    }
    if bundle["legal_verification_status"].as_str() != Some("candidate_not_legally_verified") {
        errors.push("Claude bundle legal verification status is invalid".to_string());
    }
    if bundle["runtime_activation"].as_bool() != Some(false) {
        errors.push("Claude bundle runtime_activation must be false".to_string());
    }
    if bundle["proof_binding"].as_bool() != Some(false) {
        errors.push("Claude bundle proof_binding must be false".to_string());
    }

    let rules = bundle["rules"]
        .as_array()
        .ok_or_else(|| "Claude shadow bundle rules must be an array".to_string())?;
    let canonical = serde_json::to_vec(rules)
        .map_err(|error| format!("could not canonicalize Claude shadow rules: {error}"))?;
    let computed_hash = hex::encode(Sha256::digest(canonical));
    if bundle["rules_sha256"].as_str() != Some(computed_hash.as_str()) {
        errors.push(format!(
            "Claude bundle rules_sha256 mismatch: computed {computed_hash}"
        ));
    }

    let allowed_operators: HashSet<&str> = [
        "administration",
        "appeal_right",
        "deadline",
        "determine_eligibility",
        "enforcement",
        "payment",
        "prohibit_or_deny",
        "reporting",
        "require",
        "verify_or_determine",
    ]
    .into_iter()
    .collect();
    let mut ids = HashSet::new();
    let mut programs = HashSet::new();
    for (index, rule) in rules.iter().enumerate() {
        let prefix = format!("rules[{index}]");
        let id = rule["rule_id"].as_str().unwrap_or_default();
        if id.is_empty() || !ids.insert(id) {
            errors.push(format!("{prefix}.rule_id is missing or duplicate"));
        }
        let program = rule["program"].as_str().unwrap_or_default();
        if program.is_empty() {
            errors.push(format!("{prefix}.program is required"));
        } else {
            programs.insert(program);
        }
        if !allowed_operators.contains(rule["operator"].as_str().unwrap_or_default()) {
            errors.push(format!("{prefix}.operator is unsupported"));
        }
        if rule["inputs_required"]
            .as_array()
            .is_none_or(|inputs| inputs.is_empty())
        {
            errors.push(format!("{prefix}.inputs_required must not be empty"));
        }
        if rule["qa_status"].as_str() != Some("qa_pass")
            || rule["mapping_status"].as_str() != Some("strong_mapping_candidate")
        {
            errors.push(format!(
                "{prefix} did not pass the deterministic selection gate"
            ));
        }
        if rule["execution_status"].as_str() != Some("shadow_only_non_runtime")
            || rule["runtime_compatible"].as_bool() != Some(false)
            || rule["proof_bound"].as_bool() != Some(false)
        {
            errors.push(format!("{prefix} claims forbidden runtime or proof status"));
        }
        if rule["legal_verification_status"].as_str() != Some("candidate_not_legally_verified") {
            errors.push(format!("{prefix}.legal_verification_status is invalid"));
        }
        if !rule["source_url"]
            .as_str()
            .is_some_and(|url| url.starts_with("https://"))
        {
            errors.push(format!("{prefix}.source_url must use https"));
        }
        if rule["citation_text"]
            .as_str()
            .is_none_or(|citation| citation.trim().is_empty())
        {
            errors.push(format!("{prefix}.citation_text is required"));
        }
    }

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(ClaudeShadowValidation {
        bundle_id: bundle["bundle_id"].as_str().unwrap_or_default().to_string(),
        rules_sha256: computed_hash,
        rule_count: rules.len(),
        program_count: programs.len(),
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeterministicRuleBundle {
    pub schema_version: String,
    pub ruleset_id: String,
    pub rules_sha256: String,
    pub legal_review_status: String,
    pub runtime_status: String,
    pub rules: Vec<DeterministicRule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeterministicRule {
    pub id: String,
    pub priority: u32,
    pub denial_reason: String,
    pub condition: RuleCondition,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RuleCondition {
    NotEqual { field: RuleField, value: u64 },
    GreaterThan { field: RuleField, value: u64 },
    NotIn { field: RuleField, values: Vec<u64> },
    FieldLessThan { left: RuleField, right: RuleField },
    FieldGreaterThan { left: RuleField, right: RuleField },
    All { conditions: Vec<RuleCondition> },
    Any { conditions: Vec<RuleCondition> },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleField {
    EligibilityActive,
    AidCode,
    BenefitLevelExists,
    DateOfServiceFrom,
    EligibilityPeriodFrom,
    EligibilityPeriodThru,
    SocAmount,
    SocMet,
    ProviderEnrolled,
    ProviderTypeValid,
    BillingCodeValid,
    UnitsValid,
    IsDuplicate,
    DisabilityDeterminationValid,
    RecipientNotDeceased,
    PhysicianCertificationValid,
}

#[derive(Clone, Debug, Default)]
pub struct ClaimRuleFacts {
    pub eligibility_active: u64,
    pub aid_code: u64,
    pub benefit_level_exists: u64,
    pub date_of_service_from: u64,
    pub eligibility_period_from: u64,
    pub eligibility_period_thru: u64,
    pub soc_amount: u64,
    pub soc_met: u64,
    pub provider_enrolled: u64,
    pub provider_type_valid: u64,
    pub billing_code_valid: u64,
    pub units_valid: u64,
    pub is_duplicate: u64,
    pub disability_determination_valid: u64,
    pub recipient_not_deceased: u64,
    pub physician_certification_valid: u64,
}

impl ClaimRuleFacts {
    fn value(&self, field: RuleField) -> u64 {
        match field {
            RuleField::EligibilityActive => self.eligibility_active,
            RuleField::AidCode => self.aid_code,
            RuleField::BenefitLevelExists => self.benefit_level_exists,
            RuleField::DateOfServiceFrom => self.date_of_service_from,
            RuleField::EligibilityPeriodFrom => self.eligibility_period_from,
            RuleField::EligibilityPeriodThru => self.eligibility_period_thru,
            RuleField::SocAmount => self.soc_amount,
            RuleField::SocMet => self.soc_met,
            RuleField::ProviderEnrolled => self.provider_enrolled,
            RuleField::ProviderTypeValid => self.provider_type_valid,
            RuleField::BillingCodeValid => self.billing_code_valid,
            RuleField::UnitsValid => self.units_valid,
            RuleField::IsDuplicate => self.is_duplicate,
            RuleField::DisabilityDeterminationValid => self.disability_determination_valid,
            RuleField::RecipientNotDeceased => self.recipient_not_deceased,
            RuleField::PhysicianCertificationValid => self.physician_certification_valid,
        }
    }
}

impl RuleCondition {
    fn matches(&self, facts: &ClaimRuleFacts) -> bool {
        match self {
            Self::NotEqual { field, value } => facts.value(*field) != *value,
            Self::GreaterThan { field, value } => facts.value(*field) > *value,
            Self::NotIn { field, values } => !values.contains(&facts.value(*field)),
            Self::FieldLessThan { left, right } => facts.value(*left) < facts.value(*right),
            Self::FieldGreaterThan { left, right } => facts.value(*left) > facts.value(*right),
            Self::All { conditions } => conditions.iter().all(|condition| condition.matches(facts)),
            Self::Any { conditions } => conditions.iter().any(|condition| condition.matches(facts)),
        }
    }

    fn validate(&self, path: &str, errors: &mut Vec<String>) {
        match self {
            Self::NotIn { values, .. } if values.is_empty() => {
                errors.push(format!("{path}.values must not be empty"));
            }
            Self::All { conditions } | Self::Any { conditions } => {
                if conditions.is_empty() {
                    errors.push(format!("{path}.conditions must not be empty"));
                }
                for (index, condition) in conditions.iter().enumerate() {
                    condition.validate(&format!("{path}.conditions[{index}]"), errors);
                }
            }
            _ => {}
        }
    }
}

impl DeterministicRuleBundle {
    pub fn from_path(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|error| format!("could not read ruleset {}: {error}", path.display()))?;
        let bundle: Self = serde_json::from_str(&raw)
            .map_err(|error| format!("invalid ruleset {}: {error}", path.display()))?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn computed_rules_sha256(&self) -> Result<String, String> {
        let canonical = serde_json::to_vec(&self.rules)
            .map_err(|error| format!("could not serialize rules for hashing: {error}"))?;
        Ok(hex::encode(Sha256::digest(canonical)))
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        if self.schema_version != RULE_SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {RULE_SCHEMA_VERSION}, got {}",
                self.schema_version
            ));
        }
        if self.ruleset_id != CURRENT_RULESET_ID {
            errors.push(format!(
                "ruleset_id must be {CURRENT_RULESET_ID}, got {}",
                self.ruleset_id
            ));
        }
        if self.legal_review_status != "prototype_reviewed_not_legal_advice" {
            errors
                .push("legal_review_status is not approved for this prototype ruleset".to_string());
        }
        if self.runtime_status != "opt_in_exact_g1_g10_parity" {
            errors.push("runtime_status must be opt_in_exact_g1_g10_parity".to_string());
        }
        if self.rules.len() != EXPECTED_RULES.len() {
            errors.push(format!(
                "rules must contain exactly {} current G1-G10 branches, got {}",
                EXPECTED_RULES.len(),
                self.rules.len()
            ));
        }

        let mut ids = HashSet::new();
        let mut priorities = HashSet::new();
        for (index, rule) in self.rules.iter().enumerate() {
            if !ids.insert(rule.id.as_str()) {
                errors.push(format!("duplicate rule id {}", rule.id));
            }
            if !priorities.insert(rule.priority) {
                errors.push(format!("duplicate priority {}", rule.priority));
            }
            rule.condition
                .validate(&format!("rules[{index}].condition"), &mut errors);
        }

        for (index, (expected_id, expected_priority, expected_reason)) in
            EXPECTED_RULES.iter().enumerate()
        {
            match self.rules.get(index) {
                Some(rule)
                    if rule.id == *expected_id
                        && rule.priority == *expected_priority
                        && rule.denial_reason == *expected_reason => {}
                Some(rule) => errors.push(format!(
                    "rules[{index}] must be {expected_id}/{expected_priority}/{expected_reason}, got {}/{}/{}",
                    rule.id, rule.priority, rule.denial_reason
                )),
                None => {}
            }
        }

        match self.computed_rules_sha256() {
            Ok(computed) => {
                if self.rules_sha256 != computed {
                    errors.push(format!(
                        "rules_sha256 does not match canonical rules: expected {computed}, got {}",
                        self.rules_sha256
                    ));
                }
                if computed != CURRENT_RULESET_SHA256 {
                    errors.push(format!(
                        "ruleset does not match the binary pin {CURRENT_RULESET_SHA256}: got {computed}"
                    ));
                }
            }
            Err(error) => errors.push(error),
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub fn evaluate(&self, facts: &ClaimRuleFacts) -> Option<String> {
        self.rules
            .iter()
            .find(|rule| rule.condition.matches(facts))
            .map(|rule| rule.denial_reason.clone())
    }
}

const EXPECTED_RULES: [(&str, u32, &str); 13] = [
    (
        "G1_IDENTITY_VERIFICATION",
        10,
        "G1_IDENTITY_VERIFICATION_FAILED",
    ),
    (
        "G2_PROGRAM_ELIGIBILITY",
        20,
        "G2_PROGRAM_ELIGIBILITY_FAILED",
    ),
    ("G2_BENEFIT_LEVEL", 30, "G2_BENEFIT_LEVEL_MISSING"),
    ("G3_MONTH_OF_SERVICE", 40, "G3_MONTH_OF_SERVICE_FAILED"),
    ("G4_SHARE_OF_COST", 50, "G4_SHARE_OF_COST_FAILED"),
    ("G5_PROVIDER_ENROLLMENT", 60, "G5_PROVIDER_NOT_ENROLLED"),
    ("G5_PROVIDER_TYPE", 70, "G5_PROVIDER_TYPE_INVALID"),
    ("G6_BILLING_CODE", 80, "G6_BILLING_CODE_INVALID"),
    ("G6_UNITS", 90, "G6_UNITS_INVALID"),
    ("G7_DUPLICATE", 100, "G7_DUPLICATE_CLAIM"),
    ("G8_DISABILITY", 110, "G8_DISABILITY_DETERMINATION_FAILED"),
    ("G9_RECIPIENT_LIFE_STATUS", 120, "G9_RECIPIENT_DECEASED"),
    (
        "G10_PHYSICIAN_CERTIFICATION",
        130,
        "G10_PHYSICIAN_CERTIFICATION_FAILED",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bundle() -> DeterministicRuleBundle {
        serde_json::from_str(include_str!("../rules_active_v1.json")).unwrap()
    }

    fn valid_facts() -> ClaimRuleFacts {
        ClaimRuleFacts {
            eligibility_active: 1,
            aid_code: 13,
            benefit_level_exists: 1,
            date_of_service_from: 20_000,
            eligibility_period_from: 19_900,
            eligibility_period_thru: 21_000,
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

    #[test]
    fn active_bundle_is_valid_and_pinned() {
        bundle().validate().unwrap();
    }

    #[test]
    fn active_bundle_approves_valid_facts() {
        assert_eq!(bundle().evaluate(&valid_facts()), None);
    }

    #[test]
    fn active_bundle_preserves_priority() {
        let mut facts = valid_facts();
        facts.eligibility_active = 0;
        facts.is_duplicate = 1;
        assert_eq!(
            bundle().evaluate(&facts).as_deref(),
            Some("G1_IDENTITY_VERIFICATION_FAILED")
        );
    }

    #[test]
    fn active_bundle_rejects_tampered_rule() {
        let mut candidate = bundle();
        candidate.rules[0].denial_reason = "TAMPERED".to_string();
        assert!(candidate.validate().unwrap_err().contains("rules[0]"));
    }

    #[test]
    fn claude_shadow_bundle_is_cross_language_validated_and_non_runtime() {
        let rules = json!([{
            "rule_id": "claude-shadow:test",
            "program": "medicaid",
            "operator": "determine_eligibility",
            "inputs_required": ["income"],
            "qa_status": "qa_pass",
            "mapping_status": "strong_mapping_candidate",
            "execution_status": "shadow_only_non_runtime",
            "runtime_compatible": false,
            "proof_bound": false,
            "legal_verification_status": "candidate_not_legally_verified",
            "source_url": "https://www.medicaid.gov/example",
            "citation_text": "Eligibility depends on qualifying income."
        }]);
        let hash = hex::encode(Sha256::digest(serde_json::to_vec(&rules).unwrap()));
        let bundle = json!({
            "schema_version": CLAUDE_SHADOW_SCHEMA_VERSION,
            "bundle_id": "claude-web-shadow:test",
            "rules_sha256": hash,
            "execution_status": "shadow_only_non_runtime",
            "legal_verification_status": "candidate_not_legally_verified",
            "runtime_activation": false,
            "proof_binding": false,
            "rules": rules
        });
        let path = std::env::temp_dir().join(format!(
            "localbce-claude-shadow-{}.json",
            std::process::id()
        ));
        fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
        let validation = validate_claude_shadow_bundle(&path).unwrap();
        assert_eq!(validation.rule_count, 1);
        assert_eq!(validation.program_count, 1);

        let mut tampered = bundle;
        tampered["runtime_activation"] = json!(true);
        fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(
            validate_claude_shadow_bundle(&path)
                .unwrap_err()
                .contains("runtime_activation")
        );
        let _ = fs::remove_file(path);
    }
}
