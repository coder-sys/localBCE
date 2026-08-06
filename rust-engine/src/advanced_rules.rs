use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub const CANONICAL_RULE_SCHEMA_VERSION: &str = "localbce-government-rule-v1";
pub const CANONICAL_BUNDLE_SCHEMA_VERSION: &str = "localbce-government-rule-bundle-v1";
pub const PROMOTION_QUEUE_SCHEMA_VERSION: &str = "localbce-rule-promotion-queue-v1";
pub const RULE_FACTS_SCHEMA_VERSION: &str = "localbce-rule-facts-v1";
pub const SHADOW_EVALUATION_SCHEMA_VERSION: &str = "localbce-rule-shadow-evaluation-v1";

const ALLOWED_BLOCKERS: &[&str] = &[
    "ambiguous_free_text_condition",
    "conflicting_duplicate",
    "exact_duplicate",
    "human_review_not_approved",
    "invalid_effective_date",
    "invalid_source_url",
    "legal_not_verified",
    "missing_effective_date",
    "missing_lineage",
    "missing_provenance",
    "missing_source_artifact",
    "missing_typed_fact",
    "semantic_duplicate",
    "source_hash_mismatch",
    "unsupported_operator",
];

const ALLOWED_RULE_TYPES: &[&str] = &[
    "administration_rule",
    "appeal_rule",
    "deadline_rule",
    "documentation_rule",
    "eligibility_rule",
    "enforcement_rule",
    "enrollment_rule",
    "exception_rule",
    "payment_rule",
    "provider_rule",
    "reporting_rule",
    "verification_rule",
];

const ALLOWED_OUTCOME_KINDS: &[&str] = &[
    "administrative",
    "appeal",
    "deadline",
    "decision",
    "enforcement",
    "obligation",
    "payment",
];

const ALLOWED_JURISDICTION_LEVELS: &[&str] = &["federal", "state", "local", "tribal", "territory"];

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Jurisdiction {
    pub country: String,
    pub level: String,
    pub state: Option<String>,
    #[serde(default)]
    pub locality: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleAuthority {
    pub issuer: String,
    pub level: String,
    pub citation: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum TypedValue {
    Boolean(bool),
    Integer(i64),
    Decimal(String),
    String(String),
    Date(String),
    List(Vec<TypedValue>),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactType {
    Boolean,
    Integer,
    Decimal,
    String,
    Date,
    List,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOperator {
    Eq,
    Neq,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    NotIn,
    Contains,
    Before,
    OnOrBefore,
    After,
    OnOrAfter,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum CanonicalCondition {
    All {
        conditions: Vec<CanonicalCondition>,
    },
    Any {
        conditions: Vec<CanonicalCondition>,
    },
    Not {
        condition: Box<CanonicalCondition>,
    },
    Compare {
        fact: String,
        fact_type: FactType,
        operator: ComparisonOperator,
        value: TypedValue,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicOutcome {
    pub kind: String,
    pub code: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, TypedValue>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSource {
    pub url: String,
    pub citation_text: String,
    pub artifact_path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalGovernmentRule {
    pub schema_version: String,
    pub rule_id: String,
    pub version: String,
    pub program: String,
    pub jurisdiction: Jurisdiction,
    pub authority: RuleAuthority,
    pub rule_type: String,
    pub conditions: CanonicalCondition,
    pub outcome: DeterministicOutcome,
    pub effective_from: String,
    pub effective_through: Option<String>,
    pub source: RuleSource,
    pub review_status: String,
    pub legal_verification_status: String,
    pub runtime_eligibility_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRuleBundle {
    pub schema_version: String,
    pub bundle_id: String,
    pub rules_sha256: String,
    pub runtime_activation: bool,
    pub proof_binding: bool,
    pub rules: Vec<CanonicalGovernmentRule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueueSource {
    pub url: String,
    pub citation_text: String,
    pub artifact_path: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredFactDraft {
    pub fact_id: String,
    pub suggested_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDraft {
    pub operator_category: Option<String>,
    pub required_facts: Vec<RequiredFactDraft>,
    pub threshold_candidate: Option<Value>,
    pub effective_date_candidate: Option<String>,
    pub outcome_kind_candidate: Option<String>,
    pub condition_source_text: String,
    pub mapping_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionQueueItem {
    pub candidate_id: String,
    pub program: String,
    pub jurisdiction: Jurisdiction,
    pub rule_type: String,
    pub source: QueueSource,
    pub draft: RuleDraft,
    pub canonical_rule: Option<CanonicalGovernmentRule>,
    pub blockers: Vec<String>,
    pub review_status: String,
    pub legal_verification_status: String,
    pub runtime_eligibility_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionQueueSummary {
    pub source_candidates: usize,
    pub promotion_review_records: usize,
    pub mapping_records: usize,
    pub qa_pass_records: usize,
    pub program_count: usize,
    pub programs: Vec<String>,
    pub queue_items: usize,
    pub runtime_eligible: usize,
    pub by_blocker: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionQueue {
    pub schema_version: String,
    pub queue_id: String,
    pub items_sha256: String,
    pub runtime_activation: bool,
    pub proof_binding: bool,
    pub warning: String,
    pub summary: PromotionQueueSummary,
    pub items: Vec<PromotionQueueItem>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFactsInput {
    pub schema_version: String,
    pub program: String,
    pub jurisdiction: Jurisdiction,
    pub evaluation_date: String,
    pub facts: BTreeMap<String, TypedValue>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowEvaluationStatus {
    Matched,
    NotMatched,
    NotApplicable,
    InsufficientData,
}

#[derive(Clone, Debug, Serialize)]
pub struct ShadowRuleResult {
    pub candidate_id: String,
    pub rule_id: Option<String>,
    pub program: String,
    pub status: ShadowEvaluationStatus,
    pub missing_facts: Vec<String>,
    pub reason_codes: Vec<String>,
    pub outcome_preview: Option<DeterministicOutcome>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ShadowEvaluationSummary {
    pub queue_items: usize,
    pub matched: usize,
    pub not_matched: usize,
    pub not_applicable: usize,
    pub insufficient_data: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ShadowEvaluationReport {
    pub schema_version: String,
    pub queue_id: String,
    pub items_sha256: String,
    pub facts_schema_version: String,
    pub runtime_activation: bool,
    pub proof_binding: bool,
    pub adjudication_effect: bool,
    pub summary: ShadowEvaluationSummary,
    pub results: Vec<ShadowRuleResult>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PromotionQueueValidation {
    pub queue_id: String,
    pub items_sha256: String,
    pub queue_items: usize,
    pub program_count: usize,
    pub runtime_eligible: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct IsoDate {
    year: u32,
    month: u32,
    day: u32,
}

impl IsoDate {
    fn parse(value: &str) -> Result<Self, String> {
        if value.len() != 10
            || value.as_bytes().get(4) != Some(&b'-')
            || value.as_bytes().get(7) != Some(&b'-')
        {
            return Err("date must use YYYY-MM-DD".to_string());
        }
        let year = value[0..4]
            .parse::<u32>()
            .map_err(|_| "date year is invalid".to_string())?;
        let month = value[5..7]
            .parse::<u32>()
            .map_err(|_| "date month is invalid".to_string())?;
        let day = value[8..10]
            .parse::<u32>()
            .map_err(|_| "date day is invalid".to_string())?;
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let max_day = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return Err("date month is out of range".to_string()),
        };
        if day == 0 || day > max_day {
            return Err("date day is out of range".to_string());
        }
        Ok(Self { year, month, day })
    }
}

impl TypedValue {
    fn fact_type(&self) -> FactType {
        match self {
            Self::Boolean(_) => FactType::Boolean,
            Self::Integer(_) => FactType::Integer,
            Self::Decimal(_) => FactType::Decimal,
            Self::String(_) => FactType::String,
            Self::Date(_) => FactType::Date,
            Self::List(_) => FactType::List,
        }
    }

    fn validate(&self, path: &str, errors: &mut Vec<String>) {
        match self {
            Self::Decimal(value) if !valid_decimal(value) => {
                errors.push(format!("{path} must be a canonical decimal string"));
            }
            Self::String(value) if value.trim().is_empty() => {
                errors.push(format!("{path} must be a non-empty string"));
            }
            Self::Date(value) => {
                if let Err(error) = IsoDate::parse(value) {
                    errors.push(format!("{path}: {error}"));
                }
            }
            Self::List(values) => {
                if values.is_empty() {
                    errors.push(format!("{path} must be a non-empty list"));
                }
                let mut types = BTreeSet::new();
                for (index, value) in values.iter().enumerate() {
                    value.validate(&format!("{path}[{index}]"), errors);
                    types.insert(value.fact_type());
                    if matches!(value, Self::List(_)) {
                        errors.push(format!("{path} cannot contain nested lists"));
                    }
                }
                if types.len() > 1 {
                    errors.push(format!("{path} members must use one type"));
                }
            }
            _ => {}
        }
    }
}

impl CanonicalCondition {
    fn validate(&self, path: &str, errors: &mut Vec<String>) {
        match self {
            Self::All { conditions } | Self::Any { conditions } => {
                if conditions.is_empty() {
                    errors.push(format!("{path}.conditions must not be empty"));
                }
                for (index, condition) in conditions.iter().enumerate() {
                    condition.validate(&format!("{path}.conditions[{index}]"), errors);
                }
            }
            Self::Not { condition } => condition.validate(&format!("{path}.condition"), errors),
            Self::Compare {
                fact,
                fact_type,
                operator,
                value,
            } => {
                if !canonical_fact_identifier(fact) {
                    errors.push(format!("{path}.fact is invalid"));
                }
                value.validate(&format!("{path}.value"), errors);
                if matches!(operator, ComparisonOperator::In | ComparisonOperator::NotIn)
                    && !matches!(value, TypedValue::List(_))
                {
                    errors.push(format!("{path}.{operator:?} requires a list value"));
                }
                if matches!(operator, ComparisonOperator::In | ComparisonOperator::NotIn)
                    && let TypedValue::List(values) = value
                    && values.iter().any(|item| item.fact_type() != *fact_type)
                {
                    errors.push(format!("{path} membership value type must match fact_type"));
                }
                if matches!(
                    operator,
                    ComparisonOperator::Before
                        | ComparisonOperator::OnOrBefore
                        | ComparisonOperator::After
                        | ComparisonOperator::OnOrAfter
                ) && (*fact_type != FactType::Date || !matches!(value, TypedValue::Date(_)))
                {
                    errors.push(format!("{path} date comparison requires date operands"));
                }
                if matches!(
                    operator,
                    ComparisonOperator::Lt
                        | ComparisonOperator::Lte
                        | ComparisonOperator::Gt
                        | ComparisonOperator::Gte
                ) && !matches!(fact_type, FactType::Integer | FactType::Decimal)
                {
                    errors.push(format!(
                        "{path} ordered comparison requires numeric operands"
                    ));
                }
                if *operator == ComparisonOperator::Contains && *fact_type != FactType::List {
                    errors.push(format!("{path} contains requires a list fact"));
                }
                if !matches!(
                    operator,
                    ComparisonOperator::In
                        | ComparisonOperator::NotIn
                        | ComparisonOperator::Contains
                ) && value.fact_type() != *fact_type
                {
                    errors.push(format!("{path}.value type must match fact_type"));
                }
            }
        }
    }

    fn evaluate(&self, facts: &BTreeMap<String, TypedValue>) -> ConditionResult {
        match self {
            Self::All { conditions } => {
                let mut missing = BTreeSet::new();
                for condition in conditions {
                    match condition.evaluate(facts) {
                        ConditionResult::Matched(false) => return ConditionResult::Matched(false),
                        ConditionResult::Missing(items) => missing.extend(items),
                        ConditionResult::TypeMismatch(fact) => {
                            return ConditionResult::TypeMismatch(fact);
                        }
                        ConditionResult::Matched(true) => {}
                    }
                }
                if missing.is_empty() {
                    ConditionResult::Matched(true)
                } else {
                    ConditionResult::Missing(missing)
                }
            }
            Self::Any { conditions } => {
                let mut missing = BTreeSet::new();
                for condition in conditions {
                    match condition.evaluate(facts) {
                        ConditionResult::Matched(true) => return ConditionResult::Matched(true),
                        ConditionResult::Missing(items) => missing.extend(items),
                        ConditionResult::TypeMismatch(fact) => {
                            return ConditionResult::TypeMismatch(fact);
                        }
                        ConditionResult::Matched(false) => {}
                    }
                }
                if missing.is_empty() {
                    ConditionResult::Matched(false)
                } else {
                    ConditionResult::Missing(missing)
                }
            }
            Self::Not { condition } => match condition.evaluate(facts) {
                ConditionResult::Matched(value) => ConditionResult::Matched(!value),
                other => other,
            },
            Self::Compare {
                fact,
                fact_type,
                operator,
                value,
            } => {
                let Some(actual) = facts.get(fact) else {
                    return ConditionResult::Missing([fact.clone()].into_iter().collect());
                };
                if actual.fact_type() != *fact_type {
                    return ConditionResult::TypeMismatch(fact.clone());
                }
                match compare_values(actual, *operator, value) {
                    Ok(result) => ConditionResult::Matched(result),
                    Err(_) => ConditionResult::TypeMismatch(fact.clone()),
                }
            }
        }
    }
}

enum ConditionResult {
    Matched(bool),
    Missing(BTreeSet<String>),
    TypeMismatch(String),
}

impl CanonicalGovernmentRule {
    fn validate(&self, evidence_root: &Path, path: &str, errors: &mut Vec<String>) {
        if self.schema_version != CANONICAL_RULE_SCHEMA_VERSION {
            errors.push(format!("{path}.schema_version is invalid"));
        }
        if !canonical_rule_identifier(&self.rule_id) {
            errors.push(format!("{path}.rule_id is invalid"));
        }
        if !valid_semver(&self.version) {
            errors.push(format!("{path}.version must use MAJOR.MINOR.PATCH"));
        }
        if !canonical_simple_identifier(&self.program) {
            errors.push(format!("{path}.program is invalid"));
        }
        validate_jurisdiction(&self.jurisdiction, &format!("{path}.jurisdiction"), errors);
        if self.authority.issuer.trim().is_empty() || self.authority.citation.trim().is_empty() {
            errors.push(format!("{path}.authority issuer and citation are required"));
        }
        if !ALLOWED_JURISDICTION_LEVELS.contains(&self.authority.level.as_str()) {
            errors.push(format!("{path}.authority.level is unsupported"));
        }
        if !ALLOWED_RULE_TYPES.contains(&self.rule_type.as_str()) {
            errors.push(format!("{path}.rule_type is unsupported"));
        }
        self.conditions
            .validate(&format!("{path}.conditions"), errors);
        if !ALLOWED_OUTCOME_KINDS.contains(&self.outcome.kind.as_str()) {
            errors.push(format!("{path}.outcome.kind is unsupported"));
        }
        if !canonical_rule_identifier(&self.outcome.code) {
            errors.push(format!("{path}.outcome.code is invalid"));
        }
        for (name, value) in &self.outcome.parameters {
            if !canonical_simple_identifier(name) {
                errors.push(format!("{path}.outcome parameter name is invalid"));
            }
            value.validate(&format!("{path}.outcome.parameters.{name}"), errors);
        }
        let effective_from = match IsoDate::parse(&self.effective_from) {
            Ok(value) => Some(value),
            Err(error) => {
                errors.push(format!("{path}.effective_from: {error}"));
                None
            }
        };
        let effective_through = self.effective_through.as_deref().and_then(|value| {
            IsoDate::parse(value)
                .map_err(|error| errors.push(format!("{path}.effective_through: {error}")))
                .ok()
        });
        if effective_from
            .zip(effective_through)
            .is_some_and(|(from, through)| through < from)
        {
            errors.push(format!("{path}.effective_through precedes effective_from"));
        }
        validate_source(
            &self.source,
            evidence_root,
            &format!("{path}.source"),
            errors,
        );
        if ![
            "unreviewed",
            "machine_reviewed",
            "human_reviewed",
            "approved",
            "rejected",
        ]
        .contains(&self.review_status.as_str())
        {
            errors.push(format!("{path}.review_status is unsupported"));
        }
        if !["not_verified", "pending", "verified", "rejected"]
            .contains(&self.legal_verification_status.as_str())
        {
            errors.push(format!("{path}.legal_verification_status is unsupported"));
        }
        if !["blocked", "shadow_only", "eligible", "active"]
            .contains(&self.runtime_eligibility_status.as_str())
        {
            errors.push(format!("{path}.runtime_eligibility_status is unsupported"));
        }
        if matches!(
            self.runtime_eligibility_status.as_str(),
            "eligible" | "active"
        ) {
            errors.push(format!(
                "{path} runtime eligibility is forbidden before Phase R5"
            ));
        }
    }

    fn applicable(&self, facts: &RuleFactsInput) -> Result<bool, String> {
        if self.program != facts.program || self.jurisdiction != facts.jurisdiction {
            return Ok(false);
        }
        let evaluation = IsoDate::parse(&facts.evaluation_date)?;
        let start = IsoDate::parse(&self.effective_from)?;
        let end = self
            .effective_through
            .as_deref()
            .map(IsoDate::parse)
            .transpose()?;
        Ok(evaluation >= start && end.is_none_or(|value| evaluation <= value))
    }
}

impl RuleFactsInput {
    fn from_path(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|error| format!("could not read rule facts {}: {error}", path.display()))?;
        let facts: Self = serde_json::from_str(&raw)
            .map_err(|error| format!("invalid rule facts {}: {error}", path.display()))?;
        facts.validate()?;
        Ok(facts)
    }

    fn validate(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        if self.schema_version != RULE_FACTS_SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {RULE_FACTS_SCHEMA_VERSION}"
            ));
        }
        if !canonical_simple_identifier(&self.program) {
            errors.push("program is invalid".to_string());
        }
        validate_jurisdiction(&self.jurisdiction, "jurisdiction", &mut errors);
        if let Err(error) = IsoDate::parse(&self.evaluation_date) {
            errors.push(format!("evaluation_date: {error}"));
        }
        for (name, value) in &self.facts {
            if !canonical_fact_identifier(name) {
                errors.push(format!("facts contains invalid identifier {name}"));
            }
            value.validate(&format!("facts.{name}"), &mut errors);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl PromotionQueue {
    fn from_path(path: &Path) -> Result<(Self, PromotionQueueValidation), String> {
        let raw = fs::read_to_string(path).map_err(|error| {
            format!("could not read promotion queue {}: {error}", path.display())
        })?;
        let value: Value = serde_json::from_str(&raw)
            .map_err(|error| format!("invalid promotion queue {}: {error}", path.display()))?;
        let computed_hash = hash_json_value(
            value
                .get("items")
                .ok_or_else(|| "promotion queue items are missing".to_string())?,
        )?;
        let queue: Self = serde_json::from_value(value)
            .map_err(|error| format!("invalid promotion queue {}: {error}", path.display()))?;
        let validation = queue.validate(&evidence_root_for(path), &computed_hash)?;
        Ok((queue, validation))
    }

    fn validate(
        &self,
        evidence_root: &Path,
        computed_hash: &str,
    ) -> Result<PromotionQueueValidation, String> {
        let mut errors = Vec::new();
        if self.schema_version != PROMOTION_QUEUE_SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {PROMOTION_QUEUE_SCHEMA_VERSION}"
            ));
        }
        if self.runtime_activation || self.proof_binding {
            errors.push("promotion queue must remain non-runtime and not proof bound".to_string());
        }
        if self.items_sha256 != computed_hash {
            errors.push(format!(
                "items_sha256 mismatch: expected {computed_hash}, got {}",
                self.items_sha256
            ));
        }
        if self.summary.queue_items != self.items.len() {
            errors.push("summary.queue_items does not match items".to_string());
        }
        if self.summary.runtime_eligible != 0 {
            errors.push("summary.runtime_eligible must remain zero".to_string());
        }
        let mut ids = BTreeSet::new();
        let mut programs = BTreeSet::new();
        for (index, item) in self.items.iter().enumerate() {
            let path = format!("items[{index}]");
            if item.candidate_id.trim().is_empty() || !ids.insert(item.candidate_id.clone()) {
                errors.push(format!("{path}.candidate_id is missing or duplicate"));
            }
            programs.insert(item.program.clone());
            validate_draft_jurisdiction(
                &item.jurisdiction,
                &format!("{path}.jurisdiction"),
                &mut errors,
            );
            let sorted: BTreeSet<_> = item.blockers.iter().cloned().collect();
            if sorted.len() != item.blockers.len()
                || sorted.iter().cloned().collect::<Vec<_>>() != item.blockers
            {
                errors.push(format!("{path}.blockers must be sorted and unique"));
            }
            for blocker in &item.blockers {
                if !ALLOWED_BLOCKERS.contains(&blocker.as_str()) {
                    errors.push(format!(
                        "{path}.blockers contains unsupported code {blocker}"
                    ));
                }
            }
            if item.runtime_eligibility_status != "blocked"
                || item.legal_verification_status != "not_verified"
            {
                errors.push(format!("{path} claims forbidden promotion status"));
            }
            if item.blockers.is_empty() && item.canonical_rule.is_none() {
                errors.push(format!("{path} has no blockers but no canonical_rule"));
            }
            if let Some(rule) = &item.canonical_rule {
                rule.validate(
                    evidence_root,
                    &format!("{path}.canonical_rule"),
                    &mut errors,
                );
            }
        }
        if self.summary.program_count != programs.len() {
            errors.push("summary.program_count does not match items".to_string());
        }
        if errors.is_empty() {
            Ok(PromotionQueueValidation {
                queue_id: self.queue_id.clone(),
                items_sha256: computed_hash.to_string(),
                queue_items: self.items.len(),
                program_count: programs.len(),
                runtime_eligible: 0,
            })
        } else {
            Err(errors.join("; "))
        }
    }
}

pub fn validate_promotion_queue_path(path: &Path) -> Result<PromotionQueueValidation, String> {
    PromotionQueue::from_path(path).map(|(_, validation)| validation)
}

pub fn validate_canonical_bundle_path(path: &Path) -> Result<(String, usize), String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "could not read canonical bundle {}: {error}",
            path.display()
        )
    })?;
    let value: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("invalid canonical bundle {}: {error}", path.display()))?;
    let computed_hash = hash_json_value(
        value
            .get("rules")
            .ok_or_else(|| "canonical bundle rules are missing".to_string())?,
    )?;
    let bundle: CanonicalRuleBundle = serde_json::from_value(value)
        .map_err(|error| format!("invalid canonical bundle {}: {error}", path.display()))?;
    let mut errors = Vec::new();
    if bundle.schema_version != CANONICAL_BUNDLE_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version must be {CANONICAL_BUNDLE_SCHEMA_VERSION}"
        ));
    }
    if bundle.runtime_activation || bundle.proof_binding {
        errors.push("canonical bundle must remain non-runtime and not proof bound".to_string());
    }
    if bundle.rules_sha256 != computed_hash {
        errors.push(format!("rules_sha256 mismatch: expected {computed_hash}"));
    }
    let evidence_root = evidence_root_for(path);
    let mut ids = BTreeSet::new();
    for (index, rule) in bundle.rules.iter().enumerate() {
        rule.validate(&evidence_root, &format!("rules[{index}]"), &mut errors);
        if !ids.insert(rule.rule_id.clone()) {
            errors.push(format!("duplicate rule_id {}", rule.rule_id));
        }
    }
    detect_conflicts(&bundle.rules, &mut errors);
    if errors.is_empty() {
        Ok((computed_hash, bundle.rules.len()))
    } else {
        Err(errors.join("; "))
    }
}

pub fn evaluate_promotion_queue_path(
    queue_path: &Path,
    facts_path: &Path,
) -> Result<ShadowEvaluationReport, String> {
    let (queue, _) = PromotionQueue::from_path(queue_path)?;
    let facts = RuleFactsInput::from_path(facts_path)?;
    let mut results = Vec::with_capacity(queue.items.len());
    for item in &queue.items {
        results.push(evaluate_item(item, &facts)?);
    }
    let summary = ShadowEvaluationSummary {
        queue_items: results.len(),
        matched: results
            .iter()
            .filter(|item| item.status == ShadowEvaluationStatus::Matched)
            .count(),
        not_matched: results
            .iter()
            .filter(|item| item.status == ShadowEvaluationStatus::NotMatched)
            .count(),
        not_applicable: results
            .iter()
            .filter(|item| item.status == ShadowEvaluationStatus::NotApplicable)
            .count(),
        insufficient_data: results
            .iter()
            .filter(|item| item.status == ShadowEvaluationStatus::InsufficientData)
            .count(),
    };
    Ok(ShadowEvaluationReport {
        schema_version: SHADOW_EVALUATION_SCHEMA_VERSION.to_string(),
        queue_id: queue.queue_id,
        items_sha256: queue.items_sha256,
        facts_schema_version: facts.schema_version,
        runtime_activation: false,
        proof_binding: false,
        adjudication_effect: false,
        summary,
        results,
    })
}

fn evaluate_item(
    item: &PromotionQueueItem,
    facts: &RuleFactsInput,
) -> Result<ShadowRuleResult, String> {
    let scope_mismatch = item.program != facts.program || item.jurisdiction != facts.jurisdiction;
    let date_mismatch = if let Some(rule) = &item.canonical_rule {
        !rule.applicable(facts)?
    } else if let Some(effective_from) = item.draft.effective_date_candidate.as_deref() {
        match (
            IsoDate::parse(effective_from),
            IsoDate::parse(&facts.evaluation_date),
        ) {
            (Ok(start), Ok(evaluation)) => evaluation < start,
            _ => false,
        }
    } else {
        false
    };
    if scope_mismatch || date_mismatch {
        return Ok(ShadowRuleResult {
            candidate_id: item.candidate_id.clone(),
            rule_id: item
                .canonical_rule
                .as_ref()
                .map(|rule| rule.rule_id.clone()),
            program: item.program.clone(),
            status: ShadowEvaluationStatus::NotApplicable,
            missing_facts: Vec::new(),
            reason_codes: vec!["scope_or_effective_date_mismatch".to_string()],
            outcome_preview: None,
        });
    }
    if !item.blockers.is_empty() || item.canonical_rule.is_none() {
        let missing_facts = item
            .draft
            .required_facts
            .iter()
            .map(|item| item.fact_id.clone())
            .filter(|fact| !facts.facts.contains_key(fact))
            .collect();
        return Ok(ShadowRuleResult {
            candidate_id: item.candidate_id.clone(),
            rule_id: item
                .canonical_rule
                .as_ref()
                .map(|rule| rule.rule_id.clone()),
            program: item.program.clone(),
            status: ShadowEvaluationStatus::InsufficientData,
            missing_facts,
            reason_codes: item.blockers.clone(),
            outcome_preview: None,
        });
    }
    let rule = item.canonical_rule.as_ref().expect("checked above");
    match rule.conditions.evaluate(&facts.facts) {
        ConditionResult::Matched(true) => Ok(ShadowRuleResult {
            candidate_id: item.candidate_id.clone(),
            rule_id: Some(rule.rule_id.clone()),
            program: item.program.clone(),
            status: ShadowEvaluationStatus::Matched,
            missing_facts: Vec::new(),
            reason_codes: Vec::new(),
            outcome_preview: Some(rule.outcome.clone()),
        }),
        ConditionResult::Matched(false) => Ok(ShadowRuleResult {
            candidate_id: item.candidate_id.clone(),
            rule_id: Some(rule.rule_id.clone()),
            program: item.program.clone(),
            status: ShadowEvaluationStatus::NotMatched,
            missing_facts: Vec::new(),
            reason_codes: Vec::new(),
            outcome_preview: None,
        }),
        ConditionResult::Missing(missing) => Ok(ShadowRuleResult {
            candidate_id: item.candidate_id.clone(),
            rule_id: Some(rule.rule_id.clone()),
            program: item.program.clone(),
            status: ShadowEvaluationStatus::InsufficientData,
            missing_facts: missing.into_iter().collect(),
            reason_codes: vec!["missing_fact".to_string()],
            outcome_preview: None,
        }),
        ConditionResult::TypeMismatch(fact) => Ok(ShadowRuleResult {
            candidate_id: item.candidate_id.clone(),
            rule_id: Some(rule.rule_id.clone()),
            program: item.program.clone(),
            status: ShadowEvaluationStatus::InsufficientData,
            missing_facts: vec![fact],
            reason_codes: vec!["fact_type_mismatch".to_string()],
            outcome_preview: None,
        }),
    }
}

fn compare_values(
    actual: &TypedValue,
    operator: ComparisonOperator,
    expected: &TypedValue,
) -> Result<bool, String> {
    match operator {
        ComparisonOperator::Eq => Ok(actual == expected),
        ComparisonOperator::Neq => Ok(actual != expected),
        ComparisonOperator::In | ComparisonOperator::NotIn => {
            let TypedValue::List(values) = expected else {
                return Err("membership comparison requires a list".to_string());
            };
            let contains = values.contains(actual);
            Ok(if operator == ComparisonOperator::In {
                contains
            } else {
                !contains
            })
        }
        ComparisonOperator::Contains => {
            let TypedValue::List(values) = actual else {
                return Err("contains comparison requires a list fact".to_string());
            };
            Ok(values.contains(expected))
        }
        ComparisonOperator::Lt
        | ComparisonOperator::Lte
        | ComparisonOperator::Gt
        | ComparisonOperator::Gte => {
            let ordering = match (actual, expected) {
                (TypedValue::Integer(left), TypedValue::Integer(right)) => left.cmp(right),
                (TypedValue::Decimal(left), TypedValue::Decimal(right)) => {
                    decimal_cmp(left, right)?
                }
                _ => return Err("ordered comparison requires matching numeric types".to_string()),
            };
            Ok(ordering_matches(ordering, operator))
        }
        ComparisonOperator::Before
        | ComparisonOperator::OnOrBefore
        | ComparisonOperator::After
        | ComparisonOperator::OnOrAfter => {
            let (TypedValue::Date(left), TypedValue::Date(right)) = (actual, expected) else {
                return Err("date comparison requires date operands".to_string());
            };
            let ordering = IsoDate::parse(left)?.cmp(&IsoDate::parse(right)?);
            Ok(ordering_matches(ordering, operator))
        }
    }
}

fn ordering_matches(ordering: Ordering, operator: ComparisonOperator) -> bool {
    match operator {
        ComparisonOperator::Lt | ComparisonOperator::Before => ordering == Ordering::Less,
        ComparisonOperator::Lte | ComparisonOperator::OnOrBefore => ordering != Ordering::Greater,
        ComparisonOperator::Gt | ComparisonOperator::After => ordering == Ordering::Greater,
        ComparisonOperator::Gte | ComparisonOperator::OnOrAfter => ordering != Ordering::Less,
        _ => false,
    }
}

fn decimal_cmp(left: &str, right: &str) -> Result<Ordering, String> {
    let left = normalized_decimal(left)?;
    let right = normalized_decimal(right)?;
    if left.0 != right.0 {
        return Ok(left.0.cmp(&right.0));
    }
    let magnitude = compare_decimal_magnitude((&left.1, &left.2), (&right.1, &right.2));
    Ok(if left.0 < 0 {
        magnitude.reverse()
    } else {
        magnitude
    })
}

fn normalized_decimal(value: &str) -> Result<(i8, String, String), String> {
    if !valid_decimal(value) {
        return Err("invalid decimal".to_string());
    }
    let (sign, unsigned) = value
        .strip_prefix('-')
        .map_or((1, value), |unsigned| (-1, unsigned));
    let (integer, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer };
    let fraction = fraction.trim_end_matches('0');
    if integer == "0" && fraction.is_empty() {
        Ok((0, "0".to_string(), String::new()))
    } else {
        Ok((sign, integer.to_string(), fraction.to_string()))
    }
}

fn compare_decimal_magnitude(left: (&str, &str), right: (&str, &str)) -> Ordering {
    match left.0.len().cmp(&right.0.len()) {
        Ordering::Equal => match left.0.cmp(right.0) {
            Ordering::Equal => {
                let width = left.1.len().max(right.1.len());
                let left_fraction = format!("{:<width$}", left.1, width = width).replace(' ', "0");
                let right_fraction =
                    format!("{:<width$}", right.1, width = width).replace(' ', "0");
                left_fraction.cmp(&right_fraction)
            }
            other => other,
        },
        other => other,
    }
}

fn valid_decimal(value: &str) -> bool {
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    if unsigned.is_empty() {
        return false;
    }
    let mut parts = unsigned.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || (integer.len() > 1 && integer.starts_with('0'))
    {
        return false;
    }
    fraction
        .is_none_or(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn canonical_rule_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    chars.all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '_' | ':' | '-')
            || character == '.'
    })
}

fn canonical_simple_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

fn canonical_fact_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '.')
        })
        && !value.contains("..")
        && !value.ends_with('.')
}

fn valid_semver(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && !parts[0].starts_with('0')
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_jurisdiction(jurisdiction: &Jurisdiction, path: &str, errors: &mut Vec<String>) {
    if jurisdiction.country != "US" {
        errors.push(format!("{path}.country must be US"));
    }
    if !ALLOWED_JURISDICTION_LEVELS.contains(&jurisdiction.level.as_str()) {
        errors.push(format!("{path}.level is unsupported"));
    }
    if matches!(jurisdiction.level.as_str(), "state" | "local")
        && jurisdiction.state.as_deref().is_none_or(|state| {
            state.len() != 2 || !state.bytes().all(|byte| byte.is_ascii_uppercase())
        })
    {
        errors.push(format!("{path}.state is required for state/local rules"));
    }
}

fn validate_draft_jurisdiction(jurisdiction: &Jurisdiction, path: &str, errors: &mut Vec<String>) {
    if jurisdiction.country != "US" {
        errors.push(format!("{path}.country must be US"));
    }
    if !ALLOWED_JURISDICTION_LEVELS.contains(&jurisdiction.level.as_str()) {
        errors.push(format!("{path}.level is unsupported"));
    }
    if let Some(state) = &jurisdiction.state
        && (state.len() != 2 || !state.bytes().all(|byte| byte.is_ascii_uppercase()))
    {
        errors.push(format!(
            "{path}.state must use a two-letter code when present"
        ));
    }
}

fn validate_source(
    source: &RuleSource,
    evidence_root: &Path,
    path: &str,
    errors: &mut Vec<String>,
) {
    if !source.url.starts_with("https://") || source.url.len() <= "https://".len() {
        errors.push(format!("{path}.url must use HTTPS"));
    }
    if source.citation_text.trim().is_empty() {
        errors.push(format!("{path}.citation_text is required"));
    }
    if source.sha256.len() != 64
        || !source
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        errors.push(format!("{path}.sha256 must be a lowercase SHA-256 digest"));
        return;
    }
    let artifact = Path::new(&source.artifact_path);
    if artifact.is_absolute()
        || artifact
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        errors.push(format!("{path}.artifact_path must be a safe relative path"));
        return;
    }
    let joined = evidence_root.join(artifact);
    let root = match evidence_root.canonicalize() {
        Ok(value) => value,
        Err(_) => {
            errors.push(format!(
                "{path}.artifact_path evidence directory is missing"
            ));
            return;
        }
    };
    let resolved = match joined.canonicalize() {
        Ok(value) => value,
        Err(_) => {
            errors.push(format!("{path}.artifact_path does not exist"));
            return;
        }
    };
    if !resolved.starts_with(&root) || !resolved.is_file() {
        errors.push(format!(
            "{path}.artifact_path escapes the evidence directory"
        ));
        return;
    }
    match fs::read(&resolved) {
        Ok(bytes) => {
            let computed = hex::encode(Sha256::digest(bytes));
            if computed != source.sha256 {
                errors.push(format!("{path}.sha256 does not match exact evidence bytes"));
            }
        }
        Err(error) => errors.push(format!("{path}.artifact_path could not be read: {error}")),
    }
}

fn evidence_root_for(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.file_name().is_some_and(|name| name == "reports") {
        parent
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("evidence")
    } else {
        parent.join("evidence")
    }
}

fn hash_json_value(value: &Value) -> Result<String, String> {
    let canonical = serde_json::to_vec(value)
        .map_err(|error| format!("could not canonicalize JSON for hashing: {error}"))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

fn detect_conflicts(rules: &[CanonicalGovernmentRule], errors: &mut Vec<String>) {
    for (left_index, left) in rules.iter().enumerate() {
        for right in &rules[left_index + 1..] {
            if left.program != right.program
                || left.jurisdiction != right.jurisdiction
                || left.conditions != right.conditions
                || left.outcome == right.outcome
            {
                continue;
            }
            let Ok(left_start) = IsoDate::parse(&left.effective_from) else {
                continue;
            };
            let Ok(right_start) = IsoDate::parse(&right.effective_from) else {
                continue;
            };
            let left_end = left
                .effective_through
                .as_deref()
                .and_then(|value| IsoDate::parse(value).ok());
            let right_end = right
                .effective_through
                .as_deref()
                .and_then(|value| IsoDate::parse(value).ok());
            let overlaps = left_end.is_none_or(|end| right_start <= end)
                && right_end.is_none_or(|end| left_start <= end);
            if overlaps {
                errors.push(format!(
                    "conflicting duplicate rules {} and {}",
                    left.rule_id, right.rule_id
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn federal() -> Jurisdiction {
        Jurisdiction {
            country: "US".to_string(),
            level: "federal".to_string(),
            state: None,
            locality: None,
        }
    }

    fn canonical_rule() -> CanonicalGovernmentRule {
        CanonicalGovernmentRule {
            schema_version: CANONICAL_RULE_SCHEMA_VERSION.to_string(),
            rule_id: "test:eligibility".to_string(),
            version: "1.0.0".to_string(),
            program: "medicaid".to_string(),
            jurisdiction: federal(),
            authority: RuleAuthority {
                issuer: "CMS".to_string(),
                level: "federal".to_string(),
                citation: "42 CFR 435.1".to_string(),
            },
            rule_type: "eligibility_rule".to_string(),
            conditions: CanonicalCondition::Compare {
                fact: "eligibility_active".to_string(),
                fact_type: FactType::Boolean,
                operator: ComparisonOperator::Eq,
                value: TypedValue::Boolean(true),
            },
            outcome: DeterministicOutcome {
                kind: "decision".to_string(),
                code: "decision.eligible".to_string(),
                parameters: BTreeMap::new(),
            },
            effective_from: "2026-01-01".to_string(),
            effective_through: None,
            source: RuleSource {
                url: "https://www.medicaid.gov/fixture".to_string(),
                citation_text: "Eligibility is active.".to_string(),
                artifact_path: "fixture.txt".to_string(),
                sha256: "0".repeat(64),
            },
            review_status: "approved".to_string(),
            legal_verification_status: "verified".to_string(),
            runtime_eligibility_status: "shadow_only".to_string(),
        }
    }

    fn temp_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "localbce-advanced-rules-{}-{nonce}",
            std::process::id()
        ))
    }

    fn queue_item(
        rule: Option<CanonicalGovernmentRule>,
        blockers: Vec<&str>,
    ) -> PromotionQueueItem {
        PromotionQueueItem {
            candidate_id: "candidate:test".to_string(),
            program: "medicaid".to_string(),
            jurisdiction: federal(),
            rule_type: "eligibility_rule".to_string(),
            source: QueueSource {
                url: "https://www.medicaid.gov/fixture".to_string(),
                citation_text: "Eligibility is active.".to_string(),
                artifact_path: None,
                sha256: None,
            },
            draft: RuleDraft {
                operator_category: Some("determine_eligibility".to_string()),
                required_facts: vec![RequiredFactDraft {
                    fact_id: "eligibility_active".to_string(),
                    suggested_type: Some("boolean".to_string()),
                }],
                threshold_candidate: None,
                effective_date_candidate: Some("2026-01-01".to_string()),
                outcome_kind_candidate: Some("decision".to_string()),
                condition_source_text: "Eligibility is active.".to_string(),
                mapping_status: "typed_complete".to_string(),
            },
            canonical_rule: rule,
            blockers: blockers.into_iter().map(str::to_string).collect(),
            review_status: "machine_reviewed".to_string(),
            legal_verification_status: "not_verified".to_string(),
            runtime_eligibility_status: "blocked".to_string(),
        }
    }

    fn facts(value: Option<TypedValue>) -> RuleFactsInput {
        let mut facts = BTreeMap::new();
        if let Some(value) = value {
            facts.insert("eligibility_active".to_string(), value);
        }
        RuleFactsInput {
            schema_version: RULE_FACTS_SCHEMA_VERSION.to_string(),
            program: "medicaid".to_string(),
            jurisdiction: federal(),
            evaluation_date: "2026-08-05".to_string(),
            facts,
        }
    }

    #[test]
    fn decimal_comparison_is_exact_without_float_conversion() {
        assert_eq!(decimal_cmp("1.10", "1.1"), Ok(Ordering::Equal));
        assert_eq!(
            decimal_cmp("999999999999999999999.9", "1000000000000000000000"),
            Ok(Ordering::Less)
        );
        assert_eq!(decimal_cmp("-2.0", "-1.99"), Ok(Ordering::Less));
    }

    #[test]
    fn iso_date_rejects_nonexistent_dates() {
        assert!(IsoDate::parse("2025-02-29").is_err());
        assert!(IsoDate::parse("2024-02-29").is_ok());
        assert!(IsoDate::parse("June 3, 2024").is_err());
    }

    #[test]
    fn shadow_evaluator_returns_matched_and_not_matched() {
        let item = queue_item(Some(canonical_rule()), Vec::new());
        let matched = evaluate_item(&item, &facts(Some(TypedValue::Boolean(true)))).unwrap();
        assert_eq!(matched.status, ShadowEvaluationStatus::Matched);
        assert!(matched.outcome_preview.is_some());

        let not_matched = evaluate_item(&item, &facts(Some(TypedValue::Boolean(false)))).unwrap();
        assert_eq!(not_matched.status, ShadowEvaluationStatus::NotMatched);
        assert!(not_matched.outcome_preview.is_none());
    }

    #[test]
    fn shadow_evaluator_returns_not_applicable_for_program_or_date() {
        let item = queue_item(Some(canonical_rule()), Vec::new());
        let mut wrong_program = facts(Some(TypedValue::Boolean(true)));
        wrong_program.program = "medicare".to_string();
        assert_eq!(
            evaluate_item(&item, &wrong_program).unwrap().status,
            ShadowEvaluationStatus::NotApplicable
        );

        let mut expired_rule = canonical_rule();
        expired_rule.effective_through = Some("2026-06-30".to_string());
        let expired = queue_item(Some(expired_rule), Vec::new());
        assert_eq!(
            evaluate_item(&expired, &facts(Some(TypedValue::Boolean(true))))
                .unwrap()
                .status,
            ShadowEvaluationStatus::NotApplicable
        );
    }

    #[test]
    fn shadow_evaluator_returns_insufficient_for_missing_or_wrong_type_facts() {
        let item = queue_item(Some(canonical_rule()), Vec::new());
        let missing = evaluate_item(&item, &facts(None)).unwrap();
        assert_eq!(missing.status, ShadowEvaluationStatus::InsufficientData);
        assert_eq!(missing.missing_facts, vec!["eligibility_active"]);
        assert_eq!(missing.reason_codes, vec!["missing_fact"]);

        let wrong_type =
            evaluate_item(&item, &facts(Some(TypedValue::String("true".to_string())))).unwrap();
        assert_eq!(wrong_type.status, ShadowEvaluationStatus::InsufficientData);
        assert_eq!(wrong_type.reason_codes, vec!["fact_type_mismatch"]);
    }

    #[test]
    fn blocked_draft_is_non_binding_insufficient_data() {
        let item = queue_item(
            None,
            vec!["ambiguous_free_text_condition", "legal_not_verified"],
        );
        let result = evaluate_item(&item, &facts(Some(TypedValue::Boolean(true)))).unwrap();
        assert_eq!(result.status, ShadowEvaluationStatus::InsufficientData);
        assert_eq!(
            result.reason_codes,
            vec!["ambiguous_free_text_condition", "legal_not_verified"]
        );
        assert!(result.outcome_preview.is_none());

        let mut wrong_program = facts(Some(TypedValue::Boolean(true)));
        wrong_program.program = "medicare".to_string();
        let out_of_scope = evaluate_item(&item, &wrong_program).unwrap();
        assert_eq!(out_of_scope.status, ShadowEvaluationStatus::NotApplicable);
        assert_eq!(
            out_of_scope.reason_codes,
            vec!["scope_or_effective_date_mismatch"]
        );
    }

    #[test]
    fn malformed_condition_operator_and_free_text_are_rejected() {
        let unsupported = serde_json::json!({
            "op": "compare",
            "fact": "income",
            "fact_type": "decimal",
            "operator": "approximately",
            "value": {"type": "decimal", "value": "100"}
        });
        assert!(serde_json::from_value::<CanonicalCondition>(unsupported).is_err());

        let free_text = serde_json::json!({
            "op": "compare",
            "fact": "income",
            "fact_type": "decimal",
            "operator": "lte",
            "value": {"type": "decimal", "value": "100"},
            "condition_text": "income should usually be low"
        });
        assert!(serde_json::from_value::<CanonicalCondition>(free_text).is_err());

        let membership = CanonicalCondition::Compare {
            fact: "age".to_string(),
            fact_type: FactType::Integer,
            operator: ComparisonOperator::In,
            value: TypedValue::List(vec![TypedValue::String("18".to_string())]),
        };
        let mut errors = Vec::new();
        membership.validate("conditions", &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("membership value type must match fact_type"))
        );
    }

    #[test]
    fn malformed_promotion_queue_rejects_unknown_fields() {
        let queue = serde_json::json!({
            "schema_version": PROMOTION_QUEUE_SCHEMA_VERSION,
            "queue_id": "queue:test",
            "items_sha256": "0".repeat(64),
            "runtime_activation": false,
            "proof_binding": false,
            "warning": "non-runtime",
            "summary": {
                "source_candidates": 0,
                "promotion_review_records": 0,
                "mapping_records": 0,
                "qa_pass_records": 0,
                "program_count": 0,
                "programs": [],
                "queue_items": 0,
                "runtime_eligible": 0,
                "by_blocker": {}
            },
            "items": [],
            "unexpected": true
        });
        assert!(serde_json::from_value::<PromotionQueue>(queue).is_err());
    }

    #[test]
    fn canonical_json_hash_is_independent_of_input_key_order() {
        let left: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        let right: Value = serde_json::from_str(r#"{"a":1,"b":2}"#).unwrap();
        assert_eq!(hash_json_value(&left), hash_json_value(&right));
    }

    #[test]
    fn canonical_bundle_validates_exact_evidence_bytes_and_rejects_tampering() {
        let root = temp_root();
        let reports = root.join("reports");
        let evidence = root.join("evidence");
        fs::create_dir_all(&reports).unwrap();
        fs::create_dir_all(&evidence).unwrap();
        let bytes = b"Official source fixture\n";
        fs::write(evidence.join("fixture.txt"), bytes).unwrap();

        let mut rule = canonical_rule();
        rule.source.sha256 = hex::encode(Sha256::digest(bytes));
        let rules = vec![rule];
        let rules_value = serde_json::to_value(&rules).unwrap();
        let bundle = CanonicalRuleBundle {
            schema_version: CANONICAL_BUNDLE_SCHEMA_VERSION.to_string(),
            bundle_id: "test:bundle".to_string(),
            rules_sha256: hash_json_value(&rules_value).unwrap(),
            runtime_activation: false,
            proof_binding: false,
            rules,
        };
        let path = reports.join("bundle.json");
        fs::write(&path, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
        assert!(validate_canonical_bundle_path(&path).is_ok());

        fs::write(evidence.join("fixture.txt"), b"tampered\n").unwrap();
        assert!(
            validate_canonical_bundle_path(&path)
                .unwrap_err()
                .contains("does not match exact evidence bytes")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_bundle_rejects_overlapping_conflicting_outcomes() {
        let mut left = canonical_rule();
        left.rule_id = "test:left".to_string();
        let mut right = canonical_rule();
        right.rule_id = "test:right".to_string();
        right.outcome.code = "decision.ineligible".to_string();
        let mut errors = Vec::new();
        detect_conflicts(&[left, right], &mut errors);
        assert_eq!(
            errors,
            vec!["conflicting duplicate rules test:left and test:right"]
        );
    }
}
