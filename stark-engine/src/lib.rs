//! First-class STARK compatibility wrapper for localBCE.
//!
//! This crate is intentionally non-runtime today. It does not import the
//! Winterfell proof-of-concept from `blind-ledger-app-layer/zk-stark`, and it is
//! not wired into `rust-engine`.
//!
//! Its first job is to document and test the bridge assumptions between the
//! active Rust adjudication model and the imported Winterfell STARK input model.

use serde::{Deserialize, Serialize};

/// Mapping quality from the active Rust claim model into the imported
/// Winterfell STARK proof-of-concept input model.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingClass {
    /// The active Rust field has the same fact and pass/fail meaning.
    Direct,
    /// The active Rust field is related but not semantically equivalent.
    Partial,
    /// The active Rust model does not currently contain this fact.
    Unmapped,
}

/// One bridge row from an imported Winterfell STARK input field to the current
/// active Rust adjudication source field or fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldMapping {
    pub imported_stark_field: &'static str,
    pub active_rust_source: Option<&'static str>,
    pub class: MappingClass,
    pub note: &'static str,
}

/// Documented compatibility bridge between:
///
/// - active `rust-engine::ClaimInput`
/// - imported `blind-ledger-app-layer/zk-stark::ClaimInput`
///
/// This is not a runtime adapter yet. It exists to prevent accidental claims
/// that the imported STARK proof system already proves the exact active
/// adjudication semantics.
pub struct ActiveClaimToStarkBridge;

/// Typed JSON data contract produced by `rust-engine` and consumed by
/// `stark-engine`.
///
/// This is a bridge input, not a proof artifact. It explicitly carries both the
/// active Rust facts and the current compatibility status against the imported
/// Winterfell proof-of-concept model.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkBridgeInput {
    pub schema_version: String,
    pub producer: String,
    pub purpose: String,
    pub runtime_mode: String,
    pub claim: BridgeClaim,
    pub adjudication: BridgeAdjudication,
    pub active_rust_facts: ActiveRustFacts,
    pub winterfell_poc_mapping: WinterfellPocMapping,
    pub public_inputs: BridgePublicInputs,
    pub proof_status: BridgeProofStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeClaim {
    pub claim_id: String,
    pub claim_amount: u64,
    pub claim_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeAdjudication {
    pub decision: u8,
    pub failure_code: u32,
    pub failure_reason: Option<String>,
    pub ruleset_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActiveRustFacts {
    pub eligibility_active: u8,
    pub aid_code: u64,
    pub benefit_level_exists: u8,
    pub date_of_service_from: u64,
    pub eligibility_period_from: u64,
    pub eligibility_period_thru: u64,
    pub soc_amount: u64,
    pub soc_met: u8,
    pub provider_enrolled: u8,
    pub provider_type_valid: u8,
    pub billing_code_valid: u8,
    pub units_valid: u8,
    pub is_duplicate: u8,
    pub disability_determination_valid: u8,
    pub recipient_not_deceased: u8,
    pub physician_certification_valid: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellPocMapping {
    pub direct: WinterfellDirectMapping,
    pub partial: WinterfellPartialMapping,
    pub unmapped: WinterfellUnmappedMapping,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellDirectMapping {
    pub eligibility_active: u8,
    pub provider_enrolled: u8,
    pub duplicate_flag: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellPartialMapping {
    pub service_line_count: PartialMappingEvidence,
    pub prior_auth_ok: PartialMappingEvidence,
    pub charge_cents: PartialMappingEvidence,
    pub program_integrity_hold: PartialMappingEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PartialMappingEvidence {
    pub source: Vec<String>,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellUnmappedMapping {
    pub member_id: Option<u64>,
    pub provider_npi: Option<u64>,
    pub diagnosis_count: Option<u64>,
    pub max_charge_cents: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgePublicInputs {
    pub claim_hash: String,
    pub decision: u8,
    pub failure_code: u32,
    pub ruleset_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeProofStatus {
    pub stark_proof_generated: bool,
    pub winterfell_poc_compatible: bool,
    pub groth16_flow_unchanged: bool,
    pub on_chain_submission: bool,
}

/// Normalized pre-proof intent produced from a validated bridge input.
///
/// This is the last object before a future prover-specific witness adapter. It
/// is intentionally not a Winterfell, Cairo, or Plonky input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkProofIntent {
    pub schema_version: String,
    pub source_schema_version: String,
    pub intent_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub decision: u8,
    pub failure_code: u32,
    pub failure_reason: Option<String>,
    pub ruleset_id: String,
    pub direct_facts: StarkProofDirectFacts,
    pub proof_readiness: StarkProofReadiness,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkProofDirectFacts {
    pub eligibility_active: u8,
    pub provider_enrolled: u8,
    pub duplicate_flag: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkProofReadiness {
    pub bridge_validated: bool,
    pub prover_selected: bool,
    pub witness_generated: bool,
    pub proof_generated: bool,
    pub on_chain_submission: bool,
}

/// Deterministic witness planning object produced from a proof intent.
///
/// This is not a generated witness and does not contain a prover trace. It
/// names the constraint groups a future STARK prover adapter must satisfy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkWitnessPlan {
    pub schema_version: String,
    pub source_schema_version: String,
    pub claim_hash: String,
    pub decision: u8,
    pub failure_code: u32,
    pub direct_facts: StarkProofDirectFacts,
    pub constraint_groups: Vec<StarkConstraintGroup>,
    pub witness_status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkConstraintGroup {
    pub group_id: String,
    pub constraints: Vec<String>,
}

/// Deterministic non-cryptographic trace preview derived from a validated
/// witness plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkMockTrace {
    pub schema_version: String,
    pub source_schema_version: String,
    pub claim_hash: String,
    pub rows: Vec<StarkMockTraceRow>,
    pub trace_status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkMockTraceRow {
    pub step_index: usize,
    pub constraint_group: String,
    pub constraint_name: String,
    pub input_value: String,
    pub expected_value: String,
    pub satisfied: bool,
}

/// Static compatibility report between a localBCE mock trace and the imported
/// Winterfell PoC input/constraint shape.
///
/// This report does not import or execute Winterfell. It is an adapter planning
/// artifact that prevents confusing the mock trace with a real prover trace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellPocCompatibilityReport {
    pub schema_version: String,
    pub source_schema_version: String,
    pub verdict: String,
    pub mock_trace_rows: usize,
    pub all_mock_rows_satisfied: bool,
    pub imported_winterfell_input_fields: Vec<String>,
    pub direct_compatible_fields: Vec<WinterfellPocFieldCompatibility>,
    pub partial_fields: Vec<WinterfellPocFieldCompatibility>,
    pub unmapped_fields: Vec<WinterfellPocFieldCompatibility>,
    pub required_mock_constraint_groups_present: bool,
    pub unsupported_winterfell_constraints: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellPocFieldCompatibility {
    pub imported_stark_field: String,
    pub active_rust_source: Option<String>,
    pub compatibility: String,
    pub note: String,
}

/// Concrete implementation checklist derived from a Winterfell PoC
/// compatibility report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellAdapterGapPlan {
    pub schema_version: String,
    pub source_schema_version: String,
    pub plan_status: String,
    pub direct_ready_fields: Vec<WinterfellPocFieldCompatibility>,
    pub partial_fields_requiring_normalization: Vec<WinterfellPocFieldCompatibility>,
    pub unmapped_fields_requiring_source_data: Vec<WinterfellPocFieldCompatibility>,
    pub unsupported_constraints_requiring_prover_work: Vec<String>,
    pub recommended_next_steps: Vec<String>,
}

/// Test-only compatibility plan for the target batch-root/public-input layer.
///
/// This intentionally does not compute Merkle roots, Poseidon hashes, or
/// governed-root commitments. It documents which target batch public inputs can
/// be derived from today's `StarkBridgeInput`, and which require upstream data
/// that the active Groth16 prototype does not yet export.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchRootCompatibilityPlan {
    pub schema_version: String,
    pub source_schema_version: String,
    pub plan_status: String,
    pub target_fields: Vec<BatchRootFieldMapping>,
    pub counts: MappingCounts,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchRootFieldMapping {
    pub target_field: String,
    pub active_bridge_source: Option<String>,
    pub class: MappingClass,
    pub note: String,
}

/// Implementation checklist derived from a batch-root compatibility plan.
///
/// This is still a planning artifact. It deliberately separates ready fields,
/// normalization work, missing source data, and future root/prover work so the
/// active Groth16 prototype is not accidentally treated as batch-root capable.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BatchRootGapReport {
    pub schema_version: String,
    pub source_schema_version: String,
    pub report_status: String,
    pub direct_ready_fields: Vec<BatchRootFieldMapping>,
    pub partial_fields_requiring_normalization: Vec<BatchRootFieldMapping>,
    pub unmapped_fields_requiring_source_data: Vec<BatchRootFieldMapping>,
    pub unsupported_root_generation_tasks: Vec<String>,
    pub recommended_next_steps: Vec<String>,
}

/// Typed source data for a future `claimSourceRoot`.
///
/// This object is intentionally pre-root. It validates the source fields needed
/// to build a future claim-source leaf/root, but it does not hash, sort, or
/// construct a Merkle tree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimSourceRootInput {
    pub schema_version: String,
    pub source_schema_version: String,
    pub input_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub claim_amount: u64,
    pub member_id: Option<String>,
    pub provider_npi: Option<String>,
    pub service_date: Option<u64>,
    pub procedure_codes: Vec<String>,
    pub diagnosis_codes: Vec<String>,
    pub service_line_count: Option<u64>,
    pub root_generation_status: String,
    pub notes: Vec<String>,
}

/// One normalized oracle fact that can eventually feed an `oracleFactsRoot`.
///
/// These are source facts only. They are not trusted, committed, or proven by
/// this crate until a future oracle attestation and root-generation phase.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleFactInput {
    pub fact_type: String,
    pub fact_key: String,
    pub fact_value: String,
    pub source_url: Option<String>,
    pub source_label: Option<String>,
    pub verification_status: String,
}

/// Typed source data for a future `oracleFactsRoot`.
///
/// This object is intentionally pre-root. It records the source shape needed by
/// a future oracle-facts tree, but it does not fetch, attest, hash, or build a
/// Merkle root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleFactsRootInput {
    pub schema_version: String,
    pub source_schema_version: String,
    pub input_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub source_manifest_id: Option<String>,
    pub facts: Vec<OracleFactInput>,
    pub attestation_refs: Vec<String>,
    pub root_generation_status: String,
    pub notes: Vec<String>,
}

impl StarkBridgeInput {
    pub const SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const PRODUCER: &'static str = "rust-engine";
    pub const EXPECTED_MAPPING_COUNTS: MappingCounts = MappingCounts {
        direct: 3,
        partial: 4,
        unmapped: 4,
    };

    pub fn mapping_counts(&self) -> MappingCounts {
        MappingCounts {
            direct: 3,
            partial: 4,
            unmapped: 4,
        }
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {}, got {}",
                Self::SCHEMA_VERSION,
                self.schema_version
            ));
        }

        if self.producer != Self::PRODUCER {
            errors.push(format!(
                "producer must be {}, got {}",
                Self::PRODUCER,
                self.producer
            ));
        }

        if self.claim.claim_hash.trim().is_empty() {
            errors.push("claim.claim_hash must be present".to_string());
        }

        if self.public_inputs.claim_hash.trim().is_empty() {
            errors.push("public_inputs.claim_hash must be present".to_string());
        }

        if !self.claim.claim_hash.trim().is_empty()
            && !self.public_inputs.claim_hash.trim().is_empty()
            && self.claim.claim_hash != self.public_inputs.claim_hash
        {
            errors.push("claim.claim_hash must match public_inputs.claim_hash".to_string());
        }

        if self.adjudication.decision > 1 {
            errors.push(format!(
                "adjudication.decision must be 0 or 1, got {}",
                self.adjudication.decision
            ));
        }

        if self.public_inputs.decision > 1 {
            errors.push(format!(
                "public_inputs.decision must be 0 or 1, got {}",
                self.public_inputs.decision
            ));
        }

        if self.adjudication.decision <= 1
            && self.public_inputs.decision <= 1
            && self.adjudication.decision != self.public_inputs.decision
        {
            errors.push("adjudication.decision must match public_inputs.decision".to_string());
        }

        if self.mapping_counts() != Self::EXPECTED_MAPPING_COUNTS {
            errors.push(format!(
                "mapping counts must be direct={}, partial={}, unmapped={}",
                Self::EXPECTED_MAPPING_COUNTS.direct,
                Self::EXPECTED_MAPPING_COUNTS.partial,
                Self::EXPECTED_MAPPING_COUNTS.unmapped
            ));
        }

        if self.proof_status.stark_proof_generated {
            errors.push("proof_status.stark_proof_generated must be false".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn to_proof_intent(&self) -> Result<StarkProofIntent, Vec<String>> {
        self.validate()?;

        Ok(StarkProofIntent {
            schema_version: "stark-proof-intent-v0".to_string(),
            source_schema_version: self.schema_version.clone(),
            intent_status: "validated_no_prover_selected".to_string(),
            claim_id: self.claim.claim_id.clone(),
            claim_hash: self.claim.claim_hash.clone(),
            decision: self.adjudication.decision,
            failure_code: self.adjudication.failure_code,
            failure_reason: self.adjudication.failure_reason.clone(),
            ruleset_id: self.adjudication.ruleset_id.clone(),
            direct_facts: StarkProofDirectFacts {
                eligibility_active: self.winterfell_poc_mapping.direct.eligibility_active,
                provider_enrolled: self.winterfell_poc_mapping.direct.provider_enrolled,
                duplicate_flag: self.winterfell_poc_mapping.direct.duplicate_flag,
            },
            proof_readiness: StarkProofReadiness {
                bridge_validated: true,
                prover_selected: false,
                witness_generated: false,
                proof_generated: false,
                on_chain_submission: false,
            },
        })
    }
}

impl StarkProofIntent {
    pub fn to_witness_plan(&self) -> StarkWitnessPlan {
        StarkWitnessPlan {
            schema_version: "stark-witness-plan-v0".to_string(),
            source_schema_version: self.schema_version.clone(),
            claim_hash: self.claim_hash.clone(),
            decision: self.decision,
            failure_code: self.failure_code,
            direct_facts: self.direct_facts.clone(),
            constraint_groups: vec![
                StarkConstraintGroup {
                    group_id: "public_adjudication_inputs".to_string(),
                    constraints: vec![
                        "claim_hash_is_public_input".to_string(),
                        "decision_is_public_input".to_string(),
                        "failure_code_is_public_input".to_string(),
                    ],
                },
                StarkConstraintGroup {
                    group_id: "direct_fact_constraints".to_string(),
                    constraints: vec![
                        "eligibility_active_is_boolean".to_string(),
                        "provider_enrolled_is_boolean".to_string(),
                        "duplicate_flag_is_boolean".to_string(),
                    ],
                },
                StarkConstraintGroup {
                    group_id: "decision_consistency".to_string(),
                    constraints: vec![
                        "approved_claim_requires_no_failure_code".to_string(),
                        "denied_claim_requires_failure_code".to_string(),
                    ],
                },
            ],
            witness_status: "planned_not_generated".to_string(),
        }
    }
}

impl StarkWitnessPlan {
    pub const SCHEMA_VERSION: &'static str = "stark-witness-plan-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-proof-intent-v0";
    pub const WITNESS_STATUS: &'static str = "planned_not_generated";
    pub const REQUIRED_CONSTRAINT_GROUPS: [&'static str; 3] = [
        "public_adjudication_inputs",
        "direct_fact_constraints",
        "decision_consistency",
    ];

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {}, got {}",
                Self::SCHEMA_VERSION,
                self.schema_version
            ));
        }

        if self.source_schema_version != Self::SOURCE_SCHEMA_VERSION {
            errors.push(format!(
                "source_schema_version must be {}, got {}",
                Self::SOURCE_SCHEMA_VERSION,
                self.source_schema_version
            ));
        }

        if self.claim_hash.trim().is_empty() {
            errors.push("claim_hash must be present".to_string());
        }

        if self.decision > 1 {
            errors.push(format!("decision must be 0 or 1, got {}", self.decision));
        }

        if self.decision == 1 && self.failure_code != 0 {
            errors.push("approved claim requires failure_code = 0".to_string());
        }

        if self.decision == 0 && self.failure_code == 0 {
            errors.push("denied claim requires failure_code != 0".to_string());
        }

        validate_boolean_fact(
            "direct_facts.eligibility_active",
            self.direct_facts.eligibility_active,
            &mut errors,
        );
        validate_boolean_fact(
            "direct_facts.provider_enrolled",
            self.direct_facts.provider_enrolled,
            &mut errors,
        );
        validate_boolean_fact(
            "direct_facts.duplicate_flag",
            self.direct_facts.duplicate_flag,
            &mut errors,
        );

        for required_group in Self::REQUIRED_CONSTRAINT_GROUPS {
            if !self
                .constraint_groups
                .iter()
                .any(|group| group.group_id == required_group)
            {
                errors.push(format!(
                    "missing required constraint group: {required_group}"
                ));
            }
        }

        if self.witness_status != Self::WITNESS_STATUS {
            errors.push(format!(
                "witness_status must be {}, got {}",
                Self::WITNESS_STATUS,
                self.witness_status
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn to_mock_trace(&self) -> Result<StarkMockTrace, Vec<String>> {
        self.validate()?;

        let mut rows = Vec::new();
        push_mock_trace_row(
            &mut rows,
            "public_adjudication_inputs",
            "claim_hash_is_public_input",
            self.claim_hash.clone(),
            "non_empty_0x_prefixed_hash".to_string(),
            self.claim_hash.starts_with("0x") && self.claim_hash.len() > 2,
        );
        push_mock_trace_row(
            &mut rows,
            "public_adjudication_inputs",
            "decision_is_public_input",
            self.decision.to_string(),
            "0_or_1".to_string(),
            self.decision <= 1,
        );
        push_mock_trace_row(
            &mut rows,
            "public_adjudication_inputs",
            "failure_code_is_public_input",
            self.failure_code.to_string(),
            "u32_failure_code".to_string(),
            true,
        );
        push_mock_trace_row(
            &mut rows,
            "direct_fact_constraints",
            "eligibility_active_is_boolean",
            self.direct_facts.eligibility_active.to_string(),
            "0_or_1".to_string(),
            self.direct_facts.eligibility_active <= 1,
        );
        push_mock_trace_row(
            &mut rows,
            "direct_fact_constraints",
            "provider_enrolled_is_boolean",
            self.direct_facts.provider_enrolled.to_string(),
            "0_or_1".to_string(),
            self.direct_facts.provider_enrolled <= 1,
        );
        push_mock_trace_row(
            &mut rows,
            "direct_fact_constraints",
            "duplicate_flag_is_boolean",
            self.direct_facts.duplicate_flag.to_string(),
            "0_or_1".to_string(),
            self.direct_facts.duplicate_flag <= 1,
        );
        push_mock_trace_row(
            &mut rows,
            "decision_consistency",
            "approved_claim_requires_no_failure_code",
            format!(
                "decision={},failure_code={}",
                self.decision, self.failure_code
            ),
            "decision_1_implies_failure_code_0".to_string(),
            self.decision != 1 || self.failure_code == 0,
        );
        push_mock_trace_row(
            &mut rows,
            "decision_consistency",
            "denied_claim_requires_failure_code",
            format!(
                "decision={},failure_code={}",
                self.decision, self.failure_code
            ),
            "decision_0_implies_failure_code_nonzero".to_string(),
            self.decision != 0 || self.failure_code != 0,
        );

        Ok(StarkMockTrace {
            schema_version: "stark-mock-trace-v0".to_string(),
            source_schema_version: self.schema_version.clone(),
            claim_hash: self.claim_hash.clone(),
            rows,
            trace_status: "mock_trace_generated_no_proof".to_string(),
        })
    }
}

impl StarkMockTrace {
    pub const SCHEMA_VERSION: &'static str = "stark-mock-trace-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-witness-plan-v0";
    pub const TRACE_STATUS: &'static str = "mock_trace_generated_no_proof";
    pub const REQUIRED_CONSTRAINT_NAMES: [&'static str; 8] = [
        "claim_hash_is_public_input",
        "decision_is_public_input",
        "failure_code_is_public_input",
        "eligibility_active_is_boolean",
        "provider_enrolled_is_boolean",
        "duplicate_flag_is_boolean",
        "approved_claim_requires_no_failure_code",
        "denied_claim_requires_failure_code",
    ];

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {}, got {}",
                Self::SCHEMA_VERSION,
                self.schema_version
            ));
        }

        if self.source_schema_version != Self::SOURCE_SCHEMA_VERSION {
            errors.push(format!(
                "source_schema_version must be {}, got {}",
                Self::SOURCE_SCHEMA_VERSION,
                self.source_schema_version
            ));
        }

        if self.claim_hash.trim().is_empty() {
            errors.push("claim_hash must be present".to_string());
        }

        if self.rows.is_empty() {
            errors.push("rows must be non-empty".to_string());
        }

        for (expected_index, row) in self.rows.iter().enumerate() {
            if row.step_index != expected_index {
                errors.push(format!(
                    "row {} step_index must be {}, got {}",
                    expected_index, expected_index, row.step_index
                ));
            }

            if row.constraint_group.trim().is_empty() {
                errors.push(format!("row {expected_index} constraint_group must be present"));
            }

            if row.constraint_name.trim().is_empty() {
                errors.push(format!("row {expected_index} constraint_name must be present"));
            }

            if !row.satisfied {
                errors.push(format!(
                    "row {} {} must be satisfied",
                    expected_index, row.constraint_name
                ));
            }
        }

        for required_group in StarkWitnessPlan::REQUIRED_CONSTRAINT_GROUPS {
            if !self
                .rows
                .iter()
                .any(|row| row.constraint_group == required_group)
            {
                errors.push(format!(
                    "missing required constraint group: {required_group}"
                ));
            }
        }

        for required_constraint in Self::REQUIRED_CONSTRAINT_NAMES {
            if !self
                .rows
                .iter()
                .any(|row| row.constraint_name == required_constraint)
            {
                errors.push(format!(
                    "missing required constraint: {required_constraint}"
                ));
            }
        }

        if self.trace_status != Self::TRACE_STATUS {
            errors.push(format!(
                "trace_status must be {}, got {}",
                Self::TRACE_STATUS,
                self.trace_status
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn winterfell_poc_compatibility_report(&self) -> WinterfellPocCompatibilityReport {
        let required_groups_present =
            StarkWitnessPlan::REQUIRED_CONSTRAINT_GROUPS
                .iter()
                .all(|required_group| {
                    self.rows
                        .iter()
                        .any(|row| row.constraint_group == *required_group)
                });
        let all_mock_rows_satisfied = self.rows.iter().all(|row| row.satisfied);
        let direct_compatible_fields = compatibility_rows_for_class(MappingClass::Direct);
        let partial_fields = compatibility_rows_for_class(MappingClass::Partial);
        let unmapped_fields = compatibility_rows_for_class(MappingClass::Unmapped);

        WinterfellPocCompatibilityReport {
            schema_version: "winterfell-poc-compatibility-report-v0".to_string(),
            source_schema_version: self.schema_version.clone(),
            verdict: "compatible_subset_not_full_winterfell_trace".to_string(),
            mock_trace_rows: self.rows.len(),
            all_mock_rows_satisfied,
            imported_winterfell_input_fields: ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            direct_compatible_fields,
            partial_fields,
            unmapped_fields,
            required_mock_constraint_groups_present: required_groups_present,
            unsupported_winterfell_constraints: vec![
                "member_id_nonzero_inverse_witness".to_string(),
                "provider_npi_nonzero_inverse_witness".to_string(),
                "service_line_count_nonzero_inverse_witness".to_string(),
                "diagnosis_count_nonzero_inverse_witness".to_string(),
                "charge_cents_positive_inverse_witness".to_string(),
                "prior_auth_ok_gate_equivalence".to_string(),
                "program_integrity_hold_inverse_gate".to_string(),
                "charge_and_max_charge_bit_decomposition".to_string(),
                "charge_lte_max_charge_comparison_witness".to_string(),
                "winterfell_commitment_hash_chain".to_string(),
                "trace_width_172_and_trace_length_16".to_string(),
            ],
            notes: vec![
                "This report is generated without importing or executing Winterfell.".to_string(),
                "The mock trace covers only the active localBCE direct bridge fields and public decision/failure consistency.".to_string(),
                "Partial and unmapped fields must be normalized before a real Winterfell or production STARK adapter can be honest.".to_string(),
                "This is not a STARK proof and does not claim cryptographic verification.".to_string(),
            ],
        }
    }
}

impl WinterfellPocCompatibilityReport {
    pub fn to_adapter_gap_plan(&self) -> WinterfellAdapterGapPlan {
        WinterfellAdapterGapPlan {
            schema_version: "winterfell-adapter-gap-plan-v0".to_string(),
            source_schema_version: self.schema_version.clone(),
            plan_status: "adapter_planning_only_no_winterfell_import".to_string(),
            direct_ready_fields: self.direct_compatible_fields.clone(),
            partial_fields_requiring_normalization: self.partial_fields.clone(),
            unmapped_fields_requiring_source_data: self.unmapped_fields.clone(),
            unsupported_constraints_requiring_prover_work: self
                .unsupported_winterfell_constraints
                .clone(),
            recommended_next_steps: vec![
                "Freeze the direct field contract for eligibility_active, provider_enrolled, and duplicate_flag.".to_string(),
                "Define deterministic normalization rules for partial fields before adapting them into a prover witness.".to_string(),
                "Extend rust-engine or upstream claim intake to supply unmapped Winterfell PoC source fields, or explicitly remove those fields from the adapter target.".to_string(),
                "Implement prover-side witness generation for inverse, comparison, bit decomposition, and commitment constraints only after source fields are available.".to_string(),
                "Keep this path separate from the active Groth16 flow until a real STARK proof verifies against public inputs.".to_string(),
            ],
        }
    }
}

impl BatchRootCompatibilityPlan {
    pub const SCHEMA_VERSION: &'static str = "batch-root-compatibility-plan-v0";
    pub const PLAN_STATUS: &'static str = "planning_only_no_root_generation";
    pub const EXPECTED_COUNTS: MappingCounts = MappingCounts {
        direct: 3,
        partial: 5,
        unmapped: 9,
    };

    pub fn from_bridge_input(input: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        input.validate()?;

        let target_fields = batch_root_field_mappings()
            .into_iter()
            .map(|mapping| BatchRootFieldMapping {
                target_field: mapping.target_field.to_string(),
                active_bridge_source: mapping.active_bridge_source.map(str::to_string),
                class: mapping.class,
                note: mapping.note.to_string(),
            })
            .collect::<Vec<_>>();
        let counts = mapping_counts_for_batch_root_fields(&target_fields);

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: input.schema_version.clone(),
            plan_status: Self::PLAN_STATUS.to_string(),
            target_fields,
            counts,
            notes: vec![
                "This plan is test-only and does not generate claim roots, oracle roots, fee roots, nullifier roots, or proof public inputs.".to_string(),
                "Current direct fields are limited to existing single-claim public adjudication inputs.".to_string(),
                "Target batch roots remain unavailable until rust-engine or an upstream intake layer exports normalized root source data.".to_string(),
                "The active Groth16 workflow remains unchanged.".to_string(),
            ],
        })
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {}, got {}",
                Self::SCHEMA_VERSION,
                self.schema_version
            ));
        }

        if self.source_schema_version != StarkBridgeInput::SCHEMA_VERSION {
            errors.push(format!(
                "source_schema_version must be {}, got {}",
                StarkBridgeInput::SCHEMA_VERSION,
                self.source_schema_version
            ));
        }

        if self.plan_status != Self::PLAN_STATUS {
            errors.push(format!(
                "plan_status must be {}, got {}",
                Self::PLAN_STATUS,
                self.plan_status
            ));
        }

        if self.target_fields.len() != BATCH_ROOT_TARGET_FIELDS.len() {
            errors.push(format!(
                "target_fields must contain {} fields, got {}",
                BATCH_ROOT_TARGET_FIELDS.len(),
                self.target_fields.len()
            ));
        }

        for required_field in BATCH_ROOT_TARGET_FIELDS {
            if !self
                .target_fields
                .iter()
                .any(|mapping| mapping.target_field == required_field)
            {
                errors.push(format!("missing batch root target field: {required_field}"));
            }
        }

        let actual_counts = mapping_counts_for_batch_root_fields(&self.target_fields);
        if self.counts != actual_counts {
            errors.push("counts must match target_fields classification".to_string());
        }

        if self.counts != Self::EXPECTED_COUNTS {
            errors.push(format!(
                "counts must be direct={}, partial={}, unmapped={}",
                Self::EXPECTED_COUNTS.direct,
                Self::EXPECTED_COUNTS.partial,
                Self::EXPECTED_COUNTS.unmapped
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn to_gap_report(&self) -> Result<BatchRootGapReport, Vec<String>> {
        self.validate()?;

        Ok(BatchRootGapReport {
            schema_version: "batch-root-gap-report-v0".to_string(),
            source_schema_version: self.schema_version.clone(),
            report_status: "gap_report_planning_only_no_root_generation".to_string(),
            direct_ready_fields: batch_root_fields_for_class(self, MappingClass::Direct),
            partial_fields_requiring_normalization: batch_root_fields_for_class(
                self,
                MappingClass::Partial,
            ),
            unmapped_fields_requiring_source_data: batch_root_fields_for_class(
                self,
                MappingClass::Unmapped,
            ),
            unsupported_root_generation_tasks: vec![
                "canonical_claim_source_leaf_schema".to_string(),
                "claim_source_merkle_root_generation".to_string(),
                "adjudication_result_leaf_schema".to_string(),
                "adjudication_result_merkle_root_generation".to_string(),
                "oracle_facts_root_source_manifest".to_string(),
                "fee_schedule_root_source_manifest".to_string(),
                "address_book_root_source_manifest".to_string(),
                "payment_root_generation".to_string(),
                "nullifier_root_before_after_transition".to_string(),
                "batch_nullifier_commitment_generation".to_string(),
                "stark_verifier_key_id_selection".to_string(),
                "combined_public_input_vector_freeze".to_string(),
            ],
            recommended_next_steps: vec![
                "Freeze the existing single-claim public input contract: claim_hash, decision, and failure_code.".to_string(),
                "Define normalized leaf schemas before generating claimSourceRoot or adjudicationResultRoot.".to_string(),
                "Add explicit source manifests for oracle facts, fee schedules, address books, payments, and nullifier state before root generation.".to_string(),
                "Choose and document the root hash strategy before implementing deterministic root generation.".to_string(),
                "Keep this report outside the active Groth16 runtime until real STARK root constraints and proofs exist.".to_string(),
            ],
        })
    }
}

impl BatchRootGapReport {
    pub const SCHEMA_VERSION: &'static str = "batch-root-gap-report-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "batch-root-compatibility-plan-v0";
    pub const REPORT_STATUS: &'static str = "gap_report_planning_only_no_root_generation";

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {}, got {}",
                Self::SCHEMA_VERSION,
                self.schema_version
            ));
        }

        if self.source_schema_version != Self::SOURCE_SCHEMA_VERSION {
            errors.push(format!(
                "source_schema_version must be {}, got {}",
                Self::SOURCE_SCHEMA_VERSION,
                self.source_schema_version
            ));
        }

        if self.report_status != Self::REPORT_STATUS {
            errors.push(format!(
                "report_status must be {}, got {}",
                Self::REPORT_STATUS,
                self.report_status
            ));
        }

        if self.direct_ready_fields.len() != BatchRootCompatibilityPlan::EXPECTED_COUNTS.direct {
            errors.push(format!(
                "direct_ready_fields must contain {} fields, got {}",
                BatchRootCompatibilityPlan::EXPECTED_COUNTS.direct,
                self.direct_ready_fields.len()
            ));
        }

        if self.partial_fields_requiring_normalization.len()
            != BatchRootCompatibilityPlan::EXPECTED_COUNTS.partial
        {
            errors.push(format!(
                "partial_fields_requiring_normalization must contain {} fields, got {}",
                BatchRootCompatibilityPlan::EXPECTED_COUNTS.partial,
                self.partial_fields_requiring_normalization.len()
            ));
        }

        if self.unmapped_fields_requiring_source_data.len()
            != BatchRootCompatibilityPlan::EXPECTED_COUNTS.unmapped
        {
            errors.push(format!(
                "unmapped_fields_requiring_source_data must contain {} fields, got {}",
                BatchRootCompatibilityPlan::EXPECTED_COUNTS.unmapped,
                self.unmapped_fields_requiring_source_data.len()
            ));
        }

        if self.unsupported_root_generation_tasks.is_empty() {
            errors.push("unsupported_root_generation_tasks must be non-empty".to_string());
        }

        if self.recommended_next_steps.is_empty() {
            errors.push("recommended_next_steps must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl ClaimSourceRootInput {
    pub const SCHEMA_VERSION: &'static str = "claim-source-root-input-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const INPUT_STATUS: &'static str = "source_schema_only_no_root_generation";
    pub const ROOT_GENERATION_STATUS: &'static str = "not_generated";

    pub fn from_bridge_input(input: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        input.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: input.schema_version.clone(),
            input_status: Self::INPUT_STATUS.to_string(),
            claim_id: input.claim.claim_id.clone(),
            claim_hash: input.claim.claim_hash.clone(),
            claim_amount: input.claim.claim_amount,
            member_id: None,
            provider_npi: None,
            service_date: Some(input.active_rust_facts.date_of_service_from),
            procedure_codes: Vec::new(),
            diagnosis_codes: Vec::new(),
            service_line_count: None,
            root_generation_status: Self::ROOT_GENERATION_STATUS.to_string(),
            notes: vec![
                "This input is a normalized source schema for future claimSourceRoot work.".to_string(),
                "member_id, provider_npi, procedure_codes, diagnosis_codes, and service_line_count are not exported by the current rust-engine bridge.".to_string(),
                "No claim-source leaf, hash, Merkle root, or STARK proof is generated from this object.".to_string(),
                "The active Groth16 workflow remains unchanged.".to_string(),
            ],
        })
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {}, got {}",
                Self::SCHEMA_VERSION,
                self.schema_version
            ));
        }

        if self.source_schema_version != Self::SOURCE_SCHEMA_VERSION {
            errors.push(format!(
                "source_schema_version must be {}, got {}",
                Self::SOURCE_SCHEMA_VERSION,
                self.source_schema_version
            ));
        }

        if self.input_status != Self::INPUT_STATUS {
            errors.push(format!(
                "input_status must be {}, got {}",
                Self::INPUT_STATUS,
                self.input_status
            ));
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if self.claim_amount == 0 {
            errors.push("claim_amount must be greater than zero".to_string());
        }

        if let Some(provider_npi) = &self.provider_npi {
            if provider_npi.len() != 10 || !provider_npi.chars().all(|ch| ch.is_ascii_digit()) {
                errors.push("provider_npi must be exactly 10 decimal digits when present".to_string());
            }
        }

        if let Some(service_line_count) = self.service_line_count {
            if service_line_count == 0 {
                errors.push("service_line_count must be greater than zero when present".to_string());
            }
            if service_line_count as usize != self.procedure_codes.len()
                && !self.procedure_codes.is_empty()
            {
                errors.push(
                    "service_line_count must match procedure_codes length when procedure codes are present"
                        .to_string(),
                );
            }
        }

        for (index, procedure_code) in self.procedure_codes.iter().enumerate() {
            if procedure_code.trim().is_empty() {
                errors.push(format!("procedure_codes[{index}] must be non-empty"));
            }
        }

        for (index, diagnosis_code) in self.diagnosis_codes.iter().enumerate() {
            if diagnosis_code.trim().is_empty() {
                errors.push(format!("diagnosis_codes[{index}] must be non-empty"));
            }
        }

        if self.root_generation_status != Self::ROOT_GENERATION_STATUS {
            errors.push(format!(
                "root_generation_status must be {}, got {}",
                Self::ROOT_GENERATION_STATUS,
                self.root_generation_status
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl OracleFactsRootInput {
    pub const SCHEMA_VERSION: &'static str = "oracle-facts-root-input-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const INPUT_STATUS: &'static str = "source_schema_only_no_root_generation";
    pub const ROOT_GENERATION_STATUS: &'static str = "not_generated";

    pub fn from_bridge_input(input: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        input.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: input.schema_version.clone(),
            input_status: Self::INPUT_STATUS.to_string(),
            claim_id: input.claim.claim_id.clone(),
            claim_hash: input.claim.claim_hash.clone(),
            source_manifest_id: None,
            facts: Vec::new(),
            attestation_refs: Vec::new(),
            root_generation_status: Self::ROOT_GENERATION_STATUS.to_string(),
            notes: vec![
                "This input is a normalized source schema for future oracleFactsRoot work.".to_string(),
                "The current rust-engine bridge exports adjudication flags, not source-backed oracle facts or attestations.".to_string(),
                "No oracle fact leaf, hash, Merkle root, source fetch, attestation, or STARK proof is generated from this object.".to_string(),
                "The active Groth16 workflow remains unchanged.".to_string(),
            ],
        })
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {}, got {}",
                Self::SCHEMA_VERSION,
                self.schema_version
            ));
        }

        if self.source_schema_version != Self::SOURCE_SCHEMA_VERSION {
            errors.push(format!(
                "source_schema_version must be {}, got {}",
                Self::SOURCE_SCHEMA_VERSION,
                self.source_schema_version
            ));
        }

        if self.input_status != Self::INPUT_STATUS {
            errors.push(format!(
                "input_status must be {}, got {}",
                Self::INPUT_STATUS,
                self.input_status
            ));
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if let Some(source_manifest_id) = &self.source_manifest_id {
            if source_manifest_id.trim().is_empty() {
                errors.push("source_manifest_id must be non-empty when present".to_string());
            }
        }

        for (index, fact) in self.facts.iter().enumerate() {
            if fact.fact_type.trim().is_empty() {
                errors.push(format!("facts[{index}].fact_type must be present"));
            }
            if fact.fact_key.trim().is_empty() {
                errors.push(format!("facts[{index}].fact_key must be present"));
            }
            if fact.fact_value.trim().is_empty() {
                errors.push(format!("facts[{index}].fact_value must be present"));
            }
            if fact.verification_status.trim().is_empty() {
                errors.push(format!(
                    "facts[{index}].verification_status must be present"
                ));
            }
            if let Some(source_url) = &fact.source_url {
                if !source_url.starts_with("https://") {
                    errors.push(format!(
                        "facts[{index}].source_url must use https when present"
                    ));
                }
            }
            if let Some(source_label) = &fact.source_label {
                if source_label.trim().is_empty() {
                    errors.push(format!(
                        "facts[{index}].source_label must be non-empty when present"
                    ));
                }
            }
        }

        for (index, attestation_ref) in self.attestation_refs.iter().enumerate() {
            if attestation_ref.trim().is_empty() {
                errors.push(format!("attestation_refs[{index}] must be non-empty"));
            }
        }

        if self.root_generation_status != Self::ROOT_GENERATION_STATUS {
            errors.push(format!(
                "root_generation_status must be {}, got {}",
                Self::ROOT_GENERATION_STATUS,
                self.root_generation_status
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn validate_boolean_fact(field: &str, value: u8, errors: &mut Vec<String>) {
    if value > 1 {
        errors.push(format!("{field} must be 0 or 1, got {value}"));
    }
}

fn is_0x_32_byte_hex(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("0x") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn compatibility_rows_for_class(class: MappingClass) -> Vec<WinterfellPocFieldCompatibility> {
    ActiveClaimToStarkBridge::field_mappings()
        .into_iter()
        .filter(|mapping| mapping.class == class)
        .map(|mapping| WinterfellPocFieldCompatibility {
            imported_stark_field: mapping.imported_stark_field.to_string(),
            active_rust_source: mapping.active_rust_source.map(str::to_string),
            compatibility: match mapping.class {
                MappingClass::Direct => "direct",
                MappingClass::Partial => "partial",
                MappingClass::Unmapped => "unmapped",
            }
            .to_string(),
            note: mapping.note.to_string(),
        })
        .collect()
}

fn batch_root_fields_for_class(
    plan: &BatchRootCompatibilityPlan,
    class: MappingClass,
) -> Vec<BatchRootFieldMapping> {
    plan.target_fields
        .iter()
        .filter(|mapping| mapping.class == class)
        .cloned()
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StaticBatchRootFieldMapping {
    target_field: &'static str,
    active_bridge_source: Option<&'static str>,
    class: MappingClass,
    note: &'static str,
}

pub const BATCH_ROOT_TARGET_FIELDS: [&str; 17] = [
    "claim_hash",
    "decision",
    "failure_code",
    "claimSourceRoot",
    "adjudicationResultRoot",
    "rulesetRoot",
    "claimCount",
    "combinedPublicInputVector",
    "oracleFactsRoot",
    "feeScheduleRoot",
    "addressBookRoot",
    "paymentRoot",
    "nullifierRootBefore",
    "nullifierRootAfter",
    "batchNullifierCommitment",
    "verifierKeyId",
    "paymentCount",
];

fn batch_root_field_mappings() -> Vec<StaticBatchRootFieldMapping> {
    vec![
        StaticBatchRootFieldMapping {
            target_field: "claim_hash",
            active_bridge_source: Some("public_inputs.claim_hash"),
            class: MappingClass::Direct,
            note: "single-claim public hash is already exported",
        },
        StaticBatchRootFieldMapping {
            target_field: "decision",
            active_bridge_source: Some("public_inputs.decision"),
            class: MappingClass::Direct,
            note: "single-claim public decision is already exported",
        },
        StaticBatchRootFieldMapping {
            target_field: "failure_code",
            active_bridge_source: Some("public_inputs.failure_code"),
            class: MappingClass::Direct,
            note: "single-claim public failure code is already exported",
        },
        StaticBatchRootFieldMapping {
            target_field: "claimSourceRoot",
            active_bridge_source: Some("claim.claim_hash"),
            class: MappingClass::Partial,
            note: "claim hash can seed a future claim leaf, but it is not a governed claim-source Merkle root",
        },
        StaticBatchRootFieldMapping {
            target_field: "adjudicationResultRoot",
            active_bridge_source: Some("adjudication.decision, adjudication.failure_code"),
            class: MappingClass::Partial,
            note: "decision fields can seed a result leaf, but no result Merkle root is generated",
        },
        StaticBatchRootFieldMapping {
            target_field: "rulesetRoot",
            active_bridge_source: Some("public_inputs.ruleset_id"),
            class: MappingClass::Partial,
            note: "ruleset_id identifies rules, but no canonical ruleset commitment/root is exported",
        },
        StaticBatchRootFieldMapping {
            target_field: "claimCount",
            active_bridge_source: Some("single dry-run claim"),
            class: MappingClass::Partial,
            note: "current bridge implies one claim, but does not model batch cardinality",
        },
        StaticBatchRootFieldMapping {
            target_field: "combinedPublicInputVector",
            active_bridge_source: Some("public_inputs"),
            class: MappingClass::Partial,
            note: "current public inputs are a subset of the future batch public input vector",
        },
        StaticBatchRootFieldMapping {
            target_field: "oracleFactsRoot",
            active_bridge_source: None,
            class: MappingClass::Unmapped,
            note: "active bridge exports adjudication flags, not oracle evidence roots",
        },
        StaticBatchRootFieldMapping {
            target_field: "feeScheduleRoot",
            active_bridge_source: None,
            class: MappingClass::Unmapped,
            note: "active bridge has no fee schedule source tree or allowed-amount leaf",
        },
        StaticBatchRootFieldMapping {
            target_field: "addressBookRoot",
            active_bridge_source: None,
            class: MappingClass::Unmapped,
            note: "active bridge has no governed provider/payment address book",
        },
        StaticBatchRootFieldMapping {
            target_field: "paymentRoot",
            active_bridge_source: None,
            class: MappingClass::Unmapped,
            note: "payment aggregation remains outside the current STARK bridge",
        },
        StaticBatchRootFieldMapping {
            target_field: "nullifierRootBefore",
            active_bridge_source: None,
            class: MappingClass::Unmapped,
            note: "active bridge does not track a nullifier tree",
        },
        StaticBatchRootFieldMapping {
            target_field: "nullifierRootAfter",
            active_bridge_source: None,
            class: MappingClass::Unmapped,
            note: "active bridge does not track a nullifier tree transition",
        },
        StaticBatchRootFieldMapping {
            target_field: "batchNullifierCommitment",
            active_bridge_source: None,
            class: MappingClass::Unmapped,
            note: "active bridge has duplicate flag only, not a batch nullifier commitment",
        },
        StaticBatchRootFieldMapping {
            target_field: "verifierKeyId",
            active_bridge_source: None,
            class: MappingClass::Unmapped,
            note: "active STARK bridge has no selected STARK verifier key",
        },
        StaticBatchRootFieldMapping {
            target_field: "paymentCount",
            active_bridge_source: None,
            class: MappingClass::Unmapped,
            note: "payment records are not part of the current bridge input",
        },
    ]
}

fn mapping_counts_for_batch_root_fields(fields: &[BatchRootFieldMapping]) -> MappingCounts {
    MappingCounts {
        direct: fields
            .iter()
            .filter(|mapping| mapping.class == MappingClass::Direct)
            .count(),
        partial: fields
            .iter()
            .filter(|mapping| mapping.class == MappingClass::Partial)
            .count(),
        unmapped: fields
            .iter()
            .filter(|mapping| mapping.class == MappingClass::Unmapped)
            .count(),
    }
}

fn push_mock_trace_row(
    rows: &mut Vec<StarkMockTraceRow>,
    constraint_group: &str,
    constraint_name: &str,
    input_value: String,
    expected_value: String,
    satisfied: bool,
) {
    rows.push(StarkMockTraceRow {
        step_index: rows.len(),
        constraint_group: constraint_group.to_string(),
        constraint_name: constraint_name.to_string(),
        input_value,
        expected_value,
        satisfied,
    });
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MappingCounts {
    pub direct: usize,
    pub partial: usize,
    pub unmapped: usize,
}

impl ActiveClaimToStarkBridge {
    /// Imported Winterfell STARK input fields, in the order used by the PoC.
    pub const IMPORTED_STARK_FIELDS: [&'static str; 11] = [
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
    ];

    /// Active Rust adjudication fields that exist today.
    pub const ACTIVE_RUST_FIELDS: [&'static str; 18] = [
        "claim_id",
        "claim_amount",
        "eligibility_active",
        "aid_code",
        "benefit_level_exists",
        "date_of_service_from",
        "eligibility_period_from",
        "eligibility_period_thru",
        "soc_amount",
        "soc_met",
        "provider_enrolled",
        "provider_type_valid",
        "billing_code_valid",
        "units_valid",
        "is_duplicate",
        "disability_determination_valid",
        "recipient_not_deceased",
        "physician_certification_valid",
    ];

    /// Compatibility map from imported STARK fields to active Rust fields.
    pub fn field_mappings() -> Vec<FieldMapping> {
        vec![
            FieldMapping {
                imported_stark_field: "member_id",
                active_rust_source: None,
                class: MappingClass::Unmapped,
                note: "active claim input has claim_id string, not numeric member_id",
            },
            FieldMapping {
                imported_stark_field: "provider_npi",
                active_rust_source: None,
                class: MappingClass::Unmapped,
                note: "active input tracks enrollment/type validity, not NPI presence",
            },
            FieldMapping {
                imported_stark_field: "eligibility_active",
                active_rust_source: Some("eligibility_active"),
                class: MappingClass::Direct,
                note: "both models treat 1 as active/pass",
            },
            FieldMapping {
                imported_stark_field: "provider_enrolled",
                active_rust_source: Some("provider_enrolled"),
                class: MappingClass::Direct,
                note: "both models treat 1 as enrolled/pass",
            },
            FieldMapping {
                imported_stark_field: "service_line_count",
                active_rust_source: Some("billing_code_valid, units_valid"),
                class: MappingClass::Partial,
                note: "active booleans imply service-line validity, not a count",
            },
            FieldMapping {
                imported_stark_field: "diagnosis_count",
                active_rust_source: None,
                class: MappingClass::Unmapped,
                note: "active input has no diagnosis count",
            },
            FieldMapping {
                imported_stark_field: "prior_auth_ok",
                active_rust_source: Some("physician_certification_valid"),
                class: MappingClass::Partial,
                note: "certification may support authorization but is not equivalent",
            },
            FieldMapping {
                imported_stark_field: "charge_cents",
                active_rust_source: Some("claim_amount"),
                class: MappingClass::Partial,
                note: "amount can map only after units/currency normalization",
            },
            FieldMapping {
                imported_stark_field: "max_charge_cents",
                active_rust_source: None,
                class: MappingClass::Unmapped,
                note: "active input has no maximum allowed charge field",
            },
            FieldMapping {
                imported_stark_field: "duplicate_flag",
                active_rust_source: Some("is_duplicate"),
                class: MappingClass::Direct,
                note: "same duplicate fact, with pass condition inverted in the gate",
            },
            FieldMapping {
                imported_stark_field: "program_integrity_hold",
                active_rust_source: Some("disability_determination_valid, recipient_not_deceased"),
                class: MappingClass::Partial,
                note: "active checks can contribute to integrity status but do not equal a hold flag",
            },
        ]
    }

    /// Fields that can be treated as direct bridge candidates today.
    pub fn direct_mappings() -> Vec<FieldMapping> {
        Self::field_mappings()
            .into_iter()
            .filter(|mapping| mapping.class == MappingClass::Direct)
            .collect()
    }
}
