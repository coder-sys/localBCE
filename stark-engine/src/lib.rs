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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

fn validate_boolean_fact(field: &str, value: u8, errors: &mut Vec<String>) {
    if value > 1 {
        errors.push(format!("{field} must be 0 or 1, got {value}"));
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
