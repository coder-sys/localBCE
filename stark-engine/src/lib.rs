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
