//! First-class STARK compatibility wrapper for localBCE.
//!
//! This crate is intentionally non-runtime today. It does not import the
//! Winterfell proof-of-concept from `blind-ledger-app-layer/zk-stark`, and it is
//! not wired into `rust-engine`.
//!
//! Its first job is to document and test the bridge assumptions between the
//! active Rust adjudication model and the imported Winterfell STARK input model.

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
