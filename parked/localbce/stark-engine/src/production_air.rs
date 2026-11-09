use serde::{Deserialize, Serialize};

use crate::{ActiveRustFacts, StarkBridgeInput};

/// Versioned, prover-independent semantics for the active G1-G10 rules.
///
/// This module defines what a future production STARK AIR must prove. It does
/// not build a Winterfell trace, generate a proof, or change runtime behavior.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionAirInputV1 {
    pub schema_version: String,
    pub source_schema_version: String,
    pub semantics_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub ruleset_id: String,
    pub facts: ProductionAirFactsV1,
    pub expected_outcome: ProductionAirOutcomeV1,
    pub runtime_wired: bool,
    pub proof_generated: bool,
    pub groth16_flow_unchanged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionAirFactsV1 {
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
pub struct ProductionAirOutcomeV1 {
    pub decision: u8,
    pub failure_code: u32,
    pub failure_reason: Option<String>,
}

/// Deterministic semantics evaluation, not a prover execution trace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionAirSemanticsTraceV1 {
    pub schema_version: String,
    pub source_schema_version: String,
    pub trace_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub ruleset_id: String,
    pub rows: Vec<ProductionAirSemanticsRowV1>,
    pub outcome: ProductionAirOutcomeV1,
    pub winterfell_trace_built: bool,
    pub proof_generated: bool,
    pub runtime_wired: bool,
    pub groth16_flow_unchanged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionAirSemanticsRowV1 {
    pub step_index: u8,
    pub gate_id: String,
    pub constraint_name: String,
    pub failure_reason: String,
    pub failure_code: u32,
    pub satisfied: bool,
    pub decisive: bool,
}

#[derive(Clone, Copy)]
struct GateEvaluation {
    gate_id: &'static str,
    constraint_name: &'static str,
    failure_reason: &'static str,
    failure_code: u32,
    satisfied: bool,
}

impl ProductionAirInputV1 {
    pub const SCHEMA_VERSION: &'static str = "stark-production-air-input-v1";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const SEMANTICS_STATUS: &'static str = "feature_gated_non_runtime_semantics";
    pub const RULESET_ID: &'static str = "current_g1_g10_denial_reason";

    pub fn from_bridge_input(bridge: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        bridge.validate()?;

        let input = Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: bridge.schema_version.clone(),
            semantics_status: Self::SEMANTICS_STATUS.to_string(),
            claim_id: bridge.claim.claim_id.clone(),
            claim_hash: bridge.claim.claim_hash.clone(),
            ruleset_id: bridge.adjudication.ruleset_id.clone(),
            facts: ProductionAirFactsV1::from(&bridge.active_rust_facts),
            expected_outcome: ProductionAirOutcomeV1 {
                decision: bridge.adjudication.decision,
                failure_code: bridge.adjudication.failure_code,
                failure_reason: bridge.adjudication.failure_reason.clone(),
            },
            runtime_wired: false,
            proof_generated: false,
            groth16_flow_unchanged: true,
        };

        let mut errors = Vec::new();
        if bridge.adjudication.failure_code != bridge.public_inputs.failure_code {
            errors.push(
                "adjudication.failure_code must match public_inputs.failure_code".to_string(),
            );
        }
        if bridge.adjudication.ruleset_id != bridge.public_inputs.ruleset_id {
            errors.push("adjudication.ruleset_id must match public_inputs.ruleset_id".to_string());
        }
        if let Err(mut input_errors) = input.validate() {
            errors.append(&mut input_errors);
        }

        if errors.is_empty() {
            Ok(input)
        } else {
            Err(errors)
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
        if self.source_schema_version != Self::SOURCE_SCHEMA_VERSION {
            errors.push(format!(
                "source_schema_version must be {}, got {}",
                Self::SOURCE_SCHEMA_VERSION,
                self.source_schema_version
            ));
        }
        if self.semantics_status != Self::SEMANTICS_STATUS {
            errors.push(format!(
                "semantics_status must be {}, got {}",
                Self::SEMANTICS_STATUS,
                self.semantics_status
            ));
        }
        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }
        if self.claim_hash.trim().is_empty() {
            errors.push("claim_hash must be present".to_string());
        }
        if self.ruleset_id != Self::RULESET_ID {
            errors.push(format!(
                "ruleset_id must be {}, got {}",
                Self::RULESET_ID,
                self.ruleset_id
            ));
        }

        self.facts.validate_boolean_facts(&mut errors);

        if self.runtime_wired {
            errors.push("runtime_wired must remain false".to_string());
        }
        if self.proof_generated {
            errors.push("proof_generated must remain false".to_string());
        }
        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must remain true".to_string());
        }

        let evaluated = evaluate_outcome(&self.facts);
        if self.expected_outcome != evaluated {
            errors.push(format!(
                "expected_outcome does not match G1-G10 semantics: expected {:?}, evaluated {:?}",
                self.expected_outcome, evaluated
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn evaluate(&self) -> Result<ProductionAirSemanticsTraceV1, Vec<String>> {
        self.validate()?;

        let evaluations = evaluate_gates(&self.facts);
        let first_failed_index = evaluations.iter().position(|gate| !gate.satisfied);
        let rows = evaluations
            .into_iter()
            .enumerate()
            .map(|(index, gate)| ProductionAirSemanticsRowV1 {
                step_index: index as u8,
                gate_id: gate.gate_id.to_string(),
                constraint_name: gate.constraint_name.to_string(),
                failure_reason: gate.failure_reason.to_string(),
                failure_code: gate.failure_code,
                satisfied: gate.satisfied,
                decisive: first_failed_index == Some(index),
            })
            .collect();

        let trace = ProductionAirSemanticsTraceV1 {
            schema_version: ProductionAirSemanticsTraceV1::SCHEMA_VERSION.to_string(),
            source_schema_version: self.schema_version.clone(),
            trace_status: ProductionAirSemanticsTraceV1::TRACE_STATUS.to_string(),
            claim_id: self.claim_id.clone(),
            claim_hash: self.claim_hash.clone(),
            ruleset_id: self.ruleset_id.clone(),
            rows,
            outcome: evaluate_outcome(&self.facts),
            winterfell_trace_built: false,
            proof_generated: false,
            runtime_wired: false,
            groth16_flow_unchanged: true,
        };
        trace.validate()?;
        Ok(trace)
    }
}

impl ProductionAirFactsV1 {
    fn validate_boolean_facts(&self, errors: &mut Vec<String>) {
        for (name, value) in [
            ("eligibility_active", self.eligibility_active),
            ("benefit_level_exists", self.benefit_level_exists),
            ("soc_met", self.soc_met),
            ("provider_enrolled", self.provider_enrolled),
            ("provider_type_valid", self.provider_type_valid),
            ("billing_code_valid", self.billing_code_valid),
            ("units_valid", self.units_valid),
            ("is_duplicate", self.is_duplicate),
            (
                "disability_determination_valid",
                self.disability_determination_valid,
            ),
            ("recipient_not_deceased", self.recipient_not_deceased),
            (
                "physician_certification_valid",
                self.physician_certification_valid,
            ),
        ] {
            if value > 1 {
                errors.push(format!("{name} must be boolean 0 or 1, got {value}"));
            }
        }
    }
}

impl From<&ActiveRustFacts> for ProductionAirFactsV1 {
    fn from(facts: &ActiveRustFacts) -> Self {
        Self {
            eligibility_active: facts.eligibility_active,
            aid_code: facts.aid_code,
            benefit_level_exists: facts.benefit_level_exists,
            date_of_service_from: facts.date_of_service_from,
            eligibility_period_from: facts.eligibility_period_from,
            eligibility_period_thru: facts.eligibility_period_thru,
            soc_amount: facts.soc_amount,
            soc_met: facts.soc_met,
            provider_enrolled: facts.provider_enrolled,
            provider_type_valid: facts.provider_type_valid,
            billing_code_valid: facts.billing_code_valid,
            units_valid: facts.units_valid,
            is_duplicate: facts.is_duplicate,
            disability_determination_valid: facts.disability_determination_valid,
            recipient_not_deceased: facts.recipient_not_deceased,
            physician_certification_valid: facts.physician_certification_valid,
        }
    }
}

impl ProductionAirSemanticsTraceV1 {
    pub const SCHEMA_VERSION: &'static str = "stark-production-air-semantics-trace-v1";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-production-air-input-v1";
    pub const TRACE_STATUS: &'static str = "semantics_evaluated_not_prover_trace";
    pub const EXPECTED_ROW_COUNT: usize = 13;
    pub const EXPECTED_FAILURE_REASONS: [&'static str; Self::EXPECTED_ROW_COUNT] = [
        "G1_IDENTITY_VERIFICATION_FAILED",
        "G2_PROGRAM_ELIGIBILITY_FAILED",
        "G2_BENEFIT_LEVEL_MISSING",
        "G3_MONTH_OF_SERVICE_FAILED",
        "G4_SHARE_OF_COST_FAILED",
        "G5_PROVIDER_NOT_ENROLLED",
        "G5_PROVIDER_TYPE_INVALID",
        "G6_BILLING_CODE_INVALID",
        "G6_UNITS_INVALID",
        "G7_DUPLICATE_CLAIM",
        "G8_DISABILITY_DETERMINATION_FAILED",
        "G9_RECIPIENT_DECEASED",
        "G10_PHYSICIAN_CERTIFICATION_FAILED",
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
        if self.trace_status != Self::TRACE_STATUS {
            errors.push(format!(
                "trace_status must be {}, got {}",
                Self::TRACE_STATUS,
                self.trace_status
            ));
        }
        if self.rows.len() != Self::EXPECTED_ROW_COUNT {
            errors.push(format!(
                "rows must contain exactly {} ordered gate evaluations",
                Self::EXPECTED_ROW_COUNT
            ));
        }

        for (index, row) in self.rows.iter().enumerate() {
            if row.step_index as usize != index {
                errors.push(format!(
                    "row {index} has invalid step_index {}",
                    row.step_index
                ));
            }
            if let Some(expected_reason) = Self::EXPECTED_FAILURE_REASONS.get(index)
                && row.failure_reason != *expected_reason
            {
                errors.push(format!(
                    "row {index} failure_reason must be {expected_reason}"
                ));
            }
        }

        let decisive_rows: Vec<_> = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.decisive)
            .collect();
        let first_failed = self.rows.iter().position(|row| !row.satisfied);

        match first_failed {
            None => {
                if !decisive_rows.is_empty() {
                    errors.push("approved trace must not contain a decisive row".to_string());
                }
                if self.outcome
                    != (ProductionAirOutcomeV1 {
                        decision: 1,
                        failure_code: 0,
                        failure_reason: None,
                    })
                {
                    errors.push("approved trace must have the approved outcome".to_string());
                }
            }
            Some(index) => {
                if decisive_rows.len() != 1 || decisive_rows[0].0 != index {
                    errors.push("exactly the first failed row must be decisive".to_string());
                }
                let row = &self.rows[index];
                let expected = ProductionAirOutcomeV1 {
                    decision: 0,
                    failure_code: row.failure_code,
                    failure_reason: Some(row.failure_reason.clone()),
                };
                if self.outcome != expected {
                    errors.push("denied trace outcome must match the decisive row".to_string());
                }
            }
        }

        if self.winterfell_trace_built {
            errors.push("winterfell_trace_built must remain false".to_string());
        }
        if self.proof_generated {
            errors.push("proof_generated must remain false".to_string());
        }
        if self.runtime_wired {
            errors.push("runtime_wired must remain false".to_string());
        }
        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must remain true".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

pub(crate) fn evaluate_outcome(facts: &ProductionAirFactsV1) -> ProductionAirOutcomeV1 {
    evaluate_gates(facts)
        .into_iter()
        .find(|gate| !gate.satisfied)
        .map_or(
            ProductionAirOutcomeV1 {
                decision: 1,
                failure_code: 0,
                failure_reason: None,
            },
            |gate| ProductionAirOutcomeV1 {
                decision: 0,
                failure_code: gate.failure_code,
                failure_reason: Some(gate.failure_reason.to_string()),
            },
        )
}

fn evaluate_gates(facts: &ProductionAirFactsV1) -> Vec<GateEvaluation> {
    vec![
        GateEvaluation {
            gate_id: "G1",
            constraint_name: "eligibility_active_equals_one",
            failure_reason: "G1_IDENTITY_VERIFICATION_FAILED",
            failure_code: 1,
            satisfied: facts.eligibility_active == 1,
        },
        GateEvaluation {
            gate_id: "G2",
            constraint_name: "aid_code_is_supported",
            failure_reason: "G2_PROGRAM_ELIGIBILITY_FAILED",
            failure_code: 201,
            satisfied: matches!(facts.aid_code, 13 | 23 | 53 | 103 | 104),
        },
        GateEvaluation {
            gate_id: "G2",
            constraint_name: "benefit_level_exists_equals_one",
            failure_reason: "G2_BENEFIT_LEVEL_MISSING",
            failure_code: 202,
            satisfied: facts.benefit_level_exists == 1,
        },
        GateEvaluation {
            gate_id: "G3",
            constraint_name: "date_of_service_within_eligibility_period",
            failure_reason: "G3_MONTH_OF_SERVICE_FAILED",
            failure_code: 3,
            satisfied: facts.date_of_service_from >= facts.eligibility_period_from
                && facts.date_of_service_from <= facts.eligibility_period_thru,
        },
        GateEvaluation {
            gate_id: "G4",
            constraint_name: "share_of_cost_is_zero_or_met",
            failure_reason: "G4_SHARE_OF_COST_FAILED",
            failure_code: 4,
            satisfied: facts.soc_amount == 0 || facts.soc_met == 1,
        },
        GateEvaluation {
            gate_id: "G5",
            constraint_name: "provider_enrolled_equals_one",
            failure_reason: "G5_PROVIDER_NOT_ENROLLED",
            failure_code: 501,
            satisfied: facts.provider_enrolled == 1,
        },
        GateEvaluation {
            gate_id: "G5",
            constraint_name: "provider_type_valid_equals_one",
            failure_reason: "G5_PROVIDER_TYPE_INVALID",
            failure_code: 502,
            satisfied: facts.provider_type_valid == 1,
        },
        GateEvaluation {
            gate_id: "G6",
            constraint_name: "billing_code_valid_equals_one",
            failure_reason: "G6_BILLING_CODE_INVALID",
            failure_code: 601,
            satisfied: facts.billing_code_valid == 1,
        },
        GateEvaluation {
            gate_id: "G6",
            constraint_name: "units_valid_equals_one",
            failure_reason: "G6_UNITS_INVALID",
            failure_code: 602,
            satisfied: facts.units_valid == 1,
        },
        GateEvaluation {
            gate_id: "G7",
            constraint_name: "duplicate_flag_equals_zero",
            failure_reason: "G7_DUPLICATE_CLAIM",
            failure_code: 7,
            satisfied: facts.is_duplicate == 0,
        },
        GateEvaluation {
            gate_id: "G8",
            constraint_name: "disability_determination_valid_equals_one",
            failure_reason: "G8_DISABILITY_DETERMINATION_FAILED",
            failure_code: 8,
            satisfied: facts.disability_determination_valid == 1,
        },
        GateEvaluation {
            gate_id: "G9",
            constraint_name: "recipient_not_deceased_equals_one",
            failure_reason: "G9_RECIPIENT_DECEASED",
            failure_code: 9,
            satisfied: facts.recipient_not_deceased == 1,
        },
        GateEvaluation {
            gate_id: "G10",
            constraint_name: "physician_certification_valid_equals_one",
            failure_reason: "G10_PHYSICIAN_CERTIFICATION_FAILED",
            failure_code: 10,
            satisfied: facts.physician_certification_valid == 1,
        },
    ]
}

#[cfg(test)]
#[path = "production_air_tests.rs"]
mod tests;
