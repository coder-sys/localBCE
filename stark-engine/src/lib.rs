//! First-class STARK compatibility wrapper for localBCE.
//!
//! This crate is intentionally non-runtime today. The default build does not
//! import the Winterfell proof-of-concept from `blind-ledger-app-layer/zk-stark`,
//! and it is not wired into `rust-engine`.
//!
//! Its first job is to document and test the bridge assumptions between the
//! active Rust adjudication model and the imported Winterfell STARK input model.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod local_verifier;
pub mod proof_artifact;
pub mod proof_commitment;
pub mod public_inputs;
pub mod real_prover;
pub mod root_semantics;
pub mod source_roots;

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

/// First Phase 5 boundary between completed Phase 4 schemas and the imported
/// Winterfell proof-of-concept.
///
/// This is not a prover adapter. It names the exact imported PoC shape and the
/// source artifacts a future adapter would need before importing Winterfell.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellAdapterBoundaryPlan {
    pub schema_version: String,
    pub source_schema_version: String,
    pub plan_status: String,
    pub imported_poc: WinterfellPocShape,
    pub required_phase4_artifacts: Vec<String>,
    pub field_bindings: Vec<WinterfellAdapterFieldBinding>,
    pub public_input_bindings: Vec<WinterfellAdapterPublicInputBinding>,
    pub unsupported_constraint_groups: Vec<String>,
    pub winterfell_dependency_imported: bool,
    pub proof_generation_enabled: bool,
    pub recommended_next_steps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellPocShape {
    pub crate_path: String,
    pub claim_input_fields: Vec<String>,
    pub public_inputs: Vec<String>,
    pub gate_count: usize,
    pub trace_width: usize,
    pub trace_length: usize,
    pub commitment_strategy: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellAdapterFieldBinding {
    pub winterfell_field: String,
    pub phase4_source_artifact: Option<String>,
    pub phase4_source_field: Option<String>,
    pub class: MappingClass,
    pub note: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellAdapterPublicInputBinding {
    pub winterfell_public_input: String,
    pub phase4_source_artifact: Option<String>,
    pub phase4_source_field: Option<String>,
    pub class: MappingClass,
    pub note: String,
}

/// Deterministic witness candidate for the imported Winterfell PoC shape.
///
/// This is not a Winterfell witness and does not import Winterfell. It is the
/// Phase 5B adapter staging object that makes missing source data explicit
/// before a prover-specific witness generator exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellWitnessCandidate {
    pub schema_version: String,
    pub source_schema_version: String,
    pub candidate_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub fields: Vec<WinterfellWitnessCandidateField>,
    pub counts: MappingCounts,
    pub winterfell_dependency_imported: bool,
    pub proof_generation_enabled: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellWitnessCandidateField {
    pub winterfell_field: String,
    pub value: Option<u64>,
    pub value_status: String,
    pub source_artifact: Option<String>,
    pub source_field: Option<String>,
    pub class: MappingClass,
    pub note: String,
}

/// Implementation gap report derived from a Winterfell witness candidate.
///
/// This is the Phase 5E handoff artifact between deterministic candidate
/// shaping and any future prover-specific adapter. It remains planning-only:
/// no Winterfell dependency is imported and no proof is generated.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellWitnessImplementationGapReport {
    pub schema_version: String,
    pub source_schema_version: String,
    pub report_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub direct_ready_fields: Vec<WinterfellWitnessCandidateField>,
    pub partial_fields_requiring_normalization: Vec<WinterfellWitnessCandidateField>,
    pub unmapped_fields_requiring_source_data: Vec<WinterfellWitnessCandidateField>,
    pub unsupported_constraints_requiring_prover_work: Vec<String>,
    pub recommended_next_steps: Vec<String>,
    pub winterfell_dependency_imported: bool,
    pub proof_generation_enabled: bool,
}

/// Upstream data contract required before the Winterfell witness candidate can
/// become a complete prover witness.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellSourceDataRequirements {
    pub schema_version: String,
    pub source_schema_version: String,
    pub requirements_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub normalized_field_requirements: Vec<WinterfellSourceDataRequirement>,
    pub source_data_requirements: Vec<WinterfellSourceDataRequirement>,
    pub required_fields_total: usize,
    pub normalized_fields_total: usize,
    pub source_data_fields_total: usize,
    pub recommended_next_steps: Vec<String>,
    pub winterfell_dependency_imported: bool,
    pub proof_generation_enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellSourceDataRequirement {
    pub winterfell_field: String,
    pub requirement_type: String,
    pub source_artifact: Option<String>,
    pub source_field: Option<String>,
    pub required_before: String,
    pub note: String,
}

/// Fixture-only source data that satisfies the Phase 5F requirements.
///
/// This is not active claim intake. It is a deterministic test fixture for
/// future adapter work, so the missing Winterfell PoC fields can be validated
/// before any prover dependency is introduced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellSourceDataFixture {
    pub schema_version: String,
    pub source_schema_version: String,
    pub fixture_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub member_id: String,
    pub provider_npi: String,
    pub diagnosis_count: u64,
    pub max_charge_cents: u64,
    pub service_line_count: u64,
    pub prior_auth_ok: u8,
    pub charge_cents: u64,
    pub program_integrity_hold: u8,
    pub source_requirements_satisfied: Vec<String>,
    pub winterfell_dependency_imported: bool,
    pub proof_generation_enabled: bool,
    pub notes: Vec<String>,
}

/// Complete adapter-ready candidate assembled from the base Winterfell witness
/// candidate plus fixture-only source data.
///
/// This is still not a Winterfell witness. It is a deterministic pre-prover
/// artifact that proves every imported PoC field can be populated once the
/// Phase 5G source-data fixture exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellCompleteWitnessCandidate {
    pub schema_version: String,
    pub source_schema_version: String,
    pub candidate_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub fields: Vec<WinterfellCompleteWitnessField>,
    pub field_count: usize,
    pub all_fields_populated: bool,
    pub winterfell_dependency_imported: bool,
    pub proof_generation_enabled: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WinterfellCompleteWitnessField {
    pub winterfell_field: String,
    pub value: u64,
    pub value_status: String,
    pub source_artifact: String,
    pub source_field: String,
    pub note: String,
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

/// One normalized fee schedule row that can eventually feed a
/// `feeScheduleRoot`.
///
/// These rows are source data only. They are not committed, sorted, hashed, or
/// proven by this crate until a future root-generation phase.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeScheduleEntryInput {
    pub fee_code: String,
    pub unit_amount_cents: u64,
    pub currency: String,
    pub effective_from: u64,
    pub effective_thru: Option<u64>,
    pub source_url: Option<String>,
    pub verification_status: String,
}

/// Typed source data for a future `feeScheduleRoot`.
///
/// This object is intentionally pre-root. It records the source shape needed by
/// a future fee schedule tree, but it does not fetch, price, hash, or build a
/// Merkle root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeScheduleRootInput {
    pub schema_version: String,
    pub source_schema_version: String,
    pub input_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub fee_schedule_id: Option<String>,
    pub entries: Vec<FeeScheduleEntryInput>,
    pub root_generation_status: String,
    pub notes: Vec<String>,
}

/// Typed source data for a future `nullifierRootBefore` ->
/// `nullifierRootAfter` transition.
///
/// This object is intentionally pre-root. It records the state-transition shape
/// needed by a future duplicate-spend/replay-prevention tree, but it does not
/// derive a nullifier, check tree membership, update a tree, or build Merkle
/// roots.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierRootTransitionInput {
    pub schema_version: String,
    pub source_schema_version: String,
    pub input_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub nullifier_candidate: Option<String>,
    pub nullifier_root_before: Option<String>,
    pub nullifier_root_after: Option<String>,
    pub transition_status: String,
    pub root_generation_status: String,
    pub notes: Vec<String>,
}

/// Phase 8 planning artifact for the future real STARK proof boundary.
///
/// This is not a real proof artifact yet. It defines the exact fields a future
/// prover output must satisfy before Solidity V1 verifier integration can be
/// considered.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkProofArtifactV1Candidate {
    pub schema_version: String,
    pub source_schema_version: String,
    pub artifact_status: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub decision: u8,
    pub failure_code: u32,
    pub public_inputs: StarkProofArtifactPublicInputs,
    pub proof: StarkProofArtifactProof,
    pub local_verification: StarkProofArtifactLocalVerification,
    pub solidity_abi_candidate: String,
    pub runtime_wired: bool,
    pub on_chain_submission: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkProofArtifactPublicInputs {
    pub claim_hash: String,
    pub decision: u8,
    pub failure_code: u32,
    pub public_input_root: Option<String>,
    pub claim_source_root: Option<String>,
    pub oracle_facts_root: Option<String>,
    pub fee_schedule_root: Option<String>,
    pub nullifier_root_before: Option<String>,
    pub nullifier_root_after: Option<String>,
    pub batch_root: Option<String>,
    pub root_status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkProofArtifactProof {
    pub proof_bytes: Option<String>,
    pub proof_bytes_status: String,
    pub proof_commitment: Option<String>,
    pub proof_commitment_status: String,
    pub prover: Option<String>,
    pub prover_status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkProofArtifactLocalVerification {
    pub verified: bool,
    pub verification_status: String,
    pub verifier: Option<String>,
}

/// Phase 8 schema boundary for the future real STARK proof artifact.
///
/// This is still not a proof artifact. It is a deterministic contract that
/// names the fields, encodings, and source responsibilities the first real
/// artifact must satisfy before runtime or Solidity verifier wiring.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkProofArtifactV1BoundarySpec {
    pub schema_version: String,
    pub source_schema_version: String,
    pub target_artifact_schema_version: String,
    pub boundary_status: String,
    pub required_public_inputs: Vec<StarkProofArtifactFieldRequirement>,
    pub required_proof_fields: Vec<StarkProofArtifactFieldRequirement>,
    pub required_local_verification_fields: Vec<StarkProofArtifactFieldRequirement>,
    pub solidity_abi_candidate: String,
    pub runtime_wiring_status: String,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StarkProofArtifactFieldRequirement {
    pub field_name: String,
    pub encoding: String,
    pub source: String,
    pub requirement_status: String,
}

/// Deterministic assembly plan for the future `public_input_root`.
///
/// This is not root generation. It defines canonical field order and source
/// requirements so the future root preimage cannot drift between prover,
/// verifier, and settlement layers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicInputRootAssemblyPlan {
    pub schema_version: String,
    pub source_schema_version: String,
    pub plan_status: String,
    pub hash_strategy: String,
    pub canonical_encoding: String,
    pub ordered_fields: Vec<PublicInputRootField>,
    pub expected_field_count: usize,
    pub public_input_root: Option<String>,
    pub root_generation_status: String,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicInputRootField {
    pub position: usize,
    pub field_name: String,
    pub encoding: String,
    pub source: String,
    pub value_status: String,
}

/// First deterministic candidate digest for `public_input_root`.
///
/// This is not the final production public input root. It hashes the current
/// assembly-plan preimage with SHA-256 so later prover/verifier layers have a
/// stable candidate contract to test against while the production hash/root
/// strategy remains explicitly unselected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicInputRootDigestCandidate {
    pub schema_version: String,
    pub source_schema_version: String,
    pub candidate_status: String,
    pub hash_algorithm: String,
    pub canonical_encoding: String,
    pub ordered_fields: Vec<PublicInputRootDigestField>,
    pub expected_field_count: usize,
    pub canonical_preimage: String,
    pub public_input_root_candidate: String,
    pub root_generation_status: String,
    pub production_hash_selected: bool,
    pub runtime_wiring_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicInputRootDigestField {
    pub position: usize,
    pub field_name: String,
    pub encoded_value: String,
    pub value_status: String,
}

/// First deterministic candidate digest for the source roots that will
/// eventually feed `public_input_root`.
///
/// This is not production root generation. It hashes the canonical serialized
/// source-root input with SHA-256 so the bridge chain can test stable artifact
/// movement while the production tree/hash strategy remains explicitly
/// unselected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceRootDigestCandidate {
    pub schema_version: String,
    pub source_schema_version: String,
    pub source_root_kind: String,
    pub candidate_status: String,
    pub hash_algorithm: String,
    pub canonical_encoding: String,
    pub canonical_preimage: String,
    pub source_root_candidate: String,
    pub root_generation_status: String,
    pub production_hash_selected: bool,
    pub runtime_wiring_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

/// Planning-only aggregation of source-root digest candidates into the future
/// `public_input_root` field set.
///
/// This does not recompute `public_input_root` and does not select production
/// Merkle/hash semantics. It records how the current source-root candidates
/// would bind to public-input fields once real root generation exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceRootAggregationPlan {
    pub schema_version: String,
    pub source_schema_version: String,
    pub plan_status: String,
    pub public_input_root_candidate: String,
    pub public_input_root_candidate_status: String,
    pub source_root_bindings: Vec<SourceRootAggregationBinding>,
    pub expected_source_root_count: usize,
    pub all_source_roots_bound: bool,
    pub root_generation_status: String,
    pub production_hash_selected: bool,
    pub runtime_wiring_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceRootAggregationBinding {
    pub position: usize,
    pub source_root_kind: String,
    pub public_input_fields: Vec<String>,
    pub source_schema_version: String,
    pub source_root_candidate: String,
    pub binding_status: String,
}

/// Deterministic preimage plan for the future `proof_commitment`.
///
/// This does not hash proof bytes and does not create a commitment. It locks
/// the canonical metadata/proof field order that a future prover adapter must
/// use before a proof artifact can be considered settlement-ready.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCommitmentPreimagePlan {
    pub schema_version: String,
    pub source_schema_version: String,
    pub plan_status: String,
    pub hash_strategy: String,
    pub canonical_encoding: String,
    pub ordered_components: Vec<ProofCommitmentPreimageComponent>,
    pub expected_component_count: usize,
    pub proof_commitment: Option<String>,
    pub commitment_generation_status: String,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCommitmentPreimageComponent {
    pub position: usize,
    pub component_name: String,
    pub encoding: String,
    pub source: String,
    pub value_status: String,
}

/// Fixture expectations for the first real STARK proof artifact.
///
/// This is still planning-only. It locks the approved/denied shapes that a
/// future real prover artifact must satisfy before local verification,
/// Solidity verifier wiring, or ClaimsRegistry adapter wiring can be enabled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofArtifactFixtureExpectationSet {
    pub schema_version: String,
    pub source_schema_version: String,
    pub expectation_set_status: String,
    pub expected_fixtures: Vec<ProofArtifactFixtureExpectation>,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofArtifactFixtureExpectation {
    pub fixture_id: String,
    pub decision: u8,
    pub failure_code: u32,
    pub required_public_input_root_status: String,
    pub required_proof_bytes_status: String,
    pub required_proof_commitment_status: String,
    pub required_local_verification_status: String,
    pub runtime_wiring_allowed: bool,
}

/// Byte encoding plan for the selected future STARK prover.
///
/// This does not select a runtime prover and does not produce proof bytes. It
/// locks the first canonical byte-contract that future prover, local verifier,
/// proof commitment, and Solidity calldata layers must agree on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedProverByteEncodingPlan {
    pub schema_version: String,
    pub source_schema_version: String,
    pub plan_status: String,
    pub selected_prover: String,
    pub proof_bytes_encoding: String,
    pub proof_bytes_status: String,
    pub canonical_byte_order: String,
    pub serialization_format: String,
    pub compression_status: String,
    pub commitment_binding_fields: Vec<String>,
    pub expected_binding_field_count: usize,
    pub runtime_wiring_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

/// Phase 8 checkpoint bundle for all pre-prover boundary artifacts.
///
/// This is a planning-only manifest. It does not generate a proof, does not
/// select production root/hash semantics, and does not allow runtime wiring.
/// Its job is to prove the current pre-prover artifacts are internally
/// coherent before real prover work begins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8PreProverBundleCheckpoint {
    pub schema_version: String,
    pub source_schema_version: String,
    pub checkpoint_status: String,
    pub artifacts: Vec<Phase8CheckpointArtifact>,
    pub expected_artifact_count: usize,
    pub all_artifacts_validated: bool,
    pub all_source_roots_bound: bool,
    pub production_hash_selected: bool,
    pub runtime_wiring_allowed: bool,
    pub proof_generation_enabled: bool,
    pub groth16_flow_unchanged: bool,
    pub recommended_next_steps: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8CheckpointArtifact {
    pub artifact_id: String,
    pub schema_version: String,
    pub status: String,
    pub validation_status: String,
}

/// Planning-only checklist for converting the validated Phase 8 pre-prover
/// bundle into a real prover implementation.
///
/// This checklist is deliberately not a proof implementation. It is the
/// implementation-control artifact that names the remaining blockers before
/// any STARK runtime cutover can be considered.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8RealProverImplementationChecklist {
    pub schema_version: String,
    pub source_schema_version: String,
    pub checklist_status: String,
    pub source_checkpoint_status: String,
    pub work_items: Vec<Phase8RealProverWorkItem>,
    pub expected_work_item_count: usize,
    pub all_pre_prover_artifacts_validated: bool,
    pub runtime_cutover_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub completion_gate: String,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8RealProverWorkItem {
    pub item_id: String,
    pub category: String,
    pub description: String,
    pub required_before: String,
    pub current_status: String,
    pub blocks_runtime_cutover: bool,
}

/// Test-only harness boundary for the first prover execution lane.
///
/// This plan permits a feature-gated/local proof-generation experiment, but it
/// does not approve runtime cutover, Solidity verifier wiring, or replacement
/// of the active Groth16 flow.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8TestOnlyProverHarnessPlan {
    pub schema_version: String,
    pub source_schema_version: String,
    pub harness_status: String,
    pub selected_preview_prover: String,
    pub execution_mode: String,
    pub required_inputs: Vec<Phase8HarnessArtifact>,
    pub expected_input_count: usize,
    pub expected_outputs: Vec<Phase8HarnessArtifact>,
    pub expected_output_count: usize,
    pub feature_gate_required: bool,
    pub test_only_proof_generation_allowed: bool,
    pub runtime_cutover_allowed: bool,
    pub on_chain_submission_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8HarnessArtifact {
    pub artifact_id: String,
    pub schema_version: String,
    pub path_hint: String,
    pub requirement_status: String,
}

/// Test-only execution report for the first local prover harness path.
///
/// This report is intentionally conservative: it can acknowledge a
/// feature-gated Winterfell proof preview, but it cannot enable runtime cutover,
/// contract writes, or replacement of the active Groth16 flow.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8TestOnlyProverHarnessExecutionReport {
    pub schema_version: String,
    pub source_schema_version: String,
    pub execution_status: String,
    pub selected_preview_prover: String,
    pub execution_mode: String,
    pub input_artifacts: Vec<Phase8HarnessArtifact>,
    pub expected_input_count: usize,
    pub output_artifacts: Vec<Phase8HarnessArtifact>,
    pub expected_output_count: usize,
    pub feature_gate_used: bool,
    pub proof_preview_status: String,
    pub proof_size_bytes: usize,
    pub prove_ms: u128,
    pub verify_ms: u128,
    pub local_verification_status: String,
    pub proof_bytes_status: String,
    pub runtime_cutover_allowed: bool,
    pub on_chain_submission_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

/// Boundary adapter plan from feature-gated proof preview to a future real
/// STARK proof artifact.
///
/// This object is not a prover and not a proof. It defines the exact
/// transformations that must happen before the preview lane can produce a real
/// `stark-proof-artifact-v1` candidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8RealProverBoundaryAdapterPlan {
    pub schema_version: String,
    pub source_schema_version: String,
    pub adapter_status: String,
    pub source_execution_status: String,
    pub source_preview_prover: String,
    pub target_prover_status: String,
    pub target_artifact_schema_version: String,
    pub required_transformations: Vec<Phase8RealProverBoundaryTransformation>,
    pub expected_transformation_count: usize,
    pub blocked_runtime_cutover_conditions: Vec<String>,
    pub expected_blocker_count: usize,
    pub preview_artifact_reusable_for_runtime: bool,
    pub real_proof_generation_allowed: bool,
    pub local_verification_required: bool,
    pub runtime_cutover_allowed: bool,
    pub on_chain_submission_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8RealProverBoundaryTransformation {
    pub transformation_id: String,
    pub source_artifact: String,
    pub target_field: String,
    pub requirement: String,
    pub status: String,
}

/// Readiness gate for producing a real `stark-proof-artifact-v1`.
///
/// This is the final conservative boundary before real proof generation work.
/// It must remain blocked until every required transformation has an explicit
/// implementation source and has been promoted by a later phase.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8RealProofArtifactReadinessGate {
    pub schema_version: String,
    pub source_schema_version: String,
    pub readiness_status: String,
    pub target_artifact_schema_version: String,
    pub transformation_gates: Vec<Phase8ReadinessTransformationGate>,
    pub expected_transformation_gate_count: usize,
    pub satisfied_gate_count: usize,
    pub unsatisfied_gate_count: usize,
    pub blockers: Vec<String>,
    pub expected_blocker_count: usize,
    pub real_proof_generation_allowed: bool,
    pub real_artifact_emission_allowed: bool,
    pub runtime_cutover_allowed: bool,
    pub on_chain_submission_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8ReadinessTransformationGate {
    pub transformation_id: String,
    pub implementation_source: Option<String>,
    pub readiness_status: String,
    pub blocks_real_proof_generation: bool,
}

/// Planned implementation-source registry for the real proof artifact
/// readiness gate.
///
/// This registry is a routing plan, not implementation evidence. It documents
/// where each blocked transformation should eventually be implemented while
/// keeping real proof generation disabled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8ImplementationSourceRegistry {
    pub schema_version: String,
    pub source_schema_version: String,
    pub registry_status: String,
    pub target_artifact_schema_version: String,
    pub planned_sources: Vec<Phase8ImplementationSourceEntry>,
    pub expected_source_count: usize,
    pub implementation_evidence_status: String,
    pub satisfied_gate_count: usize,
    pub unsatisfied_gate_count: usize,
    pub real_proof_generation_allowed: bool,
    pub real_artifact_emission_allowed: bool,
    pub runtime_cutover_allowed: bool,
    pub on_chain_submission_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8ImplementationSourceEntry {
    pub transformation_id: String,
    pub planned_module: String,
    pub planned_owner: String,
    pub implementation_status: String,
    pub evidence_required: String,
    pub blocks_real_proof_generation: bool,
}

/// Evidence slots required before a planned implementation source can satisfy
/// a real proof artifact readiness gate.
///
/// This object intentionally contains empty evidence. It defines the evidence
/// contract for a later implementation phase while keeping proof generation
/// and runtime cutover blocked.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8ImplementationEvidenceSlots {
    pub schema_version: String,
    pub source_schema_version: String,
    pub evidence_status: String,
    pub target_artifact_schema_version: String,
    pub evidence_slots: Vec<Phase8ImplementationEvidenceSlot>,
    pub expected_slot_count: usize,
    pub populated_slot_count: usize,
    pub missing_slot_count: usize,
    pub real_proof_generation_allowed: bool,
    pub real_artifact_emission_allowed: bool,
    pub runtime_cutover_allowed: bool,
    pub on_chain_submission_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8ImplementationEvidenceSlot {
    pub transformation_id: String,
    pub planned_module: String,
    pub required_evidence: Vec<String>,
    pub evidence_artifacts: Vec<String>,
    pub evidence_status: String,
    pub blocks_real_proof_generation: bool,
}

/// Readiness report generated from empty implementation evidence slots.
///
/// This report is intentionally negative: it summarizes exactly what remains
/// missing before a real prover can emit `stark-proof-artifact-v1`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8EvidenceReadinessReport {
    pub schema_version: String,
    pub source_schema_version: String,
    pub report_status: String,
    pub target_artifact_schema_version: String,
    pub transformation_reports: Vec<Phase8EvidenceTransformationReport>,
    pub expected_transformation_count: usize,
    pub populated_slot_count: usize,
    pub missing_slot_count: usize,
    pub missing_evidence_total: usize,
    pub ready_transformation_count: usize,
    pub blocked_transformation_count: usize,
    pub real_proof_generation_allowed: bool,
    pub real_artifact_emission_allowed: bool,
    pub runtime_cutover_allowed: bool,
    pub on_chain_submission_allowed: bool,
    pub groth16_flow_unchanged: bool,
    pub recommended_next_steps: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Phase8EvidenceTransformationReport {
    pub transformation_id: String,
    pub planned_module: String,
    pub required_evidence_count: usize,
    pub missing_evidence: Vec<String>,
    pub evidence_status: String,
    pub readiness_status: String,
    pub blocks_real_proof_generation: bool,
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

    pub fn to_proof_artifact_v1_candidate(
        &self,
    ) -> Result<StarkProofArtifactV1Candidate, Vec<String>> {
        self.validate()?;

        Ok(StarkProofArtifactV1Candidate {
            schema_version: StarkProofArtifactV1Candidate::SCHEMA_VERSION.to_string(),
            source_schema_version: self.schema_version.clone(),
            artifact_status: StarkProofArtifactV1Candidate::ARTIFACT_STATUS.to_string(),
            claim_id: self.claim.claim_id.clone(),
            claim_hash: self.claim.claim_hash.clone(),
            decision: self.adjudication.decision,
            failure_code: self.adjudication.failure_code,
            public_inputs: StarkProofArtifactPublicInputs {
                claim_hash: self.public_inputs.claim_hash.clone(),
                decision: self.public_inputs.decision,
                failure_code: self.public_inputs.failure_code,
                public_input_root: None,
                claim_source_root: None,
                oracle_facts_root: None,
                fee_schedule_root: None,
                nullifier_root_before: None,
                nullifier_root_after: None,
                batch_root: None,
                root_status: "requires_root_generation".to_string(),
            },
            proof: StarkProofArtifactProof {
                proof_bytes: None,
                proof_bytes_status: "not_generated".to_string(),
                proof_commitment: None,
                proof_commitment_status: "not_generated".to_string(),
                prover: None,
                prover_status: "not_selected".to_string(),
            },
            local_verification: StarkProofArtifactLocalVerification {
                verified: false,
                verification_status: "not_verified_no_real_proof".to_string(),
                verifier: None,
            },
            solidity_abi_candidate: "IStarkClaimsVerifierV1Candidate".to_string(),
            runtime_wired: false,
            on_chain_submission: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "Phase 8 candidate only: no real STARK proof bytes are included.".to_string(),
                "Root fields are intentionally absent until root generation is implemented."
                    .to_string(),
                "This artifact is shaped to match the Solidity V1 verifier ABI candidate."
                    .to_string(),
                "The active Groth16 runtime remains unchanged.".to_string(),
            ],
        })
    }
}

impl StarkProofArtifactV1Candidate {
    pub const SCHEMA_VERSION: &'static str = "stark-proof-artifact-v1-candidate";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const ARTIFACT_STATUS: &'static str = "candidate_schema_only_no_real_proof";
    pub const SOLIDITY_ABI_CANDIDATE: &'static str = "IStarkClaimsVerifierV1Candidate";

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

        if self.artifact_status != Self::ARTIFACT_STATUS {
            errors.push(format!(
                "artifact_status must be {}, got {}",
                Self::ARTIFACT_STATUS,
                self.artifact_status
            ));
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        validate_0x_32_byte_hex("claim_hash", &self.claim_hash, &mut errors);
        validate_0x_32_byte_hex(
            "public_inputs.claim_hash",
            &self.public_inputs.claim_hash,
            &mut errors,
        );

        if self.claim_hash != self.public_inputs.claim_hash {
            errors.push("claim_hash must match public_inputs.claim_hash".to_string());
        }

        if self.decision > 1 {
            errors.push("decision must be 0 or 1".to_string());
        }

        if self.public_inputs.decision > 1 {
            errors.push("public_inputs.decision must be 0 or 1".to_string());
        }

        if self.decision != self.public_inputs.decision {
            errors.push("decision must match public_inputs.decision".to_string());
        }

        if self.failure_code != self.public_inputs.failure_code {
            errors.push("failure_code must match public_inputs.failure_code".to_string());
        }

        if self.decision == 1 && self.failure_code != 0 {
            errors.push("approved proof artifact candidate requires failure_code = 0".to_string());
        }

        if self.decision == 0 && self.failure_code == 0 {
            errors.push("denied proof artifact candidate requires failure_code != 0".to_string());
        }

        if self.public_inputs.root_status != "requires_root_generation" {
            errors.push("public_inputs.root_status must be requires_root_generation".to_string());
        }

        for (name, value) in [
            ("public_input_root", &self.public_inputs.public_input_root),
            ("claim_source_root", &self.public_inputs.claim_source_root),
            ("oracle_facts_root", &self.public_inputs.oracle_facts_root),
            ("fee_schedule_root", &self.public_inputs.fee_schedule_root),
            (
                "nullifier_root_before",
                &self.public_inputs.nullifier_root_before,
            ),
            (
                "nullifier_root_after",
                &self.public_inputs.nullifier_root_after,
            ),
            ("batch_root", &self.public_inputs.batch_root),
        ] {
            if value.is_some() {
                errors.push(format!(
                    "{name} must remain absent until root generation exists"
                ));
            }
        }

        if self.proof.proof_bytes.is_some() {
            errors.push("proof.proof_bytes must remain absent in candidate artifact".to_string());
        }

        if self.proof.proof_bytes_status != "not_generated" {
            errors.push("proof.proof_bytes_status must be not_generated".to_string());
        }

        if self.proof.proof_commitment.is_some() {
            errors.push(
                "proof.proof_commitment must remain absent in candidate artifact".to_string(),
            );
        }

        if self.proof.proof_commitment_status != "not_generated" {
            errors.push("proof.proof_commitment_status must be not_generated".to_string());
        }

        if self.proof.prover.is_some() {
            errors.push("proof.prover must remain absent until prover selection".to_string());
        }

        if self.proof.prover_status != "not_selected" {
            errors.push("proof.prover_status must be not_selected".to_string());
        }

        if self.local_verification.verified {
            errors.push("local_verification.verified must be false before real proof".to_string());
        }

        if self.local_verification.verification_status != "not_verified_no_real_proof" {
            errors.push(
                "local_verification.verification_status must be not_verified_no_real_proof"
                    .to_string(),
            );
        }

        if self.local_verification.verifier.is_some() {
            errors.push(
                "local_verification.verifier must remain absent before verifier selection"
                    .to_string(),
            );
        }

        if self.solidity_abi_candidate != Self::SOLIDITY_ABI_CANDIDATE {
            errors.push(format!(
                "solidity_abi_candidate must be {}",
                Self::SOLIDITY_ABI_CANDIDATE
            ));
        }

        if self.runtime_wired {
            errors.push("runtime_wired must remain false".to_string());
        }

        if self.on_chain_submission {
            errors.push("on_chain_submission must remain false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn to_v1_boundary_spec(&self) -> Result<StarkProofArtifactV1BoundarySpec, Vec<String>> {
        self.validate()?;

        Ok(StarkProofArtifactV1BoundarySpec {
            schema_version: StarkProofArtifactV1BoundarySpec::SCHEMA_VERSION.to_string(),
            source_schema_version: self.schema_version.clone(),
            target_artifact_schema_version: "stark-proof-artifact-v1".to_string(),
            boundary_status: StarkProofArtifactV1BoundarySpec::BOUNDARY_STATUS.to_string(),
            required_public_inputs: vec![
                required_field(
                    "claim_hash",
                    "0x_prefixed_32_byte_hex",
                    "stark_bridge_input.public_inputs.claim_hash",
                ),
                required_field(
                    "decision",
                    "u8_boolean_0_or_1",
                    "stark_bridge_input.public_inputs.decision",
                ),
                required_field(
                    "failure_code",
                    "u32",
                    "stark_bridge_input.public_inputs.failure_code",
                ),
                required_field(
                    "public_input_root",
                    "0x_prefixed_32_byte_hex",
                    "root_generation.public_inputs",
                ),
                required_field(
                    "claim_source_root",
                    "0x_prefixed_32_byte_hex",
                    "claim_source_root_input",
                ),
                required_field(
                    "oracle_facts_root",
                    "0x_prefixed_32_byte_hex",
                    "oracle_facts_root_input",
                ),
                required_field(
                    "fee_schedule_root",
                    "0x_prefixed_32_byte_hex",
                    "fee_schedule_root_input",
                ),
                required_field(
                    "nullifier_root_before",
                    "0x_prefixed_32_byte_hex",
                    "nullifier_root_transition_input",
                ),
                required_field(
                    "nullifier_root_after",
                    "0x_prefixed_32_byte_hex",
                    "nullifier_root_transition_input",
                ),
                required_field(
                    "batch_root",
                    "0x_prefixed_32_byte_hex",
                    "batch_root_generation",
                ),
            ],
            required_proof_fields: vec![
                required_field("proof_bytes", "0x_prefixed_bytes", "selected_stark_prover"),
                required_field(
                    "proof_commitment",
                    "0x_prefixed_32_byte_hex",
                    "hash_of_canonical_proof_bytes",
                ),
                required_field("prover", "string_identifier", "selected_stark_prover"),
            ],
            required_local_verification_fields: vec![
                required_field(
                    "verified",
                    "bool_true_after_local_verification",
                    "selected_stark_verifier",
                ),
                required_field(
                    "verification_status",
                    "verified_real_stark_proof",
                    "selected_stark_verifier",
                ),
                required_field("verifier", "string_identifier", "selected_stark_verifier"),
            ],
            solidity_abi_candidate: Self::SOLIDITY_ABI_CANDIDATE.to_string(),
            runtime_wiring_status: "not_wired_boundary_only".to_string(),
            groth16_flow_unchanged: true,
            notes: vec![
                "This boundary spec defines the first real STARK proof artifact contract."
                    .to_string(),
                "It does not contain proof bytes, roots, or local verification output.".to_string(),
                "All listed root fields must be generated before any runtime wiring.".to_string(),
                "The active Groth16 flow remains unchanged.".to_string(),
            ],
        })
    }
}

impl StarkProofArtifactV1BoundarySpec {
    pub const SCHEMA_VERSION: &'static str = "stark-proof-artifact-v1-boundary-spec";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-proof-artifact-v1-candidate";
    pub const TARGET_ARTIFACT_SCHEMA_VERSION: &'static str = "stark-proof-artifact-v1";
    pub const BOUNDARY_STATUS: &'static str = "schema_boundary_only_no_real_proof";
    pub const REQUIRED_PUBLIC_INPUT_FIELDS: [&'static str; 10] = [
        "claim_hash",
        "decision",
        "failure_code",
        "public_input_root",
        "claim_source_root",
        "oracle_facts_root",
        "fee_schedule_root",
        "nullifier_root_before",
        "nullifier_root_after",
        "batch_root",
    ];
    pub const REQUIRED_PROOF_FIELDS: [&'static str; 3] =
        ["proof_bytes", "proof_commitment", "prover"];
    pub const REQUIRED_LOCAL_VERIFICATION_FIELDS: [&'static str; 3] =
        ["verified", "verification_status", "verifier"];

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

        if self.target_artifact_schema_version != Self::TARGET_ARTIFACT_SCHEMA_VERSION {
            errors.push(format!(
                "target_artifact_schema_version must be {}, got {}",
                Self::TARGET_ARTIFACT_SCHEMA_VERSION,
                self.target_artifact_schema_version
            ));
        }

        if self.boundary_status != Self::BOUNDARY_STATUS {
            errors.push(format!(
                "boundary_status must be {}, got {}",
                Self::BOUNDARY_STATUS,
                self.boundary_status
            ));
        }

        validate_required_field_names(
            "required_public_inputs",
            &self.required_public_inputs,
            &Self::REQUIRED_PUBLIC_INPUT_FIELDS,
            &mut errors,
        );
        validate_required_field_names(
            "required_proof_fields",
            &self.required_proof_fields,
            &Self::REQUIRED_PROOF_FIELDS,
            &mut errors,
        );
        validate_required_field_names(
            "required_local_verification_fields",
            &self.required_local_verification_fields,
            &Self::REQUIRED_LOCAL_VERIFICATION_FIELDS,
            &mut errors,
        );

        for requirement in self
            .required_public_inputs
            .iter()
            .chain(self.required_proof_fields.iter())
            .chain(self.required_local_verification_fields.iter())
        {
            if requirement.encoding.trim().is_empty() {
                errors.push(format!(
                    "{}.encoding must be present",
                    requirement.field_name
                ));
            }
            if requirement.source.trim().is_empty() {
                errors.push(format!("{}.source must be present", requirement.field_name));
            }
            if requirement.requirement_status != "required_before_runtime_wiring" {
                errors.push(format!(
                    "{}.requirement_status must be required_before_runtime_wiring",
                    requirement.field_name
                ));
            }
        }

        if self.solidity_abi_candidate != StarkProofArtifactV1Candidate::SOLIDITY_ABI_CANDIDATE {
            errors.push(format!(
                "solidity_abi_candidate must be {}",
                StarkProofArtifactV1Candidate::SOLIDITY_ABI_CANDIDATE
            ));
        }

        if self.runtime_wiring_status != "not_wired_boundary_only" {
            errors.push("runtime_wiring_status must be not_wired_boundary_only".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn to_public_input_root_assembly_plan(
        &self,
    ) -> Result<PublicInputRootAssemblyPlan, Vec<String>> {
        self.validate()?;

        let ordered_fields = Self::REQUIRED_PUBLIC_INPUT_FIELDS
            .iter()
            .enumerate()
            .map(|(index, field_name)| {
                let requirement = self
                    .required_public_inputs
                    .iter()
                    .find(|requirement| requirement.field_name == *field_name)
                    .expect("boundary spec validation guarantees required public input field");

                PublicInputRootField {
                    position: index,
                    field_name: requirement.field_name.clone(),
                    encoding: requirement.encoding.clone(),
                    source: requirement.source.clone(),
                    value_status: if matches!(
                        requirement.field_name.as_str(),
                        "claim_hash" | "decision" | "failure_code"
                    ) {
                        "available_from_bridge_input".to_string()
                    } else {
                        "requires_future_root_generation".to_string()
                    },
                }
            })
            .collect();

        Ok(PublicInputRootAssemblyPlan {
            schema_version: PublicInputRootAssemblyPlan::SCHEMA_VERSION.to_string(),
            source_schema_version: self.schema_version.clone(),
            plan_status: PublicInputRootAssemblyPlan::PLAN_STATUS.to_string(),
            hash_strategy: "canonical_preimage_defined_hash_not_selected".to_string(),
            canonical_encoding: "ordered_field_name_colon_canonical_value_utf8_joined_by_newline"
                .to_string(),
            ordered_fields,
            expected_field_count: Self::REQUIRED_PUBLIC_INPUT_FIELDS.len(),
            public_input_root: None,
            root_generation_status: "not_generated".to_string(),
            groth16_flow_unchanged: true,
            notes: vec![
                "This plan defines public input root preimage order only.".to_string(),
                "It does not hash, generate, or verify a public_input_root.".to_string(),
                "The first three fields are available from StarkBridgeInput.".to_string(),
                "Root fields remain future generated dependencies.".to_string(),
            ],
        })
    }

    pub fn to_proof_commitment_preimage_plan(
        &self,
    ) -> Result<ProofCommitmentPreimagePlan, Vec<String>> {
        self.validate()?;

        Ok(ProofCommitmentPreimagePlan {
            schema_version: ProofCommitmentPreimagePlan::SCHEMA_VERSION.to_string(),
            source_schema_version: self.schema_version.clone(),
            plan_status: ProofCommitmentPreimagePlan::PLAN_STATUS.to_string(),
            hash_strategy: "canonical_preimage_defined_hash_not_selected".to_string(),
            canonical_encoding:
                "ordered_component_name_colon_canonical_value_utf8_joined_by_newline".to_string(),
            ordered_components: ProofCommitmentPreimagePlan::REQUIRED_ORDERED_COMPONENTS
                .iter()
                .enumerate()
                .map(
                    |(position, component_name)| ProofCommitmentPreimageComponent {
                        position,
                        component_name: component_name.to_string(),
                        encoding: proof_commitment_component_encoding(component_name).to_string(),
                        source: proof_commitment_component_source(component_name).to_string(),
                        value_status: proof_commitment_component_status(component_name).to_string(),
                    },
                )
                .collect(),
            expected_component_count: ProofCommitmentPreimagePlan::REQUIRED_ORDERED_COMPONENTS
                .len(),
            proof_commitment: None,
            commitment_generation_status: "not_generated".to_string(),
            groth16_flow_unchanged: true,
            notes: vec![
                "This plan defines proof commitment preimage order only.".to_string(),
                "It does not hash, generate, or verify proof_commitment.".to_string(),
                "Proof bytes and public_input_root remain future dependencies.".to_string(),
                "The active Groth16 flow remains unchanged.".to_string(),
            ],
        })
    }

    pub fn to_fixture_expectation_set(
        &self,
    ) -> Result<ProofArtifactFixtureExpectationSet, Vec<String>> {
        self.validate()?;

        Ok(ProofArtifactFixtureExpectationSet {
            schema_version: ProofArtifactFixtureExpectationSet::SCHEMA_VERSION.to_string(),
            source_schema_version: self.schema_version.clone(),
            expectation_set_status: ProofArtifactFixtureExpectationSet::EXPECTATION_SET_STATUS
                .to_string(),
            expected_fixtures: vec![
                ProofArtifactFixtureExpectation::approved_claim(),
                ProofArtifactFixtureExpectation::denied_claim(),
            ],
            groth16_flow_unchanged: true,
            notes: vec![
                "These fixture expectations define approved and denied shapes for future real STARK proof artifacts."
                    .to_string(),
                "They require roots, proof bytes, proof commitments, and local verification before runtime wiring."
                    .to_string(),
                "They do not generate a real proof and do not replace the active Groth16 flow."
                    .to_string(),
            ],
        })
    }

    pub fn to_selected_prover_byte_encoding_plan(
        &self,
    ) -> Result<SelectedProverByteEncodingPlan, Vec<String>> {
        self.validate()?;

        Ok(SelectedProverByteEncodingPlan {
            schema_version: SelectedProverByteEncodingPlan::SCHEMA_VERSION.to_string(),
            source_schema_version: self.schema_version.clone(),
            plan_status: SelectedProverByteEncodingPlan::PLAN_STATUS.to_string(),
            selected_prover: "winterfell_poc_preview".to_string(),
            proof_bytes_encoding: "0x_prefixed_canonical_stark_proof_bytes".to_string(),
            proof_bytes_status: "not_generated_encoding_contract_only".to_string(),
            canonical_byte_order: "prover_native_bytes_preserved_no_reordering".to_string(),
            serialization_format: "opaque_bytes_for_contract_boundary_v1".to_string(),
            compression_status: "no_additional_compression_selected".to_string(),
            commitment_binding_fields: SelectedProverByteEncodingPlan::REQUIRED_BINDING_FIELDS
                .iter()
                .map(|field| field.to_string())
                .collect(),
            expected_binding_field_count: SelectedProverByteEncodingPlan::REQUIRED_BINDING_FIELDS
                .len(),
            runtime_wiring_allowed: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "This plan defines the proof byte encoding contract only.".to_string(),
                "It does not generate proof bytes or select a production prover.".to_string(),
                "The proof commitment must bind the selected prover and canonical proof bytes."
                    .to_string(),
                "The active Groth16 flow remains unchanged.".to_string(),
            ],
        })
    }
}

impl PublicInputRootAssemblyPlan {
    pub const SCHEMA_VERSION: &'static str = "public-input-root-assembly-plan-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-proof-artifact-v1-boundary-spec";
    pub const PLAN_STATUS: &'static str = "planning_only_no_root_generation";
    pub const REQUIRED_ORDERED_FIELDS: [&'static str; 10] = [
        "claim_hash",
        "decision",
        "failure_code",
        "public_input_root",
        "claim_source_root",
        "oracle_facts_root",
        "fee_schedule_root",
        "nullifier_root_before",
        "nullifier_root_after",
        "batch_root",
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

        if self.plan_status != Self::PLAN_STATUS {
            errors.push(format!(
                "plan_status must be {}, got {}",
                Self::PLAN_STATUS,
                self.plan_status
            ));
        }

        if self.hash_strategy.trim().is_empty() {
            errors.push("hash_strategy must be present".to_string());
        }

        if self.canonical_encoding.trim().is_empty() {
            errors.push("canonical_encoding must be present".to_string());
        }

        if self.expected_field_count != Self::REQUIRED_ORDERED_FIELDS.len() {
            errors.push(format!(
                "expected_field_count must be {}",
                Self::REQUIRED_ORDERED_FIELDS.len()
            ));
        }

        if self.ordered_fields.len() != Self::REQUIRED_ORDERED_FIELDS.len() {
            errors.push(format!(
                "ordered_fields must contain exactly {} fields",
                Self::REQUIRED_ORDERED_FIELDS.len()
            ));
        }

        for (expected_position, expected_name) in Self::REQUIRED_ORDERED_FIELDS.iter().enumerate() {
            match self.ordered_fields.get(expected_position) {
                Some(field) => {
                    if field.position != expected_position {
                        errors.push(format!(
                            "ordered_fields[{expected_position}].position must be {expected_position}"
                        ));
                    }
                    if field.field_name != *expected_name {
                        errors.push(format!(
                            "ordered_fields[{expected_position}] must be {expected_name}"
                        ));
                    }
                    if field.encoding.trim().is_empty() {
                        errors.push(format!("{}.encoding must be present", field.field_name));
                    }
                    if field.source.trim().is_empty() {
                        errors.push(format!("{}.source must be present", field.field_name));
                    }
                    if !matches!(
                        field.value_status.as_str(),
                        "available_from_bridge_input" | "requires_future_root_generation"
                    ) {
                        errors.push(format!(
                            "{}.value_status must be available_from_bridge_input or requires_future_root_generation",
                            field.field_name
                        ));
                    }
                }
                None => errors.push(format!(
                    "ordered_fields missing position {expected_position}: {expected_name}"
                )),
            }
        }

        if self.public_input_root.is_some() {
            errors.push(
                "public_input_root must remain absent until root generation exists".to_string(),
            );
        }

        if self.root_generation_status != "not_generated" {
            errors.push("root_generation_status must be not_generated".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn to_digest_candidate(&self) -> Result<PublicInputRootDigestCandidate, Vec<String>> {
        self.validate()?;

        let ordered_fields: Vec<PublicInputRootDigestField> = self
            .ordered_fields
            .iter()
            .map(|field| PublicInputRootDigestField {
                position: field.position,
                field_name: field.field_name.clone(),
                encoded_value: public_input_root_candidate_value(field),
                value_status: field.value_status.clone(),
            })
            .collect();
        let canonical_preimage =
            build_public_input_root_candidate_preimage(&ordered_fields, &self.canonical_encoding);
        let public_input_root_candidate = sha256_hex(&canonical_preimage);

        Ok(PublicInputRootDigestCandidate {
            schema_version: PublicInputRootDigestCandidate::SCHEMA_VERSION.to_string(),
            source_schema_version: self.schema_version.clone(),
            candidate_status: PublicInputRootDigestCandidate::CANDIDATE_STATUS.to_string(),
            hash_algorithm: PublicInputRootDigestCandidate::HASH_ALGORITHM.to_string(),
            canonical_encoding: self.canonical_encoding.clone(),
            expected_field_count: ordered_fields.len(),
            ordered_fields,
            canonical_preimage,
            public_input_root_candidate,
            root_generation_status: "candidate_generated_not_runtime".to_string(),
            production_hash_selected: false,
            runtime_wiring_allowed: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "This digest candidate hashes the public input root assembly plan placeholders."
                    .to_string(),
                "It is deterministic test scaffolding, not a production public_input_root."
                    .to_string(),
                "Production hash/root strategy remains unselected.".to_string(),
                "The active Groth16 flow remains unchanged.".to_string(),
            ],
        })
    }
}

impl PublicInputRootDigestCandidate {
    pub const SCHEMA_VERSION: &'static str = "public-input-root-digest-candidate-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "public-input-root-assembly-plan-v0";
    pub const CANDIDATE_STATUS: &'static str = "candidate_digest_from_plan_only_no_runtime";
    pub const HASH_ALGORITHM: &'static str = "sha2_256_candidate_not_production_hash";

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

        if self.candidate_status != Self::CANDIDATE_STATUS {
            errors.push(format!(
                "candidate_status must be {}, got {}",
                Self::CANDIDATE_STATUS,
                self.candidate_status
            ));
        }

        if self.hash_algorithm != Self::HASH_ALGORITHM {
            errors.push(format!(
                "hash_algorithm must be {}, got {}",
                Self::HASH_ALGORITHM,
                self.hash_algorithm
            ));
        }

        if self.canonical_encoding.trim().is_empty() {
            errors.push("canonical_encoding must be present".to_string());
        }

        if self.expected_field_count != PublicInputRootAssemblyPlan::REQUIRED_ORDERED_FIELDS.len() {
            errors.push(format!(
                "expected_field_count must be {}",
                PublicInputRootAssemblyPlan::REQUIRED_ORDERED_FIELDS.len()
            ));
        }

        if self.ordered_fields.len() != PublicInputRootAssemblyPlan::REQUIRED_ORDERED_FIELDS.len() {
            errors.push(format!(
                "ordered_fields must contain exactly {} fields",
                PublicInputRootAssemblyPlan::REQUIRED_ORDERED_FIELDS.len()
            ));
        }

        for (expected_position, expected_name) in
            PublicInputRootAssemblyPlan::REQUIRED_ORDERED_FIELDS
                .iter()
                .enumerate()
        {
            match self.ordered_fields.get(expected_position) {
                Some(field) => {
                    if field.position != expected_position {
                        errors.push(format!(
                            "ordered_fields[{expected_position}].position must be {expected_position}"
                        ));
                    }
                    if field.field_name != *expected_name {
                        errors.push(format!(
                            "ordered_fields[{expected_position}] must be {expected_name}"
                        ));
                    }
                    if field.encoded_value.trim().is_empty() {
                        errors.push(format!(
                            "{}.encoded_value must be present",
                            field.field_name
                        ));
                    }
                    if !matches!(
                        field.value_status.as_str(),
                        "available_from_bridge_input" | "requires_future_root_generation"
                    ) {
                        errors.push(format!(
                            "{}.value_status must be available_from_bridge_input or requires_future_root_generation",
                            field.field_name
                        ));
                    }
                }
                None => errors.push(format!(
                    "ordered_fields missing position {expected_position}: {expected_name}"
                )),
            }
        }

        if self.canonical_preimage.trim().is_empty() {
            errors.push("canonical_preimage must be present".to_string());
        } else {
            let expected_preimage = build_public_input_root_candidate_preimage(
                &self.ordered_fields,
                &self.canonical_encoding,
            );
            if self.canonical_preimage != expected_preimage {
                errors.push("canonical_preimage must match ordered_fields".to_string());
            }
        }

        validate_0x_32_byte_hex(
            "public_input_root_candidate",
            &self.public_input_root_candidate,
            &mut errors,
        );

        if !self.canonical_preimage.trim().is_empty() {
            let expected_digest = sha256_hex(&self.canonical_preimage);
            if self.public_input_root_candidate != expected_digest {
                errors.push(
                    "public_input_root_candidate must equal sha2_256(canonical_preimage)"
                        .to_string(),
                );
            }
        }

        if self.root_generation_status != "candidate_generated_not_runtime" {
            errors
                .push("root_generation_status must be candidate_generated_not_runtime".to_string());
        }

        if self.production_hash_selected {
            errors.push("production_hash_selected must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl SourceRootDigestCandidate {
    pub const SCHEMA_VERSION: &'static str = "source-root-digest-candidate-v0";
    pub const CANDIDATE_STATUS: &'static str = "candidate_digest_from_source_input_only_no_runtime";
    pub const HASH_ALGORITHM: &'static str = "sha2_256_candidate_not_production_hash";
    pub const CANONICAL_ENCODING: &'static str = "canonical_json_preimage_v0";
    pub const ROOT_GENERATION_STATUS: &'static str = "candidate_generated_not_runtime";

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!(
                "schema_version must be {}, got {}",
                Self::SCHEMA_VERSION,
                self.schema_version
            ));
        }

        match expected_source_root_schema_version(&self.source_root_kind) {
            Some(expected_schema_version) => {
                if self.source_schema_version != expected_schema_version {
                    errors.push(format!(
                        "{} source_schema_version must be {}, got {}",
                        self.source_root_kind, expected_schema_version, self.source_schema_version
                    ));
                }
            }
            None => errors.push(format!(
                "source_root_kind is unsupported: {}",
                self.source_root_kind
            )),
        }

        if self.candidate_status != Self::CANDIDATE_STATUS {
            errors.push(format!(
                "candidate_status must be {}, got {}",
                Self::CANDIDATE_STATUS,
                self.candidate_status
            ));
        }

        if self.hash_algorithm != Self::HASH_ALGORITHM {
            errors.push(format!(
                "hash_algorithm must be {}, got {}",
                Self::HASH_ALGORITHM,
                self.hash_algorithm
            ));
        }

        if self.canonical_encoding != Self::CANONICAL_ENCODING {
            errors.push(format!(
                "canonical_encoding must be {}, got {}",
                Self::CANONICAL_ENCODING,
                self.canonical_encoding
            ));
        }

        if self.canonical_preimage.trim().is_empty() {
            errors.push("canonical_preimage must be present".to_string());
        }

        validate_0x_32_byte_hex(
            "source_root_candidate",
            &self.source_root_candidate,
            &mut errors,
        );

        if !self.canonical_preimage.trim().is_empty() {
            let expected_digest = sha256_hex(&self.canonical_preimage);
            if self.source_root_candidate != expected_digest {
                errors.push(
                    "source_root_candidate must equal sha2_256(canonical_preimage)".to_string(),
                );
            }
        }

        if self.root_generation_status != Self::ROOT_GENERATION_STATUS {
            errors.push(format!(
                "root_generation_status must be {}",
                Self::ROOT_GENERATION_STATUS
            ));
        }

        if self.production_hash_selected {
            errors.push("production_hash_selected must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl SourceRootAggregationPlan {
    pub const SCHEMA_VERSION: &'static str = "source-root-aggregation-plan-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        "public-input-root-digest-candidate-v0+source-root-digest-candidate-v0";
    pub const PLAN_STATUS: &'static str = "planning_only_source_roots_bound_no_public_root_rewrite";
    pub const PUBLIC_INPUT_ROOT_CANDIDATE_STATUS: &'static str =
        "public_input_root_digest_candidate_preserved";
    pub const BINDING_STATUS: &'static str = "source_root_candidate_bound_to_public_input_fields";
    pub const ROOT_GENERATION_STATUS: &'static str = "not_generated_binding_plan_only";
    pub const REQUIRED_SOURCE_ROOT_KINDS: [&'static str; 4] = [
        "claim_source_root",
        "oracle_facts_root",
        "fee_schedule_root",
        "nullifier_root_transition",
    ];

    pub fn from_candidates(
        public_input_root: &PublicInputRootDigestCandidate,
        source_roots: &[SourceRootDigestCandidate],
    ) -> Result<Self, Vec<String>> {
        public_input_root.validate()?;
        let mut errors = Vec::new();

        if source_roots.len() != Self::REQUIRED_SOURCE_ROOT_KINDS.len() {
            errors.push(format!(
                "source_roots must contain exactly {} candidates",
                Self::REQUIRED_SOURCE_ROOT_KINDS.len()
            ));
        }

        let mut bindings = Vec::with_capacity(Self::REQUIRED_SOURCE_ROOT_KINDS.len());
        for (position, expected_kind) in Self::REQUIRED_SOURCE_ROOT_KINDS.iter().enumerate() {
            let matches: Vec<&SourceRootDigestCandidate> = source_roots
                .iter()
                .filter(|candidate| candidate.source_root_kind == *expected_kind)
                .collect();

            match matches.as_slice() {
                [candidate] => {
                    if let Err(candidate_errors) = candidate.validate() {
                        errors.extend(candidate_errors);
                    }
                    bindings.push(SourceRootAggregationBinding {
                        position,
                        source_root_kind: candidate.source_root_kind.clone(),
                        public_input_fields: source_root_public_input_fields(expected_kind)
                            .iter()
                            .map(|field| (*field).to_string())
                            .collect(),
                        source_schema_version: candidate.source_schema_version.clone(),
                        source_root_candidate: candidate.source_root_candidate.clone(),
                        binding_status: Self::BINDING_STATUS.to_string(),
                    });
                }
                [] => errors.push(format!("missing source root candidate: {expected_kind}")),
                _ => errors.push(format!(
                    "source root candidate must be unique: {expected_kind}"
                )),
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: Self::SOURCE_SCHEMA_VERSION.to_string(),
            plan_status: Self::PLAN_STATUS.to_string(),
            public_input_root_candidate: public_input_root.public_input_root_candidate.clone(),
            public_input_root_candidate_status: Self::PUBLIC_INPUT_ROOT_CANDIDATE_STATUS
                .to_string(),
            expected_source_root_count: bindings.len(),
            source_root_bindings: bindings,
            all_source_roots_bound: true,
            root_generation_status: Self::ROOT_GENERATION_STATUS.to_string(),
            production_hash_selected: false,
            runtime_wiring_allowed: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "This plan binds source-root digest candidates into the public-input-root field set."
                    .to_string(),
                "It preserves the existing public_input_root digest candidate and does not recompute it."
                    .to_string(),
                "Production hash/root semantics remain unselected.".to_string(),
                "The active Groth16 flow remains unchanged.".to_string(),
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

        if self.plan_status != Self::PLAN_STATUS {
            errors.push(format!(
                "plan_status must be {}, got {}",
                Self::PLAN_STATUS,
                self.plan_status
            ));
        }

        validate_0x_32_byte_hex(
            "public_input_root_candidate",
            &self.public_input_root_candidate,
            &mut errors,
        );

        if self.public_input_root_candidate_status != Self::PUBLIC_INPUT_ROOT_CANDIDATE_STATUS {
            errors.push(format!(
                "public_input_root_candidate_status must be {}",
                Self::PUBLIC_INPUT_ROOT_CANDIDATE_STATUS
            ));
        }

        if self.expected_source_root_count != Self::REQUIRED_SOURCE_ROOT_KINDS.len() {
            errors.push(format!(
                "expected_source_root_count must be {}",
                Self::REQUIRED_SOURCE_ROOT_KINDS.len()
            ));
        }

        if self.source_root_bindings.len() != Self::REQUIRED_SOURCE_ROOT_KINDS.len() {
            errors.push(format!(
                "source_root_bindings must contain exactly {} bindings",
                Self::REQUIRED_SOURCE_ROOT_KINDS.len()
            ));
        }

        for (position, expected_kind) in Self::REQUIRED_SOURCE_ROOT_KINDS.iter().enumerate() {
            match self.source_root_bindings.get(position) {
                Some(binding) => {
                    if binding.position != position {
                        errors.push(format!(
                            "source_root_bindings[{position}].position must be {position}"
                        ));
                    }
                    if binding.source_root_kind != *expected_kind {
                        errors.push(format!(
                            "source_root_bindings[{position}].source_root_kind must be {expected_kind}"
                        ));
                    }
                    let expected_fields: Vec<String> =
                        source_root_public_input_fields(expected_kind)
                            .iter()
                            .map(|field| (*field).to_string())
                            .collect();
                    if binding.public_input_fields != expected_fields {
                        errors.push(format!(
                            "source_root_bindings[{position}].public_input_fields must match {expected_kind}"
                        ));
                    }
                    match expected_source_root_schema_version(expected_kind) {
                        Some(expected_schema_version)
                            if binding.source_schema_version == expected_schema_version => {}
                        Some(expected_schema_version) => errors.push(format!(
                            "source_root_bindings[{position}].source_schema_version must be {expected_schema_version}"
                        )),
                        None => errors.push(format!("unsupported source root kind: {expected_kind}")),
                    }
                    validate_0x_32_byte_hex(
                        &format!("source_root_bindings[{position}].source_root_candidate"),
                        &binding.source_root_candidate,
                        &mut errors,
                    );
                    if binding.binding_status != Self::BINDING_STATUS {
                        errors.push(format!(
                            "source_root_bindings[{position}].binding_status must be {}",
                            Self::BINDING_STATUS
                        ));
                    }
                }
                None => errors.push(format!(
                    "source_root_bindings missing position {position}: {expected_kind}"
                )),
            }
        }

        if !self.all_source_roots_bound {
            errors.push("all_source_roots_bound must be true".to_string());
        }

        if self.root_generation_status != Self::ROOT_GENERATION_STATUS {
            errors.push(format!(
                "root_generation_status must be {}",
                Self::ROOT_GENERATION_STATUS
            ));
        }

        if self.production_hash_selected {
            errors.push("production_hash_selected must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl ProofCommitmentPreimagePlan {
    pub const SCHEMA_VERSION: &'static str = "proof-commitment-preimage-plan-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-proof-artifact-v1-boundary-spec";
    pub const PLAN_STATUS: &'static str = "planning_only_no_commitment_generation";
    pub const REQUIRED_ORDERED_COMPONENTS: [&'static str; 8] = [
        "target_artifact_schema_version",
        "solidity_abi_candidate",
        "prover",
        "proof_bytes",
        "public_input_root",
        "claim_hash",
        "decision",
        "failure_code",
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

        if self.plan_status != Self::PLAN_STATUS {
            errors.push(format!(
                "plan_status must be {}, got {}",
                Self::PLAN_STATUS,
                self.plan_status
            ));
        }

        if self.hash_strategy.trim().is_empty() {
            errors.push("hash_strategy must be present".to_string());
        }

        if self.canonical_encoding.trim().is_empty() {
            errors.push("canonical_encoding must be present".to_string());
        }

        if self.expected_component_count != Self::REQUIRED_ORDERED_COMPONENTS.len() {
            errors.push(format!(
                "expected_component_count must be {}",
                Self::REQUIRED_ORDERED_COMPONENTS.len()
            ));
        }

        if self.ordered_components.len() != Self::REQUIRED_ORDERED_COMPONENTS.len() {
            errors.push(format!(
                "ordered_components must contain exactly {} components",
                Self::REQUIRED_ORDERED_COMPONENTS.len()
            ));
        }

        for (expected_position, expected_name) in
            Self::REQUIRED_ORDERED_COMPONENTS.iter().enumerate()
        {
            match self.ordered_components.get(expected_position) {
                Some(component) => {
                    if component.position != expected_position {
                        errors.push(format!(
                            "ordered_components[{expected_position}].position must be {expected_position}"
                        ));
                    }
                    if component.component_name != *expected_name {
                        errors.push(format!(
                            "ordered_components[{expected_position}] must be {expected_name}"
                        ));
                    }
                    if component.encoding.trim().is_empty() {
                        errors.push(format!(
                            "{}.encoding must be present",
                            component.component_name
                        ));
                    }
                    if component.source.trim().is_empty() {
                        errors.push(format!(
                            "{}.source must be present",
                            component.component_name
                        ));
                    }
                    if !matches!(
                        component.value_status.as_str(),
                        "available_from_boundary_spec"
                            | "available_from_future_artifact_public_inputs"
                            | "requires_selected_prover"
                            | "requires_real_proof_bytes"
                            | "requires_public_input_root_generation"
                    ) {
                        errors.push(format!(
                            "{}.value_status is invalid",
                            component.component_name
                        ));
                    }
                }
                None => errors.push(format!(
                    "ordered_components missing position {expected_position}: {expected_name}"
                )),
            }
        }

        if self.proof_commitment.is_some() {
            errors.push(
                "proof_commitment must remain absent until commitment generation exists"
                    .to_string(),
            );
        }

        if self.commitment_generation_status != "not_generated" {
            errors.push("commitment_generation_status must be not_generated".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl ProofArtifactFixtureExpectationSet {
    pub const SCHEMA_VERSION: &'static str = "proof-artifact-fixture-expectations-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-proof-artifact-v1-boundary-spec";
    pub const EXPECTATION_SET_STATUS: &'static str = "planning_only_no_real_proof";
    pub const EXPECTED_FIXTURE_IDS: [&'static str; 2] = ["approved_claim", "denied_claim"];

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

        if self.expectation_set_status != Self::EXPECTATION_SET_STATUS {
            errors.push(format!(
                "expectation_set_status must be {}, got {}",
                Self::EXPECTATION_SET_STATUS,
                self.expectation_set_status
            ));
        }

        if self.expected_fixtures.len() != Self::EXPECTED_FIXTURE_IDS.len() {
            errors.push(format!(
                "expected_fixtures must contain exactly {} fixtures",
                Self::EXPECTED_FIXTURE_IDS.len()
            ));
        }

        for fixture_id in Self::EXPECTED_FIXTURE_IDS {
            if !self.has_fixture(fixture_id) {
                errors.push(format!("missing expected fixture: {fixture_id}"));
            }
        }

        for fixture in &self.expected_fixtures {
            fixture.validate(&mut errors);
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn has_fixture(&self, fixture_id: &str) -> bool {
        self.expected_fixtures
            .iter()
            .any(|fixture| fixture.fixture_id == fixture_id)
    }
}

impl ProofArtifactFixtureExpectation {
    const REQUIRED_DEPENDENCY_STATUS: &'static str = "required_before_runtime_wiring";

    fn approved_claim() -> Self {
        Self {
            fixture_id: "approved_claim".to_string(),
            decision: 1,
            failure_code: 0,
            required_public_input_root_status: Self::REQUIRED_DEPENDENCY_STATUS.to_string(),
            required_proof_bytes_status: Self::REQUIRED_DEPENDENCY_STATUS.to_string(),
            required_proof_commitment_status: Self::REQUIRED_DEPENDENCY_STATUS.to_string(),
            required_local_verification_status: Self::REQUIRED_DEPENDENCY_STATUS.to_string(),
            runtime_wiring_allowed: false,
        }
    }

    fn denied_claim() -> Self {
        Self {
            fixture_id: "denied_claim".to_string(),
            decision: 0,
            failure_code: 7,
            required_public_input_root_status: Self::REQUIRED_DEPENDENCY_STATUS.to_string(),
            required_proof_bytes_status: Self::REQUIRED_DEPENDENCY_STATUS.to_string(),
            required_proof_commitment_status: Self::REQUIRED_DEPENDENCY_STATUS.to_string(),
            required_local_verification_status: Self::REQUIRED_DEPENDENCY_STATUS.to_string(),
            runtime_wiring_allowed: false,
        }
    }

    fn validate(&self, errors: &mut Vec<String>) {
        if !matches!(self.fixture_id.as_str(), "approved_claim" | "denied_claim") {
            errors.push(format!(
                "{}.fixture_id must be approved_claim or denied_claim",
                self.fixture_id
            ));
        }

        match self.fixture_id.as_str() {
            "approved_claim" => {
                if self.decision != 1 {
                    errors.push("approved_claim decision must be 1".to_string());
                }
                if self.failure_code != 0 {
                    errors.push("approved_claim failure_code must be 0".to_string());
                }
            }
            "denied_claim" => {
                if self.decision != 0 {
                    errors.push("denied_claim decision must be 0".to_string());
                }
                if self.failure_code == 0 {
                    errors.push("denied_claim failure_code must be non-zero".to_string());
                }
            }
            _ => {}
        }

        validate_fixture_dependency_status(
            &self.fixture_id,
            "required_public_input_root_status",
            &self.required_public_input_root_status,
            errors,
        );
        validate_fixture_dependency_status(
            &self.fixture_id,
            "required_proof_bytes_status",
            &self.required_proof_bytes_status,
            errors,
        );
        validate_fixture_dependency_status(
            &self.fixture_id,
            "required_proof_commitment_status",
            &self.required_proof_commitment_status,
            errors,
        );
        validate_fixture_dependency_status(
            &self.fixture_id,
            "required_local_verification_status",
            &self.required_local_verification_status,
            errors,
        );

        if self.runtime_wiring_allowed {
            errors.push(format!(
                "{}.runtime_wiring_allowed must be false",
                self.fixture_id
            ));
        }
    }
}

impl SelectedProverByteEncodingPlan {
    pub const SCHEMA_VERSION: &'static str = "selected-prover-byte-encoding-plan-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-proof-artifact-v1-boundary-spec";
    pub const PLAN_STATUS: &'static str = "planning_only_no_proof_bytes";
    pub const REQUIRED_BINDING_FIELDS: [&'static str; 5] = [
        "selected_prover",
        "proof_bytes_encoding",
        "canonical_byte_order",
        "serialization_format",
        "proof_bytes",
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

        if self.plan_status != Self::PLAN_STATUS {
            errors.push(format!(
                "plan_status must be {}, got {}",
                Self::PLAN_STATUS,
                self.plan_status
            ));
        }

        if self.selected_prover != "winterfell_poc_preview" {
            errors.push("selected_prover must be winterfell_poc_preview".to_string());
        }

        if self.proof_bytes_encoding != "0x_prefixed_canonical_stark_proof_bytes" {
            errors.push(
                "proof_bytes_encoding must be 0x_prefixed_canonical_stark_proof_bytes".to_string(),
            );
        }

        if self.proof_bytes_status != "not_generated_encoding_contract_only" {
            errors.push(
                "proof_bytes_status must be not_generated_encoding_contract_only".to_string(),
            );
        }

        if self.canonical_byte_order != "prover_native_bytes_preserved_no_reordering" {
            errors.push(
                "canonical_byte_order must be prover_native_bytes_preserved_no_reordering"
                    .to_string(),
            );
        }

        if self.serialization_format != "opaque_bytes_for_contract_boundary_v1" {
            errors.push(
                "serialization_format must be opaque_bytes_for_contract_boundary_v1".to_string(),
            );
        }

        if self.compression_status != "no_additional_compression_selected" {
            errors
                .push("compression_status must be no_additional_compression_selected".to_string());
        }

        if self.expected_binding_field_count != Self::REQUIRED_BINDING_FIELDS.len() {
            errors.push(format!(
                "expected_binding_field_count must be {}",
                Self::REQUIRED_BINDING_FIELDS.len()
            ));
        }

        if self.commitment_binding_fields.len() != Self::REQUIRED_BINDING_FIELDS.len() {
            errors.push(format!(
                "commitment_binding_fields must contain exactly {} fields",
                Self::REQUIRED_BINDING_FIELDS.len()
            ));
        }

        for (index, expected_field) in Self::REQUIRED_BINDING_FIELDS.iter().enumerate() {
            match self.commitment_binding_fields.get(index) {
                Some(field) if field == expected_field => {}
                Some(_) => errors.push(format!(
                    "commitment_binding_fields[{index}] must be {expected_field}"
                )),
                None => errors.push(format!(
                    "commitment_binding_fields missing position {index}: {expected_field}"
                )),
            }
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Phase8PreProverBundleCheckpoint {
    pub const SCHEMA_VERSION: &'static str = "phase8-pre-prover-bundle-checkpoint-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        "stark-proof-artifact-v1-boundary-spec+phase8-planning-artifacts";
    pub const CHECKPOINT_STATUS: &'static str =
        "pre_prover_bundle_validated_planning_only_no_real_proof";
    pub const EXPECTED_ARTIFACT_IDS: [&'static str; 6] = [
        "stark_proof_artifact_v1_boundary_spec",
        "public_input_root_digest_candidate",
        "source_root_aggregation_plan",
        "proof_commitment_preimage_plan",
        "proof_artifact_fixture_expectations",
        "selected_prover_byte_encoding_plan",
    ];

    pub fn from_artifacts(
        boundary_spec: &StarkProofArtifactV1BoundarySpec,
        public_input_root_digest_candidate: &PublicInputRootDigestCandidate,
        source_root_aggregation_plan: &SourceRootAggregationPlan,
        proof_commitment_preimage_plan: &ProofCommitmentPreimagePlan,
        proof_artifact_fixture_expectations: &ProofArtifactFixtureExpectationSet,
        selected_prover_byte_encoding_plan: &SelectedProverByteEncodingPlan,
    ) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();

        collect_validation_errors(
            "stark_proof_artifact_v1_boundary_spec",
            boundary_spec.validate(),
            &mut errors,
        );
        collect_validation_errors(
            "public_input_root_digest_candidate",
            public_input_root_digest_candidate.validate(),
            &mut errors,
        );
        collect_validation_errors(
            "source_root_aggregation_plan",
            source_root_aggregation_plan.validate(),
            &mut errors,
        );
        collect_validation_errors(
            "proof_commitment_preimage_plan",
            proof_commitment_preimage_plan.validate(),
            &mut errors,
        );
        collect_validation_errors(
            "proof_artifact_fixture_expectations",
            proof_artifact_fixture_expectations.validate(),
            &mut errors,
        );
        collect_validation_errors(
            "selected_prover_byte_encoding_plan",
            selected_prover_byte_encoding_plan.validate(),
            &mut errors,
        );

        if public_input_root_digest_candidate.public_input_root_candidate
            != source_root_aggregation_plan.public_input_root_candidate
        {
            errors.push(
                "public_input_root_digest_candidate must match source_root_aggregation_plan"
                    .to_string(),
            );
        }

        if proof_commitment_preimage_plan.source_schema_version != boundary_spec.schema_version {
            errors.push(
                "proof_commitment_preimage_plan must be derived from the boundary spec".to_string(),
            );
        }

        if proof_artifact_fixture_expectations.source_schema_version != boundary_spec.schema_version
        {
            errors.push(
                "proof_artifact_fixture_expectations must be derived from the boundary spec"
                    .to_string(),
            );
        }

        if selected_prover_byte_encoding_plan.source_schema_version != boundary_spec.schema_version
        {
            errors.push(
                "selected_prover_byte_encoding_plan must be derived from the boundary spec"
                    .to_string(),
            );
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: Self::SOURCE_SCHEMA_VERSION.to_string(),
            checkpoint_status: Self::CHECKPOINT_STATUS.to_string(),
            artifacts: vec![
                Phase8CheckpointArtifact::new(
                    "stark_proof_artifact_v1_boundary_spec",
                    &boundary_spec.schema_version,
                    &boundary_spec.boundary_status,
                ),
                Phase8CheckpointArtifact::new(
                    "public_input_root_digest_candidate",
                    &public_input_root_digest_candidate.schema_version,
                    &public_input_root_digest_candidate.candidate_status,
                ),
                Phase8CheckpointArtifact::new(
                    "source_root_aggregation_plan",
                    &source_root_aggregation_plan.schema_version,
                    &source_root_aggregation_plan.plan_status,
                ),
                Phase8CheckpointArtifact::new(
                    "proof_commitment_preimage_plan",
                    &proof_commitment_preimage_plan.schema_version,
                    &proof_commitment_preimage_plan.plan_status,
                ),
                Phase8CheckpointArtifact::new(
                    "proof_artifact_fixture_expectations",
                    &proof_artifact_fixture_expectations.schema_version,
                    &proof_artifact_fixture_expectations.expectation_set_status,
                ),
                Phase8CheckpointArtifact::new(
                    "selected_prover_byte_encoding_plan",
                    &selected_prover_byte_encoding_plan.schema_version,
                    &selected_prover_byte_encoding_plan.plan_status,
                ),
            ],
            expected_artifact_count: Self::EXPECTED_ARTIFACT_IDS.len(),
            all_artifacts_validated: true,
            all_source_roots_bound: source_root_aggregation_plan.all_source_roots_bound,
            production_hash_selected: false,
            runtime_wiring_allowed: false,
            proof_generation_enabled: false,
            groth16_flow_unchanged: true,
            recommended_next_steps: vec![
                "Select production root/hash semantics before replacing candidate digests.".to_string(),
                "Generate real prover witness data only after the source-root and public-input contracts are frozen.".to_string(),
                "Replace planning-only proof bytes and proof commitment placeholders with real prover output.".to_string(),
                "Keep Groth16 active until local STARK verification and settlement adapter tests pass with real artifacts.".to_string(),
            ],
            notes: vec![
                "This checkpoint validates Phase 8 pre-prover planning artifacts as a bundle.".to_string(),
                "It does not generate a STARK proof, public input root, source root, or proof commitment.".to_string(),
                "It does not permit runtime or on-chain wiring.".to_string(),
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

        if self.checkpoint_status != Self::CHECKPOINT_STATUS {
            errors.push(format!(
                "checkpoint_status must be {}, got {}",
                Self::CHECKPOINT_STATUS,
                self.checkpoint_status
            ));
        }

        if self.expected_artifact_count != Self::EXPECTED_ARTIFACT_IDS.len() {
            errors.push(format!(
                "expected_artifact_count must be {}",
                Self::EXPECTED_ARTIFACT_IDS.len()
            ));
        }

        if self.artifacts.len() != Self::EXPECTED_ARTIFACT_IDS.len() {
            errors.push(format!(
                "artifacts must contain exactly {} entries",
                Self::EXPECTED_ARTIFACT_IDS.len()
            ));
        }

        for (position, expected_id) in Self::EXPECTED_ARTIFACT_IDS.iter().enumerate() {
            match self.artifacts.get(position) {
                Some(artifact) => {
                    if artifact.artifact_id != *expected_id {
                        errors.push(format!(
                            "artifacts[{position}].artifact_id must be {expected_id}"
                        ));
                    }
                    if artifact.schema_version.trim().is_empty() {
                        errors.push(format!("{expected_id}.schema_version must be present"));
                    }
                    if artifact.status.trim().is_empty() {
                        errors.push(format!("{expected_id}.status must be present"));
                    }
                    if artifact.validation_status != "validated" {
                        errors.push(format!("{expected_id}.validation_status must be validated"));
                    }
                }
                None => errors.push(format!("missing checkpoint artifact: {expected_id}")),
            }
        }

        if !self.all_artifacts_validated {
            errors.push("all_artifacts_validated must be true".to_string());
        }

        if !self.all_source_roots_bound {
            errors.push("all_source_roots_bound must be true".to_string());
        }

        if self.production_hash_selected {
            errors.push("production_hash_selected must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.proof_generation_enabled {
            errors.push("proof_generation_enabled must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.recommended_next_steps.is_empty() {
            errors.push("recommended_next_steps must be non-empty".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Phase8CheckpointArtifact {
    fn new(artifact_id: &str, schema_version: &str, status: &str) -> Self {
        Self {
            artifact_id: artifact_id.to_string(),
            schema_version: schema_version.to_string(),
            status: status.to_string(),
            validation_status: "validated".to_string(),
        }
    }
}

impl Phase8RealProverImplementationChecklist {
    pub const SCHEMA_VERSION: &'static str = "phase8-real-prover-implementation-checklist-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "phase8-pre-prover-bundle-checkpoint-v0";
    pub const CHECKLIST_STATUS: &'static str =
        "implementation_checklist_only_no_real_proof_no_runtime_cutover";
    pub const COMPLETION_GATE: &'static str =
        "all_work_items_complete_and_real_stark_artifact_locally_verified";
    pub const EXPECTED_WORK_ITEM_IDS: [&'static str; 7] = [
        "select_production_hash_and_root_semantics",
        "generate_real_source_roots",
        "generate_real_public_input_root",
        "generate_real_stark_witness",
        "generate_real_stark_proof_bytes",
        "generate_and_bind_proof_commitment",
        "verify_real_stark_artifact_locally_before_solidity_cutover",
    ];

    pub fn from_checkpoint(
        checkpoint: &Phase8PreProverBundleCheckpoint,
    ) -> Result<Self, Vec<String>> {
        checkpoint.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: checkpoint.schema_version.clone(),
            checklist_status: Self::CHECKLIST_STATUS.to_string(),
            source_checkpoint_status: checkpoint.checkpoint_status.clone(),
            work_items: vec![
                Phase8RealProverWorkItem::new(
                    "select_production_hash_and_root_semantics",
                    "root_hash_strategy",
                    "Choose the production hash/root strategy for public input, source roots, and proof commitment.",
                    "real_root_generation",
                    "pending_candidate_sha256_only",
                ),
                Phase8RealProverWorkItem::new(
                    "generate_real_source_roots",
                    "source_roots",
                    "Replace source-root digest candidates with real claim/oracle/fee/nullifier roots.",
                    "public_input_root_generation",
                    "pending_source_digest_candidates_only",
                ),
                Phase8RealProverWorkItem::new(
                    "generate_real_public_input_root",
                    "public_inputs",
                    "Generate the real public_input_root from frozen public-input and source-root semantics.",
                    "real_stark_proof_artifact",
                    "pending_public_input_digest_candidate_only",
                ),
                Phase8RealProverWorkItem::new(
                    "generate_real_stark_witness",
                    "witness",
                    "Convert validated bridge inputs and root source data into a real prover witness.",
                    "real_stark_proof_bytes",
                    "pending_witness_plan_only",
                ),
                Phase8RealProverWorkItem::new(
                    "generate_real_stark_proof_bytes",
                    "proof",
                    "Generate opaque 0x-prefixed proof bytes using the selected prover boundary.",
                    "local_verification",
                    "pending_no_real_proof_bytes",
                ),
                Phase8RealProverWorkItem::new(
                    "generate_and_bind_proof_commitment",
                    "proof_commitment",
                    "Generate the proof commitment over prover identity, proof bytes, public input root, claim_hash, decision, and failure_code.",
                    "settlement_boundary_artifact",
                    "pending_preimage_plan_only",
                ),
                Phase8RealProverWorkItem::new(
                    "verify_real_stark_artifact_locally_before_solidity_cutover",
                    "verification",
                    "Run local verification against the real artifact before Solidity verifier or ClaimsRegistry cutover.",
                    "runtime_cutover",
                    "pending_no_local_real_stark_verification",
                ),
            ],
            expected_work_item_count: Self::EXPECTED_WORK_ITEM_IDS.len(),
            all_pre_prover_artifacts_validated: checkpoint.all_artifacts_validated
                && checkpoint.all_source_roots_bound,
            runtime_cutover_allowed: false,
            groth16_flow_unchanged: true,
            completion_gate: Self::COMPLETION_GATE.to_string(),
            notes: vec![
                "This checklist is generated from the validated Phase 8 pre-prover bundle checkpoint."
                    .to_string(),
                "It does not generate roots, witnesses, proof bytes, proof commitments, or Solidity verifier output."
                    .to_string(),
                "Every work item currently blocks runtime cutover.".to_string(),
                "Groth16 remains the active production prototype path until the completion gate is satisfied."
                    .to_string(),
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

        if self.checklist_status != Self::CHECKLIST_STATUS {
            errors.push(format!(
                "checklist_status must be {}, got {}",
                Self::CHECKLIST_STATUS,
                self.checklist_status
            ));
        }

        if self.source_checkpoint_status != Phase8PreProverBundleCheckpoint::CHECKPOINT_STATUS {
            errors.push(format!(
                "source_checkpoint_status must be {}",
                Phase8PreProverBundleCheckpoint::CHECKPOINT_STATUS
            ));
        }

        if self.expected_work_item_count != Self::EXPECTED_WORK_ITEM_IDS.len() {
            errors.push(format!(
                "expected_work_item_count must be {}",
                Self::EXPECTED_WORK_ITEM_IDS.len()
            ));
        }

        if self.work_items.len() != Self::EXPECTED_WORK_ITEM_IDS.len() {
            errors.push(format!(
                "work_items must contain exactly {} items",
                Self::EXPECTED_WORK_ITEM_IDS.len()
            ));
        }

        for (position, expected_id) in Self::EXPECTED_WORK_ITEM_IDS.iter().enumerate() {
            match self.work_items.get(position) {
                Some(item) => {
                    if item.item_id != *expected_id {
                        errors.push(format!(
                            "work_items[{position}].item_id must be {expected_id}"
                        ));
                    }
                    item.validate(expected_id, &mut errors);
                }
                None => errors.push(format!("missing work item: {expected_id}")),
            }
        }

        if !self.all_pre_prover_artifacts_validated {
            errors.push("all_pre_prover_artifacts_validated must be true".to_string());
        }

        if self.runtime_cutover_allowed {
            errors.push("runtime_cutover_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.completion_gate != Self::COMPLETION_GATE {
            errors.push(format!("completion_gate must be {}", Self::COMPLETION_GATE));
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Phase8RealProverWorkItem {
    fn new(
        item_id: &str,
        category: &str,
        description: &str,
        required_before: &str,
        current_status: &str,
    ) -> Self {
        Self {
            item_id: item_id.to_string(),
            category: category.to_string(),
            description: description.to_string(),
            required_before: required_before.to_string(),
            current_status: current_status.to_string(),
            blocks_runtime_cutover: true,
        }
    }

    fn validate(&self, expected_id: &str, errors: &mut Vec<String>) {
        if self.item_id != expected_id {
            errors.push(format!("work item id must be {expected_id}"));
        }
        if self.category.trim().is_empty() {
            errors.push(format!("{expected_id}.category must be present"));
        }
        if self.description.trim().is_empty() {
            errors.push(format!("{expected_id}.description must be present"));
        }
        if self.required_before.trim().is_empty() {
            errors.push(format!("{expected_id}.required_before must be present"));
        }
        if self.current_status.trim().is_empty() {
            errors.push(format!("{expected_id}.current_status must be present"));
        }
        if !self.blocks_runtime_cutover {
            errors.push(format!("{expected_id}.blocks_runtime_cutover must be true"));
        }
    }
}

impl Phase8TestOnlyProverHarnessPlan {
    pub const SCHEMA_VERSION: &'static str = "phase8-test-only-prover-harness-plan-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        "phase8-real-prover-implementation-checklist-v0";
    pub const HARNESS_STATUS: &'static str = "test_only_harness_boundary_no_runtime_cutover";
    pub const SELECTED_PREVIEW_PROVER: &'static str = "winterfell_poc_preview";
    pub const EXECUTION_MODE: &'static str = "local_feature_gated_test_only_no_contract_writes";
    pub const REQUIRED_INPUT_IDS: [&'static str; 3] = [
        "complete_winterfell_witness_candidate",
        "selected_prover_byte_encoding_plan",
        "phase8_real_prover_implementation_checklist",
    ];
    pub const EXPECTED_OUTPUT_IDS: [&'static str; 4] = [
        "winterfell_proof_preview",
        "stark_proof_artifact_v1_candidate",
        "stark_settlement_boundary_artifact",
        "phase8_harness_execution_log",
    ];

    pub fn from_checklist(
        checklist: &Phase8RealProverImplementationChecklist,
    ) -> Result<Self, Vec<String>> {
        checklist.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: checklist.schema_version.clone(),
            harness_status: Self::HARNESS_STATUS.to_string(),
            selected_preview_prover: Self::SELECTED_PREVIEW_PROVER.to_string(),
            execution_mode: Self::EXECUTION_MODE.to_string(),
            required_inputs: vec![
                Phase8HarnessArtifact::required_input(
                    "complete_winterfell_witness_candidate",
                    WinterfellCompleteWitnessCandidate::SCHEMA_VERSION,
                    "complete_winterfell_witness_candidate.json",
                ),
                Phase8HarnessArtifact::required_input(
                    "selected_prover_byte_encoding_plan",
                    SelectedProverByteEncodingPlan::SCHEMA_VERSION,
                    "selected_prover_byte_encoding_plan.json",
                ),
                Phase8HarnessArtifact::required_input(
                    "phase8_real_prover_implementation_checklist",
                    Self::SOURCE_SCHEMA_VERSION,
                    "phase8_real_prover_implementation_checklist.json",
                ),
            ],
            expected_input_count: Self::REQUIRED_INPUT_IDS.len(),
            expected_outputs: vec![
                Phase8HarnessArtifact::expected_output(
                    "winterfell_proof_preview",
                    "winterfell-poc-proof-preview-v0",
                    "winterfell_proof_preview.json",
                ),
                Phase8HarnessArtifact::expected_output(
                    "stark_proof_artifact_v1_candidate",
                    StarkProofArtifactV1Candidate::SCHEMA_VERSION,
                    "stark_proof_artifact_v1_candidate.json",
                ),
                Phase8HarnessArtifact::expected_output(
                    "stark_settlement_boundary_artifact",
                    "stark-settlement-boundary-artifact-v0",
                    "stark_settlement_boundary_artifact.json",
                ),
                Phase8HarnessArtifact::expected_output(
                    "phase8_harness_execution_log",
                    "phase8-harness-execution-log-v0",
                    "phase8_harness_execution_log.json",
                ),
            ],
            expected_output_count: Self::EXPECTED_OUTPUT_IDS.len(),
            feature_gate_required: true,
            test_only_proof_generation_allowed: true,
            runtime_cutover_allowed: false,
            on_chain_submission_allowed: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "This plan defines the first feature-gated prover harness boundary.".to_string(),
                "It permits local/test-only proof generation through the Winterfell preview path."
                    .to_string(),
                "It does not permit runtime cutover, contract writes, or on-chain submission."
                    .to_string(),
                "Groth16 remains the active production prototype flow.".to_string(),
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

        if self.harness_status != Self::HARNESS_STATUS {
            errors.push(format!(
                "harness_status must be {}, got {}",
                Self::HARNESS_STATUS,
                self.harness_status
            ));
        }

        if self.selected_preview_prover != Self::SELECTED_PREVIEW_PROVER {
            errors.push(format!(
                "selected_preview_prover must be {}",
                Self::SELECTED_PREVIEW_PROVER
            ));
        }

        if self.execution_mode != Self::EXECUTION_MODE {
            errors.push(format!("execution_mode must be {}", Self::EXECUTION_MODE));
        }

        validate_harness_artifacts(
            "required_inputs",
            &self.required_inputs,
            &Self::REQUIRED_INPUT_IDS,
            "required_before_test_only_harness_execution",
            &mut errors,
        );

        if self.expected_input_count != Self::REQUIRED_INPUT_IDS.len() {
            errors.push(format!(
                "expected_input_count must be {}",
                Self::REQUIRED_INPUT_IDS.len()
            ));
        }

        validate_harness_artifacts(
            "expected_outputs",
            &self.expected_outputs,
            &Self::EXPECTED_OUTPUT_IDS,
            "expected_from_test_only_harness_execution",
            &mut errors,
        );

        if self.expected_output_count != Self::EXPECTED_OUTPUT_IDS.len() {
            errors.push(format!(
                "expected_output_count must be {}",
                Self::EXPECTED_OUTPUT_IDS.len()
            ));
        }

        if !self.feature_gate_required {
            errors.push("feature_gate_required must be true".to_string());
        }

        if !self.test_only_proof_generation_allowed {
            errors.push("test_only_proof_generation_allowed must be true".to_string());
        }

        if self.runtime_cutover_allowed {
            errors.push("runtime_cutover_allowed must be false".to_string());
        }

        if self.on_chain_submission_allowed {
            errors.push("on_chain_submission_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Phase8HarnessArtifact {
    fn required_input(artifact_id: &str, schema_version: &str, path_hint: &str) -> Self {
        Self {
            artifact_id: artifact_id.to_string(),
            schema_version: schema_version.to_string(),
            path_hint: path_hint.to_string(),
            requirement_status: "required_before_test_only_harness_execution".to_string(),
        }
    }

    fn expected_output(artifact_id: &str, schema_version: &str, path_hint: &str) -> Self {
        Self {
            artifact_id: artifact_id.to_string(),
            schema_version: schema_version.to_string(),
            path_hint: path_hint.to_string(),
            requirement_status: "expected_from_test_only_harness_execution".to_string(),
        }
    }
}

impl Phase8TestOnlyProverHarnessExecutionReport {
    pub const SCHEMA_VERSION: &'static str = "phase8-test-only-prover-harness-execution-report-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "phase8-test-only-prover-harness-plan-v0";
    pub const EXECUTION_STATUS: &'static str =
        "test_only_harness_execution_report_no_runtime_cutover";
    pub const LOCAL_VERIFICATION_STATUS: &'static str = "winterfell_preview_verified_locally";
    pub const PROOF_BYTES_STATUS: &'static str = "preview_bytes_observed_not_production_artifact";

    pub fn from_artifact_json_values(
        plan: &Phase8TestOnlyProverHarnessPlan,
        complete_witness_candidate: &serde_json::Value,
        selected_prover_byte_encoding_plan: &serde_json::Value,
        checklist: &serde_json::Value,
        proof_preview: &serde_json::Value,
        proof_artifact_candidate: &serde_json::Value,
        settlement_boundary_artifact: &serde_json::Value,
    ) -> Result<Self, Vec<String>> {
        plan.validate()?;

        let mut errors = Vec::new();

        validate_json_artifact(
            "complete_winterfell_witness_candidate",
            complete_witness_candidate,
            WinterfellCompleteWitnessCandidate::SCHEMA_VERSION,
            None,
            &mut errors,
        );
        validate_json_artifact(
            "selected_prover_byte_encoding_plan",
            selected_prover_byte_encoding_plan,
            SelectedProverByteEncodingPlan::SCHEMA_VERSION,
            Some(("plan_status", SelectedProverByteEncodingPlan::PLAN_STATUS)),
            &mut errors,
        );
        validate_json_artifact(
            "phase8_real_prover_implementation_checklist",
            checklist,
            Phase8RealProverImplementationChecklist::SCHEMA_VERSION,
            Some((
                "checklist_status",
                Phase8RealProverImplementationChecklist::CHECKLIST_STATUS,
            )),
            &mut errors,
        );
        validate_json_artifact(
            "winterfell_proof_preview",
            proof_preview,
            "winterfell-poc-proof-preview-v0",
            Some((
                "proof_status",
                "winterfell_poc_proof_generated_and_verified_feature_only",
            )),
            &mut errors,
        );
        validate_json_artifact(
            "stark_proof_artifact_v1_candidate",
            proof_artifact_candidate,
            StarkProofArtifactV1Candidate::SCHEMA_VERSION,
            Some((
                "artifact_status",
                StarkProofArtifactV1Candidate::ARTIFACT_STATUS,
            )),
            &mut errors,
        );
        validate_json_artifact(
            "stark_settlement_boundary_artifact",
            settlement_boundary_artifact,
            "stark-settlement-boundary-artifact-v0",
            Some(("artifact_status", "settlement_boundary_preview_not_runtime")),
            &mut errors,
        );

        let proof_preview_status = json_string_field(
            proof_preview,
            "proof_status",
            "winterfell_proof_preview",
            &mut errors,
        );
        let proof_size_bytes = json_usize_field(
            proof_preview,
            "proof_size_bytes",
            "winterfell_proof_preview",
            &mut errors,
        );
        let prove_ms = json_u128_field(
            proof_preview,
            "prove_ms",
            "winterfell_proof_preview",
            &mut errors,
        );
        let verify_ms = json_u128_field(
            proof_preview,
            "verify_ms",
            "winterfell_proof_preview",
            &mut errors,
        );

        if json_bool_field(
            proof_preview,
            "verified",
            "winterfell_proof_preview",
            &mut errors,
        ) != Some(true)
        {
            errors.push("winterfell_proof_preview.verified must be true".to_string());
        }
        if json_bool_field(
            proof_preview,
            "proof_generation_enabled",
            "winterfell_proof_preview",
            &mut errors,
        ) != Some(true)
        {
            errors
                .push("winterfell_proof_preview.proof_generation_enabled must be true".to_string());
        }
        if json_bool_field(
            proof_preview,
            "runtime_wired",
            "winterfell_proof_preview",
            &mut errors,
        ) != Some(false)
        {
            errors.push("winterfell_proof_preview.runtime_wired must be false".to_string());
        }
        if json_bool_field(
            proof_preview,
            "on_chain_submission",
            "winterfell_proof_preview",
            &mut errors,
        ) != Some(false)
        {
            errors.push("winterfell_proof_preview.on_chain_submission must be false".to_string());
        }
        if json_bool_field(
            settlement_boundary_artifact,
            "runtime_wired",
            "stark_settlement_boundary_artifact",
            &mut errors,
        ) != Some(false)
        {
            errors
                .push("stark_settlement_boundary_artifact.runtime_wired must be false".to_string());
        }
        if json_bool_field(
            settlement_boundary_artifact,
            "on_chain_submission",
            "stark_settlement_boundary_artifact",
            &mut errors,
        ) != Some(false)
        {
            errors.push(
                "stark_settlement_boundary_artifact.on_chain_submission must be false".to_string(),
            );
        }
        if json_bool_field(
            settlement_boundary_artifact,
            "groth16_flow_unchanged",
            "stark_settlement_boundary_artifact",
            &mut errors,
        ) != Some(true)
        {
            errors.push(
                "stark_settlement_boundary_artifact.groth16_flow_unchanged must be true"
                    .to_string(),
            );
        }

        if proof_size_bytes == 0 {
            errors.push(
                "winterfell_proof_preview.proof_size_bytes must be greater than zero".to_string(),
            );
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        let report = Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: plan.schema_version.clone(),
            execution_status: Self::EXECUTION_STATUS.to_string(),
            selected_preview_prover: plan.selected_preview_prover.clone(),
            execution_mode: plan.execution_mode.clone(),
            input_artifacts: plan.required_inputs.clone(),
            expected_input_count: plan.expected_input_count,
            output_artifacts: plan.expected_outputs.clone(),
            expected_output_count: plan.expected_output_count,
            feature_gate_used: true,
            proof_preview_status,
            proof_size_bytes,
            prove_ms,
            verify_ms,
            local_verification_status: Self::LOCAL_VERIFICATION_STATUS.to_string(),
            proof_bytes_status: Self::PROOF_BYTES_STATUS.to_string(),
            runtime_cutover_allowed: false,
            on_chain_submission_allowed: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "This report summarizes a feature-gated local prover harness preview.".to_string(),
                "The proof preview was locally generated and verified, but remains test-only."
                    .to_string(),
                "No STARK proof is accepted by runtime contracts from this report.".to_string(),
                "The active Groth16 flow remains unchanged.".to_string(),
            ],
        };
        report.validate()?;

        Ok(report)
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

        if self.execution_status != Self::EXECUTION_STATUS {
            errors.push(format!(
                "execution_status must be {}, got {}",
                Self::EXECUTION_STATUS,
                self.execution_status
            ));
        }

        if self.selected_preview_prover != Phase8TestOnlyProverHarnessPlan::SELECTED_PREVIEW_PROVER
        {
            errors.push(format!(
                "selected_preview_prover must be {}",
                Phase8TestOnlyProverHarnessPlan::SELECTED_PREVIEW_PROVER
            ));
        }

        if self.execution_mode != Phase8TestOnlyProverHarnessPlan::EXECUTION_MODE {
            errors.push(format!(
                "execution_mode must be {}",
                Phase8TestOnlyProverHarnessPlan::EXECUTION_MODE
            ));
        }

        validate_harness_artifacts(
            "input_artifacts",
            &self.input_artifacts,
            &Phase8TestOnlyProverHarnessPlan::REQUIRED_INPUT_IDS,
            "required_before_test_only_harness_execution",
            &mut errors,
        );

        if self.expected_input_count != Phase8TestOnlyProverHarnessPlan::REQUIRED_INPUT_IDS.len() {
            errors.push(format!(
                "expected_input_count must be {}",
                Phase8TestOnlyProverHarnessPlan::REQUIRED_INPUT_IDS.len()
            ));
        }

        validate_harness_artifacts(
            "output_artifacts",
            &self.output_artifacts,
            &Phase8TestOnlyProverHarnessPlan::EXPECTED_OUTPUT_IDS,
            "expected_from_test_only_harness_execution",
            &mut errors,
        );

        if self.expected_output_count != Phase8TestOnlyProverHarnessPlan::EXPECTED_OUTPUT_IDS.len()
        {
            errors.push(format!(
                "expected_output_count must be {}",
                Phase8TestOnlyProverHarnessPlan::EXPECTED_OUTPUT_IDS.len()
            ));
        }

        if !self.feature_gate_used {
            errors.push("feature_gate_used must be true".to_string());
        }

        if self.proof_preview_status != "winterfell_poc_proof_generated_and_verified_feature_only" {
            errors.push(
                "proof_preview_status must be winterfell_poc_proof_generated_and_verified_feature_only"
                    .to_string(),
            );
        }

        if self.proof_size_bytes == 0 {
            errors.push("proof_size_bytes must be greater than zero".to_string());
        }

        if self.local_verification_status != Self::LOCAL_VERIFICATION_STATUS {
            errors.push(format!(
                "local_verification_status must be {}",
                Self::LOCAL_VERIFICATION_STATUS
            ));
        }

        if self.proof_bytes_status != Self::PROOF_BYTES_STATUS {
            errors.push(format!(
                "proof_bytes_status must be {}",
                Self::PROOF_BYTES_STATUS
            ));
        }

        if self.runtime_cutover_allowed {
            errors.push("runtime_cutover_allowed must be false".to_string());
        }

        if self.on_chain_submission_allowed {
            errors.push("on_chain_submission_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Phase8RealProverBoundaryAdapterPlan {
    pub const SCHEMA_VERSION: &'static str = "phase8-real-prover-boundary-adapter-plan-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        "phase8-test-only-prover-harness-execution-report-v0";
    pub const ADAPTER_STATUS: &'static str =
        "preview_to_real_prover_boundary_adapter_no_runtime_cutover";
    pub const TARGET_PROVER_STATUS: &'static str =
        "production_prover_not_selected_real_proof_not_generated";
    pub const TARGET_ARTIFACT_SCHEMA_VERSION: &'static str = "stark-proof-artifact-v1";
    pub const TRANSFORMATION_STATUS: &'static str = "required_before_real_artifact_generation";
    pub const REQUIRED_TRANSFORMATION_IDS: [&'static str; 7] = [
        "replace_preview_proof_bytes_with_real_proof_bytes",
        "select_production_hash_and_root_semantics",
        "bind_public_input_root",
        "bind_source_roots",
        "generate_proof_commitment_from_canonical_bytes",
        "locally_verify_real_stark_proof",
        "emit_stark_proof_artifact_v1",
    ];
    pub const BLOCKED_RUNTIME_CUTOVER_CONDITIONS: [&'static str; 6] = [
        "production_prover_not_selected",
        "real_proof_bytes_not_generated",
        "production_public_input_root_not_generated",
        "source_roots_not_production_ready",
        "real_proof_not_locally_verified",
        "solidity_verifier_not_runtime_integrated",
    ];

    pub fn from_execution_report(
        report: &Phase8TestOnlyProverHarnessExecutionReport,
    ) -> Result<Self, Vec<String>> {
        report.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: report.schema_version.clone(),
            adapter_status: Self::ADAPTER_STATUS.to_string(),
            source_execution_status: report.execution_status.clone(),
            source_preview_prover: report.selected_preview_prover.clone(),
            target_prover_status: Self::TARGET_PROVER_STATUS.to_string(),
            target_artifact_schema_version: Self::TARGET_ARTIFACT_SCHEMA_VERSION.to_string(),
            required_transformations: vec![
                Phase8RealProverBoundaryTransformation::new(
                    "replace_preview_proof_bytes_with_real_proof_bytes",
                    "winterfell_proof_preview",
                    "proof.proof_bytes",
                    "Preview bytes cannot be reused for runtime; generate real proof bytes with the selected production prover.",
                ),
                Phase8RealProverBoundaryTransformation::new(
                    "select_production_hash_and_root_semantics",
                    "phase8_pre_prover_bundle_checkpoint",
                    "public_inputs.public_input_root",
                    "Replace candidate SHA-256 planning roots with selected production root semantics.",
                ),
                Phase8RealProverBoundaryTransformation::new(
                    "bind_public_input_root",
                    "public_input_root_assembly_plan",
                    "public_inputs.public_input_root",
                    "Bind the final public input root to the exact public input field order.",
                ),
                Phase8RealProverBoundaryTransformation::new(
                    "bind_source_roots",
                    "source_root_aggregation_plan",
                    "public_inputs.claim_source_root+oracle_facts_root+fee_schedule_root+nullifier_roots",
                    "Bind all source roots used by the proof and settlement interface.",
                ),
                Phase8RealProverBoundaryTransformation::new(
                    "generate_proof_commitment_from_canonical_bytes",
                    "selected_prover_byte_encoding_plan",
                    "proof.proof_commitment",
                    "Commit to canonical real proof bytes using the selected production commitment scheme.",
                ),
                Phase8RealProverBoundaryTransformation::new(
                    "locally_verify_real_stark_proof",
                    "selected_stark_verifier",
                    "local_verification",
                    "Verify the generated real proof against the final public inputs before any settlement work.",
                ),
                Phase8RealProverBoundaryTransformation::new(
                    "emit_stark_proof_artifact_v1",
                    "real_stark_prover_output",
                    "stark-proof-artifact-v1",
                    "Emit a complete artifact with proof bytes, proof commitment, public roots, and local verification.",
                ),
            ],
            expected_transformation_count: Self::REQUIRED_TRANSFORMATION_IDS.len(),
            blocked_runtime_cutover_conditions: Self::BLOCKED_RUNTIME_CUTOVER_CONDITIONS
                .iter()
                .map(|condition| (*condition).to_string())
                .collect(),
            expected_blocker_count: Self::BLOCKED_RUNTIME_CUTOVER_CONDITIONS.len(),
            preview_artifact_reusable_for_runtime: false,
            real_proof_generation_allowed: false,
            local_verification_required: true,
            runtime_cutover_allowed: false,
            on_chain_submission_allowed: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "This adapter plan converts the test-only preview report into real prover implementation requirements.".to_string(),
                "It does not permit preview proof bytes to be reused as runtime proof bytes.".to_string(),
                "Real proof generation remains blocked until production prover, hash, root, and verification choices are complete.".to_string(),
                "Groth16 remains the active runtime path.".to_string(),
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

        if self.adapter_status != Self::ADAPTER_STATUS {
            errors.push(format!(
                "adapter_status must be {}, got {}",
                Self::ADAPTER_STATUS,
                self.adapter_status
            ));
        }

        if self.source_execution_status
            != Phase8TestOnlyProverHarnessExecutionReport::EXECUTION_STATUS
        {
            errors.push(format!(
                "source_execution_status must be {}",
                Phase8TestOnlyProverHarnessExecutionReport::EXECUTION_STATUS
            ));
        }

        if self.source_preview_prover != Phase8TestOnlyProverHarnessPlan::SELECTED_PREVIEW_PROVER {
            errors.push(format!(
                "source_preview_prover must be {}",
                Phase8TestOnlyProverHarnessPlan::SELECTED_PREVIEW_PROVER
            ));
        }

        if self.target_prover_status != Self::TARGET_PROVER_STATUS {
            errors.push(format!(
                "target_prover_status must be {}",
                Self::TARGET_PROVER_STATUS
            ));
        }

        if self.target_artifact_schema_version != Self::TARGET_ARTIFACT_SCHEMA_VERSION {
            errors.push(format!(
                "target_artifact_schema_version must be {}",
                Self::TARGET_ARTIFACT_SCHEMA_VERSION
            ));
        }

        validate_real_prover_transformations(&self.required_transformations, &mut errors);

        if self.expected_transformation_count != Self::REQUIRED_TRANSFORMATION_IDS.len() {
            errors.push(format!(
                "expected_transformation_count must be {}",
                Self::REQUIRED_TRANSFORMATION_IDS.len()
            ));
        }

        validate_ordered_strings(
            "blocked_runtime_cutover_conditions",
            &self.blocked_runtime_cutover_conditions,
            &Self::BLOCKED_RUNTIME_CUTOVER_CONDITIONS,
            &mut errors,
        );

        if self.expected_blocker_count != Self::BLOCKED_RUNTIME_CUTOVER_CONDITIONS.len() {
            errors.push(format!(
                "expected_blocker_count must be {}",
                Self::BLOCKED_RUNTIME_CUTOVER_CONDITIONS.len()
            ));
        }

        if self.preview_artifact_reusable_for_runtime {
            errors.push("preview_artifact_reusable_for_runtime must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        if !self.local_verification_required {
            errors.push("local_verification_required must be true".to_string());
        }

        if self.runtime_cutover_allowed {
            errors.push("runtime_cutover_allowed must be false".to_string());
        }

        if self.on_chain_submission_allowed {
            errors.push("on_chain_submission_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Phase8RealProverBoundaryTransformation {
    fn new(
        transformation_id: &str,
        source_artifact: &str,
        target_field: &str,
        requirement: &str,
    ) -> Self {
        Self {
            transformation_id: transformation_id.to_string(),
            source_artifact: source_artifact.to_string(),
            target_field: target_field.to_string(),
            requirement: requirement.to_string(),
            status: Phase8RealProverBoundaryAdapterPlan::TRANSFORMATION_STATUS.to_string(),
        }
    }
}

impl Phase8RealProofArtifactReadinessGate {
    pub const SCHEMA_VERSION: &'static str = "phase8-real-proof-artifact-readiness-gate-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        Phase8RealProverBoundaryAdapterPlan::SCHEMA_VERSION;
    pub const READINESS_STATUS: &'static str = "not_ready_real_proof_generation_blocked";
    pub const TRANSFORMATION_GATE_STATUS: &'static str = "implementation_source_missing";

    pub fn from_boundary_adapter_plan(
        plan: &Phase8RealProverBoundaryAdapterPlan,
    ) -> Result<Self, Vec<String>> {
        plan.validate()?;

        let transformation_gates: Vec<Phase8ReadinessTransformationGate> = plan
            .required_transformations
            .iter()
            .map(|transformation| Phase8ReadinessTransformationGate {
                transformation_id: transformation.transformation_id.clone(),
                implementation_source: None,
                readiness_status: Self::TRANSFORMATION_GATE_STATUS.to_string(),
                blocks_real_proof_generation: true,
            })
            .collect();

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: plan.schema_version.clone(),
            readiness_status: Self::READINESS_STATUS.to_string(),
            target_artifact_schema_version: plan.target_artifact_schema_version.clone(),
            expected_transformation_gate_count: transformation_gates.len(),
            satisfied_gate_count: 0,
            unsatisfied_gate_count: transformation_gates.len(),
            transformation_gates,
            blockers: plan.blocked_runtime_cutover_conditions.clone(),
            expected_blocker_count: plan.blocked_runtime_cutover_conditions.len(),
            real_proof_generation_allowed: false,
            real_artifact_emission_allowed: false,
            runtime_cutover_allowed: false,
            on_chain_submission_allowed: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "This readiness gate intentionally blocks real STARK proof generation.".to_string(),
                "Every transformation must get an explicit implementation source before a real artifact can be emitted.".to_string(),
                "Groth16 remains the active runtime path while this gate is unsatisfied.".to_string(),
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

        if self.readiness_status != Self::READINESS_STATUS {
            errors.push(format!(
                "readiness_status must be {}",
                Self::READINESS_STATUS
            ));
        }

        if self.target_artifact_schema_version
            != Phase8RealProverBoundaryAdapterPlan::TARGET_ARTIFACT_SCHEMA_VERSION
        {
            errors.push(format!(
                "target_artifact_schema_version must be {}",
                Phase8RealProverBoundaryAdapterPlan::TARGET_ARTIFACT_SCHEMA_VERSION
            ));
        }

        validate_readiness_transformation_gates(&self.transformation_gates, &mut errors);

        if self.expected_transformation_gate_count
            != Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS.len()
        {
            errors.push(format!(
                "expected_transformation_gate_count must be {}",
                Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS.len()
            ));
        }

        if self.satisfied_gate_count != 0 {
            errors.push("satisfied_gate_count must be 0".to_string());
        }

        if self.unsatisfied_gate_count
            != Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS.len()
        {
            errors.push(format!(
                "unsatisfied_gate_count must be {}",
                Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS.len()
            ));
        }

        validate_ordered_strings(
            "blockers",
            &self.blockers,
            &Phase8RealProverBoundaryAdapterPlan::BLOCKED_RUNTIME_CUTOVER_CONDITIONS,
            &mut errors,
        );

        if self.expected_blocker_count
            != Phase8RealProverBoundaryAdapterPlan::BLOCKED_RUNTIME_CUTOVER_CONDITIONS.len()
        {
            errors.push(format!(
                "expected_blocker_count must be {}",
                Phase8RealProverBoundaryAdapterPlan::BLOCKED_RUNTIME_CUTOVER_CONDITIONS.len()
            ));
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        if self.real_artifact_emission_allowed {
            errors.push("real_artifact_emission_allowed must be false".to_string());
        }

        if self.runtime_cutover_allowed {
            errors.push("runtime_cutover_allowed must be false".to_string());
        }

        if self.on_chain_submission_allowed {
            errors.push("on_chain_submission_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Phase8ImplementationSourceRegistry {
    pub const SCHEMA_VERSION: &'static str = "phase8-implementation-source-registry-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        Phase8RealProofArtifactReadinessGate::SCHEMA_VERSION;
    pub const REGISTRY_STATUS: &'static str = "planned_sources_only_real_proof_generation_blocked";
    pub const IMPLEMENTATION_EVIDENCE_STATUS: &'static str = "planned_not_implemented_no_evidence";
    pub const IMPLEMENTATION_STATUS: &'static str = "planned_not_implemented";
    pub const EVIDENCE_REQUIRED: &'static str =
        "implemented_code_tests_and_local_validation_required";
    pub const PLANNED_SOURCES: [(&'static str, &'static str, &'static str); 7] = [
        (
            "replace_preview_proof_bytes_with_real_proof_bytes",
            "stark-engine/src/real_prover.rs",
            "stark-engine",
        ),
        (
            "select_production_hash_and_root_semantics",
            "stark-engine/src/root_semantics.rs",
            "stark-engine",
        ),
        (
            "bind_public_input_root",
            "stark-engine/src/public_inputs.rs",
            "stark-engine",
        ),
        (
            "bind_source_roots",
            "stark-engine/src/source_roots.rs",
            "stark-engine",
        ),
        (
            "generate_proof_commitment_from_canonical_bytes",
            "stark-engine/src/proof_commitment.rs",
            "stark-engine",
        ),
        (
            "locally_verify_real_stark_proof",
            "stark-engine/src/local_verifier.rs",
            "stark-engine",
        ),
        (
            "emit_stark_proof_artifact_v1",
            "stark-engine/src/proof_artifact.rs",
            "stark-engine",
        ),
    ];

    pub fn from_readiness_gate(
        gate: &Phase8RealProofArtifactReadinessGate,
    ) -> Result<Self, Vec<String>> {
        gate.validate()?;

        let planned_sources = Self::PLANNED_SOURCES
            .iter()
            .map(|(transformation_id, planned_module, planned_owner)| {
                Phase8ImplementationSourceEntry {
                    transformation_id: (*transformation_id).to_string(),
                    planned_module: (*planned_module).to_string(),
                    planned_owner: (*planned_owner).to_string(),
                    implementation_status: Self::IMPLEMENTATION_STATUS.to_string(),
                    evidence_required: Self::EVIDENCE_REQUIRED.to_string(),
                    blocks_real_proof_generation: true,
                }
            })
            .collect::<Vec<_>>();

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: gate.schema_version.clone(),
            registry_status: Self::REGISTRY_STATUS.to_string(),
            target_artifact_schema_version: gate.target_artifact_schema_version.clone(),
            expected_source_count: planned_sources.len(),
            planned_sources,
            implementation_evidence_status: Self::IMPLEMENTATION_EVIDENCE_STATUS.to_string(),
            satisfied_gate_count: 0,
            unsatisfied_gate_count: gate.unsatisfied_gate_count,
            real_proof_generation_allowed: false,
            real_artifact_emission_allowed: false,
            runtime_cutover_allowed: false,
            on_chain_submission_allowed: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "This registry names planned implementation modules only.".to_string(),
                "No implementation source is treated as complete by this artifact.".to_string(),
                "Real STARK proof generation remains blocked until evidence is added in a later phase.".to_string(),
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

        if self.registry_status != Self::REGISTRY_STATUS {
            errors.push(format!("registry_status must be {}", Self::REGISTRY_STATUS));
        }

        if self.target_artifact_schema_version
            != Phase8RealProverBoundaryAdapterPlan::TARGET_ARTIFACT_SCHEMA_VERSION
        {
            errors.push(format!(
                "target_artifact_schema_version must be {}",
                Phase8RealProverBoundaryAdapterPlan::TARGET_ARTIFACT_SCHEMA_VERSION
            ));
        }

        validate_implementation_source_entries(&self.planned_sources, &mut errors);

        if self.expected_source_count != Self::PLANNED_SOURCES.len() {
            errors.push(format!(
                "expected_source_count must be {}",
                Self::PLANNED_SOURCES.len()
            ));
        }

        if self.implementation_evidence_status != Self::IMPLEMENTATION_EVIDENCE_STATUS {
            errors.push(format!(
                "implementation_evidence_status must be {}",
                Self::IMPLEMENTATION_EVIDENCE_STATUS
            ));
        }

        if self.satisfied_gate_count != 0 {
            errors.push("satisfied_gate_count must be 0".to_string());
        }

        if self.unsatisfied_gate_count
            != Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS.len()
        {
            errors.push(format!(
                "unsatisfied_gate_count must be {}",
                Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS.len()
            ));
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        if self.real_artifact_emission_allowed {
            errors.push("real_artifact_emission_allowed must be false".to_string());
        }

        if self.runtime_cutover_allowed {
            errors.push("runtime_cutover_allowed must be false".to_string());
        }

        if self.on_chain_submission_allowed {
            errors.push("on_chain_submission_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Phase8ImplementationEvidenceSlots {
    pub const SCHEMA_VERSION: &'static str = "phase8-implementation-evidence-slots-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        Phase8ImplementationSourceRegistry::SCHEMA_VERSION;
    pub const EVIDENCE_STATUS: &'static str = "evidence_slots_empty_real_proof_generation_blocked";
    pub const SLOT_EVIDENCE_STATUS: &'static str = "evidence_missing";
    pub const REQUIRED_EVIDENCE: [(&'static str, [&'static str; 4]); 7] = [
        (
            "replace_preview_proof_bytes_with_real_proof_bytes",
            [
                "real_prover_code_path",
                "real_proof_bytes_fixture",
                "real_prover_unit_tests",
                "local_real_proof_validation_log",
            ],
        ),
        (
            "select_production_hash_and_root_semantics",
            [
                "hash_semantics_code_path",
                "root_semantics_spec",
                "hash_semantics_tests",
                "production_hash_selection_record",
            ],
        ),
        (
            "bind_public_input_root",
            [
                "public_input_binding_code_path",
                "canonical_public_input_order_tests",
                "public_input_root_fixture",
                "root_binding_validation_log",
            ],
        ),
        (
            "bind_source_roots",
            [
                "source_root_binding_code_path",
                "claim_oracle_fee_nullifier_root_tests",
                "source_root_fixture",
                "source_root_validation_log",
            ],
        ),
        (
            "generate_proof_commitment_from_canonical_bytes",
            [
                "proof_commitment_code_path",
                "canonical_proof_byte_encoding_tests",
                "proof_commitment_fixture",
                "commitment_validation_log",
            ],
        ),
        (
            "locally_verify_real_stark_proof",
            [
                "local_verifier_code_path",
                "valid_real_proof_verification_test",
                "invalid_real_proof_rejection_test",
                "local_verification_log",
            ],
        ),
        (
            "emit_stark_proof_artifact_v1",
            [
                "artifact_emitter_code_path",
                "stark_proof_artifact_v1_fixture",
                "artifact_schema_validation_tests",
                "artifact_round_trip_validation_log",
            ],
        ),
    ];

    pub fn from_registry(
        registry: &Phase8ImplementationSourceRegistry,
    ) -> Result<Self, Vec<String>> {
        registry.validate()?;

        let evidence_slots = registry
            .planned_sources
            .iter()
            .zip(Self::REQUIRED_EVIDENCE.iter())
            .map(|(source, (transformation_id, required_evidence))| {
                Phase8ImplementationEvidenceSlot {
                    transformation_id: (*transformation_id).to_string(),
                    planned_module: source.planned_module.clone(),
                    required_evidence: required_evidence
                        .iter()
                        .map(|evidence| (*evidence).to_string())
                        .collect(),
                    evidence_artifacts: Vec::new(),
                    evidence_status: Self::SLOT_EVIDENCE_STATUS.to_string(),
                    blocks_real_proof_generation: true,
                }
            })
            .collect::<Vec<_>>();

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: registry.schema_version.clone(),
            evidence_status: Self::EVIDENCE_STATUS.to_string(),
            target_artifact_schema_version: registry.target_artifact_schema_version.clone(),
            expected_slot_count: evidence_slots.len(),
            populated_slot_count: 0,
            missing_slot_count: evidence_slots.len(),
            evidence_slots,
            real_proof_generation_allowed: false,
            real_artifact_emission_allowed: false,
            runtime_cutover_allowed: false,
            on_chain_submission_allowed: false,
            groth16_flow_unchanged: true,
            notes: vec![
                "This artifact defines evidence slots only; no implementation evidence is populated.".to_string(),
                "Every evidence slot blocks real STARK proof generation until a later phase provides artifacts.".to_string(),
                "Groth16 remains the active runtime path.".to_string(),
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

        if self.evidence_status != Self::EVIDENCE_STATUS {
            errors.push(format!("evidence_status must be {}", Self::EVIDENCE_STATUS));
        }

        if self.target_artifact_schema_version
            != Phase8RealProverBoundaryAdapterPlan::TARGET_ARTIFACT_SCHEMA_VERSION
        {
            errors.push(format!(
                "target_artifact_schema_version must be {}",
                Phase8RealProverBoundaryAdapterPlan::TARGET_ARTIFACT_SCHEMA_VERSION
            ));
        }

        validate_implementation_evidence_slots(&self.evidence_slots, &mut errors);

        if self.expected_slot_count != Self::REQUIRED_EVIDENCE.len() {
            errors.push(format!(
                "expected_slot_count must be {}",
                Self::REQUIRED_EVIDENCE.len()
            ));
        }

        if self.populated_slot_count != 0 {
            errors.push("populated_slot_count must be 0".to_string());
        }

        if self.missing_slot_count != Self::REQUIRED_EVIDENCE.len() {
            errors.push(format!(
                "missing_slot_count must be {}",
                Self::REQUIRED_EVIDENCE.len()
            ));
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        if self.real_artifact_emission_allowed {
            errors.push("real_artifact_emission_allowed must be false".to_string());
        }

        if self.runtime_cutover_allowed {
            errors.push("runtime_cutover_allowed must be false".to_string());
        }

        if self.on_chain_submission_allowed {
            errors.push("on_chain_submission_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Phase8EvidenceReadinessReport {
    pub const SCHEMA_VERSION: &'static str = "phase8-evidence-readiness-report-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        Phase8ImplementationEvidenceSlots::SCHEMA_VERSION;
    pub const REPORT_STATUS: &'static str = "not_ready_missing_implementation_evidence";
    pub const TRANSFORMATION_READINESS_STATUS: &'static str = "blocked_missing_evidence";
    pub const RECOMMENDED_NEXT_STEPS: [&'static str; 5] = [
        "implement_real_prover_module",
        "add_real_proof_bytes_fixture",
        "add_local_real_proof_verification_tests",
        "populate_evidence_artifacts",
        "rerun_evidence_readiness_report",
    ];

    pub fn from_evidence_slots(
        slots: &Phase8ImplementationEvidenceSlots,
    ) -> Result<Self, Vec<String>> {
        slots.validate()?;

        let transformation_reports = slots
            .evidence_slots
            .iter()
            .map(|slot| Phase8EvidenceTransformationReport {
                transformation_id: slot.transformation_id.clone(),
                planned_module: slot.planned_module.clone(),
                required_evidence_count: slot.required_evidence.len(),
                missing_evidence: slot.required_evidence.clone(),
                evidence_status: slot.evidence_status.clone(),
                readiness_status: Self::TRANSFORMATION_READINESS_STATUS.to_string(),
                blocks_real_proof_generation: true,
            })
            .collect::<Vec<_>>();

        let missing_evidence_total = transformation_reports
            .iter()
            .map(|report| report.missing_evidence.len())
            .sum();

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: slots.schema_version.clone(),
            report_status: Self::REPORT_STATUS.to_string(),
            target_artifact_schema_version: slots.target_artifact_schema_version.clone(),
            expected_transformation_count: transformation_reports.len(),
            populated_slot_count: slots.populated_slot_count,
            missing_slot_count: slots.missing_slot_count,
            missing_evidence_total,
            ready_transformation_count: 0,
            blocked_transformation_count: transformation_reports.len(),
            transformation_reports,
            real_proof_generation_allowed: false,
            real_artifact_emission_allowed: false,
            runtime_cutover_allowed: false,
            on_chain_submission_allowed: false,
            groth16_flow_unchanged: true,
            recommended_next_steps: Self::RECOMMENDED_NEXT_STEPS
                .iter()
                .map(|step| (*step).to_string())
                .collect(),
            notes: vec![
                "This report is generated from empty implementation evidence slots.".to_string(),
                "Every transformation remains blocked until real implementation evidence is populated and validated.".to_string(),
                "No real STARK proof bytes are generated by this report.".to_string(),
                "Groth16 remains the active runtime path.".to_string(),
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

        if self.report_status != Self::REPORT_STATUS {
            errors.push(format!("report_status must be {}", Self::REPORT_STATUS));
        }

        if self.target_artifact_schema_version
            != Phase8RealProverBoundaryAdapterPlan::TARGET_ARTIFACT_SCHEMA_VERSION
        {
            errors.push(format!(
                "target_artifact_schema_version must be {}",
                Phase8RealProverBoundaryAdapterPlan::TARGET_ARTIFACT_SCHEMA_VERSION
            ));
        }

        validate_evidence_transformation_reports(&self.transformation_reports, &mut errors);

        if self.expected_transformation_count
            != Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len()
        {
            errors.push(format!(
                "expected_transformation_count must be {}",
                Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len()
            ));
        }

        if self.populated_slot_count != 0 {
            errors.push("populated_slot_count must be 0".to_string());
        }

        if self.missing_slot_count != Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len() {
            errors.push(format!(
                "missing_slot_count must be {}",
                Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len()
            ));
        }

        let expected_missing_evidence_total: usize =
            Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE
                .iter()
                .map(|(_, evidence)| evidence.len())
                .sum();
        if self.missing_evidence_total != expected_missing_evidence_total {
            errors.push(format!(
                "missing_evidence_total must be {expected_missing_evidence_total}"
            ));
        }

        if self.ready_transformation_count != 0 {
            errors.push("ready_transformation_count must be 0".to_string());
        }

        if self.blocked_transformation_count
            != Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len()
        {
            errors.push(format!(
                "blocked_transformation_count must be {}",
                Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len()
            ));
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        if self.real_artifact_emission_allowed {
            errors.push("real_artifact_emission_allowed must be false".to_string());
        }

        if self.runtime_cutover_allowed {
            errors.push("runtime_cutover_allowed must be false".to_string());
        }

        if self.on_chain_submission_allowed {
            errors.push("on_chain_submission_allowed must be false".to_string());
        }

        if !self.groth16_flow_unchanged {
            errors.push("groth16_flow_unchanged must be true".to_string());
        }

        validate_ordered_strings(
            "recommended_next_steps",
            &self.recommended_next_steps,
            &Self::RECOMMENDED_NEXT_STEPS,
            &mut errors,
        );

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

fn validate_fixture_dependency_status(
    fixture_id: &str,
    field_name: &str,
    value: &str,
    errors: &mut Vec<String>,
) {
    if value != ProofArtifactFixtureExpectation::REQUIRED_DEPENDENCY_STATUS {
        errors.push(format!(
            "{fixture_id}.{field_name} must be {}",
            ProofArtifactFixtureExpectation::REQUIRED_DEPENDENCY_STATUS
        ));
    }
}

fn validate_json_artifact(
    artifact_id: &str,
    value: &serde_json::Value,
    expected_schema_version: &str,
    expected_status: Option<(&str, &str)>,
    errors: &mut Vec<String>,
) {
    match value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
    {
        Some(schema_version) if schema_version == expected_schema_version => {}
        Some(schema_version) => errors.push(format!(
            "{artifact_id}.schema_version must be {expected_schema_version}, got {schema_version}"
        )),
        None => errors.push(format!("{artifact_id}.schema_version must be present")),
    }

    if let Some((field_name, expected_value)) = expected_status {
        match value.get(field_name).and_then(serde_json::Value::as_str) {
            Some(actual_value) if actual_value == expected_value => {}
            Some(actual_value) => errors.push(format!(
                "{artifact_id}.{field_name} must be {expected_value}, got {actual_value}"
            )),
            None => errors.push(format!("{artifact_id}.{field_name} must be present")),
        }
    }
}

fn json_string_field(
    value: &serde_json::Value,
    field_name: &str,
    artifact_id: &str,
    errors: &mut Vec<String>,
) -> String {
    match value.get(field_name).and_then(serde_json::Value::as_str) {
        Some(field_value) if !field_value.trim().is_empty() => field_value.to_string(),
        Some(_) => {
            errors.push(format!("{artifact_id}.{field_name} must be non-empty"));
            String::new()
        }
        None => {
            errors.push(format!("{artifact_id}.{field_name} must be present"));
            String::new()
        }
    }
}

fn json_usize_field(
    value: &serde_json::Value,
    field_name: &str,
    artifact_id: &str,
    errors: &mut Vec<String>,
) -> usize {
    match value.get(field_name).and_then(serde_json::Value::as_u64) {
        Some(field_value) => match usize::try_from(field_value) {
            Ok(converted) => converted,
            Err(_) => {
                errors.push(format!("{artifact_id}.{field_name} is too large"));
                0
            }
        },
        None => {
            errors.push(format!("{artifact_id}.{field_name} must be present"));
            0
        }
    }
}

fn json_u128_field(
    value: &serde_json::Value,
    field_name: &str,
    artifact_id: &str,
    errors: &mut Vec<String>,
) -> u128 {
    match value.get(field_name).and_then(serde_json::Value::as_u64) {
        Some(field_value) => u128::from(field_value),
        None => {
            errors.push(format!("{artifact_id}.{field_name} must be present"));
            0
        }
    }
}

fn json_bool_field(
    value: &serde_json::Value,
    field_name: &str,
    artifact_id: &str,
    errors: &mut Vec<String>,
) -> Option<bool> {
    match value.get(field_name).and_then(serde_json::Value::as_bool) {
        Some(field_value) => Some(field_value),
        None => {
            errors.push(format!("{artifact_id}.{field_name} must be present"));
            None
        }
    }
}

fn collect_validation_errors(
    artifact_id: &str,
    result: Result<(), Vec<String>>,
    errors: &mut Vec<String>,
) {
    if let Err(validation_errors) = result {
        errors.extend(
            validation_errors
                .into_iter()
                .map(|error| format!("{artifact_id}: {error}")),
        );
    }
}

fn validate_harness_artifacts(
    collection_name: &str,
    artifacts: &[Phase8HarnessArtifact],
    expected_ids: &[&str],
    expected_status: &str,
    errors: &mut Vec<String>,
) {
    if artifacts.len() != expected_ids.len() {
        errors.push(format!(
            "{collection_name} must contain exactly {} artifacts",
            expected_ids.len()
        ));
    }

    for (position, expected_id) in expected_ids.iter().enumerate() {
        match artifacts.get(position) {
            Some(artifact) => {
                if artifact.artifact_id != *expected_id {
                    errors.push(format!(
                        "{collection_name}[{position}].artifact_id must be {expected_id}"
                    ));
                }
                if artifact.schema_version.trim().is_empty() {
                    errors.push(format!("{expected_id}.schema_version must be present"));
                }
                if artifact.path_hint.trim().is_empty() {
                    errors.push(format!("{expected_id}.path_hint must be present"));
                }
                if artifact.requirement_status != expected_status {
                    errors.push(format!(
                        "{expected_id}.requirement_status must be {expected_status}"
                    ));
                }
            }
            None => errors.push(format!("{collection_name} missing artifact: {expected_id}")),
        }
    }
}

fn validate_real_prover_transformations(
    transformations: &[Phase8RealProverBoundaryTransformation],
    errors: &mut Vec<String>,
) {
    if transformations.len()
        != Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS.len()
    {
        errors.push(format!(
            "required_transformations must contain exactly {} transformations",
            Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS.len()
        ));
    }

    for (position, expected_id) in Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS
        .iter()
        .enumerate()
    {
        match transformations.get(position) {
            Some(transformation) => {
                if transformation.transformation_id != *expected_id {
                    errors.push(format!(
                        "required_transformations[{position}].transformation_id must be {expected_id}"
                    ));
                }
                if transformation.source_artifact.trim().is_empty() {
                    errors.push(format!("{expected_id}.source_artifact must be present"));
                }
                if transformation.target_field.trim().is_empty() {
                    errors.push(format!("{expected_id}.target_field must be present"));
                }
                if transformation.requirement.trim().is_empty() {
                    errors.push(format!("{expected_id}.requirement must be present"));
                }
                if transformation.status
                    != Phase8RealProverBoundaryAdapterPlan::TRANSFORMATION_STATUS
                {
                    errors.push(format!(
                        "{expected_id}.status must be {}",
                        Phase8RealProverBoundaryAdapterPlan::TRANSFORMATION_STATUS
                    ));
                }
            }
            None => errors.push(format!(
                "required_transformations missing transformation: {expected_id}"
            )),
        }
    }
}

fn validate_readiness_transformation_gates(
    gates: &[Phase8ReadinessTransformationGate],
    errors: &mut Vec<String>,
) {
    if gates.len() != Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS.len() {
        errors.push(format!(
            "transformation_gates must contain exactly {} gates",
            Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS.len()
        ));
    }

    for (position, expected_id) in Phase8RealProverBoundaryAdapterPlan::REQUIRED_TRANSFORMATION_IDS
        .iter()
        .enumerate()
    {
        match gates.get(position) {
            Some(gate) => {
                if gate.transformation_id != *expected_id {
                    errors.push(format!(
                        "transformation_gates[{position}].transformation_id must be {expected_id}"
                    ));
                }
                if gate.implementation_source.is_some() {
                    errors.push(format!("{expected_id}.implementation_source must be null"));
                }
                if gate.readiness_status
                    != Phase8RealProofArtifactReadinessGate::TRANSFORMATION_GATE_STATUS
                {
                    errors.push(format!(
                        "{expected_id}.readiness_status must be {}",
                        Phase8RealProofArtifactReadinessGate::TRANSFORMATION_GATE_STATUS
                    ));
                }
                if !gate.blocks_real_proof_generation {
                    errors.push(format!(
                        "{expected_id}.blocks_real_proof_generation must be true"
                    ));
                }
            }
            None => errors.push(format!("transformation_gates missing gate: {expected_id}")),
        }
    }
}

fn validate_implementation_source_entries(
    entries: &[Phase8ImplementationSourceEntry],
    errors: &mut Vec<String>,
) {
    if entries.len() != Phase8ImplementationSourceRegistry::PLANNED_SOURCES.len() {
        errors.push(format!(
            "planned_sources must contain exactly {} entries",
            Phase8ImplementationSourceRegistry::PLANNED_SOURCES.len()
        ));
    }

    for (position, (expected_id, expected_module, expected_owner)) in
        Phase8ImplementationSourceRegistry::PLANNED_SOURCES
            .iter()
            .enumerate()
    {
        match entries.get(position) {
            Some(entry) => {
                if entry.transformation_id != *expected_id {
                    errors.push(format!(
                        "planned_sources[{position}].transformation_id must be {expected_id}"
                    ));
                }
                if entry.planned_module != *expected_module {
                    errors.push(format!(
                        "{expected_id}.planned_module must be {expected_module}"
                    ));
                }
                if entry.planned_owner != *expected_owner {
                    errors.push(format!(
                        "{expected_id}.planned_owner must be {expected_owner}"
                    ));
                }
                if entry.implementation_status
                    != Phase8ImplementationSourceRegistry::IMPLEMENTATION_STATUS
                {
                    errors.push(format!(
                        "{expected_id}.implementation_status must be {}",
                        Phase8ImplementationSourceRegistry::IMPLEMENTATION_STATUS
                    ));
                }
                if entry.evidence_required != Phase8ImplementationSourceRegistry::EVIDENCE_REQUIRED
                {
                    errors.push(format!(
                        "{expected_id}.evidence_required must be {}",
                        Phase8ImplementationSourceRegistry::EVIDENCE_REQUIRED
                    ));
                }
                if !entry.blocks_real_proof_generation {
                    errors.push(format!(
                        "{expected_id}.blocks_real_proof_generation must be true"
                    ));
                }
            }
            None => errors.push(format!("planned_sources missing entry: {expected_id}")),
        }
    }
}

fn validate_implementation_evidence_slots(
    slots: &[Phase8ImplementationEvidenceSlot],
    errors: &mut Vec<String>,
) {
    if slots.len() != Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len() {
        errors.push(format!(
            "evidence_slots must contain exactly {} slots",
            Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len()
        ));
    }

    for (position, (expected_id, expected_evidence)) in
        Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE
            .iter()
            .enumerate()
    {
        match slots.get(position) {
            Some(slot) => {
                if slot.transformation_id != *expected_id {
                    errors.push(format!(
                        "evidence_slots[{position}].transformation_id must be {expected_id}"
                    ));
                }

                match Phase8ImplementationSourceRegistry::PLANNED_SOURCES.get(position) {
                    Some((_, expected_module, _)) if slot.planned_module == *expected_module => {}
                    Some((_, expected_module, _)) => errors.push(format!(
                        "{expected_id}.planned_module must be {expected_module}"
                    )),
                    None => errors.push(format!("{expected_id}.planned_module has no source plan")),
                }

                let actual_evidence = slot
                    .required_evidence
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                if actual_evidence != expected_evidence {
                    errors.push(format!(
                        "{expected_id}.required_evidence must match the required evidence contract"
                    ));
                }

                if !slot.evidence_artifacts.is_empty() {
                    errors.push(format!("{expected_id}.evidence_artifacts must be empty"));
                }

                if slot.evidence_status != Phase8ImplementationEvidenceSlots::SLOT_EVIDENCE_STATUS {
                    errors.push(format!(
                        "{expected_id}.evidence_status must be {}",
                        Phase8ImplementationEvidenceSlots::SLOT_EVIDENCE_STATUS
                    ));
                }

                if !slot.blocks_real_proof_generation {
                    errors.push(format!(
                        "{expected_id}.blocks_real_proof_generation must be true"
                    ));
                }
            }
            None => errors.push(format!("evidence_slots missing slot: {expected_id}")),
        }
    }
}

fn validate_evidence_transformation_reports(
    reports: &[Phase8EvidenceTransformationReport],
    errors: &mut Vec<String>,
) {
    if reports.len() != Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len() {
        errors.push(format!(
            "transformation_reports must contain exactly {} reports",
            Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE.len()
        ));
    }

    for (position, (expected_id, expected_evidence)) in
        Phase8ImplementationEvidenceSlots::REQUIRED_EVIDENCE
            .iter()
            .enumerate()
    {
        match reports.get(position) {
            Some(report) => {
                if report.transformation_id != *expected_id {
                    errors.push(format!(
                        "transformation_reports[{position}].transformation_id must be {expected_id}"
                    ));
                }

                match Phase8ImplementationSourceRegistry::PLANNED_SOURCES.get(position) {
                    Some((_, expected_module, _)) if report.planned_module == *expected_module => {}
                    Some((_, expected_module, _)) => errors.push(format!(
                        "{expected_id}.planned_module must be {expected_module}"
                    )),
                    None => errors.push(format!("{expected_id}.planned_module has no source plan")),
                }

                if report.required_evidence_count != expected_evidence.len() {
                    errors.push(format!(
                        "{expected_id}.required_evidence_count must be {}",
                        expected_evidence.len()
                    ));
                }

                let actual_missing_evidence = report
                    .missing_evidence
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                if actual_missing_evidence != expected_evidence {
                    errors.push(format!(
                        "{expected_id}.missing_evidence must match the required evidence contract"
                    ));
                }

                if report.evidence_status != Phase8ImplementationEvidenceSlots::SLOT_EVIDENCE_STATUS
                {
                    errors.push(format!(
                        "{expected_id}.evidence_status must be {}",
                        Phase8ImplementationEvidenceSlots::SLOT_EVIDENCE_STATUS
                    ));
                }

                if report.readiness_status
                    != Phase8EvidenceReadinessReport::TRANSFORMATION_READINESS_STATUS
                {
                    errors.push(format!(
                        "{expected_id}.readiness_status must be {}",
                        Phase8EvidenceReadinessReport::TRANSFORMATION_READINESS_STATUS
                    ));
                }

                if !report.blocks_real_proof_generation {
                    errors.push(format!(
                        "{expected_id}.blocks_real_proof_generation must be true"
                    ));
                }
            }
            None => errors.push(format!(
                "transformation_reports missing report: {expected_id}"
            )),
        }
    }
}

fn validate_ordered_strings(
    collection_name: &str,
    values: &[String],
    expected_values: &[&str],
    errors: &mut Vec<String>,
) {
    if values.len() != expected_values.len() {
        errors.push(format!(
            "{collection_name} must contain exactly {} values",
            expected_values.len()
        ));
    }

    for (position, expected_value) in expected_values.iter().enumerate() {
        match values.get(position) {
            Some(value) if value == expected_value => {}
            Some(_) => errors.push(format!(
                "{collection_name}[{position}] must be {expected_value}"
            )),
            None => errors.push(format!("{collection_name} missing value: {expected_value}")),
        }
    }
}

fn public_input_root_candidate_value(field: &PublicInputRootField) -> String {
    match field.value_status.as_str() {
        "available_from_bridge_input" => {
            format!("__available_from_bridge_input__::{}", field.field_name)
        }
        "requires_future_root_generation" => {
            format!("__requires_future_root_generation__::{}", field.field_name)
        }
        _ => format!("__invalid_value_status__::{}", field.field_name),
    }
}

fn build_public_input_root_candidate_preimage(
    ordered_fields: &[PublicInputRootDigestField],
    canonical_encoding: &str,
) -> String {
    let mut lines = Vec::with_capacity(ordered_fields.len() + 1);
    lines.push(format!("canonical_encoding:{canonical_encoding}"));
    lines.extend(ordered_fields.iter().map(|field| {
        format!(
            "{}:{}:{}:{}",
            field.position, field.field_name, field.value_status, field.encoded_value
        )
    }));
    lines.join("\n")
}

fn expected_source_root_schema_version(source_root_kind: &str) -> Option<&'static str> {
    match source_root_kind {
        "claim_source_root" => Some(ClaimSourceRootInput::SCHEMA_VERSION),
        "oracle_facts_root" => Some(OracleFactsRootInput::SCHEMA_VERSION),
        "fee_schedule_root" => Some(FeeScheduleRootInput::SCHEMA_VERSION),
        "nullifier_root_transition" => Some(NullifierRootTransitionInput::SCHEMA_VERSION),
        _ => None,
    }
}

fn source_root_public_input_fields(source_root_kind: &str) -> &'static [&'static str] {
    match source_root_kind {
        "claim_source_root" => &["claim_source_root"],
        "oracle_facts_root" => &["oracle_facts_root"],
        "fee_schedule_root" => &["fee_schedule_root"],
        "nullifier_root_transition" => &["nullifier_root_before", "nullifier_root_after"],
        _ => &[],
    }
}

fn source_root_digest_candidate_from_source<T: Serialize>(
    source_schema_version: &str,
    source_root_kind: &str,
    source: &T,
    notes: Vec<String>,
) -> Result<SourceRootDigestCandidate, Vec<String>> {
    let source_json = serde_json::to_string(source)
        .map_err(|err| vec![format!("could not serialize source root input: {err}")])?;
    let canonical_preimage = build_source_root_candidate_preimage(
        source_schema_version,
        source_root_kind,
        SourceRootDigestCandidate::CANONICAL_ENCODING,
        &source_json,
    );
    let source_root_candidate = sha256_hex(&canonical_preimage);

    Ok(SourceRootDigestCandidate {
        schema_version: SourceRootDigestCandidate::SCHEMA_VERSION.to_string(),
        source_schema_version: source_schema_version.to_string(),
        source_root_kind: source_root_kind.to_string(),
        candidate_status: SourceRootDigestCandidate::CANDIDATE_STATUS.to_string(),
        hash_algorithm: SourceRootDigestCandidate::HASH_ALGORITHM.to_string(),
        canonical_encoding: SourceRootDigestCandidate::CANONICAL_ENCODING.to_string(),
        canonical_preimage,
        source_root_candidate,
        root_generation_status: SourceRootDigestCandidate::ROOT_GENERATION_STATUS.to_string(),
        production_hash_selected: false,
        runtime_wiring_allowed: false,
        groth16_flow_unchanged: true,
        notes,
    })
}

fn build_source_root_candidate_preimage(
    source_schema_version: &str,
    source_root_kind: &str,
    canonical_encoding: &str,
    source_json: &str,
) -> String {
    [
        format!("source_schema_version:{source_schema_version}"),
        format!("source_root_kind:{source_root_kind}"),
        format!("canonical_encoding:{canonical_encoding}"),
        format!("source_json:{source_json}"),
    ]
    .join("\n")
}

fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    format!("0x{digest:x}")
}

fn proof_commitment_component_encoding(component_name: &str) -> &'static str {
    match component_name {
        "target_artifact_schema_version" | "solidity_abi_candidate" | "prover" => {
            "string_identifier"
        }
        "proof_bytes" => "0x_prefixed_bytes",
        "public_input_root" | "claim_hash" => "0x_prefixed_32_byte_hex",
        "decision" => "u8_boolean_0_or_1",
        "failure_code" => "u32",
        _ => "unknown",
    }
}

fn proof_commitment_component_source(component_name: &str) -> &'static str {
    match component_name {
        "target_artifact_schema_version" => {
            "stark_proof_artifact_v1_boundary_spec.target_artifact_schema_version"
        }
        "solidity_abi_candidate" => "stark_proof_artifact_v1_boundary_spec.solidity_abi_candidate",
        "prover" => "selected_stark_prover",
        "proof_bytes" => "selected_stark_prover.proof_bytes",
        "public_input_root" => "public_input_root_generation",
        "claim_hash" => "future_stark_proof_artifact.public_inputs.claim_hash",
        "decision" => "future_stark_proof_artifact.public_inputs.decision",
        "failure_code" => "future_stark_proof_artifact.public_inputs.failure_code",
        _ => "unknown",
    }
}

fn proof_commitment_component_status(component_name: &str) -> &'static str {
    match component_name {
        "target_artifact_schema_version" | "solidity_abi_candidate" => {
            "available_from_boundary_spec"
        }
        "prover" => "requires_selected_prover",
        "proof_bytes" => "requires_real_proof_bytes",
        "public_input_root" => "requires_public_input_root_generation",
        "claim_hash" | "decision" | "failure_code" => {
            "available_from_future_artifact_public_inputs"
        }
        _ => "unknown",
    }
}

fn required_field(
    field_name: &str,
    encoding: &str,
    source: &str,
) -> StarkProofArtifactFieldRequirement {
    StarkProofArtifactFieldRequirement {
        field_name: field_name.to_string(),
        encoding: encoding.to_string(),
        source: source.to_string(),
        requirement_status: "required_before_runtime_wiring".to_string(),
    }
}

fn validate_required_field_names(
    collection_name: &str,
    requirements: &[StarkProofArtifactFieldRequirement],
    expected_names: &[&str],
    errors: &mut Vec<String>,
) {
    if requirements.len() != expected_names.len() {
        errors.push(format!(
            "{collection_name} must contain exactly {} fields",
            expected_names.len()
        ));
    }

    for expected_name in expected_names {
        if !requirements
            .iter()
            .any(|requirement| requirement.field_name == *expected_name)
        {
            errors.push(format!("{collection_name} missing field: {expected_name}"));
        }
    }
}

fn validate_0x_32_byte_hex(name: &str, value: &str, errors: &mut Vec<String>) {
    let trimmed = value.trim();
    if trimmed.len() != 66
        || !trimmed.starts_with("0x")
        || !trimmed[2..].chars().all(|ch| ch.is_ascii_hexdigit())
    {
        errors.push(format!("{name} must be a 0x-prefixed 32-byte hex string"));
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
                errors.push(format!(
                    "row {expected_index} constraint_group must be present"
                ));
            }

            if row.constraint_name.trim().is_empty() {
                errors.push(format!(
                    "row {expected_index} constraint_name must be present"
                ));
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

impl WinterfellAdapterBoundaryPlan {
    pub const SCHEMA_VERSION: &'static str = "winterfell-adapter-boundary-plan-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-phase4-checkpoint-v0";
    pub const PLAN_STATUS: &'static str = "adapter_boundary_only_no_winterfell_import";

    pub fn phase5a() -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: Self::SOURCE_SCHEMA_VERSION.to_string(),
            plan_status: Self::PLAN_STATUS.to_string(),
            imported_poc: WinterfellPocShape {
                crate_path: "blind-ledger-app-layer/zk-stark".to_string(),
                claim_input_fields: ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS
                    .iter()
                    .map(|field| (*field).to_string())
                    .collect(),
                public_inputs: vec![
                    "commitment".to_string(),
                    "decision".to_string(),
                    "failure_code".to_string(),
                ],
                gate_count: 10,
                trace_width: 172,
                trace_length: 16,
                commitment_strategy:
                    "local AIR-bound algebraic PoC commitment, not production root/hash"
                        .to_string(),
            },
            required_phase4_artifacts: vec![
                "StarkBridgeInput".to_string(),
                "ClaimSourceRootInput".to_string(),
                "OracleFactsRootInput".to_string(),
                "FeeScheduleRootInput".to_string(),
                "NullifierRootTransitionInput".to_string(),
                "BatchRootCompatibilityPlan".to_string(),
                "BatchRootGapReport".to_string(),
                "StarkProofIntent".to_string(),
                "StarkWitnessPlan".to_string(),
                "StarkMockTrace".to_string(),
            ],
            field_bindings: winterfell_adapter_field_bindings(),
            public_input_bindings: winterfell_adapter_public_input_bindings(),
            unsupported_constraint_groups: vec![
                "member_id_nonzero_inverse_witness".to_string(),
                "provider_npi_nonzero_inverse_witness".to_string(),
                "service_line_count_nonzero_inverse_witness".to_string(),
                "diagnosis_count_nonzero_inverse_witness".to_string(),
                "charge_cents_positive_inverse_witness".to_string(),
                "charge_and_max_charge_bit_decomposition".to_string(),
                "charge_lte_max_charge_comparison_witness".to_string(),
                "winterfell_commitment_hash_chain".to_string(),
                "trace_width_172_and_trace_length_16_generation".to_string(),
                "public_commitment_binding_to_phase4_roots".to_string(),
            ],
            winterfell_dependency_imported: false,
            proof_generation_enabled: false,
            recommended_next_steps: vec![
                "Keep Winterfell in blind-ledger-app-layer/zk-stark as a reference until adapter inputs are deterministic.".to_string(),
                "Build a test-only normalized Winterfell witness candidate from Phase 4 artifacts before importing the Winterfell crate.".to_string(),
                "Resolve partial fields with deterministic source data: service_line_count, prior_auth_ok, charge_cents, and program_integrity_hold.".to_string(),
                "Resolve unmapped fields or remove them from the first adapter target: member_id, provider_npi, diagnosis_count, and max_charge_cents.".to_string(),
                "Replace the PoC commitment with a production public-input binding strategy before any real proof path.".to_string(),
            ],
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

        if self.plan_status != Self::PLAN_STATUS {
            errors.push(format!(
                "plan_status must be {}, got {}",
                Self::PLAN_STATUS,
                self.plan_status
            ));
        }

        if self.imported_poc.crate_path != "blind-ledger-app-layer/zk-stark" {
            errors.push(
                "imported_poc.crate_path must point to blind-ledger-app-layer/zk-stark".to_string(),
            );
        }

        if self.imported_poc.claim_input_fields
            != ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect::<Vec<_>>()
        {
            errors.push("imported_poc.claim_input_fields must match the imported Winterfell PoC ClaimInput order".to_string());
        }

        if self.imported_poc.public_inputs != ["commitment", "decision", "failure_code"] {
            errors.push(
                "imported_poc.public_inputs must be commitment, decision, failure_code".to_string(),
            );
        }

        if self.imported_poc.gate_count != 10 {
            errors.push(format!(
                "imported_poc.gate_count must be 10, got {}",
                self.imported_poc.gate_count
            ));
        }

        if self.imported_poc.trace_width != 172 {
            errors.push(format!(
                "imported_poc.trace_width must be 172, got {}",
                self.imported_poc.trace_width
            ));
        }

        if self.imported_poc.trace_length != 16 {
            errors.push(format!(
                "imported_poc.trace_length must be 16, got {}",
                self.imported_poc.trace_length
            ));
        }

        if self.required_phase4_artifacts.len() < 10 {
            errors.push(
                "required_phase4_artifacts must include the Phase 4 artifact chain".to_string(),
            );
        }

        if self.field_bindings.len() != ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.len() {
            errors.push(format!(
                "field_bindings must contain {} fields, got {}",
                ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.len(),
                self.field_bindings.len()
            ));
        }

        for required_field in ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS {
            if !self
                .field_bindings
                .iter()
                .any(|binding| binding.winterfell_field == required_field)
            {
                errors.push(format!(
                    "missing Winterfell field binding: {required_field}"
                ));
            }
        }

        let counts = mapping_counts_for_winterfell_adapter_fields(&self.field_bindings);
        if counts
            != (MappingCounts {
                direct: 3,
                partial: 4,
                unmapped: 4,
            })
        {
            errors.push(
                "field_bindings must classify as direct=3, partial=4, unmapped=4".to_string(),
            );
        }

        if self.public_input_bindings.len() != 3 {
            errors.push(format!(
                "public_input_bindings must contain 3 public inputs, got {}",
                self.public_input_bindings.len()
            ));
        }

        for required_public_input in ["commitment", "decision", "failure_code"] {
            if !self
                .public_input_bindings
                .iter()
                .any(|binding| binding.winterfell_public_input == required_public_input)
            {
                errors.push(format!(
                    "missing Winterfell public input binding: {required_public_input}"
                ));
            }
        }

        if self.unsupported_constraint_groups.is_empty() {
            errors.push("unsupported_constraint_groups must be non-empty".to_string());
        }

        if self.winterfell_dependency_imported {
            errors.push("winterfell_dependency_imported must be false in Phase 5A".to_string());
        }

        if self.proof_generation_enabled {
            errors.push("proof_generation_enabled must be false in Phase 5A".to_string());
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

impl WinterfellWitnessCandidate {
    pub const SCHEMA_VERSION: &'static str = "winterfell-witness-candidate-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const CANDIDATE_STATUS: &'static str = "incomplete_needs_source_data_no_prover";

    pub fn from_bridge_input(input: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        input.validate()?;

        let fields = winterfell_witness_candidate_fields(input);
        let counts = mapping_counts_for_winterfell_witness_candidate_fields(&fields);

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: input.schema_version.clone(),
            candidate_status: Self::CANDIDATE_STATUS.to_string(),
            claim_id: input.claim.claim_id.clone(),
            claim_hash: input.claim.claim_hash.clone(),
            fields,
            counts,
            winterfell_dependency_imported: false,
            proof_generation_enabled: false,
            notes: vec![
                "This is a deterministic candidate for the imported Winterfell PoC ClaimInput shape.".to_string(),
                "Only direct bridge fields are populated today; partial and unmapped fields remain explicit None values.".to_string(),
                "This is not a Winterfell witness, does not import Winterfell, and does not generate a STARK proof.".to_string(),
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

        if self.candidate_status != Self::CANDIDATE_STATUS {
            errors.push(format!(
                "candidate_status must be {}, got {}",
                Self::CANDIDATE_STATUS,
                self.candidate_status
            ));
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if self.fields.len() != ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.len() {
            errors.push(format!(
                "fields must contain {} Winterfell fields, got {}",
                ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.len(),
                self.fields.len()
            ));
        }

        for required_field in ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS {
            if !self
                .fields
                .iter()
                .any(|field| field.winterfell_field == required_field)
            {
                errors.push(format!(
                    "missing Winterfell witness field: {required_field}"
                ));
            }
        }

        let actual_counts = mapping_counts_for_winterfell_witness_candidate_fields(&self.fields);
        if self.counts != actual_counts {
            errors.push("counts must match fields classification".to_string());
        }

        if self.counts
            != (MappingCounts {
                direct: 3,
                partial: 4,
                unmapped: 4,
            })
        {
            errors.push("counts must be direct=3, partial=4, unmapped=4".to_string());
        }

        for field in &self.fields {
            if field.winterfell_field.trim().is_empty() {
                errors.push("winterfell_field must be present".to_string());
            }

            match field.class {
                MappingClass::Direct => {
                    if field.value.is_none() {
                        errors.push(format!(
                            "{} direct field must have a candidate value",
                            field.winterfell_field
                        ));
                    }
                    if field.value_status != "populated_direct" {
                        errors.push(format!(
                            "{} direct field value_status must be populated_direct",
                            field.winterfell_field
                        ));
                    }
                }
                MappingClass::Partial => {
                    if field.value.is_some() {
                        errors.push(format!(
                            "{} partial field must not be populated in Phase 5B",
                            field.winterfell_field
                        ));
                    }
                    if field.value_status != "needs_normalization" {
                        errors.push(format!(
                            "{} partial field value_status must be needs_normalization",
                            field.winterfell_field
                        ));
                    }
                }
                MappingClass::Unmapped => {
                    if field.value.is_some() {
                        errors.push(format!(
                            "{} unmapped field must not be populated in Phase 5B",
                            field.winterfell_field
                        ));
                    }
                    if field.value_status != "needs_source_data" {
                        errors.push(format!(
                            "{} unmapped field value_status must be needs_source_data",
                            field.winterfell_field
                        ));
                    }
                }
            }
        }

        if self.winterfell_dependency_imported {
            errors.push("winterfell_dependency_imported must be false in Phase 5B".to_string());
        }

        if self.proof_generation_enabled {
            errors.push("proof_generation_enabled must be false in Phase 5B".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn to_implementation_gap_report(
        &self,
    ) -> Result<WinterfellWitnessImplementationGapReport, Vec<String>> {
        self.validate()?;

        Ok(WinterfellWitnessImplementationGapReport {
            schema_version: WinterfellWitnessImplementationGapReport::SCHEMA_VERSION.to_string(),
            source_schema_version: self.schema_version.clone(),
            report_status: WinterfellWitnessImplementationGapReport::REPORT_STATUS.to_string(),
            claim_id: self.claim_id.clone(),
            claim_hash: self.claim_hash.clone(),
            direct_ready_fields: winterfell_candidate_fields_for_class(self, MappingClass::Direct),
            partial_fields_requiring_normalization: winterfell_candidate_fields_for_class(
                self,
                MappingClass::Partial,
            ),
            unmapped_fields_requiring_source_data: winterfell_candidate_fields_for_class(
                self,
                MappingClass::Unmapped,
            ),
            unsupported_constraints_requiring_prover_work:
                winterfell_unsupported_constraint_tasks(),
            recommended_next_steps: vec![
                "Freeze the populated direct witness fields: eligibility_active, provider_enrolled, and duplicate_flag.".to_string(),
                "Define deterministic normalization for service_line_count, prior_auth_ok, charge_cents, and program_integrity_hold before populating partial fields.".to_string(),
                "Add source-data export paths for member_id, provider_npi, diagnosis_count, and max_charge_cents before treating the candidate as a full Winterfell witness.".to_string(),
                "Implement inverse, comparison, bit-decomposition, commitment, trace-width, and trace-length constraints only after all source fields are available.".to_string(),
                "Keep this report outside active Groth16 runtime until a real STARK prover and verifier path exists.".to_string(),
            ],
            winterfell_dependency_imported: false,
            proof_generation_enabled: false,
        })
    }
}

impl WinterfellWitnessImplementationGapReport {
    pub const SCHEMA_VERSION: &'static str = "winterfell-witness-implementation-gap-report-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "winterfell-witness-candidate-v0";
    pub const REPORT_STATUS: &'static str =
        "implementation_gap_report_planning_only_no_winterfell_import";

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

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if self.direct_ready_fields.len() != 3 {
            errors.push(format!(
                "direct_ready_fields must contain 3 fields, got {}",
                self.direct_ready_fields.len()
            ));
        }

        if self.partial_fields_requiring_normalization.len() != 4 {
            errors.push(format!(
                "partial_fields_requiring_normalization must contain 4 fields, got {}",
                self.partial_fields_requiring_normalization.len()
            ));
        }

        if self.unmapped_fields_requiring_source_data.len() != 4 {
            errors.push(format!(
                "unmapped_fields_requiring_source_data must contain 4 fields, got {}",
                self.unmapped_fields_requiring_source_data.len()
            ));
        }

        for field in &self.direct_ready_fields {
            if field.class != MappingClass::Direct || field.value.is_none() {
                errors.push(format!(
                    "{} direct_ready_fields entry must be direct and populated",
                    field.winterfell_field
                ));
            }
        }

        for field in &self.partial_fields_requiring_normalization {
            if field.class != MappingClass::Partial || field.value.is_some() {
                errors.push(format!(
                    "{} partial_fields_requiring_normalization entry must be partial and unpopulated",
                    field.winterfell_field
                ));
            }
        }

        for field in &self.unmapped_fields_requiring_source_data {
            if field.class != MappingClass::Unmapped || field.value.is_some() {
                errors.push(format!(
                    "{} unmapped_fields_requiring_source_data entry must be unmapped and unpopulated",
                    field.winterfell_field
                ));
            }
        }

        if self
            .unsupported_constraints_requiring_prover_work
            .is_empty()
        {
            errors.push(
                "unsupported_constraints_requiring_prover_work must be non-empty".to_string(),
            );
        }

        if self.recommended_next_steps.is_empty() {
            errors.push("recommended_next_steps must be non-empty".to_string());
        }

        if self.winterfell_dependency_imported {
            errors.push("winterfell_dependency_imported must be false in Phase 5E".to_string());
        }

        if self.proof_generation_enabled {
            errors.push("proof_generation_enabled must be false in Phase 5E".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn to_source_data_requirements(
        &self,
    ) -> Result<WinterfellSourceDataRequirements, Vec<String>> {
        self.validate()?;

        let normalized_field_requirements = self
            .partial_fields_requiring_normalization
            .iter()
            .map(|field| winterfell_source_data_requirement(field, "deterministic_normalization"))
            .collect::<Vec<_>>();
        let source_data_requirements = self
            .unmapped_fields_requiring_source_data
            .iter()
            .map(|field| winterfell_source_data_requirement(field, "missing_source_data"))
            .collect::<Vec<_>>();

        Ok(WinterfellSourceDataRequirements {
            schema_version: WinterfellSourceDataRequirements::SCHEMA_VERSION.to_string(),
            source_schema_version: self.schema_version.clone(),
            requirements_status:
                WinterfellSourceDataRequirements::REQUIREMENTS_STATUS.to_string(),
            claim_id: self.claim_id.clone(),
            claim_hash: self.claim_hash.clone(),
            required_fields_total: normalized_field_requirements.len()
                + source_data_requirements.len(),
            normalized_fields_total: normalized_field_requirements.len(),
            source_data_fields_total: source_data_requirements.len(),
            normalized_field_requirements,
            source_data_requirements,
            recommended_next_steps: vec![
                "Choose an owning upstream source for member_id, provider_npi, diagnosis_count, and max_charge_cents.".to_string(),
                "Define deterministic normalization formulas for service_line_count, prior_auth_ok, charge_cents, and program_integrity_hold.".to_string(),
                "Add fixtures for every required field before a Winterfell adapter imports prover code.".to_string(),
                "Keep the active Groth16 runtime unchanged until the source-data contract is satisfied and a real STARK proof verifies.".to_string(),
            ],
            winterfell_dependency_imported: false,
            proof_generation_enabled: false,
        })
    }
}

impl WinterfellSourceDataRequirements {
    pub const SCHEMA_VERSION: &'static str = "winterfell-source-data-requirements-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        "winterfell-witness-implementation-gap-report-v0";
    pub const REQUIREMENTS_STATUS: &'static str =
        "source_data_requirements_planning_only_no_winterfell_import";

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

        if self.requirements_status != Self::REQUIREMENTS_STATUS {
            errors.push(format!(
                "requirements_status must be {}, got {}",
                Self::REQUIREMENTS_STATUS,
                self.requirements_status
            ));
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if self.normalized_field_requirements.len() != 4 {
            errors.push(format!(
                "normalized_field_requirements must contain 4 fields, got {}",
                self.normalized_field_requirements.len()
            ));
        }

        if self.source_data_requirements.len() != 4 {
            errors.push(format!(
                "source_data_requirements must contain 4 fields, got {}",
                self.source_data_requirements.len()
            ));
        }

        if self.normalized_fields_total != self.normalized_field_requirements.len() {
            errors.push("normalized_fields_total must match normalized requirements".to_string());
        }

        if self.source_data_fields_total != self.source_data_requirements.len() {
            errors.push("source_data_fields_total must match source-data requirements".to_string());
        }

        if self.required_fields_total
            != self.normalized_field_requirements.len() + self.source_data_requirements.len()
        {
            errors.push(
                "required_fields_total must equal normalized plus source-data requirements"
                    .to_string(),
            );
        }

        for requirement in &self.normalized_field_requirements {
            validate_winterfell_source_requirement(
                requirement,
                "deterministic_normalization",
                &mut errors,
            );
        }

        for requirement in &self.source_data_requirements {
            validate_winterfell_source_requirement(requirement, "missing_source_data", &mut errors);
        }

        if self.recommended_next_steps.is_empty() {
            errors.push("recommended_next_steps must be non-empty".to_string());
        }

        if self.winterfell_dependency_imported {
            errors.push("winterfell_dependency_imported must be false in Phase 5F".to_string());
        }

        if self.proof_generation_enabled {
            errors.push("proof_generation_enabled must be false in Phase 5F".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl WinterfellSourceDataFixture {
    pub const SCHEMA_VERSION: &'static str = "winterfell-source-data-fixture-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "winterfell-source-data-requirements-v0";
    pub const FIXTURE_STATUS: &'static str =
        "fixture_only_satisfies_phase5f_requirements_no_winterfell_import";
    pub const REQUIRED_FIELDS: [&'static str; 8] = [
        "member_id",
        "provider_npi",
        "diagnosis_count",
        "max_charge_cents",
        "service_line_count",
        "prior_auth_ok",
        "charge_cents",
        "program_integrity_hold",
    ];

    pub fn demo_from_requirements(
        requirements: &WinterfellSourceDataRequirements,
    ) -> Result<Self, Vec<String>> {
        requirements.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: requirements.schema_version.clone(),
            fixture_status: Self::FIXTURE_STATUS.to_string(),
            claim_id: requirements.claim_id.clone(),
            claim_hash: requirements.claim_hash.clone(),
            member_id: "MEMBER-FIXTURE-001".to_string(),
            provider_npi: "1234567893".to_string(),
            diagnosis_count: 1,
            max_charge_cents: 150_000,
            service_line_count: 1,
            prior_auth_ok: 1,
            charge_cents: 100_000,
            program_integrity_hold: 0,
            source_requirements_satisfied: Self::REQUIRED_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            winterfell_dependency_imported: false,
            proof_generation_enabled: false,
            notes: vec![
                "This is deterministic fixture data for Phase 5 adapter tests only.".to_string(),
                "It is not produced by rust-engine and is not used by the active Groth16 runtime."
                    .to_string(),
                "No Winterfell dependency is imported and no STARK proof is generated.".to_string(),
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

        if self.fixture_status != Self::FIXTURE_STATUS {
            errors.push(format!(
                "fixture_status must be {}, got {}",
                Self::FIXTURE_STATUS,
                self.fixture_status
            ));
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if self.member_id.trim().is_empty() {
            errors.push("member_id must be present".to_string());
        }

        if !is_10_digit_npi(&self.provider_npi) {
            errors.push("provider_npi must be a 10-digit numeric string".to_string());
        }

        if self.diagnosis_count == 0 {
            errors.push("diagnosis_count must be greater than 0".to_string());
        }

        if self.max_charge_cents == 0 {
            errors.push("max_charge_cents must be greater than 0".to_string());
        }

        if self.service_line_count == 0 {
            errors.push("service_line_count must be greater than 0".to_string());
        }

        if self.charge_cents == 0 {
            errors.push("charge_cents must be greater than 0".to_string());
        }

        if self.charge_cents > self.max_charge_cents {
            errors.push("charge_cents must be less than or equal to max_charge_cents".to_string());
        }

        validate_boolean_fact("prior_auth_ok", self.prior_auth_ok, &mut errors);
        validate_boolean_fact(
            "program_integrity_hold",
            self.program_integrity_hold,
            &mut errors,
        );

        for required_field in Self::REQUIRED_FIELDS {
            if !self
                .source_requirements_satisfied
                .iter()
                .any(|field| field == required_field)
            {
                errors.push(format!(
                    "source_requirements_satisfied missing {required_field}"
                ));
            }
        }

        if self.source_requirements_satisfied.len() != Self::REQUIRED_FIELDS.len() {
            errors.push(format!(
                "source_requirements_satisfied must contain {} fields, got {}",
                Self::REQUIRED_FIELDS.len(),
                self.source_requirements_satisfied.len()
            ));
        }

        if self.winterfell_dependency_imported {
            errors.push("winterfell_dependency_imported must be false in Phase 5G".to_string());
        }

        if self.proof_generation_enabled {
            errors.push("proof_generation_enabled must be false in Phase 5G".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn to_complete_witness_candidate(
        &self,
        candidate: &WinterfellWitnessCandidate,
    ) -> Result<WinterfellCompleteWitnessCandidate, Vec<String>> {
        self.validate()?;
        candidate.validate()?;

        if self.claim_id != candidate.claim_id {
            return Err(vec![format!(
                "fixture claim_id {} must match candidate claim_id {}",
                self.claim_id, candidate.claim_id
            )]);
        }

        if self.claim_hash != candidate.claim_hash {
            return Err(vec![format!(
                "fixture claim_hash {} must match candidate claim_hash {}",
                self.claim_hash, candidate.claim_hash
            )]);
        }

        let fields = ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS
            .iter()
            .map(|field| complete_winterfell_field(field, candidate, self))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(WinterfellCompleteWitnessCandidate {
            schema_version: WinterfellCompleteWitnessCandidate::SCHEMA_VERSION.to_string(),
            source_schema_version:
                WinterfellCompleteWitnessCandidate::SOURCE_SCHEMA_VERSION.to_string(),
            candidate_status: WinterfellCompleteWitnessCandidate::CANDIDATE_STATUS.to_string(),
            claim_id: self.claim_id.clone(),
            claim_hash: self.claim_hash.clone(),
            field_count: fields.len(),
            all_fields_populated: fields.len() == ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.len(),
            fields,
            winterfell_dependency_imported: false,
            proof_generation_enabled: false,
            notes: vec![
                "This complete candidate is assembled from a base Winterfell witness candidate and Phase 5G fixture data.".to_string(),
                "It is adapter-ready test data only; it is not a Winterfell witness and does not generate a proof.".to_string(),
                "The active Groth16 runtime remains unchanged.".to_string(),
            ],
        })
    }
}

impl WinterfellCompleteWitnessCandidate {
    pub const SCHEMA_VERSION: &'static str = "winterfell-complete-witness-candidate-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        "winterfell-witness-candidate-v0+winterfell-source-data-fixture-v0";
    pub const CANDIDATE_STATUS: &'static str =
        "complete_adapter_ready_fixture_no_winterfell_import";

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

        if self.candidate_status != Self::CANDIDATE_STATUS {
            errors.push(format!(
                "candidate_status must be {}, got {}",
                Self::CANDIDATE_STATUS,
                self.candidate_status
            ));
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if self.fields.len() != ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.len() {
            errors.push(format!(
                "fields must contain {} Winterfell fields, got {}",
                ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS.len(),
                self.fields.len()
            ));
        }

        if self.field_count != self.fields.len() {
            errors.push("field_count must match fields length".to_string());
        }

        if !self.all_fields_populated {
            errors.push("all_fields_populated must be true".to_string());
        }

        for required_field in ActiveClaimToStarkBridge::IMPORTED_STARK_FIELDS {
            if !self
                .fields
                .iter()
                .any(|field| field.winterfell_field == required_field)
            {
                errors.push(format!(
                    "missing complete Winterfell field: {required_field}"
                ));
            }
        }

        for field in &self.fields {
            if field.winterfell_field.trim().is_empty() {
                errors.push("winterfell_field must be present".to_string());
            }

            if field.value_status != "populated_adapter_ready_fixture" {
                errors.push(format!(
                    "{} value_status must be populated_adapter_ready_fixture",
                    field.winterfell_field
                ));
            }

            if field.source_artifact.trim().is_empty() {
                errors.push(format!(
                    "{} source_artifact must be present",
                    field.winterfell_field
                ));
            }

            if field.source_field.trim().is_empty() {
                errors.push(format!(
                    "{} source_field must be present",
                    field.winterfell_field
                ));
            }

            if field.note.trim().is_empty() {
                errors.push(format!("{} note must be present", field.winterfell_field));
            }
        }

        if self.winterfell_dependency_imported {
            errors.push("winterfell_dependency_imported must be false in Phase 5H".to_string());
        }

        if self.proof_generation_enabled {
            errors.push("proof_generation_enabled must be false in Phase 5H".to_string());
        }

        if self.notes.is_empty() {
            errors.push("notes must be non-empty".to_string());
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

    pub fn to_digest_candidate(&self) -> Result<SourceRootDigestCandidate, Vec<String>> {
        self.validate()?;
        source_root_digest_candidate_from_source(
            Self::SCHEMA_VERSION,
            "claim_source_root",
            self,
            vec![
                "This candidate hashes claim source root input source data only.".to_string(),
                "It is not a production claimSourceRoot and does not build a Merkle tree."
                    .to_string(),
                "Production hash/root strategy remains unselected.".to_string(),
                "The active Groth16 flow remains unchanged.".to_string(),
            ],
        )
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
                errors.push(
                    "provider_npi must be exactly 10 decimal digits when present".to_string(),
                );
            }
        }

        if let Some(service_line_count) = self.service_line_count {
            if service_line_count == 0 {
                errors
                    .push("service_line_count must be greater than zero when present".to_string());
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

    pub fn to_digest_candidate(&self) -> Result<SourceRootDigestCandidate, Vec<String>> {
        self.validate()?;
        source_root_digest_candidate_from_source(
            Self::SCHEMA_VERSION,
            "oracle_facts_root",
            self,
            vec![
                "This candidate hashes oracle facts root input source data only.".to_string(),
                "It is not a production oracleFactsRoot and does not build a Merkle tree."
                    .to_string(),
                "Production hash/root strategy remains unselected.".to_string(),
                "The active Groth16 flow remains unchanged.".to_string(),
            ],
        )
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

impl FeeScheduleRootInput {
    pub const SCHEMA_VERSION: &'static str = "fee-schedule-root-input-v0";
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
            fee_schedule_id: None,
            entries: Vec::new(),
            root_generation_status: Self::ROOT_GENERATION_STATUS.to_string(),
            notes: vec![
                "This input is a normalized source schema for future feeScheduleRoot work."
                    .to_string(),
                "The current rust-engine bridge exports claim amount and billing validity flags, not source-backed fee schedule entries.".to_string(),
                "No fee schedule leaf, hash, Merkle root, pricing calculation, or STARK proof is generated from this object.".to_string(),
                "The active Groth16 workflow remains unchanged.".to_string(),
            ],
        })
    }

    pub fn to_digest_candidate(&self) -> Result<SourceRootDigestCandidate, Vec<String>> {
        self.validate()?;
        source_root_digest_candidate_from_source(
            Self::SCHEMA_VERSION,
            "fee_schedule_root",
            self,
            vec![
                "This candidate hashes fee schedule root input source data only.".to_string(),
                "It is not a production feeScheduleRoot and does not build a Merkle tree."
                    .to_string(),
                "Production hash/root strategy remains unselected.".to_string(),
                "The active Groth16 flow remains unchanged.".to_string(),
            ],
        )
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

        if let Some(fee_schedule_id) = &self.fee_schedule_id {
            if fee_schedule_id.trim().is_empty() {
                errors.push("fee_schedule_id must be non-empty when present".to_string());
            }
        }

        for (index, entry) in self.entries.iter().enumerate() {
            if entry.fee_code.trim().is_empty() {
                errors.push(format!("entries[{index}].fee_code must be present"));
            }

            if entry.unit_amount_cents == 0 {
                errors.push(format!(
                    "entries[{index}].unit_amount_cents must be greater than zero"
                ));
            }

            if entry.currency.len() != 3
                || !entry.currency.chars().all(|ch| ch.is_ascii_uppercase())
            {
                errors.push(format!(
                    "entries[{index}].currency must be a 3-letter uppercase code"
                ));
            }

            if let Some(effective_thru) = entry.effective_thru {
                if effective_thru < entry.effective_from {
                    errors.push(format!(
                        "entries[{index}].effective_thru must be greater than or equal to effective_from"
                    ));
                }
            }

            if let Some(source_url) = &entry.source_url {
                if !source_url.starts_with("https://") {
                    errors.push(format!(
                        "entries[{index}].source_url must use https when present"
                    ));
                }
            }

            if entry.verification_status.trim().is_empty() {
                errors.push(format!(
                    "entries[{index}].verification_status must be present"
                ));
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

impl NullifierRootTransitionInput {
    pub const SCHEMA_VERSION: &'static str = "nullifier-root-transition-input-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-bridge-input-v0";
    pub const INPUT_STATUS: &'static str = "transition_schema_only_no_root_generation";
    pub const TRANSITION_STATUS: &'static str = "not_applied";
    pub const ROOT_GENERATION_STATUS: &'static str = "not_generated";

    pub fn from_bridge_input(input: &StarkBridgeInput) -> Result<Self, Vec<String>> {
        input.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: input.schema_version.clone(),
            input_status: Self::INPUT_STATUS.to_string(),
            claim_id: input.claim.claim_id.clone(),
            claim_hash: input.claim.claim_hash.clone(),
            nullifier_candidate: None,
            nullifier_root_before: None,
            nullifier_root_after: None,
            transition_status: Self::TRANSITION_STATUS.to_string(),
            root_generation_status: Self::ROOT_GENERATION_STATUS.to_string(),
            notes: vec![
                "This input is a normalized transition schema for future nullifierRoot work."
                    .to_string(),
                "The current rust-engine bridge exports claim_hash and duplicate flag, not privacy-preserving nullifier source material or tree state.".to_string(),
                "No nullifier derivation, membership check, root transition, Merkle root, or STARK proof is generated from this object.".to_string(),
                "The active Groth16 workflow remains unchanged.".to_string(),
            ],
        })
    }

    pub fn to_digest_candidate(&self) -> Result<SourceRootDigestCandidate, Vec<String>> {
        self.validate()?;
        source_root_digest_candidate_from_source(
            Self::SCHEMA_VERSION,
            "nullifier_root_transition",
            self,
            vec![
                "This candidate hashes nullifier root transition input source data only."
                    .to_string(),
                "It is not a production nullifier root transition and does not build or update a Merkle tree."
                    .to_string(),
                "Production hash/root strategy remains unselected.".to_string(),
                "The active Groth16 flow remains unchanged.".to_string(),
            ],
        )
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

        if let Some(nullifier_candidate) = &self.nullifier_candidate {
            if !is_0x_32_byte_hex(nullifier_candidate) {
                errors.push(
                    "nullifier_candidate must be a 0x-prefixed 32-byte hex string when present"
                        .to_string(),
                );
            }
        }

        if let Some(nullifier_root_before) = &self.nullifier_root_before {
            if !is_0x_32_byte_hex(nullifier_root_before) {
                errors.push(
                    "nullifier_root_before must be a 0x-prefixed 32-byte hex string when present"
                        .to_string(),
                );
            }
        }

        if let Some(nullifier_root_after) = &self.nullifier_root_after {
            if !is_0x_32_byte_hex(nullifier_root_after) {
                errors.push(
                    "nullifier_root_after must be a 0x-prefixed 32-byte hex string when present"
                        .to_string(),
                );
            }
        }

        if self.transition_status != Self::TRANSITION_STATUS {
            errors.push(format!(
                "transition_status must be {}, got {}",
                Self::TRANSITION_STATUS,
                self.transition_status
            ));
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

fn is_10_digit_npi(value: &str) -> bool {
    value.len() == 10 && value.chars().all(|ch| ch.is_ascii_digit())
}

fn complete_winterfell_field(
    field: &str,
    candidate: &WinterfellWitnessCandidate,
    fixture: &WinterfellSourceDataFixture,
) -> Result<WinterfellCompleteWitnessField, Vec<String>> {
    let candidate_field = candidate
        .fields
        .iter()
        .find(|candidate_field| candidate_field.winterfell_field == field);

    let (value, source_artifact, source_field, note) = match field {
        "member_id" => (
            stable_fixture_string_to_u64(&fixture.member_id),
            "WinterfellSourceDataFixture",
            "member_id",
            "Fixture member_id is deterministically normalized into a u64 adapter value.",
        ),
        "provider_npi" => (
            fixture.provider_npi.parse::<u64>().map_err(|err| {
                vec![format!(
                    "provider_npi must parse to u64 for complete candidate: {err}"
                )]
            })?,
            "WinterfellSourceDataFixture",
            "provider_npi",
            "Fixture provider_npi is parsed as the numeric PoC adapter value.",
        ),
        "eligibility_active" | "provider_enrolled" | "duplicate_flag" => {
            let Some(candidate_field) = candidate_field else {
                return Err(vec![format!("base candidate missing direct field {field}")]);
            };
            let Some(value) = candidate_field.value else {
                return Err(vec![format!(
                    "base candidate direct field {field} is not populated"
                )]);
            };
            (
                value,
                candidate_field
                    .source_artifact
                    .as_deref()
                    .unwrap_or("WinterfellWitnessCandidate"),
                candidate_field.source_field.as_deref().unwrap_or(field),
                "Direct field is carried forward from the validated base witness candidate.",
            )
        }
        "service_line_count" => (
            fixture.service_line_count,
            "WinterfellSourceDataFixture",
            "service_line_count",
            "Fixture service_line_count satisfies the deterministic normalization requirement.",
        ),
        "diagnosis_count" => (
            fixture.diagnosis_count,
            "WinterfellSourceDataFixture",
            "diagnosis_count",
            "Fixture diagnosis_count satisfies the missing source-data requirement.",
        ),
        "prior_auth_ok" => (
            fixture.prior_auth_ok as u64,
            "WinterfellSourceDataFixture",
            "prior_auth_ok",
            "Fixture prior_auth_ok satisfies the deterministic normalization requirement.",
        ),
        "charge_cents" => (
            fixture.charge_cents,
            "WinterfellSourceDataFixture",
            "charge_cents",
            "Fixture charge_cents satisfies the deterministic normalization requirement.",
        ),
        "max_charge_cents" => (
            fixture.max_charge_cents,
            "WinterfellSourceDataFixture",
            "max_charge_cents",
            "Fixture max_charge_cents satisfies the missing source-data requirement.",
        ),
        "program_integrity_hold" => (
            fixture.program_integrity_hold as u64,
            "WinterfellSourceDataFixture",
            "program_integrity_hold",
            "Fixture program_integrity_hold satisfies the deterministic normalization requirement.",
        ),
        _ => {
            return Err(vec![format!(
                "unsupported Winterfell complete witness field: {field}"
            )]);
        }
    };

    Ok(WinterfellCompleteWitnessField {
        winterfell_field: field.to_string(),
        value,
        value_status: "populated_adapter_ready_fixture".to_string(),
        source_artifact: source_artifact.to_string(),
        source_field: source_field.to_string(),
        note: note.to_string(),
    })
}

fn stable_fixture_string_to_u64(value: &str) -> u64 {
    value.bytes().fold(0xcbf29ce484222325u64, |hash, byte| {
        hash ^ (byte as u64).wrapping_mul(0x100000001b3)
    })
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

fn mapping_counts_for_winterfell_adapter_fields(
    fields: &[WinterfellAdapterFieldBinding],
) -> MappingCounts {
    MappingCounts {
        direct: fields
            .iter()
            .filter(|binding| binding.class == MappingClass::Direct)
            .count(),
        partial: fields
            .iter()
            .filter(|binding| binding.class == MappingClass::Partial)
            .count(),
        unmapped: fields
            .iter()
            .filter(|binding| binding.class == MappingClass::Unmapped)
            .count(),
    }
}

fn mapping_counts_for_winterfell_witness_candidate_fields(
    fields: &[WinterfellWitnessCandidateField],
) -> MappingCounts {
    MappingCounts {
        direct: fields
            .iter()
            .filter(|field| field.class == MappingClass::Direct)
            .count(),
        partial: fields
            .iter()
            .filter(|field| field.class == MappingClass::Partial)
            .count(),
        unmapped: fields
            .iter()
            .filter(|field| field.class == MappingClass::Unmapped)
            .count(),
    }
}

fn winterfell_candidate_fields_for_class(
    candidate: &WinterfellWitnessCandidate,
    class: MappingClass,
) -> Vec<WinterfellWitnessCandidateField> {
    candidate
        .fields
        .iter()
        .filter(|field| field.class == class)
        .cloned()
        .collect()
}

fn winterfell_source_data_requirement(
    field: &WinterfellWitnessCandidateField,
    requirement_type: &str,
) -> WinterfellSourceDataRequirement {
    WinterfellSourceDataRequirement {
        winterfell_field: field.winterfell_field.clone(),
        requirement_type: requirement_type.to_string(),
        source_artifact: field.source_artifact.clone(),
        source_field: field.source_field.clone(),
        required_before: "real_winterfell_witness_generation".to_string(),
        note: field.note.clone(),
    }
}

fn validate_winterfell_source_requirement(
    requirement: &WinterfellSourceDataRequirement,
    expected_type: &str,
    errors: &mut Vec<String>,
) {
    if requirement.winterfell_field.trim().is_empty() {
        errors.push("winterfell_field must be present".to_string());
    }

    if requirement.requirement_type != expected_type {
        errors.push(format!(
            "{} requirement_type must be {}, got {}",
            requirement.winterfell_field, expected_type, requirement.requirement_type
        ));
    }

    if requirement.required_before != "real_winterfell_witness_generation" {
        errors.push(format!(
            "{} required_before must be real_winterfell_witness_generation",
            requirement.winterfell_field
        ));
    }

    if requirement.note.trim().is_empty() {
        errors.push(format!(
            "{} requirement note must be present",
            requirement.winterfell_field
        ));
    }
}

fn winterfell_unsupported_constraint_tasks() -> Vec<String> {
    vec![
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
    ]
}

fn winterfell_witness_candidate_fields(
    input: &StarkBridgeInput,
) -> Vec<WinterfellWitnessCandidateField> {
    winterfell_adapter_field_bindings()
        .into_iter()
        .map(|binding| {
            let value = match binding.winterfell_field.as_str() {
                "eligibility_active" => Some(input.active_rust_facts.eligibility_active as u64),
                "provider_enrolled" => Some(input.active_rust_facts.provider_enrolled as u64),
                "duplicate_flag" => Some(input.active_rust_facts.is_duplicate as u64),
                _ => None,
            };
            let value_status = match binding.class {
                MappingClass::Direct => "populated_direct",
                MappingClass::Partial => "needs_normalization",
                MappingClass::Unmapped => "needs_source_data",
            };

            WinterfellWitnessCandidateField {
                winterfell_field: binding.winterfell_field,
                value,
                value_status: value_status.to_string(),
                source_artifact: binding.phase4_source_artifact,
                source_field: binding.phase4_source_field,
                class: binding.class,
                note: binding.note,
            }
        })
        .collect()
}

fn winterfell_adapter_field_bindings() -> Vec<WinterfellAdapterFieldBinding> {
    vec![
        WinterfellAdapterFieldBinding {
            winterfell_field: "member_id".to_string(),
            phase4_source_artifact: Some("ClaimSourceRootInput".to_string()),
            phase4_source_field: Some("member_id".to_string()),
            class: MappingClass::Unmapped,
            note: "Phase 4 schema can carry member_id, but active rust-engine does not export it."
                .to_string(),
        },
        WinterfellAdapterFieldBinding {
            winterfell_field: "provider_npi".to_string(),
            phase4_source_artifact: Some("ClaimSourceRootInput".to_string()),
            phase4_source_field: Some("provider_npi".to_string()),
            class: MappingClass::Unmapped,
            note: "Phase 4 schema can carry provider_npi, but active rust-engine does not export it.".to_string(),
        },
        WinterfellAdapterFieldBinding {
            winterfell_field: "eligibility_active".to_string(),
            phase4_source_artifact: Some("StarkBridgeInput".to_string()),
            phase4_source_field: Some("active_rust_facts.eligibility_active".to_string()),
            class: MappingClass::Direct,
            note: "Direct boolean field in both active Rust and imported Winterfell PoC."
                .to_string(),
        },
        WinterfellAdapterFieldBinding {
            winterfell_field: "provider_enrolled".to_string(),
            phase4_source_artifact: Some("StarkBridgeInput".to_string()),
            phase4_source_field: Some("active_rust_facts.provider_enrolled".to_string()),
            class: MappingClass::Direct,
            note: "Direct boolean field in both active Rust and imported Winterfell PoC."
                .to_string(),
        },
        WinterfellAdapterFieldBinding {
            winterfell_field: "service_line_count".to_string(),
            phase4_source_artifact: Some("ClaimSourceRootInput".to_string()),
            phase4_source_field: Some("service_line_count".to_string()),
            class: MappingClass::Partial,
            note: "Phase 4 schema has optional service_line_count; active bridge only has billing_code_valid and units_valid.".to_string(),
        },
        WinterfellAdapterFieldBinding {
            winterfell_field: "diagnosis_count".to_string(),
            phase4_source_artifact: Some("ClaimSourceRootInput".to_string()),
            phase4_source_field: Some("diagnosis_codes.len".to_string()),
            class: MappingClass::Unmapped,
            note: "Phase 4 can derive a count from diagnosis_codes only after upstream source data exists.".to_string(),
        },
        WinterfellAdapterFieldBinding {
            winterfell_field: "prior_auth_ok".to_string(),
            phase4_source_artifact: Some("StarkBridgeInput".to_string()),
            phase4_source_field: Some("active_rust_facts.physician_certification_valid".to_string()),
            class: MappingClass::Partial,
            note: "Physician certification may support authorization but is not equivalent to prior_auth_ok.".to_string(),
        },
        WinterfellAdapterFieldBinding {
            winterfell_field: "charge_cents".to_string(),
            phase4_source_artifact: Some("StarkBridgeInput".to_string()),
            phase4_source_field: Some("claim.claim_amount".to_string()),
            class: MappingClass::Partial,
            note: "Claim amount needs currency, unit, and fee schedule normalization before it can be Winterfell charge_cents.".to_string(),
        },
        WinterfellAdapterFieldBinding {
            winterfell_field: "max_charge_cents".to_string(),
            phase4_source_artifact: Some("FeeScheduleRootInput".to_string()),
            phase4_source_field: Some("entries.unit_amount_cents".to_string()),
            class: MappingClass::Unmapped,
            note: "Phase 4 fee schedule schema exists, but active bridge has no fee schedule row or max allowed charge.".to_string(),
        },
        WinterfellAdapterFieldBinding {
            winterfell_field: "duplicate_flag".to_string(),
            phase4_source_artifact: Some("StarkBridgeInput".to_string()),
            phase4_source_field: Some("active_rust_facts.is_duplicate".to_string()),
            class: MappingClass::Direct,
            note: "Same duplicate fact; Winterfell gate proves duplicate_flag == 0 for approval.".to_string(),
        },
        WinterfellAdapterFieldBinding {
            winterfell_field: "program_integrity_hold".to_string(),
            phase4_source_artifact: Some("OracleFactsRootInput".to_string()),
            phase4_source_field: Some("facts".to_string()),
            class: MappingClass::Partial,
            note: "Active Rust has related validity flags, but no canonical program integrity hold source fact.".to_string(),
        },
    ]
}

fn winterfell_adapter_public_input_bindings() -> Vec<WinterfellAdapterPublicInputBinding> {
    vec![
        WinterfellAdapterPublicInputBinding {
            winterfell_public_input: "commitment".to_string(),
            phase4_source_artifact: Some("BatchRootCompatibilityPlan".to_string()),
            phase4_source_field: Some("combinedPublicInputVector".to_string()),
            class: MappingClass::Partial,
            note: "PoC commitment is an AIR-bound algebraic hash; Phase 4 roots need a production commitment strategy.".to_string(),
        },
        WinterfellAdapterPublicInputBinding {
            winterfell_public_input: "decision".to_string(),
            phase4_source_artifact: Some("StarkBridgeInput".to_string()),
            phase4_source_field: Some("public_inputs.decision".to_string()),
            class: MappingClass::Direct,
            note: "Decision is a direct public adjudication input.".to_string(),
        },
        WinterfellAdapterPublicInputBinding {
            winterfell_public_input: "failure_code".to_string(),
            phase4_source_artifact: Some("StarkBridgeInput".to_string()),
            phase4_source_field: Some("public_inputs.failure_code".to_string()),
            class: MappingClass::Direct,
            note: "Failure code is a direct public adjudication input.".to_string(),
        },
    ]
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

#[cfg(feature = "winterfell-poc")]
pub mod winterfell_poc_adapter {
    use super::{WinterfellCompleteWitnessCandidate, WinterfellCompleteWitnessField};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    /// Feature-gated preview proving that the localBCE complete witness
    /// candidate can be shaped into the imported Winterfell PoC input model.
    ///
    /// This module intentionally does not call the prover. It is the first
    /// compile-time import boundary for `blind-ledger-app-layer/zk-stark`.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct WinterfellPocAdapterPreview {
        pub schema_version: String,
        pub source_schema_version: String,
        pub adapter_status: String,
        pub claim_id: String,
        pub claim_hash: String,
        pub poc_decision: u32,
        pub poc_failure_code: u32,
        pub poc_gates: [u32; 10],
        pub field_count: usize,
        pub winterfell_dependency_imported: bool,
        pub proof_generation_enabled: bool,
        pub notes: Vec<String>,
    }

    /// Feature-gated proof preview generated by the imported Winterfell PoC.
    ///
    /// This is a local proof prototype report, not an active runtime artifact.
    /// It is only available when `stark-engine` is built with the
    /// `winterfell-poc` feature.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct WinterfellPocProofPreview {
        pub schema_version: String,
        pub source_schema_version: String,
        pub proof_status: String,
        pub claim_id: String,
        pub claim_hash: String,
        pub decision: u32,
        pub failure_code: u32,
        pub gates: [u32; 10],
        pub proof_size_bytes: usize,
        pub prove_ms: u128,
        pub prove_us: u128,
        pub verify_ms: u128,
        pub verify_us: u128,
        pub verified: bool,
        pub winterfell_dependency_imported: bool,
        pub proof_generation_enabled: bool,
        pub runtime_wired: bool,
        pub on_chain_submission: bool,
        pub notes: Vec<String>,
    }

    /// Feature-gated real local proof fixture generated by the imported
    /// Winterfell PoC.
    ///
    /// This contains real Winterfell proof bytes for the PoC AIR, but it is not
    /// production evidence for the active localBCE runtime until the semantic
    /// gaps and verifier boundary are closed.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct WinterfellPocRealProofFixture {
        pub schema_version: String,
        pub source_schema_version: String,
        pub fixture_status: String,
        pub prover_name: String,
        pub prover_version: String,
        pub claim_id: String,
        pub claim_hash: String,
        pub decision: u32,
        pub failure_code: u32,
        pub gates: [u32; 10],
        pub proof_bytes_hex: String,
        pub proof_bytes_len: usize,
        pub proof_bytes_sha256: String,
        pub public_inputs_json: serde_json::Value,
        pub local_verification_status: String,
        pub verified: bool,
        pub winterfell_dependency_imported: bool,
        pub proof_generation_enabled: bool,
        pub production_semantics_complete: bool,
        pub runtime_wired: bool,
        pub on_chain_submission: bool,
        pub accepted_as_runtime_evidence: bool,
        pub notes: Vec<String>,
    }

    /// Settlement-boundary preview derived from a validated Winterfell proof
    /// preview.
    ///
    /// This is the first object shaped like something a future settlement
    /// contract or attestation anchor could consume. It intentionally excludes
    /// proof bytes and does not imply on-chain verification.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct StarkSettlementBoundaryArtifact {
        pub schema_version: String,
        pub source_schema_version: String,
        pub artifact_status: String,
        pub claim_id: String,
        pub claim_hash: String,
        pub decision: u32,
        pub failure_code: u32,
        pub proof_preview_status: String,
        pub proof_verified: bool,
        pub proof_size_bytes: usize,
        pub verifier_target: String,
        pub runtime_wired: bool,
        pub on_chain_submission: bool,
        pub groth16_flow_unchanged: bool,
        pub settlement_contract_ready: bool,
        pub notes: Vec<String>,
    }

    /// Solidity-facing interface plan derived from a settlement-boundary
    /// artifact.
    ///
    /// This is documentation-as-data for a future verifier/attestation
    /// contract. It does not modify Solidity and does not declare a live
    /// verifier interface.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct StarkSolidityVerifierInterfacePlan {
        pub schema_version: String,
        pub source_schema_version: String,
        pub interface_status: String,
        pub interface_name: String,
        pub function_signature: String,
        pub solidity_inputs: Vec<SolidityVerifierInput>,
        pub required_checks: Vec<String>,
        pub unsupported_runtime_work: Vec<String>,
        pub contract_modification_allowed: bool,
        pub runtime_wired: bool,
        pub on_chain_submission: bool,
        pub notes: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct SolidityVerifierInput {
        pub name: String,
        pub solidity_type: String,
        pub source_field: String,
        pub value_preview: String,
        pub status: String,
    }

    /// Gap report for moving from a Solidity verifier interface plan to an
    /// active settlement integration.
    ///
    /// This report is still pre-contract. It exists to make the blockers
    /// explicit before any Solidity files are modified.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct StarkSettlementIntegrationGapReport {
        pub schema_version: String,
        pub source_schema_version: String,
        pub report_status: String,
        pub verifier_contract_gaps: Vec<String>,
        pub claims_registry_integration_gaps: Vec<String>,
        pub governance_gaps: Vec<String>,
        pub calldata_public_input_gaps: Vec<String>,
        pub test_requirements: Vec<String>,
        pub recommended_next_steps: Vec<String>,
        pub contract_modification_allowed: bool,
        pub runtime_wired: bool,
        pub on_chain_submission: bool,
        pub notes: Vec<String>,
    }

    /// Planning-only implementation sequence for closing settlement integration
    /// gaps.
    ///
    /// This is intentionally not a contract spec. It gives the safe order of
    /// operations for later Solidity-scoped phases while keeping Groth16 as the
    /// active runtime path.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct StarkSettlementIntegrationImplementationPlan {
        pub schema_version: String,
        pub source_schema_version: String,
        pub plan_status: String,
        pub phases: Vec<SettlementIntegrationPhase>,
        pub blocked_by: Vec<String>,
        pub required_artifacts: Vec<String>,
        pub safety_invariants: Vec<String>,
        pub contract_modification_allowed: bool,
        pub runtime_wired: bool,
        pub on_chain_submission: bool,
        pub notes: Vec<String>,
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct SettlementIntegrationPhase {
        pub phase_id: String,
        pub title: String,
        pub source_gap_category: String,
        pub allowed_scope: String,
        pub actions: Vec<String>,
        pub completion_gate: String,
    }

    /// Runtime cutover readiness report for STARK settlement.
    ///
    /// This is intentionally conservative: it converts the implementation plan
    /// into explicit gates and keeps runtime readiness false until later
    /// contract/prover/governance phases satisfy those gates.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct StarkSettlementRuntimeReadinessReport {
        pub schema_version: String,
        pub source_schema_version: String,
        pub readiness_status: String,
        pub ready_for_runtime: bool,
        pub ready_for_contract_changes: bool,
        pub ready_for_on_chain_submission: bool,
        pub satisfied_gates: Vec<String>,
        pub unsatisfied_gates: Vec<String>,
        pub required_evidence: Vec<String>,
        pub next_review_actions: Vec<String>,
        pub groth16_regression_required: bool,
        pub stark_smoke_chain_required: bool,
        pub foundry_regression_required: bool,
        pub human_approval_required: bool,
        pub notes: Vec<String>,
    }

    impl WinterfellPocAdapterPreview {
        pub const SCHEMA_VERSION: &'static str = "winterfell-poc-adapter-preview-v0";
        pub const SOURCE_SCHEMA_VERSION: &'static str = "winterfell-complete-witness-candidate-v0";
        pub const ADAPTER_STATUS: &'static str =
            "winterfell_poc_imported_input_mapped_no_proof_generation";

        pub fn from_complete_candidate(
            candidate: &WinterfellCompleteWitnessCandidate,
        ) -> Result<Self, Vec<String>> {
            let poc_input = to_poc_claim_input(candidate)?;
            let poc_output = blind_ledger_stark::output_for_claim(poc_input);

            Ok(Self {
                schema_version: Self::SCHEMA_VERSION.to_string(),
                source_schema_version: candidate.schema_version.clone(),
                adapter_status: Self::ADAPTER_STATUS.to_string(),
                claim_id: candidate.claim_id.clone(),
                claim_hash: candidate.claim_hash.clone(),
                poc_decision: poc_output.decision,
                poc_failure_code: poc_output.failure_code,
                poc_gates: poc_output.gates,
                field_count: candidate.field_count,
                winterfell_dependency_imported: true,
                proof_generation_enabled: false,
                notes: vec![
                    "The imported Winterfell PoC crate was compiled behind the winterfell-poc feature.".to_string(),
                    "This preview maps complete localBCE adapter data into blind_ledger_stark::ClaimInput.".to_string(),
                    "No Winterfell proof is generated by this adapter preview.".to_string(),
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

            if self.adapter_status != Self::ADAPTER_STATUS {
                errors.push(format!(
                    "adapter_status must be {}, got {}",
                    Self::ADAPTER_STATUS,
                    self.adapter_status
                ));
            }

            if self.claim_id.trim().is_empty() {
                errors.push("claim_id must be present".to_string());
            }

            if !self.claim_hash.starts_with("0x") || self.claim_hash.len() != 66 {
                errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
            }

            if self.poc_decision > 1 {
                errors.push("poc_decision must be 0 or 1".to_string());
            }

            for (idx, gate) in self.poc_gates.iter().enumerate() {
                if *gate > 1 {
                    errors.push(format!("poc_gates[{idx}] must be 0 or 1"));
                }
            }

            if self.field_count != 11 {
                errors.push(format!("field_count must be 11, got {}", self.field_count));
            }

            if !self.winterfell_dependency_imported {
                errors.push(
                    "winterfell_dependency_imported must be true for feature-gated preview"
                        .to_string(),
                );
            }

            if self.proof_generation_enabled {
                errors.push("proof_generation_enabled must remain false".to_string());
            }

            if self.notes.is_empty() {
                errors.push("notes must be non-empty".to_string());
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }
    }

    impl WinterfellPocProofPreview {
        pub const SCHEMA_VERSION: &'static str = "winterfell-poc-proof-preview-v0";
        pub const SOURCE_SCHEMA_VERSION: &'static str = "winterfell-complete-witness-candidate-v0";
        pub const PROOF_STATUS: &'static str =
            "winterfell_poc_proof_generated_and_verified_feature_only";

        pub fn from_complete_candidate(
            candidate: &WinterfellCompleteWitnessCandidate,
        ) -> Result<Self, Vec<String>> {
            let poc_input = to_poc_claim_input(candidate)?;
            let (proof, public_inputs, output, prove_duration) =
                blind_ledger_stark::prove_claim(poc_input).map_err(|err| {
                    vec![format!("Winterfell PoC proof generation failed: {err}")]
                })?;
            let proof_size_bytes = proof.to_bytes().len();
            let (verified, verify_duration) =
                blind_ledger_stark::verify_claim(proof, public_inputs);

            Ok(Self {
                schema_version: Self::SCHEMA_VERSION.to_string(),
                source_schema_version: candidate.schema_version.clone(),
                proof_status: Self::PROOF_STATUS.to_string(),
                claim_id: candidate.claim_id.clone(),
                claim_hash: candidate.claim_hash.clone(),
                decision: output.decision,
                failure_code: output.failure_code,
                gates: output.gates,
                proof_size_bytes,
                prove_ms: prove_duration.as_millis(),
                prove_us: prove_duration.as_micros(),
                verify_ms: verify_duration.as_millis(),
                verify_us: verify_duration.as_micros(),
                verified,
                winterfell_dependency_imported: true,
                proof_generation_enabled: true,
                runtime_wired: false,
                on_chain_submission: false,
                notes: vec![
                    "This report is produced only with the winterfell-poc feature enabled."
                        .to_string(),
                    "The imported Winterfell PoC generated and verified a local proof.".to_string(),
                    "The active rust-engine Groth16 runtime remains unchanged.".to_string(),
                    "No on-chain STARK verifier or settlement path is used by this preview."
                        .to_string(),
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

            if self.proof_status != Self::PROOF_STATUS {
                errors.push(format!(
                    "proof_status must be {}, got {}",
                    Self::PROOF_STATUS,
                    self.proof_status
                ));
            }

            if self.claim_id.trim().is_empty() {
                errors.push("claim_id must be present".to_string());
            }

            if !self.claim_hash.starts_with("0x") || self.claim_hash.len() != 66 {
                errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
            }

            if self.decision > 1 {
                errors.push("decision must be 0 or 1".to_string());
            }

            for (idx, gate) in self.gates.iter().enumerate() {
                if *gate > 1 {
                    errors.push(format!("gates[{idx}] must be 0 or 1"));
                }
            }

            if self.proof_size_bytes == 0 {
                errors.push("proof_size_bytes must be greater than zero".to_string());
            }

            if !self.verified {
                errors.push("verified must be true".to_string());
            }

            if !self.winterfell_dependency_imported {
                errors.push("winterfell_dependency_imported must be true".to_string());
            }

            if !self.proof_generation_enabled {
                errors.push("proof_generation_enabled must be true".to_string());
            }

            if self.runtime_wired {
                errors.push("runtime_wired must remain false".to_string());
            }

            if self.on_chain_submission {
                errors.push("on_chain_submission must remain false".to_string());
            }

            if self.notes.is_empty() {
                errors.push("notes must be non-empty".to_string());
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }

        pub fn to_settlement_boundary_artifact(
            &self,
        ) -> Result<StarkSettlementBoundaryArtifact, Vec<String>> {
            self.validate()?;

            Ok(StarkSettlementBoundaryArtifact {
                schema_version: "stark-settlement-boundary-artifact-v0".to_string(),
                source_schema_version: self.schema_version.clone(),
                artifact_status: StarkSettlementBoundaryArtifact::ARTIFACT_STATUS.to_string(),
                claim_id: self.claim_id.clone(),
                claim_hash: self.claim_hash.clone(),
                decision: self.decision,
                failure_code: self.failure_code,
                proof_preview_status: self.proof_status.clone(),
                proof_verified: self.verified,
                proof_size_bytes: self.proof_size_bytes,
                verifier_target: "future_stark_settlement_or_attestation_contract".to_string(),
                runtime_wired: false,
                on_chain_submission: false,
                groth16_flow_unchanged: true,
                settlement_contract_ready: false,
                notes: vec![
                    "This artifact is derived from a feature-gated Winterfell proof preview."
                        .to_string(),
                    "It is shaped for future settlement-boundary planning only.".to_string(),
                    "It does not contain proof bytes and is not submitted on-chain.".to_string(),
                    "The active Groth16 ClaimsRegistry path remains unchanged.".to_string(),
                ],
            })
        }
    }

    impl WinterfellPocRealProofFixture {
        pub const SCHEMA_VERSION: &'static str = "winterfell-poc-real-proof-fixture-v0";
        pub const SOURCE_SCHEMA_VERSION: &'static str = "winterfell-complete-witness-candidate-v0";
        pub const FIXTURE_STATUS: &'static str =
            "real_winterfell_poc_proof_generated_and_verified_non_runtime";
        pub const PROVER_NAME: &'static str = "winterfell-poc";
        pub const PROVER_VERSION: &'static str = "0.13.1";

        pub fn from_complete_candidate(
            candidate: &WinterfellCompleteWitnessCandidate,
        ) -> Result<Self, Vec<String>> {
            let poc_input = to_poc_claim_input(candidate)?;
            let (proof, public_inputs, output, _prove_duration) =
                blind_ledger_stark::prove_claim(poc_input).map_err(|err| {
                    vec![format!("Winterfell PoC proof generation failed: {err}")]
                })?;
            let proof_bytes = proof.to_bytes();
            let proof_bytes_hex = format!("0x{}", hex_lower(&proof_bytes));
            let proof_bytes_sha256 = format!("0x{}", hex_lower(&Sha256::digest(&proof_bytes)));
            let (verified, _verify_duration) =
                blind_ledger_stark::verify_claim(proof, public_inputs);
            let public_inputs_json =
                blind_ledger_stark::format_public_inputs(public_inputs, &output);

            Ok(Self {
                schema_version: Self::SCHEMA_VERSION.to_string(),
                source_schema_version: candidate.schema_version.clone(),
                fixture_status: Self::FIXTURE_STATUS.to_string(),
                prover_name: Self::PROVER_NAME.to_string(),
                prover_version: Self::PROVER_VERSION.to_string(),
                claim_id: candidate.claim_id.clone(),
                claim_hash: candidate.claim_hash.clone(),
                decision: output.decision,
                failure_code: output.failure_code,
                gates: output.gates,
                proof_bytes_hex,
                proof_bytes_len: proof_bytes.len(),
                proof_bytes_sha256,
                public_inputs_json,
                local_verification_status: "verified".to_string(),
                verified,
                winterfell_dependency_imported: true,
                proof_generation_enabled: true,
                production_semantics_complete: false,
                runtime_wired: false,
                on_chain_submission: false,
                accepted_as_runtime_evidence: false,
                notes: vec![
                    "This fixture contains real proof bytes generated by the imported Winterfell PoC."
                        .to_string(),
                    "The proof is locally verified against the imported PoC AIR only.".to_string(),
                    "It is not accepted as active localBCE runtime evidence yet.".to_string(),
                    "The active Groth16 runtime flow remains unchanged.".to_string(),
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

            if self.fixture_status != Self::FIXTURE_STATUS {
                errors.push(format!(
                    "fixture_status must be {}, got {}",
                    Self::FIXTURE_STATUS,
                    self.fixture_status
                ));
            }

            if self.prover_name != Self::PROVER_NAME {
                errors.push(format!("prover_name must be {}", Self::PROVER_NAME));
            }

            if self.prover_version != Self::PROVER_VERSION {
                errors.push(format!("prover_version must be {}", Self::PROVER_VERSION));
            }

            if self.claim_id.trim().is_empty() {
                errors.push("claim_id must be present".to_string());
            }

            if !self.claim_hash.starts_with("0x") || self.claim_hash.len() != 66 {
                errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
            }

            if self.decision > 1 {
                errors.push("decision must be 0 or 1".to_string());
            }

            for (idx, gate) in self.gates.iter().enumerate() {
                if *gate > 1 {
                    errors.push(format!("gates[{idx}] must be 0 or 1"));
                }
            }

            if !self.proof_bytes_hex.starts_with("0x") {
                errors.push("proof_bytes_hex must be 0x-prefixed".to_string());
            }

            if self.proof_bytes_len == 0 {
                errors.push("proof_bytes_len must be greater than zero".to_string());
            }

            if self.proof_bytes_hex.len() != 2 + self.proof_bytes_len * 2 {
                errors.push("proof_bytes_hex length must match proof_bytes_len".to_string());
            }

            if !is_0x_32_byte_hex(&self.proof_bytes_sha256) {
                errors.push(
                    "proof_bytes_sha256 must be a 0x-prefixed 32-byte hex string".to_string(),
                );
            }

            if self.local_verification_status != "verified" {
                errors.push("local_verification_status must be verified".to_string());
            }

            if !self.verified {
                errors.push("verified must be true".to_string());
            }

            if !self.winterfell_dependency_imported {
                errors.push("winterfell_dependency_imported must be true".to_string());
            }

            if !self.proof_generation_enabled {
                errors.push("proof_generation_enabled must be true".to_string());
            }

            if self.production_semantics_complete {
                errors.push("production_semantics_complete must remain false".to_string());
            }

            if self.runtime_wired {
                errors.push("runtime_wired must remain false".to_string());
            }

            if self.on_chain_submission {
                errors.push("on_chain_submission must remain false".to_string());
            }

            if self.accepted_as_runtime_evidence {
                errors.push("accepted_as_runtime_evidence must remain false".to_string());
            }

            if self.notes.is_empty() {
                errors.push("notes must be non-empty".to_string());
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }
    }

    impl StarkSettlementBoundaryArtifact {
        pub const SCHEMA_VERSION: &'static str = "stark-settlement-boundary-artifact-v0";
        pub const SOURCE_SCHEMA_VERSION: &'static str = "winterfell-poc-proof-preview-v0";
        pub const ARTIFACT_STATUS: &'static str = "settlement_boundary_preview_not_runtime";

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

            if self.artifact_status != Self::ARTIFACT_STATUS {
                errors.push(format!(
                    "artifact_status must be {}, got {}",
                    Self::ARTIFACT_STATUS,
                    self.artifact_status
                ));
            }

            if self.claim_id.trim().is_empty() {
                errors.push("claim_id must be present".to_string());
            }

            if !self.claim_hash.starts_with("0x") || self.claim_hash.len() != 66 {
                errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
            }

            if self.decision > 1 {
                errors.push("decision must be 0 or 1".to_string());
            }

            if self.proof_preview_status != WinterfellPocProofPreview::PROOF_STATUS {
                errors.push(format!(
                    "proof_preview_status must be {}",
                    WinterfellPocProofPreview::PROOF_STATUS
                ));
            }

            if !self.proof_verified {
                errors.push("proof_verified must be true".to_string());
            }

            if self.proof_size_bytes == 0 {
                errors.push("proof_size_bytes must be greater than zero".to_string());
            }

            if self.verifier_target.trim().is_empty() {
                errors.push("verifier_target must be present".to_string());
            }

            if self.runtime_wired {
                errors.push("runtime_wired must remain false".to_string());
            }

            if self.on_chain_submission {
                errors.push("on_chain_submission must remain false".to_string());
            }

            if !self.groth16_flow_unchanged {
                errors.push("groth16_flow_unchanged must be true".to_string());
            }

            if self.settlement_contract_ready {
                errors.push("settlement_contract_ready must remain false".to_string());
            }

            if self.notes.is_empty() {
                errors.push("notes must be non-empty".to_string());
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }

        pub fn to_solidity_verifier_interface_plan(
            &self,
        ) -> Result<StarkSolidityVerifierInterfacePlan, Vec<String>> {
            self.validate()?;

            Ok(StarkSolidityVerifierInterfacePlan {
                schema_version: StarkSolidityVerifierInterfacePlan::SCHEMA_VERSION.to_string(),
                source_schema_version: self.schema_version.clone(),
                interface_status: StarkSolidityVerifierInterfacePlan::INTERFACE_STATUS.to_string(),
                interface_name: "IStarkClaimsVerifierV1Candidate".to_string(),
                function_signature:
                    "verifyStarkClaim((bytes32,uint8,uint32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32) publicInputs,bytes proof) external view returns (bool)"
                        .to_string(),
                solidity_inputs: vec![
                    SolidityVerifierInput {
                        name: "claimHash".to_string(),
                        solidity_type: "bytes32".to_string(),
                        source_field: "claim_hash".to_string(),
                        value_preview: self.claim_hash.clone(),
                        status: "available_from_boundary_artifact".to_string(),
                    },
                    SolidityVerifierInput {
                        name: "decision".to_string(),
                        solidity_type: "uint8".to_string(),
                        source_field: "decision".to_string(),
                        value_preview: self.decision.to_string(),
                        status: "available_from_boundary_artifact".to_string(),
                    },
                    SolidityVerifierInput {
                        name: "failureCode".to_string(),
                        solidity_type: "uint32".to_string(),
                        source_field: "failure_code".to_string(),
                        value_preview: self.failure_code.to_string(),
                        status: "available_from_boundary_artifact".to_string(),
                    },
                    SolidityVerifierInput {
                        name: "publicInputRoot".to_string(),
                        solidity_type: "bytes32".to_string(),
                        source_field: "future_public_input_root".to_string(),
                        value_preview: "unavailable_in_preview".to_string(),
                        status: "requires_root_generation".to_string(),
                    },
                    SolidityVerifierInput {
                        name: "claimSourceRoot".to_string(),
                        solidity_type: "bytes32".to_string(),
                        source_field: "future_claim_source_root".to_string(),
                        value_preview: "unavailable_in_preview".to_string(),
                        status: "requires_root_generation".to_string(),
                    },
                    SolidityVerifierInput {
                        name: "oracleFactsRoot".to_string(),
                        solidity_type: "bytes32".to_string(),
                        source_field: "future_oracle_facts_root".to_string(),
                        value_preview: "unavailable_in_preview".to_string(),
                        status: "requires_root_generation".to_string(),
                    },
                    SolidityVerifierInput {
                        name: "feeScheduleRoot".to_string(),
                        solidity_type: "bytes32".to_string(),
                        source_field: "future_fee_schedule_root".to_string(),
                        value_preview: "unavailable_in_preview".to_string(),
                        status: "requires_root_generation".to_string(),
                    },
                    SolidityVerifierInput {
                        name: "nullifierRootBefore".to_string(),
                        solidity_type: "bytes32".to_string(),
                        source_field: "future_nullifier_root_before".to_string(),
                        value_preview: "unavailable_in_preview".to_string(),
                        status: "requires_root_generation".to_string(),
                    },
                    SolidityVerifierInput {
                        name: "nullifierRootAfter".to_string(),
                        solidity_type: "bytes32".to_string(),
                        source_field: "future_nullifier_root_after".to_string(),
                        value_preview: "unavailable_in_preview".to_string(),
                        status: "requires_root_generation".to_string(),
                    },
                    SolidityVerifierInput {
                        name: "batchRoot".to_string(),
                        solidity_type: "bytes32".to_string(),
                        source_field: "future_batch_root".to_string(),
                        value_preview: "unavailable_in_preview".to_string(),
                        status: "requires_root_generation".to_string(),
                    },
                    SolidityVerifierInput {
                        name: "proof".to_string(),
                        solidity_type: "bytes".to_string(),
                        source_field: "future_stark_proof_bytes_or_attestation_payload".to_string(),
                        value_preview: "unavailable_in_preview".to_string(),
                        status: "requires_real_verifier_artifact".to_string(),
                    },
                ],
                required_checks: vec![
                    "claimHash must match the adjudicated claim hash".to_string(),
                    "decision must be 0 or 1".to_string(),
                    "approved decisions require failureCode == 0".to_string(),
                    "denied decisions require failureCode != 0".to_string(),
                    "all V1 root fields must be nonzero before production verification"
                        .to_string(),
                    "proof bytes must bind to the verified STARK public inputs".to_string(),
                    "verifier key or attestation authority must be governed".to_string(),
                ],
                unsupported_runtime_work: vec![
                    "Solidity verifier contract implementation".to_string(),
                    "Verifier artifact pinning and governance".to_string(),
                    "Proof byte format and calldata encoding".to_string(),
                    "ClaimsRegistry STARK settlement path".to_string(),
                    "Replay/nullifier enforcement for STARK settlement".to_string(),
                ],
                contract_modification_allowed: false,
                runtime_wired: false,
                on_chain_submission: false,
                notes: vec![
                    "This plan is generated from a STARK settlement-boundary preview artifact."
                        .to_string(),
                    "It is a future Solidity interface sketch, not an active contract ABI."
                        .to_string(),
                    "Do not modify ClaimsRegistry or Verifier.sol from this artifact alone."
                        .to_string(),
                    "The active Groth16 settlement path remains unchanged.".to_string(),
                ],
            })
        }
    }

    impl StarkSolidityVerifierInterfacePlan {
        pub const SCHEMA_VERSION: &'static str = "stark-solidity-verifier-interface-plan-v0";
        pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-settlement-boundary-artifact-v0";
        pub const INTERFACE_STATUS: &'static str =
            "solidity_interface_plan_only_no_contract_changes";
        pub const V1_CANDIDATE_INTERFACE_NAME: &'static str = "IStarkClaimsVerifierV1Candidate";
        pub const V1_CANDIDATE_INPUTS: [(&'static str, &'static str); 11] = [
            ("claimHash", "bytes32"),
            ("decision", "uint8"),
            ("failureCode", "uint32"),
            ("publicInputRoot", "bytes32"),
            ("claimSourceRoot", "bytes32"),
            ("oracleFactsRoot", "bytes32"),
            ("feeScheduleRoot", "bytes32"),
            ("nullifierRootBefore", "bytes32"),
            ("nullifierRootAfter", "bytes32"),
            ("batchRoot", "bytes32"),
            ("proof", "bytes"),
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

            if self.interface_status != Self::INTERFACE_STATUS {
                errors.push(format!(
                    "interface_status must be {}, got {}",
                    Self::INTERFACE_STATUS,
                    self.interface_status
                ));
            }

            if self.interface_name.trim().is_empty() {
                errors.push("interface_name must be present".to_string());
            }

            if self.interface_name != "IStarkClaimsVerifierV1Candidate" {
                errors.push("interface_name must be IStarkClaimsVerifierV1Candidate".to_string());
            }

            if !self.function_signature.contains("verifyStarkClaim(") {
                errors.push("function_signature must define verifyStarkClaim".to_string());
            }

            for required_input in [
                "claimHash",
                "decision",
                "failureCode",
                "publicInputRoot",
                "claimSourceRoot",
                "oracleFactsRoot",
                "feeScheduleRoot",
                "nullifierRootBefore",
                "nullifierRootAfter",
                "batchRoot",
                "proof",
            ] {
                if !self
                    .solidity_inputs
                    .iter()
                    .any(|input| input.name == required_input)
                {
                    errors.push(format!("missing Solidity verifier input: {required_input}"));
                }
            }

            for input in &self.solidity_inputs {
                if input.name.trim().is_empty() {
                    errors.push("solidity input name must be present".to_string());
                }
                if input.solidity_type.trim().is_empty() {
                    errors.push(format!("{} solidity_type must be present", input.name));
                }
                if input.source_field.trim().is_empty() {
                    errors.push(format!("{} source_field must be present", input.name));
                }
                if input.status.trim().is_empty() {
                    errors.push(format!("{} status must be present", input.name));
                }
            }

            if self.required_checks.len() < 4 {
                errors.push("required_checks must include settlement guard checks".to_string());
            }

            if self.unsupported_runtime_work.is_empty() {
                errors.push("unsupported_runtime_work must be non-empty".to_string());
            }

            if self.contract_modification_allowed {
                errors.push("contract_modification_allowed must remain false".to_string());
            }

            if self.runtime_wired {
                errors.push("runtime_wired must remain false".to_string());
            }

            if self.on_chain_submission {
                errors.push("on_chain_submission must remain false".to_string());
            }

            if self.notes.is_empty() {
                errors.push("notes must be non-empty".to_string());
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }

        pub fn validate_v1_candidate_alignment(&self) -> Result<(), Vec<String>> {
            let mut errors = Vec::new();

            if let Err(validation_errors) = self.validate() {
                errors.extend(validation_errors);
            }

            if self.interface_name != Self::V1_CANDIDATE_INTERFACE_NAME {
                errors.push(format!(
                    "interface_name must match V1 candidate {}, got {}",
                    Self::V1_CANDIDATE_INTERFACE_NAME,
                    self.interface_name
                ));
            }

            if !self.function_signature.contains("verifyStarkClaim(") {
                errors
                    .push("function_signature must use V1 candidate verifyStarkClaim".to_string());
            }

            if self.solidity_inputs.len() != Self::V1_CANDIDATE_INPUTS.len() {
                errors.push(format!(
                    "solidity_inputs must contain exactly {} V1 candidate inputs, got {}",
                    Self::V1_CANDIDATE_INPUTS.len(),
                    self.solidity_inputs.len()
                ));
            }

            for (index, (expected_name, expected_type)) in
                Self::V1_CANDIDATE_INPUTS.iter().enumerate()
            {
                let Some(input) = self.solidity_inputs.get(index) else {
                    errors.push(format!("missing V1 candidate input at index {index}"));
                    continue;
                };

                if input.name != *expected_name {
                    errors.push(format!(
                        "solidity_inputs[{index}].name must be {expected_name}, got {}",
                        input.name
                    ));
                }

                if input.solidity_type != *expected_type {
                    errors.push(format!(
                        "solidity_inputs[{index}].solidity_type for {} must be {expected_type}, got {}",
                        input.name, input.solidity_type
                    ));
                }
            }

            for root_name in [
                "publicInputRoot",
                "claimSourceRoot",
                "oracleFactsRoot",
                "feeScheduleRoot",
                "nullifierRootBefore",
                "nullifierRootAfter",
                "batchRoot",
            ] {
                match self
                    .solidity_inputs
                    .iter()
                    .find(|input| input.name == root_name)
                {
                    Some(input) => {
                        if input.value_preview != "unavailable_in_preview" {
                            errors.push(format!(
                                "{root_name} value_preview must be unavailable_in_preview"
                            ));
                        }
                        if input.status != "requires_root_generation" {
                            errors.push(format!(
                                "{root_name} status must be requires_root_generation"
                            ));
                        }
                    }
                    None => errors.push(format!("missing V1 candidate root input {root_name}")),
                }
            }

            match self
                .solidity_inputs
                .iter()
                .find(|input| input.name == "proof")
            {
                Some(input) => {
                    if input.value_preview != "unavailable_in_preview" {
                        errors
                            .push("proof value_preview must be unavailable_in_preview".to_string());
                    }
                    if input.status != "requires_real_verifier_artifact" {
                        errors.push(
                            "proof status must be requires_real_verifier_artifact".to_string(),
                        );
                    }
                }
                None => errors.push("missing V1 candidate proof input".to_string()),
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }

        pub fn to_settlement_integration_gap_report(
            &self,
        ) -> Result<StarkSettlementIntegrationGapReport, Vec<String>> {
            self.validate()?;

            Ok(StarkSettlementIntegrationGapReport {
                schema_version: StarkSettlementIntegrationGapReport::SCHEMA_VERSION.to_string(),
                source_schema_version: self.schema_version.clone(),
                report_status: StarkSettlementIntegrationGapReport::REPORT_STATUS.to_string(),
                verifier_contract_gaps: vec![
                    "Select verifier architecture: native verifier, verifier precompile, or governed attestation anchor.".to_string(),
                    "Define proofCommitment bytes format and binding to STARK public inputs.".to_string(),
                    "Pin verifier key or attestation authority through governed configuration.".to_string(),
                    "Define verifier failure modes and revert/error surface.".to_string(),
                ],
                claims_registry_integration_gaps: vec![
                    "Add a separate STARK settlement path without changing current Groth16 submission behavior.".to_string(),
                    "Define event schema for STARK-verified adjudications.".to_string(),
                    "Define replay/nullifier enforcement before accepting STARK settlement.".to_string(),
                    "Preserve duplicate claim protection and fee behavior from ClaimsRegistry.".to_string(),
                ],
                governance_gaps: vec![
                    "Add verifier artifact pinning policy.".to_string(),
                    "Define upgrade and emergency pause controls for STARK settlement.".to_string(),
                    "Define operator permissions for submitting STARK settlement artifacts.".to_string(),
                ],
                calldata_public_input_gaps: vec![
                    "Freeze calldata encoding for claimHash, decision, failureCode, and proofCommitment.".to_string(),
                    "Define public input root ordering once batch roots are real.".to_string(),
                    "Define conversion from 0x-prefixed claim_hash string to Solidity bytes32.".to_string(),
                    "Add negative tests for mismatched public inputs.".to_string(),
                ],
                test_requirements: vec![
                    "Foundry interface-only tests before ClaimsRegistry changes.".to_string(),
                    "Foundry mock verifier tests before real verifier wiring.".to_string(),
                    "End-to-end dry run proving Groth16 path still passes unchanged.".to_string(),
                    "Negative tests for invalid decision/failureCode/proofCommitment combinations.".to_string(),
                ],
                recommended_next_steps: vec![
                    "Create a Solidity interface-only file or test fixture in a later explicit Solidity-scoped phase.".to_string(),
                    "Add a mock STARK verifier contract only after this gap report is reviewed.".to_string(),
                    "Keep ClaimsRegistry unchanged until mock verifier tests are green.".to_string(),
                    "Keep Groth16 verifier and current ClaimsRegistry path as the compatibility baseline.".to_string(),
                ],
                contract_modification_allowed: false,
                runtime_wired: false,
                on_chain_submission: false,
                notes: vec![
                    "This report is generated from a Solidity verifier interface plan.".to_string(),
                    "It is a blocker list, not an implementation approval.".to_string(),
                    "No Solidity files are modified by this phase.".to_string(),
                    "The active Groth16 runtime remains unchanged.".to_string(),
                ],
            })
        }
    }

    impl StarkSettlementIntegrationGapReport {
        pub const SCHEMA_VERSION: &'static str = "stark-settlement-integration-gap-report-v0";
        pub const SOURCE_SCHEMA_VERSION: &'static str = "stark-solidity-verifier-interface-plan-v0";
        pub const REPORT_STATUS: &'static str = "settlement_integration_gap_report_no_runtime";

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

            if self.verifier_contract_gaps.is_empty() {
                errors.push("verifier_contract_gaps must be non-empty".to_string());
            }

            if self.claims_registry_integration_gaps.is_empty() {
                errors.push("claims_registry_integration_gaps must be non-empty".to_string());
            }

            if self.governance_gaps.is_empty() {
                errors.push("governance_gaps must be non-empty".to_string());
            }

            if self.calldata_public_input_gaps.is_empty() {
                errors.push("calldata_public_input_gaps must be non-empty".to_string());
            }

            if self.test_requirements.is_empty() {
                errors.push("test_requirements must be non-empty".to_string());
            }

            if self.recommended_next_steps.is_empty() {
                errors.push("recommended_next_steps must be non-empty".to_string());
            }

            if self.contract_modification_allowed {
                errors.push("contract_modification_allowed must remain false".to_string());
            }

            if self.runtime_wired {
                errors.push("runtime_wired must remain false".to_string());
            }

            if self.on_chain_submission {
                errors.push("on_chain_submission must remain false".to_string());
            }

            if self.notes.is_empty() {
                errors.push("notes must be non-empty".to_string());
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }

        pub fn to_settlement_implementation_plan(
            &self,
        ) -> Result<StarkSettlementIntegrationImplementationPlan, Vec<String>> {
            self.validate()?;

            Ok(StarkSettlementIntegrationImplementationPlan {
                schema_version: StarkSettlementIntegrationImplementationPlan::SCHEMA_VERSION
                    .to_string(),
                source_schema_version: self.schema_version.clone(),
                plan_status: StarkSettlementIntegrationImplementationPlan::PLAN_STATUS.to_string(),
                phases: vec![
                    SettlementIntegrationPhase {
                        phase_id: "phase_1_interface_fixtures".to_string(),
                        title: "Add interface-only Solidity fixtures".to_string(),
                        source_gap_category: "verifier_contract_gaps".to_string(),
                        allowed_scope: "tests_and_interfaces_only".to_string(),
                        actions: vec![
                            "Create an interface-only STARK verifier fixture in a Solidity-scoped phase.".to_string(),
                            "Freeze verifyClaim input names and types from the interface plan.".to_string(),
                            "Add Foundry tests that compile the interface without touching ClaimsRegistry.".to_string(),
                        ],
                        completion_gate:
                            "Foundry build and interface-only tests pass with ClaimsRegistry unchanged."
                                .to_string(),
                    },
                    SettlementIntegrationPhase {
                        phase_id: "phase_2_mock_verifier_harness".to_string(),
                        title: "Add mock verifier behavior tests".to_string(),
                        source_gap_category: "verifier_contract_gaps".to_string(),
                        allowed_scope: "test_contracts_only".to_string(),
                        actions: vec![
                            "Add a mock STARK verifier that accepts deterministic preview artifacts.".to_string(),
                            "Test valid and invalid proofCommitment/public-input combinations.".to_string(),
                            "Keep the mock verifier outside the production deployment path.".to_string(),
                        ],
                        completion_gate:
                            "Mock verifier tests cover success, rejection, malformed proofCommitment, and mismatched public inputs."
                                .to_string(),
                    },
                    SettlementIntegrationPhase {
                        phase_id: "phase_3_claims_registry_adapter_plan".to_string(),
                        title: "Plan a separate ClaimsRegistry STARK settlement adapter".to_string(),
                        source_gap_category: "claims_registry_integration_gaps".to_string(),
                        allowed_scope: "planning_and_tests_only".to_string(),
                        actions: vec![
                            "Define a separate STARK submission function or adapter path.".to_string(),
                            "Preserve current Groth16 submit path and fee behavior as the compatibility baseline.".to_string(),
                            "Specify STARK event fields without changing the deployed contract yet.".to_string(),
                        ],
                        completion_gate:
                            "Adapter plan proves Groth16 behavior remains unchanged and documents every new STARK event/public input."
                                .to_string(),
                    },
                    SettlementIntegrationPhase {
                        phase_id: "phase_4_governance_and_artifact_pinning".to_string(),
                        title: "Define governance and verifier artifact pinning".to_string(),
                        source_gap_category: "governance_gaps".to_string(),
                        allowed_scope: "ops_docs_and_inactive_config_only".to_string(),
                        actions: vec![
                            "Map verifier artifact pins to ops governance scaffolding.".to_string(),
                            "Define emergency pause and upgrade review gates before runtime wiring.".to_string(),
                            "Require production_usable=false until a real verifier is reviewed.".to_string(),
                        ],
                        completion_gate:
                            "Ops scaffolding identifies verifier artifacts, owners, review gates, and rollback behavior."
                                .to_string(),
                    },
                    SettlementIntegrationPhase {
                        phase_id: "phase_5_runtime_cutover_readiness".to_string(),
                        title: "Gate any runtime cutover behind end-to-end evidence".to_string(),
                        source_gap_category: "test_requirements".to_string(),
                        allowed_scope: "readiness_report_only".to_string(),
                        actions: vec![
                            "Run Groth16 regression, STARK smoke chain, Foundry tests, and settlement mock tests together.".to_string(),
                            "Require an explicit human decision before modifying ClaimsRegistry runtime behavior.".to_string(),
                            "Document rollback criteria and known unsupported STARK production risks.".to_string(),
                        ],
                        completion_gate:
                            "A readiness report passes all checks and still marks runtime_wired=false until a separate implementation phase."
                                .to_string(),
                    },
                ],
                blocked_by: vec![
                    "No production STARK Solidity verifier has been selected or audited.".to_string(),
                    "proofCommitment bytes format is not production-final.".to_string(),
                    "Verifier key or attestation authority governance is not active.".to_string(),
                    "ClaimsRegistry STARK settlement path has not been designed or tested.".to_string(),
                ],
                required_artifacts: vec![
                    "stark_settlement_boundary_artifact.json".to_string(),
                    "stark_solidity_verifier_interface_plan.json".to_string(),
                    "stark_settlement_integration_gap_report.json".to_string(),
                    "future_mock_stark_verifier_foundry_tests".to_string(),
                    "future_stark_settlement_readiness_report".to_string(),
                ],
                safety_invariants: vec![
                    "The active Groth16 workflow remains unchanged.".to_string(),
                    "No Solidity contract is modified by this implementation plan.".to_string(),
                    "No on-chain STARK submission occurs in planning phases.".to_string(),
                    "ClaimsRegistry fee and duplicate-claim behavior remain the baseline.".to_string(),
                ],
                contract_modification_allowed: false,
                runtime_wired: false,
                on_chain_submission: false,
                notes: vec![
                    "This implementation plan is derived from the settlement integration gap report."
                        .to_string(),
                    "It is an ordering and safety artifact, not permission to modify contracts."
                        .to_string(),
                    "Each runtime-affecting step must be requested as a separate explicit phase."
                        .to_string(),
                ],
            })
        }
    }

    impl StarkSettlementIntegrationImplementationPlan {
        pub const SCHEMA_VERSION: &'static str =
            "stark-settlement-integration-implementation-plan-v0";
        pub const SOURCE_SCHEMA_VERSION: &'static str =
            "stark-settlement-integration-gap-report-v0";
        pub const PLAN_STATUS: &'static str =
            "settlement_integration_implementation_plan_no_runtime";

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

            if self.plan_status != Self::PLAN_STATUS {
                errors.push(format!(
                    "plan_status must be {}, got {}",
                    Self::PLAN_STATUS,
                    self.plan_status
                ));
            }

            if self.phases.len() < 5 {
                errors.push("phases must include at least five ordered steps".to_string());
            }

            for phase in &self.phases {
                if phase.phase_id.trim().is_empty() {
                    errors.push("phase_id must be present".to_string());
                }
                if phase.title.trim().is_empty() {
                    errors.push(format!("{} title must be present", phase.phase_id));
                }
                if phase.source_gap_category.trim().is_empty() {
                    errors.push(format!(
                        "{} source_gap_category must be present",
                        phase.phase_id
                    ));
                }
                if phase.allowed_scope.trim().is_empty() {
                    errors.push(format!("{} allowed_scope must be present", phase.phase_id));
                }
                if phase.actions.is_empty() {
                    errors.push(format!("{} actions must be non-empty", phase.phase_id));
                }
                if phase.completion_gate.trim().is_empty() {
                    errors.push(format!(
                        "{} completion_gate must be present",
                        phase.phase_id
                    ));
                }
            }

            if self.blocked_by.is_empty() {
                errors.push("blocked_by must be non-empty".to_string());
            }

            if self.required_artifacts.is_empty() {
                errors.push("required_artifacts must be non-empty".to_string());
            }

            if !self
                .safety_invariants
                .iter()
                .any(|invariant| invariant.contains("Groth16 workflow remains unchanged"))
            {
                errors.push(
                    "safety_invariants must preserve the active Groth16 workflow".to_string(),
                );
            }

            if self.contract_modification_allowed {
                errors.push("contract_modification_allowed must remain false".to_string());
            }

            if self.runtime_wired {
                errors.push("runtime_wired must remain false".to_string());
            }

            if self.on_chain_submission {
                errors.push("on_chain_submission must remain false".to_string());
            }

            if self.notes.is_empty() {
                errors.push("notes must be non-empty".to_string());
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }

        pub fn to_runtime_readiness_report(
            &self,
        ) -> Result<StarkSettlementRuntimeReadinessReport, Vec<String>> {
            self.validate()?;

            Ok(StarkSettlementRuntimeReadinessReport {
                schema_version: StarkSettlementRuntimeReadinessReport::SCHEMA_VERSION.to_string(),
                source_schema_version: self.schema_version.clone(),
                readiness_status: StarkSettlementRuntimeReadinessReport::READINESS_STATUS
                    .to_string(),
                ready_for_runtime: false,
                ready_for_contract_changes: false,
                ready_for_on_chain_submission: false,
                satisfied_gates: vec![
                    "STARK settlement implementation plan exists and validates.".to_string(),
                    "Active Groth16 runtime remains the compatibility baseline.".to_string(),
                    "Planning artifacts explicitly keep runtime_wired=false.".to_string(),
                ],
                unsatisfied_gates: vec![
                    "Production STARK verifier contract is not selected, audited, or deployed."
                        .to_string(),
                    "proofCommitment/public-input calldata format is not production-final."
                        .to_string(),
                    "ClaimsRegistry STARK adapter path is not implemented or tested.".to_string(),
                    "Verifier artifact governance and emergency controls are not active."
                        .to_string(),
                    "End-to-end Groth16 plus STARK plus Foundry regression bundle has not been approved for cutover."
                        .to_string(),
                ],
                required_evidence: vec![
                    "cargo test and cargo check in rust-engine".to_string(),
                    "cargo test, cargo check, and feature-gated Winterfell checks in stark-engine"
                        .to_string(),
                    "bash scripts/validate_stark_bridge_chain.sh".to_string(),
                    "forge test and forge build in blind-ledger".to_string(),
                    "human review of verifier artifact pinning and rollback plan".to_string(),
                ],
                next_review_actions: vec![
                    "Review interface-only Solidity fixture scope before any contract file changes."
                        .to_string(),
                    "Add mock verifier tests in a later Solidity-scoped phase.".to_string(),
                    "Keep ClaimsRegistry unchanged until mock verifier behavior is green.".to_string(),
                    "Document the exact decision point for enabling any runtime STARK path."
                        .to_string(),
                ],
                groth16_regression_required: true,
                stark_smoke_chain_required: true,
                foundry_regression_required: true,
                human_approval_required: true,
                notes: vec![
                    "This report is generated from the STARK settlement implementation plan."
                        .to_string(),
                    "It is a readiness gate, not a runtime activation artifact.".to_string(),
                    "The active Groth16 ClaimsRegistry path remains unchanged.".to_string(),
                ],
            })
        }
    }

    impl StarkSettlementRuntimeReadinessReport {
        pub const SCHEMA_VERSION: &'static str = "stark-settlement-runtime-readiness-report-v0";
        pub const SOURCE_SCHEMA_VERSION: &'static str =
            "stark-settlement-integration-implementation-plan-v0";
        pub const READINESS_STATUS: &'static str = "not_ready_runtime_cutover_blocked";

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

            if self.readiness_status != Self::READINESS_STATUS {
                errors.push(format!(
                    "readiness_status must be {}, got {}",
                    Self::READINESS_STATUS,
                    self.readiness_status
                ));
            }

            if self.ready_for_runtime {
                errors.push("ready_for_runtime must remain false".to_string());
            }

            if self.ready_for_contract_changes {
                errors.push("ready_for_contract_changes must remain false".to_string());
            }

            if self.ready_for_on_chain_submission {
                errors.push("ready_for_on_chain_submission must remain false".to_string());
            }

            if self.satisfied_gates.is_empty() {
                errors.push("satisfied_gates must be non-empty".to_string());
            }

            if self.unsatisfied_gates.is_empty() {
                errors.push("unsatisfied_gates must be non-empty".to_string());
            }

            if self.required_evidence.len() < 4 {
                errors.push("required_evidence must include regression evidence".to_string());
            }

            if self.next_review_actions.is_empty() {
                errors.push("next_review_actions must be non-empty".to_string());
            }

            if !self.groth16_regression_required {
                errors.push("groth16_regression_required must be true".to_string());
            }

            if !self.stark_smoke_chain_required {
                errors.push("stark_smoke_chain_required must be true".to_string());
            }

            if !self.foundry_regression_required {
                errors.push("foundry_regression_required must be true".to_string());
            }

            if !self.human_approval_required {
                errors.push("human_approval_required must be true".to_string());
            }

            if self.notes.is_empty() {
                errors.push("notes must be non-empty".to_string());
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }
    }

    pub fn to_poc_claim_input(
        candidate: &WinterfellCompleteWitnessCandidate,
    ) -> Result<blind_ledger_stark::ClaimInput, Vec<String>> {
        candidate.validate()?;

        Ok(blind_ledger_stark::ClaimInput {
            member_id: normalized_u32_field(candidate, "member_id")?,
            provider_npi: normalized_u32_field(candidate, "provider_npi")?,
            eligibility_active: boolean_u32_field(candidate, "eligibility_active")?,
            provider_enrolled: boolean_u32_field(candidate, "provider_enrolled")?,
            service_line_count: normalized_u32_field(candidate, "service_line_count")?,
            diagnosis_count: normalized_u32_field(candidate, "diagnosis_count")?,
            prior_auth_ok: boolean_u32_field(candidate, "prior_auth_ok")?,
            charge_cents: normalized_u32_field(candidate, "charge_cents")?,
            max_charge_cents: normalized_u32_field(candidate, "max_charge_cents")?,
            duplicate_flag: boolean_u32_field(candidate, "duplicate_flag")?,
            program_integrity_hold: boolean_u32_field(candidate, "program_integrity_hold")?,
        })
    }

    fn boolean_u32_field(
        candidate: &WinterfellCompleteWitnessCandidate,
        field_name: &str,
    ) -> Result<u32, Vec<String>> {
        let value = required_field(candidate, field_name)?.value;
        match value {
            0 | 1 => Ok(value as u32),
            _ => Err(vec![format!(
                "{field_name} must be boolean 0/1, got {value}"
            )]),
        }
    }

    fn normalized_u32_field(
        candidate: &WinterfellCompleteWitnessCandidate,
        field_name: &str,
    ) -> Result<u32, Vec<String>> {
        let value = required_field(candidate, field_name)?.value;
        if value == 0 {
            return Err(vec![format!("{field_name} must be non-zero")]);
        }

        if value <= u32::MAX as u64 {
            Ok(value as u32)
        } else {
            let folded = ((value >> 32) as u32) ^ (value as u32);
            Ok(folded.max(1))
        }
    }

    fn required_field<'a>(
        candidate: &'a WinterfellCompleteWitnessCandidate,
        field_name: &str,
    ) -> Result<&'a WinterfellCompleteWitnessField, Vec<String>> {
        candidate
            .fields
            .iter()
            .find(|field| field.winterfell_field == field_name)
            .ok_or_else(|| vec![format!("complete witness candidate missing {field_name}")])
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    }

    fn is_0x_32_byte_hex(value: &str) -> bool {
        let Some(hex) = value.strip_prefix("0x") else {
            return false;
        };

        hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn maps_complete_candidate_into_imported_winterfell_claim_input() {
            let candidate = sample_complete_candidate();
            let poc_input = to_poc_claim_input(&candidate).unwrap();

            assert_ne!(poc_input.member_id, 0);
            assert_eq!(poc_input.provider_npi, 1_999_999_987);
            assert_eq!(poc_input.eligibility_active, 1);
            assert_eq!(poc_input.provider_enrolled, 1);
            assert_eq!(poc_input.service_line_count, 1);
            assert_eq!(poc_input.diagnosis_count, 1);
            assert_eq!(poc_input.prior_auth_ok, 1);
            assert_eq!(poc_input.charge_cents, 100_000);
            assert_eq!(poc_input.max_charge_cents, 150_000);
            assert_eq!(poc_input.duplicate_flag, 0);
            assert_eq!(poc_input.program_integrity_hold, 0);
        }

        #[test]
        fn adapter_preview_evaluates_imported_poc_output_without_proving() {
            let candidate = sample_complete_candidate();
            let preview = WinterfellPocAdapterPreview::from_complete_candidate(&candidate).unwrap();

            assert_eq!(preview.validate(), Ok(()));
            assert_eq!(preview.poc_decision, 1);
            assert_eq!(preview.poc_failure_code, 0);
            assert_eq!(preview.poc_gates, [1; 10]);
            assert!(preview.winterfell_dependency_imported);
            assert!(!preview.proof_generation_enabled);
        }

        #[test]
        fn proof_preview_generates_and_verifies_feature_gated_winterfell_proof() {
            let candidate = sample_complete_candidate();
            let preview = WinterfellPocProofPreview::from_complete_candidate(&candidate).unwrap();

            assert_eq!(preview.validate(), Ok(()));
            assert_eq!(preview.decision, 1);
            assert_eq!(preview.failure_code, 0);
            assert_eq!(preview.gates, [1; 10]);
            assert!(preview.proof_size_bytes > 0);
            assert!(preview.verified);
            assert!(preview.winterfell_dependency_imported);
            assert!(preview.proof_generation_enabled);
            assert!(!preview.runtime_wired);
            assert!(!preview.on_chain_submission);
        }

        #[test]
        fn real_proof_fixture_contains_verified_winterfell_poc_proof_bytes() {
            let candidate = sample_complete_candidate();
            let fixture =
                WinterfellPocRealProofFixture::from_complete_candidate(&candidate).unwrap();

            assert_eq!(fixture.validate(), Ok(()));
            assert_eq!(fixture.claim_id, candidate.claim_id);
            assert_eq!(fixture.claim_hash, candidate.claim_hash);
            assert_eq!(fixture.decision, 1);
            assert_eq!(fixture.failure_code, 0);
            assert_eq!(fixture.gates, [1; 10]);
            assert!(fixture.proof_bytes_len > 0);
            assert!(fixture.proof_bytes_hex.starts_with("0x"));
            assert!(fixture.proof_bytes_sha256.starts_with("0x"));
            assert_eq!(fixture.local_verification_status, "verified");
            assert!(fixture.verified);
            assert!(fixture.winterfell_dependency_imported);
            assert!(fixture.proof_generation_enabled);
            assert!(!fixture.production_semantics_complete);
            assert!(!fixture.runtime_wired);
            assert!(!fixture.on_chain_submission);
            assert!(!fixture.accepted_as_runtime_evidence);
        }

        #[test]
        fn real_proof_fixture_rejects_runtime_claims() {
            let candidate = sample_complete_candidate();
            let mut fixture =
                WinterfellPocRealProofFixture::from_complete_candidate(&candidate).unwrap();
            fixture.production_semantics_complete = true;
            fixture.runtime_wired = true;
            fixture.on_chain_submission = true;
            fixture.accepted_as_runtime_evidence = true;

            let errors = fixture.validate().unwrap_err();
            assert!(
                errors
                    .iter()
                    .any(|error| error == "production_semantics_complete must remain false")
            );
            assert!(
                errors
                    .iter()
                    .any(|error| error == "runtime_wired must remain false")
            );
            assert!(
                errors
                    .iter()
                    .any(|error| error == "on_chain_submission must remain false")
            );
            assert!(
                errors
                    .iter()
                    .any(|error| error == "accepted_as_runtime_evidence must remain false")
            );
        }

        fn sample_complete_candidate() -> WinterfellCompleteWitnessCandidate {
            let field_names = [
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
            let values = [
                9_876_543_210_u64,
                1_999_999_987,
                1,
                1,
                1,
                1,
                1,
                100_000,
                150_000,
                0,
                0,
            ];

            WinterfellCompleteWitnessCandidate {
                schema_version: WinterfellCompleteWitnessCandidate::SCHEMA_VERSION.to_string(),
                source_schema_version: WinterfellCompleteWitnessCandidate::SOURCE_SCHEMA_VERSION
                    .to_string(),
                candidate_status: WinterfellCompleteWitnessCandidate::CANDIDATE_STATUS.to_string(),
                claim_id: "CLAIM-DEMO-011".to_string(),
                claim_hash: "0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607"
                    .to_string(),
                fields: field_names
                    .iter()
                    .zip(values)
                    .map(|(field_name, value)| WinterfellCompleteWitnessField {
                        winterfell_field: (*field_name).to_string(),
                        value,
                        value_status: "populated_adapter_ready_fixture".to_string(),
                        source_artifact: "unit_test".to_string(),
                        source_field: (*field_name).to_string(),
                        note: "feature-gated Winterfell PoC adapter test field".to_string(),
                    })
                    .collect(),
                field_count: 11,
                all_fields_populated: true,
                winterfell_dependency_imported: false,
                proof_generation_enabled: false,
                notes: vec![
                    "unit test complete candidate".to_string(),
                    "no proof generation".to_string(),
                ],
            }
        }
    }
}
