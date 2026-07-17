//! First-class STARK compatibility wrapper for localBCE.
//!
//! This crate is intentionally non-runtime today. The default build does not
//! import the Winterfell proof-of-concept from `blind-ledger-app-layer/zk-stark`,
//! and it is not wired into `rust-engine`.
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
                schema_version: StarkSettlementBoundaryArtifact::SCHEMA_VERSION.to_string(),
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
