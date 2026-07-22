//! Inactive Phase 8 real prover module boundary.
//!
//! This file intentionally contains no prover implementation and is not wired
//! into runtime execution.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::WinterfellCompleteWitnessCandidate;

pub const TRANSFORMATION_ID: &str = "replace_preview_proof_bytes_with_real_proof_bytes";
pub const MODULE_PATH: &str = "stark-engine/src/real_prover.rs";
pub const IMPLEMENTATION_STATUS: &str = "scaffold_only_not_implemented";
pub const RUNTIME_WIRING_ALLOWED: bool = false;
pub const REAL_PROOF_GENERATION_ALLOWED: bool = false;
pub const REAL_PROVER_ADAPTER_FEATURE_ENABLED: bool = cfg!(feature = "real-prover-adapter");
pub const REAL_PROVER_UNIT_TEST_PATH: &str = "stark-engine/tests/phase8_test_only_real_prover.rs";
pub const LOCAL_REAL_PROOF_VALIDATION_LOG_PATH: &str =
    "stark-engine/reports/local_real_proof_validation.log";
pub const REAL_PROOF_BYTES_FIXTURE_PATH: &str =
    "stark-engine/fixtures/real_proof_bytes_fixture.bin";
pub const REQUIRED_REAL_PROVER_UNIT_TESTS: [&str; 3] = [
    "real_prover_evidence_record_generates_unsatisfied_contract",
    "real_prover_attempt_artifact_is_blocked_by_missing_evidence",
    "real_prover_adapter_invocation_is_default_blocked",
];
pub const REQUIRED_EVIDENCE: [&str; 4] = [
    "real_prover_code_path",
    "real_proof_bytes_fixture",
    "real_prover_unit_tests",
    "local_real_proof_validation_log",
];

/// Test-only deterministic byte package for exercising Phase 8 adapter seams.
///
/// This is not a STARK proof, is not accepted as implementation evidence, and
/// must not be wired into settlement or runtime paths.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TestOnlyProofBytes {
    pub schema_version: String,
    pub source_schema_version: String,
    pub byte_status: String,
    pub transformation_id: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub deterministic_digest: String,
    pub bytes_hex: String,
    pub byte_length: usize,
    pub runtime_wiring_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub accepted_as_implementation_evidence: bool,
    pub notes: Vec<String>,
}

/// Test-only fixture-shaped artifact for the future real proof bytes slot.
///
/// This proves the fixture schema and digest plumbing can be exercised without
/// claiming that the bytes came from a real STARK prover.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TestOnlyRealProofBytesFixture {
    pub schema_version: String,
    pub source_schema_version: String,
    pub fixture_status: String,
    pub transformation_id: String,
    pub fixture_path: String,
    pub expected_fixture_path: String,
    pub path_matches_expected: bool,
    pub claim_id: String,
    pub claim_hash: String,
    pub proof_bytes_digest: String,
    pub proof_bytes_hex: String,
    pub proof_bytes_length: usize,
    pub proof_bytes_present: bool,
    pub local_real_proof_verified: bool,
    pub test_only_fixture: bool,
    pub accepted_as_complete_evidence: bool,
    pub implementation_satisfied: bool,
    pub runtime_wiring_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub notes: Vec<String>,
}

/// Test-only validation-log-shaped artifact for the future local proof check.
///
/// This validates the log contract that a real prover must satisfy later. It
/// does not claim local verification of a production STARK proof.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TestOnlyLocalRealProofValidationLogFixture {
    pub schema_version: String,
    pub source_schema_version: String,
    pub log_status: String,
    pub transformation_id: String,
    pub log_path: String,
    pub expected_log_path: String,
    pub path_matches_expected: bool,
    pub prover_name: String,
    pub proof_artifact_schema_version: String,
    pub proof_bytes_digest: String,
    pub local_verification_status: String,
    pub verification_timestamp: String,
    pub claim_id: String,
    pub claim_hash: String,
    pub test_only_fixture: bool,
    pub local_real_proof_verified: bool,
    pub accepted_as_complete_evidence: bool,
    pub implementation_satisfied: bool,
    pub runtime_wiring_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub notes: Vec<String>,
}

/// First real-prover implementation evidence record.
///
/// This record is intentionally unsatisfied until a later phase provides real
/// implementation artifacts. It prevents a test-only byte package from being
/// mistaken for evidence that a production STARK prover exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RealProverEvidenceRecord {
    pub schema_version: String,
    pub source_schema_version: String,
    pub evidence_status: String,
    pub transformation_id: String,
    pub planned_module: String,
    pub required_evidence: Vec<String>,
    pub real_prover_code_path: Option<String>,
    pub real_proof_bytes_fixture: Option<String>,
    pub real_prover_unit_tests: Option<String>,
    pub local_real_proof_validation_log: Option<String>,
    pub populated_evidence_count: usize,
    pub missing_evidence_count: usize,
    pub implementation_satisfied: bool,
    pub test_only_bytes_are_evidence: bool,
    pub runtime_wiring_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub accepted_as_implementation_evidence: bool,
    pub notes: Vec<String>,
}

/// Non-runtime record that a real prover attempt was considered but blocked.
///
/// This is intentionally not a proof attempt result. It exists to keep Phase 8
/// honest: until the real prover evidence record is satisfied, no real prover
/// execution is allowed and no proof bytes can be emitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RealProverAttemptArtifact {
    pub schema_version: String,
    pub source_schema_version: String,
    pub attempt_status: String,
    pub transformation_id: String,
    pub planned_module: String,
    pub blocker_status: String,
    pub missing_evidence: Vec<String>,
    pub missing_evidence_count: usize,
    pub populated_evidence_count: usize,
    pub implementation_satisfied: bool,
    pub attempted_real_proof_generation: bool,
    pub emitted_real_proof_bytes: bool,
    pub local_real_proof_verified: bool,
    pub runtime_wiring_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub accepted_as_implementation_evidence: bool,
    pub notes: Vec<String>,
}

/// Feature-gated real prover adapter invocation.
///
/// This is the first implementation source path for a real prover adapter, but
/// it is still non-runtime and non-emitting. In the default build it is blocked
/// by the disabled feature gate. If the feature is enabled before evidence is
/// satisfied, it remains blocked by the unsatisfied evidence contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RealProverAdapterInvocation {
    pub schema_version: String,
    pub source_schema_version: String,
    pub adapter_status: String,
    pub transformation_id: String,
    pub planned_module: String,
    pub feature_gate: String,
    pub feature_enabled: bool,
    pub blocker_status: String,
    pub source_attempt_status: String,
    pub implementation_satisfied: bool,
    pub attempted_real_proof_generation: bool,
    pub emitted_real_proof_bytes: bool,
    pub local_real_proof_verified: bool,
    pub runtime_wiring_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub accepted_as_implementation_evidence: bool,
    pub notes: Vec<String>,
}

/// Candidate validation for the `real_prover_code_path` evidence slot.
///
/// This validates the planned source path for the future real prover adapter,
/// but it does not satisfy the full real prover evidence contract by itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RealProverCodePathEvidence {
    pub schema_version: String,
    pub source_schema_version: String,
    pub evidence_slot: String,
    pub evidence_status: String,
    pub transformation_id: String,
    pub candidate_code_path: String,
    pub expected_code_path: String,
    pub path_matches_expected: bool,
    pub source_module_status: String,
    pub implementation_satisfied: bool,
    pub accepted_as_complete_evidence: bool,
    pub runtime_wiring_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub notes: Vec<String>,
}

/// Candidate validation for the `real_prover_unit_tests` evidence slot.
///
/// This confirms the expected focused test file and required test coverage
/// names for the guarded real prover boundary, but it still does not satisfy
/// the complete real prover evidence contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RealProverUnitTestsEvidence {
    pub schema_version: String,
    pub source_schema_version: String,
    pub evidence_slot: String,
    pub evidence_status: String,
    pub transformation_id: String,
    pub candidate_test_path: String,
    pub expected_test_path: String,
    pub path_matches_expected: bool,
    pub required_tests: Vec<String>,
    pub required_test_count: usize,
    pub coverage_status: String,
    pub implementation_satisfied: bool,
    pub accepted_as_complete_evidence: bool,
    pub runtime_wiring_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub notes: Vec<String>,
}

/// Candidate validation for the `local_real_proof_validation_log` evidence slot.
///
/// This declares the required local validation log path and expected status for
/// a future real proof verification run. It does not claim a real proof has
/// been generated or verified yet.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalRealProofValidationLogEvidence {
    pub schema_version: String,
    pub source_schema_version: String,
    pub evidence_slot: String,
    pub evidence_status: String,
    pub transformation_id: String,
    pub candidate_log_path: String,
    pub expected_log_path: String,
    pub path_matches_expected: bool,
    pub validation_log_status: String,
    pub local_real_proof_verified: bool,
    pub implementation_satisfied: bool,
    pub accepted_as_complete_evidence: bool,
    pub runtime_wiring_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub required_log_fields: Vec<String>,
    pub required_log_field_count: usize,
    pub notes: Vec<String>,
}

/// Candidate validation for the `real_proof_bytes_fixture` evidence slot.
///
/// This declares the future fixture path and required metadata for real proof
/// bytes. It explicitly rejects placeholder/test-only bytes by keeping the
/// fixture status missing and all completion flags false.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RealProofBytesFixtureEvidence {
    pub schema_version: String,
    pub source_schema_version: String,
    pub evidence_slot: String,
    pub evidence_status: String,
    pub transformation_id: String,
    pub candidate_fixture_path: String,
    pub expected_fixture_path: String,
    pub path_matches_expected: bool,
    pub fixture_status: String,
    pub proof_bytes_present: bool,
    pub proof_bytes_digest_present: bool,
    pub test_only_bytes_rejected: bool,
    pub local_real_proof_verified: bool,
    pub implementation_satisfied: bool,
    pub accepted_as_complete_evidence: bool,
    pub runtime_wiring_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub required_fixture_fields: Vec<String>,
    pub required_fixture_field_count: usize,
    pub notes: Vec<String>,
}

/// Aggregate checkpoint for all Phase 8 real-prover evidence slot candidates.
///
/// This summary is intentionally blocked today. It confirms that all four
/// evidence slots are declared, while none are complete enough to satisfy real
/// prover implementation evidence or runtime cutover.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RealProverEvidenceSummary {
    pub schema_version: String,
    pub source_schema_version: String,
    pub summary_status: String,
    pub transformation_id: String,
    pub declared_slots: Vec<String>,
    pub declared_slot_count: usize,
    pub satisfied_slots: Vec<String>,
    pub satisfied_slot_count: usize,
    pub missing_or_unsatisfied_slots: Vec<String>,
    pub missing_or_unsatisfied_slot_count: usize,
    pub blockers: Vec<String>,
    pub blocker_count: usize,
    pub all_slots_declared: bool,
    pub all_slots_satisfied: bool,
    pub implementation_satisfied: bool,
    pub runtime_cutover_allowed: bool,
    pub real_proof_generation_allowed: bool,
    pub real_proof_bytes_fixture_present: bool,
    pub local_real_proof_verified: bool,
    pub test_only_bytes_rejected: bool,
    pub notes: Vec<String>,
}

impl TestOnlyProofBytes {
    pub const SCHEMA_VERSION: &'static str = "phase8-test-only-proof-bytes-v0";
    pub const BYTE_STATUS: &'static str = "test_only_deterministic_placeholder_not_real_proof";
    pub const BYTE_LENGTH: usize = 32;

    pub fn from_complete_witness_candidate(
        candidate: &WinterfellCompleteWitnessCandidate,
    ) -> Result<Self, Vec<String>> {
        candidate.validate()?;

        let canonical_json = serde_json::to_string(candidate).map_err(|err| {
            vec![format!(
                "could not serialize complete Winterfell witness candidate: {err}"
            )]
        })?;
        let digest = Sha256::digest(canonical_json.as_bytes());
        let bytes_hex = format!("0x{}", hex_lower(&digest));

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: candidate.schema_version.clone(),
            byte_status: Self::BYTE_STATUS.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            claim_id: candidate.claim_id.clone(),
            claim_hash: candidate.claim_hash.clone(),
            deterministic_digest: bytes_hex.clone(),
            bytes_hex,
            byte_length: Self::BYTE_LENGTH,
            runtime_wiring_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            accepted_as_implementation_evidence: false,
            notes: vec![
                "These bytes are a deterministic test-only placeholder.".to_string(),
                "They are not generated by a production STARK prover.".to_string(),
                "They do not satisfy the Phase 8 implementation evidence slots.".to_string(),
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

        if self.source_schema_version != WinterfellCompleteWitnessCandidate::SCHEMA_VERSION {
            errors.push(format!(
                "source_schema_version must be {}",
                WinterfellCompleteWitnessCandidate::SCHEMA_VERSION
            ));
        }

        if self.byte_status != Self::BYTE_STATUS {
            errors.push(format!("byte_status must be {}", Self::BYTE_STATUS));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if !is_0x_32_byte_hex(&self.deterministic_digest) {
            errors
                .push("deterministic_digest must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if self.bytes_hex != self.deterministic_digest {
            errors.push("bytes_hex must match deterministic_digest".to_string());
        }

        if self.byte_length != Self::BYTE_LENGTH {
            errors.push(format!("byte_length must be {}", Self::BYTE_LENGTH));
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        if self.accepted_as_implementation_evidence {
            errors.push("accepted_as_implementation_evidence must be false".to_string());
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

impl TestOnlyRealProofBytesFixture {
    pub const SCHEMA_VERSION: &'static str = "phase8-test-only-real-proof-bytes-fixture-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = TestOnlyProofBytes::SCHEMA_VERSION;
    pub const FIXTURE_STATUS: &'static str =
        "test_only_fixture_shape_validated_not_real_proof_evidence";

    pub fn from_test_only_proof_bytes(bytes: &TestOnlyProofBytes) -> Result<Self, Vec<String>> {
        bytes.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: bytes.schema_version.clone(),
            fixture_status: Self::FIXTURE_STATUS.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            fixture_path: REAL_PROOF_BYTES_FIXTURE_PATH.to_string(),
            expected_fixture_path: REAL_PROOF_BYTES_FIXTURE_PATH.to_string(),
            path_matches_expected: true,
            claim_id: bytes.claim_id.clone(),
            claim_hash: bytes.claim_hash.clone(),
            proof_bytes_digest: bytes.deterministic_digest.clone(),
            proof_bytes_hex: bytes.bytes_hex.clone(),
            proof_bytes_length: bytes.byte_length,
            proof_bytes_present: true,
            local_real_proof_verified: false,
            test_only_fixture: true,
            accepted_as_complete_evidence: false,
            implementation_satisfied: false,
            runtime_wiring_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            notes: vec![
                "This artifact validates the future real proof bytes fixture shape.".to_string(),
                "The bytes are deterministic test-only bytes, not production STARK proof bytes."
                    .to_string(),
                "This fixture must not satisfy the real_proof_bytes_fixture evidence slot."
                    .to_string(),
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
                "source_schema_version must be {}",
                Self::SOURCE_SCHEMA_VERSION
            ));
        }

        if self.fixture_status != Self::FIXTURE_STATUS {
            errors.push(format!("fixture_status must be {}", Self::FIXTURE_STATUS));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        if self.fixture_path != REAL_PROOF_BYTES_FIXTURE_PATH {
            errors.push(format!(
                "fixture_path must be {REAL_PROOF_BYTES_FIXTURE_PATH}"
            ));
        }

        if self.expected_fixture_path != REAL_PROOF_BYTES_FIXTURE_PATH {
            errors.push(format!(
                "expected_fixture_path must be {REAL_PROOF_BYTES_FIXTURE_PATH}"
            ));
        }

        if !self.path_matches_expected {
            errors.push("path_matches_expected must be true".to_string());
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if !is_0x_32_byte_hex(&self.proof_bytes_digest) {
            errors.push("proof_bytes_digest must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if self.proof_bytes_hex != self.proof_bytes_digest {
            errors.push("proof_bytes_hex must match proof_bytes_digest".to_string());
        }

        if self.proof_bytes_length != TestOnlyProofBytes::BYTE_LENGTH {
            errors.push(format!(
                "proof_bytes_length must be {}",
                TestOnlyProofBytes::BYTE_LENGTH
            ));
        }

        if !self.proof_bytes_present {
            errors.push("proof_bytes_present must be true".to_string());
        }

        if self.local_real_proof_verified {
            errors.push("local_real_proof_verified must be false".to_string());
        }

        if !self.test_only_fixture {
            errors.push("test_only_fixture must be true".to_string());
        }

        if self.accepted_as_complete_evidence {
            errors.push("accepted_as_complete_evidence must be false".to_string());
        }

        if self.implementation_satisfied {
            errors.push("implementation_satisfied must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
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

impl TestOnlyLocalRealProofValidationLogFixture {
    pub const SCHEMA_VERSION: &'static str =
        "phase8-test-only-local-real-proof-validation-log-fixture-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = TestOnlyRealProofBytesFixture::SCHEMA_VERSION;
    pub const LOG_STATUS: &'static str =
        "test_only_validation_log_shape_validated_not_real_proof_verification";
    pub const PROVER_NAME: &'static str = "test_only_phase8_fixture_prover";
    pub const PROOF_ARTIFACT_SCHEMA_VERSION: &'static str = "stark-proof-artifact-v1";
    pub const LOCAL_VERIFICATION_STATUS: &'static str =
        "test_only_shape_validated_real_verification_not_performed";
    pub const VERIFICATION_TIMESTAMP: &'static str = "1970-01-01T00:00:00Z";

    pub fn from_test_only_fixture(
        fixture: &TestOnlyRealProofBytesFixture,
    ) -> Result<Self, Vec<String>> {
        fixture.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: fixture.schema_version.clone(),
            log_status: Self::LOG_STATUS.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            log_path: LOCAL_REAL_PROOF_VALIDATION_LOG_PATH.to_string(),
            expected_log_path: LOCAL_REAL_PROOF_VALIDATION_LOG_PATH.to_string(),
            path_matches_expected: true,
            prover_name: Self::PROVER_NAME.to_string(),
            proof_artifact_schema_version: Self::PROOF_ARTIFACT_SCHEMA_VERSION.to_string(),
            proof_bytes_digest: fixture.proof_bytes_digest.clone(),
            local_verification_status: Self::LOCAL_VERIFICATION_STATUS.to_string(),
            verification_timestamp: Self::VERIFICATION_TIMESTAMP.to_string(),
            claim_id: fixture.claim_id.clone(),
            claim_hash: fixture.claim_hash.clone(),
            test_only_fixture: true,
            local_real_proof_verified: false,
            accepted_as_complete_evidence: false,
            implementation_satisfied: false,
            runtime_wiring_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            notes: vec![
                "This artifact validates the future local real proof validation log shape."
                    .to_string(),
                "The source bytes are test-only fixture bytes, not production STARK proof bytes."
                    .to_string(),
                "No production proof was locally verified by this artifact.".to_string(),
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
                "source_schema_version must be {}",
                Self::SOURCE_SCHEMA_VERSION
            ));
        }

        if self.log_status != Self::LOG_STATUS {
            errors.push(format!("log_status must be {}", Self::LOG_STATUS));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        if self.log_path != LOCAL_REAL_PROOF_VALIDATION_LOG_PATH {
            errors.push(format!(
                "log_path must be {LOCAL_REAL_PROOF_VALIDATION_LOG_PATH}"
            ));
        }

        if self.expected_log_path != LOCAL_REAL_PROOF_VALIDATION_LOG_PATH {
            errors.push(format!(
                "expected_log_path must be {LOCAL_REAL_PROOF_VALIDATION_LOG_PATH}"
            ));
        }

        if !self.path_matches_expected {
            errors.push("path_matches_expected must be true".to_string());
        }

        if self.prover_name != Self::PROVER_NAME {
            errors.push(format!("prover_name must be {}", Self::PROVER_NAME));
        }

        if self.proof_artifact_schema_version != Self::PROOF_ARTIFACT_SCHEMA_VERSION {
            errors.push(format!(
                "proof_artifact_schema_version must be {}",
                Self::PROOF_ARTIFACT_SCHEMA_VERSION
            ));
        }

        if !is_0x_32_byte_hex(&self.proof_bytes_digest) {
            errors.push("proof_bytes_digest must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if self.local_verification_status != Self::LOCAL_VERIFICATION_STATUS {
            errors.push(format!(
                "local_verification_status must be {}",
                Self::LOCAL_VERIFICATION_STATUS
            ));
        }

        if self.verification_timestamp != Self::VERIFICATION_TIMESTAMP {
            errors.push(format!(
                "verification_timestamp must be {}",
                Self::VERIFICATION_TIMESTAMP
            ));
        }

        if self.claim_id.trim().is_empty() {
            errors.push("claim_id must be present".to_string());
        }

        if !is_0x_32_byte_hex(&self.claim_hash) {
            errors.push("claim_hash must be a 0x-prefixed 32-byte hex string".to_string());
        }

        if !self.test_only_fixture {
            errors.push("test_only_fixture must be true".to_string());
        }

        if self.local_real_proof_verified {
            errors.push("local_real_proof_verified must be false".to_string());
        }

        if self.accepted_as_complete_evidence {
            errors.push("accepted_as_complete_evidence must be false".to_string());
        }

        if self.implementation_satisfied {
            errors.push("implementation_satisfied must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
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

impl RealProverEvidenceRecord {
    pub const SCHEMA_VERSION: &'static str = "phase8-real-prover-evidence-record-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = TestOnlyProofBytes::SCHEMA_VERSION;
    pub const EVIDENCE_STATUS: &'static str = "real_prover_evidence_missing";

    pub fn from_test_only_proof_bytes(bytes: &TestOnlyProofBytes) -> Result<Self, Vec<String>> {
        bytes.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: bytes.schema_version.clone(),
            evidence_status: Self::EVIDENCE_STATUS.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            planned_module: MODULE_PATH.to_string(),
            required_evidence: REQUIRED_EVIDENCE
                .iter()
                .map(|evidence| (*evidence).to_string())
                .collect(),
            real_prover_code_path: None,
            real_proof_bytes_fixture: None,
            real_prover_unit_tests: None,
            local_real_proof_validation_log: None,
            populated_evidence_count: 0,
            missing_evidence_count: REQUIRED_EVIDENCE.len(),
            implementation_satisfied: false,
            test_only_bytes_are_evidence: false,
            runtime_wiring_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            accepted_as_implementation_evidence: false,
            notes: vec![
                "This evidence record is an empty real-prover evidence contract.".to_string(),
                "Test-only proof bytes are not accepted as implementation evidence.".to_string(),
                "Real prover code, fixture bytes, tests, and local validation logs are still missing."
                    .to_string(),
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
                "source_schema_version must be {}",
                Self::SOURCE_SCHEMA_VERSION
            ));
        }

        if self.evidence_status != Self::EVIDENCE_STATUS {
            errors.push(format!("evidence_status must be {}", Self::EVIDENCE_STATUS));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        if self.planned_module != MODULE_PATH {
            errors.push(format!("planned_module must be {MODULE_PATH}"));
        }

        let expected_evidence = REQUIRED_EVIDENCE.to_vec();
        let actual_evidence = self
            .required_evidence
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if actual_evidence != expected_evidence {
            errors
                .push("required_evidence must match the real prover evidence contract".to_string());
        }

        for (field_name, value) in [
            ("real_prover_code_path", &self.real_prover_code_path),
            ("real_proof_bytes_fixture", &self.real_proof_bytes_fixture),
            ("real_prover_unit_tests", &self.real_prover_unit_tests),
            (
                "local_real_proof_validation_log",
                &self.local_real_proof_validation_log,
            ),
        ] {
            if value.is_some() {
                errors.push(format!(
                    "{field_name} must be empty until real evidence exists"
                ));
            }
        }

        if self.populated_evidence_count != 0 {
            errors.push("populated_evidence_count must be 0".to_string());
        }

        if self.missing_evidence_count != REQUIRED_EVIDENCE.len() {
            errors.push(format!(
                "missing_evidence_count must be {}",
                REQUIRED_EVIDENCE.len()
            ));
        }

        if self.implementation_satisfied {
            errors.push("implementation_satisfied must be false".to_string());
        }

        if self.test_only_bytes_are_evidence {
            errors.push("test_only_bytes_are_evidence must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        if self.accepted_as_implementation_evidence {
            errors.push("accepted_as_implementation_evidence must be false".to_string());
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

impl RealProverAttemptArtifact {
    pub const SCHEMA_VERSION: &'static str = "phase8-real-prover-attempt-artifact-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = RealProverEvidenceRecord::SCHEMA_VERSION;
    pub const ATTEMPT_STATUS: &'static str = "blocked_missing_real_prover_evidence_no_attempt_made";
    pub const BLOCKER_STATUS: &'static str = "real_prover_evidence_record_unsatisfied";

    pub fn blocked_from_evidence_record(
        record: &RealProverEvidenceRecord,
    ) -> Result<Self, Vec<String>> {
        record.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: record.schema_version.clone(),
            attempt_status: Self::ATTEMPT_STATUS.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            planned_module: MODULE_PATH.to_string(),
            blocker_status: Self::BLOCKER_STATUS.to_string(),
            missing_evidence: record.required_evidence.clone(),
            missing_evidence_count: record.missing_evidence_count,
            populated_evidence_count: record.populated_evidence_count,
            implementation_satisfied: record.implementation_satisfied,
            attempted_real_proof_generation: false,
            emitted_real_proof_bytes: false,
            local_real_proof_verified: false,
            runtime_wiring_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            accepted_as_implementation_evidence: false,
            notes: vec![
                "Real prover execution is blocked because implementation evidence is missing."
                    .to_string(),
                "This artifact records a blocked non-runtime attempt boundary, not a proof."
                    .to_string(),
                "No real proof bytes were generated or emitted.".to_string(),
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
                "source_schema_version must be {}",
                Self::SOURCE_SCHEMA_VERSION
            ));
        }

        if self.attempt_status != Self::ATTEMPT_STATUS {
            errors.push(format!("attempt_status must be {}", Self::ATTEMPT_STATUS));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        if self.planned_module != MODULE_PATH {
            errors.push(format!("planned_module must be {MODULE_PATH}"));
        }

        if self.blocker_status != Self::BLOCKER_STATUS {
            errors.push(format!("blocker_status must be {}", Self::BLOCKER_STATUS));
        }

        let expected_evidence = REQUIRED_EVIDENCE.to_vec();
        let actual_evidence = self
            .missing_evidence
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if actual_evidence != expected_evidence {
            errors
                .push("missing_evidence must match the real prover evidence contract".to_string());
        }

        if self.missing_evidence_count != REQUIRED_EVIDENCE.len() {
            errors.push(format!(
                "missing_evidence_count must be {}",
                REQUIRED_EVIDENCE.len()
            ));
        }

        if self.populated_evidence_count != 0 {
            errors.push("populated_evidence_count must be 0".to_string());
        }

        if self.implementation_satisfied {
            errors.push("implementation_satisfied must be false".to_string());
        }

        if self.attempted_real_proof_generation {
            errors.push("attempted_real_proof_generation must be false".to_string());
        }

        if self.emitted_real_proof_bytes {
            errors.push("emitted_real_proof_bytes must be false".to_string());
        }

        if self.local_real_proof_verified {
            errors.push("local_real_proof_verified must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        if self.accepted_as_implementation_evidence {
            errors.push("accepted_as_implementation_evidence must be false".to_string());
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

impl RealProverAdapterInvocation {
    pub const SCHEMA_VERSION: &'static str = "phase8-real-prover-adapter-invocation-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = RealProverAttemptArtifact::SCHEMA_VERSION;
    pub const FEATURE_GATE: &'static str = "real-prover-adapter";
    pub const ADAPTER_STATUS_FEATURE_DISABLED: &'static str =
        "blocked_real_prover_adapter_feature_disabled";
    pub const ADAPTER_STATUS_EVIDENCE_MISSING: &'static str =
        "blocked_real_prover_evidence_missing";

    pub fn from_attempt_artifact(
        artifact: &RealProverAttemptArtifact,
    ) -> Result<Self, Vec<String>> {
        artifact.validate()?;

        let adapter_status = if REAL_PROVER_ADAPTER_FEATURE_ENABLED {
            Self::ADAPTER_STATUS_EVIDENCE_MISSING
        } else {
            Self::ADAPTER_STATUS_FEATURE_DISABLED
        };

        let blocker_status = if REAL_PROVER_ADAPTER_FEATURE_ENABLED {
            RealProverAttemptArtifact::BLOCKER_STATUS
        } else {
            "real_prover_adapter_feature_disabled"
        };

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: artifact.schema_version.clone(),
            adapter_status: adapter_status.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            planned_module: MODULE_PATH.to_string(),
            feature_gate: Self::FEATURE_GATE.to_string(),
            feature_enabled: REAL_PROVER_ADAPTER_FEATURE_ENABLED,
            blocker_status: blocker_status.to_string(),
            source_attempt_status: artifact.attempt_status.clone(),
            implementation_satisfied: artifact.implementation_satisfied,
            attempted_real_proof_generation: false,
            emitted_real_proof_bytes: false,
            local_real_proof_verified: false,
            runtime_wiring_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            accepted_as_implementation_evidence: false,
            notes: vec![
                "Real prover adapter invocation is a non-runtime guarded source path.".to_string(),
                "The adapter refuses to emit proof bytes while feature or evidence gates are blocked."
                    .to_string(),
                "No production STARK proof was generated.".to_string(),
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
                "source_schema_version must be {}",
                Self::SOURCE_SCHEMA_VERSION
            ));
        }

        let expected_status = if self.feature_enabled {
            Self::ADAPTER_STATUS_EVIDENCE_MISSING
        } else {
            Self::ADAPTER_STATUS_FEATURE_DISABLED
        };
        if self.adapter_status != expected_status {
            errors.push(format!("adapter_status must be {expected_status}"));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        if self.planned_module != MODULE_PATH {
            errors.push(format!("planned_module must be {MODULE_PATH}"));
        }

        if self.feature_gate != Self::FEATURE_GATE {
            errors.push(format!("feature_gate must be {}", Self::FEATURE_GATE));
        }

        if self.feature_enabled != REAL_PROVER_ADAPTER_FEATURE_ENABLED {
            errors.push(format!(
                "feature_enabled must match compiled feature state {}",
                REAL_PROVER_ADAPTER_FEATURE_ENABLED
            ));
        }

        let expected_blocker = if self.feature_enabled {
            RealProverAttemptArtifact::BLOCKER_STATUS
        } else {
            "real_prover_adapter_feature_disabled"
        };
        if self.blocker_status != expected_blocker {
            errors.push(format!("blocker_status must be {expected_blocker}"));
        }

        if self.source_attempt_status != RealProverAttemptArtifact::ATTEMPT_STATUS {
            errors.push(format!(
                "source_attempt_status must be {}",
                RealProverAttemptArtifact::ATTEMPT_STATUS
            ));
        }

        if self.implementation_satisfied {
            errors.push("implementation_satisfied must be false".to_string());
        }

        if self.attempted_real_proof_generation {
            errors.push("attempted_real_proof_generation must be false".to_string());
        }

        if self.emitted_real_proof_bytes {
            errors.push("emitted_real_proof_bytes must be false".to_string());
        }

        if self.local_real_proof_verified {
            errors.push("local_real_proof_verified must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        if self.accepted_as_implementation_evidence {
            errors.push("accepted_as_implementation_evidence must be false".to_string());
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

impl RealProverCodePathEvidence {
    pub const SCHEMA_VERSION: &'static str = "phase8-real-prover-code-path-evidence-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = RealProverAdapterInvocation::SCHEMA_VERSION;
    pub const EVIDENCE_SLOT: &'static str = "real_prover_code_path";
    pub const EVIDENCE_STATUS: &'static str = "code_path_candidate_validated_not_sufficient";

    pub fn from_adapter_invocation(
        invocation: &RealProverAdapterInvocation,
    ) -> Result<Self, Vec<String>> {
        invocation.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: invocation.schema_version.clone(),
            evidence_slot: Self::EVIDENCE_SLOT.to_string(),
            evidence_status: Self::EVIDENCE_STATUS.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            candidate_code_path: MODULE_PATH.to_string(),
            expected_code_path: MODULE_PATH.to_string(),
            path_matches_expected: true,
            source_module_status: IMPLEMENTATION_STATUS.to_string(),
            implementation_satisfied: false,
            accepted_as_complete_evidence: false,
            runtime_wiring_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            notes: vec![
                "The real prover code path points at the intended source module.".to_string(),
                "This validates only one evidence slot candidate.".to_string(),
                "The module remains scaffold-only and does not generate real proof bytes."
                    .to_string(),
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
                "source_schema_version must be {}",
                Self::SOURCE_SCHEMA_VERSION
            ));
        }

        if self.evidence_slot != Self::EVIDENCE_SLOT {
            errors.push(format!("evidence_slot must be {}", Self::EVIDENCE_SLOT));
        }

        if self.evidence_status != Self::EVIDENCE_STATUS {
            errors.push(format!("evidence_status must be {}", Self::EVIDENCE_STATUS));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        if self.candidate_code_path != MODULE_PATH {
            errors.push(format!("candidate_code_path must be {MODULE_PATH}"));
        }

        if self.expected_code_path != MODULE_PATH {
            errors.push(format!("expected_code_path must be {MODULE_PATH}"));
        }

        if !self.path_matches_expected {
            errors.push("path_matches_expected must be true".to_string());
        }

        if self.source_module_status != IMPLEMENTATION_STATUS {
            errors.push(format!(
                "source_module_status must be {IMPLEMENTATION_STATUS}"
            ));
        }

        if self.implementation_satisfied {
            errors.push("implementation_satisfied must be false".to_string());
        }

        if self.accepted_as_complete_evidence {
            errors.push("accepted_as_complete_evidence must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
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

impl RealProverUnitTestsEvidence {
    pub const SCHEMA_VERSION: &'static str = "phase8-real-prover-unit-tests-evidence-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = RealProverCodePathEvidence::SCHEMA_VERSION;
    pub const EVIDENCE_SLOT: &'static str = "real_prover_unit_tests";
    pub const EVIDENCE_STATUS: &'static str = "unit_tests_candidate_validated_not_sufficient";
    pub const COVERAGE_STATUS: &'static str = "focused_boundary_tests_declared";

    pub fn from_code_path_evidence(
        evidence: &RealProverCodePathEvidence,
    ) -> Result<Self, Vec<String>> {
        evidence.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: evidence.schema_version.clone(),
            evidence_slot: Self::EVIDENCE_SLOT.to_string(),
            evidence_status: Self::EVIDENCE_STATUS.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            candidate_test_path: REAL_PROVER_UNIT_TEST_PATH.to_string(),
            expected_test_path: REAL_PROVER_UNIT_TEST_PATH.to_string(),
            path_matches_expected: true,
            required_tests: REQUIRED_REAL_PROVER_UNIT_TESTS
                .iter()
                .map(|test| (*test).to_string())
                .collect(),
            required_test_count: REQUIRED_REAL_PROVER_UNIT_TESTS.len(),
            coverage_status: Self::COVERAGE_STATUS.to_string(),
            implementation_satisfied: false,
            accepted_as_complete_evidence: false,
            runtime_wiring_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            notes: vec![
                "The focused Phase 8 test file is the declared unit-test evidence candidate."
                    .to_string(),
                "These tests cover blocked real prover evidence, attempt, and adapter boundaries."
                    .to_string(),
                "This validates only one evidence slot candidate.".to_string(),
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
                "source_schema_version must be {}",
                Self::SOURCE_SCHEMA_VERSION
            ));
        }

        if self.evidence_slot != Self::EVIDENCE_SLOT {
            errors.push(format!("evidence_slot must be {}", Self::EVIDENCE_SLOT));
        }

        if self.evidence_status != Self::EVIDENCE_STATUS {
            errors.push(format!("evidence_status must be {}", Self::EVIDENCE_STATUS));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        if self.candidate_test_path != REAL_PROVER_UNIT_TEST_PATH {
            errors.push(format!(
                "candidate_test_path must be {REAL_PROVER_UNIT_TEST_PATH}"
            ));
        }

        if self.expected_test_path != REAL_PROVER_UNIT_TEST_PATH {
            errors.push(format!(
                "expected_test_path must be {REAL_PROVER_UNIT_TEST_PATH}"
            ));
        }

        if !self.path_matches_expected {
            errors.push("path_matches_expected must be true".to_string());
        }

        let expected_tests = REQUIRED_REAL_PROVER_UNIT_TESTS.to_vec();
        let actual_tests = self
            .required_tests
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if actual_tests != expected_tests {
            errors.push(
                "required_tests must match the real prover boundary test contract".to_string(),
            );
        }

        if self.required_test_count != REQUIRED_REAL_PROVER_UNIT_TESTS.len() {
            errors.push(format!(
                "required_test_count must be {}",
                REQUIRED_REAL_PROVER_UNIT_TESTS.len()
            ));
        }

        if self.coverage_status != Self::COVERAGE_STATUS {
            errors.push(format!("coverage_status must be {}", Self::COVERAGE_STATUS));
        }

        if self.implementation_satisfied {
            errors.push("implementation_satisfied must be false".to_string());
        }

        if self.accepted_as_complete_evidence {
            errors.push("accepted_as_complete_evidence must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
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

impl LocalRealProofValidationLogEvidence {
    pub const SCHEMA_VERSION: &'static str = "phase8-local-real-proof-validation-log-evidence-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = RealProverUnitTestsEvidence::SCHEMA_VERSION;
    pub const EVIDENCE_SLOT: &'static str = "local_real_proof_validation_log";
    pub const EVIDENCE_STATUS: &'static str = "validation_log_path_declared_not_verified";
    pub const VALIDATION_LOG_STATUS: &'static str = "real_proof_validation_log_missing";
    pub const REQUIRED_LOG_FIELDS: [&'static str; 5] = [
        "prover_name",
        "proof_artifact_schema_version",
        "proof_bytes_digest",
        "local_verification_status",
        "verification_timestamp",
    ];

    pub fn from_unit_tests_evidence(
        evidence: &RealProverUnitTestsEvidence,
    ) -> Result<Self, Vec<String>> {
        evidence.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: evidence.schema_version.clone(),
            evidence_slot: Self::EVIDENCE_SLOT.to_string(),
            evidence_status: Self::EVIDENCE_STATUS.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            candidate_log_path: LOCAL_REAL_PROOF_VALIDATION_LOG_PATH.to_string(),
            expected_log_path: LOCAL_REAL_PROOF_VALIDATION_LOG_PATH.to_string(),
            path_matches_expected: true,
            validation_log_status: Self::VALIDATION_LOG_STATUS.to_string(),
            local_real_proof_verified: false,
            implementation_satisfied: false,
            accepted_as_complete_evidence: false,
            runtime_wiring_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            required_log_fields: Self::REQUIRED_LOG_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            required_log_field_count: Self::REQUIRED_LOG_FIELDS.len(),
            notes: vec![
                "The local real proof validation log path is declared for future evidence."
                    .to_string(),
                "No local real proof validation log exists in this artifact.".to_string(),
                "This validates only one evidence slot candidate.".to_string(),
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
                "source_schema_version must be {}",
                Self::SOURCE_SCHEMA_VERSION
            ));
        }

        if self.evidence_slot != Self::EVIDENCE_SLOT {
            errors.push(format!("evidence_slot must be {}", Self::EVIDENCE_SLOT));
        }

        if self.evidence_status != Self::EVIDENCE_STATUS {
            errors.push(format!("evidence_status must be {}", Self::EVIDENCE_STATUS));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        if self.candidate_log_path != LOCAL_REAL_PROOF_VALIDATION_LOG_PATH {
            errors.push(format!(
                "candidate_log_path must be {LOCAL_REAL_PROOF_VALIDATION_LOG_PATH}"
            ));
        }

        if self.expected_log_path != LOCAL_REAL_PROOF_VALIDATION_LOG_PATH {
            errors.push(format!(
                "expected_log_path must be {LOCAL_REAL_PROOF_VALIDATION_LOG_PATH}"
            ));
        }

        if !self.path_matches_expected {
            errors.push("path_matches_expected must be true".to_string());
        }

        if self.validation_log_status != Self::VALIDATION_LOG_STATUS {
            errors.push(format!(
                "validation_log_status must be {}",
                Self::VALIDATION_LOG_STATUS
            ));
        }

        if self.local_real_proof_verified {
            errors.push("local_real_proof_verified must be false".to_string());
        }

        if self.implementation_satisfied {
            errors.push("implementation_satisfied must be false".to_string());
        }

        if self.accepted_as_complete_evidence {
            errors.push("accepted_as_complete_evidence must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        let expected_fields = Self::REQUIRED_LOG_FIELDS.to_vec();
        let actual_fields = self
            .required_log_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if actual_fields != expected_fields {
            errors.push(
                "required_log_fields must match the local real proof validation log contract"
                    .to_string(),
            );
        }

        if self.required_log_field_count != Self::REQUIRED_LOG_FIELDS.len() {
            errors.push(format!(
                "required_log_field_count must be {}",
                Self::REQUIRED_LOG_FIELDS.len()
            ));
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

impl RealProofBytesFixtureEvidence {
    pub const SCHEMA_VERSION: &'static str = "phase8-real-proof-bytes-fixture-evidence-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str =
        LocalRealProofValidationLogEvidence::SCHEMA_VERSION;
    pub const EVIDENCE_SLOT: &'static str = "real_proof_bytes_fixture";
    pub const EVIDENCE_STATUS: &'static str = "real_proof_bytes_fixture_declared_missing";
    pub const FIXTURE_STATUS: &'static str = "real_proof_bytes_fixture_missing";
    pub const REQUIRED_FIXTURE_FIELDS: [&'static str; 5] = [
        "fixture_path",
        "proof_artifact_schema_version",
        "proof_bytes_digest",
        "prover_name",
        "local_verification_log_path",
    ];

    pub fn from_validation_log_evidence(
        evidence: &LocalRealProofValidationLogEvidence,
    ) -> Result<Self, Vec<String>> {
        evidence.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: evidence.schema_version.clone(),
            evidence_slot: Self::EVIDENCE_SLOT.to_string(),
            evidence_status: Self::EVIDENCE_STATUS.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            candidate_fixture_path: REAL_PROOF_BYTES_FIXTURE_PATH.to_string(),
            expected_fixture_path: REAL_PROOF_BYTES_FIXTURE_PATH.to_string(),
            path_matches_expected: true,
            fixture_status: Self::FIXTURE_STATUS.to_string(),
            proof_bytes_present: false,
            proof_bytes_digest_present: false,
            test_only_bytes_rejected: true,
            local_real_proof_verified: false,
            implementation_satisfied: false,
            accepted_as_complete_evidence: false,
            runtime_wiring_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            required_fixture_fields: Self::REQUIRED_FIXTURE_FIELDS
                .iter()
                .map(|field| (*field).to_string())
                .collect(),
            required_fixture_field_count: Self::REQUIRED_FIXTURE_FIELDS.len(),
            notes: vec![
                "The real proof bytes fixture path is declared for future evidence.".to_string(),
                "No real proof bytes fixture exists in this artifact.".to_string(),
                "Test-only placeholder bytes are explicitly rejected as real fixture evidence."
                    .to_string(),
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
                "source_schema_version must be {}",
                Self::SOURCE_SCHEMA_VERSION
            ));
        }

        if self.evidence_slot != Self::EVIDENCE_SLOT {
            errors.push(format!("evidence_slot must be {}", Self::EVIDENCE_SLOT));
        }

        if self.evidence_status != Self::EVIDENCE_STATUS {
            errors.push(format!("evidence_status must be {}", Self::EVIDENCE_STATUS));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        if self.candidate_fixture_path != REAL_PROOF_BYTES_FIXTURE_PATH {
            errors.push(format!(
                "candidate_fixture_path must be {REAL_PROOF_BYTES_FIXTURE_PATH}"
            ));
        }

        if self.expected_fixture_path != REAL_PROOF_BYTES_FIXTURE_PATH {
            errors.push(format!(
                "expected_fixture_path must be {REAL_PROOF_BYTES_FIXTURE_PATH}"
            ));
        }

        if !self.path_matches_expected {
            errors.push("path_matches_expected must be true".to_string());
        }

        if self.fixture_status != Self::FIXTURE_STATUS {
            errors.push(format!("fixture_status must be {}", Self::FIXTURE_STATUS));
        }

        if self.proof_bytes_present {
            errors.push("proof_bytes_present must be false".to_string());
        }

        if self.proof_bytes_digest_present {
            errors.push("proof_bytes_digest_present must be false".to_string());
        }

        if !self.test_only_bytes_rejected {
            errors.push("test_only_bytes_rejected must be true".to_string());
        }

        if self.local_real_proof_verified {
            errors.push("local_real_proof_verified must be false".to_string());
        }

        if self.implementation_satisfied {
            errors.push("implementation_satisfied must be false".to_string());
        }

        if self.accepted_as_complete_evidence {
            errors.push("accepted_as_complete_evidence must be false".to_string());
        }

        if self.runtime_wiring_allowed {
            errors.push("runtime_wiring_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        let expected_fields = Self::REQUIRED_FIXTURE_FIELDS.to_vec();
        let actual_fields = self
            .required_fixture_fields
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if actual_fields != expected_fields {
            errors.push(
                "required_fixture_fields must match the real proof bytes fixture contract"
                    .to_string(),
            );
        }

        if self.required_fixture_field_count != Self::REQUIRED_FIXTURE_FIELDS.len() {
            errors.push(format!(
                "required_fixture_field_count must be {}",
                Self::REQUIRED_FIXTURE_FIELDS.len()
            ));
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

impl RealProverEvidenceSummary {
    pub const SCHEMA_VERSION: &'static str = "phase8-real-prover-evidence-summary-v0";
    pub const SOURCE_SCHEMA_VERSION: &'static str = "phase8-real-prover-evidence-slots-v0";
    pub const SUMMARY_STATUS: &'static str =
        "all_slots_declared_zero_slots_satisfied_runtime_blocked";
    pub const BLOCKERS: [&'static str; 4] = [
        "real_proof_bytes_fixture_missing",
        "local_real_proof_validation_log_missing",
        "real_prover_implementation_not_satisfied",
        "runtime_cutover_blocked",
    ];

    pub fn from_evidence_slots(
        code_path: &RealProverCodePathEvidence,
        unit_tests: &RealProverUnitTestsEvidence,
        validation_log: &LocalRealProofValidationLogEvidence,
        proof_fixture: &RealProofBytesFixtureEvidence,
    ) -> Result<Self, Vec<String>> {
        code_path.validate()?;
        unit_tests.validate()?;
        validation_log.validate()?;
        proof_fixture.validate()?;

        Ok(Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: Self::SOURCE_SCHEMA_VERSION.to_string(),
            summary_status: Self::SUMMARY_STATUS.to_string(),
            transformation_id: TRANSFORMATION_ID.to_string(),
            declared_slots: REQUIRED_EVIDENCE
                .iter()
                .map(|slot| (*slot).to_string())
                .collect(),
            declared_slot_count: REQUIRED_EVIDENCE.len(),
            satisfied_slots: Vec::new(),
            satisfied_slot_count: 0,
            missing_or_unsatisfied_slots: REQUIRED_EVIDENCE
                .iter()
                .map(|slot| (*slot).to_string())
                .collect(),
            missing_or_unsatisfied_slot_count: REQUIRED_EVIDENCE.len(),
            blockers: Self::BLOCKERS
                .iter()
                .map(|blocker| (*blocker).to_string())
                .collect(),
            blocker_count: Self::BLOCKERS.len(),
            all_slots_declared: true,
            all_slots_satisfied: false,
            implementation_satisfied: false,
            runtime_cutover_allowed: RUNTIME_WIRING_ALLOWED,
            real_proof_generation_allowed: REAL_PROOF_GENERATION_ALLOWED,
            real_proof_bytes_fixture_present: proof_fixture.proof_bytes_present,
            local_real_proof_verified: validation_log.local_real_proof_verified,
            test_only_bytes_rejected: proof_fixture.test_only_bytes_rejected,
            notes: vec![
                "All four real prover evidence slots are declared.".to_string(),
                "No evidence slot is satisfied by real prover implementation evidence yet."
                    .to_string(),
                "Real proof bytes and local real proof validation are still missing.".to_string(),
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
                "source_schema_version must be {}",
                Self::SOURCE_SCHEMA_VERSION
            ));
        }

        if self.summary_status != Self::SUMMARY_STATUS {
            errors.push(format!("summary_status must be {}", Self::SUMMARY_STATUS));
        }

        if self.transformation_id != TRANSFORMATION_ID {
            errors.push(format!("transformation_id must be {TRANSFORMATION_ID}"));
        }

        let expected_slots = REQUIRED_EVIDENCE.to_vec();
        let declared_slots = self
            .declared_slots
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if declared_slots != expected_slots {
            errors.push("declared_slots must match the real prover evidence contract".to_string());
        }

        if self.declared_slot_count != REQUIRED_EVIDENCE.len() {
            errors.push(format!(
                "declared_slot_count must be {}",
                REQUIRED_EVIDENCE.len()
            ));
        }

        if !self.satisfied_slots.is_empty() {
            errors.push("satisfied_slots must be empty".to_string());
        }

        if self.satisfied_slot_count != 0 {
            errors.push("satisfied_slot_count must be 0".to_string());
        }

        let unsatisfied_slots = self
            .missing_or_unsatisfied_slots
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if unsatisfied_slots != expected_slots {
            errors.push(
                "missing_or_unsatisfied_slots must match the real prover evidence contract"
                    .to_string(),
            );
        }

        if self.missing_or_unsatisfied_slot_count != REQUIRED_EVIDENCE.len() {
            errors.push(format!(
                "missing_or_unsatisfied_slot_count must be {}",
                REQUIRED_EVIDENCE.len()
            ));
        }

        let expected_blockers = Self::BLOCKERS.to_vec();
        let actual_blockers = self.blockers.iter().map(String::as_str).collect::<Vec<_>>();
        if actual_blockers != expected_blockers {
            errors.push("blockers must match the Phase 8 evidence summary contract".to_string());
        }

        if self.blocker_count != Self::BLOCKERS.len() {
            errors.push(format!("blocker_count must be {}", Self::BLOCKERS.len()));
        }

        if !self.all_slots_declared {
            errors.push("all_slots_declared must be true".to_string());
        }

        if self.all_slots_satisfied {
            errors.push("all_slots_satisfied must be false".to_string());
        }

        if self.implementation_satisfied {
            errors.push("implementation_satisfied must be false".to_string());
        }

        if self.runtime_cutover_allowed {
            errors.push("runtime_cutover_allowed must be false".to_string());
        }

        if self.real_proof_generation_allowed {
            errors.push("real_proof_generation_allowed must be false".to_string());
        }

        if self.real_proof_bytes_fixture_present {
            errors.push("real_proof_bytes_fixture_present must be false".to_string());
        }

        if self.local_real_proof_verified {
            errors.push("local_real_proof_verified must be false".to_string());
        }

        if !self.test_only_bytes_rejected {
            errors.push("test_only_bytes_rejected must be true".to_string());
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
