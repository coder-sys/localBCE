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
