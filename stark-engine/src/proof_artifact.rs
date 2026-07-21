//! Inactive Phase 8 proof artifact emitter module boundary.
//!
//! This file intentionally contains no real `stark-proof-artifact-v1` emitter
//! and is not wired into runtime execution.

pub const TRANSFORMATION_ID: &str = "emit_stark_proof_artifact_v1";
pub const MODULE_PATH: &str = "stark-engine/src/proof_artifact.rs";
pub const IMPLEMENTATION_STATUS: &str = "scaffold_only_not_implemented";
pub const RUNTIME_WIRING_ALLOWED: bool = false;
pub const REAL_PROOF_GENERATION_ALLOWED: bool = false;
pub const REQUIRED_EVIDENCE: [&str; 4] = [
    "artifact_emitter_code_path",
    "stark_proof_artifact_v1_fixture",
    "artifact_schema_validation_tests",
    "artifact_round_trip_validation_log",
];
