//! Inactive Phase 8 real prover module boundary.
//!
//! This file intentionally contains no prover implementation and is not wired
//! into runtime execution.

pub const TRANSFORMATION_ID: &str = "replace_preview_proof_bytes_with_real_proof_bytes";
pub const MODULE_PATH: &str = "stark-engine/src/real_prover.rs";
pub const IMPLEMENTATION_STATUS: &str = "scaffold_only_not_implemented";
pub const RUNTIME_WIRING_ALLOWED: bool = false;
pub const REAL_PROOF_GENERATION_ALLOWED: bool = false;
pub const REQUIRED_EVIDENCE: [&str; 4] = [
    "real_prover_code_path",
    "real_proof_bytes_fixture",
    "real_prover_unit_tests",
    "local_real_proof_validation_log",
];
