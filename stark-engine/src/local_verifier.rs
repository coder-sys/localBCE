//! Inactive Phase 8 local verifier module boundary.
//!
//! This file intentionally contains no real STARK proof verifier
//! implementation and is not wired into runtime execution.

pub const TRANSFORMATION_ID: &str = "locally_verify_real_stark_proof";
pub const MODULE_PATH: &str = "stark-engine/src/local_verifier.rs";
pub const IMPLEMENTATION_STATUS: &str = "scaffold_only_not_implemented";
pub const RUNTIME_WIRING_ALLOWED: bool = false;
pub const REAL_PROOF_GENERATION_ALLOWED: bool = false;
pub const REQUIRED_EVIDENCE: [&str; 4] = [
    "local_verifier_code_path",
    "valid_real_proof_verification_test",
    "invalid_real_proof_rejection_test",
    "local_verification_log",
];
