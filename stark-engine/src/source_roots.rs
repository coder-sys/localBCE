//! Inactive Phase 8 source roots module boundary.
//!
//! This file intentionally contains no source root binding implementation and
//! is not wired into runtime execution.

pub const TRANSFORMATION_ID: &str = "bind_source_roots";
pub const MODULE_PATH: &str = "stark-engine/src/source_roots.rs";
pub const IMPLEMENTATION_STATUS: &str = "scaffold_only_not_implemented";
pub const RUNTIME_WIRING_ALLOWED: bool = false;
pub const REAL_PROOF_GENERATION_ALLOWED: bool = false;
pub const REQUIRED_EVIDENCE: [&str; 4] = [
    "source_root_binding_code_path",
    "claim_oracle_fee_nullifier_root_tests",
    "source_root_fixture",
    "source_root_validation_log",
];
