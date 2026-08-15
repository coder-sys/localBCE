//! Non-activating native v3 authority run.
//!
//! This module is the narrow orchestration seam between independently
//! verified component receipts and the accepting composition.  It deliberately
//! accepts only opaque receipts.  Serialized roots, status fields, and caller
//! booleans cannot enter this function, so a transport producer cannot be
//! mistaken for a proof producer.

use alloc::vec::Vec;

use crate::composite_parent_public_coin::{
    VerifiedCompositeParentPrefix, VerifiedV3CompositeReceipt,
};
use crate::fri_pipeline::VerifiedFriPipelineV3;
use crate::h4_proof_package_v2::VerifiedH4V2;
use crate::selected_public_coin_v3::{
    VerifiedSemanticV3Continuation, VerifiedStrictSemanticV3PublicCoin,
};
use crate::typed_state_proof_package::VerifiedTypedStateV3;
use crate::v3_authority_coordinator::{V3CoordinatorError, V3NativeAuthorityCoordinator};

#[derive(Clone, Debug)]
pub struct V3AuthorityReceipts {
    pub strict: VerifiedStrictSemanticV3PublicCoin,
    pub semantic: VerifiedFriPipelineV3,
    pub continuation: VerifiedSemanticV3Continuation,
    pub h4: VerifiedH4V2,
    pub typed: VerifiedTypedStateV3,
    pub parent_prefix: VerifiedCompositeParentPrefix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V3AuthorityRunError {
    Coordinator(V3CoordinatorError),
    Receipt(crate::composite_receipt_v3::V3CompositeReceiptV4Error),
}

impl From<V3CoordinatorError> for V3AuthorityRunError {
    fn from(value: V3CoordinatorError) -> Self {
        Self::Coordinator(value)
    }
}

impl From<crate::composite_receipt_v3::V3CompositeReceiptV4Error> for V3AuthorityRunError {
    fn from(value: crate::composite_receipt_v3::V3CompositeReceiptV4Error) -> Self {
        Self::Receipt(value)
    }
}

/// Result of a native authority run.  The receipt is accepting-library
/// evidence, while the lifecycle flags remain deliberately nonactivating for
/// this project phase.
#[derive(Clone, Debug)]
pub struct V3AuthorityRunResult {
    pub receipt: VerifiedV3CompositeReceipt,
    pub proof_suite_id: Option<[u8; 64]>,
    pub production_usable: bool,
    pub activation_allowed: bool,
}

impl V3AuthorityRunResult {
    /// Serialize the native receipt as retained evidence.  The existing
    /// decoder returns an untrusted evidence record and cannot recreate the
    /// accepting receipt.  Lifecycle claims stay explicit and nonactivating
    /// at this boundary.
    pub fn receipt_evidence(&self) -> Result<Vec<u8>, V3AuthorityRunError> {
        Ok(crate::composite_receipt_v3::encode_verified_v3_composite_receipt(&self.receipt)?)
    }
}

/// Run all native authority stages in one transaction-shaped boundary.
///
/// The input values must already have been produced by their component
/// verifiers.  This function is therefore the real coordinator seam, not a
/// witness-to-proof producer.  A failure leaves no accepting result and never
/// changes activation state.
pub fn complete_v3_authority_run(
    receipts: V3AuthorityReceipts,
) -> Result<V3AuthorityRunResult, V3AuthorityRunError> {
    let V3AuthorityReceipts {
        strict,
        semantic,
        continuation,
        h4,
        typed,
        parent_prefix,
    } = receipts;
    let mut coordinator = V3NativeAuthorityCoordinator::new();
    coordinator.bind_strict(strict)?;
    coordinator.bind_semantic(semantic)?;
    coordinator.bind_continuation(continuation)?;
    coordinator.bind_h4(h4)?;
    coordinator.bind_typed(typed)?;
    coordinator.bind_parent_prefix(parent_prefix)?;
    let receipt = coordinator.complete()?;
    Ok(V3AuthorityRunResult {
        receipt,
        proof_suite_id: None,
        production_usable: false,
        activation_allowed: false,
    })
}

/// The receipt-only coordinator exists as a native library boundary.
pub const V3_NATIVE_IN_MEMORY_AUTHORITY_RUN_AVAILABLE: bool = true;
/// The file-backed executable replays the raw witness through every native
/// component verifier before calling `complete_v3_authority_run`.
pub const V3_EXECUTABLE_AUTHORITY_RUN_AVAILABLE: bool = true;
