//! Typed in-memory coordinator for the native v3 authority products.
//!
//! This is the smallest complete coordination boundary that can be built from
//! the current native APIs.  Each binding method accepts only an opaque
//! verifier receipt.  The coordinator never accepts serialized digests,
//! caller-selected status flags, or an outer envelope as a substitute for a
//! receipt.  `complete_verified_v3_composite` remains the accepting library
//! authority; this module supplies the explicit state machine around it.
//!
//! The type is intentionally not an executable proof-run orchestrator.  A
//! caller still has to obtain every receipt from the corresponding native
//! verifier and must retain the raw artifact/evidence record separately.

use crate::composite_parent_public_coin::{
    CompositeParentPublicCoinError, VerifiedCompositeParentPrefix, VerifiedV3CompositeReceipt,
    complete_verified_v3_composite, complete_verified_v3_composite_after_bridge_divisibility,
};
use crate::fri_pipeline::VerifiedFriPipelineV3;
use crate::h4_proof_package_v2::VerifiedH4V2;
use crate::selected_public_coin_v3::{
    VerifiedSemanticV3Continuation, VerifiedStrictSemanticV3PublicCoin,
};
use crate::semantic_h4_bridge::VerifiedBridgeDivisibility;
use crate::typed_state_proof_package::VerifiedTypedStateV3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V3CoordinatorError {
    AlreadyCompleted,
    AlreadyBoundStrict,
    AlreadyBoundSemantic,
    AlreadyBoundContinuation,
    AlreadyBoundH4,
    AlreadyBoundTyped,
    AlreadyBoundParentPrefix,
    MissingStrict,
    MissingSemantic,
    MissingContinuation,
    MissingH4,
    MissingTyped,
    MissingParentPrefix,
    Composition(CompositeParentPublicCoinError),
}

impl From<CompositeParentPublicCoinError> for V3CoordinatorError {
    fn from(value: CompositeParentPublicCoinError) -> Self {
        Self::Composition(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V3CoordinatorPhase {
    Empty,
    NativeReceiptsBound,
    AcceptedNonactivating,
}

impl Default for V3CoordinatorPhase {
    fn default() -> Self {
        Self::Empty
    }
}

/// Explicit state machine for the native v3 composition.
#[derive(Clone, Debug, Default)]
pub struct V3NativeAuthorityCoordinator {
    strict: Option<VerifiedStrictSemanticV3PublicCoin>,
    semantic: Option<VerifiedFriPipelineV3>,
    continuation: Option<VerifiedSemanticV3Continuation>,
    h4: Option<VerifiedH4V2>,
    typed: Option<VerifiedTypedStateV3>,
    parent_prefix: Option<VerifiedCompositeParentPrefix>,
    phase: V3CoordinatorPhase,
}

impl V3NativeAuthorityCoordinator {
    pub const fn new() -> Self {
        Self {
            strict: None,
            semantic: None,
            continuation: None,
            h4: None,
            typed: None,
            parent_prefix: None,
            phase: V3CoordinatorPhase::Empty,
        }
    }

    pub const fn phase(&self) -> V3CoordinatorPhase {
        self.phase
    }

    pub fn bind_strict(
        &mut self,
        receipt: VerifiedStrictSemanticV3PublicCoin,
    ) -> Result<(), V3CoordinatorError> {
        self.ensure_not_completed()?;
        if self.strict.is_some() {
            return Err(V3CoordinatorError::AlreadyBoundStrict);
        }
        self.strict = Some(receipt);
        self.refresh_phase();
        Ok(())
    }

    pub fn bind_semantic(
        &mut self,
        receipt: VerifiedFriPipelineV3,
    ) -> Result<(), V3CoordinatorError> {
        self.ensure_not_completed()?;
        if self.semantic.is_some() {
            return Err(V3CoordinatorError::AlreadyBoundSemantic);
        }
        self.semantic = Some(receipt);
        self.refresh_phase();
        Ok(())
    }

    pub fn bind_continuation(
        &mut self,
        receipt: VerifiedSemanticV3Continuation,
    ) -> Result<(), V3CoordinatorError> {
        self.ensure_not_completed()?;
        if self.continuation.is_some() {
            return Err(V3CoordinatorError::AlreadyBoundContinuation);
        }
        self.continuation = Some(receipt);
        self.refresh_phase();
        Ok(())
    }

    pub fn bind_h4(&mut self, receipt: VerifiedH4V2) -> Result<(), V3CoordinatorError> {
        self.ensure_not_completed()?;
        if self.h4.is_some() {
            return Err(V3CoordinatorError::AlreadyBoundH4);
        }
        self.h4 = Some(receipt);
        self.refresh_phase();
        Ok(())
    }

    pub fn bind_typed(&mut self, receipt: VerifiedTypedStateV3) -> Result<(), V3CoordinatorError> {
        self.ensure_not_completed()?;
        if self.typed.is_some() {
            return Err(V3CoordinatorError::AlreadyBoundTyped);
        }
        self.typed = Some(receipt);
        self.refresh_phase();
        Ok(())
    }

    pub fn bind_parent_prefix(
        &mut self,
        receipt: VerifiedCompositeParentPrefix,
    ) -> Result<(), V3CoordinatorError> {
        self.ensure_not_completed()?;
        if self.parent_prefix.is_some() {
            return Err(V3CoordinatorError::AlreadyBoundParentPrefix);
        }
        self.parent_prefix = Some(receipt);
        self.refresh_phase();
        Ok(())
    }

    /// Complete the accepting library composition transactionally.
    ///
    /// The stored receipts remain available after a successful completion so
    /// callers can inspect the phase and independently serialize the returned
    /// evidence.  A failed composition leaves the coordinator in the bound
    /// phase and does not mark an acceptance.
    pub fn complete(&mut self) -> Result<VerifiedV3CompositeReceipt, V3CoordinatorError> {
        if self.phase == V3CoordinatorPhase::AcceptedNonactivating {
            return Err(V3CoordinatorError::AlreadyCompleted);
        }
        let (strict, semantic, continuation, h4, typed, prefix) = self.bound_receipts()?;

        let receipt =
            complete_verified_v3_composite(strict, semantic, &continuation, h4, typed, prefix)?;
        self.phase = V3CoordinatorPhase::AcceptedNonactivating;
        Ok(receipt)
    }

    /// Complete through the proof-native post-Z bridge authority when its
    /// opaque divisibility receipt is available. The receipt must come from
    /// [`crate::semantic_h4_bridge::verify_authenticated_semantic_h4_bridge`]
    /// or another verifier-owned constructor; this method never accepts raw
    /// digest pairs or a caller success flag.
    pub fn complete_after_bridge_divisibility(
        &mut self,
        divisibility: &VerifiedBridgeDivisibility,
    ) -> Result<VerifiedV3CompositeReceipt, V3CoordinatorError> {
        if self.phase == V3CoordinatorPhase::AcceptedNonactivating {
            return Err(V3CoordinatorError::AlreadyCompleted);
        }
        let (strict, semantic, continuation, h4, typed, prefix) = self.bound_receipts()?;
        let receipt = complete_verified_v3_composite_after_bridge_divisibility(
            strict,
            semantic,
            &continuation,
            h4,
            typed,
            prefix,
            divisibility,
        )?;
        self.phase = V3CoordinatorPhase::AcceptedNonactivating;
        Ok(receipt)
    }

    fn bound_receipts(
        &mut self,
    ) -> Result<
        (
            VerifiedStrictSemanticV3PublicCoin,
            VerifiedFriPipelineV3,
            VerifiedSemanticV3Continuation,
            VerifiedH4V2,
            VerifiedTypedStateV3,
            VerifiedCompositeParentPrefix,
        ),
        V3CoordinatorError,
    > {
        self.refresh_phase();
        let strict = self
            .strict
            .as_ref()
            .cloned()
            .ok_or(V3CoordinatorError::MissingStrict)?;
        let semantic = self
            .semantic
            .as_ref()
            .cloned()
            .ok_or(V3CoordinatorError::MissingSemantic)?;
        let continuation = self
            .continuation
            .as_ref()
            .cloned()
            .ok_or(V3CoordinatorError::MissingContinuation)?;
        let h4 = self
            .h4
            .as_ref()
            .cloned()
            .ok_or(V3CoordinatorError::MissingH4)?;
        let typed = self
            .typed
            .as_ref()
            .cloned()
            .ok_or(V3CoordinatorError::MissingTyped)?;
        let prefix = self
            .parent_prefix
            .as_ref()
            .cloned()
            .ok_or(V3CoordinatorError::MissingParentPrefix)?;
        Ok((strict, semantic, continuation, h4, typed, prefix))
    }

    fn ensure_not_completed(&self) -> Result<(), V3CoordinatorError> {
        if self.phase == V3CoordinatorPhase::AcceptedNonactivating {
            Err(V3CoordinatorError::AlreadyCompleted)
        } else {
            Ok(())
        }
    }

    fn refresh_phase(&mut self) {
        if self.phase == V3CoordinatorPhase::AcceptedNonactivating {
            return;
        }
        self.phase = if self.strict.is_some()
            && self.semantic.is_some()
            && self.continuation.is_some()
            && self.h4.is_some()
            && self.typed.is_some()
            && self.parent_prefix.is_some()
        {
            V3CoordinatorPhase::NativeReceiptsBound
        } else {
            V3CoordinatorPhase::Empty
        };
    }
}

/// This marks only the native in-memory coordinator. It is not an outer
/// envelope verifier, a witness-to-proof producer, or a production selector.
pub const V3_NATIVE_COORDINATOR_AVAILABLE: bool = true;
