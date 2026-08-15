use bl_pq512_crypto_core::v3_authority_coordinator::{
    V3_NATIVE_COORDINATOR_AVAILABLE, V3CoordinatorError, V3CoordinatorPhase,
    V3NativeAuthorityCoordinator,
};

#[test]
fn coordinator_starts_empty_and_does_not_claim_acceptance() {
    let coordinator = V3NativeAuthorityCoordinator::new();
    assert_eq!(coordinator.phase(), V3CoordinatorPhase::Empty);
    assert!(V3_NATIVE_COORDINATOR_AVAILABLE);
}

#[test]
fn coordinator_requires_the_first_opaque_receipt() {
    let mut coordinator = V3NativeAuthorityCoordinator::default();
    assert!(matches!(
        coordinator.complete(),
        Err(V3CoordinatorError::MissingStrict)
    ));
    assert_eq!(coordinator.phase(), V3CoordinatorPhase::Empty);
}
