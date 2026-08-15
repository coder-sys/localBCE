use bl_pq512_crypto_core::typed_state_proof_package::{
    TYPED_STATE_PROOF_PACKAGE_BYTES, TYPED_STATE_PROOF_PACKAGE_PREFIX_BYTES,
    TypedStateProofPackageError, TypedStateProofVerificationKey,
    verify_typed_state_proof_package_v1,
};

#[test]
fn typed_state_proof_package_v1_has_one_fixed_transcript_slot() {
    assert_eq!(TYPED_STATE_PROOF_PACKAGE_PREFIX_BYTES, 1_156);
    assert_eq!(TYPED_STATE_PROOF_PACKAGE_BYTES, 83_887_236);
}

#[test]
fn typed_state_proof_package_v1_fails_closed_before_parsing_short_input() {
    let result = verify_typed_state_proof_package_v1(
        b"BLTSPK01",
        TypedStateProofVerificationKey {
            expected_profile_label: b"K512_CALIBRATION",
            expected_program_commitment: [7_u8; 64],
        },
    );
    assert_eq!(result, Err(TypedStateProofPackageError::Length));
}
