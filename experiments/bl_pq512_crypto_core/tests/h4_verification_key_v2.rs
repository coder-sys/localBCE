use bl_pq512_crypto_core::binding_root_v2::{BindingDigestV2, BindingRoleV2};
use bl_pq512_crypto_core::h4_proof_package_v2::{
    H4AggregatePackageV2VerificationKey, H4ProofProfileV2, encode_h4_global_round_frame_v2,
    h4_strict_pq_schedule_v2, verify_h4_global_transcript_v2,
};
use bl_pq512_crypto_core::h4_verification_key_v2::{
    H4_VERIFICATION_KEY_V2_BYTES, decode_h4_verification_key_v2, encode_h4_verification_key_v2,
};
use bl_pq512_crypto_core::strict_h4_transcript_producer::{
    StrictH4TranscriptProducerInput, produce_strict_h4_transcript,
};
use bl_pq512_crypto_core::strict_pq_public_coin_v2::{
    STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2, StrictPqGovernedVerifierKeyV2, StrictPqKeyContextV2,
    StrictPqLamportSecretKeyV2, StrictPqRootUseRegistryV2,
};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

fn fill(value: u8) -> [u8; 64] {
    [value; 64]
}

fn deterministic_secret(lane: u8, index: usize) -> [u8; 128] {
    let mut secret = [0_u8; 128];
    for half in 0..2_u8 {
        let mut hash = Sha3_512::new();
        hash.update(b"BL/STRICT-PQ-V2/H4-VK-TEST-SECRET\0");
        hash.update([lane, half]);
        hash.update((index as u32).to_be_bytes());
        let digest: [u8; 64] = hash.finalize().into();
        let offset = usize::from(half) * 64;
        secret[offset..offset + 64].copy_from_slice(&digest);
    }
    secret
}

fn deterministic_tail(lane: u8) -> [u8; 128] {
    let mut tail = [0_u8; 128];
    for half in 0..2_u8 {
        let mut hash = Sha3_512::new();
        hash.update(b"BL/STRICT-PQ-V2/H4-VK-TEST-TAIL\0");
        hash.update([lane, half]);
        let digest: [u8; 64] = hash.finalize().into();
        let offset = usize::from(half) * 64;
        tail[offset..offset + 64].copy_from_slice(&digest);
    }
    tail
}

fn encoded_secrets(lane: u8) -> Vec<u8> {
    (0..STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2)
        .flat_map(|index| deterministic_secret(lane, index))
        .collect()
}

fn governed_key(profile: H4ProofProfileV2) -> StrictPqGovernedVerifierKeyV2 {
    let (secret_1, public_1) = StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(
        StrictPqKeyContextV2::new(
            fill(0x11),
            fill(0x22),
            9,
            7,
            fill(0x33),
            fill(0x41),
            fill(0x51),
            0,
        )
        .unwrap(),
        (0..STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2)
            .map(|index| deterministic_secret(1, index))
            .collect(),
    )
    .unwrap();
    let (secret_2, public_2) = StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(
        StrictPqKeyContextV2::new(
            fill(0x11),
            fill(0x22),
            9,
            7,
            fill(0x33),
            fill(0x42),
            fill(0x52),
            0,
        )
        .unwrap(),
        (0..STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2)
            .map(|index| deterministic_secret(2, index))
            .collect(),
    )
    .unwrap();
    drop((secret_1, secret_2));
    StrictPqGovernedVerifierKeyV2::new(
        fill(0x61),
        fill(0x62),
        profile.transcript_rounds(),
        vec![public_1, public_2],
    )
    .unwrap()
}

fn binding(value: u8) -> BindingDigestV2 {
    BindingDigestV2::hash(BindingRoleV2::Payload, &[value]).unwrap()
}

fn verification_key(profile: H4ProofProfileV2) -> H4AggregatePackageV2VerificationKey {
    let zero = BindingDigestV2::decode(&[0_u8; 128]).unwrap();
    let gkr_statement_bindings = match profile {
        H4ProofProfileV2::K128 => [binding(2), zero, zero, zero],
        H4ProofProfileV2::K512 => [binding(2), binding(3), binding(4), binding(5)],
    };
    H4AggregatePackageV2VerificationKey::new(
        profile,
        0,
        fill(0x71),
        fill(0x72),
        binding(1),
        gkr_statement_bindings,
        binding(6),
        binding(7),
        governed_key(profile),
    )
    .unwrap()
}

#[test]
fn current_h4_verification_key_round_trips_and_rejects_mutations() {
    for profile in [H4ProofProfileV2::K128, H4ProofProfileV2::K512] {
        let key = verification_key(profile);
        let encoded = encode_h4_verification_key_v2(&key);
        assert_eq!(encoded.len(), H4_VERIFICATION_KEY_V2_BYTES);
        assert_eq!(decode_h4_verification_key_v2(&encoded).unwrap(), key);

        for offset in [0, 8, 10, 12, 13, 14, 16] {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 1;
            assert!(
                decode_h4_verification_key_v2(&mutated).is_err(),
                "offset={offset}"
            );
        }
        for offset in [20, 148, 912, 1_040, encoded.len() - 1] {
            let mut mutated = encoded.clone();
            mutated[offset] ^= 1;
            assert_ne!(
                decode_h4_verification_key_v2(&mutated).unwrap(),
                key,
                "offset={offset}"
            );
        }
    }
}

#[test]
fn strict_h4_transcript_producer_replays_a_fresh_k128_schedule() {
    let profile = H4ProofProfileV2::K128;
    let key = governed_key(profile);
    let (descriptors, _) = h4_strict_pq_schedule_v2(profile).unwrap();
    let mut raw_frames = Vec::new();
    for descriptor in descriptors {
        let frame = encode_h4_global_round_frame_v2(profile, descriptor, &[b"synthetic"]).unwrap();
        raw_frames.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        raw_frames.extend_from_slice(&frame);
    }
    let key_bytes = key.encode();
    let mut secret_0 = encoded_secrets(1);
    let mut secret_1 = encoded_secrets(2);
    let mut tail_0 = deterministic_tail(1);
    let mut tail_1 = deterministic_tail(2);
    let produced = produce_strict_h4_transcript(StrictH4TranscriptProducerInput {
        profile,
        governed_key: &key_bytes,
        contributor_secret_material: [&secret_0, &secret_1],
        contributor_tails: [&tail_0, &tail_1],
        raw_frames: &raw_frames,
    })
    .unwrap();
    secret_0.zeroize();
    secret_1.zeroize();
    tail_0.zeroize();
    tail_1.zeroize();

    let mut registry = StrictPqRootUseRegistryV2::new();
    let verified = verify_h4_global_transcript_v2(
        profile,
        &key,
        &produced.encoded_bundle,
        &raw_frames,
        &mut registry,
    )
    .unwrap();
    assert_eq!(produced.round_count, profile.transcript_rounds() as usize);
    assert_eq!(verified.rounds().len(), produced.round_count);
    assert_eq!(
        verified.final_transcript_root(),
        &produced.final_transcript_root
    );
    assert_eq!(registry.reserved_root_count(), 2);
}
