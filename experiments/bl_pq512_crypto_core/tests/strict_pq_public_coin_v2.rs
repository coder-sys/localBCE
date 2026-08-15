extern crate alloc;

#[allow(dead_code)]
#[path = "../src/binding_root_v2.rs"]
mod binding_root_v2;
#[allow(dead_code)]
#[path = "../src/field.rs"]
mod field;
#[allow(dead_code)]
#[path = "../src/sampler.rs"]
mod sampler;
#[allow(dead_code)]
#[path = "../src/strict_pq_public_coin_v2.rs"]
mod strict_pq_public_coin_v2;

use std::collections::BTreeSet;
use std::sync::OnceLock;

use sha3::{Digest, Sha3_512};

use binding_root_v2::{BINDING_V2_BYTES, BindingRootV2};
use field::Fp16;
use strict_pq_public_coin_v2::{
    STRICT_PQ_ANCHOR_BYTES_V2, STRICT_PQ_BUNDLE_HEADER_BYTES_V2, STRICT_PQ_CHAIN_TARGETS_LOG2_V2,
    STRICT_PQ_COLLISION_ROLE_COUNT_V2, STRICT_PQ_COMPOSED_COLLISION_TARGET_LOG2_CEIL_V2,
    STRICT_PQ_COMPOSED_PREIMAGE_TARGET_LOG2_CEIL_V2, STRICT_PQ_CONSERVATIVE_COLLISION_WORK_BITS_V2,
    STRICT_PQ_CONSERVATIVE_PREIMAGE_WORK_BITS_V2, STRICT_PQ_FP16_CHALLENGE_DOMAIN_V2,
    STRICT_PQ_FP16_MAX_ATTEMPTS_V2, STRICT_PQ_FP16_TRANSCRIPT_DOMAIN_V2,
    STRICT_PQ_GENERIC_MAX_CONTRIBUTORS_V2, STRICT_PQ_GENERIC_MAX_ROUNDS_V2,
    STRICT_PQ_GENERIC_MAX_SHAPE_BYTES_V2, STRICT_PQ_GENERIC_OTS_INSTANCES_LOG2_V2,
    STRICT_PQ_GOVERNED_KEY_BYTES_V2, STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2, STRICT_PQ_H4_MAX_ROUNDS_V2,
    STRICT_PQ_HEAD_MESSAGE_BYTES_V2, STRICT_PQ_KEY_CONTEXT_BYTES_V2,
    STRICT_PQ_LAMPORT_COLLISION_TARGET_LOG2_CEIL_V2, STRICT_PQ_LAMPORT_FRONTIER_DIGESTS_V2,
    STRICT_PQ_LAMPORT_MULTIPROOF_BYTES_V2, STRICT_PQ_LAMPORT_POSITIONS_V2,
    STRICT_PQ_LAMPORT_PREIMAGE_TARGET_LOG2_V2, STRICT_PQ_LAMPORT_PUBLIC_KEY_BYTES_V2,
    STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2, STRICT_PQ_LAMPORT_REVEAL_BYTES_V2,
    STRICT_PQ_LAMPORT_SECRET_BYTES_V2, STRICT_PQ_LAMPORT_SIGNATURE_BYTES_V2,
    STRICT_PQ_MAX_ATTEMPTS_V2, STRICT_PQ_MAX_BUNDLE_BYTES_V2, STRICT_PQ_MAX_FP16_OUTPUTS_V2,
    STRICT_PQ_MESSAGE_BINDING_INSTANCES_LOG2_V2, STRICT_PQ_Q128_COLLISION_BOUND_EXPONENT_V2,
    STRICT_PQ_Q128_COMBINED_BOUND_EXPONENT_V2, STRICT_PQ_Q128_PREIMAGE_BOUND_EXPONENT_V2,
    STRICT_PQ_QUALIFYING_ROUND_BYTES_V2, STRICT_PQ_REQUIRED_CONTRIBUTORS_V2,
    StrictPqFp16ChallengeBatchV2, StrictPqFp16PolicyV2, StrictPqFp16RoundOutputV2,
    StrictPqGovernedVerifierKeyV2, StrictPqH4ProfileV2, StrictPqHeadMessageV2,
    StrictPqKeyContextV2, StrictPqLamportPublicKeyV2, StrictPqLamportSecretKeyV2,
    StrictPqLamportSignatureV2, StrictPqPublicCoinBundleV2, StrictPqPublicCoinV2Error,
    StrictPqRootUseRegistryV2, StrictPqRoundDescriptorV2, StrictPqTranscriptBuilderV2,
    build_chain_from_supplied_tail_v2, derive_strict_pq_fp16_challenges_v2,
    replay_strict_pq_fp16_public_coin_v2, replay_strict_pq_public_coin_v2, sign_chain_head_v2,
    strict_pq_bounded_bundle_len_v2, strict_pq_candidate_bundle_len_v2,
};

const FIXTURE_ROUNDS: u32 = 3;

#[derive(Clone)]
struct Fixture {
    governed_key: StrictPqGovernedVerifierKeyV2,
    bundle: StrictPqPublicCoinBundleV2,
    raw_messages: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct Fp16Fixture {
    bundle: StrictPqPublicCoinBundleV2,
    outputs: Vec<StrictPqFp16RoundOutputV2>,
    policies: Vec<StrictPqFp16PolicyV2>,
}

fn fill(value: u8) -> [u8; 64] {
    [value; 64]
}

fn deterministic_secret(lane: u8, index: usize) -> [u8; 128] {
    let mut secret = [0_u8; 128];
    for half in 0..2_u8 {
        let mut hash = Sha3_512::new();
        hash.update(b"BL/STRICT-PQ-V2/TEST-SECRET\0");
        hash.update([lane, half]);
        hash.update((index as u32).to_be_bytes());
        let digest: [u8; 64] = hash.finalize().into();
        let offset = usize::from(half) * 64;
        secret[offset..offset + 64].copy_from_slice(&digest);
    }
    secret
}

fn deterministic_secrets(lane: u8) -> Vec<[u8; 128]> {
    (0..STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2)
        .map(|index| deterministic_secret(lane, index))
        .collect()
}

fn deterministic_tail(lane: u8) -> [u8; 128] {
    let mut tail = [0_u8; 128];
    for half in 0..2_u8 {
        let mut hash = Sha3_512::new();
        hash.update(b"BL/STRICT-PQ-V2/TEST-TAIL\0");
        hash.update([lane, half]);
        let digest: [u8; 64] = hash.finalize().into();
        let offset = usize::from(half) * 64;
        tail[offset..offset + 64].copy_from_slice(&digest);
    }
    tail
}

fn context(lane: u8, attempt: u8) -> StrictPqKeyContextV2 {
    StrictPqKeyContextV2::new(
        fill(0x11),
        fill(0x22),
        9,
        0x0102_0304_0506_0708,
        fill(0x33),
        fill(0x40 + lane),
        fill(0x50 + lane),
        attempt,
    )
    .unwrap()
}

fn build_fixture() -> Fixture {
    let (secret_1, public_1) = StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(
        context(1, 2),
        deterministic_secrets(1),
    )
    .unwrap();
    let (secret_2, public_2) = StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(
        context(2, 2),
        deterministic_secrets(2),
    )
    .unwrap();
    let governed_key = StrictPqGovernedVerifierKeyV2::new(
        fill(0x61),
        fill(0x62),
        FIXTURE_ROUNDS,
        vec![public_1.clone(), public_2.clone()],
    )
    .unwrap();
    let chain_1 = build_chain_from_supplied_tail_v2(
        &public_1,
        governed_key.session_id(),
        governed_key.schedule_commitment(),
        governed_key.round_count(),
        deterministic_tail(1),
    )
    .unwrap();
    let chain_2 = build_chain_from_supplied_tail_v2(
        &public_2,
        governed_key.session_id(),
        governed_key.schedule_commitment(),
        governed_key.round_count(),
        deterministic_tail(2),
    )
    .unwrap();
    let anchor_1 = sign_chain_head_v2(secret_1, &governed_key, *chain_1.head()).unwrap();
    let anchor_2 = sign_chain_head_v2(secret_2, &governed_key, *chain_2.head()).unwrap();

    let raw_messages = vec![
        b"round-zero/raw-v2-message".to_vec(),
        (0_u8..=63).collect(),
        b"round-two/final-message/with-explicit-length".to_vec(),
    ];
    let mut registry = StrictPqRootUseRegistryV2::new();
    let mut builder =
        StrictPqTranscriptBuilderV2::start(&governed_key, vec![anchor_1, anchor_2], &mut registry)
            .unwrap();
    assert_eq!(registry.reserved_root_count(), 2);
    for ordinal in 0..FIXTURE_ROUNDS {
        builder
            .absorb_round(
                StrictPqRoundDescriptorV2::new(
                    0x0200 + ordinal as u16,
                    ordinal,
                    2 + ordinal as u16,
                )
                .unwrap(),
                &raw_messages[ordinal as usize],
                vec![
                    chain_1.reveals()[ordinal as usize],
                    chain_2.reveals()[ordinal as usize],
                ],
            )
            .unwrap();
    }
    let bundle = builder.finish().unwrap();
    Fixture {
        governed_key,
        bundle,
        raw_messages,
    }
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(build_fixture)
}

fn build_fp16_fixture() -> Fp16Fixture {
    let fixture = fixture();
    let policies = vec![
        StrictPqFp16PolicyV2::Uniform,
        StrictPqFp16PolicyV2::Nonzero,
        StrictPqFp16PolicyV2::NonzeroNonone,
    ];
    let mut registry = StrictPqRootUseRegistryV2::new();
    let mut builder = StrictPqTranscriptBuilderV2::start(
        &fixture.governed_key,
        fixture.bundle.anchors().to_vec(),
        &mut registry,
    )
    .unwrap();
    let mut outputs = Vec::with_capacity(FIXTURE_ROUNDS as usize);
    for ((round, raw_message), policy) in fixture
        .bundle
        .rounds()
        .iter()
        .zip(&fixture.raw_messages)
        .zip(&policies)
    {
        outputs.push(
            builder
                .absorb_fp16_round(
                    StrictPqH4ProfileV2::K512,
                    *policy,
                    round.descriptor(),
                    raw_message,
                    round.reveals().to_vec(),
                )
                .unwrap(),
        );
    }
    Fp16Fixture {
        bundle: builder.finish().unwrap(),
        outputs,
        policies,
    }
}

fn fp16_fixture() -> &'static Fp16Fixture {
    static FIXTURE: OnceLock<Fp16Fixture> = OnceLock::new();
    FIXTURE.get_or_init(build_fp16_fixture)
}

fn fp16_batch_digest(batch: &StrictPqFp16ChallengeBatchV2) -> [u8; 64] {
    sha3_512(&batch.canonical_transcript_bytes())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn sha3_512(bytes: &[u8]) -> [u8; 64] {
    Sha3_512::digest(bytes).into()
}

fn first_head_message(fixture: &Fixture) -> StrictPqHeadMessageV2 {
    let public_key = &fixture.governed_key.contributors()[0];
    let anchor = &fixture.bundle.anchors()[0];
    StrictPqHeadMessageV2::new(
        public_key.context().clone(),
        *fixture.governed_key.session_id(),
        *fixture.governed_key.schedule_commitment(),
        fixture.governed_key.round_count(),
        *anchor.chain_head(),
    )
    .unwrap()
}

#[test]
fn exact_grammar_sizes_resource_caps_and_security_bounds() {
    assert_eq!(STRICT_PQ_MAX_ATTEMPTS_V2, 4);
    assert_eq!(STRICT_PQ_REQUIRED_CONTRIBUTORS_V2, 2);
    assert_eq!(STRICT_PQ_GENERIC_MAX_CONTRIBUTORS_V2, 16);
    assert_eq!(STRICT_PQ_GENERIC_MAX_ROUNDS_V2, 65_536);
    assert_eq!(STRICT_PQ_H4_MAX_ROUNDS_V2, 7_059);
    assert_eq!(STRICT_PQ_MAX_BUNDLE_BYTES_V2, 16_777_216);

    assert_eq!(STRICT_PQ_LAMPORT_POSITIONS_V2, 1_024);
    assert_eq!(STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2, 2_048);
    assert_eq!(STRICT_PQ_LAMPORT_SECRET_BYTES_V2, 128);
    assert_eq!(
        STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2 * STRICT_PQ_LAMPORT_SECRET_BYTES_V2,
        262_144
    );
    assert_eq!(STRICT_PQ_LAMPORT_REVEAL_BYTES_V2, 131_072);
    assert_eq!(STRICT_PQ_LAMPORT_FRONTIER_DIGESTS_V2, 1_024);
    assert_eq!(STRICT_PQ_LAMPORT_MULTIPROOF_BYTES_V2, 139_292);
    assert_eq!(STRICT_PQ_LAMPORT_SIGNATURE_BYTES_V2, 270_380);
    assert_eq!(STRICT_PQ_KEY_CONTEXT_BYTES_V2, 356);
    assert_eq!(STRICT_PQ_LAMPORT_PUBLIC_KEY_BYTES_V2, 484);
    assert_eq!(STRICT_PQ_GOVERNED_KEY_BYTES_V2, 1_116);
    assert_eq!(STRICT_PQ_HEAD_MESSAGE_BYTES_V2, 628);
    assert_eq!(STRICT_PQ_ANCHOR_BYTES_V2, 270_636);
    assert_eq!(STRICT_PQ_QUALIFYING_ROUND_BYTES_V2, 392);
    assert_eq!(STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2, 3_308_688);
    assert!(STRICT_PQ_H4_MAX_BUNDLE_BYTES_V2 < STRICT_PQ_MAX_BUNDLE_BYTES_V2);
    assert_eq!(strict_pq_candidate_bundle_len_v2(2, 7_059), Ok(3_308_688));
    assert_eq!(strict_pq_bounded_bundle_len_v2(2, 7_059), Ok(3_308_688));

    assert_eq!(STRICT_PQ_GENERIC_MAX_SHAPE_BYTES_V2, 147_461_088);
    assert_eq!(
        strict_pq_candidate_bundle_len_v2(16, 65_536),
        Ok(147_461_088)
    );
    assert_eq!(
        strict_pq_bounded_bundle_len_v2(16, 65_536),
        Err(StrictPqPublicCoinV2Error::BundleTooLarge)
    );

    assert_eq!(STRICT_PQ_GENERIC_OTS_INSTANCES_LOG2_V2, 70);
    assert_eq!(STRICT_PQ_COLLISION_ROLE_COUNT_V2, 5);
    assert_eq!(STRICT_PQ_LAMPORT_COLLISION_TARGET_LOG2_CEIL_V2, 73);
    assert_eq!(STRICT_PQ_LAMPORT_PREIMAGE_TARGET_LOG2_V2, 81);
    assert_eq!(STRICT_PQ_MESSAGE_BINDING_INSTANCES_LOG2_V2, 82);
    assert_eq!(STRICT_PQ_CHAIN_TARGETS_LOG2_V2, 86);
    assert_eq!(STRICT_PQ_COMPOSED_COLLISION_TARGET_LOG2_CEIL_V2, 83);
    assert_eq!(STRICT_PQ_COMPOSED_PREIMAGE_TARGET_LOG2_CEIL_V2, 87);
    assert_eq!(STRICT_PQ_Q128_COLLISION_BOUND_EXPONENT_V2, 557);
    assert_eq!(STRICT_PQ_Q128_PREIMAGE_BOUND_EXPONENT_V2, 681);
    assert_eq!(STRICT_PQ_Q128_COMBINED_BOUND_EXPONENT_V2, 556);
    assert_eq!(STRICT_PQ_CONSERVATIVE_COLLISION_WORK_BITS_V2, 258);
    assert_eq!(STRICT_PQ_CONSERVATIVE_PREIMAGE_WORK_BITS_V2, 425);

    assert_eq!(STRICT_PQ_MAX_FP16_OUTPUTS_V2, 4_096);
    assert_eq!(STRICT_PQ_FP16_MAX_ATTEMPTS_V2, 16);
    assert_eq!(
        StrictPqRoundDescriptorV2::new(1, 0, STRICT_PQ_MAX_FP16_OUTPUTS_V2 + 1),
        Err(StrictPqPublicCoinV2Error::Descriptor)
    );
    assert_eq!(
        STRICT_PQ_FP16_CHALLENGE_DOMAIN_V2,
        b"BL/PQ512/WAVE2/STRICT-PQ/FP16-CHALLENGE/v2\0"
    );
    assert_eq!(
        STRICT_PQ_FP16_TRANSCRIPT_DOMAIN_V2,
        b"BL/PQ512/WAVE2/STRICT-PQ/FP16-TRANSCRIPT/v2\0"
    );
}

#[test]
fn fp16_sampler_kat_and_exact_typed_policies() {
    let seed = core::array::from_fn(|index| index as u8);
    let session_id = fill(0x71);
    let descriptor = StrictPqRoundDescriptorV2::new(0x0345, 7, 3).unwrap();
    assert_eq!(descriptor.kind(), 0x0345);
    assert_eq!(descriptor.ordinal(), 7);
    assert_eq!(descriptor.output_count(), 3);

    let batch = derive_strict_pq_fp16_challenges_v2(
        StrictPqH4ProfileV2::K512,
        StrictPqFp16PolicyV2::NonzeroNonone,
        &session_id,
        2,
        7,
        descriptor,
        &seed,
    )
    .unwrap();
    assert_eq!(batch.profile(), StrictPqH4ProfileV2::K512);
    assert_eq!(batch.policy(), StrictPqFp16PolicyV2::NonzeroNonone);
    assert_eq!(batch.descriptor(), descriptor);
    assert_eq!(batch.seed(), &seed);
    assert_eq!(batch.samples().len(), 3);
    let expected_digests = [
        concat!(
            "3adad76c534db867ad2545ee6fed8b5a6199e58dcaf6fa934a1045dbda20141a",
            "a86af99330227f0e19caeb9614af37da4daa789c3fa4df023d5e53628ed432aa"
        ),
        concat!(
            "1d6e2c0e84dd501275c0d0d21a1185479ecdf4a1b38c41a732771d4177d06739",
            "4f14ddcf9e38c37122fabc0ea2432e0e1551baba35a9bccff598f8de7df7fa16"
        ),
        concat!(
            "68ea2798d03efc811cf007996c1d554e1c8d1cc5c03368874f4aa73d46d0bdde",
            "100b6661757b248149224ebcc9cab88ea31503de3e1c39d3849a6ea17f9935f4"
        ),
    ];
    let expected_elements = [
        concat!(
            "7edfe99e678481a804ca202c614ea4b72392004806ff2e3c290b988412d9e3a9",
            "67d5d8d529dbebca3218a69f4497d3c67ff6326f5c6080263de1f2a46bb9d753"
        ),
        concat!(
            "0250fcd317747a331f7ad21c5fa951b21068f43d19ee8f9c0b9dc59f4ca0e9c7",
            "59c65341620d610c5d0947a074d67e40710629183b957fc71e7f4d9016091951"
        ),
        concat!(
            "0522967645ce4a313b089e6b24c7bf6c2efbede66b313b5c53c8296b0a30a7a6",
            "5760b4607346cb627fe6f5e40cc3360b055e7478147347ed684b8ed613d2f6c1"
        ),
    ];
    for (draw, sample) in batch.samples().iter().enumerate() {
        assert_eq!(sample.draw(), draw as u16);
        assert_eq!(sample.accepted_attempt(), 0);
        assert!(StrictPqFp16PolicyV2::NonzeroNonone.accepts(sample.element()));
        assert_eq!(hex(&sample.digest()), expected_digests[draw]);
        assert_eq!(hex(&sample.element().encode()), expected_elements[draw]);
    }
    assert_eq!(
        hex(&fp16_batch_digest(&batch)),
        concat!(
            "dfa19ca7a0b4e0ed1c3bb78ba316211a88b08cf64aab96d04424d17774121ecb",
            "686eff47a567fd29c611b11f91346dd9a87a7012061456ea79faf32101363012"
        )
    );

    assert!(StrictPqFp16PolicyV2::Uniform.accepts(Fp16::ZERO));
    assert!(StrictPqFp16PolicyV2::Uniform.accepts(Fp16::ONE));
    assert!(!StrictPqFp16PolicyV2::Nonzero.accepts(Fp16::ZERO));
    assert!(StrictPqFp16PolicyV2::Nonzero.accepts(Fp16::ONE));
    assert!(!StrictPqFp16PolicyV2::NonzeroNonone.accepts(Fp16::ZERO));
    assert!(!StrictPqFp16PolicyV2::NonzeroNonone.accepts(Fp16::ONE));
    assert!(!StrictPqFp16PolicyV2::OodsOutsideFp8.accepts(Fp16::ONE));
    let mut outside_coefficients = [0_u32; 16];
    outside_coefficients[8] = 1;
    let outside_fp8 = Fp16::from_coefficients(outside_coefficients).unwrap();
    assert!(StrictPqFp16PolicyV2::OodsOutsideFp8.accepts(outside_fp8));
    assert_eq!(
        derive_strict_pq_fp16_challenges_v2(
            StrictPqH4ProfileV2::K512,
            StrictPqFp16PolicyV2::OodsOutsideFp8,
            &session_id,
            2,
            7,
            StrictPqRoundDescriptorV2::new(0x0345, 7, 2).unwrap(),
            &seed,
        ),
        Err(StrictPqPublicCoinV2Error::Descriptor)
    );
}

#[test]
fn fp16_derivation_binds_profile_policy_context_descriptor_and_all_seed_bytes() {
    let session_id = fill(0x71);
    let seed = core::array::from_fn(|index| index as u8);
    let descriptor = StrictPqRoundDescriptorV2::new(0x0345, 7, 2).unwrap();
    let derive_digest = |profile, policy, session: &[u8; 64], attempt, round, descriptor, seed| {
        fp16_batch_digest(
            &derive_strict_pq_fp16_challenges_v2(
                profile, policy, session, attempt, round, descriptor, seed,
            )
            .unwrap(),
        )
    };
    let mut digests = BTreeSet::new();
    digests.insert(derive_digest(
        StrictPqH4ProfileV2::K512,
        StrictPqFp16PolicyV2::Uniform,
        &session_id,
        2,
        7,
        descriptor,
        &seed,
    ));
    digests.insert(derive_digest(
        StrictPqH4ProfileV2::K128,
        StrictPqFp16PolicyV2::Uniform,
        &session_id,
        2,
        7,
        descriptor,
        &seed,
    ));
    digests.insert(derive_digest(
        StrictPqH4ProfileV2::K512,
        StrictPqFp16PolicyV2::Nonzero,
        &session_id,
        2,
        7,
        descriptor,
        &seed,
    ));
    let mut changed_session = session_id;
    changed_session[63] ^= 1;
    digests.insert(derive_digest(
        StrictPqH4ProfileV2::K512,
        StrictPqFp16PolicyV2::Uniform,
        &changed_session,
        2,
        7,
        descriptor,
        &seed,
    ));
    digests.insert(derive_digest(
        StrictPqH4ProfileV2::K512,
        StrictPqFp16PolicyV2::Uniform,
        &session_id,
        3,
        7,
        descriptor,
        &seed,
    ));
    digests.insert(derive_digest(
        StrictPqH4ProfileV2::K512,
        StrictPqFp16PolicyV2::Uniform,
        &session_id,
        2,
        8,
        StrictPqRoundDescriptorV2::new(0x0345, 8, 2).unwrap(),
        &seed,
    ));
    digests.insert(derive_digest(
        StrictPqH4ProfileV2::K512,
        StrictPqFp16PolicyV2::Uniform,
        &session_id,
        2,
        7,
        StrictPqRoundDescriptorV2::new(0x0346, 7, 2).unwrap(),
        &seed,
    ));
    digests.insert(derive_digest(
        StrictPqH4ProfileV2::K512,
        StrictPqFp16PolicyV2::Uniform,
        &session_id,
        2,
        7,
        StrictPqRoundDescriptorV2::new(0x0345, 7, 3).unwrap(),
        &seed,
    ));
    let mut changed_first_half = seed;
    changed_first_half[0] ^= 1;
    digests.insert(derive_digest(
        StrictPqH4ProfileV2::K512,
        StrictPqFp16PolicyV2::Uniform,
        &session_id,
        2,
        7,
        descriptor,
        &changed_first_half,
    ));
    let mut changed_second_half = seed;
    changed_second_half[127] ^= 1;
    digests.insert(derive_digest(
        StrictPqH4ProfileV2::K512,
        StrictPqFp16PolicyV2::Uniform,
        &session_id,
        2,
        7,
        descriptor,
        &changed_second_half,
    ));
    assert_eq!(digests.len(), 10);
}

#[test]
fn fp16_bundle_replay_reconstructs_outputs_and_rejects_schedule_mutations() {
    let fixture = fixture();
    let fp16 = fp16_fixture();
    let encoded = fp16.bundle.encode().unwrap();
    let decoded = StrictPqPublicCoinBundleV2::decode(&encoded).unwrap();
    let outputs = replay_strict_pq_fp16_public_coin_v2(
        &fixture.governed_key,
        &decoded,
        StrictPqH4ProfileV2::K512,
        &fp16.policies,
        &fixture.raw_messages,
        &mut StrictPqRootUseRegistryV2::new(),
    )
    .unwrap();
    assert_eq!(outputs, fp16.outputs);
    assert_eq!(
        outputs
            .iter()
            .map(|output| output.challenges().samples().len())
            .collect::<Vec<_>>(),
        vec![2, 3, 4]
    );
    assert_eq!(
        hex(&sha3_512(&encoded)),
        concat!(
            "0ef3e42bcc4fc18959249ab1ed1c01a9b17ca359d825947af76a98d8c44b97be",
            "b93a5f815b63d654f3dff23e54e20dc04f526fabf446c811221ff9c6f502aa73"
        )
    );
    assert_eq!(
        hex(fp16.bundle.final_transcript_root()),
        concat!(
            "1c997b5afa29679d7578e69649c791015abc48d665c0e8dc1c3f2160e5cd475c",
            "e4c6d16042f9b82217af0d301c05f7110a398414ebfde5b843208805a844214e",
            "8a5ca39ce16dccf00bf27cd377c1527bd75c24ae3d65765338ad4f8c7e053c98",
            "88c8b8d39c2f8436e4dade2050e25f10738294258169e53b8de9f0bf05ccead2"
        )
    );
    assert_eq!(
        outputs
            .iter()
            .map(|output| hex(&fp16_batch_digest(output.challenges())))
            .collect::<Vec<_>>(),
        vec![
            concat!(
                "246ddead9792e083db620ebacab3f9c5ff4337f288ba413536d25721e1cb9a66",
                "cf419e08ec57942a5fbab5525c90f9e18c1225cab9000ec860857a3283cebb88"
            ),
            concat!(
                "9fb7da74f02c17ee85252c62b09db763757c49365b6d12ad9aa872a012fe6f05",
                "d05bb803366a15dcb6795657c26f9c578c91c038a769faa32517117cd66f2f51"
            ),
            concat!(
                "3f39cdd656ca15151480509cb7f579ce893a8ad4fad222b33bae70759db27ebcd",
                "5f94d79dea02c65620028083089a7486daa1c5b46c096d109e8320e19c59768"
            ),
        ]
    );

    assert_eq!(
        replay_strict_pq_fp16_public_coin_v2(
            &fixture.governed_key,
            &decoded,
            StrictPqH4ProfileV2::K128,
            &fp16.policies,
            &fixture.raw_messages,
            &mut StrictPqRootUseRegistryV2::new(),
        ),
        Err(StrictPqPublicCoinV2Error::TranscriptMismatch)
    );
    let mut changed_policies = fp16.policies.clone();
    changed_policies[0] = StrictPqFp16PolicyV2::Nonzero;
    assert_eq!(
        replay_strict_pq_fp16_public_coin_v2(
            &fixture.governed_key,
            &decoded,
            StrictPqH4ProfileV2::K512,
            &changed_policies,
            &fixture.raw_messages,
            &mut StrictPqRootUseRegistryV2::new(),
        ),
        Err(StrictPqPublicCoinV2Error::TranscriptMismatch)
    );
    assert_eq!(
        replay_strict_pq_fp16_public_coin_v2(
            &fixture.governed_key,
            &decoded,
            StrictPqH4ProfileV2::K512,
            &fp16.policies[..2],
            &fixture.raw_messages,
            &mut StrictPqRootUseRegistryV2::new(),
        ),
        Err(StrictPqPublicCoinV2Error::ChallengePolicyCount)
    );
}

#[test]
fn deterministic_roots_head_signature_bundle_and_transcript_kats() {
    let fixture = fixture();
    let public_1 = &fixture.governed_key.contributors()[0];
    let public_2 = &fixture.governed_key.contributors()[1];
    let head = first_head_message(fixture);
    let signature = fixture.bundle.anchors()[0].signature().encode().unwrap();
    let bundle = fixture.bundle.encode().unwrap();
    assert_eq!(
        hex(public_1.root().as_bytes()),
        concat!(
            "84eca248181d63200c3777e1c86bde95b853814533e380371e9809387b4299c1",
            "220c4348f62009a46c79d6e90d5a9459c67857e0abf4471a9eacc423344b2fcc",
            "347c9a596d03ae7195789dc6660bbcc1dd160f90dd3407e12ccc10f43a1da9b8",
            "d6218f2edf3965e30f69df13ae4b2c680b117ca22d78a57600eed213aa3b840e"
        )
    );
    assert_eq!(
        hex(public_2.root().as_bytes()),
        concat!(
            "5a0dd1881ca811908038f7ea4833e11d410f7c93cb8e0a6a2a4d16c983c380d6",
            "cbcf84abdc75e9ec81a902b073e386c904221f9b052c9242aa98dc25f0079590",
            "fb4c1dac05ca94dcc36aae501e55968895dc8648dc8aa79f81cd16832c58f069",
            "a6e729fdac44a4818247499702cab3bf5e6abce775ed3e4f6707f9fcb70ae0ce"
        )
    );
    assert_eq!(
        hex(head.digest().unwrap().as_bytes()),
        concat!(
            "d4073a46c0d610fc55542677642e25327dafa8fa838a6444bde3c279eaf15c9c",
            "8d5d084b0ec525e121ac677801e12dc6961d87c894296e74037da0c7de186565",
            "f1adf0de91ad1c5617ddc7f5e60d1fed8a7ba7718b90ae306176e15762c8bfcc",
            "fdecdaf260542e8c6a7329d9a18ce4ecd812f99fbfcd5049c1a21b13785105e4"
        )
    );
    assert_eq!(
        hex(&sha3_512(&signature)),
        concat!(
            "57a85019c4c87992c63f2f71cfbee30b1cfe1000978afb0435896c8357e1ed3e",
            "5f200853f7af954db53b958c9491941b4016d7f9d82974a2bd4eaea347124049"
        )
    );
    assert_eq!(
        hex(&sha3_512(&bundle)),
        concat!(
            "7e7e7054671aa393e56262548ed60e9675ec2f6da50da49b9e0b0f5a3658d6b",
            "6fb37f4c5b2e6e30ca0dc13e36adcc4cc54b25d85023241f54510e4b949d8744d"
        )
    );
    assert_eq!(
        hex(fixture.bundle.final_transcript_root()),
        concat!(
            "1f1650cf54b37fd099139d198e6e7d9bf52f02032500c8e995115682bce0294d",
            "8b9fd265e3fae7ecd0683c39ff9d2236aa35b36b85e0b03beffba0ab7cce1af8",
            "a819e16220c6931fd9cc19e89ea3cd5757eb1678ae09a5d110069ee089f45a961",
            "d35fcd8ea747ae0273cf80cb254478356bd034e5224c0cc67e845b0d5ad43bc"
        )
    );
}

#[test]
fn canonical_key_bundle_roundtrip_and_replay() {
    let fixture = fixture();
    let key_bytes = fixture.governed_key.encode();
    assert_eq!(key_bytes.len(), STRICT_PQ_GOVERNED_KEY_BYTES_V2);
    assert_eq!(
        StrictPqGovernedVerifierKeyV2::decode(&key_bytes).unwrap(),
        fixture.governed_key
    );

    let encoded = fixture.bundle.encode().unwrap();
    assert_eq!(
        encoded.len(),
        strict_pq_bounded_bundle_len_v2(2, FIXTURE_ROUNDS).unwrap()
    );
    let decoded = StrictPqPublicCoinBundleV2::decode(&encoded).unwrap();
    assert_eq!(decoded, fixture.bundle);
    let mut registry = StrictPqRootUseRegistryV2::new();
    let seeds = replay_strict_pq_public_coin_v2(
        &fixture.governed_key,
        &decoded,
        &fixture.raw_messages,
        &mut registry,
    )
    .unwrap();
    assert_eq!(seeds.len(), FIXTURE_ROUNDS as usize);
    assert!(seeds.iter().all(|seed| seed.len() == BINDING_V2_BYTES));
    assert_eq!(registry.reserved_root_count(), 2);
}

#[test]
fn lamport_index_reveal_root_and_raw_head_message_mutations_reject() {
    let fixture = fixture();
    let public_key = &fixture.governed_key.contributors()[0];
    let head = first_head_message(fixture);
    let signature = fixture.bundle.anchors()[0].signature();
    signature.verify(public_key, &head).unwrap();

    let mut index_mutation = signature.encode().unwrap();
    let first_index = 16 + STRICT_PQ_LAMPORT_REVEAL_BYTES_V2 + 28;
    index_mutation[first_index + 7] ^= 1;
    let index_mutation = StrictPqLamportSignatureV2::decode(&index_mutation).unwrap();
    assert_eq!(
        index_mutation.verify(public_key, &head),
        Err(StrictPqPublicCoinV2Error::SignatureIndexMismatch)
    );

    let mut reveal_mutation = signature.encode().unwrap();
    reveal_mutation[16] ^= 1;
    let reveal_mutation = StrictPqLamportSignatureV2::decode(&reveal_mutation).unwrap();
    assert_eq!(
        reveal_mutation.verify(public_key, &head),
        Err(StrictPqPublicCoinV2Error::SignatureMismatch)
    );

    for lane_offset in [0, 64] {
        let mut public_key_bytes = public_key.encode();
        public_key_bytes[STRICT_PQ_KEY_CONTEXT_BYTES_V2 + lane_offset] ^= 1;
        let mutated_key = StrictPqLamportPublicKeyV2::decode(&public_key_bytes).unwrap();
        assert_eq!(
            signature.verify(&mutated_key, &head),
            Err(StrictPqPublicCoinV2Error::SignatureMismatch)
        );
    }

    let mut raw_head = head.encode();
    let chain_head_offset = raw_head.len() - BINDING_V2_BYTES;
    raw_head[chain_head_offset] ^= 1;
    let mutated_head = StrictPqHeadMessageV2::decode(&raw_head).unwrap();
    assert!(signature.verify(public_key, &mutated_head).is_err());
}

#[test]
fn replay_rejects_message_chain_anchor_attempt_and_reuse_attacks() {
    let fixture = fixture();

    let mut messages = fixture.raw_messages.clone();
    messages[1][0] ^= 1;
    assert_eq!(
        replay_strict_pq_public_coin_v2(
            &fixture.governed_key,
            &fixture.bundle,
            &messages,
            &mut StrictPqRootUseRegistryV2::new(),
        ),
        Err(StrictPqPublicCoinV2Error::RoundMismatch)
    );

    let first_round = STRICT_PQ_BUNDLE_HEADER_BYTES_V2
        + STRICT_PQ_REQUIRED_CONTRIBUTORS_V2 * STRICT_PQ_ANCHOR_BYTES_V2;
    let first_reveal = first_round + 8 + BINDING_V2_BYTES;
    let mut chain_mutation = fixture.bundle.encode().unwrap();
    chain_mutation[first_reveal] ^= 1;
    let chain_mutation = StrictPqPublicCoinBundleV2::decode(&chain_mutation).unwrap();
    assert_eq!(
        replay_strict_pq_public_coin_v2(
            &fixture.governed_key,
            &chain_mutation,
            &fixture.raw_messages,
            &mut StrictPqRootUseRegistryV2::new(),
        ),
        Err(StrictPqPublicCoinV2Error::ChainMismatch)
    );

    let first_anchor_head = STRICT_PQ_BUNDLE_HEADER_BYTES_V2 + 64 + 64;
    let mut anchor_mutation = fixture.bundle.encode().unwrap();
    anchor_mutation[first_anchor_head] ^= 1;
    let anchor_mutation = StrictPqPublicCoinBundleV2::decode(&anchor_mutation).unwrap();
    assert!(
        replay_strict_pq_public_coin_v2(
            &fixture.governed_key,
            &anchor_mutation,
            &fixture.raw_messages,
            &mut StrictPqRootUseRegistryV2::new(),
        )
        .is_err()
    );

    let mut attempt_mutation = fixture.bundle.encode().unwrap();
    attempt_mutation[26] = 3;
    let attempt_mutation = StrictPqPublicCoinBundleV2::decode(&attempt_mutation).unwrap();
    assert_eq!(
        replay_strict_pq_public_coin_v2(
            &fixture.governed_key,
            &attempt_mutation,
            &fixture.raw_messages,
            &mut StrictPqRootUseRegistryV2::new(),
        ),
        Err(StrictPqPublicCoinV2Error::AttemptMismatch)
    );

    let mut registry = StrictPqRootUseRegistryV2::new();
    replay_strict_pq_public_coin_v2(
        &fixture.governed_key,
        &fixture.bundle,
        &fixture.raw_messages,
        &mut registry,
    )
    .unwrap();
    assert_eq!(
        replay_strict_pq_public_coin_v2(
            &fixture.governed_key,
            &fixture.bundle,
            &fixture.raw_messages,
            &mut registry,
        ),
        Err(StrictPqPublicCoinV2Error::SlotAlreadyUsed)
    );
}

#[test]
fn parser_rejects_noncanonical_and_oversized_shapes_before_large_allocation() {
    let encoded = fixture().bundle.encode().unwrap();
    for length in [
        0,
        1,
        STRICT_PQ_BUNDLE_HEADER_BYTES_V2 - 1,
        encoded.len() - 1,
    ] {
        assert!(StrictPqPublicCoinBundleV2::decode(&encoded[..length]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        StrictPqPublicCoinBundleV2::decode(&trailing),
        Err(StrictPqPublicCoinV2Error::BundleLength)
    );

    for (offset, expected) in [
        (0, StrictPqPublicCoinV2Error::Magic),
        (9, StrictPqPublicCoinV2Error::Version),
        (11, StrictPqPublicCoinV2Error::Flags),
        (27, StrictPqPublicCoinV2Error::Reserved),
    ] {
        let mut mutation = encoded.clone();
        mutation[offset] ^= 1;
        assert_eq!(StrictPqPublicCoinBundleV2::decode(&mutation), Err(expected));
    }
    let mut declared_length = encoded.clone();
    declared_length[23] ^= 1;
    assert_eq!(
        StrictPqPublicCoinBundleV2::decode(&declared_length),
        Err(StrictPqPublicCoinV2Error::BundleLength)
    );
    let first_round = STRICT_PQ_BUNDLE_HEADER_BYTES_V2
        + STRICT_PQ_REQUIRED_CONTRIBUTORS_V2 * STRICT_PQ_ANCHOR_BYTES_V2;
    let mut ordinal = encoded;
    ordinal[first_round + 5] ^= 1;
    assert_eq!(
        StrictPqPublicCoinBundleV2::decode(&ordinal),
        Err(StrictPqPublicCoinV2Error::Descriptor)
    );

    let mut oversized_header = vec![0_u8; STRICT_PQ_BUNDLE_HEADER_BYTES_V2];
    oversized_header[..8].copy_from_slice(strict_pq_public_coin_v2::STRICT_PQ_BUNDLE_MAGIC_V2);
    oversized_header[8..10].copy_from_slice(&2_u16.to_be_bytes());
    oversized_header[12..16]
        .copy_from_slice(&(STRICT_PQ_BUNDLE_HEADER_BYTES_V2 as u32).to_be_bytes());
    oversized_header[16..24]
        .copy_from_slice(&(STRICT_PQ_GENERIC_MAX_SHAPE_BYTES_V2 as u64).to_be_bytes());
    oversized_header[24..26].copy_from_slice(&16_u16.to_be_bytes());
    oversized_header[26] = 0;
    oversized_header[28..32].copy_from_slice(&65_536_u32.to_be_bytes());
    assert_eq!(
        StrictPqPublicCoinBundleV2::decode(&oversized_header),
        Err(StrictPqPublicCoinV2Error::BundleTooLarge)
    );
}

#[test]
fn governed_profile_is_exactly_two_contributors_four_attempts_and_7059_rounds() {
    let fixture = fixture();
    let contributors = fixture.governed_key.contributors();
    assert_eq!(
        StrictPqGovernedVerifierKeyV2::new(
            *fixture.governed_key.session_id(),
            *fixture.governed_key.schedule_commitment(),
            1,
            vec![contributors[0].clone()],
        ),
        Err(StrictPqPublicCoinV2Error::ContributorCount)
    );
    assert_eq!(
        StrictPqGovernedVerifierKeyV2::new(
            *fixture.governed_key.session_id(),
            *fixture.governed_key.schedule_commitment(),
            STRICT_PQ_H4_MAX_ROUNDS_V2 + 1,
            contributors.to_vec(),
        ),
        Err(StrictPqPublicCoinV2Error::RoundCount)
    );
    assert_eq!(
        StrictPqGovernedVerifierKeyV2::new(
            *fixture.governed_key.session_id(),
            *fixture.governed_key.schedule_commitment(),
            1,
            vec![contributors[1].clone(), contributors[0].clone()],
        ),
        Err(StrictPqPublicCoinV2Error::ContributorOrder)
    );
    assert_eq!(
        StrictPqKeyContextV2::new(
            fill(0x11),
            fill(0x22),
            9,
            7,
            fill(0x33),
            fill(0x41),
            fill(0x51),
            4,
        ),
        Err(StrictPqPublicCoinV2Error::AttemptOutOfRange)
    );
}

#[test]
fn keygen_rejects_zero_duplicate_and_wrong_secret_sets() {
    assert!(matches!(
        StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(context(1, 0), vec![]),
        Err(StrictPqPublicCoinV2Error::SecretCount)
    ));

    let zero = vec![[0_u8; 128]; STRICT_PQ_LAMPORT_PUBLIC_VALUES_V2];
    assert!(matches!(
        StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(context(1, 0), zero),
        Err(StrictPqPublicCoinV2Error::ZeroSecret)
    ));

    let mut duplicate = deterministic_secrets(9);
    duplicate[1] = duplicate[0];
    assert!(matches!(
        StrictPqLamportSecretKeyV2::keygen_from_supplied_secrets(context(1, 0), duplicate),
        Err(StrictPqPublicCoinV2Error::DuplicateSecret)
    ));
}

#[test]
fn changed_key_id_cannot_allocate_a_second_root_for_the_same_slot() {
    let fixture = fixture();
    let mut registry = StrictPqRootUseRegistryV2::new();
    registry
        .reserve_governed_key(&fixture.governed_key)
        .unwrap();

    let original = &fixture.governed_key.contributors()[0];
    let replacement_context = StrictPqKeyContextV2::new(
        *original.context().candidate_protocol_id(),
        *original.context().schema_id(),
        original.context().epoch(),
        original.context().statement_sequence(),
        *original.context().statement_id(),
        *original.context().contributor_id(),
        fill(0x7a),
        original.context().attempt(),
    )
    .unwrap();
    let mut replacement_root = original.root().to_bytes();
    replacement_root[0] ^= 1;
    let replacement = StrictPqLamportPublicKeyV2::from_parts(
        replacement_context,
        BindingRootV2::decode(&replacement_root).unwrap(),
    )
    .unwrap();
    let replacement_key = StrictPqGovernedVerifierKeyV2::new(
        *fixture.governed_key.session_id(),
        *fixture.governed_key.schedule_commitment(),
        fixture.governed_key.round_count(),
        vec![replacement, fixture.governed_key.contributors()[1].clone()],
    )
    .unwrap();
    assert_eq!(
        registry.reserve_governed_key(&replacement_key),
        Err(StrictPqPublicCoinV2Error::SlotAlreadyUsed)
    );
}
