use std::{hint::black_box, time::Instant};

use bl_pq512_crypto_core::{
    field::{Fp16, M31_MODULUS},
    gkr_packed_bridge_fp16::{
        PACKED_INSTANCES, PACKED_MESSAGE_COEFFICIENTS, evaluate_message, lagrange_basis,
        packed_round_message,
    },
};

const KECCAK_ROUNDS: usize = 24;
const LAYERS_PER_ROUND: usize = 7;
const CLAIM_SCHEDULE: [usize; LAYERS_PER_ROUND] = [2, 1, 2, 1, 3, 1, 1];

fn field(seed: usize) -> Fp16 {
    let mut state = (seed as u64) ^ 0xa409_3822_299f_31d0;
    let coordinates = core::array::from_fn(|_| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state as u32) % M31_MODULUS
    });
    Fp16::from_coefficients(coordinates).expect("canonical deterministic field element")
}

fn weights<const CLAIMS: usize>(salt: usize) -> [[Fp16; PACKED_INSTANCES]; CLAIMS] {
    core::array::from_fn(|claim| {
        core::array::from_fn(|position| field(salt + claim * 97 + position * 11))
    })
}

fn queries<const CLAIMS: usize>(salt: usize) -> [Fp16; CLAIMS] {
    core::array::from_fn(|claim| field(salt + claim * 19))
}

fn main() {
    let setup_started = Instant::now();
    let basis = lagrange_basis();
    let one_claim_weights = weights::<1>(1);
    let two_claim_weights = weights::<2>(10_001);
    let three_claim_weights = weights::<3>(20_001);
    let setup_seconds = setup_started.elapsed().as_secs_f64();

    let prover_started = Instant::now();
    let mut messages = Vec::with_capacity(LAYERS_PER_ROUND * KECCAK_ROUNDS);
    for round in 0..KECCAK_ROUNDS {
        for (layer, claims) in CLAIM_SCHEDULE.iter().copied().enumerate() {
            let salt = 30_001 + round * 1_001 + layer * 101;
            messages.push(match claims {
                1 => packed_round_message(&basis, &one_claim_weights, &queries::<1>(salt)),
                2 => packed_round_message(&basis, &two_claim_weights, &queries::<2>(salt)),
                3 => packed_round_message(&basis, &three_claim_weights, &queries::<3>(salt)),
                _ => unreachable!("frozen claim schedule"),
            });
        }
    }
    let prover_seconds = prover_started.elapsed().as_secs_f64();
    assert_eq!(messages.len(), 168);
    assert!(
        messages
            .iter()
            .all(|message| message[PACKED_MESSAGE_COEFFICIENTS - 1] != Fp16::ZERO)
    );

    let verifier_started = Instant::now();
    let mut checksum = Fp16::ZERO;
    for (layer, message) in messages.iter().enumerate() {
        checksum = checksum + evaluate_message(message, field(40_001 + layer * 101));
    }
    let verifier_seconds = verifier_started.elapsed().as_secs_f64();
    black_box(&messages);
    black_box(checksum);
    assert_ne!(checksum, Fp16::ZERO);

    let one_message_size = PACKED_MESSAGE_COEFFICIENTS * 64;
    let all_messages_size = one_message_size * messages.len();
    println!("scope=fp16_gkr_b16_univariate_bridge");
    println!("evidence_class=exact_algebra_release_geometry");
    println!("keccak_rounds={KECCAK_ROUNDS}");
    println!("layers_per_round={LAYERS_PER_ROUND}");
    println!("claim_schedule=2,1,2,1,3,1,1");
    println!("gkr_layers={}", messages.len());
    println!("packed_instances={PACKED_INSTANCES}");
    println!("message_degree=30");
    println!("message_coefficients={PACKED_MESSAGE_COEFFICIENTS}");
    println!("independent_lanes=1");
    println!(
        "one_packed_message_mb={:.6}",
        one_message_size as f64 / 1_000_000.0
    );
    println!(
        "all_packed_messages_mb={:.6}",
        all_messages_size as f64 / 1_000_000.0
    );
    println!("basis_setup_seconds={setup_seconds:.6}");
    println!("all_message_finalize_seconds={prover_seconds:.6}");
    println!("all_message_verify_seconds={verifier_seconds:.6}");
    println!("message_before_challenge_required=true");
    println!("algebra_kat_in_library=true");
    println!("proof_system_qualification=false");
}
