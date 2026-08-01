use std::{hint::black_box, time::Instant};

use bl_pq512_crypto_core::{
    gf128::{Gf128, Gf128Triple},
    gkr_packed_bridge::{
        PACKED_INSTANCES, PACKED_MESSAGE_COEFFICIENTS, evaluate_message, lagrange_basis,
        packed_round_message,
    },
};

const KECCAK_ROUNDS: usize = 24;
const LANES: usize = 3;

fn field(seed: usize) -> Gf128 {
    Gf128::from_u128(
        (seed as u128).wrapping_mul(0x9e37_79b9_7f4a_7c15_d6e8_feb8_6659_fd93)
            ^ 0xa409_3822_299f_31d0_082e_fa98_ec4e_6c89,
    )
}

fn weights<const CLAIMS: usize>(salt: usize) -> [[Gf128Triple; PACKED_INSTANCES]; CLAIMS] {
    core::array::from_fn(|claim| {
        core::array::from_fn(|position| {
            Gf128Triple(core::array::from_fn(|lane| {
                field(salt + claim * 97 + position * 11 + lane * 43)
            }))
        })
    })
}

fn queries<const CLAIMS: usize>(salt: usize) -> [[Gf128; LANES]; CLAIMS] {
    core::array::from_fn(|claim| core::array::from_fn(|lane| field(salt + claim * 19 + lane * 29)))
}

fn main() {
    let setup_started = Instant::now();
    let basis = lagrange_basis();
    let theta_weights = weights::<3>(1);
    let chi_weights = weights::<1>(10_001);
    let setup_seconds = setup_started.elapsed().as_secs_f64();

    let prover_started = Instant::now();
    let mut messages = Vec::with_capacity(2 * KECCAK_ROUNDS);
    for round in 0..KECCAK_ROUNDS {
        messages.push(packed_round_message(
            &basis,
            &theta_weights,
            &queries::<3>(20_001 + round * 101),
        ));
        messages.push(packed_round_message(
            &basis,
            &chi_weights,
            &queries::<1>(30_001 + round * 101),
        ));
    }
    let prover_seconds = prover_started.elapsed().as_secs_f64();
    assert_eq!(messages.len(), 48);
    assert!(
        messages
            .iter()
            .all(|message| { message[PACKED_MESSAGE_COEFFICIENTS - 1] != Gf128Triple::ZERO })
    );

    let verifier_started = Instant::now();
    let mut checksum = Gf128Triple::ZERO;
    for (layer, message) in messages.iter().enumerate() {
        let challenge = core::array::from_fn(|lane| field(40_001 + layer * 101 + lane * 17));
        checksum += evaluate_message(message, challenge);
    }
    let verifier_seconds = verifier_started.elapsed().as_secs_f64();
    black_box(&messages);
    black_box(checksum);
    assert_ne!(checksum, Gf128Triple::ZERO);

    let one_message_size = PACKED_MESSAGE_COEFFICIENTS * LANES * 16;
    let all_messages_size = one_message_size * messages.len();
    println!("scope=binary_gkr_b16_univariate_bridge");
    println!("evidence_class=exact_algebra_release_geometry");
    println!("keccak_rounds={KECCAK_ROUNDS}");
    println!("merged_layers={}", messages.len());
    println!("packed_instances={PACKED_INSTANCES}");
    println!("message_degree=30");
    println!("message_coefficients={PACKED_MESSAGE_COEFFICIENTS}");
    println!("independent_lanes={LANES}");
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
