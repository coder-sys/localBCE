//! Exact full-schedule control for the relay-free DAG wire tail.
//!
//! This runs all 168 two-source sparse reductions and independent verifications
//! after the shared packed/group coordinate has already been fixed. Completed
//! challenges are deterministic KAT inputs; production must authenticate every
//! message before releasing its challenge.

use std::{hint::black_box, time::Instant};

use bl_pq512_crypto_core::{
    Fp16,
    field::M31_MODULUS,
    gkr_sumcheck::{
        LayerOutputClaim, prove_two_source_sparse_gkr_layer_reference,
        verify_two_source_sparse_gkr_layer_reference,
    },
    keccak_gkr_dag::{KeccakDagGateKind, KeccakDagLayer, build_keccak_gkr_dag_round},
};

const KECCAK_ROUNDS: usize = 24;

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

fn gate_value(kind: KeccakDagGateKind, left: Fp16, right: Fp16) -> Fp16 {
    let xor = left + right - left * right - left * right;
    match kind {
        KeccakDagGateKind::Xor => xor,
        KeccakDagGateKind::NotLeftAndRight => right - left * right,
        KeccakDagGateKind::XorConstant(false) => xor,
        KeccakDagGateKind::XorConstant(true) => Fp16::ONE - xor,
        KeccakDagGateKind::Zero => Fp16::ZERO,
    }
}

fn evaluate_layer(layer: &KeccakDagLayer, left: &[Fp16], right: &[Fp16]) -> Vec<Fp16> {
    layer
        .gates
        .iter()
        .map(|gate| gate_value(gate.kind, left[gate.left], right[gate.right]))
        .collect()
}

fn multilinear_evaluate(values: &[Fp16], point: &[Fp16]) -> Fp16 {
    assert_eq!(values.len(), 1_usize << point.len());
    let mut folded = values.to_vec();
    for challenge in point {
        let half = folded.len() / 2;
        for index in 0..half {
            let zero = folded[2 * index];
            let one = folded[2 * index + 1];
            folded[index] = zero + *challenge * (one - zero);
        }
        folded.truncate(half);
    }
    folded[0]
}

fn main() {
    let setup_started = Instant::now();
    let mut fixtures = Vec::with_capacity(KECCAK_ROUNDS * 7);
    for round in 0..KECCAK_ROUNDS {
        for (layer_index, layer) in build_keccak_gkr_dag_round(round)
            .expect("public Keccak DAG")
            .into_iter()
            .enumerate()
        {
            let salt = 1 + round * 10_001 + layer_index * 1_003;
            let left = (0..layer.left_width)
                .map(|index| field(salt + index * 3))
                .collect::<Vec<_>>();
            let right = (0..layer.right_width)
                .map(|index| field(salt + 100_003 + index * 5))
                .collect::<Vec<_>>();
            let output = evaluate_layer(&layer, &left, &right);
            let output_variables = layer.padded_width.trailing_zeros() as usize;
            let point = (0..output_variables)
                .map(|index| field(salt + 200_003 + index * 7))
                .collect::<Vec<_>>();
            let claim = LayerOutputClaim {
                value: multilinear_evaluate(&output, &point),
                point,
                coefficient: Fp16::ONE,
            };
            let challenge_count = layer.left_width.trailing_zeros() as usize
                + layer.right_width.trailing_zeros() as usize;
            let challenges = (0..challenge_count)
                .map(|index| field(salt + 300_007 + index * 11))
                .collect::<Vec<_>>();
            fixtures.push((layer, left, right, claim, challenges));
        }
    }
    let setup_seconds = setup_started.elapsed().as_secs_f64();

    let prove_started = Instant::now();
    let proofs = fixtures
        .iter()
        .map(|(layer, left, right, claim, challenges)| {
            prove_two_source_sparse_gkr_layer_reference(
                layer,
                left,
                right,
                core::slice::from_ref(claim),
                challenges,
            )
            .expect("exact wire-tail proof")
        })
        .collect::<Vec<_>>();
    let prove_seconds = prove_started.elapsed().as_secs_f64();

    let verify_started = Instant::now();
    for ((layer, _, _, claim, challenges), proof) in fixtures.iter().zip(&proofs) {
        verify_two_source_sparse_gkr_layer_reference(
            layer,
            core::slice::from_ref(claim),
            challenges,
            proof,
        )
        .expect("independent wire-tail verification");
    }
    let verify_seconds = verify_started.elapsed().as_secs_f64();
    let rounds = proofs.iter().map(|proof| proof.rounds.len()).sum::<usize>();
    let message_coefficients = proofs
        .iter()
        .map(|proof| 3 * proof.rounds.len())
        .sum::<usize>();
    black_box(&proofs);

    println!("scope=fp16_relay_free_dag_wire_tail");
    println!("evidence_class=exact_algebra_full_168_layer_schedule");
    println!("keccak_rounds={KECCAK_ROUNDS}");
    println!("layers_per_round=7");
    println!("layers={}", proofs.len());
    println!("wire_sumcheck_rounds={rounds}");
    println!("wire_message_coefficients={message_coefficients}");
    println!("shared_packed_group_coordinate_fixed=true");
    println!("setup_seconds={setup_seconds:.6}");
    println!("all_wire_tail_prove_seconds={prove_seconds:.6}");
    println!("all_wire_tail_verify_seconds={verify_seconds:.6}");
    println!("complete_gkr_qualification=false");
    println!("complete_proof_qualification=false");
}
