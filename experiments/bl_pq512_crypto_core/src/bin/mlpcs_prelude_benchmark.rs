use std::time::Instant;

use bl_pq512_crypto_core::{
    Fp16, M31,
    field::M31_MODULUS,
    multilinear_pcs::{
        MLPCS_AUXILIARY_MASK_VARIABLES, MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE, MLPCS_INPUT_LOG_SIZE,
        MultilinearOpeningClaim, PackedGkrInputClaims, evaluate_multilinear,
    },
    multilinear_pcs_transcript::prove_selected_multilinear_pcs_prelude_control,
    packed_boolean_sumcheck::{PACK_BITS, packed_lagrange_node_weights},
};
use sha3::{Digest, Sha3_512};

fn fp(value: u32) -> Fp16 {
    Fp16::from_m31(M31::from_canonical(value % M31_MODULUS).unwrap())
}

fn interpolate_shards(evaluations: &[Fp16], shard_query: Fp16, wire_variables: u8) -> Vec<Fp16> {
    let wire_count = 1_usize << wire_variables;
    let group_count = evaluations.len() / (wire_count * PACK_BITS);
    let lagrange = packed_lagrange_node_weights(shard_query).unwrap();
    let mut interpolated = vec![Fp16::ZERO; wire_count * group_count];
    for group in 0..group_count {
        for wire in 0..wire_count {
            interpolated[group * wire_count + wire] =
                (0..PACK_BITS).fold(Fp16::ZERO, |sum, shard| {
                    let index = wire + wire_count * (shard + PACK_BITS * group);
                    sum + lagrange[shard] * evaluations[index]
                });
        }
    }
    interpolated
}

fn main() {
    let allocation_started = Instant::now();
    let main_evaluations = (0..1_usize << MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
        .map(|index| fp((index as u32).wrapping_mul(65_537).wrapping_add(17)))
        .collect::<Vec<_>>();
    let auxiliary_evaluations = (0..1_usize << MLPCS_AUXILIARY_MASK_VARIABLES)
        .map(|index| fp((index as u32).wrapping_mul(8_191).wrapping_add(29)))
        .collect::<Vec<_>>();
    let base_variables = MLPCS_INPUT_LOG_SIZE - PACK_BITS.trailing_zeros() as u8;
    let shard_query = fp(97);
    let wire_variables = 11_u8;
    let opening_points = [
        (0..base_variables)
            .map(|index| fp(101 + u32::from(index) * 2))
            .collect::<Vec<_>>(),
        (0..base_variables)
            .map(|index| fp(151 + u32::from(index) * 2))
            .collect::<Vec<_>>(),
    ];
    let interpolated_input = interpolate_shards(
        &main_evaluations[..1_usize << MLPCS_INPUT_LOG_SIZE],
        shard_query,
        wire_variables,
    );
    let opening_claims = PackedGkrInputClaims {
        claims: [
            MultilinearOpeningClaim {
                point: opening_points[0].clone(),
                value: evaluate_multilinear(&interpolated_input, &opening_points[0]).unwrap(),
            },
            MultilinearOpeningClaim {
                point: opening_points[1].clone(),
                value: evaluate_multilinear(&interpolated_input, &opening_points[1]).unwrap(),
            },
        ],
        shard_query,
        wire_variables,
    };
    let batch_challenges = (0..MLPCS_HIDDEN_POLYNOMIAL_LOG_SIZE)
        .map(|index| fp(211 + u32::from(index) * 2))
        .collect::<Vec<_>>();
    let allocation_seconds = allocation_started.elapsed().as_secs_f64();

    let prove_started = Instant::now();
    let (opening_values, proof) = prove_selected_multilinear_pcs_prelude_control(
        main_evaluations,
        auxiliary_evaluations,
        &opening_claims,
        fp(59),
        fp(61),
        fp(67),
        fp(71),
        &batch_challenges,
    )
    .expect("selected prelude control must prove");
    let prove_seconds = prove_started.elapsed().as_secs_f64();
    let encoded = proof.encode().expect("selected prelude must encode");
    let digest = Sha3_512::digest(&encoded);
    println!("allocation_seconds={allocation_seconds:.9}");
    println!("prove_seconds={prove_seconds:.9}");
    println!("proof_bytes={}", encoded.len());
    println!(
        "opening_values={:?},{:?}",
        opening_values[0].coefficients(),
        opening_values[1].coefficients()
    );
    println!("proof_sha3_512={digest:x}");
    println!("mode=scalar_reference_completed_challenges_not_production_transcript");
}
