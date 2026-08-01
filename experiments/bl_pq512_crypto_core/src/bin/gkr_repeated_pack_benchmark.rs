use std::time::Instant;

use bl_pq512_crypto_core::{
    Fp16,
    gkr_sumcheck::{
        prove_repeated_pack_keccak_layer_control, verify_repeated_pack_keccak_layer_control,
    },
    keccak_gkr_wiring::build_keccak_gkr_round,
    packed_boolean_sumcheck::{PACK_BITS, PackedBooleanTable},
};

fn fp16(seed: u32) -> Fp16 {
    Fp16::from_coefficients(core::array::from_fn(|coefficient| {
        (u64::from(seed) + 65_537 * coefficient as u64).rem_euclid(2_147_483_647) as u32
    }))
    .expect("benchmark coordinates are canonical")
}

fn parse_permutations() -> Result<usize, String> {
    let value = std::env::args()
        .nth(1)
        .ok_or_else(|| "permutation_count_missing".to_string())?;
    let permutations = value
        .parse::<usize>()
        .map_err(|_| "permutation_count_invalid".to_string())?;
    if !matches!(permutations, 782 | 894) {
        return Err("permutation_count_must_be_782_or_894".to_string());
    }
    Ok(permutations)
}

fn run() -> Result<(), String> {
    let permutations = parse_permutations()?;
    let group_count = 128;
    let ordinal = 5;
    let layer =
        build_keccak_gkr_round(ordinal).map_err(|error| error.to_string())?[ordinal].clone();
    let groups = (0..group_count)
        .map(|group| {
            core::array::from_fn(|shard| {
                let active = group * PACK_BITS + shard < permutations;
                (0..layer.input_width)
                    .map(|wire| {
                        active
                            && ((wire as u64 + 29 * shard as u64 + 101 * group as u64 + 1)
                                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                                >> 63)
                                == 1
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let group_point = (0..group_count.trailing_zeros() as usize)
        .map(|index| fp16(1_001 + 7 * index as u32))
        .collect::<Vec<_>>();
    let output_point = (0..layer.padded_width.trailing_zeros() as usize)
        .map(|index| fp16(1_101 + 11 * index as u32))
        .collect::<Vec<_>>();
    let repeated_input_width = layer.input_width * group_count;
    let sparse_challenges = (0..2 * repeated_input_width.trailing_zeros() as usize)
        .map(|index| fp16(1_301 + 13 * index as u32))
        .collect::<Vec<_>>();
    let shard_query = fp16(1_901);
    let bridge_challenge = fp16(1_909);

    let table_start = Instant::now();
    let table = PackedBooleanTable::build().map_err(|error| error.to_string())?;
    let table_elapsed = table_start.elapsed();
    let prove_start = Instant::now();
    let (claim, proof, report) = prove_repeated_pack_keccak_layer_control(
        &table,
        &layer,
        &groups,
        &group_point,
        &output_point,
        shard_query,
        bridge_challenge,
        &sparse_challenges,
    )
    .map_err(|error| format!("{error:?}"))?;
    let prove_elapsed = prove_start.elapsed();
    let verify_start = Instant::now();
    verify_repeated_pack_keccak_layer_control(
        &layer,
        group_count,
        claim,
        &group_point,
        &output_point,
        shard_query,
        bridge_challenge,
        &sparse_challenges,
        &proof,
    )
    .map_err(|error| format!("{error:?}"))?;
    let verify_elapsed = verify_start.elapsed();

    println!("permutations={permutations}");
    println!("group_count={group_count}");
    println!("active_groups={}", permutations.div_ceil(PACK_BITS));
    println!("dummy_lanes={}", group_count * PACK_BITS - permutations);
    println!("layer_ordinal={ordinal}");
    println!("layer_gates={}", layer.padded_width);
    println!("repeated_gates={}", report.gates);
    println!("sumcheck_rounds={}", proof.sparse_layer.rounds.len());
    println!("table_bytes={}", report.table_bytes);
    println!("accumulator_bytes={}", report.accumulator_bytes);
    println!("table_build_ns={}", table_elapsed.as_nanos());
    println!("prove_ns={}", prove_elapsed.as_nanos());
    println!("verify_ns={}", verify_elapsed.as_nanos());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("repeated-pack GKR benchmark failed: {error}");
        std::process::exit(1);
    }
}
