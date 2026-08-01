use std::hint::black_box;
use std::time::Instant;

use bl_pq512_crypto_core::field::{Fp16, M31_MODULUS};
use bl_pq512_crypto_core::multilinear_pcs::{
    MLPCS_LDE_LOG_SIZE, derive_two_adic_root, evaluate_packed_boolean_multilinear,
    interpolate_packed_boolean_hypercube,
};
use sha3::{Digest, Sha3_512};

const KECCAK_STATE_BITS: usize = 1_600;

fn main() {
    let permutations: usize = std::env::args()
        .nth(1)
        .expect("usage: multilinear_terminal_benchmark <permutations>")
        .parse()
        .expect("permutations must be an integer");
    let active_evaluations = permutations
        .checked_mul(KECCAK_STATE_BITS)
        .expect("active evaluation count overflow");
    let evaluation_count = active_evaluations.next_power_of_two();
    let mut packed = vec![0_u8; evaluation_count / 8];
    let mut state = 0x6a09_e667_f3bc_c909_u64 ^ permutations as u64;
    for index in 0..active_evaluations {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        packed[index / 8] |= ((state >> 63) as u8) << (index % 8);
    }
    let point: Vec<_> = (0..evaluation_count.ilog2())
        .map(|coordinate| {
            let mut coefficients = [0_u32; 16];
            for (index, coefficient) in coefficients.iter_mut().enumerate() {
                *coefficient = ((coordinate as u64 + 1) * 131
                    + (index as u64 + 3) * 977
                    + permutations as u64)
                    .rem_euclid(M31_MODULUS as u64) as u32;
            }
            Fp16::from_coefficients(coefficients).expect("generated coefficients are canonical")
        })
        .collect();

    let started = Instant::now();
    let value = evaluate_packed_boolean_multilinear(&packed, evaluation_count, &point)
        .expect("fixed-shape terminal evaluation must succeed");
    let elapsed = started.elapsed();
    black_box(value);

    let interpolation_started = Instant::now();
    let coefficients = interpolate_packed_boolean_hypercube(&packed, evaluation_count)
        .expect("fixed-shape interpolation must succeed");
    let interpolation_elapsed = interpolation_started.elapsed();
    black_box(&coefficients);

    let mut digest = Sha3_512::new();
    digest.update(b"BL-PQ512-MLPCS-TERMINAL-BENCHMARK-V1");
    digest.update((permutations as u64).to_be_bytes());
    digest.update((evaluation_count as u64).to_be_bytes());
    digest.update(value.encode());
    digest.update(coefficients[0].encode());
    digest.update(coefficients[evaluation_count / 2].encode());
    digest.update(coefficients[evaluation_count - 1].encode());
    println!("permutations={permutations}");
    println!("active_evaluations={active_evaluations}");
    println!("evaluation_count={evaluation_count}");
    println!("packed_input_bytes={}", packed.len());
    println!("elapsed_ns={}", elapsed.as_nanos());
    println!(
        "interpolation_elapsed_ns={}",
        interpolation_elapsed.as_nanos()
    );
    println!(
        "coefficient_bytes={}",
        coefficients.len() * core::mem::size_of::<Fp16>()
    );
    let root = derive_two_adic_root(MLPCS_LDE_LOG_SIZE).expect("selected LDE root must derive");
    println!(
        "lde_root_coefficients={}",
        root.coefficients()
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("value_sha3_512={:x}", digest.finalize());
}
