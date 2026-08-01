use std::hint::black_box;
use std::time::Instant;

use bl_pq512_crypto_core::field::{Fp16, M31, M31_MODULUS};

const ROUNDS: usize = 4_096;

fn main() {
    println!("scope=scalar_field_substrate metric=fp16_and_m31_mix proof_throughput_claim=false");
    for size in [128_usize, 256, 512] {
        run_fp16_case(size);
        run_m31_case(size);
    }
}

fn run_fp16_case(size: usize) {
    let mut values = (0..size)
        .map(|index| deterministic_element(index as u32))
        .collect::<Vec<_>>();
    let factor = deterministic_element(0x51a7);
    let started = Instant::now();
    for round in 0..ROUNDS {
        let addend = deterministic_element(round as u32 + 1);
        for value in &mut values {
            *value = black_box(value.square().mul(factor).add(addend));
        }
    }
    let elapsed = started.elapsed();
    black_box(values);
    let updates = size * ROUNDS;
    let updates_per_second = updates as f64 / elapsed.as_secs_f64();
    println!(
        "case=K{size} field=fp16 scalar_updates={updates} elapsed_seconds={:.6} scalar_updates_per_second={updates_per_second:.2}",
        elapsed.as_secs_f64()
    );
}

fn run_m31_case(size: usize) {
    let mut values = (0..size)
        .map(|index| deterministic_scalar(index as u32))
        .collect::<Vec<_>>();
    let factor = deterministic_scalar(0x51a7);
    let started = Instant::now();
    for round in 0..ROUNDS {
        let addend = deterministic_scalar(round as u32 + 1);
        for value in &mut values {
            *value = black_box(value.square().mul(factor).add(addend));
        }
    }
    let elapsed = started.elapsed();
    black_box(values);
    let updates = size * ROUNDS;
    let updates_per_second = updates as f64 / elapsed.as_secs_f64();
    println!(
        "case=K{size} field=m31 scalar_updates={updates} elapsed_seconds={:.6} scalar_updates_per_second={updates_per_second:.2}",
        elapsed.as_secs_f64()
    );
}

fn deterministic_element(seed: u32) -> Fp16 {
    let mut coefficients = [0_u32; 16];
    for (index, coefficient) in coefficients.iter_mut().enumerate() {
        let mixed = seed
            .wrapping_mul(0x9e37_79b9)
            .wrapping_add((index as u32 + 1).wrapping_mul(0x045d_9f3b));
        *coefficient = mixed % M31_MODULUS;
    }
    Fp16::from_coefficients(coefficients).expect("benchmark generator emits canonical coefficients")
}

fn deterministic_scalar(seed: u32) -> M31 {
    M31::from_canonical(seed.wrapping_mul(0x045d_9f3b) % M31_MODULUS)
        .expect("benchmark generator emits a canonical scalar")
}
