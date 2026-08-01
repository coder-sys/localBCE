use std::hint::black_box;
use std::time::Instant;

use bl_pq512_crypto_core::keccak_gkr_wiring::execute_packed_keccak_gkr_circuit;

fn main() {
    let instances: usize = std::env::args()
        .nth(1)
        .expect("usage: gkr_packed_boundary_benchmark <instances>")
        .parse()
        .expect("instances must be an integer");
    let mut states: Vec<[u64; 25]> = (0..instances)
        .map(|instance| {
            core::array::from_fn(|lane| {
                (instance as u64 + 1)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left(lane as u32)
            })
        })
        .collect();
    let mut boundaries = Vec::with_capacity(216);
    let started = Instant::now();
    execute_packed_keccak_gkr_circuit(&mut states, |_, _, _, values| {
        boundaries.push(values.to_vec());
    })
    .expect("packed circuit execution must succeed");
    let elapsed = started.elapsed();
    let boundary_bytes: usize = boundaries
        .iter()
        .map(|boundary| boundary.len() * core::mem::size_of::<u64>())
        .sum();
    let checksum = boundaries
        .iter()
        .flat_map(|boundary| boundary.iter())
        .fold(0_u64, |accumulator, value| {
            accumulator.rotate_left(1) ^ value
        });
    black_box(&boundaries);
    println!("instances={instances}");
    println!("layers={}", boundaries.len());
    println!("elapsed_ns={}", elapsed.as_nanos());
    println!("boundary_bytes={boundary_bytes}");
    println!("checksum={checksum:016x}");
}
