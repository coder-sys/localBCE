use std::time::Instant;

use bl_pq512_crypto_core::sha3_coprocessor::execute_bit_sliced_keccak_f1600;
use sha3::{Digest, Sha3_512};

fn parse_instances() -> Result<usize, String> {
    let value = std::env::args()
        .nth(1)
        .ok_or_else(|| "instances_missing".to_string())?;
    let instances = value
        .parse::<usize>()
        .map_err(|_| "instances_invalid".to_string())?;
    if instances == 0 || instances > 1_000_000 {
        return Err("instances_out_of_bounds".to_string());
    }
    Ok(instances)
}

fn run() -> Result<(), String> {
    let instances = parse_instances()?;
    let mut states = (0..instances)
        .map(|instance| {
            core::array::from_fn(|lane| {
                (instance as u64 + 1)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left(lane as u32)
                    ^ lane as u64
            })
        })
        .collect::<Vec<[u64; 25]>>();
    let start = Instant::now();
    let report = execute_bit_sliced_keccak_f1600(&mut states, |_, _| {})
        .map_err(|error| format!("{error:?}"))?;
    let elapsed = start.elapsed();
    let mut digest = Sha3_512::new();
    for state in &states {
        for lane in state {
            digest.update(lane.to_le_bytes());
        }
    }
    println!("instances={instances}");
    println!("rounds={}", report.round_count);
    println!("machine_words_per_plane={}", report.machine_words_per_plane);
    println!("working_bytes={}", report.working_bytes);
    println!("wall_ns={}", elapsed.as_nanos());
    println!(
        "permutations_per_second={:.3}",
        instances as f64 / elapsed.as_secs_f64()
    );
    println!("output_sha3_512={:x}", digest.finalize());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("SHA3 coprocessor benchmark failed: {error}");
        std::process::exit(1);
    }
}
