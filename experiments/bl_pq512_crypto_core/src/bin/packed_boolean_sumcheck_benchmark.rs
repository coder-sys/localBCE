use std::time::Instant;

use bl_pq512_crypto_core::{
    Fp16,
    packed_boolean_sumcheck::{
        PackedBooleanGate, PackedBooleanTable, reduce_packed_boolean_indexed_parallel,
        reduce_packed_boolean_stream,
    },
};
use sha3::{Digest, Sha3_512};

fn parse_gates() -> Result<usize, String> {
    let value = std::env::args()
        .nth(1)
        .ok_or_else(|| "gate_count_missing".to_string())?;
    let gates = value
        .parse::<usize>()
        .map_err(|_| "gate_count_invalid".to_string())?;
    if gates == 0 || gates > 200_000_000 {
        return Err("gate_count_out_of_bounds".to_string());
    }
    Ok(gates)
}

fn parse_workers() -> Result<usize, String> {
    let value = std::env::args().nth(2).unwrap_or_else(|| "1".to_string());
    let workers = value
        .parse::<usize>()
        .map_err(|_| "worker_count_invalid".to_string())?;
    if workers == 0 || workers > 256 {
        return Err("worker_count_out_of_bounds".to_string());
    }
    Ok(workers)
}

fn run() -> Result<(), String> {
    let gate_count = parse_gates()?;
    let worker_count = parse_workers()?;
    let table_start = Instant::now();
    let table = PackedBooleanTable::build().map_err(|error| error.to_string())?;
    let table_elapsed = table_start.elapsed();
    let weights = (0..256)
        .map(|index| {
            Fp16::from_coefficients(core::array::from_fn(|coefficient| {
                (((index as u64 + 1) * (coefficient as u64 + 3) * 0x9e37_79b9_u64) % 2_147_483_647)
                    as u32
            }))
            .expect("reduced coefficients are canonical")
        })
        .collect::<Vec<_>>();
    let shard_query = Fp16::from_coefficients(core::array::from_fn(|coefficient| {
        ((coefficient as u64 + 17) * 65_537 % 2_147_483_647) as u32
    }))
    .expect("reduced coefficients are canonical");

    let reduction_start = Instant::now();
    let gate_at = |index: usize| {
        let mixed = (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        (
            if index & 3 == 0 {
                PackedBooleanGate::And
            } else {
                PackedBooleanGate::Xor
            },
            mixed as u8,
            mixed.rotate_left(29) as u8,
            weights[index & 255],
        )
    };
    let (polynomial, report) = if worker_count == 1 {
        reduce_packed_boolean_stream(&table, (0..gate_count).map(gate_at), shard_query)
    } else {
        reduce_packed_boolean_indexed_parallel(
            &table,
            gate_count,
            worker_count,
            gate_at,
            shard_query,
        )
    }
    .map_err(|error| error.to_string())?;
    let reduction_elapsed = reduction_start.elapsed();
    let mut digest = Sha3_512::new();
    for coefficient in polynomial {
        digest.update(coefficient.encode());
    }

    println!("gates={gate_count}");
    println!("workers={worker_count}");
    println!("pack_bits=8");
    println!("table_bytes={}", report.table_bytes);
    println!("accumulator_bytes={}", report.accumulator_bytes);
    println!(
        "private_worker_accumulator_bytes={}",
        report.accumulator_bytes * worker_count
    );
    println!("nonzero_product_buckets={}", report.nonzero_product_buckets);
    println!("table_build_ns={}", table_elapsed.as_nanos());
    println!("reduction_ns={}", reduction_elapsed.as_nanos());
    println!(
        "gates_per_second={:.3}",
        gate_count as f64 / reduction_elapsed.as_secs_f64()
    );
    println!("output_sha3_512={:x}", digest.finalize());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("packed Boolean sumcheck benchmark failed: {error}");
        std::process::exit(1);
    }
}
