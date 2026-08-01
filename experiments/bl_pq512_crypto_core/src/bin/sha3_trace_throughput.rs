use std::hint::black_box;
use std::time::Instant;

use bl_pq512_crypto_core::sha3_air::{RATE_BYTES, for_each_sha3_512_trace_row};

const NODE_CALLS: usize = 34_026;
const LEAF_CALLS: usize = 2_048;
const HEADER_CALLS: usize = 6;

fn main() {
    let started = Instant::now();
    let mut trace_rows = 0_usize;
    let mut calls = 0_usize;
    let mut permutations = 0_usize;

    run_calls(
        141,
        NODE_CALLS,
        &mut calls,
        &mut permutations,
        &mut trace_rows,
    );
    run_calls(
        212,
        LEAF_CALLS,
        &mut calls,
        &mut permutations,
        &mut trace_rows,
    );
    run_calls(
        84,
        HEADER_CALLS,
        &mut calls,
        &mut permutations,
        &mut trace_rows,
    );

    assert_eq!(calls, 36_080);
    assert_eq!(permutations, 74_208);
    assert_eq!(trace_rows, 1_780_992);
    let elapsed = started.elapsed();
    println!(
        "scope=k128_economic_fixed_privacy_sha3_trace proof_throughput_claim=false calls={calls} permutations={permutations} trace_rows={trace_rows} elapsed_seconds={:.6} trace_rows_per_second={:.2}",
        elapsed.as_secs_f64(),
        trace_rows as f64 / elapsed.as_secs_f64(),
    );
}

fn run_calls(
    message_bytes: usize,
    count: usize,
    calls: &mut usize,
    permutations: &mut usize,
    trace_rows: &mut usize,
) {
    let mut message = vec![0_u8; message_bytes];
    for ordinal in 0..count {
        message[..8].copy_from_slice(&(ordinal as u64).to_be_bytes());
        let digest =
            for_each_sha3_512_trace_row(&message, message_bytes, |_, _, _, _, _, witness| {
                *trace_rows += 1;
                black_box(witness.output_bytes[0]);
            })
            .expect("benchmark capacities exactly match their messages");
        black_box(digest);
        *calls += 1;
        *permutations += message_bytes / RATE_BYTES as usize + 1;
    }
}
