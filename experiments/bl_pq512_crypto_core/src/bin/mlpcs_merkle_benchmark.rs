use std::hint::black_box;
use std::time::Instant;

use bl_pq512_crypto_core::merkle::MerkleTree;

const FP16_BYTES: usize = 64;
const ELEMENTS_PER_LEAF: usize = 16;

fn main() {
    let log_elements: u32 = std::env::args()
        .nth(1)
        .expect("usage: mlpcs_merkle_benchmark <log_elements>")
        .parse()
        .expect("log_elements must be an integer");
    let workers: usize = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "16".to_string())
        .parse()
        .expect("workers must be an integer");
    let commitment_count: usize = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "1".to_string())
        .parse()
        .expect("commitment_count must be an integer");
    if !(1..=22).contains(&commitment_count) {
        panic!("commitment_count must be in 1..=22");
    }
    if !(4..=25).contains(&log_elements) {
        panic!("log_elements must be in 4..=25");
    }
    let element_count = 1_usize << log_elements;
    let payload_bytes = element_count * FP16_BYTES;
    let leaf_bytes = ELEMENTS_PER_LEAF * FP16_BYTES;
    let leaf_count = payload_bytes / leaf_bytes;

    let fill_started = Instant::now();
    let mut payload = vec![0_u8; payload_bytes];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = (index as u64)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .rotate_left((index & 63) as u32) as u8;
    }
    let fill_elapsed = fill_started.elapsed();
    let commit_started = Instant::now();
    let mut roots = Vec::with_capacity(commitment_count);
    for round in 0..commitment_count {
        let round_bytes = payload_bytes >> round;
        let leaves = payload[..round_bytes]
            .chunks_exact(leaf_bytes)
            .collect::<Vec<_>>();
        let tree = MerkleTree::from_leaf_payloads_parallel(&leaves, workers)
            .expect("selected tree shape must commit");
        roots.push(tree.root());
    }
    let commit_elapsed = commit_started.elapsed();
    black_box(&roots);
    println!("log_elements={log_elements}");
    println!("element_count={element_count}");
    println!("payload_bytes={payload_bytes}");
    println!("leaf_bytes={leaf_bytes}");
    println!("leaf_count={leaf_count}");
    println!("workers={workers}");
    println!("commitment_count={commitment_count}");
    println!("fill_elapsed_ns={}", fill_elapsed.as_nanos());
    println!("commit_elapsed_ns={}", commit_elapsed.as_nanos());
    println!("first_root={:02x?}", roots[0].into_bytes());
    println!("last_root={:02x?}", roots[roots.len() - 1].into_bytes());
}
