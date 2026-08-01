use std::{collections::BTreeSet, hint::black_box, time::Instant};

use bl_pq512_crypto_core::merkle::{MerkleProof, stateless_root_and_frontier_parallel};

const B128_BYTES: usize = 16;

fn main() {
    let log_message_length: u32 = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "21".to_string())
        .parse()
        .expect("log_message_length must be an integer");
    let workers: usize = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "16".to_string())
        .parse()
        .expect("workers must be an integer");
    let query_count: usize = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "617".to_string())
        .parse()
        .expect("query_count must be an integer");
    let log_zk_expansion: u32 = std::env::args()
        .nth(4)
        .unwrap_or_else(|| "2".to_string())
        .parse()
        .expect("log_zk_expansion must be an integer");
    let log_elements_per_leaf: u32 = std::env::args()
        .nth(5)
        .unwrap_or_else(|| "1".to_string())
        .parse()
        .expect("log_elements_per_leaf must be an integer");
    let oracle_count: usize = std::env::args()
        .nth(6)
        .unwrap_or_else(|| "1".to_string())
        .parse()
        .expect("oracle_count must be an integer");
    if !(4..=24).contains(&log_message_length) {
        panic!("log_message_length must be in 4..=24");
    }
    if query_count == 0 {
        panic!("query_count must be positive");
    }
    if !(1..=4).contains(&log_zk_expansion) {
        panic!("log_zk_expansion must be in 1..=4");
    }
    if log_elements_per_leaf > log_message_length + log_zk_expansion {
        panic!("log_elements_per_leaf exceeds the codeword geometry");
    }
    if !(1..=8).contains(&oracle_count) {
        panic!("oracle_count must be in 1..=8");
    }

    let codeword_elements = 1_usize << (log_message_length + log_zk_expansion);
    let codeword_mb = codeword_elements * B128_BYTES;
    let elements_per_leaf = 1_usize << log_elements_per_leaf;
    let leaf_bytes = B128_BYTES * elements_per_leaf;
    let leaf_count = codeword_elements / elements_per_leaf;
    let depth = leaf_count.ilog2() as usize;

    let mut codeword = vec![0_u8; codeword_mb];
    let query_indices = (0..query_count)
        .map(|draw| {
            let mixed = (draw as u64)
                .wrapping_mul(0xd6e8_feb8_6659_fd93)
                .rotate_left((draw & 63) as u32);
            (mixed as usize) & (leaf_count - 1)
        })
        .collect::<Vec<_>>();
    let mut target_set = BTreeSet::new();
    for &query in &query_indices {
        for level in 0..depth {
            target_set.insert((level, (query >> level) ^ 1));
        }
    }
    let targets = target_set.into_iter().collect::<Vec<_>>();

    let mut fill_seconds = 0.0;
    let mut commit_seconds = 0.0;
    let mut replay_seconds = 0.0;
    let mut verify_seconds = 0.0;
    let mut roots = Vec::with_capacity(oracle_count);
    for oracle_index in 0..oracle_count {
        let fill_started = Instant::now();
        for (index, byte) in codeword.iter_mut().enumerate() {
            *byte = (index as u64)
                .wrapping_add((oracle_index as u64).wrapping_mul(0xd6e8_feb8_6659_fd93))
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .rotate_left((index & 63) as u32) as u8;
        }
        fill_seconds += fill_started.elapsed().as_secs_f64();

        let commit_started = Instant::now();
        let commitment = stateless_root_and_frontier_parallel::<&[u8], _>(
            leaf_count,
            &[],
            workers,
            |leaf_index| {
                let start = leaf_index * leaf_bytes;
                &codeword[start..start + leaf_bytes]
            },
        )
        .expect("stateless commitment must succeed");
        commit_seconds += commit_started.elapsed().as_secs_f64();

        let replay_started = Instant::now();
        let replay = stateless_root_and_frontier_parallel::<&[u8], _>(
            leaf_count,
            &targets,
            workers,
            |leaf_index| {
                let start = leaf_index * leaf_bytes;
                &codeword[start..start + leaf_bytes]
            },
        )
        .expect("stateless frontier replay must succeed");
        replay_seconds += replay_started.elapsed().as_secs_f64();
        assert_eq!(replay.root(), commitment.root());

        let verify_started = Instant::now();
        for &query in &query_indices {
            let siblings = (0..depth)
                .map(|level| {
                    *replay
                        .frontier_node(level, (query >> level) ^ 1)
                        .expect("requested sibling must be present")
                })
                .collect::<Vec<_>>();
            let proof = MerkleProof::from_parts(query, leaf_count, siblings)
                .expect("frontier must form a strict proof");
            let start = query * leaf_bytes;
            assert!(
                proof
                    .verify(&codeword[start..start + leaf_bytes], &replay.root())
                    .expect("strict proof verification must run")
            );
        }
        verify_seconds += verify_started.elapsed().as_secs_f64();
        roots.push(replay.root());
        black_box(&replay);
    }
    black_box(&codeword);
    black_box(&roots);

    println!("scope=zk_basefold_stateless_sha3_512_merkle");
    println!("evidence_class=exact_geometry_synthetic_payload");
    println!("log_message_length={log_message_length}");
    println!("log_zk_expansion={log_zk_expansion}");
    println!("codeword_elements={codeword_elements}");
    println!("codeword_mb={:.6}", codeword_mb as f64 / 1_000_000.0);
    println!("oracle_count={oracle_count}");
    println!(
        "total_committed_volume_mb={:.6}",
        oracle_count as f64 * codeword_mb as f64 / 1_000_000.0
    );
    println!("log_elements_per_leaf={log_elements_per_leaf}");
    println!("elements_per_leaf={elements_per_leaf}");
    println!("leaf_bytes={leaf_bytes}");
    println!("leaf_count={leaf_count}");
    println!("tree_depth={depth}");
    println!("workers={workers}");
    println!("query_count={query_count}");
    println!("distinct_frontier_nodes={}", targets.len());
    println!(
        "frontier_mb={:.6}",
        targets.len() as f64 * 64.0 / 1_000_000.0
    );
    println!("fill_seconds={fill_seconds:.6}");
    println!("commit_seconds={commit_seconds:.6}");
    println!("replay_seconds={replay_seconds:.6}");
    println!("verify_seconds={verify_seconds:.6}");
    println!("roots_match=true");
    println!("all_query_proofs_verified=true");
    println!("proof_system_qualification=false");
}
