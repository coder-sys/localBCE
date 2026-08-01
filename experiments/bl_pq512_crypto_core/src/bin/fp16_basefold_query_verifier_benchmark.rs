use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use bl_pq512_crypto_core::merkle::{
    ChildHash, LeafHash, MerkleProof, NodeHash, RootHash, hash_leaf, hash_node, hash_root,
};
use sha3::{Digest, Sha3_512};

const QUERY_COUNT: usize = 640;
const LEAF_BYTES: usize = 512;
const MAIN_INITIAL_ORACLES: usize = 3;
const MAIN_INITIAL_DEPTH: usize = 20;
const MAIN_FOLDED_DEPTHS: [usize; 6] = [17, 14, 11, 8, 5, 2];
const AUXILIARY_INITIAL_DEPTH: usize = 13;
const AUXILIARY_FOLDED_DEPTHS: [usize; 4] = [10, 7, 4, 1];

struct QueryCase {
    payload: [u8; LEAF_BYTES],
    proof: MerkleProof,
    root: RootHash,
}

fn deterministic_digest(oracle: usize, query: usize, level: usize) -> [u8; 64] {
    Sha3_512::digest(
        [
            b"BL/PQ512/FP16-BASEFOLD/QUERY-VERIFY-BENCHMARK/v1".as_slice(),
            &u64::try_from(oracle).expect("bounded oracle").to_be_bytes(),
            &u64::try_from(query).expect("bounded query").to_be_bytes(),
            &u64::try_from(level).expect("bounded level").to_be_bytes(),
        ]
        .concat(),
    )
    .into()
}

fn query_index(query: usize, leaf_count: usize) -> usize {
    query.wrapping_mul(0xd6e8_feb8_6659_fd93_usize) & (leaf_count - 1)
}

fn build_case(oracle: usize, query: usize, depth: usize) -> QueryCase {
    let mut payload = [0_u8; LEAF_BYTES];
    for (offset, byte) in payload.iter_mut().enumerate() {
        *byte = oracle
            .wrapping_mul(131)
            .wrapping_add(query.wrapping_mul(17))
            .wrapping_add(offset) as u8;
    }
    let leaf_count = 1_usize << depth;
    let leaf_index = query_index(query, leaf_count);
    let siblings = (0..depth)
        .map(|level| deterministic_digest(oracle, query, level))
        .collect::<Vec<_>>();
    let proof =
        MerkleProof::from_parts(leaf_index, leaf_count, siblings.clone()).expect("valid geometry");

    let mut current = ChildHash::Leaf(hash_leaf(&payload).expect("bounded leaf"));
    let mut index = leaf_index;
    for (level, sibling) in siblings.into_iter().enumerate() {
        let sibling = if level == 0 {
            ChildHash::Leaf(LeafHash::from_bytes(sibling))
        } else {
            ChildHash::Node(NodeHash::from_bytes(sibling))
        };
        current = ChildHash::Node(if index & 1 == 0 {
            hash_node(current, sibling)
        } else {
            hash_node(sibling, current)
        });
        index >>= 1;
    }
    let root = hash_root(u64::try_from(leaf_count).expect("bounded tree"), current)
        .expect("valid root geometry");
    QueryCase {
        payload,
        proof,
        root,
    }
}

fn canonical_multiproof_shape(depth: usize) -> (usize, usize) {
    let leaf_count = 1_usize << depth;
    let mut current = (0..QUERY_COUNT)
        .map(|query| query_index(query, leaf_count))
        .collect::<BTreeSet<_>>();
    let unique_leaves = current.len();
    let mut helpers = 0;
    for _ in 0..depth {
        for &node in &current {
            if !current.contains(&(node ^ 1)) {
                helpers += 1;
            }
        }
        current = current.into_iter().map(|node| node >> 1).collect();
    }
    assert_eq!(current, BTreeSet::from([0]));
    (unique_leaves, helpers)
}

fn main() {
    let workers = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "16".to_string())
        .parse::<usize>()
        .expect("workers must be an integer");
    assert!((1..=64).contains(&workers));

    let mut geometries = vec![(MAIN_INITIAL_DEPTH, MAIN_INITIAL_ORACLES)];
    geometries.extend(MAIN_FOLDED_DEPTHS.into_iter().map(|depth| (depth, 1)));
    geometries.push((AUXILIARY_INITIAL_DEPTH, 2));
    geometries.extend(AUXILIARY_FOLDED_DEPTHS.into_iter().map(|depth| (depth, 1)));

    let total_paths = geometries
        .iter()
        .map(|(_, oracles)| QUERY_COUNT * oracles)
        .sum::<usize>();
    let total_node_hashes = geometries
        .iter()
        .map(|(depth, oracles)| QUERY_COUNT * oracles * depth)
        .sum::<usize>();
    let encoded_path_payload = geometries
        .iter()
        .map(|(depth, oracles)| QUERY_COUNT * oracles * (LEAF_BYTES + depth * 64))
        .sum::<usize>();
    let (canonical_leaf_values, canonical_helper_nodes) = geometries
        .iter()
        .map(|(depth, oracles)| {
            let (leaves, helpers) = canonical_multiproof_shape(*depth);
            (leaves * oracles, helpers * oracles)
        })
        .fold((0, 0), |(leaves, helpers), (next_leaves, next_helpers)| {
            (leaves + next_leaves, helpers + next_helpers)
        });
    let canonical_multiproof_payload =
        canonical_leaf_values * LEAF_BYTES + canonical_helper_nodes * 64;

    let mut cases = Vec::with_capacity(total_paths);
    let mut oracle = 0;
    for (depth, oracle_count) in geometries {
        for _ in 0..oracle_count {
            for query in 0..QUERY_COUNT {
                cases.push(build_case(oracle, query, depth));
            }
            oracle += 1;
        }
    }
    assert_eq!(cases.len(), total_paths);

    let rejected_root = {
        let mut value = cases[0].root.into_bytes();
        value[63] ^= 1;
        RootHash::from_bytes(value)
    };
    assert!(
        !cases[0]
            .proof
            .verify(&cases[0].payload, &rejected_root)
            .expect("mutation verification must run")
    );

    let accepted = AtomicUsize::new(0);
    let chunk = cases.len().div_ceil(workers);
    let started = Instant::now();
    std::thread::scope(|scope| {
        for slice in cases.chunks(chunk) {
            let accepted = &accepted;
            scope.spawn(move || {
                let mut local = 0;
                for case in slice {
                    assert!(
                        case.proof
                            .verify(&case.payload, &case.root)
                            .expect("strict verification must run")
                    );
                    local += 1;
                }
                accepted.fetch_add(local, Ordering::Relaxed);
            });
        }
    });
    let verify_seconds = started.elapsed().as_secs_f64();
    assert_eq!(accepted.load(Ordering::Relaxed), total_paths);

    println!("scope=fp16_basefold_query_verifier");
    println!("evidence_class=exact_candidate_geometry_sha3_512_kernel");
    println!("query_count={QUERY_COUNT}");
    println!("leaf_mb={:.6}", LEAF_BYTES as f64 / 1_000_000.0);
    println!("main_initial_oracles={MAIN_INITIAL_ORACLES}");
    println!("main_initial_depth={MAIN_INITIAL_DEPTH}");
    println!("main_folded_depths=17,14,11,8,5,2");
    println!("auxiliary_initial_oracles=2");
    println!("auxiliary_initial_depth={AUXILIARY_INITIAL_DEPTH}");
    println!("auxiliary_folded_depths=10,7,4,1");
    println!("total_paths={total_paths}");
    println!("total_node_hashes={total_node_hashes}");
    println!(
        "encoded_path_payload_mb={:.6}",
        encoded_path_payload as f64 / 1_000_000.0
    );
    println!("canonical_opened_leaves={canonical_leaf_values}");
    println!("canonical_helper_nodes={canonical_helper_nodes}");
    println!(
        "canonical_multiproof_payload_mb={:.6}",
        canonical_multiproof_payload as f64 / 1_000_000.0
    );
    println!("workers={workers}");
    println!("verify_seconds={verify_seconds:.6}");
    println!("all_paths_verified=true");
    println!("root_mutation_rejected=true");
    println!("proof_system_qualification=false");
}
