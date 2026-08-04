use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    time::Instant,
};

use bl_pq512_crypto_core::{
    merkle::RootHash,
    merkle_multiproof::{CanonicalMerkleMultiProof, canonical_frontier_positions},
};
use sha3::{Digest, Sha3_512};

const PROTOCOL_MAGIC: &[u8; 8] = b"BLZKRSV1";
const PCS_MAGIC: &[u8; 8] = b"BLPQPCS1";
const PCS_VERSION: u16 = 1;
const SEGMENT_LEAF_DOMAIN: u16 = 516;
const THEOREM_8_1_COMPLETE_SEGMENT_COUNTS: [usize; 2] = [21, 37];
const SEGMENT_KIND_BASE: u64 = 32;
const INITIAL_TREE_LEAVES: usize = 1 << 17;
const FP16_SIZE: usize = 64;
const MAIN_MASK_LEAF_SIZE: usize = 64;
const MAIN_MASK_DATA_SIZE: usize = INITIAL_TREE_LEAVES * MAIN_MASK_LEAF_SIZE;
const AUXILIARY_TREE_LEAVES: usize = 1 << 13;
const SUMCHECK_LEAF_SIZE: usize = 9 * 64;
const SUMCHECK_DATA_SIZE: usize = AUXILIARY_TREE_LEAVES * SUMCHECK_LEAF_SIZE;
const GKR_MASK_LEAF_SIZE: usize = 64 * 64;
const GKR_MASK_DATA_SIZE: usize = AUXILIARY_TREE_LEAVES * GKR_MASK_LEAF_SIZE;
const COMPLETE_AUXILIARY_LEAF_SIZE: usize = 74 * 64;
const STATE_SQUAREFREE_LEAF_SIZE: usize = 64;
const STATE_SQUAREFREE_DATA_SIZE: usize = AUXILIARY_TREE_LEAVES * STATE_SQUAREFREE_LEAF_SIZE;
const COMPLETE_AUXILIARY_DATA_SIZE: usize = AUXILIARY_TREE_LEAVES * COMPLETE_AUXILIARY_LEAF_SIZE;
const MAIN_OPENING_COUNT: usize = 1_600;
const AUXILIARY_OPENING_COUNT: usize = 1_218;
const DIGEST_SIZE: usize = 64;

fn read_exact_array<const N: usize>(reader: &mut impl Read) -> io::Result<[u8; N]> {
    let mut value = [0_u8; N];
    reader.read_exact(&mut value)?;
    Ok(value)
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    Ok(u32::from_be_bytes(read_exact_array(reader)?))
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    Ok(u64::from_be_bytes(read_exact_array(reader)?))
}

fn hash_parts(domain: u16, parts: &[&[u8]]) -> [u8; DIGEST_SIZE] {
    let mut hash = Sha3_512::new();
    hash.update(PCS_MAGIC);
    hash.update(PCS_VERSION.to_be_bytes());
    hash.update(domain.to_be_bytes());
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn segment_leaf_hash(
    boundary: u64,
    kind: u64,
    data_size: usize,
    leaf_size: usize,
    leaf_index: usize,
    payload: &[u8],
) -> Result<[u8; DIGEST_SIZE], &'static str> {
    if payload.len() != leaf_size {
        return Err("leaf_size");
    }
    let data_size = u64::try_from(data_size).map_err(|_| "data_size")?;
    let leaf_size = u64::try_from(leaf_size).map_err(|_| "leaf_size")?;
    let leaf_index = u64::try_from(leaf_index).map_err(|_| "leaf_index")?;
    Ok(hash_parts(
        SEGMENT_LEAF_DOMAIN,
        &[
            &boundary.to_be_bytes(),
            &kind.to_be_bytes(),
            &data_size.to_be_bytes(),
            &leaf_size.to_be_bytes(),
            &leaf_index.to_be_bytes(),
            payload,
        ],
    ))
}

fn fail(message: impl core::fmt::Display) -> ! {
    eprintln!("ERR:{message}");
    std::process::exit(2);
}

fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    let mutation_kat = match arguments.as_slice() {
        [_] => false,
        [_, mode] if mode == "--mutation-kat" => true,
        _ => fail("usage: fp16_zk_rs_interleaved_verify [--mutation-kat]"),
    };
    if let Err(error) = run(mutation_kat) {
        fail(error);
    }
}

fn run(mutation_kat: bool) -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());

    let magic =
        read_exact_array::<8>(&mut reader).map_err(|error| format!("protocol_magic:{error}"))?;
    if &magic != PROTOCOL_MAGIC {
        return Err("protocol_magic".to_string());
    }
    let segment_count =
        usize::try_from(read_u32(&mut reader).map_err(|error| format!("segment_count:{error}"))?)
            .map_err(|_| "segment_count".to_string())?;
    if !THEOREM_8_1_COMPLETE_SEGMENT_COUNTS.contains(&segment_count) {
        return Err(format!(
            "segment_count:expected=21|37:actual={segment_count}"
        ));
    }
    let initial_segments = segment_count - 5;
    let segments_per_boundary = initial_segments / 2;
    let interleavings_per_segment = 256 / segments_per_boundary;
    let initial_leaf_size = interleavings_per_segment * FP16_SIZE;
    let initial_data_size = INITIAL_TREE_LEAVES * initial_leaf_size;

    for segment_ordinal in 0..segment_count {
        let boundary = read_u64(&mut reader).map_err(|error| format!("boundary:{error}"))?;
        let kind = read_u64(&mut reader).map_err(|error| format!("kind:{error}"))?;
        let data_size =
            usize::try_from(read_u64(&mut reader).map_err(|error| format!("data_size:{error}"))?)
                .map_err(|_| "data_size".to_string())?;
        let tree_leaves =
            usize::try_from(read_u64(&mut reader).map_err(|error| format!("tree_leaves:{error}"))?)
                .map_err(|_| "tree_leaves".to_string())?;
        let leaf_size =
            usize::try_from(read_u64(&mut reader).map_err(|error| format!("leaf_size:{error}"))?)
                .map_err(|_| "leaf_size".to_string())?;
        let opening_count = usize::try_from(
            read_u32(&mut reader).map_err(|error| format!("opening_count:{error}"))?,
        )
        .map_err(|_| "opening_count".to_string())?;
        let frontier_count = usize::try_from(
            read_u32(&mut reader).map_err(|error| format!("frontier_count:{error}"))?,
        )
        .map_err(|_| "frontier_count".to_string())?;
        let root = read_exact_array::<DIGEST_SIZE>(&mut reader)
            .map_err(|error| format!("root:{error}"))?;

        let (
            expected_boundary,
            expected_kind,
            expected_data_size,
            expected_tree_leaves,
            expected_leaf_size,
            expected_opening_count,
        ) = if segment_ordinal < initial_segments {
            (
                u64::try_from(segment_ordinal / segments_per_boundary).map_err(|_| "boundary")?,
                SEGMENT_KIND_BASE
                    + u64::try_from(segment_ordinal % segments_per_boundary).map_err(|_| "kind")?,
                initial_data_size,
                INITIAL_TREE_LEAVES,
                initial_leaf_size,
                MAIN_OPENING_COUNT,
            )
        } else if segment_ordinal == initial_segments {
            (
                2,
                64,
                SUMCHECK_DATA_SIZE,
                AUXILIARY_TREE_LEAVES,
                SUMCHECK_LEAF_SIZE,
                AUXILIARY_OPENING_COUNT,
            )
        } else if segment_ordinal == initial_segments + 1 {
            (
                2,
                67,
                GKR_MASK_DATA_SIZE,
                AUXILIARY_TREE_LEAVES,
                GKR_MASK_LEAF_SIZE,
                AUXILIARY_OPENING_COUNT,
            )
        } else if segment_ordinal == initial_segments + 2 {
            (
                2,
                65,
                MAIN_MASK_DATA_SIZE,
                INITIAL_TREE_LEAVES,
                MAIN_MASK_LEAF_SIZE,
                MAIN_OPENING_COUNT,
            )
        } else if segment_ordinal == initial_segments + 3 {
            (
                2,
                66,
                COMPLETE_AUXILIARY_DATA_SIZE,
                AUXILIARY_TREE_LEAVES,
                COMPLETE_AUXILIARY_LEAF_SIZE,
                AUXILIARY_OPENING_COUNT,
            )
        } else if segment_ordinal == initial_segments + 4 {
            (
                2,
                68,
                STATE_SQUAREFREE_DATA_SIZE,
                AUXILIARY_TREE_LEAVES,
                STATE_SQUAREFREE_LEAF_SIZE,
                AUXILIARY_OPENING_COUNT,
            )
        } else {
            return Err(format!("segment_ordinal:{segment_ordinal}"));
        };
        if boundary != expected_boundary
            || kind != expected_kind
            || data_size != expected_data_size
            || tree_leaves != expected_tree_leaves
            || leaf_size != expected_leaf_size
            || opening_count != expected_opening_count
        {
            return Err(format!(
                "geometry:segment={segment_ordinal}:boundary={boundary}:kind={kind}:data_size={data_size}:tree_leaves={tree_leaves}:leaf_size={leaf_size}:opening_count={opening_count}"
            ));
        }

        let mut indices = Vec::with_capacity(opening_count);
        for _ in 0..opening_count {
            indices.push(
                usize::try_from(read_u32(&mut reader).map_err(|error| format!("index:{error}"))?)
                    .map_err(|_| "index".to_string())?,
            );
        }
        let frontier_positions = canonical_frontier_positions(tree_leaves, &indices)
            .map_err(|error| format!("frontier_positions:{error:?}"))?;
        if frontier_count != frontier_positions.len() {
            return Err(format!(
                "frontier_count:expected={}:actual={frontier_count}",
                frontier_positions.len()
            ));
        }

        let leaf_payload_size = opening_count
            .checked_mul(leaf_size)
            .ok_or_else(|| "leaf_payload_size".to_string())?;
        let mut leaf_payloads = vec![0_u8; leaf_payload_size];
        reader
            .read_exact(&mut leaf_payloads)
            .map_err(|error| format!("leaf_payloads:{error}"))?;
        let frontier_size = frontier_count
            .checked_mul(DIGEST_SIZE)
            .ok_or_else(|| "frontier_size".to_string())?;
        let mut frontier = vec![0_u8; frontier_size];
        reader
            .read_exact(&mut frontier)
            .map_err(|error| format!("frontier:{error}"))?;

        let proof =
            CanonicalMerkleMultiProof::from_frontier_bytes(tree_leaves, &indices, &frontier)
                .map_err(|error| format!("proof_parse:{error:?}"))?;
        let root = RootHash::from_bytes(root);

        let verify_started = Instant::now();
        let mut leaf_hashes = indices
            .iter()
            .copied()
            .zip(leaf_payloads.chunks_exact(leaf_size))
            .map(|(index, payload)| {
                segment_leaf_hash(boundary, kind, data_size, leaf_size, index, payload)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(str::to_string)?;
        let verified = proof
            .verify_leaf_hashes(tree_leaves, &indices, &leaf_hashes, &root)
            .map_err(|error| format!("verify:{error:?}"))?;
        let verify_seconds = verify_started.elapsed().as_secs_f64();
        if !verified {
            return Err(format!("root_mismatch:segment={segment_ordinal}"));
        }
        writeln!(
            writer,
            "OK segment={segment_ordinal} verify_seconds={verify_seconds:.9}"
        )
        .map_err(|error| format!("stdout:{error}"))?;
        writer.flush().map_err(|error| format!("flush:{error}"))?;

        if mutation_kat {
            let mutation_started = Instant::now();
            leaf_hashes[0][0] ^= 1;
            let leaf_mutation_rejected = !proof
                .verify_leaf_hashes(tree_leaves, &indices, &leaf_hashes, &root)
                .map_err(|error| format!("leaf_mutation:{error:?}"))?;
            leaf_hashes[0][0] ^= 1;

            frontier[0] ^= 1;
            let frontier_mutation =
                CanonicalMerkleMultiProof::from_frontier_bytes(tree_leaves, &indices, &frontier)
                    .map_err(|error| format!("frontier_mutation_parse:{error:?}"))?;
            let frontier_mutation_rejected = !frontier_mutation
                .verify_leaf_hashes(tree_leaves, &indices, &leaf_hashes, &root)
                .map_err(|error| format!("frontier_mutation:{error:?}"))?;
            frontier[0] ^= 1;

            let mut mutated_root = root.into_bytes();
            mutated_root[0] ^= 1;
            let root_mutation_rejected = !proof
                .verify_leaf_hashes(
                    tree_leaves,
                    &indices,
                    &leaf_hashes,
                    &RootHash::from_bytes(mutated_root),
                )
                .map_err(|error| format!("root_mutation:{error:?}"))?;
            let mutation_seconds = mutation_started.elapsed().as_secs_f64();
            if !(leaf_mutation_rejected && frontier_mutation_rejected && root_mutation_rejected) {
                return Err(format!(
                    "mutation_accepted:segment={segment_ordinal}:leaf={leaf_mutation_rejected}:frontier={frontier_mutation_rejected}:root={root_mutation_rejected}"
                ));
            }

            writeln!(
                writer,
                "MUTATION segment={segment_ordinal} mutation_seconds={mutation_seconds:.9} leaf_mutation_rejected=true frontier_mutation_rejected=true root_mutation_rejected=true"
            )
            .map_err(|error| format!("stdout:{error}"))?;
            writer.flush().map_err(|error| format!("flush:{error}"))?;
        }
    }

    writeln!(writer, "DONE segments={segment_count}").map_err(|error| format!("stdout:{error}"))?;
    writer.flush().map_err(|error| format!("flush:{error}"))?;
    Ok(())
}
