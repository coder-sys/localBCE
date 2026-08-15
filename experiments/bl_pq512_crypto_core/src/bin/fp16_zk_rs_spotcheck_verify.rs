use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    sync::{Arc, mpsc},
    thread,
    time::Instant,
};

use bl_pq512_crypto_core::field::Fp16;
use sha3::{Digest, Sha3_512};

const INPUT_MAGIC: &[u8; 8] = b"BLSPOT05";
const OUTPUT_MAGIC: &[u8; 8] = b"BLSPOUT1";
const INTERLEAVINGS: usize = 512;
const MAIN_QUERIES: usize = 1_600;
const AUXILIARY_QUERIES: usize = 1_218;
const SUMCHECK_WORDS: usize = 9;
const NON_GKR_AUXILIARY_WORDS: usize = SUMCHECK_WORDS + 1;
const SUMCHECK_BASE_WORDS: usize = SUMCHECK_WORDS + NON_GKR_AUXILIARY_WORDS;
const GKR_MASK_OUTER_LOG: u32 = 7;
const GKR_MASK_OUTER_CODE_VALUES: usize = 1 << GKR_MASK_OUTER_LOG;
const FP16_BYTES: usize = 64;
const PCS_MAGIC: &[u8; 8] = b"BLPQPCS1";
const PCS_VERSION: u16 = 1;
const QUERY_DOMAIN: u16 = 524;
const GKR_MASK_OUTER_QUERY_DOMAIN: u16 = 526;
const GKR_MASK_OUTER_QUERY_LABEL: &[u8] = b"gkr_mask_outer_queries/v1";
const AUXILIARY_TREE_LEAVES: usize = 1 << 13;
const QUERY_MAX_DRAWS: u64 = 1 << 20;
const QUERY_MAX_RETRIES_PER_DRAW: u64 = 1 << 20;

fn read_fp16(reader: &mut impl Read) -> Result<Fp16, String> {
    let mut encoded = [0_u8; FP16_BYTES];
    reader
        .read_exact(&mut encoded)
        .map_err(|error| format!("read:{error}"))?;
    Fp16::decode(&encoded).map_err(|error| format!("fp16:{error:?}"))
}

fn read_u32(reader: &mut impl Read) -> Result<u32, String> {
    let mut encoded = [0_u8; 4];
    reader
        .read_exact(&mut encoded)
        .map_err(|error| format!("read_u32:{error}"))?;
    Ok(u32::from_be_bytes(encoded))
}

fn read_values(reader: &mut impl Read, count: usize) -> Result<Vec<Fp16>, String> {
    let encoded_size = count
        .checked_mul(FP16_BYTES)
        .ok_or_else(|| "read_values_size".to_string())?;
    let mut encoded = vec![0_u8; encoded_size];
    reader
        .read_exact(&mut encoded)
        .map_err(|error| format!("read_values:{error}"))?;
    encoded
        .chunks_exact(FP16_BYTES)
        .map(|value| {
            let value: &[u8; FP16_BYTES] = value
                .try_into()
                .map_err(|_| "read_values_chunk".to_string())?;
            Fp16::decode(value).map_err(|error| format!("fp16:{error:?}"))
        })
        .collect()
}

fn hash_parts(domain: u16, parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    hash.update(PCS_MAGIC);
    hash.update(PCS_VERSION.to_be_bytes());
    hash.update(domain.to_be_bytes());
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn exact_queries(
    state: &[u8; 64],
    label: &[u8],
    bound: usize,
    count: usize,
) -> Result<Vec<usize>, String> {
    if bound == 0 || count == 0 || count > bound {
        return Err("query_geometry".to_string());
    }
    let bound_u64 = u64::try_from(bound).map_err(|_| "query_bound".to_string())?;
    let threshold = ((1_u128 << 64) - u128::from(bound_u64)) % u128::from(bound_u64);
    let mut queries = Vec::with_capacity(count);
    let mut seen = std::collections::BTreeSet::new();
    let mut draw = 0_u64;
    while queries.len() < count {
        if draw >= QUERY_MAX_DRAWS {
            return Err("query_draw_limit".to_string());
        }
        let mut retry = 0_u64;
        loop {
            if retry >= QUERY_MAX_RETRIES_PER_DRAW {
                return Err("query_retry_limit".to_string());
            }
            let digest = hash_parts(
                QUERY_DOMAIN,
                &[state, label, &draw.to_be_bytes(), &retry.to_be_bytes()],
            );
            let random_word = u64::from_le_bytes(
                digest[..8]
                    .try_into()
                    .map_err(|_| "query_digest".to_string())?,
            );
            let product = u128::from(random_word) * u128::from(bound_u64);
            if (product & u128::from(u64::MAX)) >= threshold {
                let candidate =
                    usize::try_from(product >> 64).map_err(|_| "query_candidate".to_string())?;
                if seen.insert(candidate) {
                    queries.push(candidate);
                    break;
                }
            }
            retry = retry
                .checked_add(1)
                .ok_or_else(|| "query_retry".to_string())?;
        }
        draw = draw
            .checked_add(1)
            .ok_or_else(|| "query_draw".to_string())?;
    }
    queries.sort_unstable();
    Ok(queries)
}

fn gkr_mask_outer_coordinates(state: &[u8; 64], inner: &[usize]) -> Result<Vec<usize>, String> {
    inner
        .iter()
        .copied()
        .enumerate()
        .map(|(ordinal, inner_query)| {
            let ordinal =
                u64::try_from(ordinal).map_err(|_| "gkr_mask_query_ordinal".to_string())?;
            let inner_query =
                u32::try_from(inner_query).map_err(|_| "gkr_mask_inner_query".to_string())?;
            let digest = hash_parts(
                GKR_MASK_OUTER_QUERY_DOMAIN,
                &[
                    state,
                    GKR_MASK_OUTER_QUERY_LABEL,
                    &ordinal.to_be_bytes(),
                    &inner_query.to_be_bytes(),
                ],
            );
            let random_word = u64::from_le_bytes(
                digest[..8]
                    .try_into()
                    .map_err(|_| "gkr_mask_outer_query".to_string())?,
            );
            usize::try_from((u128::from(random_word) * GKR_MASK_OUTER_CODE_VALUES as u128) >> 64)
                .map_err(|_| "gkr_mask_outer_query".to_string())
        })
        .collect()
}

fn fold_initial_openings(
    reader: &mut impl Read,
    weights: &[Fp16],
    initial_segments: usize,
    words_per_segment: usize,
) -> Result<Vec<Fp16>, String> {
    let workers = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(16)
        .min(MAIN_QUERIES);
    let query_chunk = MAIN_QUERIES.div_ceil(workers);
    thread::scope(|scope| {
        let mut senders = Vec::with_capacity(workers);
        let mut handles = Vec::with_capacity(workers);
        for start in (0..MAIN_QUERIES).step_by(query_chunk) {
            let end = MAIN_QUERIES.min(start + query_chunk);
            let (sender, receiver) = mpsc::sync_channel::<(usize, Arc<Vec<u8>>)>(1);
            senders.push(sender);
            handles.push(scope.spawn(move || {
                let mut folded = vec![Fp16::ZERO; end - start];
                while let Ok((segment, encoded)) = receiver.recv() {
                    let segment_weights =
                        &weights[segment * words_per_segment..(segment + 1) * words_per_segment];
                    for (local_query, accumulator) in folded.iter_mut().enumerate() {
                        let query = start + local_query;
                        let row_offset = query * words_per_segment * FP16_BYTES;
                        for (word, weight) in segment_weights.iter().enumerate() {
                            let value_offset = row_offset + word * FP16_BYTES;
                            let value: &[u8; FP16_BYTES] = encoded
                                [value_offset..value_offset + FP16_BYTES]
                                .try_into()
                                .map_err(|_| {
                                    (
                                        segment * MAIN_QUERIES * words_per_segment
                                            + query * words_per_segment
                                            + word,
                                        "read_values_chunk".to_string(),
                                    )
                                })?;
                            let value = Fp16::decode(value).map_err(|error| {
                                (
                                    segment * MAIN_QUERIES * words_per_segment
                                        + query * words_per_segment
                                        + word,
                                    format!("fp16:{error:?}"),
                                )
                            })?;
                            *accumulator = *accumulator + value * *weight;
                        }
                    }
                }
                Ok::<_, (usize, String)>((start, folded))
            }));
        }

        let encoded_size = MAIN_QUERIES
            .checked_mul(words_per_segment)
            .and_then(|count| count.checked_mul(FP16_BYTES))
            .ok_or_else(|| "read_values_size".to_string())?;
        let mut input_error = None;
        let mut send_failed = false;
        for segment in 0..initial_segments {
            let mut encoded = vec![0_u8; encoded_size];
            if let Err(error) = reader.read_exact(&mut encoded) {
                input_error = Some(format!("read_values:{error}"));
                break;
            }
            let encoded = Arc::new(encoded);
            for sender in &senders {
                if sender.send((segment, Arc::clone(&encoded))).is_err() {
                    send_failed = true;
                    break;
                }
            }
            if send_failed {
                break;
            }
        }
        drop(senders);

        let mut pieces = Vec::with_capacity(handles.len());
        let mut decode_error = None;
        for handle in handles {
            match handle
                .join()
                .map_err(|_| "initial_spotcheck_worker_panicked".to_string())?
            {
                Ok(piece) => pieces.push(piece),
                Err(error) => {
                    if decode_error
                        .as_ref()
                        .is_none_or(|(index, _)| error.0 < *index)
                    {
                        decode_error = Some(error);
                    }
                }
            }
        }
        if let Some((_, error)) = decode_error {
            return Err(error);
        }
        if let Some(error) = input_error {
            return Err(error);
        }
        if send_failed {
            return Err("initial_spotcheck_channel".to_string());
        }
        pieces.sort_unstable_by_key(|(start, _)| *start);
        let mut folded = Vec::with_capacity(MAIN_QUERIES);
        for (_, piece) in pieces {
            folded.extend(piece);
        }
        if folded.len() != MAIN_QUERIES {
            return Err("initial_spotcheck_length".to_string());
        }
        Ok(folded)
    })
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let started = Instant::now();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    let mut magic = [0_u8; 8];
    reader
        .read_exact(&mut magic)
        .map_err(|error| format!("magic:{error}"))?;
    if &magic != INPUT_MAGIC {
        return Err("magic".to_string());
    }
    let initial_segments =
        usize::try_from(read_u32(&mut reader)?).map_err(|_| "initial_segments".to_string())?;
    let words_per_segment =
        usize::try_from(read_u32(&mut reader)?).map_err(|_| "words_per_segment".to_string())?;
    if !matches!((initial_segments, words_per_segment), (32, 16) | (16, 32)) {
        return Err(format!(
            "initial_geometry:{initial_segments}:{words_per_segment}"
        ));
    }
    let mut query_seed = [0_u8; 64];
    reader
        .read_exact(&mut query_seed)
        .map_err(|error| format!("query_seed:{error}"))?;
    Fp16::decode(&query_seed).map_err(|error| format!("query_seed:{error:?}"))?;
    let auxiliary_queries = exact_queries(
        &query_seed,
        b"aux_queries",
        AUXILIARY_TREE_LEAVES,
        AUXILIARY_QUERIES,
    )?;
    let tensor_queries = gkr_mask_outer_coordinates(&query_seed, &auxiliary_queries)?;
    if tensor_queries.len() != AUXILIARY_QUERIES {
        return Err("tensor_query_shape".to_string());
    }
    let weights = read_values(&mut reader, INTERLEAVINGS)?;
    let combination = read_fp16(&mut reader)?;
    let folded = fold_initial_openings(&mut reader, &weights, initial_segments, words_per_segment)?;
    let sumcheck_and_base = read_values(&mut reader, AUXILIARY_QUERIES * SUMCHECK_BASE_WORDS)?;
    let gkr_mask = read_values(&mut reader, AUXILIARY_QUERIES)?;
    let state_squarefree = read_values(&mut reader, AUXILIARY_QUERIES)?;
    let base_main = read_values(&mut reader, MAIN_QUERIES)?;
    let base_gkr_mask = read_values(&mut reader, AUXILIARY_QUERIES)?;
    let answer_main = read_values(&mut reader, MAIN_QUERIES)?;
    let answer_auxiliary = read_values(&mut reader, AUXILIARY_QUERIES * NON_GKR_AUXILIARY_WORDS)?;
    let answer_gkr_mask = read_values(&mut reader, AUXILIARY_QUERIES)?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("trailing:{error}"))?
        != 0
    {
        return Err("trailing_input".to_string());
    }
    let workers = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(16)
        .min(MAIN_QUERIES);
    let query_chunk = MAIN_QUERIES.div_ceil(workers);
    thread::scope(|scope| -> Result<(), String> {
        let handles = (0..MAIN_QUERIES)
            .step_by(query_chunk)
            .map(|start| {
                let end = MAIN_QUERIES.min(start + query_chunk);
                let folded = &folded;
                let base_main = &base_main;
                let answer_main = &answer_main;
                scope.spawn(move || {
                    (start..end).find(|&query| {
                        answer_main[query] != base_main[query] + folded[query] * combination
                    })
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            if let Some(query) = handle
                .join()
                .map_err(|_| "main_spotcheck_worker_panicked".to_string())?
            {
                return Err(format!("main_spotcheck:{query}"));
            }
        }
        Ok(())
    })?;
    let workers = thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(16)
        .min(AUXILIARY_QUERIES);
    let query_chunk = AUXILIARY_QUERIES.div_ceil(workers);
    thread::scope(|scope| -> Result<(), String> {
        let handles = (0..AUXILIARY_QUERIES)
            .step_by(query_chunk)
            .map(|start| {
                let end = AUXILIARY_QUERIES.min(start + query_chunk);
                let sumcheck_and_base = &sumcheck_and_base;
                let gkr_mask = &gkr_mask;
                let base_gkr_mask = &base_gkr_mask;
                let answer_gkr_mask = &answer_gkr_mask;
                let state_squarefree = &state_squarefree;
                let answer_auxiliary = &answer_auxiliary;
                scope.spawn(move || {
                    for query in start..end {
                        for word in 0..SUMCHECK_WORDS {
                            let source = sumcheck_and_base[query * SUMCHECK_BASE_WORDS + word];
                            let base = sumcheck_and_base
                                [query * SUMCHECK_BASE_WORDS + SUMCHECK_WORDS + word];
                            let index = query * NON_GKR_AUXILIARY_WORDS + word;
                            if answer_auxiliary[index] != base + source * combination {
                                return Some((query, word));
                            }
                        }
                        let squarefree_word = NON_GKR_AUXILIARY_WORDS - 1;
                        let squarefree_index = query * NON_GKR_AUXILIARY_WORDS + squarefree_word;
                        let squarefree_base = sumcheck_and_base
                            [query * SUMCHECK_BASE_WORDS + SUMCHECK_WORDS + squarefree_word];
                        if answer_auxiliary[squarefree_index]
                            != squarefree_base + state_squarefree[query] * combination
                        {
                            return Some((query, squarefree_word));
                        }
                        if answer_gkr_mask[query]
                            != base_gkr_mask[query] + gkr_mask[query] * combination
                        {
                            return Some((query, SUMCHECK_WORDS));
                        }
                    }
                    None
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            if let Some((query, word)) = handle
                .join()
                .map_err(|_| "auxiliary_spotcheck_worker_panicked".to_string())?
            {
                return Err(format!("auxiliary_spotcheck:{query}:{word}"));
            }
        }
        Ok(())
    })?;
    writer
        .write_all(OUTPUT_MAGIC)
        .and_then(|_| writer.write_all(&started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("output:{error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{FP16_BYTES, MAIN_QUERIES, fold_initial_openings};
    use bl_pq512_crypto_core::field::Fp16;

    #[test]
    fn streamed_parallel_initial_fold_accepts_canonical_zeroes() {
        let words = 16;
        let mut encoded = Cursor::new(vec![0_u8; MAIN_QUERIES * words * FP16_BYTES]);
        let folded =
            fold_initial_openings(&mut encoded, &vec![Fp16::ONE; words], 1, words).unwrap();
        assert_eq!(folded, vec![Fp16::ZERO; MAIN_QUERIES]);
        assert_eq!(encoded.position() as usize, encoded.get_ref().len());
    }

    #[test]
    fn streamed_parallel_initial_fold_rejects_noncanonical_values() {
        let words = 16;
        let mut bytes = vec![0_u8; MAIN_QUERIES * words * FP16_BYTES];
        bytes[..4].copy_from_slice(&0x7fff_ffff_u32.to_be_bytes());
        let error =
            fold_initial_openings(&mut Cursor::new(bytes), &vec![Fp16::ONE; words], 1, words)
                .unwrap_err();
        assert_eq!(
            error,
            "fp16:NonCanonicalCoefficient { index: 0, value: 2147483647 }"
        );
    }

    #[test]
    fn streamed_parallel_initial_fold_rejects_short_input() {
        let words = 16;
        let error = fold_initial_openings(
            &mut Cursor::new(vec![0_u8; MAIN_QUERIES * words * FP16_BYTES - 1]),
            &vec![Fp16::ONE; words],
            1,
            words,
        )
        .unwrap_err();
        assert!(error.starts_with("read_values:"));
    }
}
