use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    sync::{Arc, mpsc},
    thread,
    time::Instant,
};

use bl_pq512_crypto_core::field::Fp16;

const INPUT_MAGIC: &[u8; 8] = b"BLSPOT03";
const OUTPUT_MAGIC: &[u8; 8] = b"BLSPOUT1";
const INTERLEAVINGS: usize = 512;
const MAIN_QUERIES: usize = 1_600;
const AUXILIARY_QUERIES: usize = 1_218;
const SUMCHECK_WORDS: usize = 9;
const GKR_MASK_WORDS: usize = 64;
const STATE_SQUAREFREE_WORDS: usize = 1;
const COMPLETE_AUXILIARY_WORDS: usize = SUMCHECK_WORDS + GKR_MASK_WORDS + STATE_SQUAREFREE_WORDS;
const FP16_BYTES: usize = 64;

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
    let weights = read_values(&mut reader, INTERLEAVINGS)?;
    let combination = read_fp16(&mut reader)?;
    let folded = fold_initial_openings(&mut reader, &weights, initial_segments, words_per_segment)?;
    let sumcheck = read_values(&mut reader, AUXILIARY_QUERIES * SUMCHECK_WORDS)?;
    let gkr_mask = read_values(&mut reader, AUXILIARY_QUERIES * GKR_MASK_WORDS)?;
    let state_squarefree = read_values(&mut reader, AUXILIARY_QUERIES)?;
    let base_main = read_values(&mut reader, MAIN_QUERIES)?;
    let base_auxiliary = read_values(&mut reader, AUXILIARY_QUERIES * COMPLETE_AUXILIARY_WORDS)?;
    let answer_main = read_values(&mut reader, MAIN_QUERIES)?;
    let answer_auxiliary = read_values(&mut reader, AUXILIARY_QUERIES * COMPLETE_AUXILIARY_WORDS)?;
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
                let sumcheck = &sumcheck;
                let gkr_mask = &gkr_mask;
                let state_squarefree = &state_squarefree;
                let base_auxiliary = &base_auxiliary;
                let answer_auxiliary = &answer_auxiliary;
                scope.spawn(move || {
                    for query in start..end {
                        for word in 0..COMPLETE_AUXILIARY_WORDS {
                            let index = query * COMPLETE_AUXILIARY_WORDS + word;
                            let source = if word < SUMCHECK_WORDS {
                                sumcheck[query * SUMCHECK_WORDS + word]
                            } else if word < SUMCHECK_WORDS + GKR_MASK_WORDS {
                                gkr_mask[query * GKR_MASK_WORDS + word - SUMCHECK_WORDS]
                            } else {
                                state_squarefree[query]
                            };
                            if answer_auxiliary[index]
                                != base_auxiliary[index] + source * combination
                            {
                                return Some((query, word));
                            }
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
