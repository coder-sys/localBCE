use std::io::{self, Read};

use bl_pq512_crypto_core::air_composition::{
    add_logup_to_composition, build_air_composition_from_main, build_air_main_trace_oracle,
    prepare_logup_for_composition,
};
use bl_pq512_crypto_core::air_ir::MAX_AIR_BINARY_BYTES;
use bl_pq512_crypto_core::air_logup::build_air_logup_oracle;
use bl_pq512_crypto_core::composition_mask::mask_composition_components;
use bl_pq512_crypto_core::deep_quotient::{build_deep_quotient_oracles, deep_claims_commitment};
use bl_pq512_crypto_core::field::Fp16;
use bl_pq512_crypto_core::fri_pipeline::{
    build_fri_mask_oracle, prove_fri_pipeline, start_interactive_fri, verify_fri_pipeline_v2,
};
use bl_pq512_crypto_core::oods::{
    OODS_DEFAULT_MAX_ATTEMPTS, sample_oods_parameter, stereographic_circle_point,
};
use bl_pq512_crypto_core::oracle_commitment::{
    commit_air_oracles_with_precommitments, commit_interaction_trace_oracle,
    commit_main_trace_oracle,
};
use bl_pq512_crypto_core::proof_format::{
    decode_fri_pipeline_proof_v2, encode_fri_pipeline_proof_v2_with_attribution,
};
use bl_pq512_crypto_core::sampler::{DEFAULT_MAX_ATTEMPTS, sample_uniform_fp16};
use sha3::{Digest, Sha3_512};

fn take<'a>(input: &'a [u8], offset: &mut usize, length: usize) -> Result<&'a [u8], ()> {
    let end = offset.checked_add(length).ok_or(())?;
    let value = input.get(*offset..end).ok_or(())?;
    *offset = end;
    Ok(value)
}

fn word(input: &[u8], offset: &mut usize) -> Result<u32, ()> {
    Ok(u32::from_be_bytes(
        take(input, offset, 4)?.try_into().map_err(|_| ())?,
    ))
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() {
    let mut input = Vec::new();
    if io::stdin()
        .take((MAX_AIR_BINARY_BYTES * 2 + 2048) as u64)
        .read_to_end(&mut input)
        .is_err()
    {
        std::process::exit(2);
    }
    let parsed = (|| -> Result<_, ()> {
        let mut offset = 0;
        let p_len = usize::try_from(word(&input, &mut offset)?).map_err(|_| ())?;
        let program = take(&input, &mut offset, p_len)?;
        let e_len = usize::try_from(word(&input, &mut offset)?).map_err(|_| ())?;
        let execution = take(&input, &mut offset, e_len)?;
        let alpha = Fp16::decode(take(&input, &mut offset, 64)?).map_err(|_| ())?;
        let beta = Fp16::decode(take(&input, &mut offset, 64)?).map_err(|_| ())?;
        let gamma = Fp16::decode(take(&input, &mut offset, 64)?).map_err(|_| ())?;
        let seed = take(&input, &mut offset, 64)?;
        let session = take(&input, &mut offset, 64)?;
        let masks = usize::try_from(word(&input, &mut offset)?).map_err(|_| ())?;
        let blowup = take(&input, &mut offset, 1)?[0];
        if offset != input.len() {
            return Err(());
        }
        Ok((
            program, execution, alpha, beta, gamma, seed, session, masks, blowup,
        ))
    })();
    let Ok((program, execution, alpha, beta, gamma, seed, session, masks, blowup)) = parsed else {
        eprintln!("complete_composition_input_invalid");
        std::process::exit(2);
    };
    let result = (|| {
        let main = build_air_main_trace_oracle(program, execution, seed, session, masks, blowup)?;
        let main_tree = commit_main_trace_oracle(&main)
            .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        let mut logup = build_air_logup_oracle(
            program, execution, beta, gamma, seed, session, masks, blowup,
        )?;
        prepare_logup_for_composition(program, &main, &mut logup, seed, session, masks)?;
        let interaction_tree =
            commit_interaction_trace_oracle(&main.program_binary_commitment, &logup).map_err(
                |_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter,
            )?;
        let mut composition = build_air_composition_from_main(program, execution, alpha, main)?;
        let terms = add_logup_to_composition(
            program,
            execution,
            &mut composition,
            &mut logup,
            beta,
            gamma,
            alpha,
            seed,
            session,
            masks,
        )?;
        mask_composition_components(&mut composition, seed, session, masks)
            .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        let commitments = commit_air_oracles_with_precommitments(
            main_tree,
            interaction_tree,
            &composition,
            &logup,
        )
        .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        let sampled = sample_oods_parameter(seed, session, 3, OODS_DEFAULT_MAX_ATTEMPTS)
            .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        let query = stereographic_circle_point(sampled.parameter)
            .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        let deep = build_deep_quotient_oracles(&composition, &logup, query)
            .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        let batch_coefficient = sample_uniform_fp16(seed, session, 100, 0, DEFAULT_MAX_ATTEMPTS)
            .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?
            .element;
        let largest_log = deep.batches[0].log_size;
        let fold_coefficients = (0..u32::from(largest_log - 1))
            .map(|index| {
                sample_uniform_fp16(seed, session, 101, index, DEFAULT_MAX_ATTEMPTS)
                    .map(|sample| sample.element)
                    .map_err(|_| {
                        bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let roots = commitments.roots();
        let main_root_bytes = roots.main_trace.into_bytes();
        let interaction_root_bytes = roots.interaction_trace.map(|root| root.into_bytes());
        let composition_root_bytes = roots.composition.into_bytes();
        let claims_commitment = deep_claims_commitment(
            &composition.program_binary_commitment,
            deep.query,
            &deep.claims,
            &main_root_bytes,
            interaction_root_bytes.as_ref(),
            &composition_root_bytes,
        )
        .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        // Preserve the real interactive chronology even in this deterministic
        // cross-language harness: the mask root exists before the batching
        // challenge, and every layer root exists before the next fold challenge.
        let fri_mask = build_fri_mask_oracle(&deep, claims_commitment, seed, session)
            .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        let _pre_challenge_mask_root = fri_mask.mask_tree.root();
        let mut fri_builder = start_interactive_fri(&deep, fri_mask, batch_coefficient)
            .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        for coefficient in &fold_coefficients {
            let _pre_next_challenge_layer_root =
                fri_builder.fold_next(*coefficient).map_err(|_| {
                    bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter
                })?;
        }
        let fri = fri_builder
            .finish()
            .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        let query_indices = [3_usize, (1_usize << largest_log) - 2];
        let proof = prove_fri_pipeline(
            &deep,
            &fri,
            &commitments,
            &composition,
            &logup,
            &query_indices,
        )
        .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        let encoded = encode_fri_pipeline_proof_v2_with_attribution(&proof)
            .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        if encoded.attribution.total_bytes() != Some(encoded.bytes.len()) {
            return Err(bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter);
        }
        let encoded_proof = encoded.bytes;
        let layer_log_sizes = (2..=largest_log).rev().collect::<Vec<_>>();
        let decoded_proof =
            decode_fri_pipeline_proof_v2(&encoded_proof, &query_indices, &layer_log_sizes)
                .map_err(|_| {
                    bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter
                })?;
        let mut parser_rejections = 0_u8;
        parser_rejections += u8::from(
            decode_fri_pipeline_proof_v2(
                &encoded_proof[..encoded_proof.len() - 1],
                &query_indices,
                &layer_log_sizes,
            )
            .is_err(),
        );
        let mut malformed = encoded_proof.clone();
        malformed[0] ^= 1;
        parser_rejections += u8::from(
            decode_fri_pipeline_proof_v2(&malformed, &query_indices, &layer_log_sizes).is_err(),
        );
        let mut malformed = encoded_proof.clone();
        malformed.push(0);
        parser_rejections += u8::from(
            decode_fri_pipeline_proof_v2(&malformed, &query_indices, &layer_log_sizes).is_err(),
        );
        if parser_rejections != 3 {
            return Err(bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter);
        }
        let proof_verified = verify_fri_pipeline_v2(
            &decoded_proof,
            program,
            masks,
            blowup,
            &[],
            alpha,
            beta,
            gamma,
            &commitments.roots(),
            &fri.mask_tree.root(),
            deep.query,
            &deep.claims,
            batch_coefficient,
            &fold_coefficients,
            &fri.layer_roots,
            fri.final_constant,
            &query_indices,
        )
        .map_err(|_| bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter)?;
        if !proof_verified {
            return Err(bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter);
        }
        let verify_candidate = |candidate, candidate_alpha, candidate_queries: &[usize]| {
            verify_fri_pipeline_v2(
                candidate,
                program,
                masks,
                blowup,
                &[],
                candidate_alpha,
                beta,
                gamma,
                &commitments.roots(),
                &fri.mask_tree.root(),
                deep.query,
                &deep.claims,
                batch_coefficient,
                &fold_coefficients,
                &fri.layer_roots,
                fri.final_constant,
                candidate_queries,
            )
            .unwrap_or(false)
        };
        let mut attack_rejections = 0_u8;
        let mut forged = decoded_proof.clone();
        forged.fri_layer_multiproofs.layers[0].opened_values[0] =
            forged.fri_layer_multiproofs.layers[0].opened_values[0].add(Fp16::ONE);
        attack_rejections += u8::from(!verify_candidate(&forged, alpha, &query_indices));
        let mut forged = decoded_proof.clone();
        forged.logup_final_sums[0] = forged.logup_final_sums[0].add(Fp16::ONE);
        forged.logup_final_sums[1] = forged.logup_final_sums[1].sub(Fp16::ONE);
        attack_rejections += u8::from(!verify_candidate(&forged, alpha, &query_indices));
        attack_rejections += u8::from(!verify_candidate(
            &decoded_proof,
            alpha.add(Fp16::ONE),
            &query_indices,
        ));
        let wrong_queries = [query_indices[0] + 2, query_indices[1]];
        attack_rejections += u8::from(!verify_candidate(&decoded_proof, alpha, &wrong_queries));
        if attack_rejections != 4 {
            return Err(bl_pq512_crypto_core::air_composition::AirCompositionError::Parameter);
        }
        Ok::<_, bl_pq512_crypto_core::air_composition::AirCompositionError>((
            composition,
            logup,
            terms,
            commitments,
            deep,
            fri,
            proof_verified,
            attack_rejections,
            encoded_proof.len(),
            parser_rejections,
        ))
    })();
    match result {
        Ok((
            composition,
            logup,
            terms,
            commitments,
            deep,
            fri,
            proof_verified,
            attack_rejections,
            proof_bytes,
            parser_rejections,
        )) => {
            let mut hash = Sha3_512::new();
            for table in &composition.tables {
                for value in &table.composition {
                    hash.update(value.encode());
                }
            }
            println!("OK");
            println!("pending={}", composition.lookup_count_pending_logup);
            println!("logup_terms={terms}");
            println!("interactions={}", logup.interactions.len());
            println!(
                "main_root={}",
                hex(&commitments.main_trace.root().into_bytes())
            );
            println!(
                "interaction_root={}",
                hex(&commitments
                    .interaction_trace
                    .as_ref()
                    .expect("lookup test has interaction tree")
                    .root()
                    .into_bytes())
            );
            println!(
                "composition_root={}",
                hex(&commitments.composition.root().into_bytes())
            );
            println!("deep_claims_commitment={}", hex(&fri.claims_commitment));
            println!("deep_domains={}", deep.batches.len());
            println!(
                "oods_claims={}",
                deep.claims
                    .iter()
                    .map(|claim| claim.values.len())
                    .sum::<usize>()
            );
            println!("fri_mask_root={}", hex(&fri.mask_tree.root().into_bytes()));
            println!("fri_layers={}", fri.layer_roots.len());
            println!("fri_final={}", hex(&fri.final_constant.encode()));
            println!("fri_proof_verified={proof_verified}");
            println!("fri_attack_rejections={attack_rejections}");
            println!("proof_bytes={proof_bytes}");
            println!("parser_rejections={parser_rejections}");
            println!(
                "composition_coefficients={}",
                composition
                    .tables
                    .iter()
                    .map(|table| table.composition_coefficient_count.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!("digest={:x}", hash.finalize());
        }
        Err(error) => {
            eprintln!("ERR:{error:?}");
            std::process::exit(2);
        }
    }
}
