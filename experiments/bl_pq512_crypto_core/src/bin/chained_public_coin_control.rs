use std::time::Instant;

use bl_pq512_crypto_core::chained_public_coin::{
    ChainedRoundDescriptor, decode_chained_public_coin_bundle, encode_chained_public_coin_bundle,
    verify_chained_public_coin_bundle,
};
use bl_pq512_crypto_core::chained_public_coin_client::ChainedPublicCoinCoordinator;
use bl_pq512_crypto_core::fp16_relay_free_gkr_schedule::{
    COMBINED_ROUNDS as ARCHITECTURE_ROUNDS, GKR_CLAIM_MIX_ROUNDS, GKR_GROUP_ROUNDS_PER_LAYER,
    GKR_LAYERS, GKR_MASK_BATCH_ROUNDS, GKR_OUTPUT_QUERY_ROUNDS, GKR_ROUNDS,
    GKR_WIRE_ROUNDS_PER_KECCAK_ROUND, KECCAK_ROUNDS, PCS_DOWNSTREAM_ROUNDS as PCS_VECTOR_ROUNDS,
    STATE_RELATION_ROUNDS, SelectedGkrRoundKind, WIRE_ROUNDS_BY_LAYER, selected_gkr_round_kind,
    selected_gkr_round_output_count,
};
use sha3::{Digest, Sha3_512};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn gkr_round_code(kind: SelectedGkrRoundKind) -> u16 {
    match kind {
        SelectedGkrRoundKind::OutputQuery => 100,
        SelectedGkrRoundKind::PackedBridge => 110,
        SelectedGkrRoundKind::SharedGroup => 111,
        SelectedGkrRoundKind::Wire => 112,
        SelectedGkrRoundKind::Terminal => 113,
        SelectedGkrRoundKind::ClaimMix => 114,
        SelectedGkrRoundKind::MaskBatch => 115,
    }
}

fn descriptor(round: u32, round_count: u32) -> ChainedRoundDescriptor {
    if round_count == ARCHITECTURE_ROUNDS {
        if round < GKR_ROUNDS {
            return ChainedRoundDescriptor {
                kind: gkr_round_code(
                    selected_gkr_round_kind(round).expect("GKR round kind is total"),
                ),
                ordinal: round,
                output_count: selected_gkr_round_output_count(round)
                    .expect("GKR output count is total"),
            };
        }
        if round < GKR_ROUNDS + STATE_RELATION_ROUNDS {
            let state_round = round - GKR_ROUNDS;
            return ChainedRoundDescriptor {
                kind: if state_round == 0 {
                    120
                } else if state_round <= 12 {
                    121
                } else {
                    122
                },
                ordinal: round,
                output_count: if state_round == 0 { 18 } else { 1 },
            };
        }
        let pcs_round = round - GKR_ROUNDS - STATE_RELATION_ROUNDS;
        return ChainedRoundDescriptor {
            kind: match pcs_round {
                0 => 799,
                1 => 800,
                2..=10 => 801,
                11 => 802,
                12 => 803,
                _ => unreachable!("PCS schedule has thirteen rounds"),
            },
            ordinal: round,
            output_count: 1,
        };
    }
    ChainedRoundDescriptor {
        kind: 100,
        ordinal: round,
        output_count: 1,
    }
}

fn message(round: u32, round_count: u32) -> Vec<u8> {
    let length = if round_count == ARCHITECTURE_ROUNDS && round > 0 && round < GKR_ROUNDS {
        match selected_gkr_round_kind(round).expect("GKR round kind is total") {
            SelectedGkrRoundKind::PackedBridge => 46 * 64,
            SelectedGkrRoundKind::SharedGroup => 4 * 64,
            SelectedGkrRoundKind::Wire => 3 * 64,
            SelectedGkrRoundKind::Terminal => 5 * 64,
            SelectedGkrRoundKind::ClaimMix => 4 * 26 * 64,
            SelectedGkrRoundKind::MaskBatch => 64,
            SelectedGkrRoundKind::OutputQuery => unreachable!("round zero handled separately"),
        }
    } else if round_count == ARCHITECTURE_ROUNDS
        && round >= GKR_ROUNDS
        && round < GKR_ROUNDS + STATE_RELATION_ROUNDS
    {
        if round == GKR_ROUNDS {
            64 + 64 + 2
        } else if round < GKR_ROUNDS + 13 {
            64 + 2 + 4 * 64
        } else {
            64 + 2 + 3 * 64
        }
    } else if round_count == ARCHITECTURE_ROUNDS && round >= GKR_ROUNDS + STATE_RELATION_ROUNDS {
        match round - GKR_ROUNDS - STATE_RELATION_ROUNDS {
            // The last GKR challenge is reused as the seven-claim batching
            // challenge. The first downstream message fixes those claims and
            // that challenge before the independent coordinate batching
            // challenge is released.
            0 => 264 + 64,
            1 => 328,
            2..=10 => 16 + 2_048 * 64,
            11 => 228,
            12 => 178,
            _ => unreachable!("PCS schedule has thirteen rounds"),
        }
    } else {
        64
    };
    let mut output = Vec::with_capacity(length);
    let mut counter = 0_u32;
    while output.len() < length {
        let block = Sha3_512::digest(
            [
                b"control-prover-message".as_slice(),
                &round.to_be_bytes(),
                &counter.to_be_bytes(),
            ]
            .concat(),
        );
        output.extend_from_slice(&block);
        counter += 1;
    }
    output.truncate(length);
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let round_count = match std::env::args().nth(1) {
        Some(value) if value == "architecture" => ARCHITECTURE_ROUNDS,
        Some(value) => value.parse::<u32>()?,
        None => 3,
    };
    if round_count == 0 || round_count > 65_535 {
        return Err("round count must be in 1..=65535".into());
    }
    let service = std::env::current_exe()?
        .parent()
        .ok_or("control executable parent")?
        .join("chained_public_coin_service.exe");
    let session_id: [u8; 64] = Sha3_512::digest(b"BL/PQ512/CHAIN-CONTROL/SESSION/v1").into();
    let schedule: [u8; 64] = Sha3_512::digest(b"BL/PQ512/CHAIN-CONTROL/SCHEDULE/v1").into();
    let total_started = Instant::now();
    let spawn_started = Instant::now();
    let mut coordinator =
        ChainedPublicCoinCoordinator::spawn(&service, session_id, 0, schedule, round_count)
            .map_err(|error| format!("{error:?}"))?;
    let spawn_seconds = spawn_started.elapsed().as_secs_f64();
    let rounds_started = Instant::now();
    let mut challenge_digest = Sha3_512::new();
    for round in 0..round_count {
        let message = message(round, round_count);
        let challenges = coordinator
            .challenge(descriptor(round, round_count), &message)
            .map_err(|error| format!("{error:?}"))?;
        for challenge in challenges {
            challenge_digest.update(challenge.encode());
        }
    }
    let round_seconds = rounds_started.elapsed().as_secs_f64();
    let finish_started = Instant::now();
    let bundle = coordinator
        .finish_bundle()
        .map_err(|error| format!("{error:?}"))?;
    let finish_seconds = finish_started.elapsed().as_secs_f64();
    let encode_started = Instant::now();
    let encoded = encode_chained_public_coin_bundle(&bundle)?;
    let encode_seconds = encode_started.elapsed().as_secs_f64();
    let decode_started = Instant::now();
    let decoded = decode_chained_public_coin_bundle(&encoded)?;
    let decode_seconds = decode_started.elapsed().as_secs_f64();
    let verify_started = Instant::now();
    let verified = verify_chained_public_coin_bundle(&decoded)?;
    let verify_seconds = verify_started.elapsed().as_secs_f64();
    let total_seconds = total_started.elapsed().as_secs_f64();
    let final_root = bundle.claimed_final_transcript_root;
    println!("status=verified");
    println!("authenticated_chain_heads=true");
    println!("message_before_challenge=true");
    println!("dual_pq_suites=true");
    println!("independent_bundle_replay=true");
    println!("rounds={round_count}");
    println!("verified_rounds={}", verified.len());
    println!("architecture_rounds={ARCHITECTURE_ROUNDS}");
    println!("gkr_rounds={GKR_ROUNDS}");
    println!("gkr_output_query_rounds={GKR_OUTPUT_QUERY_ROUNDS}");
    println!("keccak_rounds={KECCAK_ROUNDS}");
    println!("gkr_layers={GKR_LAYERS}");
    println!("gkr_bridge_rounds={GKR_LAYERS}");
    println!("gkr_terminal_rounds={GKR_LAYERS}");
    println!("gkr_claim_mix_rounds={GKR_CLAIM_MIX_ROUNDS}");
    println!("gkr_mask_batch_rounds={GKR_MASK_BATCH_ROUNDS}");
    println!(
        "gkr_group_rounds={}",
        GKR_LAYERS * GKR_GROUP_ROUNDS_PER_LAYER
    );
    println!(
        "gkr_wire_rounds={}",
        KECCAK_ROUNDS * GKR_WIRE_ROUNDS_PER_KECCAK_ROUND
    );
    println!("gkr_group_rounds_per_layer={GKR_GROUP_ROUNDS_PER_LAYER}");
    println!(
        "gkr_wire_rounds_by_layer={}",
        WIRE_ROUNDS_BY_LAYER
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("pcs_vector_rounds={PCS_VECTOR_ROUNDS}");
    println!("bundle_mb={:.6}", encoded.len() as f64 / 1_000_000.0);
    println!("spawn_and_head_auth_seconds={spawn_seconds:.6}");
    println!("round_accept_seconds={round_seconds:.6}");
    println!("finish_seconds={finish_seconds:.6}");
    println!("encode_seconds={encode_seconds:.6}");
    println!("decode_seconds={decode_seconds:.6}");
    println!("independent_verify_seconds={verify_seconds:.6}");
    println!("total_seconds={total_seconds:.6}");
    println!("challenge_digest={}", hex(&challenge_digest.finalize()));
    println!("final_transcript_root={}", hex(&final_root));
    println!("complete_proof_qualification=false");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_schedule_has_exact_corrected_round_counts() {
        assert_eq!(GKR_LAYERS, 168);
        assert_eq!(GKR_ROUNDS, 6_073);
        assert_eq!(PCS_VECTOR_ROUNDS, 13);
        assert_eq!(STATE_RELATION_ROUNDS, 25);
        assert_eq!(ARCHITECTURE_ROUNDS, 6_111);
        assert_eq!(descriptor(0, ARCHITECTURE_ROUNDS).output_count, 27);
    }

    #[test]
    fn downstream_pcs_descriptors_are_complete_and_ordered() {
        let kinds = ((GKR_ROUNDS + STATE_RELATION_ROUNDS)..ARCHITECTURE_ROUNDS)
            .map(|round| descriptor(round, ARCHITECTURE_ROUNDS).kind)
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                799, 800, 801, 801, 801, 801, 801, 801, 801, 801, 801, 802, 803
            ]
        );
        assert_eq!(kinds.iter().filter(|kind| **kind == 801).count(), 9);
    }

    #[test]
    fn every_architecture_round_has_a_closed_descriptor_and_message_shape() {
        for round in 0..ARCHITECTURE_ROUNDS {
            let round_descriptor = descriptor(round, ARCHITECTURE_ROUNDS);
            assert_eq!(round_descriptor.ordinal, round);
            assert!(!message(round, ARCHITECTURE_ROUNDS).is_empty());
            if round < GKR_ROUNDS {
                assert_eq!(
                    round_descriptor.output_count,
                    selected_gkr_round_output_count(round).unwrap()
                );
            }
        }
        assert_eq!(message(GKR_ROUNDS, ARCHITECTURE_ROUNDS).len(), 130);
        assert_eq!(message(GKR_ROUNDS + 1, ARCHITECTURE_ROUNDS).len(), 322);
        assert_eq!(
            message(GKR_ROUNDS + STATE_RELATION_ROUNDS, ARCHITECTURE_ROUNDS).len(),
            328
        );
        assert_eq!(
            message(GKR_ROUNDS + STATE_RELATION_ROUNDS + 2, ARCHITECTURE_ROUNDS).len(),
            16 + 2_048 * 64
        );
    }
}
