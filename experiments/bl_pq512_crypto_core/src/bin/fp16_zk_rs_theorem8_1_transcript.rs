use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    time::Instant,
};

use bl_pq512_crypto_core::{
    field::{Fp16, M31},
    fp16_zk_rs_gkr_binding::{
        BOUNDARY_VARIABLES, GKR_CLAIM_COUNT, PackedComponentClaim, bind_gkr_boundary_claims,
    },
    gkr_sumcheck::LayerOutputClaim,
};
use sha3::{Digest, Sha3_512};

const INPUT_MAGIC: &[u8; 8] = b"BLT8IN01";
const OUTPUT_MAGIC: &[u8; 8] = b"BLT8OUT1";
const STREAM_INPUT_MAGIC: &[u8; 8] = b"BLT8SI06";
const STREAM_CLAIMS_MAGIC: &[u8; 8] = b"BLT8GC06";
const STREAM_INITIAL_MAGIC: &[u8; 8] = b"BLT8SO06";
const STREAM_CHALLENGE_MAGIC: &[u8; 8] = b"BLT8CH01";
const STREAM_PROVER_ROUND_MAGIC: &[u8; 8] = b"BLT8PR04";
const STREAM_SOURCE_QUADRATIC_MAGIC: &[u8; 8] = b"BLT8SQ01";
const STREAM_ROUND_MAGIC: &[u8; 8] = b"BLT8HR04";
const STREAM_MASK_EVALUATION_MAGIC: &[u8; 8] = b"BLT8ME01";
const STREAM_FINAL_MAGIC: &[u8; 8] = b"BLT8SF04";
const PCS_MAGIC: &[u8; 8] = b"BLPQPCS1";
const PCS_VERSION: u16 = 1;
const TRANSCRIPT_DOMAIN: u16 = 522;
const CHALLENGE_DOMAIN: u16 = 523;
const GKR_BINDING_DOMAIN: u16 = 525;
const SUMCHECK_ROUNDS: usize = 9;
const INTERLEAVINGS: usize = 1 << SUMCHECK_ROUNDS;
const MASK_MESSAGE_VALUES: usize = 2_048;
const FP16_BYTES: usize = 64;

fn read_exact_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], String> {
    let mut value = [0_u8; N];
    reader
        .read_exact(&mut value)
        .map_err(|error| format!("read:{error}"))?;
    Ok(value)
}

fn read_fp16(reader: &mut impl Read) -> Result<Fp16, String> {
    let encoded = read_exact_array::<FP16_BYTES>(reader)?;
    Fp16::decode(&encoded).map_err(|error| format!("fp16:{error:?}"))
}

fn read_u32(reader: &mut impl Read) -> Result<u32, String> {
    Ok(u32::from_be_bytes(read_exact_array::<4>(reader)?))
}

fn read_gkr_claim(reader: &mut impl Read) -> Result<PackedComponentClaim, String> {
    let boundary = read_u32(reader)?;
    let boundary = u8::try_from(boundary).map_err(|_| "gkr_boundary".to_string())?;
    let coefficient = read_fp16(reader)?;
    let value = read_fp16(reader)?;
    let shard_query = read_fp16(reader)?;
    let mut point = Vec::with_capacity(BOUNDARY_VARIABLES);
    for _ in 0..BOUNDARY_VARIABLES {
        point.push(read_fp16(reader)?);
    }
    let mut component_evaluations = [Fp16::ZERO; 16];
    for evaluation in &mut component_evaluations {
        *evaluation = read_fp16(reader)?;
    }
    Ok(PackedComponentClaim {
        boundary,
        claim: LayerOutputClaim {
            point,
            value,
            coefficient,
        },
        shard_query,
        component_evaluations,
    })
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

fn gkr_claims_digest(claims: &[PackedComponentClaim]) -> [u8; 64] {
    let mut payload =
        Vec::with_capacity(GKR_CLAIM_COUNT * (4 + (3 + BOUNDARY_VARIABLES + 16) * FP16_BYTES));
    for claim in claims {
        payload.extend_from_slice(&u32::from(claim.boundary).to_be_bytes());
        payload.extend_from_slice(&claim.claim.coefficient.encode());
        payload.extend_from_slice(&claim.claim.value.encode());
        payload.extend_from_slice(&claim.shard_query.encode());
        for coordinate in &claim.claim.point {
            payload.extend_from_slice(&coordinate.encode());
        }
        for evaluation in claim.component_evaluations {
            payload.extend_from_slice(&evaluation.encode());
        }
    }
    hash_parts(
        GKR_BINDING_DOMAIN,
        &[
            b"BL/PQ512/FP16-ZK-RS/GKR-MIXED-CLAIMS/HASH-PACKED-STATE-DIRECT/v3\0",
            &payload,
        ],
    )
}

fn gkr_binding_digest(
    claims_digest: &[u8; 64],
    claim_challenge: Fp16,
    coordinate_challenge: Fp16,
    target: Fp16,
) -> [u8; 64] {
    hash_parts(
        GKR_BINDING_DOMAIN + 1,
        &[
            b"BL/PQ512/FP16-ZK-RS/ROW-BATCHED-BINDING/MIXED-v3\0",
            claims_digest,
            &claim_challenge.encode(),
            &coordinate_challenge.encode(),
            &target.encode(),
        ],
    )
}

fn transcript_absorb(state: [u8; 64], label: &[u8], payload: &[u8]) -> [u8; 64] {
    hash_parts(
        TRANSCRIPT_DOMAIN,
        &[
            &state,
            label,
            &u64::try_from(payload.len())
                .expect("bounded transcript payload")
                .to_be_bytes(),
            payload,
        ],
    )
}

fn exact_challenge(state: &[u8; 64], label: &[u8]) -> Fp16 {
    let mut coefficients = [0_u32; 16];
    let mut accepted = 0_usize;
    let mut counter = 0_u64;
    while accepted < coefficients.len() {
        let digest = hash_parts(CHALLENGE_DOMAIN, &[state, label, &counter.to_be_bytes()]);
        for chunk in digest.chunks_exact(4) {
            let candidate = u32::from_be_bytes(chunk.try_into().expect("four-byte chunk"));
            if candidate < bl_pq512_crypto_core::field::M31_MODULUS {
                coefficients[accepted] = candidate;
                accepted += 1;
                if accepted == coefficients.len() {
                    break;
                }
            }
        }
        counter += 1;
    }
    Fp16::from_coefficients(coefficients).expect("rejection sampling yields canonical coefficients")
}

fn fp16_from_m31(value: u32) -> Fp16 {
    Fp16::from_m31(M31::from_canonical(value).expect("bounded M31 scalar"))
}

fn scale_m31(element: Fp16, value: usize) -> Result<Fp16, String> {
    let scalar = u32::try_from(value).map_err(|_| "scalar".to_string())?;
    Ok(element.mul_by_m31(M31::from_canonical(scalar).map_err(|_| "scalar".to_string())?))
}

fn sum(values: impl IntoIterator<Item = Fp16>) -> Fp16 {
    values
        .into_iter()
        .fold(Fp16::ZERO, |accumulator, value| accumulator + value)
}

fn polynomial_eval(coefficients: &[Fp16], point: Fp16) -> Fp16 {
    coefficients
        .iter()
        .rev()
        .fold(Fp16::ZERO, |accumulator, coefficient| {
            accumulator * point + *coefficient
        })
}

fn interpolate(left: Fp16, right: Fp16, point: Fp16) -> Fp16 {
    left + (right - left) * point
}

fn fold(values: &[Fp16], point: Fp16) -> Vec<Fp16> {
    values
        .chunks_exact(2)
        .map(|pair| interpolate(pair[0], pair[1], point))
        .collect()
}

fn constraint_at(values: &[Fp16], forms: &[Fp16], point: Fp16) -> Fp16 {
    let values = fold(values, point);
    let forms = fold(forms, point);
    sum(values
        .into_iter()
        .zip(forms)
        .map(|(value, form)| value * form))
}

fn quadratic_coefficients(at_zero: Fp16, at_one: Fp16, at_two: Fp16) -> [Fp16; 3] {
    let two = fp16_from_m31(2);
    let inverse_two = Fp16::from_m31(
        M31::from_canonical(bl_pq512_crypto_core::field::M31_MODULUS.div_ceil(2))
            .expect("inverse two is canonical"),
    );
    let coefficient_two = (at_two - at_one * two + at_zero) * inverse_two;
    let coefficient_one = at_one - at_zero - coefficient_two;
    [at_zero, coefficient_one, coefficient_two]
}

fn encode_values(values: &[Fp16]) -> Vec<u8> {
    values.iter().flat_map(|value| value.encode()).collect()
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [] => run(),
        [flag] if flag == "--stream" => run_stream(),
        _ => Err("arguments".to_string()),
    };
    if let Err(error) = result {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let started = Instant::now();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    let mut writer = BufWriter::with_capacity(1 << 20, stdout.lock());
    let magic = read_exact_array::<8>(&mut reader)?;
    if &magic != INPUT_MAGIC {
        return Err("input_magic".to_string());
    }
    let initial_root = read_exact_array::<64>(&mut reader)?;
    let mask_root = read_exact_array::<64>(&mut reader)?;
    let mut masks = vec![vec![Fp16::ZERO; MASK_MESSAGE_VALUES]; SUMCHECK_ROUNDS];
    for mask in &mut masks {
        for coefficient in mask {
            *coefficient = read_fp16(&mut reader)?;
        }
    }
    let mut values = Vec::with_capacity(INTERLEAVINGS);
    for _ in 0..INTERLEAVINGS {
        values.push(read_fp16(&mut reader)?);
    }
    let trailing = {
        let mut value = [0_u8; 1];
        reader
            .read(&mut value)
            .map_err(|error| format!("trailing:{error}"))?
    };
    if trailing != 0 {
        return Err("trailing_input".to_string());
    }

    let mut forms = (0..INTERLEAVINGS)
        .map(|index| fp16_from_m31(u32::try_from(index + 1).expect("interleaving form fits M31")))
        .collect::<Vec<_>>();
    let initial_target = sum(values
        .iter()
        .copied()
        .zip(forms.iter().copied())
        .map(|(value, form)| value * form));
    let endpoints = masks
        .iter()
        .map(|mask| mask[0] + sum(mask.iter().copied()))
        .collect::<Vec<_>>();
    let mask_target = scale_m31(sum(endpoints.iter().copied()), 1 << 8)?;
    let mut transcript = hash_parts(
        TRANSCRIPT_DOMAIN,
        &[
            &initial_root,
            &mask_root,
            &initial_target.encode(),
            &mask_target.encode(),
        ],
    );
    let epsilon = exact_challenge(&transcript, b"epsilon");
    let mut expected = initial_target * epsilon + mask_target;
    let mut challenges = Vec::with_capacity(SUMCHECK_ROUNDS);
    let mut messages = Vec::with_capacity(SUMCHECK_ROUNDS);
    let mut mask_evaluations = Vec::with_capacity(SUMCHECK_ROUNDS);

    for round in 0..SUMCHECK_ROUNDS {
        let remaining = SUMCHECK_ROUNDS - round - 1;
        let mut coefficients = masks[round]
            .iter()
            .copied()
            .map(|coefficient| scale_m31(coefficient, 1 << remaining))
            .collect::<Result<Vec<_>, _>>()?;
        let mut constant = Fp16::ZERO;
        for evaluation in &mask_evaluations {
            constant = constant + scale_m31(*evaluation, 1 << remaining)?;
        }
        if remaining != 0 {
            for endpoint in &endpoints[round + 1..] {
                constant = constant + scale_m31(*endpoint, 1 << (remaining - 1))?;
            }
        }
        coefficients[0] = coefficients[0] + constant;
        let quadratic = quadratic_coefficients(
            constraint_at(&values, &forms, Fp16::ZERO),
            constraint_at(&values, &forms, Fp16::ONE),
            constraint_at(&values, &forms, fp16_from_m31(2)),
        );
        for (coefficient, constraint) in coefficients.iter_mut().zip(quadratic) {
            *coefficient = *coefficient + constraint * epsilon;
        }
        if polynomial_eval(&coefficients, Fp16::ZERO) + polynomial_eval(&coefficients, Fp16::ONE)
            != expected
        {
            return Err(format!("sumcheck_chain:{round}"));
        }
        let encoded = encode_values(&coefficients);
        transcript = transcript_absorb(transcript, format!("h{round}").as_bytes(), &encoded);
        let challenge = exact_challenge(&transcript, format!("gamma{round}").as_bytes());
        expected = polynomial_eval(&coefficients, challenge);
        mask_evaluations.push(polynomial_eval(&masks[round], challenge));
        values = fold(&values, challenge);
        forms = fold(&forms, challenge);
        challenges.push(challenge);
        messages.push(encoded);
    }
    let terminal_target = values[0] * forms[0] * epsilon + sum(mask_evaluations.iter().copied());
    if terminal_target != expected {
        return Err("terminal_target".to_string());
    }

    writer
        .write_all(OUTPUT_MAGIC)
        .and_then(|_| writer.write_all(&initial_target.encode()))
        .and_then(|_| writer.write_all(&mask_target.encode()))
        .and_then(|_| writer.write_all(&epsilon.encode()))
        .map_err(|error| format!("output:{error}"))?;
    for (message, challenge) in messages.iter().zip(&challenges) {
        writer
            .write_all(message)
            .and_then(|_| writer.write_all(&challenge.encode()))
            .map_err(|error| format!("output:{error}"))?;
    }
    writer
        .write_all(&terminal_target.encode())
        .and_then(|_| writer.write_all(&forms[0].encode()))
        .and_then(|_| writer.write_all(&values[0].encode()))
        .and_then(|_| writer.write_all(&transcript))
        .and_then(|_| writer.write_all(&started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("output:{error}"))?;
    Ok(())
}

fn run_stream() -> Result<(), String> {
    let started = Instant::now();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    let mut writer = BufWriter::with_capacity(1 << 20, stdout.lock());
    let magic = read_exact_array::<8>(&mut reader)?;
    if &magic != STREAM_INPUT_MAGIC {
        return Err("stream_input_magic".to_string());
    }
    let initial_root = read_exact_array::<64>(&mut reader)?;
    let mask_root = read_exact_array::<64>(&mut reader)?;
    let gkr_mask_root = read_exact_array::<64>(&mut reader)?;
    let gkr_mask_opening = read_fp16(&mut reader)?;
    let mut claims = Vec::with_capacity(GKR_CLAIM_COUNT);
    for _ in 0..GKR_CLAIM_COUNT {
        claims.push(read_gkr_claim(&mut reader)?);
    }
    let claims_digest = gkr_claims_digest(&claims);
    let mut masks = vec![vec![Fp16::ZERO; MASK_MESSAGE_VALUES]; SUMCHECK_ROUNDS];
    for mask in &mut masks {
        for coefficient in mask {
            *coefficient = read_fp16(&mut reader)?;
        }
    }
    let endpoints = masks
        .iter()
        .map(|mask| mask[0] + sum(mask.iter().copied()))
        .collect::<Vec<_>>();
    let mask_target = scale_m31(sum(endpoints.iter().copied()), 1 << 8)?;
    writer
        .write_all(STREAM_CLAIMS_MAGIC)
        .and_then(|_| writer.write_all(&initial_root))
        .and_then(|_| writer.write_all(&mask_root))
        .and_then(|_| writer.write_all(&gkr_mask_root))
        .and_then(|_| writer.write_all(&gkr_mask_opening.encode()))
        .and_then(|_| writer.write_all(&claims_digest))
        .and_then(|_| writer.write_all(&mask_target.encode()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("stream_claims:{error}"))?;

    let claim_challenge = read_stream_challenge(&mut reader, 0)?;
    let coordinate_challenge = read_stream_challenge(&mut reader, 1)?;
    let binding = bind_gkr_boundary_claims(&claims, claim_challenge, coordinate_challenge)
        .map_err(|error| format!("stream_gkr_binding:{error:?}"))?;
    let gkr_scale = (0..GKR_CLAIM_COUNT).fold(Fp16::ONE, |power, _| power * claim_challenge);
    let initial_target = binding.expected_target + gkr_scale * gkr_mask_opening;
    let binding_digest = gkr_binding_digest(
        &claims_digest,
        claim_challenge,
        coordinate_challenge,
        initial_target,
    );
    writer
        .write_all(STREAM_INITIAL_MAGIC)
        .and_then(|_| writer.write_all(&initial_root))
        .and_then(|_| writer.write_all(&mask_root))
        .and_then(|_| writer.write_all(&gkr_mask_root))
        .and_then(|_| writer.write_all(&gkr_mask_opening.encode()))
        .and_then(|_| writer.write_all(&binding_digest))
        .and_then(|_| writer.write_all(&initial_target.encode()))
        .and_then(|_| writer.write_all(&mask_target.encode()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("stream_initial:{error}"))?;
    let epsilon = read_stream_challenge(&mut reader, 2)?;
    if epsilon.is_zero() {
        return Err("stream_zero_epsilon".to_string());
    }
    let mut expected = initial_target * epsilon + mask_target;
    let mut mask_evaluations = Vec::with_capacity(SUMCHECK_ROUNDS);

    for round in 0..SUMCHECK_ROUNDS {
        let remaining = SUMCHECK_ROUNDS - round - 1;
        let mut mask_coefficients = masks[round]
            .iter()
            .copied()
            .map(|coefficient| scale_m31(coefficient, 1 << remaining))
            .collect::<Result<Vec<_>, _>>()?;
        let mut constant = Fp16::ZERO;
        for evaluation in &mask_evaluations {
            constant = constant + scale_m31(*evaluation, 1 << remaining)?;
        }
        if remaining != 0 {
            for endpoint in &endpoints[round + 1..] {
                constant = constant + scale_m31(*endpoint, 1 << (remaining - 1))?;
            }
        }
        mask_coefficients[0] = mask_coefficients[0] + constant;

        let prover_round =
            read_stream_prover_round(&mut reader, u32::try_from(round).expect("round fits u32"))?;
        let coefficients = complete_stream_coefficients(&mask_coefficients, epsilon, prover_round);
        if coefficients[3..] != mask_coefficients[3..] {
            return Err(format!("stream_source_polynomial_degree:{round}"));
        }
        if coefficients[0] + sum(coefficients.iter().copied()) != expected {
            return Err(format!("stream_sumcheck_chain:{round}"));
        }
        let encoded = encode_values(&coefficients);
        writer
            .write_all(STREAM_ROUND_MAGIC)
            .and_then(|_| {
                writer.write_all(&u32::try_from(round).expect("round fits u32").to_be_bytes())
            })
            .and_then(|_| {
                writer.write_all(
                    &u32::try_from(encoded.len())
                        .expect("message length fits u32")
                        .to_be_bytes(),
                )
            })
            .and_then(|_| writer.write_all(&encoded))
            .and_then(|_| writer.flush())
            .map_err(|error| format!("stream_round:{error}"))?;
        let challenge = read_stream_challenge(
            &mut reader,
            u32::try_from(round + 3).expect("round fits u32"),
        )?;
        let evaluation = polynomial_eval(&coefficients, challenge);
        let low_difference = [
            coefficients[0] - mask_coefficients[0],
            coefficients[1] - mask_coefficients[1],
            coefficients[2] - mask_coefficients[2],
        ];
        let scaled_mask_evaluation =
            evaluation - polynomial_eval(&low_difference, challenge) - constant;
        let scale_inverse =
            M31::from_canonical(u32::try_from(1 << remaining).expect("sumcheck scale fits M31"))
                .map_err(|_| "stream_mask_scale".to_string())?
                .inverse()
                .map_err(|_| "stream_mask_scale_inverse".to_string())?;
        let mask_evaluation = scaled_mask_evaluation.mul_by_m31(scale_inverse);
        expected = evaluation;
        mask_evaluations.push(mask_evaluation);
        writer
            .write_all(STREAM_MASK_EVALUATION_MAGIC)
            .and_then(|_| {
                writer.write_all(&u32::try_from(round).expect("round fits u32").to_be_bytes())
            })
            .and_then(|_| writer.write_all(&mask_evaluation.encode()))
            .and_then(|_| writer.flush())
            .map_err(|error| format!("stream_mask_evaluation:{round}:{error}"))?;
    }
    let mask_terminal = sum(mask_evaluations.iter().copied());
    let source_terminal = (expected - mask_terminal)
        * epsilon
            .inverse()
            .map_err(|_| "stream_zero_epsilon".to_string())?;
    writer
        .write_all(STREAM_FINAL_MAGIC)
        .and_then(|_| writer.write_all(&expected.encode()))
        .and_then(|_| writer.write_all(&source_terminal.encode()))
        .and_then(|_| writer.write_all(&mask_terminal.encode()))
        .and_then(|_| writer.write_all(&started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("stream_final:{error}"))?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("stream_trailing:{error}"))?
        != 0
    {
        return Err("stream_trailing_input".to_string());
    }
    Ok(())
}

enum StreamProverRound {
    Complete(Vec<Fp16>),
    SourceQuadratic([Fp16; 3]),
}

fn complete_stream_coefficients(
    mask_coefficients: &[Fp16],
    epsilon: Fp16,
    prover_round: StreamProverRound,
) -> Vec<Fp16> {
    match prover_round {
        StreamProverRound::Complete(coefficients) => coefficients,
        StreamProverRound::SourceQuadratic(source) => {
            let mut coefficients = mask_coefficients.to_vec();
            for (coefficient, source) in coefficients.iter_mut().zip(source) {
                *coefficient = *coefficient + source * epsilon;
            }
            coefficients
        }
    }
}

fn read_stream_prover_round(
    reader: &mut impl Read,
    expected_ordinal: u32,
) -> Result<StreamProverRound, String> {
    let magic = read_exact_array::<8>(reader)?;
    if &magic != STREAM_PROVER_ROUND_MAGIC && &magic != STREAM_SOURCE_QUADRATIC_MAGIC {
        return Err(format!("stream_prover_round_magic:{expected_ordinal}"));
    }
    let ordinal = read_u32(reader)?;
    if ordinal != expected_ordinal {
        return Err(format!(
            "stream_prover_round_ordinal:{ordinal}/{expected_ordinal}"
        ));
    }
    if &magic == STREAM_SOURCE_QUADRATIC_MAGIC {
        return Ok(StreamProverRound::SourceQuadratic([
            read_fp16(reader)?,
            read_fp16(reader)?,
            read_fp16(reader)?,
        ]));
    }
    let length = read_u32(reader)? as usize;
    if length != MASK_MESSAGE_VALUES * FP16_BYTES {
        return Err(format!("stream_prover_round_length:{length}"));
    }
    (0..MASK_MESSAGE_VALUES)
        .map(|_| read_fp16(reader))
        .collect::<Result<Vec<_>, _>>()
        .map(StreamProverRound::Complete)
}

fn read_stream_challenge(reader: &mut impl Read, expected_ordinal: u32) -> Result<Fp16, String> {
    if &read_exact_array::<8>(reader)? != STREAM_CHALLENGE_MAGIC {
        return Err(format!("stream_challenge_magic:{expected_ordinal}"));
    }
    let ordinal = u32::from_be_bytes(read_exact_array::<4>(reader)?);
    if ordinal != expected_ordinal {
        return Err(format!(
            "stream_challenge_ordinal:{ordinal}/{expected_ordinal}"
        ));
    }
    read_fp16(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_quadratic_transport_matches_complete_masked_message() {
        let mut mask_coefficients = vec![Fp16::ZERO; MASK_MESSAGE_VALUES];
        mask_coefficients[0] = Fp16::ONE;
        mask_coefficients[3] = Fp16::ONE;
        mask_coefficients[MASK_MESSAGE_VALUES - 1] = Fp16::ONE;
        let source = [Fp16::ONE, Fp16::ZERO, Fp16::ONE];
        let epsilon = Fp16::ONE + Fp16::ONE;

        let mut legacy = mask_coefficients.clone();
        for (coefficient, source_coefficient) in legacy.iter_mut().zip(source) {
            *coefficient = *coefficient + source_coefficient * epsilon;
        }

        assert_eq!(
            complete_stream_coefficients(
                &mask_coefficients,
                epsilon,
                StreamProverRound::Complete(legacy.clone()),
            ),
            legacy
        );
        assert_eq!(
            complete_stream_coefficients(
                &mask_coefficients,
                epsilon,
                StreamProverRound::SourceQuadratic(source),
            ),
            legacy
        );
    }
}
