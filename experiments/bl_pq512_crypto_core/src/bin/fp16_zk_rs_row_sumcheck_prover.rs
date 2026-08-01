use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    time::Instant,
};

use bl_pq512_crypto_core::{
    field::Fp16,
    fp16_zk_rs_gkr_binding::{
        BOUNDARY_VARIABLES, GKR_CLAIM_COUNT, PackedComponentClaim, WORDS_PER_BOUNDARY,
        bind_gkr_boundary_claims, coordinate_linearized_coefficients,
    },
    fp16_zk_rs_row_sumcheck::Fp16ZkRsRowSumcheck,
    gkr_packed_bridge_fp16::PACKED_INSTANCES,
    gkr_sumcheck::LayerOutputClaim,
};

const INPUT_MAGIC: &[u8; 8] = b"BLRSPV01";
const READY_MAGIC: &[u8; 8] = b"BLRSPR01";
const MESSAGE_MAGIC: &[u8; 8] = b"BLRSPM01";
const CHALLENGE_MAGIC: &[u8; 8] = b"BLRSPC01";
const FINAL_MAGIC: &[u8; 8] = b"BLRSPF01";
const PARAMETERS_INPUT_MAGIC: &[u8; 8] = b"BLRSPA01";
const PARAMETERS_OUTPUT_MAGIC: &[u8; 8] = b"BLRSPA02";
const WORD_ROUNDS: usize = 9;
const GLOBAL_WORDS: usize = 2 * WORDS_PER_BOUNDARY;
const FP16_BYTES: usize = 64;

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [] => run(),
        [flag] if flag == "--parameters" => run_parameters(),
        _ => Err("arguments".to_string()),
    };
    if let Err(error) = result {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run_parameters() -> Result<(), String> {
    let started = Instant::now();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    let mut writer = BufWriter::new(stdout.lock());
    if &read_array::<8>(&mut reader)? != PARAMETERS_INPUT_MAGIC {
        return Err("parameters_input_magic".to_string());
    }
    let claim_challenge = read_fp16(&mut reader)?;
    let coordinate_challenge = read_fp16(&mut reader)?;
    let claims = (0..GKR_CLAIM_COUNT)
        .map(|_| read_claim(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;
    let binding = bind_gkr_boundary_claims(&claims, claim_challenge, coordinate_challenge)
        .map_err(|error| format!("parameters_binding:{error:?}"))?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("parameters_trailing:{error}"))?
        != 0
    {
        return Err("parameters_trailing_input".to_string());
    }
    let coordinate_map = coordinate_linearized_coefficients(coordinate_challenge);
    let mut claim_power = Fp16::ONE;
    writer
        .write_all(PARAMETERS_OUTPUT_MAGIC)
        .and_then(|_| writer.write_all(&binding.expected_target.encode()))
        .map_err(|error| format!("parameters_output_header:{error}"))?;
    for coefficient in coordinate_map {
        writer
            .write_all(&coefficient.encode())
            .map_err(|error| format!("parameters_coordinate_map:{error}"))?;
    }
    for _ in 0..GKR_CLAIM_COUNT {
        writer
            .write_all(&claim_power.encode())
            .map_err(|error| format!("parameters_claim_power:{error}"))?;
        claim_power = claim_power * claim_challenge;
    }
    writer
        .write_all(&started.elapsed().as_secs_f64().to_be_bytes())
        .and_then(|_| writer.flush())
        .map_err(|error| format!("parameters_output:{error}"))
}

fn run() -> Result<(), String> {
    let started = Instant::now();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = BufReader::with_capacity(1 << 20, stdin.lock());
    let mut writer = BufWriter::with_capacity(1 << 20, stdout.lock());
    if &read_array::<8>(&mut reader)? != INPUT_MAGIC {
        return Err("input_magic".to_string());
    }
    let claim_challenge = read_fp16(&mut reader)?;
    let coordinate_challenge = read_fp16(&mut reader)?;
    let claims = (0..GKR_CLAIM_COUNT)
        .map(|_| read_claim(&mut reader))
        .collect::<Result<Vec<_>, _>>()?;
    let binding = bind_gkr_boundary_claims(&claims, claim_challenge, coordinate_challenge)
        .map_err(|error| format!("binding:{error:?}"))?;
    let component_rows = (0..GKR_CLAIM_COUNT)
        .map(|_| {
            (0..GLOBAL_WORDS)
                .map(|_| {
                    let mut components = [Fp16::ZERO; PACKED_INSTANCES];
                    for component in &mut components {
                        *component = read_fp16(&mut reader)?;
                    }
                    Ok(components)
                })
                .collect::<Result<Vec<_>, String>>()
        })
        .collect::<Result<Vec<_>, _>>()?;
    #[cfg(feature = "parallel")]
    let workers = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    #[cfg(feature = "parallel")]
    let mut prover = Fp16ZkRsRowSumcheck::new_parallel(&binding, &component_rows, workers)
        .map_err(|error| format!("row_state:{error:?}"))?;
    #[cfg(not(feature = "parallel"))]
    let mut prover = Fp16ZkRsRowSumcheck::new(&binding, &component_rows)
        .map_err(|error| format!("row_state:{error:?}"))?;
    writer
        .write_all(READY_MAGIC)
        .and_then(|_| writer.write_all(&binding.expected_target.encode()))
        .and_then(|_| writer.write_all(&started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("ready:{error}"))?;

    for round in 0..WORD_ROUNDS {
        #[cfg(feature = "parallel")]
        let coefficients = prover
            .round_coefficients_parallel(workers)
            .map_err(|error| format!("round:{round}:{error:?}"))?;
        #[cfg(not(feature = "parallel"))]
        let coefficients = prover
            .round_coefficients()
            .map_err(|error| format!("round:{round}:{error:?}"))?;
        writer
            .write_all(MESSAGE_MAGIC)
            .and_then(|_| writer.write_all(&(round as u32).to_be_bytes()))
            .map_err(|error| format!("message_header:{round}:{error}"))?;
        for coefficient in coefficients {
            writer
                .write_all(&coefficient.encode())
                .map_err(|error| format!("message:{round}:{error}"))?;
        }
        writer
            .flush()
            .map_err(|error| format!("message_flush:{round}:{error}"))?;
        if &read_array::<8>(&mut reader)? != CHALLENGE_MAGIC {
            return Err(format!("challenge_magic:{round}"));
        }
        let ordinal = u32::from_be_bytes(read_array::<4>(&mut reader)?);
        if ordinal != round as u32 {
            return Err(format!("challenge_ordinal:{ordinal}/{round}"));
        }
        let challenge = read_fp16(&mut reader)?;
        #[cfg(feature = "parallel")]
        prover
            .fold_parallel(challenge, workers)
            .map_err(|error| format!("fold:{round}:{error:?}"))?;
        #[cfg(not(feature = "parallel"))]
        prover
            .fold(challenge)
            .map_err(|error| format!("fold:{round}:{error:?}"))?;
    }
    let target = prover
        .terminal_target()
        .map_err(|error| format!("terminal:{error:?}"))?;
    writer
        .write_all(FINAL_MAGIC)
        .and_then(|_| writer.write_all(&target.encode()))
        .and_then(|_| writer.write_all(&started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("final:{error}"))?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("trailing:{error}"))?
        != 0
    {
        return Err("trailing_input".to_string());
    }
    Ok(())
}

fn read_array<const N: usize>(reader: &mut impl Read) -> Result<[u8; N], String> {
    let mut value = [0_u8; N];
    reader
        .read_exact(&mut value)
        .map_err(|error| format!("read:{error}"))?;
    Ok(value)
}

fn read_u32(reader: &mut impl Read) -> Result<u32, String> {
    Ok(u32::from_be_bytes(read_array::<4>(reader)?))
}

fn read_fp16(reader: &mut impl Read) -> Result<Fp16, String> {
    Fp16::decode(&read_array::<FP16_BYTES>(reader)?).map_err(|error| format!("fp16:{error:?}"))
}

fn read_claim(reader: &mut impl Read) -> Result<PackedComponentClaim, String> {
    let boundary = u8::try_from(read_u32(reader)?).map_err(|_| "boundary".to_string())?;
    let coefficient = read_fp16(reader)?;
    let value = read_fp16(reader)?;
    let shard_query = read_fp16(reader)?;
    let point = (0..BOUNDARY_VARIABLES)
        .map(|_| read_fp16(reader))
        .collect::<Result<Vec<_>, _>>()?;
    let mut component_evaluations = [Fp16::ZERO; PACKED_INSTANCES];
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
