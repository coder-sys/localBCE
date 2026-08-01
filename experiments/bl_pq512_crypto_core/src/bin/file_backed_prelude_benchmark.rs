use std::{
    env,
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use bl_pq512_crypto_core::{
    Fp16, field::M31_MODULUS, file_backed_sumcheck::product_round_and_fold_files,
};

fn deterministic_value(index: usize, lane: u32) -> Fp16 {
    Fp16::from_coefficients(core::array::from_fn(|coordinate| {
        let value = (index as u64)
            .wrapping_mul(1_000_003 + 2 * coordinate as u64)
            .wrapping_add(u64::from(lane) * 65_537)
            .wrapping_add(97 * coordinate as u64)
            % u64::from(M31_MODULUS);
        value as u32
    }))
    .expect("deterministic coordinates are canonical")
}

fn challenge(round: usize) -> Fp16 {
    Fp16::from_coefficients(core::array::from_fn(|coordinate| {
        (((round + 1) * 131 + (coordinate + 3) * 977) as u64 % u64::from(M31_MODULUS)) as u32
    }))
    .expect("challenge coordinates are canonical")
}

fn create_table(path: &Path, value_count: usize, lane: u32) -> Result<(), String> {
    let mut output = BufWriter::with_capacity(
        16 << 20,
        File::create(path).map_err(|error| error.to_string())?,
    );
    for index in 0..value_count {
        output
            .write_all(&deterministic_value(index, lane).encode())
            .map_err(|error| error.to_string())?;
    }
    output.flush().map_err(|error| error.to_string())
}

fn evaluate_round(coefficients: [Fp16; 3], at: Fp16) -> Fp16 {
    coefficients[0] + at * coefficients[1] + at.square() * coefficients[2]
}

fn boolean_sum(coefficients: [Fp16; 3]) -> Fp16 {
    coefficients[0] + coefficients[0] + coefficients[1] + coefficients[2]
}

fn parse_arguments() -> Result<(PathBuf, u8, usize, usize), String> {
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() < 2 || arguments.len() > 5 {
        return Err(
            "usage: file_backed_prelude_benchmark <scratch-dir> [log-size] [slab-log] [workers]"
                .into(),
        );
    }
    let log_size = arguments
        .get(2)
        .map_or(Ok(22_u8), |value| value.parse::<u8>())
        .map_err(|_| "invalid_log_size")?;
    let slab_log = arguments
        .get(3)
        .map_or(Ok(17_u8), |value| value.parse::<u8>())
        .map_err(|_| "invalid_slab_log")?;
    if log_size == 0 || log_size >= usize::BITS as u8 || slab_log == 0 || slab_log > log_size {
        return Err("unsupported_geometry".into());
    }
    let workers = arguments.get(4).map_or_else(
        || {
            std::thread::available_parallelism()
                .map(usize::from)
                .map_err(|_| "parallelism_unavailable")
        },
        |value| value.parse::<usize>().map_err(|_| "invalid_workers"),
    )?;
    if workers == 0 {
        return Err("invalid_workers".into());
    }
    Ok((
        PathBuf::from(&arguments[1]),
        log_size,
        1_usize << slab_log,
        workers,
    ))
}

fn run() -> Result<(), String> {
    let (scratch, log_size, slab_values, workers) = parse_arguments()?;
    fs::create_dir_all(&scratch).map_err(|error| error.to_string())?;
    let value_count = 1_usize << log_size;
    let paths = [
        scratch.join("input-left.bin"),
        scratch.join("input-right.bin"),
        scratch.join("output-left.bin"),
        scratch.join("output-right.bin"),
    ];
    let generation_started = Instant::now();
    for (lane, path) in paths.iter().enumerate() {
        create_table(path, value_count, lane as u32 + 1)?;
    }
    let generation_seconds = generation_started.elapsed().as_secs_f64();

    let mut current_count = value_count;
    let mut input_claim = None;
    let mut output_claim = None;
    let proving_started = Instant::now();
    for round in 0..usize::from(log_size) {
        let round_started = Instant::now();
        let current_challenge = challenge(round);
        let lane_workers = (workers / 2).max(1);
        let (input, output) = std::thread::scope(|scope| {
            let input = scope.spawn(|| {
                product_round_and_fold_files(
                    &paths[0],
                    &paths[1],
                    current_count,
                    current_challenge,
                    slab_values,
                    lane_workers,
                )
            });
            let output = scope.spawn(|| {
                product_round_and_fold_files(
                    &paths[2],
                    &paths[3],
                    current_count,
                    current_challenge,
                    slab_values,
                    lane_workers,
                )
            });
            Ok::<_, &str>((
                input.join().map_err(|_| "input_worker_panicked")?,
                output.join().map_err(|_| "output_worker_panicked")?,
            ))
        })?;
        let input = input.map_err(|error| error.to_string())?;
        let output = output.map_err(|error| error.to_string())?;
        let expected_input = input_claim.unwrap_or_else(|| boolean_sum(input.coefficients));
        let expected_output = output_claim.unwrap_or_else(|| boolean_sum(output.coefficients));
        if boolean_sum(input.coefficients) != expected_input
            || boolean_sum(output.coefficients) != expected_output
        {
            return Err(format!("round_recurrence_failed:{round}"));
        }
        input_claim = Some(evaluate_round(input.coefficients, current_challenge));
        output_claim = Some(evaluate_round(output.coefficients, current_challenge));
        current_count /= 2;
        if input.next_value_count != current_count || output.next_value_count != current_count {
            return Err(format!("round_shape_failed:{round}"));
        }
        println!(
            "round={round} values={} seconds={:.6}",
            current_count * 2,
            round_started.elapsed().as_secs_f64()
        );
    }
    let proving_seconds = proving_started.elapsed().as_secs_f64();
    for path in &paths {
        if fs::metadata(path).map_err(|error| error.to_string())?.len() != 64 {
            return Err(format!("terminal_file_length:{}", path.display()));
        }
    }
    println!("log_size={log_size}");
    println!("workers={workers}");
    println!("slab_values={slab_values}");
    println!("generation_seconds={generation_seconds:.6}");
    println!("dual_lane_proving_seconds={proving_seconds:.6}");
    println!("terminal_files_verified=true");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error={error}");
        std::process::exit(1);
    }
}
