use std::{
    io::{self, BufReader, BufWriter, Read, Write},
    time::Instant,
};

use bl_pq512_crypto_core::field::Fp16;

const INPUT_MAGIC: &[u8; 8] = b"BLP9IN01";
const OUTPUT_MAGIC: &[u8; 8] = b"BLP9OUT1";
const POLYNOMIALS: usize = 9;
const COEFFICIENTS: usize = 2_048;
const FP16_BYTES: usize = 64;

fn read_fp16(reader: &mut impl Read) -> Result<Fp16, String> {
    let mut encoded = [0_u8; FP16_BYTES];
    reader
        .read_exact(&mut encoded)
        .map_err(|error| format!("read:{error}"))?;
    Fp16::decode(&encoded).map_err(|error| format!("fp16:{error:?}"))
}

fn evaluate(coefficients: &[Fp16], point: Fp16) -> Fp16 {
    coefficients
        .iter()
        .rev()
        .fold(Fp16::ZERO, |accumulator, coefficient| {
            accumulator * point + *coefficient
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
    let mut polynomials = vec![vec![Fp16::ZERO; COEFFICIENTS]; POLYNOMIALS];
    for polynomial in &mut polynomials {
        for coefficient in polynomial {
            *coefficient = read_fp16(&mut reader)?;
        }
    }
    let mut points = Vec::with_capacity(POLYNOMIALS);
    for _ in 0..POLYNOMIALS {
        points.push(read_fp16(&mut reader)?);
    }
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| format!("trailing:{error}"))?
        != 0
    {
        return Err("trailing_input".to_string());
    }
    let evaluations = polynomials
        .iter()
        .zip(points)
        .map(|(polynomial, point)| evaluate(polynomial, point))
        .collect::<Vec<_>>();
    let total = evaluations
        .iter()
        .copied()
        .fold(Fp16::ZERO, |accumulator, value| accumulator + value);
    writer
        .write_all(OUTPUT_MAGIC)
        .map_err(|error| format!("output:{error}"))?;
    for evaluation in evaluations {
        writer
            .write_all(&evaluation.encode())
            .map_err(|error| format!("output:{error}"))?;
    }
    writer
        .write_all(&total.encode())
        .and_then(|_| writer.write_all(&started.elapsed().as_secs_f64().to_be_bytes()))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("output:{error}"))?;
    Ok(())
}
