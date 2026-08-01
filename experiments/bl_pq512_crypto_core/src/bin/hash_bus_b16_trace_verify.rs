use std::{env, path::PathBuf, time::Instant};

use bl_pq512_crypto_core::{
    hash_bus_b16_boundary::HashBusB16BoundaryFile, hash_bus_b16_gkr_plan::HashBusB16GkrPlan,
    hash_bus_b16_trace::verify_hash_bus_b16_shard,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 {
        return Err("usage: hash_bus_b16_trace_verify BOUNDARY".to_string());
    }
    let path = PathBuf::from(&arguments[0]);
    let started = Instant::now();
    let plan = HashBusB16GkrPlan::selected().map_err(|error| format!("plan:{error:?}"))?;
    let plan_bytes = plan
        .encode()
        .map_err(|error| format!("plan_encode:{error:?}"))?;
    let plan_commitment = plan
        .commitment()
        .map_err(|error| format!("plan_commitment:{error:?}"))?;
    let mut boundary =
        HashBusB16BoundaryFile::open(&path).map_err(|error| format!("boundary:{error:?}"))?;
    let header = boundary.header().clone();
    let mut shard_seconds = Vec::with_capacity(usize::from(header.coprocessor_shards));
    for shard_index in 0..header.coprocessor_shards {
        let shard = boundary
            .read_shard(shard_index)
            .map_err(|error| format!("read_shard:{shard_index}:{error:?}"))?;
        let shard_started = Instant::now();
        verify_hash_bus_b16_shard(&shard, 16)
            .map_err(|error| format!("verify_shard:{shard_index}:{error:?}"))?;
        shard_seconds.push(shard_started.elapsed().as_secs_f64());
    }
    println!("profile={:?}", header.profile);
    println!("coprocessor_shards={}", header.coprocessor_shards);
    println!("logical_workers=16");
    println!("gkr_plan_bytes={}", plan_bytes.len());
    println!("gkr_plan_commitment={}", hex(&plan_commitment));
    println!("file_bytes={}", header.file_bytes);
    println!("file_sha3_512={}", hex(&header.file_sha3_512));
    for (shard, seconds) in shard_seconds.iter().enumerate() {
        println!("shard_{shard}_verification_seconds={seconds:.6}");
    }
    println!("total_seconds={:.6}", started.elapsed().as_secs_f64());
    println!("semantic_keccak_boundary_verified=true");
    println!("complete_proof_qualification=false");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    output
}
