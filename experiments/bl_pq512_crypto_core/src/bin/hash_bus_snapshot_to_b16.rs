use std::{
    env,
    fs::{File, read},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use bl_pq512_crypto_core::{
    hash_bus::{build_hash_bus_descriptor, build_hash_bus_descriptor_with_state},
    hash_bus_b16_boundary::{
        HASH_BUS_B16_MAGIC, HASH_BUS_B16_STATE_MAGIC, HASH_BUS_B16_STATE_VERSION,
        HASH_BUS_B16_VERSION, HashBusB16BoundaryFile,
    },
    hash_bus_snapshot::HashBusSnapshot,
    hash_bus_source::{KECCAK_STATE_BITS, for_each_hash_bus_b16_group},
};
use sha3::{Digest, Sha3_512};

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[0] == "--inspect" {
        return inspect(&PathBuf::from(&arguments[1]));
    }
    if arguments.len() != 2 {
        return Err(
            "usage: hash_bus_snapshot_to_b16 INPUT OUTPUT | --inspect BOUNDARY".to_string(),
        );
    }
    let input = PathBuf::from(&arguments[0]);
    let output = PathBuf::from(&arguments[1]);
    if input == output {
        return Err("arguments".to_string());
    }
    let encoded = read(&input).map_err(|error| format!("read_snapshot:{error}"))?;
    let snapshot =
        HashBusSnapshot::decode(&encoded).map_err(|error| format!("decode_snapshot:{error:?}"))?;
    let descriptor = if snapshot.state_composed {
        build_hash_bus_descriptor_with_state(snapshot.profile)
    } else {
        build_hash_bus_descriptor(snapshot.profile)
    }
    .map_err(|error| format!("descriptor:{error:?}"))?;
    if descriptor.descriptor_commitment != snapshot.descriptor_commitment {
        return Err("descriptor_commitment".to_string());
    }

    let file = File::create(&output).map_err(|error| format!("create_output:{error}"))?;
    let mut writer = BufWriter::with_capacity(1 << 20, file);
    let mut hash = Sha3_512::new();
    let mut bytes_written = 0_u64;
    let mut sink_write_error = None;
    let mut write = |bytes: &[u8]| -> Result<(), String> {
        writer
            .write_all(bytes)
            .map_err(|error| format!("write_output:{error}"))?;
        hash.update(bytes);
        bytes_written = bytes_written
            .checked_add(u64::try_from(bytes.len()).map_err(|_| "output_length".to_string())?)
            .ok_or_else(|| "output_length".to_string())?;
        Ok(())
    };
    let (output_magic, output_version) = if snapshot.state_composed {
        (HASH_BUS_B16_STATE_MAGIC, HASH_BUS_B16_STATE_VERSION)
    } else {
        (HASH_BUS_B16_MAGIC, HASH_BUS_B16_VERSION)
    };
    write(output_magic)?;
    write(&output_version.to_be_bytes())?;
    write(&[snapshot.profile as u8])?;
    write(&snapshot.semantic_program_commitment)?;
    write(&snapshot.descriptor_commitment)?;
    write(&snapshot.semantic_port_commitment)?;
    write(&descriptor.coprocessor_shards.to_be_bytes())?;
    write(&descriptor.padded_permutations.to_be_bytes())?;
    write(
        &u16::try_from(KECCAK_STATE_BITS)
            .map_err(|_| "state_bits".to_string())?
            .to_be_bytes(),
    )?;

    let mut expected_shard = 0_u16;
    let mut expected_group = 0_u16;
    let group_count = usize::try_from(bl_pq512_crypto_core::hash_bus::GROUP_COUNT)
        .map_err(|_| "group_count".to_string())?;
    let values_per_boundary = KECCAK_STATE_BITS
        .checked_mul(group_count)
        .ok_or_else(|| "boundary_length".to_string())?;
    let mut shard_input = vec![0_u16; values_per_boundary];
    let mut shard_output = vec![0_u16; values_per_boundary];
    let mut byte_chunk = Vec::with_capacity(1 << 20);
    let messages = snapshot.messages.iter().map(|message| message.borrowed());
    for_each_hash_bus_b16_group(
        &descriptor,
        messages,
        |shard, group, input_patterns, output_patterns| {
            if shard != expected_shard || group != expected_group {
                return Err(bl_pq512_crypto_core::hash_bus_source::HashBusSourceError::Schedule);
            }
            let group = usize::from(group);
            for wire in 0..KECCAK_STATE_BITS {
                let index = wire * group_count + group;
                shard_input[index] = input_patterns[wire];
                shard_output[index] = output_patterns[wire];
            }
            expected_group += 1;
            if u64::from(expected_group) == bl_pq512_crypto_core::hash_bus::GROUP_COUNT {
                for boundary in [&shard_input, &shard_output] {
                    for patterns in boundary.chunks((1 << 20) / 2) {
                        byte_chunk.clear();
                        for pattern in patterns {
                            byte_chunk.extend_from_slice(&pattern.to_le_bytes());
                        }
                        write(&byte_chunk).map_err(|error| {
                            sink_write_error = Some(error);
                            bl_pq512_crypto_core::hash_bus_source::HashBusSourceError::Overflow
                        })?;
                    }
                }
                expected_group = 0;
                expected_shard += 1;
            }
            Ok(())
        },
    )
    .map_err(|error| {
        sink_write_error
            .take()
            .unwrap_or_else(|| format!("stream_bus:{error:?}"))
    })?;
    if expected_shard != descriptor.coprocessor_shards || expected_group != 0 {
        return Err("group_count".to_string());
    }
    writer
        .flush()
        .map_err(|error| format!("flush_output:{error}"))?;
    drop(writer);
    let digest: [u8; 64] = hash.finalize().into();
    println!("profile={:?}", snapshot.profile);
    println!(
        "semantic_program_commitment={}",
        hex(&snapshot.semantic_program_commitment)
    );
    println!(
        "descriptor_commitment={}",
        hex(&snapshot.descriptor_commitment)
    );
    println!(
        "semantic_port_commitment={}",
        hex(&snapshot.semantic_port_commitment)
    );
    println!("coprocessor_shards={}", descriptor.coprocessor_shards);
    println!("total_permutations={}", descriptor.total_permutations);
    println!(
        "groups={}",
        u64::from(descriptor.coprocessor_shards) * 8_192
    );
    println!("live_wires_per_boundary={KECCAK_STATE_BITS}");
    println!("output_bytes={bytes_written}");
    println!(
        "output_decimal_mb={:.6}",
        bytes_written as f64 / 1_000_000.0
    );
    println!("output_sha3_512={}", hex(&digest));
    Ok(())
}

fn inspect(path: &Path) -> Result<(), String> {
    let mut boundary =
        HashBusB16BoundaryFile::open(path).map_err(|error| format!("open_boundary:{error:?}"))?;
    let header = boundary.header().clone();
    let mut patterns = 0_u64;
    for shard in 0..header.coprocessor_shards {
        let shard = boundary
            .read_shard(shard)
            .map_err(|error| format!("read_shard:{error:?}"))?;
        patterns = patterns
            .checked_add(
                u64::try_from(shard.input.len() + shard.output.len())
                    .map_err(|_| "pattern_count".to_string())?,
            )
            .ok_or_else(|| "pattern_count".to_string())?;
    }
    println!("profile={:?}", header.profile);
    println!(
        "semantic_program_commitment={}",
        hex(&header.semantic_program_commitment)
    );
    println!(
        "descriptor_commitment={}",
        hex(&header.descriptor_commitment)
    );
    println!(
        "semantic_port_commitment={}",
        hex(&header.semantic_port_commitment)
    );
    println!("coprocessor_shards={}", header.coprocessor_shards);
    println!("padded_permutations={}", header.padded_permutations);
    println!("live_wires_per_boundary={}", header.live_wires);
    println!("decoded_patterns={patterns}");
    println!("file_bytes={}", header.file_bytes);
    println!(
        "file_decimal_mb={:.6}",
        header.file_bytes as f64 / 1_000_000.0
    );
    println!("file_sha3_512={}", hex(&header.file_sha3_512));
    println!("boundary_verified=true");
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
