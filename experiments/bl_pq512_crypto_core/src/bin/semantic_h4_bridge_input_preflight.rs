use std::{env, fs, path::Path};

use bl_pq512_crypto_core::{
    hash_bus_b16_boundary::HashBusB16BoundaryFile,
    hash_bus_snapshot::{HashBusSnapshot, MAX_HASH_BUS_SNAPSHOT_BYTES},
    semantic_h4_bridge_accelerator_plan::{
        semantic_h4_bridge_accelerator_plan, semantic_h4_bridge_required_free_device_bytes,
    },
    semantic_h4_bridge_boundary::{PackedB16SemanticH4Boundary, SemanticH4BridgeBoundarySource},
    semantic_h4_bridge_gkr::{SemanticH4BridgeCircuit, SemanticH4BridgeProfile},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("ERR:{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    let [boundary_path, snapshot_path] = arguments.as_slice() else {
        return Err("usage:semantic_h4_bridge_input_preflight BOUNDARY SNAPSHOT".to_string());
    };
    let boundary_path = Path::new(boundary_path);
    let snapshot_path = Path::new(snapshot_path);
    if !boundary_path.is_file() || !snapshot_path.is_file() {
        return Err("input_missing".to_string());
    }
    let snapshot_bytes = fs::metadata(snapshot_path)
        .map_err(|_| "snapshot_metadata".to_string())?
        .len();
    if snapshot_bytes == 0 || snapshot_bytes > MAX_HASH_BUS_SNAPSHOT_BYTES as u64 {
        return Err("snapshot_size".to_string());
    }
    let encoded = fs::read(snapshot_path).map_err(|_| "snapshot_read".to_string())?;
    let snapshot =
        HashBusSnapshot::decode(&encoded).map_err(|error| format!("snapshot:{error:?}"))?;
    let mut boundary = HashBusB16BoundaryFile::open(boundary_path)
        .map_err(|error| format!("boundary:{error:?}"))?;
    let header = boundary.header().clone();
    let source = PackedB16SemanticH4Boundary::from_snapshot(&mut boundary, &snapshot)
        .map_err(|error| format!("join:{error:?}"))?;
    println!("status=verified");
    println!("profile={:?}", header.profile);
    println!("state_composed=true");
    println!("calls={}", source.total_calls());
    println!("permutations={}", source.total_permutations());
    println!("shards={}", header.coprocessor_shards);
    println!("snapshot_bytes={snapshot_bytes}");
    println!("boundary_bytes={}", header.file_bytes);
    let bridge_profile = match header.profile {
        bl_pq512_crypto_core::wave1a_global_schedule::Profile::K128Calibration => {
            SemanticH4BridgeProfile::K128
        }
        bl_pq512_crypto_core::wave1a_global_schedule::Profile::K512Calibration => {
            SemanticH4BridgeProfile::K512
        }
        _ => return Err("profile_unsupported".to_string()),
    };
    let plans = semantic_h4_bridge_accelerator_plan(bridge_profile)
        .ok_or_else(|| "accelerator_plan".to_string())?;
    let required_device_free_bytes = semantic_h4_bridge_required_free_device_bytes(bridge_profile)
        .ok_or_else(|| "accelerator_device_requirement".to_string())?;
    let adapter = SemanticH4BridgeBoundarySource::new(bridge_profile, &source)
        .map_err(|error| format!("adapter:{error:?}"))?;
    let live_rate_groups = usize::try_from(source.total_permutations())
        .map_err(|_| "rate_groups".to_string())?
        .checked_mul(72)
        .ok_or_else(|| "rate_groups".to_string())?;
    let live_block_groups =
        usize::try_from(source.total_permutations()).map_err(|_| "block_groups".to_string())?;
    let live_digest_groups = usize::try_from(source.total_calls())
        .map_err(|_| "digest_groups".to_string())?
        .checked_mul(64)
        .ok_or_else(|| "digest_groups".to_string())?;
    for (circuit, live_groups, group_log) in [
        (
            SemanticH4BridgeCircuit::Rate,
            live_rate_groups,
            bridge_profile.rate_group_log(),
        ),
        (SemanticH4BridgeCircuit::Inactive, live_block_groups, 19),
        (SemanticH4BridgeCircuit::Capacity, live_block_groups, 19),
        (SemanticH4BridgeCircuit::Digest, live_digest_groups, 24),
    ] {
        let domain = 1_usize
            .checked_shl(u32::from(group_log))
            .ok_or_else(|| "relation_domain".to_string())?;
        for group in [0, live_groups - 1, domain - 1] {
            let value = adapter
                .relation_value(circuit, group)
                .map_err(|error| format!("relation:{circuit:?}:{group}:{error:?}"))?;
            if value != bl_pq512_crypto_core::field::Fp16::ZERO {
                if circuit == SemanticH4BridgeCircuit::Digest {
                    let call = group / 64;
                    let byte = group % 64;
                    return Err(format!(
                        "relation_nonzero:{circuit:?}:{group}:call={call}:byte={byte}:boundary={}:expected={}",
                        source
                            .boundary_digest_byte(call, byte)
                            .map_err(|error| format!("boundary_digest:{error:?}"))?,
                        source
                            .expected_digest_byte(call, byte)
                            .map_err(|error| format!("expected_digest:{error:?}"))?,
                    ));
                }
                return Err(format!("relation_nonzero:{circuit:?}:{group}"));
            }
        }
    }
    println!("bridge_layers={}", plans.len());
    println!("relation_edge_samples=12");
    println!(
        "maximum_streaming_rounds={}",
        plans
            .iter()
            .map(|plan| plan.streaming_rounds)
            .max()
            .unwrap_or(0)
    );
    println!(
        "maximum_transition_table_bytes={}",
        plans
            .iter()
            .map(|plan| plan.transition_table_bytes)
            .max()
            .unwrap_or(0)
    );
    println!(
        "maximum_chunk_working_set_bytes={}",
        plans
            .iter()
            .map(|plan| plan.chunk_working_set_bytes)
            .max()
            .unwrap_or(0)
    );
    println!(
        "minimum_chunk_groups={}",
        plans
            .iter()
            .map(|plan| plan.chunk_groups)
            .min()
            .unwrap_or(0)
    );
    println!("required_free_device_bytes={required_device_free_bytes}");
    println!(
        "semantic_port_commitment={}",
        hex(&header.semantic_port_commitment)
    );
    println!("proofSuiteId=null");
    println!("production_usable=false");
    println!("activation=false");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}
