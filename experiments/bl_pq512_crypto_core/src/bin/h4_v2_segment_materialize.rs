//! Stream-materialize one current H4-v2 native segment opening.
//!
//! The producer supplies the live canonical leaf payload stream and the
//! verifier-derived sorted query indices. This command hashes every leaf
//! under the current v2 leaf frame, builds the native 128-byte Merkle tree,
//! and writes exactly the segment grammar consumed by `BLH4PK02`. It never
//! accepts a legacy root and never derives a root from a caller assertion.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use bl_pq512_crypto_core::binding_root_v2::{
    BINDING_V2_BYTES, BindingMerkleLeafV2, BindingMerkleTreeV2,
};
use bl_pq512_crypto_core::h4_proof_package_v2::{
    H4RsSegmentDescriptorV2, answer_tensor_root_v2, h4_rs_segment_leaf_payload_v2,
};

const USAGE: &str = "usage: h4_v2_segment_materialize <boundary> <kind> <data-bytes> <leaf-count> <leaf-bytes> <raw> <indices> <output>";
const SOURCE_USAGE: &str = "usage: h4_v2_segment_materialize --source-tensor <boundary> <kind> <leaf-count> <leaf-bytes> <row-bytes> <indices> <output> <segment-0> ... <segment-n>";
const ANSWER_USAGE: &str = "usage: h4_v2_segment_materialize --answer-tensor <answer-coefficients>";
const SEGMENT_HEADER_BYTES: usize = 5 * 8 + 2 * 4 + BINDING_V2_BYTES;
const MAX_OPENINGS: usize = 4_096;

fn absolute_regular_file(value: &std::ffi::OsString, label: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{label}_path_not_absolute"));
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("{label}_metadata:{:?}", error.kind()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label}_not_regular"));
    }
    Ok(path)
}

fn output_path(value: &std::ffi::OsString) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err("output_path_not_absolute".to_owned());
    }
    if path.exists() {
        return Err("output_exists".to_owned());
    }
    Ok(path)
}

fn parse_u64(value: &std::ffi::OsString, label: &str) -> Result<u64, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{label}_utf8"))?
        .parse::<u64>()
        .map_err(|_| format!("{label}_invalid"))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

fn read_indices(path: &Path) -> Result<Vec<u64>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("indices_metadata:{:?}", error.kind()))?;
    if metadata.len() == 0 || metadata.len() % 4 != 0 {
        return Err("indices_length".to_owned());
    }
    let bytes = fs::read(path).map_err(|error| format!("indices_read:{:?}", error.kind()))?;
    let mut indices = Vec::with_capacity(bytes.len() / 4);
    for chunk in bytes.chunks_exact(4) {
        indices.push(u64::from(u32::from_be_bytes(
            chunk
                .try_into()
                .map_err(|_| "indices_encoding".to_owned())?,
        )));
    }
    if indices.is_empty()
        || indices.len() > MAX_OPENINGS
        || indices.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("indices_order".to_owned());
    }
    Ok(indices)
}

fn run_answer_tensor(args: &[std::ffi::OsString]) -> Result<(), String> {
    if args.len() != 3 {
        return Err(ANSWER_USAGE.to_owned());
    }
    let coefficients = absolute_regular_file(&args[2], "answer_coefficients")?;
    let metadata = fs::metadata(&coefficients)
        .map_err(|error| format!("answer_coefficients_metadata:{:?}", error.kind()))?;
    let expected =
        u64::try_from(bl_pq512_crypto_core::h4_proof_package_v2::H4_ANSWER_COEFFICIENT_BYTES)
            .map_err(|_| "answer_coefficients_geometry".to_owned())?;
    if metadata.len() != expected {
        return Err(format!(
            "answer_coefficients_length:{}/{}",
            metadata.len(),
            expected
        ));
    }
    let bytes = fs::read(&coefficients)
        .map_err(|error| format!("answer_coefficients_read:{:?}", error.kind()))?;
    let root = answer_tensor_root_v2(&bytes).map_err(|error| format!("answer_tensor:{error:?}"))?;
    println!("status=H4_V2_ANSWER_TENSOR_ROOT_MATERIALIZED");
    println!("root={}", hex(root.as_bytes()));
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn run_segment(args: &[std::ffi::OsString]) -> Result<(), String> {
    if args.len() != 9 {
        return Err(USAGE.to_owned());
    }
    let boundary = parse_u64(&args[1], "boundary")?;
    let kind = parse_u64(&args[2], "kind")?;
    let data_bytes = parse_u64(&args[3], "data_bytes")?;
    let leaf_count = parse_u64(&args[4], "leaf_count")?;
    let leaf_bytes = parse_u64(&args[5], "leaf_bytes")?;
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || leaf_bytes == 0
        || !leaf_bytes.is_multiple_of(64)
        || data_bytes != leaf_count.checked_mul(leaf_bytes).ok_or("geometry")?
    {
        return Err("geometry".to_owned());
    }
    let raw = absolute_regular_file(&args[6], "raw")?;
    let indices_path = absolute_regular_file(&args[7], "indices")?;
    let output = output_path(&args[8])?;
    let raw_metadata =
        fs::metadata(&raw).map_err(|error| format!("raw_metadata:{:?}", error.kind()))?;
    if raw_metadata.len() != data_bytes {
        return Err(format!("raw_length:{}/{}", raw_metadata.len(), data_bytes));
    }
    let indices = read_indices(&indices_path)?;
    if indices.last().copied().unwrap_or(leaf_count) >= leaf_count {
        return Err("indices_range".to_owned());
    }
    let descriptor = H4RsSegmentDescriptorV2 {
        boundary,
        kind,
        data_bytes,
        leaf_count,
        leaf_bytes,
    };
    let leaf_size = usize::try_from(leaf_bytes).map_err(|_| "leaf_bytes_host".to_owned())?;
    let mut reader = File::open(&raw).map_err(|error| format!("raw_open:{:?}", error.kind()))?;
    let mut payload = vec![0_u8; leaf_size];
    let mut leaf_digests =
        Vec::with_capacity(usize::try_from(leaf_count).map_err(|_| "leaf_count_host".to_owned())?);
    for index in 0..leaf_count {
        reader
            .read_exact(&mut payload)
            .map_err(|error| format!("raw_read:{:?}", error.kind()))?;
        let framed = h4_rs_segment_leaf_payload_v2(descriptor, &payload)
            .map_err(|error| format!("leaf_frame:{error:?}"))?;
        leaf_digests.push(
            BindingMerkleLeafV2::hash(index, &framed)
                .map_err(|error| format!("leaf_hash:{error:?}"))?
                .digest(),
        );
    }
    let tree = BindingMerkleTreeV2::from_leaf_digests(leaf_digests)
        .map_err(|error| format!("tree:{error:?}"))?;
    let proof = tree
        .prove(&indices)
        .map_err(|error| format!("proof:{error:?}"))?;
    let mut encoded = Vec::with_capacity(
        SEGMENT_HEADER_BYTES
            + indices.len() * 4
            + indices.len() * leaf_size
            + proof.frontier_digests().len() * BINDING_V2_BYTES,
    );
    encoded.extend_from_slice(&boundary.to_be_bytes());
    encoded.extend_from_slice(&kind.to_be_bytes());
    encoded.extend_from_slice(&data_bytes.to_be_bytes());
    encoded.extend_from_slice(&leaf_count.to_be_bytes());
    encoded.extend_from_slice(&leaf_bytes.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(indices.len())
            .map_err(|_| "opening_count".to_owned())?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(
        &u32::try_from(proof.frontier_digests().len())
            .map_err(|_| "frontier_count".to_owned())?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(tree.root().as_bytes());
    for index in &indices {
        encoded.extend_from_slice(
            &u32::try_from(*index)
                .map_err(|_| "index_width".to_owned())?
                .to_be_bytes(),
        );
    }
    for index in &indices {
        reader
            .seek(SeekFrom::Start(
                index.checked_mul(leaf_bytes).ok_or("seek_overflow")?,
            ))
            .map_err(|error| format!("raw_seek:{:?}", error.kind()))?;
        reader
            .read_exact(&mut payload)
            .map_err(|error| format!("opening_read:{:?}", error.kind()))?;
        encoded.extend_from_slice(&payload);
    }
    for digest in proof.frontier_digests() {
        encoded.extend_from_slice(digest.as_bytes());
    }
    if encoded.len() < SEGMENT_HEADER_BYTES {
        return Err("encoded_length".to_owned());
    }
    let partial = PathBuf::from(format!("{}.partial", output.display()));
    if partial.exists() {
        return Err("partial_output_exists".to_owned());
    }
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("partial_output_open:{:?}", error.kind()))?;
    if let Err(error) = writer.write_all(&encoded).and_then(|_| writer.sync_all()) {
        drop(writer);
        let _ = fs::remove_file(&partial);
        return Err(format!("partial_output_write:{:?}", error.kind()));
    }
    drop(writer);
    if output.exists() {
        let _ = fs::remove_file(&partial);
        return Err("output_created_during_materialization".to_owned());
    }
    fs::rename(&partial, &output).map_err(|error| {
        let _ = fs::remove_file(&partial);
        format!("output_publish:{:?}", error.kind())
    })?;
    println!("status=H4_V2_SEGMENT_MATERIALIZED");
    println!("root={}", hex(tree.root().as_bytes()));
    println!("segment_bytes={}", encoded.len());
    println!("opening_count={}", indices.len());
    println!("frontier_count={}", proof.frontier_digests().len());
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn run_source_tensor(args: &[std::ffi::OsString]) -> Result<(), String> {
    if args.len() < 10 {
        return Err(SOURCE_USAGE.to_owned());
    }
    let boundary = parse_u64(&args[2], "boundary")?;
    let kind = parse_u64(&args[3], "kind")?;
    let leaf_count = parse_u64(&args[4], "leaf_count")?;
    let leaf_bytes = parse_u64(&args[5], "leaf_bytes")?;
    let row_bytes = parse_u64(&args[6], "row_bytes")?;
    if leaf_count == 0
        || !leaf_count.is_power_of_two()
        || leaf_bytes == 0
        || !leaf_bytes.is_multiple_of(64)
        || row_bytes == 0
        || !row_bytes.is_multiple_of(64)
    {
        return Err("geometry".to_owned());
    }
    let segment_count = u64::try_from(args.len() - 9).map_err(|_| "segment_count".to_owned())?;
    if segment_count == 0
        || row_bytes
            .checked_mul(segment_count)
            .ok_or_else(|| "geometry".to_owned())?
            != leaf_bytes
    {
        return Err("interleave_geometry".to_owned());
    }
    let data_bytes = leaf_count
        .checked_mul(leaf_bytes)
        .ok_or_else(|| "geometry".to_owned())?;
    let indices_path = absolute_regular_file(&args[7], "indices")?;
    let output = output_path(&args[8])?;
    let indices = read_indices(&indices_path)?;
    if indices.last().copied().unwrap_or(leaf_count) >= leaf_count {
        return Err("indices_range".to_owned());
    }

    let segment_size = leaf_count
        .checked_mul(row_bytes)
        .ok_or_else(|| "segment_geometry".to_owned())?;
    let mut readers = Vec::with_capacity(
        usize::try_from(segment_count).map_err(|_| "segment_count_host".to_owned())?,
    );
    for (segment_index, value) in args[9..].iter().enumerate() {
        let path = absolute_regular_file(value, &format!("source_segment_{segment_index}"))?;
        let metadata = fs::metadata(&path).map_err(|error| {
            format!("source_segment_{segment_index}_metadata:{:?}", error.kind())
        })?;
        if metadata.len() != segment_size {
            return Err(format!(
                "source_segment_{segment_index}_length:{}/{}",
                metadata.len(),
                segment_size
            ));
        }
        readers.push(
            File::open(&path).map_err(|error| {
                format!("source_segment_{segment_index}_open:{:?}", error.kind())
            })?,
        );
    }
    let descriptor = H4RsSegmentDescriptorV2 {
        boundary,
        kind,
        data_bytes,
        leaf_count,
        leaf_bytes,
    };
    let leaf_size = usize::try_from(leaf_bytes).map_err(|_| "leaf_bytes_host".to_owned())?;
    let row_size = usize::try_from(row_bytes).map_err(|_| "row_bytes_host".to_owned())?;
    let mut payload = vec![0_u8; leaf_size];
    let mut row = vec![0_u8; row_size];
    let mut leaf_digests =
        Vec::with_capacity(usize::try_from(leaf_count).map_err(|_| "leaf_count_host".to_owned())?);
    for index in 0..leaf_count {
        for (segment_index, reader) in readers.iter_mut().enumerate() {
            reader.read_exact(&mut row).map_err(|error| {
                format!("source_segment_{segment_index}_read:{:?}", error.kind())
            })?;
            let start = segment_index
                .checked_mul(row_size)
                .ok_or_else(|| "payload_offset".to_owned())?;
            payload[start..start + row_size].copy_from_slice(&row);
        }
        let framed = h4_rs_segment_leaf_payload_v2(descriptor, &payload)
            .map_err(|error| format!("leaf_frame:{error:?}"))?;
        leaf_digests.push(
            BindingMerkleLeafV2::hash(index, &framed)
                .map_err(|error| format!("leaf_hash:{error:?}"))?
                .digest(),
        );
    }
    let tree = BindingMerkleTreeV2::from_leaf_digests(leaf_digests)
        .map_err(|error| format!("tree:{error:?}"))?;
    let proof = tree
        .prove(&indices)
        .map_err(|error| format!("proof:{error:?}"))?;
    let mut encoded = Vec::with_capacity(
        SEGMENT_HEADER_BYTES
            + indices.len() * 4
            + indices.len() * leaf_size
            + proof.frontier_digests().len() * BINDING_V2_BYTES,
    );
    encoded.extend_from_slice(&boundary.to_be_bytes());
    encoded.extend_from_slice(&kind.to_be_bytes());
    encoded.extend_from_slice(&data_bytes.to_be_bytes());
    encoded.extend_from_slice(&leaf_count.to_be_bytes());
    encoded.extend_from_slice(&leaf_bytes.to_be_bytes());
    encoded.extend_from_slice(
        &u32::try_from(indices.len())
            .map_err(|_| "opening_count".to_owned())?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(
        &u32::try_from(proof.frontier_digests().len())
            .map_err(|_| "frontier_count".to_owned())?
            .to_be_bytes(),
    );
    encoded.extend_from_slice(tree.root().as_bytes());
    for index in &indices {
        encoded.extend_from_slice(
            &u32::try_from(*index)
                .map_err(|_| "index_width".to_owned())?
                .to_be_bytes(),
        );
    }
    for index in &indices {
        for (segment_index, reader) in readers.iter_mut().enumerate() {
            reader
                .seek(SeekFrom::Start(
                    index
                        .checked_mul(row_bytes)
                        .ok_or_else(|| "seek_overflow".to_owned())?,
                ))
                .map_err(|error| {
                    format!("source_segment_{segment_index}_seek:{:?}", error.kind())
                })?;
            reader.read_exact(&mut row).map_err(|error| {
                format!(
                    "source_segment_{segment_index}_opening_read:{:?}",
                    error.kind()
                )
            })?;
            let start = segment_index
                .checked_mul(row_size)
                .ok_or_else(|| "payload_offset".to_owned())?;
            payload[start..start + row_size].copy_from_slice(&row);
        }
        encoded.extend_from_slice(&payload);
    }
    for digest in proof.frontier_digests() {
        encoded.extend_from_slice(digest.as_bytes());
    }
    let partial = PathBuf::from(format!("{}.partial", output.display()));
    if partial.exists() {
        return Err("partial_output_exists".to_owned());
    }
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)
        .map_err(|error| format!("partial_output_open:{:?}", error.kind()))?;
    if let Err(error) = writer.write_all(&encoded).and_then(|_| writer.sync_all()) {
        drop(writer);
        let _ = fs::remove_file(&partial);
        return Err(format!("partial_output_write:{:?}", error.kind()));
    }
    drop(writer);
    if output.exists() {
        let _ = fs::remove_file(&partial);
        return Err("output_created_during_materialization".to_owned());
    }
    fs::rename(&partial, &output).map_err(|error| {
        let _ = fs::remove_file(&partial);
        format!("output_publish:{:?}", error.kind())
    })?;
    println!("status=H4_V2_SOURCE_TENSOR_MATERIALIZED");
    println!("root={}", hex(tree.root().as_bytes()));
    println!("segment_bytes={}", encoded.len());
    println!("opening_count={}", indices.len());
    println!("frontier_count={}", proof.frontier_digests().len());
    println!("source_segment_count={segment_count}");
    println!("production_usable=false");
    println!("activation_allowed=false");
    Ok(())
}

fn main() -> ExitCode {
    let args = env::args_os().collect::<Vec<_>>();
    let result = if args.get(1).and_then(|value| value.to_str()) == Some("--answer-tensor") {
        run_answer_tensor(&args)
    } else if args.get(1).and_then(|value| value.to_str()) == Some("--source-tensor") {
        run_source_tensor(&args)
    } else {
        run_segment(&args)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERR {error}");
            ExitCode::from(2)
        }
    }
}
