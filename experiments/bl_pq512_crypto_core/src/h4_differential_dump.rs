//! Opt-in, write-once evidence for the H4 source/answer differential.
//!
//! The dump is activated only by the bounded diagnostic capture environment.
//! It never participates in an accepting predicate and is a no-op for normal
//! callers.  Files are created with create-new semantics so a retry cannot
//! replace an earlier observation.

use crate::field::Fp16;
use alloc::{
    format,
    string::{String, ToString},
};

#[cfg(feature = "std")]
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

#[derive(Clone, Copy, Debug)]
pub struct H4BufferAccess<'a> {
    pub label: &'a str,
    pub base_offset_bytes: u64,
    pub element_stride_bytes: u64,
    pub element_count: u64,
    pub index_formula: &'a str,
}

#[cfg(feature = "std")]
fn capture_directory() -> Result<Option<std::path::PathBuf>, String> {
    let Some(value) = env::var_os("BL_CURRENT_H4_CAPTURE_DIR") else {
        return Ok(None);
    };
    let path = std::path::PathBuf::from(value);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("h4_dump_directory:{path:?}:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || !path.is_absolute() {
        return Err("h4_dump_directory_invalid".to_string());
    }
    Ok(Some(path))
}

#[cfg(feature = "std")]
fn checked_name(name: &str) -> Result<(), String> {
    if name.is_empty() || Path::new(name).file_name().and_then(|value| value.to_str()) != Some(name)
    {
        return Err("h4_dump_name".to_string());
    }
    Ok(())
}

#[cfg(feature = "std")]
fn open_dump(name: &str) -> Result<Option<std::fs::File>, String> {
    checked_name(name)?;
    let Some(directory) = capture_directory()? else {
        return Ok(None);
    };
    let path = directory.join(name);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map(Some)
        .map_err(|error| format!("h4_dump_open:{path:?}:{error}"))
}

#[cfg(feature = "std")]
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[cfg(feature = "std")]
fn fp16_text(value: Fp16) -> String {
    hex(&value.encode())
}

#[cfg(feature = "std")]
pub fn write_h4_path_dump(
    name: &str,
    path_label: &str,
    point_vectors: &[(&str, &[Fp16])],
    vectors: &[(&str, &[Fp16])],
    buffers: &[H4BufferAccess<'_>],
    results: &[(&str, Fp16)],
) -> Result<(), String> {
    let Some(mut output) = open_dump(name)? else {
        return Ok(());
    };
    writeln!(output, "format=BLH4DIFF01").map_err(|error| error.to_string())?;
    writeln!(output, "path={path_label}").map_err(|error| error.to_string())?;
    let point_count = point_vectors
        .iter()
        .map(|(_, values)| values.len())
        .sum::<usize>();
    writeln!(output, "point_vector_count={}", point_vectors.len())
        .map_err(|error| error.to_string())?;
    writeln!(output, "point_count={point_count}").map_err(|error| error.to_string())?;
    let mut point_index = 0_usize;
    for (vector_index, (label, values)) in point_vectors.iter().enumerate() {
        writeln!(output, "point_vector[{vector_index}].label={label}")
            .map_err(|error| error.to_string())?;
        writeln!(
            output,
            "point_vector[{vector_index}].count={}",
            values.len()
        )
        .map_err(|error| error.to_string())?;
        for (index, value) in values.iter().copied().enumerate() {
            writeln!(output, "point[{point_index}].label={label}[{index}]")
                .map_err(|error| error.to_string())?;
            writeln!(output, "point[{point_index}].encoding={}", fp16_text(value))
                .map_err(|error| error.to_string())?;
            point_index += 1;
        }
    }
    writeln!(output, "vector_count={}", vectors.len()).map_err(|error| error.to_string())?;
    for (vector_index, (label, values)) in vectors.iter().enumerate() {
        writeln!(output, "vector[{vector_index}].label={label}")
            .map_err(|error| error.to_string())?;
        writeln!(output, "vector[{vector_index}].count={}", values.len())
            .map_err(|error| error.to_string())?;
        for (index, value) in values.iter().copied().enumerate() {
            writeln!(
                output,
                "vector[{vector_index}][{index}].label={label}[{index}]"
            )
            .map_err(|error| error.to_string())?;
            writeln!(
                output,
                "vector[{vector_index}][{index}].encoding={}",
                fp16_text(value)
            )
            .map_err(|error| error.to_string())?;
        }
    }
    writeln!(output, "buffer_count={}", buffers.len()).map_err(|error| error.to_string())?;
    for (index, buffer) in buffers.iter().enumerate() {
        writeln!(output, "buffer[{index}].label={}", buffer.label)
            .map_err(|error| error.to_string())?;
        writeln!(
            output,
            "buffer[{index}].base_offset_bytes={}",
            buffer.base_offset_bytes
        )
        .map_err(|error| error.to_string())?;
        writeln!(
            output,
            "buffer[{index}].element_stride_bytes={}",
            buffer.element_stride_bytes
        )
        .map_err(|error| error.to_string())?;
        writeln!(
            output,
            "buffer[{index}].element_count={}",
            buffer.element_count
        )
        .map_err(|error| error.to_string())?;
        writeln!(
            output,
            "buffer[{index}].index_formula={}",
            buffer.index_formula
        )
        .map_err(|error| error.to_string())?;
    }
    writeln!(output, "result_count={}", results.len()).map_err(|error| error.to_string())?;
    for (index, (label, value)) in results.iter().enumerate() {
        writeln!(output, "result[{index}].label={label}").map_err(|error| error.to_string())?;
        writeln!(output, "result[{index}].encoding={}", fp16_text(*value))
            .map_err(|error| error.to_string())?;
    }
    output.flush().map_err(|error| error.to_string())?;
    output
        .sync_all()
        .map_err(|error| format!("h4_dump_sync:{error}"))?;
    Ok(())
}

#[cfg(feature = "std")]
pub fn write_h4_u16_vector_dump(
    name: &str,
    vector_label: &str,
    values: &[u16],
) -> Result<(), String> {
    let Some(mut output) = open_dump(name)? else {
        return Ok(());
    };
    output
        .write_all(b"BLH4VEC01")
        .map_err(|error| error.to_string())?;
    let label = vector_label.as_bytes();
    let label_length = u16::try_from(label.len()).map_err(|_| "h4_dump_label".to_string())?;
    output
        .write_all(&label_length.to_be_bytes())
        .and_then(|_| output.write_all(&[0_u8; 6]))
        .and_then(|_| {
            output.write_all(
                &u64::try_from(values.len())
                    .map_err(|_| std::io::Error::other("h4_dump_count"))?
                    .to_be_bytes(),
            )
        })
        .and_then(|_| output.write_all(label))
        .map_err(|error| error.to_string())?;
    for value in values {
        output
            .write_all(&value.to_le_bytes())
            .map_err(|error| error.to_string())?;
    }
    output.flush().map_err(|error| error.to_string())?;
    output
        .sync_all()
        .map_err(|error| format!("h4_dump_sync:{error}"))?;
    Ok(())
}

/// Write an exact Fp16 vector for the differential run.
///
/// The vector is separate from the human-readable path dump: the latter
/// carries labels and indexing, while this file makes an element-for-element
/// comparison independent of formatting or rounding. Bytes are the canonical
/// `Fp16::encode()` representation in vector order.
#[cfg(feature = "std")]
pub fn write_h4_fp16_vector_dump(
    name: &str,
    vector_label: &str,
    values: &[Fp16],
) -> Result<(), String> {
    let Some(mut output) = open_dump(name)? else {
        return Ok(());
    };
    output
        .write_all(b"BLH4FP01")
        .map_err(|error| error.to_string())?;
    let label = vector_label.as_bytes();
    let label_length = u16::try_from(label.len()).map_err(|_| "h4_dump_label".to_string())?;
    output
        .write_all(&label_length.to_be_bytes())
        .and_then(|_| output.write_all(&[0_u8; 6]))
        .and_then(|_| {
            output.write_all(
                &u64::try_from(values.len())
                    .map_err(|_| std::io::Error::other("h4_dump_count"))?
                    .to_be_bytes(),
            )
        })
        .and_then(|_| output.write_all(label))
        .map_err(|error| error.to_string())?;
    for value in values {
        output
            .write_all(&value.encode())
            .map_err(|error| error.to_string())?;
    }
    output.flush().map_err(|error| error.to_string())?;
    output
        .sync_all()
        .map_err(|error| format!("h4_dump_sync:{error}"))?;
    Ok(())
}

#[cfg(feature = "std")]
pub fn write_h4_scalar_dump(
    name: &str,
    path_label: &str,
    results: &[(&str, Fp16)],
) -> Result<(), String> {
    write_h4_path_dump(name, path_label, &[], &[], &[], results)
}

#[cfg(not(feature = "std"))]
pub fn write_h4_path_dump(
    _name: &str,
    _path_label: &str,
    _point_vectors: &[(&str, &[Fp16])],
    _vectors: &[(&str, &[Fp16])],
    _buffers: &[H4BufferAccess<'_>],
    _results: &[(&str, Fp16)],
) -> Result<(), String> {
    Ok(())
}
