//! Owned, bounded-memory scratch storage for authenticated streaming executions.

use core::fmt;

use alloc::{format, string::String, vec, vec::Vec};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::field::M31;
use crate::streaming_ir::{StreamingAirManifest, StreamingExecutionVerifier, StreamingIrError};

const SCRATCH_MARKER: &[u8; 8] = b"BLPQSCR1";
const SCRATCH_MARKER_LENGTH: u64 = 73;

#[derive(Debug)]
pub enum StreamingStoreError {
    Streaming(StreamingIrError),
    Io(std::io::ErrorKind),
    Parent,
    Ownership,
    FileShape,
    Overflow,
}

impl From<StreamingIrError> for StreamingStoreError {
    fn from(value: StreamingIrError) -> Self {
        Self::Streaming(value)
    }
}

impl From<std::io::Error> for StreamingStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}

impl fmt::Display for StreamingStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 streaming store error: {self:?}")
    }
}

impl core::error::Error for StreamingStoreError {}

pub struct StreamingScratchStore {
    manifest: StreamingAirManifest,
    verifier: StreamingExecutionVerifier,
    session_path: PathBuf,
    marker: Option<File>,
    current_file: Option<File>,
    finished: bool,
}

impl StreamingScratchStore {
    pub fn create(
        scratch_parent: &Path,
        session_nonce: &[u8; 32],
        manifest: &StreamingAirManifest,
    ) -> Result<Self, StreamingStoreError> {
        if !scratch_parent.is_absolute() || !scratch_parent.is_dir() {
            return Err(StreamingStoreError::Parent);
        }
        let session_path = scratch_parent.join(session_directory_name(session_nonce));
        fs::create_dir(&session_path)?;
        let marker_path = session_path.join("OWNER");
        let marker_result = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&marker_path);
        let mut marker = match marker_result {
            Ok(file) => file,
            Err(error) => {
                let _ = fs::remove_dir(&session_path);
                return Err(error.into());
            }
        };
        if let Err(error) = marker
            .write_all(SCRATCH_MARKER)
            .and_then(|()| marker.write_all(&manifest.commitment))
            .and_then(|()| marker.write_all(&[0]))
            .and_then(|()| marker.sync_data())
        {
            drop(marker);
            let _ = fs::remove_file(&marker_path);
            let _ = fs::remove_dir(&session_path);
            return Err(error.into());
        }
        Ok(Self {
            manifest: manifest.clone(),
            verifier: StreamingExecutionVerifier::new(manifest),
            session_path,
            marker: Some(marker),
            current_file: None,
            finished: false,
        })
    }

    pub fn absorb(&mut self, encoded: &[u8]) -> Result<usize, StreamingStoreError> {
        let chunk = self.verifier.absorb(encoded)?;
        let expected_count = self
            .manifest
            .tables
            .get(chunk.table_index)
            .and_then(|table| {
                table
                    .columns
                    .iter()
                    .find(|column| column.column_index == chunk.column_index)
            })
            .map(|column| column.value_count)
            .ok_or(StreamingStoreError::FileShape)?;
        if chunk.row_start == 0 {
            if self.current_file.is_some() {
                return Err(StreamingStoreError::FileShape);
            }
            self.current_file = Some(OpenOptions::new().write(true).create_new(true).open(
                column_path(&self.session_path, chunk.table_index, chunk.column_index),
            )?);
        }
        let file = self
            .current_file
            .as_mut()
            .ok_or(StreamingStoreError::FileShape)?;
        for value in &chunk.values {
            file.write_all(&value.as_u32().to_be_bytes())?;
        }
        let row_end = chunk
            .row_start
            .checked_add(chunk.values.len())
            .ok_or(StreamingStoreError::Overflow)?;
        if row_end == expected_count {
            file.sync_data()?;
            self.current_file = None;
        }
        Ok(chunk.values.len())
    }

    pub fn finish(mut self) -> Result<StreamingScratchExecution, StreamingStoreError> {
        self.verifier.finish()?;
        if self.current_file.is_some() {
            return Err(StreamingStoreError::FileShape);
        }
        validate_file_shapes(&self.session_path, &self.manifest)?;
        let marker = self.marker.as_mut().ok_or(StreamingStoreError::Ownership)?;
        marker.seek(SeekFrom::Start(SCRATCH_MARKER_LENGTH - 1))?;
        marker.write_all(&[1])?;
        marker.sync_data()?;
        drop(self.marker.take());
        self.finished = true;
        Ok(StreamingScratchExecution {
            manifest: self.manifest.clone(),
            session_path: self.session_path.clone(),
        })
    }
}

impl Drop for StreamingScratchStore {
    fn drop(&mut self) {
        if !self.finished {
            drop(self.marker.take());
            let _ = cleanup_owned_session(&self.session_path, &self.manifest.commitment);
        }
    }
}

pub struct StreamingScratchExecution {
    manifest: StreamingAirManifest,
    session_path: PathBuf,
}

impl StreamingScratchExecution {
    #[must_use]
    pub const fn manifest(&self) -> &StreamingAirManifest {
        &self.manifest
    }

    #[must_use]
    pub fn scratch_path(&self) -> &Path {
        &self.session_path
    }

    pub fn read_column_range(
        &self,
        table_index: usize,
        column_index: usize,
        row_start: usize,
        maximum_values: usize,
    ) -> Result<Vec<M31>, StreamingStoreError> {
        if maximum_values == 0 {
            return Err(StreamingStoreError::FileShape);
        }
        let value_count = self
            .manifest
            .tables
            .get(table_index)
            .and_then(|table| {
                table
                    .columns
                    .iter()
                    .find(|column| column.column_index == column_index)
            })
            .map(|column| column.value_count)
            .ok_or(StreamingStoreError::FileShape)?;
        if row_start >= value_count {
            return Err(StreamingStoreError::FileShape);
        }
        let count = maximum_values.min(value_count - row_start);
        let offset = u64::try_from(row_start)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .ok_or(StreamingStoreError::Overflow)?;
        let byte_count = count.checked_mul(4).ok_or(StreamingStoreError::Overflow)?;
        let mut encoded = vec![0_u8; byte_count];
        let mut file = File::open(column_path(&self.session_path, table_index, column_index))?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut encoded)?;
        let mut values = Vec::with_capacity(count);
        for word in encoded.chunks_exact(4) {
            let raw = u32::from_be_bytes(
                word.try_into()
                    .map_err(|_| StreamingStoreError::FileShape)?,
            );
            values.push(M31::from_canonical(raw).map_err(|_| StreamingStoreError::FileShape)?);
        }
        Ok(values)
    }
}

impl Drop for StreamingScratchExecution {
    fn drop(&mut self) {
        let _ = cleanup_owned_session(&self.session_path, &self.manifest.commitment);
    }
}

fn session_directory_name(nonce: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::from("blpq-stream-");
    for byte in nonce {
        name.push(DIGITS[usize::from(byte >> 4)] as char);
        name.push(DIGITS[usize::from(byte & 15)] as char);
    }
    name
}

fn column_path(parent: &Path, table_index: usize, column_index: usize) -> PathBuf {
    parent.join(format!("t{table_index:08x}-c{column_index:08x}.m31"))
}

fn validate_file_shapes(
    session_path: &Path,
    manifest: &StreamingAirManifest,
) -> Result<(), StreamingStoreError> {
    for table in &manifest.tables {
        for column in &table.columns {
            let expected = u64::try_from(column.value_count)
                .ok()
                .and_then(|value| value.checked_mul(4))
                .ok_or(StreamingStoreError::Overflow)?;
            if fs::metadata(column_path(
                session_path,
                column.table_index,
                column.column_index,
            ))?
            .len()
                != expected
            {
                return Err(StreamingStoreError::FileShape);
            }
        }
    }
    Ok(())
}

fn cleanup_owned_session(
    session_path: &Path,
    expected_commitment: &[u8; 64],
) -> Result<(), StreamingStoreError> {
    let marker_path = session_path.join("OWNER");
    let mut marker = File::open(&marker_path)?;
    let mut observed = [0_u8; SCRATCH_MARKER_LENGTH as usize];
    marker.read_exact(&mut observed)?;
    if &observed[..8] != SCRATCH_MARKER || &observed[8..72] != expected_commitment {
        return Err(StreamingStoreError::Ownership);
    }
    drop(marker);
    fs::remove_dir_all(session_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::streaming_ir::{
        STREAMING_VALUE_CHUNK_MAGIC, STREAMING_VALUE_CHUNK_VERSION, StreamingColumnManifest,
        StreamingTableManifest, streaming_column_commitment,
    };

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_parent() -> PathBuf {
        let counter = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "blpq-streaming-store-test-{}-{counter}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn fixture() -> (StreamingAirManifest, Vec<M31>) {
        let values = vec![
            M31::from_canonical(1).unwrap(),
            M31::from_canonical(2).unwrap(),
            M31::from_canonical(3).unwrap(),
        ];
        let program_commitment = [0x31; 64];
        let commitment = streaming_column_commitment(&program_commitment, 0, 0, &values).unwrap();
        (
            StreamingAirManifest {
                program_binary_commitment: program_commitment,
                public_inputs: Vec::new(),
                public_bindings: Vec::new(),
                tables: vec![StreamingTableManifest {
                    table_index: 0,
                    row_count: values.len(),
                    columns: vec![StreamingColumnManifest {
                        table_index: 0,
                        column_index: 0,
                        value_count: values.len(),
                        commitment,
                    }],
                }],
                commitment: [0x51; 64],
            },
            values,
        )
    }

    fn chunk(manifest: &StreamingAirManifest, row_start: usize, values: &[M31]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(STREAMING_VALUE_CHUNK_MAGIC);
        encoded.extend_from_slice(&STREAMING_VALUE_CHUNK_VERSION.to_be_bytes());
        encoded.extend_from_slice(&manifest.program_binary_commitment);
        encoded.extend_from_slice(&manifest.commitment);
        encoded.extend_from_slice(&0_u32.to_be_bytes());
        encoded.extend_from_slice(&0_u32.to_be_bytes());
        encoded.extend_from_slice(&u64::try_from(row_start).unwrap().to_be_bytes());
        encoded.extend_from_slice(&u32::try_from(values.len()).unwrap().to_be_bytes());
        for value in values {
            encoded.extend_from_slice(&value.as_u32().to_be_bytes());
        }
        encoded
    }

    #[test]
    fn complete_store_reads_bounded_ranges_and_cleans_owned_directory() {
        let parent = test_parent();
        let (manifest, values) = fixture();
        let mut store = StreamingScratchStore::create(&parent, &[0x61; 32], &manifest).unwrap();
        assert_eq!(store.absorb(&chunk(&manifest, 0, &values[..2])).unwrap(), 2);
        assert_eq!(store.absorb(&chunk(&manifest, 2, &values[2..])).unwrap(), 1);
        let execution = store.finish().unwrap();
        assert!(execution.scratch_path().is_dir());
        assert_eq!(
            execution.read_column_range(0, 0, 1, 8).unwrap(),
            values[1..]
        );
        drop(execution);
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
        fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn incomplete_store_cleans_only_its_owned_directory() {
        let parent = test_parent();
        let unrelated = parent.join("unrelated");
        fs::write(&unrelated, b"preserve").unwrap();
        let (manifest, values) = fixture();
        {
            let mut store = StreamingScratchStore::create(&parent, &[0x71; 32], &manifest).unwrap();
            store.absorb(&chunk(&manifest, 0, &values[..1])).unwrap();
        }
        assert_eq!(fs::read(&unrelated).unwrap(), b"preserve");
        fs::remove_file(unrelated).unwrap();
        fs::remove_dir(parent).unwrap();
    }
}
