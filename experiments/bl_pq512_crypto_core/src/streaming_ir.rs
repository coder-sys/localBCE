//! Canonical program-bound manifest for out-of-core AIR executions.

use core::fmt;

use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::air_ir::{AIR_PROGRAM_DOMAIN, AirIrError, parse_air_program};
use crate::field::{M31, M31_MODULUS};

pub const STREAMING_MANIFEST_MAGIC: &[u8; 8] = b"BLPQAIM1";
pub const STREAMING_MANIFEST_VERSION: u16 = 1;
pub const STREAMING_COLUMN_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/STREAMING-AIR-COLUMN/v1\0";
pub const STREAMING_MANIFEST_DOMAIN: &[u8] = b"BL/PQ512/WAVE1B/STREAMING-AIR-MANIFEST/v1\0";
pub const MAX_STREAMING_MANIFEST_BYTES: usize = 64 << 20;
pub const STREAMING_VALUE_CHUNK_MAGIC: &[u8; 8] = b"BLPQAIC1";
pub const STREAMING_VALUE_CHUNK_VERSION: u16 = 1;
pub const MAX_STREAMING_CHUNK_VALUES: usize = 1 << 20;
const STREAMING_VALUE_CHUNK_HEADER_BYTES: usize = 158;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamingColumnManifest {
    pub table_index: usize,
    pub column_index: usize,
    pub value_count: usize,
    pub commitment: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamingTableManifest {
    pub table_index: usize,
    pub row_count: usize,
    pub columns: Vec<StreamingColumnManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamingAirManifest {
    pub program_binary_commitment: [u8; 64],
    pub public_inputs: Vec<M31>,
    pub public_bindings: Vec<StreamingPublicInputBinding>,
    pub tables: Vec<StreamingTableManifest>,
    pub commitment: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamingPublicInputBinding {
    pub table_index: usize,
    pub column_index: usize,
    pub row: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamingValueChunk {
    pub table_index: usize,
    pub column_index: usize,
    pub row_start: usize,
    pub values: Vec<M31>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamingIrError {
    Air(AirIrError),
    EncodingLength,
    Truncated,
    TrailingBytes,
    Magic,
    Version,
    Shape,
    ZeroCommitment,
    Overflow,
    ProgramMismatch,
    CommitmentMismatch,
    NonCanonicalField,
    Order,
    ColumnCommitmentMismatch,
    Incomplete,
}

impl From<AirIrError> for StreamingIrError {
    fn from(value: AirIrError) -> Self {
        Self::Air(value)
    }
}

impl fmt::Display for StreamingIrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BL-PQ512 streaming IR error: {self:?}")
    }
}

impl core::error::Error for StreamingIrError {}

struct Reader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(encoded: &'a [u8]) -> Result<Self, StreamingIrError> {
        if encoded.len() < 82 || encoded.len() > MAX_STREAMING_MANIFEST_BYTES {
            return Err(StreamingIrError::EncodingLength);
        }
        Ok(Self { encoded, offset: 0 })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StreamingIrError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StreamingIrError::Overflow)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(StreamingIrError::Truncated)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, StreamingIrError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| StreamingIrError::Truncated)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, StreamingIrError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| StreamingIrError::Truncated)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, StreamingIrError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| StreamingIrError::Truncated)?,
        ))
    }

    fn digest(&mut self) -> Result<[u8; 64], StreamingIrError> {
        let value: [u8; 64] = self
            .take(64)?
            .try_into()
            .map_err(|_| StreamingIrError::Truncated)?;
        if !value.iter().any(|byte| *byte != 0) {
            return Err(StreamingIrError::ZeroCommitment);
        }
        Ok(value)
    }
}

pub fn decode_streaming_air_manifest(
    encoded: &[u8],
    program_encoded: &[u8],
) -> Result<StreamingAirManifest, StreamingIrError> {
    let program = parse_air_program(program_encoded)?;
    let mut program_hash = Sha3_512::new();
    program_hash.update(AIR_PROGRAM_DOMAIN);
    program_hash.update(program_encoded);
    let expected_program_commitment: [u8; 64] = program_hash.finalize().into();

    let mut reader = Reader::new(encoded)?;
    if reader.take(8)? != STREAMING_MANIFEST_MAGIC {
        return Err(StreamingIrError::Magic);
    }
    if reader.u16()? != STREAMING_MANIFEST_VERSION {
        return Err(StreamingIrError::Version);
    }
    let program_binary_commitment = reader.digest()?;
    if program_binary_commitment != expected_program_commitment {
        return Err(StreamingIrError::ProgramMismatch);
    }
    let public_input_count =
        usize::try_from(reader.u32()?).map_err(|_| StreamingIrError::Overflow)?;
    if public_input_count != program.public_inputs.len() {
        return Err(StreamingIrError::Shape);
    }
    let mut public_inputs = Vec::with_capacity(public_input_count);
    let mut public_bindings = Vec::with_capacity(public_input_count);
    for binding in &program.public_inputs {
        let raw = reader.u32()?;
        let value = M31::from_canonical(raw).map_err(|_| StreamingIrError::NonCanonicalField)?;
        if let Some((_, fixed)) = program.tables[binding.table]
            .fixed_columns
            .iter()
            .find(|(column, _)| *column == binding.column)
            && fixed.get(binding.row) != Some(value)
        {
            return Err(StreamingIrError::ProgramMismatch);
        }
        public_inputs.push(value);
        public_bindings.push(StreamingPublicInputBinding {
            table_index: binding.table,
            column_index: binding.column,
            row: binding.row,
        });
    }
    let table_count = usize::try_from(reader.u32()?).map_err(|_| StreamingIrError::Overflow)?;
    if table_count != program.tables.len() {
        return Err(StreamingIrError::Shape);
    }
    let mut tables = Vec::with_capacity(table_count);
    for (expected_table_index, table) in program.tables.iter().enumerate() {
        let table_index = usize::try_from(reader.u32()?).map_err(|_| StreamingIrError::Overflow)?;
        let row_count = usize::try_from(reader.u64()?).map_err(|_| StreamingIrError::Overflow)?;
        let column_count =
            usize::try_from(reader.u32()?).map_err(|_| StreamingIrError::Overflow)?;
        let fixed = table
            .fixed_columns
            .iter()
            .map(|(index, _)| *index)
            .collect::<alloc::collections::BTreeSet<_>>();
        let expected_columns = (0..table.columns.len())
            .filter(|index| !fixed.contains(index))
            .collect::<Vec<_>>();
        if table_index != expected_table_index
            || row_count != table.rows
            || column_count != expected_columns.len()
        {
            return Err(StreamingIrError::Shape);
        }
        let mut columns = Vec::with_capacity(column_count);
        for expected_column_index in expected_columns {
            let column_index =
                usize::try_from(reader.u32()?).map_err(|_| StreamingIrError::Overflow)?;
            let value_count =
                usize::try_from(reader.u64()?).map_err(|_| StreamingIrError::Overflow)?;
            let commitment = reader.digest()?;
            if column_index != expected_column_index || value_count != row_count {
                return Err(StreamingIrError::Shape);
            }
            columns.push(StreamingColumnManifest {
                table_index,
                column_index,
                value_count,
                commitment,
            });
        }
        tables.push(StreamingTableManifest {
            table_index,
            row_count,
            columns,
        });
    }
    if reader.offset != encoded.len() {
        return Err(StreamingIrError::TrailingBytes);
    }
    let mut manifest_hash = Sha3_512::new();
    manifest_hash.update(STREAMING_MANIFEST_DOMAIN);
    manifest_hash.update(encoded);
    Ok(StreamingAirManifest {
        program_binary_commitment,
        public_inputs,
        public_bindings,
        tables,
        commitment: manifest_hash.finalize().into(),
    })
}

pub fn streaming_column_commitment(
    program_binary_commitment: &[u8; 64],
    table_index: usize,
    column_index: usize,
    values: &[crate::field::M31],
) -> Result<[u8; 64], StreamingIrError> {
    if values.is_empty() {
        return Err(StreamingIrError::Shape);
    }
    let mut hash = Sha3_512::new();
    hash.update(STREAMING_COLUMN_DOMAIN);
    hash.update(program_binary_commitment);
    hash.update(
        u32::try_from(table_index)
            .map_err(|_| StreamingIrError::Overflow)?
            .to_be_bytes(),
    );
    hash.update(
        u32::try_from(column_index)
            .map_err(|_| StreamingIrError::Overflow)?
            .to_be_bytes(),
    );
    hash.update(
        u64::try_from(values.len())
            .map_err(|_| StreamingIrError::Overflow)?
            .to_be_bytes(),
    );
    for value in values {
        hash.update(value.as_u32().to_be_bytes());
    }
    Ok(hash.finalize().into())
}

pub fn decode_streaming_value_chunk(
    encoded: &[u8],
    expected_program_commitment: &[u8; 64],
    expected_manifest_commitment: &[u8; 64],
) -> Result<StreamingValueChunk, StreamingIrError> {
    if encoded.len() < STREAMING_VALUE_CHUNK_HEADER_BYTES {
        return Err(StreamingIrError::EncodingLength);
    }
    let mut reader = Reader { encoded, offset: 0 };
    if reader.take(8)? != STREAMING_VALUE_CHUNK_MAGIC {
        return Err(StreamingIrError::Magic);
    }
    if reader.u16()? != STREAMING_VALUE_CHUNK_VERSION {
        return Err(StreamingIrError::Version);
    }
    if reader.digest()? != *expected_program_commitment
        || reader.digest()? != *expected_manifest_commitment
    {
        return Err(StreamingIrError::CommitmentMismatch);
    }
    let table_index = usize::try_from(reader.u32()?).map_err(|_| StreamingIrError::Overflow)?;
    let column_index = usize::try_from(reader.u32()?).map_err(|_| StreamingIrError::Overflow)?;
    let row_start = usize::try_from(reader.u64()?).map_err(|_| StreamingIrError::Overflow)?;
    let value_count = usize::try_from(reader.u32()?).map_err(|_| StreamingIrError::Overflow)?;
    if value_count == 0 || value_count > MAX_STREAMING_CHUNK_VALUES {
        return Err(StreamingIrError::Shape);
    }
    let value_bytes = value_count
        .checked_mul(4)
        .ok_or(StreamingIrError::Overflow)?;
    if reader.offset.checked_add(value_bytes) != Some(encoded.len()) {
        return Err(if reader.offset + value_bytes < encoded.len() {
            StreamingIrError::TrailingBytes
        } else {
            StreamingIrError::Truncated
        });
    }
    let mut values = Vec::with_capacity(value_count);
    for _ in 0..value_count {
        let raw = reader.u32()?;
        if raw >= M31_MODULUS {
            return Err(StreamingIrError::NonCanonicalField);
        }
        values.push(M31::from_canonical(raw).map_err(|_| StreamingIrError::NonCanonicalField)?);
    }
    Ok(StreamingValueChunk {
        table_index,
        column_index,
        row_start,
        values,
    })
}

pub struct StreamingExecutionVerifier {
    manifest: StreamingAirManifest,
    table_index: usize,
    column_position: usize,
    next_row: usize,
    column_hash: Option<Sha3_512>,
}

impl StreamingExecutionVerifier {
    #[must_use]
    pub fn new(manifest: &StreamingAirManifest) -> Self {
        let table_index = manifest
            .tables
            .iter()
            .position(|table| !table.columns.is_empty())
            .unwrap_or(manifest.tables.len());
        Self {
            manifest: manifest.clone(),
            table_index,
            column_position: 0,
            next_row: 0,
            column_hash: first_column_hash_at(manifest, table_index, 0),
        }
    }

    pub fn absorb(&mut self, encoded: &[u8]) -> Result<StreamingValueChunk, StreamingIrError> {
        let chunk = decode_streaming_value_chunk(
            encoded,
            &self.manifest.program_binary_commitment,
            &self.manifest.commitment,
        )?;
        let expected = *self.current_column().ok_or(StreamingIrError::Order)?;
        if chunk.table_index != self.table_index
            || chunk.column_index != expected.column_index
            || chunk.row_start != self.next_row
            || chunk.values.len() > expected.value_count - self.next_row
        {
            return Err(StreamingIrError::Order);
        }
        for (binding, expected) in self
            .manifest
            .public_bindings
            .iter()
            .zip(&self.manifest.public_inputs)
        {
            if binding.table_index == chunk.table_index
                && binding.column_index == chunk.column_index
                && binding.row >= chunk.row_start
                && binding.row < chunk.row_start + chunk.values.len()
                && chunk.values[binding.row - chunk.row_start] != *expected
            {
                return Err(StreamingIrError::ProgramMismatch);
            }
        }
        let hash = self.column_hash.as_mut().ok_or(StreamingIrError::Order)?;
        for value in &chunk.values {
            hash.update(value.as_u32().to_be_bytes());
        }
        self.next_row += chunk.values.len();
        if self.next_row == expected.value_count {
            let observed: [u8; 64] = hash.clone().finalize().into();
            if observed != expected.commitment {
                return Err(StreamingIrError::ColumnCommitmentMismatch);
            }
            self.advance_column();
        }
        Ok(chunk)
    }

    pub fn finish(&self) -> Result<(), StreamingIrError> {
        if self.table_index == self.manifest.tables.len()
            && self.column_position == 0
            && self.next_row == 0
            && self.column_hash.is_none()
        {
            Ok(())
        } else {
            Err(StreamingIrError::Incomplete)
        }
    }

    fn current_column(&self) -> Option<&StreamingColumnManifest> {
        self.manifest
            .tables
            .get(self.table_index)
            .and_then(|table| table.columns.get(self.column_position))
    }

    fn advance_column(&mut self) {
        self.column_position += 1;
        self.next_row = 0;
        if self.column_position == self.manifest.tables[self.table_index].columns.len() {
            self.table_index += 1;
            self.column_position = 0;
            while self.table_index < self.manifest.tables.len()
                && self.manifest.tables[self.table_index].columns.is_empty()
            {
                self.table_index += 1;
            }
        }
        self.column_hash =
            first_column_hash_at(&self.manifest, self.table_index, self.column_position);
    }
}

fn first_column_hash_at(
    manifest: &StreamingAirManifest,
    table_index: usize,
    column_position: usize,
) -> Option<Sha3_512> {
    let column = manifest
        .tables
        .get(table_index)?
        .columns
        .get(column_position)?;
    let mut hash = Sha3_512::new();
    hash.update(STREAMING_COLUMN_DOMAIN);
    hash.update(manifest.program_binary_commitment);
    hash.update(u32::try_from(column.table_index).ok()?.to_be_bytes());
    hash.update(u32::try_from(column.column_index).ok()?.to_be_bytes());
    hash.update(u64::try_from(column.value_count).ok()?.to_be_bytes());
    Some(hash)
}
