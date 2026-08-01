//! Fail-closed reader for the canonical compact B16 hash-bus boundary.

use alloc::{vec, vec::Vec};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use sha3::{Digest, Sha3_512};

use crate::{
    hash_bus::{GROUP_COUNT, HashBusError, build_hash_bus_descriptor},
    hash_bus_source::KECCAK_STATE_BITS,
    wave1a_global_schedule::Profile,
};

pub const HASH_BUS_B16_MAGIC: &[u8; 8] = b"BLHBB101";
pub const HASH_BUS_B16_VERSION: u16 = 1;
pub const HASH_BUS_B16_HEADER_BYTES: u64 = 215;
pub const HASH_BUS_B16_GKR_STATEMENT_DOMAIN: &[u8] =
    b"BL/PQ512/WAVE2/HASH-BUS-B16/GKR-STATEMENT/v1\0";
const READ_CHUNK_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashBusB16BoundaryError {
    Io,
    Encoding,
    Shape,
    Overflow,
    Descriptor(HashBusError),
}

impl From<HashBusError> for HashBusB16BoundaryError {
    fn from(value: HashBusError) -> Self {
        Self::Descriptor(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashBusB16BoundaryHeader {
    pub profile: Profile,
    pub semantic_program_commitment: [u8; 64],
    pub descriptor_commitment: [u8; 64],
    pub semantic_port_commitment: [u8; 64],
    pub coprocessor_shards: u16,
    pub padded_permutations: u64,
    pub live_wires: u16,
    pub file_bytes: u64,
    pub file_sha3_512: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashBusB16Shard {
    /// Wire-major patterns, with 8,192 groups on the minor axis.
    pub input: Vec<u16>,
    /// Wire-major patterns, with 8,192 groups on the minor axis.
    pub output: Vec<u16>,
}

pub struct HashBusB16BoundaryFile {
    file: File,
    header: HashBusB16BoundaryHeader,
}

impl HashBusB16BoundaryHeader {
    /// Bind one exact semantic-bus shard to the selected public GKR wiring.
    ///
    /// The file digest covers the complete canonical one/four-shard boundary;
    /// the explicit shard ordinal selects the source consumed by this proof.
    pub fn gkr_statement_binding(
        &self,
        shard: u16,
        gkr_plan_commitment: [u8; 64],
    ) -> Result<[u8; 64], HashBusB16BoundaryError> {
        if shard >= self.coprocessor_shards || !gkr_plan_commitment.iter().any(|byte| *byte != 0) {
            return Err(HashBusB16BoundaryError::Shape);
        }
        let mut hash = Sha3_512::new();
        hash.update(HASH_BUS_B16_GKR_STATEMENT_DOMAIN);
        hash.update([self.profile as u8]);
        hash.update(self.semantic_program_commitment);
        hash.update(self.descriptor_commitment);
        hash.update(self.semantic_port_commitment);
        hash.update(self.coprocessor_shards.to_be_bytes());
        hash.update(self.padded_permutations.to_be_bytes());
        hash.update(self.live_wires.to_be_bytes());
        hash.update(self.file_bytes.to_be_bytes());
        hash.update(self.file_sha3_512);
        hash.update(shard.to_be_bytes());
        hash.update(gkr_plan_commitment);
        Ok(hash.finalize().into())
    }
}

fn profile_from_tag(tag: u8) -> Result<Profile, HashBusB16BoundaryError> {
    match tag {
        1 => Ok(Profile::K128Calibration),
        2 => Ok(Profile::K256DesignPoint),
        3 => Ok(Profile::K512Calibration),
        _ => Err(HashBusB16BoundaryError::Encoding),
    }
}

fn read_array<const N: usize>(
    input: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], HashBusB16BoundaryError> {
    let end = cursor
        .checked_add(N)
        .ok_or(HashBusB16BoundaryError::Overflow)?;
    let value = input
        .get(*cursor..end)
        .ok_or(HashBusB16BoundaryError::Encoding)?
        .try_into()
        .map_err(|_| HashBusB16BoundaryError::Encoding)?;
    *cursor = end;
    Ok(value)
}

fn boundary_values() -> Result<usize, HashBusB16BoundaryError> {
    KECCAK_STATE_BITS
        .checked_mul(usize::try_from(GROUP_COUNT).map_err(|_| HashBusB16BoundaryError::Overflow)?)
        .ok_or(HashBusB16BoundaryError::Overflow)
}

fn expected_file_bytes(shards: u16) -> Result<u64, HashBusB16BoundaryError> {
    let payload = u64::try_from(boundary_values()?)
        .map_err(|_| HashBusB16BoundaryError::Overflow)?
        .checked_mul(2)
        .and_then(|value| value.checked_mul(2))
        .and_then(|value| value.checked_mul(u64::from(shards)))
        .ok_or(HashBusB16BoundaryError::Overflow)?;
    HASH_BUS_B16_HEADER_BYTES
        .checked_add(payload)
        .ok_or(HashBusB16BoundaryError::Overflow)
}

fn hash_file(file: &mut File) -> Result<[u8; 64], HashBusB16BoundaryError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| HashBusB16BoundaryError::Io)?;
    let mut hash = Sha3_512::new();
    let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| HashBusB16BoundaryError::Io)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

impl HashBusB16BoundaryFile {
    pub fn open(path: &Path) -> Result<Self, HashBusB16BoundaryError> {
        let mut file = File::open(path).map_err(|_| HashBusB16BoundaryError::Io)?;
        let file_bytes = file
            .metadata()
            .map_err(|_| HashBusB16BoundaryError::Io)?
            .len();
        if file_bytes < HASH_BUS_B16_HEADER_BYTES {
            return Err(HashBusB16BoundaryError::Shape);
        }
        let mut encoded = [0_u8; HASH_BUS_B16_HEADER_BYTES as usize];
        file.read_exact(&mut encoded)
            .map_err(|_| HashBusB16BoundaryError::Io)?;
        let mut cursor = 0_usize;
        if &read_array::<8>(&encoded, &mut cursor)? != HASH_BUS_B16_MAGIC
            || u16::from_be_bytes(read_array::<2>(&encoded, &mut cursor)?) != HASH_BUS_B16_VERSION
        {
            return Err(HashBusB16BoundaryError::Encoding);
        }
        let profile = profile_from_tag(read_array::<1>(&encoded, &mut cursor)?[0])?;
        let semantic_program_commitment = read_array::<64>(&encoded, &mut cursor)?;
        let descriptor_commitment = read_array::<64>(&encoded, &mut cursor)?;
        let semantic_port_commitment = read_array::<64>(&encoded, &mut cursor)?;
        let coprocessor_shards = u16::from_be_bytes(read_array::<2>(&encoded, &mut cursor)?);
        let padded_permutations = u64::from_be_bytes(read_array::<8>(&encoded, &mut cursor)?);
        let live_wires = u16::from_be_bytes(read_array::<2>(&encoded, &mut cursor)?);
        if cursor != encoded.len() {
            return Err(HashBusB16BoundaryError::Encoding);
        }

        let descriptor = build_hash_bus_descriptor(profile)?;
        if descriptor.descriptor_commitment != descriptor_commitment
            || descriptor.coprocessor_shards != coprocessor_shards
            || descriptor.padded_permutations != padded_permutations
            || live_wires
                != u16::try_from(KECCAK_STATE_BITS)
                    .map_err(|_| HashBusB16BoundaryError::Overflow)?
            || file_bytes != expected_file_bytes(coprocessor_shards)?
        {
            return Err(HashBusB16BoundaryError::Shape);
        }
        let file_sha3_512 = hash_file(&mut file)?;
        Ok(Self {
            file,
            header: HashBusB16BoundaryHeader {
                profile,
                semantic_program_commitment,
                descriptor_commitment,
                semantic_port_commitment,
                coprocessor_shards,
                padded_permutations,
                live_wires,
                file_bytes,
                file_sha3_512,
            },
        })
    }

    pub fn header(&self) -> &HashBusB16BoundaryHeader {
        &self.header
    }

    pub fn read_shard(&mut self, shard: u16) -> Result<HashBusB16Shard, HashBusB16BoundaryError> {
        if shard >= self.header.coprocessor_shards {
            return Err(HashBusB16BoundaryError::Shape);
        }
        let values = boundary_values()?;
        let boundary_bytes = u64::try_from(values)
            .map_err(|_| HashBusB16BoundaryError::Overflow)?
            .checked_mul(2)
            .ok_or(HashBusB16BoundaryError::Overflow)?;
        let offset = HASH_BUS_B16_HEADER_BYTES
            .checked_add(
                u64::from(shard)
                    .checked_mul(2)
                    .and_then(|value| value.checked_mul(boundary_bytes))
                    .ok_or(HashBusB16BoundaryError::Overflow)?,
            )
            .ok_or(HashBusB16BoundaryError::Overflow)?;
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| HashBusB16BoundaryError::Io)?;
        let input = read_u16_values(&mut self.file, values)?;
        let output = read_u16_values(&mut self.file, values)?;
        Ok(HashBusB16Shard { input, output })
    }
}

fn read_u16_values(file: &mut File, count: usize) -> Result<Vec<u16>, HashBusB16BoundaryError> {
    let mut values = vec![0_u16; count];
    let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
    let mut cursor = 0_usize;
    while cursor < count {
        let take = (count - cursor).min(buffer.len() / 2);
        let bytes = take
            .checked_mul(2)
            .ok_or(HashBusB16BoundaryError::Overflow)?;
        file.read_exact(&mut buffer[..bytes])
            .map_err(|_| HashBusB16BoundaryError::Io)?;
        for (destination, encoded) in values[cursor..cursor + take]
            .iter_mut()
            .zip(buffer[..bytes].chunks_exact(2))
        {
            *destination = u16::from_le_bytes(
                encoded
                    .try_into()
                    .map_err(|_| HashBusB16BoundaryError::Encoding)?,
            );
        }
        cursor += take;
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        format,
        fs::{OpenOptions, remove_file},
        io::Write,
    };

    #[test]
    fn canonical_k128_boundary_rejects_trailing_bytes() {
        let descriptor = build_hash_bus_descriptor(Profile::K128Calibration).unwrap();
        let path = std::env::temp_dir().join(format!(
            "bl-hash-bus-b16-boundary-{}.bin",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(HASH_BUS_B16_MAGIC).unwrap();
        file.write_all(&HASH_BUS_B16_VERSION.to_be_bytes()).unwrap();
        file.write_all(&[Profile::K128Calibration as u8]).unwrap();
        file.write_all(&[7_u8; 64]).unwrap();
        file.write_all(&descriptor.descriptor_commitment).unwrap();
        file.write_all(&[9_u8; 64]).unwrap();
        file.write_all(&descriptor.coprocessor_shards.to_be_bytes())
            .unwrap();
        file.write_all(&descriptor.padded_permutations.to_be_bytes())
            .unwrap();
        file.write_all(&(KECCAK_STATE_BITS as u16).to_be_bytes())
            .unwrap();
        let expected = expected_file_bytes(descriptor.coprocessor_shards).unwrap();
        file.set_len(expected).unwrap();
        drop(file);

        let mut boundary = HashBusB16BoundaryFile::open(&path).unwrap();
        assert_eq!(boundary.header().file_bytes, 52_429_015);
        let statement = boundary
            .header()
            .gkr_statement_binding(0, [11_u8; 64])
            .unwrap();
        assert_ne!(statement, [0_u8; 64]);
        assert!(matches!(
            boundary.header().gkr_statement_binding(1, [11_u8; 64]),
            Err(HashBusB16BoundaryError::Shape)
        ));
        assert!(matches!(
            boundary.header().gkr_statement_binding(0, [0_u8; 64]),
            Err(HashBusB16BoundaryError::Shape)
        ));
        let shard = boundary.read_shard(0).unwrap();
        assert_eq!(shard.input.len(), KECCAK_STATE_BITS * GROUP_COUNT as usize);
        assert_eq!(shard.output, shard.input);
        assert_ne!(boundary.header().file_sha3_512, [0_u8; 64]);
        drop(boundary);

        let file = OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(expected + 1).unwrap();
        drop(file);
        assert!(matches!(
            HashBusB16BoundaryFile::open(&path),
            Err(HashBusB16BoundaryError::Shape)
        ));
        remove_file(path).unwrap();
    }
}
