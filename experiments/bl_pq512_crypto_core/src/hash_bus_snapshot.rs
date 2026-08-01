//! Canonical owned message snapshot for the Wave 1A semantic SHA3 bus.
//!
//! The snapshot is an integration boundary, not a new source of semantics.
//! Decoding derives the expected schedule from the profile, checks every
//! capacity and SHA3-512 digest, and recomputes the semantic-port commitment.

use alloc::vec::Vec;
use core::fmt;

use sha3::{Digest, Sha3_512};

use crate::{
    hash_bus::{HashBusError, build_hash_bus_descriptor},
    hash_bus_source::HashBusMessage,
    wave1a_global_schedule::Profile,
};

pub const HASH_BUS_SNAPSHOT_MAGIC: &[u8; 8] = b"BLHBSN01";
pub const HASH_BUS_SNAPSHOT_VERSION: u16 = 1;
pub const HASH_BUS_SEMANTIC_PORT_DOMAIN: &[u8] = b"BL/PQ512/WAVE2/HASH-BUS-SEMANTIC-PORT/v1\0";
pub const MAX_HASH_BUS_MESSAGE_BYTES: usize = 1 << 20;
pub const MAX_HASH_BUS_SNAPSHOT_BYTES: usize = 1 << 30;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedHashBusMessage {
    pub message: Vec<u8>,
    pub capacity: u64,
    pub digest: [u8; 64],
}

impl OwnedHashBusMessage {
    pub fn borrowed(&self) -> HashBusMessage<'_> {
        HashBusMessage {
            message: &self.message,
            capacity: self.capacity,
            digest: self.digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashBusSnapshot {
    pub profile: Profile,
    pub semantic_program_commitment: [u8; 64],
    pub descriptor_commitment: [u8; 64],
    pub semantic_port_commitment: [u8; 64],
    pub messages: Vec<OwnedHashBusMessage>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashBusSnapshotError {
    Shape,
    Encoding,
    Capacity,
    Digest,
    Commitment,
    Overflow,
    Descriptor(HashBusError),
}

impl From<HashBusError> for HashBusSnapshotError {
    fn from(value: HashBusError) -> Self {
        Self::Descriptor(value)
    }
}

impl fmt::Display for HashBusSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "hash bus snapshot error: {self:?}")
    }
}

impl core::error::Error for HashBusSnapshotError {}

fn profile_from_byte(value: u8) -> Result<Profile, HashBusSnapshotError> {
    match value {
        1 => Ok(Profile::K128Calibration),
        2 => Ok(Profile::K256DesignPoint),
        3 => Ok(Profile::K512Calibration),
        _ => Err(HashBusSnapshotError::Encoding),
    }
}

fn validate_messages(
    profile: Profile,
    messages: &[OwnedHashBusMessage],
) -> Result<[u8; 64], HashBusSnapshotError> {
    let descriptor = build_hash_bus_descriptor(profile)?;
    if messages.len()
        != usize::try_from(descriptor.total_calls).map_err(|_| HashBusSnapshotError::Overflow)?
    {
        return Err(HashBusSnapshotError::Shape);
    }
    let mut cursor = 0_usize;
    for run in &descriptor.runs {
        let count = usize::try_from(run.count).map_err(|_| HashBusSnapshotError::Overflow)?;
        let end = cursor
            .checked_add(count)
            .ok_or(HashBusSnapshotError::Overflow)?;
        for message in messages
            .get(cursor..end)
            .ok_or(HashBusSnapshotError::Shape)?
        {
            if message.capacity != run.capacity
                || message.message.len() > MAX_HASH_BUS_MESSAGE_BYTES
                || u64::try_from(message.message.len())
                    .map_err(|_| HashBusSnapshotError::Overflow)?
                    > message.capacity
            {
                return Err(HashBusSnapshotError::Capacity);
            }
            let digest: [u8; 64] = Sha3_512::digest(&message.message).into();
            if digest != message.digest {
                return Err(HashBusSnapshotError::Digest);
            }
        }
        cursor = end;
    }
    if cursor != messages.len() {
        return Err(HashBusSnapshotError::Shape);
    }
    Ok(descriptor.descriptor_commitment)
}

pub fn hash_bus_semantic_port_commitment(
    profile: Profile,
    semantic_program_commitment: [u8; 64],
    messages: &[OwnedHashBusMessage],
) -> Result<[u8; 64], HashBusSnapshotError> {
    let descriptor_commitment = validate_messages(profile, messages)?;
    let mut hash = Sha3_512::new();
    hash.update(HASH_BUS_SEMANTIC_PORT_DOMAIN);
    hash.update(HASH_BUS_SNAPSHOT_VERSION.to_be_bytes());
    hash.update([profile as u8]);
    hash.update(semantic_program_commitment);
    hash.update(descriptor_commitment);
    hash.update(
        u64::try_from(messages.len())
            .map_err(|_| HashBusSnapshotError::Overflow)?
            .to_be_bytes(),
    );
    for (index, message) in messages.iter().enumerate() {
        hash.update(
            u64::try_from(index)
                .map_err(|_| HashBusSnapshotError::Overflow)?
                .to_be_bytes(),
        );
        hash.update(message.capacity.to_be_bytes());
        hash.update(
            u32::try_from(message.message.len())
                .map_err(|_| HashBusSnapshotError::Overflow)?
                .to_be_bytes(),
        );
        hash.update(&message.message);
        hash.update(message.digest);
    }
    Ok(hash.finalize().into())
}

impl HashBusSnapshot {
    pub fn new(
        profile: Profile,
        semantic_program_commitment: [u8; 64],
        messages: Vec<OwnedHashBusMessage>,
    ) -> Result<Self, HashBusSnapshotError> {
        let descriptor_commitment = validate_messages(profile, &messages)?;
        let semantic_port_commitment =
            hash_bus_semantic_port_commitment(profile, semantic_program_commitment, &messages)?;
        Ok(Self {
            profile,
            semantic_program_commitment,
            descriptor_commitment,
            semantic_port_commitment,
            messages,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, HashBusSnapshotError> {
        let expected = Self::new(
            self.profile,
            self.semantic_program_commitment,
            self.messages.clone(),
        )?;
        if expected.descriptor_commitment != self.descriptor_commitment
            || expected.semantic_port_commitment != self.semantic_port_commitment
        {
            return Err(HashBusSnapshotError::Commitment);
        }
        let mut length: usize = 8 + 2 + 1 + 64 * 3 + 8;
        for message in &self.messages {
            length = length
                .checked_add(8 + 4 + 64)
                .and_then(|value| value.checked_add(message.message.len()))
                .ok_or(HashBusSnapshotError::Overflow)?;
        }
        if length > MAX_HASH_BUS_SNAPSHOT_BYTES {
            return Err(HashBusSnapshotError::Shape);
        }
        let mut encoded = Vec::with_capacity(length);
        encoded.extend_from_slice(HASH_BUS_SNAPSHOT_MAGIC);
        encoded.extend_from_slice(&HASH_BUS_SNAPSHOT_VERSION.to_be_bytes());
        encoded.push(self.profile as u8);
        encoded.extend_from_slice(&self.semantic_program_commitment);
        encoded.extend_from_slice(&self.descriptor_commitment);
        encoded.extend_from_slice(&self.semantic_port_commitment);
        encoded.extend_from_slice(
            &u64::try_from(self.messages.len())
                .map_err(|_| HashBusSnapshotError::Overflow)?
                .to_be_bytes(),
        );
        for message in &self.messages {
            encoded.extend_from_slice(&message.capacity.to_be_bytes());
            encoded.extend_from_slice(
                &u32::try_from(message.message.len())
                    .map_err(|_| HashBusSnapshotError::Overflow)?
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(&message.message);
            encoded.extend_from_slice(&message.digest);
        }
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, HashBusSnapshotError> {
        if encoded.len() > MAX_HASH_BUS_SNAPSHOT_BYTES {
            return Err(HashBusSnapshotError::Shape);
        }
        let mut reader = Reader::new(encoded);
        if reader.take(8)? != HASH_BUS_SNAPSHOT_MAGIC {
            return Err(HashBusSnapshotError::Encoding);
        }
        if reader.u16()? != HASH_BUS_SNAPSHOT_VERSION {
            return Err(HashBusSnapshotError::Encoding);
        }
        let profile = profile_from_byte(reader.u8()?)?;
        let semantic_program_commitment = reader.array()?;
        let descriptor_commitment = reader.array()?;
        let semantic_port_commitment = reader.array()?;
        let count = usize::try_from(reader.u64()?).map_err(|_| HashBusSnapshotError::Overflow)?;
        let descriptor = build_hash_bus_descriptor(profile)?;
        if count
            != usize::try_from(descriptor.total_calls)
                .map_err(|_| HashBusSnapshotError::Overflow)?
        {
            return Err(HashBusSnapshotError::Shape);
        }
        let mut messages = Vec::with_capacity(count);
        for _ in 0..count {
            let capacity = reader.u64()?;
            let length =
                usize::try_from(reader.u32()?).map_err(|_| HashBusSnapshotError::Overflow)?;
            if length > MAX_HASH_BUS_MESSAGE_BYTES {
                return Err(HashBusSnapshotError::Shape);
            }
            let message = reader.take(length)?.to_vec();
            let digest = reader.array()?;
            messages.push(OwnedHashBusMessage {
                message,
                capacity,
                digest,
            });
        }
        if !reader.is_empty() {
            return Err(HashBusSnapshotError::Encoding);
        }
        let snapshot = Self::new(profile, semantic_program_commitment, messages)?;
        if snapshot.descriptor_commitment != descriptor_commitment
            || snapshot.semantic_port_commitment != semantic_port_commitment
        {
            return Err(HashBusSnapshotError::Commitment);
        }
        Ok(snapshot)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], HashBusSnapshotError> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or(HashBusSnapshotError::Overflow)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(HashBusSnapshotError::Encoding)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, HashBusSnapshotError> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(HashBusSnapshotError::Encoding)?)
    }

    fn u16(&mut self) -> Result<u16, HashBusSnapshotError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| HashBusSnapshotError::Encoding)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, HashBusSnapshotError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| HashBusSnapshotError::Encoding)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, HashBusSnapshotError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| HashBusSnapshotError::Encoding)?,
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], HashBusSnapshotError> {
        self.take(N)?
            .try_into()
            .map_err(|_| HashBusSnapshotError::Encoding)
    }

    fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex_64(value: &str) -> [u8; 64] {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid hex"),
            }
        }
        let bytes = value.as_bytes();
        assert_eq!(bytes.len(), 128);
        core::array::from_fn(|index| nibble(bytes[2 * index]) << 4 | nibble(bytes[2 * index + 1]))
    }

    fn empty_k128_snapshot() -> HashBusSnapshot {
        let descriptor = build_hash_bus_descriptor(Profile::K128Calibration).unwrap();
        let digest: [u8; 64] = Sha3_512::digest([]).into();
        let messages = descriptor
            .runs
            .iter()
            .flat_map(|run| {
                core::iter::repeat_n(
                    OwnedHashBusMessage {
                        message: Vec::new(),
                        capacity: run.capacity,
                        digest,
                    },
                    run.count as usize,
                )
            })
            .collect();
        HashBusSnapshot::new(Profile::K128Calibration, [7_u8; 64], messages).unwrap()
    }

    #[test]
    fn canonical_k128_snapshot_round_trips_and_binds_every_port() {
        let snapshot = empty_k128_snapshot();
        let encoded = snapshot.encode().unwrap();
        let decoded = HashBusSnapshot::decode(&encoded).unwrap();
        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.messages.len(), 46_858);
        assert_eq!(
            <[u8; 64]>::from(Sha3_512::digest(&encoded)),
            decode_hex_64(
                "b3575b160e3d870671d23cd864f1dfedd7cefa87721f68598434c7bc36cd64a0\
                 f387c29babe0034dbb5ee496587eef208cc11581d3cc1d58038a4ffd224dc623"
            )
        );

        let mut forged_capacity = snapshot.clone();
        forged_capacity.messages[0].capacity += 1;
        assert_eq!(
            forged_capacity.encode(),
            Err(HashBusSnapshotError::Capacity)
        );

        let mut forged_digest = snapshot.clone();
        forged_digest.messages[0].digest[0] ^= 1;
        assert_eq!(forged_digest.encode(), Err(HashBusSnapshotError::Digest));

        let mut forged_commitment = encoded;
        forged_commitment[8 + 2 + 1 + 64 * 2] ^= 1;
        assert_eq!(
            HashBusSnapshot::decode(&forged_commitment),
            Err(HashBusSnapshotError::Commitment)
        );
    }
}
