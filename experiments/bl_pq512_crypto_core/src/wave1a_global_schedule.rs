//! Compact exact call-order manifest for the segmented Wave 1A SHA3 engine.
//!
//! Physical component traces remain independently testable.  This manifest
//! fixes the order in which a streaming prover consumes those segments without
//! cloning millions of Keccak rows into a second in-memory trace.

use sha3::{Digest, Sha3_512};

use crate::ordered_map_schedule::{OrderedMapScheduleError, build_ordered_map_batch_schedule};

pub const DOMAIN: &[u8] = b"BL/PQ512/WAVE1A/GLOBAL-SHA3-SCHEDULE/v1\0";
pub const COMPONENT_COUNT: usize = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Profile {
    K128Calibration = 1,
    K256DesignPoint = 2,
    K512Calibration = 3,
}

impl Profile {
    pub const fn claim_slots(self) -> u64 {
        match self {
            Self::K128Calibration => 128,
            Self::K256DesignPoint => 256,
            Self::K512Calibration => 512,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalSha3Segment {
    pub tag: u8,
    pub call_offset: u64,
    pub call_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wave1AGlobalSha3Schedule {
    pub profile: Profile,
    pub segments: [GlobalSha3Segment; COMPONENT_COUNT],
    pub total_calls: u64,
    pub commitment_512: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlobalScheduleError {
    DimensionOverflow,
    OrderedMap(OrderedMapScheduleError),
}

impl From<OrderedMapScheduleError> for GlobalScheduleError {
    fn from(value: OrderedMapScheduleError) -> Self {
        Self::OrderedMap(value)
    }
}

pub fn build_wave1a_global_sha3_schedule(
    profile: Profile,
) -> Result<Wave1AGlobalSha3Schedule, GlobalScheduleError> {
    let k = profile.claim_slots();
    let truth = 4_u64
        .checked_mul(k)
        .and_then(|value| value.checked_add(4))
        .ok_or(GlobalScheduleError::DimensionOverflow)?;
    let a12 = k
        .checked_add(1)
        .ok_or(GlobalScheduleError::DimensionOverflow)?;
    let replay = build_ordered_map_batch_schedule(a12, 24)?.sha3_call_rows;
    let lane = build_ordered_map_batch_schedule(k, 24)?.sha3_call_rows;
    let ledger = build_ordered_map_batch_schedule(
        k.checked_mul(2)
            .ok_or(GlobalScheduleError::DimensionOverflow)?,
        24,
    )?
    .sha3_call_rows;
    let payment = lane
        .checked_mul(2)
        .and_then(|value| value.checked_add(ledger))
        .and_then(|value| value.checked_add(6 * k))
        .ok_or(GlobalScheduleError::DimensionOverflow)?;
    let counts = [truth, a12, 1, replay, payment, 4];
    let mut offset = 0_u64;
    let mut segments = [GlobalSha3Segment {
        tag: 0,
        call_offset: 0,
        call_count: 0,
    }; COMPONENT_COUNT];
    for (index, count) in counts.into_iter().enumerate() {
        segments[index] = GlobalSha3Segment {
            tag: index as u8 + 1,
            call_offset: offset,
            call_count: count,
        };
        offset = offset
            .checked_add(count)
            .ok_or(GlobalScheduleError::DimensionOverflow)?;
    }
    let mut hash = Sha3_512::new();
    hash.update(DOMAIN);
    hash.update([profile as u8, COMPONENT_COUNT as u8]);
    for segment in segments {
        hash.update([segment.tag]);
        hash.update(segment.call_offset.to_be_bytes());
        hash.update(segment.call_count.to_be_bytes());
    }
    Ok(Wave1AGlobalSha3Schedule {
        profile,
        segments,
        total_calls: offset,
        commitment_512: hash.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex_64(value: &str) -> [u8; 64] {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid test hex"),
            }
        }
        let bytes = value.as_bytes();
        assert_eq!(bytes.len(), 128);
        let mut result = [0_u8; 64];
        for index in 0..64 {
            result[index] = (nibble(bytes[2 * index]) << 4) | nibble(bytes[2 * index + 1]);
        }
        result
    }

    #[test]
    fn all_profiles_have_contiguous_exact_offsets() {
        for (profile, expected, commitment) in [
            (
                Profile::K128Calibration,
                46_858,
                "2d2792d30f838618190a95817f44204308e2a0e7f460b71e48da779ccd2472cb11ae3342a2df9a52f01561c80aaa3d3fafa2d77271fd9eb4f6ee6270006e3aa6",
            ),
            (
                Profile::K256DesignPoint,
                88_198,
                "a8eb2fcd3a7f80fabded6665cbd04fce4d7dbc5ce748f24d81c11b086d402fe3ffed9331df49f46f869be49f9d0c541f9f1c303c90b97ec4719b3713f83e9300",
            ),
            (
                Profile::K512Calibration,
                165_762,
                "419d20a6525b95e9ac0d6764a4fbe8d7422b1735509d79761005d24637a49b2958dfa7ce69592a977d44719060d44c5d335efdde9fe933a7241911df61ebd1cd",
            ),
        ] {
            let schedule = build_wave1a_global_sha3_schedule(profile).unwrap();
            let mut offset = 0;
            for segment in schedule.segments {
                assert_eq!(segment.call_offset, offset);
                offset += segment.call_count;
            }
            assert_eq!(offset, expected);
            assert_eq!(schedule.total_calls, expected);
            assert_eq!(schedule.commitment_512, decode_hex_64(commitment));
        }
    }
}
