//! Compact claim-source bundle validation and streamed SHA3-512 tree schedule.

use alloc::{string::String, vec::Vec};

use sha3::{Digest, Sha3_512};

use crate::{
    oracle_bundle::{OracleProfile, TOKEN_ENCODED_BYTES, decode_authorization_token},
    sha3_air::{
        KECCAK_ROUNDS, RATE_BYTES, Sha3TraceError, for_each_sha3_512_trace_row, sha3_512_reference,
    },
};

pub const CLAIM_SOURCE_BUNDLE_BYTES: usize = 5_648;
pub const MAX_CLAIM_SOURCE_SLOTS: usize = 512;
pub const BUNDLE_MAGIC: &[u8; 8] = b"BLPQCSB2";
pub const NODE_MAGIC: &[u8; 8] = b"BLPQCSN2";
pub const ROOT_MAGIC: &[u8; 8] = b"BLPQCST2";
pub const SCHEDULE_DOMAIN: &[u8] = b"BL/PQ512/WAVE1A/CLAIM-SOURCE-SHA3-SCHEDULE/v2\0";
const DIAGNOSES: usize = 16;
const LINES: usize = 50;
const DIAGNOSIS_BYTES: usize = 17;
const PROCEDURE_BYTES: usize = 11;
const NPI_BYTES: usize = 11;
const LINE_BYTES: usize = 1 + TOKEN_ENCODED_BYTES + PROCEDURE_BYTES + 4 + 4 + TOKEN_ENCODED_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimSourceError {
    BundleCountInvalid,
    BundleLengthInvalid,
    BundleMagicInvalid,
    BundleProfileInvalid,
    BundleSlotInvalid,
    BundleEncodingInvalid,
    BundleSemanticInvalid,
    ExpectedRootInvalid,
    CountOverflow,
    Trace(Sha3TraceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimSourceScheduleReport {
    pub slots: u64,
    pub calls: u64,
    pub permutations: u64,
    pub keccak_round_rows: u64,
    pub root: [u8; 64],
    pub commitment: [u8; 64],
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ClaimSourceError> {
        let stop = self
            .offset
            .checked_add(count)
            .ok_or(ClaimSourceError::BundleEncodingInvalid)?;
        let value = self
            .bytes
            .get(self.offset..stop)
            .ok_or(ClaimSourceError::BundleEncodingInvalid)?;
        self.offset = stop;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ClaimSourceError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ClaimSourceError> {
        let raw: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ClaimSourceError::BundleEncodingInvalid)?;
        Ok(u16::from_be_bytes(raw))
    }

    fn u32(&mut self) -> Result<u32, ClaimSourceError> {
        let raw: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ClaimSourceError::BundleEncodingInvalid)?;
        Ok(u32::from_be_bytes(raw))
    }

    fn u64(&mut self) -> Result<u64, ClaimSourceError> {
        let raw: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| ClaimSourceError::BundleEncodingInvalid)?;
        Ok(u64::from_be_bytes(raw))
    }
}

fn token(cursor: &mut Cursor<'_>) -> Result<String, ClaimSourceError> {
    let encoded: [u8; TOKEN_ENCODED_BYTES] = cursor
        .take(TOKEN_ENCODED_BYTES)?
        .try_into()
        .map_err(|_| ClaimSourceError::BundleEncodingInvalid)?;
    decode_authorization_token(encoded).map_err(|_| ClaimSourceError::BundleEncodingInvalid)
}

fn fixed_ascii(
    cursor: &mut Cursor<'_>,
    capacity: usize,
    allowed: fn(u8) -> bool,
) -> Result<String, ClaimSourceError> {
    let raw = cursor.take(capacity + 1)?;
    let length = usize::from(raw[0]);
    if length > capacity
        || raw[1..=length].iter().any(|value| !allowed(*value))
        || raw[1 + length..].iter().any(|value| *value != 0)
    {
        return Err(ClaimSourceError::BundleEncodingInvalid);
    }
    String::from_utf8(raw[1..=length].to_vec()).map_err(|_| ClaimSourceError::BundleEncodingInvalid)
}

fn diagnosis_byte(value: u8) -> bool {
    value.is_ascii_uppercase() || value.is_ascii_digit() || value == b'.'
}

fn procedure_byte(value: u8) -> bool {
    value.is_ascii_uppercase() || value.is_ascii_digit()
}

fn digit(value: u8) -> bool {
    value.is_ascii_digit()
}

fn npi_valid(value: &str) -> bool {
    if value.len() != 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let mut payload = Vec::with_capacity(14);
    payload.extend_from_slice(b"80840");
    payload.extend_from_slice(&value.as_bytes()[..9]);
    let mut total = 0_u32;
    for (index, byte) in payload.iter().rev().enumerate() {
        let mut value = u32::from(*byte - b'0');
        if index.is_multiple_of(2) {
            value *= 2;
            value = value / 10 + value % 10;
        }
        total += value;
    }
    (10 - total % 10) % 10 == u32::from(value.as_bytes()[9] - b'0')
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedLine {
    original_index: u8,
    line_id: String,
    line_id_rank: [u8; TOKEN_ENCODED_BYTES],
    procedure: String,
    charge: u32,
    units: u32,
    authorization: String,
    authorization_rank: [u8; TOKEN_ENCODED_BYTES],
}

type LineKey<'a> = (
    (usize, &'a [u8]),
    u32,
    u32,
    [u8; TOKEN_ENCODED_BYTES],
    [u8; TOKEN_ENCODED_BYTES],
);

fn ascii_key(value: &str) -> (usize, &[u8]) {
    (value.len(), value.as_bytes())
}

fn line_key(line: &ParsedLine) -> LineKey<'_> {
    (
        ascii_key(&line.procedure),
        line.charge,
        line.units,
        line.authorization_rank,
        line.line_id_rank,
    )
}

pub fn validate_claim_source_bundle(
    profile: OracleProfile,
    expected_slot: usize,
    encoded: &[u8],
) -> Result<(), ClaimSourceError> {
    if encoded.len() != CLAIM_SOURCE_BUNDLE_BYTES {
        return Err(ClaimSourceError::BundleLengthInvalid);
    }
    let mut cursor = Cursor::new(encoded);
    if cursor.take(BUNDLE_MAGIC.len())? != BUNDLE_MAGIC {
        return Err(ClaimSourceError::BundleMagicInvalid);
    }
    if cursor.u8()? != profile.code() {
        return Err(ClaimSourceError::BundleProfileInvalid);
    }
    if usize::from(cursor.u16()?) != expected_slot || expected_slot >= profile.claim_slots() {
        return Err(ClaimSourceError::BundleSlotInvalid);
    }
    let real = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(ClaimSourceError::BundleEncodingInvalid),
    };
    let authority = token(&mut cursor)?;
    let sequence = cursor.u64()?;
    let claim_id = token(&mut cursor)?;
    let member_id = token(&mut cursor)?;
    let npi = fixed_ascii(&mut cursor, NPI_BYTES - 1, digit)?;
    let attempt = cursor.u32()?;
    let revision = cursor.u8()?;
    let parent = cursor.u32()?;
    let total_charge = cursor.u32()?;
    let patient_responsibility = cursor.u32()?;
    let diagnosis_count = usize::from(cursor.u8()?);
    if diagnosis_count > DIAGNOSES {
        return Err(ClaimSourceError::BundleEncodingInvalid);
    }
    let mut diagnoses = Vec::with_capacity(diagnosis_count);
    for index in 0..DIAGNOSES {
        let value = fixed_ascii(&mut cursor, DIAGNOSIS_BYTES - 1, diagnosis_byte)?;
        if (index < diagnosis_count) == value.is_empty() {
            return Err(ClaimSourceError::BundleEncodingInvalid);
        }
        if index < diagnosis_count {
            diagnoses.push(value);
        }
    }
    if diagnoses
        .windows(2)
        .any(|pair| ascii_key(&pair[0]) >= ascii_key(&pair[1]))
    {
        return Err(ClaimSourceError::BundleSemanticInvalid);
    }

    let line_count = usize::from(cursor.u8()?);
    if line_count > LINES {
        return Err(ClaimSourceError::BundleEncodingInvalid);
    }
    let mut lines = Vec::with_capacity(line_count);
    for index in 0..LINES {
        if index >= line_count {
            if cursor.take(LINE_BYTES)?.iter().any(|value| *value != 0) {
                return Err(ClaimSourceError::BundleEncodingInvalid);
            }
            continue;
        }
        let original_index = cursor.u8()?;
        let line_id = token(&mut cursor)?;
        let procedure = fixed_ascii(&mut cursor, PROCEDURE_BYTES - 1, procedure_byte)?;
        let charge = cursor.u32()?;
        let units = cursor.u32()?;
        let authorization = token(&mut cursor)?;
        if usize::from(original_index) >= LINES
            || line_id.is_empty()
            || !(2..=10).contains(&procedure.len())
        {
            return Err(ClaimSourceError::BundleSemanticInvalid);
        }
        lines.push(ParsedLine {
            original_index,
            line_id_rank: crate::oracle_bundle::encode_authorization_token(&line_id)
                .map_err(|_| ClaimSourceError::BundleEncodingInvalid)?,
            line_id,
            procedure,
            charge,
            units,
            authorization_rank: crate::oracle_bundle::encode_authorization_token(&authorization)
                .map_err(|_| ClaimSourceError::BundleEncodingInvalid)?,
            authorization,
        });
    }
    if cursor.offset != encoded.len() {
        return Err(ClaimSourceError::BundleEncodingInvalid);
    }
    if lines
        .windows(2)
        .any(|pair| line_key(&pair[0]) > line_key(&pair[1]))
        || lines.iter().enumerate().any(|(index, line)| {
            lines[..index].iter().any(|prior| {
                prior.line_id == line.line_id || prior.original_index == line.original_index
            })
        })
    {
        return Err(ClaimSourceError::BundleSemanticInvalid);
    }
    let observed_total = lines.iter().try_fold(0_u32, |accumulator, line| {
        accumulator.checked_add(line.charge)
    });
    if observed_total != Some(total_charge) {
        return Err(ClaimSourceError::BundleSemanticInvalid);
    }
    if real {
        if authority.is_empty()
            || sequence == 0
            || claim_id.is_empty()
            || attempt != 1
            || revision != 1
            || parent != 0
            || (!npi.is_empty() && !npi_valid(&npi))
        {
            return Err(ClaimSourceError::BundleSemanticInvalid);
        }
    } else if !authority.is_empty()
        || sequence != 0
        || !claim_id.is_empty()
        || !member_id.is_empty()
        || !npi.is_empty()
        || attempt != 0
        || revision != 0
        || parent != 0
        || total_charge != 0
        || patient_responsibility != 0
        || !diagnoses.is_empty()
        || !lines.is_empty()
    {
        return Err(ClaimSourceError::BundleSemanticInvalid);
    }
    Ok(())
}

fn trace_call(
    ordinal: u32,
    kind: u8,
    message: &[u8],
    commitment: &mut Sha3_512,
    permutations: &mut u64,
    rows: &mut u64,
) -> Result<[u8; 64], ClaimSourceError> {
    let mut call_rows = 0_u64;
    let digest = for_each_sha3_512_trace_row(message, message.len(), |_, _, _, _, _, _| {
        call_rows += 1;
    })
    .map_err(ClaimSourceError::Trace)?;
    if digest != sha3_512_reference(message) {
        return Err(ClaimSourceError::BundleEncodingInvalid);
    }
    let call_permutations = (message.len() / usize::from(RATE_BYTES) + 1) as u64;
    *permutations = permutations
        .checked_add(call_permutations)
        .ok_or(ClaimSourceError::CountOverflow)?;
    *rows = rows
        .checked_add(call_rows)
        .ok_or(ClaimSourceError::CountOverflow)?;
    commitment.update(ordinal.to_be_bytes());
    commitment.update([kind]);
    commitment.update(
        u16::try_from(message.len())
            .map_err(|_| ClaimSourceError::CountOverflow)?
            .to_be_bytes(),
    );
    commitment.update(
        u16::try_from(message.len())
            .map_err(|_| ClaimSourceError::CountOverflow)?
            .to_be_bytes(),
    );
    commitment.update(message);
    commitment.update(digest);
    Ok(digest)
}

pub fn evaluate_claim_source_schedule(
    profile: OracleProfile,
    bundles: &[Vec<u8>],
    expected_root: [u8; 64],
) -> Result<ClaimSourceScheduleReport, ClaimSourceError> {
    if bundles.len() != profile.claim_slots() || bundles.len() > MAX_CLAIM_SOURCE_SLOTS {
        return Err(ClaimSourceError::BundleCountInvalid);
    }
    let mut commitment = Sha3_512::new();
    commitment.update(SCHEDULE_DOMAIN);
    commitment.update([profile.code()]);
    commitment.update(
        u16::try_from(bundles.len())
            .map_err(|_| ClaimSourceError::CountOverflow)?
            .to_be_bytes(),
    );
    let mut permutations = 0_u64;
    let mut round_rows = 0_u64;
    let mut ordinal = 0_u32;
    let mut current = Vec::with_capacity(bundles.len());
    for (slot, bundle) in bundles.iter().enumerate() {
        validate_claim_source_bundle(profile, slot, bundle)?;
        current.push(trace_call(
            ordinal,
            1,
            bundle,
            &mut commitment,
            &mut permutations,
            &mut round_rows,
        )?);
        ordinal = ordinal
            .checked_add(1)
            .ok_or(ClaimSourceError::CountOverflow)?;
    }
    for child_height in 0..profile.tree_depth() {
        let mut next = Vec::with_capacity(current.len() / 2);
        for (position, pair) in current.chunks_exact(2).enumerate() {
            let mut message = Vec::with_capacity(140);
            message.extend_from_slice(NODE_MAGIC);
            message.extend_from_slice(&[
                profile.code(),
                u8::try_from(child_height).map_err(|_| ClaimSourceError::CountOverflow)?,
            ]);
            message.extend_from_slice(
                &u16::try_from(position)
                    .map_err(|_| ClaimSourceError::CountOverflow)?
                    .to_be_bytes(),
            );
            message.extend_from_slice(&pair[0]);
            message.extend_from_slice(&pair[1]);
            next.push(trace_call(
                ordinal,
                2,
                &message,
                &mut commitment,
                &mut permutations,
                &mut round_rows,
            )?);
            ordinal = ordinal
                .checked_add(1)
                .ok_or(ClaimSourceError::CountOverflow)?;
        }
        current = next;
    }
    if current.len() != 1 {
        return Err(ClaimSourceError::BundleCountInvalid);
    }
    let mut root_message = Vec::with_capacity(76);
    root_message.extend_from_slice(ROOT_MAGIC);
    root_message.extend_from_slice(&[
        profile.code(),
        u8::try_from(profile.tree_depth()).map_err(|_| ClaimSourceError::CountOverflow)?,
    ]);
    root_message.extend_from_slice(
        &u16::try_from(profile.claim_slots())
            .map_err(|_| ClaimSourceError::CountOverflow)?
            .to_be_bytes(),
    );
    root_message.extend_from_slice(&current[0]);
    let root = trace_call(
        ordinal,
        3,
        &root_message,
        &mut commitment,
        &mut permutations,
        &mut round_rows,
    )?;
    if root != expected_root {
        return Err(ClaimSourceError::ExpectedRootInvalid);
    }
    commitment.update(root);
    if round_rows != permutations * u64::from(KECCAK_ROUNDS) {
        return Err(ClaimSourceError::CountOverflow);
    }
    Ok(ClaimSourceScheduleReport {
        slots: u64::try_from(bundles.len()).map_err(|_| ClaimSourceError::CountOverflow)?,
        calls: u64::from(ordinal) + 1,
        permutations,
        keccak_round_rows: round_rows,
        root,
        commitment: commitment.finalize().into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_wrong_bundle_count() {
        assert_eq!(
            evaluate_claim_source_schedule(OracleProfile::K128, &[], [0_u8; 64]),
            Err(ClaimSourceError::BundleCountInvalid)
        );
    }

    #[test]
    fn rejects_wrong_bundle_length_before_hashing() {
        assert_eq!(
            validate_claim_source_bundle(OracleProfile::K128, 0, b"short"),
            Err(ClaimSourceError::BundleLengthInvalid)
        );
    }
}
