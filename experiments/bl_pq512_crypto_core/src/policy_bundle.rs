//! Packed policy-bundle validation and bounded SHA3-512 trace streaming.

use core::fmt;

use alloc::vec::Vec;
use sha3::{Digest, Sha3_512};

use crate::oracle_bundle::OracleProfile;
use crate::sha3_air::{
    KECCAK_ROUNDS, Sha3TraceError, for_each_sha3_512_trace_row, sha3_512_reference,
};

pub const POLICY_LINES_PER_CLAIM: usize = 50;
pub const LINE_BYTES: usize = 18;
pub const LINE_BASE: usize = 14;
pub const POLICY_BUNDLE_BYTES: usize = LINE_BASE + POLICY_LINES_PER_CLAIM * LINE_BYTES;
pub const MAX_POLICY_SLOTS: usize = 512;
const RATE_BYTES: usize = 72;
const BUNDLE_MAGIC: &[u8; 8] = b"BLPQPOL2";
const EXECUTION_ROOT_MAGIC: &[u8; 8] = b"BLPQPXR2";
const SCHEDULE_DOMAIN: &[u8] = b"BL/PQ512/WAVE1A/POLICY-SHA3-SCHEDULE/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyBundleError {
    BundleLength,
    BundleMagic,
    Profile,
    SlotIndex,
    Boolean,
    EnabledPrefix,
    ProcedureLength,
    ProcedurePadding,
    DisabledNotZero,
    BundleCount,
    BundleOrder,
    ExpectedExecutionRootInvalid,
    CountOverflow,
    Trace(Sha3TraceError),
}

impl fmt::Display for PolicyBundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "policy bundle error: {self:?}")
    }
}

impl core::error::Error for PolicyBundleError {}

fn boolean(value: u8) -> Result<bool, PolicyBundleError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PolicyBundleError::Boolean),
    }
}

pub fn validate_policy_bundle(
    encoded: &[u8],
    expected_profile: OracleProfile,
    expected_slot: usize,
) -> Result<(), PolicyBundleError> {
    if encoded.len() != POLICY_BUNDLE_BYTES {
        return Err(PolicyBundleError::BundleLength);
    }
    if encoded.get(..8) != Some(BUNDLE_MAGIC.as_slice()) {
        return Err(PolicyBundleError::BundleMagic);
    }
    if encoded[8] != expected_profile.code() {
        return Err(PolicyBundleError::Profile);
    }
    let slot = u32::from_be_bytes(
        encoded[9..13]
            .try_into()
            .map_err(|_| PolicyBundleError::SlotIndex)?,
    );
    if usize::try_from(slot).map_err(|_| PolicyBundleError::SlotIndex)? != expected_slot {
        return Err(PolicyBundleError::SlotIndex);
    }
    let real = boolean(encoded[13])?;
    let mut gap_seen = false;
    for index in 0..POLICY_LINES_PER_CLAIM {
        let base = LINE_BASE + index * LINE_BYTES;
        let enabled = boolean(encoded[base])?;
        let _present = boolean(encoded[base + 1])?;
        let length = usize::from(encoded[base + 2]);
        let _requires = boolean(encoded[base + 17])?;
        if !enabled {
            gap_seen = true;
        } else if gap_seen || !real {
            return Err(PolicyBundleError::EnabledPrefix);
        }
        if (enabled && !(2..=10).contains(&length)) || (!enabled && length != 0) {
            return Err(PolicyBundleError::ProcedureLength);
        }
        if encoded[base + 3 + length..base + 13]
            .iter()
            .any(|value| *value != 0)
        {
            return Err(PolicyBundleError::ProcedurePadding);
        }
        if !enabled
            && encoded[base + 1..base + LINE_BYTES]
                .iter()
                .any(|value| *value != 0)
        {
            return Err(PolicyBundleError::DisabledNotZero);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyScheduleReport {
    pub slots: u64,
    pub calls: u64,
    pub permutations: u64,
    pub keccak_round_rows: u64,
    pub execution_root: [u8; 64],
    pub commitment: [u8; 64],
}

fn trace_call(
    ordinal: u32,
    kind: u8,
    message: &[u8],
    commitment: &mut Sha3_512,
    permutations: &mut u64,
    rows: &mut u64,
) -> Result<[u8; 64], PolicyBundleError> {
    let mut call_rows = 0_u64;
    let digest =
        for_each_sha3_512_trace_row(message, message.len(), |_, _, _, _, _, _| call_rows += 1)
            .map_err(PolicyBundleError::Trace)?;
    if digest != sha3_512_reference(message) {
        return Err(PolicyBundleError::BundleLength);
    }
    *permutations = permutations
        .checked_add((message.len() / RATE_BYTES + 1) as u64)
        .ok_or(PolicyBundleError::CountOverflow)?;
    *rows = rows
        .checked_add(call_rows)
        .ok_or(PolicyBundleError::CountOverflow)?;
    commitment.update(ordinal.to_be_bytes());
    commitment.update([kind]);
    let length = u16::try_from(message.len()).map_err(|_| PolicyBundleError::CountOverflow)?;
    commitment.update(length.to_be_bytes());
    commitment.update(length.to_be_bytes());
    commitment.update(message);
    commitment.update(digest);
    Ok(digest)
}

pub fn evaluate_policy_schedule(
    profile: OracleProfile,
    bundles: &[Vec<u8>],
    expected_execution_root: [u8; 64],
) -> Result<PolicyScheduleReport, PolicyBundleError> {
    if bundles.len() != profile.claim_slots() || bundles.len() > MAX_POLICY_SLOTS {
        return Err(PolicyBundleError::BundleCount);
    }
    let mut commitment = Sha3_512::new();
    commitment.update(SCHEDULE_DOMAIN);
    commitment.update([profile.code()]);
    commitment.update(
        u16::try_from(bundles.len())
            .map_err(|_| PolicyBundleError::CountOverflow)?
            .to_be_bytes(),
    );
    let mut permutations = 0_u64;
    let mut rows = 0_u64;
    let mut leaves = Vec::with_capacity(bundles.len());
    for (slot, bundle) in bundles.iter().enumerate() {
        validate_policy_bundle(bundle, profile, slot)?;
        leaves.push(trace_call(
            u32::try_from(slot).map_err(|_| PolicyBundleError::CountOverflow)?,
            1,
            bundle,
            &mut commitment,
            &mut permutations,
            &mut rows,
        )?);
    }
    let mut root_message = Vec::with_capacity(11 + 64 * leaves.len());
    root_message.extend_from_slice(EXECUTION_ROOT_MAGIC);
    root_message.push(profile.code());
    root_message.extend_from_slice(
        &u16::try_from(profile.claim_slots())
            .map_err(|_| PolicyBundleError::CountOverflow)?
            .to_be_bytes(),
    );
    for digest in &leaves {
        root_message.extend_from_slice(digest);
    }
    let execution_root = trace_call(
        u32::try_from(bundles.len()).map_err(|_| PolicyBundleError::CountOverflow)?,
        2,
        &root_message,
        &mut commitment,
        &mut permutations,
        &mut rows,
    )?;
    if execution_root != expected_execution_root {
        return Err(PolicyBundleError::ExpectedExecutionRootInvalid);
    }
    commitment.update(execution_root);
    if rows != permutations * u64::from(KECCAK_ROUNDS) {
        return Err(PolicyBundleError::CountOverflow);
    }
    Ok(PolicyScheduleReport {
        slots: u64::try_from(bundles.len()).map_err(|_| PolicyBundleError::CountOverflow)?,
        calls: u64::try_from(bundles.len() + 1).map_err(|_| PolicyBundleError::CountOverflow)?,
        permutations,
        keccak_round_rows: rows,
        execution_root,
        commitment: commitment.finalize().into(),
    })
}
