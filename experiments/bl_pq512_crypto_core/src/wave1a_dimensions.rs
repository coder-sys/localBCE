//! Cross-language constants for the nonactivating Wave 1A physical relation.
//!
//! These values are an independently typed Rust surface for the Python
//! physical-relation dimension ledger.  They select no proof suite and grant
//! no soundness credit.

pub const TABLES: u32 = 16;
pub const COMMITMENTS: u32 = 4;
pub const TRACE_COLUMNS_ACROSS_TABLES: u32 = 2_279;
pub const CONSTRAINTS: u32 = 4_844;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const LOOKUP_MESSAGE_WIDTH_ACROSS_TABLES: u32 = 276;
pub const MAX_D_EFF_ENVELOPE: u128 = 1_u128 << 111;
pub const ACTIVATION_ALLOWED: bool = false;
pub const PROOF_SUITE_ID: Option<[u8; 64]> = None;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationProfile {
    K128,
    K256,
    K512,
}

impl CalibrationProfile {
    pub const fn profile_id(self) -> &'static str {
        match self {
            Self::K128 => "K128_CALIBRATION",
            Self::K256 => "K256_DESIGN_POINT",
            Self::K512 => "K512_CALIBRATION",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DimensionRecord {
    pub profile: CalibrationProfile,
    pub logical_rows: u64,
    pub padded_rows: u64,
    pub padded_cells: u64,
    pub d_eff_upper_bound: u64,
    pub program_commitment_sha3_512_hex: &'static str,
}

pub const RECORDS: [DimensionRecord; 3] = [
    DimensionRecord {
        profile: CalibrationProfile::K128,
        logical_rows: 294_412,
        padded_rows: 389_520,
        padded_cells: 44_205_824,
        d_eff_upper_bound: 713_641_951_232,
        program_commitment_sha3_512_hex: "0d3544a1038006667f5ab795540c3ecd8ec83991d3e647e2106770d023c6a2f2\
             dda783fb3ac6fc916b261922e6ef10b67c692909fc25e918d8021e5527aa9c81",
    },
    DimensionRecord {
        profile: CalibrationProfile::K256,
        logical_rows: 601_996,
        padded_rows: 779_024,
        padded_cells: 88_410_240,
        d_eff_upper_bound: 1_427_283_902_464,
        program_commitment_sha3_512_hex: "5581a2307e693341b95baeabc87b90943f0775babed6937fb3cae580e59af2164\
             d83d9626b3538ec0076bf5e71fa92fe11e6b4bace14593a21dc4c955b293067",
    },
    DimensionRecord {
        profile: CalibrationProfile::K512,
        logical_rows: 1_230_476,
        padded_rows: 1_562_128,
        padded_cells: 177_212_288,
        d_eff_upper_bound: 2_854_567_804_928,
        program_commitment_sha3_512_hex: "c6dd66f955a86a3d490311c45338acbc29bee5487ed0dd77a275bd414582668eaa\
             2b75489492ec8ee6c4d6bc1d3415e02025bfc4489d6f315b1b416063ff8b38",
    },
];

pub fn record_for(profile: CalibrationProfile) -> &'static DimensionRecord {
    match profile {
        CalibrationProfile::K128 => &RECORDS[0],
        CalibrationProfile::K256 => &RECORDS[1],
        CalibrationProfile::K512 => &RECORDS[2],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibration_records_are_exact_and_nonactivating() {
        assert_eq!(RECORDS.len(), 3);
        const { assert!(!ACTIVATION_ALLOWED) };
        assert!(PROOF_SUITE_ID.is_none());
        for record in RECORDS {
            assert_eq!(record.program_commitment_sha3_512_hex.len(), 128);
            assert!(
                record
                    .program_commitment_sha3_512_hex
                    .bytes()
                    .all(|value| value.is_ascii_hexdigit())
            );
            assert!(u128::from(record.d_eff_upper_bound) < MAX_D_EFF_ENVELOPE);
        }
    }

    #[test]
    fn design_point_values_match_the_frozen_ledger() {
        let record = record_for(CalibrationProfile::K256);
        assert_eq!(record.profile.profile_id(), "K256_DESIGN_POINT");
        assert_eq!(record.logical_rows, 601_996);
        assert_eq!(record.padded_rows, 779_024);
        assert_eq!(record.padded_cells, 88_410_240);
        assert_eq!(record.d_eff_upper_bound, 1_427_283_902_464);
        assert_eq!(TABLES, 16);
        assert_eq!(COMMITMENTS, 4);
        assert_eq!(TRACE_COLUMNS_ACROSS_TABLES, 2_279);
        assert_eq!(CONSTRAINTS, 4_844);
        assert_eq!(MAXIMUM_CONSTRAINT_DEGREE, 3);
        assert_eq!(LOOKUP_MESSAGE_WIDTH_ACROSS_TABLES, 276);
    }
}
