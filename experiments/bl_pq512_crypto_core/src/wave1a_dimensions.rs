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
        logical_rows: 753_164,
        padded_rows: 848_272,
        padded_cells: 114_853_632,
        d_eff_upper_bound: 1_427_283_902_464,
        program_commitment_sha3_512_hex: "d5df3ac6795e534bb6bb2ae090ff2dc9282a3dcf76c2602997e3b7cd304a9542\
             2d9c791dcd36ca5ae635afb3b6a11791d66b4ae3a194999de523247f353dd161",
    },
    DimensionRecord {
        profile: CalibrationProfile::K256,
        logical_rows: 1_519_500,
        padded_rows: 1_696_528,
        padded_cells: 229_705_856,
        d_eff_upper_bound: 2_854_567_804_928,
        program_commitment_sha3_512_hex: "2f0029505286c35976c50dcb747605e72c31b34de0463c3093621d6936b8b63d\
             e62369302ca84a583bad6e6d365db9460870c6b0c4cb973bcb55f0af4de01860",
    },
    DimensionRecord {
        profile: CalibrationProfile::K512,
        logical_rows: 3_065_484,
        padded_rows: 3_397_136,
        padded_cells: 459_803_520,
        d_eff_upper_bound: 5_709_135_609_856,
        program_commitment_sha3_512_hex: "60cb58cc01fdb445b83b919cae2f30d00fbe4842cd2b60fea8bff4943cbc8378\
             2f878c252f8d4ff1e7950c68fab141ffcb784ec141a7ffd612544929de406e70",
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
        assert_eq!(record.logical_rows, 1_519_500);
        assert_eq!(record.padded_rows, 1_696_528);
        assert_eq!(record.padded_cells, 229_705_856);
        assert_eq!(record.d_eff_upper_bound, 2_854_567_804_928);
        assert_eq!(TABLES, 16);
        assert_eq!(COMMITMENTS, 4);
        assert_eq!(TRACE_COLUMNS_ACROSS_TABLES, 2_279);
        assert_eq!(CONSTRAINTS, 4_844);
        assert_eq!(MAXIMUM_CONSTRAINT_DEGREE, 3);
        assert_eq!(LOOKUP_MESSAGE_WIDTH_ACROSS_TABLES, 276);
    }
}
