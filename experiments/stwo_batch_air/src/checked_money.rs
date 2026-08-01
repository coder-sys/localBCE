//! Exact integer/limb reference for future AIR columns; not an AIR constraint.

pub const MAX_CLAIM_SLOTS: usize = 512;
pub const LIMB_BITS: u32 = 16;
pub const LIMB_MASK: u64 = (1_u64 << LIMB_BITS) - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct U32Limbs {
    pub low: u16,
    pub high: u16,
}

impl U32Limbs {
    pub fn from_u32(value: u32) -> Self {
        Self {
            low: (u64::from(value) & LIMB_MASK) as u16,
            high: (u64::from(value) >> LIMB_BITS) as u16,
        }
    }

    pub fn recompose(self) -> u32 {
        u32::from(self.low) | (u32::from(self.high) << LIMB_BITS)
    }
}

pub fn u64_limbs(value: u64) -> [u16; 4] {
    [
        (value & LIMB_MASK) as u16,
        ((value >> 16) & LIMB_MASK) as u16,
        ((value >> 32) & LIMB_MASK) as u16,
        ((value >> 48) & LIMB_MASK) as u16,
    ]
}

pub fn recompose_u64(limbs: [u16; 4]) -> u64 {
    u64::from(limbs[0])
        | (u64::from(limbs[1]) << 16)
        | (u64::from(limbs[2]) << 32)
        | (u64::from(limbs[3]) << 48)
}

pub fn checked_batch_sum(values: &[u32]) -> Result<u64, &'static str> {
    if values.len() > MAX_CLAIM_SLOTS {
        return Err("r25_checked_money_claim_count_exceeds_k512");
    }
    values.iter().try_fold(0_u64, |total, value| {
        total
            .checked_add(u64::from(*value))
            .ok_or("r25_checked_money_u64_overflow")
    })
}

pub fn require_conservation(
    plan_payable: &[u32],
    debits: &[u32],
    credits: &[u32],
) -> Result<u64, &'static str> {
    if plan_payable.len() != debits.len() || plan_payable.len() != credits.len() {
        return Err("r25_checked_money_vector_length_mismatch");
    }
    let payable_total = checked_batch_sum(plan_payable)?;
    let debit_total = checked_batch_sum(debits)?;
    let credit_total = checked_batch_sum(credits)?;
    if payable_total != debit_total || payable_total != credit_total {
        return Err("r25_checked_money_conservation_mismatch");
    }
    Ok(payable_total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_limb_round_trip_covers_boundaries() {
        for value in [0, 1, 65_535, 65_536, 2_147_483_647, u32::MAX] {
            let limbs = U32Limbs::from_u32(value);
            assert_eq!(limbs.recompose(), value);
        }
    }

    #[test]
    fn wide_aggregate_round_trip_and_k_bounds_are_exact() {
        for claim_slots in [128_usize, 256, 512] {
            let values = vec![u32::MAX; claim_slots];
            let total = checked_batch_sum(&values).unwrap();
            assert_eq!(total, claim_slots as u64 * u64::from(u32::MAX));
            assert_eq!(recompose_u64(u64_limbs(total)), total);
        }
        assert_eq!(
            checked_batch_sum(&vec![u32::MAX; 256]).unwrap(),
            1_099_511_627_520
        );
    }

    #[test]
    fn carry_crosses_m31_without_field_reduction() {
        let values = [2_147_483_647_u32, 1_u32, u32::MAX];
        let total = checked_batch_sum(&values).unwrap();
        assert_eq!(total, 6_442_450_943);
        assert_eq!(recompose_u64(u64_limbs(total)), total);
    }

    #[test]
    fn conservation_and_length_fail_closed() {
        assert_eq!(require_conservation(&[80, 0], &[80, 0], &[80, 0]), Ok(80));
        assert_eq!(
            require_conservation(&[80], &[79], &[80]),
            Err("r25_checked_money_conservation_mismatch")
        );
        assert_eq!(
            require_conservation(&[80], &[80, 0], &[80]),
            Err("r25_checked_money_vector_length_mismatch")
        );
        assert_eq!(
            checked_batch_sum(&vec![0; MAX_CLAIM_SLOTS + 1]),
            Err("r25_checked_money_claim_count_exceeds_k512")
        );
    }
}
