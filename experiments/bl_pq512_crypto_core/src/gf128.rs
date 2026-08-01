//! Nonactivating polynomial-basis `GF(2^128)` reference arithmetic.
//!
//! The modulus is `x^128 + x^7 + x^2 + x + 1`. This module is a small,
//! constant-memory correctness oracle for the binary-native GKR experiment.
//! It is not selected by any proof or transcript profile.

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Gf128 {
    pub low: u64,
    pub high: u64,
}

impl Gf128 {
    pub const ZERO: Self = Self { low: 0, high: 0 };
    pub const ONE: Self = Self { low: 1, high: 0 };

    pub const fn from_u128(value: u128) -> Self {
        Self {
            low: value as u64,
            high: (value >> 64) as u64,
        }
    }

    pub const fn to_u128(self) -> u128 {
        self.low as u128 | ((self.high as u128) << 64)
    }

    pub fn square(self) -> Self {
        self * self
    }

    /// Returns the multiplicative inverse, or `None` for zero.
    pub fn inverse(self) -> Option<Self> {
        if self == Self::ZERO {
            return None;
        }
        // In GF(2^128), a^(2^128 - 2) = a^-1. Starting from `a`, each
        // iteration squares and multiplies by `a`, producing
        // a^(2^(i + 1) - 1). The final square removes the last `-1`.
        let mut accumulator = self;
        for _ in 0..126 {
            accumulator = accumulator.square() * self;
        }
        Some(accumulator.square())
    }
}

impl Add for Gf128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            low: self.low ^ rhs.low,
            high: self.high ^ rhs.high,
        }
    }
}

impl AddAssign for Gf128 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Sub for Gf128 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl SubAssign for Gf128 {
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}

impl Mul for Gf128 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut left = self;
        let mut right = rhs;
        let mut result = Self::ZERO;
        for _ in 0..128 {
            let mask = 0_u64.wrapping_sub(right.low & 1);
            result.low ^= left.low & mask;
            result.high ^= left.high & mask;

            let carry = left.high >> 63;
            left.high = (left.high << 1) | (left.low >> 63);
            left.low <<= 1;
            left.low ^= 0x87 & 0_u64.wrapping_sub(carry);

            right.low = (right.low >> 1) | (right.high << 63);
            right.high >>= 1;
        }
        result
    }
}

impl MulAssign for Gf128 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Gf128Triple(pub [Gf128; 3]);

impl Gf128Triple {
    pub const ZERO: Self = Self([Gf128::ZERO; 3]);
    pub const ONE: Self = Self([Gf128::ONE; 3]);
}

impl Add for Gf128Triple {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(core::array::from_fn(|lane| self.0[lane] + rhs.0[lane]))
    }
}

impl AddAssign for Gf128Triple {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Mul for Gf128Triple {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(core::array::from_fn(|lane| self.0[lane] * rhs.0[lane]))
    }
}

impl MulAssign for Gf128Triple {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiplication_matches_independent_polynomial_basis_vectors() {
        let vectors = [
            (
                0x0123_4567_89ab_cdef_0123_4567_89ab_cdef,
                0xfedc_ba98_7654_3210_fedc_ba98_7654_3210,
                0x725c_fee5_3719_bb81_d3fd_5f44_96b8_1a20,
            ),
            (
                0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
                0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
                0x5555_5555_5555_5555_5555_5555_5555_402f,
            ),
            (
                0xdead_beef_cafe_babe_1122_3344_5566_7788,
                0x8877_6655_4433_2211_abcd_ef01_2345_6789,
                0x09e8_f378_4ad4_d1a7_3a6e_e1a6_c530_4a34,
            ),
        ];
        for (left, right, expected) in vectors {
            let left = Gf128::from_u128(left);
            let right = Gf128::from_u128(right);
            assert_eq!((left * right).to_u128(), expected);
            assert_eq!(left * right, right * left);
        }
        assert_eq!(
            (Gf128::from_u128(1_u128 << 127) * Gf128::from_u128(2)).to_u128(),
            0x87
        );
    }

    #[test]
    fn triple_lanes_are_independent() {
        let left = Gf128Triple([
            Gf128::from_u128(3),
            Gf128::from_u128(5),
            Gf128::from_u128(7),
        ]);
        let right = Gf128Triple([
            Gf128::from_u128(11),
            Gf128::from_u128(13),
            Gf128::from_u128(17),
        ]);
        let product = left * right;
        for lane in 0..3 {
            assert_eq!(product.0[lane], left.0[lane] * right.0[lane]);
        }
    }

    #[test]
    fn inversion_is_total_only_on_nonzero_elements() {
        assert_eq!(Gf128::ZERO.inverse(), None);
        for value in [
            1,
            2,
            3,
            0x0123_4567_89ab_cdef_0123_4567_89ab_cdef,
            u128::MAX,
        ] {
            let value = Gf128::from_u128(value);
            let inverse = value.inverse().unwrap();
            assert_eq!(value * inverse, Gf128::ONE);
            assert_eq!(inverse * value, Gf128::ONE);
        }
    }
}
