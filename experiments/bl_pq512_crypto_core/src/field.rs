//! Canonical M31 arithmetic and the frozen degree-16 quadratic tower.

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::ops::{Add, Mul, Neg, Sub};

/// The Mersenne prime `2^31 - 1`.
pub const M31_MODULUS: u32 = 0x7fff_ffff;
/// Number of canonical M31 coefficients in [`Fp16`].
pub const EXTENSION_DEGREE: usize = 16;
/// Exact encoded length of [`Fp16`].
pub const FP16_ENCODED_LENGTH: usize = 64;
/// Frozen flat basis, in encoding order.
pub const FP16_BASIS: [&str; EXTENSION_DEGREE] = [
    "1", "i", "u", "iu", "v", "iv", "uv", "iuv", "w", "iw", "uw", "iuw", "vw", "ivw", "uvw", "iuvw",
];

/// Failure returned by canonical field construction or inversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldError {
    /// A supplied M31 coefficient was not strictly less than the modulus.
    NonCanonicalCoefficient { index: usize, value: u32 },
    /// Inversion of zero was requested.
    ZeroInverse,
    /// A Frobenius power outside the canonical range `0..16` was requested.
    FrobeniusPowerOutOfRange(u8),
}

impl fmt::Display for FieldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalCoefficient { index, value } => {
                write!(
                    formatter,
                    "coefficient {index} is noncanonical M31 value {value}"
                )
            }
            Self::ZeroInverse => formatter.write_str("zero has no multiplicative inverse"),
            Self::FrobeniusPowerOutOfRange(power) => {
                write!(formatter, "Frobenius power {power} is outside 0..16")
            }
        }
    }
}

impl core::error::Error for FieldError {}

/// Failure returned by strict 64-byte field decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// The input was not exactly 64 bytes.
    Length { actual: usize },
    /// One coefficient was not canonical M31.
    NonCanonicalCoefficient { index: usize, value: u32 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => write!(
                formatter,
                "Fp16 encoding must be {FP16_ENCODED_LENGTH} bytes, got {actual}"
            ),
            Self::NonCanonicalCoefficient { index, value } => {
                write!(
                    formatter,
                    "coefficient {index} is noncanonical M31 value {value}"
                )
            }
        }
    }
}

impl core::error::Error for DecodeError {}

/// One canonical scalar in M31.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct M31(u32);

impl M31 {
    /// Additive identity.
    pub const ZERO: Self = Self(0);
    /// Multiplicative identity.
    pub const ONE: Self = Self(1);
    /// Frozen first nonresidue: `i^2 = -1`.
    pub const NEGATIVE_ONE: Self = Self(M31_MODULUS - 1);

    /// Constructs a scalar only if `value` is canonical.
    pub const fn from_canonical(value: u32) -> Result<Self, FieldError> {
        if value < M31_MODULUS {
            Ok(Self(value))
        } else {
            Err(FieldError::NonCanonicalCoefficient { index: 0, value })
        }
    }

    /// Returns the canonical integer representative.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns whether this scalar is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Branch-minimized canonical addition.
    pub const fn add(self, rhs: Self) -> Self {
        let sum = self.0 + rhs.0;
        Self(Self::reduce_once_u32(sum))
    }

    /// Branch-minimized canonical subtraction.
    pub const fn sub(self, rhs: Self) -> Self {
        let difference = self.0.wrapping_sub(rhs.0);
        let borrow_mask = 0_u32.wrapping_sub((self.0 < rhs.0) as u32);
        Self(difference.wrapping_add(M31_MODULUS & borrow_mask))
    }

    /// Branch-minimized canonical negation.
    pub const fn neg(self) -> Self {
        let nonzero_mask = 0_u32.wrapping_sub((self.0 != 0) as u32);
        Self((M31_MODULUS - self.0) & nonzero_mask)
    }

    /// Mersenne-reduced canonical multiplication.
    pub const fn mul(self, rhs: Self) -> Self {
        let product = self.0 as u64 * rhs.0 as u64;
        let folded = (product & M31_MODULUS as u64) + (product >> 31);
        Self(Self::reduce_once_u32(folded as u32))
    }

    /// Canonical squaring.
    pub const fn square(self) -> Self {
        self.mul(self)
    }

    /// Multiplication by two in M31.
    pub const fn double(self) -> Self {
        self.add(self)
    }

    /// Fixed-work inversion by the exponent `p - 2`.
    pub fn inverse(self) -> Result<Self, FieldError> {
        if self.is_zero() {
            return Err(FieldError::ZeroInverse);
        }
        const EXPONENT: u32 = M31_MODULUS - 2;
        let mut result = Self::ONE;
        for bit in (0..31).rev() {
            let squared = result.square();
            let multiplied = squared.mul(self);
            result = Self::conditional_select(multiplied, squared, (EXPONENT >> bit) & 1);
        }
        Ok(result)
    }

    const fn conditional_select(if_one: Self, if_zero: Self, choice: u32) -> Self {
        let mask = 0_u32.wrapping_sub(choice & 1);
        Self((if_one.0 & mask) | (if_zero.0 & !mask))
    }

    const fn reduce_once_u32(value: u32) -> u32 {
        let reduced = value.wrapping_sub(M31_MODULUS);
        let underflow_mask = 0_u32.wrapping_sub((value < M31_MODULUS) as u32);
        reduced.wrapping_add(M31_MODULUS & underflow_mask)
    }
}

/// `Fp[i] / (i^2 + 1)` in basis `1,i`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Fp2 {
    c0: M31,
    c1: M31,
}

impl Fp2 {
    /// Additive identity.
    pub const ZERO: Self = Self::new(M31::ZERO, M31::ZERO);
    /// Multiplicative identity.
    pub const ONE: Self = Self::new(M31::ONE, M31::ZERO);
    /// Frozen nonresidue for the next tower step: `2+i`.
    pub const TWO_PLUS_I: Self = Self::new(M31(2), M31::ONE);

    /// Constructs an element from canonical lower-field coordinates.
    pub const fn new(c0: M31, c1: M31) -> Self {
        Self { c0, c1 }
    }

    /// Returns the two coordinates in flat basis order.
    pub const fn coordinates(self) -> [M31; 2] {
        [self.c0, self.c1]
    }

    /// Returns whether the element is zero.
    pub const fn is_zero(self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    /// Field addition.
    pub const fn add(self, rhs: Self) -> Self {
        Self::new(self.c0.add(rhs.c0), self.c1.add(rhs.c1))
    }

    /// Field subtraction.
    pub const fn sub(self, rhs: Self) -> Self {
        Self::new(self.c0.sub(rhs.c0), self.c1.sub(rhs.c1))
    }

    /// Field negation.
    pub const fn neg(self) -> Self {
        Self::new(self.c0.neg(), self.c1.neg())
    }

    /// Karatsuba multiplication with `i^2 = -1`.
    pub const fn mul(self, rhs: Self) -> Self {
        let ac = self.c0.mul(rhs.c0);
        let bd = self.c1.mul(rhs.c1);
        let cross = self.c0.add(self.c1).mul(rhs.c0.add(rhs.c1)).sub(ac).sub(bd);
        Self::new(ac.sub(bd), cross)
    }

    /// Multiplication by the frozen element `2+i` without a generic field
    /// multiplication: `(a+bi)(2+i) = (2a-b) + (a+2b)i`.
    const fn mul_by_two_plus_i(self) -> Self {
        Self::new(self.c0.double().sub(self.c1), self.c0.add(self.c1.double()))
    }

    /// Quadratic-tower squaring.
    pub const fn square(self) -> Self {
        Self::new(
            self.c0.square().sub(self.c1.square()),
            self.c0.mul(self.c1).double(),
        )
    }

    /// Quadratic-tower inversion.
    pub fn inverse(self) -> Result<Self, FieldError> {
        if self.is_zero() {
            return Err(FieldError::ZeroInverse);
        }
        let denominator = self.c0.square().add(self.c1.square()).inverse()?;
        Ok(Self::new(
            self.c0.mul(denominator),
            self.c1.neg().mul(denominator),
        ))
    }

    const fn conditional_select(if_one: Self, if_zero: Self, choice: u32) -> Self {
        Self::new(
            M31::conditional_select(if_one.c0, if_zero.c0, choice),
            M31::conditional_select(if_one.c1, if_zero.c1, choice),
        )
    }
}

/// `Fp2[u] / (u^2 - (2+i))` in basis `1,i,u,iu`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Fp4 {
    c0: Fp2,
    c1: Fp2,
}

impl Fp4 {
    /// Additive identity.
    pub const ZERO: Self = Self::new(Fp2::ZERO, Fp2::ZERO);
    /// Multiplicative identity.
    pub const ONE: Self = Self::new(Fp2::ONE, Fp2::ZERO);
    /// Frozen nonresidue for the next tower step: `u`.
    pub const U: Self = Self::new(Fp2::ZERO, Fp2::ONE);

    /// Constructs an element from lower-field coordinates.
    pub const fn new(c0: Fp2, c1: Fp2) -> Self {
        Self { c0, c1 }
    }

    /// Returns the two lower-field coordinates.
    pub const fn coordinates(self) -> [Fp2; 2] {
        [self.c0, self.c1]
    }

    /// Returns whether the element is zero.
    pub const fn is_zero(self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    /// Field addition.
    pub const fn add(self, rhs: Self) -> Self {
        Self::new(self.c0.add(rhs.c0), self.c1.add(rhs.c1))
    }

    /// Field subtraction.
    pub const fn sub(self, rhs: Self) -> Self {
        Self::new(self.c0.sub(rhs.c0), self.c1.sub(rhs.c1))
    }

    /// Field negation.
    pub const fn neg(self) -> Self {
        Self::new(self.c0.neg(), self.c1.neg())
    }

    /// Karatsuba multiplication with `u^2 = 2+i`.
    pub const fn mul(self, rhs: Self) -> Self {
        let ac = self.c0.mul(rhs.c0);
        let bd = self.c1.mul(rhs.c1);
        let cross = self.c0.add(self.c1).mul(rhs.c0.add(rhs.c1)).sub(ac).sub(bd);
        Self::new(ac.add(bd.mul_by_two_plus_i()), cross)
    }

    /// Multiplication by the frozen tower generator `u`.
    const fn mul_by_u(self) -> Self {
        Self::new(self.c1.mul_by_two_plus_i(), self.c0)
    }

    /// Quadratic-tower squaring.
    pub const fn square(self) -> Self {
        Self::new(
            self.c0.square().add(self.c1.square().mul_by_two_plus_i()),
            self.c0.mul(self.c1).add(self.c0.mul(self.c1)),
        )
    }

    /// Quadratic-tower inversion.
    pub fn inverse(self) -> Result<Self, FieldError> {
        if self.is_zero() {
            return Err(FieldError::ZeroInverse);
        }
        let denominator = self
            .c0
            .square()
            .sub(self.c1.square().mul_by_two_plus_i())
            .inverse()?;
        Ok(Self::new(
            self.c0.mul(denominator),
            self.c1.neg().mul(denominator),
        ))
    }

    const fn conditional_select(if_one: Self, if_zero: Self, choice: u32) -> Self {
        Self::new(
            Fp2::conditional_select(if_one.c0, if_zero.c0, choice),
            Fp2::conditional_select(if_one.c1, if_zero.c1, choice),
        )
    }
}

/// `Fp4[v] / (v^2 - u)` in basis `1,i,u,iu,v,iv,uv,iuv`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Fp8 {
    c0: Fp4,
    c1: Fp4,
}

impl Fp8 {
    /// Additive identity.
    pub const ZERO: Self = Self::new(Fp4::ZERO, Fp4::ZERO);
    /// Multiplicative identity.
    pub const ONE: Self = Self::new(Fp4::ONE, Fp4::ZERO);
    /// Frozen nonresidue for the top tower step: `v`.
    pub const V: Self = Self::new(Fp4::ZERO, Fp4::ONE);

    /// Constructs an element from lower-field coordinates.
    pub const fn new(c0: Fp4, c1: Fp4) -> Self {
        Self { c0, c1 }
    }

    /// Returns the two lower-field coordinates.
    pub const fn coordinates(self) -> [Fp4; 2] {
        [self.c0, self.c1]
    }

    /// Returns whether the element is zero.
    pub const fn is_zero(self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    /// Field addition.
    pub const fn add(self, rhs: Self) -> Self {
        Self::new(self.c0.add(rhs.c0), self.c1.add(rhs.c1))
    }

    /// Field subtraction.
    pub const fn sub(self, rhs: Self) -> Self {
        Self::new(self.c0.sub(rhs.c0), self.c1.sub(rhs.c1))
    }

    /// Field negation.
    pub const fn neg(self) -> Self {
        Self::new(self.c0.neg(), self.c1.neg())
    }

    /// Karatsuba multiplication with `v^2 = u`.
    pub const fn mul(self, rhs: Self) -> Self {
        let ac = self.c0.mul(rhs.c0);
        let bd = self.c1.mul(rhs.c1);
        let cross = self.c0.add(self.c1).mul(rhs.c0.add(rhs.c1)).sub(ac).sub(bd);
        Self::new(ac.add(bd.mul_by_u()), cross)
    }

    /// Multiplication by the frozen tower generator `v`.
    const fn mul_by_v(self) -> Self {
        Self::new(self.c1.mul_by_u(), self.c0)
    }

    /// Quadratic-tower squaring.
    pub const fn square(self) -> Self {
        let cross = self.c0.mul(self.c1);
        Self::new(
            self.c0.square().add(self.c1.square().mul_by_u()),
            cross.add(cross),
        )
    }

    /// Quadratic-tower inversion.
    pub fn inverse(self) -> Result<Self, FieldError> {
        if self.is_zero() {
            return Err(FieldError::ZeroInverse);
        }
        let denominator = self
            .c0
            .square()
            .sub(self.c1.square().mul_by_u())
            .inverse()?;
        Ok(Self::new(
            self.c0.mul(denominator),
            self.c1.neg().mul(denominator),
        ))
    }

    const fn conditional_select(if_one: Self, if_zero: Self, choice: u32) -> Self {
        Self::new(
            Fp4::conditional_select(if_one.c0, if_zero.c0, choice),
            Fp4::conditional_select(if_one.c1, if_zero.c1, choice),
        )
    }
}

/// `Fp8[w] / (w^2 - v)` in the frozen 16-coordinate basis.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Fp16 {
    c0: Fp8,
    c1: Fp8,
}

impl Fp16 {
    /// Additive identity.
    pub const ZERO: Self = Self::new(Fp8::ZERO, Fp8::ZERO);
    /// Multiplicative identity.
    pub const ONE: Self = Self::new(Fp8::ONE, Fp8::ZERO);

    /// Constructs an element from lower-field coordinates.
    pub const fn new(c0: Fp8, c1: Fp8) -> Self {
        Self { c0, c1 }
    }

    /// Canonically embeds one base-field scalar into the degree-16 tower.
    pub fn from_m31(value: M31) -> Self {
        let mut coefficients = [M31::ZERO; EXTENSION_DEGREE];
        coefficients[0] = value;
        Self::from_m31_coefficients(coefficients)
    }

    /// Strictly constructs from 16 canonical integers in frozen basis order.
    pub fn from_coefficients(values: [u32; EXTENSION_DEGREE]) -> Result<Self, FieldError> {
        let mut coefficients = [M31::ZERO; EXTENSION_DEGREE];
        for (index, value) in values.into_iter().enumerate() {
            coefficients[index] = M31::from_canonical(value)
                .map_err(|_| FieldError::NonCanonicalCoefficient { index, value })?;
        }
        Ok(Self::from_m31_coefficients(coefficients))
    }

    /// Returns the 16 canonical integers in frozen basis order.
    pub const fn coefficients(self) -> [u32; EXTENSION_DEGREE] {
        let a = self.c0.c0.c0.coordinates();
        let b = self.c0.c0.c1.coordinates();
        let c = self.c0.c1.c0.coordinates();
        let d = self.c0.c1.c1.coordinates();
        let e = self.c1.c0.c0.coordinates();
        let f = self.c1.c0.c1.coordinates();
        let g = self.c1.c1.c0.coordinates();
        let h = self.c1.c1.c1.coordinates();
        [
            a[0].as_u32(),
            a[1].as_u32(),
            b[0].as_u32(),
            b[1].as_u32(),
            c[0].as_u32(),
            c[1].as_u32(),
            d[0].as_u32(),
            d[1].as_u32(),
            e[0].as_u32(),
            e[1].as_u32(),
            f[0].as_u32(),
            f[1].as_u32(),
            g[0].as_u32(),
            g[1].as_u32(),
            h[0].as_u32(),
            h[1].as_u32(),
        ]
    }

    /// Returns whether top quadratic conjugation fixes this element.
    ///
    /// In the frozen flat basis this is exactly the condition that
    /// coefficients 8 through 15 are all zero.
    pub const fn is_in_fp8_subfield(self) -> bool {
        self.c1.is_zero()
    }

    /// Returns whether the element is zero.
    pub const fn is_zero(self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    /// Field addition.
    pub const fn add(self, rhs: Self) -> Self {
        Self::new(self.c0.add(rhs.c0), self.c1.add(rhs.c1))
    }

    /// Field subtraction.
    pub const fn sub(self, rhs: Self) -> Self {
        Self::new(self.c0.sub(rhs.c0), self.c1.sub(rhs.c1))
    }

    /// Field negation.
    pub const fn neg(self) -> Self {
        Self::new(self.c0.neg(), self.c1.neg())
    }

    /// Karatsuba multiplication with `w^2 = v`.
    pub const fn mul(self, rhs: Self) -> Self {
        let ac = self.c0.mul(rhs.c0);
        let bd = self.c1.mul(rhs.c1);
        let cross = self.c0.add(self.c1).mul(rhs.c0.add(rhs.c1)).sub(ac).sub(bd);
        Self::new(ac.add(bd.mul_by_v()), cross)
    }

    /// Multiply by a scalar from the canonical M31 base subfield.
    ///
    /// This avoids promoting a public/subfield coefficient into a generic
    /// Fp16 multiplication in the streamed Boolean-GKR prover.
    pub fn mul_by_m31(self, scalar: M31) -> Self {
        let values = self.coefficients();
        let mut scaled = [M31::ZERO; EXTENSION_DEGREE];
        for (destination, value) in scaled.iter_mut().zip(values) {
            *destination = M31(value).mul(scalar);
        }
        Self::from_m31_coefficients(scaled)
    }

    /// Quadratic-tower squaring.
    pub const fn square(self) -> Self {
        let cross = self.c0.mul(self.c1);
        Self::new(
            self.c0.square().add(self.c1.square().mul_by_v()),
            cross.add(cross),
        )
    }

    /// Quadratic-tower inversion.
    pub fn inverse(self) -> Result<Self, FieldError> {
        if self.is_zero() {
            return Err(FieldError::ZeroInverse);
        }
        let denominator = self
            .c0
            .square()
            .sub(self.c1.square().mul_by_v())
            .inverse()?;
        Ok(Self::new(
            self.c0.mul(denominator),
            self.c1.neg().mul(denominator),
        ))
    }

    /// Top quadratic conjugation: `(a + b*w) -> (a - b*w)`.
    pub const fn conjugate(self) -> Self {
        Self::new(self.c0, self.c1.neg())
    }

    /// Relative trace from Fp16 to the fixed Fp8 subfield.
    pub const fn trace_to_fp8(self) -> Fp8 {
        self.c0.add(self.c0)
    }

    /// Relative norm from Fp16 to the fixed Fp8 subfield.
    pub const fn norm_to_fp8(self) -> Fp8 {
        self.c0.square().sub(self.c1.square().mul_by_v())
    }

    /// Exponentiates by a public 32-bit exponent using a fixed 32-step schedule.
    pub fn pow_u32(self, exponent: u32) -> Self {
        let mut result = Self::ONE;
        for bit in (0..32).rev() {
            let squared = result.square();
            let multiplied = squared.mul(self);
            result = Self::conditional_select(multiplied, squared, (exponent >> bit) & 1);
        }
        result
    }

    /// Exponentiates by a public little-endian sequence of 32-bit words.
    ///
    /// The schedule depends only on the public exponent and is intended for
    /// parameter/domain derivation, not secret exponents.
    pub fn pow_words_le(self, exponent: &[u32]) -> Self {
        let mut result = Self::ONE;
        for word in exponent.iter().rev() {
            for bit in (0..32).rev() {
                result = result.square();
                if (word >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }

    /// Computes `self^(p^power)` for canonical `power < 16`.
    ///
    /// Field work is fixed at 512 squarings and 512 multiplications, independent
    /// of `power` and input. This is an auditable reference method, not an
    /// optimized constant-table Frobenius implementation.
    pub fn frobenius(self, power: u8) -> Result<Self, FieldError> {
        if power >= 16 {
            return Err(FieldError::FrobeniusPowerOutOfRange(power));
        }
        let exponent = frobenius_exponent(power);
        let mut result = Self::ONE;
        for bit in (0..512).rev() {
            let squared = result.square();
            let multiplied = squared.mul(self);
            let exponent_bit = (exponent[bit / 32] >> (bit % 32)) & 1;
            result = Self::conditional_select(multiplied, squared, exponent_bit);
        }
        Ok(result)
    }

    /// Encodes 16 canonical coefficients as exact four-byte big-endian words.
    pub fn encode(self) -> [u8; FP16_ENCODED_LENGTH] {
        let mut encoded = [0_u8; FP16_ENCODED_LENGTH];
        for (index, coefficient) in self.coefficients().into_iter().enumerate() {
            let start = index * 4;
            encoded[start..start + 4].copy_from_slice(&coefficient.to_be_bytes());
        }
        encoded
    }

    /// Strictly decodes an exact 64-byte coefficient-wise big-endian encoding.
    pub fn decode(encoded: &[u8]) -> Result<Self, DecodeError> {
        if encoded.len() != FP16_ENCODED_LENGTH {
            return Err(DecodeError::Length {
                actual: encoded.len(),
            });
        }
        let mut coefficients = [0_u32; EXTENSION_DEGREE];
        for (index, chunk) in encoded.chunks_exact(4).enumerate() {
            let value =
                u32::from_be_bytes(chunk.try_into().expect("chunks_exact yields four bytes"));
            if value >= M31_MODULUS {
                return Err(DecodeError::NonCanonicalCoefficient { index, value });
            }
            coefficients[index] = value;
        }
        Self::from_coefficients(coefficients).map_err(|error| match error {
            FieldError::NonCanonicalCoefficient { index, value } => {
                DecodeError::NonCanonicalCoefficient { index, value }
            }
            FieldError::ZeroInverse | FieldError::FrobeniusPowerOutOfRange(_) => {
                unreachable!("canonical construction cannot return this error")
            }
        })
    }

    pub(crate) fn from_m31_coefficients(c: [M31; EXTENSION_DEGREE]) -> Self {
        let fp2 = |offset: usize| Fp2::new(c[offset], c[offset + 1]);
        let fp4 = |offset: usize| Fp4::new(fp2(offset), fp2(offset + 2));
        let fp8 = |offset: usize| Fp8::new(fp4(offset), fp4(offset + 4));
        Self::new(fp8(0), fp8(8))
    }

    const fn conditional_select(if_one: Self, if_zero: Self, choice: u32) -> Self {
        Self::new(
            Fp8::conditional_select(if_one.c0, if_zero.c0, choice),
            Fp8::conditional_select(if_one.c1, if_zero.c1, choice),
        )
    }
}

/// Invert an Fp16 slice with one field inversion.
///
/// Montgomery batch inversion preserves fail-closed zero handling while
/// replacing one expensive inversion per value with linear multiplication.
pub(crate) fn batch_inverse_fp16(values: &[Fp16]) -> Result<Vec<Fp16>, FieldError> {
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let mut prefixes = Vec::with_capacity(values.len());
    let mut product = Fp16::ONE;
    for value in values {
        if value.is_zero() {
            return Err(FieldError::ZeroInverse);
        }
        prefixes.push(product);
        product = product.mul(*value);
    }
    let mut product_inverse = product.inverse()?;
    let mut inverses = vec![Fp16::ZERO; values.len()];
    for index in (0..values.len()).rev() {
        inverses[index] = product_inverse.mul(prefixes[index]);
        product_inverse = product_inverse.mul(values[index]);
    }
    Ok(inverses)
}

fn frobenius_exponent(power: u8) -> [u32; 16] {
    let mut limbs = [0_u32; 16];
    limbs[0] = 1;
    for _ in 0..power {
        let mut carry = 0_u64;
        for limb in &mut limbs {
            let wide = u64::from(*limb) * u64::from(M31_MODULUS) + carry;
            *limb = wide as u32;
            carry = wide >> 32;
        }
        debug_assert_eq!(carry, 0);
    }
    limbs
}

macro_rules! impl_field_operators {
    ($field:ty) => {
        impl Add for $field {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                <$field>::add(self, rhs)
            }
        }

        impl Sub for $field {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self::Output {
                <$field>::sub(self, rhs)
            }
        }

        impl Mul for $field {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self::Output {
                <$field>::mul(self, rhs)
            }
        }

        impl Neg for $field {
            type Output = Self;

            fn neg(self) -> Self::Output {
                <$field>::neg(self)
            }
        }
    };
}

impl_field_operators!(M31);
impl_field_operators!(Fp2);
impl_field_operators!(Fp4);
impl_field_operators!(Fp8);
impl_field_operators!(Fp16);

#[cfg(test)]
mod tests {
    use super::*;

    const LEFT: [u32; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const RIGHT: [u32; 16] = [
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ];
    const PRODUCT_HEX: &str = "7ffff238000016f97ffff7f40000123d7ffff49a0000151b7ffffb6600000f3f7ffff5310000128a7ffffaa500000e0e7ffff8a300000f2c7fffff07000009b0";
    const INVERSE_HEX: &str = "150654175063548e1e426d9d21cbdc9d764dee9c490c2b3d145238e02757f8291b4326e60b2b1e7b3589a30a3fcae4b543674b45156d77135d087efb1364724c";

    #[test]
    fn m31_boundary_arithmetic_is_canonical() {
        let maximum = M31::from_canonical(M31_MODULUS - 1).unwrap();
        assert_eq!((maximum + M31::ONE).as_u32(), 0);
        assert_eq!((M31::ZERO - M31::ONE).as_u32(), M31_MODULUS - 1);
        assert_eq!((-M31::ZERO).as_u32(), 0);
        assert_eq!((-M31::ONE).as_u32(), M31_MODULUS - 1);
        assert_eq!((maximum * maximum).as_u32(), 1);
        assert_eq!(
            M31::from_canonical(M31_MODULUS),
            Err(FieldError::NonCanonicalCoefficient {
                index: 0,
                value: M31_MODULUS
            })
        );
    }

    #[test]
    fn frozen_basis_and_nonresidues_are_exact() {
        assert_eq!(
            FP16_BASIS,
            [
                "1", "i", "u", "iu", "v", "iv", "uv", "iuv", "w", "iw", "uw", "iuw", "vw", "ivw",
                "uvw", "iuvw"
            ]
        );
        let i = Fp2::new(M31::ZERO, M31::ONE);
        assert_eq!(i.square(), Fp2::new(M31::NEGATIVE_ONE, M31::ZERO));
        assert_eq!(Fp4::U.square(), Fp4::new(Fp2::TWO_PLUS_I, Fp2::ZERO));
        assert_eq!(Fp8::V.square(), Fp8::new(Fp4::U, Fp4::ZERO));
        let w = Fp16::new(Fp8::ZERO, Fp8::ONE);
        assert_eq!(w.square(), Fp16::new(Fp8::V, Fp8::ZERO));
    }

    #[test]
    fn specialized_nonresidue_multipliers_match_generic_products() {
        let fp2 = Fp2::new(M31(17), M31(29));
        assert_eq!(fp2.mul_by_two_plus_i(), fp2.mul(Fp2::TWO_PLUS_I));

        let fp4 = Fp4::new(fp2, Fp2::new(M31(31), M31(43)));
        assert_eq!(fp4.mul_by_u(), fp4.mul(Fp4::U));

        let fp8 = Fp8::new(
            fp4,
            Fp4::new(Fp2::new(M31(47), M31(59)), Fp2::new(M31(61), M31(71))),
        );
        assert_eq!(fp8.mul_by_v(), fp8.mul(Fp8::V));
    }

    #[test]
    fn python_field_kats_match() {
        let left = Fp16::from_coefficients(LEFT).unwrap();
        let right = Fp16::from_coefficients(RIGHT).unwrap();
        assert_eq!((left * right).encode(), decode_hex(PRODUCT_HEX));
        let inverse = left.inverse().unwrap();
        assert_eq!(inverse.encode(), decode_hex(INVERSE_HEX));
        assert_eq!(left * inverse, Fp16::ONE);
    }

    #[test]
    fn encode_decode_is_exact_and_rejects_malformed_values() {
        let value = Fp16::from_coefficients(RIGHT).unwrap();
        assert_eq!(Fp16::decode(&value.encode()), Ok(value));
        assert_eq!(
            Fp16::decode(&[0_u8; 63]),
            Err(DecodeError::Length { actual: 63 })
        );
        assert_eq!(
            Fp16::decode(&[0_u8; 65]),
            Err(DecodeError::Length { actual: 65 })
        );

        let mut modulus = [0_u8; 64];
        modulus[..4].copy_from_slice(&M31_MODULUS.to_be_bytes());
        assert_eq!(
            Fp16::decode(&modulus),
            Err(DecodeError::NonCanonicalCoefficient {
                index: 0,
                value: M31_MODULUS
            })
        );
        let mut high_word = [0_u8; 64];
        high_word[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Fp16::decode(&high_word),
            Err(DecodeError::NonCanonicalCoefficient { index: 0, .. })
        ));
    }

    #[test]
    fn algebraic_properties_hold_for_deterministic_corpus() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..64 {
            let a = random_fp16(&mut state);
            let b = random_fp16(&mut state);
            let c = random_fp16(&mut state);
            assert_eq!((a + b) + c, a + (b + c));
            assert_eq!(a * (b + c), (a * b) + (a * c));
            assert_eq!(a.square(), a * a);
            assert_eq!(a - a, Fp16::ZERO);
            assert_eq!(a.conjugate().conjugate(), a);
            if !a.is_zero() {
                assert_eq!(a * a.inverse().unwrap(), Fp16::ONE);
            }
        }
    }

    #[test]
    fn mul_by_m31_matches_generic_fp16_product_for_random_vectors() {
        let mut state = 0xd1b5_4a32_d192_ed03_u64;
        let edge_scalars = [M31::ZERO, M31::ONE, M31(M31_MODULUS - 1)];
        for scalar in edge_scalars {
            let value = random_fp16(&mut state);
            assert_eq!(value.mul_by_m31(scalar), value * Fp16::from_m31(scalar));
        }
        for _ in 0..4_096 {
            let value = random_fp16(&mut state);
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let scalar = M31((state as u32) % M31_MODULUS);
            assert_eq!(value.mul_by_m31(scalar), value * Fp16::from_m31(scalar));
        }
    }

    #[test]
    fn frobenius_matches_exponentiation_and_independent_vectors() {
        let value = Fp16::from_coefficients(LEFT).unwrap();
        assert_eq!(value.frobenius(0).unwrap(), value);
        assert_eq!(value.frobenius(1).unwrap(), value.pow_u32(M31_MODULUS));
        let vectors = [
            (
                1,
                "000000007ffffffe0a1aa3e00143547c76da10091f16c32d2838dab63e29520245a6855749d58418440966cc206e545746fe62c02391fb2c221584677ef12784",
            ),
            (
                2,
                "00000000000000017ffffffd7ffffffc7ffffffa00000004000000077ffffff97fff7fff00088000000080007ff57fff7ff37fff7fff7fff000e800000008000",
            ),
            (
                4,
                "000000000000000100000002000000037ffffffb7ffffffa7ffffff97ffffff87ffffff6000000087ffffff40000000a0000000d7ffffff30000000f7ffffff1",
            ),
            (
                8,
                "00000000000000010000000200000003000000040000000500000006000000077ffffff77ffffff67ffffff57ffffff47ffffff37ffffff27ffffff17ffffff0",
            ),
            (
                15,
                "000000007ffffffe75e55c1f7ebcab831f16c32d0925eff641d6adfd2838dab604b80f7c7f60842e226e1b88093aa39b4c35dc935109956f2e71232455f62106",
            ),
        ];
        for (power, expected) in vectors {
            assert_eq!(
                value.frobenius(power).unwrap().encode(),
                decode_hex(expected)
            );
        }
        assert_eq!(
            value.frobenius(16),
            Err(FieldError::FrobeniusPowerOutOfRange(16))
        );
    }

    #[test]
    fn top_conjugation_trace_norm_and_generator_polynomial_are_exact() {
        let value = Fp16::from_coefficients(RIGHT).unwrap();
        assert_eq!(value.conjugate(), value.frobenius(8).unwrap());
        assert_eq!(
            value + value.conjugate(),
            Fp16::new(value.trace_to_fp8(), Fp8::ZERO)
        );
        assert_eq!(
            value * value.conjugate(),
            Fp16::new(value.norm_to_fp8(), Fp8::ZERO)
        );

        let w = Fp16::new(Fp8::ZERO, Fp8::ONE);
        let four =
            Fp16::from_coefficients([4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let five =
            Fp16::from_coefficients([5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(w.pow_u32(16) - four * w.pow_u32(8) + five, Fp16::ZERO);
    }

    #[test]
    fn zero_inverse_is_rejected_at_every_level() {
        assert_eq!(M31::ZERO.inverse(), Err(FieldError::ZeroInverse));
        assert_eq!(Fp2::ZERO.inverse(), Err(FieldError::ZeroInverse));
        assert_eq!(Fp4::ZERO.inverse(), Err(FieldError::ZeroInverse));
        assert_eq!(Fp8::ZERO.inverse(), Err(FieldError::ZeroInverse));
        assert_eq!(Fp16::ZERO.inverse(), Err(FieldError::ZeroInverse));
    }

    #[test]
    fn fp16_batch_inverse_matches_individual_inversion_and_rejects_zero() {
        let values = (1_u32..=17)
            .map(|value| Fp16::from_m31(M31::from_canonical(value * value + 3).unwrap()))
            .collect::<Vec<_>>();
        let batched = batch_inverse_fp16(&values).unwrap();
        assert_eq!(
            batched,
            values
                .iter()
                .copied()
                .map(|value| value.inverse().unwrap())
                .collect::<Vec<_>>()
        );
        let mut with_zero = values;
        with_zero[8] = Fp16::ZERO;
        assert_eq!(batch_inverse_fp16(&with_zero), Err(FieldError::ZeroInverse));
    }

    fn random_fp16(state: &mut u64) -> Fp16 {
        let mut coefficients = [0_u32; 16];
        for coefficient in &mut coefficients {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *coefficient = (*state as u32) % M31_MODULUS;
        }
        Fp16::from_coefficients(coefficients).unwrap()
    }

    fn decode_hex(value: &str) -> [u8; 64] {
        assert_eq!(value.len(), 128);
        let bytes = value.as_bytes();
        let mut decoded = [0_u8; 64];
        for (index, output) in decoded.iter_mut().enumerate() {
            *output = (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]);
        }
        decoded
    }

    const fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }
}
