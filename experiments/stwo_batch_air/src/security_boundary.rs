//! Fail-closed boundary for this validity-only S-two prototype.
//!
//! Entropy remains disconnected from proof masks. Exact masking, sampling,
//! domains, and budgets remain blocked on Z03-Z11 cryptographic review.

use std::fmt;
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

pub const SECURITY_MODE_VALIDITY_ONLY: &str = "VALIDITY_ONLY";
pub const WITNESS_HIDING_UNAVAILABLE: &str = "WITNESS_HIDING_UNAVAILABLE";
pub const ENTROPY_FAILURE: &str = "ENTROPY_FAILURE";
pub const OS_ENTROPY_PROVIDER_WIRED: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofSecurityRequirement {
    ValidityOnly,
    WitnessHidingRequired,
}

impl ProofSecurityRequirement {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "validity-only" => Ok(Self::ValidityOnly),
            "witness-hiding-required" => Ok(Self::WitnessHidingRequired),
            _ => Err("--security-mode must be validity-only or \
                 witness-hiding-required"
                .to_string()),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidityOnly => "validity-only",
            Self::WitnessHidingRequired => "witness-hiding-required",
        }
    }
}

/// Call before allocating claims, witnesses, or trace columns.
pub fn enforce_before_trace(requirement: ProofSecurityRequirement) -> Result<(), String> {
    match requirement {
        ProofSecurityRequirement::ValidityOnly => Ok(()),
        ProofSecurityRequirement::WitnessHidingRequired => {
            Err(WITNESS_HIDING_UNAVAILABLE.to_string())
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EntropyFailure;

impl fmt::Debug for EntropyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(ENTROPY_FAILURE)
    }
}

impl fmt::Display for EntropyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(ENTROPY_FAILURE)
    }
}

impl std::error::Error for EntropyFailure {}

/// Owned secret bytes with no production content accessor.
pub struct SecretEntropy {
    bytes: Vec<u8>,
}

impl SecretEntropy {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn zeroize(&mut self) {
        for byte in &mut self.bytes {
            // SAFETY: byte exclusively references an initialized byte in
            // this owned allocation.
            unsafe { ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }

    #[cfg(test)]
    fn expose_for_test(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SecretEntropy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretEntropy")
            .field("byte_count", &self.bytes.len())
            .field("contents", &"REDACTED")
            .finish()
    }
}

impl Drop for SecretEntropy {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Production-facing fail-closed interface.
///
/// No OS provider is wired in R25. This function therefore never returns
/// secret bytes and cannot fall back to caller, environment, file, or
/// deterministic entropy.
pub fn acquire_os_entropy(byte_count: usize) -> Result<SecretEntropy, EntropyFailure> {
    if byte_count == 0 || !OS_ENTROPY_PROVIDER_WIRED {
        return Err(EntropyFailure);
    }
    Err(EntropyFailure)
}

#[cfg(test)]
fn acquire_entropy_with(
    byte_count: usize,
    mut fill: impl FnMut(&mut [u8]) -> Result<usize, EntropyFailure>,
) -> Result<SecretEntropy, EntropyFailure> {
    if byte_count == 0 {
        return Err(EntropyFailure);
    }
    let mut secret = SecretEntropy {
        bytes: vec![0; byte_count],
    };
    match fill(&mut secret.bytes) {
        Ok(written) if written == byte_count => Ok(secret),
        Ok(_) | Err(_) => {
            secret.zeroize();
            Err(EntropyFailure)
        }
    }
}

#[cfg(test)]
fn deterministic_test_filler(
    mut next: u8,
) -> impl FnMut(&mut [u8]) -> Result<usize, EntropyFailure> {
    move |destination| {
        for byte in destination.iter_mut() {
            *byte = next;
            next = next.wrapping_add(1);
        }
        Ok(destination.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_parsing_is_unambiguous() {
        assert_eq!(
            ProofSecurityRequirement::parse("validity-only"),
            Ok(ProofSecurityRequirement::ValidityOnly)
        );
        assert_eq!(
            ProofSecurityRequirement::parse("witness-hiding-required"),
            Ok(ProofSecurityRequirement::WitnessHidingRequired)
        );
        assert!(ProofSecurityRequirement::parse("private").is_err());
    }

    #[test]
    fn validity_only_is_explicit_and_hiding_fails_closed() {
        assert_eq!(SECURITY_MODE_VALIDITY_ONLY, "VALIDITY_ONLY");
        assert_eq!(
            enforce_before_trace(ProofSecurityRequirement::ValidityOnly),
            Ok(())
        );
        assert_eq!(
            enforce_before_trace(ProofSecurityRequirement::WitnessHidingRequired),
            Err(WITNESS_HIDING_UNAVAILABLE.to_string())
        );
    }

    #[test]
    fn production_entropy_provider_is_unwired_and_content_free() {
        assert!(!std::hint::black_box(OS_ENTROPY_PROVIDER_WIRED));
        assert_eq!(acquire_os_entropy(64).unwrap_err(), EntropyFailure);
        assert_eq!(EntropyFailure.to_string(), ENTROPY_FAILURE);
        assert_eq!(format!("{EntropyFailure:?}"), ENTROPY_FAILURE);
    }

    #[test]
    fn test_only_fill_zeroizes_and_short_fill_fails() {
        let mut secret = acquire_entropy_with(4, deterministic_test_filler(7)).unwrap();
        assert_eq!(secret.expose_for_test(), &[7, 8, 9, 10]);
        assert_eq!(secret.len(), 4);
        assert!(!secret.is_empty());
        secret.zeroize();
        assert!(secret.expose_for_test().iter().all(|byte| *byte == 0));
        let error = acquire_entropy_with(64, |_| Ok(1)).unwrap_err();
        assert_eq!(error, EntropyFailure);
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let secret = acquire_entropy_with(2, deterministic_test_filler(0xa5)).unwrap();
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("165"));
    }
}
