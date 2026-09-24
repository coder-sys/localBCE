//! Test-only Profile 11 source host.
//!
//! Its stdin is exactly the public 3,596-byte V2 request. The fixed synthetic,
//! volatile SourceTransactionAuthority owns one consume, one test witness/seed,
//! and the opaque launch/receipt lifecycle; ML-DSA secret key and randomizer stay
//! inside this process. Successful stdout is exactly one complete source-auth
//! frame; every error is silent and bounded by exit code 1.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

use zeroize::Zeroizing;
use zkboo::{
    screening::{LOWER, SEED_BYTES, ScreeningSeed, VALUE_COUNT},
    source_appliance::{
        ExternalMuSigner, ExternalMuSignerError, SOURCE_APPLIANCE_REQUEST_BYTES,
        SOURCE_AUTH_FRAME_BYTES, SOURCE_AUTH_MU_BYTES, SOURCE_AUTH_PUBLIC_KEY_BYTES,
        SOURCE_AUTH_SIGNATURE_BYTES, SourceAppliance, SourceAuthRequest, SourceLaunchReference,
        SourceReceiptReference, SourceTransactionAuthority, SourceTransactionAuthorityError,
        SourceTransactionLaunch, SourceTransactionLifecycleError, SourceTransactionStatus,
        SourceWitness,
    },
};

const PROFILE11_TEST_ONLY: bool = true;
const KEY_SEED_BYTES: usize = 32;
const SECRET_KEY_BYTES: usize = 4_896;
const RANDOMIZER_BYTES: usize = 32;
const SIGN_OK: i32 = 0;
const KEY_EPOCH: u64 = 0x0102_0304_0506_0708;
const TEST_LAUNCH_REFERENCE_BYTES: [u8; 32] = [0xa7; 32];
const TEST_RECEIPT_REFERENCE_BYTES: [u8; 32] = [0xc3; 32];

fn test_launch_reference() -> SourceLaunchReference {
    SourceLaunchReference::from_bytes(TEST_LAUNCH_REFERENCE_BYTES)
}

fn test_receipt_reference() -> SourceReceiptReference {
    SourceReceiptReference::from_bytes(TEST_RECEIPT_REFERENCE_BYTES)
}

unsafe extern "C" {
    fn blind_source_auth_mldsa87_v1_keypair_from_seed(
        public_key: *mut u8,
        public_key_len: usize,
        secret_key: *mut u8,
        secret_key_len: usize,
        seed: *const u8,
        seed_len: usize,
    ) -> i32;
    fn blind_source_auth_mldsa87_v1_sign_hedged_extmu(
        signature: *mut u8,
        signature_len: usize,
        secret_key: *const u8,
        secret_key_len: usize,
        mu: *const u8,
        mu_len: usize,
        randomizer: *const u8,
        randomizer_len: usize,
    ) -> i32;
}

// This authority is deliberately synthetic, volatile, non-durable, and non-qualified. It exists
// only to exercise the source-owned transaction seam; a deployed authority must provide durable
// source-record burn, real entropy, and qualified custody behind the same API.
struct FixedAuthority {
    status: SourceTransactionStatus,
    request_bytes: Option<Zeroizing<Vec<u8>>>,
    bound_mu: Option<Zeroizing<[u8; SOURCE_AUTH_MU_BYTES]>>,
}

impl FixedAuthority {
    fn new() -> Self {
        Self {
            status: SourceTransactionStatus::Unknown,
            request_bytes: None,
            bound_mu: None,
        }
    }

    fn request_matches(&self, request: &SourceAuthRequest) -> bool {
        let bytes = request.to_bytes();
        self.request_bytes
            .as_ref()
            .is_some_and(|stored| stored.as_slice() == bytes.as_slice())
    }
}

impl SourceTransactionAuthority for FixedAuthority {
    fn consume(
        &mut self,
        request: &SourceAuthRequest,
    ) -> Result<SourceTransactionLaunch, SourceTransactionAuthorityError> {
        if request.expected_epoch() != KEY_EPOCH {
            return Err(SourceTransactionAuthorityError::GuaranteedNoCommit);
        }
        if self.status != SourceTransactionStatus::Unknown {
            return Err(SourceTransactionAuthorityError::ConsumedOrAmbiguous);
        }
        let request_bytes = request.to_bytes();
        self.request_bytes = Some(Zeroizing::new(request_bytes.as_slice().to_vec()));
        self.status = SourceTransactionStatus::ConsumedLaunching;
        Ok(SourceTransactionLaunch::new(
            test_launch_reference(),
            SourceWitness::from_array([LOWER; VALUE_COUNT]),
            ScreeningSeed::from_bytes([0x41; SEED_BYTES]),
        ))
    }

    fn mark_launch_terminal(
        &mut self,
        launch_reference: &SourceLaunchReference,
    ) -> Result<(), SourceTransactionLifecycleError> {
        if launch_reference != &test_launch_reference() {
            return Err(SourceTransactionLifecycleError::UnknownLaunch);
        }
        match self.status {
            SourceTransactionStatus::ConsumedLaunching => {
                self.status = SourceTransactionStatus::TerminalFailed;
                Ok(())
            }
            SourceTransactionStatus::TerminalFailed => Ok(()),
            SourceTransactionStatus::SignedFrameBound { .. } => {
                Err(SourceTransactionLifecycleError::AlreadyBound)
            }
            SourceTransactionStatus::Unknown | SourceTransactionStatus::NoCommit => {
                Err(SourceTransactionLifecycleError::UnknownLaunch)
            }
        }
    }

    fn bind_signed_frame(
        &mut self,
        launch_reference: &SourceLaunchReference,
        mu: &[u8; SOURCE_AUTH_MU_BYTES],
    ) -> Result<SourceReceiptReference, SourceTransactionLifecycleError> {
        if launch_reference != &test_launch_reference() {
            return Err(SourceTransactionLifecycleError::UnknownLaunch);
        }
        match self.status {
            SourceTransactionStatus::ConsumedLaunching => {
                self.bound_mu = Some(Zeroizing::new(*mu));
                let receipt_reference = test_receipt_reference();
                self.status = SourceTransactionStatus::SignedFrameBound { receipt_reference };
                Ok(receipt_reference)
            }
            SourceTransactionStatus::TerminalFailed => {
                Err(SourceTransactionLifecycleError::AlreadyTerminal)
            }
            SourceTransactionStatus::SignedFrameBound { .. } => {
                Err(SourceTransactionLifecycleError::AlreadyBound)
            }
            SourceTransactionStatus::Unknown | SourceTransactionStatus::NoCommit => {
                Err(SourceTransactionLifecycleError::InvalidBinding)
            }
        }
    }

    fn status_for_request(&self, request: &SourceAuthRequest) -> SourceTransactionStatus {
        if self.request_matches(request) {
            self.status
        } else {
            SourceTransactionStatus::Unknown
        }
    }

    fn status_for_launch(
        &self,
        launch_reference: &SourceLaunchReference,
    ) -> SourceTransactionStatus {
        if launch_reference == &test_launch_reference() {
            self.status
        } else {
            SourceTransactionStatus::Unknown
        }
    }
}

struct FixedSigner {
    secret_key: Zeroizing<[u8; SECRET_KEY_BYTES]>,
    randomizer: Zeroizing<[u8; RANDOMIZER_BYTES]>,
}

impl FixedSigner {
    fn new() -> Result<(Self, [u8; SOURCE_AUTH_PUBLIC_KEY_BYTES]), ()> {
        let key_seed = [0x27; KEY_SEED_BYTES];
        let mut public_key = [0u8; SOURCE_AUTH_PUBLIC_KEY_BYTES];
        let mut secret_key = Zeroizing::new([0u8; SECRET_KEY_BYTES]);
        let status = unsafe {
            blind_source_auth_mldsa87_v1_keypair_from_seed(
                public_key.as_mut_ptr(),
                public_key.len(),
                secret_key.as_mut_ptr(),
                secret_key.len(),
                key_seed.as_ptr(),
                key_seed.len(),
            )
        };
        if status != SIGN_OK {
            return Err(());
        }
        Ok((
            Self {
                secret_key,
                randomizer: Zeroizing::new([0x5a; RANDOMIZER_BYTES]),
            },
            public_key,
        ))
    }
}

impl ExternalMuSigner for FixedSigner {
    fn sign(
        &mut self,
        key_epoch: u64,
        mu: &[u8; 64],
        signature: &mut [u8; SOURCE_AUTH_SIGNATURE_BYTES],
    ) -> Result<(), ExternalMuSignerError> {
        if key_epoch != KEY_EPOCH {
            signature.fill(0);
            return Err(ExternalMuSignerError::Failed);
        }
        let status = unsafe {
            blind_source_auth_mldsa87_v1_sign_hedged_extmu(
                signature.as_mut_ptr(),
                signature.len(),
                self.secret_key.as_ptr(),
                self.secret_key.len(),
                mu.as_ptr(),
                mu.len(),
                self.randomizer.as_ptr(),
                self.randomizer.len(),
            )
        };
        if status == SIGN_OK {
            Ok(())
        } else {
            signature.fill(0);
            Err(ExternalMuSignerError::Failed)
        }
    }
}

fn run_once() -> Result<(), ()> {
    if !PROFILE11_TEST_ONLY {
        return Err(());
    }
    let mut request = Zeroizing::new([0u8; SOURCE_APPLIANCE_REQUEST_BYTES]);
    io::stdin().read_exact(&mut request[..]).map_err(|_| ())?;
    let mut trailing = [0u8; 1];
    if io::stdin().read(&mut trailing).map_err(|_| ())? != 0 {
        return Err(());
    }
    let (signer, public_key) = FixedSigner::new()?;
    let mut appliance = SourceAppliance::new(KEY_EPOCH, public_key, FixedAuthority::new(), signer)
        .map_err(|_| ())?;
    let result = appliance
        .process_request_bytes(&request[..])
        .map_err(|_| ())?;
    let (frame, _launch_reference, _receipt_reference) = result.into_parts();
    if frame.len() != SOURCE_AUTH_FRAME_BYTES {
        return Err(());
    }
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(frame.as_bytes()).map_err(|_| ())?;
    stdout.flush().map_err(|_| ())
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let result = catch_unwind(AssertUnwindSafe(run_once));
    let code = match result {
        Ok(Ok(())) => 0,
        Ok(Err(())) | Err(_) => 1,
    };
    if code != 0 {
        std::process::exit(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_public_key_shape_is_stable() {
        let (_signer, public_key) = FixedSigner::new().expect("pinned C ML-DSA keypair");
        assert_eq!(public_key.len(), SOURCE_AUTH_PUBLIC_KEY_BYTES);
    }

    fn request() -> SourceAuthRequest {
        let root = [0xa5; 64];
        let mut ordered_refs = [0u8; 3_200];
        for index in 0..VALUE_COUNT {
            let start = index * 32;
            ordered_refs[start..start + 32].fill((index + 1) as u8);
        }
        let statement = zkboo::screening::Statement::new(&[0x3c; 64], &root, 1, 2)
            .expect("canonical statement");
        SourceAuthRequest::new(KEY_EPOCH, root, ordered_refs, statement)
            .expect("canonical source request")
    }

    #[test]
    fn synthetic_authority_consumes_once_and_reports_opaque_lifecycle() {
        assert!(PROFILE11_TEST_ONLY);
        let request = request();
        let mut authority = FixedAuthority::new();
        let launch = authority.consume(&request).expect("one synthetic consume");
        assert_eq!(launch.launch_reference(), test_launch_reference());
        assert_eq!(
            authority.status_for_request(&request),
            SourceTransactionStatus::ConsumedLaunching
        );
        assert_eq!(
            authority.status_for_launch(&test_launch_reference()),
            SourceTransactionStatus::ConsumedLaunching
        );
        assert!(matches!(
            authority.consume(&request),
            Err(SourceTransactionAuthorityError::ConsumedOrAmbiguous)
        ));
        assert_eq!(
            authority.mark_launch_terminal(&test_launch_reference()),
            Ok(())
        );
        assert_eq!(
            authority.status_for_request(&request),
            SourceTransactionStatus::TerminalFailed
        );
        assert!(matches!(
            authority.consume(&request),
            Err(SourceTransactionAuthorityError::ConsumedOrAmbiguous)
        ));
    }

    #[test]
    fn synthetic_authority_binds_exact_mu_once_and_never_retries() {
        let request = request();
        let mut authority = FixedAuthority::new();
        let launch = authority.consume(&request).expect("one synthetic consume");
        let mu = [0x5d; SOURCE_AUTH_MU_BYTES];
        let receipt = authority
            .bind_signed_frame(&launch.launch_reference(), &mu)
            .expect("exact Mu binding");
        assert_eq!(receipt, test_receipt_reference());
        assert_eq!(authority.bound_mu.as_deref(), Some(&mu));
        assert_eq!(
            authority.status_for_launch(&test_launch_reference()),
            SourceTransactionStatus::SignedFrameBound {
                receipt_reference: test_receipt_reference()
            }
        );
        assert_eq!(
            authority.bind_signed_frame(&test_launch_reference(), &mu),
            Err(SourceTransactionLifecycleError::AlreadyBound)
        );
        assert_eq!(
            authority.mark_launch_terminal(&test_launch_reference()),
            Err(SourceTransactionLifecycleError::AlreadyBound)
        );
        assert!(matches!(
            authority.consume(&request),
            Err(SourceTransactionAuthorityError::ConsumedOrAmbiguous)
        ));
    }
}
