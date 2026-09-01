//! Test-only Profile 11 source host.
//!
//! Its stdin is exactly the public 3,596-byte V2 request. The fixed synthetic
//! authority, entropy, ML-DSA secret key and randomizer stay inside this
//! process. Successful stdout is exactly one complete source-auth frame;
//! every error is silent and bounded by exit code 1.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::io::{self, Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

use zeroize::Zeroizing;
use zkboo::{
    screening::{LOWER, SEED_BYTES, ScreeningSeed, VALUE_COUNT},
    source_appliance::{
        EntropyProvider, EntropyProviderError, ExternalMuSigner, ExternalMuSignerError,
        SOURCE_AUTH_FRAME_BYTES, SOURCE_AUTH_PUBLIC_KEY_BYTES, SOURCE_AUTH_SIGNATURE_BYTES,
        SOURCE_APPLIANCE_REQUEST_BYTES, SourceAppliance, SourceAuthRequest,
        SourceItemAuthority, SourceItemAuthorityError, SourceWitness,
    },
};

const PROFILE11_TEST_ONLY: bool = true;
const KEY_SEED_BYTES: usize = 32;
const SECRET_KEY_BYTES: usize = 4_896;
const RANDOMIZER_BYTES: usize = 32;
const SIGN_OK: i32 = 0;
const KEY_EPOCH: u64 = 0x0102_0304_0506_0708;

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

struct FixedAuthority {
    consumed: bool,
}

impl SourceItemAuthority for FixedAuthority {
    fn consume(
        &mut self,
        _request: &SourceAuthRequest,
    ) -> Result<SourceWitness, SourceItemAuthorityError> {
        if self.consumed {
            return Err(SourceItemAuthorityError::ConsumedOrAmbiguous);
        }
        self.consumed = true;
        Ok(SourceWitness::from_array([LOWER; VALUE_COUNT]))
    }
}

struct FixedEntropy {
    consumed: bool,
}

impl EntropyProvider for FixedEntropy {
    fn fill_seed(&mut self) -> Result<ScreeningSeed, EntropyProviderError> {
        if self.consumed {
            return Err(EntropyProviderError::Failed);
        }
        self.consumed = true;
        Ok(ScreeningSeed::from_bytes([0x41; SEED_BYTES]))
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
        _key_epoch: u64,
        mu: &[u8; 64],
        signature: &mut [u8; SOURCE_AUTH_SIGNATURE_BYTES],
    ) -> Result<(), ExternalMuSignerError> {
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
    let mut appliance = SourceAppliance::new(
        KEY_EPOCH,
        public_key,
        FixedAuthority { consumed: false },
        FixedEntropy { consumed: false },
        signer,
    )
    .map_err(|_| ())?;
    let frame = appliance.process_request_bytes(&request[..]).map_err(|_| ())?;
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
        println!("{}", public_key.iter().map(|byte| format!("{byte:02X}")).collect::<String>());
    }
}
