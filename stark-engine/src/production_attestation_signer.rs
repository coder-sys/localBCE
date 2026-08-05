use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

use secp256k1::{
    Message, Secp256k1,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use wait_timeout::ChildExt;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationSignRequestV1 {
    pub schema_version: String,
    pub request_id: String,
    pub digest: String,
    pub chain_id: u64,
    pub verifier_address: String,
    pub registry_address: String,
    pub public_inputs_hash: String,
    pub winterfell_proof_commitment: String,
    pub policy_manifest_hash: String,
    pub claim_amount: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestationSignResponseV1 {
    pub schema_version: String,
    pub request_id: String,
    pub signer_backend: String,
    pub key_id: String,
    pub attestor_address: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedExternalSignature {
    pub signer_backend: String,
    pub key_id: String,
    pub attestor_address: String,
    pub signature: [u8; 65],
}

#[derive(Clone, Debug)]
pub struct ExternalCommandSigner {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub timeout: Duration,
    pub expected_attestor: String,
    pub allowed_key_ids: BTreeSet<String>,
}

#[derive(Serialize)]
struct AttestationSignRequestPreimage<'a> {
    schema_version: &'a str,
    digest: &'a str,
    chain_id: u64,
    verifier_address: &'a str,
    registry_address: &'a str,
    public_inputs_hash: &'a str,
    winterfell_proof_commitment: &'a str,
    policy_manifest_hash: &'a str,
    claim_amount: u64,
}

impl AttestationSignRequestV1 {
    pub const SCHEMA_VERSION: &'static str = "stark-attestation-sign-request-v1";

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        digest: &str,
        chain_id: u64,
        verifier_address: &str,
        registry_address: &str,
        public_inputs_hash: &str,
        winterfell_proof_commitment: &str,
        policy_manifest_hash: &str,
        claim_amount: u64,
    ) -> Result<Self, Vec<String>> {
        let preimage = AttestationSignRequestPreimage {
            schema_version: Self::SCHEMA_VERSION,
            digest,
            chain_id,
            verifier_address,
            registry_address,
            public_inputs_hash,
            winterfell_proof_commitment,
            policy_manifest_hash,
            claim_amount,
        };
        let canonical = serde_json::to_vec(&preimage)
            .map_err(|error| vec![format!("could not serialize signing request: {error}")])?;
        let request_id = encode_hex(Sha256::digest(canonical));
        let request = Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            request_id,
            digest: normalize_hex(digest),
            chain_id,
            verifier_address: normalize_hex(verifier_address),
            registry_address: normalize_hex(registry_address),
            public_inputs_hash: normalize_hex(public_inputs_hash),
            winterfell_proof_commitment: normalize_hex(winterfell_proof_commitment),
            policy_manifest_hash: normalize_hex(policy_manifest_hash),
            claim_amount,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.schema_version != Self::SCHEMA_VERSION {
            errors.push(format!("schema_version must be {}", Self::SCHEMA_VERSION));
        }
        if self.chain_id == 0 {
            errors.push("chain_id must be nonzero".to_string());
        }
        validate_hex_len(&self.request_id, 32, "request_id", &mut errors);
        validate_hex_len(&self.digest, 32, "digest", &mut errors);
        validate_hex_len(&self.verifier_address, 20, "verifier_address", &mut errors);
        validate_hex_len(&self.registry_address, 20, "registry_address", &mut errors);
        validate_hex_len(
            &self.public_inputs_hash,
            32,
            "public_inputs_hash",
            &mut errors,
        );
        validate_hex_len(
            &self.winterfell_proof_commitment,
            32,
            "winterfell_proof_commitment",
            &mut errors,
        );
        validate_hex_len(
            &self.policy_manifest_hash,
            32,
            "policy_manifest_hash",
            &mut errors,
        );
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl AttestationSignResponseV1 {
    pub const SCHEMA_VERSION: &'static str = "stark-attestation-sign-response-v1";
}

impl ExternalCommandSigner {
    pub fn sign(
        &self,
        request: &AttestationSignRequestV1,
    ) -> Result<ValidatedExternalSignature, Vec<String>> {
        request.validate()?;
        if self.program.as_os_str().is_empty() {
            return Err(vec![
                "external signer program must not be empty".to_string(),
            ]);
        }
        if self.timeout.is_zero() {
            return Err(vec!["external signer timeout must be nonzero".to_string()]);
        }
        if self.allowed_key_ids.is_empty() {
            return Err(vec![
                "external signer allowed_key_ids must not be empty".to_string(),
            ]);
        }

        let request_json = serde_json::to_vec(request)
            .map_err(|error| vec![format!("could not serialize signing request: {error}")])?;
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                vec![format!(
                    "could not start external attestation signer: {error}"
                )]
            })?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| vec!["external signer stdin was unavailable".to_string()])?;
        stdin
            .write_all(&request_json)
            .and_then(|_| stdin.write_all(b"\n"))
            .map_err(|error| vec![format!("could not write external signer request: {error}")])?;
        drop(stdin);

        let status = match child.wait_timeout(self.timeout) {
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(vec![format!(
                    "external attestation signer timed out after {} ms",
                    self.timeout.as_millis()
                )]);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(vec![format!("could not wait for external signer: {error}")]);
            }
        };

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut value) = child.stdout.take() {
            value
                .read_to_end(&mut stdout)
                .map_err(|error| vec![format!("could not read external signer stdout: {error}")])?;
        }
        if let Some(mut value) = child.stderr.take() {
            value
                .read_to_end(&mut stderr)
                .map_err(|error| vec![format!("could not read external signer stderr: {error}")])?;
        }
        if !status.success() {
            return Err(vec![format!(
                "external attestation signer failed with status {:?}: {}",
                status.code(),
                String::from_utf8_lossy(&stderr).trim()
            )]);
        }
        let response: AttestationSignResponseV1 = serde_json::from_slice(&stdout)
            .map_err(|error| vec![format!("external signer returned invalid JSON: {error}")])?;
        validate_response(
            request,
            &response,
            &self.expected_attestor,
            &self.allowed_key_ids,
        )
    }
}

pub fn validate_response(
    request: &AttestationSignRequestV1,
    response: &AttestationSignResponseV1,
    expected_attestor: &str,
    allowed_key_ids: &BTreeSet<String>,
) -> Result<ValidatedExternalSignature, Vec<String>> {
    let mut errors = Vec::new();
    if response.schema_version != AttestationSignResponseV1::SCHEMA_VERSION {
        errors.push(format!(
            "response schema_version must be {}",
            AttestationSignResponseV1::SCHEMA_VERSION
        ));
    }
    if response.request_id != request.request_id {
        errors.push("external signer response request_id does not match request".to_string());
    }
    if response.signer_backend.trim().is_empty() {
        errors.push("external signer backend must not be empty".to_string());
    }
    if !allowed_key_ids.contains(&response.key_id) {
        errors.push("external signer key_id is not allowlisted".to_string());
    }
    if normalize_hex(&response.attestor_address) != normalize_hex(expected_attestor) {
        errors.push(
            "external signer attestor_address does not match configured attestor".to_string(),
        );
    }

    let signature = match decode_fixed::<65>(&response.signature_hex, "signature_hex") {
        Ok(value) => Some(value),
        Err(mut value) => {
            errors.append(&mut value);
            None
        }
    };
    let digest = match decode_fixed::<32>(&request.digest, "digest") {
        Ok(value) => Some(value),
        Err(mut value) => {
            errors.append(&mut value);
            None
        }
    };
    if let (Some(signature), Some(digest)) = (signature, digest) {
        match recover_address(signature, digest) {
            Ok(recovered) => {
                if recovered != normalize_hex(expected_attestor) {
                    errors.push(
                        "external signature does not recover the configured attestor".to_string(),
                    );
                }
            }
            Err(mut value) => errors.append(&mut value),
        }
        if errors.is_empty() {
            return Ok(ValidatedExternalSignature {
                signer_backend: response.signer_backend.clone(),
                key_id: response.key_id.clone(),
                attestor_address: normalize_hex(&response.attestor_address),
                signature,
            });
        }
    }

    Err(errors)
}

fn recover_address(signature: [u8; 65], digest: [u8; 32]) -> Result<String, Vec<String>> {
    let v = signature[64];
    if !matches!(v, 27 | 28) {
        return Err(vec!["external signature v must be 27 or 28".to_string()]);
    }
    let recovery_id = RecoveryId::try_from(i32::from(v - 27))
        .map_err(|error| vec![format!("invalid external signature recovery id: {error}")])?;
    let signature = RecoverableSignature::from_compact(&signature[..64], recovery_id)
        .map_err(|error| vec![format!("invalid external signature: {error}")])?;
    let mut normalized = signature.to_standard();
    let original = normalized.serialize_compact();
    normalized.normalize_s();
    if original != normalized.serialize_compact() {
        return Err(vec![
            "external signature s value is not canonical low-s".to_string(),
        ]);
    }
    let public_key = Secp256k1::new()
        .recover_ecdsa(Message::from_digest(digest), &signature)
        .map_err(|error| vec![format!("external signature recovery failed: {error}")])?;
    let uncompressed = public_key.serialize_uncompressed();
    let hash = Keccak256::digest(&uncompressed[1..]);
    Ok(encode_hex(&hash[12..]))
}

fn validate_hex_len(value: &str, expected: usize, field: &str, errors: &mut Vec<String>) {
    match decode_hex(value, field) {
        Ok(bytes) if bytes.len() != expected => errors.push(format!(
            "{field} must be {expected} bytes, got {}",
            bytes.len()
        )),
        Ok(_) => {}
        Err(mut value) => errors.append(&mut value),
    }
}

fn decode_fixed<const N: usize>(value: &str, field: &str) -> Result<[u8; N], Vec<String>> {
    let bytes = decode_hex(value, field)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| vec![format!("{field} must be {N} bytes, got {}", bytes.len())])
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, Vec<String>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() % 2 != 0 {
        return Err(vec![format!(
            "{field} must contain an even number of hex digits"
        )]);
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| vec![format!("{field} contains invalid hex")])
        })
        .collect()
}

fn normalize_hex(value: &str) -> String {
    if value.starts_with("0x") {
        value.to_ascii_lowercase()
    } else {
        format!("0x{}", value.to_ascii_lowercase())
    }
}

fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
    let mut value = String::from("0x");
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

#[cfg(test)]
mod tests {
    use secp256k1::{PublicKey, SecretKey};

    use super::*;

    fn signed_response(
        request: &AttestationSignRequestV1,
        secret: [u8; 32],
    ) -> (String, AttestationSignResponseV1) {
        let secret = SecretKey::from_byte_array(secret).unwrap();
        let secp = Secp256k1::new();
        let digest = decode_fixed::<32>(&request.digest, "digest").unwrap();
        let signature = secp.sign_ecdsa_recoverable(Message::from_digest(digest), &secret);
        let (recovery_id, compact) = signature.serialize_compact();
        let mut signature_hex = compact.to_vec();
        signature_hex.push(u8::try_from(i32::from(recovery_id)).unwrap() + 27);
        let public_key = PublicKey::from_secret_key(&secp, &secret).serialize_uncompressed();
        let hash = Keccak256::digest(&public_key[1..]);
        let address = encode_hex(&hash[12..]);
        (
            address.clone(),
            AttestationSignResponseV1 {
                schema_version: AttestationSignResponseV1::SCHEMA_VERSION.to_string(),
                request_id: request.request_id.clone(),
                signer_backend: "test_threshold_mpc".to_string(),
                key_id: "test-key-v1".to_string(),
                attestor_address: address,
                signature_hex: encode_hex(signature_hex),
            },
        )
    }

    fn request() -> AttestationSignRequestV1 {
        AttestationSignRequestV1::new(
            &format!("0x{}", "11".repeat(32)),
            11_155_111,
            &format!("0x{}", "22".repeat(20)),
            &format!("0x{}", "33".repeat(20)),
            &format!("0x{}", "44".repeat(32)),
            &format!("0x{}", "55".repeat(32)),
            &format!("0x{}", "66".repeat(32)),
            50_000,
        )
        .unwrap()
    }

    #[test]
    fn request_id_is_deterministic_and_policy_bound() {
        let first = request();
        let second = request();
        assert_eq!(first.request_id, second.request_id);
        let changed = AttestationSignRequestV1::new(
            &first.digest,
            first.chain_id,
            &first.verifier_address,
            &first.registry_address,
            &first.public_inputs_hash,
            &first.winterfell_proof_commitment,
            &format!("0x{}", "77".repeat(32)),
            first.claim_amount,
        )
        .unwrap();
        assert_ne!(first.request_id, changed.request_id);
    }

    #[test]
    fn valid_response_recovers_expected_attestor() {
        let request = request();
        let (address, response) = signed_response(&request, [7; 32]);
        let allowed = BTreeSet::from(["test-key-v1".to_string()]);
        let validated = validate_response(&request, &response, &address, &allowed).unwrap();
        assert_eq!(validated.attestor_address, address);
        assert_eq!(validated.signature.len(), 65);
    }

    #[test]
    fn response_rejects_request_key_and_attestor_mismatches() {
        let request = request();
        let (address, mut response) = signed_response(&request, [7; 32]);
        response.request_id = format!("0x{}", "99".repeat(32));
        let errors = validate_response(
            &request,
            &response,
            &format!("0x{}", "aa".repeat(20)),
            &BTreeSet::from(["another-key".to_string()]),
        )
        .unwrap_err();
        assert!(errors.iter().any(|value| value.contains("request_id")));
        assert!(errors.iter().any(|value| value.contains("key_id")));
        assert!(
            errors
                .iter()
                .any(|value| value.contains("attestor_address"))
        );
        assert_ne!(address, format!("0x{}", "aa".repeat(20)));
    }

    #[test]
    fn response_rejects_invalid_v() {
        let request = request();
        let (address, mut response) = signed_response(&request, [7; 32]);
        let mut signature = decode_fixed::<65>(&response.signature_hex, "signature").unwrap();
        signature[64] = 29;
        response.signature_hex = encode_hex(signature);
        let errors = validate_response(
            &request,
            &response,
            &address,
            &BTreeSet::from(["test-key-v1".to_string()]),
        )
        .unwrap_err();
        assert!(errors.iter().any(|value| value.contains("27 or 28")));
    }

    #[test]
    fn response_rejects_high_s_signature() {
        let request = request();
        let (address, mut response) = signed_response(&request, [7; 32]);
        let mut signature = decode_fixed::<65>(&response.signature_hex, "signature").unwrap();
        let order = decode_fixed::<32>(
            "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            "order",
        )
        .unwrap();
        let mut borrow = 0u16;
        for index in (0..32).rev() {
            let minuend = u16::from(order[index]);
            let subtrahend = u16::from(signature[32 + index]) + borrow;
            if minuend >= subtrahend {
                signature[32 + index] = (minuend - subtrahend) as u8;
                borrow = 0;
            } else {
                signature[32 + index] = (256 + minuend - subtrahend) as u8;
                borrow = 1;
            }
        }
        signature[64] = if signature[64] == 27 { 28 } else { 27 };
        response.signature_hex = encode_hex(signature);
        let errors = validate_response(
            &request,
            &response,
            &address,
            &BTreeSet::from(["test-key-v1".to_string()]),
        )
        .unwrap_err();
        assert!(errors.iter().any(|value| value.contains("low-s")));
    }

    #[cfg(unix)]
    #[test]
    fn external_command_rejects_malformed_output() {
        let signer = ExternalCommandSigner {
            program: PathBuf::from("sh"),
            args: vec![
                "-c".to_string(),
                "cat >/dev/null; printf not-json".to_string(),
            ],
            timeout: Duration::from_secs(1),
            expected_attestor: format!("0x{}", "11".repeat(20)),
            allowed_key_ids: BTreeSet::from(["test-key-v1".to_string()]),
        };
        let errors = signer.sign(&request()).unwrap_err();
        assert!(errors.iter().any(|value| value.contains("invalid JSON")));
    }

    #[cfg(unix)]
    #[test]
    fn external_command_enforces_timeout() {
        let signer = ExternalCommandSigner {
            program: PathBuf::from("sh"),
            args: vec!["-c".to_string(), "cat >/dev/null; sleep 1".to_string()],
            timeout: Duration::from_millis(20),
            expected_attestor: format!("0x{}", "11".repeat(20)),
            allowed_key_ids: BTreeSet::from(["test-key-v1".to_string()]),
        };
        let errors = signer.sign(&request()).unwrap_err();
        assert!(errors.iter().any(|value| value.contains("timed out")));
    }
}
