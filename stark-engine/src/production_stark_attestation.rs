use secp256k1::{
    Message, PublicKey, Secp256k1, SecretKey,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use serde::{Deserialize, Serialize};
use sha2::Digest as Sha2Digest;
use sha3::Keccak256;

use crate::production_verifier_handoff::ProductionStarkVerifierHandoffV4;

const ATTESTATION_DOMAIN_LABEL: &[u8] = b"localBCE.stark.attestation.v1";
const ETHEREUM_SIGNED_MESSAGE_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n32";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProductionStarkAttestationEnvelopeV2 {
    pub schema_version: String,
    pub source_schema_version: String,
    pub trust_model: String,
    pub chain_id: u64,
    pub verifier_address: String,
    pub registry_address: String,
    pub claim_amount: u64,
    pub attestor_address: String,
    pub public_inputs: SolidityStarkPublicInputsV1,
    pub public_inputs_hash_keccak256: String,
    pub winterfell_proof_sha256: String,
    pub winterfell_proof_keccak256: String,
    pub attestation_payload_hash: String,
    pub attestation_digest: String,
    pub signature_r: String,
    pub signature_s: String,
    pub signature_v: u8,
    pub proof_envelope_encoding: String,
    pub proof_envelope_hex: String,
    pub proof_envelope_size_bytes: usize,
    pub locally_recovered_attestor: String,
    pub locally_validated: bool,
    pub native_on_chain_stark_verification: bool,
    pub settlement_ready: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolidityStarkPublicInputsV1 {
    pub claim_hash: String,
    pub decision: u8,
    pub failure_code: u32,
    pub public_input_root: String,
    pub claim_source_root: String,
    pub oracle_facts_root: String,
    pub fee_schedule_root: String,
    pub nullifier_root_before: String,
    pub nullifier_root_after: String,
    pub batch_root: String,
}

impl ProductionStarkAttestationEnvelopeV2 {
    pub const SCHEMA_VERSION: &'static str = "stark-production-attestation-envelope-v2";
    pub const TRUST_MODEL: &'static str = "authorized_attestor_after_local_winterfell_verification";
    pub const PROOF_ENVELOPE_ENCODING: &'static str =
        "r_32_s_32_v_1_then_winterfell_proof_keccak256_32_then_claim_amount_uint256_32";

    pub fn from_handoff(
        handoff: &ProductionStarkVerifierHandoffV4,
        chain_id: u64,
        verifier_address: &str,
        registry_address: &str,
        claim_amount: u64,
        private_key_hex: &str,
    ) -> Result<Self, Vec<String>> {
        handoff.validate()?;
        if chain_id == 0 {
            return Err(vec!["chain_id must be nonzero".to_string()]);
        }

        let verifier = decode_address(verifier_address)?;
        if verifier == [0; 20] {
            return Err(vec!["verifier_address must be nonzero".to_string()]);
        }
        let verifier_address = encode_hex(&verifier);
        let registry = decode_address(registry_address)?;
        if registry == [0; 20] {
            return Err(vec!["registry_address must be nonzero".to_string()]);
        }
        let registry_address = encode_hex(&registry);
        let public_inputs = SolidityStarkPublicInputsV1::from_handoff(handoff);
        public_inputs.validate()?;
        let proof = decode_hex(&handoff.source_artifact.proof.bytes_hex, "proof bytes")?;
        if proof.is_empty() {
            return Err(vec!["Winterfell proof bytes must not be empty".to_string()]);
        }

        let secret_bytes = decode_fixed::<32>(private_key_hex, "attestor private key")?;
        let secret_key = SecretKey::from_byte_array(secret_bytes)
            .map_err(|error| vec![format!("invalid attestor private key: {error}")])?;
        let secp = Secp256k1::new();
        let attestor_address = ethereum_address(&PublicKey::from_secret_key(&secp, &secret_key));

        let public_inputs_hash = public_inputs.abi_hash()?;
        let proof_keccak = keccak256(&proof);
        let payload_hash = attestation_payload_hash(
            chain_id,
            verifier,
            registry,
            public_inputs_hash,
            proof_keccak,
            claim_amount,
        );
        let digest = ethereum_signed_digest(payload_hash);
        let signature = secp.sign_ecdsa_recoverable(Message::from_digest(digest), &secret_key);
        let (recovery_id, compact) = signature.serialize_compact();
        let signature_v = u8::try_from(i32::from(recovery_id))
            .map_err(|_| vec!["recovery id did not fit in u8".to_string()])?
            + 27;

        let mut envelope = Vec::with_capacity(129);
        envelope.extend_from_slice(&compact);
        envelope.push(signature_v);
        envelope.extend_from_slice(&proof_keccak);
        envelope.extend_from_slice(&uint256_slot(claim_amount));

        let mut artifact = Self {
            schema_version: Self::SCHEMA_VERSION.to_string(),
            source_schema_version: ProductionStarkVerifierHandoffV4::SCHEMA_VERSION.to_string(),
            trust_model: Self::TRUST_MODEL.to_string(),
            chain_id,
            verifier_address,
            registry_address,
            claim_amount,
            attestor_address: attestor_address.clone(),
            public_inputs,
            public_inputs_hash_keccak256: encode_hex(&public_inputs_hash),
            winterfell_proof_sha256: handoff.proof_bytes_sha256.clone(),
            winterfell_proof_keccak256: encode_hex(&proof_keccak),
            attestation_payload_hash: encode_hex(&payload_hash),
            attestation_digest: encode_hex(&digest),
            signature_r: encode_hex(&compact[..32]),
            signature_s: encode_hex(&compact[32..]),
            signature_v,
            proof_envelope_encoding: Self::PROOF_ENVELOPE_ENCODING.to_string(),
            proof_envelope_hex: encode_hex(&envelope),
            proof_envelope_size_bytes: envelope.len(),
            locally_recovered_attestor: attestor_address,
            locally_validated: true,
            native_on_chain_stark_verification: false,
            settlement_ready: true,
        };
        artifact.validate()?;
        artifact.locally_validated = true;
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        check_equal(
            "schema_version",
            &self.schema_version,
            Self::SCHEMA_VERSION,
            &mut errors,
        );
        check_equal(
            "source_schema_version",
            &self.source_schema_version,
            ProductionStarkVerifierHandoffV4::SCHEMA_VERSION,
            &mut errors,
        );
        check_equal(
            "trust_model",
            &self.trust_model,
            Self::TRUST_MODEL,
            &mut errors,
        );
        check_equal(
            "proof_envelope_encoding",
            &self.proof_envelope_encoding,
            Self::PROOF_ENVELOPE_ENCODING,
            &mut errors,
        );
        if self.chain_id == 0 {
            errors.push("chain_id must be nonzero".to_string());
        }
        if let Err(mut input_errors) = self.public_inputs.validate() {
            errors.append(&mut input_errors);
        }

        let verifier = match decode_address(&self.verifier_address) {
            Ok(value) if value == [0; 20] => {
                errors.push("verifier_address must be nonzero".to_string());
                None
            }
            Ok(value) => Some(value),
            Err(mut value) => {
                errors.append(&mut value);
                None
            }
        };
        let registry = match decode_address(&self.registry_address) {
            Ok(value) if value == [0; 20] => {
                errors.push("registry_address must be nonzero".to_string());
                None
            }
            Ok(value) => Some(value),
            Err(mut value) => {
                errors.append(&mut value);
                None
            }
        };
        let expected_attestor = match decode_address(&self.attestor_address) {
            Ok(value) => Some(value),
            Err(mut value) => {
                errors.append(&mut value);
                None
            }
        };
        let envelope = match decode_hex(&self.proof_envelope_hex, "proof_envelope_hex") {
            Ok(value) => Some(value),
            Err(mut value) => {
                errors.append(&mut value);
                None
            }
        };

        if let (Some(verifier), Some(registry), Some(expected_attestor), Some(envelope)) =
            (verifier, registry, expected_attestor, envelope)
        {
            if envelope.len() != 129 {
                errors.push(
                    "proof envelope must contain a 65-byte signature, 32-byte proof commitment, and 32-byte claim amount"
                        .to_string(),
                );
            } else {
                if self.proof_envelope_size_bytes != envelope.len() {
                    errors
                        .push("proof_envelope_size_bytes does not match decoded bytes".to_string());
                }
                let mut proof_keccak = [0u8; 32];
                proof_keccak.copy_from_slice(&envelope[65..97]);
                if self.winterfell_proof_keccak256 != encode_hex(&proof_keccak) {
                    errors.push(
                        "winterfell_proof_keccak256 does not match envelope commitment".to_string(),
                    );
                }
                if envelope[97..121] != [0u8; 24] {
                    errors.push("claim amount exceeds the supported u64 range".to_string());
                }
                let mut claim_amount_bytes = [0u8; 8];
                claim_amount_bytes.copy_from_slice(&envelope[121..129]);
                if u64::from_be_bytes(claim_amount_bytes) != self.claim_amount {
                    errors.push("claim_amount does not match proof envelope".to_string());
                }
                if decode_fixed::<32>(&self.winterfell_proof_sha256, "winterfell_proof_sha256")
                    .is_err()
                {
                    errors.push(
                        "winterfell_proof_sha256 must remain a bytes32 audit digest".to_string(),
                    );
                }

                if let Ok(public_inputs_hash) = self.public_inputs.abi_hash() {
                    if self.public_inputs_hash_keccak256 != encode_hex(&public_inputs_hash) {
                        errors.push(
                            "public_inputs_hash_keccak256 does not match ABI encoding".to_string(),
                        );
                    }
                    let payload_hash = attestation_payload_hash(
                        self.chain_id,
                        verifier,
                        registry,
                        public_inputs_hash,
                        proof_keccak,
                        self.claim_amount,
                    );
                    let digest = ethereum_signed_digest(payload_hash);
                    if self.attestation_payload_hash != encode_hex(&payload_hash) {
                        errors.push(
                            "attestation_payload_hash does not match canonical payload".to_string(),
                        );
                    }
                    if self.attestation_digest != encode_hex(&digest) {
                        errors.push("attestation_digest does not match EIP-191 digest".to_string());
                    }
                    validate_signature(
                        &envelope[..65],
                        digest,
                        expected_attestor,
                        &self.signature_r,
                        &self.signature_s,
                        self.signature_v,
                        &self.locally_recovered_attestor,
                        &mut errors,
                    );
                }
            }
        }

        if !self.locally_validated {
            errors.push("locally_validated must be true".to_string());
        }
        if self.native_on_chain_stark_verification {
            errors.push(
                "native_on_chain_stark_verification must remain false for attestation mode"
                    .to_string(),
            );
        }
        if !self.settlement_ready {
            errors.push("settlement_ready must be true".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl SolidityStarkPublicInputsV1 {
    fn from_handoff(handoff: &ProductionStarkVerifierHandoffV4) -> Self {
        Self {
            claim_hash: handoff.source_artifact.claim_hash.clone(),
            decision: handoff.source_artifact.decision,
            failure_code: handoff.source_artifact.failure_code,
            public_input_root: handoff.public_input_root.clone(),
            claim_source_root: handoff.claim_source_root.clone(),
            oracle_facts_root: handoff.oracle_facts_root.clone(),
            fee_schedule_root: handoff.fee_schedule_root.clone(),
            nullifier_root_before: handoff.nullifier_root_before.clone(),
            nullifier_root_after: handoff.nullifier_root_after.clone(),
            batch_root: handoff.batch_root.clone(),
        }
    }

    fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for (name, value) in [
            ("claim_hash", &self.claim_hash),
            ("public_input_root", &self.public_input_root),
            ("claim_source_root", &self.claim_source_root),
            ("oracle_facts_root", &self.oracle_facts_root),
            ("fee_schedule_root", &self.fee_schedule_root),
            ("nullifier_root_before", &self.nullifier_root_before),
            ("nullifier_root_after", &self.nullifier_root_after),
            ("batch_root", &self.batch_root),
        ] {
            match decode_fixed::<32>(value, name) {
                Ok(bytes) if bytes == [0; 32] => errors.push(format!("{name} must be nonzero")),
                Ok(_) => {}
                Err(mut value) => errors.append(&mut value),
            }
        }
        if self.decision > 1 {
            errors.push("decision must be 0 or 1".to_string());
        } else if self.decision == 1 {
            if self.failure_code != 0 {
                errors.push("approved public inputs require failure_code 0".to_string());
            }
            if self.nullifier_root_before == self.nullifier_root_after {
                errors.push("approved public inputs must advance the nullifier root".to_string());
            }
        } else {
            if self.failure_code == 0 {
                errors.push("denied public inputs require a nonzero failure_code".to_string());
            }
            if self.nullifier_root_before != self.nullifier_root_after {
                errors.push("denied public inputs require a no-op nullifier root".to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn abi_hash(&self) -> Result<[u8; 32], Vec<String>> {
        let mut encoded = Vec::with_capacity(10 * 32);
        encoded.extend_from_slice(&decode_fixed::<32>(&self.claim_hash, "claim_hash")?);
        encoded.extend_from_slice(&uint256_slot(u64::from(self.decision)));
        encoded.extend_from_slice(&uint256_slot(u64::from(self.failure_code)));
        for (name, value) in [
            ("public_input_root", &self.public_input_root),
            ("claim_source_root", &self.claim_source_root),
            ("oracle_facts_root", &self.oracle_facts_root),
            ("fee_schedule_root", &self.fee_schedule_root),
            ("nullifier_root_before", &self.nullifier_root_before),
            ("nullifier_root_after", &self.nullifier_root_after),
            ("batch_root", &self.batch_root),
        ] {
            encoded.extend_from_slice(&decode_fixed::<32>(value, name)?);
        }
        Ok(keccak256(&encoded))
    }

    pub fn cast_tuple(&self) -> String {
        format!(
            "({},{},{},{},{},{},{},{},{},{})",
            self.claim_hash,
            self.decision,
            self.failure_code,
            self.public_input_root,
            self.claim_source_root,
            self.oracle_facts_root,
            self.fee_schedule_root,
            self.nullifier_root_before,
            self.nullifier_root_after,
            self.batch_root,
        )
    }
}

fn attestation_payload_hash(
    chain_id: u64,
    verifier: [u8; 20],
    registry: [u8; 20],
    public_inputs_hash: [u8; 32],
    proof_hash: [u8; 32],
    claim_amount: u64,
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(7 * 32);
    encoded.extend_from_slice(&keccak256(ATTESTATION_DOMAIN_LABEL));
    encoded.extend_from_slice(&uint256_slot(chain_id));
    encoded.extend_from_slice(&address_slot(verifier));
    encoded.extend_from_slice(&address_slot(registry));
    encoded.extend_from_slice(&public_inputs_hash);
    encoded.extend_from_slice(&proof_hash);
    encoded.extend_from_slice(&uint256_slot(claim_amount));
    keccak256(&encoded)
}

fn ethereum_signed_digest(payload_hash: [u8; 32]) -> [u8; 32] {
    let mut message = Vec::with_capacity(ETHEREUM_SIGNED_MESSAGE_PREFIX.len() + 32);
    message.extend_from_slice(ETHEREUM_SIGNED_MESSAGE_PREFIX);
    message.extend_from_slice(&payload_hash);
    keccak256(&message)
}

fn validate_signature(
    bytes: &[u8],
    digest: [u8; 32],
    expected_attestor: [u8; 20],
    signature_r: &str,
    signature_s: &str,
    signature_v: u8,
    locally_recovered_attestor: &str,
    errors: &mut Vec<String>,
) {
    if bytes.len() != 65 {
        errors.push("signature prefix must be exactly 65 bytes".to_string());
        return;
    }
    if signature_r != encode_hex(&bytes[..32]) || signature_s != encode_hex(&bytes[32..64]) {
        errors.push("signature r/s fields do not match proof envelope".to_string());
    }
    if signature_v != bytes[64] || !matches!(signature_v, 27 | 28) {
        errors.push("signature_v must match envelope and be 27 or 28".to_string());
        return;
    }

    let recovery_id = match RecoveryId::try_from(i32::from(signature_v - 27)) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("invalid recovery id: {error}"));
            return;
        }
    };
    let signature = match RecoverableSignature::from_compact(&bytes[..64], recovery_id) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("invalid recoverable signature: {error}"));
            return;
        }
    };
    let mut normalized = signature.to_standard();
    let original = normalized.serialize_compact();
    normalized.normalize_s();
    if original != normalized.serialize_compact() {
        errors.push("signature s value is not canonical low-s".to_string());
    }
    let secp = Secp256k1::new();
    match secp.recover_ecdsa(Message::from_digest(digest), &signature) {
        Ok(public_key) => {
            let recovered = ethereum_address(&public_key);
            if recovered != encode_hex(&expected_attestor) {
                errors.push("signature does not recover the configured attestor".to_string());
            }
            if locally_recovered_attestor != recovered {
                errors.push("locally_recovered_attestor does not match signature".to_string());
            }
        }
        Err(error) => errors.push(format!("signature recovery failed: {error}")),
    }
}

fn ethereum_address(public_key: &PublicKey) -> String {
    let uncompressed = public_key.serialize_uncompressed();
    let digest = keccak256(&uncompressed[1..]);
    encode_hex(&digest[12..])
}

fn uint256_slot(value: u64) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[24..].copy_from_slice(&value.to_be_bytes());
    slot
}

fn address_slot(value: [u8; 20]) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[12..].copy_from_slice(&value);
    slot
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(bytes);
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

fn decode_address(value: &str) -> Result<[u8; 20], Vec<String>> {
    decode_fixed::<20>(value, "verifier/attestor address")
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

fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
    let bytes = bytes.as_ref();
    let mut value = String::with_capacity(2 + bytes.len() * 2);
    value.push_str("0x");
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn check_equal(field: &str, actual: &str, expected: &str, errors: &mut Vec<String>) {
    if actual != expected {
        errors.push(format!("{field} must be {expected}, got {actual}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_hash_uses_ten_static_solidity_slots() {
        let inputs = SolidityStarkPublicInputsV1 {
            claim_hash: format!("0x{}", "11".repeat(32)),
            decision: 1,
            failure_code: 0,
            public_input_root: format!("0x{}", "22".repeat(32)),
            claim_source_root: format!("0x{}", "33".repeat(32)),
            oracle_facts_root: format!("0x{}", "44".repeat(32)),
            fee_schedule_root: format!("0x{}", "55".repeat(32)),
            nullifier_root_before: format!("0x{}", "66".repeat(32)),
            nullifier_root_after: format!("0x{}", "77".repeat(32)),
            batch_root: format!("0x{}", "88".repeat(32)),
        };

        assert_eq!(inputs.validate(), Ok(()));
        assert_eq!(inputs.abi_hash().unwrap().len(), 32);
    }

    #[test]
    fn denied_inputs_require_noop_nullifier_transition() {
        let inputs = SolidityStarkPublicInputsV1 {
            claim_hash: format!("0x{}", "11".repeat(32)),
            decision: 0,
            failure_code: 7,
            public_input_root: format!("0x{}", "22".repeat(32)),
            claim_source_root: format!("0x{}", "33".repeat(32)),
            oracle_facts_root: format!("0x{}", "44".repeat(32)),
            fee_schedule_root: format!("0x{}", "55".repeat(32)),
            nullifier_root_before: format!("0x{}", "66".repeat(32)),
            nullifier_root_after: format!("0x{}", "66".repeat(32)),
            batch_root: format!("0x{}", "88".repeat(32)),
        };

        assert_eq!(inputs.validate(), Ok(()));
    }

    #[test]
    fn attestation_payload_binds_registry_and_claim_amount() {
        let verifier = [0x11; 20];
        let registry = [0x22; 20];
        let public_inputs_hash = [0x33; 32];
        let proof_hash = [0x44; 32];
        let baseline = attestation_payload_hash(
            31_337,
            verifier,
            registry,
            public_inputs_hash,
            proof_hash,
            50_000,
        );

        assert_ne!(
            baseline,
            attestation_payload_hash(
                31_337,
                verifier,
                [0x23; 20],
                public_inputs_hash,
                proof_hash,
                50_000,
            )
        );
        assert_ne!(
            baseline,
            attestation_payload_hash(
                31_337,
                verifier,
                registry,
                public_inputs_hash,
                proof_hash,
                50_001,
            )
        );
    }
}
