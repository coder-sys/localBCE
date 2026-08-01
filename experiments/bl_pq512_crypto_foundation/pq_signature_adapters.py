"""Strict software PQ-signature adapters for the S09 internal reference.

These adapters exercise the locked ``pqcrypto==0.4.0`` package.  They are
real signature implementations, not synthetic test verifiers, but they are
software-only internal/reference evidence.  Their presence is not evidence of
HSM custody, a FIPS-validated cryptographic module, side-channel qualification,
or production approval.
"""

from __future__ import annotations

from importlib.metadata import version
from typing import Final

from pqcrypto.sign import ml_dsa_87, sphincs_shake_256f_simple


LOCKED_PQCRYPTO_VERSION: Final[str] = "0.4.0"
ML_DSA_87_SUITE_ID: Final[str] = "FIPS204-ML-DSA-87"
SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID: Final[str] = "FIPS205-SLH-DSA-SHAKE-256F"

INTERNAL_REFERENCE_NOTICE: Final[str] = (
    "pqcrypto-0.4.0 software adapter; internal/reference use only; not HSM-backed and not "
    "FIPS-validation or production-approval evidence"
)


class PqSignatureAdapterError(RuntimeError):
    """Stable fail-closed boundary for key generation and signing failures."""


def _runtime_version_is_locked() -> bool:
    try:
        return version("pqcrypto") == LOCKED_PQCRYPTO_VERSION
    except Exception:
        return False


class _PqcryptoSignatureAdapter:
    """Common strict wrapper around one exact pqcrypto signature module."""

    __slots__ = ()

    suite_id: str
    implementation_name: str
    public_key_size: int
    secret_key_size: int
    signature_size: int
    _module: object

    synthetic_only: Final[bool] = False
    internal_reference_only: Final[bool] = True
    software_only: Final[bool] = True
    hsm_backed: Final[bool] = False
    fips_validation_evidence: Final[bool] = False
    qualification_notice: Final[str] = INTERNAL_REFERENCE_NOTICE
    dependency_name: Final[str] = "pqcrypto"
    dependency_version: Final[str] = LOCKED_PQCRYPTO_VERSION

    def __init__(self) -> None:
        if not _runtime_version_is_locked():
            raise PqSignatureAdapterError("pq_signature_adapter_dependency_version_not_locked")
        if (
            type(getattr(self._module, "PUBLIC_KEY_SIZE", None)) is not int
            or self._module.PUBLIC_KEY_SIZE != self.public_key_size
            or type(getattr(self._module, "SECRET_KEY_SIZE", None)) is not int
            or self._module.SECRET_KEY_SIZE != self.secret_key_size
            or type(getattr(self._module, "SIGNATURE_SIZE", None)) is not int
            or self._module.SIGNATURE_SIZE != self.signature_size
        ):
            raise PqSignatureAdapterError("pq_signature_adapter_runtime_size_mismatch")

    def generate_keypair(self) -> tuple[bytes, bytes]:
        try:
            generated = self._module.generate_keypair()
        except Exception as exc:
            raise PqSignatureAdapterError("pq_signature_adapter_keygen_failed_closed") from exc
        if type(generated) is not tuple or len(generated) != 2:
            raise PqSignatureAdapterError("pq_signature_adapter_keypair_shape_invalid")
        public_key, secret_key = generated
        if type(public_key) is not bytes or len(public_key) != self.public_key_size:
            raise PqSignatureAdapterError("pq_signature_adapter_public_key_size_invalid")
        if type(secret_key) is not bytes or len(secret_key) != self.secret_key_size:
            raise PqSignatureAdapterError("pq_signature_adapter_secret_key_size_invalid")
        return public_key, secret_key

    def sign(self, *, secret_key: bytes, message: bytes) -> bytes:
        if type(secret_key) is not bytes or len(secret_key) != self.secret_key_size:
            raise PqSignatureAdapterError("pq_signature_adapter_secret_key_size_invalid")
        if type(message) is not bytes:
            raise PqSignatureAdapterError("pq_signature_adapter_message_type_invalid")
        try:
            signature = self._module.sign(secret_key, message)
        except Exception as exc:
            raise PqSignatureAdapterError("pq_signature_adapter_sign_failed_closed") from exc
        if type(signature) is not bytes or len(signature) != self.signature_size:
            raise PqSignatureAdapterError("pq_signature_adapter_signature_size_invalid")
        return signature

    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if type(public_key) is not bytes or len(public_key) != self.public_key_size:
            return False
        if type(message) is not bytes:
            return False
        if type(signature) is not bytes or len(signature) != self.signature_size:
            return False
        try:
            verified = self._module.verify(public_key, message, signature)
        except Exception:
            return False
        return verified is True


class MlDsa87PqcryptoAdapter(_PqcryptoSignatureAdapter):
    """Exact pqcrypto 0.4.0 ML-DSA-87 adapter."""

    __slots__ = ()
    suite_id = ML_DSA_87_SUITE_ID
    algorithm_name = "ML-DSA-87"
    implementation_name = "pqcrypto.sign.ml_dsa_87"
    public_key_size = 2592
    secret_key_size = 4896
    signature_size = 4627
    _module = ml_dsa_87


class SphincsShake256fSimplePqcryptoAdapter(_PqcryptoSignatureAdapter):
    """Exact pqcrypto 0.4.0 SPHINCS+-SHAKE-256f-simple adapter."""

    __slots__ = ()
    suite_id = SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID
    algorithm_name = "SPHINCS+-SHAKE-256f-simple"
    implementation_name = "pqcrypto.sign.sphincs_shake_256f_simple"
    public_key_size = 64
    secret_key_size = 128
    signature_size = 49856
    _module = sphincs_shake_256f_simple


SUPPORTED_ADAPTER_TYPES: Final[tuple[type[_PqcryptoSignatureAdapter], ...]] = (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
)


def expected_public_key_size(suite_id: str) -> int:
    if suite_id == ML_DSA_87_SUITE_ID:
        return MlDsa87PqcryptoAdapter.public_key_size
    if suite_id == SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID:
        return SphincsShake256fSimplePqcryptoAdapter.public_key_size
    raise ValueError("pq_signature_adapter_suite_not_supported")


def is_exact_supported_adapter(value: object, suite_id: str) -> bool:
    return type(value) in SUPPORTED_ADAPTER_TYPES and value.suite_id == suite_id
