"""Strict software PQ-signature adapters for the S09 internal reference.

These adapters exercise the locked ``pqcrypto==0.4.0`` package.  They are
real signature implementations, not synthetic test verifiers, but they are
software-only internal/reference evidence.  Their presence is not evidence of
HSM custody, a FIPS-validated cryptographic module, side-channel qualification,
or production approval.
"""

from __future__ import annotations

from importlib.metadata import version
from pathlib import Path
import struct
import subprocess
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


_NATIVE_SLH_REQUEST_MAGIC: Final[bytes] = b"BLPQSGN1"
_NATIVE_SLH_RESPONSE_MAGIC: Final[bytes] = b"BLPQSGR1"
_NATIVE_SLH_PROTOCOL_VERSION: Final[int] = 1
_NATIVE_SLH_SUITE_CODE: Final[int] = 2
_NATIVE_SLH_GENERATE: Final[int] = 1
_NATIVE_SLH_SIGN: Final[int] = 2
_NATIVE_SLH_VERIFY: Final[int] = 3
_NATIVE_SLH_PUBLIC_KEY_SIZE: Final[int] = 64
_NATIVE_SLH_SECRET_KEY_SIZE: Final[int] = 128
_NATIVE_SLH_SIGNATURE_SIZE: Final[int] = 49_856
_NATIVE_SLH_MAX_MESSAGE_SIZE: Final[int] = 64 << 20


class NativeSlhDsaAdapter:
    """Software-only RustCrypto FIPS-205 adapter for the candidate path.

    The legacy pqcrypto SPHINCS+-SHAKE simple module is retained for the
    historical reference suites, but it is not byte-compatible with the
    locked RustCrypto FIPS-205 implementation.  This adapter keeps the
    candidate transcript on one exact Rust implementation without claiming
    HSM, FIPS-module validation, or production custody.
    """

    __slots__ = ("_executable",)

    suite_id = SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID
    algorithm_name = "SLH-DSA-SHAKE-256f"
    implementation_name = "RustCrypto slh-dsa-0.2.0-rc.5"
    public_key_size = _NATIVE_SLH_PUBLIC_KEY_SIZE
    secret_key_size = _NATIVE_SLH_SECRET_KEY_SIZE
    signature_size = _NATIVE_SLH_SIGNATURE_SIZE
    synthetic_only: Final[bool] = False
    internal_reference_only: Final[bool] = True
    software_only: Final[bool] = True
    hsm_backed: Final[bool] = False
    fips_validation_evidence: Final[bool] = False
    fips_validated: Final[bool] = False
    qualification_notice: Final[str] = (
        "RustCrypto FIPS-205 software candidate adapter; internal/reference use only; "
        "not HSM-backed and not evidence of a FIPS-validated module or production approval"
    )
    dependency_name: Final[str] = "slh-dsa"
    dependency_version: Final[str] = "0.2.0-rc.5"

    def __init__(self, executable: Path) -> None:
        if (
            not isinstance(executable, Path)
            or not executable.is_absolute()
            or not executable.is_file()
        ):
            raise PqSignatureAdapterError("native_slh_dsa_service_executable_invalid")
        self._executable = executable

    @staticmethod
    def _length_prefixed(value: bytes, maximum: int) -> bytes:
        if type(value) is not bytes or not 0 < len(value) <= maximum:
            raise PqSignatureAdapterError("native_slh_dsa_service_payload_invalid")
        return struct.pack(">I", len(value)) + value

    def _request(self, operation: int, payload: bytes) -> bytes:
        request = b"".join(
            (
                _NATIVE_SLH_REQUEST_MAGIC,
                struct.pack(">H", _NATIVE_SLH_PROTOCOL_VERSION),
                struct.pack(">H", _NATIVE_SLH_SUITE_CODE),
                struct.pack(">H", operation),
                payload,
            )
        )
        try:
            completed = subprocess.run(
                [str(self._executable)],
                cwd=self._executable.parent,
                input=request,
                capture_output=True,
                check=False,
                timeout=120,
            )
        except Exception as exc:
            raise PqSignatureAdapterError("native_slh_dsa_service_unavailable") from exc
        if completed.returncode != 0:
            raise PqSignatureAdapterError("native_slh_dsa_service_failed_closed")
        response = completed.stdout
        if len(response) < 16 or response[:8] != _NATIVE_SLH_RESPONSE_MAGIC:
            raise PqSignatureAdapterError("native_slh_dsa_service_response_invalid")
        if int.from_bytes(response[8:10], "big") != _NATIVE_SLH_PROTOCOL_VERSION:
            raise PqSignatureAdapterError("native_slh_dsa_service_response_version_invalid")
        if int.from_bytes(response[10:12], "big") != _NATIVE_SLH_SUITE_CODE:
            raise PqSignatureAdapterError("native_slh_dsa_service_response_suite_invalid")
        if int.from_bytes(response[12:14], "big") != operation:
            raise PqSignatureAdapterError("native_slh_dsa_service_response_operation_invalid")
        if int.from_bytes(response[14:16], "big") != 0:
            raise PqSignatureAdapterError("native_slh_dsa_service_response_status_invalid")
        return response[16:]

    def generate_keypair(self) -> tuple[bytes, bytes]:
        response = self._request(_NATIVE_SLH_GENERATE, b"")
        if len(response) < 8:
            raise PqSignatureAdapterError("native_slh_dsa_keypair_response_invalid")
        public_length, secret_length = struct.unpack(">II", response[:8])
        if (
            public_length != self.public_key_size
            or secret_length != self.secret_key_size
            or len(response) != 8 + public_length + secret_length
        ):
            raise PqSignatureAdapterError("native_slh_dsa_keypair_shape_invalid")
        split = 8 + public_length
        return response[8:split], response[split:]

    def sign(self, *, secret_key: bytes, message: bytes) -> bytes:
        if type(secret_key) is not bytes or len(secret_key) != self.secret_key_size:
            raise PqSignatureAdapterError("native_slh_dsa_secret_key_size_invalid")
        payload = self._length_prefixed(secret_key, self.secret_key_size) + self._length_prefixed(
            message, _NATIVE_SLH_MAX_MESSAGE_SIZE
        )
        response = self._request(_NATIVE_SLH_SIGN, payload)
        if len(response) < 4:
            raise PqSignatureAdapterError("native_slh_dsa_signature_response_invalid")
        signature_length = struct.unpack(">I", response[:4])[0]
        if signature_length != self.signature_size or len(response) != 4 + signature_length:
            raise PqSignatureAdapterError("native_slh_dsa_signature_shape_invalid")
        return response[4:]

    def verify(self, *, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if (
            type(public_key) is not bytes
            or len(public_key) != self.public_key_size
            or type(signature) is not bytes
            or len(signature) != self.signature_size
        ):
            return False
        try:
            payload = (
                self._length_prefixed(public_key, self.public_key_size)
                + self._length_prefixed(message, _NATIVE_SLH_MAX_MESSAGE_SIZE)
                + self._length_prefixed(signature, self.signature_size)
            )
            response = self._request(_NATIVE_SLH_VERIFY, payload)
        except PqSignatureAdapterError:
            return False
        return response == b"\x01"


SUPPORTED_ADAPTER_TYPES: Final[tuple[type[object], ...]] = (
    MlDsa87PqcryptoAdapter,
    SphincsShake256fSimplePqcryptoAdapter,
    NativeSlhDsaAdapter,
)


def expected_public_key_size(suite_id: str) -> int:
    if suite_id == ML_DSA_87_SUITE_ID:
        return MlDsa87PqcryptoAdapter.public_key_size
    if suite_id == SPHINCS_SHAKE_256F_SIMPLE_SUITE_ID:
        return SphincsShake256fSimplePqcryptoAdapter.public_key_size
    raise ValueError("pq_signature_adapter_suite_not_supported")


def is_exact_supported_adapter(value: object, suite_id: str) -> bool:
    return type(value) in SUPPORTED_ADAPTER_TYPES and value.suite_id == suite_id
