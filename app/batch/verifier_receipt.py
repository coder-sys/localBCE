from __future__ import annotations

import hmac
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from hashlib import sha3_512
from typing import Protocol, Sequence

from app.batch.poseidon import FIELD_MODULUS
from app.public_inputs import PUBLIC_INPUT_FIELD_NAMES_V2


VERIFIER_RECEIPT_SCHEMA = "blind_ledger_verifier_authenticated_receipt_v1"
PRIVACY_V2_PUBLIC_INPUT_SCHEMA = "blind_ledger_private_settlement_public_inputs_v2"
PRODUCTION_VERIFICATION_KIND = "production_verifier"
SYNTHETIC_TEST_VERIFICATION_KIND = "synthetic_test_only"
SYNTHETIC_TEST_PROFILE_ID = "BL-PQ512-v1-SYNTHETIC-TEST-ONLY"
_LOCAL_TEST_ENVIRONMENTS = {"local", "test"}
_LOCAL_ENFORCEMENT_DISABLE_ENV = "BL_ALLOW_LOCAL_ENFORCEMENT_DISABLE"
_SYNTHETIC_PROOF_DOMAIN = b"BL/SYNTHETIC/VERIFIER-PROOF/v1\x00"


def _canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _canonical_identifier(name: str, value: object) -> str:
    if type(value) is not str:
        raise ValueError(f"{name}_invalid")
    text = value
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-"
    if not text or len(text) > 128 or text != text.strip() or any(character not in allowed for character in text):
        raise ValueError(f"{name}_invalid")
    return text


def _canonical_hex(name: str, value: object, *, nybbles: int) -> str:
    if type(value) is not str:
        raise ValueError(f"{name}_not_canonical_hex")
    text = value
    if len(text) != nybbles or text != text.lower() or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{name}_not_canonical_hex")
    return text


def canonical_public_inputs_v2(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise ValueError("privacy_v2_public_inputs_must_be_sequence")
    canonical = tuple(_canonical_hex(f"privacy_v2_public_input_{index}", value, nybbles=64) for index, value in enumerate(values))
    if len(canonical) != len(PUBLIC_INPUT_FIELD_NAMES_V2):
        raise ValueError("privacy_v2_public_input_count_mismatch")
    for index, value in enumerate(canonical):
        if int(value, 16) >= FIELD_MODULUS:
            raise ValueError(f"privacy_v2_public_input_not_stark_field:{index}")
    if int(canonical[0], 16) != 2:
        raise ValueError("privacy_v2_protocol_version_mismatch")
    if int(canonical[1], 16) == 0:
        raise ValueError("privacy_v2_settlement_domain_must_be_nonzero")
    return canonical


def _require_synthetic_test_environment() -> None:
    environment = os.environ.get("BL_ENV", "").strip().lower()
    if not (
        environment in _LOCAL_TEST_ENVIRONMENTS
        and os.environ.get("BL_DEV") == "1"
        and os.environ.get(_LOCAL_ENFORCEMENT_DISABLE_ENV) == "1"
    ):
        raise RuntimeError(
            "synthetic_verifier_forbidden:requires_local_test_env_and_explicit_dev_flags"
        )


@dataclass(frozen=True)
class VerifierAdapterDescriptor:
    verifier_key_id: str
    profile_id: str
    public_input_schema: str
    verifier_artifact_digest_sha3_512: str
    verification_kind: str

    def validated(self) -> "VerifierAdapterDescriptor":
        verifier_key_id = _canonical_identifier("verifier_key_id", self.verifier_key_id)
        profile_id = _canonical_identifier("verifier_profile_id", self.profile_id)
        if self.public_input_schema != PRIVACY_V2_PUBLIC_INPUT_SCHEMA:
            raise ValueError("verifier_public_input_schema_mismatch")
        artifact_digest = _canonical_hex(
            "verifier_artifact_digest_sha3_512",
            self.verifier_artifact_digest_sha3_512,
            nybbles=128,
        )
        if self.verification_kind not in {
            PRODUCTION_VERIFICATION_KIND,
            SYNTHETIC_TEST_VERIFICATION_KIND,
        }:
            raise ValueError("verifier_verification_kind_invalid")
        return VerifierAdapterDescriptor(
            verifier_key_id=verifier_key_id,
            profile_id=profile_id,
            public_input_schema=self.public_input_schema,
            verifier_artifact_digest_sha3_512=artifact_digest,
            verification_kind=self.verification_kind,
        )


@dataclass(frozen=True)
class VerificationRequest:
    batch_id: str
    verifier_key_id: str
    public_inputs: tuple[str, ...]
    proof: bytes = field(repr=False)

    @classmethod
    def create(
        cls,
        *,
        batch_id: object,
        verifier_key_id: object,
        public_inputs: Sequence[str],
        proof: bytes | bytearray | memoryview,
    ) -> "VerificationRequest":
        if not isinstance(proof, (bytes, bytearray, memoryview)) or not proof:
            raise ValueError("verifier_proof_must_be_nonempty_bytes")
        return cls(
            batch_id=_canonical_hex("batch_id", batch_id, nybbles=64),
            verifier_key_id=_canonical_identifier("verifier_key_id", verifier_key_id),
            public_inputs=canonical_public_inputs_v2(public_inputs),
            proof=bytes(proof),
        )

    def statement_payload(self) -> dict[str, object]:
        return {
            "batch_id": self.batch_id,
            "verifier_key_id": self.verifier_key_id,
            "public_input_schema": PRIVACY_V2_PUBLIC_INPUT_SCHEMA,
            "public_input_names": list(PUBLIC_INPUT_FIELD_NAMES_V2),
            "public_inputs": list(self.public_inputs),
        }

    def validated(self) -> "VerificationRequest":
        if type(self) is not VerificationRequest:
            raise ValueError("verifier_request_type_invalid")
        batch_id = _canonical_hex("batch_id", self.batch_id, nybbles=64)
        verifier_key_id = _canonical_identifier("verifier_key_id", self.verifier_key_id)
        if type(self.public_inputs) is not tuple:
            raise ValueError("verifier_request_public_inputs_not_canonical_tuple")
        public_inputs = canonical_public_inputs_v2(self.public_inputs)
        if public_inputs != self.public_inputs:
            raise ValueError("verifier_request_public_inputs_noncanonical")
        if type(self.proof) is not bytes or not self.proof:
            raise ValueError("verifier_proof_must_be_nonempty_bytes")
        if batch_id != self.batch_id or verifier_key_id != self.verifier_key_id:
            raise ValueError("verifier_request_noncanonical")
        return self


class VerifierAdapter(Protocol):
    @property
    def descriptor(self) -> VerifierAdapterDescriptor: ...

    def verify(self, request: VerificationRequest) -> None: ...


@dataclass(frozen=True)
class VerifiedBatchReceipt:
    receipt_schema: str
    public_input_schema: str
    public_input_names: tuple[str, ...]
    public_inputs: tuple[str, ...]
    settlement_domain: str
    batch_id: str
    verifier_key_id: str
    profile_id: str
    verifier_artifact_digest_sha3_512: str
    proof_digest_sha3_512: str
    verification_kind: str
    authority_tag_sha3_512: str = field(repr=False)

    @property
    def production_verified(self) -> bool:
        # A receipt is an inert data object and cannot authenticate itself. The
        # repository has no authority-owned production-verifier registration yet,
        # so exposing a truthy result here would let a caller-created object claim
        # production verification without crossing an authority trust boundary.
        return False

    def authenticated_payload(self) -> dict[str, object]:
        payload = asdict(self)
        payload.pop("authority_tag_sha3_512")
        payload["public_input_names"] = list(self.public_input_names)
        payload["public_inputs"] = list(self.public_inputs)
        return payload


class VerifierReceiptIssuer:
    """Authority-local capability issuer backed by a configured verifier adapter.

    The authority tag makes a caller-constructed or cross-authority receipt fail
    validation. This class does not provide a production verifier implementation.
    """

    def __init__(self, adapter: VerifierAdapter | None = None) -> None:
        self._adapter = adapter
        self._authority_key = secrets.token_bytes(64)
        self._adapter_descriptor: VerifierAdapterDescriptor | None = None
        if adapter is not None:
            descriptor = adapter.descriptor.validated()
            # Trust-critical stop gate: a Protocol implementation describing
            # itself as "production" is not an authority-owned registration.
            # In addition, SubmittedBatch cannot yet rederive Privacy V2 fields
            # 9-11 from its committed local transition. Production settlement
            # must remain unavailable until both gaps are closed and reviewed.
            if descriptor.verification_kind == PRODUCTION_VERIFICATION_KIND:
                raise RuntimeError("production_verifier_registration_unavailable")
            _require_synthetic_test_environment()
            self._adapter_descriptor = descriptor

    def _pinned_adapter_descriptor(self) -> VerifierAdapterDescriptor | None:
        if self._adapter is None:
            return None
        current = self._adapter.descriptor.validated()
        if current != self._adapter_descriptor:
            raise RuntimeError("verifier_adapter_descriptor_changed")
        return self._adapter_descriptor

    @property
    def adapter_descriptor(self) -> VerifierAdapterDescriptor | None:
        return self._pinned_adapter_descriptor()

    def issue(self, request: VerificationRequest) -> VerifiedBatchReceipt:
        if type(request) is not VerificationRequest:
            raise ValueError("verifier_request_type_invalid")
        request = request.validated()
        if self._adapter is None:
            raise RuntimeError("production_verifier_adapter_unavailable")
        descriptor = self._pinned_adapter_descriptor()
        if descriptor is None:
            raise RuntimeError("production_verifier_adapter_unavailable")
        if descriptor.verification_kind == PRODUCTION_VERIFICATION_KIND:
            raise RuntimeError("production_verifier_registration_unavailable")
        _require_synthetic_test_environment()
        if request.verifier_key_id != descriptor.verifier_key_id:
            raise ValueError("verifier_key_id_mismatch")
        self._adapter.verify(request)
        if self._pinned_adapter_descriptor() != descriptor:
            raise RuntimeError("verifier_adapter_descriptor_changed")
        receipt = VerifiedBatchReceipt(
            receipt_schema=VERIFIER_RECEIPT_SCHEMA,
            public_input_schema=descriptor.public_input_schema,
            public_input_names=PUBLIC_INPUT_FIELD_NAMES_V2,
            public_inputs=request.public_inputs,
            settlement_domain=request.public_inputs[1],
            batch_id=request.batch_id,
            verifier_key_id=descriptor.verifier_key_id,
            profile_id=descriptor.profile_id,
            verifier_artifact_digest_sha3_512=descriptor.verifier_artifact_digest_sha3_512,
            proof_digest_sha3_512=sha3_512(request.proof).hexdigest(),
            verification_kind=descriptor.verification_kind,
            authority_tag_sha3_512="",
        )
        tag = hmac.new(
            self._authority_key,
            _canonical_json_bytes(receipt.authenticated_payload()),
            sha3_512,
        ).hexdigest()
        return VerifiedBatchReceipt(**{**asdict(receipt), "authority_tag_sha3_512": tag})

    def validate(self, receipt: VerifiedBatchReceipt) -> None:
        if type(receipt) is not VerifiedBatchReceipt:
            raise ValueError("verifier_receipt_type_invalid")
        if receipt.receipt_schema != VERIFIER_RECEIPT_SCHEMA:
            raise ValueError("verifier_receipt_schema_mismatch")
        if receipt.public_input_schema != PRIVACY_V2_PUBLIC_INPUT_SCHEMA:
            raise ValueError("verifier_receipt_public_input_schema_mismatch")
        if receipt.public_input_names != PUBLIC_INPUT_FIELD_NAMES_V2:
            raise ValueError("verifier_receipt_public_input_names_mismatch")
        canonical = canonical_public_inputs_v2(receipt.public_inputs)
        if canonical != receipt.public_inputs:
            raise ValueError("verifier_receipt_public_inputs_noncanonical")
        if receipt.settlement_domain != canonical[1]:
            raise ValueError("verifier_receipt_settlement_domain_mismatch")
        _canonical_hex("verifier_receipt_batch_id", receipt.batch_id, nybbles=64)
        _canonical_identifier("verifier_receipt_key_id", receipt.verifier_key_id)
        _canonical_identifier("verifier_receipt_profile_id", receipt.profile_id)
        _canonical_hex(
            "verifier_receipt_artifact_digest_sha3_512",
            receipt.verifier_artifact_digest_sha3_512,
            nybbles=128,
        )
        _canonical_hex(
            "verifier_receipt_proof_digest_sha3_512",
            receipt.proof_digest_sha3_512,
            nybbles=128,
        )
        if receipt.verification_kind not in {
            PRODUCTION_VERIFICATION_KIND,
            SYNTHETIC_TEST_VERIFICATION_KIND,
        }:
            raise ValueError("verifier_receipt_verification_kind_invalid")
        if receipt.verification_kind == PRODUCTION_VERIFICATION_KIND:
            raise ValueError("production_verifier_receipt_unavailable")
        _require_synthetic_test_environment()
        supplied_tag = _canonical_hex(
            "verifier_receipt_authority_tag_sha3_512",
            receipt.authority_tag_sha3_512,
            nybbles=128,
        )
        expected_tag = hmac.new(
            self._authority_key,
            _canonical_json_bytes(receipt.authenticated_payload()),
            sha3_512,
        ).hexdigest()
        if not hmac.compare_digest(supplied_tag, expected_tag):
            raise ValueError("verifier_receipt_authority_mismatch")
        descriptor = self._pinned_adapter_descriptor()
        if descriptor is None:
            raise ValueError("verifier_receipt_adapter_unavailable")
        if receipt.verifier_key_id != descriptor.verifier_key_id:
            raise ValueError("verifier_receipt_configured_key_mismatch")
        if receipt.profile_id != descriptor.profile_id:
            raise ValueError("verifier_receipt_configured_profile_mismatch")
        if receipt.public_input_schema != descriptor.public_input_schema:
            raise ValueError("verifier_receipt_configured_schema_mismatch")
        if receipt.verifier_artifact_digest_sha3_512 != descriptor.verifier_artifact_digest_sha3_512:
            raise ValueError("verifier_receipt_configured_artifact_mismatch")
        if receipt.verification_kind != descriptor.verification_kind:
            raise ValueError("verifier_receipt_configured_kind_mismatch")


class LocalSyntheticVerifierAdapter:
    """Local-only authenticated test double. It is not a real proof verifier."""

    def __init__(self, *, verifier_key_id: str, artifact_bytes: bytes) -> None:
        _require_synthetic_test_environment()
        if not isinstance(artifact_bytes, bytes) or not artifact_bytes:
            raise ValueError("synthetic_verifier_artifact_must_be_nonempty_bytes")
        self._descriptor = VerifierAdapterDescriptor(
            verifier_key_id=_canonical_identifier("verifier_key_id", verifier_key_id),
            profile_id=SYNTHETIC_TEST_PROFILE_ID,
            public_input_schema=PRIVACY_V2_PUBLIC_INPUT_SCHEMA,
            verifier_artifact_digest_sha3_512=sha3_512(artifact_bytes).hexdigest(),
            verification_kind=SYNTHETIC_TEST_VERIFICATION_KIND,
        ).validated()
        self._proof_key = secrets.token_bytes(64)

    @property
    def descriptor(self) -> VerifierAdapterDescriptor:
        _require_synthetic_test_environment()
        return self._descriptor

    def synthetic_proof(self, request: VerificationRequest) -> bytes:
        _require_synthetic_test_environment()
        request = request.validated()
        tag = hmac.new(
            self._proof_key,
            _canonical_json_bytes(request.statement_payload()),
            sha3_512,
        ).digest()
        return _SYNTHETIC_PROOF_DOMAIN + tag

    def verify(self, request: VerificationRequest) -> None:
        _require_synthetic_test_environment()
        expected = self.synthetic_proof(request)
        if not hmac.compare_digest(request.proof, expected):
            raise ValueError("synthetic_verifier_proof_invalid")
