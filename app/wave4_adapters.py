"""Wave 4 provider-neutral adapter boundary.

The module is deliberately split from the older connector helpers.  It is the
internal engineering boundary for I01-I08: adapters exchange private facts in
memory, while the only durable/public object is a bounded provenance capsule
containing commitments, versions, freshness, and dual-PQ signatures.

No class in this module opens a network socket or accepts a live credential.
The synthetic implementation is a local qualification provider.  It is not a
production endpoint and cannot be promoted to one by changing a flag.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import Final, Protocol


WAVE4_ADAPTER_SDK_SCHEMA: Final[str] = "blind_ledger_adapter_sdk_v1"
WAVE4_CAPSULE_SCHEMA: Final[str] = "blind_ledger_provenance_capsule_v1"
WAVE4_CRYPTO_PROFILE: Final[str] = "DUAL-PQ-ML-DSA-87+SLH-DSA-SHAKE-256F"
ML_DSA_87: Final[str] = "FIPS204-ML-DSA-87"
SLH_DSA_SHAKE_256F: Final[str] = "FIPS205-SLH-DSA-SHAKE-256F"
DUAL_PQ_SUITES: Final[tuple[str, str]] = (ML_DSA_87, SLH_DSA_SHAKE_256F)

REQUIRED_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        # I02: identity, tenant, authorization, transport and credential ports.
        "identity",
        "tenant",
        "authorization",
        "transport",
        "credential",
        # I03: source and attachment ports.
        "claim_source",
        "attachment",
        # I04: eligibility, coverage, enrollment and provider status.
        "eligibility",
        "coverage",
        "enrollment",
        "provider_status",
        # I05: authorization, diagnosis/procedure and document facts.
        "prior_authorization",
        "diagnosis_procedure",
        "document_fact",
        # I06: fee, policy, ruleset and governed-root ports.
        "fee_schedule",
        "policy",
        "ruleset",
        "governed_root",
        # I07: payment, treasury, remittance and reconciliation ports.
        "payment",
        "treasury",
        "remittance",
        "reconciliation",
    }
)

MAX_IDENTIFIER_BYTES: Final[int] = 128
MAX_CAPSULE_BYTES: Final[int] = 128 * 1024
MAX_SOURCE_BYTES: Final[int] = 512 * 1024
MAX_FACTS: Final[int] = 128
MAX_RETRY_ATTEMPTS: Final[int] = 5
MAX_DEADLINE_MS: Final[int] = 60_000
MAX_SIGNATURE_BYTES: Final[int] = 64 * 1024
MAX_IDEMPOTENCY_RECORDS: Final[int] = 4_096
MAX_TRANSPORT_RESPONSES: Final[int] = 4_096

_IDENTIFIER = re.compile(r"[A-Z0-9][A-Z0-9_.:-]{0,127}\Z")
_CAPABILITY = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_HEX128 = re.compile(r"[0-9a-f]{128}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class Wave4AdapterError(RuntimeError):
    """Stable fail-closed error at the adapter boundary."""


class RetryableAdapterError(Wave4AdapterError):
    """A bounded transport/availability failure that may be retried."""


class AdapterDowngradeError(Wave4AdapterError):
    """A caller attempted to select an older adapter version."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _digest(*parts: bytes) -> bytes:
    hasher = hashlib.sha3_512()
    for part in parts:
        hasher.update(len(part).to_bytes(8, "big"))
        hasher.update(part)
    return hasher.digest()


def _digest_hex(*parts: bytes) -> str:
    return _digest(*parts).hex()


def _identifier(label: str, value: object) -> str:
    if not isinstance(value, str) or len(value.encode("ascii", "ignore")) > MAX_IDENTIFIER_BYTES:
        raise ValueError(f"{label}_invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label}_invalid") from exc
    if not encoded or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label}_invalid")
    return value


def _capability(value: object) -> str:
    if not isinstance(value, str) or _CAPABILITY.fullmatch(value) is None:
        raise ValueError("adapter_capability_invalid")
    return value


def _token(label: str, value: object) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise ValueError(f"{label}_invalid")
    return value


def _hex(label: str, value: object, *, length: int = 128) -> str:
    if not isinstance(value, str) or value != value.lower():
        raise ValueError(f"{label}_invalid")
    pattern = _HEX128 if length == 128 else _HEX64
    if pattern.fullmatch(value) is None:
        raise ValueError(f"{label}_invalid")
    return value


def _bounded_int(label: str, value: object, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label}_out_of_bounds")
    return value


def _source_id(value: object) -> str:
    source = _identifier("source_id", value)
    if not (source.startswith("SYNTHETIC-") or source.startswith("SANDBOX-")):
        raise ValueError("source_id_must_be_local_synthetic")
    return source


def _private_lookup(value: object) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise ValueError("synthetic_lookup_key_invalid")
    if not value.upper().startswith(("SYNTHETIC-", "SANDBOX-")):
        raise ValueError("synthetic_lookup_key_must_be_local")
    return value


def _mapping_copy(value: Mapping[str, object], *, label: str) -> MappingProxyType:
    if not isinstance(value, Mapping) or len(value) > MAX_FACTS:
        raise ValueError(f"{label}_invalid")
    copied: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 128:
            raise ValueError(f"{label}_key_invalid")
        if isinstance(item, (dict, list, set, tuple)):
            raise ValueError(f"{label}_value_must_be_scalar")
        if not isinstance(item, (str, int, bool, bytes, type(None))):
            raise ValueError(f"{label}_value_invalid")
        copied[key] = item
    return MappingProxyType(copied)


@dataclass(frozen=True, slots=True)
class AdapterIdentity:
    """Versioned identity and isolation declaration for one adapter."""

    provider_id: str
    adapter_id: str
    adapter_version: int
    schema_version: str
    normalization_version: int
    jurisdiction: str
    capability: str
    endpoint_id: str
    tenant_id: str
    cryptographic_profile: str = WAVE4_CRYPTO_PROFILE
    network_access: bool = False
    credential_mode: str = "none"

    def __post_init__(self) -> None:
        _source_id(self.provider_id)
        _identifier("adapter_id", self.adapter_id)
        _bounded_int("adapter_version", self.adapter_version, minimum=1, maximum=255)
        _identifier("schema_version", self.schema_version)
        _bounded_int("normalization_version", self.normalization_version, minimum=1, maximum=255)
        _identifier("jurisdiction", self.jurisdiction)
        _capability(self.capability)
        _identifier("endpoint_id", self.endpoint_id)
        _identifier("tenant_id", self.tenant_id)
        if self.cryptographic_profile != WAVE4_CRYPTO_PROFILE:
            raise ValueError("adapter_cryptographic_profile_not_dual_pq")
        if type(self.network_access) is not bool or self.network_access:
            raise ValueError("synthetic_adapter_network_access_forbidden")
        if self.credential_mode != "none":
            raise ValueError("synthetic_adapter_credential_mode_forbidden")

    def canonical_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "schema_version": self.schema_version,
            "normalization_version": self.normalization_version,
            "jurisdiction": self.jurisdiction,
            "capability": self.capability,
            "endpoint_id": self.endpoint_id,
            "tenant_id": self.tenant_id,
            "cryptographic_profile": self.cryptographic_profile,
            "network_access": self.network_access,
            "credential_mode": self.credential_mode,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.canonical_dict())

    @property
    def identity_digest_sha3_512(self) -> str:
        return _digest_hex(b"BL/WAVE4/ADAPTER-IDENTITY/V1", self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class AdapterRequest:
    """A request whose durable form contains commitments, never source data."""

    request_id: str
    capability: str
    subject_commitment_sha3_512: str
    query_commitment_sha3_512: str
    idempotency_key: str
    requested_epoch: int
    deadline_ms: int
    _lookup_key: str = field(repr=False)

    def __post_init__(self) -> None:
        _token("request_id", self.request_id)
        _capability(self.capability)
        _hex("subject_commitment_sha3_512", self.subject_commitment_sha3_512)
        _hex("query_commitment_sha3_512", self.query_commitment_sha3_512)
        _token("idempotency_key", self.idempotency_key)
        _bounded_int("requested_epoch", self.requested_epoch, minimum=1, maximum=2**63 - 1)
        _bounded_int("deadline_ms", self.deadline_ms, minimum=1, maximum=MAX_DEADLINE_MS)
        _private_lookup(self._lookup_key)

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        capability: str,
        lookup_key: str,
        idempotency_key: str,
        requested_epoch: int = 1,
        deadline_ms: int = 30_000,
    ) -> "AdapterRequest":
        request = _token("request_id", request_id)
        cap = _capability(capability)
        lookup = _private_lookup(lookup_key)
        idem = _token("idempotency_key", idempotency_key)
        epoch = _bounded_int("requested_epoch", requested_epoch, minimum=1, maximum=2**63 - 1)
        deadline = _bounded_int("deadline_ms", deadline_ms, minimum=1, maximum=MAX_DEADLINE_MS)
        subject = _digest_hex(b"BL/WAVE4/SUBJECT/V1", lookup.encode("ascii"))
        query = _digest_hex(b"BL/WAVE4/QUERY/V1", cap.encode("ascii"), lookup.encode("ascii"))
        return cls(request, cap, subject, query, idem, epoch, deadline, lookup)

    def canonical_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "capability": self.capability,
            "subject_commitment_sha3_512": self.subject_commitment_sha3_512,
            "query_commitment_sha3_512": self.query_commitment_sha3_512,
            "idempotency_key": self.idempotency_key,
            "requested_epoch": self.requested_epoch,
            "deadline_ms": self.deadline_ms,
        }

    def canonical_bytes(self) -> bytes:
        _token("request_id", self.request_id)
        _capability(self.capability)
        _hex("subject_commitment_sha3_512", self.subject_commitment_sha3_512)
        _hex("query_commitment_sha3_512", self.query_commitment_sha3_512)
        return _canonical_json(self.canonical_dict())

    @property
    def request_digest_sha3_512(self) -> str:
        return _digest_hex(b"BL/WAVE4/REQUEST/V1", self.canonical_bytes())


@dataclass(frozen=True, slots=True)
class PqSignature:
    suite_id: str
    key_id_sha3_512: str
    signature_hex: str

    def __post_init__(self) -> None:
        if self.suite_id not in DUAL_PQ_SUITES:
            raise ValueError("wave4_signature_suite_not_approved")
        _hex("signature_key_id_sha3_512", self.key_id_sha3_512, length=64)
        if not isinstance(self.signature_hex, str) or not self.signature_hex or self.signature_hex != self.signature_hex.lower():
            raise ValueError("wave4_signature_encoding_invalid")
        try:
            raw = bytes.fromhex(self.signature_hex)
        except ValueError as exc:
            raise ValueError("wave4_signature_encoding_invalid") from exc
        if not raw:
            raise ValueError("wave4_signature_empty")
        if len(raw) > MAX_SIGNATURE_BYTES:
            raise ValueError("wave4_signature_size_limit_exceeded")

    def canonical_dict(self) -> dict[str, str]:
        return {
            "suite_id": self.suite_id,
            "key_id_sha3_512": self.key_id_sha3_512,
            "signature_hex": self.signature_hex,
        }


class PqSigner(Protocol):
    suite_id: str
    key_id_sha3_512: str
    public_key: bytes
    software_only: bool
    hsm_backed: bool
    fips_validated: bool

    def sign(self, message: bytes) -> bytes: ...

    def verify(self, *, message: bytes, signature: bytes) -> bool: ...


class PqcryptoSoftwareSigner:
    """Locked software signer for local/sandbox conformance only.

    The object exposes the same port as a provider HSM but is explicitly marked
    non-production.  It is useful for exercising the exact signing and
    verification contract; it is not FIPS/HSM evidence.
    """

    __slots__ = (
        "suite_id",
        "key_id_sha3_512",
        "public_key",
        "software_only",
        "hsm_backed",
        "fips_validated",
        "_adapter",
        "_secret_key",
    )

    def __init__(
        self,
        *,
        suite_id: str,
        key_id_sha3_512: str,
        public_key: bytes,
        secret_key: bytes,
        adapter: object,
    ) -> None:
        if suite_id not in DUAL_PQ_SUITES:
            raise ValueError("wave4_signer_suite_not_approved")
        _hex("wave4_signer_key_id", key_id_sha3_512, length=64)
        if type(public_key) is not bytes or not public_key:
            raise ValueError("wave4_signer_public_key_invalid")
        if type(secret_key) is not bytes or not secret_key:
            raise ValueError("wave4_signer_secret_key_invalid")
        self.suite_id = suite_id
        self.key_id_sha3_512 = key_id_sha3_512
        self.public_key = public_key
        self.software_only = True
        self.hsm_backed = False
        self.fips_validated = False
        self._adapter = adapter
        self._secret_key = bytearray(secret_key)

    @classmethod
    def generate(cls, suite_id: str) -> "PqcryptoSoftwareSigner":
        from experiments.bl_pq512_crypto_foundation.pq_signature_adapters import (
            MlDsa87PqcryptoAdapter,
            SphincsShake256fSimplePqcryptoAdapter,
        )

        adapter = {
            ML_DSA_87: MlDsa87PqcryptoAdapter,
            SLH_DSA_SHAKE_256F: SphincsShake256fSimplePqcryptoAdapter,
        }.get(suite_id)
        if adapter is None:
            raise ValueError("wave4_signer_suite_not_approved")
        instance = adapter()
        public_key, secret_key = instance.generate_keypair()
        key_id = _digest_hex(b"BL/WAVE4/PQ-KEY-ID/V1", suite_id.encode("ascii"), public_key)[:64]
        return cls(
            suite_id=suite_id,
            key_id_sha3_512=key_id,
            public_key=public_key,
            secret_key=secret_key,
            adapter=instance,
        )

    def sign(self, message: bytes) -> bytes:
        if type(message) is not bytes:
            raise Wave4AdapterError("wave4_signer_message_invalid")
        if not self._secret_key:
            raise Wave4AdapterError("wave4_signer_destroyed")
        try:
            return self._adapter.sign(secret_key=bytes(self._secret_key), message=message)
        except Exception as exc:
            raise Wave4AdapterError("wave4_signer_failed_closed") from exc

    def verify(self, *, message: bytes, signature: bytes) -> bool:
        if type(message) is not bytes or type(signature) is not bytes:
            return False
        try:
            return self._adapter.verify(public_key=self.public_key, message=message, signature=signature)
        except Exception:
            return False

    def destroy(self) -> None:
        for index in range(len(self._secret_key)):
            self._secret_key[index] = 0
        self._secret_key.clear()


class DualPqAuthenticator:
    """Exactly one ML-DSA and one SLH-DSA signer, with no fallback."""

    __slots__ = ("_signers", "authority_id_sha3_512", "software_only", "hsm_backed", "fips_validated")

    def __init__(self, signers: Sequence[PqSigner]) -> None:
        if type(signers) not in (tuple, list) or len(signers) != 2:
            raise ValueError("wave4_dual_pq_requires_two_signers")
        checked = tuple(signers)
        if tuple(getattr(item, "suite_id", None) for item in checked) != DUAL_PQ_SUITES:
            raise ValueError("wave4_dual_pq_suite_set_invalid")
        if len({item.key_id_sha3_512 for item in checked}) != 2:
            raise ValueError("wave4_dual_pq_key_id_duplicate")
        if any(not callable(getattr(item, "sign", None)) or not callable(getattr(item, "verify", None)) for item in checked):
            raise ValueError("wave4_dual_pq_port_invalid")
        self._signers = checked
        self.software_only = all(item.software_only is True for item in checked)
        self.hsm_backed = all(item.hsm_backed is True for item in checked)
        self.fips_validated = all(item.fips_validated is True for item in checked)
        self.authority_id_sha3_512 = _digest_hex(
            b"BL/WAVE4/PQ-AUTHORITY/V1",
            *(
                _canonical_json(
                    {
                        "suite_id": item.suite_id,
                        "key_id_sha3_512": item.key_id_sha3_512,
                        "public_key_sha3_512": _digest_hex(item.public_key),
                    }
                )
                for item in checked
            ),
        )

    def sign(self, message: bytes) -> tuple[PqSignature, ...]:
        if type(message) is not bytes:
            raise Wave4AdapterError("wave4_authority_message_invalid")
        return tuple(
            PqSignature(item.suite_id, item.key_id_sha3_512, item.sign(message).hex())
            for item in self._signers
        )

    def verify(self, *, message: bytes, signatures: Sequence[PqSignature]) -> bool:
        if type(message) is not bytes or type(signatures) not in (tuple, list) or len(signatures) != 2:
            return False
        by_suite = {item.suite_id: item for item in signatures if type(item) is PqSignature}
        if tuple(by_suite) != DUAL_PQ_SUITES:
            return False
        for signer in self._signers:
            signature = by_suite[signer.suite_id]
            if signature.key_id_sha3_512 != signer.key_id_sha3_512:
                return False
            try:
                raw = bytes.fromhex(signature.signature_hex)
            except ValueError:
                return False
            if not signer.verify(message=message, signature=raw):
                return False
        return True


@dataclass(frozen=True, slots=True)
class EvidenceCapsule:
    """Public-safe provenance and freshness record for one adapter response."""

    adapter_id: str
    adapter_version: int
    provider_id: str
    schema_version: str
    normalization_version: int
    jurisdiction: str
    capability: str
    endpoint_id: str
    tenant_id: str
    cryptographic_profile: str
    request_commitment_sha3_512: str
    source_bytes_sha3_512: str
    source_epoch: int
    fetched_at: int
    freshness_deadline: int
    completeness: bool
    absence_evidence_sha3_512: str
    idempotency_key: str
    error_class: str
    authority_id_sha3_512: str
    signatures: tuple[PqSignature, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _identifier("capsule_adapter_id", self.adapter_id)
        _bounded_int("capsule_adapter_version", self.adapter_version, minimum=1, maximum=255)
        _source_id(self.provider_id)
        _identifier("capsule_schema_version", self.schema_version)
        _bounded_int("capsule_normalization_version", self.normalization_version, minimum=1, maximum=255)
        _identifier("capsule_jurisdiction", self.jurisdiction)
        _capability(self.capability)
        _identifier("capsule_endpoint_id", self.endpoint_id)
        _identifier("capsule_tenant_id", self.tenant_id)
        if self.cryptographic_profile != WAVE4_CRYPTO_PROFILE:
            raise ValueError("capsule_cryptographic_profile_not_dual_pq")
        _hex("capsule_request_commitment", self.request_commitment_sha3_512)
        _hex("capsule_source_digest", self.source_bytes_sha3_512)
        _bounded_int("capsule_source_epoch", self.source_epoch, minimum=1, maximum=2**63 - 1)
        _bounded_int("capsule_fetched_at", self.fetched_at, minimum=0, maximum=2**63 - 1)
        _bounded_int("capsule_freshness_deadline", self.freshness_deadline, minimum=0, maximum=2**63 - 1)
        if self.freshness_deadline < self.fetched_at:
            raise ValueError("capsule_freshness_window_invalid")
        if type(self.completeness) is not bool:
            raise ValueError("capsule_completeness_invalid")
        _hex("capsule_absence_digest", self.absence_evidence_sha3_512)
        _token("capsule_idempotency_key", self.idempotency_key)
        if not isinstance(self.error_class, str) or not re.fullmatch(r"[A-Z0-9_]{0,64}", self.error_class):
            raise ValueError("capsule_error_class_invalid")
        _hex("capsule_authority_id", self.authority_id_sha3_512)
        if type(self.signatures) is not tuple or len(self.signatures) not in (0, 2):
            raise ValueError("capsule_signature_count_invalid")
        if any(type(item) is not PqSignature for item in self.signatures):
            raise ValueError("capsule_signature_type_invalid")
        if self.signatures and tuple(item.suite_id for item in self.signatures) != DUAL_PQ_SUITES:
            raise ValueError("capsule_signature_suite_order_invalid")
        if len(_canonical_json(self.public_dict())) > MAX_CAPSULE_BYTES:
            raise ValueError("capsule_size_limit_exceeded")

    def unsigned_dict(self) -> dict[str, object]:
        return {
            "schema": WAVE4_CAPSULE_SCHEMA,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "provider_id": self.provider_id,
            "schema_version": self.schema_version,
            "normalization_version": self.normalization_version,
            "jurisdiction": self.jurisdiction,
            "capability": self.capability,
            "endpoint_id": self.endpoint_id,
            "tenant_id": self.tenant_id,
            "cryptographic_profile": self.cryptographic_profile,
            "request_commitment_sha3_512": self.request_commitment_sha3_512,
            "source_bytes_sha3_512": self.source_bytes_sha3_512,
            "source_epoch": self.source_epoch,
            "fetched_at": self.fetched_at,
            "freshness_deadline": self.freshness_deadline,
            "completeness": self.completeness,
            "absence_evidence_sha3_512": self.absence_evidence_sha3_512,
            "idempotency_key": self.idempotency_key,
            "error_class": self.error_class,
            "authority_id_sha3_512": self.authority_id_sha3_512,
        }

    def unsigned_bytes(self) -> bytes:
        return _canonical_json(self.unsigned_dict())

    def public_dict(self) -> dict[str, object]:
        """Return the only serializable response view; private facts are absent."""
        return {
            "schema": WAVE4_CAPSULE_SCHEMA,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "provider_id": self.provider_id,
            "schema_version": self.schema_version,
            "normalization_version": self.normalization_version,
            "jurisdiction": self.jurisdiction,
            "capability": self.capability,
            "endpoint_id": self.endpoint_id,
            "tenant_id": self.tenant_id,
            "cryptographic_profile": self.cryptographic_profile,
            "request_commitment_sha3_512": self.request_commitment_sha3_512,
            "source_bytes_sha3_512": self.source_bytes_sha3_512,
            "source_epoch": self.source_epoch,
            "fetched_at": self.fetched_at,
            "freshness_deadline": self.freshness_deadline,
            "completeness": self.completeness,
            "absence_evidence_sha3_512": self.absence_evidence_sha3_512,
            "idempotency_key": self.idempotency_key,
            "error_class": self.error_class,
            "authority_id_sha3_512": self.authority_id_sha3_512,
            "signatures": [item.canonical_dict() for item in self.signatures],
        }

    @property
    def digest_sha3_512(self) -> str:
        return _digest_hex(b"BL/WAVE4/CAPSULE/V1", self.unsigned_bytes(), _canonical_json(self.public_dict()["signatures"]))


@dataclass(frozen=True, slots=True)
class AdapterResponse:
    capsule: EvidenceCapsule
    status: str
    private_facts: Mapping[str, object] = field(repr=False)

    def __post_init__(self) -> None:
        if self.status not in {"complete", "absent"}:
            raise ValueError("adapter_response_status_invalid")
        if self.status == "complete" and not self.capsule.completeness:
            raise ValueError("adapter_response_complete_mismatch")
        if self.status == "absent" and self.capsule.completeness:
            raise ValueError("adapter_response_absent_mismatch")
        object.__setattr__(self, "private_facts", _mapping_copy(self.private_facts, label="private_facts"))

    def public_event(self) -> dict[str, object]:
        return {"status": self.status, "capsule": self.capsule.public_dict()}


class AdapterPort(Protocol):
    identity: AdapterIdentity

    def fetch(self, request: AdapterRequest) -> AdapterResponse: ...


@dataclass(frozen=True, slots=True)
class SyntheticFixture:
    capability: str
    lookup_key: str
    source_bytes: bytes
    private_facts: Mapping[str, object]
    source_epoch: int = 1
    freshness_deadline: int = 2**31
    complete: bool = True
    absence_reason: str = ""

    def __post_init__(self) -> None:
        _capability(self.capability)
        _private_lookup(self.lookup_key)
        if type(self.source_bytes) is not bytes or not self.source_bytes or len(self.source_bytes) > MAX_SOURCE_BYTES:
            raise ValueError("synthetic_fixture_source_bounds_invalid")
        object.__setattr__(self, "private_facts", _mapping_copy(self.private_facts, label="synthetic_fixture_private_facts"))
        _bounded_int("synthetic_fixture_source_epoch", self.source_epoch, minimum=1, maximum=2**63 - 1)
        _bounded_int("synthetic_fixture_freshness_deadline", self.freshness_deadline, minimum=0, maximum=2**63 - 1)
        if type(self.complete) is not bool:
            raise ValueError("synthetic_fixture_complete_invalid")
        if not self.complete and not re.fullmatch(r"[A-Z0-9_]{1,64}", self.absence_reason):
            raise ValueError("synthetic_fixture_absence_reason_invalid")


class SyntheticAdapter:
    """Immutable, networkless adapter used by the Wave 4 sandbox."""

    __slots__ = ("identity", "authenticator", "_fixtures", "_responses", "_clock", "_max_cached_responses")

    def __init__(
        self,
        identity: AdapterIdentity,
        *,
        authenticator: DualPqAuthenticator,
        fixtures: Sequence[SyntheticFixture],
        clock: Callable[[], int] | None = None,
        max_cached_responses: int = MAX_IDEMPOTENCY_RECORDS,
    ) -> None:
        if type(identity) is not AdapterIdentity:
            raise TypeError("synthetic_adapter_identity_required")
        if type(authenticator) is not DualPqAuthenticator:
            raise TypeError("synthetic_adapter_dual_pq_authenticator_required")
        if identity.capability not in REQUIRED_CAPABILITIES:
            raise ValueError("synthetic_adapter_capability_not_in_wave4_contract")
        checked = tuple(fixtures)
        if not checked or any(type(item) is not SyntheticFixture for item in checked):
            raise ValueError("synthetic_adapter_fixtures_invalid")
        if any(item.capability != identity.capability for item in checked):
            raise ValueError("synthetic_adapter_fixture_capability_mismatch")
        keys = tuple(item.lookup_key for item in checked)
        if len(set(keys)) != len(keys):
            raise ValueError("synthetic_adapter_fixture_duplicate")
        self._max_cached_responses = _bounded_int(
            "synthetic_adapter_max_cached_responses",
            max_cached_responses,
            minimum=1,
            maximum=MAX_IDEMPOTENCY_RECORDS,
        )
        self.identity = identity
        self.authenticator = authenticator
        self._fixtures = MappingProxyType({item.lookup_key: item for item in checked})
        self._responses: dict[str, tuple[str, AdapterResponse]] = {}
        self._clock = clock or (lambda: 0)

    def _capsule(
        self,
        request: AdapterRequest,
        *,
        source_digest: str,
        source_epoch: int,
        fetched_at: int,
        freshness_deadline: int,
        complete: bool,
        absence_reason: str,
    ) -> EvidenceCapsule:
        error = "" if complete else absence_reason
        unsigned = EvidenceCapsule(
            adapter_id=self.identity.adapter_id,
            adapter_version=self.identity.adapter_version,
            provider_id=self.identity.provider_id,
            schema_version=self.identity.schema_version,
            normalization_version=self.identity.normalization_version,
            jurisdiction=self.identity.jurisdiction,
            capability=self.identity.capability,
            endpoint_id=self.identity.endpoint_id,
            tenant_id=self.identity.tenant_id,
            cryptographic_profile=self.identity.cryptographic_profile,
            request_commitment_sha3_512=request.query_commitment_sha3_512,
            source_bytes_sha3_512=source_digest,
            source_epoch=source_epoch,
            fetched_at=fetched_at,
            freshness_deadline=freshness_deadline,
            completeness=complete,
            absence_evidence_sha3_512=_digest_hex(
                b"BL/WAVE4/ABSENCE/V1",
                self.identity.capability.encode("ascii"),
                request.query_commitment_sha3_512.encode("ascii"),
                error.encode("ascii"),
            ),
            idempotency_key=request.idempotency_key,
            error_class=error,
            authority_id_sha3_512=self.authenticator.authority_id_sha3_512,
            signatures=(),
        )
        return replace(unsigned, signatures=self.authenticator.sign(unsigned.unsigned_bytes()))

    def fetch(self, request: AdapterRequest) -> AdapterResponse:
        if type(request) is not AdapterRequest:
            raise TypeError("synthetic_adapter_request_required")
        if request.capability != self.identity.capability:
            raise Wave4AdapterError("adapter_capability_mismatch")
        request_digest = request.request_digest_sha3_512
        existing = self._responses.get(request.idempotency_key)
        if existing is not None:
            previous_digest, previous_response = existing
            if previous_digest != request_digest:
                raise Wave4AdapterError("adapter_idempotency_conflict")
            return previous_response
        if len(self._responses) >= self._max_cached_responses:
            raise Wave4AdapterError("adapter_idempotency_capacity_exceeded")
        now = _bounded_int("adapter_clock", self._clock(), minimum=0, maximum=2**63 - 1)
        fixture = self._fixtures.get(request._lookup_key)
        if fixture is None:
            capsule = self._capsule(
                request,
                source_digest=_digest_hex(b"BL/WAVE4/EMPTY-SOURCE/V1"),
                source_epoch=request.requested_epoch,
                fetched_at=now,
                freshness_deadline=now,
                complete=False,
                absence_reason="SOURCE_MISSING",
            )
            response = AdapterResponse(capsule, "absent", {})
        elif fixture.source_epoch < request.requested_epoch:
            capsule = self._capsule(
                request,
                source_digest=_digest_hex(fixture.source_bytes),
                source_epoch=fixture.source_epoch,
                fetched_at=now,
                freshness_deadline=min(fixture.freshness_deadline, now),
                complete=False,
                absence_reason="SOURCE_STALE",
            )
            response = AdapterResponse(capsule, "absent", {})
        elif fixture.freshness_deadline < now:
            capsule = self._capsule(
                request,
                source_digest=_digest_hex(fixture.source_bytes),
                source_epoch=fixture.source_epoch,
                fetched_at=now,
                freshness_deadline=fixture.freshness_deadline,
                complete=False,
                absence_reason="SOURCE_EXPIRED",
            )
            response = AdapterResponse(capsule, "absent", {})
        elif not fixture.complete:
            capsule = self._capsule(
                request,
                source_digest=_digest_hex(fixture.source_bytes),
                source_epoch=fixture.source_epoch,
                fetched_at=now,
                freshness_deadline=fixture.freshness_deadline,
                complete=False,
                absence_reason=fixture.absence_reason,
            )
            response = AdapterResponse(capsule, "absent", {})
        else:
            capsule = self._capsule(
                request,
                source_digest=_digest_hex(fixture.source_bytes),
                source_epoch=fixture.source_epoch,
                fetched_at=now,
                freshness_deadline=fixture.freshness_deadline,
                complete=True,
                absence_reason="",
            )
            response = AdapterResponse(capsule, "complete", fixture.private_facts)
        self.verify(response)
        self._responses[request.idempotency_key] = (request_digest, response)
        return response

    def verify(self, response: AdapterResponse) -> None:
        capsule = response.capsule
        if capsule.adapter_id != self.identity.adapter_id or capsule.adapter_version != self.identity.adapter_version:
            raise Wave4AdapterError("adapter_response_identity_mismatch")
        if capsule.authority_id_sha3_512 != self.authenticator.authority_id_sha3_512:
            raise Wave4AdapterError("adapter_response_authority_mismatch")
        if not self.authenticator.verify(message=capsule.unsigned_bytes(), signatures=capsule.signatures):
            raise Wave4AdapterError("adapter_response_pq_authentication_failed")


@dataclass(frozen=True, slots=True)
class CredentialHandle:
    provider_id: str
    handle_id: str
    root_digest_sha3_512: str
    expires_at: int

    def __post_init__(self) -> None:
        _source_id(self.provider_id)
        _identifier("credential_handle_id", self.handle_id)
        _hex("credential_root_digest", self.root_digest_sha3_512)
        _bounded_int("credential_expires_at", self.expires_at, minimum=0, maximum=2**63 - 1)


class SyntheticCredentialPort:
    """Credential simulator exposing handles only; raw credentials never leave it."""

    network_access: Final[bool] = False
    accepts_live_credentials: Final[bool] = False

    def __init__(self, provider_id: str, *, clock: Callable[[], int] | None = None) -> None:
        self.provider_id = _source_id(provider_id)
        self._clock = clock or (lambda: 0)

    def handle(self, capability: str, *, ttl_seconds: int = 300) -> CredentialHandle:
        cap = _capability(capability)
        ttl = _bounded_int("credential_ttl_seconds", ttl_seconds, minimum=1, maximum=86_400)
        handle_id = _identifier("credential_handle_id", f"SYNTHETIC-CREDENTIAL-{cap.upper()}")
        root = _digest_hex(b"BL/WAVE4/CREDENTIAL-ROOT/V1", self.provider_id.encode("ascii"), cap.encode("ascii"))
        return CredentialHandle(self.provider_id, handle_id, root, self._clock() + ttl)

    def read_secret(self, handle: CredentialHandle) -> bytes:
        if type(handle) is not CredentialHandle:
            raise Wave4AdapterError("credential_handle_invalid")
        raise Wave4AdapterError("synthetic_credential_secret_unavailable")


class SyntheticTransport:
    """Deterministic transport simulator with explicit retry injection."""

    network_access: Final[bool] = False

    def __init__(self, responses: Mapping[str, bytes], *, transient_failures: Mapping[str, int] | None = None) -> None:
        if not isinstance(responses, Mapping) or len(responses) > MAX_TRANSPORT_RESPONSES:
            raise ValueError("synthetic_transport_response_bounds_invalid")
        checked_responses: dict[str, bytes] = {}
        for key, value in responses.items():
            _hex("transport_response_key", key)
            if type(value) is not bytes or len(value) > MAX_SOURCE_BYTES:
                raise ValueError("synthetic_transport_response_bounds_invalid")
            checked_responses[key] = value
        self._responses = MappingProxyType(checked_responses)
        self._remaining = {key: _bounded_int("transient_failure_count", value, minimum=0, maximum=MAX_RETRY_ATTEMPTS) for key, value in dict(transient_failures or {}).items()}

    def fetch(self, request_digest_sha3_512: str) -> bytes:
        _hex("transport_request_digest", request_digest_sha3_512)
        remaining = self._remaining.get(request_digest_sha3_512, 0)
        if remaining:
            self._remaining[request_digest_sha3_512] = remaining - 1
            raise RetryableAdapterError("synthetic_transport_transient_failure")
        try:
            value = self._responses[request_digest_sha3_512]
        except KeyError as exc:
            raise Wave4AdapterError("synthetic_transport_response_missing") from exc
        if type(value) is not bytes or len(value) > MAX_SOURCE_BYTES:
            raise Wave4AdapterError("synthetic_transport_response_bounds_invalid")
        return value


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_ms: int = 5
    max_delay_ms: int = 100
    jitter_ms: int = 1

    def __post_init__(self) -> None:
        _bounded_int("retry_max_attempts", self.max_attempts, minimum=1, maximum=MAX_RETRY_ATTEMPTS)
        _bounded_int("retry_base_delay_ms", self.base_delay_ms, minimum=0, maximum=10_000)
        _bounded_int("retry_max_delay_ms", self.max_delay_ms, minimum=self.base_delay_ms, maximum=60_000)
        _bounded_int("retry_jitter_ms", self.jitter_ms, minimum=0, maximum=1_000)

    def delays(self) -> tuple[int, ...]:
        return tuple(
            min(self.max_delay_ms, self.base_delay_ms * (2**attempt)) + (attempt % (self.jitter_ms + 1) if self.jitter_ms else 0)
            for attempt in range(self.max_attempts - 1)
        )


def retry_call(
    operation: Callable[[], object],
    policy: RetryPolicy,
    *,
    sleep: Callable[[float], None] | None = None,
) -> object:
    """Retry only explicitly retryable failures with bounded deterministic jitter."""
    pause = sleep or (lambda seconds: None)
    last: RetryableAdapterError | None = None
    for attempt in range(policy.max_attempts):
        try:
            return operation()
        except RetryableAdapterError as exc:
            last = exc
            if attempt + 1 == policy.max_attempts:
                break
            pause(policy.delays()[attempt] / 1000.0)
    raise RetryableAdapterError("adapter_retry_exhausted") from last


class CircuitBreaker:
    """Small fail-closed circuit breaker for adapter transport health."""

    __slots__ = ("failure_threshold", "cooldown_seconds", "_failures", "_opened_at")

    def __init__(self, *, failure_threshold: int = 3, cooldown_seconds: int = 30) -> None:
        self.failure_threshold = _bounded_int("circuit_failure_threshold", failure_threshold, minimum=1, maximum=32)
        self.cooldown_seconds = _bounded_int("circuit_cooldown_seconds", cooldown_seconds, minimum=1, maximum=86_400)
        self._failures = 0
        self._opened_at: int | None = None

    @property
    def open(self) -> bool:
        return self._opened_at is not None

    def before_call(self, *, now: int) -> None:
        _bounded_int("circuit_now", now, minimum=0, maximum=2**63 - 1)
        if self._opened_at is not None and now - self._opened_at < self.cooldown_seconds:
            raise RetryableAdapterError("adapter_circuit_open")
        if self._opened_at is not None:
            self._opened_at = None
            self._failures = 0

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self, *, now: int) -> None:
        _bounded_int("circuit_failure_now", now, minimum=0, maximum=2**63 - 1)
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._opened_at = now


class AdapterRegistry:
    """Versioned registry that rejects unknown and downgraded adapter selection."""

    def __init__(self) -> None:
        self._adapters: dict[tuple[str, str, int], AdapterPort] = {}

    def register(self, adapter: AdapterPort) -> None:
        identity = getattr(adapter, "identity", None)
        if type(identity) is not AdapterIdentity:
            raise ValueError("adapter_registry_identity_missing")
        key = (identity.capability, identity.adapter_id, identity.adapter_version)
        if key in self._adapters:
            raise ValueError("adapter_registry_duplicate_identity")
        self._adapters[key] = adapter

    def capabilities(self) -> tuple[str, ...]:
        return tuple(sorted({key[0] for key in self._adapters}))

    def _versions(self, capability: str) -> tuple[AdapterIdentity, ...]:
        return tuple(
            sorted(
                (adapter.identity for adapter in self._adapters.values() if adapter.identity.capability == capability),
                key=lambda item: (item.adapter_id, item.adapter_version),
            )
        )

    def resolve(self, capability: str, *, adapter_id: str | None = None, version: int | None = None) -> AdapterPort:
        cap = _capability(capability)
        candidates = [
            adapter
            for adapter in self._adapters.values()
            if adapter.identity.capability == cap and (adapter_id is None or adapter.identity.adapter_id == adapter_id)
        ]
        if not candidates:
            raise Wave4AdapterError("adapter_registry_capability_unavailable")
        newest = max(item.identity.adapter_version for item in candidates)
        if version is not None:
            _bounded_int("adapter_version_selection", version, minimum=1, maximum=255)
            if version < newest:
                raise AdapterDowngradeError("adapter_registry_downgrade_rejected")
            candidates = [item for item in candidates if item.identity.adapter_version == version]
        else:
            candidates = [item for item in candidates if item.identity.adapter_version == newest]
        if not candidates:
            raise Wave4AdapterError("adapter_registry_version_unavailable")
        return sorted(candidates, key=lambda item: item.identity.adapter_id)[0]

    def _resolve_exact(self, capability: str, version: int) -> AdapterPort:
        cap = _capability(capability)
        _bounded_int("adapter_version_selection", version, minimum=1, maximum=255)
        candidates = [
            adapter
            for adapter in self._adapters.values()
            if adapter.identity.capability == cap and adapter.identity.adapter_version == version
        ]
        if not candidates:
            raise Wave4AdapterError("adapter_registry_version_unavailable")
        return sorted(candidates, key=lambda item: item.identity.adapter_id)[0]

    def migrate(self, capability: str, *, from_version: int, to_version: int) -> str:
        if to_version != from_version + 1:
            raise ValueError("adapter_registry_migration_must_be_successor")
        old = self._resolve_exact(capability, from_version)
        new = self._resolve_exact(capability, to_version)
        return _digest_hex(
            b"BL/WAVE4/ADAPTER-MIGRATION/V1",
            old.identity.canonical_bytes(),
            new.identity.canonical_bytes(),
        )

    def assert_complete(self) -> None:
        missing = sorted(REQUIRED_CAPABILITIES.difference(self.capabilities()))
        if missing:
            raise Wave4AdapterError("adapter_registry_missing_capabilities:" + ",".join(missing))


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    passed: tuple[str, ...]
    failures: tuple[str, ...]
    skipped: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.failures


def build_synthetic_registry(authenticator: DualPqAuthenticator, *, clock: Callable[[], int] | None = None) -> AdapterRegistry:
    """Build every I02-I07 capability over immutable local fixtures."""
    if type(authenticator) is not DualPqAuthenticator:
        raise TypeError("wave4_synthetic_registry_dual_pq_authenticator_required")
    registry = AdapterRegistry()
    for capability in sorted(REQUIRED_CAPABILITIES):
        identity = AdapterIdentity(
            provider_id="SYNTHETIC-WAVE4-PROVIDER",
            adapter_id=f"SYNTHETIC-WAVE4-{capability.upper().replace('-', '_')}-V1",
            adapter_version=1,
            schema_version="BL-WAVE4-SCHEMA-V1",
            normalization_version=1,
            jurisdiction="SYNTHETIC-LOCAL",
            capability=capability,
            endpoint_id="SYNTHETIC-ENDPOINT-WAVE4",
            tenant_id="SYNTHETIC-TENANT-WAVE4",
        )
        lookup = f"SYNTHETIC-FIXTURE-{capability.upper().replace('-', '_')}"
        fixture = SyntheticFixture(
            capability=capability,
            lookup_key=lookup,
            source_bytes=_canonical_json(
                {
                    "fixture": lookup,
                    "schema": "BL-WAVE4-FIXTURE-V1",
                    "capability": capability,
                }
            ),
            private_facts={"fixture_present": True, "capability": capability},
        )
        registry.register(SyntheticAdapter(identity, authenticator=authenticator, fixtures=(fixture,), clock=clock))
    return registry


def run_adapter_conformance(registry: AdapterRegistry, *, now: int = 0) -> ConformanceReport:
    """Run the shared I08 contract over every registered Wave 4 capability."""
    passed: list[str] = []
    failures: list[str] = []
    try:
        registry.assert_complete()
        passed.append("required_capabilities")
    except Wave4AdapterError as exc:
        failures.append(str(exc))
        return ConformanceReport(tuple(passed), tuple(failures))
    for capability in sorted(REQUIRED_CAPABILITIES):
        adapter = registry.resolve(capability)
        lookup = f"SYNTHETIC-FIXTURE-{capability.upper().replace('-', '_')}"
        request = AdapterRequest.create(
            request_id=f"SYNTHETIC-REQUEST-{capability.upper().replace('-', '_')}",
            capability=capability,
            lookup_key=lookup,
            idempotency_key=f"SYNTHETIC-IDEMPOTENCY-{capability.upper().replace('-', '_')}",
        )
        try:
            response = adapter.fetch(request)
            adapter.verify(response)  # type: ignore[attr-defined]
            if response.status != "complete" or response.capsule.error_class:
                raise Wave4AdapterError("successful_fixture_not_complete")
            public = response.public_event()
            encoded = _canonical_json(public)
            if len(encoded) > MAX_CAPSULE_BYTES:
                raise Wave4AdapterError("capsule_size_limit_exceeded")
            if any(key in public for key in {"private_facts", "source_bytes", "payload", "raw_response"}):
                raise Wave4AdapterError("private_response_field_in_public_capsule")
            if response.private_facts.get("fixture_present") is not True:
                raise Wave4AdapterError("private_fixture_fact_missing")
            repeat = adapter.fetch(request)
            if repeat.public_event() != public:
                raise Wave4AdapterError("idempotent_retry_changed_capsule")
            passed.extend((f"{capability}:authentication", f"{capability}:idempotency", f"{capability}:privacy"))
        except Exception as exc:
            failures.append(f"{capability}:{type(exc).__name__}:{exc}")
    return ConformanceReport(tuple(passed), tuple(failures))


__all__ = (
    "AdapterDowngradeError",
    "AdapterIdentity",
    "AdapterPort",
    "AdapterRegistry",
    "AdapterRequest",
    "AdapterResponse",
    "CircuitBreaker",
    "ConformanceReport",
    "CredentialHandle",
    "DUAL_PQ_SUITES",
    "DualPqAuthenticator",
    "EvidenceCapsule",
    "ML_DSA_87",
    "PqSignature",
    "PqcryptoSoftwareSigner",
    "REQUIRED_CAPABILITIES",
    "RetryPolicy",
    "RetryableAdapterError",
    "SLH_DSA_SHAKE_256F",
    "SyntheticAdapter",
    "SyntheticCredentialPort",
    "SyntheticFixture",
    "SyntheticTransport",
    "WAVE4_ADAPTER_SDK_SCHEMA",
    "WAVE4_CAPSULE_SCHEMA",
    "WAVE4_CRYPTO_PROFILE",
    "Wave4AdapterError",
    "build_synthetic_registry",
    "retry_call",
    "run_adapter_conformance",
)
