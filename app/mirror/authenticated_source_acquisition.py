"""Durable, transport-neutral acquisition of the synthetic NC FHIR fixture.

This module owns scheduling, leases, bounded fetch composition, and the small
acquisition ledger.  NC FHIR parsing, generic external evidence semantics, and
durable quarantine remain owned by their existing modules.  No network client,
credential, raw response, raw envelope, or raw external artifact crosses the
ledger boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Callable, Mapping, Protocol

from app.mirror import external_source_adapter as external_adapter
from app.mirror import external_source_adapter_independent as external_independent
from app.mirror import external_source_quarantine as quarantine
from app.mirror import nc_medicaid_fhir as nc_fhir
from app.mirror import nc_medicaid_fhir_independent as nc_independent
from app.mirror import nc_medicaid_fhir_profile as nc_profile_module
from app.mirror import authenticated_source_acquisition_independent as independent


SCHEMA = independent.SCHEMA
SCHEMA_VERSION = independent.SCHEMA_VERSION
EXPORT_SCHEMA = independent.EXPORT_SCHEMA
EXPORT_VERSION = independent.EXPORT_VERSION
STATES = independent.STATES
SAFE_FAILURES = independent.SAFE_FAILURES
BUSY_TIMEOUT_MS = independent.BUSY_TIMEOUT_MS
MAX_EXPORT_BYTES = independent.MAX_EXPORT_BYTES
GENESIS_TRANSITION = independent.GENESIS_TRANSITION
HEX128 = independent.HEX128
SAFE_TEXT = independent.SAFE_TEXT

DDL = (
    "CREATE TABLE acquisition_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE acquisition_slots ("
    "slot_id TEXT PRIMARY KEY, scheduled_at INTEGER NOT NULL, state TEXT NOT NULL, "
    "lease_id TEXT, lease_until INTEGER, attempt INTEGER NOT NULL, envelope_id TEXT, "
    "envelope_digest TEXT, artifact_id TEXT, artifact_digest TEXT, capture_id TEXT, "
    "payload_digest TEXT, snapshot_root TEXT, observed_at INTEGER, fetched_at INTEGER, "
    "quarantine_expected_head TEXT, quarantine_head TEXT, quarantine_head_root TEXT, "
    "quarantine_transition_id TEXT, quarantine_receipt_digest TEXT, quarantine_receipt_raw BLOB, "
    "failure_code TEXT, last_operation_id TEXT)",
    "CREATE TABLE acquisition_operations ("
    "operation_id TEXT PRIMARY KEY, slot_id TEXT NOT NULL, action TEXT NOT NULL, attempt INTEGER NOT NULL, "
    "request_digest TEXT NOT NULL, material_digest TEXT NOT NULL, transition_id TEXT NOT NULL, "
    "receipt_digest TEXT NOT NULL, sequence INTEGER NOT NULL, receipt_raw BLOB NOT NULL, "
    "FOREIGN KEY(slot_id) REFERENCES acquisition_slots(slot_id))",
    "CREATE TABLE acquisition_transitions ("
    "transition_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, slot_id TEXT NOT NULL, operation_id TEXT NOT NULL, "
    "prior_state TEXT NOT NULL, next_state TEXT NOT NULL, before_root TEXT NOT NULL, after_root TEXT NOT NULL, "
    "material_digest TEXT NOT NULL, observed_at INTEGER NOT NULL, transition_raw BLOB NOT NULL, "
    "FOREIGN KEY(slot_id) REFERENCES acquisition_slots(slot_id), FOREIGN KEY(operation_id) REFERENCES acquisition_operations(operation_id))",
    "CREATE TABLE acquisition_attestations ("
    "slot_id TEXT NOT NULL, page_index INTEGER NOT NULL, attempt INTEGER NOT NULL, request_digest TEXT NOT NULL, "
    "server_identity_digest TEXT NOT NULL, authorization_artifact_digest TEXT NOT NULL, terms_artifact_digest TEXT NOT NULL, "
    "response_digest TEXT NOT NULL, status INTEGER NOT NULL, media_type TEXT NOT NULL, observed_at INTEGER NOT NULL, "
    "fetched_at INTEGER NOT NULL, redirect INTEGER NOT NULL, transport_authenticated INTEGER NOT NULL, "
    "attestation_digest TEXT NOT NULL, PRIMARY KEY(slot_id,page_index,attempt), FOREIGN KEY(slot_id) REFERENCES acquisition_slots(slot_id))",
    "CREATE INDEX acquisition_slots_due_idx ON acquisition_slots(state,scheduled_at,slot_id)",
    "CREATE INDEX acquisition_transitions_sequence_idx ON acquisition_transitions(sequence)",
)


class AuthenticatedSourceAcquisitionError(ValueError):
    """Base class for bounded acquisition failures."""


class AcquisitionConflictError(AuthenticatedSourceAcquisitionError):
    """Identity, lease, lifecycle, or stale-head conflict."""


class AcquisitionBusyError(AuthenticatedSourceAcquisitionError):
    """Finite SQLite busy budget was exceeded."""


class AcquisitionResponseLost(AuthenticatedSourceAcquisitionError):
    """Post-commit response loss; exact retry is required."""


class AcquisitionInjectedFault(AuthenticatedSourceAcquisitionError):
    """Test-only precommit fault."""


class AcquisitionHold(AuthenticatedSourceAcquisitionError):
    """A bounded source/evidence condition that cannot be quarantined."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise AuthenticatedSourceAcquisitionError("acquisition:noncanonical") from exc


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update((independent.DOMAIN + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha3_512(raw).hexdigest()


def _safe(value: object, label: str) -> str:
    try:
        return independent._safe(value, label)
    except independent.IndependentAcquisitionError as exc:
        raise AuthenticatedSourceAcquisitionError(str(exc)) from exc


def _hex(value: object, label: str) -> str:
    try:
        return independent._hex(value, label)
    except independent.IndependentAcquisitionError as exc:
        raise AuthenticatedSourceAcquisitionError(str(exc)) from exc


def _int(value: object, label: str, *, minimum: int = 0, maximum: int = 2_147_483_647) -> int:
    try:
        return independent._int(value, label, minimum=minimum, maximum=maximum)
    except independent.IndependentAcquisitionError as exc:
        raise AuthenticatedSourceAcquisitionError(str(exc)) from exc


@dataclass(frozen=True)
class AuthenticatedSourceAcquisitionConfigV1:
    acquisition_id: str
    version: int
    nc_profile_digest: str
    external_policy_digest: str
    quarantine_policy_digest: str
    quarantine_chain_id: str
    quarantine_database_id: str
    transport_id: str
    transport_epoch: int
    authorization_artifact_digest: str
    terms_artifact_digest: str
    endpoint_id: str
    request_digest: str
    cadence_seconds: int
    freshness_grace_seconds: int
    max_body_bytes: int
    max_page_count: int
    max_attempts: int = 3
    lease_seconds: int = 60
    busy_timeout_ms: int = BUSY_TIMEOUT_MS
    max_slots: int = 128
    zero_phi: bool = True
    state_owned: bool = True
    live_transport_authorized: bool = False
    production_source_authentication: bool = False
    production_usable: bool = False
    activation: bool = False
    proofSuiteId: None = None

    def __post_init__(self) -> None:
        try:
            independent._config_view(self)
        except independent.IndependentAcquisitionError as exc:
            raise AuthenticatedSourceAcquisitionError(str(exc)) from exc
        if self.nc_profile_digest != nc_profile_module.NC_MEDICAID_PROFILE.profile_digest:
            raise AuthenticatedSourceAcquisitionError("acquisition:profile-drift")
        if self.max_body_bytes > nc_profile_module.NC_MEDICAID_PROFILE.transport_caps["max_page_bytes"]:
            raise AuthenticatedSourceAcquisitionError("acquisition:body-cap")
        if self.max_page_count > nc_profile_module.NC_MEDICAID_PROFILE.transport_caps["max_pages"]:
            raise AuthenticatedSourceAcquisitionError("acquisition:page-cap")
        if self.request_digest != request_digest_for_profile():
            raise AuthenticatedSourceAcquisitionError("acquisition:request-binding")

    def material(self) -> dict[str, object]:
        return {
            "acquisition_id": self.acquisition_id, "version": self.version,
            "nc_profile_digest": self.nc_profile_digest, "external_policy_digest": self.external_policy_digest,
            "quarantine_policy_digest": self.quarantine_policy_digest, "quarantine_chain_id": self.quarantine_chain_id,
            "quarantine_database_id": self.quarantine_database_id, "transport_id": self.transport_id,
            "transport_epoch": self.transport_epoch, "authorization_artifact_digest": self.authorization_artifact_digest,
            "terms_artifact_digest": self.terms_artifact_digest, "endpoint_id": self.endpoint_id,
            "request_digest": self.request_digest, "cadence_seconds": self.cadence_seconds,
            "freshness_grace_seconds": self.freshness_grace_seconds, "max_body_bytes": self.max_body_bytes,
            "max_page_count": self.max_page_count, "max_attempts": self.max_attempts,
            "lease_seconds": self.lease_seconds, "busy_timeout_ms": self.busy_timeout_ms,
            "max_slots": self.max_slots, "zero_phi": self.zero_phi, "state_owned": self.state_owned,
            "live_transport_authorized": self.live_transport_authorized,
            "production_source_authentication": self.production_source_authentication,
            "production_usable": self.production_usable, "activation": self.activation,
            "proofSuiteId": self.proofSuiteId,
        }

    @property
    def digest(self) -> str:
        return independent._config_digest(self.material())


def request_digest_for_page(page_index: int, *, profile=nc_profile_module.NC_MEDICAID_PROFILE) -> str:
    _int(page_index, "page-index", maximum=profile.transport_caps["max_pages"] - 1)
    return _digest("request", {"method": "GET", "url": profile.page_url(page_index), "page_index": page_index})


def request_digest_for_profile(*, profile=nc_profile_module.NC_MEDICAID_PROFILE) -> str:
    return request_digest_for_page(0, profile=profile)


@dataclass(frozen=True)
class AuthenticatedFhirRequestV1:
    page_index: int
    attempt: int
    method: str
    url: str
    timeout_seconds: int
    max_body_bytes: int
    profile_digest: str
    endpoint_id: str
    request_digest: str


@dataclass(frozen=True)
class FhirTransportAttestationV1:
    transport_id: str
    transport_epoch: int
    page_index: int
    attempt: int
    request_digest: str
    server_identity_digest: str
    authorization_artifact_digest: str
    terms_artifact_digest: str
    response_digest: str
    status: int
    media_type: str
    observed_at: int
    fetched_at: int
    redirect: bool
    transport_authenticated: bool
    attestation_digest: str

    def material(self) -> dict[str, object]:
        return {
            "transport_id": self.transport_id, "transport_epoch": self.transport_epoch,
            "page_index": self.page_index, "attempt": self.attempt, "request_digest": self.request_digest,
            "server_identity_digest": self.server_identity_digest,
            "authorization_artifact_digest": self.authorization_artifact_digest,
            "terms_artifact_digest": self.terms_artifact_digest, "response_digest": self.response_digest,
            "status": self.status, "media_type": self.media_type, "observed_at": self.observed_at,
            "fetched_at": self.fetched_at, "redirect": self.redirect,
            "transport_authenticated": self.transport_authenticated,
        }

    @property
    def expected_digest(self) -> str:
        return _digest("transport-attestation", self.material())

    def __post_init__(self) -> None:
        _safe(self.transport_id, "transport-id")
        _int(self.transport_epoch, "transport-epoch", maximum=1_000_000)
        _int(self.page_index, "page-index", maximum=nc_profile_module.NC_MEDICAID_PROFILE.transport_caps["max_pages"] - 1)
        _int(self.attempt, "attempt", maximum=3)
        _hex(self.request_digest, "request-digest")
        _hex(self.server_identity_digest, "server-identity")
        _hex(self.authorization_artifact_digest, "authorization-digest")
        _hex(self.terms_artifact_digest, "terms-digest")
        _hex(self.response_digest, "response-digest")
        _int(self.status, "status", minimum=100, maximum=599)
        if self.media_type != nc_profile_module.ALLOWED_MEDIA_TYPE:
            raise AuthenticatedSourceAcquisitionError("acquisition:media-type")
        _int(self.observed_at, "observed-at", minimum=1)
        _int(self.fetched_at, "fetched-at", minimum=1)
        if self.fetched_at < self.observed_at or type(self.redirect) is not bool or type(self.transport_authenticated) is not bool:
            raise AuthenticatedSourceAcquisitionError("acquisition:attestation-fields")
        _hex(self.attestation_digest, "attestation-digest")
        if self.attestation_digest != self.expected_digest:
            raise AuthenticatedSourceAcquisitionError("acquisition:attestation-digest")


@dataclass(frozen=True)
class AuthenticatedFhirResponseV1:
    body: bytes
    attestation: FhirTransportAttestationV1


class AuthenticatedFhirTransportPort(Protocol):
    """Injected transport; credentials and authentication stay inside it."""

    transport_id: str
    transport_epoch: int

    def fetch(self, request: AuthenticatedFhirRequestV1) -> AuthenticatedFhirResponseV1:
        ...


class LiveAuthenticatedFhirTransport:
    """Live-shaped port that fails before any network operation."""

    transport_id = "LIVE_TRANSPORT_DISABLED"
    transport_epoch = 0

    def fetch(self, request: AuthenticatedFhirRequestV1) -> AuthenticatedFhirResponseV1:
        del request
        raise AuthenticatedSourceAcquisitionError("acquisition:live-transport-disabled")


@dataclass(frozen=True)
class AcquisitionLease:
    slot_id: str
    lease_id: str
    attempt: int
    lease_until: int
    scheduled_at: int


def _attestation_row(attestation: FhirTransportAttestationV1, *, slot_id: str) -> dict[str, object]:
    value = attestation.material()
    value["slot_id"] = slot_id
    value.pop("transport_id", None)
    value.pop("transport_epoch", None)
    value["redirect"] = int(bool(value["redirect"]))
    value["transport_authenticated"] = int(bool(value["transport_authenticated"]))
    value["attestation_digest"] = attestation.attestation_digest
    return value


class _AuthenticatedTransportAdapter:
    """Adapter from the existing NC FHIR transport shape to the typed port."""

    def __init__(self, service: "AuthenticatedSourceAcquisitionService", port: AuthenticatedFhirTransportPort) -> None:
        self.service = service
        self.port = port
        self.attestations: dict[tuple[int, int], FhirTransportAttestationV1] = {}

    def fetch(self, request_url: str, *, timeout_seconds: int, attempt: int) -> nc_fhir.FhirTransportResponse:
        profile = self.service.profile
        page_index = next((index for index in range(self.service.config.max_page_count) if profile.page_url(index) == request_url), None)
        if page_index is None:
            raise nc_fhir.FhirTransportError("wrong-host")
        request = AuthenticatedFhirRequestV1(
            page_index=page_index, attempt=attempt, method="GET", url=request_url,
            timeout_seconds=timeout_seconds, max_body_bytes=self.service.config.max_body_bytes,
            profile_digest=self.service.config.nc_profile_digest, endpoint_id=self.service.config.endpoint_id,
            request_digest=request_digest_for_page(page_index, profile=profile),
        )
        if page_index == 0 and request.request_digest != self.service.config.request_digest:
            raise nc_fhir.FhirTransportError("request-mismatch")
        try:
            response = self.port.fetch(request)
        except nc_fhir.FhirTransportError:
            raise
        except AuthenticatedSourceAcquisitionError as exc:
            raise nc_fhir.FhirTransportError(str(exc).split(":", 1)[-1]) from exc
        except Exception as exc:
            raise nc_fhir.FhirTransportError("transport") from exc
        if not isinstance(response, AuthenticatedFhirResponseV1) or type(response.body) is not bytes:
            raise nc_fhir.FhirTransportError("transport")
        if len(response.body) > self.service.config.max_body_bytes:
            raise nc_fhir.FhirTransportError("body-cap")
        try:
            attestation = response.attestation
            if attestation.transport_id != self.service.config.transport_id or attestation.transport_epoch != self.service.config.transport_epoch:
                raise AuthenticatedSourceAcquisitionError("acquisition:transport-mismatch")
            if attestation.page_index != page_index or attestation.attempt != attempt or attestation.request_digest != request.request_digest:
                raise AuthenticatedSourceAcquisitionError("acquisition:request-mismatch")
            if attestation.authorization_artifact_digest != self.service.config.authorization_artifact_digest or attestation.terms_artifact_digest != self.service.config.terms_artifact_digest:
                raise AuthenticatedSourceAcquisitionError("acquisition:authority-mismatch")
            if attestation.server_identity_digest != external_adapter._expected_server_identity(self.service.external_policy):
                raise AuthenticatedSourceAcquisitionError("acquisition:server-identity")
            if attestation.response_digest != hashlib.sha3_512(response.body).hexdigest():
                raise AuthenticatedSourceAcquisitionError("acquisition:response-digest")
            if attestation.redirect:
                raise AuthenticatedSourceAcquisitionError("acquisition:redirect")
        except AuthenticatedSourceAcquisitionError as exc:
            raise nc_fhir.FhirTransportError(str(exc).split(":", 1)[-1]) from exc
        self.attestations[(page_index, attempt)] = attestation
        return nc_fhir.FhirTransportResponse(request_url, attestation.status, attestation.media_type, bytes(response.body))


class _NcCaptureVerifier:
    """Typed bridge from an independently verified NC envelope to the generic adapter."""

    def __init__(self, service: "AuthenticatedSourceAcquisitionService", attestations: Mapping[tuple[int, int], FhirTransportAttestationV1]) -> None:
        self.service = service
        self.attestations = dict(attestations)
        self.verifier_id = service.external_policy.verifier_id
        self.verifier_epoch = service.external_policy.verifier_epoch

    def verify(self, capture_raw: bytes) -> external_adapter.VerifiedExternalCaptureV1:
        try:
            result = nc_independent.verify_bytes(capture_raw, profile=self.service.profile)
        except nc_independent.IndependentNcMedicaidFhirError as exc:
            raise AuthenticatedSourceAcquisitionError("acquisition:nc-verifier") from exc
        page_count = int(result["page_count"])
        selected: list[FhirTransportAttestationV1] = []
        for page_index in range(page_count):
            candidates = [attestation for (index, _attempt), attestation in self.attestations.items() if index == page_index]
            if not candidates:
                raise AuthenticatedSourceAcquisitionError("acquisition:attestation-missing")
            selected.append(sorted(candidates, key=lambda item: item.attempt)[-1])
        page_digests = tuple(sorted(attestation.response_digest for attestation in selected))
        payload_digest = hashlib.sha3_512(capture_raw).hexdigest()
        capture_id = external_independent.capture_id_for_payload(payload_digest)
        transport_authenticated = all(attestation.transport_authenticated for attestation in selected)
        complete = result["source_status"] == "COMPLETE" and result["page_complete"] is True and transport_authenticated
        failure_code = "NONE" if complete else ("INCOMPLETE" if result["source_status"] in {"PARTIAL", "STALE"} else "SOURCE_FAILURE")
        server_identity = external_adapter._expected_server_identity(self.service.external_policy)
        provisional = external_adapter.VerifiedExternalCaptureV1(
            policy_digest=self.service.external_policy.digest,
            verifier_id=self.verifier_id,
            verifier_epoch=self.verifier_epoch,
            capture_id=capture_id,
            payload_sha3_512=payload_digest,
            observed_at=min(attestation.observed_at for attestation in selected),
            fetched_at=max(attestation.fetched_at for attestation in selected),
            page_digests=page_digests,
            page_count=page_count,
            server_identity_digest=server_identity,
            transport_receipt_digest="0" * 128,
            transport_authenticated=transport_authenticated,
            complete=complete,
            failure_code=failure_code,
            zero_phi=True,
        )
        receipt = external_adapter._expected_transport_receipt(self.service.external_policy, provisional, server_identity)
        return external_adapter.VerifiedExternalCaptureV1(
            policy_digest=provisional.policy_digest,
            verifier_id=provisional.verifier_id,
            verifier_epoch=provisional.verifier_epoch,
            capture_id=provisional.capture_id,
            payload_sha3_512=provisional.payload_sha3_512,
            observed_at=provisional.observed_at,
            fetched_at=provisional.fetched_at,
            page_digests=provisional.page_digests,
            page_count=provisional.page_count,
            server_identity_digest=provisional.server_identity_digest,
            transport_receipt_digest=receipt,
            transport_authenticated=provisional.transport_authenticated,
            complete=provisional.complete,
            failure_code=provisional.failure_code,
            zero_phi=True,
        )


def _resolve_database(path: str | Path) -> Path:
    if not isinstance(path, (str, Path)):
        raise AuthenticatedSourceAcquisitionError("acquisition:database-path")
    target = Path(os.path.abspath(os.fspath(path)))
    if not target.name or not target.parent.is_dir() or target.is_symlink() or target.parent.is_symlink():
        raise AuthenticatedSourceAcquisitionError("acquisition:database-path")
    return target


class AuthenticatedSourceAcquisitionService:
    """One configured cadence ledger for the fixed NC source profile."""

    def __init__(
        self,
        database: str | Path,
        *,
        config: AuthenticatedSourceAcquisitionConfigV1,
        external_policy: external_adapter.ExternalSourcePolicyV1,
        quarantine_service: quarantine.ExternalSourceQuarantineService,
        clock: Callable[[], int] | None = None,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        self.database = _resolve_database(database)
        self.config = config
        self.external_policy = external_policy
        self.quarantine_service = quarantine_service
        self.profile = nc_profile_module.NC_MEDICAID_PROFILE
        self.clock = clock or (lambda: self.profile.observation_time)
        self.fault_injector = fault_injector
        if external_policy.digest != config.external_policy_digest:
            raise AuthenticatedSourceAcquisitionError("acquisition:external-policy-drift")
        if quarantine_service.policy_digest != config.quarantine_policy_digest or quarantine_service.chain_id != config.quarantine_chain_id:
            raise AuthenticatedSourceAcquisitionError("acquisition:quarantine-drift")
        if external_policy.logical_endpoint_id != config.endpoint_id or external_policy.authorization_artifact_digest != config.authorization_artifact_digest or external_policy.terms_artifact_digest != config.terms_artifact_digest:
            raise AuthenticatedSourceAcquisitionError("acquisition:policy-binding")
        if external_policy.profile_id != self.profile.source_profile_id or external_policy.verifier_id != nc_profile_module.VERIFIER_ID or external_policy.verifier_epoch != nc_profile_module.VERIFIER_EPOCH:
            raise AuthenticatedSourceAcquisitionError("acquisition:verifier-binding")
        if config.request_digest != request_digest_for_profile(profile=self.profile):
            raise AuthenticatedSourceAcquisitionError("acquisition:request-binding")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.database, timeout=BUSY_TIMEOUT_MS / 1000.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            connection.execute("PRAGMA journal_mode=WAL")
            return connection
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise AcquisitionBusyError("acquisition:busy") from exc
            raise AuthenticatedSourceAcquisitionError("acquisition:database-open") from exc
        except sqlite3.Error as exc:
            raise AuthenticatedSourceAcquisitionError("acquisition:database-open") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if not tables:
                connection.execute("BEGIN IMMEDIATE")
                for statement in DDL:
                    connection.execute(statement)
                chain_id = independent._chain_id(self.config.digest)
                genesis = independent._genesis_root(chain_id)
                values = {
                    "schema": SCHEMA, "schema_version": str(SCHEMA_VERSION), "acquisition_id": self.config.acquisition_id,
                    "config_digest": self.config.digest, "chain_id": chain_id, "sequence": "0",
                    "state_root": independent._state_root(chain_id, 0, genesis, None), "head_transition_id": GENESIS_TRANSITION,
                    "state_owned": "1", "zero_phi": "1", "production_usable": "0", "activation": "0",
                    "payment_authority": "0", "clearance_authority": "0", "settlement_authority": "0", "proofSuiteId": "null",
                }
                for key, value in sorted(values.items()):
                    connection.execute("INSERT INTO acquisition_meta(key,value) VALUES(?,?)", (key, value))
                self._fault("after_initialize")
                connection.commit()
            elif tables != set(independent.TABLE_COLUMNS):
                raise AuthenticatedSourceAcquisitionError("acquisition:database-schema")
        except AuthenticatedSourceAcquisitionError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise AuthenticatedSourceAcquisitionError("acquisition:database-initialize") from exc
        finally:
            connection.close()
        try:
            independent.verify_database(self.database, config=self.config.material())
        except independent.IndependentAcquisitionError as exc:
            raise AuthenticatedSourceAcquisitionError(str(exc)) from exc

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)

    def _metadata(self, connection: sqlite3.Connection) -> dict[str, str]:
        return {str(row["key"]): str(row["value"]) for row in connection.execute("SELECT key,value FROM acquisition_meta ORDER BY key")}

    @staticmethod
    def _slot(connection: sqlite3.Connection, slot_id: str) -> dict[str, object] | None:
        row = connection.execute("SELECT * FROM acquisition_slots WHERE slot_id=?", (slot_id,)).fetchone()
        return dict(row) if row is not None else None

    def _transition_locked(
        self,
        connection: sqlite3.Connection,
        *,
        slot_id: str,
        action: str,
        attempt: int,
        request_digest: str,
        material: Mapping[str, object],
        prior_state: str,
        next_state: str,
        slot_updates: Mapping[str, object],
        observed_at: int,
    ) -> dict[str, object]:
        metadata = self._metadata(connection)
        sequence = int(metadata["sequence"]) + 1
        before_root = metadata["state_root"]
        material_digest = _digest("material", dict(material))
        operation_id = _digest("operation", {"acquisition_id": self.config.acquisition_id, "slot_id": slot_id, "action": action, "attempt": attempt, "request_digest": request_digest, "material_digest": material_digest})
        existing = connection.execute("SELECT * FROM acquisition_operations WHERE operation_id=?", (operation_id,)).fetchone()
        if existing is not None:
            if existing["material_digest"] != material_digest or existing["request_digest"] != request_digest:
                raise AcquisitionConflictError("acquisition:operation-conflict")
            return {"accepted": True, "operation_id": operation_id, "slot_id": slot_id, "state": next_state, "sequence": existing["sequence"], "transition_id": existing["transition_id"], "receipt_raw": bytes(existing["receipt_raw"]), "receipt_digest": existing["receipt_digest"], "action": action}
        unsigned = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "transition_id": "", "sequence": sequence,
            "slot_id": slot_id, "operation_id": operation_id, "prior_state": prior_state, "next_state": next_state,
            "before_root": before_root, "after_root": "", "material_digest": material_digest, "observed_at": observed_at,
        }
        transition_id = independent._transition_id(unsigned)
        after_root = independent._state_root(independent._chain_id(self.config.digest), sequence, before_root, transition_id)
        transition = dict(unsigned)
        transition["transition_id"] = transition_id
        transition["after_root"] = after_root
        transition_raw = _canonical(transition)
        receipt = {
            "schema": SCHEMA, "schema_version": SCHEMA_VERSION, "acquisition_id": self.config.acquisition_id,
            "operation_id": operation_id, "slot_id": slot_id, "action": action, "prior_state": prior_state,
            "next_state": next_state, "sequence": sequence, "before_root": before_root, "after_root": after_root,
            "transition_id": transition_id, "material_digest": material_digest,
            "flags": {"state_owned": True, "zero_phi": True, "production_usable": False, "activation": False, "payment_authority": False, "clearance_authority": False, "settlement_authority": False, "proofSuiteId": None},
        }
        receipt_raw = _canonical(receipt)
        receipt_digest = _raw_digest(receipt_raw)
        self._fault("before_operation_insert")
        connection.execute(
            "INSERT INTO acquisition_operations(operation_id,slot_id,action,attempt,request_digest,material_digest,transition_id,receipt_digest,sequence,receipt_raw) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (operation_id, slot_id, action, attempt, request_digest, material_digest, transition_id, receipt_digest, sequence, receipt_raw),
        )
        self._fault("after_operation_insert")
        connection.execute(
            "INSERT INTO acquisition_transitions(transition_id,sequence,slot_id,operation_id,prior_state,next_state,before_root,after_root,material_digest,observed_at,transition_raw) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (transition_id, sequence, slot_id, operation_id, prior_state, next_state, before_root, after_root, material_digest, observed_at, transition_raw),
        )
        self._fault("after_transition_insert")
        if slot_updates:
            assignments = ",".join(f"{key}=?" for key in slot_updates)
            values = [slot_updates[key] for key in slot_updates] + [slot_id]
            connection.execute(f"UPDATE acquisition_slots SET {assignments} WHERE slot_id=?", values)
        connection.execute("UPDATE acquisition_meta SET value=? WHERE key='sequence'", (str(sequence),))
        connection.execute("UPDATE acquisition_meta SET value=? WHERE key='state_root'", (after_root,))
        connection.execute("UPDATE acquisition_meta SET value=? WHERE key='head_transition_id'", (transition_id,))
        self._fault("before_commit")
        return {"accepted": True, "operation_id": operation_id, "slot_id": slot_id, "state": next_state, "sequence": sequence, "transition_id": transition_id, "receipt_raw": receipt_raw, "receipt_digest": receipt_digest, "action": action}

    def _commit_transition(self, **kwargs: object) -> dict[str, object]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            result = self._transition_locked(connection, **kwargs)  # type: ignore[arg-type]
            connection.commit()
            return result
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise AcquisitionBusyError("acquisition:busy") from exc
            raise AuthenticatedSourceAcquisitionError("acquisition:database") from exc
        except (AcquisitionConflictError, AcquisitionInjectedFault, AuthenticatedSourceAcquisitionError):
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise AuthenticatedSourceAcquisitionError("acquisition:database") from exc
        finally:
            connection.close()

    def ensure_slot(self, scheduled_at: int) -> dict[str, object]:
        scheduled_at = _int(scheduled_at, "scheduled-at", minimum=1)
        slot_id = _digest("slot", {"config_digest": self.config.digest, "scheduled_at": scheduled_at})
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = self._slot(connection, slot_id)
            if existing is not None:
                if existing["scheduled_at"] != scheduled_at:
                    raise AcquisitionConflictError("acquisition:slot-conflict")
                connection.commit()
                return {"accepted": True, "slot_id": slot_id, "state": existing["state"], "attempt": existing["attempt"]}
            connection.execute(
                "INSERT INTO acquisition_slots(slot_id,scheduled_at,state,lease_id,lease_until,attempt,envelope_id,envelope_digest,artifact_id,artifact_digest,capture_id,payload_digest,snapshot_root,observed_at,fetched_at,quarantine_expected_head,quarantine_head,quarantine_head_root,quarantine_transition_id,quarantine_receipt_digest,quarantine_receipt_raw,failure_code,last_operation_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (slot_id, scheduled_at, "DUE", None, None, 0, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None),
            )
            result = self._transition_locked(
                connection, slot_id=slot_id, action="CREATE_SLOT", attempt=0, request_digest=self.config.request_digest,
                material={"scheduled_at": scheduled_at}, prior_state="", next_state="DUE", slot_updates={"last_operation_id": None}, observed_at=scheduled_at,
            )
            connection.commit()
            return {**result, "scheduled_at": scheduled_at, "state": "DUE", "attempt": 0}
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise AcquisitionBusyError("acquisition:busy") from exc
            raise AuthenticatedSourceAcquisitionError("acquisition:database") from exc
        except (AcquisitionConflictError, AcquisitionInjectedFault, AuthenticatedSourceAcquisitionError):
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _release_expired_locked(self, connection: sqlite3.Connection, now: int) -> int:
        rows = connection.execute("SELECT * FROM acquisition_slots WHERE state IN ('LEASED','CAPTURED') AND lease_until IS NOT NULL AND lease_until<=? ORDER BY scheduled_at,slot_id", (now,)).fetchall()
        released = 0
        for row in rows:
            next_state = "HELD" if int(row["attempt"]) >= self.config.max_attempts else "DUE"
            result = self._transition_locked(
                connection, slot_id=row["slot_id"], action="REQUEUE", attempt=int(row["attempt"]), request_digest=self.config.request_digest,
                material={"reason": "lease-expired", "attempt": int(row["attempt"]), "now": now}, prior_state=row["state"], next_state=next_state,
                slot_updates={"state": next_state, "lease_id": None, "lease_until": None, "failure_code": "timeout", "last_operation_id": None}, observed_at=now,
            )
            connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], row["slot_id"]))
            released += 1
        return released

    def requeue_expired(self, now: int | None = None) -> int:
        current = _int(self.clock() if now is None else now, "now", minimum=1)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            count = self._release_expired_locked(connection, current)
            connection.commit()
            return count
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise AcquisitionBusyError("acquisition:busy") from exc
            raise AuthenticatedSourceAcquisitionError("acquisition:database") from exc
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def claim_next(self, now: int | None = None) -> AcquisitionLease | None:
        current = _int(self.clock() if now is None else now, "now", minimum=1)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._release_expired_locked(connection, current)
            row = connection.execute("SELECT * FROM acquisition_slots WHERE state='DUE' ORDER BY scheduled_at,slot_id LIMIT 1").fetchone()
            if row is None:
                connection.commit()
                return None
            attempt = int(row["attempt"]) + 1
            lease_id = _digest("lease", {"slot_id": row["slot_id"], "attempt": attempt})
            lease_until = current + self.config.lease_seconds
            result = self._transition_locked(
                connection, slot_id=row["slot_id"], action="LEASE", attempt=attempt, request_digest=self.config.request_digest,
                material={"lease_id": lease_id, "attempt": attempt, "lease_until": lease_until}, prior_state="DUE", next_state="LEASED",
                slot_updates={"state": "LEASED", "lease_id": lease_id, "lease_until": lease_until, "attempt": attempt, "failure_code": None}, observed_at=current,
            )
            connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], row["slot_id"]))
            connection.commit()
            return AcquisitionLease(str(row["slot_id"]), lease_id, attempt, lease_until, int(row["scheduled_at"]))
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise AcquisitionBusyError("acquisition:busy") from exc
            raise AuthenticatedSourceAcquisitionError("acquisition:database") from exc
        except (AcquisitionConflictError, AcquisitionInjectedFault, AuthenticatedSourceAcquisitionError):
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def claim_slot(self, slot_id: str, now: int | None = None) -> AcquisitionLease:
        _hex(slot_id, "slot-id")
        current = _int(self.clock() if now is None else now, "now", minimum=1)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._release_expired_locked(connection, current)
            row = self._slot(connection, slot_id)
            if row is None or row["state"] != "DUE":
                raise AcquisitionConflictError("acquisition:slot-not-due")
            attempt = int(row["attempt"]) + 1
            lease_id = _digest("lease", {"slot_id": slot_id, "attempt": attempt})
            lease_until = current + self.config.lease_seconds
            self._transition_locked(connection, slot_id=slot_id, action="LEASE", attempt=attempt, request_digest=self.config.request_digest, material={"lease_id": lease_id, "attempt": attempt, "lease_until": lease_until}, prior_state="DUE", next_state="LEASED", slot_updates={"state": "LEASED", "lease_id": lease_id, "lease_until": lease_until, "attempt": attempt, "failure_code": None}, observed_at=current)
            connection.commit()
            return AcquisitionLease(slot_id, lease_id, attempt, lease_until, int(row["scheduled_at"]))
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _load_lease(self, lease: AcquisitionLease | Mapping[str, object]) -> dict[str, object]:
        if isinstance(lease, AcquisitionLease):
            slot_id, lease_id, attempt = lease.slot_id, lease.lease_id, lease.attempt
        elif isinstance(lease, Mapping):
            slot_id, lease_id, attempt = lease.get("slot_id"), lease.get("lease_id"), lease.get("attempt")
        else:
            raise AcquisitionConflictError("acquisition:lease")
        _hex(slot_id, "slot-id")
        _hex(lease_id, "lease-id")
        _int(attempt, "attempt", maximum=self.config.max_attempts)
        connection = self._connect()
        try:
            row = self._slot(connection, str(slot_id))
            if row is None or row["lease_id"] != lease_id or row["attempt"] != attempt or row["state"] not in {"LEASED", "CAPTURED", "QUARANTINED"}:
                raise AcquisitionConflictError("acquisition:lease")
            if row["lease_until"] is not None and int(row["lease_until"]) <= int(self.clock()):
                raise AcquisitionConflictError("acquisition:lease-expired")
            return row
        finally:
            connection.close()

    def _record_failure(self, slot_id: str, lease_id: str, attempt: int, code: str) -> None:
        if code not in SAFE_FAILURES:
            code = "verifier"
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._slot(connection, slot_id)
            if row is None or row["lease_id"] != lease_id or int(row["attempt"]) != attempt or row["state"] not in {"LEASED", "CAPTURED"}:
                raise AcquisitionConflictError("acquisition:lease")
            now = int(self.clock())
            next_state = "HELD" if attempt >= self.config.max_attempts else "DUE"
            result = self._transition_locked(connection, slot_id=slot_id, action="FAIL", attempt=attempt, request_digest=self.config.request_digest, material={"failure_code": code, "attempt": attempt}, prior_state=row["state"], next_state=next_state, slot_updates={"state": next_state, "lease_id": None, "lease_until": None, "failure_code": code, "last_operation_id": None}, observed_at=now)
            connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], slot_id))
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _record_captured(self, lease: AcquisitionLease, *, envelope_result: Mapping[str, object], envelope_raw: bytes, artifact: external_adapter.ExternalSourceArtifactV1, capture_result: Mapping[str, object], attestations: Mapping[tuple[int, int], FhirTransportAttestationV1], expected_head: str) -> dict[str, object]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._slot(connection, lease.slot_id)
            if row is None or row["lease_id"] != lease.lease_id or int(row["attempt"]) != lease.attempt or row["state"] not in {"LEASED", "CAPTURED"}:
                raise AcquisitionConflictError("acquisition:lease")
            envelope_digest = _raw_digest(envelope_raw)
            artifact_digest = _raw_digest(artifact.raw)
            values = {"envelope_id": envelope_result["envelope_id"], "envelope_digest": envelope_digest, "artifact_id": artifact.artifact_id, "artifact_digest": artifact_digest, "capture_id": capture_result["capture_id"], "payload_digest": capture_result["payload_sha3_512"], "snapshot_root": envelope_result["snapshot_root"], "observed_at": envelope_result["observation_time"], "fetched_at": max(attestation.fetched_at for attestation in attestations.values()), "quarantine_expected_head": expected_head or None}
            if row["state"] == "CAPTURED":
                values["quarantine_expected_head"] = row["quarantine_expected_head"]
                if any(row[key] != value for key, value in values.items()):
                    raise AcquisitionConflictError("acquisition:capture-conflict")
                connection.commit()
                return {"accepted": True, "state": "CAPTURED", "slot_id": lease.slot_id, **values}
            updates = {**values, "state": "CAPTURED", "failure_code": None}
            result = self._transition_locked(connection, slot_id=lease.slot_id, action="CAPTURE", attempt=lease.attempt, request_digest=self.config.request_digest, material=values, prior_state="LEASED", next_state="CAPTURED", slot_updates=updates, observed_at=int(envelope_result["observation_time"]))
            for key, attestation in attestations.items():
                del key
                row_value = _attestation_row(attestation, slot_id=lease.slot_id)
                connection.execute(
                    "INSERT INTO acquisition_attestations(slot_id,page_index,attempt,request_digest,server_identity_digest,authorization_artifact_digest,terms_artifact_digest,response_digest,status,media_type,observed_at,fetched_at,redirect,transport_authenticated,attestation_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    tuple(row_value[name] for name in independent.ATTESTATION_COLUMNS),
                )
            connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], lease.slot_id))
            connection.commit()
            return {"accepted": True, "state": "CAPTURED", "slot_id": lease.slot_id, **values}
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise AcquisitionConflictError("acquisition:capture-collision") from exc
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _record_quarantined(self, lease: AcquisitionLease, *, artifact: external_adapter.ExternalSourceArtifactV1, quarantine_result: Mapping[str, object], head: Mapping[str, object] | None) -> dict[str, object]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._slot(connection, lease.slot_id)
            if row is None or row["lease_id"] != lease.lease_id or int(row["attempt"]) != lease.attempt or row["state"] not in {"CAPTURED", "QUARANTINED"}:
                raise AcquisitionConflictError("acquisition:lease")
            receipt_raw = bytes(quarantine_result["receipt_raw"])
            receipt_digest = _raw_digest(receipt_raw)
            head_artifact = str(quarantine_result["artifact_id"])
            head_root = str((head or {}).get("head_root", ""))
            if row["state"] == "QUARANTINED":
                if row["artifact_id"] != artifact.artifact_id or row["quarantine_receipt_digest"] != receipt_digest:
                    raise AcquisitionConflictError("acquisition:quarantine-conflict")
                connection.commit()
                return {"accepted": True, "state": "QUARANTINED", "slot_id": lease.slot_id, "artifact_id": artifact.artifact_id, "quarantine_receipt_digest": receipt_digest}
            if head_artifact != artifact.artifact_id:
                raise AcquisitionConflictError("acquisition:quarantine-artifact")
            updates = {"state": "QUARANTINED", "lease_until": None, "quarantine_head": head_artifact, "quarantine_head_root": head_root, "quarantine_transition_id": quarantine_result["transition_id"], "quarantine_receipt_digest": receipt_digest, "quarantine_receipt_raw": receipt_raw, "failure_code": None}
            result = self._transition_locked(connection, slot_id=lease.slot_id, action="QUARANTINE", attempt=lease.attempt, request_digest=self.config.request_digest, material={"artifact_id": artifact.artifact_id, "quarantine_receipt_digest": receipt_digest, "quarantine_transition_id": quarantine_result["transition_id"]}, prior_state="CAPTURED", next_state="QUARANTINED", slot_updates=updates, observed_at=int(self.clock()))
            connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], lease.slot_id))
            connection.commit()
            return {**result, "state": "QUARANTINED", "artifact_id": artifact.artifact_id, "quarantine_receipt_digest": receipt_digest}
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def acquire(self, lease: AcquisitionLease | Mapping[str, object], transport: AuthenticatedFhirTransportPort) -> dict[str, object]:
        if transport is None:
            raise AuthenticatedSourceAcquisitionError("acquisition:transport-required")
        loaded = self._load_lease(lease)
        lease_obj = AcquisitionLease(str(loaded["slot_id"]), str(loaded["lease_id"]), int(loaded["attempt"]), int(loaded["lease_until"] or 0), int(loaded["scheduled_at"]))
        if loaded["state"] == "QUARANTINED":
            return {"accepted": True, "state": "QUARANTINED", "slot_id": lease_obj.slot_id, "artifact_id": loaded["artifact_id"], "quarantine_receipt_digest": loaded["quarantine_receipt_digest"]}
        wrapper = _AuthenticatedTransportAdapter(self, transport)
        try:
            envelope_raw = nc_fhir.build_fixture_envelope(wrapper, profile=self.profile)
            envelope_result = nc_independent.verify_bytes(envelope_raw, profile=self.profile)
            if envelope_result["source_status"] != "COMPLETE" or envelope_result["page_complete"] is not True:
                raise AcquisitionHold("acquisition:incomplete")
            if envelope_result["freshness"] == "STALE":
                raise AcquisitionHold("acquisition:stale")
            capture_verifier = _NcCaptureVerifier(self, wrapper.attestations)
            artifact = external_adapter.build_artifact(self.external_policy, capture_verifier, envelope_raw)
            capture_result = external_independent.verify_artifact(artifact.raw, policy=self.external_policy.material(), capture_raw=envelope_raw)
            if capture_result["derived_status"] != "OBSERVATION_ADMITTED":
                raise AcquisitionHold("acquisition:adapter-hold")
            head = self.quarantine_service.head()
            expected_head = str(loaded["quarantine_expected_head"] or "") if loaded["state"] == "CAPTURED" else (str(head["head_artifact_id"]) if head is not None else "")
            captured = self._record_captured(lease_obj, envelope_result=envelope_result, envelope_raw=envelope_raw, artifact=artifact, capture_result=capture_result, attestations=wrapper.attestations, expected_head=expected_head)
            expected_head = str(captured.get("quarantine_expected_head") or "")
            request_key = "AQ" + lease_obj.slot_id[:30]
            try:
                quarantine_result = self.quarantine_service.admit(request_key, artifact.raw, expected_head=expected_head or None)
            except quarantine.QuarantineResponseLost as exc:
                raise AcquisitionResponseLost("acquisition:response-loss") from exc
            except quarantine.QuarantineBusyError as exc:
                self._record_failure(lease_obj.slot_id, lease_obj.lease_id, lease_obj.attempt, "busy")
                raise AcquisitionBusyError("acquisition:busy") from exc
            except quarantine.QuarantineConflictError as exc:
                self._record_failure(lease_obj.slot_id, lease_obj.lease_id, lease_obj.attempt, "quarantine-head")
                raise AcquisitionConflictError("acquisition:quarantine-head") from exc
            current_head = self.quarantine_service.head()
            result = self._record_quarantined(lease_obj, artifact=artifact, quarantine_result=quarantine_result, head=current_head)
            return {**result, "envelope_id": envelope_result["envelope_id"], "source_status": envelope_result["source_status"], "production_source_authentication": False, "production_usable": False, "activation": False, "proofSuiteId": None}
        except AcquisitionResponseLost:
            raise
        except AcquisitionBusyError:
            raise
        except AcquisitionConflictError:
            raise
        except AcquisitionHold as exc:
            code = str(exc).split(":", 1)[-1]
            self._record_failure(lease_obj.slot_id, lease_obj.lease_id, lease_obj.attempt, code if code in SAFE_FAILURES else "incomplete")
            raise
        except (nc_fhir.NcMedicaidFhirError, nc_independent.IndependentNcMedicaidFhirError, external_adapter.ExternalSourceAdapterError, external_independent.IndependentExternalSourceError, AuthenticatedSourceAcquisitionError) as exc:
            code = str(exc).split(":")[-1]
            mapped = code if code in SAFE_FAILURES else "verifier"
            self._record_failure(lease_obj.slot_id, lease_obj.lease_id, lease_obj.attempt, mapped)
            raise AuthenticatedSourceAcquisitionError(f"acquisition:{mapped}") from exc

    def export_bytes(self) -> bytes:
        self.integrity()
        connection = self._connect()
        try:
            snapshot = {table: [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")] for table in independent.TABLE_COLUMNS}
        finally:
            connection.close()
        operation_rows: list[dict[str, object]] = []
        for row in snapshot["acquisition_operations"]:
            receipt_raw = row.pop("receipt_raw")
            row["receipt_hex"] = bytes(receipt_raw).hex()
            operation_rows.append(row)
        transition_rows: list[dict[str, object]] = []
        for row in snapshot["acquisition_transitions"]:
            transition_raw = row.pop("transition_raw")
            row["transition_hex"] = bytes(transition_raw).hex()
            transition_rows.append(row)
        body: dict[str, object] = {
            "schema": EXPORT_SCHEMA, "schema_version": EXPORT_VERSION, "config": self.config.material(),
            "config_digest": self.config.digest, "chain_id": independent._chain_id(self.config.digest),
            "meta": snapshot["acquisition_meta"], "slots": [],
            "operations": operation_rows,
            "transitions": transition_rows,
            "attestations": snapshot["acquisition_attestations"], "state_owned": True, "zero_phi": True,
            "production_usable": False, "activation": False, "payment_authority": False,
            "clearance_authority": False, "settlement_authority": False, "proofSuiteId": None,
        }
        slot_rows: list[dict[str, object]] = []
        for row in snapshot["acquisition_slots"]:
            receipt_raw = row.pop("quarantine_receipt_raw")
            row["quarantine_receipt_hex"] = None if receipt_raw is None else bytes(receipt_raw).hex()
            slot_rows.append(row)
        body["slots"] = slot_rows
        body["export_root"] = _digest("export-root", body)
        raw = _canonical(body)
        if len(raw) > MAX_EXPORT_BYTES:
            raise AuthenticatedSourceAcquisitionError("acquisition:export-cap")
        return raw

    def integrity(self) -> dict[str, object]:
        try:
            return independent.verify_database(self.database, config=self.config.material())
        except independent.IndependentAcquisitionError as exc:
            raise AuthenticatedSourceAcquisitionError(str(exc)) from exc

    def support_snapshot(self) -> dict[str, object]:
        try:
            return independent.support_snapshot(self.database, config=self.config.material())
        except independent.IndependentAcquisitionError as exc:
            raise AuthenticatedSourceAcquisitionError(str(exc)) from exc

    @classmethod
    def restore_export(
        cls,
        destination: str | Path,
        raw: bytes,
        *,
        config: AuthenticatedSourceAcquisitionConfigV1,
        external_policy: external_adapter.ExternalSourcePolicyV1,
        quarantine_service: quarantine.ExternalSourceQuarantineService,
    ) -> "AuthenticatedSourceAcquisitionService":
        target = _resolve_database(destination)
        if target.exists() or target.is_symlink():
            raise AcquisitionConflictError("acquisition:restore-target-exists")
        try:
            verified = independent.verify_export_bytes(raw, config=config.material())
        except independent.IndependentAcquisitionError as exc:
            raise AuthenticatedSourceAcquisitionError(str(exc)) from exc
        stage = target.with_name("." + target.name + ".restore")
        if stage.exists():
            raise AcquisitionConflictError("acquisition:restore-stage-exists")
        service: AuthenticatedSourceAcquisitionService | None = None
        try:
            service = cls(stage, config=config, external_policy=external_policy, quarantine_service=quarantine_service)
            connection = service._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                for table in independent.TABLE_COLUMNS:
                    connection.execute(f"DELETE FROM {table}")
                for row in verified["snapshot"]["acquisition_meta"]:  # type: ignore[index]
                    connection.execute("INSERT INTO acquisition_meta(key,value) VALUES(?,?)", (row["key"], row["value"]))
                for row in verified["snapshot"]["acquisition_slots"]:  # type: ignore[index]
                    connection.execute("INSERT INTO acquisition_slots VALUES(" + ",".join("?" for _ in independent.SLOT_COLUMNS) + ")", tuple(row[column] for column in independent.SLOT_COLUMNS))
                for row in verified["snapshot"]["acquisition_operations"]:  # type: ignore[index]
                    connection.execute("INSERT INTO acquisition_operations VALUES(" + ",".join("?" for _ in independent.OPERATION_COLUMNS) + ")", tuple(row[column] for column in independent.OPERATION_COLUMNS))
                for row in verified["snapshot"]["acquisition_transitions"]:  # type: ignore[index]
                    connection.execute("INSERT INTO acquisition_transitions VALUES(" + ",".join("?" for _ in independent.TRANSITION_COLUMNS) + ")", tuple(row[column] for column in independent.TRANSITION_COLUMNS))
                for row in verified["snapshot"]["acquisition_attestations"]:  # type: ignore[index]
                    connection.execute("INSERT INTO acquisition_attestations VALUES(" + ",".join("?" for _ in independent.ATTESTATION_COLUMNS) + ")", tuple(row[column] for column in independent.ATTESTATION_COLUMNS))
                connection.commit()
            finally:
                connection.close()
            service.integrity()
            os.replace(stage, target)
            return cls(target, config=config, external_policy=external_policy, quarantine_service=quarantine_service)
        except Exception:
            if service is not None:
                for suffix in ("", "-wal", "-shm"):
                    Path(str(stage) + suffix).unlink(missing_ok=True)
            raise


def restore_export(destination: str | Path, raw: bytes, *, config: AuthenticatedSourceAcquisitionConfigV1, external_policy: external_adapter.ExternalSourcePolicyV1, quarantine_service: quarantine.ExternalSourceQuarantineService) -> AuthenticatedSourceAcquisitionService:
    return AuthenticatedSourceAcquisitionService.restore_export(destination, raw, config=config, external_policy=external_policy, quarantine_service=quarantine_service)


__all__ = [
    "SCHEMA", "SCHEMA_VERSION", "EXPORT_SCHEMA", "EXPORT_VERSION", "STATES", "SAFE_FAILURES",
    "AuthenticatedSourceAcquisitionError", "AcquisitionConflictError", "AcquisitionBusyError",
    "AcquisitionResponseLost", "AcquisitionInjectedFault", "AcquisitionHold",
    "AuthenticatedSourceAcquisitionConfigV1", "request_digest_for_page", "request_digest_for_profile",
    "AuthenticatedFhirRequestV1", "FhirTransportAttestationV1", "AuthenticatedFhirResponseV1",
    "AuthenticatedFhirTransportPort", "LiveAuthenticatedFhirTransport", "AcquisitionLease",
    "AuthenticatedSourceAcquisitionService", "restore_export",
]
