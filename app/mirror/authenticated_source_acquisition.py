"""Durable, transport-neutral authenticated NC source acquisition.

This service owns only cadence, leases, and composition.  NC FHIR parsing,
external-artifact semantics, and quarantine custody remain separate owners.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from typing import Callable, Mapping, Protocol

from app.mirror import external_source_adapter as external_adapter
from app.mirror import external_source_adapter_independent as external_independent
from app.mirror import external_source_quarantine as quarantine
from app.mirror import nc_medicaid_fhir as nc_fhir
from app.mirror import nc_medicaid_fhir_independent as nc_independent
from app.mirror import nc_medicaid_fhir_profile as profile_module
from app.mirror import authenticated_source_acquisition_independent as independent
from app.mirror import restore_publication

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

DDL = (
    "CREATE TABLE acquisition_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE acquisition_slots (slot_id TEXT PRIMARY KEY, scheduled_at INTEGER NOT NULL, state TEXT NOT NULL, lease_id TEXT, lease_until INTEGER, attempt INTEGER NOT NULL, envelope_id TEXT, envelope_digest TEXT, artifact_id TEXT, artifact_digest TEXT, capture_id TEXT, payload_digest TEXT, snapshot_root TEXT, observed_at INTEGER, fetched_at INTEGER, quarantine_expected_head TEXT, quarantine_head TEXT, quarantine_head_root TEXT, quarantine_transition_id TEXT, quarantine_receipt_digest TEXT, quarantine_receipt_raw BLOB, failure_code TEXT, last_operation_id TEXT, capture_attempt INTEGER, page_count INTEGER, page_digests_raw BLOB, selected_pages_raw BLOB, quarantine_request_digest TEXT, quarantine_material_digest TEXT, quarantine_database_id TEXT, quarantine_policy_digest TEXT, quarantine_chain_id TEXT, quarantine_dispatch_attempt INTEGER)",
    "CREATE TABLE acquisition_operations (operation_id TEXT PRIMARY KEY, slot_id TEXT NOT NULL, action TEXT NOT NULL, attempt INTEGER NOT NULL, request_digest TEXT NOT NULL, material_digest TEXT NOT NULL, material_raw BLOB NOT NULL, transition_id TEXT NOT NULL, receipt_digest TEXT NOT NULL, sequence INTEGER NOT NULL, receipt_raw BLOB NOT NULL, FOREIGN KEY(slot_id) REFERENCES acquisition_slots(slot_id))",
    "CREATE TABLE acquisition_transitions (transition_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, slot_id TEXT NOT NULL, operation_id TEXT NOT NULL, action TEXT NOT NULL, attempt INTEGER NOT NULL, request_digest TEXT NOT NULL, prior_state TEXT NOT NULL, next_state TEXT NOT NULL, before_root TEXT NOT NULL, after_root TEXT NOT NULL, material_digest TEXT NOT NULL, observed_at INTEGER NOT NULL, transition_raw BLOB NOT NULL, FOREIGN KEY(slot_id) REFERENCES acquisition_slots(slot_id), FOREIGN KEY(operation_id) REFERENCES acquisition_operations(operation_id))",
    "CREATE TABLE acquisition_attestations (slot_id TEXT NOT NULL, page_index INTEGER NOT NULL, attempt INTEGER NOT NULL, transport_id TEXT NOT NULL, transport_epoch INTEGER NOT NULL, request_digest TEXT NOT NULL, server_identity_digest TEXT NOT NULL, authorization_artifact_digest TEXT NOT NULL, terms_artifact_digest TEXT NOT NULL, response_digest TEXT NOT NULL, status INTEGER NOT NULL, media_type TEXT NOT NULL, observed_at INTEGER NOT NULL, fetched_at INTEGER NOT NULL, redirect INTEGER NOT NULL, transport_authenticated INTEGER NOT NULL, attestation_digest TEXT NOT NULL, PRIMARY KEY(slot_id,page_index,attempt), FOREIGN KEY(slot_id) REFERENCES acquisition_slots(slot_id))",
    "CREATE INDEX acquisition_slots_due_idx ON acquisition_slots(state,scheduled_at,slot_id)",
    "CREATE INDEX acquisition_transitions_sequence_idx ON acquisition_transitions(sequence)",
)


class AuthenticatedSourceAcquisitionError(ValueError):
    pass


class AcquisitionConflictError(AuthenticatedSourceAcquisitionError):
    pass


class AcquisitionBusyError(AuthenticatedSourceAcquisitionError):
    pass


class AcquisitionResponseLost(AuthenticatedSourceAcquisitionError):
    pass


class AcquisitionInjectedFault(AuthenticatedSourceAcquisitionError):
    pass


class AcquisitionHold(AuthenticatedSourceAcquisitionError):
    pass


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
    effective_start: int
    effective_end: int
    expected_server_identity_digest: str
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
        if self.nc_profile_digest != profile_module.NC_MEDICAID_PROFILE.profile_digest:
            raise AuthenticatedSourceAcquisitionError("acquisition:profile-drift")
        if self.max_body_bytes > profile_module.NC_MEDICAID_PROFILE.transport_caps["max_page_bytes"] or self.max_page_count > profile_module.NC_MEDICAID_PROFILE.transport_caps["max_pages"]:
            raise AuthenticatedSourceAcquisitionError("acquisition:profile-cap")
        if self.request_digest != request_digest_for_profile():
            raise AuthenticatedSourceAcquisitionError("acquisition:request-binding")

    def material(self) -> dict[str, object]:
        return {key: getattr(self, key) for key in independent.CONFIG_KEYS}

    @property
    def digest(self) -> str:
        return independent._config_digest(self.material())


def request_digest_for_page(page_index: int, *, profile=profile_module.NC_MEDICAID_PROFILE) -> str:
    _int(page_index, "page-index", maximum=profile.transport_caps["max_pages"] - 1)
    return _digest("request", {"method": "GET", "url": profile.page_url(page_index), "page_index": page_index})


def request_digest_for_profile(*, profile=profile_module.NC_MEDICAID_PROFILE) -> str:
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
        return {key: getattr(self, key) for key in ("transport_id", "transport_epoch", "page_index", "attempt", "request_digest", "server_identity_digest", "authorization_artifact_digest", "terms_artifact_digest", "response_digest", "status", "media_type", "observed_at", "fetched_at", "redirect", "transport_authenticated")}

    @property
    def expected_digest(self) -> str:
        return _digest("transport-attestation", self.material())

    def __post_init__(self) -> None:
        _hex(self.request_digest, "request-digest")
        _hex(self.server_identity_digest, "server-identity")
        _hex(self.authorization_artifact_digest, "authorization-digest")
        _hex(self.terms_artifact_digest, "terms-digest")
        _hex(self.response_digest, "response-digest")
        _hex(self.attestation_digest, "attestation-digest")
        _int(self.status, "status", minimum=100, maximum=599)
        _int(self.observed_at, "observed-at", minimum=1)
        _int(self.fetched_at, "fetched-at", minimum=1)
        if self.media_type != profile_module.ALLOWED_MEDIA_TYPE or self.fetched_at < self.observed_at or type(self.redirect) is not bool or type(self.transport_authenticated) is not bool or self.attestation_digest != self.expected_digest:
            raise AuthenticatedSourceAcquisitionError("acquisition:attestation-fields")


@dataclass(frozen=True)
class AuthenticatedFhirResponseV1:
    body: bytes
    attestation: FhirTransportAttestationV1


class AuthenticatedFhirTransportPort(Protocol):
    transport_id: str
    transport_epoch: int

    def fetch(self, request: AuthenticatedFhirRequestV1) -> AuthenticatedFhirResponseV1:
        ...


class LiveAuthenticatedFhirTransport:
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
    value = dict(attestation.material())
    value["slot_id"] = slot_id
    value["redirect"] = int(value["redirect"])
    value["transport_authenticated"] = int(value["transport_authenticated"])
    value["attestation_digest"] = attestation.attestation_digest
    return value


class _AuthenticatedTransportAdapter:
    def __init__(self, service: "AuthenticatedSourceAcquisitionService", port: AuthenticatedFhirTransportPort, observed_at: int) -> None:
        self.service = service
        self.port = port
        self.observed_at = observed_at
        self.attestations: dict[tuple[int, int], FhirTransportAttestationV1] = {}

    def fetch(self, request_url: str, *, timeout_seconds: int, attempt: int) -> nc_fhir.FhirTransportResponse:
        page_index = next((index for index in range(self.service.config.max_page_count) if self.service.profile.page_url(index) == request_url), None)
        if page_index is None:
            raise nc_fhir.FhirTransportError("wrong-host")
        request = AuthenticatedFhirRequestV1(page_index, attempt, "GET", request_url, timeout_seconds, self.service.config.max_body_bytes, self.service.config.nc_profile_digest, self.service.config.endpoint_id, request_digest_for_page(page_index, profile=self.service.profile))
        if page_index == 0 and request.request_digest != self.service.config.request_digest:
            raise nc_fhir.FhirTransportError("request-mismatch")
        try:
            response = self.port.fetch(request)
        except nc_fhir.FhirTransportError:
            raise
        except Exception as exc:
            raise nc_fhir.FhirTransportError("transport") from exc
        if not isinstance(response, AuthenticatedFhirResponseV1) or type(response.body) is not bytes:
            raise nc_fhir.FhirTransportError("transport")
        if len(response.body) > self.service.config.max_body_bytes:
            raise nc_fhir.FhirTransportError("body-cap")
        attestation = response.attestation
        expected_server = self.service.config.expected_server_identity_digest
        if attestation.transport_id != self.service.config.transport_id or attestation.transport_epoch != self.service.config.transport_epoch:
            raise nc_fhir.FhirTransportError("transport-mismatch")
        if attestation.page_index != page_index or attestation.attempt != attempt or attestation.request_digest != request.request_digest:
            raise nc_fhir.FhirTransportError("request-mismatch")
        if attestation.server_identity_digest != expected_server:
            raise nc_fhir.FhirTransportError("server-identity")
        if attestation.authorization_artifact_digest != self.service.config.authorization_artifact_digest or attestation.terms_artifact_digest != self.service.config.terms_artifact_digest:
            raise nc_fhir.FhirTransportError("authority-mismatch")
        if attestation.status != 200:
            raise nc_fhir.FhirTransportError("status")
        if not attestation.transport_authenticated:
            raise nc_fhir.FhirTransportError("authentication")
        if attestation.redirect or attestation.response_digest != _raw_digest(response.body):
            raise nc_fhir.FhirTransportError("response-digest")
        if attestation.observed_at != self.observed_at or attestation.fetched_at > self.observed_at + self.service.config.cadence_seconds + self.service.config.freshness_grace_seconds or attestation.fetched_at > self.service.config.effective_end + self.service.config.freshness_grace_seconds:
            raise nc_fhir.FhirTransportError("stale")
        self.attestations[(page_index, attempt)] = attestation
        return nc_fhir.FhirTransportResponse(request_url, 200, attestation.media_type, bytes(response.body))


class _NcCaptureVerifier:
    def __init__(self, service: "AuthenticatedSourceAcquisitionService", attestations: Mapping[tuple[int, int], FhirTransportAttestationV1]) -> None:
        self.service = service
        self.attestations = dict(attestations)
        self.verifier_id = service.external_policy.verifier_id
        self.verifier_epoch = service.external_policy.verifier_epoch
        self.selected_pages: list[dict[str, object]] = []
        self.page_digests: tuple[str, ...] = ()

    def verify(self, capture_raw: bytes) -> external_adapter.VerifiedExternalCaptureV1:
        try:
            result = nc_independent.verify_bytes(capture_raw, profile=self.service.profile)
        except Exception as exc:
            raise AuthenticatedSourceAcquisitionError("acquisition:nc-verifier") from exc
        page_count = int(result["page_count"])
        envelope_value = nc_independent._parse(capture_raw, self.service.profile)
        pages = envelope_value.get("pages")
        if not isinstance(pages, list) or len(pages) != page_count:
            raise AuthenticatedSourceAcquisitionError("acquisition:page-binding")
        ordered = tuple(hashlib.sha3_512(nc_fhir.canonical_json(page["bundle"])).hexdigest() for page in pages if isinstance(page, dict) and isinstance(page.get("bundle"), dict))
        if len(ordered) != page_count:
            raise AuthenticatedSourceAcquisitionError("acquisition:page-binding")
        selected: list[FhirTransportAttestationV1] = []
        for page_index in range(page_count):
            candidates = [item for (index, _attempt), item in self.attestations.items() if index == page_index]
            if not candidates:
                raise AuthenticatedSourceAcquisitionError("acquisition:attestation-missing")
            chosen = sorted(candidates, key=lambda item: item.attempt)[-1]
            if chosen.status != 200 or not chosen.transport_authenticated or chosen.response_digest != ordered[page_index]:
                raise AuthenticatedSourceAcquisitionError("acquisition:page-binding")
            selected.append(chosen)
        self.page_digests = ordered
        self.selected_pages = [{"page_index": index, "lease_attempt": self.service.active_lease_attempt, "transport_attempt": attestation.attempt, "attestation_digest": attestation.attestation_digest, "request_digest": attestation.request_digest, "response_digest": attestation.response_digest} for index, attestation in enumerate(selected)]
        payload_digest = _raw_digest(capture_raw)
        provisional = external_adapter.VerifiedExternalCaptureV1(policy_digest=self.service.external_policy.digest, verifier_id=self.service.external_policy.verifier_id, verifier_epoch=self.service.external_policy.verifier_epoch, capture_id=external_independent.capture_id_for_payload(payload_digest), payload_sha3_512=payload_digest, observed_at=min(item.observed_at for item in selected), fetched_at=max(item.fetched_at for item in selected), page_digests=tuple(sorted(item.response_digest for item in selected)), page_count=page_count, server_identity_digest=self.service.config.expected_server_identity_digest, transport_receipt_digest="0" * 128, transport_authenticated=True, complete=result["source_status"] == "COMPLETE" and result["page_complete"] is True, failure_code="NONE" if result["source_status"] == "COMPLETE" and result["page_complete"] is True else "INCOMPLETE", zero_phi=True)
        receipt = external_adapter._expected_transport_receipt(self.service.external_policy, provisional, self.service.config.expected_server_identity_digest)
        return external_adapter.VerifiedExternalCaptureV1(**{**provisional.__dict__, "transport_receipt_digest": receipt})


def _resolve_database(path: str | Path) -> Path:
    try:
        target = Path(os.path.abspath(os.fspath(path)))
    except (TypeError, ValueError) as exc:
        raise AuthenticatedSourceAcquisitionError("acquisition:database-path") from exc
    if not target.name or not target.parent.is_dir() or target.is_symlink() or target.parent.is_symlink():
        raise AuthenticatedSourceAcquisitionError("acquisition:database-path")
    return target


class AuthenticatedSourceAcquisitionService:
    def __init__(self, database: str | Path, *, config: AuthenticatedSourceAcquisitionConfigV1, external_policy: external_adapter.ExternalSourcePolicyV1, quarantine_service: quarantine.ExternalSourceQuarantineService, clock: Callable[[], int] | None = None, fault_injector: Callable[[str], None] | None = None) -> None:
        self.database = _resolve_database(database)
        self.config = config
        self.external_policy = external_policy
        self.profile = profile_module.NC_MEDICAID_PROFILE
        self.quarantine_service = quarantine_service
        self.clock = clock or (lambda: self.profile.observation_time)
        self.fault_injector = fault_injector
        self.active_lease_attempt = 0
        if config.external_policy_digest != external_policy.digest or config.effective_start != external_policy.effective_start or config.effective_end != external_policy.effective_end or config.cadence_seconds != external_policy.expected_cadence_seconds or config.freshness_grace_seconds != external_policy.freshness_grace_seconds or config.authorization_artifact_digest != external_policy.authorization_artifact_digest or config.terms_artifact_digest != external_policy.terms_artifact_digest or config.expected_server_identity_digest != external_adapter._expected_server_identity(external_policy):
            raise AuthenticatedSourceAcquisitionError("acquisition:policy-projection")
        if quarantine_service.database_id != config.quarantine_database_id or quarantine_service.policy_digest != config.quarantine_policy_digest or quarantine_service.chain_id != config.quarantine_chain_id:
            raise AuthenticatedSourceAcquisitionError("acquisition:quarantine-database")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.database, timeout=self.config.busy_timeout_ms / 1000.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(f"PRAGMA busy_timeout={self.config.busy_timeout_ms}")
            connection.execute("PRAGMA journal_mode=WAL")
            return connection
        except sqlite3.OperationalError as exc:
            if "busy" in str(exc).lower() or "locked" in str(exc).lower():
                raise AcquisitionBusyError("acquisition:busy") from exc
            raise AuthenticatedSourceAcquisitionError("acquisition:database-open") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            tables = {str(row[0]) for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
            if not tables:
                connection.execute("BEGIN IMMEDIATE")
                for statement in DDL:
                    connection.execute(statement)
                genesis = independent._genesis_root(independent._chain_id(self.config.digest))
                state_root = independent._state_root(independent._chain_id(self.config.digest), 0, genesis, None)
                values = {"schema": SCHEMA, "schema_version": str(SCHEMA_VERSION), "acquisition_id": self.config.acquisition_id, "config_digest": self.config.digest, "chain_id": independent._chain_id(self.config.digest), "sequence": "0", "state_root": state_root, "head_transition_id": GENESIS_TRANSITION, "state_owned": "1", "zero_phi": "1", "read_only": "1", "observation_only": "1", "quarantine_only": "1", "production_usable": "0", "activation": "0", "payment_authority": "0", "clearance_authority": "0", "settlement_authority": "0", "adjudication_authority": "0", "proofSuiteId": "null"}
                for key in sorted(values):
                    connection.execute("INSERT INTO acquisition_meta(key,value) VALUES(?,?)", (key, values[key]))
                connection.commit()
            elif tables != set(independent.TABLE_COLUMNS):
                raise AuthenticatedSourceAcquisitionError("acquisition:database-schema")
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        self.integrity()

    def _fault(self, point: str) -> None:
        if self.fault_injector is not None:
            self.fault_injector(point)

    @staticmethod
    def _slot(connection: sqlite3.Connection, slot_id: str) -> dict[str, object] | None:
        row = connection.execute("SELECT * FROM acquisition_slots WHERE slot_id=?", (slot_id,)).fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
        return {str(row["key"]): str(row["value"]) for row in connection.execute("SELECT key,value FROM acquisition_meta ORDER BY key")}

    def _transition_locked(self, connection: sqlite3.Connection, *, slot_id: str, action: str, attempt: int, request_digest: str, prior_state: str, next_state: str, slot_updates: Mapping[str, object], observed_at: int) -> dict[str, object]:
        current = self._slot(connection, slot_id)
        if current is None:
            raise AcquisitionConflictError("acquisition:slot-missing")
        after = dict(current)
        after.update(slot_updates)
        after["last_operation_id"] = current["last_operation_id"]
        material = independent._material_value(after, action=action, attempt=attempt, request_digest=request_digest, prior_state=prior_state, next_state=next_state)
        material_raw = _canonical(material)
        material_digest = _digest("material", material)
        metadata = self._metadata(connection)
        sequence = int(metadata["sequence"]) + 1
        before_root = metadata["state_root"]
        operation_id = _digest("operation", {"acquisition_id": self.config.acquisition_id, "slot_id": slot_id, "action": action, "attempt": attempt, "request_digest": request_digest, "material_digest": material_digest})
        existing = connection.execute("SELECT * FROM acquisition_operations WHERE operation_id=?", (operation_id,)).fetchone()
        if existing is not None:
            if existing["material_digest"] != material_digest or bytes(existing["material_raw"]) != material_raw:
                raise AcquisitionConflictError("acquisition:operation-conflict")
            return {"accepted": True, "operation_id": operation_id, "slot_id": slot_id, "state": next_state, "sequence": existing["sequence"], "transition_id": existing["transition_id"], "receipt_raw": bytes(existing["receipt_raw"]), "receipt_digest": existing["receipt_digest"], "action": action}
        transition_base = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "transition_id": "", "sequence": sequence, "slot_id": slot_id, "operation_id": operation_id, "action": action, "attempt": attempt, "request_digest": request_digest, "prior_state": prior_state, "next_state": next_state, "before_root": before_root, "after_root": "", "material_digest": material_digest, "observed_at": observed_at}
        transition_id = _digest("transition", {key: value for key, value in transition_base.items() if key != "transition_id"})
        after_root = independent._state_root(independent._chain_id(self.config.digest), sequence, before_root, transition_id)
        transition = {**transition_base, "transition_id": transition_id, "after_root": after_root}
        transition_raw = _canonical(transition)
        receipt = {"schema": SCHEMA, "schema_version": SCHEMA_VERSION, "acquisition_id": self.config.acquisition_id, "operation_id": operation_id, "slot_id": slot_id, "action": action, "attempt": attempt, "request_digest": request_digest, "prior_state": prior_state, "next_state": next_state, "sequence": sequence, "before_root": before_root, "after_root": after_root, "transition_id": transition_id, "material_digest": material_digest, "flags": independent.FIXED_FLAGS}
        receipt_raw = _canonical(receipt)
        self._fault("before_operation_insert")
        connection.execute("INSERT INTO acquisition_operations VALUES(?,?,?,?,?,?,?,?,?,?,?)", (operation_id, slot_id, action, attempt, request_digest, material_digest, material_raw, transition_id, _raw_digest(receipt_raw), sequence, receipt_raw))
        self._fault("after_operation_insert")
        connection.execute("INSERT INTO acquisition_transitions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (transition_id, sequence, slot_id, operation_id, action, attempt, request_digest, prior_state, next_state, before_root, after_root, material_digest, observed_at, transition_raw))
        self._fault("after_transition_insert")
        if slot_updates:
            assignments = ",".join(f"{key}=?" for key in slot_updates)
            connection.execute(f"UPDATE acquisition_slots SET {assignments} WHERE slot_id=?", tuple(slot_updates[key] for key in slot_updates) + (slot_id,))
        connection.execute("UPDATE acquisition_meta SET value=? WHERE key='sequence'", (str(sequence),))
        connection.execute("UPDATE acquisition_meta SET value=? WHERE key='state_root'", (after_root,))
        connection.execute("UPDATE acquisition_meta SET value=? WHERE key='head_transition_id'", (transition_id,))
        self._fault("before_commit")
        return {"accepted": True, "operation_id": operation_id, "slot_id": slot_id, "state": next_state, "sequence": sequence, "transition_id": transition_id, "receipt_raw": receipt_raw, "receipt_digest": _raw_digest(receipt_raw), "action": action}

    def ensure_slot(self, scheduled_at: int) -> dict[str, object]:
        scheduled_at = _int(scheduled_at, "scheduled-at", minimum=1)
        if scheduled_at < self.config.effective_start or scheduled_at > self.config.effective_end or (scheduled_at - self.config.effective_start) % self.config.cadence_seconds:
            raise AcquisitionConflictError("acquisition:slot-grid")
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
            if int(connection.execute("SELECT COUNT(*) FROM acquisition_slots").fetchone()[0]) >= self.config.max_slots:
                raise AcquisitionConflictError("acquisition:slot-cap")
            empty = [slot_id, scheduled_at, "DUE", None, None, 0] + [None] * (len(independent.SLOT_COLUMNS) - 6)
            connection.execute("INSERT INTO acquisition_slots VALUES(" + ",".join("?" for _ in independent.SLOT_COLUMNS) + ")", tuple(empty))
            result = self._transition_locked(connection, slot_id=slot_id, action="CREATE_SLOT", attempt=0, request_digest=self.config.request_digest, prior_state="", next_state="DUE", slot_updates={}, observed_at=scheduled_at)
            connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], slot_id))
            connection.commit()
            return {**result, "scheduled_at": scheduled_at, "state": "DUE", "attempt": 0}
        except AcquisitionConflictError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            if "busy" in str(exc).lower() or "locked" in str(exc).lower():
                raise AcquisitionBusyError("acquisition:busy") from exc
            raise AuthenticatedSourceAcquisitionError("acquisition:database") from exc
        finally:
            connection.close()

    def _release_expired_locked(self, connection: sqlite3.Connection, now: int) -> int:
        rows = connection.execute("SELECT * FROM acquisition_slots WHERE state IN ('LEASED','CAPTURED','QUARANTINE_PENDING') AND lease_until IS NOT NULL AND lease_until<=? ORDER BY scheduled_at,slot_id", (now,)).fetchall()
        released = 0
        for row_value in rows:
            row = dict(row_value)
            attempt = int(row["attempt"])
            if row["state"] == "QUARANTINE_PENDING":
                if attempt >= self.config.max_attempts:
                    next_state, action, failure = "QUARANTINE_UNCONFIRMED", "QUARANTINE_UNCONFIRMED", "quarantine-unconfirmed"
                else:
                    next_state, action, failure = "QUARANTINE_PENDING", "RECOVER_QUARANTINE", "response-loss"
            else:
                next_state = "HELD" if attempt >= self.config.max_attempts else "DUE"
                action, failure = ("FAIL", "timeout")
            result = self._transition_locked(connection, slot_id=row["slot_id"], action=action, attempt=attempt, request_digest=self.config.request_digest, prior_state=row["state"], next_state=next_state, slot_updates={"state": next_state, "lease_id": None, "lease_until": None, "failure_code": failure}, observed_at=now)
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
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _lease_row_locked(self, connection: sqlite3.Connection, row: Mapping[str, object], now: int, *, recovery: bool = False) -> AcquisitionLease:
        attempt = int(row["attempt"]) if recovery else int(row["attempt"]) + 1
        if attempt > self.config.max_attempts:
            raise AcquisitionConflictError("acquisition:attempt-cap")
        lease_id = _digest("lease", {"slot_id": row["slot_id"], "attempt": attempt, "recovery": recovery})
        until = now + self.config.lease_seconds
        slot_updates: dict[str, object] = {"state": "QUARANTINE_PENDING" if recovery else "LEASED", "lease_id": lease_id, "lease_until": until, "attempt": attempt, "failure_code": None}
        if not recovery:
            head = self.quarantine_service.head()
            slot_updates["quarantine_expected_head"] = "" if head is None else str(head["head_artifact_id"])
        result = self._transition_locked(connection, slot_id=row["slot_id"], action="RECOVER_QUARANTINE" if recovery else "LEASE", attempt=attempt, request_digest=self.config.request_digest, prior_state=row["state"], next_state="QUARANTINE_PENDING" if recovery else "LEASED", slot_updates=slot_updates, observed_at=now)
        connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], row["slot_id"]))
        return AcquisitionLease(str(row["slot_id"]), lease_id, attempt, until, int(row["scheduled_at"]))

    def claim_next(self, now: int | None = None) -> AcquisitionLease | None:
        current = _int(self.clock() if now is None else now, "now", minimum=1)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._release_expired_locked(connection, current)
            row = connection.execute("SELECT * FROM acquisition_slots WHERE state='DUE' AND scheduled_at<=? ORDER BY scheduled_at,slot_id LIMIT 1", (current,)).fetchone()
            if row is None:
                connection.commit()
                return None
            lease = self._lease_row_locked(connection, dict(row), current)
            connection.commit()
            return lease
        except Exception:
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
            if int(row["scheduled_at"]) > current:
                raise AcquisitionConflictError("acquisition:future-slot")
            lease = self._lease_row_locked(connection, row, current)
            connection.commit()
            return lease
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def recover_quarantine(self, slot_id: str, now: int | None = None) -> AcquisitionLease:
        _hex(slot_id, "slot-id")
        current = _int(self.clock() if now is None else now, "now", minimum=1)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._slot(connection, slot_id)
            if row is None or row["state"] not in {"QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED"} or row["lease_id"] is not None:
                raise AcquisitionConflictError("acquisition:quarantine-recovery")
            if row["state"] == "QUARANTINE_UNCONFIRMED":
                raise AcquisitionConflictError("acquisition:quarantine-unconfirmed")
            lease = self._lease_row_locked(connection, row, current, recovery=True)
            connection.commit()
            return lease
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
            if row is None or int(row["attempt"]) != attempt or row["state"] not in {"LEASED", "CAPTURED", "QUARANTINE_PENDING", "QUARANTINED"} and not (row["state"] == "QUARANTINE_UNCONFIRMED" and attempt == int(row["attempt"])):
                raise AcquisitionConflictError("acquisition:lease")
            normal_lease_id = _digest("lease", {"slot_id": str(slot_id), "attempt": attempt, "recovery": False})
            recovery_lease_id = _digest("lease", {"slot_id": str(slot_id), "attempt": attempt, "recovery": True})
            allowed_lease_ids = {normal_lease_id} if row["state"] in {"LEASED", "CAPTURED"} else {normal_lease_id, recovery_lease_id}
            if row["state"] in {"LEASED", "CAPTURED", "QUARANTINE_PENDING"} and row["lease_id"] != lease_id:
                raise AcquisitionConflictError("acquisition:lease")
            if row["state"] in {"QUARANTINED", "QUARANTINE_UNCONFIRMED"} and str(lease_id) not in allowed_lease_ids:
                raise AcquisitionConflictError("acquisition:lease")
            if row["lease_until"] is not None and int(row["lease_until"]) <= int(self.clock()) and row["state"] not in {"QUARANTINED", "QUARANTINE_UNCONFIRMED"}:
                raise AcquisitionConflictError("acquisition:lease-expired")
            return row
        finally:
            connection.close()

    def _record_failure(self, slot_id: str, lease_id: str, attempt: int, code: str) -> None:
        code = code if code in SAFE_FAILURES else "verifier"
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._slot(connection, slot_id)
            if row is None or row["lease_id"] != lease_id or int(row["attempt"]) != attempt or row["state"] not in {"LEASED", "CAPTURED"}:
                raise AcquisitionConflictError("acquisition:lease")
            next_state = "HELD" if attempt >= self.config.max_attempts else "DUE"
            result = self._transition_locked(connection, slot_id=slot_id, action="FAIL", attempt=attempt, request_digest=self.config.request_digest, prior_state=row["state"], next_state=next_state, slot_updates={"state": next_state, "lease_id": None, "lease_until": None, "failure_code": code}, observed_at=int(self.clock()))
            connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], slot_id))
            connection.commit()
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _capture_values(self, lease: AcquisitionLease, envelope_result: Mapping[str, object], envelope_raw: bytes, artifact: external_adapter.ExternalSourceArtifactV1, capture_result: Mapping[str, object], verifier: _NcCaptureVerifier, attestations: Mapping[tuple[int, int], FhirTransportAttestationV1], expected_head: str) -> dict[str, object]:
        if envelope_result["observation_time"] != lease.scheduled_at:
            raise AcquisitionConflictError("acquisition:observation-time")
        return {"envelope_id": envelope_result["envelope_id"], "envelope_digest": _raw_digest(envelope_raw), "artifact_id": artifact.artifact_id, "artifact_digest": _raw_digest(artifact.raw), "capture_id": capture_result["capture_id"], "payload_digest": capture_result["payload_sha3_512"], "snapshot_root": envelope_result["snapshot_root"], "observed_at": envelope_result["observation_time"], "fetched_at": max(item.fetched_at for item in attestations.values()), "quarantine_expected_head": expected_head, "capture_attempt": lease.attempt, "page_count": len(verifier.page_digests), "page_digests_raw": _canonical(list(verifier.page_digests)), "selected_pages_raw": _canonical(verifier.selected_pages)}

    def _record_captured(self, lease: AcquisitionLease, *, envelope_result: Mapping[str, object], envelope_raw: bytes, artifact: external_adapter.ExternalSourceArtifactV1, capture_result: Mapping[str, object], verifier: _NcCaptureVerifier, attestations: Mapping[tuple[int, int], FhirTransportAttestationV1], expected_head: str) -> dict[str, object]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._slot(connection, lease.slot_id)
            if row is None or row["lease_id"] != lease.lease_id or int(row["attempt"]) != lease.attempt or row["state"] not in {"LEASED", "CAPTURED", "QUARANTINE_PENDING"}:
                if row is not None and row["state"] == "QUARANTINED" and int(row["attempt"]) == lease.attempt:
                    values = self._capture_values(lease, envelope_result, envelope_raw, artifact, capture_result, verifier, attestations, expected_head)
                    for key in values:
                        if key != "quarantine_expected_head" and row[key] != values[key]:
                            raise AcquisitionConflictError("acquisition:capture-conflict")
                    connection.commit()
                    return {"accepted": True, "state": "QUARANTINED", "slot_id": lease.slot_id, "artifact_id": row["artifact_id"], "quarantine_receipt_digest": row["quarantine_receipt_digest"]}
                raise AcquisitionConflictError("acquisition:lease")
            values = self._capture_values(lease, envelope_result, envelope_raw, artifact, capture_result, verifier, attestations, expected_head)
            if row["state"] in {"CAPTURED", "QUARANTINE_PENDING"}:
                if any(row[key] != value for key, value in values.items() if key != "quarantine_expected_head"):
                    raise AcquisitionConflictError("acquisition:capture-conflict")
                connection.commit()
                return {"accepted": True, "state": row["state"], "slot_id": lease.slot_id, **values}
            result = self._transition_locked(connection, slot_id=lease.slot_id, action="CAPTURE", attempt=lease.attempt, request_digest=self.config.request_digest, prior_state="LEASED", next_state="CAPTURED", slot_updates={**values, "state": "CAPTURED", "failure_code": None}, observed_at=lease.scheduled_at)
            for attestation in attestations.values():
                row_value = _attestation_row(attestation, slot_id=lease.slot_id)
                connection.execute("INSERT INTO acquisition_attestations VALUES(" + ",".join("?" for _ in independent.ATTESTATION_COLUMNS) + ")", tuple(row_value[name] for name in independent.ATTESTATION_COLUMNS))
            connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], lease.slot_id))
            connection.commit()
            return {**result, "state": "CAPTURED", "slot_id": lease.slot_id, **values}
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _request_key(self, slot_id: str) -> str:
        return "AQ" + slot_id[:30]

    def _begin_quarantine(self, lease: AcquisitionLease, *, artifact: external_adapter.ExternalSourceArtifactV1, expected_head: str) -> dict[str, object]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._slot(connection, lease.slot_id)
            artifact_digest = _raw_digest(artifact.raw)
            if row is not None and row["state"] == "QUARANTINED" and int(row["attempt"]) == lease.attempt:
                if row["artifact_id"] != artifact.artifact_id or row["artifact_digest"] != artifact_digest:
                    raise AcquisitionConflictError("acquisition:quarantine-conflict")
                connection.commit()
                return {"accepted": True, "state": "QUARANTINED", "slot_id": lease.slot_id, "artifact_id": row["artifact_id"], "quarantine_receipt_digest": row["quarantine_receipt_digest"]}
            if (
                row is None
                or int(row["attempt"]) != lease.attempt
                or row["state"] not in {"CAPTURED", "QUARANTINE_PENDING"}
                or row["lease_id"] != lease.lease_id
                or row["lease_until"] is None
                or int(row["lease_until"]) <= int(self.clock())
            ):
                raise AcquisitionConflictError("acquisition:lease")
            request_key = self._request_key(lease.slot_id)
            request_digest = quarantine._request_digest(request_key)
            material_digest = _raw_digest(artifact.raw)
            expected = {"quarantine_request_digest": request_digest, "quarantine_material_digest": material_digest, "artifact_id": artifact.artifact_id, "artifact_digest": _raw_digest(artifact.raw), "quarantine_expected_head": expected_head, "quarantine_database_id": self.config.quarantine_database_id, "quarantine_policy_digest": self.config.quarantine_policy_digest, "quarantine_chain_id": self.config.quarantine_chain_id, "quarantine_dispatch_attempt": lease.attempt}
            if row["state"] == "QUARANTINE_PENDING":
                if any(row[key] != value for key, value in expected.items()):
                    raise AcquisitionConflictError("acquisition:dispatch-conflict")
                connection.commit()
                return {"accepted": True, "state": row["state"], "slot_id": lease.slot_id, **expected}
            result = self._transition_locked(connection, slot_id=lease.slot_id, action="BEGIN_QUARANTINE", attempt=lease.attempt, request_digest=self.config.request_digest, prior_state="CAPTURED", next_state="QUARANTINE_PENDING", slot_updates={"state": "QUARANTINE_PENDING", **expected, "failure_code": "response-loss"}, observed_at=int(self.clock()))
            connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], lease.slot_id))
            connection.commit()
            return {**result, "state": "QUARANTINE_PENDING", "slot_id": lease.slot_id, **expected, "request_key": request_key}
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _record_quarantined(self, slot_id: str, *, artifact_id: str, artifact_digest: str, quarantine_result: Mapping[str, object]) -> dict[str, object]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._slot(connection, slot_id)
            if row is None or row["state"] not in {"QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED", "QUARANTINED"}:
                raise AcquisitionConflictError("acquisition:quarantine-state")
            verified = quarantine_result.get("verified_receipt")
            if not isinstance(verified, quarantine.independent.VerifiedAdmissionReceiptV1):
                raise AcquisitionConflictError("acquisition:quarantine-receipt-type")
            receipt_raw = verified.receipt_raw
            receipt_digest = verified.receipt_digest
            if verified.database_id != self.config.quarantine_database_id or verified.policy_digest != self.config.quarantine_policy_digest or verified.chain_id != self.config.quarantine_chain_id or verified.artifact_id != artifact_id or verified.artifact_digest != artifact_digest:
                raise AcquisitionConflictError("acquisition:quarantine-binding")
            result_bindings = {
                "operation_id": verified.operation_id,
                "action": verified.action,
                "policy_digest": verified.policy_digest,
                "database_id": verified.database_id,
                "chain_id": verified.chain_id,
                "artifact_id": verified.artifact_id,
                "artifact_digest": verified.artifact_digest,
                "capture_id": verified.capture_id,
                "prior_head": verified.prior_head,
                "head_artifact_id": verified.head_artifact_id,
                "head_root": verified.after_root,
                "after_root": verified.after_root,
                "state": verified.state,
                "sequence": verified.sequence,
                "transition_id": verified.transition_id,
                "receipt_raw": verified.receipt_raw,
                "receipt_digest": verified.receipt_digest,
            }
            if (
                verified.action not in {quarantine.ACTION_ADMIT, quarantine.ACTION_SUPERSEDE}
                or verified.state != quarantine.QUARANTINE_STATUS
                or quarantine_result.get("accepted") is not True
                or quarantine_result.get("durable_status") != quarantine.QUARANTINE_STATUS
                or quarantine_result.get("flags") != quarantine.FIXED_FLAGS
                or any(quarantine_result.get(key) != value for key, value in result_bindings.items())
                or row["artifact_id"] != verified.artifact_id
                or row["artifact_digest"] != verified.artifact_digest
                or row["quarantine_expected_head"] != verified.prior_head
                or row["quarantine_database_id"] != verified.database_id
                or row["quarantine_policy_digest"] != verified.policy_digest
                or row["quarantine_chain_id"] != verified.chain_id
            ):
                raise AcquisitionConflictError("acquisition:quarantine-binding")
            if row["state"] == "QUARANTINED":
                if any((
                    row["capture_id"] != verified.capture_id,
                    row["quarantine_head"] != verified.head_artifact_id,
                    row["quarantine_head_root"] != verified.after_root,
                    row["quarantine_transition_id"] != verified.transition_id,
                    row["quarantine_receipt_digest"] != receipt_digest,
                    row["quarantine_receipt_raw"] != receipt_raw,
                )):
                    raise AcquisitionConflictError("acquisition:quarantine-conflict")
                connection.commit()
                return {"accepted": True, "state": "QUARANTINED", "slot_id": slot_id, "artifact_id": verified.artifact_id, "quarantine_receipt_digest": receipt_digest, **independent.FIXED_FLAGS}
            updates = {"state": "QUARANTINED", "lease_id": None, "lease_until": None, "artifact_id": verified.artifact_id, "artifact_digest": verified.artifact_digest, "capture_id": verified.capture_id, "quarantine_head": verified.head_artifact_id, "quarantine_head_root": verified.after_root, "quarantine_transition_id": verified.transition_id, "quarantine_receipt_digest": receipt_digest, "quarantine_receipt_raw": receipt_raw, "failure_code": None}
            result = self._transition_locked(connection, slot_id=slot_id, action="CONFIRM_QUARANTINE", attempt=int(row["attempt"]), request_digest=self.config.request_digest, prior_state=row["state"], next_state="QUARANTINED", slot_updates=updates, observed_at=int(self.clock()))
            connection.execute("UPDATE acquisition_slots SET last_operation_id=? WHERE slot_id=?", (result["operation_id"], slot_id))
            connection.commit()
            return {**result, "state": "QUARANTINED", "slot_id": slot_id, "artifact_id": verified.artifact_id, "quarantine_receipt_digest": receipt_digest, **independent.FIXED_FLAGS}
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _lookup_quarantine(self, row: Mapping[str, object]) -> dict[str, object] | None:
        if row["artifact_id"] in (None, "") or row["artifact_digest"] in (None, "") or row["quarantine_request_digest"] in (None, ""):
            return None
        return self.quarantine_service.lookup_request(self._request_key(str(row["slot_id"])), artifact_id=str(row["artifact_id"]), artifact_digest=str(row["artifact_digest"]), expected_head=str(row["quarantine_expected_head"] or "") or None)

    def _validate_port(self, transport: AuthenticatedFhirTransportPort) -> None:
        if getattr(transport, "transport_id", None) != self.config.transport_id or getattr(transport, "transport_epoch", None) != self.config.transport_epoch:
            raise AuthenticatedSourceAcquisitionError("acquisition:transport-mismatch")

    def acquire(self, lease: AcquisitionLease | Mapping[str, object], transport: AuthenticatedFhirTransportPort) -> dict[str, object]:
        if transport is None:
            raise AuthenticatedSourceAcquisitionError("acquisition:transport-required")
        self._validate_port(transport)
        loaded = self._load_lease(lease)
        lease_obj = AcquisitionLease(str(loaded["slot_id"]), str(loaded["lease_id"]), int(loaded["attempt"]), int(loaded["lease_until"] or 0), int(loaded["scheduled_at"]))
        self.active_lease_attempt = lease_obj.attempt
        if loaded["state"] == "QUARANTINED":
            return {"accepted": True, "state": "QUARANTINED", "slot_id": lease_obj.slot_id, "artifact_id": loaded["artifact_id"], "quarantine_receipt_digest": loaded["quarantine_receipt_digest"], **independent.FIXED_FLAGS}
        if loaded["state"] in {"QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED"}:
            found = self._lookup_quarantine(loaded)
            if found is not None:
                return self._record_quarantined(str(loaded["slot_id"]), artifact_id=str(loaded["artifact_id"]), artifact_digest=str(loaded["artifact_digest"]), quarantine_result=found)
            if loaded["state"] == "QUARANTINE_UNCONFIRMED":
                raise AcquisitionConflictError("acquisition:quarantine-unconfirmed")
        wrapper = _AuthenticatedTransportAdapter(self, transport, lease_obj.scheduled_at)
        try:
            envelope_raw = nc_fhir.build_fixture_envelope(wrapper, profile=self.profile)
            envelope_result = nc_independent.verify_bytes(envelope_raw, profile=self.profile)
            if envelope_result["observation_time"] != lease_obj.scheduled_at or envelope_result["source_status"] != "COMPLETE" or envelope_result["page_complete"] is not True:
                raise AcquisitionHold("acquisition:incomplete")
            if envelope_result["freshness"] == "STALE":
                raise AcquisitionHold("acquisition:stale")
            capture_verifier = _NcCaptureVerifier(self, wrapper.attestations)
            artifact = external_adapter.build_artifact(self.external_policy, capture_verifier, envelope_raw)
            capture_result = external_independent.verify_artifact(artifact.raw, policy=self.external_policy.material(), capture_raw=envelope_raw)
            if capture_result["derived_status"] != "OBSERVATION_ADMITTED":
                raise AcquisitionHold("acquisition:adapter-hold")
            current_head = self.quarantine_service.head()
            expected_head = str(loaded["quarantine_expected_head"] or "") if loaded["state"] in {"LEASED", "CAPTURED", "QUARANTINE_PENDING", "QUARANTINE_UNCONFIRMED"} and loaded["quarantine_expected_head"] is not None else str(current_head["head_artifact_id"]) if current_head else ""
            captured = self._record_captured(lease_obj, envelope_result=envelope_result, envelope_raw=envelope_raw, artifact=artifact, capture_result=capture_result, verifier=capture_verifier, attestations=wrapper.attestations, expected_head=expected_head)
            dispatch = self._begin_quarantine(lease_obj, artifact=artifact, expected_head=str(captured.get("quarantine_expected_head") or expected_head))
            if dispatch.get("state") == "QUARANTINED":
                return {**dispatch, "envelope_id": envelope_result["envelope_id"], "source_status": envelope_result["source_status"], "production_source_authentication": False, **independent.FIXED_FLAGS}
            request_key = self._request_key(lease_obj.slot_id)
            try:
                q_result = self.quarantine_service.admit(request_key, artifact.raw, expected_head=str(dispatch.get("quarantine_expected_head") or "") or None)
            except (quarantine.QuarantineResponseLost, quarantine.QuarantineBusyError, quarantine.QuarantineConflictError) as exc:
                found = self._lookup_quarantine(self._slot_from_disk(lease_obj.slot_id))
                if found is not None:
                    return self._record_quarantined(lease_obj.slot_id, artifact_id=artifact.artifact_id, artifact_digest=_raw_digest(artifact.raw), quarantine_result=found)
                if isinstance(exc, quarantine.QuarantineResponseLost):
                    raise AcquisitionResponseLost("acquisition:response-loss") from exc
                if isinstance(exc, quarantine.QuarantineBusyError):
                    raise AcquisitionBusyError("acquisition:busy") from exc
                raise AcquisitionConflictError("acquisition:quarantine-head") from exc
            confirmed = self._record_quarantined(lease_obj.slot_id, artifact_id=artifact.artifact_id, artifact_digest=_raw_digest(artifact.raw), quarantine_result=q_result)
            return {**confirmed, "envelope_id": envelope_result["envelope_id"], "source_status": envelope_result["source_status"], "production_source_authentication": False, **independent.FIXED_FLAGS}
        except (AcquisitionResponseLost, AcquisitionBusyError, AcquisitionConflictError):
            raise
        except AcquisitionHold as exc:
            self._record_failure(lease_obj.slot_id, lease_obj.lease_id, lease_obj.attempt, str(exc).split(":")[-1] if str(exc).split(":")[-1] in SAFE_FAILURES else "incomplete")
            raise
        except (nc_fhir.NcMedicaidFhirError, nc_independent.IndependentNcMedicaidFhirError, external_adapter.ExternalSourceAdapterError, external_independent.IndependentExternalSourceError, AuthenticatedSourceAcquisitionError) as exc:
            code = str(exc).split(":")[-1]
            mapped = code if code in SAFE_FAILURES else "verifier"
            self._record_failure(lease_obj.slot_id, lease_obj.lease_id, lease_obj.attempt, mapped)
            raise AuthenticatedSourceAcquisitionError(f"acquisition:{mapped}") from exc

    def _slot_from_disk(self, slot_id: str) -> dict[str, object]:
        connection = self._connect()
        try:
            row = self._slot(connection, slot_id)
            if row is None:
                raise AcquisitionConflictError("acquisition:slot-missing")
            return row
        finally:
            connection.close()

    def integrity(self) -> dict[str, object]:
        try:
            return independent.verify_database(self.database, config=self.config.material())
        except independent.IndependentAcquisitionError as exc:
            raise AuthenticatedSourceAcquisitionError(str(exc)) from exc

    def export_bytes(self) -> bytes:
        try:
            snapshot_result = independent.snapshot_database(self.database, config=self.config.material())
            snapshot = snapshot_result["snapshot"]
            body: dict[str, object] = {"schema": EXPORT_SCHEMA, "schema_version": EXPORT_VERSION, "config": self.config.material(), "config_digest": self.config.digest, "chain_id": independent._chain_id(self.config.digest), "meta": snapshot["acquisition_meta"], "slots": [], "operations": [], "transitions": [], "attestations": snapshot["acquisition_attestations"], **independent.FIXED_FLAGS}
            body["slots"] = [{**{key: row[key] for key in independent.SLOT_COLUMNS if key not in {"quarantine_receipt_raw", "page_digests_raw", "selected_pages_raw"}}, "quarantine_receipt_hex": None if row["quarantine_receipt_raw"] is None else bytes(row["quarantine_receipt_raw"]).hex(), "page_digests_hex": None if row["page_digests_raw"] is None else bytes(row["page_digests_raw"]).hex(), "selected_pages_hex": None if row["selected_pages_raw"] is None else bytes(row["selected_pages_raw"]).hex()} for row in snapshot["acquisition_slots"]]
            body["operations"] = [{**{key: row[key] for key in independent.OPERATION_COLUMNS if key not in {"material_raw", "receipt_raw"}}, "material_hex": bytes(row["material_raw"]).hex(), "receipt_hex": bytes(row["receipt_raw"]).hex()} for row in snapshot["acquisition_operations"]]
            body["transitions"] = [{**{key: row[key] for key in independent.TRANSITION_COLUMNS if key != "transition_raw"}, "transition_hex": bytes(row["transition_raw"]).hex()} for row in snapshot["acquisition_transitions"]]
            body["export_root"] = _digest("export-root", body)
            raw = _canonical(body)
            if len(raw) > MAX_EXPORT_BYTES:
                raise AuthenticatedSourceAcquisitionError("acquisition:export-cap")
            independent.verify_export_bytes(raw, config=self.config.material())
            return raw
        except independent.IndependentAcquisitionError as exc:
            raise AuthenticatedSourceAcquisitionError(str(exc)) from exc

    def support_snapshot(self) -> dict[str, object]:
        try:
            return independent.support_snapshot(self.database, config=self.config.material())
        except independent.IndependentAcquisitionError as exc:
            raise AuthenticatedSourceAcquisitionError(str(exc)) from exc

    @classmethod
    def restore_export(cls, destination: str | Path, raw: bytes, *, config: AuthenticatedSourceAcquisitionConfigV1, external_policy: external_adapter.ExternalSourcePolicyV1, quarantine_service: quarantine.ExternalSourceQuarantineService, fault_injector: Callable[[str], None] | None = None) -> "AuthenticatedSourceAcquisitionService":
        try:
            verified = independent.verify_export_bytes(raw, config=config.material())
        except independent.IndependentAcquisitionError as exc:
            raise AuthenticatedSourceAcquisitionError(str(exc)) from exc

        def build_stage(stage: Path) -> None:
            service = cls(stage, config=config, external_policy=external_policy, quarantine_service=quarantine_service, fault_injector=fault_injector)
            connection = service._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                for table in independent.TABLE_COLUMNS:
                    connection.execute(f"DELETE FROM {table}")
                snapshot = verified["snapshot"]
                for table in independent.TABLE_COLUMNS:
                    for row in snapshot[table]:
                        connection.execute(f"INSERT INTO {table} VALUES(" + ",".join("?" for _ in independent.TABLE_COLUMNS[table]) + ")", tuple(row[column] for column in independent.TABLE_COLUMNS[table]))
                connection.commit()
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

        def verify_database(path: Path) -> object:
            try:
                return independent.verify_database(path, config=config.material())
            except independent.IndependentAcquisitionError as exc:
                raise AuthenticatedSourceAcquisitionError(str(exc)) from exc

        def open_service(path: Path) -> AuthenticatedSourceAcquisitionService:
            return cls(path, config=config, external_policy=external_policy, quarantine_service=quarantine_service)

        try:
            return restore_publication.publish_create_only(
                destination, raw, expected_evidence=verified, build_stage=build_stage, verify_database=verify_database,
                open_service=open_service, fault_injector=fault_injector,
            )
        except (AcquisitionResponseLost, AcquisitionInjectedFault):
            raise
        except restore_publication.RestorePublicationConflict as exc:
            raise AcquisitionConflictError(str(exc)) from exc
        except (restore_publication.RestorePublicationError, AuthenticatedSourceAcquisitionError) as exc:
            raise AuthenticatedSourceAcquisitionError(str(exc)) from exc


def restore_export(destination: str | Path, raw: bytes, *, config: AuthenticatedSourceAcquisitionConfigV1, external_policy: external_adapter.ExternalSourcePolicyV1, quarantine_service: quarantine.ExternalSourceQuarantineService, fault_injector: Callable[[str], None] | None = None) -> AuthenticatedSourceAcquisitionService:
    return AuthenticatedSourceAcquisitionService.restore_export(destination, raw, config=config, external_policy=external_policy, quarantine_service=quarantine_service, fault_injector=fault_injector)


__all__ = ["SCHEMA", "SCHEMA_VERSION", "EXPORT_SCHEMA", "EXPORT_VERSION", "STATES", "SAFE_FAILURES", "AuthenticatedSourceAcquisitionError", "AcquisitionConflictError", "AcquisitionBusyError", "AcquisitionResponseLost", "AcquisitionInjectedFault", "AcquisitionHold", "AuthenticatedSourceAcquisitionConfigV1", "request_digest_for_page", "request_digest_for_profile", "AuthenticatedFhirRequestV1", "FhirTransportAttestationV1", "AuthenticatedFhirResponseV1", "AuthenticatedFhirTransportPort", "LiveAuthenticatedFhirTransport", "AcquisitionLease", "AuthenticatedSourceAcquisitionService", "restore_export", "_digest"]
