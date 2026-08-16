"""Verifier-owned, synthetic-only NC Medicaid FHIR source profile.

The profile is a fixture qualification contract, not a live-source authorization.
Its graph projection deliberately uses the existing V2 source-role grammar while
declaring that the projection is observation-only and never an enrollment,
licensing, credentialing, completeness, or nonmembership claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

from app.mirror.source_admission import EvidenceMode, SourceProfile, SourceRole


class NcMedicaidFhirProfileError(ValueError):
    """Raised when the immutable fixture profile is not internally consistent."""


SOURCE_PROFILE_ID = "ncmedicaid.provider-directory.fhir-r4.practitioner-role-location.v1"
SOURCE_PROFILE_VERSION = 1
OWNER_ID = "NCDHHS"
SYSTEM_ID = "NC Medicaid Provider Directory API"
BASE_URL = "https://provider-directory-api.connect.medicaid.ncdhhs.gov/fhir"
HOST = "provider-directory-api.connect.medicaid.ncdhhs.gov"
FHIR_VERSION = "4.0.1"
SOURCE_MEANING = "provider-directory-observation-associated-with-NCTracks-and-health-plan-contract-data"
TRANSPORT_PROVENANCE = "official-hostname-over-tls-unverified"
RECORD_AUTHENTICATION = "undocumented"
CAPABILITY_STATEMENT_IDENTITY = "NC_MEDICAID_FHIR_CAPABILITY_STATEMENT_UNBOUND_V1"
CAPABILITY_STATEMENT_DIGEST: str | None = None
VERIFIER_ID = "SYNTH_NC_MEDICAID_FHIR_VERIFIER_V1"
VERIFIER_EPOCH = 1
SCOPE = SOURCE_PROFILE_ID
SYNTHETIC_SUBJECT = "SYNTH_NC_MEDICAID_PROVIDER_001"
SYNTHETIC_PRACTITIONER_ID = "SYNTH_NC_PRACTITIONER_001"
SYNTHETIC_ROLE_ID = "SYNTH_NC_PRACTITIONER_ROLE_001"
SYNTHETIC_LOCATION_ID = "SYNTH_NC_LOCATION_001"
SYNTHETIC_CREDENTIAL_ID = "SYNTH_NC_FHIR_DIRECTORY_PRACTITIONER_001"
SYNTHETIC_ENROLLMENT_ID = "SYNTH_NC_FHIR_DIRECTORY_ROLE_LOCATION_001"
FIXTURE_OBSERVATION_TIME = 7_000
FIXTURE_FETCHED_AT = "2026-08-15T12:00:00Z"
FIXTURE_LAST_UPDATED = "2026-08-14T12:00:00Z"
MAX_SERVER_MARKER_AGE_DAYS = 365

ALLOWED_RESOURCE_TYPES = ("Practitioner", "PractitionerRole", "Location")
RESOURCE_CARDINALITY = (
    ("Practitioner", 1),
    ("PractitionerRole", 1),
    ("Location", 1),
)
ALLOWED_RESOURCE_FIELDS = (
    ("Practitioner", ("resourceType", "id", "identifier", "name", "active")),
    (
        "PractitionerRole",
        (
            "resourceType",
            "id",
            "identifier",
            "active",
            "practitioner",
            "location",
            "code",
            "specialty",
            "network",
            "period",
            "endpoint",
        ),
    ),
    ("Location", ("resourceType", "id", "identifier", "name", "status", "address", "endpoint")),
)
QUERY_PARAMETERS = (
    ("_count", "3"),
    ("_include", "PractitionerRole:location"),
    ("_include", "PractitionerRole:practitioner"),
    ("identifier", "urn:synthetic:ncmedicaid|SYNTH_NC_MEDICAID_PROVIDER_001"),
)
PAGE_PARAMETER = "page"
REQUEST_URL = BASE_URL + "/Practitioner?_count=3&_include=PractitionerRole%3Alocation&_include=PractitionerRole%3Apractitioner&identifier=urn%3Asynthetic%3Ancmedicaid%7CSYNTH_NC_MEDICAID_PROVIDER_001"
ALLOWED_MEDIA_TYPE = "application/fhir+json"
TRANSPORT_CAPS = {
    "max_page_bytes": 131_072,
    "max_envelope_bytes": 524_288,
    "max_pages": 4,
    "max_resources": 3,
    "max_depth": 20,
    "max_nodes": 8_192,
    "max_string_bytes": 256,
    "max_identifiers": 4,
    "max_retries": 2,
    "max_retry_after_seconds": 30,
    "timeout_seconds": 5,
}
CLAIM_FLAGS = {
    "observation_only": True,
    "record_returned_by_source": True,
    "source_truth_proven": False,
    "enrollment_status_proven": False,
    "license_status_proven": False,
    "credential_status_proven": False,
    "completeness": "UNKNOWN",
    "allow_nonmembership": False,
    "production_source_authentication": False,
    "live_transport_authorized": False,
    "synthetic_only": True,
    "production_usable": False,
    "proofSuiteId": None,
}

_GRAPH_ROLES = (
    SourceRole(
        "SYNTH_NC_FHIR_PRACTITIONER",
        "FHIR_PRACTITIONER",
        "CREDENTIAL",
        "SYNTH_NC_FHIR_DIRECTORY_OBSERVATION_AUTHORITY",
        "SYNTH_NC_FHIR_DIRECTORY_PROVENANCE",
    ),
    SourceRole(
        "SYNTH_NC_FHIR_PRACTITIONER_ROLE_LOCATION",
        "FHIR_PRACTITIONER_ROLE_LOCATION",
        "ENROLLMENT",
        "SYNTH_NC_FHIR_DIRECTORY_OBSERVATION_AUTHORITY",
        "SYNTH_NC_FHIR_DIRECTORY_PROVENANCE",
    ),
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/NC-MEDICAID/FHIR/PROFILE/" + label + "/v1\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


@dataclass(frozen=True)
class NcMedicaidFhirSourceProfile:
    """Immutable state-side profile used by both fixture producer and verifier."""

    source_profile_id: str = SOURCE_PROFILE_ID
    version: int = SOURCE_PROFILE_VERSION
    owner: str = OWNER_ID
    system: str = SYSTEM_ID
    base_url: str = BASE_URL
    host: str = HOST
    fhir_version: str = FHIR_VERSION
    source_meaning: str = SOURCE_MEANING
    transport_provenance: str = TRANSPORT_PROVENANCE
    record_authentication: str = RECORD_AUTHENTICATION
    capability_statement_identity: str = CAPABILITY_STATEMENT_IDENTITY
    capability_statement_digest: str | None = CAPABILITY_STATEMENT_DIGEST
    allowed_resource_types: tuple[str, ...] = ALLOWED_RESOURCE_TYPES
    resource_cardinality: tuple[tuple[str, int], ...] = RESOURCE_CARDINALITY
    allowed_resource_fields: tuple[tuple[str, tuple[str, ...]], ...] = ALLOWED_RESOURCE_FIELDS
    query_parameters: tuple[tuple[str, str], ...] = QUERY_PARAMETERS
    page_parameter: str = PAGE_PARAMETER
    request_url: str = REQUEST_URL
    allowed_media_type: str = ALLOWED_MEDIA_TYPE
    transport_caps: Mapping[str, int] = field(default_factory=lambda: MappingProxyType(dict(TRANSPORT_CAPS)))
    observation_time: int = FIXTURE_OBSERVATION_TIME
    fetched_at: str = FIXTURE_FETCHED_AT
    max_server_marker_age_days: int = MAX_SERVER_MARKER_AGE_DAYS
    evidence_mode: str = "OBSERVATION_ONLY"
    completeness: str = "UNKNOWN"
    require_complete: bool = False
    allow_nonmembership: bool = False
    live_transport_authorized: bool = False
    synthetic_only: bool = True
    production_usable: bool = False

    def __post_init__(self) -> None:
        if (
            self.source_profile_id != SOURCE_PROFILE_ID
            or self.version != SOURCE_PROFILE_VERSION
            or self.owner != OWNER_ID
            or self.system != SYSTEM_ID
            or self.base_url != BASE_URL
            or self.host != HOST
            or self.fhir_version != FHIR_VERSION
            or self.source_meaning != SOURCE_MEANING
            or self.transport_provenance != TRANSPORT_PROVENANCE
            or self.record_authentication != RECORD_AUTHENTICATION
            or self.capability_statement_identity != CAPABILITY_STATEMENT_IDENTITY
            or self.capability_statement_digest is not None
            or self.allowed_resource_types != ALLOWED_RESOURCE_TYPES
            or self.resource_cardinality != RESOURCE_CARDINALITY
            or self.allowed_resource_fields != ALLOWED_RESOURCE_FIELDS
            or self.query_parameters != QUERY_PARAMETERS
            or self.page_parameter != PAGE_PARAMETER
            or self.request_url != REQUEST_URL
            or self.allowed_media_type != ALLOWED_MEDIA_TYPE
            or self.observation_time != FIXTURE_OBSERVATION_TIME
            or self.fetched_at != FIXTURE_FETCHED_AT
            or self.max_server_marker_age_days != MAX_SERVER_MARKER_AGE_DAYS
            or self.evidence_mode != "OBSERVATION_ONLY"
            or self.completeness != "UNKNOWN"
            or self.require_complete is not False
            or self.allow_nonmembership is not False
            or self.live_transport_authorized is not False
            or self.synthetic_only is not True
            or self.production_usable is not False
        ):
            raise NcMedicaidFhirProfileError("profile:fixed-contract")
        if urlsplit(self.base_url).hostname != self.host or not self.base_url.startswith("https://"):
            raise NcMedicaidFhirProfileError("profile:host")
        if set(self.transport_caps) != set(TRANSPORT_CAPS) or dict(self.transport_caps) != TRANSPORT_CAPS:
            raise NcMedicaidFhirProfileError("profile:transport-caps")

    def material(self) -> dict[str, object]:
        return {
            "source_profile_id": self.source_profile_id,
            "version": self.version,
            "owner": self.owner,
            "system": self.system,
            "base_url": self.base_url,
            "host": self.host,
            "fhir_version": self.fhir_version,
            "source_meaning": self.source_meaning,
            "transport_provenance": self.transport_provenance,
            "record_authentication": self.record_authentication,
            "capability_statement_identity": self.capability_statement_identity,
            "capability_statement_digest": self.capability_statement_digest,
            "allowed_resource_types": list(self.allowed_resource_types),
            "resource_cardinality": {key: value for key, value in self.resource_cardinality},
            "allowed_resource_fields": {key: list(value) for key, value in self.allowed_resource_fields},
            "query_parameters": [list(value) for value in self.query_parameters],
            "page_parameter": self.page_parameter,
            "request_url": self.request_url,
            "allowed_media_type": self.allowed_media_type,
            "transport_caps": dict(self.transport_caps),
            "observation_time": self.observation_time,
            "fetched_at": self.fetched_at,
            "max_server_marker_age_days": self.max_server_marker_age_days,
            "evidence_mode": self.evidence_mode,
            "completeness": self.completeness,
            "require_complete": self.require_complete,
            "allow_nonmembership": self.allow_nonmembership,
            "live_transport_authorized": self.live_transport_authorized,
            "synthetic_only": self.synthetic_only,
            "production_usable": self.production_usable,
        }

    @property
    def profile_digest(self) -> str:
        return _digest("source-profile", self.material())

    @property
    def graph_profile(self) -> SourceProfile:
        return SourceProfile(
            profile_id=self.source_profile_id,
            version=2,
            subject=SYNTHETIC_SUBJECT,
            scope=SCOPE,
            observation_time=None,
            effective_start=6_000,
            effective_end=9_000,
            source_roles=tuple(role.source_id for role in _GRAPH_ROLES),
            require_complete=False,
            verifier_id=VERIFIER_ID,
            verifier_epoch=VERIFIER_EPOCH,
            evidence_mode=EvidenceMode.OBSERVATION_ONLY,
            source_role_details=_GRAPH_ROLES,
            credential_id=SYNTHETIC_CREDENTIAL_ID,
            enrollment_id=SYNTHETIC_ENROLLMENT_ID,
            observation_start=6_000,
            observation_end=9_000,
            allow_nonmembership=False,
            source_contract_digest=self.profile_digest,
        )

    def binding(self) -> dict[str, object]:
        graph_profile = self.graph_profile
        return {
            "source_profile_id": self.source_profile_id,
            "source_profile_version": self.version,
            "source_profile_digest": self.profile_digest,
            "graph_profile_version": graph_profile.version,
            "graph_profile_digest": graph_profile.profile_digest,
            "source_meaning": self.source_meaning,
            "transport_provenance": self.transport_provenance,
            "record_authentication": self.record_authentication,
            "capability_statement_identity": self.capability_statement_identity,
            "capability_statement_digest": self.capability_statement_digest,
        }

    def page_url(self, sequence: int) -> str:
        if type(sequence) is not int or sequence < 0 or sequence >= self.transport_caps["max_pages"]:
            raise NcMedicaidFhirProfileError("profile:page")
        return self.request_url if sequence == 0 else self.request_url + "&" + self.page_parameter + "=" + str(sequence + 1)


NC_MEDICAID_PROFILE = NcMedicaidFhirSourceProfile()
NC_MEDICAID_GRAPH_PROFILE = NC_MEDICAID_PROFILE.graph_profile
NC_MEDICAID_GRAPH_PROFILE_REGISTRY: Mapping[str, SourceProfile] = MappingProxyType(
    {NC_MEDICAID_GRAPH_PROFILE.profile_id: NC_MEDICAID_GRAPH_PROFILE}
)


__all__ = [
    "ALLOWED_MEDIA_TYPE",
    "ALLOWED_RESOURCE_FIELDS",
    "ALLOWED_RESOURCE_TYPES",
    "BASE_URL",
    "CAPABILITY_STATEMENT_DIGEST",
    "CAPABILITY_STATEMENT_IDENTITY",
    "CLAIM_FLAGS",
    "FIXTURE_FETCHED_AT",
    "FIXTURE_LAST_UPDATED",
    "NC_MEDICAID_GRAPH_PROFILE",
    "NC_MEDICAID_GRAPH_PROFILE_REGISTRY",
    "NC_MEDICAID_PROFILE",
    "NcMedicaidFhirProfileError",
    "NcMedicaidFhirSourceProfile",
    "RECORD_AUTHENTICATION",
    "REQUEST_URL",
    "SOURCE_MEANING",
    "SOURCE_PROFILE_ID",
    "SOURCE_PROFILE_VERSION",
    "TRANSPORT_PROVENANCE",
]
