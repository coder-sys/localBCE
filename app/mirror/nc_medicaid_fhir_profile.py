"""One immutable synthetic NC Medicaid FHIR source contract.

The contract contains only source grammar, endpoint shape, verifier identity,
caps and fixed nonclaims.  Provider/capture identity and observation time live
in :class:`DynamicCaptureContext`, which is supplied by each verified capture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from types import MappingProxyType
from typing import Mapping
from urllib.parse import quote

from app.mirror.source_admission import EvidenceMode, SourceProfile, SourceRole


class NcMedicaidFhirProfileError(ValueError):
    """Raised when the immutable fixture contract is inconsistent."""


SOURCE_CONTRACT_SCHEMA = "mirror-ncmedicaid-fhir-source-contract-v3"
SOURCE_CONTRACT_VERSION = 3
SOURCE_PROFILE_ID = "ncmedicaid.provider-directory.fhir-r4.practitioner-role-location.v5"
SOURCE_PROFILE_VERSION = 5
OWNER_ID = "NCDHHS"
SYSTEM_ID = "NC Medicaid Provider Directory API"
BASE_URL = "https://provider-directory-api.connect.medicaid.ncdhhs.gov/fhir"
HOST = "provider-directory-api.connect.medicaid.ncdhhs.gov"
FHIR_VERSION = "4.0.1"
SOURCE_MEANING = "provider-directory-observation-associated-with-NCTracks-and-health-plan-contract-data"
TRANSPORT_PROVENANCE = "official-hostname-over-tls-unverified"
RECORD_AUTHENTICATION = "undocumented"
CAPABILITY_STATEMENT_IDENTITY = "NC_MEDICAID_FHIR_CAPABILITY_STATEMENT_UNBOUND_V4"
CAPABILITY_STATEMENT_DIGEST: str | None = None
VERIFIER_ID = "SYNTH_NC_MEDICAID_FHIR_VERIFIER_V5"
VERIFIER_EPOCH = 5
SCOPE = SOURCE_PROFILE_ID

# Capture defaults are fixture examples; the canonical resource variants below
# are immutable contract material.
SYNTHETIC_PRACTITIONER_ID = "SYNTH_NC_PRACTITIONER_001"
SYNTHETIC_ROLE_ID = "SYNTH_NC_PRACTITIONER_ROLE_001"
SYNTHETIC_LOCATION_ID = "SYNTH_NC_LOCATION_001"
SYNTHETIC_CHANGED_LOCATION_NAME = "Synthetic NC Site Changed"
FIXTURE_OBSERVATION_TIME = 7_000
FIXTURE_FETCHED_AT = 7_010
FIXTURE_LAST_UPDATED = "2026-08-14T12:00:00Z"
MAX_SERVER_MARKER_AGE_DAYS = 365
_CAPTURE_CLOCK = MappingProxyType({
    "kind": "SYNTHETIC_LOGICAL_SECONDS_V1", "reference_tick": 7_010,
    "reference_utc": "2026-08-14T12:00:00Z", "seconds_per_tick": 1,
})
# One contract-wide cap for the complete canonical intake frame.  The
# envelope and evidence caps remain separately typed below; this value is the
# bound that every boundary applies before parsing or copying the frame.
COMPLETE_FRAME_CAP_BYTES = 262_144

ALLOWED_RESOURCE_TYPES = ("Practitioner", "PractitionerRole", "Location")
RESOURCE_CARDINALITY = (("Practitioner", 1), ("PractitionerRole", 1), ("Location", 1))
ALLOWED_RESOURCE_FIELDS = (
    ("Practitioner", ("resourceType", "id", "identifier", "name", "active")),
    ("PractitionerRole", ("resourceType", "id", "identifier", "active", "practitioner", "location", "code", "specialty", "network", "period", "endpoint")),
    ("Location", ("resourceType", "id", "identifier", "name", "status", "address", "endpoint")),
)
QUERY_PARAMETER_TEMPLATE = (
    ("_count", "3"), ("_include", "PractitionerRole:location"),
    ("_include", "PractitionerRole:practitioner"), ("identifier", "urn:synthetic:ncmedicaid|{subject_locator_digest}"),
)
PAGE_PARAMETER = "page"
ALLOWED_MEDIA_TYPE = "application/fhir+json"
TRANSPORT_CAPS = {
    # 64 KiB evidence + the 19-byte magic/88-byte fixed header + four
    # 76-byte directory entries leave exactly 196,197 bytes for the
    # canonical envelope inside the 262,144-byte intake-artifact cap.
    "max_page_bytes": 131_072, "max_envelope_bytes": 196_197, "max_pages": 4,
    "complete_frame_bytes": COMPLETE_FRAME_CAP_BYTES,
    "max_resources": 3, "max_depth": 20, "max_nodes": 8_192,
    "max_string_bytes": 512, "max_identifiers": 4, "max_retries": 2,
    "max_retry_after_seconds": 30, "timeout_seconds": 5,
}
CLAIM_FLAGS = {
    "observation_only": True, "record_returned_by_source": True,
    "source_truth_proven": False, "enrollment_status_proven": False,
    "license_status_proven": False, "credential_status_proven": False,
    "completeness": "UNKNOWN", "allow_nonmembership": False,
    "production_source_authentication": False, "live_transport_authorized": False,
    "synthetic_only": True, "production_usable": False, "proofSuiteId": None,
}

_GRAPH_ROLES = (
    SourceRole("SYNTH_NC_FHIR_PRACTITIONER", "FHIR_PRACTITIONER", "CREDENTIAL", "SYNTH_NC_FHIR_DIRECTORY_OBSERVATION_AUTHORITY", "SYNTH_NC_FHIR_DIRECTORY_PROVENANCE"),
    SourceRole("SYNTH_NC_FHIR_PRACTITIONER_ROLE_LOCATION", "FHIR_PRACTITIONER_ROLE_LOCATION", "ENROLLMENT", "SYNTH_NC_FHIR_DIRECTORY_OBSERVATION_AUTHORITY", "SYNTH_NC_FHIR_DIRECTORY_PROVENANCE"),
)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise NcMedicaidFhirProfileError("profile:noncanonical")


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(("BL/MIRROR/NC-MEDICAID/FHIR/CONTRACT/" + label + "/v3\0").encode("ascii"))
    digest.update(_canonical(value))
    return digest.hexdigest()


def _opaque(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 128 or any(char not in "0123456789abcdef" for char in value):
        raise NcMedicaidFhirProfileError("profile:" + label)
    return value


def _fixture_opaque(label: str) -> str:
    return hashlib.sha3_512(("BL/MIRROR/NC-MEDICAID/FIXTURE/" + label).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class DynamicCaptureContext:
    """Opaque per-capture identity and verifier-owned time context."""

    subject_id: str
    credential_id: str
    enrollment_id: str
    subject_locator_digest: str
    observation_time: int
    fetched_at: int

    def __post_init__(self) -> None:
        for label, value in (("subject", self.subject_id), ("credential", self.credential_id), ("enrollment", self.enrollment_id), ("subject-locator", self.subject_locator_digest)):
            _opaque(value, label)
        if type(self.observation_time) is not int or type(self.fetched_at) is not int or self.observation_time < 0 or not self.observation_time <= self.fetched_at <= 2_147_483_647:
            raise NcMedicaidFhirProfileError("profile:context-time")

    def material(self) -> dict[str, object]:
        return {
            "subject_id": self.subject_id, "credential_id": self.credential_id,
            "enrollment_id": self.enrollment_id, "subject_locator_digest": self.subject_locator_digest,
            "observation_time": self.observation_time, "fetched_at": self.fetched_at,
        }


DEFAULT_CAPTURE_CONTEXT = DynamicCaptureContext(
    _fixture_opaque("subject"), _fixture_opaque("credential"), _fixture_opaque("enrollment"),
    _fixture_opaque("subject-locator"), FIXTURE_OBSERVATION_TIME, FIXTURE_FETCHED_AT,
)

_SYNTHETIC_RESOURCES = {
    "Practitioner": {
        "resourceType": "Practitioner", "id": SYNTHETIC_PRACTITIONER_ID,
        "identifier": [{"system": "urn:synthetic:ncmedicaid:provider", "value": "NCPROV-001"}],
        "name": [{"use": "official", "family": "Synthetic", "given": ["Provider"]}], "active": True,
    },
    "PractitionerRole": {
        "resourceType": "PractitionerRole", "id": SYNTHETIC_ROLE_ID,
        "identifier": [{"system": "urn:synthetic:ncmedicaid:role", "value": "NCROLE-001"}], "active": True,
        "practitioner": {"reference": "Practitioner/" + SYNTHETIC_PRACTITIONER_ID},
        "location": [{"reference": "Location/" + SYNTHETIC_LOCATION_ID}],
        "code": [{"coding": [{"system": "urn:synthetic:ncmedicaid:role", "code": "primary-care", "display": "Primary Care"}], "text": "Synthetic primary care"}],
        "specialty": [{"coding": [{"system": "urn:synthetic:ncmedicaid:specialty", "code": "family-medicine", "display": "Family Medicine"}], "text": "Synthetic family medicine"}],
        "network": [], "period": {"start": "2026-01-01", "end": "2026-12-31"}, "endpoint": [],
    },
    "Location": {
        "resourceType": "Location", "id": SYNTHETIC_LOCATION_ID,
        "identifier": [{"system": "urn:synthetic:ncmedicaid:location", "value": "NCLOC-001"}],
        "name": "Synthetic NC Site", "status": "active",
        "address": {"use": "work", "line": ["1 Synthetic Way"], "city": "Raleigh", "state": "NC", "postalCode": "27601", "country": "US"},
        "endpoint": [],
    },
}
_SYNTHETIC_RESOURCE_VARIANTS = {
    "Practitioner": {"baseline": _SYNTHETIC_RESOURCES["Practitioner"]},
    "PractitionerRole": {"baseline": _SYNTHETIC_RESOURCES["PractitionerRole"]},
    "Location": {"baseline": _SYNTHETIC_RESOURCES["Location"], "changed": {**_SYNTHETIC_RESOURCES["Location"], "name": SYNTHETIC_CHANGED_LOCATION_NAME}},
}
_SYNTHETIC_RESOURCE_BYTES = MappingProxyType({resource_type: MappingProxyType({variant: _canonical(resource) for variant, resource in variants.items()}) for resource_type, variants in _SYNTHETIC_RESOURCE_VARIANTS.items()})


def _synthetic_resource_digest(raw: bytes) -> str:
    digest = hashlib.sha3_512()
    digest.update(b"BL/MIRROR/NC-MEDICAID/FHIR/SYNTHETIC-RESOURCE/v2\0")
    digest.update(raw)
    return digest.hexdigest()


_SYNTHETIC_RESOURCE_DIGESTS = MappingProxyType({
    resource_type: MappingProxyType({variant: _synthetic_resource_digest(raw) for variant, raw in variants.items()})
    for resource_type, variants in _SYNTHETIC_RESOURCE_BYTES.items()
})


def synthetic_resource_variants(resource_type: str) -> tuple[bytes, ...]:
    try:
        return tuple(_SYNTHETIC_RESOURCE_BYTES[resource_type].values())
    except (KeyError, TypeError):
        raise NcMedicaidFhirProfileError("profile:synthetic-resource") from None


def synthetic_resource(resource_type: str, variant: str = "baseline") -> dict[str, object]:
    try:
        raw = _SYNTHETIC_RESOURCE_BYTES[resource_type][variant]
    except (KeyError, TypeError):
        raise NcMedicaidFhirProfileError("profile:synthetic-resource") from None
    return json.loads(raw.decode("ascii"))


@dataclass(frozen=True)
class NcMedicaidFhirSourceProfile:
    """The immutable static source contract; capture context is separate."""

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
    query_parameters: tuple[tuple[str, str], ...] = QUERY_PARAMETER_TEMPLATE
    page_parameter: str = PAGE_PARAMETER
    allowed_media_type: str = ALLOWED_MEDIA_TYPE
    transport_caps: Mapping[str, int] = field(default_factory=lambda: MappingProxyType(dict(TRANSPORT_CAPS)))
    max_server_marker_age_days: int = MAX_SERVER_MARKER_AGE_DAYS
    evidence_mode: str = "OBSERVATION_ONLY"
    completeness: str = "UNKNOWN"
    require_complete: bool = False
    allow_nonmembership: bool = False
    live_transport_authorized: bool = False
    synthetic_only: bool = True
    production_usable: bool = False

    def __post_init__(self) -> None:
        if (self.source_profile_id, self.version, self.owner, self.system, self.base_url, self.host, self.fhir_version, self.source_meaning, self.transport_provenance, self.record_authentication, self.capability_statement_identity) != (SOURCE_PROFILE_ID, SOURCE_PROFILE_VERSION, OWNER_ID, SYSTEM_ID, BASE_URL, HOST, FHIR_VERSION, SOURCE_MEANING, TRANSPORT_PROVENANCE, RECORD_AUTHENTICATION, CAPABILITY_STATEMENT_IDENTITY):
            raise NcMedicaidFhirProfileError("profile:fixed-contract")
        if self.capability_statement_digest is not None or self.allowed_resource_types != ALLOWED_RESOURCE_TYPES or self.resource_cardinality != RESOURCE_CARDINALITY or self.allowed_resource_fields != ALLOWED_RESOURCE_FIELDS or self.query_parameters != QUERY_PARAMETER_TEMPLATE or self.page_parameter != PAGE_PARAMETER or self.allowed_media_type != ALLOWED_MEDIA_TYPE or self.max_server_marker_age_days != MAX_SERVER_MARKER_AGE_DAYS or self.evidence_mode != "OBSERVATION_ONLY" or self.completeness != "UNKNOWN" or self.require_complete is not False or self.allow_nonmembership is not False or self.live_transport_authorized is not False or self.synthetic_only is not True or self.production_usable is not False:
            raise NcMedicaidFhirProfileError("profile:fixed-contract")
        if not self.base_url.startswith("https://") or self.host not in self.base_url:
            raise NcMedicaidFhirProfileError("profile:host")
        if dict(self.transport_caps) != TRANSPORT_CAPS:
            raise NcMedicaidFhirProfileError("profile:transport-caps")

    @property
    def default_context(self) -> DynamicCaptureContext:
        return DEFAULT_CAPTURE_CONTEXT

    @property
    def capture_clock(self) -> Mapping[str, str | int]:
        """Fixed synthetic mapping; capture and graph times remain logical ticks."""
        return _CAPTURE_CLOCK

    def material(self) -> dict[str, object]:
        return {
            "schema": SOURCE_CONTRACT_SCHEMA, "schema_version": SOURCE_CONTRACT_VERSION,
            "source_profile_id": self.source_profile_id, "version": self.version,
            "owner": self.owner, "system": self.system, "base_url": self.base_url,
            "host": self.host, "fhir_version": self.fhir_version, "source_meaning": self.source_meaning,
            "transport_provenance": self.transport_provenance, "record_authentication": self.record_authentication,
            "capability_statement_identity": self.capability_statement_identity,
            "capability_statement_digest": self.capability_statement_digest,
            "allowed_resource_types": list(self.allowed_resource_types),
            "resource_cardinality": {key: value for key, value in self.resource_cardinality},
            "allowed_resource_fields": {key: list(value) for key, value in self.allowed_resource_fields},
            "synthetic_resource_digests": {key: dict(value) for key, value in _SYNTHETIC_RESOURCE_DIGESTS.items()},
            "query_template": {"parameters": [list(value) for value in QUERY_PARAMETER_TEMPLATE], "page_parameter": self.page_parameter},
            "allowed_media_type": self.allowed_media_type, "transport_caps": dict(self.transport_caps),
            "max_server_marker_age_days": self.max_server_marker_age_days,
            "capture_clock": dict(self.capture_clock),
            "evidence_mode": self.evidence_mode, "completeness": self.completeness,
            "require_complete": self.require_complete, "allow_nonmembership": self.allow_nonmembership,
            "live_transport_authorized": self.live_transport_authorized, "synthetic_only": self.synthetic_only,
            "production_usable": self.production_usable, "flags": dict(CLAIM_FLAGS),
            "verifier_id": VERIFIER_ID, "verifier_epoch": VERIFIER_EPOCH,
        }

    @property
    def profile_digest(self) -> str:
        return _digest("source-contract", self.material())

    @property
    def graph_profile(self) -> SourceProfile:
        return self.graph_profile_for_context(self.default_context)

    def graph_profile_for_context(self, context: DynamicCaptureContext) -> SourceProfile:
        if not isinstance(context, DynamicCaptureContext):
            raise NcMedicaidFhirProfileError("profile:context")
        return SourceProfile(
            profile_id=self.source_profile_id, version=3, subject=context.subject_id, scope=SCOPE,
            observation_time=None, effective_start=6_000, effective_end=9_000,
            source_roles=tuple(role.source_id for role in _GRAPH_ROLES), require_complete=False,
            verifier_id=VERIFIER_ID, verifier_epoch=VERIFIER_EPOCH, evidence_mode=EvidenceMode.OBSERVATION_ONLY,
            source_role_details=_GRAPH_ROLES, credential_id=context.credential_id, enrollment_id=context.enrollment_id,
            observation_start=context.observation_time, observation_end=context.observation_time + 1,
            allow_nonmembership=False, source_contract_digest=self.profile_digest,
        )

    def is_authorized_graph_profile(self, candidate: object) -> bool:
        """Return whether a dynamic graph profile is producible by this contract."""
        try:
            if type(candidate) is not SourceProfile:
                return False
            expected = self.graph_profile
            if (
                candidate.profile_id != expected.profile_id
                or candidate.version != expected.version
                or candidate.scope != expected.scope
                or candidate.observation_time is not None
                or candidate.effective_start != expected.effective_start
                or candidate.effective_end != expected.effective_end
                or candidate.source_roles != expected.source_roles
                or candidate.require_complete is not False
                or candidate.verifier_id != expected.verifier_id
                or candidate.verifier_epoch != expected.verifier_epoch
                or candidate.evidence_mode != expected.evidence_mode
                or candidate.source_role_details != expected.source_role_details
                or candidate.allow_nonmembership is not False
                or candidate.canonical_order != expected.canonical_order
                or candidate.root_rule != expected.root_rule
                or candidate.source_contract_digest != self.profile_digest
            ):
                return False
            for label, value in (
                ("subject", candidate.subject),
                ("credential", candidate.credential_id),
                ("enrollment", candidate.enrollment_id),
            ):
                _opaque(value, label)
            observation_start = candidate.observation_start
            observation_end = candidate.observation_end
            if (
                type(observation_start) is not int
                or type(observation_end) is not int
                or observation_end != observation_start + 1
                or observation_start < expected.effective_start
                or observation_end > expected.effective_end
            ):
                return False
            return True
        except Exception:
            return False

    def binding(self, context: DynamicCaptureContext | None = None) -> dict[str, object]:
        graph_profile = self.graph_profile_for_context(context or self.default_context)
        return {
            "source_profile_id": self.source_profile_id, "source_profile_version": self.version,
            "source_profile_digest": self.profile_digest, "graph_profile_version": graph_profile.version,
            "graph_profile_digest": graph_profile.profile_digest, "source_meaning": self.source_meaning,
            "transport_provenance": self.transport_provenance, "record_authentication": self.record_authentication,
            "capability_statement_identity": self.capability_statement_identity,
            "capability_statement_digest": self.capability_statement_digest,
        }

    def request_url_for_context(self, context: DynamicCaptureContext) -> str:
        return BASE_URL + "/Practitioner?_count=3&_include=PractitionerRole%3Alocation&_include=PractitionerRole%3Apractitioner&identifier=" + quote("urn:synthetic:ncmedicaid|" + context.subject_locator_digest, safe="")

    def page_url(self, sequence: int, context: DynamicCaptureContext | None = None) -> str:
        if type(sequence) is not int or sequence < 0 or sequence >= self.transport_caps["max_pages"]:
            raise NcMedicaidFhirProfileError("profile:page")
        base = self.request_url_for_context(context or self.default_context)
        return base if sequence == 0 else base + "&" + self.page_parameter + "=" + str(sequence + 1)


NC_MEDICAID_PROFILE = NcMedicaidFhirSourceProfile()
NC_MEDICAID_GRAPH_PROFILE = NC_MEDICAID_PROFILE.graph_profile
NC_MEDICAID_GRAPH_PROFILE_REGISTRY: Mapping[str, SourceProfile] = MappingProxyType({NC_MEDICAID_GRAPH_PROFILE.profile_id: NC_MEDICAID_GRAPH_PROFILE})
REQUEST_URL = NC_MEDICAID_PROFILE.page_url(0)
