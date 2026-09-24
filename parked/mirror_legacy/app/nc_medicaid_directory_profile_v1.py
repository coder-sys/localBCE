"""Versioned NC Medicaid directory-observation contract.

This module owns public source-contract data and local bounds only.  It does
not implement a network client, source authentication, source qualification,
or durable state.  The companion adapter runs against a caller-supplied
synthetic transport port and the independent verifier owns capture
interpretation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from types import MappingProxyType
import re
from typing import Mapping
from urllib.parse import quote, urlencode, urlsplit


class NcMedicaidDirectoryProfileError(ValueError):
    """Stable profile-construction failure."""


SOURCE_CONTRACT_SCHEMA = "mirror-ncmedicaid-provider-directory-observation-v1"
SOURCE_CONTRACT_VERSION = 1
SOURCE_PROFILE_ID = "ncmedicaid.provider-directory.fhir-r4.directory-observation.v1"
SOURCE_PROFILE_VERSION = 1
OWNER_ID = "NCDHHS"
SYSTEM_ID = "NC Medicaid Provider Directory API"
BASE_URL = "https://provider-directory-api.connect.medicaid.ncdhhs.gov/fhir"
HOST = "provider-directory-api.connect.medicaid.ncdhhs.gov"
FHIR_VERSION = "4.0.1"
ALLOWED_MEDIA_TYPE = "application/fhir+json"
CAPABILITY_STATEMENT_URL = BASE_URL + "/metadata"
CAPABILITY_STATEMENT_DATE = "2026-03-02"
CAPABILITY_STATEMENT_DIGEST_ALGORITHM = "sha256"
CAPABILITY_STATEMENT_DIGEST = "6bf2d579cc42a87087d0636ad59fc4fdb71ec08044cc854238fcac85754efd03"
CAPABILITY_STATEMENT_IDENTITY = (
    CAPABILITY_STATEMENT_URL
    + "#sha256="
    + CAPABILITY_STATEMENT_DIGEST
)
SOURCE_MEANING = (
    "public-provider-directory-observation-from-NCTracks-and-health-plan-contract-data"
)
TRANSPORT_PROVENANCE = "official-hostname-over-tls-unverified"
RECORD_AUTHENTICATION = "public-access-and-capability-security-unresolved"
VERIFIER_ID = "NC_MEDICAID_DIRECTORY_OBSERVATION_VERIFIER_V1"
VERIFIER_EPOCH = 1

ALLOWED_RESOURCE_TYPES = ("Practitioner", "PractitionerRole", "Location")
DOCUMENTED_INTERACTIONS = (
    ("Location", ("read", "search-type")),
    ("Practitioner", ("read", "search-type")),
    ("PractitionerRole", ("read", "search-type")),
)
DOCUMENTED_SEARCH_PARAMETERS = (
    (
        "Location",
        (
            ("_id", "token"),
            ("identifier", "token"),
            ("address", "string"),
            ("address-city", "string"),
            ("address-postalcode", "string"),
            ("address-state", "string"),
            ("endpoint", "reference"),
            ("organization", "reference"),
            ("partof", "reference"),
            ("type", "token"),
        ),
    ),
    (
        "Practitioner",
        (
            ("_id", "token"),
            ("identifier", "token"),
            ("given", "string"),
            ("name", "string"),
            ("family", "string"),
            ("period", "date"),
        ),
    ),
    (
        "PractitionerRole",
        (
            ("_id", "token"),
            ("endpoint", "reference"),
            ("identifier", "token"),
            ("location", "reference"),
            ("organization", "reference"),
            ("practitioner", "reference"),
            ("role", "token"),
            ("service", "reference"),
            ("specialty", "token"),
            ("network", "reference"),
            ("period", "date"),
        ),
    ),
)

# The source contract deliberately selects only the fields needed to bind the
# three-step observation.  Other ordinary fields are counted as ignored by
# the verifier without copying their values to the public result.
SELECTED_RESOURCE_FIELDS = (
    ("Practitioner", ("resourceType", "id", "active", "meta")),
    (
        "PractitionerRole",
        ("resourceType", "id", "active", "practitioner", "location", "period", "meta"),
    ),
    ("Location", ("resourceType", "id", "status", "meta")),
)

CONTINUATION_PARAMETER_NAMES = (
    "page",
    "cursor",
    "offset",
    "_getpages",
    "_getpagesoffset",
    "continuation",
    "pageToken",
)
FORBIDDEN_QUERY_PARAMETERS = (
    "_include",
    "_revinclude",
    "_has",
    "_sort",
    "_elements",
    "_summary",
    "_contained",
    "_type",
)

PROFILE_FLAGS = MappingProxyType(
    {
        "read_only": True,
        "observation_only": True,
        "synthetic_only": True,
        "production_usable": False,
        "activation": False,
        "payment_authority": False,
        "clearance_authority": False,
        "source_truth_proven": False,
        "enrollment_status_proven": False,
        "license_status_proven": False,
        "credential_status_proven": False,
        "completeness": "UNKNOWN",
        "source_freshness": "UNKNOWN",
        "production_source_authentication": False,
        "proofSuiteId": None,
    }
)

# These are local engineering bounds for the synthetic component.  They are
# not API guarantees and do not imply source completeness or freshness.
TRANSPORT_CAPS = MappingProxyType(
    {
        "max_response_bytes": 131_072,
        "max_total_response_bytes": 262_144,
        "max_capture_bytes": 262_144,
        "max_url_bytes": 2_048,
        "max_string_bytes": 1_024,
        "max_depth": 20,
        "max_nodes": 8_192,
        "max_total_nodes": 16_384,
        "max_page_resources": 32,
        "max_total_resources": 96,
        "max_total_matches": 64,
        "max_search_pages": 4,
        "max_search_pages_total": 8,
        "max_location_reads": 32,
        "max_requests": 40,
        "max_retries": 2,
        "max_retry_after_seconds": 30,
        "timeout_seconds": 5,
    }
)

_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_HEX_PATTERN = re.compile(r"^[0-9a-f]{128}$")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise NcMedicaidDirectoryProfileError("profile:noncanonical") from None


def _digest(label: str, value: object) -> str:
    digest = hashlib.sha3_512()
    digest.update(
        ("BL/MIRROR/NC-MEDICAID/DIRECTORY/" + label + "/v1\0").encode("ascii")
    )
    digest.update(_canonical(value))
    return digest.hexdigest()


def validate_source_id(value: object, label: str = "source-id") -> str:
    if type(value) is not str or _ID_PATTERN.fullmatch(value) is None:
        raise NcMedicaidDirectoryProfileError("profile:" + label)
    return value


def validate_operation_ref(value: object) -> str:
    if type(value) is not str or _HEX_PATTERN.fullmatch(value) is None:
        raise NcMedicaidDirectoryProfileError("profile:operation-ref")
    return value


def _validate_base_url(value: object) -> None:
    if type(value) is not str or value != BASE_URL:
        raise NcMedicaidDirectoryProfileError("profile:base-url")
    try:
        parts = urlsplit(value)
        if (
            parts.scheme != "https"
            or parts.hostname != HOST
            or parts.path != "/fhir"
            or parts.query
            or parts.fragment
            or parts.username is not None
            or parts.password is not None
            or parts.port not in (None, 443)
        ):
            raise NcMedicaidDirectoryProfileError("profile:base-url")
    except (ValueError, NcMedicaidDirectoryProfileError):
        raise
    except Exception:
        raise NcMedicaidDirectoryProfileError("profile:base-url") from None


@dataclass(frozen=True)
class DirectoryOperationContext:
    """Opaque one-operation context used only during an in-memory capture."""

    operation_ref: str
    practitioner_id: str

    def __post_init__(self) -> None:
        validate_operation_ref(self.operation_ref)
        validate_source_id(self.practitioner_id, "practitioner-id")

    def material(self) -> dict[str, str]:
        return {
            "operation_ref": self.operation_ref,
            "practitioner_id": self.practitioner_id,
        }


@dataclass(frozen=True)
class NcMedicaidDirectoryProfileV1:
    """Immutable public contract for the bounded directory observation."""

    source_contract_schema: str = SOURCE_CONTRACT_SCHEMA
    source_contract_version: int = SOURCE_CONTRACT_VERSION
    source_profile_id: str = SOURCE_PROFILE_ID
    source_profile_version: int = SOURCE_PROFILE_VERSION
    owner: str = OWNER_ID
    system: str = SYSTEM_ID
    base_url: str = BASE_URL
    host: str = HOST
    fhir_version: str = FHIR_VERSION
    allowed_media_type: str = ALLOWED_MEDIA_TYPE
    source_meaning: str = SOURCE_MEANING
    transport_provenance: str = TRANSPORT_PROVENANCE
    record_authentication: str = RECORD_AUTHENTICATION
    capability_statement_identity: str = CAPABILITY_STATEMENT_IDENTITY
    capability_statement_digest: str = CAPABILITY_STATEMENT_DIGEST
    capability_statement_date: str = CAPABILITY_STATEMENT_DATE
    allowed_resource_types: tuple[str, ...] = ALLOWED_RESOURCE_TYPES
    documented_interactions: tuple[tuple[str, tuple[str, ...]], ...] = DOCUMENTED_INTERACTIONS
    documented_search_parameters: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = DOCUMENTED_SEARCH_PARAMETERS
    selected_resource_fields: tuple[tuple[str, tuple[str, ...]], ...] = SELECTED_RESOURCE_FIELDS
    continuation_parameter_names: tuple[str, ...] = CONTINUATION_PARAMETER_NAMES
    forbidden_query_parameters: tuple[str, ...] = FORBIDDEN_QUERY_PARAMETERS
    transport_caps: Mapping[str, int] = field(
        default_factory=lambda: MappingProxyType(dict(TRANSPORT_CAPS))
    )
    flags: Mapping[str, object] = field(
        default_factory=lambda: MappingProxyType(dict(PROFILE_FLAGS))
    )
    synthetic_only: bool = True
    production_usable: bool = False

    def __post_init__(self) -> None:
        fixed = (
            self.source_contract_schema,
            self.source_contract_version,
            self.source_profile_id,
            self.source_profile_version,
            self.owner,
            self.system,
            self.base_url,
            self.host,
            self.fhir_version,
            self.allowed_media_type,
            self.source_meaning,
            self.transport_provenance,
            self.record_authentication,
            self.capability_statement_identity,
            self.capability_statement_digest,
            self.capability_statement_date,
        )
        expected = (
            SOURCE_CONTRACT_SCHEMA,
            SOURCE_CONTRACT_VERSION,
            SOURCE_PROFILE_ID,
            SOURCE_PROFILE_VERSION,
            OWNER_ID,
            SYSTEM_ID,
            BASE_URL,
            HOST,
            FHIR_VERSION,
            ALLOWED_MEDIA_TYPE,
            SOURCE_MEANING,
            TRANSPORT_PROVENANCE,
            RECORD_AUTHENTICATION,
            CAPABILITY_STATEMENT_IDENTITY,
            CAPABILITY_STATEMENT_DIGEST,
            CAPABILITY_STATEMENT_DATE,
        )
        if fixed != expected:
            raise NcMedicaidDirectoryProfileError("profile:fixed-contract")
        _validate_base_url(self.base_url)
        if not isinstance(self.transport_caps, Mapping) or not isinstance(
            self.flags, Mapping
        ):
            raise NcMedicaidDirectoryProfileError("profile:mutable-contract")
        if (
            self.allowed_resource_types != ALLOWED_RESOURCE_TYPES
            or self.documented_interactions != DOCUMENTED_INTERACTIONS
            or self.documented_search_parameters != DOCUMENTED_SEARCH_PARAMETERS
            or self.selected_resource_fields != SELECTED_RESOURCE_FIELDS
            or self.continuation_parameter_names != CONTINUATION_PARAMETER_NAMES
            or self.forbidden_query_parameters != FORBIDDEN_QUERY_PARAMETERS
            or dict(self.transport_caps) != TRANSPORT_CAPS
            or dict(self.flags) != PROFILE_FLAGS
            or self.synthetic_only is not True
            or self.production_usable is not False
        ):
            raise NcMedicaidDirectoryProfileError("profile:fixed-contract")
        if (
            type(self.capability_statement_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.capability_statement_digest) is None
        ):
            raise NcMedicaidDirectoryProfileError("profile:capability-digest")
        if (
            type(self.transport_caps) is not MappingProxyType
            or type(self.flags) is not MappingProxyType
        ):
            raise NcMedicaidDirectoryProfileError("profile:mutable-contract")

    def material(self) -> dict[str, object]:
        return {
            "schema": self.source_contract_schema,
            "schema_version": self.source_contract_version,
            "source_profile_id": self.source_profile_id,
            "source_profile_version": self.source_profile_version,
            "owner": self.owner,
            "system": self.system,
            "base_url": self.base_url,
            "host": self.host,
            "fhir_version": self.fhir_version,
            "allowed_media_type": self.allowed_media_type,
            "source_meaning": self.source_meaning,
            "transport_provenance": self.transport_provenance,
            "record_authentication": self.record_authentication,
            "capability_statement_identity": self.capability_statement_identity,
            "capability_statement_digest": self.capability_statement_digest,
            "capability_statement_date": self.capability_statement_date,
            "allowed_resource_types": list(self.allowed_resource_types),
            "documented_interactions": {
                key: list(value) for key, value in self.documented_interactions
            },
            "documented_search_parameters": {
                key: {name: kind for name, kind in value}
                for key, value in self.documented_search_parameters
            },
            "selected_resource_fields": {
                key: list(value) for key, value in self.selected_resource_fields
            },
            "continuation_parameter_names": list(self.continuation_parameter_names),
            "forbidden_query_parameters": list(self.forbidden_query_parameters),
            "transport_caps": dict(self.transport_caps),
            "flags": dict(self.flags),
            "synthetic_only": self.synthetic_only,
            "production_usable": self.production_usable,
            "verifier_id": VERIFIER_ID,
            "verifier_epoch": VERIFIER_EPOCH,
        }

    @property
    def profile_digest(self) -> str:
        return _digest("source-contract", self.material())

    def practitioner_search_url(self, practitioner_id: str) -> str:
        validate_source_id(practitioner_id, "practitioner-id")
        return self.base_url + "/Practitioner?" + urlencode(
            [("_id", practitioner_id)],
            quote_via=quote,
        )

    def practitioner_role_search_url(self, practitioner_id: str) -> str:
        validate_source_id(practitioner_id, "practitioner-id")
        return self.base_url + "/PractitionerRole?" + urlencode(
            [("practitioner", "Practitioner/" + practitioner_id)],
            quote_via=quote,
        )

    def location_read_url(self, location_id: str) -> str:
        validate_source_id(location_id, "location-id")
        if location_id == "." or location_id == "..":
            raise NcMedicaidDirectoryProfileError("profile:location-id")
        return self.base_url + "/Location/" + location_id


NC_MEDICAID_DIRECTORY_PROFILE_V1 = NcMedicaidDirectoryProfileV1()


__all__ = [
    "ALLOWED_MEDIA_TYPE",
    "ALLOWED_RESOURCE_TYPES",
    "BASE_URL",
    "CAPABILITY_STATEMENT_DATE",
    "CAPABILITY_STATEMENT_DIGEST",
    "CAPABILITY_STATEMENT_DIGEST_ALGORITHM",
    "CAPABILITY_STATEMENT_IDENTITY",
    "CAPABILITY_STATEMENT_URL",
    "CONTINUATION_PARAMETER_NAMES",
    "DirectoryOperationContext",
    "DOCUMENTED_INTERACTIONS",
    "DOCUMENTED_SEARCH_PARAMETERS",
    "FORBIDDEN_QUERY_PARAMETERS",
    "FHIR_VERSION",
    "HOST",
    "NcMedicaidDirectoryProfileError",
    "NcMedicaidDirectoryProfileV1",
    "NC_MEDICAID_DIRECTORY_PROFILE_V1",
    "PROFILE_FLAGS",
    "RECORD_AUTHENTICATION",
    "SELECTED_RESOURCE_FIELDS",
    "SOURCE_CONTRACT_SCHEMA",
    "SOURCE_CONTRACT_VERSION",
    "SOURCE_MEANING",
    "SOURCE_PROFILE_ID",
    "SOURCE_PROFILE_VERSION",
    "SYSTEM_ID",
    "TRANSPORT_CAPS",
    "TRANSPORT_PROVENANCE",
    "VERIFIER_EPOCH",
    "VERIFIER_ID",
    "validate_operation_ref",
    "validate_source_id",
]
