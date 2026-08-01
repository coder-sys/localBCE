"""Bounded in-memory synthetic government adapter reference.

This module deliberately has no network transport, credential input, or live
government integration.  It defines a narrow versioned adapter seam and turns
synthetic claim, oracle, policy, and authorization snapshots into the strict
canonical raw records consumed by the P01/P02 reference trees.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Final, Protocol, Sequence

from app.batch.pq_tree_reference import (
    CanonicalField,
    DualTreeReference,
    SYNTHETIC_BYTES_MAGIC,
    derive_dual_tree_reference,
    encode_canonical_record,
    parse_canonical_record,
    require_synthetic_canonical_record,
    require_synthetic_reference_enabled,
)
from app.multipart_ascii import encode_multipart_ascii64


SNAPSHOT_SCHEMA_ID: Final[str] = "bl-government-snapshot-reference-v0"
SNAPSHOT_VERSION: Final[int] = 0
DEFAULT_ADAPTER_ID: Final[str] = "SYNTHETIC-GOVERNMENT-MEMORY-REFERENCE-V0"
REQUIRED_RECORD_TYPES: Final[tuple[str, ...]] = ("auth", "claim", "oracle", "policy")
MAX_REFERENCE_SNAPSHOTS: Final[int] = 16
MAX_REFERENCE_RECORDS: Final[int] = 64
MAX_REFERENCE_FIELDS_PER_RECORD: Final[int] = 32
MAX_REFERENCE_RECORD_BYTES: Final[int] = 16_384
MAX_REFERENCE_SNAPSHOT_BYTES: Final[int] = 512 * 1024

_IDENTIFIER_PATTERN: Final[re.Pattern[str]] = re.compile(r"[A-Z0-9][A-Z0-9-]{0,63}\Z")
_RECORD_FIELD_PROFILES: Final[dict[str, dict[str, str]]] = {
    "auth": {
        "authorization_present": "bool",
        "authorization_reference": "ascii",
    },
    "claim": {
        "claim_id": "ascii",
        "total_cents": "u64",
    },
    "oracle": {
        "provider_enrolled": "bool",
        "eligibility_active": "bool",
    },
    "policy": {
        "fee_cents": "u64",
        "policy_version": "ascii",
    },
}


def _identifier(label: str, value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label}_invalid")
    if not value.startswith("SYNTHETIC-") or value == "SYNTHETIC-":
        raise ValueError(f"{label}_not_synthetic")
    encode_multipart_ascii64(value, label=label, allow_empty=False)
    return value


def _field_order_key(field: CanonicalField) -> tuple[int, bytes]:
    raw = field.name.encode("ascii")
    return len(raw), raw


@dataclass(frozen=True, slots=True)
class GovernmentReferenceRecord:
    record_type: str
    record_id: str
    source_system: str
    fields: tuple[CanonicalField, ...]

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        if self.record_type not in REQUIRED_RECORD_TYPES:
            raise ValueError("government_reference_record_type_invalid")
        _identifier("government_reference_record_id", self.record_id)
        _identifier("government_reference_source_system", self.source_system)
        if not isinstance(self.fields, tuple):
            raise TypeError("government_reference_fields_must_be_tuple")
        if not self.fields or len(self.fields) > MAX_REFERENCE_FIELDS_PER_RECORD:
            raise ValueError("government_reference_field_count_invalid")
        if any(not isinstance(field, CanonicalField) for field in self.fields):
            raise TypeError("government_reference_fields_must_be_canonical_fields")
        names = tuple(field.name for field in self.fields)
        if names != tuple(sorted(names, key=lambda name: (len(name.encode("ascii")), name.encode("ascii")))) or len(set(names)) != len(names):
            raise ValueError("government_reference_fields_not_strictly_sorted_unique")
        if any(name.startswith("meta.") or name.startswith("payload.") for name in names):
            raise ValueError("government_reference_field_uses_reserved_prefix")
        observed = {field.name: field.type_name for field in self.fields}
        if observed != _RECORD_FIELD_PROFILES[self.record_type]:
            raise ValueError("government_reference_fields_not_allowlisted")
        fields_by_name = {field.name: field for field in self.fields}
        authenticated_absence = False
        if self.record_type == "auth":
            present = fields_by_name["authorization_present"].payload == b"\x01"
            reference_present = bool(fields_by_name["authorization_reference"].payload)
            if present != reference_present:
                raise ValueError("government_reference_authorization_reference_inconsistent")
            authenticated_absence = not present
        for field in self.fields:
            if field.type_name == "ascii":
                if not field.payload:
                    if authenticated_absence and field.name == "authorization_reference":
                        continue
                    raise ValueError(f"government_reference_ascii_field_empty:{field.name}")
                value = field.payload.decode("ascii")
                if not value.startswith("SYNTHETIC-") or value == "SYNTHETIC-":
                    raise ValueError(f"government_reference_ascii_field_not_synthetic:{field.name}")
                encode_multipart_ascii64(value, label=field.name, allow_empty=False)
            elif field.type_name == "bytes" and not field.payload.startswith(SYNTHETIC_BYTES_MAGIC):
                raise ValueError(f"government_reference_bytes_field_not_synthetic:{field.name}")

    def canonical_bytes(
        self,
        *,
        adapter_id: str,
        snapshot_id: str,
        snapshot_version: int,
    ) -> bytes:
        require_synthetic_reference_enabled()
        adapter = _identifier("government_reference_adapter_id", adapter_id)
        snapshot = _identifier("government_reference_snapshot_id", snapshot_id)
        metadata = (
            CanonicalField.identifier("meta.adapter_id", adapter),
            CanonicalField.identifier("meta.record_id", self.record_id),
            CanonicalField.identifier("meta.snapshot_id", snapshot),
            CanonicalField.u64("meta.snapshot_version", snapshot_version),
            CanonicalField.identifier("meta.source_system", self.source_system),
        )
        payload = tuple(
            CanonicalField(f"payload.{field.name}", field.type_name, field.payload)
            for field in self.fields
        )
        encoded = encode_canonical_record(
            f"synthetic_government_{self.record_type}",
            tuple(sorted((*metadata, *payload), key=_field_order_key)),
        )
        if len(encoded) > MAX_REFERENCE_RECORD_BYTES:
            raise ValueError("government_reference_record_exceeds_size_limit")
        require_synthetic_canonical_record(parse_canonical_record(encoded))
        return encoded


@dataclass(frozen=True, slots=True)
class GovernmentReferenceSnapshot:
    snapshot_id: str
    snapshot_version: int
    records: tuple[GovernmentReferenceRecord, ...]
    schema_id: str = SNAPSHOT_SCHEMA_ID
    synthetic_only: bool = True

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        snapshot_id = _identifier("government_reference_snapshot_id", self.snapshot_id)
        if not snapshot_id.startswith("SYNTHETIC-") or snapshot_id == "SYNTHETIC-":
            raise ValueError("government_reference_snapshot_id_not_synthetic")
        if (
            isinstance(self.snapshot_version, bool)
            or not isinstance(self.snapshot_version, int)
            or self.snapshot_version != SNAPSHOT_VERSION
        ):
            raise ValueError("government_reference_snapshot_version_invalid")
        if self.schema_id != SNAPSHOT_SCHEMA_ID:
            raise ValueError("government_reference_snapshot_schema_invalid")
        if self.synthetic_only is not True:
            raise ValueError("government_reference_snapshot_must_be_synthetic")
        if not isinstance(self.records, tuple):
            raise TypeError("government_reference_records_must_be_tuple")
        if not self.records or len(self.records) > MAX_REFERENCE_RECORDS:
            raise ValueError("government_reference_record_count_invalid")
        if any(not isinstance(record, GovernmentReferenceRecord) for record in self.records):
            raise TypeError("government_reference_records_must_be_reference_records")
        keys = tuple((record.record_type, record.record_id) for record in self.records)
        if len(set(keys)) != len(keys):
            raise ValueError("government_reference_record_key_duplicate")
        actual_types = {record.record_type for record in self.records}
        if actual_types != set(REQUIRED_RECORD_TYPES):
            raise ValueError("government_reference_record_types_incomplete_or_unknown")

    def canonical_records(self, *, adapter_id: str) -> tuple[bytes, ...]:
        require_synthetic_reference_enabled()
        encoded = tuple(
            record.canonical_bytes(
                adapter_id=adapter_id,
                snapshot_id=self.snapshot_id,
                snapshot_version=self.snapshot_version,
            )
            for record in self.records
        )
        ordered = tuple(sorted(encoded))
        if len(set(ordered)) != len(ordered):
            raise ValueError("government_reference_canonical_record_duplicate")
        if sum(len(item) for item in ordered) > MAX_REFERENCE_SNAPSHOT_BYTES:
            raise ValueError("government_reference_snapshot_exceeds_size_limit")
        for item in ordered:
            if parse_canonical_record(item).encoded != item:
                raise ValueError("government_reference_record_not_canonical")
        return ordered


class GovernmentSnapshotAdapter(Protocol):
    """Minimal seam future adapters can implement after separate authorization."""

    adapter_id: str
    schema_id: str
    transport_kind: str
    network_access: bool
    accepts_credentials: bool

    def snapshot_ids(self) -> tuple[str, ...]:
        ...

    def fetch_snapshot(self, snapshot_id: str) -> GovernmentReferenceSnapshot:
        ...

    def derive_snapshot_roots(
        self,
        snapshot_id: str,
        *,
        tree_kind: str,
        tree_height: int,
    ) -> DualTreeReference:
        ...


class InMemorySyntheticGovernmentAdapter:
    """Immutable local snapshot adapter with no transport or credential surface."""

    schema_id: Final[str] = SNAPSHOT_SCHEMA_ID
    transport_kind: Final[str] = "in_memory"
    network_access: Final[bool] = False
    accepts_credentials: Final[bool] = False
    __slots__ = ("_adapter_id", "_snapshots")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("synthetic_government_adapter_is_immutable")

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    def __init__(
        self,
        snapshots: Sequence[GovernmentReferenceSnapshot],
        *,
        adapter_id: str = DEFAULT_ADAPTER_ID,
    ) -> None:
        require_synthetic_reference_enabled()
        resolved_adapter_id = _identifier("government_reference_adapter_id", adapter_id)
        supplied = tuple(snapshots)
        if not supplied or len(supplied) > MAX_REFERENCE_SNAPSHOTS:
            raise ValueError("government_reference_snapshot_count_invalid")
        if any(not isinstance(snapshot, GovernmentReferenceSnapshot) for snapshot in supplied):
            raise TypeError("government_reference_snapshots_must_be_reference_snapshots")
        identifiers = tuple(snapshot.snapshot_id for snapshot in supplied)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("government_reference_snapshot_id_duplicate")
        object.__setattr__(self, "_adapter_id", resolved_adapter_id)
        object.__setattr__(
            self,
            "_snapshots",
            MappingProxyType({snapshot.snapshot_id: snapshot for snapshot in supplied}),
        )

    def snapshot_ids(self) -> tuple[str, ...]:
        require_synthetic_reference_enabled()
        return tuple(sorted(self._snapshots, key=lambda value: (len(value.encode("ascii")), value.encode("ascii"))))

    def fetch_snapshot(self, snapshot_id: str) -> GovernmentReferenceSnapshot:
        require_synthetic_reference_enabled()
        identifier = _identifier("government_reference_snapshot_id", snapshot_id)
        try:
            return self._snapshots[identifier]
        except KeyError as exc:
            raise KeyError("government_reference_snapshot_not_found") from exc

    def derive_snapshot_roots(
        self,
        snapshot_id: str,
        *,
        tree_kind: str,
        tree_height: int,
    ) -> DualTreeReference:
        require_synthetic_reference_enabled()
        snapshot = self.fetch_snapshot(snapshot_id)
        canonical_records = snapshot.canonical_records(adapter_id=self.adapter_id)
        result = derive_dual_tree_reference(
            canonical_records,
            tree_kind=tree_kind,
            tree_height=tree_height,
        )
        if result.canonical_records != canonical_records:
            raise ValueError("government_reference_dual_tree_record_divergence")
        return result
