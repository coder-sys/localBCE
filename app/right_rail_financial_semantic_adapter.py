"""Read-only owner-to-Lean adapter for the synthetic financial workflow.

The adapter is deliberately a transaction-boundary producer, not another owner.
It accepts an already-open ``sqlite3.Connection`` from the financial owner,
reconstructs and authenticates the bounded facts needed by the semantic
engine, and returns an immutable canonical snapshot.  It never opens a
database, writes a row, advances a revision, creates a receipt, or creates a
reservation/lease table.

The owner-side snapshot envelope and the handed-off BLFIN02/BLFRES02 binary
seam are frozen here from the Engine packet.  The binary codec is deliberately
small and strict: fixed-width big-endian naturals, raw digests, bounded UTF-8
strings/lists, explicit enum tags, and no trailing bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import functools
import itertools
import json
import re
import sqlite3
from typing import Any, Final, Mapping

from app import right_rail_financial_owner as owner
from app import right_rail_financial_owner_independent as independent


class SemanticAdapterError(owner.FinancialError):
    """Base error for the fail-closed adapter boundary."""


class SemanticAdapterInputError(SemanticAdapterError):
    pass


class SemanticAdapterIntegrityError(SemanticAdapterError):
    pass


class SemanticAdapterAuthorityError(SemanticAdapterError):
    pass


class SemanticAdapterCodecError(SemanticAdapterError):
    pass


SEMANTIC_INPUT_SCHEMA: Final[str] = "RR/FINANCIAL/SEMANTIC-INPUT/v1"
SEMANTIC_INPUT_VERSION: Final[int] = 1
MAX_FACT_ROWS: Final[int] = 256
MAX_SNAPSHOT_BYTES: Final[int] = 4 * 1024 * 1024
MAX_JSON_COLUMN_BYTES: Final[int] = independent.MAX_JSON_BYTES
_SNAPSHOT_DOMAIN: Final[bytes] = b"RR/FINANCIAL/SEMANTIC-INPUT/v1\x00"
_HEX_DIGEST = re.compile(r"[0-9A-F]{128}\Z")


def _fail(error_type: type[SemanticAdapterError], code: str) -> None:
    error = error_type(code)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    raise error


def _text(value: object, label: str, *, max_bytes: int = 4096) -> str:
    if type(value) is not str or not value or "\x00" in value or len(value.encode("utf-8")) > max_bytes:
        _fail(SemanticAdapterInputError, label)
    return value


def _id(value: object, label: str) -> str:
    if type(value) is not str or owner._ID.fullmatch(value) is None:
        _fail(SemanticAdapterInputError, label)
    return value


def _role(value: object, label: str) -> str:
    if type(value) is not str or owner._ROLE.fullmatch(value) is None:
        _fail(SemanticAdapterInputError, label)
    return value


def _time(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 2**63:
        _fail(SemanticAdapterInputError, label)
    return value


def _cents(value: object, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or abs(value) > owner._MAX_CENTS or (positive and value <= 0):
        _fail(SemanticAdapterIntegrityError, label)
    return value


def _blob(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        _fail(SemanticAdapterIntegrityError, label)
    return bytes(value)


def _hex(value: bytes, label: str = "digest") -> str:
    _blob(value, label)
    return value.hex().upper()


def _digest(value: str, label: str) -> bytes:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        _fail(SemanticAdapterIntegrityError, label)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        _fail(SemanticAdapterIntegrityError, label)
    return _blob(raw, label)


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return owner._canonical(value)
    except (TypeError, ValueError, OverflowError):
        _fail(SemanticAdapterIntegrityError, "canonical_value")


def _validate_json_tree(value: object, *, depth: int = 0) -> None:
    if depth > 32:
        _fail(SemanticAdapterIntegrityError, "json_depth")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > owner._MAX_CENTS:
            _fail(SemanticAdapterIntegrityError, "json_integer_range")
        return
    if type(value) is str:
        if "\x00" in value or len(value.encode("utf-8")) > 16 * 1024:
            _fail(SemanticAdapterIntegrityError, "json_text")
        return
    if type(value) is list:
        if len(value) > MAX_FACT_ROWS:
            _fail(SemanticAdapterIntegrityError, "json_list_bound")
        for item in value:
            _validate_json_tree(item, depth=depth + 1)
        return
    if type(value) is dict:
        if len(value) > 128:
            _fail(SemanticAdapterIntegrityError, "json_map_bound")
        for key, item in value.items():
            if type(key) is not str:
                _fail(SemanticAdapterIntegrityError, "json_key")
            _validate_json_tree(item, depth=depth + 1)
        return
    _fail(SemanticAdapterIntegrityError, "json_value")


def _parse_json_column(value: object, label: str, *, expected_type: type[Any] | None = None) -> Any:
    if type(value) is not str:
        _fail(SemanticAdapterIntegrityError, label)
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        _fail(SemanticAdapterIntegrityError, label)
    if not encoded or len(encoded) > MAX_JSON_COLUMN_BYTES:
        _fail(SemanticAdapterIntegrityError, label)
    try:
        parsed = json.loads(encoded.decode("ascii"))
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError):
        _fail(SemanticAdapterIntegrityError, label)
    try:
        _validate_json_tree(parsed)
        canonical = _canonical(parsed)
    except SemanticAdapterError:
        raise
    except (RecursionError, TypeError, ValueError, OverflowError):
        _fail(SemanticAdapterIntegrityError, label)
    if canonical != encoded:
        _fail(SemanticAdapterIntegrityError, label)
    if expected_type is not None and type(parsed) is not expected_type:
        _fail(SemanticAdapterIntegrityError, label)
    return parsed


def _wrapped_values(value: object, label: str) -> list[Any]:
    parsed = _parse_json_column(value, label, expected_type=dict)
    if set(parsed) != {"values"} or type(parsed["values"]) is not list or not parsed["values"]:
        _fail(SemanticAdapterIntegrityError, label)
    return list(parsed["values"])


def _row_map(row: sqlite3.Row, columns: tuple[str, ...]) -> dict[str, Any]:
    return {column: row[column] for column in columns}


def _bounded_rows(
    connection: sqlite3.Connection,
    query: str,
    args: tuple[Any, ...],
    *,
    label: str,
    limit: int,
) -> list[sqlite3.Row]:
    rows = connection.execute(f"{query} LIMIT ?", (*args, limit + 1)).fetchall()
    if len(rows) > limit:
        _fail(SemanticAdapterIntegrityError, f"{label}_bound")
    return rows


def _require_connection(connection: object) -> sqlite3.Connection:
    if type(connection) is not sqlite3.Connection:
        _fail(SemanticAdapterInputError, "connection_type")
    if not connection.in_transaction:
        _fail(SemanticAdapterInputError, "transaction_required")
    if connection.row_factory is not sqlite3.Row:
        _fail(SemanticAdapterInputError, "row_factory_required")
    return connection


@dataclass(frozen=True, slots=True)
class TrustedAuthorityContext:
    """Authenticated authority material supplied for this semantic read.

    ``source`` is explicit so a historical row is never silently rebound to
    the current ``financial_meta`` authority.  The digest is recomputed from
    the supplied actors; callers cannot provide a synthetic ``verified`` bit
    or make a copied digest authoritative.
    """

    authority_id: str
    epoch: int
    actors: tuple[owner.AuthorityActor, ...]
    digest: bytes
    source: str = "CURRENT"

    def __post_init__(self) -> None:
        _id(self.authority_id, "authority_context_id")
        if type(self.epoch) is not int or self.epoch < 1:
            _fail(SemanticAdapterInputError, "authority_context_epoch")
        if type(self.actors) is not tuple or not self.actors:
            _fail(SemanticAdapterInputError, "authority_context_actors")
        if any(type(actor) is not owner.AuthorityActor for actor in self.actors):
            _fail(SemanticAdapterInputError, "authority_context_actor_type")
        if len({actor.actor_id for actor in self.actors}) != len(self.actors):
            _fail(SemanticAdapterInputError, "authority_context_actor_duplicate")
        if self.source not in {"CURRENT", "HISTORICAL"}:
            _fail(SemanticAdapterInputError, "authority_context_source")
        supplied = _blob(self.digest, "authority_context_digest")
        try:
            reconstructed = owner.SyntheticTrustedAuthority(
                authority_id=self.authority_id,
                epoch=self.epoch,
                actors=self.actors,
            ).digest
        except owner.FinancialError:
            _fail(SemanticAdapterInputError, "authority_context_actors")
        if supplied != reconstructed:
            _fail(SemanticAdapterAuthorityError, "authority_context_digest")

    @classmethod
    def from_authority(
        cls,
        authority: owner.SyntheticTrustedAuthority,
        *,
        source: str = "CURRENT",
    ) -> "TrustedAuthorityContext":
        if type(authority) is not owner.SyntheticTrustedAuthority:
            _fail(SemanticAdapterInputError, "authority_context_type")
        return cls(
            authority_id=authority.authority_id,
            epoch=authority.epoch,
            actors=authority.actors,
            digest=authority.digest,
            source=source,
        )

    @property
    def actor_roles(self) -> list[dict[str, Any]]:
        return [
            {"actor_id": actor.actor_id, "roles": list(actor.roles)}
            for actor in self.actors
        ]

    @property
    def authority(self) -> owner.SyntheticTrustedAuthority:
        """Return a freshly reconstructed authority for the checker seam."""

        try:
            return owner.SyntheticTrustedAuthority(
                authority_id=self.authority_id,
                epoch=self.epoch,
                actors=self.actors,
            )
        except owner.FinancialError:
            _fail(SemanticAdapterAuthorityError, "authority_context_reconstruction")


_SNAPSHOT_VALIDATION_TOKEN: Final[object] = object()


@dataclass(frozen=True, slots=True, init=False)
class LockedSemanticSnapshot:
    """Immutable canonical owner-side snapshot handed to the Engine."""

    canonical_bytes: bytes
    snapshot_digest: bytes
    obligation_id: str
    pre_evaluation_revision: int
    evaluation_time_ms: int
    _validation_token: object = field(default=None, repr=False, compare=False)

    def __init__(
        self,
        canonical_bytes: bytes,
        snapshot_digest: bytes,
        obligation_id: str,
        pre_evaluation_revision: int,
        evaluation_time_ms: int,
        *,
        _validation_token: object | None = None,
    ) -> None:
        if _validation_token is not _SNAPSHOT_VALIDATION_TOKEN:
            _fail(SemanticAdapterAuthorityError, "snapshot_unverified")
        object.__setattr__(self, "canonical_bytes", canonical_bytes)
        object.__setattr__(self, "snapshot_digest", snapshot_digest)
        object.__setattr__(self, "obligation_id", obligation_id)
        object.__setattr__(self, "pre_evaluation_revision", pre_evaluation_revision)
        object.__setattr__(self, "evaluation_time_ms", evaluation_time_ms)
        object.__setattr__(self, "_validation_token", _SNAPSHOT_VALIDATION_TOKEN)

    @property
    def data(self) -> dict[str, Any]:
        return json.loads(self.canonical_bytes.decode("ascii"))


def _require_validated_snapshot(snapshot: object, label: str = "snapshot_type") -> LockedSemanticSnapshot:
    if type(snapshot) is not LockedSemanticSnapshot:
        _fail(SemanticAdapterInputError, label)
    if snapshot._validation_token is not _SNAPSHOT_VALIDATION_TOKEN:
        _fail(SemanticAdapterAuthorityError, "snapshot_unverified")
    return snapshot


BLFIN02_MAGIC: Final[bytes] = b"BLFIN02"
BLFRES02_MAGIC: Final[bytes] = b"BLFRES02"
PAYMENT_MAGIC: Final[bytes] = b"BLFPAY01"
PAYMENT_ANSWER_MAGIC: Final[bytes] = b"BLFPRS01"
MAX_WIRE_BYTES: Final[int] = 8 * 1024 * 1024
MAX_WIRE_LIST: Final[int] = 10_000
_U64_MAX: Final[int] = (1 << 64) - 1

_MODE_TAGS: Final[dict[str, int]] = {"LIVE": 1, "SHADOW": 2, "TEST": 3}
_PROVENANCE_TAGS: Final[dict[str, int]] = {"ROOT": 1, "CONTINUITY_RESTORE": 2}
_PACK_STATUS_TAGS: Final[dict[str, int]] = {"APPROVED": 1, "REVOKED": 2}
_PAYMENT_STATUS_TAGS: Final[dict[str, int]] = {"ACTIVE": 1, "REVERSED": 2}
_CLAIM_STATUS_TAGS: Final[dict[str, int]] = {"CLAIMED": 1, "AUTHORIZED": 2, "REJECTED": 3}
_DECISION_TAGS: Final[dict[str, int]] = {
    "OFFSET_AUTHORIZED": 1,
    "OFFSET_REJECTED_CORRECTION_AUTHORIZED": 2,
}
_CASE_STATUS_TAGS: Final[dict[str, int]] = {
    "OPEN": 1,
    "AUTHORIZED": 2,
    "CORRECTION_REQUIRED": 3,
    "ACTIONED": 4,
    "RESOLVED": 5,
}
_ACTION_STATUS_TAGS: Final[dict[str, int]] = {"READY": 1, "ACKNOWLEDGED": 2, "CANCELLED": 3}
_VERIFICATION_STATUS_TAGS: Final[dict[str, int]] = {
    "MISSING_EVIDENCE": 1,
    "SUPPORTED": 2,
    "CONFLICT_VISIBLE": 3,
}
_DELIVERY_STATUS_TAGS: Final[dict[str, int]] = {
    "NONE": 1,
    "READY": 2,
    "ACKNOWLEDGED": 3,
    "CANCELLED": 4,
}


def _wire_id(value: object, label: str) -> str:
    if type(value) is not str or owner._ID.fullmatch(value) is None or len(value.encode("utf-8")) > 128:
        _fail(SemanticAdapterCodecError, label)
    return value


def _wire_role(value: object, label: str) -> str:
    if type(value) is not str or owner._ROLE.fullmatch(value) is None or len(value.encode("utf-8")) > 128:
        _fail(SemanticAdapterCodecError, label)
    return value


def _wire_text(value: object, label: str, *, max_bytes: int = 512) -> str:
    if type(value) is not str or not value or "\x00" in value:
        _fail(SemanticAdapterCodecError, label)
    encoded = value.encode("utf-8")
    if len(encoded) > max_bytes or len(encoded) > 0xFFFF:
        _fail(SemanticAdapterCodecError, label)
    return value


def _wire_nat(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value > _U64_MAX:
        _fail(SemanticAdapterCodecError, label)
    return value


def _wire_digest(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 64:
        _fail(SemanticAdapterCodecError, label)
    return bytes(value)


def _wire_hex_digest(value: object, label: str) -> bytes:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        _fail(SemanticAdapterCodecError, label)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        _fail(SemanticAdapterCodecError, label)
    return _wire_digest(raw, label)


def _wire_tag(tags: Mapping[str, int], value: object, label: str) -> int:
    if type(value) is not str or value not in tags:
        _fail(SemanticAdapterCodecError, label)
    return tags[value]


def _wire_mapping(value: object, label: str, keys: set[str] | None = None) -> dict[str, Any]:
    if type(value) is not dict or (keys is not None and set(value) != keys):
        _fail(SemanticAdapterCodecError, label)
    return value


class _WireWriter:
    def __init__(self) -> None:
        self._buffer = bytearray()

    def raw(self, value: bytes, label: str) -> None:
        if type(value) is not bytes:
            _fail(SemanticAdapterCodecError, label)
        self._buffer.extend(value)

    def byte(self, value: int, label: str) -> None:
        if type(value) is not int or not 0 <= value <= 0xFF:
            _fail(SemanticAdapterCodecError, label)
        self._buffer.append(value)

    def nat(self, value: object, label: str) -> None:
        self._buffer.extend(_wire_nat(value, label).to_bytes(8, "big"))

    def count(self, value: object, label: str) -> None:
        if type(value) is not int or not 0 <= value <= MAX_WIRE_LIST or value > 0xFFFF:
            _fail(SemanticAdapterCodecError, label)
        self._buffer.extend(value.to_bytes(2, "big"))

    def string(self, value: object, label: str, *, max_bytes: int = 512) -> None:
        text = _wire_text(value, label, max_bytes=max_bytes)
        encoded = text.encode("utf-8")
        self.count(len(encoded), f"{label}_length")
        self.raw(encoded, label)

    def identifier(self, value: object, label: str) -> None:
        self.string(_wire_id(value, label), label, max_bytes=128)

    def role(self, value: object, label: str) -> None:
        self.string(_wire_role(value, label), label, max_bytes=128)

    def digest(self, value: object, label: str) -> None:
        self.raw(_wire_digest(value, label), label)

    def boolean(self, value: object, label: str) -> None:
        if type(value) is not bool:
            _fail(SemanticAdapterCodecError, label)
        self.byte(1 if value else 0, label)

    def option_nat(self, value: object, label: str) -> None:
        if value is None:
            self.byte(0, label)
            return
        self.byte(1, label)
        self.nat(value, label)

    def option_identifier(self, value: object, label: str) -> None:
        if value is None:
            self.byte(0, label)
            return
        self.byte(1, label)
        self.identifier(value, label)

    def list(self, values: object, label: str, encode_item: Any) -> None:
        if type(values) is not list or len(values) > MAX_WIRE_LIST:
            _fail(SemanticAdapterCodecError, label)
        self.count(len(values), label)
        for index, value in enumerate(values):
            encode_item(value, f"{label}_{index}")

    def finish(self, *, label: str) -> bytes:
        if len(self._buffer) > MAX_WIRE_BYTES:
            _fail(SemanticAdapterCodecError, label)
        return bytes(self._buffer)


class _WireReader:
    def __init__(self, payload: bytes, *, max_bytes: int) -> None:
        if type(payload) is not bytes or not payload or len(payload) > max_bytes:
            _fail(SemanticAdapterCodecError, "wire_size")
        self._payload = payload
        self._offset = 0

    def take(self, size: int, label: str) -> bytes:
        if type(size) is not int or size < 0 or self._offset + size > len(self._payload):
            _fail(SemanticAdapterCodecError, label)
        value = self._payload[self._offset : self._offset + size]
        self._offset += size
        return value

    def byte(self, label: str) -> int:
        return self.take(1, label)[0]

    def nat(self, label: str) -> int:
        return int.from_bytes(self.take(8, label), "big")

    def count(self, label: str) -> int:
        value = int.from_bytes(self.take(2, label), "big")
        if value > MAX_WIRE_LIST:
            _fail(SemanticAdapterCodecError, label)
        return value

    def string(self, label: str, *, max_bytes: int = 512) -> str:
        size = int.from_bytes(self.take(2, f"{label}_length"), "big")
        if size > max_bytes:
            _fail(SemanticAdapterCodecError, label)
        raw = self.take(size, label)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            _fail(SemanticAdapterCodecError, label)
        if value.encode("utf-8") != raw:
            _fail(SemanticAdapterCodecError, label)
        return _wire_text(value, label, max_bytes=max_bytes)

    def identifier(self, label: str) -> str:
        return _wire_id(self.string(label, max_bytes=128), label)

    def role(self, label: str) -> str:
        return _wire_role(self.string(label, max_bytes=128), label)

    def digest(self, label: str) -> bytes:
        return _wire_digest(self.take(64, label), label)

    def boolean(self, label: str) -> bool:
        value = self.byte(label)
        if value not in (0, 1):
            _fail(SemanticAdapterCodecError, label)
        return bool(value)

    def option_nat(self, label: str) -> int | None:
        tag = self.byte(label)
        if tag == 0:
            return None
        if tag != 1:
            _fail(SemanticAdapterCodecError, label)
        return self.nat(label)

    def option_identifier(self, label: str) -> str | None:
        tag = self.byte(label)
        if tag == 0:
            return None
        if tag != 1:
            _fail(SemanticAdapterCodecError, label)
        return self.identifier(label)

    def list(self, label: str, decode_item: Any) -> list[Any]:
        count = self.count(label)
        return [decode_item(f"{label}_{index}") for index in range(count)]

    def finish(self) -> None:
        if self._offset != len(self._payload):
            _fail(SemanticAdapterCodecError, "wire_trailing_bytes")


def _write_tag(writer: _WireWriter, tags: Mapping[str, int], value: object, label: str) -> None:
    writer.byte(_wire_tag(tags, value, label), label)


def _read_tag(reader: _WireReader, tags: Mapping[str, int], label: str) -> str:
    tag = reader.byte(label)
    inverse = {number: name for name, number in tags.items()}
    if tag not in inverse:
        _fail(SemanticAdapterCodecError, label)
    return inverse[tag]


def _write_context(
    writer: _WireWriter,
    *,
    owner_id: object,
    mode: object,
    provenance: object,
    state_id: object,
    deployment_id: object,
    program_id: object,
    period_id: object,
    population_id: object,
    item_id: object,
    obligation_id: object,
    currency: object,
) -> None:
    writer.identifier(owner_id, "owner_id")
    _write_tag(writer, _MODE_TAGS, mode, "mode")
    _write_tag(writer, _PROVENANCE_TAGS, provenance, "provenance")
    writer.identifier(state_id, "state_id")
    writer.identifier(deployment_id, "deployment_id")
    writer.identifier(program_id, "program_id")
    writer.identifier(period_id, "period_id")
    writer.identifier(population_id, "population_id")
    writer.identifier(item_id, "item_id")
    writer.identifier(obligation_id, "obligation_id")
    writer.string(currency, "currency", max_bytes=128)


def _write_authority(writer: _WireWriter, authority: Mapping[str, Any]) -> None:
    writer.identifier(authority["authority_id"], "authority_id")
    writer.nat(authority["epoch"], "authority_epoch")
    writer.digest(_wire_hex_digest(authority["digest"], "authority_digest"), "authority_digest")
    writer.boolean(True, "synthetic_only")
    actors = authority["actors"]

    def encode_actor(value: object, label: str) -> None:
        actor = _wire_mapping(value, label, {"actor_id", "roles"})
        writer.identifier(actor["actor_id"], f"{label}_id")
        writer.list(actor["roles"], f"{label}_roles", writer.identifier)

    writer.list(actors, "authority_actors", encode_actor)


def _write_control_pack(writer: _WireWriter, pack: Mapping[str, Any], currency: object) -> None:
    wrapper = _wire_mapping(pack, "control_pack", {"status", "canonical_fields", "digest"})
    fields = _wire_mapping(
        wrapper["canonical_fields"],
        "control_pack_fields",
        {
            "pack_id", "state_id", "deployment_id", "program_id", "period_id", "version",
            "source_refs", "effective_start_ms", "effective_end_ms", "recorded_at_ms", "approved_at_ms",
            "calculation_rule_id", "adjustment_rule_id", "authorized_roles", "expected_tests",
        },
    )
    writer.identifier(fields["pack_id"], "pack_id")
    writer.identifier(fields["state_id"], "pack_state_id")
    writer.identifier(fields["deployment_id"], "pack_deployment_id")
    writer.identifier(fields["program_id"], "pack_program_id")
    writer.identifier(fields["period_id"], "pack_period_id")
    writer.string(currency, "pack_currency", max_bytes=128)
    writer.nat(fields["version"], "pack_version")
    writer.list(fields["source_refs"], "pack_source_refs", writer.string)
    writer.nat(fields["effective_start_ms"], "pack_effective_start")
    writer.nat(fields["effective_end_ms"], "pack_effective_end")
    writer.nat(fields["recorded_at_ms"], "pack_recorded_at")
    writer.nat(fields["approved_at_ms"], "pack_approved_at")
    writer.identifier(fields["calculation_rule_id"], "pack_calculation_rule")
    writer.identifier(fields["adjustment_rule_id"], "pack_adjustment_rule")
    writer.list(fields["authorized_roles"], "pack_authorized_roles", writer.role)
    writer.list(fields["expected_tests"], "pack_expected_tests", writer.string)
    expected_digest = owner._digest(owner._EVIDENCE_DOMAIN, _canonical(fields))
    stored_digest = _wire_hex_digest(wrapper["digest"], "pack_digest")
    if stored_digest != expected_digest:
        _fail(SemanticAdapterIntegrityError, "pack_digest")
    writer.digest(stored_digest, "pack_digest")
    _write_tag(writer, _PACK_STATUS_TAGS, wrapper["status"], "pack_status")


def _write_obligation(writer: _WireWriter, obligation: Mapping[str, Any]) -> None:
    writer.identifier(obligation["population_id"], "obligation_population_id")
    writer.identifier(obligation["item_id"], "obligation_item_id")
    writer.identifier(obligation["obligation_id"], "obligation_id")
    writer.nat(obligation["owed_cents"], "obligation_owed_cents")
    writer.nat(obligation["due_at_ms"], "obligation_due_at")
    writer.nat(obligation["rule_version"], "obligation_rule_version")
    writer.boolean(obligation["reporting_complete"], "obligation_reporting_complete")


@functools.lru_cache(maxsize=1 << 14, typed=True)
def _record_wire(encode: Any, context: object, *items: object) -> bytes:
    writer = _WireWriter()
    encode(writer, dict(zip(items[::2], items[1::2])), "record", context)
    return bytes(writer._buffer)


def _write_records(writer: _WireWriter, records: object, label: str, encode: Any, context: object = None) -> None:
    """A record's bytes depend only on its typed keys and values, and every evaluation re-sends an obligation's
    earlier rows, so they come from a bounded cache. A record that fails is encoded again under its own label."""
    def write(value: object, item_label: str) -> None:
        record = _wire_mapping(value, item_label)
        try:
            writer.raw(_record_wire(encode, context, *itertools.chain.from_iterable(record.items())), item_label)
        except Exception:
            encode(writer, record, item_label, context)
    writer.list(records, label, write)


def _encode_payment(writer: _WireWriter, payment: dict[str, Any], label: str, _context: None) -> None:
    for key, field_label in (
        ("payment_id", "payment_id"), ("obligation_id", "payment_obligation_id"),
        ("item_id", "payment_item_id"), ("evidence_id", "payment_evidence_id"),
        ("common_origin_id", "payment_origin"),
    ):
        writer.identifier(payment[key], f"{label}_{field_label}")
    writer.nat(payment["amount_cents"], f"{label}_amount")
    writer.nat(payment["event_at_ms"], f"{label}_event_at")
    writer.option_identifier(payment["reversed_by_evidence_id"], f"{label}_reversed_by")
    active = payment["active"]
    status = "ACTIVE" if active == 1 else "REVERSED" if active == 0 else None
    _write_tag(writer, _PAYMENT_STATUS_TAGS, status, f"{label}_status")


def _write_claims(writer: _WireWriter, claims: object) -> None:
    def encode_claim(value: object, label: str) -> None:
        claim = _wire_mapping(value, label)
        for key, field_label in (
            ("claim_id", "claim_id"), ("obligation_id", "claim_obligation_id"),
            ("evidence_id", "claim_evidence_id"),
        ):
            writer.identifier(claim[key], f"{label}_{field_label}")
        writer.nat(claim["amount_cents"], f"{label}_amount")
        writer.role(claim["owner_role"], f"{label}_owner_role")
        writer.nat(claim["deadline_ms"], f"{label}_deadline")
        _write_tag(writer, _CLAIM_STATUS_TAGS, claim["status"], f"{label}_status")

    writer.list(claims, "claims", encode_claim)


def _write_determinations(writer: _WireWriter, determinations: object) -> None:
    def encode_determination(value: object, label: str) -> None:
        determination = _wire_mapping(value, label)
        for key, field_label in (
            ("determination_id", "determination_id"), ("obligation_id", "determination_obligation_id"),
            ("claim_id", "determination_claim_id"), ("actor_id", "determination_actor_id"),
        ):
            writer.identifier(determination[key], f"{label}_{field_label}")
        writer.role(determination["actor_role"], f"{label}_actor_role")
        writer.identifier(determination["authority_id"], f"{label}_authority_id")
        writer.nat(determination["authority_epoch"], f"{label}_authority_epoch")
        writer.digest(_wire_hex_digest(determination["authority_digest"], f"{label}_authority_digest"), f"{label}_authority_digest")
        _write_tag(writer, _DECISION_TAGS, determination["decision"], f"{label}_decision")
        writer.nat(determination["amount_cents"], f"{label}_amount")
        writer.list(determination["supporting_evidence"], f"{label}_supporting_evidence", lambda binding, binding_label: writer.identifier(
            _wire_mapping(binding, binding_label, {"evidence_id", "record_digest"})["evidence_id"], binding_label))
        writer.nat(determination["expected_revision"], f"{label}_expected_revision")
        writer.nat(determination["resulting_revision"], f"{label}_resulting_revision")
        writer.nat(determination["decided_at_ms"], f"{label}_decided_at")

    writer.list(determinations, "determinations", encode_determination)


def _encode_evidence(writer: _WireWriter, record: dict[str, Any], label: str, obligation_id: object) -> None:
    writer.identifier(record["evidence_id"], f"{label}_evidence_id")
    writer.identifier(obligation_id, f"{label}_obligation_id")
    writer.identifier(record["item_id"], f"{label}_item_id")
    writer.string(record["kind"], f"{label}_kind")
    writer.identifier(record["common_origin_id"], f"{label}_common_origin_id")
    writer.string(record["source_id"], f"{label}_source_id")
    writer.string(record["source_version"], f"{label}_source_version")
    writer.string(record["local_ref"], f"{label}_local_ref")
    writer.nat(record["applicable_at_ms"], f"{label}_applicable_at")
    writer.nat(record["event_at_ms"], f"{label}_event_at")
    writer.nat(record["received_at_ms"], f"{label}_received_at")
    writer.option_nat(record["amount_cents"], f"{label}_amount")
    writer.option_identifier(record["reversal_of"], f"{label}_reversal_of")
    writer.option_identifier(record["supersedes"], f"{label}_supersedes")


def _write_conflicts(writer: _WireWriter, conflicts: object) -> None:
    def encode_conflict(value: object, label: str) -> None:
        conflict = _wire_mapping(value, label)
        for key, field_label in (
            ("conflict_id", "conflict_id"), ("obligation_id", "conflict_obligation_id"),
            ("common_origin_id", "conflict_origin"), ("existing_payment_id", "conflict_payment_id"),
            ("candidate_evidence_id", "conflict_evidence_id"),
        ):
            writer.identifier(conflict[key], f"{label}_{field_label}")
        writer.nat(conflict["existing_amount_cents"], f"{label}_existing_amount")
        writer.nat(conflict["candidate_amount_cents"], f"{label}_candidate_amount")
        writer.string(conflict["reason"], f"{label}_reason")
        writer.nat(conflict["visible_at_ms"], f"{label}_visible_at")

    writer.list(conflicts, "conflicts", encode_conflict)


def _write_cases(writer: _WireWriter, cases: object) -> None:
    def encode_case(value: object, label: str) -> None:
        case = _wire_mapping(value, label)
        writer.identifier(case["case_id"], f"{label}_case_id")
        writer.identifier(case["obligation_id"], f"{label}_obligation_id")
        writer.string(case["reason"], f"{label}_reason")
        writer.role(case["next_action_owner"], f"{label}_next_action_owner")
        writer.nat(case["due_at_ms"], f"{label}_due_at")
        _write_tag(writer, _CASE_STATUS_TAGS, case["status"], f"{label}_status")
        writer.nat(case["updated_at_ms"], f"{label}_updated_at")

    writer.list(cases, "cases", encode_case)


def _write_actions(writer: _WireWriter, actions: object, *, currency: object) -> None:
    def encode_action(value: object, label: str) -> None:
        action = _wire_mapping(value, label)
        writer.identifier(action["action_id"], f"{label}_action_id")
        writer.identifier(action["obligation_id"], f"{label}_obligation_id")
        writer.option_identifier(action["determination_id"], f"{label}_determination_id")
        writer.identifier(action["kind"], f"{label}_kind")
        payload = _wire_mapping(action["payload"], f"{label}_payload")
        writer.nat(payload["amount_cents"], f"{label}_amount")
        writer.string(payload["currency"], f"{label}_currency", max_bytes=128)
        if payload["currency"] != currency:
            _fail(SemanticAdapterIntegrityError, f"{label}_currency")
        writer.nat(action["revision"], f"{label}_revision")
        _write_tag(writer, _ACTION_STATUS_TAGS, action["status"], f"{label}_status")
        writer.digest(_wire_hex_digest(action["payload_digest"], f"{label}_payload_digest"), f"{label}_payload_digest")
        writer.nat(action["created_at_ms"], f"{label}_created_at")

    writer.list(actions, "actions", encode_action)


def encode_blfin02_input(snapshot: LockedSemanticSnapshot) -> bytes:
    """Encode one authenticated owner snapshot using the Engine BLFIN02 wire contract."""

    return _encode_blfin02(_require_validated_snapshot(snapshot).data)


def _encode_blfin02(data: Mapping[str, Any]) -> bytes:
    try:
        scope = _wire_mapping(data["scope"], "scope", {"state_id", "deployment_id", "program_id", "period_id", "currency"})
        owner_body = _wire_mapping(data["owner"], "owner")
        pre = _wire_mapping(data["pre_evaluation"], "pre_evaluation", {"obligation_id", "item_id", "revision"})
        authority = _wire_mapping(data["authority"], "authority")
        obligation = _wire_mapping(data["obligation"], "obligation")
        population = _wire_mapping(data["population"], "population")
        writer = _WireWriter()
        writer.raw(BLFIN02_MAGIC, "input_magic")
        _write_context(
            writer,
            owner_id=owner_body["owner_id"],
            mode=owner_body["mode"],
            provenance=owner_body["provenance"],
            state_id=scope["state_id"],
            deployment_id=scope["deployment_id"],
            program_id=scope["program_id"],
            period_id=scope["period_id"],
            population_id=population["population_id"],
            item_id=pre["item_id"],
            obligation_id=pre["obligation_id"],
            currency=scope["currency"],
        )
        _write_authority(writer, authority)
        _write_control_pack(writer, data["control_pack"], scope["currency"])
        _write_obligation(writer, obligation)
        writer.nat(pre["revision"], "before_revision")
        writer.nat(data["evaluation_time_ms"], "evaluated_at")
        _write_records(writer, data["payments"], "payments", _encode_payment)
        _write_claims(writer, data["claims"])
        _write_determinations(writer, data["determinations"])
        _write_records(writer, data["evidence"], "evidence", _encode_evidence, pre["obligation_id"])
        _write_conflicts(writer, data["conflicts"])
        _write_cases(writer, data["cases"])
        _write_actions(writer, data["actions"], currency=scope["currency"])
        return writer.finish(label="input_size")
    except SemanticAdapterError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        _fail(SemanticAdapterCodecError, "input_record_shape")


@dataclass(frozen=True, slots=True)
class DecodedLeanResult:
    owner_id: str
    mode: str
    provenance: str
    state_id: str
    deployment_id: str
    program_id: str
    period_id: str
    population_id: str
    item_id: str
    obligation_id: str
    currency: str
    authority_id: str
    authority_epoch: int
    authority_digest: bytes
    pack_id: str
    pack_digest: bytes
    before_revision: int
    after_revision: int
    evaluated_at_ms: int
    rule_version: int
    evidence_ids: tuple[str, ...]
    completion_at_ms: int | None
    owed_cents: int
    claimed_adjustment_cents: int
    lawful_adjustment_cents: int
    received_cash_cents: int
    shortfall_cents: int
    overage_cents: int
    cash_satisfied: bool
    amount_satisfied: bool
    timely: bool
    reporting_complete: bool
    verification_status: str
    case_status: str
    delivery_status: str


def _encode_blfres02_result(result: DecodedLeanResult) -> bytes:
    writer = _WireWriter()
    writer.raw(BLFRES02_MAGIC, "result_magic")
    _write_context(
        writer,
        owner_id=result.owner_id,
        mode=result.mode,
        provenance=result.provenance,
        state_id=result.state_id,
        deployment_id=result.deployment_id,
        program_id=result.program_id,
        period_id=result.period_id,
        population_id=result.population_id,
        item_id=result.item_id,
        obligation_id=result.obligation_id,
        currency=result.currency,
    )
    writer.identifier(result.authority_id, "authority_id")
    writer.nat(result.authority_epoch, "authority_epoch")
    writer.digest(result.authority_digest, "authority_digest")
    writer.identifier(result.pack_id, "pack_id")
    writer.digest(result.pack_digest, "pack_digest")
    writer.nat(result.before_revision, "before_revision")
    writer.nat(result.after_revision, "after_revision")
    writer.nat(result.evaluated_at_ms, "evaluated_at")
    writer.nat(result.rule_version, "rule_version")
    writer.list(list(result.evidence_ids), "evidence_ids", writer.identifier)
    writer.option_nat(result.completion_at_ms, "completion_at")
    for field in (
        "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents",
        "received_cash_cents", "shortfall_cents", "overage_cents",
    ):
        writer.nat(getattr(result, field), field)
    for field in ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete"):
        writer.boolean(getattr(result, field), field)
    _write_tag(writer, _VERIFICATION_STATUS_TAGS, result.verification_status, "verification_status")
    _write_tag(writer, _CASE_STATUS_TAGS, result.case_status, "case_status")
    _write_tag(writer, _DELIVERY_STATUS_TAGS, result.delivery_status, "delivery_status")
    return writer.finish(label="result_size")


def _bind_result_identity(result: DecodedLeanResult, data: Mapping[str, Any]) -> None:
    """Everything a result must share with the input it evaluated; none of it is a decision."""
    scope = _wire_mapping(data["scope"], "scope")
    owner_body = _wire_mapping(data["owner"], "owner")
    authority = _wire_mapping(data["authority"], "authority")
    pre = _wire_mapping(data["pre_evaluation"], "pre_evaluation")
    population = _wire_mapping(data["population"], "population")
    pack = _wire_mapping(data["control_pack"], "control_pack")
    pack_fields = _wire_mapping(pack["canonical_fields"], "control_pack_fields")
    obligation = _wire_mapping(data["obligation"], "obligation")
    expected_context = (
        owner_body["owner_id"], owner_body["mode"], owner_body["provenance"],
        scope["state_id"], scope["deployment_id"], scope["program_id"], scope["period_id"],
        population["population_id"], pre["item_id"], pre["obligation_id"], scope["currency"],
    )
    actual_context = (
        result.owner_id, result.mode, result.provenance, result.state_id, result.deployment_id,
        result.program_id, result.period_id, result.population_id, result.item_id,
        result.obligation_id, result.currency,
    )
    if actual_context != expected_context:
        _fail(SemanticAdapterCodecError, "result_context_binding")
    if (result.authority_id, result.authority_epoch, result.authority_digest) != (
        authority["authority_id"], authority["epoch"], _wire_hex_digest(authority["digest"], "authority_digest"),
    ):
        _fail(SemanticAdapterAuthorityError, "result_authority_binding")
    if (result.pack_id, result.pack_digest) != (pack_fields["pack_id"], _wire_hex_digest(pack["digest"], "pack_digest")):
        _fail(SemanticAdapterIntegrityError, "result_pack_binding")
    if result.before_revision != pre["revision"] or result.after_revision != pre["revision"] + 1:
        _fail(SemanticAdapterCodecError, "result_revision_binding")
    if result.evaluated_at_ms != data["evaluation_time_ms"]:
        _fail(SemanticAdapterCodecError, "result_time_binding")
    if result.rule_version != obligation["rule_version"] or result.rule_version != pack_fields["version"]:
        _fail(SemanticAdapterIntegrityError, "result_rule_version")
    if result.evidence_ids != tuple(evidence["evidence_id"] for evidence in data["evidence"]):
        _fail(SemanticAdapterIntegrityError, "result_evidence_ids")


def decode_live_result(payload: bytes, data: Mapping[str, Any]) -> DecodedLeanResult:
    """Decode the worker's BLFRES02 answer to ``live_evaluation_input`` and bind it to that input."""

    reader = _WireReader(payload, max_bytes=MAX_WIRE_BYTES)
    if reader.take(len(BLFRES02_MAGIC), "result_magic") != BLFRES02_MAGIC:
        _fail(SemanticAdapterCodecError, "result_magic")
    try:
        context = {
            "owner_id": reader.identifier("owner_id"),
            "mode": _read_tag(reader, _MODE_TAGS, "mode"),
            "provenance": _read_tag(reader, _PROVENANCE_TAGS, "provenance"),
            "state_id": reader.identifier("state_id"),
            "deployment_id": reader.identifier("deployment_id"),
            "program_id": reader.identifier("program_id"),
            "period_id": reader.identifier("period_id"),
            "population_id": reader.identifier("population_id"),
            "item_id": reader.identifier("item_id"),
            "obligation_id": reader.identifier("obligation_id"),
            "currency": reader.string("currency", max_bytes=128),
        }
        result = DecodedLeanResult(
            **context,
            authority_id=reader.identifier("authority_id"),
            authority_epoch=reader.nat("authority_epoch"),
            authority_digest=reader.digest("authority_digest"),
            pack_id=reader.identifier("pack_id"),
            pack_digest=reader.digest("pack_digest"),
            before_revision=reader.nat("before_revision"),
            after_revision=reader.nat("after_revision"),
            evaluated_at_ms=reader.nat("evaluated_at"),
            rule_version=reader.nat("rule_version"),
            evidence_ids=tuple(reader.list("evidence_ids", lambda label: reader.identifier(label))),
            completion_at_ms=reader.option_nat("completion_at"),
            owed_cents=reader.nat("owed_cents"),
            claimed_adjustment_cents=reader.nat("claimed_adjustment_cents"),
            lawful_adjustment_cents=reader.nat("lawful_adjustment_cents"),
            received_cash_cents=reader.nat("received_cash_cents"),
            shortfall_cents=reader.nat("shortfall_cents"),
            overage_cents=reader.nat("overage_cents"),
            cash_satisfied=reader.boolean("cash_satisfied"),
            amount_satisfied=reader.boolean("amount_satisfied"),
            timely=reader.boolean("timely"),
            reporting_complete=reader.boolean("reporting_complete"),
            verification_status=_read_tag(reader, _VERIFICATION_STATUS_TAGS, "verification_status"),
            case_status=_read_tag(reader, _CASE_STATUS_TAGS, "case_status"),
            delivery_status=_read_tag(reader, _DELIVERY_STATUS_TAGS, "delivery_status"),
        )
        reader.finish()
        _bind_result_identity(result, data)
        if _encode_blfres02_result(result) != payload:
            _fail(SemanticAdapterCodecError, "result_canonical")
        return result
    except SemanticAdapterError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        _fail(SemanticAdapterCodecError, "result_record_shape")


@dataclass(frozen=True, slots=True)
class PaymentOutcome:
    """What Lean decided for one payment command (BLFPRS01), bound to the command it answered."""

    status: str  # RECORDED, REVERSED, CONFLICT_RECORDED, CONFLICT_UNCHANGED, ALIAS, DUPLICATE or REFUSED
    reason: int | None = None  # a refusal's code, 1..16
    payment_id: str | None = None
    conflict_id: str | None = None
    evidence: dict[str, Any] | None = None
    payment_row: dict[str, Any] | None = None
    conflict_row: dict[str, Any] | None = None
    requests: tuple[tuple[str, int, int, int, bool], ...] = ()  # (action_id, amount, paid, revision, counted) after the step
    decided: DecodedLeanResult | None = None
    event_kind: str | None = None
    event_payload: dict[str, Any] | None = None

    def answer(self, projection: Mapping[str, Any]) -> dict[str, Any]:
        if self.status.startswith("CONFLICT"):
            return {"status": "CONFLICT", "conflict_id": self.conflict_id, **projection}
        status = self.status if self.status in ("RECORDED", "REVERSED") else "DUPLICATE"
        return {"status": status, **({} if self.payment_id is None else {"payment_id": self.payment_id}), **projection}


_PAYMENT_ROW = (("payment_id", "identifier"), ("obligation_id", "identifier"), ("item_id", "identifier"), ("evidence_id", "identifier"),
                ("common_origin_id", "identifier"), ("amount_cents", "nat"), ("event_at_ms", "nat"), ("reversed_by_evidence_id", "option_identifier"))
_EVIDENCE_ROW = (("evidence_id", "identifier"), ("obligation_id", "identifier"), ("item_id", "identifier"), ("kind", "string"),
                 ("common_origin_id", "identifier"), ("source_id", "string"), ("source_version", "string"), ("local_ref", "string"),
                 ("applicable_at_ms", "nat"), ("event_at_ms", "nat"), ("received_at_ms", "nat"), ("amount_cents", "option_nat"),
                 ("reversal_of", "option_identifier"), ("supersedes", "option_identifier"))
_CONFLICT_ROW = (("conflict_id", "identifier"), ("obligation_id", "identifier"), ("common_origin_id", "identifier"), ("existing_payment_id", "identifier"),
                 ("candidate_evidence_id", "identifier"), ("existing_amount_cents", "nat"), ("candidate_amount_cents", "nat"), ("reason", "string"), ("visible_at_ms", "nat"))


def _read_image(reader: _WireReader, spec: Any, encode: Any, context: object = None, *, skip: int = 0) -> dict[str, Any]:
    """One record, read field by field and re-encoded with the writer the input used: the slice must be byte-equal."""
    start = reader._offset
    row = {key: getattr(reader, kind)(key) for key, kind in spec}
    if spec is _PAYMENT_ROW:
        row["active"] = int(_read_tag(reader, _PAYMENT_STATUS_TAGS, "status") == "ACTIVE")
    writer = _WireWriter()
    encode(writer, row, "image", context)
    if bytes(writer._buffer)[skip:] != reader._payload[start : reader._offset]:
        _fail(SemanticAdapterCodecError, "payment_response")
    if "obligation_id" in row and spec is _EVIDENCE_ROW:
        del row["obligation_id"]
    return row


def decode_payment_outcome(answer: bytes, data: Mapping[str, Any], command: Mapping[str, Any]) -> PaymentOutcome:
    """Decode the worker's BLFPRS01 answer to ``live_payment_input`` and bind it to that command."""

    pre = _wire_mapping(data["pre_evaluation"], "pre_evaluation")
    reader = _WireReader(answer, max_bytes=MAX_WIRE_BYTES)
    evidence_row = lambda: _read_image(reader, _EVIDENCE_ROW, _encode_evidence, pre["obligation_id"])  # noqa: E731

    def bind(holds: object) -> None:
        if not holds:
            _fail(SemanticAdapterIntegrityError, "payment_binding")

    pid, origin = command["payment_id"], command["common_origin_id"]
    stored = {row["payment_id"]: row for row in data["payments"]}
    by_origin = {row["common_origin_id"]: row["payment_id"] for row in data["payments"]}
    known = {row["evidence_id"]: row for row in data["evidence"]}
    conflict_id = f"conflict:{pre['item_id']}:{origin}:{command['evidence_id']}"
    conflict_ids = {row["conflict_id"] for row in data["conflicts"]}

    def bind_evidence(row: Mapping[str, Any] | None) -> None:
        """Every field Lean builds for the command's evidence row, from the command and the pre-state (Types.lean confirmation, reversalRecord).
        Lean writes the row only when its id is not stored (evidenceSlot fresh). A stored id never reaches tags 1-3 or 5: one store holds one
        period, so an item's evidence is its one obligation's, and a stored confirmation always has a payment of its origin (tag 4 or 6)."""
        if command["kind"] == "record":
            time = command["event_at_ms"]
            want = {"kind": "PAYMENT_CONFIRMATION", "common_origin_id": origin, "source_id": command["source_id"], "source_version": command["source_version"],
                    "local_ref": command["local_ref"] or f"payment:{pid}", "amount_cents": command["amount_cents"], "reversal_of": None}
        else:
            time = data["evaluation_time_ms"] if command["event_at_ms"] is None else command["event_at_ms"]
            want = {"kind": "PAYMENT_REVERSAL", "common_origin_id": origin or f"reversal:{pid}", "source_id": "synthetic-payment-source", "source_version": "fixture-v1",
                    "local_ref": f"reversal:{pid}", "amount_cents": stored.get(pid, {}).get("amount_cents"), "reversal_of": pid}
        want |= {"evidence_id": command["evidence_id"], "item_id": pre["item_id"], "supersedes": None, "applicable_at_ms": time, "event_at_ms": time,
                 "received_at_ms": data["evaluation_time_ms"]}
        bind(row is not None and command["evidence_id"] not in known and all(row[key] == value for key, value in want.items()))

    try:
        if reader.take(len(PAYMENT_ANSWER_MAGIC), "payment_magic") != PAYMENT_ANSWER_MAGIC:
            _fail(SemanticAdapterCodecError, "payment_response")
        tag = reader.byte("payment_tag")
        if 1 <= tag <= 3:
            evidence = evidence_row() if reader.boolean("evidence") else None
            payment = _read_image(reader, _PAYMENT_ROW, _encode_payment) if reader.boolean("payment") else None
            conflict = _read_image(reader, _CONFLICT_ROW, lambda w, v, _l, _c: _write_conflicts(w, [v]), skip=2) if reader.boolean("conflict") else None
            receipt = (reader.identifier("receipt"), reader.nat("receipt"), reader.option_identifier("receipt")) if reader.boolean("receipt") else None
            for _ in range(4):  # the new ItemState (Codec.lean readItemState): read strictly, only the request balances are kept
                reader.nat("state")
            reader.list("contributions", lambda label: (reader.nat(label), reader.string(label), reader.nat(label)))
            _read_tag(reader, _CASE_STATUS_TAGS, "case_status")
            _read_tag(reader, _DELIVERY_STATUS_TAGS, "delivery_status")
            reader.take(2, "conflict_count")
            reader.list("evidence_ids", reader.identifier)
            requests = reader.list("requests", lambda label: (reader.identifier(label), reader.nat(label), reader.nat(label), reader.nat(label), reader.boolean(label)))
            reader.take(4, "anchor_bytes")
            result = reader.take(int.from_bytes(reader.take(4, "result_size"), "big"), "result")
            reader.finish()
            bind_evidence(evidence)
            bind(payment is None or (payment["obligation_id"], payment["item_id"]) == (pre["obligation_id"], pre["item_id"]))
            post = known | ({} if evidence is None else {evidence["evidence_id"]: evidence})
            fields: dict[str, Any] = {"evidence": evidence, "payment_row": payment, "conflict_row": conflict, "requests": tuple(requests),
                                      "decided": decode_live_result(result, {**data, "evidence": [post[key] for key in sorted(post)]})}
            if tag == 1:
                bind(payment and receipt and not conflict and payment["active"] == 1 and payment["reversed_by_evidence_id"] is None)
                bind(all(payment[key] == command[key] for key in ("payment_id", "evidence_id", "amount_cents", "common_origin_id", "event_at_ms")))
                bind(receipt == (command["payment_id"], pre["revision"], command["pays_action_id"]))
                fields |= {"payment_id": payment["payment_id"], "event_kind": "PAYMENT_RECEIVED", "event_payload": {
                    **{key: payment[key] for key in ("payment_id", "evidence_id", "amount_cents", "common_origin_id")},
                    **({} if receipt[2] is None else {"pays_action_id": receipt[2]})}}
            elif tag == 2:
                bind(evidence and payment and not conflict and payment["payment_id"] == command["payment_id"] and payment["active"] == 0 and payment["reversed_by_evidence_id"] == command["evidence_id"])
                fields |= {"payment_id": payment["payment_id"], "event_kind": "PAYMENT_REVERSED", "event_payload": {"payment_id": payment["payment_id"], "evidence_id": command["evidence_id"]}}
            else:
                existing = by_origin.get(origin)  # Transition.lean conflictImage, a new conflict id
                bind(command["kind"] == "record" and not payment and conflict_id not in conflict_ids and conflict == {
                    "conflict_id": conflict_id, "obligation_id": pre["obligation_id"], "common_origin_id": origin, "existing_payment_id": existing,
                    "candidate_evidence_id": command["evidence_id"], "existing_amount_cents": stored.get(existing, {}).get("amount_cents"),
                    "candidate_amount_cents": command["amount_cents"], "reason": "CONFLICTING_COMMON_ORIGIN_AMOUNT", "visible_at_ms": data["evaluation_time_ms"]})
                fields |= {"conflict_id": conflict["conflict_id"], "event_kind": "PAYMENT_CONFLICT_VISIBLE", "event_payload": {
                    key: conflict[key] for key in ("conflict_id", "candidate_evidence_id", "existing_payment_id", "common_origin_id")}}
            return PaymentOutcome(("RECORDED", "REVERSED", "CONFLICT_RECORDED")[tag - 1], **fields)
        if tag == 4:
            outcome = PaymentOutcome("CONFLICT_UNCHANGED", conflict_id=reader.identifier("conflict_id"))
            bind(command["kind"] == "record" and outcome.conflict_id == conflict_id and conflict_id in conflict_ids)
        elif tag == 5:
            payment_id, evidence = reader.identifier("payment_id"), evidence_row()
            bind_evidence(evidence)
            bind(command["kind"] == "record" and payment_id == by_origin.get(origin) and stored[payment_id]["amount_cents"] == command["amount_cents"])
            outcome = PaymentOutcome("ALIAS", payment_id=payment_id, evidence=evidence, event_kind="PAYMENT_DUPLICATE_EVIDENCE", event_payload={
                "candidate_evidence_id": evidence["evidence_id"], "existing_payment_id": payment_id, "common_origin_id": evidence["common_origin_id"]})
        elif tag == 6:
            duplicate_of = reader.option_identifier("payment_id")
            record = command["kind"] == "record"  # Lean answers DUPLICATE only for a stored evidence id; a fresh record's twin must be a stored payment of that amount
            bind(command["evidence_id"] in known and duplicate_of == ((pid if pid in stored else by_origin.get(origin)) if record else None)
                 and (not record or duplicate_of is not None and (pid in stored or stored[duplicate_of]["amount_cents"] == command["amount_cents"])))
            outcome = PaymentOutcome("DUPLICATE", payment_id=duplicate_of)
        elif tag == 7 and 1 <= (code := reader.byte("refusal")) <= 16:
            outcome = PaymentOutcome("REFUSED", reason=code)
        else:
            _fail(SemanticAdapterCodecError, "payment_response")
        reader.finish()
        return outcome
    except SemanticAdapterError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
        _fail(SemanticAdapterCodecError, "payment_response")


def _verify_owner_connection(
    connection: sqlite3.Connection,
    *,
    expected_config: object,
    expected_scope: object,
    authority_context: TrustedAuthorityContext,
    expected_mode: str,
    expected_owner_id: str,
    expected_continuity_epoch: int | None,
) -> dict[str, object]:
    """Use the existing independent verifier as the database trust boundary."""

    try:
        return independent.verify_database_connection(
            connection,
            expected_config=expected_config,
            expected_scope=expected_scope,
            expected_authority=authority_context.authority,
            expected_mode=expected_mode,
            expected_owner_id=expected_owner_id,
            expected_continuity_epoch=expected_continuity_epoch,
        )
    except independent.IndependentFinancialError as error:
        code = str(error)
        if code in {
            "meta:authority-binding",
            "meta:mode-binding",
            "meta:owner-binding",
            "identity:meta-binding",
        }:
            _fail(SemanticAdapterAuthorityError, f"owner_verifier:{code}")
        _fail(SemanticAdapterIntegrityError, f"owner_verifier:{code}")


def _read_verified_identity(connection: sqlite3.Connection) -> dict[str, Any]:
    """Materialize identity fields after the independent checker has passed."""

    rows = connection.execute("SELECT * FROM financial_identity WHERE id=1").fetchall()
    if len(rows) != 1:
        _fail(SemanticAdapterIntegrityError, "identity_cardinality")
    row = rows[0]
    identity = _row_map(row, owner._TABLE_COLUMNS["financial_identity"])
    anchor_head = _blob(identity["anchor_head"], "identity_anchor_head")
    genesis_head = _blob(identity["genesis_head"], "identity_genesis_head")
    source_digest = _blob(identity["source_package_digest"], "identity_source_digest")
    identity_digest = _blob(identity["identity_digest"], "identity_digest")
    return {
        "id": 1,
        "schema_version": int(identity["schema_version"]),
        "provenance": str(identity["provenance"]),
        "bound_mode": str(identity["bound_mode"]),
        "bound_owner_id": str(identity["bound_owner_id"]),
        "anchor_sequence": int(identity["anchor_sequence"]),
        "anchor_head": _hex(anchor_head),
        "genesis_head": _hex(genesis_head),
        "source_package_digest": _hex(source_digest),
        "identity_digest": _hex(identity_digest),
    }


def _read_verified_meta(
    connection: sqlite3.Connection,
    verification: Mapping[str, object],
) -> tuple[dict[str, str], dict[str, Any]]:
    """Read only material needed for the snapshot after independent verification."""

    raw_scope = verification.get("scope")
    if not isinstance(raw_scope, Mapping):
        _fail(SemanticAdapterIntegrityError, "owner_verifier:scope-shape")
    scope = {
        "state_id": _id(raw_scope.get("state_id"), "scope_state"),
        "deployment_id": _id(raw_scope.get("deployment_id"), "scope_deployment"),
        "program_id": _id(raw_scope.get("program_id"), "scope_program"),
        "period_id": _id(raw_scope.get("period_id"), "scope_period"),
        "currency": str(raw_scope.get("currency")),
    }
    owner_id = _id(verification.get("owner_id"), "meta_owner")
    mode = str(verification.get("mode"))
    return scope, {"owner_id": owner_id, "mode": mode, **_read_verified_identity(connection)}


def _load_population_and_pack(
    connection: sqlite3.Connection,
    obligation: sqlite3.Row,
    scope: Mapping[str, str],
) -> tuple[dict[str, Any], dict[str, Any], owner.ControlPack]:
    population_id = _id(obligation["population_id"], "population_id")
    population_rows = connection.execute(
        "SELECT * FROM population_imports WHERE population_id=?",
        (population_id,),
    ).fetchall()
    if len(population_rows) != 1:
        _fail(SemanticAdapterIntegrityError, "population_missing")
    population = population_rows[0]
    if population["status"] != "PUBLISHED" or population["source_complete"] != 1:
        _fail(SemanticAdapterIntegrityError, "population_status")
    expected_count = population["expected_count"]
    imported_count = population["imported_count"]
    validated_count = population["validated_count"]
    if type(expected_count) is not int or not 1 <= expected_count <= owner._MAX_ROWS or imported_count != expected_count or validated_count != expected_count:
        _fail(SemanticAdapterIntegrityError, "population_counts")
    inclusion_rules = _wrapped_values(population["inclusion_rules_json"], "population_rules")
    if any(type(value) is not str for value in inclusion_rules):
        _fail(SemanticAdapterIntegrityError, "population_rules")
    validation_digest = _blob(population["validation_digest"], "population_validation_digest")
    item_rows = connection.execute(
        "SELECT * FROM population_items WHERE population_id=? AND item_id=?",
        (population_id, obligation["item_id"]),
    ).fetchall()
    if len(item_rows) != 1:
        _fail(SemanticAdapterIntegrityError, "population_item_missing")
    item = item_rows[0]
    if tuple(item[column] for column in ("currency", "owed_cents", "due_at_ms")) != tuple(obligation[column] for column in ("currency", "owed_cents", "due_at_ms")):
        _fail(SemanticAdapterIntegrityError, "population_item_binding")
    pack_rows = connection.execute(
        "SELECT * FROM control_packs WHERE pack_id=? AND status='APPROVED'",
        (population["pack_id"],),
    ).fetchall()
    if len(pack_rows) != 1:
        _fail(SemanticAdapterIntegrityError, "control_pack_missing")
    row = pack_rows[0]
    source_refs = _wrapped_values(row["source_refs_json"], "control_pack_source_refs")
    authorized_roles = _wrapped_values(row["authorized_roles_json"], "control_pack_roles")
    expected_tests = _wrapped_values(row["expected_tests_json"], "control_pack_tests")
    if any(type(value) is not str for value in (*source_refs, *authorized_roles, *expected_tests)):
        _fail(SemanticAdapterIntegrityError, "control_pack_values")
    try:
        pack = owner.ControlPack(
            pack_id=str(row["pack_id"]),
            state_id=str(row["state_id"]),
            deployment_id=str(row["deployment_id"]),
            program_id=str(row["program_id"]),
            period_id=str(row["period_id"]),
            version=int(row["version"]),
            source_refs=tuple(source_refs),
            effective_start_ms=int(row["effective_start_ms"]),
            effective_end_ms=int(row["effective_end_ms"]),
            recorded_at_ms=int(row["recorded_at_ms"]),
            approved_at_ms=int(row["approved_at_ms"]),
            calculation_rule_id=str(row["calculation_rule_id"]),
            adjustment_rule_id=str(row["adjustment_rule_id"]),
            authorized_roles=tuple(authorized_roles),
            expected_tests=tuple(expected_tests),
        )
        owner._control_pack_policy(
            calculation_rule_id=pack.calculation_rule_id,
            adjustment_rule_id=pack.adjustment_rule_id,
            authorized_roles=pack.authorized_roles,
            expected_tests=pack.expected_tests,
        )
    except owner.FinancialError:
        _fail(SemanticAdapterIntegrityError, "control_pack_contract")
    stored_pack_digest = _blob(row["pack_digest"], "control_pack_digest")
    if stored_pack_digest != pack.digest or pack.state_id != scope["state_id"] or pack.deployment_id != scope["deployment_id"] or pack.program_id != scope["program_id"] or pack.period_id != scope["period_id"]:
        _fail(SemanticAdapterIntegrityError, "control_pack_binding")
    if int(obligation["rule_version"]) != pack.version:
        _fail(SemanticAdapterIntegrityError, "control_pack_rule_version")
    population_body = {
        "population_id": population_id,
        "pack_id": str(population["pack_id"]),
        "cutoff_ms": _time(population["cutoff_ms"], "population_cutoff"),
        "inclusion_rules": inclusion_rules,
        "expected_count": expected_count,
        "source_complete": True,
        "imported_count": imported_count,
        "validated_count": validated_count,
        "validation_digest": _hex(validation_digest),
        "status": "PUBLISHED",
    }
    item_body = {
        "population_id": population_id,
        "item_id": _id(item["item_id"], "population_item_id"),
        "display_label": _text(item["display_label"], "population_item_label", max_bytes=128),
        "owed_cents": _cents(item["owed_cents"], "population_item_owed", positive=True),
        "due_at_ms": _time(item["due_at_ms"], "population_item_due"),
        "currency": str(item["currency"]),
    }
    pack_body = json.loads(pack.canonical_bytes.decode("ascii"))
    return population_body, {
        "status": "APPROVED",
        "canonical_fields": pack_body,
        "digest": _hex(stored_pack_digest),
    }, pack


def _load_obligation(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    scope: Mapping[str, str],
    evaluation_time_ms: int,
) -> tuple[sqlite3.Row, dict[str, Any]]:
    _id(obligation_id, "obligation_id")
    rows = connection.execute("SELECT * FROM obligations WHERE obligation_id=?", (obligation_id,)).fetchall()
    if len(rows) != 1:
        _fail(SemanticAdapterIntegrityError, "obligation_missing")
    row = rows[0]
    if str(row["period_id"]) != scope["period_id"] or str(row["currency"]) != scope["currency"]:
        _fail(SemanticAdapterIntegrityError, "obligation_scope")
    if _id(row["item_id"], "obligation_item") is None:
        _fail(SemanticAdapterIntegrityError, "obligation_item")
    if type(row["revision"]) is not int or not 0 <= row["revision"] <= owner._MAX_ROWS:
        _fail(SemanticAdapterIntegrityError, "obligation_revision")
    _time(row["updated_at_ms"], "obligation_updated")
    if int(row["updated_at_ms"]) > evaluation_time_ms:
        _fail(SemanticAdapterIntegrityError, "obligation_after_evaluation")
    for field in ("owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents", "shortfall_cents", "overage_cents"):
        _cents(row[field], f"obligation_{field}")
    for field in ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete"):
        if row[field] not in (0, 1):
            _fail(SemanticAdapterIntegrityError, f"obligation_{field}")
    body = {
        "obligation_id": str(row["obligation_id"]),
        "population_id": str(row["population_id"]),
        "item_id": str(row["item_id"]),
        "period_id": str(row["period_id"]),
        "currency": str(row["currency"]),
        "owed_cents": int(row["owed_cents"]),
        "due_at_ms": _time(row["due_at_ms"], "obligation_due"),
        "rule_version": int(row["rule_version"]),
        "revision": int(row["revision"]),
        "claimed_adjustment_cents": int(row["claimed_adjustment_cents"]),
        "lawful_adjustment_cents": int(row["lawful_adjustment_cents"]),
        "received_cash_cents": int(row["received_cash_cents"]),
        "shortfall_cents": int(row["shortfall_cents"]),
        "overage_cents": int(row["overage_cents"]),
        "cash_satisfied": bool(row["cash_satisfied"]),
        "amount_satisfied": bool(row["amount_satisfied"]),
        "timely": bool(row["timely"]),
        "reporting_complete": bool(row["reporting_complete"]),
        "verification_status": str(row["verification_status"]),
        "case_status": str(row["case_status"]),
        "delivery_status": str(row["delivery_status"]),
        "current_evaluation_id": None if row["current_evaluation_id"] is None else str(row["current_evaluation_id"]),
        "updated_at_ms": int(row["updated_at_ms"]),
    }
    return row, body


def _load_evidence(
    connection: sqlite3.Connection,
    *,
    item_id: str,
    evaluation_time_ms: int,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    rows = _bounded_rows(
        connection,
        "SELECT evidence_id,item_id,kind,common_origin_id,source_id,source_version,local_ref,applicable_at_ms,event_at_ms,received_at_ms,content_digest,record_digest,amount_cents,reversal_of,supersedes FROM evidence WHERE item_id=? ORDER BY evidence_id",
        (item_id,),
        label="evidence",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        content_digest = _blob(row["content_digest"], "evidence_content_digest")
        record_digest = _blob(row["record_digest"], "evidence_record_digest")
        amount = None if row["amount_cents"] is None else _cents(row["amount_cents"], "evidence_amount", positive=True)
        evidence_id = _id(row["evidence_id"], "evidence_id")
        applicable_at = _time(row["applicable_at_ms"], "evidence_applicable_at")
        received_at = _time(row["received_at_ms"], "evidence_received_at")
        if str(row["item_id"]) != item_id or applicable_at > evaluation_time_ms or received_at > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "evidence_time_binding")
        body = {
            "evidence_id": evidence_id,
            "item_id": item_id,
            "kind": str(row["kind"]),
            "common_origin_id": str(row["common_origin_id"]),
            "source_id": str(row["source_id"]),
            "source_version": str(row["source_version"]),
            "local_ref": str(row["local_ref"]),
            "applicable_at_ms": applicable_at,
            "event_at_ms": _time(row["event_at_ms"], "evidence_event_at"),
            "received_at_ms": received_at,
            "content_digest": _hex(content_digest),
            "record_digest": _hex(record_digest),
            "amount_cents": amount,
            "reversal_of": None if row["reversal_of"] is None else str(row["reversal_of"]),
            "supersedes": None if row["supersedes"] is None else str(row["supersedes"]),
        }
        by_id[evidence_id] = body
        result.append(body)
    return result, by_id


def _load_payments(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    item_id: str,
    evidence: Mapping[str, Mapping[str, Any]],
    evaluation_time_ms: int,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    rows = _bounded_rows(
        connection,
        "SELECT payment_id,obligation_id,item_id,evidence_id,common_origin_id,amount_cents,event_at_ms,active,reversed_by_evidence_id FROM payments WHERE obligation_id=? ORDER BY payment_id",
        (obligation_id,),
        label="payments",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    origins: set[str] = set()
    for row in rows:
        payment_id = _id(row["payment_id"], "payment_id")
        if str(row["item_id"]) != item_id or str(row["obligation_id"]) != obligation_id:
            _fail(SemanticAdapterIntegrityError, "payment_scope")
        amount = _cents(row["amount_cents"], "payment_amount", positive=True)
        event_at = _time(row["event_at_ms"], "payment_event")
        if event_at > evaluation_time_ms or row["active"] not in (0, 1):
            _fail(SemanticAdapterIntegrityError, "payment_time_status")
        origin = _id(row["common_origin_id"], "payment_origin")
        if origin in origins:
            _fail(SemanticAdapterIntegrityError, "payment_origin_duplicate")
        origins.add(origin)
        evidence_id = _id(row["evidence_id"], "payment_evidence")
        evidence_row = evidence.get(evidence_id)
        if evidence_row is None or evidence_row["item_id"] != item_id or evidence_row["common_origin_id"] != origin or evidence_row["amount_cents"] != amount:
            _fail(SemanticAdapterIntegrityError, "payment_evidence_binding")
        reversed_by = None if row["reversed_by_evidence_id"] is None else _id(row["reversed_by_evidence_id"], "payment_reversal")
        if row["active"] == 1 and reversed_by is not None:
            _fail(SemanticAdapterIntegrityError, "payment_active_reversal")
        if row["active"] == 0:
            if reversed_by is None or reversed_by not in evidence or evidence[reversed_by]["kind"] != "PAYMENT_REVERSAL" or evidence[reversed_by]["reversal_of"] != payment_id:
                _fail(SemanticAdapterIntegrityError, "payment_reversal_binding")
        body = {
            "payment_id": payment_id,
            "obligation_id": obligation_id,
            "item_id": item_id,
            "evidence_id": evidence_id,
            "common_origin_id": origin,
            "amount_cents": amount,
            "event_at_ms": event_at,
            "active": int(row["active"]),
            "reversed_by_evidence_id": reversed_by,
        }
        by_id[payment_id] = body
        result.append(body)
    for evidence_row in evidence.values():
        if evidence_row["kind"] != "PAYMENT_REVERSAL":
            continue
        target_id = evidence_row["reversal_of"]
        target = by_id.get(target_id)
        if target is None or target["item_id"] != item_id or evidence_row["amount_cents"] != target["amount_cents"] or target["active"] != 0:
            _fail(SemanticAdapterIntegrityError, "payment_reversal_evidence")
    return result, by_id


def _load_claims(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    evidence: Mapping[str, Mapping[str, Any]],
    evaluation_time_ms: int,
    limit: int,
) -> list[dict[str, Any]]:
    rows = _bounded_rows(
        connection,
        "SELECT claim_id,obligation_id,evidence_id,amount_cents,owner_role,deadline_ms,status,created_at_ms,updated_at_ms FROM claimed_adjustments WHERE obligation_id=? ORDER BY claim_id",
        (obligation_id,),
        label="claims",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    for row in rows:
        claim_id = _id(row["claim_id"], "claim_id")
        if str(row["obligation_id"]) != obligation_id:
            _fail(SemanticAdapterIntegrityError, "claim_scope")
        evidence_id = _id(row["evidence_id"], "claim_evidence")
        evidence_row = evidence.get(evidence_id)
        amount = _cents(row["amount_cents"], "claim_amount", positive=True)
        if evidence_row is None or evidence_row["kind"] != "OFFSET_CLAIM" or evidence_row["amount_cents"] != amount:
            _fail(SemanticAdapterIntegrityError, "claim_evidence_binding")
        role = _role(row["owner_role"], "claim_owner_role")
        status = str(row["status"])
        if status not in {"CLAIMED", "AUTHORIZED", "REJECTED"}:
            _fail(SemanticAdapterIntegrityError, "claim_status")
        deadline = _time(row["deadline_ms"], "claim_deadline")
        created = _time(row["created_at_ms"], "claim_created")
        updated = _time(row["updated_at_ms"], "claim_updated")
        if created > evaluation_time_ms or updated > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "claim_time_binding")
        body = {
            "claim_id": claim_id,
            "obligation_id": obligation_id,
            "evidence_id": evidence_id,
            "amount_cents": amount,
            "owner_role": role,
            "deadline_ms": deadline,
            "status": status,
            "created_at_ms": created,
            "updated_at_ms": updated,
        }
        result.append(body)
    return result


def _load_cases(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    pack: owner.ControlPack,
    evaluation_time_ms: int,
    limit: int,
) -> list[dict[str, Any]]:
    rows = _bounded_rows(
        connection,
        "SELECT case_id,obligation_id,reason,contractual_accountability,next_action_owner,due_at_ms,completion_conditions_json,status,updated_at_ms FROM cases WHERE obligation_id=? ORDER BY case_id",
        (obligation_id,),
        label="cases",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    for row in rows:
        case_id = _id(row["case_id"], "case_id")
        owner_role = _role(row["next_action_owner"], "case_owner_role")
        if owner_role not in pack.authorized_roles or str(row["obligation_id"]) != obligation_id:
            _fail(SemanticAdapterAuthorityError, "case_owner_role")
        conditions = _parse_json_column(row["completion_conditions_json"], "case_conditions", expected_type=dict)
        status = str(row["status"])
        if status not in {"OPEN", "AUTHORIZED", "ACTIONED", "CORRECTION_REQUIRED", "RESOLVED"}:
            _fail(SemanticAdapterIntegrityError, "case_status")
        updated = _time(row["updated_at_ms"], "case_updated")
        if updated > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "case_time_binding")
        body = {
            "case_id": case_id,
            "obligation_id": obligation_id,
            "reason": _id(row["reason"], "case_reason"),
            "contractual_accountability": _id(row["contractual_accountability"], "case_accountability"),
            "next_action_owner": owner_role,
            "due_at_ms": _time(row["due_at_ms"], "case_due"),
            "completion_conditions": conditions,
            "status": status,
            "updated_at_ms": updated,
        }
        result.append(body)
    if not result:
        _fail(SemanticAdapterIntegrityError, "case_missing")
    return result


def _load_actions(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    evaluation_time_ms: int,
    limit: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, Any]]]:
    rows = _bounded_rows(
        connection,
        "SELECT action_id,obligation_id,determination_id,kind,status,revision,payload_json,payload_digest,idempotency_key,created_at_ms FROM actions WHERE obligation_id=? ORDER BY action_id",
        (obligation_id,),
        label="actions",
        limit=limit,
    )
    outbox_rows = _bounded_rows(
        connection,
        "SELECT action_id,status,attempt,payload_digest,acknowledgment_ref,updated_at_ms FROM action_outbox WHERE action_id IN (SELECT action_id FROM actions WHERE obligation_id=?) ORDER BY action_id",
        (obligation_id,),
        label="action_outbox",
        limit=limit,
    )
    outbox_by_id: dict[str, dict[str, Any]] = {}
    for row in outbox_rows:
        action_id = _id(row["action_id"], "outbox_action")
        if action_id in outbox_by_id:
            _fail(SemanticAdapterIntegrityError, "outbox_duplicate")
        if row["status"] not in {"READY", "ACKNOWLEDGED"} or type(row["attempt"]) is not int or row["attempt"] < 0 or row["attempt"] > owner._MAX_ROWS:
            _fail(SemanticAdapterIntegrityError, "outbox_status")
        payload_digest = _blob(row["payload_digest"], "outbox_payload_digest")
        updated = _time(row["updated_at_ms"], "outbox_updated")
        if updated > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "outbox_time_binding")
        acknowledgment = None if row["acknowledgment_ref"] is None else _id(row["acknowledgment_ref"], "acknowledgment_ref")
        outbox_by_id[action_id] = {
            "action_id": action_id,
            "status": str(row["status"]),
            "attempt": int(row["attempt"]),
            "payload_digest": _hex(payload_digest),
            "acknowledgment_ref": acknowledgment,
            "updated_at_ms": updated,
        }
    result: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        action_id = _id(row["action_id"], "action_id")
        status = str(row["status"])
        if str(row["obligation_id"]) != obligation_id or status not in {"READY", "ACKNOWLEDGED"}:
            _fail(SemanticAdapterIntegrityError, "action_status")
        revision = row["revision"]
        if type(revision) is not int or not 0 <= revision <= owner._MAX_ROWS:
            _fail(SemanticAdapterIntegrityError, "action_revision")
        payload = _parse_json_column(row["payload_json"], "action_payload", expected_type=dict)
        payload_digest = _blob(row["payload_digest"], "action_payload_digest")
        idempotency = _blob(row["idempotency_key"], "action_idempotency")
        created = _time(row["created_at_ms"], "action_created")
        if created > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "action_time_binding")
        if action_id not in outbox_by_id or outbox_by_id[action_id]["payload_digest"] != _hex(payload_digest) or outbox_by_id[action_id]["status"] != status:
            _fail(SemanticAdapterIntegrityError, "action_outbox_binding")
        body = {
            "action_id": action_id,
            "obligation_id": obligation_id,
            "determination_id": _id(row["determination_id"], "action_determination"),
            "kind": _id(row["kind"], "action_kind"),
            "status": status,
            "revision": int(revision),
            "payload": payload,
            "payload_digest": _hex(payload_digest),
            "idempotency_key": _hex(idempotency),
            "created_at_ms": created,
        }
        by_id[action_id] = body
        result.append(body)
    return result, list(outbox_by_id.values()), by_id


def _load_conflicts(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    item_id: str,
    evidence: Mapping[str, Mapping[str, Any]],
    payments: Mapping[str, Mapping[str, Any]],
    evaluation_time_ms: int,
    limit: int,
) -> list[dict[str, Any]]:
    rows = _bounded_rows(
        connection,
        "SELECT conflict_id,obligation_id,common_origin_id,existing_payment_id,candidate_evidence_id,existing_amount_cents,candidate_amount_cents,reason,visible_at_ms FROM financial_conflicts WHERE obligation_id=? ORDER BY conflict_id",
        (obligation_id,),
        label="conflicts",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    for row in rows:
        conflict_id = _id(row["conflict_id"], "conflict_id")
        common_origin = _id(row["common_origin_id"], "conflict_origin")
        existing_payment_id = _id(row["existing_payment_id"], "conflict_payment")
        candidate_evidence_id = _id(row["candidate_evidence_id"], "conflict_evidence")
        existing = payments.get(existing_payment_id)
        candidate = evidence.get(candidate_evidence_id)
        if str(row["obligation_id"]) != obligation_id or existing is None or candidate is None:
            _fail(SemanticAdapterIntegrityError, "conflict_binding")
        existing_amount = _cents(row["existing_amount_cents"], "conflict_existing_amount", positive=True)
        candidate_amount = _cents(row["candidate_amount_cents"], "conflict_candidate_amount", positive=True)
        if existing["common_origin_id"] != common_origin or candidate["item_id"] != item_id or candidate["common_origin_id"] != common_origin or existing_amount != existing["amount_cents"] or candidate_amount != candidate["amount_cents"] or existing_amount == candidate_amount or row["reason"] != "CONFLICTING_COMMON_ORIGIN_AMOUNT":
            _fail(SemanticAdapterIntegrityError, "conflict_binding")
        visible = _time(row["visible_at_ms"], "conflict_visible")
        if visible > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "conflict_time_binding")
        result.append(
            {
                "conflict_id": conflict_id,
                "obligation_id": obligation_id,
                "common_origin_id": common_origin,
                "existing_payment_id": existing_payment_id,
                "candidate_evidence_id": candidate_evidence_id,
                "existing_amount_cents": existing_amount,
                "candidate_amount_cents": candidate_amount,
                "reason": "CONFLICTING_COMMON_ORIGIN_AMOUNT",
                "visible_at_ms": visible,
            }
        )
    return result


def _load_evaluations(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    obligation: sqlite3.Row,
    scope: Mapping[str, str],
    pack: owner.ControlPack,
    authority_context: TrustedAuthorityContext,
    evidence: Mapping[str, Mapping[str, Any]],
    evaluation_time_ms: int,
    limit: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, Any]]:
    rows = _bounded_rows(
        connection,
        "SELECT evaluation_id,obligation_id,revision,rule_version,evidence_ids_json,authority_id,evaluated_at_ms,owed_cents,claimed_adjustment_cents,lawful_adjustment_cents,received_cash_cents,shortfall_cents,overage_cents,cash_satisfied,amount_satisfied,timely,reporting_complete,verification_status,case_status,delivery_status,result_digest,contract_version,scope_json,control_pack_id,control_pack_version,control_pack_digest,authority_epoch,authority_digest,evidence_bindings_json,input_snapshot_json,input_snapshot_digest,receipt_digest FROM evaluations WHERE obligation_id=? ORDER BY revision",
        (obligation_id,),
        label="evaluations",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    revisions: list[int] = []
    for row in rows:
        if str(row["obligation_id"]) != obligation_id or str(row["contract_version"]) != owner._EVALUATION_RECEIPT_CONTRACT:
            _fail(SemanticAdapterIntegrityError, "evaluation_contract")
        evaluation_id = _id(row["evaluation_id"], "evaluation_id")
        revision = row["revision"]
        if type(revision) is not int or not 0 <= revision <= owner._MAX_ROWS:
            _fail(SemanticAdapterIntegrityError, "evaluation_revision")
        evaluated_at = _time(row["evaluated_at_ms"], "evaluation_time")
        if evaluated_at > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "evaluation_time_binding")
        authority_id = _id(row["authority_id"], "evaluation_authority_id")
        authority_epoch = row["authority_epoch"]
        if type(authority_epoch) is not int or authority_epoch < 1:
            _fail(SemanticAdapterIntegrityError, "evaluation_authority_epoch")
        authority_digest = _blob(row["authority_digest"], "evaluation_authority_digest")
        if (authority_id, authority_epoch, authority_digest) != (authority_context.authority_id, authority_context.epoch, authority_context.digest):
            _fail(SemanticAdapterAuthorityError, "evaluation_authority_stale")
        evidence_ids_value = _parse_json_column(row["evidence_ids_json"], "evaluation_evidence_ids", expected_type=dict)
        bindings_value = _parse_json_column(row["evidence_bindings_json"], "evaluation_bindings", expected_type=dict)
        scope_value = _parse_json_column(row["scope_json"], "evaluation_scope", expected_type=dict)
        input_snapshot = _parse_json_column(row["input_snapshot_json"], "evaluation_input", expected_type=dict)
        if set(evidence_ids_value) != {"evidence_ids"} or type(evidence_ids_value["evidence_ids"]) is not list:
            _fail(SemanticAdapterIntegrityError, "evaluation_evidence_ids")
        evidence_ids = evidence_ids_value["evidence_ids"]
        if any(type(value) is not str for value in evidence_ids) or evidence_ids != sorted(evidence_ids) or len(set(evidence_ids)) != len(evidence_ids):
            _fail(SemanticAdapterIntegrityError, "evaluation_evidence_ids")
        if set(bindings_value) != {"bindings"} or type(bindings_value["bindings"]) is not list:
            _fail(SemanticAdapterIntegrityError, "evaluation_bindings")
        bindings = bindings_value["bindings"]
        if [binding.get("evidence_id") for binding in bindings if type(binding) is dict] != evidence_ids or any(type(binding) is not dict or set(binding) != {"evidence_id", "record_digest"} for binding in bindings):
            _fail(SemanticAdapterIntegrityError, "evaluation_bindings")
        for binding in bindings:
            evidence_row = evidence.get(binding["evidence_id"])
            if evidence_row is None or binding["record_digest"] != evidence_row["record_digest"]:
                _fail(SemanticAdapterIntegrityError, "evaluation_bindings")
            _digest(binding["record_digest"], "evaluation_binding_digest")
        if scope_value != dict(scope):
            _fail(SemanticAdapterIntegrityError, "evaluation_scope")
        if type(input_snapshot.get("pre_revision")) is not int or input_snapshot["pre_revision"] != (revision if revision == 0 else revision - 1):
            _fail(SemanticAdapterIntegrityError, "evaluation_input_revision")
        input_digest = _blob(row["input_snapshot_digest"], "evaluation_input_digest")
        if input_digest != owner._digest(owner._EVALUATION_INPUT_DOMAIN, _canonical(input_snapshot)):
            _fail(SemanticAdapterIntegrityError, "evaluation_input_digest")
        stored_pack_digest = _blob(row["control_pack_digest"], "evaluation_pack_digest")
        if str(row["control_pack_id"]) != pack.pack_id or row["control_pack_version"] != pack.version or stored_pack_digest != pack.digest:
            _fail(SemanticAdapterIntegrityError, "evaluation_pack_binding")
        result_body = {
            "evaluation_id": evaluation_id,
            "obligation_id": obligation_id,
            "revision": int(revision),
            "rule_version": int(row["rule_version"]),
            "evidence_ids": evidence_ids,
            "authority_id": authority_id,
            "evaluated_at_ms": evaluated_at,
            "owed_cents": _cents(row["owed_cents"], "evaluation_owed"),
            "claimed_adjustment_cents": _cents(row["claimed_adjustment_cents"], "evaluation_claimed"),
            "lawful_adjustment_cents": _cents(row["lawful_adjustment_cents"], "evaluation_lawful"),
            "received_cash_cents": _cents(row["received_cash_cents"], "evaluation_cash"),
            "shortfall_cents": _cents(row["shortfall_cents"], "evaluation_shortfall"),
            "overage_cents": _cents(row["overage_cents"], "evaluation_overage"),
            "cash_satisfied": int(row["cash_satisfied"]),
            "amount_satisfied": int(row["amount_satisfied"]),
            "timely": int(row["timely"]),
            "reporting_complete": int(row["reporting_complete"]),
            "verification_status": str(row["verification_status"]),
            "case_status": str(row["case_status"]),
            "delivery_status": str(row["delivery_status"]),
        }
        for field in ("cash_satisfied", "amount_satisfied", "timely", "reporting_complete"):
            if result_body[field] not in (0, 1):
                _fail(SemanticAdapterIntegrityError, "evaluation_boolean")
        result_digest = _blob(row["result_digest"], "evaluation_result_digest")
        expected_result_digest = owner._digest(owner._EVALUATION_RESULT_DOMAIN, _canonical(result_body))
        if result_digest != expected_result_digest:
            _fail(SemanticAdapterIntegrityError, "evaluation_result_digest")
        receipt_body = owner._evaluation_receipt_body(
            result={**result_body, "result_digest": _hex(result_digest)},
            scope=scope,
            control_pack_id=pack.pack_id,
            control_pack_version=pack.version,
            control_pack_digest=pack.digest,
            evidence_bindings=bindings,
            authority_id=authority_id,
            authority_epoch=authority_epoch,
            authority_digest=authority_digest,
            input_snapshot_digest=input_digest,
            result_digest=result_digest,
        )
        receipt_digest = owner._digest(owner._EVALUATION_RECEIPT_DOMAIN, _canonical(receipt_body))
        stored_receipt_digest = _blob(row["receipt_digest"], "evaluation_receipt_digest")
        if stored_receipt_digest != receipt_digest:
            _fail(SemanticAdapterIntegrityError, "evaluation_receipt_digest")
        receipt = {
            **receipt_body,
            "receipt_digest": _hex(receipt_digest),
            "evaluation_result_digest": _hex(result_digest),
        }
        full = {"receipt": receipt, "input_snapshot": input_snapshot}
        result.append(full)
        by_id[evaluation_id] = full
        revisions.append(int(revision))
    current_revision = int(obligation["revision"])
    if revisions != list(range(current_revision + 1)) or not result:
        _fail(SemanticAdapterIntegrityError, "evaluation_history")
    current_id = obligation["current_evaluation_id"]
    if current_id is None or str(current_id) != result[-1]["receipt"]["evaluation_id"] or int(result[-1]["receipt"]["revision"]) != current_revision:
        _fail(SemanticAdapterIntegrityError, "evaluation_current_binding")
    # The latest persisted receipt must still agree with the current projection.
    latest = result[-1]["receipt"]
    for field in (
        "owed_cents", "claimed_adjustment_cents", "lawful_adjustment_cents", "received_cash_cents",
        "shortfall_cents", "overage_cents", "cash_satisfied", "amount_satisfied", "timely",
        "reporting_complete", "verification_status", "case_status", "delivery_status",
    ):
        expected_value = int(obligation[field]) if field in {"cash_satisfied", "amount_satisfied", "timely", "reporting_complete"} else obligation[field]
        if latest[field] != expected_value:
            _fail(SemanticAdapterIntegrityError, "evaluation_projection_binding")
    return result, by_id, latest


def _load_determinations(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    evidence: Mapping[str, Mapping[str, Any]],
    actions: list[dict[str, Any]],
    authority_context: TrustedAuthorityContext,
    evaluation_time_ms: int,
    limit: int,
) -> list[dict[str, Any]]:
    rows = _bounded_rows(
        connection,
        "SELECT determination_id,obligation_id,claim_id,actor_id,actor_role,authority_id,authority_epoch,authority_digest,decision,amount_cents,supporting_evidence_json,expected_revision,resulting_revision,decided_at_ms,determination_digest,input_evaluation_id,input_evaluation_result_digest FROM determinations WHERE obligation_id=? ORDER BY determination_id",
        (obligation_id,),
        label="determinations",
        limit=limit,
    )
    result: list[dict[str, Any]] = []
    for row in rows:
        determination_id = _id(row["determination_id"], "determination_id")
        if str(row["obligation_id"]) != obligation_id:
            _fail(SemanticAdapterIntegrityError, "determination_scope")
        actor_id = _id(row["actor_id"], "determination_actor")
        actor_role = _role(row["actor_role"], "determination_role")
        authority_id = _id(row["authority_id"], "determination_authority")
        authority_epoch = row["authority_epoch"]
        if type(authority_epoch) is not int or authority_epoch < 1:
            _fail(SemanticAdapterIntegrityError, "determination_authority_epoch")
        authority_digest = _blob(row["authority_digest"], "determination_authority_digest")
        if (authority_id, authority_epoch, authority_digest) != (authority_context.authority_id, authority_context.epoch, authority_context.digest):
            _fail(SemanticAdapterAuthorityError, "determination_authority_stale")
        supporting = _parse_json_column(row["supporting_evidence_json"], "determination_evidence", expected_type=dict)
        if set(supporting) != {"bindings"} or type(supporting["bindings"]) is not list:
            _fail(SemanticAdapterIntegrityError, "determination_evidence")
        bindings = supporting["bindings"]
        if any(type(binding) is not dict or set(binding) != {"evidence_id", "record_digest"} for binding in bindings):
            _fail(SemanticAdapterIntegrityError, "determination_evidence")
        if [binding["evidence_id"] for binding in bindings] != sorted(binding["evidence_id"] for binding in bindings) or len({binding["evidence_id"] for binding in bindings}) != len(bindings):
            _fail(SemanticAdapterIntegrityError, "determination_evidence")
        expected_revision = row["expected_revision"]
        resulting_revision = row["resulting_revision"]
        if type(expected_revision) is not int or type(resulting_revision) is not int or not 0 <= expected_revision <= owner._MAX_ROWS or not 0 <= resulting_revision <= owner._MAX_ROWS:
            _fail(SemanticAdapterIntegrityError, "determination_revision")
        body = {
            "determination_id": determination_id,
            "obligation_id": obligation_id,
            "claim_id": _id(row["claim_id"], "determination_claim"),
            "actor_id": actor_id,
            "actor_role": actor_role,
            "authority_id": authority_id,
            "authority_epoch": authority_epoch,
            "authority_digest": _hex(authority_digest),
            "decision": _id(row["decision"], "determination_decision"),
            "amount_cents": _cents(row["amount_cents"], "determination_amount", positive=True),
            "supporting_evidence": bindings,
            "expected_revision": expected_revision,
            "resulting_revision": resulting_revision,
            "decided_at_ms": _time(row["decided_at_ms"], "determination_time"),
            "determination_digest": _hex(_blob(row["determination_digest"], "determination_digest")),
            "input_evaluation_id": _id(row["input_evaluation_id"], "determination_evaluation_id"),
            "input_evaluation_result_digest": _hex(_blob(row["input_evaluation_result_digest"], "determination_eval_digest")),
            "action_id": "",
        }
        if body["decided_at_ms"] > evaluation_time_ms:
            _fail(SemanticAdapterIntegrityError, "determination_time_binding")
        result.append(body)
    for determination in result:
        action = next((value for value in actions if value["determination_id"] == determination["determination_id"]), None)
        if action is None:
            _fail(SemanticAdapterIntegrityError, "determination_action_missing")
        determination["action_id"] = action["action_id"]
    return result


def _load_facts(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    scope: Mapping[str, str],
    evaluation_time_ms: int,
    limit: int,
) -> tuple[sqlite3.Row, owner.ControlPack, dict[str, dict[str, Any]], dict[str, Any]]:
    """The cross-bound facts BLFIN02 carries for one obligation, short of its determinations."""

    obligation_row, obligation_body = _load_obligation(
        connection, obligation_id=obligation_id, scope=scope, evaluation_time_ms=evaluation_time_ms,
    )
    item_id = str(obligation_row["item_id"])
    population_body, pack_body, pack = _load_population_and_pack(connection, obligation_row, scope)
    evidence_body, evidence_by_id = _load_evidence(
        connection, item_id=item_id, evaluation_time_ms=evaluation_time_ms, limit=limit,
    )
    payments_body, payments_by_id = _load_payments(
        connection, obligation_id=obligation_id, item_id=item_id, evidence=evidence_by_id,
        evaluation_time_ms=evaluation_time_ms, limit=limit,
    )
    claims_body = _load_claims(
        connection, obligation_id=obligation_id, evidence=evidence_by_id,
        evaluation_time_ms=evaluation_time_ms, limit=limit,
    )
    cases_body = _load_cases(
        connection, obligation_id=obligation_id, pack=pack, evaluation_time_ms=evaluation_time_ms, limit=limit,
    )
    actions_body, outbox_body, _ = _load_actions(
        connection, obligation_id=obligation_id, evaluation_time_ms=evaluation_time_ms, limit=limit,
    )
    conflicts_body = _load_conflicts(
        connection, obligation_id=obligation_id, item_id=item_id, evidence=evidence_by_id,
        payments=payments_by_id, evaluation_time_ms=evaluation_time_ms, limit=limit,
    )
    return obligation_row, pack, evidence_by_id, {
        "pre_evaluation": {"obligation_id": obligation_id, "item_id": item_id, "revision": int(obligation_row["revision"])},
        "population": population_body,
        "control_pack": pack_body,
        "obligation": obligation_body,
        "evidence": evidence_body,
        "payments": payments_body,
        "claims": claims_body,
        "cases": cases_body,
        "actions": actions_body,
        "action_outbox": outbox_body,
        "conflicts": conflicts_body,
    }


def _authority_body(authority_context: TrustedAuthorityContext) -> dict[str, Any]:
    return {
        "context": authority_context.source,
        "authority_id": authority_context.authority_id,
        "epoch": authority_context.epoch,
        "digest": _hex(authority_context.digest),
        "actors": authority_context.actor_roles,
    }


def live_evaluation_input(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    authority_context: TrustedAuthorityContext,
    evaluation_time_ms: int,
    verification: Mapping[str, object],
) -> tuple[bytes, dict[str, Any]]:
    """BLFIN02 for the owner's live decision, read inside the writer's own transaction.

    ``verification`` is the writer's bound scope, owner and mode.  Only the facts
    BLFIN02 carries are read; evaluation history is not an input to the decision.
    """

    connection = _require_connection(connection)
    if type(authority_context) is not TrustedAuthorityContext:
        _fail(SemanticAdapterInputError, "authority_context_type")
    _time(evaluation_time_ms, "evaluation_time")
    try:
        scope, identity = _read_verified_meta(connection, verification)
        _row, _pack, evidence_by_id, facts = _load_facts(
            connection, obligation_id=obligation_id, scope=scope,
            evaluation_time_ms=evaluation_time_ms, limit=owner._MAX_ROWS,
        )
        facts["determinations"] = _load_determinations(
            connection, obligation_id=obligation_id, evidence=evidence_by_id, actions=facts["actions"],
            authority_context=authority_context, evaluation_time_ms=evaluation_time_ms, limit=owner._MAX_ROWS,
        )
        data = {
            "scope": scope,
            "owner": identity,
            "authority": _authority_body(authority_context),
            "evaluation_time_ms": evaluation_time_ms,
            **facts,
        }
        return _encode_blfin02(data), data
    except SemanticAdapterError:
        raise
    except sqlite3.Error:
        _fail(SemanticAdapterIntegrityError, "database_read")
    except (TypeError, ValueError, KeyError, IndexError):
        _fail(SemanticAdapterIntegrityError, "record_shape")


def encode_payment_item(*, blfin02: bytes, receipts: Any, foreign: tuple[bool, bool], expected_revision: int | None, command: Mapping[str, Any]) -> bytes:
    """One BLFPAY01 form-A item (Codec.lean encodePaymentRequest): the BLFIN02 input, the payment receipts, the two
    foreign-id flags, the expected revision and the command."""

    writer = _WireWriter()
    writer.raw(PAYMENT_MAGIC + b"\x01" + len(blfin02).to_bytes(4, "big") + blfin02, "payment_input")
    writer.list(receipts, "receipts", lambda row, label: (writer.identifier(row[0], label), writer.nat(row[1], label), writer.option_identifier(row[2], label)))
    writer.byte(int(foreign[0]) + 2 * int(foreign[1]), "foreign")
    writer.option_nat(expected_revision, "expected_revision")
    if command["kind"] == "record":
        writer.byte(1, "command")
        for key in ("payment_id", "evidence_id", "common_origin_id", "source_id"):
            writer.identifier(command[key], key)
        writer.string(command["source_version"], "source_version")
        writer.byte(int(command["local_ref"] is not None), "local_ref")
        if command["local_ref"] is not None:
            writer.string(command["local_ref"], "local_ref")
        writer.nat(command["amount_cents"], "amount")
        writer.nat(command["event_at_ms"], "event_at")
        writer.option_identifier(command["pays_action_id"], "pays_action_id")
    elif command["kind"] == "reverse":
        writer.byte(2, "command")
        writer.identifier(command["payment_id"], "payment_id")
        writer.identifier(command["evidence_id"], "evidence_id")
        writer.option_identifier(command["common_origin_id"], "common_origin_id")
        writer.option_nat(command["event_at_ms"], "event_at")
    else:
        _fail(SemanticAdapterInputError, "payment_command")
    return writer.finish(label="payment_size")


def live_payment_input(connection: sqlite3.Connection, *, obligation_id: str, authority_context: TrustedAuthorityContext, now_ms: int, verification: Mapping[str, object],
                       expected_revision: int | None, command: Mapping[str, Any], receipts: Any) -> tuple[bytes, dict[str, Any]]:
    """The BLFPAY01 item for the owner's payment command, read inside the writer's own transaction."""

    wire, data = live_evaluation_input(connection, obligation_id=obligation_id, authority_context=authority_context, evaluation_time_ms=now_ms, verification=verification)
    foreign = (connection.execute("SELECT 1 FROM payments WHERE payment_id=? AND obligation_id<>?", (command["payment_id"], obligation_id)).fetchone() is not None,
               connection.execute("SELECT 1 FROM evidence WHERE evidence_id=? AND item_id<>?", (command["evidence_id"], data["pre_evaluation"]["item_id"])).fetchone() is not None)
    item = encode_payment_item(blfin02=wire, receipts=receipts, foreign=foreign, expected_revision=expected_revision, command=command)
    return item, {**data, "blfin02": wire, "receipts": receipts, "foreign": foreign}


def _make_snapshot(body: dict[str, Any]) -> LockedSemanticSnapshot:
    """The only snapshot constructor: the Owner loader and the Engine's rebound
    bodies both come through here, so the bounds are checked once, here."""

    unsigned_bytes = _canonical(body)
    _validate_json_tree(json.loads(unsigned_bytes))
    pre = body["pre_evaluation"]
    obligation_id = _id(pre["obligation_id"], "snapshot_obligation")
    revision = pre["revision"]
    if type(revision) is not int or not 0 <= revision <= owner._MAX_ROWS:
        _fail(SemanticAdapterCodecError, "snapshot_revision")
    evaluation_time = _time(body["evaluation_time_ms"], "snapshot_time")
    digest = owner._digest(_SNAPSHOT_DOMAIN, unsigned_bytes)
    body["snapshot_digest"] = _hex(digest)
    encoded = _canonical(body)
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        _fail(SemanticAdapterCodecError, "snapshot_size")
    return LockedSemanticSnapshot(
        encoded,
        digest,
        obligation_id,
        revision,
        evaluation_time,
        _validation_token=_SNAPSHOT_VALIDATION_TOKEN,
    )


def build_locked_semantic_snapshot(
    connection: sqlite3.Connection,
    *,
    obligation_id: str,
    authority_context: TrustedAuthorityContext,
    evaluation_time_ms: int,
    expected_config: object,
    expected_scope: object,
    expected_mode: str,
    expected_owner_id: str,
    expected_continuity_epoch: int | None = None,
    max_fact_rows: int = MAX_FACT_ROWS,
    verified_by: LockedSemanticSnapshot | None = None,
) -> LockedSemanticSnapshot:
    """Produce a bounded authenticated snapshot from one owner transaction.

    This function performs SELECT/PRAGMA work only.  It intentionally does not
    call ``sqlite3.connect`` or any owner command, and it never commits or
    rolls back the caller's transaction. ``verified_by``, a snapshot this same
    transaction verified before its own writes, supplies scope and owner instead
    of verifying the whole database again (the writer's pre-COMMIT check follows).
    """

    connection = _require_connection(connection)
    if type(authority_context) is not TrustedAuthorityContext:
        _fail(SemanticAdapterInputError, "authority_context_type")
    _time(evaluation_time_ms, "evaluation_time")
    _id(expected_owner_id, "expected_owner_id")
    if expected_mode not in owner._MODES:
        _fail(SemanticAdapterInputError, "expected_mode")
    if type(max_fact_rows) is not int or not 1 <= max_fact_rows <= MAX_FACT_ROWS:
        _fail(SemanticAdapterInputError, "fact_row_bound")
    try:
        if verified_by is not None:
            verified = _require_validated_snapshot(verified_by).data
            scope, identity = dict(verified["scope"]), dict(verified["owner"])
        else:
            scope, identity = _read_verified_meta(connection, _verify_owner_connection(
                connection,
                expected_config=expected_config,
                expected_scope=expected_scope,
                authority_context=authority_context,
                expected_mode=expected_mode,
                expected_owner_id=expected_owner_id,
                expected_continuity_epoch=expected_continuity_epoch,
            ))
        obligation_row, pack, evidence_by_id, facts = _load_facts(
            connection, obligation_id=obligation_id, scope=scope,
            evaluation_time_ms=evaluation_time_ms, limit=max_fact_rows,
        )
        evaluations_body, evaluations_by_id, current_evaluation = _load_evaluations(
            connection,
            obligation_id=obligation_id,
            obligation=obligation_row,
            scope=scope,
            pack=pack,
            authority_context=authority_context,
            evidence=evidence_by_id,
            evaluation_time_ms=evaluation_time_ms,
            limit=max_fact_rows,
        )
        facts["determinations"] = _load_determinations(
            connection, obligation_id=obligation_id, evidence=evidence_by_id, actions=facts["actions"],
            authority_context=authority_context, evaluation_time_ms=evaluation_time_ms, limit=max_fact_rows,
        )
        body = {
            "schema": SEMANTIC_INPUT_SCHEMA,
            "version": SEMANTIC_INPUT_VERSION,
            "scope": dict(scope),
            "owner": identity,
            "authority": _authority_body(authority_context),
            "evaluation_time_ms": evaluation_time_ms,
            **facts,
            "population_item": {
                "population_id": facts["population"]["population_id"],
                "item_id": str(obligation_row["item_id"]),
                "display_label": _text(
                    connection.execute(
                        "SELECT display_label FROM population_items WHERE population_id=? AND item_id=?",
                        (obligation_row["population_id"], obligation_row["item_id"]),
                    ).fetchone()[0],
                    "population_item_label",
                    max_bytes=128,
                ),
                "owed_cents": int(obligation_row["owed_cents"]),
                "due_at_ms": int(obligation_row["due_at_ms"]),
                "currency": str(obligation_row["currency"]),
            },
            "evaluations": evaluations_body,
            "current_evaluation": {
                "receipt": current_evaluation,
                "input_snapshot": evaluations_by_id[current_evaluation["evaluation_id"]]["input_snapshot"],
            },
        }
        encoded = _canonical(body)
        if len(encoded) > MAX_SNAPSHOT_BYTES:
            _fail(SemanticAdapterIntegrityError, "snapshot_size")
        return _make_snapshot(body)
    except SemanticAdapterError:
        raise
    except sqlite3.Error:
        _fail(SemanticAdapterIntegrityError, "database_read")
    except (TypeError, ValueError, KeyError, IndexError):
        _fail(SemanticAdapterIntegrityError, "record_shape")


def bind_resulting_state(
    connection: sqlite3.Connection,
    before: LockedSemanticSnapshot,
    *,
    authority_context: TrustedAuthorityContext,
    evaluation_time_ms: int,
    mutation: Mapping[str, Any],
) -> None:
    """A writer's declared post-state is its own: ``mutation``'s resulting input is this transaction's
    snapshot after its writes (verified by ``before``), and its resulting result evaluated that snapshot."""

    identity = _require_validated_snapshot(before).data["owner"]
    post = build_locked_semantic_snapshot(
        connection, obligation_id=before.obligation_id, authority_context=authority_context, evaluation_time_ms=evaluation_time_ms,
        expected_config=None, expected_scope=None, expected_mode=identity["mode"], expected_owner_id=identity["owner_id"], verified_by=before,
    )
    if encode_blfin02_input(post) != mutation["resulting_input_wire"]:
        _fail(SemanticAdapterIntegrityError, "resulting_input")
    _bind_result_identity(mutation["resulting_result"], post.data)

