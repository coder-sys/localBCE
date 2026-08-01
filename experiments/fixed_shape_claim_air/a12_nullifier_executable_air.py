"""Executable fixed-capacity A12 wide nullifier and compatibility-alias AIR."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha3_512
from types import MappingProxyType
from typing import Final, Mapping, Sequence

from app.batch.pq_nullifier_derivation import (
    ATTEMPT_DOMAIN_CODE,
    COVER_DOMAIN_CODE_V2,
    ENCODING_MAGIC,
    ENCODING_MAGIC_V2,
    AttemptReplayIdentityV1,
    CoverReplayContextV2,
    NullifierDerivationAuthorityV1,
    encode_attempt_preimage_v1,
    encode_cover_preimage_v2,
    pepper_commitment_sha3_512,
)

from .application_sha3_executable_air import (
    ApplicationSha3AirInstance,
    Sha3Call,
    build_application_sha3_executable_air,
    build_application_sha3_interface_air,
)
from .executable_air import (
    M31,
    AirProgram,
    AirTable,
    Identity,
    LookupArgument,
    LookupSide,
    TraceTable,
    boolean,
    cell,
    const,
    freeze_columns,
    namespace_air_program,
)
from .semantics import StructuralError
from .stark252_projection_air import (
    Stark252ProjectionRequest,
    build_stark252_projection_air,
    compatibility_felt_from_sha3_512,
)


PROGRAM_ID: Final[str] = "BL-WAVE1A-A12-WIDE-AUTHORITATIVE-NULLIFIER-AIR-v3"
PREIMAGE_CAPACITY: Final[int] = 254
PEPPER_MESSAGE_CAPACITY: Final[int] = 76


@dataclass(frozen=True, slots=True)
class AttemptNullifierAirRequest:
    operation_id: str
    identity: AttemptReplayIdentityV1

    def __post_init__(self) -> None:
        if type(self.operation_id) is not str or not self.operation_id:
            raise StructuralError("a12_air_operation_id_invalid")
        if not isinstance(self.identity, AttemptReplayIdentityV1):
            raise StructuralError("a12_air_attempt_identity_invalid")
        self.identity.require_bl_pq512_v1()


@dataclass(frozen=True, slots=True)
class CoverNullifierAirRequest:
    operation_id: str
    context: CoverReplayContextV2
    private_nonce_512: bytes

    def __post_init__(self) -> None:
        if type(self.operation_id) is not str or not self.operation_id:
            raise StructuralError("a12_air_operation_id_invalid")
        if not isinstance(self.context, CoverReplayContextV2):
            raise StructuralError("a12_air_cover_context_invalid")
        if (
            type(self.private_nonce_512) is not bytes
            or len(self.private_nonce_512) != 64
            or not any(self.private_nonce_512)
        ):
            raise StructuralError("a12_air_cover_nonce_invalid")


NullifierAirRequest = AttemptNullifierAirRequest | CoverNullifierAirRequest


@dataclass(frozen=True, slots=True)
class A12NullifierAirInstance:
    program: AirProgram
    traces: Mapping[str, TraceTable]
    operation_ids: tuple[str, ...]
    preimages: tuple[bytes, ...]
    strong_nullifiers: tuple[bytes, ...]
    compatibility_aliases: tuple[int, ...]
    authority_id_512: bytes
    pepper_commitment: bytes
    sha3: ApplicationSha3AirInstance
    nullifier_hashes_constrained: bool = True
    hash_ports_constrained: bool = False
    sha3_interface_only: bool = False

    def __post_init__(self) -> None:
        if (
            self.sha3_interface_only != self.hash_ports_constrained
            or (self.sha3_interface_only and self.nullifier_hashes_constrained)
            or (not self.nullifier_hashes_constrained and not self.hash_ports_constrained)
        ):
            raise StructuralError("a12_air_false_completion_claim")


def _append(columns: dict[str, list[int]], name: str, value: int) -> None:
    columns.setdefault(name, []).append(value)


def _append_fixed_text(
    columns: dict[str, list[int]], prefix: str, raw: bytes, capacity: int
) -> None:
    _append(columns, f"{prefix}_length", len(raw))
    for index in range(capacity):
        _append(columns, f"{prefix}_live_{index}", int(index < len(raw)))
        _append(columns, f"{prefix}_byte_{index}", raw[index] if index < len(raw) else 0)


def _append_bytes(columns: dict[str, list[int]], prefix: str, raw: bytes, capacity: int) -> None:
    if len(raw) != capacity:
        raise StructuralError("a12_air_internal_byte_length_invalid")
    for index, value in enumerate(raw):
        _append(columns, f"{prefix}_{index}", value)


def _nonzero_inverse(flags: Sequence[int]) -> int:
    total = sum(flags)
    return pow(total, -1, M31) if total else 0


def _balanced_sum(values):
    """Build a logarithmic-depth sum AST for wide byte/flag reductions."""

    level = list(values)
    if not level:
        return const(0)
    while len(level) > 1:
        level = [
            level[index] + level[index + 1]
            if index + 1 < len(level)
            else level[index]
            for index in range(0, len(level), 2)
        ]
    return level[0]


def _field_sources(
    table: str,
    row: int,
    selector,
    position,
    value,
) -> LookupSide:
    return LookupSide(table, selector, (position, value), row, row + 1)


def build_a12_nullifier_executable_air(
    requests: Sequence[NullifierAirRequest],
    authority: NullifierDerivationAuthorityV1,
    *,
    interface_only: bool = False,
) -> A12NullifierAirInstance:
    materialized = tuple(requests)
    if not materialized or not isinstance(authority, NullifierDerivationAuthorityV1):
        raise StructuralError("a12_air_requests_or_authority_invalid")
    operation_ids = tuple(request.operation_id for request in materialized)
    if len(set(operation_ids)) != len(operation_ids):
        raise StructuralError("a12_air_operation_id_duplicate")

    preimages: list[bytes] = []
    strong: list[bytes] = []
    compatibility_aliases: list[int] = []
    request_columns: dict[str, list[int]] = {}
    byte_property_counts: Counter[tuple[int, int]] = Counter()
    character_counts: Counter[tuple[int, int]] = Counter()

    for request_index, request in enumerate(materialized):
        attempt = isinstance(request, AttemptNullifierAirRequest)
        if attempt:
            assert isinstance(request, AttemptNullifierAirRequest)
            identity = request.identity
            preimage = encode_attempt_preimage_v1(identity, authority)
            authority_raw = identity.source_authority_id.encode("ascii")
            claim_raw = identity.source_claim_id.encode("ascii")
            profile_raw = b""
            domain = epoch = batch = slot = nonce = bytes()
        else:
            assert isinstance(request, CoverNullifierAirRequest)
            preimage = encode_cover_preimage_v2(request.context, request.private_nonce_512)
            authority_raw = claim_raw = b""
            profile_raw = request.context.profile_id.encode("ascii")
            domain = request.context.strong_settlement_domain_id_512
            epoch = request.context.epoch.to_bytes(8, "big")
            batch = request.context.strong_batch_nonce_512
            slot = request.context.slot_index.to_bytes(2, "big")
            nonce = request.private_nonce_512
        preimages.append(preimage)
        digest = sha3_512(preimage).digest()
        strong.append(digest)
        compatibility_aliases.append(compatibility_felt_from_sha3_512(digest))
        _append(request_columns, "request_index", request_index)
        _append(request_columns, "is_attempt", int(attempt))
        _append_fixed_text(request_columns, "authority", authority_raw, 64)
        _append_fixed_text(request_columns, "claim", claim_raw, 64)
        _append_fixed_text(request_columns, "profile", profile_raw, 32)
        _append_bytes(request_columns, "cover_domain", domain if not attempt else bytes(64), 64)
        _append_bytes(request_columns, "cover_epoch", epoch if not attempt else bytes(8), 8)
        _append_bytes(request_columns, "cover_batch", batch if not attempt else bytes(64), 64)
        _append_bytes(request_columns, "cover_slot", slot if not attempt else bytes(2), 2)
        _append_bytes(request_columns, "cover_nonce", nonce if not attempt else bytes(64), 64)
        _append_bytes(request_columns, "pepper", authority.pepper_512 if attempt else bytes(64), 64)
        for prefix, raw, required in (
            ("cover_domain", domain if not attempt else bytes(64), not attempt),
            ("cover_epoch", epoch if not attempt else bytes(8), not attempt),
            ("cover_batch", batch if not attempt else bytes(64), not attempt),
            ("cover_nonce", nonce if not attempt else bytes(64), not attempt),
            ("pepper", authority.pepper_512 if attempt else bytes(64), attempt),
        ):
            flags = tuple(int(value != 0) for value in raw)
            for index, (value, flag) in enumerate(zip(raw, flags, strict=True)):
                _append(request_columns, f"{prefix}_nonzero_{index}", flag)
                byte_property_counts[(value, flag)] += 1
            _append(request_columns, f"{prefix}_inverse", _nonzero_inverse(flags) if required else 0)
            _append(request_columns, f"{prefix}_nonzero_product", int(required))
        for prefix, raw, kind in (
            ("authority", authority_raw, 1),
            ("claim", claim_raw, 1),
            ("profile", profile_raw, 3),
        ):
            for index, value in enumerate(raw):
                character_counts[(kind if index == 0 or kind == 3 else 2, value)] += 1

    rows = len(materialized)
    request_identities: list[Identity] = [
        Identity("is_attempt_boolean", boolean(cell("is_attempt")), 0, rows)
    ]
    for prefix, capacity, attempt_lane in (
        ("authority", 64, True),
        ("claim", 64, True),
        ("profile", 32, False),
    ):
        live_values = []
        lane = cell("is_attempt") if attempt_lane else 1 - cell("is_attempt")
        for index in range(capacity):
            live = cell(f"{prefix}_live_{index}")
            value = cell(f"{prefix}_byte_{index}")
            live_values.append(live)
            request_identities.extend(
                (
                    Identity(f"{prefix}_live_boolean_{index}", boolean(live), 0, rows),
                    Identity(f"{prefix}_padding_zero_{index}", (1 - live) * value, 0, rows),
                    Identity(f"{prefix}_disabled_live_{index}", (1 - lane) * live, 0, rows),
                )
            )
            if index + 1 < capacity:
                request_identities.append(
                    Identity(
                        f"{prefix}_live_prefix_{index}",
                        cell(f"{prefix}_live_{index + 1}") * (1 - live),
                        0,
                        rows,
                    )
                )
        request_identities.extend(
            (
                Identity(
                    f"{prefix}_length",
                    cell(f"{prefix}_length") - _balanced_sum(live_values),
                    0,
                    rows,
                ),
                Identity(f"{prefix}_required", cell(f"{prefix}_live_0") - lane, 0, rows),
            )
        )
    for prefix, capacity, required in (
        ("cover_domain", 64, 1 - cell("is_attempt")),
        ("cover_epoch", 8, 1 - cell("is_attempt")),
        ("cover_batch", 64, 1 - cell("is_attempt")),
        ("cover_nonce", 64, 1 - cell("is_attempt")),
        ("pepper", 64, cell("is_attempt")),
    ):
        nonzero_values = []
        for index in range(capacity):
            flag = cell(f"{prefix}_nonzero_{index}")
            nonzero_values.append(flag)
            request_identities.extend(
                (
                    Identity(f"{prefix}_nonzero_boolean_{index}", boolean(flag), 0, rows),
                    Identity(
                        f"{prefix}_disabled_zero_{index}",
                        (1 - required) * cell(f"{prefix}_{index}"),
                        0,
                        rows,
                    ),
                )
            )
        request_identities.append(
            Identity(
                f"{prefix}_nonzero_product",
                cell(f"{prefix}_nonzero_product")
                - _balanced_sum(nonzero_values) * cell(f"{prefix}_inverse"),
                0,
                rows,
            )
        )
        request_identities.append(
            Identity(
                f"{prefix}_required_nonzero",
                required * (cell(f"{prefix}_nonzero_product") - 1),
                0,
                rows,
            )
        )

    request_trace = TraceTable("a12_request", freeze_columns(request_columns))
    request_table = AirTable(
        "a12_request",
        tuple(request_trace.columns),
        rows,
        tuple(request_identities),
        MappingProxyType({"request_index": tuple(range(rows))}),
    )

    authority_columns: dict[str, list[int]] = {}
    _append(
        authority_columns,
        "attempt_count",
        sum(isinstance(request, AttemptNullifierAirRequest) for request in materialized),
    )
    _append_bytes(authority_columns, "authority_id", authority.authority_id_512, 64)
    _append_bytes(authority_columns, "pepper", authority.pepper_512, 64)
    commitment = pepper_commitment_sha3_512(authority.pepper_512)
    _append_bytes(authority_columns, "commitment", commitment, 64)
    authority_trace = TraceTable("a12_authority", freeze_columns(authority_columns))
    authority_table = AirTable("a12_authority", tuple(authority_trace.columns), 1, ())

    output_columns: dict[str, list[int]] = {"request_index": list(range(rows))}
    for digest, alias in zip(strong, compatibility_aliases, strict=True):
        _append_bytes(output_columns, "strong", digest, 64)
        _append_bytes(output_columns, "compatibility", alias.to_bytes(32, "big"), 32)
    output_trace = TraceTable("a12_output", freeze_columns(output_columns))
    output_table = AirTable(
        "a12_output",
        tuple(output_trace.columns),
        rows,
        (),
        MappingProxyType({"request_index": tuple(range(rows))}),
    )

    calls = tuple(
        Sha3Call(f"a12_{index}", preimage, PREIMAGE_CAPACITY)
        for index, preimage in enumerate(preimages)
    ) + (
        Sha3Call(
            "a12_pepper",
            b"BLPQPEP1" + b"\x00\x01\x00\x40" + authority.pepper_512,
            PEPPER_MESSAGE_CAPACITY,
        ),
    )
    sha3 = (
        build_application_sha3_interface_air(calls)
        if interface_only
        else build_application_sha3_executable_air(calls)
    )
    raw_projection = build_stark252_projection_air(
        tuple(
            Stark252ProjectionRequest(f"a12_{index}", digest)
            for index, digest in enumerate(strong)
        )
    )
    projection = namespace_air_program(
        raw_projection.program,
        raw_projection.traces,
        "a12_projection",
    )
    projection_table = projection.table_names["stark252_projection"]

    lookups: list[LookupArgument] = []
    for request_index, request in enumerate(materialized):
        call_rows = sha3.call_rows[f"a12_{request_index}"]
        attempt = isinstance(request, AttemptNullifierAirRequest)
        attempt_selector = cell("is_attempt")
        cover_selector = 1 - cell("is_attempt")
        sources: list[LookupSide] = []

        def add(selector, position, value) -> None:
            sources.append(
                _field_sources("a12_request", request_index, selector, position, value)
            )

        for position, (attempt_byte, cover_byte) in enumerate(
            zip(ENCODING_MAGIC, ENCODING_MAGIC_V2, strict=True)
        ):
            add(attempt_selector, const(position), const(attempt_byte))
            add(cover_selector, const(position), const(cover_byte))
        add(const(1), const(8), const(0))
        add(attempt_selector, const(9), const(1))
        add(cover_selector, const(9), const(2))
        add(attempt_selector, const(10), const(ATTEMPT_DOMAIN_CODE >> 8))
        add(attempt_selector, const(11), const(ATTEMPT_DOMAIN_CODE & 0xFF))
        add(cover_selector, const(10), const(COVER_DOMAIN_CODE_V2 >> 8))
        add(cover_selector, const(11), const(COVER_DOMAIN_CODE_V2 & 0xFF))
        attempt_total = 95 + cell("authority_length") + cell("claim_length")
        cover_total = 222 + cell("profile_length")
        for position in range(12, 15):
            add(const(1), const(position), const(0))
        add(attempt_selector, const(15), attempt_total)
        add(cover_selector, const(15), cover_total)

        # Attempt grammar.
        add(attempt_selector, const(16), const(0))
        add(attempt_selector, const(17), cell("authority_length"))
        for index in range(64):
            add(
                cell(f"authority_live_{index}"),
                const(18 + index),
                cell(f"authority_byte_{index}"),
            )
        claim_base = 18 + cell("authority_length")
        add(attempt_selector, claim_base, const(0))
        add(attempt_selector, claim_base + 1, cell("claim_length"))
        for index in range(64):
            add(
                cell(f"claim_live_{index}"),
                claim_base + 2 + index,
                cell(f"claim_byte_{index}"),
            )
        attempt_tail = claim_base + 2 + cell("claim_length")
        for offset, value in enumerate(b"\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x40"):
            add(attempt_selector, attempt_tail + offset, const(value))
        for index in range(64):
            add(attempt_selector, attempt_tail + 11 + index, cell(f"pepper_{index}"))

        # Cover grammar.
        add(cover_selector, const(16), const(0))
        add(cover_selector, const(17), cell("profile_length"))
        for index in range(32):
            add(
                cell(f"profile_live_{index}"),
                const(18 + index),
                cell(f"profile_byte_{index}"),
            )
        cover_base = 18 + cell("profile_length")
        cursor = cover_base
        for prefix, capacity in (
            ("cover_domain", 64),
            ("cover_epoch", 8),
            ("cover_batch", 64),
            ("cover_slot", 2),
        ):
            for index in range(capacity):
                add(cover_selector, cursor + index, cell(f"{prefix}_{index}"))
            cursor += capacity
        add(cover_selector, cursor, const(0))
        add(cover_selector, cursor + 1, const(64))
        for index in range(64):
            add(cover_selector, cursor + 2 + index, cell(f"cover_nonce_{index}"))

        destination = LookupSide(
            "sha3_message_batch",
            cell("live"),
            (cell("position"), cell("value")),
            call_rows.message_start,
            call_rows.message_stop,
        )
        lookups.append(
            LookupArgument(f"a12_preimage_binding_{request_index}", tuple(sources), (destination,))
        )
        lookups.append(
            LookupArgument(
                f"a12_strong_output_{request_index}",
                (
                    LookupSide(
                        "sha3_digest_batch",
                        const(1),
                        tuple(cell(f"value_{index}") for index in range(64)),
                        call_rows.digest_row,
                        call_rows.digest_row + 1,
                    ),
                ),
                (
                    LookupSide(
                        "a12_output",
                        const(1),
                        tuple(cell(f"strong_{index}") for index in range(64)),
                        request_index,
                        request_index + 1,
                    ),
                ),
            )
        )
        lookups.extend(
            (
                LookupArgument(
                    f"a12_projection_input_{request_index}",
                    (
                        LookupSide(
                            "sha3_digest_batch",
                            const(1),
                            tuple(cell(f"value_{index}") for index in range(64)),
                            call_rows.digest_row,
                            call_rows.digest_row + 1,
                        ),
                    ),
                    (
                        LookupSide(
                            projection_table,
                            const(1),
                            tuple(cell(f"digest_{index}") for index in range(64)),
                            request_index,
                            request_index + 1,
                        ),
                    ),
                ),
                LookupArgument(
                    f"a12_compatibility_output_{request_index}",
                    (
                        LookupSide(
                            projection_table,
                            const(1),
                            tuple(cell(f"alias_{31 - index}") for index in range(32)),
                            request_index,
                            request_index + 1,
                        ),
                    ),
                    (
                        LookupSide(
                            "a12_output",
                            const(1),
                            tuple(cell(f"compatibility_{index}") for index in range(32)),
                            request_index,
                            request_index + 1,
                        ),
                    ),
                ),
            )
        )

    pepper_tuple = tuple(cell(f"pepper_{index}") for index in range(64))
    lookups.append(
        LookupArgument(
            "a12_shared_pepper",
            (LookupSide("a12_request", cell("is_attempt"), pepper_tuple, 0, rows),),
            (
                LookupSide(
                    "a12_authority",
                    const(1),
                    pepper_tuple,
                    0,
                    1,
                    cell("attempt_count"),
                ),
            ),
        )
    )
    pepper_sources = tuple(
        _field_sources("a12_authority", 0, const(1), const(position), const(value))
        for position, value in enumerate(b"BLPQPEP1\x00\x01\x00\x40")
    ) + tuple(
        _field_sources(
            "a12_authority", 0, const(1), const(12 + index), cell(f"pepper_{index}")
        )
        for index in range(64)
    )
    pepper_rows = sha3.call_rows["a12_pepper"]
    lookups.extend(
        (
            LookupArgument(
                "a12_pepper_preimage",
                pepper_sources,
                (
                    LookupSide(
                        "sha3_message_batch",
                        cell("live"),
                        (cell("position"), cell("value")),
                        pepper_rows.message_start,
                        pepper_rows.message_stop,
                    ),
                ),
            ),
            LookupArgument(
                "a12_pepper_commitment",
                (
                    LookupSide(
                        "sha3_digest_batch",
                        const(1),
                        tuple(cell(f"value_{index}") for index in range(64)),
                        pepper_rows.digest_row,
                        pepper_rows.digest_row + 1,
                    ),
                ),
                (
                    LookupSide(
                        "a12_authority",
                        const(1),
                        tuple(cell(f"commitment_{index}") for index in range(64)),
                        0,
                        1,
                    ),
                ),
            ),
        )
    )

    byte_values = tuple(range(256))
    byte_nonzero = tuple(int(value != 0) for value in byte_values)
    byte_trace = TraceTable(
        "a12_byte_property",
        freeze_columns(
            {
                "value": byte_values,
                "nonzero": byte_nonzero,
                "multiplicity": tuple(
                    byte_property_counts[(value, int(value != 0))] for value in byte_values
                ),
            }
        ),
    )
    byte_table = AirTable(
        "a12_byte_property",
        ("value", "nonzero", "multiplicity"),
        256,
        (),
        MappingProxyType({"value": byte_values, "nonzero": byte_nonzero}),
    )
    byte_sources: list[LookupSide] = []
    for prefix, capacity in (
        ("cover_domain", 64),
        ("cover_epoch", 8),
        ("cover_batch", 64),
        ("cover_nonce", 64),
        ("pepper", 64),
    ):
        for index in range(capacity):
            byte_sources.append(
                LookupSide(
                    "a12_request",
                    const(1),
                    (cell(f"{prefix}_{index}"), cell(f"{prefix}_nonzero_{index}")),
                    0,
                    rows,
                )
            )
    lookups.append(
        LookupArgument(
            "a12_byte_nonzero",
            tuple(byte_sources),
            (
                LookupSide(
                    "a12_byte_property",
                    const(1),
                    (cell("value"), cell("nonzero")),
                    0,
                    256,
                    cell("multiplicity"),
                ),
            ),
        )
    )

    char_kinds: list[int] = []
    char_values: list[int] = []
    for kind, alphabet in (
        (1, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        (2, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"),
        (3, bytes(range(128))),
    ):
        for value in alphabet:
            char_kinds.append(kind)
            char_values.append(value)
    char_trace = TraceTable(
        "a12_character",
        freeze_columns(
            {
                "kind": char_kinds,
                "value": char_values,
                "multiplicity": tuple(
                    character_counts[(kind, value)]
                    for kind, value in zip(char_kinds, char_values, strict=True)
                ),
            }
        ),
    )
    char_table = AirTable(
        "a12_character",
        ("kind", "value", "multiplicity"),
        len(char_kinds),
        (),
        MappingProxyType({"kind": tuple(char_kinds), "value": tuple(char_values)}),
    )
    char_sources: list[LookupSide] = []
    for prefix, capacity, base_kind in (
        ("authority", 64, 1),
        ("claim", 64, 1),
        ("profile", 32, 3),
    ):
        for index in range(capacity):
            char_sources.append(
                LookupSide(
                    "a12_request",
                    cell(f"{prefix}_live_{index}"),
                    (const(base_kind if index == 0 or base_kind == 3 else 2), cell(f"{prefix}_byte_{index}")),
                    0,
                    rows,
                )
            )
    lookups.append(
        LookupArgument(
            "a12_canonical_characters",
            tuple(char_sources),
            (
                LookupSide(
                    "a12_character",
                    const(1),
                    (cell("kind"), cell("value")),
                    0,
                    len(char_kinds),
                    cell("multiplicity"),
                ),
            ),
        )
    )

    program = AirProgram(
        PROGRAM_ID,
        (
            *sha3.program.tables,
            *projection.program.tables,
            request_table,
            authority_table,
            output_table,
            byte_table,
            char_table,
        ),
        (*sha3.program.lookups, *projection.program.lookups, *lookups),
    )
    return A12NullifierAirInstance(
        program,
        MappingProxyType(
            {
                **dict(sha3.traces),
                **dict(projection.traces),
                "a12_request": request_trace,
                "a12_authority": authority_trace,
                "a12_output": output_trace,
                "a12_byte_property": byte_trace,
                "a12_character": char_trace,
            }
        ),
        operation_ids,
        tuple(preimages),
        tuple(strong),
        tuple(compatibility_aliases),
        authority.authority_id_512,
        commitment,
        sha3,
        nullifier_hashes_constrained=not interface_only,
        hash_ports_constrained=interface_only,
        sha3_interface_only=interface_only,
    )


__all__ = [
    "A12NullifierAirInstance",
    "AttemptNullifierAirRequest",
    "CoverNullifierAirRequest",
    "build_a12_nullifier_executable_air",
]
