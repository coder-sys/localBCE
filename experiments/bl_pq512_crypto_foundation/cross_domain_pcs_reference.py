"""Independent projection-consistent SHA3-512 cross-domain PCS reference."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from hashlib import sha3_512
from typing import Final

from experiments.bl_pq512_crypto_foundation.field16_reference import Fp16, M31_MODULUS


CROSS_DOMAIN_MAGIC: Final[bytes] = b"BLPQXDM1"
CROSS_DOMAIN_VERSION: Final[int] = 1
CROSS_DOMAIN_EVALUATION_DOMAIN: Final[int] = 516
CROSS_DOMAIN_CHILDREN_DOMAIN: Final[int] = 517
CROSS_DOMAIN_INSERT_DOMAIN: Final[int] = 518
CROSS_DOMAIN_ROOT_DOMAIN: Final[int] = 519
CROSS_DOMAIN_LAYOUT_DOMAIN: Final[int] = 520
MAX_DOMAIN_LOG_SIZE: Final[int] = 30


class CommitmentStage(IntEnum):
    PREPROCESSED = 1
    MAIN_TRACE = 2
    INTERACTION_TRACE = 3
    COMPOSITION = 4
    DEEP_QUOTIENT = 5
    FRI_LAYER = 6
    FRI_BATCH_MASK = 7


class EvaluationField(IntEnum):
    M31 = 1
    FP16 = 2

    @property
    def encoded_width(self) -> int:
        return 4 if self is EvaluationField.M31 else 64


@dataclass(frozen=True, slots=True)
class DomainSpec:
    log_size: int
    field: EvaluationField
    column_count: int

    def __post_init__(self) -> None:
        if type(self.log_size) is not int or not 1 <= self.log_size <= MAX_DOMAIN_LOG_SIZE:
            raise ValueError("cross_domain_log_size_invalid")
        if not isinstance(self.field, EvaluationField):
            raise ValueError("cross_domain_field_invalid")
        if type(self.column_count) is not int or not 1 <= self.column_count <= 0xFFFFFFFF:
            raise ValueError("cross_domain_column_count_invalid")

    @property
    def payload_length(self) -> int:
        return self.column_count * self.field.encoded_width

    def encode(self) -> bytes:
        return b"".join(
            (
                self.log_size.to_bytes(1, "big"),
                int(self.field).to_bytes(2, "big"),
                self.column_count.to_bytes(4, "big"),
            )
        )


@dataclass(frozen=True, slots=True)
class CrossDomainLayout:
    stage: CommitmentStage
    commitment_id: bytes
    specs: tuple[DomainSpec, ...]
    identity: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.stage, CommitmentStage):
            raise ValueError("cross_domain_stage_invalid")
        if type(self.commitment_id) is not bytes or len(self.commitment_id) != 64:
            raise ValueError("cross_domain_commitment_id_must_be_64_bytes")
        if not any(self.commitment_id):
            raise ValueError("cross_domain_commitment_id_must_be_nonzero")
        if type(self.specs) is not tuple or not self.specs:
            raise ValueError("cross_domain_specs_required")
        if any(type(spec) is not DomainSpec for spec in self.specs):
            raise TypeError("cross_domain_spec_type_invalid")
        log_sizes = tuple(spec.log_size for spec in self.specs)
        if log_sizes != tuple(sorted(set(log_sizes))):
            raise ValueError("cross_domain_specs_not_strictly_increasing")
        expected = _digest(
            CROSS_DOMAIN_LAYOUT_DOMAIN,
            int(self.stage).to_bytes(2, "big"),
            self.commitment_id,
            len(self.specs).to_bytes(4, "big"),
            *(spec.encode() for spec in self.specs),
        )
        if self.identity not in (b"", expected):
            raise ValueError("cross_domain_layout_identity_mismatch")
        object.__setattr__(self, "identity", expected)

    @property
    def maximum_log_size(self) -> int:
        return self.specs[-1].log_size

    def spec_at(self, log_size: int) -> DomainSpec | None:
        return next((spec for spec in self.specs if spec.log_size == log_size), None)


@dataclass(frozen=True, slots=True)
class DomainEvaluationBatch:
    spec: DomainSpec
    rows: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if type(self.spec) is not DomainSpec:
            raise TypeError("cross_domain_batch_spec_type_invalid")
        if type(self.rows) is not tuple or len(self.rows) != 1 << self.spec.log_size:
            raise ValueError("cross_domain_batch_row_count_mismatch")
        for row_index, row in enumerate(self.rows):
            _validate_row(self.spec, row, row_index)


@dataclass(frozen=True, slots=True)
class DomainOpening:
    spec: DomainSpec
    fft_index: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class CrossDomainProof:
    query_fft_index: int
    siblings: tuple[bytes, ...]
    openings: tuple[DomainOpening, ...]

    def verify(self, layout: CrossDomainLayout, expected_root: bytes) -> bool:
        if type(layout) is not CrossDomainLayout:
            raise TypeError("cross_domain_layout_required")
        if type(expected_root) is not bytes or len(expected_root) != 64:
            raise ValueError("cross_domain_root_must_be_64_bytes")
        maximum_log = layout.maximum_log_size
        _validate_index(self.query_fft_index, maximum_log)
        if len(self.siblings) != maximum_log or any(
            type(sibling) is not bytes or len(sibling) != 64 for sibling in self.siblings
        ):
            raise ValueError("cross_domain_sibling_shape_invalid")
        if len(self.openings) != len(layout.specs):
            raise ValueError("cross_domain_opening_count_mismatch")

        maximum_transposed = transpose_circle_fft_index(self.query_fft_index, maximum_log)
        by_log: dict[int, DomainOpening] = {}
        for opening, spec in zip(self.openings, layout.specs, strict=True):
            if type(opening) is not DomainOpening or opening.spec != spec:
                raise ValueError("cross_domain_opening_spec_mismatch")
            level_index = maximum_transposed >> (maximum_log - spec.log_size)
            expected_fft_index = inverse_transpose_circle_fft_index(level_index, spec.log_size)
            if opening.fft_index != expected_fft_index:
                raise ValueError("cross_domain_opening_index_mismatch")
            _validate_row(spec, opening.payload, opening.fft_index)
            by_log[spec.log_size] = opening

        current_index = maximum_transposed
        current = _hash_insert(
            maximum_log,
            current_index,
            _empty_hash(),
            _hash_evaluation(layout, by_log[maximum_log]),
        )
        for sibling_offset, parent_log in enumerate(range(maximum_log - 1, -1, -1)):
            sibling = self.siblings[sibling_offset]
            current = (
                _hash_children(current, sibling)
                if current_index & 1 == 0
                else _hash_children(sibling, current)
            )
            current_index >>= 1
            if parent_log in by_log:
                current = _hash_insert(
                    parent_log,
                    current_index,
                    current,
                    _hash_evaluation(layout, by_log[parent_log]),
                )
        return _hash_root(layout, current) == expected_root


@dataclass(frozen=True, slots=True)
class CrossDomainTree:
    layout: CrossDomainLayout
    batches: tuple[DomainEvaluationBatch, ...]
    levels: tuple[tuple[bytes, ...], ...]
    root: bytes

    @classmethod
    def build(
        cls,
        layout: CrossDomainLayout,
        batches: tuple[DomainEvaluationBatch, ...],
    ) -> "CrossDomainTree":
        if type(layout) is not CrossDomainLayout:
            raise TypeError("cross_domain_layout_required")
        if type(batches) is not tuple or len(batches) != len(layout.specs):
            raise ValueError("cross_domain_batch_count_mismatch")
        if any(type(batch) is not DomainEvaluationBatch for batch in batches):
            raise TypeError("cross_domain_batch_type_invalid")
        if tuple(batch.spec for batch in batches) != layout.specs:
            raise ValueError("cross_domain_batch_spec_mismatch")

        maximum_log = layout.maximum_log_size
        levels: list[tuple[bytes, ...]] = [()] * (maximum_log + 1)
        by_log = {batch.spec.log_size: batch for batch in batches}
        for log_size in range(maximum_log, -1, -1):
            count = 1 << log_size
            if log_size == maximum_log:
                nodes = [_empty_hash()] * count
            else:
                children = levels[log_size + 1]
                nodes = [
                    _hash_children(children[index], children[index + 1])
                    for index in range(0, len(children), 2)
                ]
            batch = by_log.get(log_size)
            if batch is not None:
                for fft_index, payload in enumerate(batch.rows):
                    transposed_index = transpose_circle_fft_index(fft_index, log_size)
                    opening = DomainOpening(batch.spec, fft_index, payload)
                    nodes[transposed_index] = _hash_insert(
                        log_size,
                        transposed_index,
                        nodes[transposed_index],
                        _hash_evaluation(layout, opening),
                    )
            levels[log_size] = tuple(nodes)
        root = _hash_root(layout, levels[0][0])
        return cls(layout, batches, tuple(levels), root)

    def proof(self, query_fft_index: int) -> CrossDomainProof:
        maximum_log = self.layout.maximum_log_size
        _validate_index(query_fft_index, maximum_log)
        maximum_transposed = transpose_circle_fft_index(query_fft_index, maximum_log)
        current_index = maximum_transposed
        siblings: list[bytes] = []
        for level in range(maximum_log, 0, -1):
            siblings.append(self.levels[level][current_index ^ 1])
            current_index >>= 1

        openings: list[DomainOpening] = []
        for batch in self.batches:
            level_index = maximum_transposed >> (maximum_log - batch.spec.log_size)
            fft_index = inverse_transpose_circle_fft_index(level_index, batch.spec.log_size)
            openings.append(DomainOpening(batch.spec, fft_index, batch.rows[fft_index]))
        return CrossDomainProof(query_fft_index, tuple(siblings), tuple(openings))


def build_fri_batch_mask_tree(
    *,
    commitment_id: bytes,
    batch_masks: tuple[object, ...],
) -> CrossDomainTree:
    """Commit one independent Fp16 mask column on every FRI input domain.

    The returned typed root is the prover message that must be fixed before
    the public-coin batching coefficient is drawn.  Transcript ordering is a
    separate gate; this helper makes the committed algebraic object exact.
    """

    from experiments.bl_pq512_crypto_foundation.circle_fri_reference import (
        FriDomainBatch,
    )

    if type(batch_masks) is not tuple or not batch_masks:
        raise ValueError("cross_domain_fri_batch_masks_required")
    if any(type(batch) is not FriDomainBatch for batch in batch_masks):
        raise TypeError("cross_domain_fri_batch_mask_type_invalid")
    if any(batch.column_count != 1 for batch in batch_masks):
        raise ValueError("cross_domain_fri_batch_mask_must_have_one_column")
    ordered = tuple(sorted(batch_masks, key=lambda batch: batch.log_size))
    if len({batch.log_size for batch in ordered}) != len(ordered):
        raise ValueError("cross_domain_fri_batch_mask_domain_duplicate")

    specs = tuple(
        DomainSpec(batch.log_size, EvaluationField.FP16, 1) for batch in ordered
    )
    layout = CrossDomainLayout(
        CommitmentStage.FRI_BATCH_MASK,
        commitment_id,
        specs,
    )
    batches = tuple(
        DomainEvaluationBatch(
            spec,
            tuple(row[0].encode() for row in batch.rows),
        )
        for spec, batch in zip(specs, ordered, strict=True)
    )
    return CrossDomainTree.build(layout, batches)


def transpose_circle_fft_index(index: int, log_size: int) -> int:
    _validate_index(index, log_size)
    return (index >> 1) | ((index & 1) << (log_size - 1))


def inverse_transpose_circle_fft_index(index: int, log_size: int) -> int:
    _validate_index(index, log_size)
    high = (index >> (log_size - 1)) & 1
    lower_mask = (1 << (log_size - 1)) - 1
    return ((index & lower_mask) << 1) | high


def project_circle_fft_index(index: int, log_size: int) -> int:
    if type(log_size) is not int or log_size < 2:
        raise ValueError("cross_domain_projection_domain_too_small")
    transposed = transpose_circle_fft_index(index, log_size)
    return inverse_transpose_circle_fft_index(transposed >> 1, log_size - 1)


def _validate_index(index: int, log_size: int) -> None:
    if type(log_size) is not int or not 1 <= log_size <= MAX_DOMAIN_LOG_SIZE:
        raise ValueError("cross_domain_log_size_invalid")
    if type(index) is not int or not 0 <= index < 1 << log_size:
        raise ValueError("cross_domain_index_out_of_bounds")


def _validate_row(spec: DomainSpec, row: object, row_index: int) -> bytes:
    if type(row) is not bytes or len(row) != spec.payload_length:
        raise ValueError("cross_domain_row_length_mismatch")
    if spec.field is EvaluationField.M31:
        for offset in range(0, len(row), 4):
            if int.from_bytes(row[offset : offset + 4], "big") >= M31_MODULUS:
                raise ValueError(f"cross_domain_m31_not_canonical:{row_index}:{offset // 4}")
    else:
        for offset in range(0, len(row), 64):
            try:
                Fp16.decode(row[offset : offset + 64])
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"cross_domain_fp16_not_canonical:{row_index}:{offset // 64}"
                ) from exc
    return row


def _hash_evaluation(layout: CrossDomainLayout, opening: DomainOpening) -> bytes:
    return _digest(
        CROSS_DOMAIN_EVALUATION_DOMAIN,
        layout.identity,
        opening.spec.encode(),
        opening.fft_index.to_bytes(8, "big"),
        len(opening.payload).to_bytes(8, "big"),
        opening.payload,
    )


def _empty_hash() -> bytes:
    return _digest(CROSS_DOMAIN_CHILDREN_DOMAIN)


def _hash_children(left: bytes, right: bytes) -> bytes:
    return _digest(CROSS_DOMAIN_CHILDREN_DOMAIN, left, right)


def _hash_insert(
    log_size: int,
    transposed_index: int,
    children: bytes,
    evaluation: bytes,
) -> bytes:
    return _digest(
        CROSS_DOMAIN_INSERT_DOMAIN,
        log_size.to_bytes(1, "big"),
        transposed_index.to_bytes(8, "big"),
        children,
        evaluation,
    )


def _hash_root(layout: CrossDomainLayout, top: bytes) -> bytes:
    return _digest(
        CROSS_DOMAIN_ROOT_DOMAIN,
        layout.identity,
        layout.maximum_log_size.to_bytes(1, "big"),
        top,
    )


def _digest(domain: int, *parts: bytes) -> bytes:
    if type(domain) is not int or not 0 <= domain <= 0xFFFF:
        raise ValueError("cross_domain_hash_domain_not_u16")
    if any(type(part) is not bytes for part in parts):
        raise TypeError("cross_domain_hash_part_must_be_bytes")
    return sha3_512(
        b"".join(
            (
                CROSS_DOMAIN_MAGIC,
                CROSS_DOMAIN_VERSION.to_bytes(2, "big"),
                domain.to_bytes(2, "big"),
                *parts,
            )
        )
    ).digest()
