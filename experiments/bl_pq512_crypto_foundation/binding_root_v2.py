"""Byte-exact Python mirror of the nonactivating Rust BindingRootV2 substrate.

Every digest is ``LEFT || RIGHT``.  Both SHA3-512 lanes authenticate the same
canonical frame under independent frozen domains.  This module deliberately
does not accept a legacy 64-byte digest as a v2 digest, leaf, or root.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from hashlib import sha3_512
from typing import Final, Sequence


BINDING_V2_BYTES: Final[int] = 128
BINDING_V2_LANE_BYTES: Final[int] = 64
BINDING_V2_MAGIC: Final[bytes] = b"BLBIND02"
BINDING_V2_VERSION: Final[int] = 2
BINDING_V2_LEFT_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE2/BINDING/LEFT/v2\x00"
BINDING_V2_RIGHT_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE2/BINDING/RIGHT/v2\x00"

BINDING_MERKLE_MULTIPROOF_V2_MAGIC: Final[bytes] = b"BLB2MP02"
BINDING_MERKLE_MULTIPROOF_V2_VERSION: Final[int] = 2
BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES: Final[int] = 28
MAX_BINDING_MERKLE_LEAVES_V2: Final[int] = 1 << 32
MAX_BINDING_MERKLE_OPENINGS_V2: Final[int] = 4_096
MAX_BINDING_MERKLE_FRONTIER_V2: Final[int] = 131_072
MAX_BINDING_MERKLE_MULTIPROOF_V2_BYTES: Final[int] = (
    BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES
    + MAX_BINDING_MERKLE_OPENINGS_V2 * 8
    + MAX_BINDING_MERKLE_FRONTIER_V2 * BINDING_V2_BYTES
)

_U32_MAX: Final[int] = (1 << 32) - 1
_U64_MAX: Final[int] = (1 << 64) - 1


class BindingRoleV2(IntEnum):
    PAYLOAD = 0x0001
    MERKLE_LEAF = 0x0101
    MERKLE_NODE = 0x0102
    MERKLE_ROOT = 0x0103


class BindingRootV2Error(ValueError):
    """Fail-closed rejection carrying the corresponding Rust variant name."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise BindingRootV2Error(code)


def _require_bytes(value: object, label: str) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be bytes")
    return value


def _require_u32(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _U32_MAX:
        _fail("ArithmeticOverflow")
    return value


def _require_u64(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _U64_MAX:
        _fail("ArithmeticOverflow")
    return value


def _hash_lane(
    domain: bytes, role: BindingRoleV2, payload_len: int, payload: bytes
) -> bytes:
    digest = sha3_512()
    digest.update(domain)
    digest.update(BINDING_V2_MAGIC)
    digest.update(BINDING_V2_VERSION.to_bytes(2, "big"))
    digest.update(int(role).to_bytes(2, "big"))
    digest.update(payload_len.to_bytes(8, "big"))
    digest.update(payload)
    return digest.digest()


@dataclass(frozen=True, order=True, slots=True)
class BindingDigestV2:
    _encoded: bytes

    def __post_init__(self) -> None:
        if type(self._encoded) is not bytes or len(self._encoded) != BINDING_V2_BYTES:
            _fail("DigestLength")

    @classmethod
    def hash(cls, role: BindingRoleV2, payload: bytes) -> "BindingDigestV2":
        if not isinstance(role, BindingRoleV2):
            raise TypeError("role must be BindingRoleV2")
        payload = _require_bytes(payload, "payload")
        payload_len = len(payload)
        if payload_len > _U64_MAX:
            _fail("ArithmeticOverflow")
        return cls(
            _hash_lane(BINDING_V2_LEFT_DOMAIN, role, payload_len, payload)
            + _hash_lane(BINDING_V2_RIGHT_DOMAIN, role, payload_len, payload)
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "BindingDigestV2":
        if type(encoded) is not bytes or len(encoded) != BINDING_V2_BYTES:
            _fail("DigestLength")
        return cls(encoded)

    @property
    def as_bytes(self) -> bytes:
        return self._encoded

    def to_bytes(self) -> bytes:
        return self._encoded

    def __bytes__(self) -> bytes:
        return self._encoded


@dataclass(frozen=True, slots=True)
class BindingMerkleLeafV2:
    _digest: BindingDigestV2

    def __post_init__(self) -> None:
        if not isinstance(self._digest, BindingDigestV2):
            raise TypeError("digest must be BindingDigestV2")

    @classmethod
    def hash(cls, index: int, payload: bytes) -> "BindingMerkleLeafV2":
        index = _require_u64(index)
        payload = _require_bytes(payload, "payload")
        return cls(
            BindingDigestV2.hash(
                BindingRoleV2.MERKLE_LEAF,
                index.to_bytes(8, "big") + payload,
            )
        )

    @classmethod
    def decode(cls, encoded: bytes) -> "BindingMerkleLeafV2":
        return cls(BindingDigestV2.decode(encoded))

    @property
    def digest(self) -> BindingDigestV2:
        return self._digest

    @property
    def as_bytes(self) -> bytes:
        return self._digest.as_bytes


@dataclass(frozen=True, slots=True)
class BindingMerkleNodeV2:
    _digest: BindingDigestV2

    def __post_init__(self) -> None:
        if not isinstance(self._digest, BindingDigestV2):
            raise TypeError("digest must be BindingDigestV2")

    @classmethod
    def hash(
        cls,
        level: int,
        index: int,
        left: BindingDigestV2,
        right: BindingDigestV2,
    ) -> "BindingMerkleNodeV2":
        level = _require_u32(level)
        if level == 0:
            _fail("InvalidNodeLevel")
        index = _require_u64(index)
        if not isinstance(left, BindingDigestV2) or not isinstance(
            right, BindingDigestV2
        ):
            raise TypeError("children must be BindingDigestV2")
        frame = (
            level.to_bytes(4, "big")
            + index.to_bytes(8, "big")
            + left.as_bytes
            + right.as_bytes
        )
        return cls(BindingDigestV2.hash(BindingRoleV2.MERKLE_NODE, frame))

    @property
    def digest(self) -> BindingDigestV2:
        return self._digest

    @property
    def as_bytes(self) -> bytes:
        return self._digest.as_bytes


def _validate_leaf_count(leaf_count: int) -> None:
    leaf_count = _require_u64(leaf_count)
    if leaf_count == 0:
        _fail("EmptyTree")
    if leaf_count & (leaf_count - 1):
        _fail("NonPowerOfTwo")
    if leaf_count > MAX_BINDING_MERKLE_LEAVES_V2:
        _fail("TooManyLeaves")


def _tree_height(leaf_count: int) -> int:
    _validate_leaf_count(leaf_count)
    return leaf_count.bit_length() - 1


@dataclass(frozen=True, slots=True)
class BindingRootV2:
    _digest: BindingDigestV2

    def __post_init__(self) -> None:
        if not isinstance(self._digest, BindingDigestV2):
            raise TypeError("digest must be BindingDigestV2")

    @classmethod
    def _from_top(
        cls, leaf_count: int, top: BindingDigestV2
    ) -> "BindingRootV2":
        height = _tree_height(leaf_count)
        if not isinstance(top, BindingDigestV2):
            raise TypeError("top must be BindingDigestV2")
        frame = (
            leaf_count.to_bytes(8, "big")
            + height.to_bytes(4, "big")
            + top.as_bytes
        )
        return cls(BindingDigestV2.hash(BindingRoleV2.MERKLE_ROOT, frame))

    @classmethod
    def decode(cls, encoded: bytes) -> "BindingRootV2":
        return cls(BindingDigestV2.decode(encoded))

    @property
    def digest(self) -> BindingDigestV2:
        return self._digest

    @property
    def as_bytes(self) -> bytes:
        return self._digest.as_bytes

    def to_bytes(self) -> bytes:
        return self._digest.to_bytes()


def _validate_indices(leaf_count: int, indices: Sequence[int]) -> tuple[int, ...]:
    materialized = tuple(indices)
    if not materialized or len(materialized) > MAX_BINDING_MERKLE_OPENINGS_V2:
        _fail("TooManyOpenings")
    previous: int | None = None
    for raw_index in materialized:
        index = _require_u64(raw_index)
        if index >= leaf_count:
            _fail("IndexOutOfRange")
        if previous is not None and previous >= index:
            _fail("IndicesNotStrictlyIncreasing")
        previous = index
    return materialized


@dataclass(frozen=True, order=True, slots=True)
class BindingMerklePositionV2:
    level: int
    index: int

    def __post_init__(self) -> None:
        _require_u32(self.level)
        _require_u64(self.index)


def canonical_binding_frontier_positions_v2(
    leaf_count: int, selected_indices: Sequence[int]
) -> tuple[BindingMerklePositionV2, ...]:
    """Return the unique bottom-up, then left-to-right frontier."""

    height = _tree_height(leaf_count)
    active = list(_validate_indices(leaf_count, selected_indices))
    frontier: list[BindingMerklePositionV2] = []
    for level in range(height):
        active_set = set(active)
        level_frontier = sorted(
            (index ^ 1 for index in active if (index ^ 1) not in active_set)
        )
        frontier.extend(
            BindingMerklePositionV2(level=level, index=index)
            for index in level_frontier
        )
        if len(frontier) > MAX_BINDING_MERKLE_FRONTIER_V2:
            _fail("TooManyFrontierDigests")
        parents: list[int] = []
        for index in active:
            parent = index >> 1
            if not parents or parents[-1] != parent:
                parents.append(parent)
        active = parents
    if active != [0]:
        _fail("NonPowerOfTwo")
    return tuple(frontier)


def _encoded_proof_len(selected_count: int, frontier_count: int) -> int:
    if type(selected_count) is not int or type(frontier_count) is not int:
        _fail("ArithmeticOverflow")
    if selected_count < 0 or frontier_count < 0:
        _fail("ArithmeticOverflow")
    length = (
        BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES
        + selected_count * 8
        + frontier_count * BINDING_V2_BYTES
    )
    if length > _U64_MAX:
        _fail("ArithmeticOverflow")
    return length


@dataclass(frozen=True, slots=True)
class BindingMerkleMultiProofV2:
    leaf_count: int
    selected_indices: tuple[int, ...]
    frontier_digests: tuple[BindingDigestV2, ...]

    def __post_init__(self) -> None:
        if type(self.selected_indices) is not tuple or type(self.frontier_digests) is not tuple:
            raise TypeError("proof vectors must be tuples")
        positions = canonical_binding_frontier_positions_v2(
            self.leaf_count, self.selected_indices
        )
        if len(self.frontier_digests) != len(positions):
            _fail("FrontierLength")
        if any(
            not isinstance(digest, BindingDigestV2)
            for digest in self.frontier_digests
        ):
            raise TypeError("frontier entries must be BindingDigestV2")

    @classmethod
    def _from_parts(
        cls,
        leaf_count: int,
        selected_indices: Sequence[int],
        frontier_digests: Sequence[BindingDigestV2],
    ) -> "BindingMerkleMultiProofV2":
        return cls(leaf_count, tuple(selected_indices), tuple(frontier_digests))

    def encode(self) -> bytes:
        selected_count = len(self.selected_indices)
        frontier_count = len(self.frontier_digests)
        if selected_count > _U32_MAX or frontier_count > _U32_MAX:
            _fail("ArithmeticOverflow")
        expected_len = _encoded_proof_len(selected_count, frontier_count)
        encoded = bytearray()
        encoded.extend(BINDING_MERKLE_MULTIPROOF_V2_MAGIC)
        encoded.extend(BINDING_MERKLE_MULTIPROOF_V2_VERSION.to_bytes(2, "big"))
        encoded.extend((0).to_bytes(2, "big"))
        encoded.extend(self.leaf_count.to_bytes(8, "big"))
        encoded.extend(selected_count.to_bytes(4, "big"))
        encoded.extend(frontier_count.to_bytes(4, "big"))
        for index in self.selected_indices:
            encoded.extend(index.to_bytes(8, "big"))
        for digest in self.frontier_digests:
            encoded.extend(digest.as_bytes)
        if len(encoded) != expected_len:
            _fail("ProofLength")
        return bytes(encoded)

    @classmethod
    def decode(cls, encoded: bytes) -> "BindingMerkleMultiProofV2":
        if (
            type(encoded) is not bytes
            or len(encoded) < BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES
            or len(encoded) > MAX_BINDING_MERKLE_MULTIPROOF_V2_BYTES
        ):
            _fail("ProofLength")
        if encoded[:8] != BINDING_MERKLE_MULTIPROOF_V2_MAGIC:
            _fail("ProofMagic")
        if int.from_bytes(encoded[8:10], "big") != BINDING_MERKLE_MULTIPROOF_V2_VERSION:
            _fail("ProofVersion")
        if encoded[10:12] != bytes(2):
            _fail("ProofFlags")
        leaf_count = int.from_bytes(encoded[12:20], "big")
        _validate_leaf_count(leaf_count)
        selected_count = int.from_bytes(encoded[20:24], "big")
        frontier_count = int.from_bytes(encoded[24:28], "big")
        if selected_count == 0 or selected_count > MAX_BINDING_MERKLE_OPENINGS_V2:
            _fail("TooManyOpenings")
        if frontier_count > MAX_BINDING_MERKLE_FRONTIER_V2:
            _fail("TooManyFrontierDigests")
        expected_len = _encoded_proof_len(selected_count, frontier_count)
        if len(encoded) != expected_len:
            _fail("ProofLength")

        offset = BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES
        selected_indices = tuple(
            int.from_bytes(encoded[offset + index * 8 : offset + (index + 1) * 8], "big")
            for index in range(selected_count)
        )
        offset += selected_count * 8
        expected_frontier = canonical_binding_frontier_positions_v2(
            leaf_count, selected_indices
        )
        if frontier_count != len(expected_frontier):
            _fail("FrontierLength")
        frontier_digests = tuple(
            BindingDigestV2.decode(
                encoded[
                    offset + index * BINDING_V2_BYTES : offset
                    + (index + 1) * BINDING_V2_BYTES
                ]
            )
            for index in range(frontier_count)
        )
        offset += frontier_count * BINDING_V2_BYTES
        if offset != len(encoded):
            _fail("ProofLength")
        return cls._from_parts(leaf_count, selected_indices, frontier_digests)

    def verify_payloads(
        self, payloads: Sequence[bytes], expected_root: BindingRootV2
    ) -> None:
        if len(payloads) != len(self.selected_indices):
            _fail("PayloadCount")
        leaves = tuple(
            BindingMerkleLeafV2.hash(index, _require_bytes(payload, "payload"))
            for index, payload in zip(self.selected_indices, payloads, strict=True)
        )
        self.verify_leaf_hashes(leaves, expected_root)

    def verify_leaf_hashes(
        self,
        leaf_hashes: Sequence[BindingMerkleLeafV2],
        expected_root: BindingRootV2,
    ) -> None:
        if len(leaf_hashes) != len(self.selected_indices):
            _fail("PayloadCount")
        if not isinstance(expected_root, BindingRootV2):
            raise TypeError("expected_root must be BindingRootV2")
        frontier_positions = canonical_binding_frontier_positions_v2(
            self.leaf_count, self.selected_indices
        )
        if len(frontier_positions) != len(self.frontier_digests):
            _fail("FrontierLength")
        active: dict[int, BindingDigestV2] = {}
        for index, leaf in zip(self.selected_indices, leaf_hashes, strict=True):
            if not isinstance(leaf, BindingMerkleLeafV2):
                raise TypeError("leaf hashes must be BindingMerkleLeafV2")
            if index in active:
                _fail("IndicesNotStrictlyIncreasing")
            active[index] = leaf.digest

        frontier_offset = 0
        for level in range(_tree_height(self.leaf_count)):
            while (
                frontier_offset < len(frontier_positions)
                and frontier_positions[frontier_offset].level == level
            ):
                position = frontier_positions[frontier_offset]
                if position.index in active:
                    _fail("FrontierLength")
                active[position.index] = self.frontier_digests[frontier_offset]
                frontier_offset += 1
            entries = sorted(active.items())
            if not entries or len(entries) % 2:
                _fail("FrontierLength")
            parents: dict[int, BindingDigestV2] = {}
            for offset in range(0, len(entries), 2):
                left_index, left = entries[offset]
                right_index, right = entries[offset + 1]
                if left_index & 1 or right_index != left_index + 1:
                    _fail("FrontierLength")
                parent_index = left_index >> 1
                if parent_index in parents:
                    _fail("FrontierLength")
                parents[parent_index] = BindingMerkleNodeV2.hash(
                    level + 1, parent_index, left, right
                ).digest
            active = parents
        if frontier_offset != len(frontier_positions) or len(active) != 1 or 0 not in active:
            _fail("FrontierLength")
        actual_root = BindingRootV2._from_top(self.leaf_count, active[0])
        if actual_root != expected_root:
            _fail("RootMismatch")


@dataclass(frozen=True, slots=True)
class BindingMerkleTreeV2:
    _levels: tuple[tuple[BindingDigestV2, ...], ...]
    _root: BindingRootV2

    @classmethod
    def from_payloads(cls, payloads: Sequence[bytes]) -> "BindingMerkleTreeV2":
        materialized = tuple(payloads)
        leaf_count = len(materialized)
        _validate_leaf_count(leaf_count)
        current = tuple(
            BindingMerkleLeafV2.hash(index, _require_bytes(payload, "payload")).digest
            for index, payload in enumerate(materialized)
        )
        levels: list[tuple[BindingDigestV2, ...]] = [current]
        level = 1
        while len(current) > 1:
            parents = tuple(
                BindingMerkleNodeV2.hash(
                    level,
                    parent_index,
                    current[parent_index * 2],
                    current[parent_index * 2 + 1],
                ).digest
                for parent_index in range(len(current) // 2)
            )
            levels.append(parents)
            current = parents
            level += 1
        return cls(tuple(levels), BindingRootV2._from_top(leaf_count, current[0]))

    @property
    def root(self) -> BindingRootV2:
        return self._root

    @property
    def leaf_count(self) -> int:
        return len(self._levels[0])

    def prove(self, selected_indices: Sequence[int]) -> BindingMerkleMultiProofV2:
        positions = canonical_binding_frontier_positions_v2(
            self.leaf_count, selected_indices
        )
        frontier_digests: list[BindingDigestV2] = []
        for position in positions:
            try:
                frontier_digests.append(self._levels[position.level][position.index])
            except IndexError:
                _fail("FrontierLength")
        return BindingMerkleMultiProofV2._from_parts(
            self.leaf_count, selected_indices, frontier_digests
        )


__all__ = (
    "BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES",
    "BINDING_MERKLE_MULTIPROOF_V2_MAGIC",
    "BINDING_MERKLE_MULTIPROOF_V2_VERSION",
    "BINDING_V2_BYTES",
    "BINDING_V2_LANE_BYTES",
    "BINDING_V2_LEFT_DOMAIN",
    "BINDING_V2_MAGIC",
    "BINDING_V2_RIGHT_DOMAIN",
    "BINDING_V2_VERSION",
    "MAX_BINDING_MERKLE_FRONTIER_V2",
    "MAX_BINDING_MERKLE_LEAVES_V2",
    "MAX_BINDING_MERKLE_MULTIPROOF_V2_BYTES",
    "MAX_BINDING_MERKLE_OPENINGS_V2",
    "BindingDigestV2",
    "BindingMerkleLeafV2",
    "BindingMerkleMultiProofV2",
    "BindingMerkleNodeV2",
    "BindingMerklePositionV2",
    "BindingMerkleTreeV2",
    "BindingRoleV2",
    "BindingRootV2",
    "BindingRootV2Error",
    "canonical_binding_frontier_positions_v2",
)
