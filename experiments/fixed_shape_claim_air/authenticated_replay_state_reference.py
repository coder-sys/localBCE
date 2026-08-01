"""Deterministic header for the depth-64 full-key replay ordered map.

The indexed tree authenticates complete 512-bit keys, predecessor/successor
links, and two-leaf insertions.  Its historical root omitted the sequential
allocator cursor.  This wrapper makes ``nextAppendIndex`` authoritative and
requires every insertion to consume exactly that index.  It remains a
synthetic reference, not a production verifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha3_512
import hmac
from typing import Final, Iterable

from app.batch.pq_strong_nullifier_reference import (
    StrongIndexedNullifierTree,
    StrongNonMembershipWitness,
    verify_strong_nonmembership_witness,
)
from app.batch.pq_tree_reference import require_synthetic_reference_enabled


REPLAY_STATE_STATUS: Final[str] = (
    "SYNTHETIC_DEPTH64_ORDERED_REPLAY_STATE_V1_NOT_PRODUCTION"
)
_HEADER_DOMAIN: Final[bytes] = b"BL/PQ512/WAVE1A/REPLAY-STATE-HEADER/v1"
_U64_LIMIT: Final[int] = 1 << 64


def replay_state_root(next_append_index: int, inner_root: bytes) -> bytes:
    if type(next_append_index) is not int or not 2 <= next_append_index < _U64_LIMIT:
        raise ValueError("replay_state_next_append_index_invalid")
    if type(inner_root) is not bytes or len(inner_root) != 64 or not any(inner_root):
        raise ValueError("replay_state_inner_root_invalid")
    return sha3_512(
        _HEADER_DOMAIN + next_append_index.to_bytes(8, "big") + inner_root
    ).digest()


@dataclass(frozen=True, slots=True)
class AuthenticatedReplayTransition:
    status: str
    next_append_index_before: int
    next_append_index_after: int
    root_before: bytes
    root_after: bytes
    inner: StrongNonMembershipWitness

    def __post_init__(self) -> None:
        require_synthetic_reference_enabled()
        if self.status != REPLAY_STATE_STATUS:
            raise ValueError("replay_state_status_invalid")
        if not isinstance(self.inner, StrongNonMembershipWitness):
            raise TypeError("replay_state_inner_witness_required")
        if (
            type(self.next_append_index_before) is not int
            or self.next_append_index_before < 2
            or self.next_append_index_before >= _U64_LIMIT - 1
            or self.next_append_index_after != self.next_append_index_before + 1
        ):
            raise ValueError("replay_state_cursor_transition_invalid")
        if self.inner.inserted_index != self.next_append_index_before:
            raise ValueError("replay_state_insertion_not_at_cursor")
        expected_before = replay_state_root(
            self.next_append_index_before, self.inner.root_before
        )
        expected_after = replay_state_root(
            self.next_append_index_after, self.inner.root_after
        )
        if not hmac.compare_digest(self.root_before, expected_before):
            raise ValueError("replay_state_root_before_invalid")
        if not hmac.compare_digest(self.root_after, expected_after):
            raise ValueError("replay_state_root_after_invalid")

    @property
    def nullifier(self) -> bytes:
        return self.inner.nullifier

    @property
    def predecessor_path(self) -> tuple[bytes, ...]:
        return self.inner.predecessor_path

    @property
    def insertion_path(self) -> tuple[bytes, ...]:
        return self.inner.insertion_path


def build_authenticated_replay_transitions(
    existing_values: Iterable[bytes],
    inserted_values: Iterable[bytes],
) -> tuple[AuthenticatedReplayTransition, ...]:
    require_synthetic_reference_enabled()
    existing = tuple(existing_values)
    inserted = tuple(inserted_values)
    tree = StrongIndexedNullifierTree(existing)
    cursor = len(existing) + 2
    if cursor >= _U64_LIMIT:
        raise ValueError("replay_state_capacity_exhausted")
    transitions: list[AuthenticatedReplayTransition] = []
    for value in inserted:
        inner = tree.prove_nonmembership(value)
        transition = AuthenticatedReplayTransition(
            REPLAY_STATE_STATUS,
            cursor,
            cursor + 1,
            replay_state_root(cursor, inner.root_before),
            replay_state_root(cursor + 1, inner.root_after),
            inner,
        )
        require_authenticated_replay_transition(transition)
        transitions.append(transition)
        tree.insert(value)
        cursor += 1
    return tuple(transitions)


def require_authenticated_replay_transition(
    transition: AuthenticatedReplayTransition,
) -> None:
    if not isinstance(transition, AuthenticatedReplayTransition):
        raise TypeError("authenticated_replay_transition_required")
    transition.__post_init__()
    if not verify_strong_nonmembership_witness(transition.inner):
        raise ValueError("replay_state_inner_witness_rejected")


__all__ = [
    "AuthenticatedReplayTransition",
    "REPLAY_STATE_STATUS",
    "build_authenticated_replay_transitions",
    "replay_state_root",
    "require_authenticated_replay_transition",
]
