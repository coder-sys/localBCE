"""Two-party trust-boundary session grammar and fail-closed state machine.

The session is intentionally not a proof protocol.  It demonstrates only the
message ordering, transcript binding, verifier-owned challenge generation,
fixture authentication, replay markers, and canonical parsing needed before a
backend can be considered.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
from typing import Callable, Iterable

from .profile import (
    FIXED_CHALLENGE_BYTES,
    FIXED_SALT_BYTES,
    FIXED_SESSION_ID_BYTES,
    MAX_RETRIES,
    ProfileBindings,
    ProfileError,
    STATEMENT_DOMAIN,
    build_profile_bindings,
    build_security_ledger,
    nonzero64,
    read_exact,
    u16,
    u32,
    u64,
)
from experiments.native_v3_phase0.native_v3_fixture import build_fixture


FRAME_MAGIC = b"BLTBFRM1"
FRAME_VERSION = 1
FRAME_HEADER_BYTES = 8 + 2 + 1 + 1 + 2 + FIXED_SESSION_ID_BYTES + 64 + 4
STATEMENT_MAGIC = b"BLTBST01"
STATEMENT_VERSION = 1
COMMITMENT_KIND = 1
CHALLENGE_KIND = 2
RESPONSE_KIND = 3
PROVER_ROLE = 1
VERIFIER_ROLE = 2
COMMITMENT_ROUND = 0
CHALLENGE_ROUND = 1
RESPONSE_ROUND = 2
TRANSCRIPT_MAGIC = b"BLTBTX01"
TRANSCRIPT_VERSION = 1
OPENING_MAGIC = b"BLTBOP01"
OPENING_VERSION = 1
PROVER_STATE_MAGIC = b"BLTBPS01"
PROVER_STATE_VERSION = 1

FRAME_DOMAINS = {
    COMMITMENT_KIND: b"BL/NATIVE-V3/TBP/COMMITMENT/v1\0",
    CHALLENGE_KIND: b"BL/NATIVE-V3/TBP/CHALLENGE/v1\0",
    RESPONSE_KIND: b"BL/NATIVE-V3/TBP/RESPONSE/v1\0",
}
COMMITMENT_DOMAIN = b"BL/NATIVE-V3/TBP/COMMITMENT-DIGEST/v1\0"
CHALLENGE_DOMAIN = b"BL/NATIVE-V3/TBP/CHALLENGE-DIGEST/v1\0"
CHALLENGE_AUTH_DOMAIN = b"BL/NATIVE-V3/TBP/CHALLENGE-AUTH/v1\0"
VECTOR_LEAF_DOMAIN = b"BL/NATIVE-V3/TBP/VECTOR-LEAF/v1\0"
VECTOR_NODE_DOMAIN = b"BL/NATIVE-V3/TBP/VECTOR-NODE/v1\0"
HANDLE_DOMAIN = b"BL/NATIVE-V3/TBP/COMMITMENT-HANDLE/v1\0"
TRANSCRIPT_DOMAIN = b"BL/NATIVE-V3/TBP/TRANSCRIPT/v1\0"
RESPONSE_DOMAIN = b"BL/NATIVE-V3/TBP/RESPONSE-DIGEST/v1\0"


RandomBytes = Callable[[int], bytes]


def _sha(domain: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha3_512()
    h.update(domain)
    for part in parts:
        h.update(part)
    return h.digest()


def _hmac_sha3(key: bytes, message: bytes) -> bytes:
    if len(key) != 32:
        raise ProfileError("challenge-auth:key-width")
    block_size = 72  # SHA3-512 sponge rate; this is a fixture MAC, not a PQ signature.
    key_block = key + b"\0" * (block_size - len(key))
    inner = hashlib.sha3_512(bytes(x ^ 0x36 for x in key_block) + message).digest()
    return hashlib.sha3_512(bytes(x ^ 0x5C for x in key_block) + inner).digest()


def _random(source: RandomBytes | None, length: int) -> bytes:
    value = secrets.token_bytes(length) if source is None else source(length)
    if len(value) != length:
        raise ProfileError("randomness:wrong-length")
    return value


def _tag(kind: int, role: int, round_number: int) -> bytes:
    try:
        domain = FRAME_DOMAINS[kind]
    except KeyError as exc:
        raise ProfileError("frame:unknown-kind") from exc
    return _sha(b"BL/NATIVE-V3/TBP/FRAME-TAG/v1\0", domain, bytes((kind, role)), u16(round_number))


def _frame(kind: int, role: int, round_number: int, session_id: bytes, payload: bytes) -> bytes:
    if len(session_id) != FIXED_SESSION_ID_BYTES or not any(session_id):
        raise ProfileError("frame:session-id")
    return b"".join(
        (
            FRAME_MAGIC,
            u16(FRAME_VERSION),
            bytes((kind, role)),
            u16(round_number),
            session_id,
            _tag(kind, role, round_number),
            u32(len(payload)),
            payload,
        )
    )


def _parse_frame(data: bytes, expected_kind: int, expected_role: int, expected_round: int) -> tuple[bytes, bytes]:
    if len(data) < FRAME_HEADER_BYTES:
        raise ProfileError("frame:truncated")
    offset = 0
    magic, offset = read_exact(data, offset, 8, "frame:magic")
    if magic != FRAME_MAGIC:
        raise ProfileError("frame:magic")
    version, offset = read_exact(data, offset, 2, "frame:version")
    if version != u16(FRAME_VERSION):
        raise ProfileError("frame:version")
    kind, offset = read_exact(data, offset, 1, "frame:kind")
    role, offset = read_exact(data, offset, 1, "frame:role")
    round_bytes, offset = read_exact(data, offset, 2, "frame:round")
    round_number = int.from_bytes(round_bytes, "big")
    if (kind[0], role[0], round_number) != (expected_kind, expected_role, expected_round):
        raise ProfileError("frame:role-kind-round")
    session_id, offset = read_exact(data, offset, FIXED_SESSION_ID_BYTES, "frame:session")
    if not any(session_id):
        raise ProfileError("frame:zero-session")
    tag, offset = read_exact(data, offset, 64, "frame:tag")
    if not hmac.compare_digest(tag, _tag(kind[0], role[0], round_number)):
        raise ProfileError("frame:domain-tag")
    payload_length_bytes, offset = read_exact(data, offset, 4, "frame:length")
    payload_length = int.from_bytes(payload_length_bytes, "big")
    payload, offset = read_exact(data, offset, payload_length, "frame:payload")
    if offset != len(data):
        raise ProfileError("frame:trailing")
    return session_id, payload


@dataclass(frozen=True)
class ProfileStatement:
    session_id: bytes
    bindings: ProfileBindings

    def __post_init__(self) -> None:
        if len(self.session_id) != FIXED_SESSION_ID_BYTES or not any(self.session_id):
            raise ProfileError("statement:session-id")

    def canonical_bytes(self) -> bytes:
        b = self.bindings
        return b"".join(
            (
                STATEMENT_MAGIC,
                u16(STATEMENT_VERSION),
                u16(0),
                b"\0",  # proof-suite marker: null until a future theorem-backed suite exists.
                b"\0" * 3,
                b"\0" * 64,
                self.session_id,
                b.profile_id,
                b.attempt_id,
                b.phase0_statement_digest,
                b.source_root,
                b.control_set_id,
                b.decision_access_join_id,
                b.frozen_receipt_binding,
                b.completeness_id,
                b.chronology_id,
                b.replay_id,
                b.exception_id_or_sentinel,
                b.state_before_id,
                b.state_after_id,
                u64(b.statement_sequence_before),
                u64(b.statement_sequence_after),
                u64(b.event_time),
                u64(b.observation_time),
                u64(b.rule_effective_time),
                u64(b.decision_time),
            )
        )

    @classmethod
    def parse(cls, data: bytes, bindings: ProfileBindings | None = None) -> "ProfileStatement":
        if bindings is None:
            bindings = build_profile_bindings()
        expected_length = len(cls(b"\1" * FIXED_SESSION_ID_BYTES, bindings).canonical_bytes())
        if len(data) != expected_length:
            raise ProfileError("statement:length")
        offset = 0
        magic, offset = read_exact(data, offset, 8, "statement:magic")
        if magic != STATEMENT_MAGIC:
            raise ProfileError("statement:magic")
        version, offset = read_exact(data, offset, 2, "statement:version")
        if version != u16(STATEMENT_VERSION):
            raise ProfileError("statement:version")
        flags, offset = read_exact(data, offset, 2, "statement:flags")
        if flags != b"\0\0":
            raise ProfileError("statement:flags")
        suite_marker, offset = read_exact(data, offset, 1, "statement:suite-marker")
        reserved, offset = read_exact(data, offset, 3, "statement:reserved")
        suite_id, offset = read_exact(data, offset, 64, "statement:suite")
        if suite_marker != b"\0" or reserved != b"\0" * 3 or suite_id != b"\0" * 64:
            raise ProfileError("statement:proof-suite-not-null")
        session_id, offset = read_exact(data, offset, FIXED_SESSION_ID_BYTES, "statement:session")
        values: list[bytes] = []
        for index in range(13):
            value, offset = read_exact(data, offset, 64, f"statement:binding-{index}")
            values.append(nonzero64(value, f"statement:binding-{index}"))
        integer_values: list[int] = []
        for index in range(6):
            value, offset = read_exact(data, offset, 8, f"statement:time-{index}")
            integer_values.append(int.from_bytes(value, "big"))
        if offset != len(data):
            raise ProfileError("statement:trailing")
        expected_values = [
            bindings.profile_id,
            bindings.attempt_id,
            bindings.phase0_statement_digest,
            bindings.source_root,
            bindings.control_set_id,
            bindings.decision_access_join_id,
            bindings.frozen_receipt_binding,
            bindings.completeness_id,
            bindings.chronology_id,
            bindings.replay_id,
            bindings.exception_id_or_sentinel,
            bindings.state_before_id,
            bindings.state_after_id,
        ]
        if values != expected_values:
            raise ProfileError("statement:verifier-owned-binding-mismatch")
        if integer_values != [
            bindings.statement_sequence_before,
            bindings.statement_sequence_after,
            bindings.event_time,
            bindings.observation_time,
            bindings.rule_effective_time,
            bindings.decision_time,
        ]:
            raise ProfileError("statement:time-or-sequence-mismatch")
        statement = cls(session_id, bindings)
        if statement.canonical_bytes() != data:
            raise ProfileError("statement:noncanonical")
        return statement


@dataclass(frozen=True)
class VectorLeaf:
    index: int
    value: bytes
    salt: bytes

    def canonical_bytes(self) -> bytes:
        if self.index not in (0, 1):
            raise ProfileError("leaf:index")
        if len(self.salt) != FIXED_SALT_BYTES:
            raise ProfileError("leaf:salt")
        if len(self.value) > 0xFFFFFFFF:
            raise ProfileError("leaf:value-length")
        return b"".join(
            (
                b"BLTBLF01",
                u16(1),
                u16(0),
                _sha(b"BL/NATIVE-V3/TBP/LEAF-TAG/v1\0", VECTOR_LEAF_DOMAIN),
                u32(self.index),
                u32(len(self.value)),
                self.value,
                u16(len(self.salt)),
                self.salt,
            )
        )

    @classmethod
    def parse(cls, data: bytes) -> "VectorLeaf":
        offset = 0
        magic, offset = read_exact(data, offset, 8, "leaf:magic")
        if magic != b"BLTBLF01":
            raise ProfileError("leaf:magic")
        version, offset = read_exact(data, offset, 2, "leaf:version")
        reserved, offset = read_exact(data, offset, 2, "leaf:reserved")
        if version != u16(1) or reserved != b"\0\0":
            raise ProfileError("leaf:header")
        tag, offset = read_exact(data, offset, 64, "leaf:tag")
        if tag != _sha(b"BL/NATIVE-V3/TBP/LEAF-TAG/v1\0", VECTOR_LEAF_DOMAIN):
            raise ProfileError("leaf:domain")
        index_bytes, offset = read_exact(data, offset, 4, "leaf:index")
        value_length_bytes, offset = read_exact(data, offset, 4, "leaf:value-length")
        value, offset = read_exact(data, offset, int.from_bytes(value_length_bytes, "big"), "leaf:value")
        salt_length_bytes, offset = read_exact(data, offset, 2, "leaf:salt-length")
        salt, offset = read_exact(data, offset, int.from_bytes(salt_length_bytes, "big"), "leaf:salt")
        leaf = cls(int.from_bytes(index_bytes, "big"), value, salt)
        if offset != len(data) or leaf.canonical_bytes() != data:
            raise ProfileError("leaf:noncanonical")
        return leaf


def leaf_hash(leaf: VectorLeaf) -> bytes:
    return _sha(VECTOR_LEAF_DOMAIN, leaf.canonical_bytes())


def node_bytes(height: int, left_index: int, left_hash: bytes, right_hash: bytes) -> bytes:
    if height != 0 or left_index != 0 or len(left_hash) != 64 or len(right_hash) != 64:
        raise ProfileError("node:geometry")
    return b"".join(
        (
            b"BLTBND01",
            u16(1),
            u16(0),
            _sha(b"BL/NATIVE-V3/TBP/NODE-TAG/v1\0", VECTOR_NODE_DOMAIN),
            u16(height),
            u32(left_index),
            left_hash,
            right_hash,
        )
    )


def node_hash(height: int, left_index: int, left_hash: bytes, right_hash: bytes) -> bytes:
    return _sha(VECTOR_NODE_DOMAIN, node_bytes(height, left_index, left_hash, right_hash))


def vector_root(leaves: Iterable[VectorLeaf]) -> bytes:
    ordered = tuple(leaves)
    if len(ordered) != 2 or [leaf.index for leaf in ordered] != [0, 1]:
        raise ProfileError("vector:order-or-count")
    return node_hash(0, 0, leaf_hash(ordered[0]), leaf_hash(ordered[1]))


@dataclass(frozen=True)
class CommitmentMessage:
    session_id: bytes
    statement_digest: bytes
    vector_root: bytes
    handle: bytes
    leaf_count: int = 2
    salt_bytes: int = FIXED_SALT_BYTES

    def payload(self) -> bytes:
        nonzero64(self.statement_digest, "commitment:statement")
        nonzero64(self.vector_root, "commitment:root")
        nonzero64(self.handle, "commitment:handle")
        if self.leaf_count != 2 or self.salt_bytes != FIXED_SALT_BYTES:
            raise ProfileError("commitment:profile-geometry")
        return b"".join((self.statement_digest, self.vector_root, self.handle, u32(self.leaf_count), u16(self.salt_bytes), u16(0)))

    def canonical_bytes(self) -> bytes:
        return _frame(COMMITMENT_KIND, PROVER_ROLE, COMMITMENT_ROUND, self.session_id, self.payload())

    @property
    def digest(self) -> bytes:
        return _sha(COMMITMENT_DOMAIN, self.canonical_bytes())

    @classmethod
    def parse(cls, data: bytes) -> "CommitmentMessage":
        session_id, payload = _parse_frame(data, COMMITMENT_KIND, PROVER_ROLE, COMMITMENT_ROUND)
        if len(payload) != 64 * 3 + 8:
            raise ProfileError("commitment:payload-length")
        statement_digest, vector_root_value, handle = payload[:64], payload[64:128], payload[128:192]
        leaf_count = int.from_bytes(payload[192:196], "big")
        salt_bytes = int.from_bytes(payload[196:198], "big")
        if payload[198:200] != b"\0\0":
            raise ProfileError("commitment:reserved")
        result = cls(session_id, statement_digest, vector_root_value, handle, leaf_count, salt_bytes)
        if result.canonical_bytes() != data:
            raise ProfileError("commitment:noncanonical")
        return result


@dataclass(frozen=True)
class ChallengeMessage:
    session_id: bytes
    commitment_digest: bytes
    challenge_nonce: bytes
    challenge_scalar: bytes
    selected_index: int
    auth_tag: bytes

    def body(self) -> bytes:
        if len(self.challenge_nonce) != FIXED_CHALLENGE_BYTES or len(self.challenge_scalar) != FIXED_CHALLENGE_BYTES:
            raise ProfileError("challenge:randomness-width")
        if self.selected_index != int.from_bytes(self.challenge_scalar[:4], "big") % 2:
            raise ProfileError("challenge:index-not-derived")
        return b"".join((nonzero64(self.commitment_digest, "challenge:commitment"), self.challenge_nonce, self.challenge_scalar, u32(self.selected_index)))

    def payload(self) -> bytes:
        if len(self.auth_tag) != 64:
            raise ProfileError("challenge:auth-width")
        return self.body() + self.auth_tag

    def canonical_bytes(self) -> bytes:
        return _frame(CHALLENGE_KIND, VERIFIER_ROLE, CHALLENGE_ROUND, self.session_id, self.payload())

    @property
    def digest(self) -> bytes:
        return _sha(CHALLENGE_DOMAIN, self.canonical_bytes())

    @classmethod
    def issue(cls, commitment: CommitmentMessage, auth_key: bytes, source: RandomBytes | None = None) -> "ChallengeMessage":
        nonce = _random(source, FIXED_CHALLENGE_BYTES)
        scalar = _random(source, FIXED_CHALLENGE_BYTES)
        provisional = cls(commitment.session_id, commitment.digest, nonce, scalar, int.from_bytes(scalar[:4], "big") % 2, b"\0" * 64)
        tag = _hmac_sha3(auth_key, CHALLENGE_AUTH_DOMAIN + provisional.session_id + provisional.body())
        return cls(commitment.session_id, commitment.digest, nonce, scalar, provisional.selected_index, tag)

    @classmethod
    def parse(cls, data: bytes, auth_key: bytes | None = None) -> "ChallengeMessage":
        session_id, payload = _parse_frame(data, CHALLENGE_KIND, VERIFIER_ROLE, CHALLENGE_ROUND)
        if len(payload) != 64 + 32 + 32 + 4 + 64:
            raise ProfileError("challenge:payload-length")
        challenge = cls(
            session_id,
            payload[:64],
            payload[64:96],
            payload[96:128],
            int.from_bytes(payload[128:132], "big"),
            payload[132:196],
        )
        if auth_key is not None:
            expected = _hmac_sha3(auth_key, CHALLENGE_AUTH_DOMAIN + session_id + challenge.body())
            if not hmac.compare_digest(expected, challenge.auth_tag):
                raise ProfileError("challenge:authentication")
        if challenge.canonical_bytes() != data:
            raise ProfileError("challenge:noncanonical")
        return challenge


@dataclass(frozen=True)
class Opening:
    index: int
    value: bytes
    salt: bytes
    sibling_is_left: bool
    sibling_hash: bytes

    def canonical_bytes(self) -> bytes:
        if self.index not in (0, 1) or len(self.salt) != FIXED_SALT_BYTES or len(self.sibling_hash) != 64:
            raise ProfileError("opening:fields")
        return b"".join(
            (
                OPENING_MAGIC,
                u16(OPENING_VERSION),
                u16(0),
                u32(self.index),
                u32(len(self.value)),
                self.value,
                u16(len(self.salt)),
                self.salt,
                u16(1),
                bytes((1 if self.sibling_is_left else 0,)),
                b"\0",
                self.sibling_hash,
            )
        )

    @classmethod
    def parse(cls, data: bytes) -> "Opening":
        offset = 0
        magic, offset = read_exact(data, offset, 8, "opening:magic")
        version, offset = read_exact(data, offset, 2, "opening:version")
        reserved, offset = read_exact(data, offset, 2, "opening:reserved")
        if magic != OPENING_MAGIC or version != u16(OPENING_VERSION) or reserved != b"\0\0":
            raise ProfileError("opening:header")
        index_bytes, offset = read_exact(data, offset, 4, "opening:index")
        value_length_bytes, offset = read_exact(data, offset, 4, "opening:value-length")
        value, offset = read_exact(data, offset, int.from_bytes(value_length_bytes, "big"), "opening:value")
        salt_length_bytes, offset = read_exact(data, offset, 2, "opening:salt-length")
        salt, offset = read_exact(data, offset, int.from_bytes(salt_length_bytes, "big"), "opening:salt")
        path_count_bytes, offset = read_exact(data, offset, 2, "opening:path-count")
        direction, offset = read_exact(data, offset, 1, "opening:direction")
        reserved_path, offset = read_exact(data, offset, 1, "opening:path-reserved")
        sibling_hash, offset = read_exact(data, offset, 64, "opening:sibling")
        opening = cls(int.from_bytes(index_bytes, "big"), value, salt, direction[0] == 1, sibling_hash)
        if int.from_bytes(path_count_bytes, "big") != 1 or direction[0] not in (0, 1) or reserved_path != b"\0":
            raise ProfileError("opening:path-grammar")
        if offset != len(data) or opening.canonical_bytes() != data:
            raise ProfileError("opening:noncanonical")
        return opening


def verify_opening(opening: Opening, commitment: CommitmentMessage, challenge: ChallengeMessage) -> None:
    if opening.index != challenge.selected_index:
        raise ProfileError("opening:challenge-index")
    leaf = VectorLeaf(opening.index, opening.value, opening.salt)
    current = leaf_hash(leaf)
    if opening.sibling_is_left:
        current = node_hash(0, 0, opening.sibling_hash, current)
    else:
        current = node_hash(0, 0, current, opening.sibling_hash)
    if not hmac.compare_digest(current, commitment.vector_root):
        raise ProfileError("opening:root")


@dataclass(frozen=True)
class ResponseMessage:
    session_id: bytes
    commitment_digest: bytes
    challenge_digest: bytes
    handle: bytes
    response_nonce: bytes
    opening: Opening

    def payload(self) -> bytes:
        if len(self.response_nonce) != FIXED_CHALLENGE_BYTES:
            raise ProfileError("response:nonce")
        opening_bytes = self.opening.canonical_bytes()
        return b"".join((nonzero64(self.commitment_digest, "response:commitment"), nonzero64(self.challenge_digest, "response:challenge"), nonzero64(self.handle, "response:handle"), self.response_nonce, u32(len(opening_bytes)), opening_bytes))

    def canonical_bytes(self) -> bytes:
        return _frame(RESPONSE_KIND, PROVER_ROLE, RESPONSE_ROUND, self.session_id, self.payload())

    @property
    def digest(self) -> bytes:
        return _sha(RESPONSE_DOMAIN, self.canonical_bytes())

    @classmethod
    def parse(cls, data: bytes) -> "ResponseMessage":
        session_id, payload = _parse_frame(data, RESPONSE_KIND, PROVER_ROLE, RESPONSE_ROUND)
        if len(payload) < 64 * 3 + 32 + 4:
            raise ProfileError("response:payload-length")
        opening_length = int.from_bytes(payload[224:228], "big")
        opening_bytes, end = read_exact(payload, 228, opening_length, "response:opening")
        if end != len(payload):
            raise ProfileError("response:trailing")
        response = cls(session_id, payload[:64], payload[64:128], payload[128:192], payload[192:224], Opening.parse(opening_bytes))
        if response.canonical_bytes() != data:
            raise ProfileError("response:noncanonical")
        return response


@dataclass(frozen=True)
class Transcript:
    session_id: bytes
    statement: bytes
    commitment: bytes
    challenge: bytes
    response: bytes

    def canonical_bytes(self) -> bytes:
        frames = (self.commitment, self.challenge, self.response)
        body = b"".join(
            (
                TRANSCRIPT_MAGIC,
                u16(TRANSCRIPT_VERSION),
                u16(0),
                self.session_id,
                u32(len(self.statement)),
                self.statement,
                u16(len(frames)),
                *(u32(len(frame)) + frame for frame in frames),
            )
        )
        return body + _sha(TRANSCRIPT_DOMAIN, self.session_id, self.statement, *frames)

    @classmethod
    def parse(cls, data: bytes) -> "Transcript":
        offset = 0
        magic, offset = read_exact(data, offset, 8, "transcript:magic")
        version, offset = read_exact(data, offset, 2, "transcript:version")
        flags, offset = read_exact(data, offset, 2, "transcript:flags")
        if magic != TRANSCRIPT_MAGIC or version != u16(TRANSCRIPT_VERSION) or flags != b"\0\0":
            raise ProfileError("transcript:header")
        session_id, offset = read_exact(data, offset, FIXED_SESSION_ID_BYTES, "transcript:session")
        statement_length_bytes, offset = read_exact(data, offset, 4, "transcript:statement-length")
        statement, offset = read_exact(data, offset, int.from_bytes(statement_length_bytes, "big"), "transcript:statement")
        frame_count_bytes, offset = read_exact(data, offset, 2, "transcript:frame-count")
        if int.from_bytes(frame_count_bytes, "big") != 3:
            raise ProfileError("transcript:frame-count")
        frames: list[bytes] = []
        for index in range(3):
            length_bytes, offset = read_exact(data, offset, 4, f"transcript:frame-{index}-length")
            frame, offset = read_exact(data, offset, int.from_bytes(length_bytes, "big"), f"transcript:frame-{index}")
            frames.append(frame)
        digest, offset = read_exact(data, offset, 64, "transcript:digest")
        if offset != len(data):
            raise ProfileError("transcript:trailing")
        expected = _sha(TRANSCRIPT_DOMAIN, session_id, statement, *frames)
        if not hmac.compare_digest(digest, expected):
            raise ProfileError("transcript:digest")
        statement_obj = ProfileStatement.parse(statement)
        commitment = CommitmentMessage.parse(frames[0])
        challenge = ChallengeMessage.parse(frames[1])
        response = ResponseMessage.parse(frames[2])
        if statement_obj.session_id != session_id or commitment.session_id != session_id or challenge.session_id != session_id or response.session_id != session_id:
            raise ProfileError("transcript:session-binding")
        if [commitment.digest, challenge.digest, response.digest] != [
            _sha(COMMITMENT_DOMAIN, frames[0]),
            _sha(CHALLENGE_DOMAIN, frames[1]),
            _sha(RESPONSE_DOMAIN, frames[2]),
        ]:
            raise ProfileError("transcript:frame-binding")
        result = cls(session_id, statement, frames[0], frames[1], frames[2])
        if result.canonical_bytes() != data:
            raise ProfileError("transcript:noncanonical")
        return result


@dataclass(frozen=True)
class ProverState:
    statement: ProfileStatement
    commitment: CommitmentMessage
    leaves: tuple[VectorLeaf, VectorLeaf]

    def canonical_bytes(self) -> bytes:
        statement_bytes = self.statement.canonical_bytes()
        commitment_bytes = self.commitment.canonical_bytes()
        leaves = tuple(leaf.canonical_bytes() for leaf in self.leaves)
        return b"".join((PROVER_STATE_MAGIC, u16(PROVER_STATE_VERSION), u16(0), u32(len(statement_bytes)), statement_bytes, u32(len(commitment_bytes)), commitment_bytes, u16(len(leaves)), *(u32(len(leaf)) + leaf for leaf in leaves)))

    @classmethod
    def parse(cls, data: bytes) -> "ProverState":
        offset = 0
        magic, offset = read_exact(data, offset, 8, "prover-state:magic")
        version, offset = read_exact(data, offset, 2, "prover-state:version")
        reserved, offset = read_exact(data, offset, 2, "prover-state:reserved")
        if magic != PROVER_STATE_MAGIC or version != u16(PROVER_STATE_VERSION) or reserved != b"\0\0":
            raise ProfileError("prover-state:header")
        statement_length, offset = read_exact(data, offset, 4, "prover-state:statement-length")
        statement_bytes, offset = read_exact(data, offset, int.from_bytes(statement_length, "big"), "prover-state:statement")
        commitment_length, offset = read_exact(data, offset, 4, "prover-state:commitment-length")
        commitment_bytes, offset = read_exact(data, offset, int.from_bytes(commitment_length, "big"), "prover-state:commitment")
        leaf_count, offset = read_exact(data, offset, 2, "prover-state:leaf-count")
        if int.from_bytes(leaf_count, "big") != 2:
            raise ProfileError("prover-state:leaf-count")
        leaves: list[VectorLeaf] = []
        for index in range(2):
            leaf_length, offset = read_exact(data, offset, 4, f"prover-state:leaf-{index}-length")
            leaf_bytes, offset = read_exact(data, offset, int.from_bytes(leaf_length, "big"), f"prover-state:leaf-{index}")
            leaves.append(VectorLeaf.parse(leaf_bytes))
        if offset != len(data):
            raise ProfileError("prover-state:trailing")
        statement = ProfileStatement.parse(statement_bytes)
        commitment = CommitmentMessage.parse(commitment_bytes)
        state = cls(statement, commitment, (leaves[0], leaves[1]))
        if vector_root(state.leaves) != commitment.vector_root:
            raise ProfileError("prover-state:root")
        if commitment.statement_digest != _sha(STATEMENT_DOMAIN, statement_bytes):
            raise ProfileError("prover-state:statement-binding")
        if state.canonical_bytes() != data:
            raise ProfileError("prover-state:noncanonical")
        return state


def _marker(root: Path, *parts: str) -> Path:
    path = root.joinpath(*parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def claim_marker(root: Path, name: str, content: bytes = b"claimed\n") -> None:
    path = _marker(root, name)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise ProfileError(f"registry:replay:{path.name}") from exc
    try:
        os.write(descriptor, content)
    finally:
        os.close(descriptor)


def _random_marker(root: Path, label: str, value: bytes) -> None:
    claim_marker(root, f"random-{label}-{hashlib.sha3_512(value).hexdigest()}.used")


@dataclass
class ProverSession:
    bindings: ProfileBindings
    random_source: RandomBytes | None = None
    registry_dir: Path | None = None
    state: ProverState | None = None

    def commit(self) -> ProverState:
        if self.state is not None:
            raise ProfileError("prover:commit-repeat")
        session_id = _random(self.random_source, FIXED_SESSION_ID_BYTES)
        root = self.registry_dir
        if root is not None:
            attempt_root = root / "attempts" / self.bindings.attempt_id.hex()
            attempt_root.mkdir(parents=True, exist_ok=True)
            attempts = list(attempt_root.glob("*.started"))
            if len(attempts) >= MAX_RETRIES:
                raise ProfileError("retry:cap")
            claim_marker(attempt_root, f"{session_id.hex()}.started")
        salts = (_random(self.random_source, FIXED_SALT_BYTES), _random(self.random_source, FIXED_SALT_BYTES))
        if root is not None:
            _random_marker(root / "randomness", "salt", salts[0])
            _random_marker(root / "randomness", "salt", salts[1])
        fixture = build_fixture()
        leaves = (VectorLeaf(0, fixture.source_payload, salts[0]), VectorLeaf(1, b"BL/NATIVE-V3/TBP/fixed-padding-v1", salts[1]))
        statement = ProfileStatement(session_id, self.bindings)
        root_hash = vector_root(leaves)
        statement_digest = _sha(STATEMENT_DOMAIN, statement.canonical_bytes())
        handle = _sha(HANDLE_DOMAIN, session_id, statement_digest, root_hash)
        commitment = CommitmentMessage(session_id, statement_digest, root_hash, handle)
        self.state = ProverState(statement, commitment, leaves)
        return self.state

    def respond(self, challenge_bytes: bytes) -> tuple[ResponseMessage, Transcript]:
        if self.state is None:
            raise ProfileError("prover:no-commitment")
        challenge = ChallengeMessage.parse(challenge_bytes)
        if challenge.session_id != self.state.statement.session_id or challenge.commitment_digest != self.state.commitment.digest:
            raise ProfileError("prover:challenge-not-for-commitment")
        response_nonce = _random(self.random_source, FIXED_CHALLENGE_BYTES)
        if self.registry_dir is not None:
            _random_marker(self.registry_dir / "randomness", "response", response_nonce)
        leaf = self.state.leaves[challenge.selected_index]
        sibling = self.state.leaves[1 - challenge.selected_index]
        opening = Opening(challenge.selected_index, leaf.value, leaf.salt, challenge.selected_index == 1, leaf_hash(sibling))
        response = ResponseMessage(self.state.statement.session_id, self.state.commitment.digest, challenge.digest, self.state.commitment.handle, response_nonce, opening)
        transcript = Transcript(self.state.statement.session_id, self.state.statement.canonical_bytes(), self.state.commitment.canonical_bytes(), challenge_bytes, response.canonical_bytes())
        return response, transcript

    def abort(self) -> None:
        if self.state is None:
            raise ProfileError("prover:no-session")
        if self.registry_dir is not None:
            claim_marker(self.registry_dir / "aborted", f"{self.state.statement.session_id.hex()}.aborted")
        self.state = None


@dataclass
class VerifierSession:
    auth_key: bytes
    random_source: RandomBytes | None = None
    registry_dir: Path | None = None
    challenged_sessions: set[bytes] | None = None

    def __post_init__(self) -> None:
        if len(self.auth_key) != 32:
            raise ProfileError("verifier:key-width")
        if self.challenged_sessions is None:
            self.challenged_sessions = set()

    def issue_challenge(self, commitment_bytes: bytes, statement_bytes: bytes) -> ChallengeMessage:
        statement = ProfileStatement.parse(statement_bytes)
        commitment = CommitmentMessage.parse(commitment_bytes)
        if commitment.session_id != statement.session_id:
            raise ProfileError("verifier:statement-commitment-session")
        if commitment.statement_digest != _sha(STATEMENT_DOMAIN, statement_bytes):
            raise ProfileError("verifier:statement-commitment-digest")
        if commitment.handle != _sha(HANDLE_DOMAIN, statement.session_id, commitment.statement_digest, commitment.vector_root):
            raise ProfileError("verifier:handle")
        if statement.session_id in self.challenged_sessions:
            raise ProfileError("verifier:challenge-repeat")
        if self.registry_dir is not None:
            if (self.registry_dir / "aborted" / f"{statement.session_id.hex()}.aborted").exists():
                raise ProfileError("verifier:aborted-session")
            claim_marker(self.registry_dir / "challenges", f"{statement.session_id.hex()}.issued")
        challenge = ChallengeMessage.issue(commitment, self.auth_key, self.random_source)
        if self.registry_dir is not None:
            _random_marker(self.registry_dir / "randomness", "challenge", challenge.challenge_nonce + challenge.challenge_scalar)
        self.challenged_sessions.add(statement.session_id)
        return challenge


@dataclass(frozen=True)
class VerificationResult:
    session_id: bytes
    transcript_digest: bytes
    commitment_digest: bytes
    challenge_digest: bytes
    profile_only: bool = True
    complete_bound_available: bool = False
    production_usable: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "status": "TRUST_BOUNDARY_PROFILE_ACCEPTED",
            "session_id": self.session_id.hex(),
            "transcript_digest": self.transcript_digest.hex(),
            "commitment_digest": self.commitment_digest.hex(),
            "challenge_digest": self.challenge_digest.hex(),
            "profile_only": self.profile_only,
            "complete_bound_available": self.complete_bound_available,
            "production_usable": self.production_usable,
            "proof_suite_id": None,
        }


def verify_session(
    statement_bytes: bytes,
    commitment_bytes: bytes,
    challenge_bytes: bytes,
    response_bytes: bytes,
    transcript_bytes: bytes,
    auth_key: bytes,
    registry_dir: Path,
    bindings: ProfileBindings | None = None,
) -> VerificationResult:
    if bindings is None:
        bindings = build_profile_bindings()
    statement = ProfileStatement.parse(statement_bytes, bindings)
    commitment = CommitmentMessage.parse(commitment_bytes)
    challenge = ChallengeMessage.parse(challenge_bytes, auth_key)
    response = ResponseMessage.parse(response_bytes)
    transcript = Transcript.parse(transcript_bytes)
    if commitment.session_id != statement.session_id or challenge.session_id != statement.session_id or response.session_id != statement.session_id or transcript.session_id != statement.session_id:
        raise ProfileError("verify:session-binding")
    if commitment.statement_digest != _sha(STATEMENT_DOMAIN, statement_bytes):
        raise ProfileError("verify:statement-digest")
    if commitment.digest != challenge.commitment_digest or response.commitment_digest != commitment.digest:
        raise ProfileError("verify:commitment-binding")
    if response.challenge_digest != challenge.digest:
        raise ProfileError("verify:challenge-binding")
    if response.handle != commitment.handle:
        raise ProfileError("verify:handle")
    if transcript.statement != statement_bytes or transcript.commitment != commitment_bytes or transcript.challenge != challenge_bytes or transcript.response != response_bytes:
        raise ProfileError("verify:transcript-frame-order")
    verify_opening(response.opening, commitment, challenge)
    accepted_marker = registry_dir / "accepted" / f"{statement.session_id.hex()}.accepted"
    claim_marker(registry_dir / "accepted", accepted_marker.name, transcript.canonical_bytes())
    return VerificationResult(statement.session_id, _sha(TRANSCRIPT_DOMAIN, transcript.session_id, transcript.statement, transcript.commitment, transcript.challenge, transcript.response), commitment.digest, challenge.digest)


def create_session_artifacts(directory: Path, auth_key: bytes | None = None, random_source: RandomBytes | None = None) -> ProverState:
    directory.mkdir(parents=True, exist_ok=True)
    registry = directory / "registry"
    bindings = build_profile_bindings()
    prover = ProverSession(bindings, random_source=random_source, registry_dir=registry)
    state = prover.commit()
    (directory / "statement.bin").write_bytes(state.statement.canonical_bytes())
    (directory / "commitment.bin").write_bytes(state.commitment.canonical_bytes())
    (directory / "prover_state.bin").write_bytes(state.canonical_bytes())
    if auth_key is None:
        auth_key = secrets.token_bytes(32)
    if len(auth_key) != 32:
        raise ProfileError("auth-key:width")
    (directory / "verifier.key").write_bytes(auth_key)
    return state


def issue_session_challenge(directory: Path, random_source: RandomBytes | None = None) -> ChallengeMessage:
    registry = directory / "registry"
    verifier = VerifierSession((directory / "verifier.key").read_bytes(), random_source=random_source, registry_dir=registry)
    challenge = verifier.issue_challenge((directory / "commitment.bin").read_bytes(), (directory / "statement.bin").read_bytes())
    (directory / "challenge.bin").write_bytes(challenge.canonical_bytes())
    return challenge


def respond_to_challenge(directory: Path, random_source: RandomBytes | None = None) -> Transcript:
    state = ProverState.parse((directory / "prover_state.bin").read_bytes())
    prover = ProverSession(build_profile_bindings(), random_source=random_source, registry_dir=directory / "registry", state=state)
    response, transcript = prover.respond((directory / "challenge.bin").read_bytes())
    (directory / "response.bin").write_bytes(response.canonical_bytes())
    (directory / "transcript.bin").write_bytes(transcript.canonical_bytes())
    return transcript


def verify_session_directory(directory: Path) -> VerificationResult:
    return verify_session(
        (directory / "statement.bin").read_bytes(),
        (directory / "commitment.bin").read_bytes(),
        (directory / "challenge.bin").read_bytes(),
        (directory / "response.bin").read_bytes(),
        (directory / "transcript.bin").read_bytes(),
        (directory / "verifier.key").read_bytes(),
        directory / "python-verifier-registry",
    )


def main() -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("manifest")
    sub.add_parser("ledger")
    create = sub.add_parser("create")
    create.add_argument("directory", type=Path)
    challenge = sub.add_parser("challenge")
    challenge.add_argument("directory", type=Path)
    respond = sub.add_parser("respond")
    respond.add_argument("directory", type=Path)
    verify = sub.add_parser("verify")
    verify.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "manifest":
        from .profile import profile_manifest

        print(json.dumps(profile_manifest(), sort_keys=True, indent=2))
    elif args.command == "ledger":
        print(json.dumps(build_security_ledger(), sort_keys=True, indent=2))
    elif args.command == "create":
        state = create_session_artifacts(args.directory)
        print(f"status=TRUST_BOUNDARY_PROVER_COMMITMENT_READY session_id={state.statement.session_id.hex()} commitment_bytes={len(state.commitment.canonical_bytes())}")
    elif args.command == "challenge":
        challenge = issue_session_challenge(args.directory)
        print(f"status=TRUST_BOUNDARY_VERIFIER_CHALLENGE_READY session_id={challenge.session_id.hex()} challenge_bytes={len(challenge.canonical_bytes())} selected_index={challenge.selected_index}")
    elif args.command == "respond":
        transcript = respond_to_challenge(args.directory)
        print(f"status=TRUST_BOUNDARY_PROVER_RESPONSE_READY session_id={transcript.session_id.hex()} transcript_bytes={len(transcript.canonical_bytes())}")
    elif args.command == "verify":
        print(json.dumps(verify_session_directory(args.directory).as_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
