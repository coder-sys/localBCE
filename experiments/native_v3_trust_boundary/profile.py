"""Canonical native-v3 trust-boundary profile and symbolic security ledger.

This module deliberately stops below the proof boundary.  It binds the frozen
Phase-0 fixture into a fixed public profile and records unresolved theorem
terms; it does not prove source membership, policy semantics, hiding, or state
transition correctness.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from typing import Any

from experiments.native_v3_phase0.native_v3_fixture import (
    ACCESS_READ,
    ACCESS_WRITE,
    DIRECTIVE_CLEAR,
    DIRECTIVE_NAMES,
    DIRECTIVE_POLICY_RESULT,
    EXPECTED_AMOUNT_SCOPE,
    EXPECTED_REASON_ID,
    EXPECTED_RULE_ID,
    NO_EXCEPTION_SENTINEL,
    build_fixture,
)


class ProfileError(ValueError):
    """Raised for malformed or noncanonical trust-boundary data."""


PROFILE_VERSION = 1
PROFILE_NAME = "BL-NATIVE-V3-TRUST-BOUNDARY-PROFILE-v1"
PROFILE_ID_DOMAIN = b"BL/NATIVE-V3/TBP/PROFILE-ID/v1\0"
FRAME_DOMAIN = b"BL/NATIVE-V3/TBP/FRAME/v1\0"
STATEMENT_DOMAIN = b"BL/NATIVE-V3/TBP/STATEMENT/v1\0"
CONTROL_SET_DOMAIN = b"BL/NATIVE-V3/TBP/AUTOMATIC-CONTROL-SET/v1\0"
JOIN_DOMAIN = b"BL/NATIVE-V3/TBP/DECISION-ACCESS-JOIN/v1\0"
RECEIPT_DOMAIN = b"BL/NATIVE-V3/TBP/FROZEN-RECEIPT/v1\0"
COMPLETENESS_DOMAIN = b"BL/NATIVE-V3/TBP/COMPLETENESS/v1\0"
CHRONOLOGY_DOMAIN = b"BL/NATIVE-V3/TBP/CHRONOLOGY/v1\0"
REPLAY_DOMAIN = b"BL/NATIVE-V3/TBP/REPLAY/v1\0"
ATTEMPT_DOMAIN = b"BL/NATIVE-V3/TBP/ATTEMPT/v1\0"
PROFILE_BINDINGS_DOMAIN = b"BL/NATIVE-V3/TBP/BINDINGS/v1\0"
ACCESS_DOMAIN = b"BL/NATIVE-V3/TBP/ACCESS-ROW/v1\0"

PROFILE_ID = hashlib.sha3_512(PROFILE_ID_DOMAIN + PROFILE_NAME.encode()).digest()
FIXED_SALT_BYTES = 32
FIXED_SESSION_ID_BYTES = 32
FIXED_CHALLENGE_BYTES = 32
MAX_RETRIES = 4

EVENT_TIME = 7_000
OBSERVATION_TIME = 7_001
RULE_EFFECTIVE_TIME = 6_999
DECISION_TIME = 7_002


CANONICAL_GRAMMAR: dict[str, Any] = {
    "integer_encoding": "unsigned big-endian",
    "hash": "SHA3-512",
    "domain_separation": {
        "profile_id": PROFILE_ID_DOMAIN.decode("ascii"),
        "statement_digest": STATEMENT_DOMAIN.decode("ascii"),
        "frame_tag": "BL/NATIVE-V3/TBP/FRAME-TAG/v1\\0",
        "commitment_digest": "BL/NATIVE-V3/TBP/COMMITMENT-DIGEST/v1\\0",
        "challenge_digest": "BL/NATIVE-V3/TBP/CHALLENGE-DIGEST/v1\\0",
        "challenge_authentication": "BL/NATIVE-V3/TBP/CHALLENGE-AUTH/v1\\0",
        "vector_leaf": "BL/NATIVE-V3/TBP/VECTOR-LEAF/v1\\0",
        "vector_node": "BL/NATIVE-V3/TBP/VECTOR-NODE/v1\\0",
        "leaf_tag": "BL/NATIVE-V3/TBP/LEAF-TAG/v1\\0",
        "node_tag": "BL/NATIVE-V3/TBP/NODE-TAG/v1\\0",
        "commitment_handle": "BL/NATIVE-V3/TBP/COMMITMENT-HANDLE/v1\\0",
        "transcript": "BL/NATIVE-V3/TBP/TRANSCRIPT/v1\\0",
    },
    "frame": {
        "fields": [
            ["magic", "bytes[8]", "BLTBFRM1"],
            ["version", "u16", 1],
            ["kind", "u8", "commitment=1,challenge=2,response=3"],
            ["role", "u8", "prover=1,verifier=2"],
            ["round", "u16", "commitment=0,challenge=1,response=2"],
            ["session_id", "bytes[32]", "nonzero; OS-CSPRNG session uniqueness"],
            ["domain_tag", "bytes[64]", "SHA3-512(frame-tag-domain,kind-domain,kind||role,round)"],
            ["payload_length", "u32", "exact remaining payload length"],
            ["payload", "bytes[payload_length]", "no trailing bytes"],
        ],
        "message_order": ["statement", "prover_commitment", "verifier_challenge", "prover_response"],
    },
    "statement": {
        "magic": "BLTBST01",
        "length_bytes": 992,
        "fields": [
            ["magic", "bytes[8]"],
            ["version", "u16=1"],
            ["flags", "u16=0"],
            ["proof_suite_marker", "u8=0"],
            ["reserved", "bytes[3]=0"],
            ["proof_suite_id", "bytes[64]=0/null"],
            ["session_id", "bytes[32]"],
            ["profile_id", "bytes[64]"],
            ["attempt_id", "bytes[64]"],
            ["phase0_statement_digest", "bytes[64]"],
            ["source_root", "bytes[64]"],
            ["control_set_id", "bytes[64]"],
            ["decision_access_join_id", "bytes[64]"],
            ["frozen_receipt_binding", "bytes[64]"],
            ["completeness_id", "bytes[64]"],
            ["chronology_id", "bytes[64]"],
            ["replay_id", "bytes[64]"],
            ["exception_id_or_sentinel", "bytes[64]"],
            ["state_before_id", "bytes[64]"],
            ["state_after_id", "bytes[64]"],
            ["statement_sequence_before", "u64"],
            ["statement_sequence_after", "u64"],
            ["event_time", "u64"],
            ["observation_time", "u64"],
            ["rule_effective_time", "u64"],
            ["decision_time", "u64"],
        ],
    },
    "commitment_payload": {
        "fields": [
            ["statement_digest", "bytes[64]"],
            ["vector_root", "bytes[64]"],
            ["commitment_handle", "bytes[64]"],
            ["leaf_count", "u32=2"],
            ["salt_bytes", "u16=32"],
            ["reserved", "u16=0"],
        ],
        "handle": "SHA3-512(handle-domain,session_id,statement_digest,vector_root)",
    },
    "challenge_payload": {
        "fields": [
            ["commitment_digest", "bytes[64]"],
            ["challenge_nonce", "bytes[32]", "verifier OS-CSPRNG"],
            ["challenge_scalar", "bytes[32]", "verifier OS-CSPRNG"],
            ["selected_index", "u32", "big-endian first four scalar bytes modulo 2"],
            ["auth_tag", "bytes[64]", "fixture-only HMAC-SHA3-512 under verifier-held 32-byte key"],
        ],
        "prover_supplied_challenge": False,
        "fresh_after_commitment": True,
    },
    "response_payload": {
        "fields": [
            ["commitment_digest", "bytes[64]"],
            ["challenge_digest", "bytes[64]"],
            ["commitment_handle", "bytes[64]"],
            ["response_nonce", "bytes[32]", "prover OS-CSPRNG"],
            ["opening_length", "u32"],
            ["opening", "bytes[opening_length]"],
        ],
    },
    "vector_leaf": {
        "magic": "BLTBLF01",
        "fields": [
            ["magic", "bytes[8]"],
            ["version", "u16=1"],
            ["reserved", "u16=0"],
            ["leaf_tag", "bytes[64]"],
            ["index", "u32", "ordered indices exactly 0 then 1"],
            ["value_length", "u32"],
            ["value", "bytes[value_length]", "fixture-only private registered fact or fixed padding"],
            ["salt_length", "u16=32"],
            ["salt", "bytes[32]", "hidden in statement; no production hiding claim"],
        ],
    },
    "vector_node": {
        "magic": "BLTBND01",
        "fields": [
            ["magic", "bytes[8]"],
            ["version", "u16=1"],
            ["reserved", "u16=0"],
            ["node_tag", "bytes[64]"],
            ["height", "u16=0"],
            ["left_index", "u32=0"],
            ["left_hash", "bytes[64]"],
            ["right_hash", "bytes[64]"],
        ],
        "root": "SHA3-512(vector-node-domain,canonical-node-bytes)",
    },
    "opening": {
        "magic": "BLTBOP01",
        "fields": [
            ["magic", "bytes[8]"],
            ["version", "u16=1"],
            ["reserved", "u16=0"],
            ["index", "u32"],
            ["value_length", "u32"],
            ["value", "bytes[value_length]"],
            ["salt_length", "u16=32"],
            ["salt", "bytes[32]"],
            ["path_count", "u16=1"],
            ["sibling_is_left", "u8 in {0,1}"],
            ["path_reserved", "u8=0"],
            ["sibling_hash", "bytes[64]"],
        ],
        "order": "exactly one sibling; index must equal verifier-selected index",
    },
    "transcript": {
        "magic": "BLTBTX01",
        "fields": [
            ["magic", "bytes[8]"],
            ["version", "u16=1"],
            ["flags", "u16=0"],
            ["session_id", "bytes[32]"],
            ["statement_length", "u32"],
            ["statement", "bytes[statement_length]"],
            ["frame_count", "u16=3"],
            ["ordered_frames", "3 x (u32 length, bytes)"],
            ["transcript_digest", "bytes[64]", "SHA3-512(transcript-domain,session,statement,commitment,challenge,response)"],
        ],
    },
    "private_or_fixture_only": ["vector values", "leaf salts", "prover response nonce", "verifier authentication key"],
}


def _sha(domain: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha3_512()
    h.update(domain)
    for part in parts:
        h.update(part)
    return h.digest()


def u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise ProfileError("u16-range")
    return value.to_bytes(2, "big")


def u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ProfileError("u32-range")
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise ProfileError("u64-range")
    return value.to_bytes(8, "big")


def nonzero64(value: bytes, label: str) -> bytes:
    if len(value) != 64 or not any(value):
        raise ProfileError(f"{label}:width-or-zero")
    return value


def fixed_field(value: bytes, label: str) -> bytes:
    return nonzero64(value, label)


def read_exact(data: bytes, offset: int, length: int, label: str) -> tuple[bytes, int]:
    end = offset + length
    if end > len(data):
        raise ProfileError(f"{label}:truncated")
    return data[offset:end], end


def _ascii_field(value: bytes, label: str) -> bytes:
    if len(value) > 0xFFFF:
        raise ProfileError(f"{label}:too-long")
    return u16(len(value)) + value


def access_row_bytes(index: int, count: int, operation_index: int, mode: int, value: bytes) -> bytes:
    if count != 2 or index not in (0, 1) or operation_index != 0:
        raise ProfileError("access-row:geometry")
    if mode not in (ACCESS_READ, ACCESS_WRITE) or len(value) != 64:
        raise ProfileError("access-row:fields")
    return b"BLTBAC01" + u16(1) + u16(0) + u32(index) + u32(count) + u32(operation_index) + bytes((mode, 0)) + u32(len(value)) + value


def control_set_bytes() -> bytes:
    scope = _sha(b"BL/NATIVE-V3/TBP/SCOPE/v1\0", b"synthetic-subject-payment-scope-v1")
    conflict_policy = b"priority-then-human-review"
    directive_mapping = bytes((1, 1, 2, 2, 3, 3, 4, 4, 5, 5))
    return b"BLTBCT01" + u16(1) + u16(0) + u32(1) + EXPECTED_RULE_ID + u16(1) + _ascii_field(conflict_policy, "control-set:conflict") + scope + u64(0) + u64(16) + u16(len(directive_mapping)) + directive_mapping


@dataclass(frozen=True)
class ProfileBindings:
    profile_id: bytes
    attempt_id: bytes
    phase0_statement_digest: bytes
    source_root: bytes
    control_set_id: bytes
    decision_access_join_id: bytes
    frozen_receipt_binding: bytes
    completeness_id: bytes
    chronology_id: bytes
    replay_id: bytes
    exception_id_or_sentinel: bytes
    state_before_id: bytes
    state_after_id: bytes
    statement_sequence_before: int
    statement_sequence_after: int
    event_time: int
    observation_time: int
    rule_effective_time: int
    decision_time: int

    def __post_init__(self) -> None:
        for label, value in (
            ("profile-id", self.profile_id),
            ("attempt-id", self.attempt_id),
            ("phase0-statement", self.phase0_statement_digest),
            ("source-root", self.source_root),
            ("control-set", self.control_set_id),
            ("decision-access-join", self.decision_access_join_id),
            ("receipt", self.frozen_receipt_binding),
            ("completeness", self.completeness_id),
            ("chronology", self.chronology_id),
            ("replay", self.replay_id),
            ("exception", self.exception_id_or_sentinel),
            ("state-before", self.state_before_id),
            ("state-after", self.state_after_id),
        ):
            fixed_field(value, label)
        if self.statement_sequence_after != self.statement_sequence_before + 1:
            raise ProfileError("bindings:sequence")
        if len({self.event_time, self.observation_time, self.rule_effective_time, self.decision_time}) != 4:
            raise ProfileError("bindings:times-not-distinct")
        if not (self.rule_effective_time < self.event_time < self.observation_time < self.decision_time):
            raise ProfileError("bindings:chronology")

    def canonical_bytes(self) -> bytes:
        return b"".join(
            (
                b"BLTBBN01",
                u16(PROFILE_VERSION),
                u16(0),
                self.profile_id,
                self.attempt_id,
                self.phase0_statement_digest,
                self.source_root,
                self.control_set_id,
                self.decision_access_join_id,
                self.frozen_receipt_binding,
                self.completeness_id,
                self.chronology_id,
                self.replay_id,
                self.exception_id_or_sentinel,
                self.state_before_id,
                self.state_after_id,
                u64(self.statement_sequence_before),
                u64(self.statement_sequence_after),
                u64(self.event_time),
                u64(self.observation_time),
                u64(self.rule_effective_time),
                u64(self.decision_time),
            )
        )


def build_profile_bindings() -> ProfileBindings:
    fixture = build_fixture()
    phase0_statement = fixture.statement.canonical_bytes()
    operation = fixture.operation.canonical_bytes()
    access_rows = b"".join(
        access_row_bytes(index, 2, access.operation_index, access.mode, access.value)
        for index, access in enumerate(fixture.accesses)
    )
    join_bytes = b"".join((u32(1), operation, u32(2), access_rows))
    decision_access_join_id = _sha(JOIN_DOMAIN, join_bytes)
    auth_bytes = (
        NO_EXCEPTION_SENTINEL
        if fixture.exception_authorization is None
        else fixture.exception_authorization.canonical_bytes()
    )
    receipt_bytes = b"".join(
        (
            phase0_statement,
            operation,
            auth_bytes,
            fixture.before_state.canonical_bytes(),
            fixture.after_state.canonical_bytes(),
        )
    )
    frozen_receipt_binding = _sha(RECEIPT_DOMAIN, receipt_bytes)
    source_root = fixture.before_state.source_registry_root
    completeness_bytes = b"".join(
        (
            b"BLTBFC01",
            u16(1),
            u16(0),
            source_root,
            fixture.source_leaf.leaf_id,
            fixture.operation.address,
            u64(OBSERVATION_TIME),
            b"\1",
            u32(1),
        )
    )
    completeness_id = _sha(COMPLETENESS_DOMAIN, completeness_bytes)
    chronology_bytes = b"".join(
        (
            b"BLTBCH01",
            u16(1),
            u16(0),
            u64(EVENT_TIME),
            u64(OBSERVATION_TIME),
            u64(RULE_EFFECTIVE_TIME),
            u64(DECISION_TIME),
            u64(fixture.statement.epoch),
        )
    )
    chronology_id = _sha(CHRONOLOGY_DOMAIN, chronology_bytes)
    attempt_id = _sha(ATTEMPT_DOMAIN, fixture.source_leaf.leaf_id, fixture.operation.row_id, b"synthetic-attempt-v1")
    replay_id = _sha(
        REPLAY_DOMAIN,
        attempt_id,
        u64(fixture.statement.epoch),
        u64(fixture.statement.sequence_before),
        fixture.before_state.state_id,
        fixture.after_state.state_id,
    )
    control_set_id = _sha(CONTROL_SET_DOMAIN, control_set_bytes())
    return ProfileBindings(
        profile_id=PROFILE_ID,
        attempt_id=attempt_id,
        phase0_statement_digest=_sha(STATEMENT_DOMAIN, phase0_statement),
        source_root=source_root,
        control_set_id=control_set_id,
        decision_access_join_id=decision_access_join_id,
        frozen_receipt_binding=frozen_receipt_binding,
        completeness_id=completeness_id,
        chronology_id=chronology_id,
        replay_id=replay_id,
        exception_id_or_sentinel=fixture.operation.exception_authorization_id,
        state_before_id=fixture.before_state.state_id,
        state_after_id=fixture.after_state.state_id,
        statement_sequence_before=fixture.statement.sequence_before,
        statement_sequence_after=fixture.statement.sequence_after,
        event_time=EVENT_TIME,
        observation_time=OBSERVATION_TIME,
        rule_effective_time=RULE_EFFECTIVE_TIME,
        decision_time=DECISION_TIME,
    )


def _decimal_fraction(value: Fraction, digits: int = 80) -> str:
    with localcontext() as ctx:
        ctx.prec = digits
        return format(Decimal(value.numerator) / Decimal(value.denominator), "f")


def _decimal_log2(value: Fraction, digits: int = 50) -> str:
    if value <= 0:
        raise ProfileError("ledger:log2-nonpositive")
    with localcontext() as ctx:
        ctx.prec = digits + 12
        result = (Decimal(value.numerator).ln() - Decimal(value.denominator).ln()) / Decimal(2).ln()
        return format(+result, "f")


def build_security_ledger() -> dict[str, Any]:
    ell = 28
    rate = 1
    field_degree = 256
    theta = 4
    gamma = 324
    instances = 56
    extraction_plus_sumcheck = Fraction((1 << (ell + rate)) + (2 * ell), 1 << field_degree)
    query = Fraction(1, 2) + Fraction(1, 2 * (1 << rate))
    query = query**gamma
    epsilon_single = extraction_plus_sumcheck + query
    epsilon_union = instances * epsilon_single
    unresolved = [
        {
            "id": "vc_collapse_binding",
            "symbol": "epsilon_VCCollapse(lambda,t_VCCollapse)",
            "coefficient": "sum_i L_i*q_i",
            "status": "UNRESOLVED",
            "source": "2025/947 interactive IOP-to-argument bound",
            "bound": None,
        },
        {
            "id": "salted_leaf_hiding",
            "symbol": "epsilon_SaltedLeafHiding(lambda,salt_bytes)",
            "coefficient": "1",
            "status": "UNRESOLVED",
            "source": "Diamond 2025/1015 honest-verifier ideal-vector-oracle discussion",
            "bound": None,
        },
        {
            "id": "malicious_verifier_zk_composition",
            "symbol": "epsilon_MaliciousVerifierZK(lambda)",
            "coefficient": "1",
            "status": "UNRESOLVED",
            "source": "2026/307 abstract IOP composition",
            "bound": None,
        },
        {
            "id": "semantic_state_composition",
            "symbol": "epsilon_SemanticStateComposition(lambda)",
            "coefficient": "1",
            "status": "UNRESOLVED",
            "source": "No primary theorem for this native-v3 composition",
            "bound": None,
        },
        {
            "id": "abort_retry_union",
            "symbol": "epsilon_AbortRetryUnion(lambda,retry_cap)",
            "coefficient": "retry_cap * session_count",
            "status": "UNRESOLVED",
            "source": "No pinned abort/retry/grinding composition theorem",
            "bound": None,
        },
        {
            "id": "verifier_challenge_authentication",
            "symbol": "epsilon_VerifierChallengeAuthentication(lambda)",
            "coefficient": "1",
            "status": "UNRESOLVED",
            "source": "Fixture HMAC tag only; no production PQ authority selected",
            "bound": None,
        },
    ]
    ledger: dict[str, Any] = {
        "schema": "BL/NATIVE-V3/TRUST-BOUNDARY-SECURITY-LEDGER/v1",
        "profile_id": PROFILE_ID.hex(),
        "proof_backend_selected": False,
        "proof_suite_id": None,
        "complete_bound_available": False,
        "production_usable": False,
        "activation": False,
        "dp24": {
            "theorem": "ePrint_2024_504_Theorem_4_17",
            "construction": "4.12",
            "model": "ideal-vector-oracle-only",
            "ell": ell,
            "rate_R": rate,
            "field_degree": field_degree,
            "theta": theta,
            "gamma": gamma,
            "instances": instances,
            "epsilon_extraction_plus_sumcheck_fraction": {"numerator": extraction_plus_sumcheck.numerator, "denominator": extraction_plus_sumcheck.denominator},
            "epsilon_query_fraction": {"numerator": query.numerator, "denominator": query.denominator},
            "epsilon_single_fraction": {"numerator": epsilon_single.numerator, "denominator": epsilon_single.denominator},
            "epsilon_union_fraction": {"numerator": epsilon_union.numerator, "denominator": epsilon_union.denominator},
            "epsilon_single_decimal": _decimal_fraction(epsilon_single),
            "epsilon_union_decimal": _decimal_fraction(epsilon_union),
            "bits_single_decimal": _decimal_log2(Fraction(1, 1) / epsilon_single),
            "bits_union_decimal": _decimal_log2(Fraction(1, 1) / epsilon_union),
        },
        "unresolved_terms": unresolved,
        "zero_placeholders_allowed": False,
        "nonclaims": [
            "no proof backend",
            "no ZK",
            "no concrete vector-commitment binding reduction",
            "no salted-leaf hiding theorem",
            "no semantic/state proof composition",
            "no production challenge authentication",
            "no production usability or activation",
        ],
    }
    validate_security_ledger(ledger)
    return ledger


def validate_security_ledger(ledger: dict[str, Any]) -> None:
    if ledger.get("complete_bound_available") is not False:
        raise ProfileError("ledger:complete-bound-must-be-false")
    if ledger.get("production_usable") is not False or ledger.get("activation") is not False:
        raise ProfileError("ledger:production-flags")
    if ledger.get("proof_backend_selected") is not False or ledger.get("proof_suite_id") is not None:
        raise ProfileError("ledger:backend-selected")
    terms = ledger.get("unresolved_terms")
    if not isinstance(terms, list) or not terms:
        raise ProfileError("ledger:terms-missing")
    for term in terms:
        if term.get("status") != "UNRESOLVED":
            raise ProfileError(f"ledger:term-not-unresolved:{term.get('id')}")
        if term.get("bound") is not None:
            raise ProfileError(f"ledger:caller-bound-forbidden:{term.get('id')}")
        if not term.get("symbol") or not term.get("coefficient") or not term.get("source"):
            raise ProfileError(f"ledger:term-incomplete:{term.get('id')}")
    if ledger.get("zero_placeholders_allowed") is not False:
        raise ProfileError("ledger:zero-placeholders")


def profile_manifest() -> dict[str, Any]:
    bindings = build_profile_bindings()
    return {
        "schema": "BL/NATIVE-V3/TRUST-BOUNDARY-PROFILE/v1",
        "profile_name": PROFILE_NAME,
        "profile_id": PROFILE_ID.hex(),
        "status": "TRUST_BOUNDARY_ONLY",
        "proof_backend_selected": False,
        "proof_suite_id": None,
        "complete_bound_available": False,
        "production_usable": False,
        "activation": False,
        "fixture_only": True,
        "phase0_binding_ids": {
            "attempt_id": bindings.attempt_id.hex(),
            "phase0_statement_digest": bindings.phase0_statement_digest.hex(),
            "source_root": bindings.source_root.hex(),
            "control_set_id": bindings.control_set_id.hex(),
            "decision_access_join_id": bindings.decision_access_join_id.hex(),
            "frozen_receipt_binding": bindings.frozen_receipt_binding.hex(),
            "completeness_id": bindings.completeness_id.hex(),
            "chronology_id": bindings.chronology_id.hex(),
            "replay_id": bindings.replay_id.hex(),
            "exception_id_or_sentinel": bindings.exception_id_or_sentinel.hex(),
            "state_before_id": bindings.state_before_id.hex(),
            "state_after_id": bindings.state_after_id.hex(),
        },
        "grammar": CANONICAL_GRAMMAR,
        "verifier_owned_public_bindings": {
            "profile_id": PROFILE_ID.hex(),
            "phase0_statement_digest": bindings.phase0_statement_digest.hex(),
            "source_root": bindings.source_root.hex(),
            "phase0_typed_receipt": {
                "policy_result_code": DIRECTIVE_POLICY_RESULT[DIRECTIVE_CLEAR],
                "policy_result": "PASS",
                "effective_directive_code": DIRECTIVE_CLEAR,
                "effective_directive": DIRECTIVE_NAMES[DIRECTIVE_CLEAR],
                "receipt_binding": bindings.frozen_receipt_binding.hex(),
                "exception_id_or_sentinel": bindings.exception_id_or_sentinel.hex(),
                "economic_clearance": "profile fixture only; verifier acceptance is never CLEAR",
            },
            "automatic_control_set": {
                "control_set_id": bindings.control_set_id.hex(),
                "owner": "verifier",
                "rule_order": [EXPECTED_RULE_ID.hex()],
                "conflict_policy": "priority-then-human-review",
                "scope": "SHA3-512(BL/NATIVE-V3/TBP/SCOPE/v1\\0,synthetic-subject-payment-scope-v1)",
                "effective_interval": [0, 16],
                "directive_mapping": [1, 1, 2, 2, 3, 3, 4, 4, 5, 5],
            },
            "decision_access_join": {
                "join_id": bindings.decision_access_join_id.hex(),
                "decision_row_count": 1,
                "state_access_row_count": 2,
                "access_order": ["read", "write"],
                "operation_index": 0,
                "canonical_join": "u32(decision_count)||operation_row||u32(access_count)||ordered_state_access_rows",
            },
            "frozen_receipt": bindings.frozen_receipt_binding.hex(),
            "completeness_or_nonmembership": {
                "completeness_id": bindings.completeness_id.hex(),
                "source_root": bindings.source_root.hex(),
                "subject_leaf": "registered source leaf bound by Phase-0 fixture",
                "observation_time": bindings.observation_time,
                "complete": True,
                "absence_authorized": False,
            },
            "chronology": {
                "chronology_id": bindings.chronology_id.hex(),
                "event_time": bindings.event_time,
                "observation_time": bindings.observation_time,
                "rule_effective_time": bindings.rule_effective_time,
                "decision_time": bindings.decision_time,
                "sequence_before": bindings.statement_sequence_before,
                "sequence_after": bindings.statement_sequence_after,
            },
            "replay": {
                "replay_id": bindings.replay_id.hex(),
                "attempt_id": bindings.attempt_id.hex(),
                "retry_cap": MAX_RETRIES,
                "exception_id_or_sentinel": bindings.exception_id_or_sentinel.hex(),
            },
            "state_transition": {
                "before_state_root": bindings.state_before_id.hex(),
                "after_state_root": bindings.state_after_id.hex(),
                "exact_transition": "one chronological read/write transition; profile evidence only",
            },
        },
        "retry_cap": MAX_RETRIES,
        "security_ledger": "security_ledger.json",
        "nonclaims": [
            "protocol-boundary evidence only",
            "no ZK or native hiding claim",
            "no VC collapse/binding claim",
            "no source membership or policy proof",
            "no state transition authorization",
        ],
    }


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("manifest", "ledger"))
    args = parser.parse_args()
    payload = profile_manifest() if args.command == "manifest" else build_security_ledger()
    print(json.dumps(payload, sort_keys=True, indent=2))
