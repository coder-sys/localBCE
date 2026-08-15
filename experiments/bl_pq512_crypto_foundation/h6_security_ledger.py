"""Closed, typed, nonactivating H6 security and availability ledger.

This module never accepts caller-supplied closure claims.  It reads the
governed source universe, derives the numerical terms and caps from those
sources, and fails closed while any acceptance-root migration, theorem link,
privacy proof, parser/resource gate, or operational assumption is pending.

The Fp8 OODS rejection is deliberately not an acceptance-error term.  The
sampler rejects it before constructing ``OodsParameter``; exhausting the
fixed cap returns an error.  It is therefore recorded as availability only,
including its approximately 2^-248 one-draw probability.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from fractions import Fraction
import hashlib
import math
from pathlib import Path
import re
from typing import Final

from experiments.bl_pq512_crypto_core.cuda import fp16_zk_rs_security_ledger as base


ROOT: Final[Path] = Path(__file__).resolve().parents[2]
TARGET_BITS: Final[int] = 256
STATUS: Final[str] = "H6_SECURITY_LEDGER_V2_INCOMPLETE_NONACTIVATING"
GOVERNED_ATTEMPTS: Final[int] = 4
PROOF_SUITE_ID: Final[None] = None
ACTIVATION_ALLOWED: Final[bool] = False
PRODUCTION_USABLE: Final[bool] = False
_DOMAIN: Final[bytes] = b"BL/PQ512/H6/CLOSED-SECURITY-LEDGER/v2\x00"


class SourceRole(str, Enum):
    LEDGER = "ledger"
    ALGEBRAIC_THEOREM = "algebraic_theorem"
    FIELD_SAMPLER = "field_sampler"
    PCS_GKR = "pcs_gkr"
    HIDING = "hiding"
    BINDING_SUBSTRATE = "binding_substrate"
    ACCEPTANCE_ROOT = "acceptance_root"
    PUBLIC_COIN = "public_coin"
    PARSER_RESOURCE = "parser_resource"


class LedgerEffect(str, Enum):
    ACCEPTANCE = "acceptance_error"
    AVAILABILITY = "fail_closed_availability"
    PRIVACY = "privacy_gate"
    IMPLEMENTATION = "implementation_gate"
    EXTERNAL_ASSUMPTION = "external_assumption"
    PROVENANCE = "provenance_only"


class LedgerState(str, Enum):
    VERIFIED = "verified"
    PENDING_MIGRATION = "pending_migration"
    PENDING_EXTERNAL = "pending_external"
    FAIL_CLOSED = "fail_closed"
    NOT_CREDITED = "not_credited"


class UnionScope(str, Enum):
    CHARGED = "charged"
    SUPPORTING = "supporting_only"
    EXCLUDED = "excluded_from_acceptance_union"
    GATE = "qualification_gate"


@dataclass(frozen=True, slots=True)
class SourceContract:
    relative_path: str
    role: SourceRole


@dataclass(frozen=True, slots=True)
class SourceEvidence:
    relative_path: str
    role: SourceRole
    sha3_512: bytes


@dataclass(frozen=True, slots=True)
class LedgerTerm:
    term_id: str
    effect: LedgerEffect
    state: LedgerState
    union_scope: UnionScope
    event_probability: Fraction | None
    instance_multiplier: int
    work_bits: int | None
    sources: tuple[str, ...]
    rationale: str

    @property
    def event_bits(self) -> float | None:
        if self.event_probability is None:
            return None
        return _bits(self.event_probability)

    @property
    def charged_probability(self) -> Fraction | None:
        if self.union_scope is not UnionScope.CHARGED or self.event_probability is None:
            return None
        return self.event_probability * self.instance_multiplier

    @property
    def charged_bits(self) -> float | None:
        probability = self.charged_probability
        return None if probability is None else _bits(probability)


@dataclass(frozen=True, slots=True)
class DerivedParameters:
    governed_attempts: int
    required_contributors: int
    generic_max_contributors: int
    statement_lifetime_log2: int
    h4_max_shards: int
    h4_max_segments_per_shard: int
    h4_max_iopp_targets_per_attempt: int
    iopp_lifetime_multiplier: int
    oods_attempt_cap: int
    strict_h4_rounds: int
    strict_h4_bundle_bytes: int
    strict_max_bundle_bytes: int
    collision_bound_exponent: int
    preimage_bound_exponent: int
    combined_bound_exponent: int
    collision_work_bits: int
    preimage_work_bits: int


@dataclass(frozen=True, slots=True)
class H6SecurityLedger:
    status: str
    target_bits: int
    parameters: DerivedParameters
    sources: tuple[SourceEvidence, ...]
    terms: tuple[LedgerTerm, ...]
    iopp_per_target_error: Fraction
    iopp_per_target_bits: float
    known_acceptance_error: Fraction
    known_acceptance_bits: float
    verified_acceptance_error: Fraction
    verified_acceptance_bits: float
    source_manifest_sha3_512: bytes
    ledger_digest_sha3_512: bytes

    @property
    def pending_term_ids(self) -> tuple[str, ...]:
        return tuple(
            term.term_id
            for term in self.terms
            if term.state in (LedgerState.PENDING_MIGRATION, LedgerState.PENDING_EXTERNAL)
        )

    @property
    def minimum_known_acceptance_bits(self) -> float:
        values = (
            term.charged_bits
            for term in self.terms
            if term.effect is LedgerEffect.ACCEPTANCE and term.charged_bits is not None
        )
        return min(values, default=math.inf)

    @property
    def qualification_blockers(self) -> tuple[str, ...]:
        blockers = list(self.pending_term_ids)
        if any(
            term.effect is LedgerEffect.ACCEPTANCE
            and term.union_scope is UnionScope.CHARGED
            and term.charged_probability is None
            for term in self.terms
        ):
            blockers.append("unknown_charged_acceptance_probability")
        if self.minimum_known_acceptance_bits < self.target_bits:
            blockers.append("known_acceptance_term_below_target")
        if self.known_acceptance_bits < self.target_bits:
            blockers.append("known_acceptance_union_below_target")
        if _ledger_digest(self) != self.ledger_digest_sha3_512:
            blockers.append("ledger_digest_mismatch")
        return tuple(dict.fromkeys(blockers))

    @property
    def qualifies(self) -> bool:
        return (
            self.status == STATUS
            and self.target_bits == TARGET_BITS
            and self.parameters.governed_attempts == GOVERNED_ATTEMPTS
            and PROOF_SUITE_ID is None
            and not ACTIVATION_ALLOWED
            and not PRODUCTION_USABLE
            and not self.qualification_blockers
        )

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "target_error_bits": self.target_bits,
            "governed_attempts": self.parameters.governed_attempts,
            "required_contributors": self.parameters.required_contributors,
            "statement_lifetime_log2": self.parameters.statement_lifetime_log2,
            "h4_max_shards": self.parameters.h4_max_shards,
            "h4_max_segments_per_shard": self.parameters.h4_max_segments_per_shard,
            "h4_max_iopp_targets_per_attempt": self.parameters.h4_max_iopp_targets_per_attempt,
            "iopp_lifetime_multiplier": self.parameters.iopp_lifetime_multiplier,
            "iopp_per_target_error_bits": self.iopp_per_target_bits,
            "known_acceptance_error_bits": self.known_acceptance_bits,
            "verified_acceptance_error_bits": self.verified_acceptance_bits,
            "minimum_known_acceptance_bits": self.minimum_known_acceptance_bits,
            "sources": tuple(
                {
                    "path": source.relative_path,
                    "role": source.role.value,
                    "sha3_512": source.sha3_512.hex(),
                }
                for source in self.sources
            ),
            "terms": tuple(
                {
                    "term_id": term.term_id,
                    "effect": term.effect.value,
                    "state": term.state.value,
                    "union_scope": term.union_scope.value,
                    "event_bits": term.event_bits,
                    "instance_multiplier": term.instance_multiplier,
                    "charged_bits": term.charged_bits,
                    "work_bits": term.work_bits,
                    "sources": term.sources,
                    "rationale": term.rationale,
                }
                for term in self.terms
            ),
            "qualification_blockers": self.qualification_blockers,
            "source_manifest_sha3_512": self.source_manifest_sha3_512.hex(),
            "ledger_digest_sha3_512": self.ledger_digest_sha3_512.hex(),
            "proofSuiteId": PROOF_SUITE_ID,
            "activationAllowed": ACTIVATION_ALLOWED,
            "productionUsable": PRODUCTION_USABLE,
            "qualifies": self.qualifies,
        }


_LEDGER_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_foundation/h6_security_ledger.py",
    "experiments/bl_pq512_crypto_foundation/internal_package_matrix.py",
)
_ALGEBRAIC_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/cuda/fp16_zk_rs_security_ledger.py",
    "experiments/bl_pq512_crypto_foundation/field16_reference.py",
    "experiments/bl_pq512_crypto_core/src/field.rs",
    "experiments/bl_pq512_crypto_core/src/proof_parameters.rs",
)
_SAMPLER_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/sampler.rs",
    "experiments/bl_pq512_crypto_core/src/oods.rs",
)
_PCS_GKR_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/circle_fri.rs",
    "experiments/bl_pq512_crypto_core/src/circle_hiding.rs",
    "experiments/bl_pq512_crypto_core/src/trace_mask.rs",
    "experiments/bl_pq512_crypto_core/src/multilinear_pcs.rs",
    "experiments/bl_pq512_crypto_core/src/gkr_sumcheck.rs",
    "experiments/bl_pq512_crypto_core/src/gkr_packed_bridge_fp16.rs",
    "experiments/bl_pq512_crypto_core/src/state_relation_gkr.rs",
    "experiments/bl_pq512_crypto_core/src/state_squarefree_gkr.rs",
    "experiments/bl_pq512_crypto_core/src/state_uniqueness_gkr.rs",
)
_HIDING_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/cuda/fp16_zk_rs_hiding_simulator_kat.py",
    "experiments/bl_pq512_crypto_foundation/native_hiding_parameters.py",
)
_BINDING_SUBSTRATE_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/binding_root_v2.rs",
    "experiments/bl_pq512_crypto_foundation/binding_root_v2.py",
)
_CORE_ROOT_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/merkle.rs",
    "experiments/bl_pq512_crypto_core/src/merkle_multiproof.rs",
    "experiments/bl_pq512_crypto_core/src/cross_domain.rs",
    "experiments/bl_pq512_crypto_core/src/proof_format.rs",
    "experiments/bl_pq512_crypto_core/src/oracle_commitment.rs",
    "experiments/bl_pq512_crypto_core/src/selected_challenge.rs",
)
_FRI_ROOT_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/disk_fri.rs",
    "experiments/bl_pq512_crypto_core/src/fri_layer_multiproof.rs",
    "experiments/bl_pq512_crypto_core/src/fri_pipeline.rs",
    "experiments/bl_pq512_crypto_core/src/fri_proof.rs",
    "experiments/bl_pq512_crypto_core/src/deep_quotient.rs",
    "experiments/bl_pq512_crypto_core/src/disk_air.rs",
    "experiments/bl_pq512_crypto_core/src/disk_composition.rs",
    "experiments/bl_pq512_crypto_core/src/disk_logup.rs",
)
_MLPCS_ROOT_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/multilinear_pcs_query.rs",
    "experiments/bl_pq512_crypto_core/src/multilinear_pcs_proof.rs",
    "experiments/bl_pq512_crypto_core/src/multilinear_pcs_transcript.rs",
    "experiments/bl_pq512_crypto_core/src/streaming_mlpcs.rs",
)
_H4_ROOT_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/h4_proof_package_v1.rs",
    "experiments/bl_pq512_crypto_core/src/semantic_h4_bridge.rs",
)
_TYPED_STATE_ROOT_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/typed_state_proof_package.rs",
    "experiments/bl_pq512_crypto_foundation/typed_state_air_proof.py",
    "experiments/bl_pq512_crypto_foundation/state_air_proof.py",
)
_PUBLIC_COIN_ROOT_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/selected_public_coin.rs",
    "experiments/bl_pq512_crypto_core/src/selected_public_coin_v3.rs",
    "experiments/bl_pq512_crypto_core/src/composite_parent_public_coin.rs",
    "experiments/bl_pq512_crypto_foundation/selected_public_coin.py",
    "experiments/bl_pq512_crypto_foundation/public_coin_reference.py",
    "experiments/bl_pq512_crypto_foundation/durable_selected_public_coin.py",
    "experiments/bl_pq512_crypto_foundation/selected_public_coin_v3.py",
    "experiments/bl_pq512_crypto_foundation/selected_prover_orchestrator.py",
)
_V3_ROOT_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/v3_composite_envelope.rs",
    "experiments/bl_pq512_crypto_foundation/v3_composite_envelope.py",
)
_STRICT_COIN_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/strict_pq_public_coin_v2.rs",
    "experiments/bl_pq512_crypto_foundation/durable_public_coin_custody.py",
)
_RESOURCE_SOURCES: Final[tuple[str, ...]] = (
    "experiments/bl_pq512_crypto_core/src/resource_preflight.rs",
)

_PATHS_BY_ROLE: Final[tuple[tuple[SourceRole, tuple[str, ...]], ...]] = (
    (SourceRole.LEDGER, _LEDGER_SOURCES),
    (SourceRole.ALGEBRAIC_THEOREM, _ALGEBRAIC_SOURCES),
    (SourceRole.FIELD_SAMPLER, _SAMPLER_SOURCES),
    (SourceRole.PCS_GKR, _PCS_GKR_SOURCES),
    (SourceRole.HIDING, _HIDING_SOURCES),
    (SourceRole.BINDING_SUBSTRATE, _BINDING_SUBSTRATE_SOURCES),
    (
        SourceRole.ACCEPTANCE_ROOT,
        _CORE_ROOT_SOURCES
        + _FRI_ROOT_SOURCES
        + _MLPCS_ROOT_SOURCES
        + _H4_ROOT_SOURCES
        + _TYPED_STATE_ROOT_SOURCES
        + _PUBLIC_COIN_ROOT_SOURCES
        + _V3_ROOT_SOURCES,
    ),
    (SourceRole.PUBLIC_COIN, _STRICT_COIN_SOURCES),
    (SourceRole.PARSER_RESOURCE, _RESOURCE_SOURCES),
)
_SOURCE_CONTRACTS: Final[tuple[SourceContract, ...]] = tuple(
    SourceContract(path, role)
    for role, paths in _PATHS_BY_ROLE
    for path in paths
)

_ROOT_TERM_GROUPS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("binding.core_merkle_opening_roots_v2", _CORE_ROOT_SOURCES),
    ("binding.fri_deep_roots_v2", _FRI_ROOT_SOURCES),
    ("binding.mlpcs_roots_v2", _MLPCS_ROOT_SOURCES),
    ("binding.h4_package_roots_v2", _H4_ROOT_SOURCES),
    ("binding.typed_state_opening_roots_v2", _TYPED_STATE_ROOT_SOURCES),
    ("binding.public_coin_transcript_roots_v2", _PUBLIC_COIN_ROOT_SOURCES),
    ("binding.v3_container_opening_roots_v2", _V3_ROOT_SOURCES),
)

_STATIC_TERM_IDS: Final[tuple[str, ...]] = (
    "composition.h4_iopp_target_envelope",
    "composition.selected_dynamic_algebraic_budget",
    "hiding.construction_8_2_mechanics",
    "hiding.selected_native_complete_simulator",
    "sampler.field_out_of_range_rejection",
    "sampler.oods_fp8_rejection",
    "sampler.oods_attempt_cap_exhaustion",
    "sampler.oods_four_attempt_availability_union",
    "sampler.oods_exceptional_denominator",
    "binding.substrate_dual_domain",
    *(term_id for term_id, _ in _ROOT_TERM_GROUPS),
    "authentication.lamport_merkle_collision_component",
    "authentication.chain_preimage_component",
    "authentication.strict_coin_combined_forgery_union",
    "authentication.ml_dsa_87_provenance_only",
    "authentication.slh_dsa_shake_256f_provenance_only",
    "public_coin.governed_attempt_cap",
    "public_coin.exact_two_contributors",
    "public_coin.parser_and_size_caps",
    "public_coin.in_memory_root_reuse_guard",
    "public_coin.durable_atomic_root_consumption",
    "public_coin.honest_reveal_timing",
    "public_coin.global_statement_lifetime",
    "public_coin.cross_key_secret_nonreuse",
    "public_coin.adaptive_abort_grinding",
    "parser.binding_multiproof_canonical",
    "parser.h4_v3_binding_root_v2_grammar",
    "resource.strict_bundle_16mib",
    "resource.h4_root_v2_package",
    "resource.v3_root_v2_envelope",
    "resource.scratch_5gb",
    "ledger.closed_source_universe",
)


def _bits(probability: Fraction) -> float:
    if probability == 0:
        return math.inf
    return math.log2(probability.denominator) - math.log2(probability.numerator)


def _source_manifest() -> tuple[bytes, tuple[SourceEvidence, ...], dict[str, bytes]]:
    if len({contract.relative_path for contract in _SOURCE_CONTRACTS}) != len(_SOURCE_CONTRACTS):
        raise ValueError("h6_security_source_contract_duplicate")
    hasher = hashlib.sha3_512(_DOMAIN + b"sources\x00")
    evidence: list[SourceEvidence] = []
    contents: dict[str, bytes] = {}
    for contract in _SOURCE_CONTRACTS:
        path = ROOT / Path(contract.relative_path)
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"h6_security_source_missing:{contract.relative_path}")
        data = path.read_bytes()
        contents[contract.relative_path] = data
        digest = hashlib.sha3_512(data).digest()
        encoded = contract.relative_path.encode("ascii")
        role = contract.role.value.encode("ascii")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
        hasher.update(len(role).to_bytes(2, "big"))
        hasher.update(role)
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(digest)
        evidence.append(SourceEvidence(contract.relative_path, contract.role, digest))
    return hasher.digest(), tuple(evidence), contents


def _rust_integer(data: bytes, name: str) -> int:
    text = data.decode("utf-8")
    match = re.search(
        rf"pub const {re.escape(name)}\s*:[^=;]+\s*=\s*([0-9][0-9_]*)\s*;",
        text,
    )
    if match is None:
        raise ValueError(f"h6_security_rust_constant_missing:{name}")
    return int(match.group(1).replace("_", ""))


def _require_marker(data: bytes, marker: bytes, label: str) -> None:
    if marker not in data:
        raise ValueError(f"h6_security_source_marker_missing:{label}")


def _derive_parameters(contents: dict[str, bytes]) -> DerivedParameters:
    strict = contents[_STRICT_COIN_SOURCES[0]]
    binding = contents[_BINDING_SUBSTRATE_SOURCES[0]]
    proof_parameters = contents[_ALGEBRAIC_SOURCES[-1]]
    oods = contents[_SAMPLER_SOURCES[1]]
    h4 = contents[_H4_ROOT_SOURCES[0]]

    attempts = _rust_integer(strict, "STRICT_PQ_MAX_ATTEMPTS_V2")
    contributors = _rust_integer(strict, "STRICT_PQ_REQUIRED_CONTRIBUTORS_V2")
    generic_contributors = _rust_integer(strict, "STRICT_PQ_GENERIC_MAX_CONTRIBUTORS_V2")
    ots_instances_log2 = _rust_integer(strict, "STRICT_PQ_GENERIC_OTS_INSTANCES_LOG2_V2")
    if attempts != GOVERNED_ATTEMPTS or attempts <= 0 or attempts & (attempts - 1):
        raise ValueError("h6_security_governed_attempt_cap_mismatch")
    if (
        contributors != 2
        or generic_contributors <= 0
        or generic_contributors & (generic_contributors - 1)
    ):
        raise ValueError("h6_security_contributor_cap_mismatch")
    lifetime_log2 = (
        ots_instances_log2
        - (attempts.bit_length() - 1)
        - (generic_contributors.bit_length() - 1)
    )
    if lifetime_log2 != 64:
        raise ValueError("h6_security_statement_lifetime_mismatch")

    if _rust_integer(binding, "BINDING_V2_BYTES") != 128:
        raise ValueError("h6_security_binding_root_width_mismatch")
    _require_marker(binding, b"BINDING_V2_LEFT_DOMAIN", "binding_left_domain")
    _require_marker(binding, b"BINDING_V2_RIGHT_DOMAIN", "binding_right_domain")
    if _rust_integer(proof_parameters, "PER_TERM_SOUNDNESS_BITS") != TARGET_BITS:
        raise ValueError("h6_security_proof_parameter_target_mismatch")
    _require_marker(
        proof_parameters,
        b"pub const ACTIVATION_ALLOWED: bool = false;",
        "activation_false",
    )

    h4_text = h4.decode("utf-8")
    shard_match = re.search(r"Self::K512\s*=>\s*([0-9_]+)", h4_text)
    segment_match = re.search(
        r"matches!\(segment_count,\s*21\s*\|\s*([0-9_]+)\)", h4_text
    )
    if shard_match is None or segment_match is None:
        raise ValueError("h6_security_h4_target_envelope_missing")
    max_shards = int(shard_match.group(1).replace("_", ""))
    max_segments = int(segment_match.group(1).replace("_", ""))
    if (max_shards, max_segments) != (4, 37):
        raise ValueError("h6_security_h4_target_envelope_changed")

    binding_bytes = _rust_integer(binding, "BINDING_V2_BYTES")
    multiproof_header = _rust_integer(binding, "BINDING_MERKLE_MULTIPROOF_V2_HEADER_BYTES")
    positions = _rust_integer(strict, "STRICT_PQ_LAMPORT_POSITIONS_V2")
    secret_bytes = _rust_integer(strict, "STRICT_PQ_LAMPORT_SECRET_BYTES_V2")
    frontier = _rust_integer(strict, "STRICT_PQ_LAMPORT_FRONTIER_DIGESTS_V2")
    signature_header = _rust_integer(strict, "STRICT_PQ_LAMPORT_SIGNATURE_HEADER_BYTES_V2")
    bundle_header = _rust_integer(strict, "STRICT_PQ_BUNDLE_HEADER_BYTES_V2")
    descriptor_bytes = _rust_integer(strict, "STRICT_PQ_ROUND_DESCRIPTOR_BYTES_V2")
    strict_rounds = _rust_integer(strict, "STRICT_PQ_H4_MAX_ROUNDS_V2")
    _require_marker(
        strict,
        b"STRICT_PQ_MAX_BUNDLE_BYTES_V2: usize = 16 << 20;",
        "strict_bundle_cap",
    )
    maximum_bundle = 16 << 20
    reveal_bytes = positions * secret_bytes
    multiproof_bytes = multiproof_header + positions * 8 + frontier * binding_bytes
    signature_bytes = signature_header + reveal_bytes + multiproof_bytes
    anchor_bytes = 64 + 64 + binding_bytes + signature_bytes
    round_bytes = descriptor_bytes + binding_bytes + contributors * binding_bytes
    h4_bundle_bytes = bundle_header + contributors * anchor_bytes + strict_rounds * round_bytes
    if h4_bundle_bytes != 3_308_688 or h4_bundle_bytes > maximum_bundle:
        raise ValueError("h6_security_strict_bundle_envelope_mismatch")

    max_targets = max_shards * max_segments
    multiplier = (1 << lifetime_log2) * attempts * max_targets
    return DerivedParameters(
        governed_attempts=attempts,
        required_contributors=contributors,
        generic_max_contributors=generic_contributors,
        statement_lifetime_log2=lifetime_log2,
        h4_max_shards=max_shards,
        h4_max_segments_per_shard=max_segments,
        h4_max_iopp_targets_per_attempt=max_targets,
        iopp_lifetime_multiplier=multiplier,
        oods_attempt_cap=_rust_integer(oods, "OODS_DEFAULT_MAX_ATTEMPTS"),
        strict_h4_rounds=strict_rounds,
        strict_h4_bundle_bytes=h4_bundle_bytes,
        strict_max_bundle_bytes=maximum_bundle,
        collision_bound_exponent=_rust_integer(
            strict, "STRICT_PQ_Q128_COLLISION_BOUND_EXPONENT_V2"
        ),
        preimage_bound_exponent=_rust_integer(
            strict, "STRICT_PQ_Q128_PREIMAGE_BOUND_EXPONENT_V2"
        ),
        combined_bound_exponent=_rust_integer(
            strict, "STRICT_PQ_Q128_COMBINED_BOUND_EXPONENT_V2"
        ),
        collision_work_bits=_rust_integer(
            strict, "STRICT_PQ_CONSERVATIVE_COLLISION_WORK_BITS_V2"
        ),
        preimage_work_bits=_rust_integer(
            strict, "STRICT_PQ_CONSERVATIVE_PREIMAGE_WORK_BITS_V2"
        ),
    )


def _iopp_terms() -> tuple[tuple[str, Fraction], ...]:
    field_inverse = Fraction(1, base.FIELD_CARDINALITY)
    nonzero_field_inverse = Fraction(1, base.FIELD_CARDINALITY - 1)
    errors: list[tuple[str, Fraction]] = [
        ("gkr_claim_batch", Fraction(base.GKR_CLAIMS - 1, base.FIELD_CARDINALITY)),
        (
            "packed_coordinate_batch",
            Fraction(base.PACKED_COORDINATES - 1, base.FIELD_CARDINALITY),
        ),
        ("source_mask_batch", field_inverse),
        (
            "quadratic_row_sumcheck",
            Fraction(base.SUMCHECK_ROUNDS * base.SUMCHECK_DEGREE, base.FIELD_CARDINALITY),
        ),
        (
            "state_key_compression_collision",
            Fraction(
                base.STATE_PHASES * base.STATE_CAPACITY * (base.STATE_CAPACITY - 1) // 2,
                base.FIELD_CARDINALITY,
            ),
        ),
        (
            "state_squarefree_identity",
            Fraction(
                base.STATE_PHASES * (2 * base.STATE_CAPACITY - 1),
                base.FIELD_CARDINALITY,
            ),
        ),
        (
            "state_squarefree_sumchecks",
            Fraction(base.STATE_SUMCHECK_DEGREE_BUDGET, base.FIELD_CARDINALITY),
        ),
        (
            "state_squarefree_claim_combinations",
            base.STATE_CLAIM_COMBINATIONS * nonzero_field_inverse,
        ),
        (
            "state_coefficient_claim_combination",
            base.STATE_COEFFICIENT_CLAIM_COMBINATIONS * nonzero_field_inverse,
        ),
        ("initial_list_field", field_inverse),
    ]
    for round_index in range(1, base.SUMCHECK_ROUNDS + 1):
        remaining_interleaving = 1 << (base.SUMCHECK_ROUNDS - round_index)
        errors.append(
            (
                f"sumcheck_round_{round_index}_mca_plus_field",
                Fraction(remaining_interleaving * base.MAIN_BLOCK, base.FIELD_CARDINALITY)
                + Fraction(base.MASK_MESSAGE, base.FIELD_CARDINALITY),
            )
        )
    base_error = Fraction(base.MAIN_BLOCK, base.FIELD_CARDINALITY)
    base_error += Fraction(base.SUMCHECK_ROUNDS * base.MASK_BLOCK, base.FIELD_CARDINALITY)
    base_error += field_inverse
    errors.append(("base_combination", base_error))
    errors.append(
        (
            "spotcheck_max",
            max(
                (1 - base.MAIN_DELTA) ** base.MAIN_QUERIES,
                (1 - base.MASK_DELTA) ** base.MASK_QUERIES,
            ),
        )
    )
    return tuple(errors)


def _term(
    term_id: str,
    effect: LedgerEffect,
    state: LedgerState,
    union_scope: UnionScope,
    sources: tuple[str, ...],
    rationale: str,
    *,
    event_probability: Fraction | None = None,
    instance_multiplier: int = 1,
    work_bits: int | None = None,
) -> LedgerTerm:
    return LedgerTerm(
        term_id=term_id,
        effect=effect,
        state=state,
        union_scope=union_scope,
        event_probability=event_probability,
        instance_multiplier=instance_multiplier,
        work_bits=work_bits,
        sources=sources,
        rationale=rationale,
    )


def _root_migration_rationale(sources: tuple[str, ...], contents: dict[str, bytes]) -> str:
    without_v2_reference = sum(b"BindingRootV2" not in contents[source] for source in sources)
    return (
        f"{without_v2_reference}/{len(sources)} inventoried sources have no BindingRootV2 "
        "reference; even zero requires reviewed encoder/decoder/transcript ownership before closure"
    )


def _build_terms(
    parameters: DerivedParameters,
    contents: dict[str, bytes],
) -> tuple[LedgerTerm, ...]:
    iopp_sources = _ALGEBRAIC_SOURCES + _PCS_GKR_SOURCES + (_H4_ROOT_SOURCES[0],)
    terms = [
        _term(
            f"iopp.{label}",
            LedgerEffect.ACCEPTANCE,
            LedgerState.VERIFIED,
            UnionScope.CHARGED,
            iopp_sources,
            "Exact Theorem 8.1 component charged over 2^64 statements, four attempts, four K512 shards, and 37 segments.",
            event_probability=probability,
            instance_multiplier=parameters.iopp_lifetime_multiplier,
        )
        for label, probability in _iopp_terms()
    ]
    field_cardinality = ((1 << 31) - 1) ** 16
    if base.FIELD_CARDINALITY != field_cardinality:
        raise ValueError("h6_security_field_cardinality_mismatch")
    acceptance_limit = (1 << 16) * field_cardinality
    out_of_range = Fraction((1 << 512) - acceptance_limit, 1 << 512)
    fp8_rejection = Fraction(1, ((1 << 31) - 1) ** 8)
    oods_one_attempt_rejection = Fraction(
        (1 << 512) - (1 << 16) * (field_cardinality - ((1 << 31) - 1) ** 8),
        1 << 512,
    )
    oods_cap_exhaustion = oods_one_attempt_rejection ** parameters.oods_attempt_cap

    terms.extend(
        (
            _term(
                "composition.h4_iopp_target_envelope",
                LedgerEffect.EXTERNAL_ASSUMPTION,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.GATE,
                (_ALGEBRAIC_SOURCES[0], _H4_ROOT_SOURCES[0]),
                "The 4-shard x 37-segment charge is conservative and machine-derived, but its exact reduction to Theorem 8.1 targets still requires reviewed composition ownership.",
            ),
            _term(
                "composition.selected_dynamic_algebraic_budget",
                LedgerEffect.ACCEPTANCE,
                LedgerState.PENDING_MIGRATION,
                UnionScope.CHARGED,
                (_ALGEBRAIC_SOURCES[-1], _H4_ROOT_SOURCES[0]),
                "The selected program derives LogUp, composition, DEEP, FRI-batch, and fold numerators dynamically; exact K128/K512 materialization is not in this ledger yet.",
            ),
            _term(
                "hiding.construction_8_2_mechanics",
                LedgerEffect.PRIVACY,
                LedgerState.VERIFIED,
                UnionScope.GATE,
                (_HIDING_SOURCES[0],) + _PCS_GKR_SOURCES,
                "The executable conditioned-view KAT covers the legacy Construction 8.2 mechanics and reports zero statistical hiding error for that model.",
            ),
            _term(
                "hiding.selected_native_complete_simulator",
                LedgerEffect.PRIVACY,
                LedgerState.PENDING_MIGRATION,
                UnionScope.GATE,
                (_HIDING_SOURCES[1], _ALGEBRAIC_SOURCES[-1]),
                "Native hiding declares four final coverage gaps and simulator_complete=false; no activation credit is taken.",
            ),
            _term(
                "sampler.field_out_of_range_rejection",
                LedgerEffect.AVAILABILITY,
                LedgerState.FAIL_CLOSED,
                UnionScope.EXCLUDED,
                _SAMPLER_SOURCES,
                "A digest at or above 2^16*p^16 is rejected before reduction; this changes availability only.",
                event_probability=out_of_range,
            ),
            _term(
                "sampler.oods_fp8_rejection",
                LedgerEffect.AVAILABILITY,
                LedgerState.FAIL_CLOSED,
                UnionScope.EXCLUDED,
                _SAMPLER_SOURCES,
                "Conditional on a uniform Fp16 draw, membership in Fp8 has exact probability 1/p^8 and is rejected before OodsParameter exists.",
                event_probability=fp8_rejection,
            ),
            _term(
                "sampler.oods_attempt_cap_exhaustion",
                LedgerEffect.AVAILABILITY,
                LedgerState.FAIL_CLOSED,
                UnionScope.EXCLUDED,
                _SAMPLER_SOURCES,
                "All 16 internal draws reject; sample_oods_parameter returns AttemptCapExhausted and no proof is accepted.",
                event_probability=oods_cap_exhaustion,
            ),
            _term(
                "sampler.oods_four_attempt_availability_union",
                LedgerEffect.AVAILABILITY,
                LedgerState.FAIL_CLOSED,
                UnionScope.EXCLUDED,
                _SAMPLER_SOURCES + (_STRICT_COIN_SOURCES[0],),
                "Union bound for an OODS cap exhaustion in any of four governed proof attempts; aborts remain fail closed.",
                event_probability=oods_cap_exhaustion * parameters.governed_attempts,
            ),
            _term(
                "sampler.oods_exceptional_denominator",
                LedgerEffect.ACCEPTANCE,
                LedgerState.VERIFIED,
                UnionScope.CHARGED,
                _SAMPLER_SOURCES + (_ALGEBRAIC_SOURCES[2],),
                "Roots of 1+t^2 lie in Fp2 subset Fp8; the validated Fp16\\Fp8 type excludes them before inversion.",
                event_probability=Fraction(0, 1),
                instance_multiplier=parameters.iopp_lifetime_multiplier,
            ),
            _term(
                "binding.substrate_dual_domain",
                LedgerEffect.EXTERNAL_ASSUMPTION,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.GATE,
                _BINDING_SUBSTRATE_SOURCES,
                "The 128-byte substrate is implemented, but additive dual-lane strength requires the explicit independent-domain ideal-sponge/QROM theorem and its concrete constants.",
            ),
        )
    )
    for term_id, sources in _ROOT_TERM_GROUPS:
        terms.append(
            _term(
                term_id,
                LedgerEffect.ACCEPTANCE,
                LedgerState.PENDING_MIGRATION,
                UnionScope.CHARGED,
                sources + _BINDING_SUBSTRATE_SOURCES,
                _root_migration_rationale(sources, contents),
            )
        )
    terms.extend(
        (
            _term(
                "authentication.lamport_merkle_collision_component",
                LedgerEffect.ACCEPTANCE,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.SUPPORTING,
                _STRICT_COIN_SOURCES[:1] + _BINDING_SUBSTRATE_SOURCES,
                "Generic malicious-prover collision component, already unioned over the strict source's lifetime target ceiling.",
                event_probability=Fraction(1, 1 << parameters.collision_bound_exponent),
                work_bits=parameters.collision_work_bits,
            ),
            _term(
                "authentication.chain_preimage_component",
                LedgerEffect.ACCEPTANCE,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.SUPPORTING,
                _STRICT_COIN_SOURCES[:1] + _BINDING_SUBSTRATE_SOURCES,
                "Fixed-target Lamport/chain preimage component after the signed head is fixed.",
                event_probability=Fraction(1, 1 << parameters.preimage_bound_exponent),
                work_bits=parameters.preimage_work_bits,
            ),
            _term(
                "authentication.strict_coin_combined_forgery_union",
                LedgerEffect.ACCEPTANCE,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.CHARGED,
                _STRICT_COIN_SOURCES[:1] + _BINDING_SUBSTRATE_SOURCES,
                "Conservative combined Lamport, Merkle, message-binding, and chain bound under unit-leading-constant independent-domain ideal-sponge/QROM assumptions.",
                event_probability=Fraction(1, 1 << parameters.combined_bound_exponent),
                work_bits=min(parameters.collision_work_bits, parameters.preimage_work_bits),
            ),
            _term(
                "authentication.ml_dsa_87_provenance_only",
                LedgerEffect.PROVENANCE,
                LedgerState.NOT_CREDITED,
                UnionScope.EXCLUDED,
                _PUBLIC_COIN_ROOT_SOURCES,
                "ML-DSA-87 signatures remain provenance metadata; category labels provide no exact >=256-bit acceptance reduction.",
            ),
            _term(
                "authentication.slh_dsa_shake_256f_provenance_only",
                LedgerEffect.PROVENANCE,
                LedgerState.NOT_CREDITED,
                UnionScope.EXCLUDED,
                _PUBLIC_COIN_ROOT_SOURCES,
                "SLH-DSA-SHAKE-256f signatures remain provenance metadata and are not multiplied with ML-DSA.",
            ),
            _term(
                "public_coin.governed_attempt_cap",
                LedgerEffect.IMPLEMENTATION,
                LedgerState.VERIFIED,
                UnionScope.GATE,
                _STRICT_COIN_SOURCES[:1],
                "Parser, key context, encoder, and replay verifier reject attempt indices outside 0..4.",
            ),
            _term(
                "public_coin.exact_two_contributors",
                LedgerEffect.IMPLEMENTATION,
                LedgerState.VERIFIED,
                UnionScope.GATE,
                _STRICT_COIN_SOURCES[:1],
                "The governed verifier key requires exactly two independent custody lanes.",
            ),
            _term(
                "public_coin.parser_and_size_caps",
                LedgerEffect.IMPLEMENTATION,
                LedgerState.VERIFIED,
                UnionScope.GATE,
                _STRICT_COIN_SOURCES[:1],
                "Canonical parser caps 16 contributors, 2^16 rounds, and 16 MiB before allocation; governed H4 caps at 7,059 rounds.",
            ),
            _term(
                "public_coin.in_memory_root_reuse_guard",
                LedgerEffect.IMPLEMENTATION,
                LedgerState.VERIFIED,
                UnionScope.GATE,
                _STRICT_COIN_SOURCES[:1],
                "The pure module rejects a second root for a statement/contributor/attempt slot in one registry instance.",
            ),
            _term(
                "public_coin.durable_atomic_root_consumption",
                LedgerEffect.EXTERNAL_ASSUMPTION,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.GATE,
                _STRICT_COIN_SOURCES,
                "Crash-safe DB/custody must atomically consume exact root/index/attempt slots, including aborts; the pure in-memory registry is insufficient.",
            ),
            _term(
                "public_coin.honest_reveal_timing",
                LedgerEffect.EXTERNAL_ASSUMPTION,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.GATE,
                _STRICT_COIN_SOURCES,
                "At least one governed lane must keep its reveal secret until the prover message is immutably fixed.",
            ),
            _term(
                "public_coin.global_statement_lifetime",
                LedgerEffect.EXTERNAL_ASSUMPTION,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.GATE,
                _STRICT_COIN_SOURCES,
                "A nonresetting globally governed counter must enforce at most 2^64 statements per key lifetime.",
            ),
            _term(
                "public_coin.cross_key_secret_nonreuse",
                LedgerEffect.EXTERNAL_ASSUMPTION,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.GATE,
                _STRICT_COIN_SOURCES,
                "Custody must prevent Lamport secret reuse across keys; the pure key builder detects duplicates only within one supplied key.",
            ),
            _term(
                "public_coin.adaptive_abort_grinding",
                LedgerEffect.EXTERNAL_ASSUMPTION,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.GATE,
                _STRICT_COIN_SOURCES,
                "The four-attempt union is sound only when every aborted attempt is durably consumed and cannot be replayed or forked.",
            ),
            _term(
                "parser.binding_multiproof_canonical",
                LedgerEffect.IMPLEMENTATION,
                LedgerState.VERIFIED,
                UnionScope.GATE,
                _BINDING_SUBSTRATE_SOURCES,
                "BindingRootV2 multiproofs reject noncanonical indices, frontier lengths, flags, versions, trailing bytes, and oversized shapes.",
            ),
            _term(
                "parser.h4_v3_binding_root_v2_grammar",
                LedgerEffect.IMPLEMENTATION,
                LedgerState.PENDING_MIGRATION,
                UnionScope.GATE,
                _H4_ROOT_SOURCES + _V3_ROOT_SOURCES + _PUBLIC_COIN_ROOT_SOURCES,
                "H4/v3 encoders, decoders, and transcript fields still carry legacy 64-byte acceptance roots.",
            ),
            _term(
                "resource.strict_bundle_16mib",
                LedgerEffect.IMPLEMENTATION,
                LedgerState.VERIFIED,
                UnionScope.GATE,
                _STRICT_COIN_SOURCES[:1],
                f"Exact governed bundle is {parameters.strict_h4_bundle_bytes} bytes, below the {parameters.strict_max_bundle_bytes}-byte cap.",
            ),
            _term(
                "resource.h4_root_v2_package",
                LedgerEffect.IMPLEMENTATION,
                LedgerState.PENDING_MIGRATION,
                UnionScope.GATE,
                _H4_ROOT_SOURCES + _RESOURCE_SOURCES,
                "Derived compact cores fit the fixed 192 MiB shard body, but migrated grammar bytes and resource preflight have not been implemented and rerun.",
            ),
            _term(
                "resource.v3_root_v2_envelope",
                LedgerEffect.IMPLEMENTATION,
                LedgerState.PENDING_MIGRATION,
                UnionScope.GATE,
                _V3_ROOT_SOURCES + _RESOURCE_SOURCES,
                "Derived K128/K512 totals fit 2 GiB, but fixed component sizes and the missing 512-byte H4 aggregate-header accounting require code migration and verification.",
            ),
            _term(
                "resource.scratch_5gb",
                LedgerEffect.EXTERNAL_ASSUMPTION,
                LedgerState.PENDING_EXTERNAL,
                UnionScope.GATE,
                _RESOURCE_SOURCES + _H4_ROOT_SOURCES,
                "The generic selected disk route already exceeds 5 GB; the qualifying H4 route needs a fresh BindingRootV2 measurement before any claim.",
            ),
            _term(
                "ledger.closed_source_universe",
                LedgerEffect.IMPLEMENTATION,
                LedgerState.VERIFIED,
                UnionScope.GATE,
                _LEDGER_SOURCES,
                "Every term source is a typed contract, every contract is used, and unknown terms, sources, effects, states, or union scopes reject.",
            ),
        )
    )
    return tuple(terms)


def _expected_term_ids() -> tuple[str, ...]:
    return tuple(f"iopp.{label}" for label, _ in _iopp_terms()) + _STATIC_TERM_IDS


def _validate_closed_universe(
    sources: tuple[SourceEvidence, ...],
    terms: tuple[LedgerTerm, ...],
) -> None:
    registered_sources = {contract.relative_path for contract in _SOURCE_CONTRACTS}
    actual_sources = {source.relative_path for source in sources}
    if actual_sources != registered_sources or len(actual_sources) != len(sources):
        raise ValueError("h6_security_source_universe_mismatch")
    if any(not isinstance(source.role, SourceRole) for source in sources):
        raise ValueError("h6_security_source_role_unknown")
    expected_ids = _expected_term_ids()
    actual_ids = tuple(term.term_id for term in terms)
    if len(set(actual_ids)) != len(actual_ids) or set(actual_ids) != set(expected_ids):
        raise ValueError("h6_security_term_universe_mismatch")
    used_sources: set[str] = set()
    term_id_pattern = re.compile(r"[a-z0-9_]+(?:\.[a-z0-9_]+)+")
    for term in terms:
        if (
            not term_id_pattern.fullmatch(term.term_id)
            or not isinstance(term.effect, LedgerEffect)
            or not isinstance(term.state, LedgerState)
            or not isinstance(term.union_scope, UnionScope)
        ):
            raise ValueError("h6_security_term_classification_unknown")
        if not term.sources or not set(term.sources) <= registered_sources:
            raise ValueError("h6_security_term_source_unknown")
        used_sources.update(term.sources)
        if term.instance_multiplier < 1:
            raise ValueError("h6_security_term_multiplier_invalid")
        if term.event_probability is not None and not (0 <= term.event_probability <= 1):
            raise ValueError("h6_security_term_probability_invalid")
        if term.effect is LedgerEffect.AVAILABILITY:
            if term.state is not LedgerState.FAIL_CLOSED or term.union_scope is not UnionScope.EXCLUDED:
                raise ValueError("h6_security_availability_not_fail_closed")
        if term.effect is LedgerEffect.PROVENANCE:
            if term.state is not LedgerState.NOT_CREDITED or term.union_scope is not UnionScope.EXCLUDED:
                raise ValueError("h6_security_provenance_credited")
        if (
            term.effect is LedgerEffect.ACCEPTANCE
            and term.charged_bits is not None
            and term.charged_bits < TARGET_BITS
        ):
            raise ValueError(f"h6_security_acceptance_term_below_target:{term.term_id}")
    if used_sources != registered_sources:
        missing = sorted(registered_sources - used_sources)
        raise ValueError(f"h6_security_unclassified_source:{','.join(missing)}")


def _append_integer(digest: hashlib._Hash, value: int) -> None:
    width = max(1, (value.bit_length() + 7) // 8)
    digest.update(width.to_bytes(4, "big"))
    digest.update(value.to_bytes(width, "big"))


def _ledger_digest(ledger: H6SecurityLedger) -> bytes:
    digest = hashlib.sha3_512(_DOMAIN + b"ledger\x00")
    digest.update(ledger.status.encode("ascii"))
    _append_integer(digest, ledger.target_bits)
    for value in (
        ledger.parameters.governed_attempts,
        ledger.parameters.required_contributors,
        ledger.parameters.generic_max_contributors,
        ledger.parameters.statement_lifetime_log2,
        ledger.parameters.h4_max_shards,
        ledger.parameters.h4_max_segments_per_shard,
        ledger.parameters.h4_max_iopp_targets_per_attempt,
        ledger.parameters.iopp_lifetime_multiplier,
        ledger.parameters.oods_attempt_cap,
        ledger.parameters.strict_h4_rounds,
        ledger.parameters.strict_h4_bundle_bytes,
        ledger.parameters.strict_max_bundle_bytes,
        ledger.parameters.collision_bound_exponent,
        ledger.parameters.preimage_bound_exponent,
        ledger.parameters.combined_bound_exponent,
        ledger.parameters.collision_work_bits,
        ledger.parameters.preimage_work_bits,
    ):
        _append_integer(digest, value)
    for source in ledger.sources:
        digest.update(source.relative_path.encode("ascii"))
        digest.update(source.role.value.encode("ascii"))
        digest.update(source.sha3_512)
    for term in ledger.terms:
        digest.update(term.term_id.encode("ascii"))
        digest.update(term.effect.value.encode("ascii"))
        digest.update(term.state.value.encode("ascii"))
        digest.update(term.union_scope.value.encode("ascii"))
        if term.event_probability is None:
            digest.update(b"\x00")
        else:
            digest.update(b"\x01")
            _append_integer(digest, term.event_probability.numerator)
            _append_integer(digest, term.event_probability.denominator)
        _append_integer(digest, term.instance_multiplier)
        _append_integer(digest, 0 if term.work_bits is None else term.work_bits + 1)
        for source in term.sources:
            digest.update(source.encode("ascii"))
        digest.update(term.rationale.encode("ascii"))
    digest.update(ledger.source_manifest_sha3_512)
    return digest.digest()


def build_h6_security_ledger() -> H6SecurityLedger:
    source_manifest, sources, contents = _source_manifest()
    parameters = _derive_parameters(contents)
    terms = _build_terms(parameters, contents)
    _validate_closed_universe(sources, terms)
    iopp = sum((probability for _, probability in _iopp_terms()), Fraction(0, 1))
    known = sum(
        (
            term.charged_probability
            for term in terms
            if term.effect is LedgerEffect.ACCEPTANCE
            and term.charged_probability is not None
        ),
        Fraction(0, 1),
    )
    verified = sum(
        (
            term.charged_probability
            for term in terms
            if term.effect is LedgerEffect.ACCEPTANCE
            and term.state is LedgerState.VERIFIED
            and term.charged_probability is not None
        ),
        Fraction(0, 1),
    )
    provisional = H6SecurityLedger(
        status=STATUS,
        target_bits=TARGET_BITS,
        parameters=parameters,
        sources=sources,
        terms=terms,
        iopp_per_target_error=iopp,
        iopp_per_target_bits=_bits(iopp),
        known_acceptance_error=known,
        known_acceptance_bits=_bits(known),
        verified_acceptance_error=verified,
        verified_acceptance_bits=_bits(verified),
        source_manifest_sha3_512=source_manifest,
        ledger_digest_sha3_512=b"",
    )
    return H6SecurityLedger(
        status=provisional.status,
        target_bits=provisional.target_bits,
        parameters=provisional.parameters,
        sources=provisional.sources,
        terms=provisional.terms,
        iopp_per_target_error=provisional.iopp_per_target_error,
        iopp_per_target_bits=provisional.iopp_per_target_bits,
        known_acceptance_error=provisional.known_acceptance_error,
        known_acceptance_bits=provisional.known_acceptance_bits,
        verified_acceptance_error=provisional.verified_acceptance_error,
        verified_acceptance_bits=provisional.verified_acceptance_bits,
        source_manifest_sha3_512=provisional.source_manifest_sha3_512,
        ledger_digest_sha3_512=_ledger_digest(provisional),
    )


def require_h6_security_ledger() -> H6SecurityLedger:
    ledger = build_h6_security_ledger()
    if not ledger.qualifies:
        raise ValueError(
            "h6_security_ledger_incomplete:" + ",".join(ledger.qualification_blockers)
        )
    return ledger


__all__: tuple[str, ...] = (
    "ACTIVATION_ALLOWED",
    "GOVERNED_ATTEMPTS",
    "H6SecurityLedger",
    "LedgerEffect",
    "LedgerState",
    "LedgerTerm",
    "PRODUCTION_USABLE",
    "PROOF_SUITE_ID",
    "STATUS",
    "SourceEvidence",
    "SourceRole",
    "TARGET_BITS",
    "UnionScope",
    "build_h6_security_ledger",
    "require_h6_security_ledger",
)
