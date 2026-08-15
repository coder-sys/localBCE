"""Auditable Wave 1B inventory of application SHA3-512 call sites and work.

The R33 physical relation deliberately left SHA3-512 as an abstract port.  A
raw host profile is not a safe replacement for that port: fixture building,
public constant construction, verifier recomputation, and evidence hashing all
use the same ``hashlib.sha3_512`` symbol.  This module freezes an explicit
classification of every scoped static call site and reconciles one complete
K128 relation-verifier recomputation by call site and preimage length.

The K128 result is retained as a historical, nonactivating fresh-process
measurement of the old 51*K oracle relation.  It was superseded by the packed
one-bundle-per-claim schedule in ``application_sha3_shared_schedule``.  Keeping
the raw observation here makes the optimization auditable; it must not be used
as a current theorem or parameter-selection input.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha3_512
import json
from pathlib import Path
from types import MappingProxyType
from typing import Final, Mapping, Sequence


STATUS: Final[str] = (
    "WAVE1B_HISTORICAL_51XK_SHA3_PORT_MEASUREMENT_"
    "SUPERSEDED_BY_PACKED_ORACLE_SCHEDULE_NONACTIVATING"
)
RATE_BYTES: Final[int] = 72
KECCAK_ROUNDS_PER_PERMUTATION: Final[int] = 24
GOVERNED_SOURCE_DIRECTORIES: Final[tuple[str, ...]] = (
    "app/batch",
    "experiments/fixed_shape_claim_air",
)


class PortDisposition(StrEnum):
    """Whether one static SHA3 call belongs in the Wave 1B application AIR."""

    AIR_REQUIRED = "AIR_REQUIRED"
    PUBLIC_PRECOMPUTED = "PUBLIC_PRECOMPUTED"
    HOST_EVIDENCE_ONLY = "HOST_EVIDENCE_ONLY"
    WAVE1C_VERIFIER_STATE = "WAVE1C_VERIFIER_STATE"
    SUPERSEDED_REFERENCE = "SUPERSEDED_REFERENCE"


@dataclass(frozen=True, order=True, slots=True)
class CallsiteId:
    path: str
    qualified_name: str
    ordinal: int = 0

    def __post_init__(self) -> None:
        if type(self.path) is not str or not self.path.endswith(".py"):
            raise ValueError("sha3_inventory_callsite_path_invalid")
        if type(self.qualified_name) is not str or not self.qualified_name:
            raise ValueError("sha3_inventory_callsite_name_invalid")
        if type(self.ordinal) is not int or self.ordinal < 0:
            raise ValueError("sha3_inventory_callsite_ordinal_invalid")

    @property
    def stable_id(self) -> str:
        return f"{self.path}:{self.qualified_name}#{self.ordinal}"


@dataclass(frozen=True, slots=True)
class RuntimeObservation:
    callsite: CallsiteId
    preimage_bytes: int
    invocations: int

    def __post_init__(self) -> None:
        if type(self.preimage_bytes) is not int or self.preimage_bytes < 0:
            raise ValueError("sha3_inventory_preimage_length_invalid")
        if type(self.invocations) is not int or self.invocations <= 0:
            raise ValueError("sha3_inventory_invocation_count_invalid")

    @property
    def permutations_per_invocation(self) -> int:
        return sha3_512_permutation_count(self.preimage_bytes)

    @property
    def total_permutations(self) -> int:
        return self.invocations * self.permutations_per_invocation


def _call(path: str, qualified_name: str, ordinal: int = 0) -> CallsiteId:
    return CallsiteId(path, qualified_name, ordinal)


_A = PortDisposition.AIR_REQUIRED
_P = PortDisposition.PUBLIC_PRECOMPUTED
_H = PortDisposition.HOST_EVIDENCE_ONLY
_V = PortDisposition.WAVE1C_VERIFIER_STATE
_S = PortDisposition.SUPERSEDED_REFERENCE


# This is deliberately exhaustive.  Tests rescan the source AST and reject an
# added, removed, or renamed SHA3 call until it receives an explicit review
# classification here.
CALLSITE_DISPOSITIONS: Final[Mapping[CallsiteId, PortDisposition]] = MappingProxyType(
    {
        _call("app/batch/pq_nullifier_derivation.py", "pepper_commitment_sha3_512"): _A,
        _call("app/batch/pq_nullifier_derivation.py", "derive_attempt_nullifiers_v1"): _A,
        _call("app/batch/pq_nullifier_derivation.py", "derive_cover_nullifiers_v1"): _A,
        _call("app/batch/pq_nullifier_derivation.py", "derive_cover_nullifiers_v2"): _A,
        _call("app/batch/pq_sparse_tree_reference.py", "_wide"): _A,
        _call("app/batch/pq_state_reference.py", "_hash_record"): _V,
        _call("app/batch/pq_strong_nullifier_reference.py", "_leaf_hash"): _A,
        _call("app/batch/pq_strong_nullifier_reference.py", "_node_hash"): _A,
        _call("app/batch/pq_suite_candidate.py", "candidate_salt_use_tag"): _A,
        _call("app/batch/pq_suite_candidate.py", "canonical_registry_sha3_512"): _P,
        _call("app/batch/pq_tree_reference.py", "<module>"): _P,
        _call("app/batch/pq_tree_reference.py", "_wide_digest"): _A,
        _call(
            "app/batch/pq_tree_reference.py",
            "_derive_dual_tree_reference_and_levels",
        ): _H,
        _call(
            "app/batch/pq_verifier_reference.py",
            "SyntheticActiveRegistryV1.__post_init__",
        ): _V,
        _call(
            "app/batch/pq_verifier_reference.py",
            "SyntheticActiveRegistryV1._validate_integrity",
        ): _V,
        _call(
            "app/batch/pq_verifier_reference.py",
            "reference_candidate_strong_batch_commitment",
        ): _V,
        _call(
            "app/batch/pq_verifier_reference.py",
            "SyntheticStrongVerifierAuthorityV1.__init__",
        ): _V,
        _call(
            "app/batch/pq_verifier_reference.py",
            "SyntheticStrongVerifierAuthorityV1.build_synthetic_proof",
        ): _V,
        _call(
            "app/batch/pq_verifier_reference.py",
            "SyntheticStrongVerifierAuthorityV1.verify",
        ): _V,
        _call("app/batch/verifier_receipt.py", "VerifierReceiptIssuer.issue"): _V,
        _call(
            "app/batch/verifier_receipt.py",
            "LocalSyntheticVerifierAdapter.__init__",
        ): _V,
        _call(
            "experiments/fixed_shape_claim_air/a12_nullifier_executable_air.py",
            "build_a12_nullifier_executable_air",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/air_binary_ir.py",
            "air_binary_commitment",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/air_binary_ir.py",
            "air_program_commitment",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/air_streaming_ir.py",
            "StreamingAirManifest.commitment_512",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/air_streaming_ir.py",
            "streaming_column_commitment",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/application_sha3_executable_air.py",
            "build_application_sha3_interface_air",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "<module>",
            0,
        ): _P,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "<module>",
            1,
        ): _P,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "BenefitScopeV1.commitment_512",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "_map_key",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "member_benefit_key",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "provider_payable_key",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "provider_obligation_key",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "_dummy_key",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "AuthenticatedPaymentMapState.root",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "_operation_commitment",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "build_authenticated_payment_map_transition",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_reference.py",
            "AuthenticatedPaymentState.root",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_reference.py",
            "payment_operation_commitment",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_reference.py",
            "_next_payment_state",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/authenticated_replay_state_reference.py",
            "replay_state_root",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/claim_payment_maps_executable_air.py",
            "_payment_key_sha3",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/claim_payment_maps_executable_air.py",
            "_payment_log_sha3",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/executable_air.py",
            "AirProgram.commitment",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/executable_air.py",
            "_trace_commitment",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/executable_air.py",
            "evaluate_serialized",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/integrated_state_reference.py",
            "_registry_root",
        ): _V,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_reference.py",
            "OrderedMapLeaf.digest",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_reference.py",
            "_node_hash",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_reference.py",
            "ordered_map_state_root",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/integrated_state_reference.py",
            "_snapshot_for",
        ): _V,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_batch_executable_air.py",
            "_node_rows",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_batch_reference.py",
            "OrderedMapHashCall.__post_init__",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_batch_reference.py",
            "ordered_map_batch_schedule_commitment",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_batch_reference.py",
            "ordered_map_hash_schedule_commitment",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_batch_reference.py",
            "_multiproof_root",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_batch_reference.py",
            "build_ordered_map_hash_schedule",
            0,
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_batch_reference.py",
            "build_ordered_map_hash_schedule",
            1,
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/ordered_map_batch_reference.py",
            "build_ordered_map_hash_schedule",
            2,
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/hash_bus_snapshot.py",
            "_encode_snapshot",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/hash_bus_snapshot.py",
            "_port_commitment",
            0,
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/hash_bus_snapshot.py",
            "_port_commitment",
            1,
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/hash_bus_snapshot.py",
            "state_composed_descriptor_commitment",
            0,
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/hash_bus_snapshot.py",
            "state_composed_descriptor_commitment",
            1,
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/payment_state.py",
            "reference_payment_state_root",
        ): _S,
        _call(
            "experiments/fixed_shape_claim_air/payment_state.py",
            "reference_slot_operation_commitment",
        ): _S,
        _call(
            "experiments/fixed_shape_claim_air/payment_state.py",
            "append_reference_operation_log",
        ): _S,
        _call(
            "experiments/fixed_shape_claim_air/physical_air_reference.py",
            "build_wave1a_physical_air_program",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/physical_air_reference.py",
            "_slot_binding",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/physical_air_reference.py",
            "build_wave1a_physical_relation_trace",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/replay_ordered_map_executable_air.py",
            "<module>",
        ): _P,
        _call(
            "experiments/fixed_shape_claim_air/sha3_512_executable_air.py",
            "sha3_512_trace_rows_commitment",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/semantic_bus_binding_air.py",
            "SemanticBusBridgeProgram.commitment_512",
        ): _S,
        _call(
            "experiments/fixed_shape_claim_air/semantic_bus_binding_air.py",
            "build_synthetic_semantic_h4_bridge",
        ): _S,
        _call(
            "experiments/fixed_shape_claim_air/vector_corpus.py",
            "corpus_sha3_512",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/whole_product_vector_corpus.py",
            "_digest",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/whole_product_vector_corpus.py",
            "manifest_sha3_512",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/wave1a_global_sha3_capacity_schedule.py",
            "build_wave1a_global_sha3_capacity_schedule",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/wave1a_global_sha3_capacity_schedule.py",
            "build_wave1a_global_sha3_capacity_schedule",
            1,
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/wave1a_global_sha3_schedule.py",
            "build_wave1a_global_sha3_schedule",
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/typed_state_relation_executable_air.py",
            "_authority_columns",
        ): _V,
        _call(
            "experiments/fixed_shape_claim_air/typed_state_relation_executable_air.py",
            "TypedStateRelationAirInstance.relation_digest_512",
        ): _V,
        _call(
            "experiments/fixed_shape_claim_air/wave1a_relation_reference.py",
            "_strong_governance_commitment",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/wave1a_relation_reference.py",
            "_strong_batch_commitment",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/wave1a_relation_reference.py",
            "_derive_replay_values",
            0,
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/wave1a_relation_reference.py",
            "_derive_replay_values",
            1,
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/wave1a_relation_reference.py",
            "_strong_value_commitment",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/wave1a_relation_reference.py",
            "_strong_settlement_commitment",
        ): _A,
        _call(
            "experiments/fixed_shape_claim_air/witness_schema_reference.py",
            "parse_structural_witness_json",
            0,
        ): _H,
        _call(
            "experiments/fixed_shape_claim_air/witness_schema_reference.py",
            "parse_structural_witness_json",
            1,
        ): _H,
    }
)


# These callsites belong to the sealed 51*K measurement below but were
# physically removed by the depth-64 economic-map migration.  They remain
# classified solely so the historical counts are reproducible; the live AST
# inventory above must not require dead code to remain in the repository.
HISTORICAL_REMOVED_DISPOSITIONS: Final[Mapping[CallsiteId, PortDisposition]] = (
    MappingProxyType(
        {
            _call(
                "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
                "_path_index",
            ): _A,
            _call(
                "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
                "_leaf_hash",
            ): _A,
            _call(
                "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
                "_empty_hashes",
                0,
            ): _P,
            _call(
                "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
                "_empty_hashes",
                1,
            ): _P,
            _call(
                "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
                "_SparseMapBuilder._rehash_path",
            ): _A,
        }
    )
)


SCANNED_PATHS: Final[tuple[str, ...]] = tuple(
    sorted({callsite.path for callsite in CALLSITE_DISPOSITIONS})
)


def _obs(
    path: str,
    qualified_name: str,
    preimage_bytes: int,
    invocations: int,
    ordinal: int = 0,
) -> RuntimeObservation:
    return RuntimeObservation(
        _call(path, qualified_name, ordinal), preimage_bytes, invocations
    )


# H0 remeasured every callsite added after the R36 50-port checkpoint.  The
# cover-v2 helper is measured in an isolated exact-call phase because the mixed
# K128 physical fixture derives that same 238-byte preimage inside the composed
# replay relation.  The four payment-key sites are the exact physical-trace
# counts from the fresh phase-separated K128 run.
H0_RECONCILED_ADDITION_MEASUREMENTS: Final[
    tuple[tuple[CallsiteId, str, int, int], ...]
] = (
    (
        _call("app/batch/pq_nullifier_derivation.py", "derive_cover_nullifiers_v2"),
        "ISOLATED_EXACT_HELPER",
        238,
        1,
    ),
    (
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "_dummy_key",
        ),
        "K128_PHYSICAL_TRACE_BUILD",
        169,
        512,
    ),
    (
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "member_benefit_key",
        ),
        "K128_PHYSICAL_TRACE_BUILD",
        139,
        1,
    ),
    (
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "provider_obligation_key",
        ),
        "K128_PHYSICAL_TRACE_BUILD",
        136,
        1,
    ),
    (
        _call(
            "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
            "provider_payable_key",
        ),
        "K128_PHYSICAL_TRACE_BUILD",
        43,
        1,
    ),
)
RECONCILED_ADDITION_WIDTHS: Final[Mapping[str, int]] = MappingProxyType(
    {
        callsite.stable_id: preimage_bytes
        for callsite, _phase, preimage_bytes, _invocations in (
            H0_RECONCILED_ADDITION_MEASUREMENTS
        )
    }
)


# Captured from one isolated build_wave1a_physical_relation_trace call over the
# frozen mixed K128 fixture.  Fixture/context construction and the initial
# relation build were separate phases and are excluded.  All 404,482 observed
# calls reconcile below; none is silently skipped.
K128_PHYSICAL_VERIFIER_OBSERVATIONS: Final[tuple[RuntimeObservation, ...]] = (
    _obs("app/batch/pq_nullifier_derivation.py", "derive_attempt_nullifiers_v1", 136, 2),
    _obs("app/batch/pq_nullifier_derivation.py", "derive_cover_nullifiers_v1", 206, 126),
    _obs("app/batch/pq_sparse_tree_reference.py", "_wide", 190, 3),
    _obs("app/batch/pq_sparse_tree_reference.py", "_wide", 246, 48),
    _obs("app/batch/pq_sparse_tree_reference.py", "_wide", 1310, 3),
    _obs("app/batch/pq_strong_nullifier_reference.py", "_leaf_hash", 196, 34832),
    _obs("app/batch/pq_strong_nullifier_reference.py", "_node_hash", 181, 99304),
    _obs("app/batch/pq_suite_candidate.py", "candidate_salt_use_tag", 78, 1),
    _obs("app/batch/pq_tree_reference.py", "_wide_digest", 234, 12),
    _obs("app/batch/pq_tree_reference.py", "_wide_digest", 235, 1),
    _obs("app/batch/pq_tree_reference.py", "_wide_digest", 302, 138),
    _obs("app/batch/pq_tree_reference.py", "_wide_digest", 480, 3),
    _obs("app/batch/pq_tree_reference.py", "_wide_digest", 570, 6),
    _obs("app/batch/pq_tree_reference.py", "_wide_digest", 1522, 1),
    _obs("app/batch/pq_tree_reference.py", "_wide_digest", 8525, 3),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_empty_hashes",
        50,
        4,
        0,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_empty_hashes",
        51,
        2,
        0,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_empty_hashes",
        179,
        2048,
        1,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_empty_hashes",
        180,
        1024,
        1,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_leaf_hash",
        188,
        5,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_leaf_hash",
        195,
        2,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_leaf_hash",
        211,
        2,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_map_key",
        59,
        1,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_map_key",
        129,
        1,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_map_key",
        139,
        1,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_map_key",
        151,
        381,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_map_key",
        154,
        127,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_operation_commitment",
        688,
        128,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_path_index",
        116,
        262,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_path_index",
        117,
        264,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_SparseMapBuilder._rehash_path",
        179,
        132096,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "_SparseMapBuilder._rehash_path",
        180,
        132608,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "build_authenticated_payment_map_transition",
        167,
        128,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "BenefitScopeV1.commitment_512",
        150,
        9,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_maps_reference.py",
        "AuthenticatedPaymentMapState.root",
        495,
        6,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_reference.py",
        "_next_payment_state",
        181,
        128,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_reference.py",
        "payment_operation_commitment",
        73,
        128,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/authenticated_payment_reference.py",
        "AuthenticatedPaymentState.root",
        165,
        512,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/physical_air_reference.py",
        "_slot_binding",
        629,
        126,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/physical_air_reference.py",
        "_slot_binding",
        630,
        1,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/physical_air_reference.py",
        "_slot_binding",
        632,
        1,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/physical_air_reference.py",
        "build_wave1a_physical_air_program",
        6137,
        1,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/physical_air_reference.py",
        "build_wave1a_physical_relation_trace",
        8938,
        1,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/wave1a_relation_reference.py",
        "_strong_governance_commitment",
        577,
        1,
    ),
    _obs(
        "experiments/fixed_shape_claim_air/wave1a_relation_reference.py",
        "_strong_batch_commitment",
        9733,
        1,
    ),
)


# Nullifier authority construction validates this hash before the measured
# physical-verifier phase.  The circuit must not inherit that host-object trust
# shortcut, so the mandatory constraint is explicitly restored here.
K128_REQUIRED_OUTSIDE_OBSERVED_PHASE: Final[tuple[RuntimeObservation, ...]] = (
    _obs(
        "app/batch/pq_nullifier_derivation.py",
        "pepper_commitment_sha3_512",
        76,
        1,
    ),
)


def sha3_512_permutation_count(preimage_bytes: int) -> int:
    """Return the exact SHA3-512 sponge permutation count for one message."""

    if type(preimage_bytes) is not int or preimage_bytes < 0:
        raise ValueError("sha3_inventory_preimage_length_invalid")
    # SHA3 domain/final padding always consumes one final rate block.  When the
    # final byte is the only free byte, 0x06 and 0x80 combine as 0x86.
    return preimage_bytes // RATE_BYTES + 1


class _Sha3Visitor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.stack: list[str] = []
        self.counts: dict[str, int] = {}
        self.callsites: list[CallsiteId] = []
        self.sha3_aliases: set[str] = set()
        self.hashlib_aliases: set[str] = set()
        self.hashlib_new_aliases: set[str] = set()
        self.noncanonical_forms: list[str] = []

    def _reject(self, node: ast.AST, form: str) -> None:
        self.noncanonical_forms.append(
            f"{self.path}:{getattr(node, 'lineno', 0)}:{form}"
        )

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            if alias.name == "hashlib":
                self.hashlib_aliases.add(alias.asname or "hashlib")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module == "hashlib":
            for alias in node.names:
                local_name = alias.asname or alias.name
                if alias.name == "sha3_512":
                    if alias.asname is not None:
                        self.sha3_aliases.add(local_name)
                        self._reject(node, "aliased_sha3_512_import")
                elif alias.name == "new":
                    self.hashlib_new_aliases.add(local_name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        function = node.func
        is_canonical_sha3 = isinstance(function, ast.Name) and function.id == "sha3_512"
        if is_canonical_sha3:
            qualified = ".".join(self.stack) or "<module>"
            ordinal = self.counts.get(qualified, 0)
            self.counts[qualified] = ordinal + 1
            self.callsites.append(CallsiteId(self.path, qualified, ordinal))
        elif isinstance(function, ast.Name) and function.id in self.sha3_aliases:
            self._reject(node, "aliased_sha3_512_call")
        elif isinstance(function, ast.Attribute) and function.attr == "sha3_512":
            if (
                isinstance(function.value, ast.Name)
                and function.value.id in self.hashlib_aliases
            ):
                self._reject(node, "hashlib_attribute_sha3_512_call")
            elif (
                isinstance(function.value, ast.Call)
                and isinstance(function.value.func, ast.Name)
                and function.value.func.id == "__import__"
                and function.value.args
                and isinstance(function.value.args[0], ast.Constant)
                and function.value.args[0].value == "hashlib"
            ):
                self._reject(node, "dynamic_import_sha3_512_call")
            else:
                self._reject(node, "noncanonical_attribute_sha3_512_call")
        elif (
            (
                isinstance(function, ast.Attribute)
                and function.attr == "new"
                and isinstance(function.value, ast.Name)
                and function.value.id in self.hashlib_aliases
            )
            or (
                isinstance(function, ast.Name)
                and function.id in self.hashlib_new_aliases
            )
        ):
            if (
                node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "sha3_512"
            ):
                self._reject(node, "hashlib_new_sha3_512_call")
        elif (
            isinstance(function, ast.Name)
            and function.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "sha3_512"
        ):
            self._reject(node, "dynamic_getattr_sha3_512")
        self.generic_visit(node)


def scan_scoped_sha3_callsites(repository_root: Path) -> tuple[CallsiteId, ...]:
    """Independently rescan every governed source directory for SHA3 calls."""

    if not isinstance(repository_root, Path):
        raise TypeError("sha3_inventory_repository_root_path_required")
    observed: list[CallsiteId] = []
    noncanonical_forms: list[str] = []
    governed_files: list[tuple[str, Path]] = []
    for relative_directory in GOVERNED_SOURCE_DIRECTORIES:
        source_directory = repository_root / relative_directory
        if not source_directory.is_dir():
            raise ValueError(
                "sha3_inventory_governed_source_directory_missing:"
                f"{relative_directory}"
            )
        governed_files.extend(
            (path.relative_to(repository_root).as_posix(), path)
            for path in source_directory.rglob("*.py")
            if path.is_file()
        )
    for relative, source_path in sorted(governed_files):
        source = source_path.read_text(encoding="utf-8")
        visitor = _Sha3Visitor(relative)
        visitor.visit(ast.parse(source, filename=relative))
        observed.extend(visitor.callsites)
        noncanonical_forms.extend(visitor.noncanonical_forms)
    if noncanonical_forms:
        raise ValueError(
            "sha3_inventory_noncanonical_form:"
            f"forms={sorted(noncanonical_forms)}"
        )
    return tuple(sorted(observed))


def _observations_for(disposition: PortDisposition) -> tuple[RuntimeObservation, ...]:
    dispositions = {**HISTORICAL_REMOVED_DISPOSITIONS, **CALLSITE_DISPOSITIONS}
    return tuple(
        value
        for value in K128_PHYSICAL_VERIFIER_OBSERVATIONS
        if dispositions[value.callsite] is disposition
    )


def k128_inventory_summary() -> dict[str, object]:
    air_observed = _observations_for(PortDisposition.AIR_REQUIRED)
    air_complete = air_observed + K128_REQUIRED_OUTSIDE_OBSERVED_PHASE
    public = _observations_for(PortDisposition.PUBLIC_PRECOMPUTED)
    host = _observations_for(PortDisposition.HOST_EVIDENCE_ONLY)
    counts = {
        value.value: sum(1 for observed in CALLSITE_DISPOSITIONS.values() if observed is value)
        for value in PortDisposition
    }
    return {
        "status": STATUS,
        "staticInventoryCurrent": True,
        "comprehensiveSourceScopeCurrent": True,
        "governedSourceDirectories": list(GOVERNED_SOURCE_DIRECTORIES),
        "measurementCurrent": False,
        "supersededByPackedSharedSchedule": True,
        "historicalOracleRecordsPerSlot": 51,
        "profileId": "K128_CALIBRATION",
        "staticCallsiteCount": len(CALLSITE_DISPOSITIONS),
        "staticDispositionCounts": counts,
        "reconciledAdditionMeasurementCurrent": True,
        "reconciledAdditionCount": len(H0_RECONCILED_ADDITION_MEASUREMENTS),
        "reconciledAdditionMeasurements": [
            {
                "id": callsite.stable_id,
                "phase": phase,
                "preimageBytes": preimage_bytes,
                "invocations": invocations,
            }
            for callsite, phase, preimage_bytes, invocations in (
                H0_RECONCILED_ADDITION_MEASUREMENTS
            )
        ],
        "physicalVerifierObservedInvocations": sum(
            value.invocations for value in K128_PHYSICAL_VERIFIER_OBSERVATIONS
        ),
        "physicalVerifierObservedPermutations": sum(
            value.total_permutations for value in K128_PHYSICAL_VERIFIER_OBSERVATIONS
        ),
        "airObservedInvocations": sum(value.invocations for value in air_observed),
        "airObservedPermutations": sum(value.total_permutations for value in air_observed),
        "airRequiredRestoredInvocations": sum(
            value.invocations for value in K128_REQUIRED_OUTSIDE_OBSERVED_PHASE
        ),
        "airRequiredRestoredPermutations": sum(
            value.total_permutations for value in K128_REQUIRED_OUTSIDE_OBSERVED_PHASE
        ),
        "conservativeAirInvocations": sum(value.invocations for value in air_complete),
        "conservativeAirPermutations": sum(value.total_permutations for value in air_complete),
        "conservativeAirKeccakRoundRows": sum(
            value.total_permutations for value in air_complete
        )
        * KECCAK_ROUNDS_PER_PERMUTATION,
        "publicPrecomputedInvocationsInObservedPhase": sum(
            value.invocations for value in public
        ),
        "hostEvidenceInvocationsInObservedPhase": sum(
            value.invocations for value in host
        ),
        "finalAirScheduleSelected": False,
        "interactionPackingSelected": False,
        "proofSuiteId": None,
        "activationAllowed": False,
    }


def inventory_canonical_sha3_512() -> str:
    payload = {
        "summary": k128_inventory_summary(),
        "callsites": [
            {
                "id": callsite.stable_id,
                "disposition": CALLSITE_DISPOSITIONS[callsite].value,
            }
            for callsite in sorted(CALLSITE_DISPOSITIONS)
        ],
        "observations": [
            {
                "id": value.callsite.stable_id,
                "preimageBytes": value.preimage_bytes,
                "invocations": value.invocations,
                "permutationsPerInvocation": value.permutations_per_invocation,
            }
            for value in K128_PHYSICAL_VERIFIER_OBSERVATIONS
        ],
        "restored": [
            {
                "id": value.callsite.stable_id,
                "preimageBytes": value.preimage_bytes,
                "invocations": value.invocations,
                "permutationsPerInvocation": value.permutations_per_invocation,
            }
            for value in K128_REQUIRED_OUTSIDE_OBSERVED_PHASE
        ],
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha3_512(encoded).hexdigest()


def require_inventory_consistent(repository_root: Path) -> None:
    observed = scan_scoped_sha3_callsites(repository_root)
    expected = tuple(sorted(CALLSITE_DISPOSITIONS))
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        added = sorted(set(observed) - set(expected))
        raise ValueError(
            "sha3_inventory_static_callsite_drift:"
            f"missing={[value.stable_id for value in missing]}:"
            f"added={[value.stable_id for value in added]}"
        )
    for observation in (
        *K128_PHYSICAL_VERIFIER_OBSERVATIONS,
        *K128_REQUIRED_OUTSIDE_OBSERVED_PHASE,
    ):
        if (
            observation.callsite not in CALLSITE_DISPOSITIONS
            and observation.callsite not in HISTORICAL_REMOVED_DISPOSITIONS
        ):
            raise ValueError("sha3_inventory_observation_unclassified")
    summary = k128_inventory_summary()
    if summary["physicalVerifierObservedInvocations"] != 404_482:
        raise ValueError("sha3_inventory_observed_invocation_reconciliation_failed")
    if summary["conservativeAirInvocations"] != 401_275:
        raise ValueError("sha3_inventory_air_invocation_reconciliation_failed")
    if summary["conservativeAirPermutations"] != 1_205_016:
        raise ValueError("sha3_inventory_permutation_reconciliation_failed")
    if summary["conservativeAirKeccakRoundRows"] != 28_920_384:
        raise ValueError("sha3_inventory_round_row_reconciliation_failed")


__all__: Sequence[str] = (
    "CALLSITE_DISPOSITIONS",
    "GOVERNED_SOURCE_DIRECTORIES",
    "K128_PHYSICAL_VERIFIER_OBSERVATIONS",
    "K128_REQUIRED_OUTSIDE_OBSERVED_PHASE",
    "H0_RECONCILED_ADDITION_MEASUREMENTS",
    "HISTORICAL_REMOVED_DISPOSITIONS",
    "PortDisposition",
    "RECONCILED_ADDITION_WIDTHS",
    "STATUS",
    "inventory_canonical_sha3_512",
    "k128_inventory_summary",
    "require_inventory_consistent",
    "scan_scoped_sha3_callsites",
    "sha3_512_permutation_count",
)
