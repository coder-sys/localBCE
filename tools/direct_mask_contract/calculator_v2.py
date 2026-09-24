"""Exact finite arithmetic for the filtered direct-mask v2 contract.

This module is deliberately separate from :mod:`calculator`, which remains the v1
calculator.  It computes a proposed, nonactivating accounting report; it does not
implement the protocol, enforce counters, prove a theorem, or select a product
profile.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import Counter
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Mapping

try:  # Package execution is the supported path; the fallback keeps direct execution useful.
    from .calculator import ContractError
except ImportError:  # pragma: no cover - only used by ``python calculator_v2.py``.
    class ContractError(ValueError):
        """A v2 manifest or runtime admission value is not contract-valid."""

try:
    from .lean_adapter import (
        FormalArithmeticError,
        run_formal_cap,
        run_formal_row,
        run_formal_runtime,
    )
except ImportError:  # pragma: no cover - only used by direct script execution.
    from lean_adapter import (  # type: ignore[no-redef]
        FormalArithmeticError,
        run_formal_cap,
        run_formal_row,
        run_formal_runtime,
    )


CONTRACT_ROOT = Path(__file__).resolve().parent
DEFAULT_MANIFEST = CONTRACT_ROOT / "manifest_v2.json"
UNKNOWN = "UNKNOWN"
MAX_INPUT_BITS = 4096
STIRLING_EVALUATION_MAX_R = 128
INDEPENDENT_EVALUATION_MAX_R = 4096
SECOND_MOMENT_GROUP_FACTOR_LIMIT = 1 << 25
SECOND_MOMENT_WORKING_ARRAY_LIMIT_BYTES = 128 * 1024 * 1024
SECOND_MOMENT_RUNTIME_LIMIT_SECONDS = 60

_SOURCE_WORD_BITS = 64
_SOURCE_WORD_COUNT = 100
_SOURCE_PUBLIC_BLOCK_COUNT = 50
_SOURCE_DISJOINT_PAIR_COUNT = 25
_SOURCE_DRAWS_PER_WORD = 128
_SOURCE_LOWER = 0x1122334455667788
_SOURCE_UPPER = 0xDDEEFF0011223344

_MISSING = object()


class _AvailabilityDeadline:
    """One deadline shared by path-vector and grouped-pair calculation work."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self.started = clock()
        self.deadline = self.started + SECOND_MOMENT_RUNTIME_LIMIT_SECONDS
        self.checks = 0

    def check(self) -> None:
        self.checks += 1
        if self._clock() > self.deadline:
            raise ContractError("availability.second_moment: runtime_resource_limit")

_EXPECTED_FILTERS: dict[str, dict[str, Any]] = {
    "H0": {
        "payload_bits": 768,
        "acceptance_bits_start": 768,
        "acceptance_bits_end": 778,
        "acceptance_bits": 10,
        "acceptance": "bits[768,778) == 0",
        "squeeze_bytes": 98,
        "byte_rule": "payload=bytes[0:96]; byte[96]=0; low 2 bits of byte[97]=0",
        "search_space": "fresh_public_128_bit_IV",
    },
    "H1": {
        "payload_bits": 512,
        "acceptance_bits": 0,
        "acceptance": "none",
    },
    "FS1": {
        "payload_bits": 2112,
        "acceptance_bits": 0,
        "acceptance": "none",
        "squeeze_bytes": 264,
    },
    "FS2": {
        "payload_bits": 832,
        "acceptance_bits_start": 832,
        "acceptance_bits_end": 838,
        "acceptance_bits": 6,
        "acceptance": "bits[832,838) == 0",
        "squeeze_bytes": 105,
        "byte_rule": "payload=bytes[0:104]; low 6 bits of byte[104]=0",
        "search_space": "fresh_512_bit_sigma2",
    },
    "FS3": {
        "payload_bits": 256,
        "acceptance_bits_start": 256,
        "acceptance_bits_end": 263,
        "acceptance_bits": 7,
        "acceptance": "bits[256,263) == 0",
        "squeeze_bytes": 33,
        "byte_rule": "payload=bytes[0:32]; low 7 bits of byte[32]=0",
        "search_space": "fresh_512_bit_sigma3",
    },
}

_EXPECTED_COUNTER_FIELDS = [
    "Q", "A", "V", "M", "E_U", "S", "R0", "R2", "R3",
    "h0_first", "h0_accepted", "h0_rejected", "h0_aborted", "h0_oracle_evaluations",
    "fs2_first", "fs2_accepted", "fs2_rejected", "fs2_aborted", "fs2_oracle_evaluations",
    "fs3_first", "fs3_accepted", "fs3_rejected", "fs3_aborted", "fs3_oracle_evaluations",
]
_EXPECTED_PRECONDITION_FLAGS = [
    "one_commitment_per_attempt",
    "source_generation_admitted",
    "U96_nonzero",
    "source_coins_independent",
    "source_cap_enforced",
]

_EXPECTED_COUNTER_IDENTITIES = [
    "R0 = h0_accepted + h0_rejected + h0_aborted",
    "R2 = fs2_accepted + fs2_rejected + fs2_aborted",
    "R3 = fs3_accepted + fs3_rejected + fs3_aborted",
    "h0_first = A",
    "h0_first <= R0",
    "fs2_first <= A and fs2_first <= R2",
    "fs3_first <= A and fs3_first <= R3",
    "h0_accepted <= h0_first",
    "fs2_accepted <= fs2_first",
    "fs3_accepted <= fs3_first",
    "h0_oracle_evaluations <= R0",
    "fs2_oracle_evaluations <= R2",
    "fs3_oracle_evaluations <= R3",
    "fs2_first = 0 implies R2 = 0",
    "fs3_first = 0 implies R3 = 0",
    "M <= A",
    "P <= A + R2 + R3",
]

_EXPECTED_RESERVATION_EXAMPLES = [
    {
        "name": "first_accept",
        "reservations": 1,
        "first": 1,
        "accepted": 1,
        "rejected": 0,
        "aborted": 0,
        "oracle_evaluations": 1,
        "effect": "one reservation and one successful observed candidate",
    },
    {
        "name": "reject_then_accept",
        "reservations": 2,
        "first": 1,
        "accepted": 1,
        "rejected": 1,
        "aborted": 0,
        "oracle_evaluations": 2,
        "effect": "the first reservation is rejected; the second is accepted; first is not added to outcomes",
    },
    {
        "name": "all_reject_exhaustion",
        "reservations": 3,
        "first": 1,
        "accepted": 0,
        "rejected": 3,
        "aborted": 0,
        "oracle_evaluations": 3,
        "effect": "retry exhaustion charges all three reservations and fails closed",
    },
    {
        "name": "rng_failure_before_query",
        "reservations": 1,
        "first": 1,
        "accepted": 0,
        "rejected": 0,
        "aborted": 1,
        "oracle_evaluations": 0,
        "effect": "the reservation is charged even though no oracle answer was observed",
    },
    {
        "name": "crash_or_unknown_after_reservation",
        "reservations": 1,
        "first": 1,
        "accepted": 0,
        "rejected": 0,
        "aborted": 1,
        "oracle_evaluations": 1,
        "effect": "a later observation classifies the same reservation once; R is not incremented",
    },
]

_EXPECTED_DECODER_PATH_UNION = {
    "source_commit": "392e53e2b3d5936cb9cb2681b9e2d803143b1e17",
    "source_tree": "34dc614591712efd4faca0dedc064bfd63e51a92",
    "source_facts": [
        "vendor/faest-ref/utils.c:39-61 defines 17 width-8 and 16 width-7 decoded groups from contiguous little-endian challenge slices",
        "vendor/faest-ref/bavc.c:103-114 defines the pinned pos_in_tree leaf map",
        "vendor/faest-ref/bavc.c:338-360 marks each selected leaf and its heap ancestors and accepts n_h - 2*tau + 1 <= T_open",
    ],
    "parameters": {
        "tau": 33,
        "tau1": 17,
        "k": 8,
        "L": 6400,
        "heap_nodes": 12799,
        "group_count": 33,
        "group_widths": "17 groups of 8 bits followed by 16 groups of 7 bits",
        "selectable_leaves": 6400,
        "choice_denominator": "2^248",
        "parent_rule": "parent(v)=(v-1)//2 for v>0",
        "pos_in_tree_first_half": "L-1 + tau*j + i for 0 <= j < 2^(k-1)",
        "pos_in_tree_second_half": "L-1 + tau*2^(k-1) + tau1*(j mod 2^(k-1)) + i for 2^(k-1) <= j < 2^k",
        "T_open": 229,
        "n_h_acceptance_threshold": 294,
        "rejection_event": "n_h >= 295",
        "threshold_relation": "n_h - 2*tau + 1 <= T_open",
    },
    "assumptions": {
        "decoded_group_choices_uniform": True,
        "decoded_group_choices_independent": True,
        "leaf_map_is_injective": True,
        "mapping_is_source_derived_not_inferred": True,
        "fresh_uniform_ro_for_collision_split": True,
        "fixed_prefix_collision_split": True,
    },
    "first_moment_formula": "E[n_h] = sum_v (1 - product_i(1 - c[i,v]/2^width_i))",
    "tail_formula": "Pr[n_h >= 295] <= min(1,(E[n_h]-33)/(295-33))",
    "second_moment_formula": "Var[n_h] = J/2^248 - (S/2^248)^2 with J=B+sum_v[Z(c_v)-Z(2*c_v)]+2*sum_(a proper ancestor of b)[Z(c_a)-Z(c_a+c_b)]",
    "second_moment_pair_identity": "disjoint: Z(c_v+c_w)/2^248; nested: Z(c_ancestor)/2^248; self: Z(c_v)/2^248",
    "cantelli_formula": "Pr[n_h >= 295] <= Var[n_h]/(Var[n_h]+(295-E[n_h])^2)",
    "selected_tail_formula": "min(first_moment_tail,cantelli_tail)",
    "grouping_formula": "B=sum_(ordered signature pairs) n_c*n_d*Z(c+d), using symmetry over unordered signature pairs",
    "signed_nested_Z_is_not_a_probability": True,
    "resource_guard": {
        "group_factor_multiplication_limit": "2^25",
        "working_array_limit_bytes": 134217728,
        "runtime_limit_seconds": 60,
        "stop_before_pair_phase_if_exceeded": True,
    },
    "deterministic_lower_bound_n_h": 33,
    "lower_bound_proof": "the source-derived pos_in_tree map is injective over the 33 disjoint decoder groups, so one selected leaf per group marks at least 33 distinct heap nodes",
}


def _is_exact_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _fraction_payload(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def _formal_result_cap() -> dict[str, Any]:
    try:
        return run_formal_cap()
    except FormalArithmeticError as exc:
        raise ContractError(f"formal_arithmetic: {exc}") from exc


def _formal_result_for_counters(counters: Mapping[str, Any]) -> dict[str, Any]:
    try:
        cap = _cap_counters()
        if all(counters.get(key) == cap.get(key) for key in (*_EXPECTED_COUNTER_FIELDS, *_EXPECTED_PRECONDITION_FLAGS)):
            return _formal_result_cap()
        return run_formal_runtime(counters)
    except FormalArithmeticError as exc:
        raise ContractError(f"formal_arithmetic: {exc}") from exc


def _formal_fraction(record: Mapping[str, Any], key: str, name: str) -> Fraction:
    if key not in record:
        raise ContractError(f"formal_arithmetic: {name}: missing")
    try:
        numerator, denominator = record[key]
        value = Fraction(int(numerator), int(denominator))
    except (TypeError, ValueError, ZeroDivisionError) as exc:
        raise ContractError(f"formal_arithmetic: {name}: invalid_fraction") from exc
    if denominator <= 0:
        raise ContractError(f"formal_arithmetic: {name}: nonpositive_denominator")
    return value


def _formal_int(record: Mapping[str, Any], key: str, name: str) -> int:
    if key not in record or not _is_exact_int(record[key]):
        raise ContractError(f"formal_arithmetic: {name}: missing_or_invalid_integer")
    if record[key] < 0:
        raise ContractError(f"formal_arithmetic: {name}: negative_integer")
    return record[key]


def _formal_bool(record: Mapping[str, Any], key: str, name: str) -> bool:
    if key not in record or not isinstance(record[key], bool):
        raise ContractError(f"formal_arithmetic: {name}: missing_or_invalid_bool")
    return record[key]


def _match_formal_fraction(
    expected: Fraction,
    record: Mapping[str, Any],
    key: str,
    name: str,
) -> dict[str, str]:
    actual = _formal_fraction(record, key, name)
    if actual != expected:
        raise ContractError(
            f"formal_arithmetic: {name}: mismatch; python={_fraction_payload(expected)}; lean={_fraction_payload(actual)}"
        )
    return _fraction_payload(actual)


def _match_formal_int(expected: int, record: Mapping[str, Any], key: str, name: str) -> int:
    actual = _formal_int(record, key, name)
    if actual != expected:
        raise ContractError(f"formal_arithmetic: {name}: mismatch; python={expected}; lean={actual}")
    return actual


def _match_formal_bool(expected: bool, record: Mapping[str, Any], key: str, name: str) -> bool:
    actual = _formal_bool(record, key, name)
    if actual is not expected:
        raise ContractError(f"formal_arithmetic: {name}: mismatch; python={expected}; lean={actual}")
    return actual


def _pow2(bits: int) -> int:
    if not _is_exact_int(bits) or bits < 0:
        raise ContractError("bits: invalid_power")
    return 1 << bits


_GENERATOR_SECURITY_CONSTANTS = (
    Fraction(math.comb(_pow2(248), 3), _pow2(1024)) * (1 + Fraction(125049**5, _pow2(64))),
    (1 + Fraction(172231**2, _pow2(64))) / _pow2(262),
    Fraction(3, _pow2(263)),
)


def _required(mapping: Mapping[str, Any], key: str, name: str | None = None) -> Any:
    label = name or key
    if key not in mapping:
        raise ContractError(f"{label}: missing")
    value = mapping[key]
    if value == UNKNOWN or value is None:
        raise ContractError(f"{label}: unknown")
    return value


def _exact_int(
    value: Any,
    name: str,
    *,
    maximum: int | None = None,
    max_bits: int = MAX_INPUT_BITS,
) -> int:
    if value is _MISSING:
        raise ContractError(f"{name}: missing")
    if value == UNKNOWN or value is None:
        raise ContractError(f"{name}: unknown")
    if not _is_exact_int(value):
        raise ContractError(f"{name}: integer_required")
    if value < 0:
        raise ContractError(f"{name}: underflow")
    if value.bit_length() > max_bits:
        raise ContractError(f"{name}: overflow")
    if maximum is not None and value > maximum:
        raise ContractError(f"{name}: overflow")
    return value


def _exact_bool(mapping: Mapping[str, Any], key: str, *, expected: bool | None = None) -> bool:
    value = _required(mapping, key)
    if not isinstance(value, bool):
        raise ContractError(f"{key}: boolean_required")
    if expected is not None and value is not expected:
        raise ContractError(f"{key}: required_precondition_false")
    return value


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{name}: object_required")
    return value


def _manifest_power(value: Any, expected_bits: int, name: str) -> int:
    if value != f"2^{expected_bits}":
        raise ContractError(f"{name}: wrong_cap")
    return _pow2(expected_bits)


def _expect(mapping: Mapping[str, Any], key: str, expected: Any, name: str | None = None) -> None:
    label = name or key
    if key not in mapping:
        raise ContractError(f"{label}: missing")
    value = mapping[key]
    if isinstance(expected, bool):
        valid = value is expected
    elif _is_exact_int(expected):
        valid = _is_exact_int(value) and value == expected
    else:
        valid = value == expected
    if not valid:
        raise ContractError(f"{label}: identity_mismatch")


def load_manifest(path: str | Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    manifest_path = Path(path)
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"manifest: unreadable:{manifest_path}") from exc
    _validate_manifest(raw)
    return dict(raw)


def _validate_manifest(manifest: Mapping[str, Any]) -> None:
    if not isinstance(manifest, Mapping):
        raise ContractError("manifest: object_required")
    _expect(manifest, "manifest_version", "direct-mask-contract/v2-filtered")
    _expect(manifest, "candidate_id", "BLIND-DIRECT-MASK-FAEST256F-DEG3-V2-FILTERED")

    status = _require_mapping(_required(manifest, "status"), "status")
    for key in ("qualified", "selected", "activation", "production_usable"):
        _expect(status, key, False, f"status.{key}")
    _expect(status, "proof_suite_id", None, "status.proof_suite_id")

    preserved = _require_mapping(_required(manifest, "v1_preservation"), "v1_preservation")
    for key, expected in {
        "input_commit": "79850857df1ce2aed0e10651c469f4d13d6cf412",
        "input_tree": "5267b4f9b24aa7a256ffbe0200c2c5a175502e18",
        "v1_manifest_sha256": "BE425F4C594AE89E1CCD69B3DE29EE2B94DD903269A8BBBF807DE14DAB4011FA",
        "v1_manifest": "tools/direct_mask_contract/manifest.json",
        "v1_calculator": "tools/direct_mask_contract/calculator.py",
    }.items():
        _expect(preserved, key, expected, f"v1_preservation.{key}")
    _expect(preserved, "v2_does_not_qualify_or_replace_v1", True)
    _expect(preserved, "v1_files_preserved", True)

    provenance = _require_mapping(_required(manifest, "provenance"), "provenance")
    for key, expected in {
        "vole_source_commit": "392e53e2b3d5936cb9cb2681b9e2d803143b1e17",
        "vole_source_tree": "34dc614591712efd4faca0dedc064bfd63e51a92",
        "pipeline_source_commit": "530e880ef6cbd5fa4e023f42d3aa66a0d213d9e2",
        "pipeline_source_tree": "e1119b850c3a886a4df09f375fd50d9ac81e94d7",
        "faest_vendor_commit": "ebefcbd8adda5faf447ef3dba5103794d17b4281",
        "faest_vendor_tree": "f0c2e69f3eb0735fd544d04dc3dcfcc12e275e31",
        "native_v2_status": "SEPARATE_CANDIDATE_EXISTS_NOT_REVIEWED_OR_RUN_IN_THIS_CONTRACT",
        "state_selection_status": "NOT_SELECTED_AND_NOT_WRITTEN",
    }.items():
        _expect(provenance, key, expected, f"provenance.{key}")

    protocol = _require_mapping(_required(manifest, "protocol"), "protocol")
    for key, expected in {
        "field": "GF(2^256)",
        "field_modulus": "X^256+X^10+X^5+X^2+1",
        "degree": 3,
        "ell_bits": 125048,
        "constraint_count": 172232,
        "a": 125049,
        "m_minus_1": 172231,
        "tau": 33,
        "total_leaves": 6400,
        "T_open": 229,
        "path_union_threshold_n_h": 294,
        "mask_count": 6,
        "ordinary_bit_vole_rows": 126584,
        "ordinary_bit_vole_row_bytes": 15823,
        "statement_bytes": 1147,
        "frame_bytes": 534370,
        "source_U_bytes": 96,
        "inner_wire_magic": "DMV2",
        "inner_wire_version": 2,
        "canonical_signed_field": "x.challenge_mode=2",
        "challenge_mode": 2,
        "reject_inner_wire_v1": True,
        "transcript_prefix": "BL/DMV/FAEST-256F/v2",
        "preserved_source_commitment_id": True,
        "preserved_relation_id": True,
    }.items():
        _expect(protocol, key, expected, f"protocol.{key}")
    if protocol.get("S0") != "2^248":
        raise ContractError("protocol.S0: wrong_parameter")

    oracle = _require_mapping(_required(manifest, "random_oracle"), "random_oracle")
    _expect(oracle, "common_output_bits", 2112, "random_oracle.common_output_bits")
    _expect(oracle, "typed_domains", ["H0", "H1", "FS1", "FS2", "FS3"])
    _expect(oracle, "domain_separation_required", True)
    _expect(oracle, "little_endian_squeeze", True)
    _expect(oracle, "filters_are_disjoint", True)
    _expect(oracle, "filtered_suffix_bits_are_discarded", True)
    filters = _require_mapping(_required(oracle, "filters"), "random_oracle.filters")
    for name, expected_filter in _EXPECTED_FILTERS.items():
        value = _require_mapping(_required(filters, name), f"random_oracle.filters.{name}")
        for key, expected in expected_filter.items():
            _expect(value, key, expected, f"random_oracle.filters.{name}.{key}")
        bits = expected_filter["acceptance_bits"]
        if bits:
            start = expected_filter["acceptance_bits_start"]
            end = expected_filter["acceptance_bits_end"]
            if end - start != bits:
                raise ContractError(f"random_oracle.filters.{name}: interval_mismatch")
        else:
            if "acceptance_bits_start" in value or "acceptance_bits_end" in value:
                raise ContractError(f"random_oracle.filters.{name}: unexpected_acceptance_interval")
    original = _require_mapping(_required(oracle, "original_fs3_checks"), "original_fs3_checks")
    for key, expected in {
        "grinding_bits": 8,
        "decoder_payload_bits": 248,
        "T_open": 229,
        "opening_node_threshold": 294,
        "opening_threshold_relation": "n_h - 2*tau + 1 <= T_open",
        "all_checks_remain_required": True,
    }.items():
        _expect(original, key, expected, f"random_oracle.original_fs3_checks.{key}")

    algorithm = _require_mapping(_required(manifest, "honest_algorithm"), "honest_algorithm")
    _expect(algorithm, "status", "PROPOSED_NATIVE_CALL_ORDER_NOT_IMPLEMENTED")
    _expect(algorithm, "U_must_be_nonzero", True)
    ownership = _require_mapping(_required(algorithm, "U_ownership"), "honest_algorithm.U_ownership")
    for key, expected in {
        "owner": "State",
        "state_issued": True,
        "public": True,
        "nonzero": True,
        "part_of_public_statement": True,
        "independent_of_source_coins": True,
        "independent_of_public_statement": False,
    }.items():
        _expect(ownership, key, expected, f"honest_algorithm.U_ownership.{key}")
    h0 = _require_mapping(_required(algorithm, "h0"), "honest_algorithm.h0")
    for key in (
        "search_fresh_public_IV_before_commitment",
        "search_before_root_and_six_mask_randomness",
        "fresh_IV_per_candidate",
        "commitment_created_only_after_H0_pass",
    ):
        _expect(h0, key, True, f"honest_algorithm.h0.{key}")
    _expect(h0, "candidate_counter", "R0")
    post_h0 = _require_mapping(_required(algorithm, "post_H0_pass"), "honest_algorithm.post_H0_pass")
    for key in (
        "sample_hidden_randomness_once_independently",
        "hold_m2_fixed_during_FS2_search",
        "fresh_sigma2_per_FS2_candidate",
        "compute_m3_after_FS2_pass",
        "hold_m3_fixed_during_FS3_search",
        "fresh_sigma3_per_FS3_candidate",
    ):
        _expect(post_h0, key, True, f"honest_algorithm.post_H0_pass.{key}")
    _expect(post_h0, "fresh_sigma1_bits", 512)
    filter_search = _require_mapping(
        _required(algorithm, "filter_search_probabilities"),
        "honest_algorithm.filter_search_probabilities",
    )
    for key, expected in {
        "H0_search_space": "2^128",
        "H0_filter_probability": "2^-10",
        "FS2_search_space": "2^512",
        "FS2_filter_probability": "2^-6",
        "FS3_filter_probability_before_original_gate": "2^-7",
    }.items():
        _expect(filter_search, key, expected, f"honest_algorithm.filter_search_probabilities.{key}")
    rejected = _require_mapping(_required(algorithm, "rejected_candidate_behavior"), "honest_algorithm.rejected_candidate_behavior")
    for key in (
        "H0_no_commitment_rebuild",
        "FS2_no_commitment_rebuild",
        "FS3_no_commitment_rebuild",
        "chronological_counter_charge",
        "crash_abandon_and_unknown_outcome_charge",
    ):
        _expect(rejected, key, True, f"honest_algorithm.rejected_candidate_behavior.{key}")
    _expect(rejected, "retry_exhaustion", "FAIL_CLOSED")
    cache = _require_mapping(_required(algorithm, "prefix_cache"), "honest_algorithm.prefix_cache")
    _expect(cache, "allowed_only_for_byte_equivalent_fixed_input_including_final_length_word", True)
    _expect(cache, "fresh_nonce_remains_required", True)

    accounting = _require_mapping(_required(manifest, "candidate_accounting"), "candidate_accounting")
    _expect(accounting, "required_counters", _EXPECTED_COUNTER_FIELDS)
    _expect(
        accounting,
        "required_precondition_flags",
        ["one_commitment_per_attempt", "source_generation_admitted", "U96_nonzero", "source_coins_independent", "source_cap_enforced"],
    )
    caps = _require_mapping(_required(accounting, "caps"), "candidate_accounting.caps")
    for key, bits in {
        "Q_max": 128,
        "A_max": 32,
        "V_max": 32,
        "E_U_max_when_source_generation_admitted": 32,
        "S_max_when_source_cap_enforced": 32,
        "R0_multiplier_per_A": 16,
        "R2_multiplier_per_A": 12,
        "R3_multiplier_per_A": 22,
    }.items():
        _manifest_power(_required(caps, key), bits, f"candidate_accounting.caps.{key}")
    # Keep these as a list in the manifest, but validate the exact ordered strings.
    _expect(
        accounting,
        "required_identities",
        _EXPECTED_COUNTER_IDENTITIES,
    )
    _expect(accounting, "reservation_examples", _EXPECTED_RESERVATION_EXAMPLES)
    reconciliation = _require_mapping(
        _required(accounting, "counter_reconciliation"), "candidate_accounting.counter_reconciliation"
    )
    for key, expected in {
        "Q": "all adversarial quantum-random-oracle queries in the single global experiment",
        "A": "all admitted honest proof invocations, including failed, crashed, abandoned, and pre-abort attempts",
        "V": "all verifier invocations entering the backend, including retransmission verification",
        "R0": "all H0 reservations, including rejected and aborted/unknown reservations; included in q history but never an adaptive-reprogramming event",
        "R2": "all FS2 reservations, including rejected and aborted/unknown reservations; each full answer is sampled before filtering when an oracle evaluation occurs",
        "R3": "all FS3 reservations, including rejected and aborted/unknown reservations; each full answer is sampled before filtering when an oracle evaluation occurs",
        "M": "fresh BAVC commitments actually generated after H0 pass; M<=A only under one_commitment_per_attempt",
        "S": "distinct fresh source commitments/root-pad expansions; independent source opportunities and not inferred from A",
        "E_U": "independent source-U issuances, including the initial issuance; separate from S and from proof-oracle events",
        "P": "an upper bound on FS1 plus FS2/FS3 adaptive reprogramming events; reservations with no observed answer are charged conservatively but do not create a hidden H0 event",
        "caps": "Q,A,V,E_U,S,R0,R2,R3 caps are admission conditions only; the calculator cannot enforce them globally and native enforcement is pending",
    }.items():
        _expect(reconciliation, key, expected, f"candidate_accounting.counter_reconciliation.{key}")
    _expect(reconciliation, "state_101_reservations_unchanged", True)
    certificate = _require_mapping(_required(manifest, "certificate"), "certificate")
    _expect(
        certificate,
        "row_bounds",
        {
            "H0_leaf_bad_or_completion": "j/2^768 + e0",
            "H1_vector": "34*j/2^512",
            "H1_outer": "2*j/2^512",
            "FS1": "2*j/2^2112 + eKOS",
            "FS2": "2*j/2^832 + e2",
            "FS3": "e3",
            "other_typed_input": "0",
        },
        "certificate.row_bounds",
    )
    constants = _require_mapping(_required(certificate, "constants"), "certificate.constants")
    for key, expected in {
        "e0": "33*binom(2^256,2)/2^778",
        "eKOS": "binom(2^248,3)*2^-1024*(1+125049^5/2^64)",
        "e2": "(1+172231^2/2^64)/2^262",
        "e3": "3/2^263",
    }.items():
        _expect(constants, key, expected, f"certificate.constants.{key}")
    _expect(certificate, "simplified_replacement_bound", "delta(j) <= 102*j/2^512 + 3/2^263")
    _expect(certificate, "density_checks", {"a_lt_2^17": True, "m_minus_1_lt_2^18": True, "max_e0_eKOS_e2_e3_is_e3": True})
    _expect(certificate, "collision_rows_count_even_when_rejected", True)
    _expect(certificate, "replacement_stability_required", True)
    _expect(certificate, "chronological_extraction_required", True)
    _expect(certificate, "one_typed_insertion_uses_maximum_not_independent_union", True)
    _expect(
        certificate,
        "witness_sizes",
        {"H0_leaf_bad": 1, "H1_or_FS1_or_FS2_collision": 2, "H1_chain": 36, "FS1_chain": 37, "FS2_chain": 38, "FS3_chain": 38},
        "certificate.witness_sizes",
    )
    theorem = _require_mapping(_required(certificate, "theorem_application"), "certificate.theorem_application")
    _expect(theorem, "reference", "https://faest.info/faest-spec-v3.0.pdf")
    _expect(theorem, "locator", "FAEST v3.0 Lemma 10.44, Eq. (16), zero-based PDF page index 121 (printed page 122), extracted lines L10147-L10168")
    _expect(
        theorem,
        "applicability",
        "CONDITIONAL_ON_LITERAL_DMV2_FILTERED_GAME_AND_LOCAL_WITNESS_CORRESPONDENCE",
        "certificate.theorem_application.applicability",
    )
    _expect(theorem, "game", "OUTPUT_LOCAL_WITNESS_STATIC_PARTIAL_ORACLE_REPLACEMENT_GAME")
    _expect(theorem, "derivation_status", "CONDITIONAL_DERIVATION_RECORDED_SOURCE_CORRESPONDENCE_AND_PRIVACY_PREMISES_PENDING")
    _expect(
        theorem,
        "reference_provenance",
        {
            "document": "FAEST v3: Algorithm Specifications",
            "version": "3.0",
            "date": "2026-09-01",
            "url": "https://faest.info/faest-spec-v3.0.pdf",
            "retrieval_resource_id": "turn209view0",
            "locator": "Eq. (16), extracted lines L10147-L10168, zero-based PDF page index 121 (printed page 122)",
            "statement_paraphrase": "The source states sqrt(Pr_{z<-A^H}[<z,P,H>]) <= sum_{k=1..q_alg+qP} sqrt(10*max_{x,D: |D|<=k and not P(D)} Pr_{u<-Y}[P(D[x->u])]).",
            "formula": "sqrt(Pr_{z<-A^H}[<z,P,H>]) <= sum_{k=1..q_alg+qP} sqrt(10*max_{x,D: |D|<=k and not P(D)} Pr_{u<-Y}[P(D[x->u])])",
            "local_byte_hash": "UNAVAILABLE_WEB_RESOURCE",
            "provenance_limit": "Conditional adaptation only; no local PDF byte hash is available and the generic lemma does not prove DMV2 applicability.",
        },
        "certificate.theorem_application.reference_provenance",
    )
    typed_encoding = _require_mapping(
        _required(theorem, "typed_oracle_encoding"), "certificate.theorem_application.typed_oracle_encoding"
    )
    for key, expected in {
        "common_output_bits": 2112,
        "transcript_prefix": "FS-only ASCII BL/DMV/FAEST-256F/v2 (20 bytes, no NUL); never prepended to vendor H0/H1 rows",
        "domain_separation": ["H0 vendor terminal tag 00", "H1 vendor terminal tag 01", "FS1 ASCII FS1", "FS2 ASCII FS2", "FS3 ASCII FS3"],
        "part_encoding": "FS-only canonical_part = uint32_le(byte_length)||bytes; every part length word, including the final part's word, is part of the fixed input; vendor H0/H1 have no part-length words",
        "canonical_part_lengths": "statement=1147 bytes; uhash=96 bytes; m1=506416 bytes; nonce1/nonce2/nonce3=64 bytes; gamma1=264 bytes; m2=15887 bytes; gamma2=104 bytes; m3=96 bytes",
        "H0": "vendor H0 = iv[16]||00, exactly 17 bytes; no FS prefix or part lengths; squeeze 98 bytes; retain raw[0:96] as the 768-bit nu payload and require raw[96]=0 and low 2 bits of raw[97]=0",
        "H1_vector": "both vendor vector forms are active: C_0||...||C_127||01 is 128*96+1=12289 bytes and C_0||...||C_255||01 is 256*96+1=24577 bytes; each retains the first 512 output bits",
        "H1_vector_128": "C_0||...||C_127||01, exactly 12289 bytes; retain the first 512 output bits",
        "H1_vector_256": "C_0||...||C_255||01, exactly 24577 bytes; retain the first 512 output bits",
        "H1_outer": "h_0||...||h_32||01, exactly 33*64+1=2113 bytes; retain the first 512 output bits",
        "FS1": "ASCII prefix BL/DMV/FAEST-256F/v2||ASCII FS1||length-prefixed [statement,uhash,m1,sigma1], with m1 length 506416; squeeze 264 bytes and retain all 2112 bits",
        "FS2": "ASCII prefix BL/DMV/FAEST-256F/v2||ASCII FS2||length-prefixed [statement,uhash,m1,sigma1,gamma1,m2,sigma2], with m1 length 506416; squeeze 105 bytes, retain raw[0:104] as the 832-bit payload, and require low 6 bits of raw[104]=0",
        "FS3": "ASCII prefix BL/DMV/FAEST-256F/v2||ASCII FS3||length-prefixed [statement,uhash,m1,sigma1,gamma1,m2,sigma2,gamma2,m3,sigma3], with m1 length 506416; squeeze 33 bytes, retain raw[0:32] as the 256-bit payload, and require low 7 bits of raw[32]=0",
        "unused_common_output_suffixes": "The common 2112-bit H suffixes not retained by H0/H1/FS2/FS3 are independent sampled bits and are ignored; the active squeezes are H0=98, FS1=264, FS2=105, FS3=33 bytes",
        "disjointness_argument": "The vendor H0/H1 terminal tags and exact lengths are distinct, while every FS input has the FS-only prefix, a distinct three-byte ASCII domain, and the fixed canonical part grammar including m1 length 506416; therefore the canonical active input families are disjoint",
        "typed_input_sets_disjoint": True,
        "full_answer_sampled_before_filter": True,
    }.items():
        _expect(typed_encoding, key, expected, f"certificate.theorem_application.typed_oracle_encoding.{key}")
    _expect(theorem, "chronology", [
        "Sample fresh public IVs and query H0 before root, six-mask, or commitment randomness; reject a candidate unless its H0 filter suffix is zero.",
        "After H0 passes, sample hidden commitment randomness once, build the commitment, sample fresh sigma1, and obtain the full FS1 answer.",
        "Hold m2 fixed while reserving fresh sigma2 candidates; sample every full FS2 answer before filtering and retain the 832-bit payload only after its suffix passes.",
        "After FS2 passes, compute and hold m3 fixed while reserving fresh sigma3 candidates; sample every full FS3 answer before filtering, then run the original payload-dependent grinding, decoder, and opening checks.",
        "Stop, abort, and charge reservations exactly where the honest algorithm stops; rejected candidates do not rebuild the commitment.",
    ])
    local_witness = _require_mapping(
        _required(theorem, "local_witness_predicate"), "certificate.theorem_application.local_witness_predicate"
    )
    _expect(
        local_witness,
        "definition",
        "P_F(D) holds iff D contains one filtered H0 LeafBad witness, two distinct active H1/FS1/FS2 payload-collision rows with equal retained payloads, or an explicit filtered false-statement chain satisfying B1^F, B2^F, or B3^F.",
    )
    _expect(
        local_witness,
        "filtered_predicates",
        [
            "LeafBad_F = H0-filter-pass AND old LeafBad(iv,nu); a rejected H0 row cannot be a filtered LeafBad witness.",
            "Collision_F is unchanged: equal 512-bit H1 payloads (including both 128- and 256-leaf vector forms and the outer form), equal full 2112-bit FS1 answers, or equal 832-bit FS2 payloads over all active rows, including rows rejected by an independent suffix filter.",
            "B1^F = an explicit complete H0-passing good-nu chain plus the old local B1 event; every selected ancestor and filter condition is in the witness.",
            "B2^F = an explicit complete H0-passing good-nu chain, local B1 absent for that selected chain, an FS2 row whose six-bit suffix passes, and the old local B2 event; no global absence or rejected terminal row is used.",
            "B3^F = an explicit H0- and FS2-passing chain, prior local B1/B2 algebraic bad events absent for that selected chain, an FS3 row whose seven-bit suffix passes, and the old local B3 event; an FS3 row rejected by its suffix cannot trigger B3^F.",
        ],
        "certificate.theorem_application.local_witness_predicate.filtered_predicates",
    )
    _expect(local_witness, "witness_sizes", {"H0_leaf_bad": 1, "typed_collision": 2, "H1_chain": 36, "FS1_chain": 37, "FS2_or_FS3_chain": 38})
    _expect(local_witness, "monotone", True)
    for key in ("replacement_stable", "chronological_extraction", "rejected_rows_remain_in_database"):
        _expect(local_witness, key, True, f"certificate.theorem_application.local_witness_predicate.{key}")
    _expect(local_witness, "qP", 38)
    _expect(
        local_witness,
        "collision_scope",
        "H1 512-bit, FS1 full 2112-bit, and FS2 832-bit payload collisions are charged over all active rows, even when a record later fails its independent filter.",
    )
    _expect(
        local_witness,
        "witness_locality",
        "Every chain-local absence condition is evaluated only from the selected explicit rows and fixed deterministic algorithms, never from an arbitrary global choice of rows; replacing or deleting unrelated rows therefore preserves the witness.",
    )
    _expect(
        local_witness,
        "acceptance_completeness",
        "Every false accepted filtered proof forces P_F because the verifier checks the H0, FS2, and FS3 suffixes; a rejected terminal row alone cannot supply a filter-discounted algebraic witness.",
    )
    _expect(
        theorem,
        "selector",
        "QUERY_ONLY_INEFFICIENT_SELECTOR_OUTPUTS_THE_COMPLETE_VERIFIER_INPUT_LIST_AND_USES_FINITE_EXHAUSTIVE_MEMBERSHIP_TESTING_WITHOUT_ADDITIONAL_ORACLE_QUERIES",
    )
    filter_derivation = _require_mapping(
        _required(theorem, "filter_derivation"), "certificate.theorem_application.filter_derivation"
    )
    for key, expected in {
        "H0": "The 10-bit suffix is independent of the 768-bit nu payload. The exact filtered LeafBad_F direct term is e0=33*binom(2^256,2)/2^778; the retained j/2^768 completion term is conservative and is not claimed to gain the filter factor.",
        "FS2": "The 6-bit suffix is independent of the original 832-bit gamma2 payload. The direct B2_F term is the old epsilon_z multiplied by 2^-6, giving e2=(1+172231^2/2^64)/2^262; the 2*j/2^832 collision/completion term remains conservative and rejected FS2 records remain collision rows.",
        "FS3": "For a fixed chain, B3 has at most three accepting 256-bit gamma3 payloads; an independent seven-bit suffix gives e3=(3/2^256)*2^-7=3/2^263. The whole v1 answer is not multiplied by 2^-7.",
        "direct_event_scope": "The 2^-10, 2^-6, and 2^-7 factors apply only to the corresponding filtered LeafBad_F, B2_F, and B3_F direct events; completion terms retain conservative v1 values, and a rejected terminal row alone never creates a discounted algebraic event.",
        "one_row_insertion_ledger": {
            "H0": "filtered LeafBad_F direct e0 plus conservative j/2^768 completion",
            "H1_vector": "34*j/2^512, including both 128- and 256-leaf vector forms",
            "H1_outer": "2*j/2^512",
            "FS1": "2*j/2^2112 + eKOS",
            "FS2": "2*j/2^832 + e2, with e2 only for direct B2_F",
            "FS3": "e3, only for direct B3_F",
            "other_typed_input": "0",
            "combination": "A single typed insertion takes the maximum over typed roles, not an independent union sum; collisions and ancestor completion are separated from direct algebraic events.",
        },
        "simplified_delta": "delta(j)<=102*j/2^512+3/2^263",
    }.items():
        _expect(filter_derivation, key, expected, f"certificate.theorem_application.filter_derivation.{key}")
    _expect(
        theorem,
        "hidden_coin_independence",
        "H0 is never programmed. Root and six-mask commitment coins are sampled only after the public-IV search and are independent of the accepted H0 answer; this is a DMV2 game premise, not a fact supplied by the current v1 source.",
    )
    _expect(
        theorem,
        "H0_chain_entry",
        "Only an H0 record whose 10-bit suffix passes and whose old LeafBad predicate is false supplies good nu/uhash to an honest algebraic chain; rejected H0 records remain in D for collision accounting but cannot be the chain's accepted row.",
    )
    native_gap = _require_mapping(
        _required(theorem, "native_gap"), "certificate.theorem_application.native_gap"
    )
    _expect(
        native_gap,
        "failing_premise",
        "The filtered arithmetic and P_F game correspondence remain conditional. This contract has not independently established source correspondence to the separate DMV2 candidate, durable reservation enforcement, the fresh-nonce honest-search premise, or product activation; the named generic FAEST/GHHM results do not supply those premises.",
    )
    _expect(
        native_gap,
        "minimal_remedy",
        "Review the separate literal DMV2 source against the exact typed encodings, causal call order, full-answer filters, unchanged-commitment retries, and durable R0/R2/R3 ledger; separately close the stated privacy and operational assumptions before any product claim.",
    )
    _expect(
        native_gap,
        "affected_claims_stopped",
        ["native correspondence", "product activation", "concrete product security claim"],
    )
    _expect(
        theorem,
        "remaining_unresolved_premises",
        [
            "source correspondence and durable native enforcement for the separate DMV2 candidate",
            "fresh independent nonce and fixed-prefix honest-search assumptions required by the adaptive-reprogramming application",
            "the causal simulator's operational exclusions and concrete primitive advantages",
        ],
    )
    _expect(theorem, "derived_arithmetic_is_not_theorem_verification", True)

    qrom = _require_mapping(_required(manifest, "qrom_soundness"), "qrom_soundness")
    for key, expected in {
        "formula": "B_snd(q_eff)=min(1,1020*q_eff^3/2^512+30*q_eff^2/2^263)",
        "q_alg_formula": "Q+35*A+38*V+R0+R2+R3",
        "q_eff_formula": "q_alg+qP=q_alg+38=Q+35*A+38*V+R0+R2+R3+38",
        "q_formula": "q_eff=Q+35*A+38*V+R0+R2+R3+38",
        "q_hist_formula": "Q+39*A+41*V+R0+R2+R3",
        "literal_oracle_call_upper_bound": "39*A+41*V+R0+R2+R3",
        "local_witness_completion_overhead": 38,
        "Q_target": "2^128",
        "not_a_2^-128_false_acceptance_probability": True,
        "not_concrete_quantum_gate_or_work_bound": True,
        "no_extra_global_union_multiplier": True,
        "no_extra_101_or_lifetime_union_multiplier": True,
        "reference_status": "CONDITIONAL_DMV2_FILTERED_DERIVATION_RECORDED_SOURCE_CORRESPONDENCE_AND_PRIVACY_PREMISES_PENDING",
        "local_witness_selector": "QUERY_ONLY_INEFFICIENT_SELECTOR_OUTPUTS_THE_COMPLETE_VERIFIER_INPUT_LIST_AND_USES_FINITE_EXHAUSTIVE_MEMBERSHIP_TESTING_WITHOUT_ADDITIONAL_ORACLE_QUERIES",
        "filter_factor_derivation": "only the filtered LeafBad_F, B2_F, and B3_F direct events receive their independent 2^-10, 2^-6, and 2^-7 factors; H0/FS2 completion and collision rows remain charged after filtering",
        "lemma_success_sqrt_formula": "sqrt(Pr_{z<-A^H}[<z,P,H>]) <= sum_{k=1..q_alg+qP} sqrt(10*max_{x,D: |D|<=k and not P(D)} Pr_{u<-Y}[P(D[x->u])])",
        "cauchy_schwarz_derivation": "p_false <= (sum_{k=1..q_eff} sqrt(10*delta(k)))^2 <= q_eff*sum_{k=1..q_eff} 10*delta(k) = 510*q_eff^2*(q_eff+1)/2^512 + 30*q_eff^2/2^263 <= 1020*q_eff^3/2^512 + 30*q_eff^2/2^263",
        "q_formula_scope": "q_alg=Q+35*A+38*V+R0+R2+R3; q_eff=q_alg+qP=q_alg+38; 35*A is 33 H1 vector rows plus one H1 outer row plus one FS1 row per admitted attempt; R0/R2/R3 are candidate oracle calls; V uses the typed verifier call ledger",
        "q_hist_scope": "q_hist is the declared whole-history typed-call cap Q+39*A+41*V+R0+R2+R3, including duplicate/reconstruction history and aborted reservations as an upper-bound ledger",
        "calculator_and_native_enforcement": "static arithmetic and boolean preconditions are not global counter or source-correspondence enforcement; native caps, source review, and privacy premises remain pending",
    }.items():
        _expect(qrom, key, expected, f"qrom_soundness.{key}")

    privacy = _require_mapping(_required(manifest, "privacy"), "privacy")
    for key, expected in {
        "composition_formula": "epsilon_priv <= min(1,epsilon_coins+epsilon_AR+epsilon_bitMH+epsilon_source+Adv_SHAKE_priv)",
        "adaptive_reprogramming_formula": "epsilon_AR <= min(1,sum_r[sqrt(qhat_r*2^-512)+qhat_r*2^-512/2])",
        "adaptive_reprogramming_reference": "https://arxiv.org/html/2010.15103",
        "adaptive_reprogramming_locator": "GHHM HTML lines 160-173; Theorem 2.1 and Eq. (2) at lines 164-173",
        "P_bound": "P<=A+R2+R3",
        "bit_hiding_formula": "M*(397*alpha4+33*alpha2048+33*alpha989+85297284/2^128)",
        "source_hiding_formula": "S*(alpha8+alpha50+1253/2^128)",
        "M_bound": "M<=A",
        "P_cap_constant": 4198401,
        "q_hist_cap_constant": 4264016,
        "switching_under_M_cap": "85297284/2^96",
        "combined_switching_only_if_S_cap_enforced": "85298537/2^96",
        "Q_star_formula": "Q*<=2*q_hist+explicit_overlay",
        "program_full_uniform_answer_before_filter": True,
        "never_force_filter": True,
        "nonce_pmax": "2^-512",
        "fixed_prefix_fresh_nonce_assumption": True,
        "fixed_prefix_assumption_text": "Before each FS1/FS2/FS3 event, the full typed prefix is fixed and the fresh 512-bit nonce is sampled independently of prior history; this is a conditional honest-search premise, not an adaptive adversarial prequery claim.",
        "accepted_rejected_transcript_distribution": "For each independent FS candidate the simulator samples the complete uniform answer Y=(payload,suffix) before testing the suffix; Pr[payload=p,suffix=0^f|pass]=2^-payload_bits and Pr[payload=p,suffix=s|reject]=2^-(payload_bits+f)/(1-2^-f) for every nonzero s. It pre-samples candidates in order and selects the first suffix/opening-passing index or the prescribed abort. Because m2 is fixed across rejected FS2 candidates, the selected gamma2 payload remains uniform; the FS3 grinding/decoder/Topen gate depends only on gamma3 indices, not seeds or witness.",
        "simulator_correspondence": {
            "causal_full_answer_reprogramming": "Apply the GHHM reprogramming hop before the backward change of variables: sample every full FS answer uniformly, retain every failed candidate and every reprogramming charge, and never force a filter suffix.",
            "joint_history": "Fixed prefixes, full answers, rejected answers, queried prefixes, and chronological input order have the same joint distribution as the honest causal history; repeated inputs use chronological overwrite semantics and m2/m3 stay unchanged across retries.",
            "commitment_and_masks": "The simulator does not rebuild the commitment or masks on retries. After the selected gamma2/gamma3 events, reuse the reviewed exact pointwise hidden-path and six-mask endpoint change of variables; no second GHHM hop is applied.",
            "output_and_leakage": "Only the final proof or prescribed abort is returned. Timing, partial-memory, crash/recovery, and hostile-reset leakage remain outside this theorem, as do concrete primitive advantages and RNG/custody premises.",
        },
        "FS3_opening_depends_on_payload": True,
        "simulator_stop_rule": "The simulator preserves candidate order, pre-samples every independent FS answer, selects the first suffix/opening-passing index or prescribed abort, preserves all reprogramming charges, filter decisions, original payload-dependent opening decisions, retry exhaustion, and abort-only output exactly as the honest algorithm.",
        "no_public_IV_birthday_term_for_pointwise_witness": True,
        "source_pair_bound": "binom(2^256,2)/(2^768-1)<2^-257",
        "no_generic_SHAKE_RO_equivalence": True,
    }.items():
        _expect(privacy, key, expected, f"privacy.{key}")
    endpoint = _require_mapping(_required(privacy, "endpoint_normalization"), "privacy.endpoint_normalization")
    for key, expected in {
        "delta_lr_definition": "Delta_LR=abs(Pr[D(View0)=1]-Pr[D(View1)=1])",
        "one_sided_endpoint_definition": "E_one_sided bounds each real-to-common-ideal side E0 and E1",
        "common_ideal_premise": True,
        "conversion": "Delta_LR<=min(1,E0+E1)<=min(1,2*E_one_sided)",
        "guessing_success": "Pguess=(1+Delta_LR)/2",
        "strict_half_success_condition": "E_one_sided<1/4 implies Delta_LR<1/2 and Pguess<3/4",
        "not_equivalent": True,
    }.items():
        _expect(endpoint, key, expected, f"privacy.endpoint_normalization.{key}")
    _expect(
        privacy,
        "adaptive_reprogramming_provenance",
        {
            "document": "Tight adaptive reprogramming in the QROM",
            "url": "https://arxiv.org/html/2010.15103",
            "retrieval_resource_id": "turn481view1",
            "locator": "HTML lines 160-173; Theorem 2.1 lines 164-173, Eq. (2)",
            "statement_paraphrase": "Reprogram samples the input/side-information distribution and then a fresh uniform answer; Theorem 2.1 bounds distinguishing advantage by the sum of sqrt(qhat_r*p_max^(r)) plus one-half qhat_r*p_max^(r) over reprogramming events.",
            "formula": "epsilon_AR <= sum_{r=1..R}(sqrt(qhat_r*p_max^(r)) + (qhat_r*p_max^(r))/2), with qhat_r=sum_{i=0..r-1} q_i",
            "local_byte_hash": "UNAVAILABLE_WEB_RESOURCE",
            "provenance_limit": "Conditional honest-search application; p_max<=2^-512 is assumed for a fixed prefix and fresh nonce, not granted for an adaptive adversary's prequery.",
        },
        "privacy.adaptive_reprogramming_provenance",
    )
    _expect(privacy, "H0_reprogrammed", False)

    feasibility = _require_mapping(_required(manifest, "concrete_feasibility"), "concrete_feasibility")
    for key, expected in {
        "status": "CONDITIONAL_PRIVACY_TARGET_COMPARISON_RECORDED",
        "target": "2^-128",
        "privacy_bound_scope": "Product authority explicitly applies 2^-128 to the complete statistical bad-event ledger and separately requires a computational PQ work/query ledger. The switching comparison below is conditional on an additional requirement epsilon_priv<=2^-128; that additional whole-privacy threshold is not inferred as universal authority.",
        "switching_formula": "epsilon_switch=(85297284*M+1253*S)/2^128",
        "target_condition_for_switching_terms_alone": "85297284*M+1253*S<=1",
    }.items():
        _expect(feasibility, key, expected, f"concrete_feasibility.{key}")
    for key in ("ledger_scope", "proof_trace", "constant_success_work_model", "model_gap"):
        _require_mapping(_required(feasibility, key), f"concrete_feasibility.{key}")
    constant_success_model = _require_mapping(
        _required(feasibility, "constant_success_work_model"), "concrete_feasibility.constant_success_work_model"
    )
    _require_mapping(
        _required(constant_success_model, "generic_key_search_screen"),
        "concrete_feasibility.constant_success_work_model.generic_key_search_screen",
    )
    generic_screen = _require_mapping(
        _required(constant_success_model, "generic_key_search_screen"),
        "concrete_feasibility.constant_success_work_model.generic_key_search_screen",
    )
    composed_analysis = _require_mapping(
        _required(constant_success_model, "composed_privacy_analysis"),
        "concrete_feasibility.constant_success_work_model.composed_privacy_analysis",
    )
    _expect(
        composed_analysis,
        "status",
        "NO_MODEL_MATCHED_STRUCTURED_GENERATOR_BOUND; RETAIN_HYBRID_CERTIFICATE",
        "concrete_feasibility.constant_success_work_model.composed_privacy_analysis.status",
    )
    bounded_proposal = _require_mapping(
        _required(constant_success_model, "bounded_generator_feasibility_proposal"),
        "concrete_feasibility.constant_success_work_model.bounded_generator_feasibility_proposal",
    )
    _expect(
        bounded_proposal,
        "status",
        "UNSELECTED_IDEAL_ORACLE_WIDE_SEED_PROPOSAL",
        "concrete_feasibility.constant_success_work_model.bounded_generator_feasibility_proposal.status",
    )
    for key in (
        "exposure_map",
        "approach_comparison",
        "selected_conditional_bound",
        "shared_work_ledger",
        "obstruction",
        "architecture_remedy",
        "model_restrictions",
    ):
        _required(
            composed_analysis,
            key,
            f"concrete_feasibility.constant_success_work_model.composed_privacy_analysis.{key}",
        )
    for key in (
        "candidate_definition",
        "literal_public_predicate",
        "opening_geometry",
        "coupling_lemma",
        "composition",
        "implementation_consequences",
        "unresolved_boundary",
        "recommendation",
    ):
        _required(
            bounded_proposal,
            key,
            f"concrete_feasibility.constant_success_work_model.bounded_generator_feasibility_proposal.{key}",
        )
    for key in (
        "work_convention",
        "toffoli_decomposition",
        "grover_diffusion",
        "primitive_game_algorithm",
        "known_history",
        "joint_budget",
    ):
        _require_mapping(_required(generic_screen, key), f"generic_key_search_screen.{key}")
    _expect(
        feasibility,
        "minimum_nontrivial_deployment",
        {
            "M": 1,
            "S": 1,
            "numerator": 85298537,
            "term": "85298537/2^128",
            "bound_exponent_floor_bits": 101,
            "strictly_exceeds_target": True,
        },
        "concrete_feasibility.minimum_nontrivial_deployment",
    )
    _expect(
        feasibility,
        "declared_lifetime_caps",
        {
            "M": "2^32",
            "S": "2^32",
            "numerator_after_cap_substitution": 85298537,
            "term": "85298537/2^96",
            "bound_exponent_floor_bits": 69,
            "strictly_exceeds_target": True,
        },
        "concrete_feasibility.declared_lifetime_caps",
    )
    _expect(
        feasibility,
        "component_checks",
        {
            "bit_hiding_at_M_1": "85297284/2^128",
            "source_hiding_at_S_1": "1253/2^128",
            "each_component_already_exceeds_2^-128": True,
            "alpha_terms_and_other_composition_terms": "UNKNOWN and nonnegative in the stated upper-bound composition",
        },
        "concrete_feasibility.component_checks",
    )
    opportunity_scope = _require_mapping(
        _required(feasibility, "opportunity_scope"), "concrete_feasibility.opportunity_scope"
    )
    for key, expected in {
        "M_cap": "2^32 via M<=A",
        "S_cap": "2^32 when source_cap_enforced",
        "global_lifetime_accounting": True,
        "rotation_refunds_consumed_budget": False,
        "multiple_instance_loss_is_not_dropped": True,
    }.items():
        _expect(opportunity_scope, key, expected, f"concrete_feasibility.opportunity_scope.{key}")
    work_model = _require_mapping(_required(feasibility, "work_model"), "concrete_feasibility.work_model")
    for key, expected in {
        "formula": "T*=T_adversary+T_pinned(A,V,S,Q,P)+T_fixed_circuit+T_hash_transpose_pack+T_opening+T_overlay",
        "work_status": "AES block counts are an exact operation-count envelope, not a quantum gate/depth/memory bound; T_adversary, reversible circuit costs, and the concrete alpha_s(T*,Q*) reduction remain UNKNOWN",
        "hidden_key_access_model": "Q1: the quantum adversary has only classical-input hidden-key AES queries; public AES computation is a separate quantum-work component",
        "no_generic_grover_substitution": True,
    }.items():
        _expect(work_model, key, expected, f"concrete_feasibility.work_model.{key}")
    _expect(
        work_model,
        "aes_block_counts",
        {
            "commit_generation_upper_bound": "6406396*A",
            "reconstruction_upper_bound": "6373495*V",
            "source_generation": "58*S",
            "at_declared_A_V_S_caps": 54889462999547904,
        },
        "concrete_feasibility.work_model.aes_block_counts",
    )
    sources = _required(feasibility, "primitive_and_model_sources")
    if not isinstance(sources, list) or len(sources) != 10:
        raise ContractError("concrete_feasibility.primitive_and_model_sources: ten_sources_required")
    expected_sources = {
        "NIST FIPS 197": "https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf",
        "Zhandry, How to Construct Quantum Random Functions": "https://eprint.iacr.org/2012/182",
        "Zalka, Grover's quantum searching algorithm is optimal": "https://arxiv.org/abs/quant-ph/9711070",
        "Hoang and Tessaro, The Multi-User Security of Double Encryption": "https://eprint.iacr.org/2017/145.pdf",
        "Banegas and Bernstein, Low-communication parallel quantum multi-target preimage search": "https://eprint.iacr.org/2017/789",
        "Bonnetain, Naya-Plasencia, and Schrottenloher, Quantum Security Analysis of AES": "https://eprint.iacr.org/2019/272",
        "Sun et al., Quantum Key-Recovery Attacks on Permutation-Based Pseudorandom Functions": "https://eprint.iacr.org/2025/501",
        "Jaques, Naehrig, Roetteler, and Virdia, Implementing Grover oracles for quantum key search on AES and LowMC": "https://arxiv.org/html/1910.01700v1",
        "Selinger, Quantum circuits of T-depth one": "https://arxiv.org/html/1210.0974",
        "NIST FIPS 202": "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf",
    }
    seen_sources: set[str] = set()
    for index, source_value in enumerate(sources):
        source = _require_mapping(source_value, f"concrete_feasibility.primitive_and_model_sources[{index}]")
        name = _required(source, "name", f"concrete_feasibility.primitive_and_model_sources[{index}].name")
        if name in seen_sources or name not in expected_sources:
            raise ContractError(f"concrete_feasibility.primitive_and_model_sources[{index}].name: unexpected")
        seen_sources.add(name)
        _expect(source, "url", expected_sources[name], f"concrete_feasibility.primitive_and_model_sources[{index}].url")
        for field in ("locator", "statement", "limit"):
            _required(source, field, f"concrete_feasibility.primitive_and_model_sources[{index}].{field}")
    if seen_sources != set(expected_sources):
        raise ContractError("concrete_feasibility.primitive_and_model_sources: incomplete_sources")
    _expect(
        feasibility,
        "unknowns",
        [
            "alpha_s(T*,Q*) for the actual hidden-key AES/Q1 multi-instance experiment",
            "T* after reversible circuit, memory, depth, and overlay costs are instantiated",
            "epsilon_coins and RNG/custody deviation",
            "Adv_SHAKE_priv for the complete counted experiment",
            "source-U generation advantage and remaining operational exclusions",
            "a model-matched full-round AES-256 Q1 multi-instance theorem",
            "non-AES product-history and QRO-overlay costs under the selected work convention",
        ],
        "concrete_feasibility.unknowns",
    )
    decision = _require_mapping(_required(feasibility, "decision"), "concrete_feasibility.decision")
    for key, expected in {
        "known_attack_status": "NO_APPLICABLE_ATTACK_ESTABLISHED_FROM_SWITCHING_TERMS_OR_RETAINED_TRANSCRIPT",
        "conditional_privacy_target_status": "IF_EPSILON_PRIV_MUST_BE<=2^-128, THE SWITCHING TERMS FAIL THAT ADDITIONAL CONDITION EVEN AT M=S=1",
        "computational_work_status": "FULLY_COUNTED_SINGLE_KEY_PRIMITIVE_SCREEN_OBSTRUCTS_CURRENT_CERTIFICATE_AT_STRICT_2^128_WORK_CAP; PRODUCT_Q1_MULTI_INSTANCE_GAP_REMAINS",
        "primitive_game_screen_status": "FULLY_COUNTED_SINGLE_KEY_PRIMITIVE_ALGORITHM_REACHES_THE_ALPHA_THRESHOLD_BELOW_STRICT_2^128_G; THIS_IS_NOT_A_REAL_TRANSCRIPT_ATTACK",
        "smallest_justified_remedy": "The fully counted primitive cap gives only a conditional necessary effective loss no larger than 429335941335 for the known residual (a >=4.651741446173654 reduction from 465*2^32); this is not an unconditional remedy or a sufficient real-AES theorem. First obtain a model-matched independent-key multi-instance reduction and separately instantiate the product whole-history, QRO-overlay and non-AES costs. If the resulting product inequality fails, redesign the privacy construction only in a separately authorized review; no target, cap, profile, or primitive change follows here.",
        "target_or_cap_change_authorized": False,
        "primitive_replacement_authorized": False,
        "production_or_activation_allowed": False,
    }.items():
        _expect(decision, key, expected, f"concrete_feasibility.decision.{key}")

    availability = _require_mapping(_required(manifest, "availability"), "availability")
    for key, expected in {
        "g_status": "UNKNOWN",
        "filtered_candidate_probability": "g/2^263",
        "conditional_good_probability_lower_bound": "1 - min(first_moment_tail,cantelli_tail)",
        "conditional_g_lower_bound": "ceil(2^248*(1-tail_bound))",
        "conditional_filtered_probability_lower_bound": "g_lower/2^263",
        "availability_bound_status": "NONVACUOUS_CONDITIONAL_SECOND_MOMENT_BOUND",
        "conditional_collision_split_upper_bound": "min(1,1/sum_{k=0..min(16,R)} binom(R,k)*p_good_lower^k+binom(R,2)/2^512)",
        "conditional_fresh_abort_inequality": "(1-p_good_lower)^R <= 1/sum_{k=0..min(16,R)} binom(R,k)*p_good_lower^k",
        "conditional_fresh_abort_reciprocal_inequality": "(1-p_good_lower)^R <= 1/(1+R*p_good_lower)",
        "conditional_bound_is_not_exact_g": True,
        "adaptive_trials_not_geometric": True,
        "large_evaluation_status": "NOT_EVALUATED_RESOURCE_GUARD",
        "fs3_cap_does_not_prove_availability": True,
        "no_large_solver_or_monte_carlo": True,
    }.items():
        _expect(availability, key, expected, f"availability.{key}")
    _expect(availability, "decoder_path_union", _EXPECTED_DECODER_PATH_UNION)

    limits = _require_mapping(_required(manifest, "claim_limits"), "claim_limits")
    for key in (
        "pure_calculator_is_not_enforcement",
        "actual_v1_source_enforces_v2_filters",
        "actual_product_state_selects_v2",
        "no_production_or_activation_claim",
        "no_128_bit_false_acceptance_claim",
        "no_128_bit_concrete_work_claim",
        "no_availability_claim_until_g_is_evaluated",
        "unknown_or_missing_runtime_inputs_fail_closed",
    ):
        expected = False if key in ("actual_v1_source_enforces_v2_filters", "actual_product_state_selects_v2") else True
        _expect(limits, key, expected, f"claim_limits.{key}")


def _security_constants(manifest: Mapping[str, Any]) -> dict[str, Fraction]:
    _validate_manifest(manifest)
    e0 = Fraction(33 * math.comb(_pow2(256), 2), _pow2(778))
    e_kos, e2, e3 = _GENERATOR_SECURITY_CONSTANTS
    return {"e0": e0, "eKOS": e_kos, "e2": e2, "e3": e3}


def certificate_constants(manifest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    loaded = load_manifest() if manifest is None else dict(manifest)
    values = _security_constants(loaded)
    formal = _formal_result_cap()["constants"]
    formal_values = {
        name: _match_formal_fraction(value, formal, name, f"certificate.constants.{name}")
        for name, value in values.items()
    }
    max_constant = max(values.values())
    formal_max = _match_formal_fraction(
        max_constant, formal, "max_constant", "certificate.constants.max_constant"
    )
    formal_max_is_e3 = _match_formal_bool(
        max_constant == values["e3"], formal, "max_is_e3", "certificate.constants.max_is_e3"
    )
    formal_density_a = _match_formal_bool(
        125049 < _pow2(17), formal, "density_a_lt_2^17", "certificate.constants.density.a"
    )
    formal_density_m = _match_formal_bool(
        172231 < _pow2(18), formal, "density_m_minus_1_lt_2^18", "certificate.constants.density.m"
    )
    return {
        "exact": formal_values,
        "max_constant": formal_max,
        "max_is_e3": formal_max_is_e3,
        "density_checks": {
            "a_lt_2^17": formal_density_a,
            "m_minus_1_lt_2^18": formal_density_m,
        },
    }


def row_bounds(manifest: Mapping[str, Any], j: int) -> dict[str, Any]:
    loaded = dict(manifest)
    j_value = _exact_int(j, "j")
    certificate_constants(loaded)
    values = _security_constants(loaded)
    rows = {
        "H0_leaf_bad_or_completion": Fraction(j_value, _pow2(768)) + values["e0"],
        "H1_vector": Fraction(34 * j_value, _pow2(512)),
        "H1_outer": Fraction(2 * j_value, _pow2(512)),
        "FS1": Fraction(2 * j_value, _pow2(2112)) + values["eKOS"],
        "FS2": Fraction(2 * j_value, _pow2(832)) + values["e2"],
        "FS3": values["e3"],
        "other_typed_input": Fraction(0, 1),
    }
    maximum = max(rows.values())
    simplified = Fraction(102 * j_value, _pow2(512)) + values["e3"]
    try:
        formal = run_formal_row(j_value)["row"]
    except FormalArithmeticError as exc:
        raise ContractError(f"formal_arithmetic: {exc}") from exc
    _match_formal_int(j_value, formal, "j", "certificate.row.j")
    formal_rows = {
        key: _match_formal_fraction(value, formal, key, f"certificate.row.{key}")
        for key, value in rows.items()
    }
    formal_maximum = _match_formal_fraction(
        maximum, formal, "maximum_row_bound", "certificate.row.maximum_row_bound"
    )
    formal_simplified = _match_formal_fraction(
        simplified, formal, "simplified_replacement_bound", "certificate.row.simplified_replacement_bound"
    )
    formal_simplified_holds = _match_formal_bool(
        maximum <= simplified,
        formal,
        "simplified_bound_holds",
        "certificate.row.simplified_bound_holds",
    )
    return {
        "j": _formal_int(formal, "j", "certificate.row.j"),
        "row_bounds_exact": formal_rows,
        "maximum_row_bound": formal_maximum,
        "simplified_replacement_bound": formal_simplified,
        "simplified_bound_holds": formal_simplified_holds,
        "single_typed_insertion_uses_maximum": True,
        "not_an_independent_union_sum": True,
    }


def _counter_fields() -> tuple[str, ...]:
    return tuple(_EXPECTED_COUNTER_FIELDS)


def _require_counters(manifest: Mapping[str, Any], counters: Mapping[str, Any]) -> dict[str, Any]:
    _validate_manifest(manifest)
    if not isinstance(counters, Mapping):
        raise ContractError("counters: object_required")
    values: dict[str, Any] = {}
    for field in _counter_fields():
        values[field] = _exact_int(counters.get(field, _MISSING), f"counters.{field}")
    values["one_commitment_per_attempt"] = _exact_bool(counters, "one_commitment_per_attempt", expected=True)
    values["source_generation_admitted"] = _exact_bool(counters, "source_generation_admitted", expected=True)
    values["U96_nonzero"] = _exact_bool(counters, "U96_nonzero", expected=True)
    values["source_coins_independent"] = _exact_bool(counters, "source_coins_independent", expected=True)
    values["source_cap_enforced"] = _exact_bool(counters, "source_cap_enforced")

    q_max = _pow2(128)
    counter_max = _pow2(32)
    if values["Q"] > q_max:
        raise ContractError("counters.Q: overflow")
    for field in ("A", "V"):
        if values[field] > counter_max:
            raise ContractError(f"counters.{field}: overflow")
    if values["E_U"] > counter_max:
        raise ContractError("counters.E_U: overflow")
    if values["source_cap_enforced"] and values["S"] > counter_max:
        raise ContractError("counters.S: overflow")

    if values["h0_first"] != values["A"]:
        raise ContractError("counters.h0_first: must_equal_A")
    for stage, total in (("h0", "R0"), ("fs2", "R2"), ("fs3", "R3")):
        outcomes = (
            values[f"{stage}_accepted"]
            + values[f"{stage}_rejected"]
            + values[f"{stage}_aborted"]
        )
        if outcomes != values[total]:
            raise ContractError(f"counters.{total}: accepted_rejected_aborted_mismatch")
        if values[f"{stage}_first"] > values[total]:
            raise ContractError(f"counters.{stage}_first: exceeds_{total}")
        if values[f"{stage}_accepted"] > values[f"{stage}_first"]:
            raise ContractError(f"counters.{stage}_accepted: exceeds_first")
        if values[f"{stage}_oracle_evaluations"] > values[total]:
            raise ContractError(f"counters.{stage}_oracle_evaluations: exceeds_{total}")
        if values[f"{stage}_first"] == 0 and values[total] != 0:
            raise ContractError(f"counters.{total}: nonzero_without_{stage}_first")

    for total, multiplier in (("R0", 16), ("R2", 12), ("R3", 22)):
        if values[total] > _pow2(multiplier) * values["A"]:
            raise ContractError(f"counters.{total}: cap_exceeded")
    if values["M"] > values["A"]:
        raise ContractError("counters.M: exceeds_A")

    # A first reservation is one per admitted H0 attempt.  Later stages have at
    # most one first reservation per attempt; terminal outcomes are disjoint and
    # actual observed oracle evaluations are tracked separately.
    for stage in ("fs2", "fs3"):
        if values[f"{stage}_first"] > values["A"]:
            raise ContractError(f"counters.{stage}_first: exceeds_A")
    return values


def _cap_counters() -> dict[str, Any]:
    A = V = _pow2(32)
    R0 = _pow2(16) * A
    R2 = _pow2(12) * A
    R3 = _pow2(22) * A
    return {
        "Q": _pow2(128),
        "A": A,
        "V": V,
        "M": A,
        "E_U": A,
        "S": A,
        "R0": R0,
        "R2": R2,
        "R3": R3,
        "h0_first": A,
        "h0_accepted": A,
        "h0_rejected": R0 - A,
        "h0_aborted": 0,
        "h0_oracle_evaluations": R0,
        "fs2_first": A,
        "fs2_accepted": A,
        "fs2_rejected": R2 - A,
        "fs2_aborted": 0,
        "fs2_oracle_evaluations": R2,
        "fs3_first": A,
        "fs3_accepted": A,
        "fs3_rejected": R3 - A,
        "fs3_aborted": 0,
        "fs3_oracle_evaluations": R3,
        "one_commitment_per_attempt": True,
        "source_generation_admitted": True,
        "U96_nonzero": True,
        "source_coins_independent": True,
        "source_cap_enforced": True,
    }


def _qrom_value(counters: Mapping[str, Any]) -> tuple[int, int, Fraction, Fraction]:
    q_alg = (
        counters["Q"]
        + 35 * counters["A"]
        + 38 * counters["V"]
        + counters["R0"]
        + counters["R2"]
        + counters["R3"]
    )
    q_eff = q_alg + 38
    uncapped = Fraction(1020 * q_eff**3, _pow2(512)) + Fraction(30 * q_eff**2, _pow2(263))
    return q_alg, q_eff, uncapped, min(Fraction(1, 1), uncapped)


def _qrom_cap_summary() -> dict[str, Any]:
    counters = _cap_counters()
    q_alg, q_eff, uncapped, bound = _qrom_value(counters)
    q_probe = math.isqrt(_pow2(257)) + 1  # exact ceil(sqrt(2)*2^128)
    probe_uncapped = Fraction(1020 * q_probe**3, _pow2(512)) + Fraction(30 * q_probe**2, _pow2(263))
    formal = _formal_result_cap()
    formal_counters = formal["counters"]
    for key in _EXPECTED_COUNTER_FIELDS:
        _match_formal_int(counters[key], formal_counters, key, f"cap_counters.{key}")
    for key in _EXPECTED_PRECONDITION_FLAGS:
        _match_formal_bool(counters[key], formal_counters, key, f"cap_counters.{key}")
    formal_qrom = formal["qrom"]
    formal_q_alg = _match_formal_int(q_alg, formal_qrom, "q_alg", "qrom.cap.q_alg")
    formal_q_eff = _match_formal_int(q_eff, formal_qrom, "q_eff", "qrom.cap.q_eff")
    formal_q = _match_formal_int(q_eff, formal_qrom, "q", "qrom.cap.q")
    formal_probe_q = _match_formal_int(q_probe, formal_qrom, "half_success_probe_q", "qrom.cap.probe_q")
    formal_probe_q_eff = _match_formal_int(
        q_probe, formal_qrom, "half_success_probe_q_eff", "qrom.cap.probe_q_eff"
    )
    return {
        "cap_counters": {key: formal_counters[key] for key in (*_EXPECTED_COUNTER_FIELDS, *_EXPECTED_PRECONDITION_FLAGS)},
        "q_alg_at_declared_caps": formal_q_alg,
        "q_eff_at_declared_caps": formal_q_eff,
        "q_at_declared_caps": formal_q,
        "q_alg_overhead_at_declared_caps": _match_formal_int(
            q_alg - _pow2(128), formal_qrom, "q_alg_overhead", "qrom.cap.q_alg_overhead"
        ),
        "q_overhead_at_declared_caps": _match_formal_int(
            q_eff - _pow2(128), formal_qrom, "q_overhead", "qrom.cap.q_overhead"
        ),
        "q_alg_overhead_formula_at_declared_caps": "4264009*2^32",
        "q_overhead_formula_at_declared_caps": "4264009*2^32+38",
        "q_overhead_lt_2^55": _match_formal_bool(
            q_eff - _pow2(128) < _pow2(55), formal_qrom, "q_overhead_lt_2^55", "qrom.cap.overhead_gate"
        ),
        "uncapped_bound_at_declared_caps": _match_formal_fraction(
            uncapped, formal_qrom, "uncapped", "qrom.cap.uncapped"
        ),
        "bound_at_declared_caps": _match_formal_fraction(bound, formal_qrom, "bound", "qrom.cap.bound"),
        "bound_lt_one_quarter": _match_formal_bool(
            bound < Fraction(1, 4), formal_qrom, "bound_lt_one_quarter", "qrom.cap.quarter_gate"
        ),
        "half_success_probe_q": formal_probe_q,
        "half_success_probe_q_eff": formal_probe_q_eff,
        "half_success_probe_formula": "ceil(2^128.5)",
        "half_success_probe_bound": _match_formal_fraction(
            probe_uncapped, formal_qrom, "half_success_probe_bound", "qrom.cap.probe_bound"
        ),
        "half_success_probe_lt_one_half": _match_formal_bool(
            probe_uncapped < Fraction(1, 2),
            formal_qrom,
            "half_success_probe_lt_one_half",
            "qrom.cap.probe_gate",
        ),
        "threshold_statement": "integer q_eff with B_snd(q_eff)>=1/2 is greater than ceil(2^128.5)",
    }


def qrom_bound(manifest: Mapping[str, Any], counters: Mapping[str, Any]) -> dict[str, Any]:
    values = _require_counters(manifest, counters)
    q_alg, q_eff, uncapped, bound = _qrom_value(values)
    formal = _formal_result_for_counters(values)
    formal_counters = formal["counters"]
    for key in _EXPECTED_COUNTER_FIELDS:
        _match_formal_int(values[key], formal_counters, key, f"runtime_counters.{key}")
    for key in _EXPECTED_PRECONDITION_FLAGS:
        _match_formal_bool(values[key], formal_counters, key, f"runtime_counters.{key}")
    formal_qrom = formal["qrom"]
    return {
        "formula": "min(1,1020*q_eff^3/2^512+30*q_eff^2/2^263)",
        "q_alg": _match_formal_int(q_alg, formal_qrom, "q_alg", "qrom.runtime.q_alg"),
        "q_eff": _match_formal_int(q_eff, formal_qrom, "q_eff", "qrom.runtime.q_eff"),
        "q": _match_formal_int(q_eff, formal_qrom, "q", "qrom.runtime.q"),
        "q_alg_formula": "Q+35*A+38*V+R0+R2+R3",
        "q_eff_formula": "q_alg+38",
        "uncapped_bound": _match_formal_fraction(
            uncapped, formal_qrom, "uncapped", "qrom.runtime.uncapped"
        ),
        "bound": _match_formal_fraction(bound, formal_qrom, "bound", "qrom.runtime.bound"),
        "accounting": {key: formal_counters[key] for key in ("Q", "A", "V", "R0", "R2", "R3")},
        "bound_kind": "conditional ideal-QROM constant-success query bound",
        "not_a_2^-128_false_acceptance_probability": True,
        "not_concrete_quantum_gate_or_work_bound": True,
    }


def _adaptive_reprogramming_cap(counters: Mapping[str, Any]) -> dict[str, Any]:
    P = counters["A"] + counters["R2"] + counters["R3"]
    q_hist = (
        counters["Q"]
        + 39 * counters["A"]
        + 41 * counters["V"]
        + counters["R0"]
        + counters["R2"]
        + counters["R3"]
    )
    linear = Fraction(P * q_hist, 2 * _pow2(512))
    target = Fraction(1, _pow2(137))
    remaining = target - linear
    sqrt_square = Fraction(P * P * q_hist, _pow2(512))
    sqrt_term_less_than_remaining = remaining > 0 and sqrt_square < remaining * remaining
    formal = _formal_result_for_counters(counters)
    formal_privacy = formal["privacy"]
    formal_p = _match_formal_int(P, formal_privacy, "P_upper_bound", "privacy.adaptive.P_upper_bound")
    formal_q_hist = _match_formal_int(q_hist, formal_privacy, "q_hist", "privacy.adaptive.q_hist")
    formal_q_hist_overhead = _match_formal_int(
        q_hist - counters["Q"], formal_privacy, "q_hist_overhead", "privacy.adaptive.q_hist_overhead"
    )
    formal_linear = _match_formal_fraction(
        linear, formal_privacy, "linear_term", "privacy.adaptive.linear_term"
    )
    formal_target = _match_formal_fraction(target, formal_privacy, "target", "privacy.adaptive.target")
    formal_sqrt = _formal_fraction(formal_privacy, "sqrt_term", "privacy.adaptive.sqrt_term")
    if formal_sqrt != sqrt_square:
        raise ContractError(
            f"formal_arithmetic: privacy.adaptive.sqrt_term: mismatch; python={_fraction_payload(sqrt_square)}; lean={_fraction_payload(formal_sqrt)}"
        )
    formal_remaining = _match_formal_fraction(
        remaining, formal_privacy, "remaining", "privacy.adaptive.remaining"
    )
    formal_sqrt_radicand = _match_formal_int(
        P * P * q_hist, formal_privacy, "sqrt_radicand", "privacy.adaptive.sqrt_radicand"
    )
    formal_strict = _match_formal_bool(
        sqrt_term_less_than_remaining,
        formal_privacy,
        "sqrt_square_lt_remaining_square",
        "privacy.adaptive.sqrt_square_lt_remaining_square",
    )
    formal_remaining_nonnegative = _match_formal_bool(
        remaining >= 0,
        formal_privacy,
        "remaining_nonnegative",
        "privacy.adaptive.remaining_nonnegative",
    )
    formal_q_hist_ratio = _match_formal_bool(
        q_hist < _pow2(128) * (1 + Fraction(1, _pow2(73))),
        formal_privacy,
        "q_hist_lt_cap_ratio",
        "privacy.adaptive.q_hist_lt_cap_ratio",
    )
    return {
        "P_upper_bound": formal_p,
        "P_formula": "A+R2+R3",
        "q_hist": formal_q_hist,
        "q_hist_formula": "Q+39*A+41*V+R0+R2+R3",
        "q_hist_overhead": formal_q_hist_overhead,
        "q_hist_overhead_formula_at_caps": "4264016*2^32",
        "q_hist_lt_2^128_times_1_plus_2^-73": formal_q_hist_ratio,
        "exact_theorem_formula": "min(1,sum_r[sqrt(qhat_r*2^-512)+qhat_r*2^-512/2])",
        "closed_cap_formula": "P*(sqrt(q_hist/2^512)+q_hist/(2*2^512))",
        "linear_term": formal_linear,
        "sqrt_term": {"radicand": formal_q_hist, "denominator": _pow2(512), "square_comparison_denominator_power": 512},
        "remaining": formal_remaining,
        "target": formal_target,
        "strictly_below_2^-137": formal_strict,
        "remaining_nonnegative": formal_remaining_nonnegative,
        "chronological_overwrite_on_repeated_input": True,
        "H0_reprogrammed": False,
    }


def privacy_bound(manifest: Mapping[str, Any], counters: Mapping[str, Any]) -> dict[str, Any]:
    values = _require_counters(manifest, counters)
    ar = _adaptive_reprogramming_cap(values)
    M_switch = Fraction(values["M"] * 85297284, _pow2(128))
    S_switch = Fraction(values["S"] * 1253, _pow2(128))
    formal = _formal_result_for_counters(values)
    formal_counters = formal["counters"]
    for key in _EXPECTED_COUNTER_FIELDS:
        _match_formal_int(values[key], formal_counters, key, f"privacy_runtime_counters.{key}")
    for key in _EXPECTED_PRECONDITION_FLAGS:
        _match_formal_bool(values[key], formal_counters, key, f"privacy_runtime_counters.{key}")
    formal_privacy = formal["privacy"]
    formal_bit_switch = _match_formal_fraction(
        M_switch, formal_privacy, "bit_switching", "privacy.bit_hiding.switching_term"
    )
    formal_source_switch = _match_formal_fraction(
        S_switch, formal_privacy, "source_switching", "privacy.source_hiding.switching_term"
    )
    formal_combined_switch = _match_formal_fraction(
        Fraction(85298537, _pow2(96)),
        formal_privacy,
        "combined_switching_at_caps",
        "privacy.combined_switching.term",
    )
    formal_combined_available = _match_formal_bool(
        values["source_cap_enforced"],
        formal_privacy,
        "combined_switching_available",
        "privacy.combined_switching.available",
    )
    formal_source_binding = _match_formal_fraction(
        Fraction(values["E_U"], _pow2(257)),
        formal_privacy,
        "source_binding",
        "privacy.source_binding.source_component",
    )
    formal_cap_privacy = _formal_result_cap()["privacy"]
    formal_bit_cap = _match_formal_fraction(
        Fraction(85297284, _pow2(96)),
        formal_cap_privacy,
        "bit_switching",
        "privacy.bit_hiding.switching_term_under_cap",
    )
    formal_source_binding_cap = _match_formal_fraction(
        Fraction(1, _pow2(225)),
        formal_cap_privacy,
        "source_binding",
        "privacy.source_binding.source_component_under_cap",
    )
    formal_q_star = _match_formal_int(
        2 * ar["q_hist"], formal_privacy, "q_star_without_overlay", "privacy.Q_star_without_overlay"
    )
    result: dict[str, Any] = {
        "adaptive_reprogramming": ar,
        "bit_hiding": {
            "formula": "M*(397*alpha4+33*alpha2048+33*alpha989+85297284/2^128)",
            "M": formal_counters["M"],
            "switching_term": formal_bit_switch,
            "switching_term_under_M_cap": formal_bit_cap,
            "alpha_terms_status": "UNKNOWN",
        },
        "source_hiding": {
            "formula": "S*(alpha8+alpha50+1253/2^128)",
            "S": formal_counters["S"],
            "switching_term": formal_source_switch,
            "S_cap_enforced": formal_combined_available,
            "alpha_terms_status": "UNKNOWN",
        },
        "combined_switching": {
            "available": formal_combined_available,
            "term": formal_combined_switch if formal_combined_available else UNKNOWN,
            "reason_if_unavailable": None if formal_combined_available else "S<=2^32 was not separately enforced",
        },
        "Q_star_without_overlay": formal_q_star,
        "Q_star_formula": "Q*<=2*q_hist+explicit_overlay",
        "overlay_work": "O(P*L_FS) per QRO call",
        "hidden_key_AES_access": "classical-input Q1 only; public AES quantum access is separate",
        "unknowns": ["alpha_s(T*,Q*)", "T*", "epsilon_coins", "Adv_SHAKE_priv", "RNG_and_custody"],
        "not_a_numeric_privacy_qualification": True,
        "endpoint_normalization": {
            "delta_lr_definition": "Delta_LR=abs(Pr[D(View0)=1]-Pr[D(View1)=1])",
            "one_sided_endpoint_definition": "E_one_sided bounds each real-to-common-ideal side E0 and E1",
            "common_ideal_premise": True,
            "conversion": "Delta_LR<=min(1,E0+E1)<=min(1,2*E_one_sided)",
            "guessing_success": "Pguess=(1+Delta_LR)/2",
            "strict_half_success_condition": "E_one_sided<1/4 implies Delta_LR<1/2 and Pguess<3/4",
            "not_equivalent": True,
        },
    }
    result["source_binding"] = {
        "formula": "E_U*2^-257+other_stat",
        "E_U": formal_counters["E_U"],
        "source_component": formal_source_binding,
        "source_component_under_E_U_cap": formal_source_binding_cap,
        "other_stat": UNKNOWN,
        "statistical_and_computational_ledgers_separate": True,
        "privacy_role": "source-U binding is not inserted into source hiding unless the reduction explicitly conditions on it",
        "integrity_role": "retain the source-U/reference union under its stated source and operation-reference premises",
        "not_silently_dropped": True,
    }
    return result


def _source_collision_game(privacy_reduction: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate the admissible, bounded source-view collision game.

    The game is deliberately separate from the source AES switching residual.  It
    is a normalized left/right diagnostic for the legal native source relation,
    not a measured attack and not another term in the v3 privacy composition.
    """

    game = _require_mapping(
        _required(privacy_reduction, "source_collision_game"),
        "privacy_reduction.source_collision_game",
    )
    _expect(game, "status", "ADMISSIBLE_BOUNDED_SOURCE_COLLISION_GAME")
    _expect(game, "fixed_aes_permutation_premise", True)
    _expect(game, "native_or_protocol_change", False)

    relation = _require_mapping(
        _required(game, "source_relation"),
        "privacy_reduction.source_collision_game.source_relation",
    )
    for key, expected in {
        "word_bits": _SOURCE_WORD_BITS,
        "word_count": _SOURCE_WORD_COUNT,
        "lower_hex": "0x1122334455667788",
        "upper_hex": "0xddeeff0011223344",
        "inclusive": True,
        "interval_size": str(_SOURCE_UPPER - _SOURCE_LOWER + 1),
        "interval_size_lower_bound": "3*2^64/4",
    }.items():
        _expect(relation, key, expected, f"privacy_reduction.source_collision_game.source_relation.{key}")

    world_zero = _require_mapping(
        _required(game, "world_0"),
        "privacy_reduction.source_collision_game.world_0",
    )
    for key, expected in {
        "name": "constant_legal_vector",
        "vector": "100 repetitions of the lower endpoint",
        "legal": True,
        "collision_probability": "0 under a fixed AES permutation with 50 distinct G1 pad inputs",
    }.items():
        _expect(world_zero, key, expected, f"privacy_reduction.source_collision_game.world_0.{key}")

    world_one = _require_mapping(
        _required(game, "world_1"),
        "privacy_reduction.source_collision_game.world_1",
    )
    _expect(world_one, "name", "bounded_independent_interval_vector")
    _expect(world_one, "legal_when_not_fallback", True)
    sampler = _require_mapping(
        _required(world_one, "sampler"),
        "privacy_reduction.source_collision_game.world_1.sampler",
    )
    for key, expected in {
        "candidates_per_word": _SOURCE_DRAWS_PER_WORD,
        "word_count": _SOURCE_WORD_COUNT,
        "max_candidate_draws": _SOURCE_DRAWS_PER_WORD * _SOURCE_WORD_COUNT,
        "keep_rule": "keep the first independent 64-bit candidate in the inclusive legal interval",
        "fallback_rule": "if any word exhausts, use the world_0 constant legal vector",
        "per_word_exhaustion_upper_bound": "4^-128",
        "any_word_fallback_upper_bound": "100*4^-128",
        "conditional_distribution": "conditional on no fallback, the 100 accepted words are independent uniform samples from the interval",
        "fallback_collision_probability": "0",
    }.items():
        _expect(sampler, key, expected, f"privacy_reduction.source_collision_game.world_1.sampler.{key}")

    distinguisher = _require_mapping(
        _required(game, "distinguisher"),
        "privacy_reduction.source_collision_game.distinguisher",
    )
    for key, expected in {
        "public_block_count": _SOURCE_PUBLIC_BLOCK_COUNT,
        "words_per_block": 2,
        "disjoint_pair_count": _SOURCE_DISJOINT_PAIR_COUNT,
        "comparison_count": math.comb(_SOURCE_PUBLIC_BLOCK_COUNT, 2),
        "predicate": "D=1 iff any collision occurs among the 25 disjoint pairs of the 50 public 128-bit C blocks",
        "pad_inputs": "LE128(2^127+j) for j=0..49",
    }.items():
        _expect(distinguisher, key, expected, f"privacy_reduction.source_collision_game.distinguisher.{key}")

    bound = _require_mapping(
        _required(game, "bound"),
        "privacy_reduction.source_collision_game.bound",
    )
    for key, expected in {
        "word_xor_intersection_count_lower_bound": "2*m-2^64",
        "word_xor_probability_lower_bound": "2^-65",
        "block_pair_probability_lower_bound": "2^-130",
        "uniform_interval_collision_lower_bound": "1-(1-2^-130)^25",
        "bounded_collision_lower_bound": "(1-100*4^-128)*(1-(1-2^-130)^25)",
        "scaled_bound_proof": "100*4^-128<1/2 and 1-(1-2^-130)^25>2^-127, hence the scaled bound is >2^-128",
    }.items():
        _expect(bound, key, expected, f"privacy_reduction.source_collision_game.bound.{key}")
    _expect(bound, "strictly_greater_than_2^-128", True, "privacy_reduction.source_collision_game.bound.strictly_greater_than_2^-128")

    composition = _require_mapping(
        _required(game, "composition"),
        "privacy_reduction.source_collision_game.composition",
    )
    for key, expected in {
        "collision_is_not_additional_privacy_loss": True,
        "existing_source_switching_residual": "S*(alpha8+alpha50+1253/2^128)",
        "interpretation": "normalized left/right source-view diagnostic only; it is not a measured leak or a second composition term",
    }.items():
        _expect(composition, key, expected, f"privacy_reduction.source_collision_game.composition.{key}")

    interval_size = _SOURCE_UPPER - _SOURCE_LOWER + 1
    modulus = _pow2(_SOURCE_WORD_BITS)
    fallback_upper = Fraction(_SOURCE_WORD_COUNT, _pow2(256))
    word_intersection_lower = 2 * interval_size - modulus
    word_probability_exact_lower = Fraction(word_intersection_lower, interval_size * interval_size)
    word_probability_conservative_lower = Fraction(1, 2 * modulus)
    block_probability_conservative_lower = word_probability_conservative_lower**2
    uniform_collision_lower = 1 - (1 - block_probability_conservative_lower) ** _SOURCE_DISJOINT_PAIR_COUNT
    bounded_collision_lower = (1 - fallback_upper) * uniform_collision_lower
    if interval_size < 3 * modulus // 4:
        raise ContractError("source_collision_game: legal_interval_below_three_quarters")
    if word_probability_exact_lower < word_probability_conservative_lower:
        raise ContractError("source_collision_game: word_xor_lower_bound_mismatch")
    if not uniform_collision_lower > Fraction(1, _pow2(127)):
        raise ContractError("source_collision_game: uniform_collision_lower_bound_not_strict")
    if not fallback_upper < Fraction(1, 2):
        raise ContractError("source_collision_game: fallback_bound_not_below_half")
    if not bounded_collision_lower > Fraction(1, _pow2(128)):
        raise ContractError("source_collision_game: bounded_lower_bound_not_strict")

    result = dict(game)
    result["computed"] = {
        "interval_size": interval_size,
        "interval_acceptance_probability": _fraction_payload(Fraction(interval_size, modulus)),
        "interval_acceptance_probability_ge_3/4": Fraction(interval_size, modulus) >= Fraction(3, 4),
        "word_xor_intersection_count_lower_bound": word_intersection_lower,
        "word_xor_probability_lower_bound_exact": _fraction_payload(word_probability_exact_lower),
        "word_xor_probability_lower_bound": _fraction_payload(word_probability_conservative_lower),
        "block_pair_probability_lower_bound": _fraction_payload(block_probability_conservative_lower),
        "uniform_interval_collision_lower_bound": _fraction_payload(uniform_collision_lower),
        "fallback_probability_upper_bound": _fraction_payload(fallback_upper),
        "fallback_probability_upper_bound_decimal": f"{float(fallback_upper):.17g}",
        "bounded_collision_lower_bound": _fraction_payload(bounded_collision_lower),
        "bounded_collision_lower_bound_decimal": f"{float(bounded_collision_lower):.17g}",
        "bounded_collision_lower_bound_log2_approx": f"{math.log2(float(bounded_collision_lower)):.17g}",
        "world_0_collision_probability": _fraction_payload(Fraction(0, 1)),
        "delta_lr_lower_bound": _fraction_payload(bounded_collision_lower),
        "uniform_lower_bound_strictly_greater_than_2^-127": uniform_collision_lower > Fraction(1, _pow2(127)),
        "bounded_lower_bound_strictly_greater_than_2^-128": bounded_collision_lower > Fraction(1, _pow2(128)),
        "max_candidate_draws": _SOURCE_DRAWS_PER_WORD * _SOURCE_WORD_COUNT,
        "d_128_bit_comparisons": math.comb(_SOURCE_PUBLIC_BLOCK_COUNT, 2),
        "conditional_interval_words_independent_uniform": True,
        "fallback_cannot_contribute_collision": True,
        "no_native_rng_or_protocol_change": True,
    }
    return result


def _switching_snapshot(M: int, S: int, target: Fraction) -> dict[str, Any]:
    numerator = 85297284 * M + 1253 * S
    term = Fraction(numerator, _pow2(128))
    # For a term num/2^d, this is the largest integer b with term <= 2^-b.
    exponent_floor_bits = 128 - (numerator - 1).bit_length()
    return {
        "M": M,
        "S": S,
        "raw_numerator": numerator,
        "numerator": term.numerator,
        "term": _fraction_payload(term),
        "bound_exponent_floor_bits": exponent_floor_bits,
        "strictly_exceeds_target": term > target,
    }


def _composed_privacy_analysis(
    feasibility: Mapping[str, Any],
    *,
    M_cap: int,
    S_cap: int,
    known_residual: Fraction,
    alpha_weight: int,
    generic_screen: Mapping[str, Any],
) -> dict[str, Any]:
    model = _require_mapping(
        _required(
            _require_mapping(_required(feasibility, "constant_success_work_model"), "constant_success_work_model"),
            "composed_privacy_analysis",
        ),
        "concrete_feasibility.constant_success_work_model.composed_privacy_analysis",
    )
    exposure = _require_mapping(_required(model, "exposure_map"), "composed_privacy_analysis.exposure_map")
    tree = _require_mapping(_required(exposure, "tree_generator"), "composed_privacy_analysis.exposure_map.tree_generator")
    opening = _require_mapping(_required(exposure, "opening_and_transcript"), "composed_privacy_analysis.exposure_map.opening_and_transcript")
    source = _require_mapping(_required(exposure, "source_generator"), "composed_privacy_analysis.exposure_map.source_generator")
    dependence = _require_mapping(_required(exposure, "dependence_boundary"), "composed_privacy_analysis.exposure_map.dependence_boundary")
    if _exact_int(_required(tree, "leaf_count"), "composed_privacy_analysis.tree_generator.leaf_count") != 6400:
        raise ContractError("composed_privacy_analysis.tree_generator: leaf_count_mismatch")
    if _exact_int(_required(tree, "hidden_leaf_count"), "composed_privacy_analysis.tree_generator.hidden_leaf_count") != 33:
        raise ContractError("composed_privacy_analysis.tree_generator: hidden_leaf_count_mismatch")
    if _exact_int(_required(tree, "hidden_path_union_nodes"), "composed_privacy_analysis.tree_generator.hidden_path_union_nodes") != 397:
        raise ContractError("composed_privacy_analysis.tree_generator: hidden_path_union_mismatch")
    if _exact_int(_required(tree, "leaf_expansion_AES_blocks"), "composed_privacy_analysis.tree_generator.leaf_expansion_AES_blocks") != 8:
        raise ContractError("composed_privacy_analysis.tree_generator: leaf_expansion_cost_mismatch")
    if _exact_int(_required(tree, "hidden_stream_AES_blocks"), "composed_privacy_analysis.tree_generator.hidden_stream_AES_blocks") != 989:
        raise ContractError("composed_privacy_analysis.tree_generator: stream_cost_mismatch")
    if _exact_int(_required(opening, "frontier_seed_slots"), "composed_privacy_analysis.opening_and_transcript.frontier_seed_slots") != 229:
        raise ContractError("composed_privacy_analysis.opening_and_transcript: frontier_width_mismatch")
    if _exact_int(_required(opening, "selected_commitment_count"), "composed_privacy_analysis.opening_and_transcript.selected_commitment_count") != 33:
        raise ContractError("composed_privacy_analysis.opening_and_transcript: selected_commitment_count_mismatch")
    if _exact_int(_required(source, "G0_AES_blocks"), "composed_privacy_analysis.source_generator.G0_AES_blocks") != 8:
        raise ContractError("composed_privacy_analysis.source_generator: G0_cost_mismatch")
    if _exact_int(_required(source, "G1_AES_blocks"), "composed_privacy_analysis.source_generator.G1_AES_blocks") != 50:
        raise ContractError("composed_privacy_analysis.source_generator: G1_cost_mismatch")
    if _required(dependence, "root_descendants_are_independent") is not False:
        raise ContractError("composed_privacy_analysis.dependence_boundary: independent_descendant_claim")
    if _required(dependence, "stream_key_is_independent_before_hybrid") is not False:
        raise ContractError("composed_privacy_analysis.dependence_boundary: independent_stream_key_claim")
    if _required(dependence, "source_G1_key_is_independent_before_G0_hybrid") is not False:
        raise ContractError("composed_privacy_analysis.dependence_boundary: independent_source_key_claim")

    hybrid_loss = _require_mapping(
        _required(generic_screen, "hybrid_loss_analysis"),
        "generic_key_search_screen.hybrid_loss_analysis",
    )
    effective_weight_cap = _exact_int(
        _required(hybrid_loss, "maximum_effective_weight_at_fully_counted_primitive_cap"),
        "generic_key_search_screen.hybrid_loss_analysis.maximum_effective_weight_at_fully_counted_primitive_cap",
    )
    if effective_weight_cap <= 0:
        raise ContractError("composed_privacy_analysis: nonpositive_effective_weight_cap")
    required_reduction = Fraction(alpha_weight, effective_weight_cap)
    known_history = _exact_int(
        _required(
            _require_mapping(_required(generic_screen, "known_history"), "generic_key_search_screen.known_history"),
            "known_history_G_cost_at_declared_caps",
        ),
        "generic_key_search_screen.known_history.known_history_G_cost_at_declared_caps",
    )
    primitive_cap = _require_mapping(
        _required(generic_screen, "at_work_cap_fully_counted_primitive"),
        "generic_key_search_screen.at_work_cap_fully_counted_primitive",
    )
    selected_bound = _require_mapping(
        _required(model, "selected_conditional_bound"),
        "composed_privacy_analysis.selected_conditional_bound",
    )
    return {
        "status": _required(model, "status"),
        "scope": _required(model, "scope"),
        "exposure_map": {
            "tree_generator": tree,
            "opening_and_transcript": opening,
            "source_generator": source,
            "dependence_boundary": dependence,
            "request_and_retry_accounting": _required(exposure, "request_and_retry_accounting"),
            "qro_and_candidate_access": _required(exposure, "qro_and_candidate_access"),
        },
        "approach_comparison": _required(model, "approach_comparison"),
        "selected_argument": _required(model, "selected_argument"),
        "selected_conditional_bound": {
            "formula": selected_bound["formula"],
            "direct_generator_term": selected_bound["direct_generator_term"],
            "switching_term_at_declared_caps": _fraction_payload(Fraction(85298537, _pow2(96))),
            "safe_budget_before_unknown_terms": _fraction_payload(known_residual),
            "unknown_terms": selected_bound["unknown_terms"],
            "condition_before_unknown_terms": selected_bound["condition_before_unknowns"],
            "current_proven_hybrid_upper_bound": selected_bound["current_proven_hybrid_upper_bound"],
            "current_proven_effective_weight_at_caps": alpha_weight,
            "required_effective_weight_at_fully_counted_single_key_cap": effective_weight_cap,
            "required_reduction_factor_from_current_weight": f"{float(required_reduction):.17g}",
            "not_a_joint_target_oracle": True,
        },
        "shared_work_ledger": {
            "one_total_budget": _required(model, "shared_work_ledger")["one_total_budget"],
            "total_work_condition": _required(model, "shared_work_ledger")["total_work_condition"],
            "query_condition": _required(model, "shared_work_ledger")["query_condition"],
            "memory_condition": _required(model, "shared_work_ledger")["memory_condition"],
            "candidate_check_condition": _required(model, "shared_work_ledger")["candidate_check_condition"],
            "reversibility_condition": _required(model, "shared_work_ledger")["reversibility_condition"],
            "known_history_G_cost_at_declared_caps": known_history,
            "primitive_cap_total_G": _exact_int(_required(primitive_cap, "total_G_cost"), "primitive_cap.total_G_cost"),
            "primitive_cap_remaining_G_slack": _exact_int(
                _required(primitive_cap, "remaining_G_slack_below_2^128"),
                "primitive_cap.remaining_G_slack_below_2^128",
            ),
            "qrams_are_not_free": True,
            "parallelism_does_not_reduce_total_G": True,
        },
        "cap_evaluation": {
            "M_cap": M_cap,
            "S_cap": S_cap,
            "current_effective_weight": alpha_weight,
            "current_effective_weight_formula": "463*M+2*S",
            "required_effective_weight": effective_weight_cap,
            "known_residual_before_unknown_terms": _fraction_payload(known_residual),
        },
        "obstruction": _required(model, "obstruction"),
        "architecture_remedy": _required(model, "architecture_remedy"),
        "model_restrictions": _required(model, "model_restrictions"),
    }


def _bounded_generator_feasibility_proposal(
    feasibility: Mapping[str, Any],
    *,
    M_cap: int,
    V_cap: int,
    S_cap: int,
    Q_cap: int,
    P_cap_constant: int,
    q_hist_cap_constant: int,
) -> dict[str, Any]:
    model = _require_mapping(
        _required(
            _require_mapping(_required(feasibility, "constant_success_work_model"), "constant_success_work_model"),
            "bounded_generator_feasibility_proposal",
        ),
        "concrete_feasibility.constant_success_work_model.bounded_generator_feasibility_proposal",
    )
    candidate = _require_mapping(
        _required(model, "candidate_definition"),
        "bounded_generator_feasibility_proposal.candidate_definition",
    )
    tree = _require_mapping(
        _required(candidate, "tree"), "bounded_generator_feasibility_proposal.candidate_definition.tree"
    )
    leaf = _require_mapping(
        _required(candidate, "leaf"), "bounded_generator_feasibility_proposal.candidate_definition.leaf"
    )
    stream = _require_mapping(
        _required(candidate, "stream"), "bounded_generator_feasibility_proposal.candidate_definition.stream"
    )
    source = _require_mapping(
        _required(candidate, "source"), "bounded_generator_feasibility_proposal.candidate_definition.source"
    )
    opening = _require_mapping(
        _required(model, "opening_geometry"), "bounded_generator_feasibility_proposal.opening_geometry"
    )
    coupling = _require_mapping(
        _required(model, "coupling_lemma"), "bounded_generator_feasibility_proposal.coupling_lemma"
    )
    composition = _require_mapping(
        _required(model, "composition"), "bounded_generator_feasibility_proposal.composition"
    )
    superseded_design = _require_mapping(
        _required(candidate, "superseded_multi_block_design"),
        "bounded_generator_feasibility_proposal.candidate_definition.superseded_multi_block_design",
    )

    expected_tree = {
        "internal_node_count": 6399,
        "leaf_count": 6400,
        "heap_node_count": 12799,
        "stream_seed_count_per_commitment": 6400,
        "hidden_seed_count_per_commitment": 19199,
    }
    for key, expected in expected_tree.items():
        actual = _exact_int(
            _required(tree, key), f"bounded_generator_feasibility_proposal.candidate_definition.tree.{key}"
        )
        if actual != expected:
            raise ContractError(f"bounded_generator_feasibility_proposal.tree: {key}_mismatch")
    for key, expected in (
        ("commitment_sd_bits", 256),
        ("commitment_tail_bits", 768),
        ("commitment_bytes", 96),
        ("row_bytes", 15823),
    ):
        actual = _exact_int(
            _required(leaf if key != "row_bytes" else stream, key),
            f"bounded_generator_feasibility_proposal.{key}",
        )
        if actual != expected:
            raise ContractError(f"bounded_generator_feasibility_proposal: {key}_mismatch")
    if _exact_int(_required(opening, "T_open"), "bounded_generator_feasibility_proposal.opening_geometry.T_open") != 229:
        raise ContractError("bounded_generator_feasibility_proposal: T_open_mismatch")
    if _exact_int(_required(opening, "selected_leaf_count"), "bounded_generator_feasibility_proposal.opening_geometry.selected_leaf_count") != 33:
        raise ContractError("bounded_generator_feasibility_proposal: selected_leaf_count_mismatch")
    if _exact_int(_required(opening, "accepted_nh_max"), "bounded_generator_feasibility_proposal.opening_geometry.accepted_nh_max") != 294:
        raise ContractError("bounded_generator_feasibility_proposal: accepted_nh_mismatch")
    if _exact_int(_required(opening, "accepted_marked_internal_max"), "bounded_generator_feasibility_proposal.opening_geometry.accepted_marked_internal_max") != 261:
        raise ContractError("bounded_generator_feasibility_proposal: accepted_internal_mismatch")
    if _exact_int(_required(opening, "accepted_hidden_seed_max"), "bounded_generator_feasibility_proposal.opening_geometry.accepted_hidden_seed_max") != 327:
        raise ContractError("bounded_generator_feasibility_proposal: accepted_hidden_seed_mismatch")
    if _exact_int(_required(opening, "full_retry_abort_hidden_seed_max"), "bounded_generator_feasibility_proposal.opening_geometry.full_retry_abort_hidden_seed_max") != 19199:
        raise ContractError("bounded_generator_feasibility_proposal: retry_fallback_mismatch")
    if _required(source, "mode") != "CURRENT_AES_SOURCE_RETAINED":
        raise ContractError("bounded_generator_feasibility_proposal: source_mode_changed")

    q_hist = Q_cap + q_hist_cap_constant * M_cap
    overlay_program_points = P_cap_constant * M_cap
    q_star = 2 * q_hist + overlay_program_points
    hidden_seed_count = expected_tree["hidden_seed_count_per_commitment"] * M_cap
    leaf_commitment_count = expected_tree["leaf_count"] * M_cap
    source_switching = Fraction(1253 * S_cap, _pow2(128))
    known_residual = Fraction(1, 2) - source_switching - Fraction(1, _pow2(137))
    width_declarations = _require_mapping(
        _required(model, "width_alternatives"),
        "bounded_generator_feasibility_proposal.width_alternatives",
    )
    evaluations: dict[str, Any] = {}
    for width in (384, 512):
        declaration = _require_mapping(
            _required(width_declarations, str(width)),
            f"bounded_generator_feasibility_proposal.width_alternatives.{width}",
        )
        width_bytes = width // 8
        leaf_output_blocks = 1
        stream_blocks_per_row = (15823 + width_bytes - 1) // width_bytes
        if _exact_int(_required(declaration, "leaf_output_blocks"), f"width{width}.leaf_output_blocks") != leaf_output_blocks:
            raise ContractError(f"bounded_generator_feasibility_proposal.width{width}: leaf_block_count_mismatch")
        if _exact_int(_required(declaration, "stream_blocks_per_row"), f"width{width}.stream_blocks_per_row") != stream_blocks_per_row:
            raise ContractError(f"bounded_generator_feasibility_proposal.width{width}: stream_block_count_mismatch")
        per_commitment_queries = (
            2 * expected_tree["internal_node_count"]
            + expected_tree["leaf_count"] * (leaf_output_blocks + stream_blocks_per_row)
        )
        total_generator_queries = per_commitment_queries * M_cap
        superseded_per_commitment = _exact_int(
            _required(
                _require_mapping(
                    _required(superseded_design, "generator_H_queries_per_commitment"),
                    "superseded_multi_block_design.generator_H_queries_per_commitment",
                ),
                str(width),
            ),
            f"superseded_width{width}.generator_H_queries_per_commitment",
        )
        superseded_total_generator_queries = _exact_int(
            _required(
                _require_mapping(
                    _required(superseded_design, "generator_H_queries_at_caps"),
                    "superseded_multi_block_design.generator_H_queries_at_caps",
                ),
                str(width),
            ),
            f"superseded_width{width}.generator_H_queries_at_caps",
        )
        if superseded_total_generator_queries != superseded_per_commitment * M_cap:
            raise ContractError(f"bounded_generator_feasibility_proposal.width{width}: superseded_query_count_mismatch")
        verifier_per_verification = (
            2 * (expected_tree["leaf_count"] - 1)
            + (leaf_output_blocks + stream_blocks_per_row)
            * (expected_tree["leaf_count"] - opening["selected_leaf_count"])
        )
        total_verifier_queries = verifier_per_verification * V_cap
        expected_frontier_seed_bytes = width_bytes
        expected_m4_bytes = 3168 + 229 * expected_frontier_seed_bytes
        expected_frame_bytes = 534370 + (expected_m4_bytes - 10496)
        for key, expected in {
            "frontier_seed_bytes": expected_frontier_seed_bytes,
            "m4_bytes": expected_m4_bytes,
            "frame_bytes_including_40_byte_header": expected_frame_bytes,
            "frame_delta_vs_current": expected_m4_bytes - 10496,
            "generator_H_queries_per_commitment": per_commitment_queries,
            "generator_H_queries_at_caps": total_generator_queries,
            "verifier_generator_H_queries_per_verification": verifier_per_verification,
            "verifier_generator_H_queries_at_caps": total_verifier_queries,
        }.items():
            if _exact_int(_required(declaration, key), f"width{width}.{key}") != expected:
                raise ContractError(f"bounded_generator_feasibility_proposal.width{width}: {key}_mismatch")
        q_hist_v2 = q_hist + total_generator_queries + total_verifier_queries
        q_total = q_star + total_generator_queries + total_verifier_queries
        q_alg_base = Q_cap + (q_hist_cap_constant - 7) * M_cap
        q_alg_single = q_alg_base + total_generator_queries + total_verifier_queries
        qP_single = 41
        q_eff_single = q_alg_single + qP_single
        superseded_q_total = q_star + superseded_total_generator_queries
        superseded_point_count = superseded_total_generator_queries
        seed_collision = Fraction(
            math.comb(hidden_seed_count, 2), _pow2(width)
        )
        keyed_o2h_per_seed = Fraction(2 * q_total, _pow2(width // 2))
        keyed_seed_conditioning = Fraction(
            math.comb(hidden_seed_count, 2), _pow2(width)
        )
        keyed_o2h_privacy_raw = hidden_seed_count * keyed_o2h_per_seed + keyed_seed_conditioning
        keyed_o2h_privacy_bound = min(Fraction(1, 1), keyed_o2h_privacy_raw)
        commitment_collision = Fraction(
            math.comb(leaf_commitment_count, 2), _pow2(768)
        )
        query_hit = Fraction(
            4 * superseded_point_count * superseded_q_total * superseded_q_total
            + 2 * superseded_point_count * overlay_program_points,
            _pow2(width),
        )
        superseded_epsilon_seed_raw = seed_collision + commitment_collision + query_hit
        superseded_epsilon_seed = min(Fraction(1, 1), superseded_epsilon_seed_raw)
        superseded_source_alpha_sum_threshold = (known_residual - superseded_epsilon_seed) / S_cap
        superseded_uniform_alpha_threshold = superseded_source_alpha_sum_threshold / 2
        sum_k = q_eff_single * (q_eff_single + 1) // 2
        sum_choose_k_2 = (q_eff_single + 1) * q_eff_single * (q_eff_single - 1) // 6
        delta_linear_weight = (
            Fraction(1, _pow2(768))
            + Fraction(1, _pow2(1024))
            + Fraction(34, _pow2(512))
            + Fraction(2, _pow2(2112))
            + Fraction(2, _pow2(832))
        )
        delta_sum_upper = (
            Fraction(sum_choose_k_2, _pow2(778))
            + sum_k * delta_linear_weight
            + Fraction(3 * q_eff_single, _pow2(256))
        )
        soundness_row_complete_raw = 10 * q_eff_single * delta_sum_upper
        soundness_row_complete_bound = min(Fraction(1, 1), soundness_row_complete_raw)
        evaluations[str(width)] = {
            "seed_width_bits": width,
            "seed_width_bytes": width_bytes,
            "leaf_output_bits": 1024 + width,
            "leaf_output_blocks": leaf_output_blocks,
            "stream_blocks_per_row": stream_blocks_per_row,
            "tree_child_queries_per_commitment": 2 * expected_tree["internal_node_count"],
            "frontier_seed_bytes": expected_frontier_seed_bytes,
            "m4_bytes": expected_m4_bytes,
            "frame_bytes_including_40_byte_header": expected_frame_bytes,
            "frame_delta_vs_current": expected_m4_bytes - 10496,
            "candidate_total_public_RO_queries_at_caps": q_total,
            "candidate_q_hist_at_caps": q_hist_v2,
            "candidate_q_alg_at_caps": q_alg_single,
            "candidate_qP": qP_single,
            "candidate_q_eff_at_caps": q_eff_single,
            "secret_seed_count_at_caps": hidden_seed_count,
            "secret_H_input_point_count_at_caps": superseded_point_count,
            "current_secret_H_input_point_count_at_caps": total_generator_queries,
            "superseded_conditional_candidate_total_public_RO_queries_at_caps": superseded_q_total,
            "generator_H_queries_per_commitment": per_commitment_queries,
            "verifier_generator_H_queries_per_verification": verifier_per_verification,
            "generator_H_queries_at_caps": total_generator_queries,
            "verifier_generator_H_queries_at_caps": total_verifier_queries,
            "superseded_conditional_seed_collision_term": _fraction_payload(seed_collision),
            "superseded_conditional_leaf_commitment_collision_term": _fraction_payload(commitment_collision),
            "superseded_conditional_quantum_query_hit_term": _fraction_payload(query_hit),
            "superseded_conditional_epsilon_seed_raw": _fraction_payload(superseded_epsilon_seed_raw),
            "superseded_conditional_epsilon_seed_bound": _fraction_payload(superseded_epsilon_seed),
            "superseded_conditional_epsilon_seed_bound_decimal": f"{float(superseded_epsilon_seed):.17g}",
            "superseded_conditional_epsilon_seed_bound_log2_approx": f"{math.log2(float(superseded_epsilon_seed)):.17g}",
            "superseded_conditional_source_alpha_sum_threshold": _fraction_payload(superseded_source_alpha_sum_threshold),
            "superseded_conditional_source_alpha_sum_threshold_decimal": f"{float(superseded_source_alpha_sum_threshold):.17g}",
            "superseded_conditional_uniform_source_alpha_threshold": _fraction_payload(superseded_uniform_alpha_threshold),
            "keyed_o2h_per_seed_bound": _fraction_payload(keyed_o2h_per_seed),
            "keyed_o2h_seed_conditioning_term": _fraction_payload(keyed_seed_conditioning),
            "keyed_o2h_privacy_raw": _fraction_payload(keyed_o2h_privacy_raw),
            "keyed_o2h_privacy_bound": _fraction_payload(keyed_o2h_privacy_bound),
            "keyed_o2h_privacy_bound_decimal": f"{float(keyed_o2h_privacy_bound):.17g}",
            "keyed_o2h_privacy_bound_log2_approx": f"{math.log2(float(keyed_o2h_privacy_bound)):.17g}",
            "privacy_only_source_alpha_sum_threshold": _fraction_payload(
                (known_residual - keyed_o2h_privacy_bound) / S_cap
            ),
            "privacy_only_source_alpha_sum_threshold_decimal": f"{float((known_residual - keyed_o2h_privacy_bound) / S_cap):.17g}",
            "privacy_only_threshold_positive": known_residual > keyed_o2h_privacy_bound,
            "soundness_row_complete_delta_sum_upper": _fraction_payload(delta_sum_upper),
            "soundness_row_complete_bound": _fraction_payload(soundness_row_complete_bound),
            "soundness_row_complete_bound_decimal": f"{float(soundness_row_complete_bound):.17g}",
            "soundness_row_complete_bound_log2_approx": f"{math.log2(float(soundness_row_complete_bound)):.17g}" if soundness_row_complete_bound else "-inf",
            "soundness_status": "CONDITIONAL_ROW_COMPLETE_ONLY_HIDDEN_LEAF_ROW_COMPLETION_UNPROVED",
            "proof_status": "CONDITIONAL_SINGLE_ANSWER_KEYED_PRIVACY_ROW_BINDING_UNPROVED",
            "constant_success_under_zero_remaining_unknowns": None,
        }

    return {
        "status": _required(model, "status"),
        "selection": _required(model, "selection"),
        "scope": _required(model, "scope"),
        "candidate_definition": {
            "encoding": _required(candidate, "encoding"),
            "tree": tree,
            "leaf": leaf,
            "stream": stream,
            "source": source,
            "superseded_multi_block_design": _required(candidate, "superseded_multi_block_design"),
        },
        "literal_public_predicate": _required(model, "literal_public_predicate"),
        "selected_seed_disclosure": _required(model, "selected_seed_disclosure"),
        "opening_geometry": opening,
        "coupling_lemma": coupling,
        "cap_evaluation": {
            "M_cap": M_cap,
            "S_cap": S_cap,
            "Q_cap": Q_cap,
            "P_cap": overlay_program_points,
            "q_hist_at_caps": q_hist,
            "Q_star_base_at_caps": q_star,
            "known_source_switching_at_caps": _fraction_payload(source_switching),
            "known_residual_before_candidate_and_source_alpha": _fraction_payload(known_residual),
        },
        "width_evaluations": evaluations,
        "least_evaluated_width_bits": min(int(width) for width in evaluations),
        "least_sufficient_width_bits": None,
        "minimum_width_status": "UNKNOWN_HIDDEN_LEAF_ROW_COMPLETION",
        "composition": {
            "formula": _required(composition, "formula"),
            "soundness_formula": _required(composition, "soundness_formula"),
            "source_alpha_condition": _required(composition, "source_alpha_condition"),
            "concrete_H_condition": _required(composition, "concrete_H_condition"),
            "privacy_endpoint": _required(composition, "privacy_endpoint"),
            "soundness_boundary": _required(composition, "soundness_boundary"),
            "stream_fork_event": _required(composition, "stream_fork_event"),
            "remaining_unknowns": _required(composition, "remaining_unknowns"),
        },
        "implementation_consequences": _required(model, "implementation_consequences"),
        "unresolved_boundary": _required(model, "unresolved_boundary"),
        "recommendation": _required(model, "recommendation"),
    }


def _bind_formal_v3_rows(
    evaluations: dict[str, Any],
    formal_widths: Mapping[str, Mapping[str, Any]],
) -> None:
    """Require every accepted v3 arithmetic field to agree with Lean."""

    integer_fields = {
        "seed_width_bits": "seed_width_bits",
        "seed_width_bytes": "seed_width_bytes",
        "r": "r",
        "nu_bits": "nu_bits",
        "active_h0_bits": "active_h0_bits",
        "h0_squeeze_bytes": "h0_squeeze_bytes",
        "nu_serialized_bytes": "nu_serialized_bytes",
        "commitment_bytes": "commitment_bytes",
        "leaf_output_bits": "leaf_output_bits",
        "leaf_output_bytes": "leaf_output_bytes",
        "stream_blocks_per_row": "stream_blocks_per_row",
        "frontier_seed_bytes": "frontier_seed_bytes",
        "m4_bytes": "m4_bytes",
        "frame_bytes_including_40_byte_header": "frame_bytes",
        "frame_delta_vs_v2_base": "frame_delta",
        "h0_input_bytes": "h0_input_bytes",
        "h1_vector_128_input_bytes": "h1_vector_128_input_bytes",
        "h1_vector_256_input_bytes": "h1_vector_256_input_bytes",
        "h1_outer_input_bytes": "h1_outer_input_bytes",
        "fs_uhash_bytes": "fs_uhash_bytes",
        "tree_child_queries_per_commitment": "tree_child_queries_per_commitment",
        "generator_H_queries_per_commitment": "generator_H_queries_per_commitment",
        "generator_H_queries_at_caps": "generator_H_queries_at_caps",
        "verifier_generator_H_queries_per_verification": "verifier_generator_H_queries_per_verification",
        "verifier_generator_H_queries_at_caps": "verifier_generator_H_queries_at_caps",
        "candidate_q_hist_at_caps": "candidate_q_hist_at_caps",
        "candidate_q_alg_at_caps": "candidate_q_alg_at_caps",
        "candidate_qP": "candidate_qP",
        "candidate_q_eff_at_caps": "candidate_q_eff_at_caps",
        "candidate_q_H_at_caps": "candidate_q_H_at_caps",
        "candidate_total_public_RO_queries_at_caps": "candidate_total_public_RO_queries_at_caps",
        "secret_seed_count_at_caps": "secret_seed_count_at_caps",
        "hybrid_count_at_caps": "hybrid_count_at_caps",
    }
    fraction_fields = {
        "h0_completion_term": "h0_completion",
        "e_leaf_v3": "e_leaf_v3",
        "eKOS": "eKOS",
        "e2": "e2",
        "e3": "e3",
        "direct_constant_max": "direct_max",
        "delta_cap": "delta_cap",
        "delta_linear_weight": "delta_linear_weight",
        "soundness_delta_sum_upper": "delta_sum_upper",
        "soundness_row_complete_bound": "soundness_bound",
        "generator_privacy_bound": "generator_privacy_bound",
        "seed_collision_term": "seed_collision_term",
    }
    for width, row in evaluations.items():
        formal = formal_widths.get(width)
        if formal is None:
            raise ContractError(f"formal_arithmetic: width{width}: missing")
        _match_formal_int(int(width), formal, "width", f"width{width}.width")
        for field, formal_field in integer_fields.items():
            row[field] = _match_formal_int(
                row[field], formal, formal_field, f"width{width}.{field}"
            )
        for field, formal_field in fraction_fields.items():
            row[field] = _match_formal_fraction(
                Fraction(int(row[field]["numerator"]), int(row[field]["denominator"])),
                formal,
                formal_field,
                f"width{width}.{field}",
            )
        if formal.get("direct_constant_max_name") != row["direct_constant_max_name"]:
            raise ContractError(
                f"formal_arithmetic: width{width}.direct_constant_max_name: mismatch; python={row['direct_constant_max_name']}; lean={formal.get('direct_constant_max_name')}"
            )
        if formal.get("delta_cap_name") != row["delta_cap_name"]:
            raise ContractError(
                f"formal_arithmetic: width{width}.delta_cap_name: mismatch; python={row['delta_cap_name']}; lean={formal.get('delta_cap_name')}"
            )
        row["delta_cap_is_constant_for_all_k"] = _match_formal_bool(
            row["delta_cap_is_constant_for_all_k"],
            formal,
            "delta_cap_is_constant_for_all_k",
            f"width{width}.delta_cap_is_constant_for_all_k",
        )
        comparison = row["direct_constant_comparisons"]
        comparison["e3_ge_e_leaf_v3"] = _match_formal_bool(
            comparison["e3_ge_e_leaf_v3"], formal, "e3_ge_e_leaf_v3", f"width{width}.e3_ge_e_leaf_v3"
        )
        comparison["e3_ge_eKOS"] = _match_formal_bool(
            comparison["e3_ge_eKOS"], formal, "e3_ge_eKOS", f"width{width}.e3_ge_eKOS"
        )
        comparison["e3_ge_e2"] = _match_formal_bool(
            comparison["e3_ge_e2"], formal, "e3_ge_e2", f"width{width}.e3_ge_e2"
        )
        row_bounds = row["row_bounds_at_cap"]
        for field, formal_field in {
            "H0": "h0_bound",
            "H1_vector": "h1_vector_bound",
            "H1_outer": "h1_outer_bound",
            "FS1": "fs1_bound",
            "FS2": "fs2_bound",
            "FS3": "fs3_bound",
        }.items():
            row_bounds[field] = _match_formal_fraction(
                Fraction(int(row_bounds[field]["numerator"]), int(row_bounds[field]["denominator"])),
                formal,
                formal_field,
                f"width{width}.row_bounds_at_cap.{field}",
            )
        residual = row["source_residual"]
        residual["epsilon_AR_safe_upper_bound"] = _match_formal_fraction(
            Fraction(int(residual["epsilon_AR_safe_upper_bound"]["numerator"]), int(residual["epsilon_AR_safe_upper_bound"]["denominator"])),
            formal,
            "epsilon_ar_upper_bound",
            f"width{width}.source_residual.epsilon_AR_safe_upper_bound",
        )
        residual["source_switching_at_caps"] = _match_formal_fraction(
            Fraction(int(residual["source_switching_at_caps"]["numerator"]), int(residual["source_switching_at_caps"]["denominator"])),
            formal,
            "source_switching",
            f"width{width}.source_residual.source_switching_at_caps",
        )
        residual["source_alpha_sum_ceiling_at_zero_unallocated_losses"] = _match_formal_fraction(
            Fraction(int(residual["source_alpha_sum_ceiling_at_zero_unallocated_losses"]["numerator"]), int(residual["source_alpha_sum_ceiling_at_zero_unallocated_losses"]["denominator"])),
            formal,
            "source_alpha_ceiling",
            f"width{width}.source_residual.source_alpha_sum_ceiling_at_zero_unallocated_losses",
        )
        linear = row["linear_scan_envelope"]
        for stage, formal_field in (("FS1", "fs1_bytes"), ("FS2", "fs2_bytes"), ("FS3", "fs3_bytes")):
            linear["fs_input_bytes"][stage] = _match_formal_int(
                linear["fs_input_bytes"][stage], formal, formal_field, f"width{width}.linear.{stage}_bytes"
            )
        for stage, formal_field in (("FS1", "fs1_bits"), ("FS2", "fs2_bits"), ("FS3", "fs3_bits")):
            linear["fs_input_bits"][stage] = _match_formal_int(
                linear["fs_input_bits"][stage], formal, formal_field, f"width{width}.linear.{stage}_bits"
            )
        for field, formal_field in {
            "program_points_at_declared_caps": "program_points",
            "flat_table_entry_bits": "table_entry_bits",
            "flat_table_memory_bits_at_declared_caps": "table_memory_bits",
            "flat_table_memory_bytes_at_declared_caps": "table_memory_bytes",
            "flat_linear_scan_bit_comparison_units_per_forward_call_at_declared_caps": "scan_units_per_forward",
            "flat_linear_scan_bit_comparison_units_forward_history_at_declared_caps": "scan_history_units",
            "flat_linear_scan_bit_comparison_units_forward_and_reverse_at_declared_caps": "scan_forward_reverse_units",
            "q_hist_at_declared_caps": "candidate_q_hist_at_caps",
            "q_H_at_declared_caps": "candidate_q_H_at_caps",
        }.items():
            linear[field] = _match_formal_int(
                linear[field], formal, formal_field, f"width{width}.linear.{field}"
            )


def _bounded_generator_feasibility_proposal_v3(
    feasibility: Mapping[str, Any],
    *,
    M_cap: int,
    V_cap: int,
    S_cap: int,
    Q_cap: int,
    P_cap_constant: int,
    q_hist_cap_constant: int,
) -> dict[str, Any]:
    """Evaluate the separately identified v3 fixed-generator-table proposal.

    The auxiliary generator table is used only in the stronger soundness game.  It
    removes the old hidden-LEAF extraction premise from that game, but it is never
    included in the privacy experiment and never discounts actual generator QRO
    calls.  The privacy calculation below is the conditional classical-output
    hybrid in the already programmed game; concrete primitive and operational
    terms remain outside its numeric generator term.
    """

    model = _require_mapping(
        _required(
            _require_mapping(_required(feasibility, "constant_success_work_model"), "constant_success_work_model"),
            "bounded_generator_feasibility_proposal_v3",
        ),
        "concrete_feasibility.constant_success_work_model.bounded_generator_feasibility_proposal_v3",
    )
    _expect(model, "status", "UNSELECTED_IDEAL_ORACLE_WIDE_SEED_V3_PROPOSAL")
    _expect(model, "candidate_id", "DMV-RO-WIDE-SEED-v3")
    selection = _require_mapping(_required(model, "selection"), "bounded_generator_feasibility_proposal_v3.selection")
    for key in ("selected", "activation", "production_usable", "supersedes_current_protocol"):
        _expect(selection, key, False, f"bounded_generator_feasibility_proposal_v3.selection.{key}")
    _expect(selection, "proof_suite_id", None, "bounded_generator_feasibility_proposal_v3.selection.proof_suite_id")
    _expect(selection, "supersedes_v2_proposal", True, "bounded_generator_feasibility_proposal_v3.selection.supersedes_v2_proposal")

    candidate = _require_mapping(_required(model, "candidate_definition"), "bounded_generator_feasibility_proposal_v3.candidate_definition")
    _expect(candidate, "version", "DMV-RO-WIDE-SEED-v3")
    _expect(candidate, "version_ascii_bytes", 19)
    _expect(candidate, "full_generator_answer_bits", 2112)
    _expect(candidate, "full_generator_answer_bytes", 264)
    tree = _require_mapping(_required(candidate, "tree"), "bounded_generator_feasibility_proposal_v3.candidate_definition.tree")
    expected_tree = {
        "internal_node_count": 6399,
        "leaf_count": 6400,
        "heap_node_count": 12799,
        "stream_seed_count_per_commitment": 6400,
        "hidden_seed_count_per_commitment": 19199,
        "leaf_index_context_count": 6400,
    }
    for key, expected in expected_tree.items():
        _expect(tree, key, expected, f"bounded_generator_feasibility_proposal_v3.tree.{key}")
    leaf = _require_mapping(_required(candidate, "leaf"), "bounded_generator_feasibility_proposal_v3.candidate_definition.leaf")
    _expect(leaf, "row_key", "stream_seed")
    _expect(leaf, "equal_streams_are_not_binding_bad", True)
    _expect(leaf, "selected_leaf_and_stream_seeds_hidden", True)
    stream = _require_mapping(_required(candidate, "stream"), "bounded_generator_feasibility_proposal_v3.candidate_definition.stream")
    _expect(stream, "row_bytes", 15823)
    source = _require_mapping(_required(candidate, "source"), "bounded_generator_feasibility_proposal_v3.candidate_definition.source")
    _expect(source, "mode", "CURRENT_AES_SOURCE_RETAINED")
    for key in ("gf_relation_unchanged", "rows_unchanged", "six_masks_unchanged", "G0_G1_unchanged", "alpha8_and_alpha50_retained"):
        _expect(source, key, True, f"bounded_generator_feasibility_proposal_v3.source.{key}")
    encoding = _require_mapping(_required(candidate, "encoding"), "bounded_generator_feasibility_proposal_v3.candidate_definition.encoding")
    _expect(encoding, "h0", "0xd7||LP(version)||uint16_le(w)||uint8_le(0x00)||LP(IV[16])||uint32_le(0), exactly 51 bytes")
    _expect(encoding, "generator_domains_are_disjoint_from_h0_h1_fs", True)
    fs_family = _require_mapping(_required(model, "fs_family"), "bounded_generator_feasibility_proposal_v3.fs_family")
    _expect(fs_family, "prefix", "BL/DMV/FAEST-256F/v3")
    _expect(fs_family, "prefix_bytes", 20)
    _expect(fs_family, "part_encoding", "every part is uint32_le(byte_length)||bytes, including the final part length word")
    domain_inputs = _require_mapping(_required(fs_family, "domain_inputs"), "bounded_generator_feasibility_proposal_v3.fs_family.domain_inputs")
    _expect(domain_inputs, "FS1", "ASCII(\"BL/DMV/FAEST-256F/v3\")||ASCII(\"FS1\")||LP(statement)||LP(uhash)||LP(m1)||LP(sigma1)")
    _expect(domain_inputs, "FS2", "ASCII(\"BL/DMV/FAEST-256F/v3\")||ASCII(\"FS2\")||LP(statement)||LP(uhash)||LP(m1)||LP(sigma1)||LP(gamma1)||LP(m2)||LP(sigma2)")
    _expect(domain_inputs, "FS3", "ASCII(\"BL/DMV/FAEST-256F/v3\")||ASCII(\"FS3\")||LP(statement)||LP(uhash)||LP(m1)||LP(sigma1)||LP(gamma1)||LP(m2)||LP(sigma2)||LP(gamma2)||LP(m3)||LP(sigma3)")
    _expect(domain_inputs, "nul_bytes_in_domain_tags", False)

    opening = _require_mapping(_required(model, "opening_geometry"), "bounded_generator_feasibility_proposal_v3.opening_geometry")
    for key, expected in {
        "T_open": 229,
        "selected_leaf_count": 33,
        "accepted_nh_max": 294,
        "accepted_marked_internal_max": 261,
        "accepted_hidden_seed_max": 327,
        "full_retry_abort_hidden_seed_max": 19199,
        "frontier_seed_slots": 229,
    }.items():
        _expect(opening, key, expected, f"bounded_generator_feasibility_proposal_v3.opening_geometry.{key}")
    _expect(opening, "selected_seed_disclosure", False)

    stronger = _require_mapping(_required(model, "stronger_soundness_game"), "bounded_generator_feasibility_proposal_v3.stronger_soundness_game")
    _expect(stronger, "leaf_index_context_count", 6400)
    _expect(stronger, "given_to_soundness_adversary", True)
    _expect(stronger, "given_to_privacy_adversary", False)
    _expect(stronger, "actual_generator_evaluations_still_charged", True)
    _expect(stronger, "qP", 38)
    _expect(stronger, "direct_constant_max_role", "max(e_leaf_v3,eKOS,e2,e3)")
    _expect(stronger, "cap_row_max_role", "FS3")
    _expect(stronger, "cap_row_max_is_exact_for_all_k", True)
    privacy_reduction = _require_mapping(_required(model, "privacy_reduction"), "bounded_generator_feasibility_proposal_v3.privacy_reduction")
    _expect(privacy_reduction, "status", "CONDITIONAL_SINGLE_HOP_SXY_OPAQUE_HANDLE_PENDING_REVIEW")
    _expect(privacy_reduction, "selected_seed_bytes", False)
    _expect(privacy_reduction, "table_available", False)
    _expect(privacy_reduction, "numeric_bound", None)
    _expect(privacy_reduction, "privacy_claim_stopped", True)
    _expect(privacy_reduction, "hybrid_count_per_commitment", 463)
    _expect(privacy_reduction, "seed_coordinates_per_commitment", 19199)
    _expect(privacy_reduction, "one_hop_reduction_status", "CONSTRUCTED_CONDITIONAL_PENDING_DRIVER_REVIEW")
    endpoint = _require_mapping(
        _required(privacy_reduction, "endpoint_normalization"),
        "bounded_generator_feasibility_proposal_v3.privacy_reduction.endpoint_normalization",
    )
    for key, expected in {
        "delta_lr_definition": "Delta_LR=abs(Pr[D(View0)=1]-Pr[D(View1)=1])",
        "one_sided_endpoint_definition": "E_one_sided bounds each real-to-common-ideal side E0 and E1",
        "common_ideal_premise": True,
        "conversion": "Delta_LR<=min(1,E0+E1)<=min(1,2*E_one_sided)",
        "guessing_success": "Pguess=(1+Delta_LR)/2",
        "strict_half_success_condition": "E_one_sided<1/4 implies Delta_LR<1/2 and Pguess<3/4",
        "not_equivalent": True,
    }.items():
        _expect(endpoint, key, expected, f"bounded_generator_feasibility_proposal_v3.privacy_reduction.endpoint_normalization.{key}")
    source_collision_game = _source_collision_game(privacy_reduction)
    ideal_qrom_vs_shake = _require_mapping(
        _required(privacy_reduction, "ideal_qrom_vs_shake"),
        "bounded_generator_feasibility_proposal_v3.privacy_reduction.ideal_qrom_vs_shake",
    )
    for key, expected in {
        "ideal_qrom_status": "CONDITIONAL_IDEAL_QROM_ONLY",
        "qrom_scope": "q_H_v3, fixed-table soundness, and epsilon_generator_v3 use ideal independent random-function answers on the typed v3 domains",
        "concrete_shake_status": "UNPROVED",
        "concrete_shake_advantage": "Adv_SHAKE_priv=UNKNOWN",
        "generic_shake_to_qrom_bridge": False,
        "no_numerical_bridge": True,
        "qualification_effect": "the ideal-QROM values do not qualify the concrete SHAKE instantiation or close the privacy gate",
    }.items():
        _expect(ideal_qrom_vs_shake, key, expected, f"bounded_generator_feasibility_proposal_v3.privacy_reduction.ideal_qrom_vs_shake.{key}")
    one_hop_interface = _require_mapping(_required(privacy_reduction, "one_hop_interface"), "bounded_generator_feasibility_proposal_v3.privacy_reduction.one_hop_interface")
    _expect(one_hop_interface, "one_challenger_per_hop", True)
    _expect(one_hop_interface, "encoding_split", "For each legal generator input, the reversible parser factors the exact literal bytes as Encode_w(k,x): the fixed version/width/domain/IV/index/role/counter context x excludes the one w-bit seed field k. Target honest calls use F(x); only the conceptual left-world identity F(x)=H(s,x) reconstitutes the original keyed encoding.")
    _expect(privacy_reduction, "generator_term_status", "PROVISIONAL_CONDITIONAL_PENDING_DRIVER_REVIEW_OF_ONE_HOP_SIMULATOR")
    overlay = _require_mapping(_required(privacy_reduction, "fs_overlay"), "bounded_generator_feasibility_proposal_v3.privacy_reduction.fs_overlay")
    _expect(overlay, "base_qro_calls_per_simulated_query", 2)
    _expect(overlay, "uncompute_base_answer_on_overlay_hit", True)
    _expect(overlay, "public_superposition_queries_see_original_base", True)
    _expect(overlay, "q_H_formula", "2*q_hist_v3+P")
    _expect(privacy_reduction, "generator_term_formula", "min(1,2*hybrid_count*q_H/2^(w/2))")
    linear_scan = _require_mapping(
        _required(overlay, "linear_scan_envelope"),
        "bounded_generator_feasibility_proposal_v3.privacy_reduction.fs_overlay.linear_scan_envelope",
    )
    for key, expected in {
        "status": "CONDITIONAL_FLAT_LINEAR_SCAN_IMPLEMENTATION_ENVELOPE",
        "scope": "one possible flat-table lookup implementation for the simulator; not a lower bound for all simulators",
        "not_a_universal_lower_bound": True,
        "not_measured": True,
        "lookup_assumption": "compare each incoming typed FS input against every programmed point by a flat linear scan",
        "input_encoding": "versioned BL/DMV/FAEST-256F/v3 input with every part encoded as uint32_le(byte_length)||bytes",
        "program_points_formula": "P<=A+R2+R3",
        "program_points_at_declared_caps": "4198401*2^32",
        "table_entry_formula": "L_FS_bits+2112 answer bits",
        "gate_memory_access_depth_open": True,
    }.items():
        _expect(linear_scan, key, expected, f"bounded_generator_feasibility_proposal_v3.privacy_reduction.fs_overlay.linear_scan_envelope.{key}")
    linear_scan_widths = _require_mapping(
        _required(linear_scan, "widths"),
        "bounded_generator_feasibility_proposal_v3.privacy_reduction.fs_overlay.linear_scan_envelope.widths",
    )
    composition = _require_mapping(
        _required(model, "composition"),
        "bounded_generator_feasibility_proposal_v3.composition",
    )
    source_u = _require_mapping(
        _required(composition, "source_U_role_separation"),
        "bounded_generator_feasibility_proposal_v3.composition.source_U_role_separation",
    )
    _expect(
        composition,
        "full_privacy_endpoint_formula",
        "E_one_sided <= epsilon_coins+epsilon_AR+epsilon_generator_v3(w)+epsilon_source+Adv_SHAKE_priv+epsilon_operational; source-U binding is a separate integrity/applicability premise",
        "bounded_generator_feasibility_proposal_v3.composition.full_privacy_endpoint_formula",
    )
    for key, expected in {
        "privacy_role": "source-U binding is not a source-hiding loss when the source-hiding reduction does not condition on it; retain U custody/independence as a separate premise",
        "integrity_role": "keep Pr[Bad_U union Bad_ref]<=E_U*2^-257+binom(N_ref,2)/2^256 in the integrity/statistical ledger under its stated premises",
        "source_binding_formula": "Pr[Bad_U union Bad_ref] <= E_U*2^-257 + binom(N_ref,2)/2^256",
        "premises": ["source-U theorem and independence", "global operation_ref authority"],
        "not_silently_dropped": True,
        "not_a_privacy_residual_term": True,
        "custody_and_independence_remain_open": True,
    }.items():
        _expect(source_u, key, expected, f"bounded_generator_feasibility_proposal_v3.composition.source_U_role_separation.{key}")

    query_ledger = _require_mapping(_required(model, "query_ledger"), "bounded_generator_feasibility_proposal_v3.query_ledger")
    _expect(query_ledger, "qP", 38)
    _expect(query_ledger, "all_generator_queries_are_actual_and_charged", True)
    _expect(query_ledger, "oracle_uncomputation_is_separately_charged", True)
    _expect(query_ledger, "table_advice_does_not_reduce_actual_qro_ledger", True)

    q_hist_base = Q_cap + q_hist_cap_constant * M_cap
    overlay_program_points = P_cap_constant * M_cap
    q_alg_base = Q_cap + (q_hist_cap_constant - 7) * M_cap
    hidden_seed_count = expected_tree["hidden_seed_count_per_commitment"] * M_cap
    hybrid_count = 463 * M_cap
    width_declarations = _require_mapping(_required(model, "width_alternatives"), "bounded_generator_feasibility_proposal_v3.width_alternatives")
    evaluations: dict[str, Any] = {}

    e_kos, e2, e3 = _GENERATOR_SECURITY_CONSTANTS
    base_delta_linear_weight = (
        Fraction(36, _pow2(512))
        + Fraction(2, _pow2(2112))
        + Fraction(2, _pow2(832))
    )
    base_frame_without_nu_or_m4 = 534370 - 96 - 10496

    for width in (384, 512):
        declaration = _require_mapping(_required(width_declarations, str(width)), f"bounded_generator_feasibility_proposal_v3.width_alternatives.{width}")
        width_bytes = width // 8
        r = 2 * width + 288
        nu_bits = r + width - 1
        active_h0_bits = nu_bits + 10
        h0_squeeze_bytes = (active_h0_bits + 7) // 8
        nu_serialized_bytes = (nu_bits + 7) // 8
        commitment_bytes = r // 8
        leaf_output_bits = width + r
        leaf_output_bytes = leaf_output_bits // 8
        stream_blocks_per_row = (15823 + width_bytes - 1) // width_bytes
        m4_bytes = 33 * commitment_bytes + 229 * width_bytes
        frame_bytes = base_frame_without_nu_or_m4 + nu_serialized_bytes + m4_bytes
        vector_128_length = 28 + 128 * commitment_bytes
        vector_256_length = 28 + 256 * commitment_bytes
        per_commitment_queries = 2 * expected_tree["internal_node_count"] + expected_tree["leaf_count"] * (1 + stream_blocks_per_row)
        verifier_per_verification = 2 * (expected_tree["leaf_count"] - 1) + (1 + stream_blocks_per_row) * (expected_tree["leaf_count"] - opening["selected_leaf_count"])
        total_generator_queries = per_commitment_queries * M_cap
        total_verifier_queries = verifier_per_verification * V_cap
        q_hist_v3 = q_hist_base + total_generator_queries + total_verifier_queries
        q_h_v3 = 2 * q_hist_v3 + overlay_program_points
        q_total = q_h_v3
        q_alg_v3 = q_alg_base + total_generator_queries + total_verifier_queries
        qP_v3 = 38
        q_eff_v3 = q_alg_v3 + qP_v3
        def _lp_total(*payload_sizes: int) -> int:
            return sum(payload_sizes) + 4 * len(payload_sizes)

        fs_input_bytes = {
            "FS1": 20 + 3 + _lp_total(1147, nu_serialized_bytes, 506416, 64),
            "FS2": 20 + 3 + _lp_total(1147, nu_serialized_bytes, 506416, 64, 264, 15887, 64),
            "FS3": 20 + 3 + _lp_total(1147, nu_serialized_bytes, 506416, 64, 264, 15887, 64, 104, 96, 64),
        }
        fs_input_bits = {key: value * 8 for key, value in fs_input_bytes.items()}
        linear_width = _require_mapping(
            _required(linear_scan_widths, str(width)),
            f"bounded_generator_feasibility_proposal_v3.linear_scan_envelope.widths.{width}",
        )
        for stage, expected_size in fs_input_bytes.items():
            _expect(
                linear_width,
                f"{stage}_input_bytes",
                expected_size,
                f"bounded_generator_feasibility_proposal_v3.linear_scan_envelope.width{width}.{stage}_input_bytes",
            )
        fs3_input_bits = fs_input_bits["FS3"]
        flat_scan_units_per_forward_call = overlay_program_points * fs3_input_bits
        flat_table_entry_bits = fs3_input_bits + 2112
        flat_table_memory_bits = overlay_program_points * flat_table_entry_bits
        if flat_table_memory_bits % 8:
            raise ContractError(f"bounded_generator_feasibility_proposal_v3.width{width}: table_memory_not_byte_aligned")
        flat_scan_history_units = q_hist_v3 * flat_scan_units_per_forward_call
        flat_scan_forward_reverse_units = q_h_v3 * flat_scan_units_per_forward_call
        e_leaf = Fraction(
            expected_tree["leaf_index_context_count"] * math.comb(1 << width, 2),
            _pow2(r + 10),
        )
        direct_constants = {
            "e_leaf_v3": e_leaf,
            "eKOS": e_kos,
            "e2": e2,
            "e3": e3,
        }
        direct_constant_max_name = max(direct_constants, key=direct_constants.__getitem__)
        direct_constant_max = direct_constants[direct_constant_max_name]
        h0_completion_term = Fraction(1, _pow2(nu_bits))
        delta_linear_weight = h0_completion_term + base_delta_linear_weight
        row_bounds_at_cap = {
            "H0": e_leaf + h0_completion_term * q_eff_v3,
            "H1_vector": Fraction(34 * q_eff_v3, _pow2(512)),
            "H1_outer": Fraction(2 * q_eff_v3, _pow2(512)),
            "FS1": Fraction(2 * q_eff_v3, _pow2(2112)) + e_kos,
            "FS2": Fraction(2 * q_eff_v3, _pow2(832)) + e2,
            "FS3": e3,
        }
        delta_cap_name = max(row_bounds_at_cap, key=row_bounds_at_cap.__getitem__)
        delta_cap = row_bounds_at_cap[delta_cap_name]
        if delta_cap_name != "FS3":
            raise ContractError(f"bounded_generator_feasibility_proposal_v3.width{width}: cap row maximum is {delta_cap_name}, expected FS3")
        delta_sum_upper = delta_cap * q_eff_v3
        soundness_raw = 10 * q_eff_v3 * delta_sum_upper
        soundness_bound = min(Fraction(1, 1), soundness_raw)
        seed_collision_term = Fraction(0, 1)
        generator_privacy_raw = (
            Fraction(2 * hybrid_count * q_h_v3, _pow2(width // 2))
        )
        generator_privacy_bound = min(Fraction(1, 1), generator_privacy_raw)
        epsilon_ar_upper_bound = Fraction(1, _pow2(137))
        source_switching_at_cap = Fraction(1253 * S_cap, _pow2(128))
        source_alpha_sum_ceiling_zero_unknowns = (
            Fraction(1, 4)
            - epsilon_ar_upper_bound
            - generator_privacy_bound
            - source_switching_at_cap
        ) / S_cap
        if source_alpha_sum_ceiling_zero_unknowns <= 0:
            raise ContractError(f"bounded_generator_feasibility_proposal_v3.width{width}: nonpositive_source_alpha_residual")
        expected = {
            "seed_width_bits": width,
            "seed_width_bytes": width_bytes,
            "r": r,
            "nu_bits": nu_bits,
            "active_h0_bits": active_h0_bits,
            "h0_squeeze_bytes": h0_squeeze_bytes,
            "nu_serialized_bytes": nu_serialized_bytes,
            "commitment_bytes": commitment_bytes,
            "leaf_output_bits": leaf_output_bits,
            "leaf_output_bytes": leaf_output_bytes,
            "stream_blocks_per_row": stream_blocks_per_row,
            "frontier_seed_bytes": width_bytes,
            "m4_bytes": m4_bytes,
            "frame_bytes_including_40_byte_header": frame_bytes,
            "frame_delta_vs_v2_base": frame_bytes - 534370,
        }
        for key, expected_value in expected.items():
            _expect(declaration, key, expected_value, f"bounded_generator_feasibility_proposal_v3.width{width}.{key}")

        evaluations[str(width)] = {
            **expected,
            "h0_input_bytes": 51,
            "h1_vector_128_input_bytes": vector_128_length,
            "h1_vector_256_input_bytes": vector_256_length,
            "h1_outer_input_bytes": 2140,
            "fs_uhash_bytes": nu_serialized_bytes,
            "tree_child_queries_per_commitment": 2 * expected_tree["internal_node_count"],
            "generator_H_queries_per_commitment": per_commitment_queries,
            "generator_H_queries_at_caps": total_generator_queries,
            "verifier_generator_H_queries_per_verification": verifier_per_verification,
            "verifier_generator_H_queries_at_caps": total_verifier_queries,
            "candidate_q_hist_at_caps": q_hist_v3,
            "candidate_q_alg_at_caps": q_alg_v3,
            "candidate_qP": qP_v3,
            "candidate_q_eff_at_caps": q_eff_v3,
            "candidate_q_H_at_caps": q_h_v3,
            "candidate_total_public_RO_queries_at_caps": q_total,
            "secret_seed_count_at_caps": hidden_seed_count,
            "hybrid_count_at_caps": hybrid_count,
            "h0_completion_term": _fraction_payload(h0_completion_term),
            "e_leaf_v3": _fraction_payload(e_leaf),
            "eKOS": _fraction_payload(e_kos),
            "e2": _fraction_payload(e2),
            "e3": _fraction_payload(e3),
            "direct_constant_max_name": direct_constant_max_name,
            "direct_constant_max": _fraction_payload(direct_constant_max),
            "direct_constant_comparisons": {
                "e3_ge_e_leaf_v3": e3 >= e_leaf,
                "e3_ge_eKOS": e3 >= e_kos,
                "e3_ge_e2": e3 >= e2,
            },
            "row_bounds_at_cap": {key: _fraction_payload(value) for key, value in row_bounds_at_cap.items()},
            "delta_cap_name": delta_cap_name,
            "delta_cap": _fraction_payload(delta_cap),
            "delta_cap_is_constant_for_all_k": delta_cap_name == "FS3",
            "delta_linear_weight": _fraction_payload(delta_linear_weight),
            "soundness_delta_sum_upper": _fraction_payload(delta_sum_upper),
            "soundness_row_complete_bound": _fraction_payload(soundness_bound),
            "soundness_row_complete_bound_decimal": f"{float(soundness_bound):.17g}",
            "soundness_row_complete_bound_log2_approx": f"{math.log2(float(soundness_bound)):.17g}" if soundness_bound else "-inf",
            "soundness_status": "CONDITIONAL_STRONGER_QUERY_ONLY_GAME_WITH_COMPLETE_FIXED_GENERATOR_TABLE",
            "privacy_status": privacy_reduction["status"],
            "privacy_numeric_bound": None,
            "generator_privacy_bound": _fraction_payload(generator_privacy_bound),
            "generator_privacy_bound_decimal": f"{float(generator_privacy_bound):.17g}",
            "seed_collision_term": _fraction_payload(seed_collision_term),
            "proof_status": "CONDITIONAL_SOUNDNESS_ONE_HOP_PRIVACY_PENDING_REVIEW",
            "constant_success_under_zero_remaining_unknowns": None,
            "ideal_qrom_vs_shake": {
                "status": ideal_qrom_vs_shake["ideal_qrom_status"],
                "concrete_shake_status": ideal_qrom_vs_shake["concrete_shake_status"],
                "concrete_shake_advantage": ideal_qrom_vs_shake["concrete_shake_advantage"],
                "generic_shake_to_qrom_bridge": ideal_qrom_vs_shake["generic_shake_to_qrom_bridge"],
                "no_numerical_bridge": ideal_qrom_vs_shake["no_numerical_bridge"],
                "qualification_effect": ideal_qrom_vs_shake["qualification_effect"],
            },
            "endpoint_normalization": {
                "delta_lr_definition": endpoint["delta_lr_definition"],
                "one_sided_endpoint_definition": endpoint["one_sided_endpoint_definition"],
                "common_ideal_premise": endpoint["common_ideal_premise"],
                "conversion": endpoint["conversion"],
                "guessing_success": endpoint["guessing_success"],
                "strict_half_success_condition": endpoint["strict_half_success_condition"],
                "one_sided_upper_bound_formula": "E_one_sided <= u + epsilon_AR + epsilon_generator_v3(w) + S*(alpha8+alpha50+1253/2^128)",
                "delta_lr_upper_bound_formula": "Delta_LR <= min(1,2*E_one_sided)",
                "strict_alpha_condition": "alpha8+alpha50 < (1/4-u-2^-137-epsilon_generator_v3(w))/S-1253/2^128",
            },
            "source_residual": {
                "unallocated_loss_symbol": "u=epsilon_coins+Adv_SHAKE_priv+epsilon_operational",
                "unallocated_loss_terms": ["epsilon_coins", "Adv_SHAKE_priv", "epsilon_operational"],
                "epsilon_AR_safe_upper_bound": _fraction_payload(epsilon_ar_upper_bound),
                "source_switching_at_caps": _fraction_payload(source_switching_at_cap),
                "source_alpha_sum_ceiling_formula": "(1/4-u-2^-137-epsilon_generator_v3(w))/S-1253/2^128",
                "source_alpha_sum_ceiling_at_zero_unallocated_losses": _fraction_payload(source_alpha_sum_ceiling_zero_unknowns),
                "source_alpha_sum_ceiling_at_zero_unallocated_losses_decimal": f"{float(source_alpha_sum_ceiling_zero_unknowns):.17g}",
                "source_alpha_sum_strict_condition_required": True,
                "strict_delta_lr_half_success_target": "E_one_sided<1/4",
                "zero_unknowns_is_diagnostic_only": True,
                "source_u_binding_is_not_subtracted_from_privacy_residual": True,
                "source_u_role": source_u,
            },
            "source_collision_game": source_collision_game,
            "linear_scan_envelope": {
                "status": linear_scan["status"],
                "scope": linear_scan["scope"],
                "not_a_universal_lower_bound": linear_scan["not_a_universal_lower_bound"],
                "not_measured": linear_scan["not_measured"],
                "input_encoding": linear_scan["input_encoding"],
                "fs_input_bytes": fs_input_bytes,
                "fs_input_bits": fs_input_bits,
                "program_points_at_declared_caps": overlay_program_points,
                "flat_table_entry_bits": flat_table_entry_bits,
                "flat_table_memory_bits_at_declared_caps": flat_table_memory_bits,
                "flat_table_memory_bytes_at_declared_caps": flat_table_memory_bits // 8,
                "flat_linear_scan_bit_comparison_units_per_forward_call_at_declared_caps": flat_scan_units_per_forward_call,
                "flat_linear_scan_bit_comparison_units_forward_history_at_declared_caps": flat_scan_history_units,
                "flat_linear_scan_bit_comparison_units_forward_and_reverse_at_declared_caps": flat_scan_forward_reverse_units,
                "q_hist_at_declared_caps": q_hist_v3,
                "q_H_at_declared_caps": q_h_v3,
                "gate_memory_access_depth_open": linear_scan["gate_memory_access_depth_open"],
            },
            "source_u_privacy_role": source_u["privacy_role"],
            "source_u_integrity_role": source_u["integrity_role"],
        }

    formal = _formal_result_cap()
    _bind_formal_v3_rows(evaluations, formal["widths"])
    return {
        "status": _required(model, "status"),
        "candidate_id": _required(model, "candidate_id"),
        "selection": selection,
        "scope": _required(model, "scope"),
        "candidate_definition": candidate,
        "opening_geometry": opening,
        "stronger_soundness_game": stronger,
        "privacy_reduction": privacy_reduction,
        "endpoint_normalization": endpoint,
        "source_collision_game": source_collision_game,
        "ideal_qrom_vs_shake": ideal_qrom_vs_shake,
        "query_ledger": query_ledger,
        "width_evaluations": evaluations,
        "least_evaluated_width_bits": 384,
        "least_sufficient_width_bits": None,
        "minimum_width_status": _required(_require_mapping(_required(model, "composition"), "bounded_generator_feasibility_proposal_v3.composition"), "minimum_width_status"),
        "composition": {**composition, "source_U_role_separation": source_u},
        "implementation_consequences": _required(model, "implementation_consequences"),
        "recommendation": _required(model, "recommendation"),
    }


def _computational_work_model(
    feasibility: Mapping[str, Any],
    *,
    M_cap: int,
    V_cap: int,
    S_cap: int,
    aes_blocks: int,
    Q_cap: int,
    P_cap_constant: int,
    q_hist_cap_constant: int,
) -> dict[str, Any]:
    model = _require_mapping(
        _required(feasibility, "constant_success_work_model"), "concrete_feasibility.constant_success_work_model"
    )
    target_advantage = Fraction(1, 2)
    switching = Fraction(85298537, _pow2(96))
    adaptive_reprogramming_safe = Fraction(1, _pow2(137))
    known_residual = target_advantage - switching - adaptive_reprogramming_safe
    alpha_weight = 463 * M_cap + 2 * S_cap
    uniform_threshold_before_unknowns = known_residual / alpha_weight
    generic_screen = _generic_key_search_screen(
        feasibility, alpha_weight=alpha_weight, aes_blocks=aes_blocks
    )
    return {
        "model_name": model["model_name"],
        "work_threshold": model["work_threshold"],
        "success_threshold": model["success_threshold"],
        "known_additive_terms_at_declared_caps": {
            "switching": _fraction_payload(switching),
            "adaptive_reprogramming_safe_upper_bound": _fraction_payload(adaptive_reprogramming_safe),
            "known_residual_before_unknown_terms": _fraction_payload(known_residual),
        },
        "unknown_terms": model["unknown_terms"],
        "exact_weighted_alpha_budget_at_declared_caps": model[
            "exact_weighted_alpha_budget_at_declared_caps"
        ],
        "weighted_alpha_budget_at_declared_caps": model["weighted_alpha_budget_at_declared_caps"],
        "weighted_alpha_condition_at_declared_caps": model["weighted_alpha_condition_at_declared_caps"],
        "uniform_alpha_sufficient_condition_at_declared_caps": model["uniform_alpha_sufficient_condition_at_declared_caps"],
        "uniform_alpha_threshold_before_unknown_terms": _fraction_payload(uniform_threshold_before_unknowns),
        "alpha_weight_at_declared_caps": alpha_weight,
        "exact_condition_for_candidate_additive_bound": model["exact_condition_for_candidate_additive_bound"],
        "T_star_condition": model["T_star_condition"],
        "QRO_cost_separate": model["QRO_cost_separate"],
        "QRO_queries_are_not_AES_work_units": model["QRO_queries_are_not_AES_work_units"],
        "generic_key_search_screen": generic_screen,
        "composed_privacy_analysis": _composed_privacy_analysis(
            feasibility,
            M_cap=M_cap,
            S_cap=S_cap,
            known_residual=known_residual,
            alpha_weight=alpha_weight,
            generic_screen=generic_screen,
        ),
        "bounded_generator_feasibility_proposal": _bounded_generator_feasibility_proposal(
            feasibility,
            M_cap=M_cap,
            V_cap=V_cap,
            S_cap=S_cap,
            Q_cap=Q_cap,
            P_cap_constant=P_cap_constant,
            q_hist_cap_constant=q_hist_cap_constant,
        ),
        "bounded_generator_feasibility_proposal_v3": _bounded_generator_feasibility_proposal_v3(
            feasibility,
            M_cap=M_cap,
            V_cap=V_cap,
            S_cap=S_cap,
            Q_cap=Q_cap,
            P_cap_constant=P_cap_constant,
            q_hist_cap_constant=q_hist_cap_constant,
        ),
    }


def _generic_key_search_screen(
    feasibility: Mapping[str, Any], *, alpha_weight: int, aes_blocks: int
) -> dict[str, Any]:
    model = _require_mapping(
        _required(
            _require_mapping(_required(feasibility, "constant_success_work_model"), "constant_success_work_model"),
            "generic_key_search_screen",
        ),
        "concrete_feasibility.constant_success_work_model.generic_key_search_screen",
    )
    key_count = _pow2(256)
    block_count = _pow2(128)
    false_key_probability = Fraction(1, block_count * (block_count - 1) * (block_count - 2))
    real_false_key_lambda = Fraction(key_count - 1, 1) * false_key_probability
    ideal_consistent_key_lambda = Fraction(key_count, 1) * false_key_probability
    switching = Fraction(85298537, _pow2(96))
    known_residual = Fraction(1, 2) - switching
    optimistic_threshold = known_residual / alpha_weight

    numerical_break_even = _exact_int(
        _required(model, "numerical_break_even_iterations_approx"),
        "generic_key_search_screen.numerical_break_even_iterations_approx",
    )
    certified_iterations = _exact_int(
        _required(model, "rationally_certified_iterations"),
        "generic_key_search_screen.rationally_certified_iterations",
    )
    if certified_iterations <= numerical_break_even:
        raise ContractError("generic_key_search_screen: certification_margin_missing")
    def sine_lower_for(iterations: int, label: str) -> tuple[Fraction, Fraction]:
        z_value = Fraction(2 * iterations + 1, block_count)
        if not (0 < z_value < Fraction(1, 4)):
            raise ContractError(f"generic_key_search_screen.{label}: angle_domain_not_proven")
        if 4 * (2 * iterations + 1) >= block_count:
            raise ContractError(f"generic_key_search_screen.{label}: strict_angle_domain_check_failed")
        return z_value, z_value - z_value**3 / 6

    certified_z, certified_sine_lower = sine_lower_for(certified_iterations, "certified_iterations")
    certified_advantage_lower = (
        (1 - real_false_key_lambda) * certified_sine_lower**2 - ideal_consistent_key_lambda
    )

    work = _require_mapping(_required(model, "work_convention"), "generic_key_search_screen.work_convention")
    in_place = _require_mapping(
        _required(work, "aes256_oracle_r3_in_place"), "generic_key_search_screen.work_convention.aes256_oracle_r3_in_place"
    )
    maximov = _require_mapping(
        _required(work, "aes256_oracle_r3_maximov_mixcolumns"),
        "generic_key_search_screen.work_convention.aes256_oracle_r3_maximov_mixcolumns",
    )
    history_operator = _require_mapping(
        _required(work, "aes256_operator_in_place_for_history"),
        "generic_key_search_screen.work_convention.aes256_operator_in_place_for_history",
    )
    toffoli = _require_mapping(
        _required(model, "toffoli_decomposition"), "generic_key_search_screen.toffoli_decomposition"
    )
    diffusion = _require_mapping(
        _required(model, "grover_diffusion"), "generic_key_search_screen.grover_diffusion"
    )
    primitive = _require_mapping(
        _required(model, "primitive_game_algorithm"), "generic_key_search_screen.primitive_game_algorithm"
    )

    def gate_cost(entry: Mapping[str, Any], name: str) -> int:
        return sum(
            _exact_int(_required(entry, field, f"{name}.{field}"), f"{name}.{field}")
            for field in ("CNOT", "one_qubit_clifford", "T", "measurement")
        )

    in_place_cost = gate_cost(in_place, "generic_key_search_screen.in_place")
    maximov_cost = gate_cost(maximov, "generic_key_search_screen.maximov")
    history_operator_cost = gate_cost(history_operator, "generic_key_search_screen.history_operator")
    toffoli_cost = gate_cost(toffoli, "generic_key_search_screen.toffoli")
    for entry, name, expected in (
        (in_place, "in_place", in_place_cost),
        (maximov, "maximov", maximov_cost),
        (history_operator, "history_operator", history_operator_cost),
        (toffoli, "toffoli", toffoli_cost),
    ):
        declared = _exact_int(_required(entry, "G_cost", f"generic_key_search_screen.{name}.G_cost"), f"{name}.G_cost")
        if declared != expected:
            raise ContractError(f"generic_key_search_screen.{name}.G_cost: inconsistent")

    control_count = _exact_int(
        _required(diffusion, "control_count", "generic_key_search_screen.diffusion.control_count"),
        "generic_key_search_screen.diffusion.control_count",
    )
    clean_chain_ancillas = _exact_int(
        _required(diffusion, "clean_chain_ancillas", "generic_key_search_screen.diffusion.clean_chain_ancillas"),
        "generic_key_search_screen.diffusion.clean_chain_ancillas",
    )
    forward_toffolis = _exact_int(
        _required(diffusion, "forward_toffoli_count", "generic_key_search_screen.diffusion.forward_toffoli_count"),
        "generic_key_search_screen.diffusion.forward_toffoli_count",
    )
    reverse_toffolis = _exact_int(
        _required(diffusion, "reverse_toffoli_count", "generic_key_search_screen.diffusion.reverse_toffoli_count"),
        "generic_key_search_screen.diffusion.reverse_toffoli_count",
    )
    phase_z_count = _exact_int(
        _required(diffusion, "phase_Z_count", "generic_key_search_screen.diffusion.phase_Z_count"),
        "generic_key_search_screen.diffusion.phase_Z_count",
    )
    h_count = _exact_int(_required(diffusion, "H_count"), "generic_key_search_screen.diffusion.H_count")
    x_count = _exact_int(_required(diffusion, "X_count"), "generic_key_search_screen.diffusion.X_count")
    if control_count != 256 or clean_chain_ancillas != control_count - 1:
        raise ContractError("generic_key_search_screen.diffusion: 256_control_chain_mismatch")
    if forward_toffolis != clean_chain_ancillas or reverse_toffolis != clean_chain_ancillas:
        raise ContractError("generic_key_search_screen.diffusion: cleanup_chain_mismatch")
    if h_count != 2 * control_count or x_count != 2 * control_count or phase_z_count != 1:
        raise ContractError("generic_key_search_screen.diffusion: layer_count_mismatch")
    diffusion_cnot = (forward_toffolis + reverse_toffolis) * _exact_int(
        _required(toffoli, "CNOT"), "generic_key_search_screen.toffoli.CNOT"
    )
    diffusion_one_qubit = (forward_toffolis + reverse_toffolis) * _exact_int(
        _required(toffoli, "one_qubit_clifford"), "generic_key_search_screen.toffoli.one_qubit_clifford"
    ) + h_count + x_count + phase_z_count
    diffusion_t = (forward_toffolis + reverse_toffolis) * _exact_int(
        _required(toffoli, "T"), "generic_key_search_screen.toffoli.T"
    )
    diffusion_measurement = 0
    declared_diffusion_components = {
        "CNOT": diffusion_cnot,
        "one_qubit_clifford": diffusion_one_qubit,
        "T": diffusion_t,
        "measurement": diffusion_measurement,
    }
    for field, expected in declared_diffusion_components.items():
        declared = _exact_int(
            _required(diffusion, field, f"generic_key_search_screen.diffusion.{field}"),
            f"generic_key_search_screen.diffusion.{field}",
        )
        if declared != expected:
            raise ContractError(f"generic_key_search_screen.diffusion.{field}: inconsistent")
    diffusion_cost = sum(declared_diffusion_components.values())
    declared_diffusion_cost = _exact_int(
        _required(diffusion, "G_cost", "generic_key_search_screen.diffusion.G_cost"),
        "generic_key_search_screen.diffusion.G_cost",
    )
    if declared_diffusion_cost != diffusion_cost:
        raise ContractError("generic_key_search_screen.diffusion.G_cost: inconsistent")
    toffoli_depth = _exact_int(
        _required(toffoli, "serial_depth", "generic_key_search_screen.toffoli.serial_depth"),
        "generic_key_search_screen.toffoli.serial_depth",
    )
    expected_diffusion_depth = (
        forward_toffolis * toffoli_depth
        + reverse_toffolis * toffoli_depth
        + 4
        + phase_z_count
    )
    declared_diffusion_depth = _exact_int(
        _required(diffusion, "serial_depth", "generic_key_search_screen.diffusion.serial_depth"),
        "generic_key_search_screen.diffusion.serial_depth",
    )
    if declared_diffusion_depth != expected_diffusion_depth:
        raise ContractError("generic_key_search_screen.diffusion.serial_depth: inconsistent")
    declared_diffusion_width = _exact_int(
        _required(diffusion, "width_qubits", "generic_key_search_screen.diffusion.width_qubits"),
        "generic_key_search_screen.diffusion.width_qubits",
    )
    if declared_diffusion_width != control_count + clean_chain_ancillas:
        raise ContractError("generic_key_search_screen.diffusion.width_qubits: inconsistent")

    initialization = _require_mapping(
        _required(primitive, "initialization"), "generic_key_search_screen.primitive.initialization"
    )
    initial_superposition = _require_mapping(
        _required(primitive, "initial_superposition"),
        "generic_key_search_screen.primitive.initial_superposition",
    )
    per_iteration = _require_mapping(
        _required(primitive, "per_iteration"), "generic_key_search_screen.primitive.per_iteration"
    )
    finalization = _require_mapping(
        _required(primitive, "finalization"), "generic_key_search_screen.primitive.finalization"
    )
    validation = _require_mapping(
        _required(finalization, "candidate_validation"),
        "generic_key_search_screen.primitive.candidate_validation",
    )
    key_register_qubits = _exact_int(_required(primitive, "key_register_qubits"), "generic_key_search_screen.primitive.key_register_qubits")
    maximum_width = _exact_int(
        _required(primitive, "maximum_quantum_width_qubits"),
        "generic_key_search_screen.primitive.maximum_quantum_width_qubits",
    )
    if key_register_qubits != key_count.bit_length() - 1 or maximum_width != _exact_int(
        _required(in_place, "width_qubits"), "generic_key_search_screen.in_place.width_qubits"
    ):
        raise ContractError("generic_key_search_screen.primitive: width_mismatch")
    zero_preparations = _exact_int(
        _required(initialization, "zero_state_preparations"),
        "generic_key_search_screen.primitive.initialization.zero_state_preparations",
    )
    initialization_cost = _exact_int(
        _required(initialization, "G_cost"), "generic_key_search_screen.primitive.initialization.G_cost"
    )
    if zero_preparations != maximum_width or initialization_cost != zero_preparations:
        raise ContractError("generic_key_search_screen.primitive.initialization: inconsistent")
    initial_h_count = _exact_int(_required(initial_superposition, "H_count"), "generic_key_search_screen.primitive.initial_superposition.H_count")
    initial_superposition_cost = _exact_int(
        _required(initial_superposition, "G_cost"), "generic_key_search_screen.primitive.initial_superposition.G_cost"
    )
    if initial_h_count != key_register_qubits or initial_superposition_cost != initial_h_count:
        raise ContractError("generic_key_search_screen.primitive.initial_superposition: inconsistent")
    if _required(per_iteration, "selected_oracle") != "aes256_oracle_r3_in_place":
        raise ContractError("generic_key_search_screen.primitive.per_iteration: unsupported_oracle")
    per_iteration_oracle = _exact_int(_required(per_iteration, "oracle_G_cost"), "generic_key_search_screen.primitive.per_iteration.oracle_G_cost")
    per_iteration_diffusion = _exact_int(_required(per_iteration, "diffusion_G_cost"), "generic_key_search_screen.primitive.per_iteration.diffusion_G_cost")
    per_iteration_cost = _exact_int(_required(per_iteration, "total_G_cost"), "generic_key_search_screen.primitive.per_iteration.total_G_cost")
    per_iteration_depth = _exact_int(_required(per_iteration, "total_serial_depth"), "generic_key_search_screen.primitive.per_iteration.total_serial_depth")
    if per_iteration_oracle != in_place_cost or per_iteration_diffusion != diffusion_cost or per_iteration_cost != per_iteration_oracle + per_iteration_diffusion:
        raise ContractError("generic_key_search_screen.primitive.per_iteration: cost_mismatch")
    expected_per_iteration_depth = _exact_int(_required(in_place, "full_depth"), "generic_key_search_screen.in_place.full_depth") + declared_diffusion_depth
    if per_iteration_depth != expected_per_iteration_depth:
        raise ContractError("generic_key_search_screen.primitive.per_iteration: depth_mismatch")
    if _exact_int(_required(per_iteration, "width_qubits"), "generic_key_search_screen.primitive.per_iteration.width_qubits") != maximum_width:
        raise ContractError("generic_key_search_screen.primitive.per_iteration: width_mismatch")
    final_measurements = _exact_int(_required(finalization, "quantum_measurements"), "generic_key_search_screen.primitive.finalization.quantum_measurements")
    finalization_cost = _exact_int(_required(finalization, "G_cost"), "generic_key_search_screen.primitive.finalization.G_cost")
    if final_measurements != key_register_qubits or finalization_cost != final_measurements:
        raise ContractError("generic_key_search_screen.primitive.finalization: inconsistent")
    validation_evaluations = _exact_int(_required(validation, "public_AES_evaluations"), "generic_key_search_screen.primitive.validation.public_AES_evaluations")
    validation_comparisons = _exact_int(_required(validation, "classical_block_comparisons"), "generic_key_search_screen.primitive.validation.classical_block_comparisons")
    validation_per_AES = _exact_int(_required(validation, "reversible_equivalent_G_per_AES_evaluation"), "generic_key_search_screen.primitive.validation.reversible_equivalent_G_per_AES_evaluation")
    validation_cost = _exact_int(_required(validation, "reversible_equivalent_G_cost"), "generic_key_search_screen.primitive.validation.reversible_equivalent_G_cost")
    if validation_evaluations != 3 or validation_comparisons != 3 or validation_per_AES != history_operator_cost or validation_cost != validation_evaluations * validation_per_AES:
        raise ContractError("generic_key_search_screen.primitive.validation: inconsistent")
    fixed_G_cost = initialization_cost + initial_superposition_cost + finalization_cost + validation_cost
    declared_fixed_G_cost = _exact_int(_required(primitive, "fixed_G_cost"), "generic_key_search_screen.primitive.fixed_G_cost")
    declared_primitive_iteration_cost = _exact_int(_required(primitive, "per_iteration_G_cost"), "generic_key_search_screen.primitive.per_iteration_G_cost")
    if declared_fixed_G_cost != fixed_G_cost or declared_primitive_iteration_cost != per_iteration_cost:
        raise ContractError("generic_key_search_screen.primitive: fixed_cost_mismatch")

    known_history = aes_blocks * history_operator_cost
    work_limit = _pow2(128)
    strict_work_limit = work_limit - 1
    declared_history = _exact_int(
        _required(model["known_history"], "known_history_G_cost_at_declared_caps"),
        "generic_key_search_screen.known_history.known_history_G_cost_at_declared_caps",
    )
    if declared_history != known_history:
        raise ContractError("generic_key_search_screen.known_history: inconsistent")
    if strict_work_limit <= known_history + fixed_G_cost:
        raise ContractError("generic_key_search_screen: known_history_exceeds_work_limit")
    certified_total_G = fixed_G_cost + certified_iterations * per_iteration_cost
    if certified_total_G >= work_limit:
        raise ContractError("generic_key_search_screen: certified_strategy_exceeds_work_limit")
    primitive_cap_iterations = (strict_work_limit - fixed_G_cost) // per_iteration_cost
    if primitive_cap_iterations <= certified_iterations:
        raise ContractError("generic_key_search_screen: full_cost_cap_below_certified_break_even")
    primitive_cap_total_G = fixed_G_cost + primitive_cap_iterations * per_iteration_cost
    if primitive_cap_total_G >= work_limit:
        raise ContractError("generic_key_search_screen: strict_integer_work_check_failed")
    primitive_cap_z, primitive_cap_sine_lower = sine_lower_for(primitive_cap_iterations, "primitive_cap_iterations")
    primitive_cap_advantage_lower = (
        (1 - real_false_key_lambda) * primitive_cap_sine_lower**2 - ideal_consistent_key_lambda
    )
    product_cap_iterations = (strict_work_limit - known_history - fixed_G_cost) // per_iteration_cost
    if product_cap_iterations <= 0:
        raise ContractError("generic_key_search_screen: product_history_exceeds_work_limit")
    product_cap_total_G = known_history + fixed_G_cost + product_cap_iterations * per_iteration_cost
    product_cap_z, product_cap_sine_lower = sine_lower_for(product_cap_iterations, "product_cap_iterations")
    product_cap_advantage_lower = (
        (1 - real_false_key_lambda) * product_cap_sine_lower**2 - ideal_consistent_key_lambda
    )
    product_certified_total_G = known_history + certified_total_G
    if product_certified_total_G >= work_limit:
        raise ContractError("generic_key_search_screen: product_certified_strategy_exceeds_work_limit")
    primitive_serial_depth = 1 + 1 + primitive_cap_iterations * per_iteration_depth + 1
    validation_serial_depth = validation_evaluations * _exact_int(
        _required(history_operator, "full_depth"), "generic_key_search_screen.history_operator.full_depth"
    )
    total_mixed_serial_depth = primitive_serial_depth + validation_serial_depth
    current_weight = alpha_weight
    maximum_effective_weight = known_residual / primitive_cap_advantage_lower
    break_even_maximum_effective_weight = known_residual / certified_advantage_lower

    def log2_string(value: int) -> str:
        return f"{math.log2(value):.17g}"

    return {
        "status": _required(model, "status"),
        "candidate_key_count": key_count,
        "block_output_count": block_count,
        "pair_requirements": model["pair_requirements"],
        "false_key_probability_per_candidate": _fraction_payload(false_key_probability),
        "real_world_false_key_union_bound_lambda": _fraction_payload(real_false_key_lambda),
        "ideal_world_consistent_key_union_bound_lambda": _fraction_payload(ideal_consistent_key_lambda),
        "distinguisher_output_rule": model["distinguisher_output_rule"],
        "advantage_convention": model["advantage_convention"],
        "real_acceptance_lower_bound": model["real_acceptance_lower_bound"],
        "ideal_acceptance_upper_bound": model["ideal_acceptance_upper_bound"],
        "advantage_lower_bound": model["advantage_lower_bound"],
        "alpha_threshold_with_unknowns": model["alpha_threshold_with_unknowns"],
        "optimistic_zero_unknown_threshold": {
            "fraction": _fraction_payload(optimistic_threshold),
            "unknown_terms_set_to_zero_only_for_necessary_feasibility_screen": True,
        },
        "break_even_iterations_definition": model["break_even_iterations_definition"],
        "numerical_break_even_iterations_approx": numerical_break_even,
        "rationally_certified_iterations": certified_iterations,
        "rational_certification": model["rational_certification"],
        "angle_domain": {
            "certified_z": _fraction_payload(certified_z),
            "certified_z_decimal": f"{float(certified_z):.17g}",
            "certified_z_lt_one_quarter": certified_z < Fraction(1, 4),
            "arcsin_upper_bound": "arcsin(2^-128)<=2*2^-128",
            "actual_angle_interval": "z <= (2*j+1)arcsin(2^-128) <= 2z < 1/2 < pi/2",
            "sine_monotonicity_used": True,
            "cubic_lower_bound_domain": "0<=z<1/4"
        },
        "rational_sine_lower_bound_advantage": _fraction_payload(certified_advantage_lower),
        "rational_sine_lower_bound_exceeds_optimistic_threshold": certified_advantage_lower > optimistic_threshold,
        "work_convention": {
            "name": work["name"],
            "unit": work["unit"],
            "parallelism": work["parallelism"],
            "qro_queries": _exact_int(_required(work, "qro_queries"), "generic_key_search_screen.qro_queries"),
            "hidden_key_access": work["hidden_key_access"],
            "in_place_G_cost": in_place_cost,
            "maximov_G_cost": maximov_cost,
            "history_AES_operator_G_cost": history_operator_cost,
            "in_place_width_qubits": _exact_int(_required(in_place, "width_qubits"), "generic_key_search_screen.in_place.width_qubits"),
            "in_place_full_depth": _exact_int(_required(in_place, "full_depth"), "generic_key_search_screen.in_place.full_depth"),
            "maximov_width_qubits": _exact_int(_required(maximov, "width_qubits"), "generic_key_search_screen.maximov.width_qubits"),
            "maximov_full_depth": _exact_int(_required(maximov, "full_depth"), "generic_key_search_screen.maximov.full_depth"),
            "history_measurement_count": _exact_int(_required(history_operator, "measurement"), "generic_key_search_screen.history_operator.measurement"),
            "toffoli_G_cost": toffoli_cost,
            "diffusion_G_cost": diffusion_cost,
            "source": work["source"],
        },
        "toffoli_decomposition": {
            "CNOT": _exact_int(_required(toffoli, "CNOT"), "generic_key_search_screen.toffoli.CNOT"),
            "one_qubit_clifford": _exact_int(_required(toffoli, "one_qubit_clifford"), "generic_key_search_screen.toffoli.one_qubit_clifford"),
            "T": _exact_int(_required(toffoli, "T"), "generic_key_search_screen.toffoli.T"),
            "measurement": _exact_int(_required(toffoli, "measurement"), "generic_key_search_screen.toffoli.measurement"),
            "G_cost": toffoli_cost,
            "serial_depth": toffoli_depth,
            "width_qubits": _exact_int(_required(toffoli, "width_qubits"), "generic_key_search_screen.toffoli.width_qubits"),
            "source": toffoli["source"],
        },
        "grover_diffusion": {
            "control_count": control_count,
            "clean_chain_ancillas": clean_chain_ancillas,
            "forward_toffoli_count": forward_toffolis,
            "reverse_toffoli_count": reverse_toffolis,
            "CNOT": diffusion_cnot,
            "one_qubit_clifford": diffusion_one_qubit,
            "T": diffusion_t,
            "measurement": diffusion_measurement,
            "G_cost": diffusion_cost,
            "serial_depth": declared_diffusion_depth,
            "width_qubits": declared_diffusion_width,
            "ancillas_returned_to_zero": diffusion["ancillas_returned_to_zero"],
            "phase_convention": diffusion["phase_convention"],
            "cleanup_argument": diffusion["cleanup_argument"],
        },
        "primitive_game_algorithm": {
            "status": primitive["status"],
            "boundary": primitive["boundary"],
            "hidden_key_classical_queries": _exact_int(_required(primitive, "hidden_key_classical_queries"), "generic_key_search_screen.primitive.hidden_key_classical_queries"),
            "qro_queries": _exact_int(_required(primitive, "qro_queries"), "generic_key_search_screen.primitive.qro_queries"),
            "key_register_qubits": key_register_qubits,
            "maximum_quantum_width_qubits": maximum_width,
            "initialization_G_cost": initialization_cost,
            "initial_superposition_G_cost": initial_superposition_cost,
            "per_iteration_G_cost": per_iteration_cost,
            "per_iteration_serial_depth": per_iteration_depth,
            "final_measurement_G_cost": finalization_cost,
            "candidate_validation": {
                "public_AES_evaluations": validation_evaluations,
                "classical_block_comparisons": validation_comparisons,
                "reversible_equivalent_G_cost": validation_cost,
                "serial_depth_upper_bound": validation_serial_depth,
                "table8_oracle_not_recharged": validation["table8_oracle_not_recharged"],
            },
            "fixed_G_cost": fixed_G_cost,
            "strict_condition": primitive["strict_work_condition"],
        },
        "known_history": {
            "aes_blocks_at_declared_caps": aes_blocks,
            "charged_AES256_operator_G_cost_once": history_operator_cost,
            "known_history_G_cost_at_declared_caps": known_history,
            "known_history_log2_approx": log2_string(known_history),
            "known_history_charged_once_not_per_hybrid": True,
            "not_part_of_primitive_game_algorithm": True,
            "remaining_unknowns": model["known_history"]["remaining_unknowns"],
        },
        "joint_budget": {
            "primitive_condition": model["joint_budget"]["primitive_condition"],
            "product_auxiliary_condition": model["joint_budget"]["product_auxiliary_condition"],
            "strict_integer_rule": model["joint_budget"]["strict_integer_rule"],
            "primitive_fixed_G_cost": fixed_G_cost,
            "primitive_per_iteration_G_cost": per_iteration_cost,
            "primitive_certified_total_G_cost": certified_total_G,
            "primitive_certified_residual_G": work_limit - certified_total_G,
            "primitive_cap_total_G_cost": primitive_cap_total_G,
            "primitive_cap_residual_G": work_limit - primitive_cap_total_G,
            "product_known_history_G_cost": known_history,
            "product_certified_joint_total_G_cost": product_certified_total_G,
            "product_certified_joint_residual_G": work_limit - product_certified_total_G,
            "product_auxiliary_cap_total_G_cost": product_cap_total_G,
            "product_auxiliary_cap_residual_G": work_limit - product_cap_total_G,
            "marginal_intercepts_are_not_independent_allowances": True,
            "product_unknown_overlay_and_non_AES_costs_share_product_certified_residual": True,
        },
        "at_break_even_certified": {
            "iteration_count": certified_iterations,
            "total_G_cost": certified_total_G,
            "strictly_below_2^128": certified_total_G < work_limit,
            "advantage_lower_bound": _fraction_payload(certified_advantage_lower),
            "advantage_lower_bound_decimal": f"{float(certified_advantage_lower):.17g}",
            "weighted_alpha_lower_bound": _fraction_payload(current_weight * certified_advantage_lower),
            "weighted_alpha_lower_bound_decimal": f"{float(current_weight * certified_advantage_lower):.17g}",
            "weighted_exceeds_known_residual": current_weight * certified_advantage_lower > known_residual,
            "maximum_effective_weight_for_known_residual": break_even_maximum_effective_weight.numerator // break_even_maximum_effective_weight.denominator,
            "required_reduction_factor_approx": f"{float(Fraction(current_weight, 1) / (break_even_maximum_effective_weight.numerator // break_even_maximum_effective_weight.denominator)):.17g}",
        },
        "at_work_cap_fully_counted_primitive": {
            "iteration_count": primitive_cap_iterations,
            "fixed_G_cost": fixed_G_cost,
            "per_iteration_G_cost": per_iteration_cost,
            "total_G_cost": primitive_cap_total_G,
            "remaining_G_slack_below_2^128": work_limit - primitive_cap_total_G,
            "strictly_below_2^128": primitive_cap_total_G < work_limit,
            "serial_depth": primitive_serial_depth,
            "serial_depth_log2_approx": log2_string(primitive_serial_depth),
            "mixed_serial_depth_including_validation_upper_bound": total_mixed_serial_depth,
            "advantage_lower_bound": _fraction_payload(primitive_cap_advantage_lower),
            "advantage_lower_bound_decimal": f"{float(primitive_cap_advantage_lower):.17g}",
            "weighted_alpha_lower_bound": _fraction_payload(current_weight * primitive_cap_advantage_lower),
            "weighted_alpha_lower_bound_decimal": f"{float(current_weight * primitive_cap_advantage_lower):.17g}",
            "weighted_exceeds_known_residual": current_weight * primitive_cap_advantage_lower > known_residual,
            "interpretation": model["at_work_cap_fully_counted_primitive"]["interpretation"],
        },
        "product_history_auxiliary_screen": {
            "iteration_count_zero_unknown_overlay": product_cap_iterations,
            "total_G_cost": product_cap_total_G,
            "remaining_G_slack_below_2^128": work_limit - product_cap_total_G,
            "strictly_below_2^128": product_cap_total_G < work_limit,
            "advantage_lower_bound": _fraction_payload(product_cap_advantage_lower),
            "advantage_lower_bound_decimal": f"{float(product_cap_advantage_lower):.17g}",
            "weighted_alpha_lower_bound_decimal": f"{float(current_weight * product_cap_advantage_lower):.17g}",
            "interpretation": "Auxiliary only: this adds pinned history once to the complete primitive algorithm. It is not the primitive algorithm's T* and any unknown product overlay/non-AES cost consumes the same joint residual."
        },
        "hybrid_loss_analysis": {
            "current_weight": model["hybrid_loss_analysis"]["current_weight"],
            "current_weight_integer": current_weight,
            "residual_known_budget_before_unknowns": _fraction_payload(known_residual),
            "maximum_effective_weight_at_fully_counted_primitive_cap": maximum_effective_weight.numerator // maximum_effective_weight.denominator,
            "required_reduction_factor_at_fully_counted_primitive_cap_approx": f"{float(Fraction(current_weight, 1) / (maximum_effective_weight.numerator // maximum_effective_weight.denominator)):.17g}",
            "break_even_certified_maximum_effective_weight": break_even_maximum_effective_weight.numerator // break_even_maximum_effective_weight.denominator,
            "break_even_certified_required_reduction_factor_approx": f"{float(Fraction(current_weight, 1) / (break_even_maximum_effective_weight.numerator // break_even_maximum_effective_weight.denominator)):.17g}",
            "status": model["hybrid_loss_analysis"]["status"],
            "reason": model["hybrid_loss_analysis"]["reason"],
            "parallel_search_note": model["hybrid_loss_analysis"]["parallel_search_note"],
        },
    }


def concrete_feasibility(manifest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Evaluate the bounded concrete-PQ blocker without running availability."""

    loaded = load_manifest() if manifest is None else dict(manifest)
    _validate_manifest(loaded)
    feasibility = _require_mapping(_required(loaded, "concrete_feasibility"), "concrete_feasibility")
    caps = _require_mapping(
        _required(_require_mapping(_required(loaded, "candidate_accounting"), "candidate_accounting"), "caps"),
        "candidate_accounting.caps",
    )
    A_cap = _manifest_power(caps["A_max"], 32, "candidate_accounting.caps.A_max")
    V_cap = _manifest_power(caps["V_max"], 32, "candidate_accounting.caps.V_max")
    S_cap = _manifest_power(
        caps["S_max_when_source_cap_enforced"], 32, "candidate_accounting.caps.S_max_when_source_cap_enforced"
    )
    declared_opportunity_scope = _require_mapping(
        _required(feasibility, "opportunity_scope"), "concrete_feasibility.opportunity_scope"
    )
    Q_cap = _manifest_power(caps["Q_max"], 128, "candidate_accounting.caps.Q_max")
    privacy_model = _require_mapping(_required(loaded, "privacy"), "privacy")
    P_cap_constant = _exact_int(_required(privacy_model, "P_cap_constant"), "privacy.P_cap_constant")
    q_hist_cap_constant = _exact_int(
        _required(privacy_model, "q_hist_cap_constant"), "privacy.q_hist_cap_constant"
    )
    target = Fraction(1, _pow2(128))
    minimum = _switching_snapshot(1, 1, target)
    declared = _switching_snapshot(A_cap, S_cap, target)
    aes_blocks = 6406396 * A_cap + 6373495 * V_cap + 58 * S_cap
    return {
        "status": feasibility["status"],
        "target": _fraction_payload(target),
        "ledger_scope": feasibility["ledger_scope"],
        "opportunity_scope": {
            "global_lifetime_accounting_declared": declared_opportunity_scope["global_lifetime_accounting"],
            "global_lifetime_accounting_verified": False,
            "rotation_refunds_consumed_budget_declared": declared_opportunity_scope["rotation_refunds_consumed_budget"],
            "rotation_refund_behavior_verified": False,
            "clone_resistance_verified": False,
            "multiple_instance_accounting_verified": False,
            "counter_scope_status": "UNATTESTED_GLOBAL_LIFETIME",
            "offline_Q_budget_enforced": False,
            "reason": "The calculator has no authenticated cross-namespace event ledger and cannot observe adversarial offline QRO queries.",
        },
        "proof_trace": feasibility["proof_trace"],
        "switching": {
            "formula": feasibility["switching_formula"],
            "target_condition_for_switching_terms_alone": feasibility["target_condition_for_switching_terms_alone"],
            "minimum_nontrivial_deployment": minimum,
            "declared_lifetime_caps": declared,
            "component_checks": feasibility["component_checks"],
        },
        "work_model": {
            "formula": feasibility["work_model"]["formula"],
            "aes_block_counts": {
                "commit_generation_upper_bound": 6406396 * A_cap,
                "reconstruction_upper_bound": 6373495 * V_cap,
                "source_generation": 58 * S_cap,
                "at_declared_A_V_S_caps": aes_blocks,
            },
            "work_status": feasibility["work_model"]["work_status"],
            "hidden_key_access_model": feasibility["work_model"]["hidden_key_access_model"],
            "unknowns": feasibility["unknowns"],
        },
        "constant_success_work_model": _computational_work_model(
            feasibility,
            M_cap=A_cap,
            V_cap=V_cap,
            S_cap=S_cap,
            aes_blocks=aes_blocks,
            Q_cap=Q_cap,
            P_cap_constant=P_cap_constant,
            q_hist_cap_constant=q_hist_cap_constant,
        ),
        "model_gap": feasibility["model_gap"],
        "primitive_and_model_sources": feasibility["primitive_and_model_sources"],
        "decision": feasibility["decision"],
    }


def _stirling_second_kind(row_count: int, distinct_count: int) -> int:
    if distinct_count < 0 or distinct_count > row_count:
        return 0
    previous = [0] * (distinct_count + 1)
    previous[0] = 1
    for row in range(1, row_count + 1):
        current = [0] * (distinct_count + 1)
        for count in range(1, min(row, distinct_count) + 1):
            current[count] = count * previous[count] + previous[count - 1]
        previous = current
    return previous[distinct_count]


def _falling_factorial(value: int, count: int) -> int:
    result = 1
    for offset in range(count):
        result *= value - offset
    return result


def _ceil_fraction(value: Fraction) -> int:
    if value.denominator == 1:
        return value.numerator
    return value.numerator // value.denominator + 1


def _pos_in_tree(group: int, choice: int, *, tau: int, tau1: int, k: int, leaf_count: int) -> int:
    half = 1 << (k - 1)
    if choice < half:
        return leaf_count - 1 + tau * choice + group
    return leaf_count - 1 + tau * half + tau1 * (choice & (half - 1)) + group


def _availability_path_vectors(
    manifest: Mapping[str, Any], deadline: _AvailabilityDeadline | None = None
) -> dict[str, Any]:
    path_union = _require_mapping(
        _required(_require_mapping(_required(manifest, "availability"), "availability"), "decoder_path_union"),
        "availability.decoder_path_union",
    )
    parameters = _require_mapping(_required(path_union, "parameters"), "availability.decoder_path_union.parameters")
    tau = _exact_int(_required(parameters, "tau"), "availability.tau")
    tau1 = _exact_int(_required(parameters, "tau1"), "availability.tau1")
    k = _exact_int(_required(parameters, "k"), "availability.k")
    leaf_count = _exact_int(_required(parameters, "L"), "availability.L")
    heap_nodes = _exact_int(_required(parameters, "heap_nodes"), "availability.heap_nodes")
    group_count = _exact_int(_required(parameters, "group_count"), "availability.group_count")
    if heap_nodes != 2 * leaf_count - 1 or group_count != tau:
        raise ContractError("availability.decoder_path_union: geometry_mismatch")

    vectors = [[0] * group_count for _ in range(heap_nodes)]
    all_leaves: set[int] = set()
    group_choice_counts: list[int] = []
    for group in range(group_count):
        if deadline is not None:
            deadline.check()
        width = k if group < tau1 else k - 1
        choice_count = 1 << width
        group_choice_counts.append(choice_count)
        subtree_counts = [0] * heap_nodes
        group_leaves: set[int] = set()
        for choice in range(choice_count):
            if deadline is not None and choice % 32 == 0:
                deadline.check()
            leaf = _pos_in_tree(group, choice, tau=tau, tau1=tau1, k=k, leaf_count=leaf_count)
            if not (leaf_count - 1 <= leaf < heap_nodes):
                raise ContractError("availability.decoder_path_union: leaf_out_of_range")
            if leaf in group_leaves or leaf in all_leaves:
                raise ContractError("availability.decoder_path_union: noninjective_leaf_map")
            group_leaves.add(leaf)
            node = leaf
            while True:
                subtree_counts[node] += 1
                if node == 0:
                    break
                node = (node - 1) // 2
        all_leaves.update(group_leaves)
        for node, count in enumerate(subtree_counts):
            if count > choice_count:
                raise ContractError("availability.decoder_path_union: subtree_count_overflow")
            vectors[node][group] = count

    expected_leaves = set(range(leaf_count - 1, heap_nodes))
    if all_leaves != expected_leaves:
        raise ContractError("availability.decoder_path_union: incomplete_leaf_map")
    if len(group_choice_counts) != tau or sum(group_choice_counts) != leaf_count:
        raise ContractError("availability.decoder_path_union: group_geometry_mismatch")
    decoded_choice_bits = sum(width.bit_length() - 1 for width in group_choice_counts)
    if decoded_choice_bits != 248 or (1 << decoded_choice_bits) != _pow2(248):
        raise ContractError("availability.decoder_path_union: choice_denominator_mismatch")
    if _required(parameters, "choice_denominator") != "2^248":
        raise ContractError("availability.decoder_path_union: choice_denominator_metadata_mismatch")
    return {
        "vectors": [tuple(vector) for vector in vectors],
        "path_union": path_union,
        "heap_nodes": heap_nodes,
        "group_count": group_count,
        "leaf_count": leaf_count,
        "group_choice_counts": group_choice_counts,
        "selectable_leaves": len(all_leaves),
        "common_denominator": 1 << decoded_choice_bits,
        "decoded_choice_bits": decoded_choice_bits,
    }


def _z_value(signature: tuple[int, ...], group_choice_counts: list[int]) -> int:
    result = 1
    for choice_count, selected_count in zip(group_choice_counts, signature):
        result *= choice_count - selected_count
    return result


def _availability_path_union_first_moment(
    manifest: Mapping[str, Any],
    path_data: dict[str, Any] | None = None,
    deadline: _AvailabilityDeadline | None = None,
) -> dict[str, Any]:
    data = _availability_path_vectors(manifest, deadline) if path_data is None else path_data
    path_union = data["path_union"]
    vectors = data["vectors"]
    heap_nodes = data["heap_nodes"]
    group_count = data["group_count"]
    group_choice_counts = data["group_choice_counts"]
    common_denominator = data["common_denominator"]
    z_values: list[int] = []
    for node, vector in enumerate(vectors):
        if deadline is not None and node % 256 == 0:
            deadline.check()
        z_values.append(_z_value(vector, group_choice_counts))
    marked_numerator = heap_nodes * common_denominator - sum(z_values)
    expectation = Fraction(marked_numerator, common_denominator)
    deterministic_lower = _exact_int(
        _required(path_union, "deterministic_lower_bound_n_h"),
        "availability.deterministic_lower_bound_n_h",
    )
    parameters = _require_mapping(_required(path_union, "parameters"), "availability.decoder_path_union.parameters")
    rejection_threshold = _exact_int(
        _required(parameters, "n_h_acceptance_threshold"),
        "availability.n_h_acceptance_threshold",
    ) + 1
    if deterministic_lower >= rejection_threshold:
        raise ContractError("availability.decoder_path_union: lower_bound_not_below_rejection")
    excess_expectation = max(Fraction(0, 1), expectation - deterministic_lower)
    tail_bound = min(Fraction(1, 1), excess_expectation / (rejection_threshold - deterministic_lower))
    good_probability_lower = 1 - tail_bound
    g_lower_bound = _ceil_fraction((1 << 248) * good_probability_lower)
    filtered_probability_lower = Fraction(g_lower_bound, 1 << 263)
    return {
        "source_derived_mapping": True,
        "nodes_evaluated": heap_nodes,
        "groups_evaluated": group_count,
        "selectable_leaves": data["selectable_leaves"],
        "group_choice_counts": group_choice_counts,
        "decoded_choice_bits": data["decoded_choice_bits"],
        "leaf_map_injective": True,
        "common_denominator": str(common_denominator),
        "common_denominator_power": "2^248",
        "marked_numerator_sum": str(marked_numerator),
        "expectation_formula": "sum_v(1-product_i(1-c[i,v]/2^width_i))",
        "expected_n_h": _fraction_payload(expectation),
        "deterministic_lower_bound_n_h": deterministic_lower,
        "rejection_event": f"n_h >= {rejection_threshold}",
        "tail_bound_formula": "min(1,(E[n_h]-lower)/(rejection_threshold-lower))",
        "tail_bound": _fraction_payload(tail_bound),
        "good_probability_lower_bound": _fraction_payload(good_probability_lower),
        "g_lower_bound": g_lower_bound,
        "filtered_probability_lower_bound": _fraction_payload(filtered_probability_lower),
        "exact_g_status": "UNKNOWN",
        "conditional_assumptions": {
            "decoded_group_choices_uniform": True,
            "decoded_group_choices_independent": True,
            "fresh_uniform_ro_for_collision_split": True,
            "fixed_prefix_collision_split": True,
        },
    }


def _availability_second_moment(
    manifest: Mapping[str, Any],
    path_data: dict[str, Any],
    first_moment: dict[str, Any],
    deadline: _AvailabilityDeadline | None = None,
) -> dict[str, Any]:
    vectors = path_data["vectors"]
    heap_nodes = path_data["heap_nodes"]
    group_count = path_data["group_count"]
    group_choice_counts = path_data["group_choice_counts"]
    common_denominator = path_data["common_denominator"]
    signatures = Counter(vectors)
    ordered_signatures = sorted(signatures.items())
    signature_count = len(ordered_signatures)
    z_by_signature: dict[tuple[int, ...], int] = {}
    for index, signature in enumerate(signatures):
        if deadline is not None and index % 128 == 0:
            deadline.check()
        z_by_signature[signature] = _z_value(signature, group_choice_counts)
    signature_pairs = signature_count * (signature_count + 1) // 2

    ancestor_pairs = 0
    for descendant in range(1, heap_nodes):
        if deadline is not None and descendant % 256 == 0:
            deadline.check()
        ancestor = (descendant - 1) // 2
        while True:
            ancestor_pairs += 1
            if ancestor == 0:
                break
            ancestor = (ancestor - 1) // 2

    # This is a conservative count of group-factor products for the grouped
    # baseline, self correction, and both ancestor orientations.  It is checked
    # before entering any signature-pair or ancestor-correction loop.
    group_factor_upper_bound = group_count * (signature_pairs + 2 * heap_nodes + 2 * ancestor_pairs)
    working_array_upper_bound_bytes = (
        2 * heap_nodes * (group_count * 8 + 64)
        + heap_nodes * 8
        + signature_count * (group_count * 8 + 128)
    )
    if group_factor_upper_bound > SECOND_MOMENT_GROUP_FACTOR_LIMIT:
        raise ContractError("availability.second_moment: group_factor_resource_limit")
    if working_array_upper_bound_bytes > SECOND_MOMENT_WORKING_ARRAY_LIMIT_BYTES:
        raise ContractError("availability.second_moment: working_array_resource_limit")
    if deadline is not None:
        deadline.check()

    baseline = 0
    for left_index, (left, left_count) in enumerate(ordered_signatures):
        if deadline is not None:
            deadline.check()
        for right_index in range(left_index, signature_count):
            right, right_count = ordered_signatures[right_index]
            multiplicity = left_count * right_count * (1 if left_index == right_index else 2)
            combined = tuple(a + b for a, b in zip(left, right))
            baseline += multiplicity * _z_value(combined, group_choice_counts)

    self_correction = 0
    for index, (signature, count) in enumerate(signatures.items()):
        if deadline is not None and index % 128 == 0:
            deadline.check()
        self_correction += count * (
            z_by_signature[signature] - _z_value(tuple(2 * value for value in signature), group_choice_counts)
        )
    ancestor_correction = 0
    enumerated_ancestor_pairs = 0
    for descendant in range(1, heap_nodes):
        if deadline is not None:
            deadline.check()
        ancestor = (descendant - 1) // 2
        while True:
            enumerated_ancestor_pairs += 1
            ancestor_signature = vectors[ancestor]
            descendant_signature = vectors[descendant]
            combined = tuple(a + b for a, b in zip(ancestor_signature, descendant_signature))
            ancestor_correction += 2 * (
                z_by_signature[ancestor_signature] - _z_value(combined, group_choice_counts)
            )
            if ancestor == 0:
                break
            ancestor = (ancestor - 1) // 2
    if deadline is not None:
        deadline.check()

    signature_multiplicity_total = sum(signatures.values())
    ordered_pair_count = heap_nodes * heap_nodes
    disjoint_ordered_pairs = ordered_pair_count - heap_nodes - 2 * ancestor_pairs
    if (
        signature_multiplicity_total != heap_nodes
        or enumerated_ancestor_pairs != ancestor_pairs
        or disjoint_ordered_pairs < 0
    ):
        raise ContractError("availability.second_moment: pair_partition_mismatch")
    corrected_j = baseline + self_correction + ancestor_correction
    S = sum(count * z_by_signature[signature] for signature, count in signatures.items())
    second_moment = Fraction(
        heap_nodes * heap_nodes * common_denominator - 2 * heap_nodes * S + corrected_j,
        common_denominator,
    )
    variance = Fraction(corrected_j, common_denominator) - Fraction(S * S, common_denominator * common_denominator)
    if variance < 0:
        raise ContractError("availability.second_moment: negative_variance")
    expectation = Fraction(
        int(first_moment["expected_n_h"]["numerator"]),
        int(first_moment["expected_n_h"]["denominator"]),
    )
    if expectation != Fraction(heap_nodes * common_denominator - S, common_denominator):
        raise ContractError("availability.second_moment: first_moment_reconciliation_mismatch")
    rejection_threshold = int(first_moment["rejection_event"].split(">=", 1)[1].strip())
    t = rejection_threshold - expectation
    if t <= 0:
        raise ContractError("availability.second_moment: nonpositive_cantelli_t")
    first_tail = Fraction(
        int(first_moment["tail_bound"]["numerator"]),
        int(first_moment["tail_bound"]["denominator"]),
    )
    cantelli_tail = variance / (variance + t * t)
    selected_tail = min(first_tail, cantelli_tail)
    good_probability_lower = 1 - selected_tail
    g_lower_bound = _ceil_fraction((1 << 248) * good_probability_lower)
    filtered_probability_lower = Fraction(g_lower_bound, 1 << 263)
    return {
        "status": "COMPUTED_EXACT_GROUPED_SECOND_MOMENT",
        "signature_count": signature_count,
        "signature_pairs_unordered": signature_pairs,
        "signature_multiplicity_total": signature_multiplicity_total,
        "baseline_ordered_node_pairs": ordered_pair_count,
        "ancestor_pairs_one_orientation": ancestor_pairs,
        "proper_ancestor_descendant_ordered_pairs": 2 * ancestor_pairs,
        "disjoint_ordered_pairs": disjoint_ordered_pairs,
        "pair_partition_reconciles": heap_nodes + 2 * ancestor_pairs + disjoint_ordered_pairs == ordered_pair_count,
        "common_denominator": str(common_denominator),
        "common_denominator_power": "2^248",
        "S": str(S),
        "B_baseline": str(baseline),
        "self_correction": str(self_correction),
        "ancestor_correction_both_orientations": str(ancestor_correction),
        "J_corrected": str(corrected_j),
        "second_moment": _fraction_payload(second_moment),
        "expectation_reconciles_with_first_moment": True,
        "variance": _fraction_payload(variance),
        "variance_nonnegative": True,
        "cantelli_t": _fraction_payload(t),
        "first_moment_tail": _fraction_payload(first_tail),
        "cantelli_tail": _fraction_payload(cantelli_tail),
        "selected_tail": _fraction_payload(selected_tail),
        "tail_bound_kind": "minimum_of_markov_first_moment_and_cantelli",
        "good_probability_lower_bound": _fraction_payload(good_probability_lower),
        "g_lower_bound": g_lower_bound,
        "filtered_probability_lower_bound": _fraction_payload(filtered_probability_lower),
        "group_factor_multiplication_upper_bound": group_factor_upper_bound,
        "group_factor_multiplication_limit": SECOND_MOMENT_GROUP_FACTOR_LIMIT,
        "working_array_upper_bound_bytes": working_array_upper_bound_bytes,
        "working_array_limit_bytes": SECOND_MOMENT_WORKING_ARRAY_LIMIT_BYTES,
        "runtime_limit_seconds": SECOND_MOMENT_RUNTIME_LIMIT_SECONDS,
        "resource_estimate_phase": "before_grouped_pair_phase",
        "resource_guard_semantics": {
            "single_deadline_for_path_and_pair_work": deadline is not None,
            "periodic_checks_include_path_vectors": deadline is not None,
            "periodic_checks_include_grouped_pair_phase": deadline is not None,
            "deadline_checked_before_grouped_pair_phase": deadline is not None,
            "checks_performed": None if deadline is None else deadline.checks,
        },
        "resource_limits_hold": True,
        "intended_runtime": "O(N*K + K*(K+1)/2*K + N*log2(N)*K)",
        "pair_identity": {
            "disjoint_probability": "Z(c_v+c_w)/D",
            "nested_probability": "Z(c_ancestor)/D",
            "self_correction": "sum_v[Z(c_v)-Z(2*c_v)]",
            "ancestor_correction": "2*sum_(a proper ancestor of b)[Z(c_a)-Z(c_a+c_b)]",
            "signed_nested_Z_is_probability": False,
        },
        "exact_g_status": "UNKNOWN",
    }


def _conditional_collision_split_bound(p_good_lower: Fraction, retries: int) -> dict[str, Any]:
    if p_good_lower < 0 or p_good_lower >= 1:
        raise ContractError("availability.p_good_lower: outside_open_unit_interval")
    terms = min(16, retries)
    partial_sum = sum(
        (Fraction(math.comb(retries, index), 1) * (p_good_lower**index))
        for index in range(terms + 1)
    )
    # (1-p)^(-R) >= (1+p)^R >= the positive partial sum below.  This avoids
    # constructing a power with an enormous retry exponent.
    fresh_abort_upper = Fraction(1, 1) / partial_sum
    collision_term = Fraction(math.comb(retries, 2), _pow2(512))
    combined = min(Fraction(1, 1), fresh_abort_upper + collision_term)
    return {
        "p_good_lower": _fraction_payload(p_good_lower),
        "retry_count": retries,
        "partial_sum_terms": terms + 1,
        "partial_sum": _fraction_payload(partial_sum),
        "fresh_abort_upper_bound": _fraction_payload(fresh_abort_upper),
        "collision_term": _fraction_payload(collision_term),
        "collision_split_upper_bound": _fraction_payload(combined),
        "inequality_used": "(1-p_good_lower)^R <= 1/sum_{k=0..min(16,R)} binom(R,k)*p_good_lower^k",
        "reciprocal_inequality_also_valid": "(1-p_good_lower)^R <= 1/(1+R*p_good_lower)",
        "exact_g_not_substituted": True,
    }


def availability_report(
    manifest: Mapping[str, Any],
    g: int | None = None,
    retry_count: int | None = None,
    *,
    clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    _validate_manifest(manifest)
    deadline = _AvailabilityDeadline(time.perf_counter if clock is None else clock)
    path_data = _availability_path_vectors(manifest, deadline)
    path_union = _availability_path_union_first_moment(manifest, path_data, deadline)
    second_moment = _availability_second_moment(manifest, path_data, path_union, deadline)
    p_good_lower = Fraction(second_moment["g_lower_bound"], _pow2(263))
    result: dict[str, Any] = {
        "g": UNKNOWN,
        "g_status": "UNKNOWN",
        "p_good_expression": "g/2^263",
        "with_replacement_exact_abort_expression": "sum_{d=0}^R S(R,d)*(2^512)_d/2^(512R)*(1-p_good)^d",
        "collision_split_upper_bound_expression": "min(1,(1-p_good)^R+binom(R,2)/2^512)",
        "conditional_collision_split_upper_bound_expression": "min(1,1/sum_{k=0..min(16,R)} binom(R,k)*p_good_lower^k+binom(R,2)/2^512)",
        "conditional_fresh_abort_reciprocal_expression": "1/(1+R*p_good_lower)",
        "adaptive_trials_not_geometric": True,
        "large_evaluation_status": "NOT_EVALUATED_RESOURCE_GUARD",
        "fs3_cap_does_not_prove_availability": True,
        "first_moment_path_union": path_union,
        "second_moment_path_union": second_moment,
        "runtime_guard": {
            "single_calculation_deadline": True,
            "periodic_checks_include_path_vectors": True,
            "periodic_checks_include_grouped_pair_phase": True,
            "deadline_checked_before_grouped_pair_phase": True,
            "limit_seconds": SECOND_MOMENT_RUNTIME_LIMIT_SECONDS,
            "checks_performed": deadline.checks,
        },
        "conditional_lower_bound": {
            "status": "NONVACUOUS_CONDITIONAL_SECOND_MOMENT_BOUND",
            "g_is_still_unknown": True,
            "p_good_lower": _fraction_payload(p_good_lower),
            "filtered_probability_lower": _fraction_payload(p_good_lower),
            "fresh_abort_inequality": "(1-p_good_lower)^R <= 1/sum_{k=0..min(16,R)} binom(R,k)*p_good_lower^k",
            "fresh_abort_reciprocal_inequality": "(1-p_good_lower)^R <= 1/(1+R*p_good_lower)",
            "collision_term": "binom(R,2)/2^512",
            "assumptions": "independent uniform decoded groups and fresh uniform RO answers under a fixed prefix; nonce collisions are charged by the collision split",
        },
    }
    if g is None:
        if retry_count is not None:
            retries = _exact_int(retry_count, "availability.retry_count")
            result["retry_count"] = retries
            result["conditional_lower_bound"]["retry_evaluation"] = _conditional_collision_split_bound(
                p_good_lower, retries
            )
        return result
    g_value = _exact_int(g, "availability.g", maximum=_pow2(248))
    if g_value < second_moment["g_lower_bound"]:
        raise ContractError("availability.g: below_conditional_lower_bound")
    result["g"] = g_value
    result["g_status"] = "DECLARED_NOT_INDEPENDENTLY_VERIFIED"
    p_good = Fraction(g_value, _pow2(263))
    result["p_good"] = _fraction_payload(p_good)
    if retry_count is None:
        return result
    retries = _exact_int(retry_count, "availability.retry_count")
    result["retry_count"] = retries
    result["conditional_lower_bound"]["retry_evaluation"] = _conditional_collision_split_bound(
        p_good_lower, retries
    )
    if retries <= INDEPENDENT_EVALUATION_MAX_R:
        independent = (1 - p_good) ** retries
        collision = min(Fraction(1, 1), independent + Fraction(math.comb(retries, 2), _pow2(512)))
        result["independent_fresh_challenge_abort"] = _fraction_payload(independent)
        result["collision_split_upper_bound"] = _fraction_payload(collision)
    else:
        result["independent_fresh_challenge_abort"] = UNKNOWN
        result["collision_split_upper_bound"] = UNKNOWN
    if retries <= STIRLING_EVALUATION_MAX_R:
        total = _pow2(512) ** retries
        exact = Fraction(0, 1)
        for distinct in range(retries + 1):
            exact += Fraction(
                _stirling_second_kind(retries, distinct)
                * _falling_factorial(_pow2(512), distinct),
                total,
            ) * (1 - p_good) ** distinct
        result["with_replacement_exact_abort"] = _fraction_payload(exact)
        result["exact_evaluation_status"] = "EXACT_SMALL_R_ONLY"
    else:
        result["with_replacement_exact_abort"] = UNKNOWN
        result["exact_evaluation_status"] = "NOT_EVALUATED_RESOURCE_GUARD"
    return result


def calculate_report_v2(manifest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    loaded = load_manifest() if manifest is None else dict(manifest)
    _validate_manifest(loaded)
    formal = _formal_result_cap()
    constants = certificate_constants(loaded)
    qrom_caps = _qrom_cap_summary()
    cap_counters = qrom_caps["cap_counters"]
    privacy_caps = privacy_bound(loaded, cap_counters)
    feasibility = concrete_feasibility(loaded)
    return {
        "contract_version": loaded["manifest_version"],
        "candidate_id": loaded["candidate_id"],
        "status": loaded["status"],
        "v1_preservation": loaded["v1_preservation"],
        "provenance": loaded["provenance"],
        "protocol": loaded["protocol"],
        "random_oracle": loaded["random_oracle"],
        "honest_algorithm": loaded["honest_algorithm"],
        "certificate": {
            "constants": constants,
            "row_bound_at_j_0": row_bounds(loaded, 0),
            "row_bound_at_j_1": row_bounds(loaded, 1),
            "formula": loaded["certificate"]["row_bounds"],
            "simplified_formula": loaded["certificate"]["simplified_replacement_bound"],
            "witness_sizes": loaded["certificate"]["witness_sizes"],
            "theorem_application": loaded["certificate"]["theorem_application"],
        },
        "qrom_soundness": {
            "formula": loaded["qrom_soundness"]["formula"],
            "cap_evaluation": qrom_caps,
            "claim_limits": {
                "bound_kind": loaded["qrom_soundness"]["bound_kind"],
                "not_a_2^-128_false_acceptance_probability": True,
                "not_concrete_quantum_gate_or_work_bound": True,
            },
        },
        "privacy": {
            "formulas": {
                "adaptive_reprogramming": loaded["privacy"]["adaptive_reprogramming_formula"],
                "bit_hiding": loaded["privacy"]["bit_hiding_formula"],
                "source_hiding": loaded["privacy"]["source_hiding_formula"],
                "source_binding": loaded["privacy"]["source_binding_formula"],
            },
            "cap_evaluation": privacy_caps,
            "references": {
                "adaptive_reprogramming": loaded["privacy"]["adaptive_reprogramming_reference"],
            },
        },
        "concrete_feasibility": feasibility,
        "availability": availability_report(loaded),
        "candidate_accounting": loaded["candidate_accounting"],
        "source_correspondence": loaded["source_correspondence"],
        "claim_limits": loaded["claim_limits"],
        "formal_arithmetic": {
            "status": "LEAN_KERNEL_CHECKED_EXECUTED_AND_CONSUMED",
            "schema": formal["header"]["schema"],
            "build_id": formal["header"]["build_id"],
            "toolchain": formal["header"]["toolchain"],
            "binary_sha256": formal["binary_sha256"],
            "theorem_manifest_count": formal["theorems"]["manifest_count"],
            "theorem_manifest_names": formal["theorems"]["manifest_names"],
            "manifest_count_proof": formal["theorems"]["manifest_count_proof"],
            "cap_bundle": formal["theorems"]["cap_bundle"],
            "width_bundle": formal["theorems"]["width_bundle"],
            "row_bounds_bundle": formal["theorems"]["row_bounds_bundle"],
            "row_bounds_simplified": formal["theorems"]["row_bounds_simplified"],
            "width384_delta_cap_all_k": formal["theorems"]["width384_delta_cap_all_k"],
            "width512_delta_cap_all_k": formal["theorems"]["width512_delta_cap_all_k"],
            "width_delta_all_k_bundle": formal["theorems"]["width_delta_all_k_bundle"],
            "external_premises": "crypto, primitives, source custody/independence, and operations/RNG remain named premises",
        },
        "runtime_admission": {
            "admitted": False,
            "reason": "counter inputs are required for conditional arithmetic; even valid caller-supplied values are not authenticated as a global lifetime ledger",
            "counter_scope_status": "UNATTESTED_GLOBAL_LIFETIME",
            "global_lifetime_scope_verified": False,
            "offline_Q_budget_enforced": False,
            "enforced_by_calculator": False,
            "enforced_by_current_v2_source": False,
            "selected_in_product_state": False,
        },
    }


def calculate_report(manifest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Explicit v2 report entrypoint; the v1 module keeps its own same-named function."""

    return calculate_report_v2(manifest)


def admission_ledger(manifest: Mapping[str, Any], counters: Mapping[str, Any]) -> dict[str, Any]:
    loaded = dict(manifest)
    try:
        values = _require_counters(loaded, counters)
    except ContractError as exc:
        return {
            "contract_version": loaded.get("manifest_version", UNKNOWN),
            "admitted": False,
            "qualified": False,
            "activation": False,
            "production_usable": False,
            "errors": [str(exc)],
            "claim_effect": "fail_closed; no runtime claim is admitted",
        }
    report = calculate_report_v2(loaded)
    report["runtime_admission"] = {
        "admitted": False,
        "counter_input_validated": True,
        "conditional_arithmetic_available": True,
        "counters": values,
        "counter_provenance": "CALLER_SUPPLIED_UNVERIFIED",
        "counter_scope_status": "UNATTESTED_GLOBAL_LIFETIME",
        "global_lifetime_scope_verified": False,
        "offline_Q_budget_enforced": False,
        "reason": "counter values pass local syntax and identity checks only; no authenticated global-lifetime ledger or offline-Q bound is supplied",
        "claim_effect": "conditional arithmetic only; no globally scoped runtime or offline-adversary claim is admitted",
        "enforced_by_calculator": False,
        "enforced_by_current_v2_source": False,
        "selected_in_product_state": False,
    }
    qrom_evaluation = qrom_bound(loaded, values)
    qrom_evaluation["counter_scope_status"] = "UNATTESTED_GLOBAL_LIFETIME"
    qrom_evaluation["global_lifetime_scope_verified"] = False
    privacy_evaluation = privacy_bound(loaded, values)
    privacy_evaluation["counter_scope_status"] = "UNATTESTED_GLOBAL_LIFETIME"
    privacy_evaluation["global_lifetime_scope_verified"] = False
    report["qrom_soundness"]["runtime_evaluation"] = qrom_evaluation
    report["privacy"]["runtime_evaluation"] = privacy_evaluation
    report["availability"]["runtime_fs3_cap"] = values["R3"]
    report["availability"]["runtime_fs3_cap_scope_status"] = "UNATTESTED_GLOBAL_LIFETIME"
    return report


def _read_json(path: str | None) -> dict[str, Any]:
    if path is None:
        raise ContractError("json_input: path_required")
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"json_input: unreadable:{path}") from exc
    return dict(_require_mapping(value, "json_input"))


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Nonactivating filtered direct-mask v2 calculator")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--mode", choices=("report", "admit", "availability"), default="report")
    parser.add_argument("--counters")
    parser.add_argument("--g", type=int)
    parser.add_argument("--retry-count", type=int)
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        if args.mode == "report":
            result = calculate_report_v2(manifest)
        elif args.mode == "admit":
            counters = _read_json(args.counters)
            result = admission_ledger(manifest, counters)
        else:
            result = availability_report(manifest, args.g, args.retry_count)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ContractError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "admitted": False}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
