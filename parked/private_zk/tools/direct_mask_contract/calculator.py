"""Exact arithmetic and fail-closed admission ledger for the direct-mask candidate.

This module is intentionally a contract calculator, not a prover, verifier, cryptographic
implementation, or qualification gate.  It has no dependency on the Rust/C product path and never
turns a conditional or proposed calculation into a qualified claim.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import sys
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


CONTRACT_ROOT = Path(__file__).resolve().parent
DEFAULT_MANIFEST = CONTRACT_ROOT / "manifest.json"
UNKNOWN = "UNKNOWN"
STIRLING_EVALUATION_MAX_R = 128
EXHAUSTIVE_ASSIGNMENT_MAX = 1_000_000


class ContractError(ValueError):
    """A manifest, descriptor, or accounting input is not contract-valid."""


def _is_exact_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _same_exact_int(value: Any, expected: Any) -> bool:
    return _is_exact_int(value) and _is_exact_int(expected) and value == expected


def _matches_expected(value: Any, expected: Any) -> bool:
    if isinstance(expected, bool):
        return value is expected
    if _is_exact_int(expected):
        return _same_exact_int(value, expected)
    return value == expected


def _as_nonnegative_int(value: Any, name: str) -> int:
    if not _is_exact_int(value):
        raise ContractError(f"{name}: integer_required")
    if value < 0:
        raise ContractError(f"{name}: underflow")
    return value


def _as_positive_int(value: Any, name: str) -> int:
    result = _as_nonnegative_int(value, name)
    if result == 0:
        raise ContractError(f"{name}: underflow")
    return result


def _pow2(bits: int, name: str = "bits") -> int:
    return 1 << _as_nonnegative_int(bits, name)


def _fraction_payload(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def _fraction(value: int | Fraction) -> Fraction:
    return value if isinstance(value, Fraction) else Fraction(value, 1)


def _exact_div(numerator: int, denominator: int, name: str) -> int:
    if denominator <= 0:
        raise ContractError(f"{name}: invalid_denominator")
    if numerator % denominator:
        raise ContractError(f"{name}: non_integral_allocation")
    return numerator // denominator


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{name}: object_required")
    return value


def load_manifest(path: str | Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    """Load and structurally validate the single machine-readable contract source."""

    manifest_path = Path(path)
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"manifest: unreadable:{manifest_path}") from exc
    _validate_manifest(raw)
    return dict(raw)


def _validate_manifest(manifest: Mapping[str, Any]) -> None:
    if manifest.get("manifest_version") != "direct-mask-contract/v1":
        raise ContractError("manifest: wrong_version")
    status = _require_mapping(manifest.get("status"), "status")
    # These are hard policy values.  A future qualification process must create a new reviewed
    # record; this calculator must never infer or promote them.
    for key in ("qualified", "selected", "activation", "production_usable"):
        if status.get(key) is not False:
            raise ContractError(f"status.{key}: hard_false_required")
    if status.get("proof_suite_id") is not None:
        raise ContractError("status.proof_suite_id: must_be_null")
    if status.get("qualification_state") != "UNQUALIFIED":
        raise ContractError("status.qualification_state: must_be_unqualified")

    review = _require_mapping(manifest.get("review"), "review")
    if review.get("bounds_section_4") != "PROPOSED_PENDING_QUANTUM_REVIEW":
        raise ContractError("review.bounds_section_4: must_remain_proposed")
    if review.get("quantum_review_reference") != "01a07a39-edc3-76b2-b529-1dd2e080a9ca":
        raise ContractError("review.quantum_review_reference: identity_mismatch")

    provenance = _require_mapping(manifest.get("provenance"), "provenance")
    expected_provenance = {
        "implementation_base_commit": "60707e6aca0e0c320c67be76e178c7379f075e61",
        "implementation_base_tree": "2febe1822c0586d6ecaf7418d7d9056e5f190a29",
        "upstream_release": "v3.0.0",
        "upstream_commit": "ebefcbd8adda5faf447ef3dba5103794d17b4281",
        "upstream_tree": "f0c2e69f3eb0735fd544d04dc3dcfcc12e275e31",
    }
    for key, expected in expected_provenance.items():
        if provenance.get(key) != expected:
            raise ContractError(f"provenance.{key}: identity_mismatch")

    suite = _require_mapping(manifest.get("faest_256f"), "faest_256f")
    if not _same_exact_int(suite.get("lambda_bits"), 256):
        raise ContractError("faest_256f.lambda_bits: wrong_parameter")
    if not _same_exact_int(suite.get("vole_tree_count"), 33):
        raise ContractError("faest_256f.vole_tree_count: wrong_parameter")
    if not _same_exact_int(suite.get("grinding_bits"), 8):
        raise ContractError("faest_256f.grinding_bits: wrong_parameter")
    if not _same_exact_int(suite.get("opening_budget"), 229):
        raise ContractError("faest_256f.opening_budget: wrong_parameter")
    if not _same_exact_int(suite.get("total_leaves"), 6400):
        raise ContractError("faest_256f.total_leaves: wrong_parameter")
    if suite.get("non_em") is not True:
        raise ContractError("faest_256f.non_em: non_em_required")
    groups = suite.get("leaf_groups")
    expected_groups = ((17, 256), (16, 128))
    if not isinstance(groups, list) or len(groups) != len(expected_groups):
        raise ContractError("faest_256f.leaf_groups: wrong_tree_geometry")
    total = 0
    for index, group in enumerate(groups):
        group_map = _require_mapping(group, "faest_256f.leaf_group")
        count = _as_positive_int(group_map.get("tree_count"), "tree_count")
        leaves = _as_positive_int(group_map.get("leaves_per_tree"), "leaves_per_tree")
        if (count, leaves) != expected_groups[index]:
            raise ContractError("faest_256f.leaf_groups: wrong_tree_geometry")
        total += count * leaves
    if not _same_exact_int(total, suite.get("total_leaves")):
        raise ContractError("faest_256f.leaf_groups: total_mismatch")
    field = _require_mapping(suite.get("field"), "faest_256f.field")
    if field.get("modulus") != "X^256+X^10+X^5+X^2+1":
        raise ContractError("faest_256f.field.modulus: wrong_field_domain")
    if field.get("byte_embedding") != "bf256_byte_combine":
        raise ContractError("faest_256f.field.byte_embedding: wrong_field_domain")
    embedding = field.get("aes_subfield_generator_little_endian_hex")
    if embedding != (
        "e7fede0b42889796674e47a0388dd6be"
        "6ae1f1f8459822df3358c920cfa8c904"
    ):
        raise ContractError("faest_256f.field.embedding: wrong_byte_constants")

    direct = _require_mapping(manifest.get("direct_mask"), "direct_mask")
    if not _same_exact_int(direct.get("degree"), 3) or not _same_exact_int(direct.get("mask_count"), 6):
        raise ContractError("direct_mask: wrong_parameter")
    if direct.get("mask_count_formula") != "(d-1)+4":
        raise ContractError("direct_mask.mask_count_formula: wrong_parameter")
    if direct.get("ordinary_bit_vole_rows_formula") != "ell + mask_count * lambda":
        raise ContractError("direct_mask.ordinary_bit_vole_rows_formula: wrong_parameter")
    if direct.get("constraint_form") != "F_j(Z)=Z^3*f_j(rho_0(Z)/Z,...,rho_(ell-1)(Z)/Z)":
        raise ContractError("direct_mask.constraint_form: wrong_parameter")
    if direct.get("bitness_required") is not True:
        raise ContractError("direct_mask.bitness_required: must_be_true")
    if direct.get("padding_zero_constraint_required") is not True:
        raise ContractError("direct_mask.padding_zero_constraint_required: must_be_true")
    if direct.get("field_domain_required") is not True:
        raise ContractError("direct_mask.field_domain_required: must_be_true")
    if direct.get("homogenization_required") is not True:
        raise ContractError("direct_mask.homogenization_required: must_be_true")

    dimensions = _require_mapping(manifest.get("dimensions"), "dimensions")
    estimate = _require_mapping(dimensions.get("estimated"), "dimensions.estimated")
    if not _same_exact_int(estimate.get("ell_bits"), 117328) or not _same_exact_int(
        estimate.get("constraint_count"), 156788
    ):
        raise ContractError("dimensions.estimated: wrong_parameter")
    if not _same_exact_int(estimate.get("padding_zero_constraint_count"), 4):
        raise ContractError("dimensions.estimated.padding_zero_constraint_count: wrong_parameter")
    if estimate.get("source") != "illustrative_estimate_not_exporter_confirmed":
        raise ContractError("dimensions.estimated.source: stale_estimate_label_required")
    actual = dimensions.get("actual_export")
    if not isinstance(actual, Mapping):
        raise ContractError("dimensions.actual_export: missing_actual_export")
    expected_actual = {
        "status": "VERIFIED_READONLY_KERNEL_GATE",
        "dimension_source": "verified_readonly_kernel_gate",
        "exporter_confirmed": True,
        "source": "pq-direct-circuit-kernel-20260907",
        "commit": "124cd6a7107bbc20ec1e4c7e6cf2483dd5042c67",
        "tree": "1f051546b5c3bf756dcba094bbfbef7cf56ec2e2",
        "descriptor_header": "tools/direct_mask_kernel/direct_mask_kernel.h",
        "descriptor_header_sha256": "25DC2C7931E056E00FE91CCFF82815850F0A7EB5A4D3048D9A69C6325E7C9292",
        "descriptor_source": "tools/direct_mask_kernel/direct_mask_kernel.c",
        "descriptor_source_sha256": "52540EEF80B8308F365F64D07AB56F85877C9DF3D93877794A86D94F7C20F5AA",
        "algebra_status": "APPROVED_READONLY_COMPONENT_GATE",
        "algebra_header": "tools/direct_mask_kernel/direct_mask_algebra.h",
        "algebra_header_sha256": "8D16D4C9D356235FBCAA2338339516E5FCF6DFDEE5E52388FC173F3ED4185AFC",
        "algebra_source": "tools/direct_mask_kernel/direct_mask_algebra.c",
        "algebra_source_sha256": "ACC8ABB631F0E72638AE34522CB0D49098BE5E3ED7810D535EF75700D0E6B190",
        "ell_bits": 125048,
        "constraint_count": 172232,
        "padding_zero_constraint_count": 0,
        "degree": 3,
        "mask_count": 6,
        "ordinary_bit_vole_rows": 126584,
        "ordinary_bit_vole_row_bytes": 15823,
        "ell_byte_aligned": True,
    }
    for key, expected in expected_actual.items():
        if not _matches_expected(actual.get(key), expected):
            raise ContractError(f"dimensions.actual_export.{key}: identity_mismatch")
    if actual["ordinary_bit_vole_rows"] != actual["ell_bits"] + actual["mask_count"] * suite["lambda_bits"]:
        raise ContractError("dimensions.actual_export.ordinary_bit_vole_rows: formula_mismatch")
    if actual["ordinary_bit_vole_row_bytes"] * 8 != actual["ordinary_bit_vole_rows"]:
        raise ContractError("dimensions.actual_export.ordinary_bit_vole_row_bytes: formula_mismatch")
    envelope = _require_mapping(dimensions.get("admission_envelope"), "admission_envelope")
    if not _same_exact_int(envelope.get("max_ell_bits"), 131072) or not _same_exact_int(
        envelope.get("max_constraint_count"), 262144
    ):
        raise ContractError("dimensions.admission_envelope: wrong_parameter")
    if not _same_exact_int(envelope.get("required_degree"), 3) or envelope.get(
        "ell_must_be_byte_aligned"
    ) is not True:
        raise ContractError("dimensions.admission_envelope: wrong_parameter")

    transcript = _require_mapping(manifest.get("transcript"), "transcript")
    challenge_widths = transcript.get("challenge_widths_bits")
    if not isinstance(challenge_widths, list) or len(challenge_widths) != 3 or any(
        not _same_exact_int(value, expected)
        for value, expected in zip(challenge_widths, (2112, 832, 256))
    ):
        raise ContractError("transcript.challenge_widths_bits: wrong_parameter")
    if not _same_exact_int(transcript.get("round_nonce_bits"), 512):
        raise ContractError("transcript.round_nonce_bits: wrong_parameter")
    if transcript.get("final_retry_nonce_fresh") is not True:
        raise ContractError("transcript.final_retry_nonce_fresh: fresh_nonce_required")
    if transcript.get("retry_exhaustion") != "FAIL_CLOSED":
        raise ContractError("transcript.retry_exhaustion: fail_closed_required")

    wire = _require_mapping(manifest.get("wire_contract"), "wire_contract")
    wire_expected: dict[str, Any] = {
        "status": "VERIFIED_READONLY_WIRE_FACTS_NOT_E2E_PROTOCOL_APPROVAL",
        "owner": "E2E",
        "statement_bytes": 1147,
        "header_bytes": 40,
        "nu_bytes": 96,
        "nonce_count": 3,
        "nonce_bytes": 64,
        "m1_bytes": 506416,
        "m2_bytes": 15887,
        "m3_bytes": 96,
        "m4_bytes": 10496,
        "frame_bytes": 534370,
        "frame_formula": "statement_bytes + header_bytes + nu_bytes + nonce_count * nonce_bytes + m1_bytes + m2_bytes + m3_bytes + m4_bytes",
        "nonce_sampling": "WITH_REPLACEMENT_MODELLED; fresh per final candidate required",
    }
    for key, expected in wire_expected.items():
        if not _matches_expected(wire.get(key), expected):
            raise ContractError(f"wire_contract.{key}: identity_mismatch")
    wire_formula = (
        wire["statement_bytes"]
        + wire["header_bytes"]
        + wire["nu_bytes"]
        + wire["nonce_count"] * wire["nonce_bytes"]
        + wire["m1_bytes"]
        + wire["m2_bytes"]
        + wire["m3_bytes"]
        + wire["m4_bytes"]
    )
    if wire_formula != wire["frame_bytes"]:
        raise ContractError("wire_contract.frame_bytes: formula_mismatch")
    breakdown = _require_mapping(wire.get("statement_breakdown"), "wire_contract.statement_breakdown")
    breakdown_expected = {
        "source_suite_bytes": 16,
        "relation_length_bytes": 4,
        "relation_id_bytes": 23,
        "context_bytes": 64,
        "U_bytes": 96,
        "T_bytes": 96,
        "C_bytes": 800,
        "descriptor_fields": 12,
        "descriptor_field_bytes": 4,
    }
    for key, expected in breakdown_expected.items():
        if not _matches_expected(breakdown.get(key), expected):
            raise ContractError(f"wire_contract.statement_breakdown.{key}: identity_mismatch")
    statement_formula = sum(
        breakdown[key]
        for key in (
            "source_suite_bytes",
            "relation_length_bytes",
            "relation_id_bytes",
            "context_bytes",
            "U_bytes",
            "T_bytes",
            "C_bytes",
        )
    ) + breakdown["descriptor_fields"] * breakdown["descriptor_field_bytes"]
    if statement_formula != wire["statement_bytes"]:
        raise ContractError("wire_contract.statement_bytes: formula_mismatch")

    retry = _require_mapping(manifest.get("retry_abort"), "retry_abort")
    retry_expected: dict[str, Any] = {
        "raw_challenge_bits": 256,
        "grinding_bits": 8,
        "valid_challenge_bits": 248,
        "decoder": "decode_all_chall_3",
        "bavc_leaf_count": 6400,
        "bavc_leaf_heap_base": 6399,
        "opening_gate_formula": "n_h - 2 * tau + 1 <= T_open",
        "opening_node_threshold": 294,
        "valid_raw_domain": "0 <= gamma3 < 2^248",
        "p_good_expression": "sum_{gamma3=0}^{2^248-1} I[opening_node_count(decode_all_chall_3(gamma3)) <= 294] / 2^256",
        "p_good": UNKNOWN,
        "p_good_evaluation_status": "EXACT_FINITE_EXPRESSION_NOT_NUMERICALLY_EVALUATED_RESOURCE_GUARD",
        "nonce_bits": 512,
        "nonce_sampling_model": "WITH_REPLACEMENT",
        "stirling_exact_abort_expression": "sum_{d=0}^{R} S(R,d) * (2^512)_d / 2^(512*R) * (1-p_good)^d",
        "collision_upper_bound_expression": "min(1, (1-p_good)^R + binom(R,2)/2^512)",
    }
    for key, expected in retry_expected.items():
        if not _matches_expected(retry.get(key), expected):
            raise ContractError(f"retry_abort.{key}: identity_mismatch")
    widths = retry.get("challenge_group_widths_bits")
    if not isinstance(widths, list) or len(widths) != 33 or any(
        not _is_exact_int(width) for width in widths
    ) or widths != [8] * 17 + [7] * 16:
        raise ContractError("retry_abort.challenge_group_widths_bits: wrong_tree_geometry")
    retry_values = retry.get("retry_max_values")
    if not isinstance(retry_values, list) or len(retry_values) != 3 or any(
        not _same_exact_int(value, expected)
        for value, expected in zip(retry_values, (4096, 8192, 16384))
    ):
        raise ContractError("retry_abort.retry_max_values: wrong_parameter")
    for key in ("raw_challenge_bits", "grinding_bits", "valid_challenge_bits", "bavc_leaf_count", "bavc_leaf_heap_base", "opening_node_threshold", "nonce_bits"):
        if not _is_exact_int(retry[key]):
            raise ContractError(f"retry_abort.{key}: integer_required")
    if retry["raw_challenge_bits"] - retry["grinding_bits"] != retry["valid_challenge_bits"]:
        raise ContractError("retry_abort.valid_challenge_bits: formula_mismatch")

    security = _require_mapping(manifest.get("security_accounting"), "security_accounting")
    statistical = _require_mapping(
        security.get("statistical_false_acceptance"), "security_accounting.statistical_false_acceptance"
    )
    if statistical.get("formula") != "E_U * 2^-257 + other_stat":
        raise ContractError("security_accounting.statistical_false_acceptance: formula_mismatch")
    if statistical.get("source_pair_bound") != "binom(2^256,2)/(2^768-1) < 2^-257":
        raise ContractError("security_accounting.statistical_false_acceptance: source_bound_mismatch")
    if statistical.get("source_leaf_bad_bound") != "33/2^256":
        raise ContractError("security_accounting.statistical_false_acceptance: leaf_bound_mismatch")
    if statistical.get("E_U") != UNKNOWN or statistical.get("other_stat") != UNKNOWN:
        raise ContractError("security_accounting.statistical_false_acceptance: unknown_placeholder_required")
    ideal = _require_mapping(
        security.get("ideal_qrom_false_acceptance"), "security_accounting.ideal_qrom_false_acceptance"
    )
    if ideal.get("formula") != "B_snd(q) = min(1, 1020*q^3/2^512 + 360*q^2/2^256)":
        raise ContractError("security_accounting.ideal_qrom_false_acceptance: formula_mismatch")
    if ideal.get("q_formula") != "Q + 37*A + 38*V + R_retry + 38":
        raise ContractError("security_accounting.ideal_qrom_false_acceptance: q_formula_mismatch")
    if not _same_exact_int(ideal.get("local_witness_completion_overhead"), 38) or not _same_exact_int(ideal.get("local_certificate_rows"), 38):
        raise ContractError("security_accounting.ideal_qrom_false_acceptance: certificate_row_count_mismatch")
    if ideal.get("delta_j_formula") != "102*j/2^512 + 33/2^256 + 3/2^256 = 102*j/2^512 + 36/2^256":
        raise ContractError("security_accounting.ideal_qrom_false_acceptance: delta_j_formula_mismatch")
    if ideal.get("local_certificate_proof_record") != "LOCAL_CERTIFICATE_PROOF.md" or ideal.get("local_certificate_proof_status") != "REVIEWED_CONDITIONAL_QUERY_ONLY":
        raise ContractError("security_accounting.ideal_qrom_false_acceptance: proof_record_mismatch")
    concrete = _require_mapping(
        security.get("concrete_false_acceptance"), "security_accounting.concrete_false_acceptance"
    )
    if concrete.get("formula") != "E_U * 2^-257 + B_snd(q) + Adv_SHAKE_snd + Adv_source_auth + Adv_U_generation":
        raise ContractError("security_accounting.concrete_false_acceptance: formula_mismatch")
    for key in ("Adv_SHAKE_snd", "Adv_source_auth", "Adv_U_generation"):
        if concrete.get(key) != UNKNOWN:
            raise ContractError(f"security_accounting.concrete_false_acceptance.{key}: unknown_placeholder_required")
    privacy = _require_mapping(security.get("privacy"), "security_accounting.privacy")
    if privacy.get("formula") != "epsilon_priv <= min(1, epsilon_coins + epsilon_AR + epsilon_bitMH + epsilon_source + Adv_SHAKE_priv)":
        raise ContractError("security_accounting.privacy: formula_mismatch")
    if privacy.get("adaptive_reprogramming_formula") != "epsilon_AR <= min(1, sum_{r=1}^{P} [sqrt(qhat_r * 2^-512) + 1/2 * qhat_r * 2^-512])":
        raise ContractError("security_accounting.privacy: adaptive_reprogramming_formula_mismatch")
    if privacy.get("adaptive_reprogramming_event_bound") != "P <= 2*A + R_retry":
        raise ContractError("security_accounting.privacy: reprogramming_event_bound_mismatch")
    if privacy.get("bit_hiding_formula") != "epsilon_bitMH <= min(1, M * (397*alpha_4(T*,Q*) + 33*alpha_2048(T*,Q*) + 33*alpha_989(T*,Q*) + 85297284/2^128))":
        raise ContractError("security_accounting.privacy: bit_hiding_formula_mismatch")
    if privacy.get("source_hiding_formula") != "epsilon_source <= min(1, S * (alpha_8(T*,Q*) + alpha_50(T*,Q*) + 1253/2^128))":
        raise ContractError("security_accounting.privacy: source_hiding_formula_mismatch")
    if privacy.get("M_bound") != "M <= A":
        raise ContractError("security_accounting.privacy: M_bound_mismatch")
    if privacy.get("R_retry_semantics") != "R_retry counts every final FS3 candidate, including the first, successful, discarded, and pre-abort candidates":
        raise ContractError("security_accounting.privacy: R_retry_semantics_mismatch")
    if privacy.get("source_reproof_rule") != "a fresh proof invocation increments A; a fresh BAVC commitment instance increments M; an unchanged source assertion does not increment S; an exact byte-identical retransmission itself increments none of A, M, or S, but any cryptographic operation it triggers is charged separately, including V when it is verified":
        raise ContractError("security_accounting.privacy: source_reproof_rule_mismatch")
    if privacy.get("q1_aes256_definition") != "alpha_s(T*,Q*) is the maximum quantum AES-256 PRP distinguishing advantage for time at most T*, at most s DISTINCT CLASSICAL input blocks to one hidden independent random-key challenge oracle, and at most Q* queries to an independent public QRO; public AES computation and quantum computation are allowed, but superposition access to the hidden-key AES oracle is not allowed":
        raise ContractError("security_accounting.privacy: q1_definition_mismatch")
    if privacy.get("q1_aes256_access_model") != "CLASSICAL_HIDDEN_KEY_Q1_NOT_Q2":
        raise ContractError("security_accounting.privacy: q1_access_model_mismatch")
    if privacy.get("block_count_semantics") != "derived AES block counts are source-counted bounds, not measured quantum work":
        raise ContractError("security_accounting.privacy: block_count_semantics_mismatch")
    aes_games = _require_mapping(privacy.get("q1_aes256_games"), "security_accounting.privacy.q1_aes256_games")
    expected_games = {
        "node": {"block_inputs": 4, "multiplicity": 397},
        "leaf": {"block_inputs": 2048, "multiplicity": 33},
        "stream": {"block_inputs": 989, "multiplicity": 33},
    }
    if set(aes_games) != set(expected_games) or any(
        not isinstance(aes_games.get(name), Mapping)
        or not _same_exact_int(aes_games[name].get("block_inputs"), expected_games[name]["block_inputs"])
        or not _same_exact_int(aes_games[name].get("multiplicity"), expected_games[name]["multiplicity"])
        for name in expected_games
    ):
        raise ContractError("security_accounting.privacy.q1_aes256_games: identity_mismatch")
    source_games = _require_mapping(privacy.get("source_games"), "security_accounting.privacy.source_games")
    if (
        not _same_exact_int(source_games.get("G0_block_inputs"), 8)
        or not _same_exact_int(source_games.get("G1_block_inputs"), 50)
        or source_games.get("finite_switching_term") != "1253/2^128"
        or source_games.get("source_count_symbol") != "S"
        or source_games.get("source_formula") != "epsilon_source <= min(1, S * (alpha_8(T*,Q*) + alpha_50(T*,Q*) + 1253/2^128))"
    ):
        raise ContractError("security_accounting.privacy.source_games: identity_mismatch")
    blocks = _require_mapping(privacy.get("block_count_formulas"), "security_accounting.privacy.block_count_formulas")
    expected_block_formulas = {
        "commit_generation": "4*(6400-1)+(8+989)*6400=6406396",
        "reconstruction": "4*(6400-1)+(8+989)*(6400-33)=6373495",
        "source_generation": "58*S",
    }
    for key, expected in expected_block_formulas.items():
        if blocks.get(key) != expected:
            raise ContractError(f"security_accounting.privacy.block_count_formulas.{key}: identity_mismatch")
    history = _require_mapping(privacy.get("full_history"), "security_accounting.privacy.full_history")
    expected_history = {
        "q_hist_formula": "q_hist = Q + 38*A + 39*V + R_retry",
        "q_star_formula": "Q* <= 2*q_hist",
        "P_formula": "P <= 2*A + R_retry",
        "reprogramming_lookup_cost": "O(P*L_FS) per QRO call",
        "T_star": UNKNOWN,
        "T_star_formula": "T* = T_adversary + C_commit*A + C_reconstruct*V + C_source*S + C_circuit + C_VH_ZK + C_transpose_pack + C_opening*R_retry + C_SHAKE(q_hist) + C_overlay(P,L_FS)",
        "L_FS": UNKNOWN,
        "runtime_declaration_status": "INCOMPLETE_MISSING_T_STAR_OR_ROUTINE_COSTS",
    }
    for key, expected in expected_history.items():
        if history.get(key) != expected:
            raise ContractError(f"security_accounting.privacy.full_history.{key}: identity_mismatch")
    costs = _require_mapping(history.get("per_routine_costs"), "security_accounting.privacy.full_history.per_routine_costs")
    for key in ("T_adversary", "C_commit", "C_reconstruct", "C_source", "C_circuit", "C_VH_ZK", "C_transpose_pack", "C_opening", "C_SHAKE", "C_overlay"):
        if costs.get(key) != UNKNOWN:
            raise ContractError(f"security_accounting.privacy.full_history.per_routine_costs.{key}: unknown_placeholder_required")
    for key in ("epsilon_coins", "epsilon_AR", "epsilon_bitMH", "epsilon_source", "Adv_SHAKE_priv", "privacy_cap"):
        if privacy.get(key) != UNKNOWN:
            raise ContractError(f"security_accounting.privacy.{key}: unknown_placeholder_required")
    if privacy.get("proof_record") != "PRIVACY_REDUCTION_PROOF.md" or privacy.get("proof_status") != "COMPLETED_CONDITIONAL_QUERY_MODEL_NOT_CONCRETE":
        raise ContractError("security_accounting.privacy: proof_record_mismatch")

    counters = _require_mapping(manifest.get("counter_ledger"), "counter_ledger")
    reservations = _require_mapping(counters.get("acceptance_reservations"), "counter_ledger.acceptance_reservations")
    reservation_expected = {
        "per_current_batch": 101,
        "global_cap": 4294967296,
        "full_batches_at_current_charge": 42524428,
        "remaining_reservations_after_full_batches": 68,
        "scope": "operational reservation ledger; not a QROM or theorem-event multiplier",
    }
    for key, expected in reservation_expected.items():
        if not _matches_expected(reservations.get(key), expected):
            raise ContractError(f"counter_ledger.acceptance_reservations.{key}: identity_mismatch")
    if reservations["per_current_batch"] * reservations["full_batches_at_current_charge"] + reservations["remaining_reservations_after_full_batches"] != reservations["global_cap"]:
        raise ContractError("counter_ledger.acceptance_reservations: formula_mismatch")
    definitions = _require_mapping(counters.get("definitions"), "counter_ledger.definitions")
    required_counter_names = {
        "proof_attempts": "A",
        "verification_invocations": "V",
        "fs3_candidates": "R_retry",
        "source_u_parameter_issuances": "E_U",
        "source_commitments": "S",
        "commitment_instances": "M",
        "exact_retransmits": "audit_only",
    }
    for name, symbol in required_counter_names.items():
        definition = _require_mapping(definitions.get(name), f"counter_ledger.definitions.{name}")
        if definition.get("symbol") != symbol:
            raise ContractError(f"counter_ledger.definitions.{name}.symbol: identity_mismatch")
        for field in ("increment", "rollback", "recovery"):
            if not isinstance(definition.get(field), str) or not definition[field]:
                raise ContractError(f"counter_ledger.definitions.{name}.{field}: required")
    bounds = _require_mapping(counters.get("bounds"), "counter_ledger.bounds")
    if bounds.get("M") != "M <= A" or bounds.get("P") != "P <= 2*A + R_retry":
        raise ContractError("counter_ledger.bounds: identity_mismatch")
    if bounds.get("R_retry") != "includes the first final FS3 candidate":
        raise ContractError("counter_ledger.bounds.R_retry: identity_mismatch")
    if counters.get("Q_definition") != "adversary coherent QRO queries; security-model parameter, not an application counter":
        raise ContractError("counter_ledger.Q_definition: identity_mismatch")
    if counters.get("storage_requirement") != "persist opaque issuance identities and counts only; never source roots, pads, x, commitment bytes, proof bytes, or stable exact-byte hashes":
        raise ContractError("counter_ledger.storage_requirement: identity_mismatch")
    if counters.get("atomicity_requirement") != "durable nonrefundable reservation commits before the relevant cryptographic/challenge operation (or as a bounded up-front reservation); the outcome is recorded separately; reservation, outcome, and retry ledger fail closed if their journal is incomplete":
        raise ContractError("counter_ledger.atomicity_requirement: identity_mismatch")
    if counters.get("no_refund_requirement") != "rollback, crash, cleanup failure, abandoned or restarted handoff, and unknown outcome never refund a consumed reservation or counter":
        raise ContractError("counter_ledger.no_refund_requirement: identity_mismatch")
    if counters.get("recovery_requirement") != "recovery never resumes a consumed partial proof or handoff and never replays retained private material":
        raise ContractError("counter_ledger.recovery_requirement: identity_mismatch")

    resource = _require_mapping(manifest.get("resource_accounting"), "resource_accounting")
    for key in (
        "Q",
        "N",
        "M",
        "P",
        "qhat",
        "A",
        "V",
        "R_retry",
        "S",
        "E_U",
        "retry_max",
        "lifetime_attempt_budget",
        "source_u_reuse_count",
        "source_u_reissued_parameter_count",
        "Adv_Q1_AES256_node",
        "Adv_Q1_AES256_leaf",
        "Adv_Q1_AES256_stream",
        "Adv_SHAKE_snd",
        "Adv_source_auth",
        "Adv_U_generation",
        "Adv_SHAKE_priv",
        "epsilon_coins",
        "epsilon_AR",
        "epsilon_bitMH",
        "epsilon_source",
        "privacy_cap",
        "runtime_measurement",
        "privacy_policy_target",
        "T_star",
        "T_adversary",
        "q_hist",
        "Q_star",
        "L_FS",
        "reprogramming_lookup_cost",
        "C_commit",
        "C_reconstruct",
        "C_source",
        "C_circuit",
        "C_VH_ZK",
        "C_transpose_pack",
        "C_opening",
        "C_SHAKE",
        "C_overlay",
    ):
        if resource.get(key) != UNKNOWN:
            raise ContractError(f"resource_accounting.{key}: unknown_placeholder_required")
    if resource.get("runtime_declaration_status") != "INCOMPLETE_MISSING_T_STAR_OR_ROUTINE_COSTS":
        raise ContractError("resource_accounting.runtime_declaration_status: identity_mismatch")
    if resource.get("block_cost_formula") != "6406396*A + 6373495*V + 58*S":
        raise ContractError("resource_accounting.block_cost_formula: identity_mismatch")
    for key, expected in (
        ("proof_attempt_block_cost", 6406396),
        ("verification_block_cost", 6373495),
        ("source_commitment_block_cost", 58),
    ):
        if not _same_exact_int(resource.get(key), expected):
            raise ContractError(f"resource_accounting.{key}: identity_mismatch")

    source_accounting = _require_mapping(manifest.get("source_accounting"), "source_accounting")
    if source_accounting.get("single_reused_U_global_bad_event") != "<1/2^257":
        raise ContractError("source_accounting.single_reused_U_global_bad_event: bound_mismatch")
    if source_accounting.get("independently_reissued_parameter_events") != "<reissued_parameter_count/2^257":
        raise ContractError("source_accounting.independently_reissued_parameter_events: bound_mismatch")
    if source_accounting.get("pair_bound_formula") != "binom(2^256,2)/(2^768-1) < 2^-257 per independent U":
        raise ContractError("source_accounting.pair_bound_formula: bound_mismatch")
    if not _same_exact_int(source_accounting.get("initial_U_issuance_count"), 1):
        raise ContractError("source_accounting.initial_U_issuance_count: identity_mismatch")
    if source_accounting.get("initial_U_included_in_E_U") is not True:
        raise ContractError("source_accounting.initial_U_included_in_E_U: declaration_required")
    if source_accounting.get("total_independent_U_issuances_formula") != "E_U = initial_U_issuance_count + reissued_parameter_count":
        raise ContractError("source_accounting.total_independent_U_issuances_formula: identity_mismatch")
    if source_accounting.get("reuse_is_not_reissuance") is not True:
        raise ContractError("source_accounting.reuse_is_not_reissuance: declaration_required")
    if source_accounting.get("reissue_count_must_be_declared") is not True or source_accounting.get("reuse_count_must_be_declared") is not True:
        raise ContractError("source_accounting: declaration_required")


def _suite(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    return _require_mapping(manifest["faest_256f"], "faest_256f")


def _direct(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    return _require_mapping(manifest["direct_mask"], "direct_mask")


def _estimated_dimensions(manifest: Mapping[str, Any]) -> tuple[int, int]:
    dimensions = _require_mapping(manifest["dimensions"], "dimensions")
    estimate = _require_mapping(dimensions["estimated"], "dimensions.estimated")
    return (
        _as_positive_int(estimate["ell_bits"], "estimated.ell_bits"),
        _as_positive_int(estimate["constraint_count"], "estimated.constraint_count"),
    )


def _actual_dimensions(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Return the immutable read-only kernel dimensions used by all finite ledgers."""

    _validate_manifest(manifest)
    dimensions = _require_mapping(manifest["dimensions"], "dimensions")
    actual = _require_mapping(dimensions["actual_export"], "dimensions.actual_export")
    return {
        "dimension_source": actual["dimension_source"],
        "exporter_confirmed": actual["exporter_confirmed"],
        "source": actual["source"],
        "commit": actual["commit"],
        "tree": actual["tree"],
        "descriptor_header": actual["descriptor_header"],
        "descriptor_header_sha256": actual["descriptor_header_sha256"],
        "descriptor_source": actual["descriptor_source"],
        "descriptor_source_sha256": actual["descriptor_source_sha256"],
        "algebra_status": actual["algebra_status"],
        "algebra_header": actual["algebra_header"],
        "algebra_header_sha256": actual["algebra_header_sha256"],
        "algebra_source": actual["algebra_source"],
        "algebra_source_sha256": actual["algebra_source_sha256"],
        "ell_bits": _as_positive_int(actual["ell_bits"], "actual.ell_bits"),
        "constraint_count": _as_positive_int(actual["constraint_count"], "actual.constraint_count"),
        "padding_zero_constraint_count": _as_nonnegative_int(
            actual["padding_zero_constraint_count"], "actual.padding_zero_constraint_count"
        ),
        "degree": _as_positive_int(actual["degree"], "actual.degree"),
        "mask_count": _as_positive_int(actual["mask_count"], "actual.mask_count"),
        "ordinary_bit_vole_rows": _as_positive_int(
            actual["ordinary_bit_vole_rows"], "actual.ordinary_bit_vole_rows"
        ),
        "ordinary_bit_vole_row_bytes": _as_positive_int(
            actual["ordinary_bit_vole_row_bytes"], "actual.ordinary_bit_vole_row_bytes"
        ),
        "ell_byte_aligned": actual["ell_byte_aligned"],
    }


def _tree_total(manifest: Mapping[str, Any]) -> int:
    suite = _suite(manifest)
    return sum(
        _as_positive_int(group["tree_count"], "tree_count")
        * _as_positive_int(group["leaves_per_tree"], "leaves_per_tree")
        for group in suite["leaf_groups"]
    )


def _retry_parameters(manifest: Mapping[str, Any]) -> dict[str, Any]:
    _validate_manifest(manifest)
    suite = _suite(manifest)
    retry = _require_mapping(manifest["retry_abort"], "retry_abort")
    widths = list(retry["challenge_group_widths_bits"])
    return {
        "lambda_bits": _as_positive_int(suite["lambda_bits"], "lambda_bits"),
        "grinding_bits": _as_nonnegative_int(suite["grinding_bits"], "grinding_bits"),
        "tree_count": _as_positive_int(suite["vole_tree_count"], "vole_tree_count"),
        "opening_budget": _as_positive_int(suite["opening_budget"], "opening_budget"),
        "leaf_count": _as_positive_int(retry["bavc_leaf_count"], "bavc_leaf_count"),
        "leaf_heap_base": _as_nonnegative_int(retry["bavc_leaf_heap_base"], "bavc_leaf_heap_base"),
        "widths": widths,
        "opening_threshold": _as_nonnegative_int(
            retry["opening_node_threshold"], "opening_node_threshold"
        ),
        "nonce_bits": _as_positive_int(retry["nonce_bits"], "nonce_bits"),
    }


def _bavc_leaf_index_from_parameters(group: int, choice: int, parameters: Mapping[str, Any]) -> int:
    widths = parameters["widths"]
    if not _is_exact_int(group) or group < 0 or group >= len(widths):
        raise ContractError("challenge_group: overflow")
    if not _is_exact_int(choice) or choice < 0 or choice >= (1 << widths[group]):
        raise ContractError("challenge_choice: overflow")
    if group < 17:
        if choice < 128:
            leaf = 33 * choice + group
        else:
            leaf = 33 * 128 + 17 * (choice - 128) + group
    else:
        leaf = 33 * choice + group
    if leaf < 0 or leaf >= parameters["leaf_count"]:
        raise ContractError("challenge_leaf: overflow")
    return leaf


def bavc_leaf_index(manifest: Mapping[str, Any], group: int, choice: int) -> int:
    """Map one decoded challenge coordinate to the pinned BAVC leaf index."""

    return _bavc_leaf_index_from_parameters(group, choice, _retry_parameters(manifest))


def decode_all_chall_3(manifest: Mapping[str, Any], raw_challenge: int) -> dict[str, Any]:
    """Decode the little-endian 256-bit FS3 string using the FAEST challenge widths."""

    parameters = _retry_parameters(manifest)
    raw = _as_nonnegative_int(raw_challenge, "gamma3")
    lambda_bits = parameters["lambda_bits"]
    if raw >= (1 << lambda_bits):
        raise ContractError("gamma3: overflow")
    offset = 0
    choices: list[int] = []
    leaves: list[int] = []
    for group, width in enumerate(parameters["widths"]):
        choices.append((raw >> offset) & ((1 << width) - 1))
        leaves.append(_bavc_leaf_index_from_parameters(group, choices[-1], parameters))
        offset += width
    valid_grinding = (raw >> (lambda_bits - parameters["grinding_bits"])) == 0
    return {
        "raw_challenge": raw,
        "raw_challenge_bits": lambda_bits,
        "valid_grinding": valid_grinding,
        "high_grinding_bits": raw >> (lambda_bits - parameters["grinding_bits"]),
        "decoded_bits": offset,
        "group_widths_bits": list(parameters["widths"]),
        "choices": choices,
        "leaf_indices": leaves,
    }


def bavc_opening_node_count(manifest: Mapping[str, Any], leaf_indices: Sequence[int]) -> int:
    """Count the exact union of BAVC selected-leaf heap paths, including leaves and root."""

    parameters = _retry_parameters(manifest)
    if not isinstance(leaf_indices, Sequence) or isinstance(leaf_indices, (str, bytes)):
        raise ContractError("leaf_indices: sequence_required")
    marked: set[int] = set()
    for leaf in leaf_indices:
        leaf_value = _as_nonnegative_int(leaf, "leaf_index")
        if leaf_value >= parameters["leaf_count"]:
            raise ContractError("leaf_index: overflow")
        node = parameters["leaf_heap_base"] + leaf_value
        while True:
            marked.add(node)
            if node == 0:
                break
            node = (node - 1) // 2
    return len(marked)


def bavc_opening_gate(manifest: Mapping[str, Any], opening_nodes: int) -> bool:
    """Apply the pinned BAVC opening gate without changing the runtime cap."""

    parameters = _retry_parameters(manifest)
    nodes = _as_nonnegative_int(opening_nodes, "n_h")
    return nodes - 2 * parameters["tree_count"] + 1 <= parameters["opening_budget"]


def exact_good_count_enumeration(
    group_widths: Sequence[int],
    leaf_mapper: Callable[[int, int], int],
    opening_threshold: int,
    *,
    leaf_count: int,
    max_assignments: int = EXHAUSTIVE_ASSIGNMENT_MAX,
) -> dict[str, Any]:
    """Run a deliberately bounded exact finite enumeration for structural analogues.

    The production 248-bit domain is represented by :func:`p_good_exact_expression` and is
    never silently enumerated here.  Small test instances can use this same union-of-path
    combinatorics with a bounded assignment count.
    """

    if not isinstance(group_widths, Sequence) or isinstance(group_widths, (str, bytes)):
        raise ContractError("group_widths: sequence_required")
    widths = [_as_positive_int(width, "group_width") for width in group_widths]
    threshold = _as_nonnegative_int(opening_threshold, "opening_threshold")
    leaves = _as_positive_int(leaf_count, "leaf_count")
    limit = _as_positive_int(max_assignments, "max_assignments")
    total_bits = 0
    max_bits = limit.bit_length() - 1
    for width in widths:
        if total_bits > max_bits - width:
            raise ContractError("enumeration: resource_guard")
        total_bits += width
    assignments = 1 << total_bits
    if assignments > limit:
        raise ContractError("enumeration: resource_guard")
    good = 0
    for choices in itertools.product(*(range(1 << width) for width in widths)):
        mapped = [leaf_mapper(group, choice) for group, choice in enumerate(choices)]
        if any(not _is_exact_int(leaf) or leaf < 0 or leaf >= leaves for leaf in mapped):
            raise ContractError("enumeration: leaf_mapper_out_of_range")
        # The analogue uses the same complete binary heap indexing as BAVC.
        marked: set[int] = set()
        heap_base = leaves - 1
        for leaf in mapped:
            node = heap_base + leaf
            while True:
                marked.add(node)
                if node == 0:
                    break
                node = (node - 1) // 2
        if len(marked) <= threshold:
            good += 1
    return {
        "good_count": good,
        "total_assignments": assignments,
        "bad_count": assignments - good,
        "p_good": _fraction_payload(Fraction(good, assignments)),
        "evaluated": True,
    }


def p_good_exact_expression(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact finite p_good definition without claiming its huge numerator."""

    parameters = _retry_parameters(manifest)
    valid_bits = parameters["lambda_bits"] - parameters["grinding_bits"]
    raw_domain = 1 << parameters["lambda_bits"]
    valid_domain = 1 << valid_bits
    return {
        "p_good": UNKNOWN,
        "numerator": UNKNOWN,
        "denominator": str(raw_domain),
        "valid_raw_challenge_count": valid_domain,
        "valid_raw_domain": f"0 <= gamma3 < 2^{valid_bits}",
        "exact_expression": (
            f"sum_{{gamma3=0}}^{{2^{valid_bits}-1}} "
            f"I[opening_node_count(decode_all_chall_3(gamma3)) <= {parameters['opening_threshold']}] / 2^{parameters['lambda_bits']}"
        ),
        "decoder": "decode_all_chall_3",
        "group_widths_bits": list(parameters["widths"]),
        "opening_node_threshold": parameters["opening_threshold"],
        "opening_gate": "n_h - 2 * tau + 1 <= T_open",
        "evaluation_status": "EXACT_FINITE_EXPRESSION_NOT_NUMERICALLY_EVALUATED_RESOURCE_GUARD",
        "approximation_used": False,
    }


def _probability(value: Any, name: str) -> Fraction:
    if isinstance(value, Fraction):
        result = value
    elif _is_exact_int(value):
        result = Fraction(value, 1)
    elif isinstance(value, Mapping):
        result = _known_advantage(value, name)
    else:
        raise ContractError(f"{name}: exact_probability_required")
    if result < 0 or result > 1:
        raise ContractError(f"{name}: overflow")
    return result


def _stirling_second_kind(row_count: int, distinct_count: int) -> int:
    rows = _as_nonnegative_int(row_count, "row_count")
    distinct = _as_nonnegative_int(distinct_count, "distinct_count")
    if rows > STIRLING_EVALUATION_MAX_R:
        raise ContractError("stirling: resource_guard")
    if distinct > rows:
        return 0
    current = [0] * (rows + 1)
    current[0] = 1
    for row in range(1, rows + 1):
        next_row = [0] * (rows + 1)
        for value in range(1, row + 1):
            next_row[value] = current[value - 1] + value * current[value]
        current = next_row
    return current[distinct]


def _nonce_replacement_abort_exact(p_good: Fraction, retry_max: int, nonce_bits: int) -> Fraction:
    retries = _as_positive_int(retry_max, "retry_max")
    bits = _as_positive_int(nonce_bits, "nonce_bits")
    if retries > STIRLING_EVALUATION_MAX_R:
        raise ContractError("stirling: resource_guard")
    nonce_space = 1 << bits
    denominator = nonce_space**retries
    failure = 1 - p_good
    total = Fraction(0, 1)
    for distinct in range(retries + 1):
        stirling = _stirling_second_kind(retries, distinct)
        falling = math.prod(nonce_space - index for index in range(distinct))
        total += Fraction(stirling * falling, denominator) * failure**distinct
    return total


def retry_abort_ledger(
    manifest: Mapping[str, Any],
    Rmax: int | Sequence[int] | None = None,
    *,
    p_good: Fraction | int | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Describe independent-challenge and nonce-with-replacement retry outcomes exactly.

    The manifest deliberately leaves the production p_good numerator unevaluated.  Supplying an
    exact probability is supported for small structural tests only; large Stirling sums remain
    guarded and are never approximated.
    """

    _validate_manifest(manifest)
    parameters = _retry_parameters(manifest)
    spec = p_good_exact_expression(manifest)
    if Rmax is None:
        retry_values = list(_require_mapping(manifest["retry_abort"], "retry_abort")["retry_max_values"])
    elif _is_exact_int(Rmax):
        retry_values = [Rmax]
    elif isinstance(Rmax, Sequence) and not isinstance(Rmax, (str, bytes)):
        retry_values = list(Rmax)
    else:
        raise ContractError("Rmax: sequence_or_integer_required")
    retry_values = [_as_positive_int(value, "retry_max") for value in retry_values]
    exact_probability = None if p_good is None else _probability(p_good, "p_good")
    failure_expression = "(1-p_good)"
    entries: list[dict[str, Any]] = []
    for retries in retry_values:
        independent: dict[str, Any] = {
            "model": "INDEPENDENT_FRESH_CHALLENGE",
            "retry_max": retries,
            "p_abort_expression": f"(1-p_good)^{retries}",
            "expected_candidates_expression": (
                f"sum_{{r=0}}^{{{retries}-1}} (1-p_good)^r = (1-(1-p_good)^{retries})/p_good"
            ),
            "max_fs3_candidates": retries,
            "max_qrom_retry_queries": retries,
            "max_nonce_bits": retries * parameters["nonce_bits"],
            "p_abort": UNKNOWN,
            "expected_candidates": UNKNOWN,
        }
        nonce: dict[str, Any] = {
            "model": "FS3_NONCE_WITH_REPLACEMENT",
            "retry_max": retries,
            "nonce_space": f"2^{parameters['nonce_bits']}",
            "distinct_nonce_sum_expression": (
                f"sum_{{d=0}}^{retries} S({retries},d) * (2^{parameters['nonce_bits']})_d "
                f"/ 2^({parameters['nonce_bits']}*{retries}) * (1-p_good)^d"
            ),
            "p_abort": UNKNOWN,
            "p_abort_expression": (
                f"sum_{{d=0}}^{retries} S({retries},d) * (2^{parameters['nonce_bits']})_d "
                f"/ 2^({parameters['nonce_bits']}*{retries}) * (1-p_good)^d"
            ),
            "collision_upper_bound_expression": (
                f"min(1, (1-p_good)^{retries} + binom({retries},2)/2^{parameters['nonce_bits']})"
            ),
            "collision_upper_bound": UNKNOWN,
            "expected_candidates_expression": (
                f"sum_{{r=1}}^{retries} P_nonce_abort(r-1)"
            ),
            "expected_candidates": UNKNOWN,
            "max_fs3_candidates": retries,
            "max_qrom_retry_queries": retries,
            "max_nonce_bits": retries * parameters["nonce_bits"],
            "exact_evaluation_status": (
                "NOT_EVALUATED_RESOURCE_GUARD"
                if retries > STIRLING_EVALUATION_MAX_R
                else "EVALUATED_ONLY_WHEN_EXACT_P_GOOD_IS_SUPPLIED"
            ),
        }
        if exact_probability is not None:
            independent_abort = (1 - exact_probability) ** retries
            expected = (
                Fraction(retries, 1)
                if exact_probability == 0
                else (1 - independent_abort) / exact_probability
            )
            independent["p_abort"] = _fraction_payload(independent_abort)
            independent["expected_candidates"] = _fraction_payload(expected)
            if retries <= STIRLING_EVALUATION_MAX_R:
                nonce_abort = _nonce_replacement_abort_exact(
                    exact_probability, retries, parameters["nonce_bits"]
                )
                nonce_collision = min(
                    Fraction(1, 1),
                    independent_abort
                    + Fraction(math.comb(retries, 2), 1 << parameters["nonce_bits"]),
                )
                nonce_expected = sum(
                    _nonce_replacement_abort_exact(
                        exact_probability, attempt - 1, parameters["nonce_bits"]
                    )
                    if attempt > 1
                    else Fraction(1, 1)
                    for attempt in range(1, retries + 1)
                )
                nonce["p_abort"] = _fraction_payload(nonce_abort)
                nonce["collision_upper_bound"] = _fraction_payload(nonce_collision)
                nonce["expected_candidates"] = _fraction_payload(nonce_expected)
        entries.append({"independent_fresh_challenge": independent, "nonce_with_replacement": nonce})
    return {
        "review_status": "COMPLETENESS_MODEL_PENDING_EXACT_P_GOOD_NUMERATOR",
        "p_good": spec,
        "failure_expression": failure_expression,
        "retry_values": retry_values,
        "entries": entries,
        "qualified": False,
        "activation": False,
        "production_usable": False,
        "claim_effect": "retry_exhaustion_is_completeness_availability_not_soundness_qualification",
    }


def _ceil_log2(value: int) -> int:
    value = _as_positive_int(value, "value")
    return (value - 1).bit_length()


def proof_body_allocation(manifest: Mapping[str, Any], ell_bits: int, *, constraint_count: int) -> dict[str, Any]:
    """Calculate the proposed proof-body allocation with integer-only byte accounting."""

    _validate_manifest(manifest)
    suite = _suite(manifest)
    direct = _direct(manifest)
    actual = _actual_dimensions(manifest)
    ell = _as_positive_int(ell_bits, "ell_bits")
    constraints = _as_positive_int(constraint_count, "constraint_count")
    lam = _as_positive_int(suite["lambda_bits"], "lambda_bits")
    tau = _as_positive_int(suite["vole_tree_count"], "vole_tree_count")
    opening_budget = _as_positive_int(suite["opening_budget"], "opening_budget")
    masks = _as_positive_int(direct["mask_count"], "mask_count")
    rows = ell + masks * lam
    components = {
        "tree_corrections": _exact_div((tau - 1) * rows, 8, "tree_corrections"),
        "witness_correction": _exact_div(ell, 8, "witness_correction"),
        "field_elements": _exact_div((4 + 4 + 3) * lam, 8, "field_elements"),
        "commitment": _exact_div(2 * lam, 8, "commitment"),
        "iv": 16,
        "round_nonces": 3 * 64,
        "openings": _exact_div((opening_budget + 3 * tau) * lam, 8, "openings"),
    }
    components["field_elements_total"] = components["field_elements"] + components["commitment"]
    wire_components = {
        "m1": components["iv"] + components["commitment"] + components["tree_corrections"],
        "m2": components["witness_correction"] + _exact_div(8 * lam, 8, "m2_field_elements"),
        "m3": _exact_div(3 * lam, 8, "m3_field_elements"),
        "m4": components["openings"],
        "nonces": components["round_nonces"],
    }
    total = sum(
        components[name]
        for name in (
            "tree_corrections",
            "witness_correction",
            "field_elements",
            "commitment",
            "iv",
            "round_nonces",
            "openings",
        )
    )
    if total != sum(wire_components.values()):
        raise ContractError("proof_body: component_reconciliation_mismatch")
    wire = _require_mapping(manifest["wire_contract"], "wire_contract")
    actual_wire_matches = (
        ell == actual["ell_bits"]
        and constraints == actual["constraint_count"]
        and wire_components["m1"] == wire["m1_bytes"]
        and wire_components["m2"] == wire["m2_bytes"]
        and wire_components["m3"] == wire["m3_bytes"]
        and wire_components["m4"] == wire["m4_bytes"]
        and wire_components["nonces"] == wire["nonce_count"] * wire["nonce_bytes"]
    )
    return {
        "ell_bits": ell,
        "constraint_count": constraints,
        "ordinary_bit_vole_rows": rows,
        "ordinary_bit_vole_row_bytes": _exact_div(rows, 8, "ordinary_bit_vole_row_bytes"),
        "padding_zero_constraint_count": actual["padding_zero_constraint_count"]
        if ell == actual["ell_bits"] and constraints == actual["constraint_count"]
        else UNKNOWN,
        "dimension_source": (
            actual["dimension_source"]
            if ell == actual["ell_bits"] and constraints == actual["constraint_count"]
            else "explicit_input_not_kernel_export"
        ),
        "components_bytes": components,
        "wire_message_components": wire_components,
        "proof_body_bytes": total,
        "outer_frame_bytes": (
            wire["statement_bytes"] + wire["header_bytes"] + wire["nu_bytes"] + total
            if actual_wire_matches
            else UNKNOWN
        ),
        "wire_frame_reconciled": actual_wire_matches,
        "runtime_measured": False,
    }


def uncapped_hash_bounds(
    manifest: Mapping[str, Any], ell_bits: int | None = None, constraint_count: int | None = None
) -> dict[str, Any]:
    """Return the uncapped universal-hash and graph terms as exact reduced Fractions."""

    _validate_manifest(manifest)
    suite = _suite(manifest)
    direct = _direct(manifest)
    actual = _actual_dimensions(manifest)
    if ell_bits is None and constraint_count is None:
        ell_bits = actual["ell_bits"]
        constraint_count = actual["constraint_count"]
    elif ell_bits is None or constraint_count is None:
        raise ContractError("dimensions: ell_and_constraint_count_required")
    ell = _as_positive_int(ell_bits, "ell_bits")
    constraints = _as_positive_int(constraint_count, "constraint_count")
    lam = _as_positive_int(suite["lambda_bits"], "lambda_bits")
    grinding = _as_nonnegative_int(suite["grinding_bits"], "grinding_bits")
    degree = _as_positive_int(direct["degree"], "degree")
    short_bits = 64
    a = ell + degree - 2
    m_minus_one = constraints - 1
    epsilon_v = Fraction(1, _pow2(4 * lam)) * (1 + Fraction(a**5, _pow2(short_bits)))
    epsilon_z = Fraction(1, _pow2(lam)) * (1 + Fraction(m_minus_one**2, _pow2(short_bits)))
    response_space = _pow2(lam - grinding, "lambda_minus_grinding")
    e_kos = math.comb(response_space, 3) * epsilon_v
    e_poly = Fraction(degree, _pow2(lam))
    e_rbr = max(e_kos, epsilon_z, e_poly)
    return {
        "lambda_bits": lam,
        "short_challenge_bits": short_bits,
        "a": a,
        "m_minus_one": m_minus_one,
        "dimension_source": (
            actual["dimension_source"]
            if ell == actual["ell_bits"] and constraints == actual["constraint_count"]
            else "explicit_input_not_kernel_export"
        ),
        "response_space": response_space,
        "epsilon_v": _fraction_payload(epsilon_v),
        "epsilon_z": _fraction_payload(epsilon_z),
        "e_kos": _fraction_payload(e_kos),
        "e_hash": _fraction_payload(epsilon_z),
        "e_poly": _fraction_payload(e_poly),
        "e_rbr": _fraction_payload(e_rbr),
        "e_rbr_dominant_term": (
            "e_kos" if e_rbr == e_kos else "e_hash" if e_rbr == epsilon_z else "e_poly"
        ),
        "bound_status": "UNCAPPED_DERIVATION_CONDITIONAL_ON_RELATION_DIMENSIONS",
    }


def _geometry_checks(manifest: Mapping[str, Any], descriptor: Mapping[str, Any]) -> dict[str, Any]:
    suite = _suite(manifest)
    direct = _direct(manifest)
    actual = _actual_dimensions(manifest)
    dimensions = _require_mapping(manifest["dimensions"], "dimensions")
    envelope = _require_mapping(dimensions["admission_envelope"], "admission_envelope")
    checks: dict[str, bool] = {}
    ell_value = descriptor.get("ell_bits")
    m_value = descriptor.get("constraint_count")
    degree_value = descriptor.get("degree")
    checks["ell_integer"] = _is_exact_int(ell_value)
    checks["constraint_count_integer"] = _is_exact_int(m_value)
    checks["degree_integer"] = _is_exact_int(degree_value)
    if checks["ell_integer"]:
        checks["ell_positive"] = ell_value > 0
        checks["ell_within_envelope"] = ell_value <= envelope["max_ell_bits"]
        checks["ell_byte_aligned"] = ell_value % 8 == 0
    else:
        checks.update({"ell_positive": False, "ell_within_envelope": False, "ell_byte_aligned": False})
    if checks["constraint_count_integer"]:
        checks["constraint_count_positive"] = m_value > 0
        checks["constraint_count_within_envelope"] = m_value <= envelope["max_constraint_count"]
    else:
        checks.update({"constraint_count_positive": False, "constraint_count_within_envelope": False})
    checks["degree_is_three"] = (
        checks["degree_integer"] and degree_value == direct["degree"] == actual["degree"]
    )
    checks["dimension_source"] = descriptor.get("dimension_source") in {
        "exporter",
        actual["dimension_source"],
    }
    checks["exporter_confirmed"] = descriptor.get("exporter_confirmed") is True
    checks["ell_matches_actual_export"] = (
        checks["ell_integer"] and ell_value == actual["ell_bits"]
    )
    checks["constraint_count_matches_actual_export"] = (
        checks["constraint_count_integer"] and m_value == actual["constraint_count"]
    )
    checks["padding_zero_constraint_count"] = (
        _same_exact_int(
            descriptor.get("padding_zero_constraint_count"),
            actual["padding_zero_constraint_count"],
        )
    )
    checks["mask_count"] = _same_exact_int(descriptor.get("mask_count"), actual["mask_count"])
    checks["ordinary_bit_vole_rows"] = _same_exact_int(
        descriptor.get("ordinary_bit_vole_rows"), actual["ordinary_bit_vole_rows"]
    )
    checks["ordinary_bit_vole_row_bytes"] = _same_exact_int(
        descriptor.get("ordinary_bit_vole_row_bytes"), actual["ordinary_bit_vole_row_bytes"]
    )
    checks["bitness_constraints"] = descriptor.get("bitness_constraints") is True
    checks["padding_constraints"] = descriptor.get("padding_constraints") is True
    checks["field_domain"] = descriptor.get("field_domain") == _suite(manifest)["field"]["modulus"]
    checks["homogenization"] = descriptor.get("homogenization") is True
    checks["faest_256f"] = descriptor.get("suite") == "FAEST_256F"
    checks["non_em"] = descriptor.get("non_em") is True
    checks["tree_geometry"] = (
        _same_exact_int(descriptor.get("vole_tree_count"), suite["vole_tree_count"])
        and _same_exact_int(descriptor.get("total_leaves"), suite["total_leaves"])
    )
    return {"checks": checks, "passed": all(checks.values())}


def admission_ledger(manifest: Mapping[str, Any], descriptor: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a descriptor without ever producing a qualification/activation decision."""

    _validate_manifest(manifest)
    descriptor = _require_mapping(descriptor, "descriptor")
    geometry = _geometry_checks(manifest, descriptor)
    errors: list[str] = []
    checks = geometry["checks"]
    if not checks["ell_integer"] or not checks["constraint_count_integer"]:
        errors.append("underflow")
    elif not checks["ell_positive"] or not checks["constraint_count_positive"]:
        errors.append("underflow")
    if not checks["ell_within_envelope"] or not checks["constraint_count_within_envelope"]:
        errors.append("overflow")
    if (
        not checks["dimension_source"]
        or not checks["exporter_confirmed"]
        or not checks["ell_matches_actual_export"]
        or not checks["constraint_count_matches_actual_export"]
    ):
        errors.append("stale_estimate")
    if not checks["degree_is_three"] or not checks["faest_256f"] or not checks["non_em"]:
        errors.append("wrong_parameter")
    if not checks["tree_geometry"]:
        errors.append("wrong_tree_geometry")
    if not checks["ell_byte_aligned"]:
        errors.append("byte_alignment")
    if (
        not checks["padding_zero_constraint_count"]
        or not checks["mask_count"]
        or not checks["ordinary_bit_vole_rows"]
        or not checks["ordinary_bit_vole_row_bytes"]
    ):
        errors.append("actual_export_mismatch")
    if not checks["bitness_constraints"]:
        errors.append("missing_bitness_constraint")
    if not checks["padding_constraints"]:
        errors.append("missing_padding_constraint")
    if not checks["field_domain"]:
        errors.append("wrong_field_domain")
    if not checks["homogenization"]:
        errors.append("missing_homogenization")
    if descriptor.get("circuit_descriptor_owner") != "PQ":
        errors.append("wrong_descriptor_owner")
    if descriptor.get("wire_protocol_owner") != "E2E":
        errors.append("wrong_wire_owner")
    errors = _unique(errors)
    return {
        "descriptor_valid": not errors,
        "geometry_valid": geometry["passed"],
        "errors": errors,
        "qualified": False,
        "activation": False,
        "production_usable": False,
        "qualification_state": "UNQUALIFIED",
        "claim_effect": "descriptor_validity_is_not_qualification_or_activation",
    }


def _positive_fraction_component(value: Any, name: str) -> int:
    if _is_exact_int(value):
        if value < 0:
            raise ContractError(f"{name}: underflow")
        if value == 0:
            raise ContractError(f"{name}: zero_placeholder_forbidden")
        return value
    if isinstance(value, str):
        if value == "0":
            raise ContractError(f"{name}: zero_placeholder_forbidden")
        if not value or value[0] == "0" or any(char < "0" or char > "9" for char in value):
            raise ContractError(f"{name}: invalid_fraction_component")
        parsed = 0
        for char in value:
            parsed = parsed * 10 + (ord(char) - ord("0"))
        return parsed
    raise ContractError(f"{name}: invalid_fraction_component")


def _known_advantage(value: Any, name: str) -> Fraction:
    if value == UNKNOWN:
        raise ContractError(f"{name}: unknown_advantage")
    if isinstance(value, bool):
        raise ContractError(f"{name}: unknown_advantage")
    if isinstance(value, int):
        if value == 0:
            raise ContractError(f"{name}: zero_placeholder_forbidden")
        if value < 0:
            raise ContractError(f"{name}: underflow")
        result = Fraction(value, 1)
        if result > 1:
            raise ContractError(f"{name}: overflow")
        return result
    if isinstance(value, Mapping):
        try:
            raw_numerator = value["numerator"]
            raw_denominator = value["denominator"]
        except (KeyError, TypeError) as exc:
            raise ContractError(f"{name}: invalid_fraction") from exc
        numerator = _positive_fraction_component(raw_numerator, f"{name}.numerator")
        denominator = _positive_fraction_component(raw_denominator, f"{name}.denominator")
        result = Fraction(numerator, denominator)
        if result > 1:
            raise ContractError(f"{name}: overflow")
        return result
    raise ContractError(f"{name}: unknown_advantage")


def resource_ledger(manifest: Mapping[str, Any], resources: Mapping[str, Any]) -> dict[str, Any]:
    """Check declared budgets and advantages without filling omitted values."""

    _validate_manifest(manifest)
    resources = _require_mapping(resources, "resources")
    errors: list[str] = []
    integer_fields = (
        "Q",
        "A",
        "V",
        "R_retry",
        "N",
        "M",
        "P",
        "S",
        "E_U",
        "qhat",
        "retry_max",
        "lifetime_attempt_budget",
        "source_u_reuse_count",
        "source_u_reissued_parameter_count",
    )
    for name in integer_fields:
        value = resources.get(name, UNKNOWN)
        if value == UNKNOWN:
            errors.append(f"unknown_{name}")
        else:
            try:
                _as_nonnegative_int(value, name)
            except ContractError as exc:
                errors.append(str(exc))
    exact_counters: dict[str, int] = {}
    for name in ("A", "V", "R_retry"):
        value = resources.get(name, UNKNOWN)
        if value != UNKNOWN:
            try:
                exact_counters[name] = _as_nonnegative_int(value, name)
            except ContractError:
                pass
    derived_n: int | str = UNKNOWN
    if len(exact_counters) == 3:
        derived_n = sum(exact_counters.values())
        n_value = resources.get("N", UNKNOWN)
        if n_value != UNKNOWN:
            try:
                declared_n = _as_nonnegative_int(n_value, "N")
            except ContractError:
                pass
            else:
                if declared_n != derived_n:
                    errors.append("inconsistent_N")
    declared_m = resources.get("M", UNKNOWN)
    declared_p = resources.get("P", UNKNOWN)
    m_count: int | None = None
    p_count: int | None = None
    if declared_m != UNKNOWN:
        try:
            m_count = _as_nonnegative_int(declared_m, "M")
        except ContractError:
            pass
    if declared_p != UNKNOWN:
        try:
            p_count = _as_nonnegative_int(declared_p, "P")
        except ContractError:
            pass
    if m_count is not None and "A" in exact_counters and m_count > exact_counters["A"]:
        errors.append("M_exceeds_A")
    if p_count is not None and "A" in exact_counters and "R_retry" in exact_counters:
        if p_count > 2 * exact_counters["A"] + exact_counters["R_retry"]:
            errors.append("P_exceeds_2A_plus_R_retry")
    if resources.get("retry_max") != UNKNOWN and resources.get("retry_max") == 0:
        errors.append("retry_budget_exhausted")
    if (
        resources.get("lifetime_attempt_budget") != UNKNOWN
        and resources.get("lifetime_attempt_budget") == 0
    ):
        errors.append("lifetime_budget_exhausted")
    reuse_count = resources.get("source_u_reuse_count", UNKNOWN)
    if (
        reuse_count != UNKNOWN
        and isinstance(reuse_count, int)
        and not isinstance(reuse_count, bool)
        and reuse_count < 1
    ):
        errors.append("wrong_reuse_count")
    for name in (
        "Adv_Q1_AES256_node",
        "Adv_Q1_AES256_leaf",
        "Adv_Q1_AES256_stream",
        "Adv_SHAKE_snd",
        "Adv_source_auth",
        "Adv_U_generation",
        "Adv_SHAKE_priv",
        "epsilon_coins",
        "epsilon_AR",
        "epsilon_bitMH",
        "epsilon_source",
        "privacy_cap",
    ):
        if resources.get(name, UNKNOWN) == UNKNOWN:
            errors.append(f"unknown_{name}")
        else:
            try:
                _known_advantage(resources[name], name)
            except ContractError as exc:
                errors.append(str(exc))
    if len(exact_counters) == 3 and resources.get("N", UNKNOWN) == UNKNOWN:
        errors = [error for error in errors if error != "unknown_N"]
    errors = _unique(errors)
    runtime_errors: list[str] = []
    runtime_declaration_errors: list[str] = []
    runtime_integer_fields = ("T_star", "T_adversary", "q_hist", "Q_star", "L_FS")
    for name in runtime_integer_fields:
        value = resources.get(name, UNKNOWN)
        if value == UNKNOWN:
            error = f"unknown_{name}"
            runtime_errors.append(error)
            runtime_declaration_errors.append(error)
        else:
            try:
                _as_nonnegative_int(value, name)
            except ContractError as exc:
                error = str(exc)
                runtime_errors.append(error)
                runtime_declaration_errors.append(error)
    runtime_cost_fields = (
        "reprogramming_lookup_cost",
        "C_commit",
        "C_reconstruct",
        "C_source",
        "C_circuit",
        "C_VH_ZK",
        "C_transpose_pack",
        "C_opening",
        "C_SHAKE",
        "C_overlay",
    )
    for name in runtime_cost_fields:
        value = resources.get(name, UNKNOWN)
        if value == UNKNOWN:
            error = f"unknown_{name}"
            runtime_errors.append(error)
            runtime_declaration_errors.append(error)
        else:
            try:
                _as_nonnegative_int(value, name)
            except ContractError as exc:
                error = str(exc)
                runtime_errors.append(error)
                runtime_declaration_errors.append(error)

    known_runtime_counters: dict[str, int] = {}
    for name in ("Q", "A", "V", "R_retry"):
        value = resources.get(name, UNKNOWN)
        if value != UNKNOWN:
            try:
                known_runtime_counters[name] = _as_nonnegative_int(value, name)
            except ContractError:
                pass
    expected_q_hist: int | str = UNKNOWN
    if len(known_runtime_counters) == 4:
        expected_q_hist = (
            known_runtime_counters["Q"]
            + 38 * known_runtime_counters["A"]
            + 39 * known_runtime_counters["V"]
            + known_runtime_counters["R_retry"]
        )
        declared_q_hist = resources.get("q_hist", UNKNOWN)
        if declared_q_hist != UNKNOWN:
            try:
                declared_q_hist_value = _as_nonnegative_int(declared_q_hist, "q_hist")
            except ContractError:
                declared_q_hist_value = None
            if declared_q_hist_value is not None and declared_q_hist_value != expected_q_hist:
                runtime_errors.append("q_hist_inconsistent")
                runtime_declaration_errors.append("q_hist_inconsistent")
    runtime_declaration_errors = _unique(runtime_declaration_errors)
    runtime_errors.append("unverified_runtime_cost_model")
    runtime_errors = _unique(runtime_errors)
    runtime_fields_declared = not runtime_declaration_errors
    block_total: int | str = UNKNOWN
    if all(resources.get(name, UNKNOWN) != UNKNOWN for name in ("A", "V", "S")):
        try:
            block_total = (
                6406396 * _as_nonnegative_int(resources["A"], "A")
                + 6373495 * _as_nonnegative_int(resources["V"], "V")
                + 58 * _as_nonnegative_int(resources["S"], "S")
            )
        except ContractError:
            block_total = UNKNOWN
    if len(exact_counters) == 3:
        finite_status = "EXACT_A_V_R"
    elif resources.get("N", UNKNOWN) != UNKNOWN:
        finite_status = "LOOSE_N_ONLY"
    else:
        finite_status = "UNKNOWN_FINITE_COUNTERS"
    return {
        "resources_declared": not errors,
        "errors": errors,
        "finite_qrom_accounting": {
            "Q": resources.get("Q", UNKNOWN),
            "A": resources.get("A", UNKNOWN),
            "V": resources.get("V", UNKNOWN),
            "R_retry": resources.get("R_retry", UNKNOWN),
            "N": derived_n if len(exact_counters) == 3 else resources.get("N", UNKNOWN),
            "status": finite_status,
            "exact_q_formula": "Q + 37*A + 38*V + R_retry + 38",
            "loose_q_formula": "Q + 86*N + 86",
        },
        "block_costs": {
            "formula": "6406396*A + 6373495*V + 58*S",
            "proof_attempt_A": 6406396,
            "verification_V": 6373495,
            "source_commitment_S": 58,
            "total": block_total,
        },
        "counter_bounds": {
            "M": resources.get("M", UNKNOWN),
            "M_bound": "M <= A",
            "P": resources.get("P", UNKNOWN),
            "P_bound": "P <= 2*A + R_retry",
            "R_retry_semantics": "includes the first final FS3 candidate",
        },
        "runtime": {
            "fields_declared": runtime_fields_declared,
            "declaration_only": True,
            "declaration_errors": runtime_declaration_errors,
            "declaration_status": resources.get("runtime_declaration_status", UNKNOWN),
            "complete": False,
            "errors": runtime_errors,
            "T_star": resources.get("T_star", UNKNOWN),
            "q_hist": resources.get("q_hist", UNKNOWN),
            "expected_q_hist": expected_q_hist,
            "T_star_formula": "T* = T_adversary + C_commit*A + C_reconstruct*V + C_source*S + C_circuit + C_VH_ZK + C_transpose_pack + C_opening*R_retry + C_SHAKE(q_hist) + C_overlay(P,L_FS)",
            "q_hist_formula": "q_hist = Q + 38*A + 39*V + R_retry",
            "q_star_formula": "Q* <= 2*q_hist",
            "reprogramming_lookup_formula": "O(P*L_FS) per QRO call",
            "block_count_semantics": "derived AES block counts are source-counted bounds, not measured quantum work",
            "verification_status": "UNVERIFIED_RUNTIME_COST_MODEL",
        },
        "runtime_fields_declared": runtime_fields_declared,
        "runtime_declaration_only": True,
        "runtime_complete": False,
        "complete_declaration": False,
        "runtime_verification_reason": "unverified_runtime_cost_model",
        "qualified": False,
        "activation": False,
        "production_usable": False,
        "claim_effect": "resources_declared_does_not_imply_runtime_complete_or_security_or_privacy_qualification",
    }


def _qrom_uncapped_bound(q: int) -> Fraction:
    """Reviewed conditional false-accept expression before the probability cap."""

    q_value = _as_nonnegative_int(q, "q")
    return Fraction(1020 * q_value**3, _pow2(512)) + Fraction(360 * q_value**2, _pow2(256))


def _qrom_max_q(target_bits: int = 128) -> int:
    target = Fraction(1, _pow2(target_bits, "target_bits"))
    lower = 0
    upper = 1
    while _qrom_uncapped_bound(upper) <= target:
        lower = upper
        upper *= 2
    while upper - lower > 1:
        midpoint = (lower + upper) // 2
        if _qrom_uncapped_bound(midpoint) <= target:
            lower = midpoint
        else:
            upper = midpoint
    return lower


def _qrom_reference() -> dict[str, Any]:
    hypothetical_q = 1 << 64
    hypothetical_bound = _qrom_uncapped_bound(hypothetical_q)
    return {
        "target_bits": 128,
        "maximum_q_for_target": _qrom_max_q(128),
        "hypothetical_q_2^64": {
            "q": hypothetical_q,
            "uncapped_bound": _fraction_payload(hypothetical_bound),
            "negative_log2_uncapped_bound_bits": round(-math.log2(float(hypothetical_bound)), 12),
            "not_attack_probability": True,
        },
    }


def qrom_bound(
    manifest: Mapping[str, Any],
    Q: int,
    *positional: int,
    N: int | None = None,
    A: int | None = None,
    V: int | None = None,
    R: int | None = None,
    R_retry: int | None = None,
) -> dict[str, Any]:
    """Evaluate the reviewed conditional QROM bound with exact finite accounting.

    The exact form takes ``Q, A, V, R_retry`` (the Python keyword remains ``R`` for
    compatibility, or three positional counters after Q).
    The legacy ``Q, N`` form is retained only as an explicitly labelled loose upper bound.
    """

    _validate_manifest(manifest)
    if R is not None and R_retry is not None:
        raise ContractError("qrom: ambiguous_R_retry")
    if R_retry is not None:
        R = R_retry
    q_queries = _as_nonnegative_int(Q, "Q")
    if positional:
        if any(value is not None for value in (N, A, V, R)):
            raise ContractError("qrom: ambiguous_accounting")
        if len(positional) == 1:
            N = positional[0]
        elif len(positional) == 3:
            A, V, R = positional
        else:
            raise ContractError("qrom: expected_N_or_A_V_R")

    exact_requested = any(value is not None for value in (A, V, R))
    if exact_requested:
        if A is None or V is None or R is None:
            raise ContractError("qrom: A_V_R_required")
        a_count = _as_nonnegative_int(A, "A")
        v_count = _as_nonnegative_int(V, "V")
        r_count = _as_nonnegative_int(R, "R")
        derived_n = a_count + v_count + r_count
        if N is not None and _as_nonnegative_int(N, "N") != derived_n:
            raise ContractError("qrom: inconsistent_N")
        n_count: int | str = derived_n
        q_value = q_queries + 37 * a_count + 38 * v_count + r_count + 38
        accounting_model = "EXACT_A_V_R"
        finite_counters: dict[str, int | str] = {
            "Q": q_queries,
            "A": a_count,
            "V": v_count,
            "R_retry": r_count,
            "N": derived_n,
        }
    else:
        if N is None:
            raise ContractError("qrom: N_or_A_V_R_required")
        attempts = _as_nonnegative_int(N, "N")
        n_count = attempts
        q_value = q_queries + 86 * attempts + 86
        accounting_model = "LOOSE_N_ONLY"
        finite_counters = {
            "Q": q_queries,
            "A": UNKNOWN,
            "V": UNKNOWN,
            "R_retry": UNKNOWN,
            "N": attempts,
        }

    actual = _actual_dimensions(manifest)
    hash_terms = uncapped_hash_bounds(
        manifest, actual["ell_bits"], actual["constraint_count"]
    )
    uncapped = _qrom_uncapped_bound(q_value)
    bound = min(Fraction(1, 1), uncapped)
    suite = _suite(manifest)
    direct = _direct(manifest)
    return {
        "section": "4",
        "review_status": "PROPOSED_PENDING_QUANTUM_REVIEW",
        "accounting_model": accounting_model,
        "finite_counters": finite_counters,
        "Q": q_queries,
        "N": n_count,
        "R_retry": r_count if exact_requested else UNKNOWN,
        "q": q_value,
        "formula": "min(1, 1020*q^3/2^512 + 360*q^2/2^256)",
        "exact_q_formula": "Q + 37*A + 38*V + R_retry + 38",
        "loose_q_formula": "Q + 86*N + 86",
        "literal_oracle_call_upper_bound": "38*A + 39*V + R_retry",
        "local_witness_completion_overhead": 38,
        "bound_uncapped": _fraction_payload(uncapped),
        "bound": _fraction_payload(bound),
        "hash_terms": hash_terms,
        "ell_bits": actual["ell_bits"],
        "constraint_count": actual["constraint_count"],
        "dimension_source": actual["dimension_source"],
        "lambda_bits": _as_positive_int(suite["lambda_bits"], "lambda_bits"),
        "grinding_bits": _as_nonnegative_int(suite["grinding_bits"], "grinding_bits"),
        "degree": _as_positive_int(direct["degree"], "degree"),
        "reference": _qrom_reference(),
        "qualified": False,
        "qualification_effect": "none",
    }


def privacy_switch_bound(
    manifest: Mapping[str, Any], M: int | None = None, *, S: int | None = None
) -> dict[str, Any]:
    """Return explicit M/S privacy ledgers while keeping alpha and runtime inputs unknown."""

    _validate_manifest(manifest)
    suite = _suite(manifest)
    lam = _as_positive_int(suite["lambda_bits"], "lambda_bits")
    tau = _as_positive_int(suite["vole_tree_count"], "vole_tree_count")
    actual = _actual_dimensions(manifest)
    ell = actual["ell_bits"]
    t = _ceil_log2(_tree_total(manifest)) - 1
    beta = lam // 128
    n0 = 256
    rows = actual["ordinary_bit_vole_rows"]
    h_e = (rows + 127) // 128
    numerator = (1 + tau * t) * math.comb(2 * beta, 2) + tau * math.comb(4 * beta * n0, 2) + tau * math.comb(h_e, 2)
    privacy_spec = _require_mapping(
        _require_mapping(manifest["security_accounting"], "security_accounting")["privacy"],
        "security_accounting.privacy",
    )
    full_history = dict(_require_mapping(privacy_spec["full_history"], "security_accounting.privacy.full_history"))
    bit_hiding: dict[str, Any] = {
        "formula": privacy_spec["bit_hiding_formula"],
        "M_bound": privacy_spec["M_bound"],
        "M": UNKNOWN,
        "alpha_definition": privacy_spec["q1_aes256_definition"],
        "access_model": privacy_spec["q1_aes256_access_model"],
        "block_count_semantics": privacy_spec["block_count_semantics"],
        "q1_aes256_games": privacy_spec["q1_aes256_games"],
        "switching_numerator_per_M": numerator,
        "switching_bound_formula": "min(1, M * 85297284 / 2^128)",
        "delta_switch_uncapped": UNKNOWN,
        "delta_switch": UNKNOWN,
        "epsilon_bitMH": UNKNOWN,
    }
    source_hiding: dict[str, Any] = {
        "formula": privacy_spec["source_hiding_formula"],
        "S": UNKNOWN,
        "reproof_rule": privacy_spec["source_reproof_rule"],
        "source_games": privacy_spec["source_games"],
        "switching_numerator_per_S": 1253,
        "switching_bound_formula": "min(1, S * 1253 / 2^128)",
        "delta_switch_uncapped": UNKNOWN,
        "delta_switch": UNKNOWN,
        "epsilon_source": UNKNOWN,
    }
    result: dict[str, Any] = {
        "review_status": "COMPUTATIONAL_ASSUMPTION_PENDING_DECLARED_RESOURCES",
        "t": t,
        "beta": beta,
        "N0": n0,
        "h_E": h_e,
        "ell_bits": ell,
        "ordinary_bit_vole_rows": rows,
        "ordinary_bit_vole_row_bytes": actual["ordinary_bit_vole_row_bytes"],
        "dimension_source": actual["dimension_source"],
        "switching_numerator_per_M": numerator,
        "switching_bound_formula": "min(1, M * switching_numerator_per_M / 2^128)",
        "switching_bound_uncapped_formula": "M * 85297284 / 2^128",
        "delta_switch_uncapped": UNKNOWN,
        "delta_switch": UNKNOWN,
        "q1_aes256_games": privacy_spec["q1_aes256_games"],
        "source_games": privacy_spec["source_games"],
        "bit_hiding": bit_hiding,
        "source_hiding": source_hiding,
        "delta_source_switch_uncapped": UNKNOWN,
        "delta_source_switch": UNKNOWN,
        "privacy_composition_formula": privacy_spec["formula"],
        "adaptive_reprogramming_formula": privacy_spec["adaptive_reprogramming_formula"],
        "adaptive_reprogramming_event_bound": privacy_spec["adaptive_reprogramming_event_bound"],
        "full_history": full_history,
        "epsilon_coins": UNKNOWN,
        "epsilon_AR": UNKNOWN,
        "epsilon_bitMH": UNKNOWN,
        "epsilon_source": UNKNOWN,
        "Adv_SHAKE_priv": UNKNOWN,
        "privacy_cap": UNKNOWN,
        "proof_record": privacy_spec["proof_record"],
        "proof_status": privacy_spec["proof_status"],
        "qualified": False,
        "qualification_effect": "none",
    }
    if M is None:
        result["M"] = UNKNOWN
    else:
        instances = _as_nonnegative_int(M, "M")
        uncapped = Fraction(instances * numerator, _pow2(128))
        payload = _fraction_payload(min(Fraction(1, 1), uncapped))
        result["M"] = instances
        result["delta_switch_uncapped"] = _fraction_payload(uncapped)
        result["delta_switch"] = payload
        bit_hiding["M"] = instances
        bit_hiding["delta_switch_uncapped"] = _fraction_payload(uncapped)
        bit_hiding["delta_switch"] = payload
    if S is None:
        result["S"] = UNKNOWN
    else:
        source_count = _as_nonnegative_int(S, "S")
        source_uncapped = Fraction(source_count * 1253, _pow2(128))
        source_payload = _fraction_payload(min(Fraction(1, 1), source_uncapped))
        result["S"] = source_count
        result["delta_source_switch_uncapped"] = _fraction_payload(source_uncapped)
        result["delta_source_switch"] = source_payload
        source_hiding["S"] = source_count
        source_hiding["delta_switch_uncapped"] = _fraction_payload(source_uncapped)
        source_hiding["delta_switch"] = source_payload
    return result


def source_reissue_bound(manifest: Mapping[str, Any], reissued_parameter_count: int | None = None) -> dict[str, Any]:
    """Keep initial U, additional reissues, reuse, and total E_U accounting distinct."""

    _validate_manifest(manifest)
    per_parameter_upper_bound = Fraction(1, _pow2(257))
    result: dict[str, Any] = {
        "initial_U_issuance_count": 1,
        "initial_U_included_in_E_U": True,
        "additional_reissue_count": UNKNOWN,
        "single_reused_U_global_bad_event": {
            "relation": "<",
            **_fraction_payload(per_parameter_upper_bound),
        },
        "pair_bound_formula": "binom(2^256,2)/(2^768-1) < 2^-257",
        "reissued_parameter_count": UNKNOWN,
        "reissued_parameter_event_sum": UNKNOWN,
        "E_U_total_independent_issuances": UNKNOWN,
        "total_lifetime_event_sum": UNKNOWN,
        "qualified": False,
        "qualification_effect": "none",
    }
    if reissued_parameter_count is not None:
        count = _as_nonnegative_int(reissued_parameter_count, "reissued_parameter_count")
        additional_sum = Fraction(count, _pow2(257))
        additional_payload = _fraction_payload(additional_sum)
        additional_payload["relation"] = "=" if count == 0 else "<"
        total_count = 1 + count
        result["reissued_parameter_count"] = count
        result["additional_reissue_count"] = count
        result["reissued_parameter_event_sum"] = additional_payload
        result["E_U_total_independent_issuances"] = total_count
        result["total_lifetime_event_sum"] = {
            "relation": "<",
            **_fraction_payload(Fraction(total_count, _pow2(257))),
        }
    return result


def security_accounting(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Return separate statistical, ideal-QROM, concrete, and privacy ledgers."""

    _validate_manifest(manifest)
    hash_terms = uncapped_hash_bounds(manifest)
    privacy = privacy_switch_bound(manifest)
    return {
        "statistical_false_acceptance": {
            "formula": "E_U * 2^-257 + other_stat",
            "source_pair_bound": "binom(2^256,2)/(2^768-1) < 2^-257",
            "source_leaf_bad_bound": "33/2^256",
            "E_U": UNKNOWN,
            "other_stat": UNKNOWN,
            "internal_qrom_terms_not_double_counted": hash_terms,
        },
        "ideal_qrom_false_acceptance": {
            "formula": "B_snd(q) = min(1, 1020*q^3/2^512 + 360*q^2/2^256)",
            "q_formula": "Q + 37*A + 38*V + R_retry + 38",
            "literal_oracle_call_upper_bound": "38*A + 39*V + R_retry",
            "local_witness_completion_overhead": 38,
            "local_certificate_rows": 38,
            "delta_j_formula": "102*j/2^512 + 33/2^256 + 3/2^256 = 102*j/2^512 + 36/2^256",
            "local_certificate_proof_record": "LOCAL_CERTIFICATE_PROOF.md",
            "local_certificate_proof_status": "REVIEWED_CONDITIONAL_QUERY_ONLY",
            "bound": UNKNOWN,
            "status": "PROPOSED_PENDING_QUANTUM_REVIEW",
        },
        "concrete_false_acceptance": {
            "formula": "E_U * 2^-257 + B_snd(q) + Adv_SHAKE_snd + Adv_source_auth + Adv_U_generation",
            "Adv_SHAKE_snd": UNKNOWN,
            "Adv_source_auth": UNKNOWN,
            "Adv_U_generation": UNKNOWN,
            "status": "CONCRETE_PRIMITIVE_ADVANTAGES_UNDECLARED",
        },
        "privacy": privacy,
        "qualified": False,
        "activation": False,
        "production_usable": False,
    }


def counter_contract(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Expose durable counter definitions and reservation arithmetic without mutating state."""

    _validate_manifest(manifest)
    counters = _require_mapping(manifest["counter_ledger"], "counter_ledger")
    result = dict(counters)
    result["qualified"] = False
    result["activation"] = False
    result["production_usable"] = False
    result["claim_effect"] = "counter_contract_defines_accounting_only; it does not authorize production"
    return result


def wire_contract_report(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Return the immutable outer-wire facts and an independently recomputed frame total."""

    _validate_manifest(manifest)
    wire = _require_mapping(manifest["wire_contract"], "wire_contract")
    result = dict(wire)
    result["computed_frame_bytes"] = (
        wire["statement_bytes"]
        + wire["header_bytes"]
        + wire["nu_bytes"]
        + wire["nonce_count"] * wire["nonce_bytes"]
        + wire["m1_bytes"]
        + wire["m2_bytes"]
        + wire["m3_bytes"]
        + wire["m4_bytes"]
    )
    result["frame_reconciled"] = result["computed_frame_bytes"] == wire["frame_bytes"]
    result["claim_effect"] = "wire_facts_do_not_complete_or_approve_the_E2E_protocol"
    return result


def calculate_report(manifest: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Calculate the complete nonactivating report from the manifest."""

    loaded = load_manifest() if manifest is None else dict(manifest)
    _validate_manifest(loaded)
    estimated_ell, estimated_constraints = _estimated_dimensions(loaded)
    actual = _actual_dimensions(loaded)
    ell = actual["ell_bits"]
    constraints = actual["constraint_count"]
    suite = _suite(loaded)
    direct = _direct(loaded)
    rows = actual["ordinary_bit_vole_rows"]
    geometry_descriptor = {
        "ell_bits": ell,
        "constraint_count": constraints,
        "degree": direct["degree"],
        "dimension_source": actual["dimension_source"],
        "exporter_confirmed": actual["exporter_confirmed"],
        "bitness_constraints": True,
        "padding_constraints": True,
        "padding_zero_constraint_count": actual["padding_zero_constraint_count"],
        "field_domain": suite["field"]["modulus"],
        "homogenization": True,
        "suite": "FAEST_256F",
        "non_em": True,
        "vole_tree_count": suite["vole_tree_count"],
        "total_leaves": suite["total_leaves"],
        "mask_count": actual["mask_count"],
        "ordinary_bit_vole_rows": rows,
        "ordinary_bit_vole_row_bytes": actual["ordinary_bit_vole_row_bytes"],
        "circuit_descriptor_owner": "PQ",
        "wire_protocol_owner": "E2E",
    }
    resource = _require_mapping(loaded["resource_accounting"], "resource_accounting")
    return {
        "contract_version": loaded["manifest_version"],
        "candidate_id": loaded["candidate_id"],
        "qualified": False,
        "selected": False,
        "activation": False,
        "production_usable": False,
        "proof_suite_id": None,
        "review_status": loaded["review"]["bounds_section_4"],
        "provenance": loaded["provenance"],
        "faest_256f": {
            "lambda_bits": suite["lambda_bits"],
            "vole_tree_count": suite["vole_tree_count"],
            "grinding_bits": suite["grinding_bits"],
            "opening_budget": suite["opening_budget"],
            "leaf_groups": suite["leaf_groups"],
            "total_leaves": _tree_total(loaded),
            "non_em": suite["non_em"],
        },
        "dimensions": {
            "estimated_ell_bits": estimated_ell,
            "estimated_constraint_count": estimated_constraints,
            "actual_export": actual,
            "actual_ell_bits": ell,
            "actual_constraint_count": constraints,
            "padding_zero_constraint_count": actual["padding_zero_constraint_count"],
            "ordinary_bit_vole_rows": rows,
            "ordinary_bit_vole_row_bytes": actual["ordinary_bit_vole_row_bytes"],
            "geometry": admission_ledger(loaded, geometry_descriptor),
        },
        "mask_and_body": {
            "mask_count": direct["mask_count"],
            "correction_bytes": _exact_div((suite["vole_tree_count"] - 1) * direct["mask_count"] * suite["lambda_bits"], 8, "correction_bytes"),
            "proof_body": proof_body_allocation(loaded, ell, constraint_count=constraints),
        },
        "uncapped_hash_bounds": uncapped_hash_bounds(loaded, ell, constraints),
        "qrom": {
            "section": "4",
            "review_status": "PROPOSED_PENDING_QUANTUM_REVIEW",
            "accounting_model": "UNKNOWN_UNTIL_Q_A_V_R_DECLARED",
            "finite_counters": {
                "Q": resource.get("Q", UNKNOWN),
                "A": resource.get("A", UNKNOWN),
                "V": resource.get("V", UNKNOWN),
                "R_retry": resource.get("R_retry", UNKNOWN),
                "N": resource.get("N", UNKNOWN),
            },
            "q": UNKNOWN,
            "formula": "min(1, 1020*q^3/2^512 + 360*q^2/2^256)",
            "exact_q_formula": "Q + 37*A + 38*V + R_retry + 38",
            "loose_q_formula": "Q + 86*N + 86",
            "literal_oracle_call_upper_bound": "38*A + 39*V + R_retry",
            "local_witness_completion_overhead": 38,
            "bound_uncapped": UNKNOWN,
            "bound": UNKNOWN,
            "ell_bits": ell,
            "constraint_count": constraints,
            "dimension_source": actual["dimension_source"],
            "reference": _qrom_reference(),
            "qualified": False,
            "qualification_effect": "none",
        },
        "wire_contract": wire_contract_report(loaded),
        "challenge_widths_bits": loaded["transcript"]["challenge_widths_bits"],
        "retry_abort": retry_abort_ledger(loaded),
        "security_accounting": security_accounting(loaded),
        "privacy_switching": privacy_switch_bound(loaded),
        "source_accounting": source_reissue_bound(loaded),
        "counter_contract": counter_contract(loaded),
        "resource_status": resource_ledger(loaded, loaded["resource_accounting"]),
        "claim_boundary": {
            "component_only": True,
            "no_complete_kernel_or_refinement_claim": True,
            "no_deployment_or_activation_claim": True,
            "runtime_measured": False,
            "numeric_p_good_evaluated": False,
            "unknowns_fail_closed": True,
            "2^-69.7_example_is_not_attack_probability": True,
        },
    }


def _read_json(path: str | None) -> dict[str, Any]:
    if path is None:
        raise ContractError("descriptor: path_required")
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"descriptor: unreadable:{path}") from exc
    return dict(_require_mapping(value, "descriptor"))


def _main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument(
        "--mode",
        choices=("report", "admit", "qrom", "privacy", "source", "retry", "security", "counter", "wire"),
        default="report",
    )
    parser.add_argument("--descriptor")
    parser.add_argument("--Q", type=int)
    parser.add_argument("--N", type=int)
    parser.add_argument("--A", type=int)
    parser.add_argument("--V", type=int)
    parser.add_argument("--R", "--R-retry", dest="R", type=int)
    parser.add_argument("--M", type=int)
    parser.add_argument("--reissued-parameter-count", type=int)
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        if args.mode == "report":
            result = calculate_report(manifest)
        elif args.mode == "admit":
            result = admission_ledger(manifest, _read_json(args.descriptor))
        elif args.mode == "qrom":
            if args.Q is None:
                raise ContractError("qrom: Q_required")
            exact_counters = (args.A, args.V, args.R)
            if any(value is not None for value in exact_counters):
                if not all(value is not None for value in exact_counters):
                    raise ContractError("qrom: A_V_R_required")
                result = qrom_bound(
                    manifest, args.Q, N=args.N, A=args.A, V=args.V, R=args.R
                )
            else:
                if args.N is None:
                    raise ContractError("qrom: N_or_A_V_R_required")
                result = qrom_bound(manifest, args.Q, N=args.N)
        elif args.mode == "privacy":
            result = privacy_switch_bound(manifest, args.M)
        elif args.mode == "retry":
            result = retry_abort_ledger(manifest)
        elif args.mode == "security":
            result = security_accounting(manifest)
        elif args.mode == "counter":
            result = counter_contract(manifest)
        elif args.mode == "wire":
            result = wire_contract_report(manifest)
        else:
            result = source_reissue_bound(manifest, args.reissued_parameter_count)
    except ContractError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
