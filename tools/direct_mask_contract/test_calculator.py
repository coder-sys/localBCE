"""Focused executable checks for the nonactivating direct-mask contract."""

from __future__ import annotations

import copy
import unittest
from fractions import Fraction

from .calculator import (
    ContractError,
    _known_advantage,
    admission_ledger,
    bavc_leaf_index,
    bavc_opening_gate,
    bavc_opening_node_count,
    calculate_report,
    counter_contract,
    decode_all_chall_3,
    exact_good_count_enumeration,
    load_manifest,
    p_good_exact_expression,
    privacy_switch_bound,
    proof_body_allocation,
    qrom_bound,
    retry_abort_ledger,
    resource_ledger,
    security_accounting,
    source_reissue_bound,
    uncapped_hash_bounds,
    wire_contract_report,
)


def _manifest() -> dict:
    return load_manifest()


def _descriptor(manifest: dict | None = None) -> dict:
    manifest = _manifest() if manifest is None else manifest
    suite = manifest["faest_256f"]
    actual = manifest["dimensions"]["actual_export"]
    return {
        "ell_bits": actual["ell_bits"],
        "constraint_count": actual["constraint_count"],
        "degree": actual["degree"],
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
        "ordinary_bit_vole_rows": actual["ordinary_bit_vole_rows"],
        "ordinary_bit_vole_row_bytes": actual["ordinary_bit_vole_row_bytes"],
        "circuit_descriptor_owner": "PQ",
        "wire_protocol_owner": "E2E",
    }


class DirectMaskContractTests(unittest.TestCase):
    def test_report_exact_ledgers_and_nonactivation(self) -> None:
        report = calculate_report(_manifest())
        self.assertEqual(report["dimensions"]["actual_ell_bits"], 125048)
        self.assertEqual(report["dimensions"]["actual_constraint_count"], 172232)
        self.assertEqual(
            report["dimensions"]["actual_export"]["commit"],
            "124cd6a7107bbc20ec1e4c7e6cf2483dd5042c67",
        )
        self.assertEqual(
            report["dimensions"]["actual_export"]["algebra_status"],
            "APPROVED_READONLY_COMPONENT_GATE",
        )
        self.assertEqual(report["dimensions"]["padding_zero_constraint_count"], 0)
        self.assertEqual(report["dimensions"]["ordinary_bit_vole_rows"], 126584)
        self.assertEqual(report["dimensions"]["ordinary_bit_vole_row_bytes"], 15823)
        self.assertEqual(report["mask_and_body"]["correction_bytes"], 6144)
        body = report["mask_and_body"]["proof_body"]
        self.assertEqual(body["proof_body_bytes"], 533087)
        self.assertEqual(body["components_bytes"]["tree_corrections"], 506336)
        self.assertEqual(body["components_bytes"]["witness_correction"], 15631)
        self.assertEqual(body["components_bytes"]["field_elements"], 352)
        self.assertEqual(body["components_bytes"]["field_elements_total"], 416)
        self.assertEqual(body["components_bytes"]["openings"], 10496)
        self.assertEqual(body["wire_message_components"]["m1"], 506416)
        self.assertEqual(body["wire_message_components"]["m2"], 15887)
        self.assertEqual(body["wire_message_components"]["m3"], 96)
        self.assertEqual(body["wire_message_components"]["m4"], 10496)
        self.assertTrue(body["wire_frame_reconciled"])
        self.assertEqual(body["outer_frame_bytes"], 534370)
        hashes = report["uncapped_hash_bounds"]
        self.assertEqual(hashes["a"], 125049)
        self.assertEqual(hashes["m_minus_one"], 172231)
        self.assertEqual(hashes["dimension_source"], "verified_readonly_kernel_gate")
        self.assertEqual(hashes["e_rbr"], {"numerator": "3", "denominator": str(2**256)})
        privacy = report["privacy_switching"]
        self.assertEqual(privacy["t"], 12)
        self.assertEqual(privacy["h_E"], 989)
        self.assertEqual(privacy["switching_numerator_per_M"], 85297284)
        self.assertEqual(report["qrom"]["finite_counters"]["Q"], "UNKNOWN")
        self.assertEqual(report["qrom"]["exact_q_formula"], "Q + 37*A + 38*V + R_retry + 38")
        self.assertEqual(report["qrom"]["reference"]["maximum_q_for_target"], 972228778118919314)
        self.assertEqual(report["wire_contract"]["frame_bytes"], 534370)
        self.assertTrue(report["wire_contract"]["frame_reconciled"])
        self.assertEqual(report["retry_abort"]["p_good"]["p_good"], "UNKNOWN")
        self.assertEqual(len(report["retry_abort"]["entries"]), 3)
        self.assertEqual(
            report["security_accounting"]["statistical_false_acceptance"]["formula"],
            "E_U * 2^-257 + other_stat",
        )
        self.assertFalse(report["qualified"])
        self.assertFalse(report["selected"])
        self.assertFalse(report["activation"])
        self.assertFalse(report["production_usable"])

    def test_exact_helpers(self) -> None:
        manifest = _manifest()
        body = proof_body_allocation(manifest, 125048, constraint_count=172232)
        self.assertEqual(body["ordinary_bit_vole_rows"], 126584)
        self.assertEqual(body["ordinary_bit_vole_row_bytes"], 15823)
        self.assertEqual(body["dimension_source"], "verified_readonly_kernel_gate")
        self.assertEqual(uncapped_hash_bounds(manifest)["e_rbr_dominant_term"], "e_poly")
        loose = qrom_bound(manifest, 5, 7)
        self.assertEqual(loose["q"], 693)
        self.assertEqual(loose["accounting_model"], "LOOSE_N_ONLY")
        exact = qrom_bound(manifest, 5, A=7, V=8, R=9)
        self.assertEqual(exact["q"], 615)
        self.assertEqual(exact["N"], 24)
        self.assertEqual(exact["accounting_model"], "EXACT_A_V_R")
        self.assertEqual(exact["finite_counters"]["R_retry"], 9)
        self.assertEqual(qrom_bound(manifest, 5, A=7, V=8, R_retry=9)["q"], 615)
        self.assertEqual(exact["reference"]["maximum_q_for_target"], 972228778118919314)
        self.assertEqual(privacy_switch_bound(manifest, 1)["delta_switch"], {
            "numerator": "21324321",
            "denominator": str(2**126),
        })
        self.assertEqual(source_reissue_bound(manifest, 2)["reissued_parameter_event_sum"], {
            "relation": "<",
            "numerator": "1",
            "denominator": str(2**256),
        })
        zero = source_reissue_bound(manifest, 0)
        self.assertEqual(zero["initial_U_issuance_count"], 1)
        self.assertTrue(zero["initial_U_included_in_E_U"])
        self.assertEqual(zero["additional_reissue_count"], 0)
        self.assertEqual(zero["E_U_total_independent_issuances"], 1)
        self.assertEqual(zero["reissued_parameter_event_sum"], {
            "relation": "=",
            "numerator": "0",
            "denominator": "1",
        })
        one = source_reissue_bound(manifest, 1)
        self.assertEqual(one["E_U_total_independent_issuances"], 2)
        self.assertEqual(one["reissued_parameter_event_sum"], {
            "relation": "<",
            "numerator": "1",
            "denominator": str(2**257),
        })

    def test_wire_counter_and_security_ledgers_are_separate(self) -> None:
        manifest = _manifest()
        wire = wire_contract_report(manifest)
        self.assertEqual(wire["computed_frame_bytes"], 534370)
        self.assertTrue(wire["frame_reconciled"])
        self.assertEqual(wire["m1_bytes"], 506416)
        self.assertEqual(wire["m2_bytes"], 15887)
        self.assertEqual(wire["m3_bytes"], 96)
        self.assertEqual(wire["m4_bytes"], 10496)

        counters = counter_contract(manifest)
        reservation = counters["acceptance_reservations"]
        self.assertEqual(reservation["per_current_batch"], 101)
        self.assertEqual(reservation["global_cap"], 2**32)
        self.assertEqual(reservation["full_batches_at_current_charge"], 42524428)
        self.assertEqual(reservation["remaining_reservations_after_full_batches"], 68)
        self.assertEqual(counters["definitions"]["fs3_candidates"]["symbol"], "R_retry")
        self.assertEqual(counters["definitions"]["source_u_parameter_issuances"]["symbol"], "E_U")
        self.assertEqual(counters["definitions"]["commitment_instances"]["symbol"], "M")
        self.assertIn(
            "increments none of A, M, or S",
            counters["definitions"]["source_commitments"]["increment"],
        )
        self.assertIn(
            "verification of retransmitted bytes still increments V",
            counters["definitions"]["exact_retransmits"]["increment"],
        )

        security = security_accounting(manifest)
        self.assertEqual(
            security["statistical_false_acceptance"]["formula"],
            "E_U * 2^-257 + other_stat",
        )
        self.assertEqual(
            security["concrete_false_acceptance"]["formula"],
            "E_U * 2^-257 + B_snd(q) + Adv_SHAKE_snd + Adv_source_auth + Adv_U_generation",
        )
        self.assertEqual(security["ideal_qrom_false_acceptance"]["local_certificate_rows"], 38)
        self.assertEqual(
            security["ideal_qrom_false_acceptance"]["delta_j_formula"],
            "102*j/2^512 + 33/2^256 + 3/2^256 = 102*j/2^512 + 36/2^256",
        )
        privacy = security["privacy"]
        self.assertEqual(privacy["q1_aes256_games"]["node"], {"block_inputs": 4, "multiplicity": 397})
        self.assertEqual(privacy["q1_aes256_games"]["leaf"], {"block_inputs": 2048, "multiplicity": 33})
        self.assertEqual(privacy["q1_aes256_games"]["stream"], {"block_inputs": 989, "multiplicity": 33})
        self.assertEqual(privacy["source_games"]["G0_block_inputs"], 8)
        self.assertEqual(privacy["source_games"]["G1_block_inputs"], 50)
        self.assertEqual(privacy["source_games"]["finite_switching_term"], "1253/2^128")
        self.assertIn("M * (397*alpha_4(T*,Q*)", privacy["bit_hiding"]["formula"])
        self.assertIn("S * (alpha_8(T*,Q*)", privacy["source_hiding"]["formula"])
        for value in (
            privacy["delta_switch_uncapped"],
            privacy["delta_switch"],
            privacy["delta_source_switch_uncapped"],
            privacy["delta_source_switch"],
            privacy["bit_hiding"]["delta_switch_uncapped"],
            privacy["bit_hiding"]["delta_switch"],
            privacy["source_hiding"]["delta_switch_uncapped"],
            privacy["source_hiding"]["delta_switch"],
        ):
            self.assertEqual(value, "UNKNOWN")
        expected_reproof_rule = (
            "a fresh proof invocation increments A; a fresh BAVC commitment instance increments M; "
            "an unchanged source assertion does not increment S; an exact byte-identical retransmission "
            "itself increments none of A, M, or S, but any cryptographic operation it triggers is "
            "charged separately, including V when it is verified"
        )
        self.assertEqual(privacy["source_hiding"]["reproof_rule"], expected_reproof_rule)
        self.assertEqual(privacy["full_history"]["q_hist_formula"], "q_hist = Q + 38*A + 39*V + R_retry")
        self.assertEqual(privacy["full_history"]["q_star_formula"], "Q* <= 2*q_hist")
        self.assertEqual(privacy["full_history"]["runtime_declaration_status"], "INCOMPLETE_MISSING_T_STAR_OR_ROUTINE_COSTS")

    def test_exact_challenge_decoder_and_bavc_frontier(self) -> None:
        manifest = _manifest()
        decoded = decode_all_chall_3(manifest, 0)
        self.assertTrue(decoded["valid_grinding"])
        self.assertEqual(decoded["decoded_bits"], 248)
        self.assertEqual(decoded["choices"], [0] * 33)
        self.assertEqual(decoded["leaf_indices"], list(range(33)))
        self.assertEqual(bavc_leaf_index(manifest, 0, 127), 4191)
        self.assertEqual(bavc_leaf_index(manifest, 0, 128), 4224)
        self.assertEqual(bavc_leaf_index(manifest, 16, 255), 6399)
        self.assertEqual(bavc_leaf_index(manifest, 32, 127), 4223)
        self.assertTrue(bavc_opening_gate(manifest, 294))
        self.assertFalse(bavc_opening_gate(manifest, 295))
        self.assertGreater(bavc_opening_node_count(manifest, decoded["leaf_indices"]), 33)

        invalid = decode_all_chall_3(manifest, 1 << 248)
        self.assertFalse(invalid["valid_grinding"])
        self.assertEqual(invalid["high_grinding_bits"], 1)
        with self.assertRaisesRegex(ContractError, "overflow"):
            decode_all_chall_3(manifest, 1 << 256)
        with self.assertRaisesRegex(ContractError, "underflow"):
            decode_all_chall_3(manifest, -1)

    def test_small_exact_frontier_and_resource_guard(self) -> None:
        result = exact_good_count_enumeration(
            [1, 1],
            lambda group, choice: group * 2 + choice,
            5,
            leaf_count=4,
        )
        self.assertEqual(result["good_count"], 4)
        self.assertEqual(result["total_assignments"], 4)
        self.assertEqual(result["p_good"], {"numerator": "1", "denominator": "1"})
        mixed = exact_good_count_enumeration(
            [1, 1],
            lambda group, choice: group + 2 * choice,
            4,
            leaf_count=4,
        )
        self.assertEqual(mixed["good_count"], 2)
        self.assertEqual(mixed["bad_count"], 2)
        self.assertEqual(mixed["p_good"], {"numerator": "1", "denominator": "2"})
        with self.assertRaisesRegex(ContractError, "resource_guard"):
            exact_good_count_enumeration([10**100], lambda _group, choice: choice, 1, leaf_count=2)

    def test_retry_abort_models_preserve_unknown_large_probability(self) -> None:
        manifest = _manifest()
        exact = p_good_exact_expression(manifest)
        self.assertEqual(exact["p_good"], "UNKNOWN")
        self.assertEqual(exact["numerator"], "UNKNOWN")
        self.assertEqual(exact["denominator"], str(2**256))
        self.assertEqual(exact["valid_raw_challenge_count"], 2**248)
        self.assertFalse(exact["approximation_used"])
        self.assertEqual(exact["exact_expression"], manifest["retry_abort"]["p_good_expression"])

        ledger = retry_abort_ledger(manifest)
        self.assertEqual(ledger["retry_values"], [4096, 8192, 16384])
        for entry, retries in zip(ledger["entries"], ledger["retry_values"]):
            independent = entry["independent_fresh_challenge"]
            nonce = entry["nonce_with_replacement"]
            self.assertEqual(independent["p_abort"], "UNKNOWN")
            self.assertEqual(independent["max_fs3_candidates"], retries)
            self.assertEqual(independent["max_qrom_retry_queries"], retries)
            self.assertEqual(independent["max_nonce_bits"], retries * 512)
            self.assertEqual(nonce["p_abort"], "UNKNOWN")
            self.assertIn("S(", nonce["p_abort_expression"])
            self.assertEqual(nonce["exact_evaluation_status"], "NOT_EVALUATED_RESOURCE_GUARD")

        small = retry_abort_ledger(manifest, 4, p_good=Fraction(1, 2))
        small_independent = small["entries"][0]["independent_fresh_challenge"]
        self.assertEqual(small_independent["p_abort"], {"numerator": "1", "denominator": "16"})
        self.assertEqual(small_independent["expected_candidates"], {"numerator": "15", "denominator": "8"})
        small_nonce = small["entries"][0]["nonce_with_replacement"]
        self.assertNotEqual(small_nonce["p_abort"], "UNKNOWN")
        self.assertNotEqual(small_nonce["collision_upper_bound"], "UNKNOWN")

    def test_exporter_confirmed_descriptor_is_valid_but_not_qualified(self) -> None:
        result = admission_ledger(_manifest(), _descriptor())
        self.assertTrue(result["descriptor_valid"])
        self.assertTrue(result["geometry_valid"])
        self.assertEqual(result["errors"], [])
        self.assertFalse(result["qualified"])
        self.assertFalse(result["activation"])
        self.assertFalse(result["production_usable"])

        exporter_descriptor = _descriptor()
        exporter_descriptor["dimension_source"] = "exporter"
        exporter_result = admission_ledger(_manifest(), exporter_descriptor)
        self.assertTrue(exporter_result["descriptor_valid"])

    def test_actual_export_is_required_and_stale_estimates_fail_closed(self) -> None:
        manifest = _manifest()
        manifest["dimensions"]["actual_export"] = "UNKNOWN"
        with self.assertRaisesRegex(ContractError, "missing_actual_export"):
            calculate_report(manifest)

        descriptor = _descriptor()
        estimate = _manifest()["dimensions"]["estimated"]
        descriptor.update(
            ell_bits=estimate["ell_bits"],
            constraint_count=estimate["constraint_count"],
            dimension_source="estimate",
            exporter_confirmed=False,
            padding_zero_constraint_count=estimate["padding_zero_constraint_count"],
            ordinary_bit_vole_rows=estimate["ell_bits"] + 6 * 256,
            ordinary_bit_vole_row_bytes=(estimate["ell_bits"] + 6 * 256) // 8,
        )
        result = admission_ledger(_manifest(), descriptor)
        self.assertFalse(result["descriptor_valid"])
        self.assertIn("stale_estimate", result["errors"])
        self.assertIn("actual_export_mismatch", result["errors"])

    def test_required_descriptor_negative_cases_fail_closed(self) -> None:
        cases = {
            "underflow": lambda d: d.update(ell_bits=0),
            "overflow": lambda d: d.update(constraint_count=262145),
            "stale_estimate": lambda d: d.update(dimension_source="estimate", exporter_confirmed=False),
            "wrong_parameter": lambda d: d.update(degree=2),
            "missing_bitness_constraint": lambda d: d.update(bitness_constraints=False),
            "missing_padding_constraint": lambda d: d.update(padding_constraints=False),
            "wrong_field_domain": lambda d: d.update(field_domain="wrong-field"),
            "missing_homogenization": lambda d: d.update(homogenization=False),
            "wrong_tree_geometry": lambda d: d.update(total_leaves=6399),
            "actual_export_mismatch": lambda d: d.update(ordinary_bit_vole_row_bytes=15824),
        }
        for expected_error, mutate in cases.items():
            with self.subTest(expected_error=expected_error):
                descriptor = _descriptor()
                mutate(descriptor)
                result = admission_ledger(_manifest(), descriptor)
                self.assertFalse(result["descriptor_valid"])
                self.assertIn(expected_error, result["errors"])
                self.assertFalse(result["qualified"])
                self.assertFalse(result["activation"])

    def test_manifest_parameter_and_mode_negatives(self) -> None:
        manifest = _manifest()
        manifest["faest_256f"]["non_em"] = False
        with self.assertRaisesRegex(ContractError, "non_em_required"):
            calculate_report(manifest)

        manifest = _manifest()
        manifest["faest_256f"]["lambda_bits"] = 128
        with self.assertRaisesRegex(ContractError, "wrong_parameter"):
            calculate_report(manifest)

        manifest = _manifest()
        manifest["faest_256f"]["leaf_groups"] = [
            {"tree_count": 1, "leaves_per_tree": 4352},
            {"tree_count": 16, "leaves_per_tree": 128},
        ]
        with self.assertRaisesRegex(ContractError, "wrong_tree_geometry"):
            calculate_report(manifest)

        manifest = _manifest()
        manifest["transcript"]["challenge_widths_bits"] = [2112, 831, 256]
        with self.assertRaisesRegex(ContractError, "wrong_parameter"):
            calculate_report(manifest)

        manifest = _manifest()
        manifest["faest_256f"]["field"]["byte_embedding"] = "wrong-map"
        with self.assertRaisesRegex(ContractError, "wrong_field_domain"):
            calculate_report(manifest)

        manifest = _manifest()
        manifest["dimensions"]["estimated"]["source"] = "estimate"
        with self.assertRaisesRegex(ContractError, "stale_estimate_label_required"):
            calculate_report(manifest)

        manifest = _manifest()
        manifest["wire_contract"]["frame_bytes"] = 534371
        with self.assertRaisesRegex(ContractError, "identity_mismatch"):
            calculate_report(manifest)

        manifest = _manifest()
        manifest["retry_abort"]["retry_max_values"] = [4096.0, 8192, 16384]
        with self.assertRaisesRegex(ContractError, "wrong_parameter"):
            calculate_report(manifest)

        manifest = _manifest()
        manifest["security_accounting"]["privacy"]["q1_aes256_games"]["stream"]["block_inputs"] = 989.0
        with self.assertRaisesRegex(ContractError, "identity_mismatch"):
            calculate_report(manifest)

        with self.assertRaisesRegex(ContractError, "underflow"):
            qrom_bound(_manifest(), -1, 0)
        with self.assertRaisesRegex(ContractError, "underflow"):
            privacy_switch_bound(_manifest(), -1)
        with self.assertRaisesRegex(ContractError, "underflow"):
            source_reissue_bound(_manifest(), -1)
        with self.assertRaisesRegex(ContractError, "non_integral_allocation"):
            proof_body_allocation(_manifest(), 117329, constraint_count=156788)
        with self.assertRaisesRegex(ContractError, "A_V_R_required"):
            qrom_bound(_manifest(), 1, A=1, V=1)
        with self.assertRaisesRegex(ContractError, "inconsistent_N"):
            qrom_bound(_manifest(), 1, N=99, A=1, V=1, R=1)

    def test_resource_ledger_requires_declared_advantages_and_budgets(self) -> None:
        manifest = _manifest()
        unknown = resource_ledger(manifest, manifest["resource_accounting"])
        self.assertFalse(unknown["resources_declared"])
        self.assertIn("unknown_Q", unknown["errors"])
        self.assertIn("unknown_A", unknown["errors"])
        self.assertIn("unknown_V", unknown["errors"])
        self.assertIn("unknown_R_retry", unknown["errors"])
        self.assertIn("unknown_Adv_Q1_AES256_node", unknown["errors"])

        resources = copy.deepcopy(manifest["resource_accounting"])
        for name in (
            "Q", "A", "V", "R_retry", "M", "P", "S", "E_U", "qhat",
            "retry_max", "lifetime_attempt_budget",
        ):
            resources[name] = 1
        resources["N"] = 3
        resources["source_u_reuse_count"] = 1
        resources["source_u_reissued_parameter_count"] = 0
        for name in (
            "Adv_Q1_AES256_node", "Adv_Q1_AES256_leaf", "Adv_Q1_AES256_stream",
            "Adv_SHAKE_snd", "Adv_source_auth", "Adv_U_generation", "Adv_SHAKE_priv",
            "epsilon_coins", "epsilon_AR", "epsilon_bitMH", "epsilon_source", "privacy_cap",
        ):
            resources[name] = {"numerator": 1, "denominator": 2}
        declared = resource_ledger(manifest, resources)
        self.assertTrue(declared["resources_declared"])
        self.assertFalse(declared["runtime_complete"])
        self.assertFalse(declared["complete_declaration"])
        self.assertIn("unknown_T_star", declared["runtime"]["errors"])
        self.assertEqual(declared["errors"], [])
        self.assertEqual(declared["finite_qrom_accounting"]["N"], 3)
        self.assertEqual(declared["finite_qrom_accounting"]["status"], "EXACT_A_V_R")
        self.assertEqual(declared["block_costs"]["proof_attempt_A"], 6406396)
        self.assertEqual(declared["block_costs"]["verification_V"], 6373495)
        self.assertEqual(declared["block_costs"]["source_commitment_S"], 58)
        self.assertEqual(declared["block_costs"]["total"], 12779949)

        fully_declared = copy.deepcopy(resources)
        for name in (
            "T_star", "T_adversary", "Q_star", "L_FS",
            "reprogramming_lookup_cost", "C_commit", "C_reconstruct", "C_source",
            "C_circuit", "C_VH_ZK", "C_transpose_pack", "C_opening", "C_SHAKE", "C_overlay",
        ):
            fully_declared[name] = 0
        fully_declared["q_hist"] = 79
        fully_declared["runtime_declaration_status"] = "COMPLETE_DECLARED_T_STAR_AND_ROUTINE_COSTS"
        complete_shape = resource_ledger(manifest, fully_declared)
        self.assertTrue(complete_shape["resources_declared"])
        self.assertTrue(complete_shape["runtime_fields_declared"])
        self.assertTrue(complete_shape["runtime"]["fields_declared"])
        self.assertTrue(complete_shape["runtime"]["declaration_only"])
        self.assertFalse(complete_shape["runtime_complete"])
        self.assertFalse(complete_shape["runtime"]["complete"])
        self.assertFalse(complete_shape["complete_declaration"])
        self.assertEqual(
            complete_shape["runtime_verification_reason"],
            "unverified_runtime_cost_model",
        )
        self.assertIn("unverified_runtime_cost_model", complete_shape["runtime"]["errors"])

        contradictory = copy.deepcopy(fully_declared)
        contradictory["q_hist"] = 0
        contradiction_result = resource_ledger(manifest, contradictory)
        self.assertFalse(contradiction_result["runtime_fields_declared"])
        self.assertIn("q_hist_inconsistent", contradiction_result["runtime"]["errors"])
        self.assertEqual(contradiction_result["runtime"]["q_hist"], 0)

        unknown_q_hist = copy.deepcopy(fully_declared)
        unknown_q_hist["q_hist"] = "UNKNOWN"
        unknown_q_hist_result = resource_ledger(manifest, unknown_q_hist)
        self.assertFalse(unknown_q_hist_result["runtime_fields_declared"])
        self.assertEqual(unknown_q_hist_result["runtime"]["q_hist"], "UNKNOWN")
        self.assertEqual(unknown_q_hist_result["runtime"]["expected_q_hist"], 79)
        self.assertNotIn("q_hist_inconsistent", unknown_q_hist_result["runtime"]["errors"])

        resources_without_derived_n = copy.deepcopy(resources)
        resources_without_derived_n["N"] = "UNKNOWN"
        derived = resource_ledger(manifest, resources_without_derived_n)
        self.assertTrue(derived["resources_declared"])
        self.assertNotIn("unknown_N", derived["errors"])
        self.assertEqual(derived["finite_qrom_accounting"]["N"], 3)

        resources["retry_max"] = 0
        resources["lifetime_attempt_budget"] = 0
        resources["source_u_reuse_count"] = 0
        exhausted = resource_ledger(manifest, resources)
        self.assertIn("retry_budget_exhausted", exhausted["errors"])
        self.assertIn("lifetime_budget_exhausted", exhausted["errors"])
        self.assertIn("wrong_reuse_count", exhausted["errors"])

        resources["retry_max"] = -1
        underflow = resource_ledger(manifest, resources)
        self.assertIn("retry_max: underflow", underflow["errors"])

        resources["source_u_reuse_count"] = "1"
        malformed = resource_ledger(manifest, resources)
        self.assertIn("source_u_reuse_count: integer_required", malformed["errors"])

        resources["source_u_reuse_count"] = 1
        resources["N"] = 4
        inconsistent = resource_ledger(manifest, resources)
        self.assertIn("inconsistent_N", inconsistent["errors"])

        resources["N"] = 3
        resources["M"] = 2
        exceeds_m = resource_ledger(manifest, resources)
        self.assertIn("M_exceeds_A", exceeds_m["errors"])
        resources["M"] = 1
        resources["P"] = 4
        exceeds_p = resource_ledger(manifest, resources)
        self.assertIn("P_exceeds_2A_plus_R_retry", exceeds_p["errors"])

    def test_fraction_components_are_exact_and_fail_closed(self) -> None:
        self.assertEqual(
            _known_advantage({"numerator": 2, "denominator": 100}, "sample"),
            Fraction(1, 50),
        )
        large = (2**200) + 123
        self.assertEqual(
            _known_advantage(
                {"numerator": str(large), "denominator": str(2**201)},
                "sample",
            ),
            Fraction(large, 2**201),
        )
        self.assertEqual(
            _known_advantage({"numerator": "29", "denominator": "100"}, "sample"),
            Fraction(29, 100),
        )
        with self.assertRaisesRegex(ContractError, "overflow"):
            _known_advantage({"numerator": 2, "denominator": 1}, "sample")

        manifest = _manifest()
        resources = copy.deepcopy(manifest["resource_accounting"])
        for name in (
            "Q", "A", "V", "R_retry", "M", "P", "S", "E_U", "qhat",
            "retry_max", "lifetime_attempt_budget",
        ):
            resources[name] = 1
        resources["N"] = 3
        resources["source_u_reuse_count"] = 1
        resources["source_u_reissued_parameter_count"] = 0
        for name in (
            "Adv_Q1_AES256_node", "Adv_Q1_AES256_leaf", "Adv_Q1_AES256_stream",
            "Adv_SHAKE_snd", "Adv_source_auth", "Adv_U_generation", "Adv_SHAKE_priv",
            "epsilon_coins", "epsilon_AR", "epsilon_bitMH", "epsilon_source", "privacy_cap",
        ):
            resources[name] = {"numerator": 1, "denominator": 2}

        for raw in (2.9, True):
            with self.subTest(raw=raw):
                invalid = copy.deepcopy(resources)
                invalid["Adv_Q1_AES256_node"] = {"numerator": raw, "denominator": 100}
                result = resource_ledger(manifest, invalid)
                self.assertFalse(result["resources_declared"])
                self.assertIn("Adv_Q1_AES256_node.numerator: invalid_fraction_component", result["errors"])

        for spelling in (" 2", "+2", "2 ", "2.0", "2/1", "nan", "01", "-2", ""):
            with self.subTest(spelling=spelling):
                with self.assertRaisesRegex(ContractError, "invalid_fraction_component"):
                    _known_advantage({"numerator": spelling, "denominator": "100"}, "sample")
        for zero_component in (0, "0"):
            with self.subTest(zero_component=zero_component):
                with self.assertRaisesRegex(ContractError, "zero_placeholder_forbidden"):
                    _known_advantage(
                        {"numerator": zero_component, "denominator": 100},
                        "sample",
                    )

    def test_numeric_boundaries_do_not_coerce_bool_or_float(self) -> None:
        for field, bad_value in (
            ("ell_bits", 125048.0),
            ("padding_zero_constraint_count", False),
            ("degree", 3.0),
            ("mask_count", 6.0),
            ("ordinary_bit_vole_rows", 126584.0),
            ("ordinary_bit_vole_row_bytes", 15823.0),
        ):
            with self.subTest(actual_export_field=field):
                manifest = _manifest()
                manifest["dimensions"]["actual_export"][field] = bad_value
                with self.assertRaisesRegex(ContractError, "identity_mismatch"):
                    calculate_report(manifest)

        manifest = _manifest()
        manifest["faest_256f"]["lambda_bits"] = 256.0
        with self.assertRaisesRegex(ContractError, "wrong_parameter"):
            calculate_report(manifest)

        for field, bad_value, expected_error in (
            ("degree", 3.0, "wrong_parameter"),
            ("mask_count", 6.0, "actual_export_mismatch"),
            ("ordinary_bit_vole_rows", 126584.0, "actual_export_mismatch"),
            ("ordinary_bit_vole_row_bytes", 15823.0, "actual_export_mismatch"),
            ("padding_zero_constraint_count", False, "actual_export_mismatch"),
            ("vole_tree_count", 33.0, "wrong_tree_geometry"),
            ("total_leaves", 6400.0, "wrong_tree_geometry"),
        ):
            with self.subTest(descriptor_field=field):
                descriptor = _descriptor()
                descriptor[field] = bad_value
                result = admission_ledger(_manifest(), descriptor)
                self.assertFalse(result["descriptor_valid"])
                self.assertIn(expected_error, result["errors"])

    def test_unknown_or_missing_descriptor_values_remain_fail_closed(self) -> None:
        descriptor = _descriptor()
        del descriptor["field_domain"]
        result = admission_ledger(_manifest(), descriptor)
        self.assertIn("wrong_field_domain", result["errors"])
        self.assertFalse(result["qualified"])

        with self.assertRaisesRegex(ContractError, "descriptor: path_required"):
            # Exercise the public CLI-adjacent JSON reader contract without relying on files.
            from .calculator import _read_json

            _read_json(None)


if __name__ == "__main__":
    unittest.main()
