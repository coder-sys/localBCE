"""Pinned full-attack screen for the reproduced Hint-MLWE Set-1 baseline.

Run from the pinned lattice-estimator checkout with that checkout on
PYTHONPATH. This emits evidence to stdout and does not qualify a candidate.
"""

import hashlib
import json
import sys
import time

from sage.all import log, oo

from estimator import LWE, ND, SIS
from estimator.lwe_guess import exhaustive_search
from estimator.reduction import ADPS16, RC


ESTIMATOR_COMMIT = "3e48ef421ec256afddb3e7d2249a77eab6e9ba12"
UPSTREAM_COMMIT = "c86212e45af9e957d1ae2be58c111e2d85b253be"

PUBLISHED_BASELINE = {
    "source": "reproduced_upstream_set_1_current_pinned_estimator",
    "ring_degree": 64,
    "q": 1_152_921_611_981_031_877,
    "kmlwe": 34,
    "kmsis": 33,
    "m1": 12,
    "m2": 68,
    "hiding_sd": 12,
    "simulation_sd": 9,
    "binding_bound": 1.773442e12,
    "knowledge_bound": 1.1136207e17,
}

D512_TERNARY_Q68_OPTIMISTIC = {
    "source": "derived_d512_ternary_q68_no_compression_lower_bound",
    "ring_degree": 512,
    "q": 295_147_905_522_950_209_637,
    "kmlwe": 34,
    "kmsis": 33,
    "m1": 12,
    "m2": 69,
    "hiding_sd": 20,
    "simulation_sd": 15,
    "binding_bound": 134_663_000_000_000,
    "knowledge_bound": 115_659_600_000_000_000_000,
}

D256_BOX4_Q68_FEASIBILITY = {
    "source": "derived_d256_box4_q68_D0_gamma2498_feasibility",
    "ring_degree": 256,
    "q": 380_250_000_390_000_000_101,
    "kmlwe": 34,
    "kmsis": 33,
    "m1": 12,
    "m2": 69,
    "hiding_sd": 20,
    "simulation_sd": 15,
    "binding_bound": 108_080_000_000_000,
    "knowledge_bound": 370_042_000_000_000_000_000,
}

D256_BOX4_Q68_K32_FEASIBILITY = {
    "source": "derived_d256_box4_q68_D0_gamma2498_kmlwe32",
    "ring_degree": 256,
    "q": 380_250_000_390_000_000_101,
    "kmlwe": 32,
    "kmsis": 33,
    "m1": 12,
    "m2": 67,
    "hiding_sd": 20,
    "simulation_sd": 15,
    "binding_bound": 106_630_000_000_000,
    "knowledge_bound": 370_042_000_000_000_000_000,
}

D256_BOX4_Q68_K28_FEASIBILITY = {
    "source": "derived_d256_box4_q68_D0_gamma2498_kmlwe28",
    "ring_degree": 256,
    "q": 380_250_000_390_000_000_101,
    "kmlwe": 28,
    "kmsis": 33,
    "m1": 12,
    "m2": 63,
    "hiding_sd": 20,
    "simulation_sd": 15,
    "binding_bound": 103_667_000_000_000,
    "knowledge_bound": 370_042_000_000_000_000_000,
}

D256_BOX4_Q68_K29_FEASIBILITY = {
    "source": "derived_d256_box4_q68_D0_gamma2498_kmlwe29",
    "ring_degree": 256,
    "q": 380_250_000_390_000_000_101,
    "kmlwe": 29,
    "kmsis": 33,
    "m1": 12,
    "m2": 64,
    "hiding_sd": 20,
    "simulation_sd": 15,
    "binding_bound": 104_415_171_370_354,
    "knowledge_bound": 370_041_749_296_234_044_387,
}

D256_BOX4_K29_M13_OPTION = {
    "source": "derived_d256_box4_k29_m13_prime_option",
    "ring_degree": 256,
    "q": 390_189_592_673_851_991_077,
    "kmlwe": 29,
    "kmsis": 33,
    "m1": 13,
    "m2": 64,
    "hiding_sd": 20,
    "simulation_sd": 15,
    "binding_bound": 106_148_136_257_144,
    "knowledge_bound": 390_189_139_425_620_770_708,
}

D256_BOX4_K29_M16_OPTION = {
    "source": "derived_d256_box4_k29_m16_prime_option",
    "ring_degree": 256,
    "q": 480_467_452_801_831_653_637,
    "kmlwe": 29,
    "kmsis": 33,
    "m1": 16,
    "m2": 64,
    "hiding_sd": 20,
    "simulation_sd": 15,
    "binding_bound": 119_035_968_284_222,
    "knowledge_bound": 480_465_046_211_388_581_519,
}

D256_BOX4_K29_M24_OPTION = {
    "source": "derived_d256_box4_k29_m24_prime_option",
    "ring_degree": 256,
    "q": 721_373_037_436_575_079_397,
    "kmlwe": 29,
    "kmsis": 33,
    "m1": 24,
    "m2": 64,
    "hiding_sd": 20,
    "simulation_sd": 15,
    "binding_bound": 149_853_442_095_462,
    "knowledge_bound": 721_370_884_265_725_584_102,
}

D256_BOX4_K29_M32_OPTION = {
    "source": "derived_d256_box4_k29_m32_prime_option",
    "ring_degree": 256,
    "q": 962_464_919_352_595_762_757,
    "kmlwe": 29,
    "kmsis": 33,
    "m1": 32,
    "m2": 64,
    "hiding_sd": 20,
    "simulation_sd": 15,
    "binding_bound": 177_589_556_222_710,
    "knowledge_bound": 962_464_052_383_097_641_755,
}

PROFILES = {
    "published": PUBLISHED_BASELINE,
    "d512_ternary_q68_optimistic": D512_TERNARY_Q68_OPTIMISTIC,
    "d256_box4_q68_feasibility": D256_BOX4_Q68_FEASIBILITY,
    "d256_box4_q68_k32_feasibility": D256_BOX4_Q68_K32_FEASIBILITY,
    "d256_box4_q68_k28_feasibility": D256_BOX4_Q68_K28_FEASIBILITY,
    "d256_box4_q68_k29_feasibility": D256_BOX4_Q68_K29_FEASIBILITY,
    "d256_box4_k29_m13_option": D256_BOX4_K29_M13_OPTION,
    "d256_box4_k29_m16_option": D256_BOX4_K29_M16_OPTION,
    "d256_box4_k29_m24_option": D256_BOX4_K29_M24_OPTION,
    "d256_box4_k29_m32_option": D256_BOX4_K29_M32_OPTION,
}
BASELINE = PUBLISHED_BASELINE

LWE_EXPECTED_ATTACKS = {
    "arora-gb",
    "bkw",
    "usvp",
    "bdd",
    "bdd_hybrid",
    "bdd_mitm_hybrid",
    "dual",
    "dual_hybrid",
}
SIS_EXPECTED_ATTACKS = {"lattice"}


def _bits(value):
    if value == oo:
        return "infinity"
    return float(log(value, 2).n())


def _emit(label, payload):
    print(
        f"{label}="
        f"{json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str)}",
        flush=True,
    )


def _run_lwe(case_name, standard_deviation, reduction_model, only_attack=None):
    dimension = BASELINE["kmlwe"] * BASELINE["ring_degree"]
    distribution = ND.DiscreteGaussian(standard_deviation)
    params = LWE.Parameters(
        n=dimension,
        q=BASELINE["q"],
        Xs=distribution,
        Xe=distribution,
        m=dimension,
        tag=case_name,
    )
    print(f"INPUT:{case_name}:{params!r}", flush=True)
    started = time.perf_counter()
    if only_attack == "exhaustive_quantum":
        quantum_exhaustive = exhaustive_search(params, quantum=True)
        elapsed = time.perf_counter() - started
        print(
            f"RAW:{case_name}:exhaustive_quantum:"
            f"{quantum_exhaustive!r}",
            flush=True,
        )
        _emit(
            f"SUMMARY:{case_name}",
            {
                "elapsed_seconds": elapsed,
                "expected_attack_count": 1,
                "returned_attack_count": 1,
                "missing_attacks": [],
                "minimum_finite_attack": "exhaustive_quantum",
                "minimum_finite_rop_bits": _bits(
                    quantum_exhaustive["rop"]
                ),
            },
        )
        return
    dependency_closure = {
        "bdd_hybrid": {"bdd", "bdd_hybrid"},
        "bdd_mitm_hybrid": {
            "bdd",
            "bdd_hybrid",
            "bdd_mitm_hybrid",
        },
    }
    expected_attacks = (
        dependency_closure.get(only_attack, {only_attack})
        if only_attack is not None
        else LWE_EXPECTED_ATTACKS
    )
    deny_list = tuple(LWE_EXPECTED_ATTACKS.difference(expected_attacks))
    results = LWE.estimate(
        params,
        red_cost_model=reduction_model,
        deny_list=deny_list,
        jobs=1,
        catch_exceptions=True,
        quiet=True,
    )
    elapsed = time.perf_counter() - started
    for attack_name in sorted(results):
        print(
            f"RAW:{case_name}:{attack_name}:{results[attack_name]!r}",
            flush=True,
        )
    missing = sorted(expected_attacks.difference(results))
    finite = {
        name: _bits(result["rop"])
        for name, result in results.items()
        if result["rop"] != oo
    }
    if only_attack is None:
        quantum_exhaustive = exhaustive_search(params, quantum=True)
        print(
            f"RAW:{case_name}:exhaustive_quantum:"
            f"{quantum_exhaustive!r}",
            flush=True,
        )
        if quantum_exhaustive["rop"] != oo:
            finite["exhaustive_quantum"] = _bits(
                quantum_exhaustive["rop"]
            )
    _emit(
        f"SUMMARY:{case_name}",
        {
            "elapsed_seconds": elapsed,
            "expected_attack_count": (
                len(expected_attacks) + (1 if only_attack is None else 0)
            ),
            "returned_default_attack_count": len(results),
            "missing_default_attacks": missing,
            "minimum_finite_attack": (
                min(finite, key=finite.get) if finite else None
            ),
            "minimum_finite_rop_bits": (
                min(finite.values()) if finite else None
            ),
            "quantum_exhaustive_checked": only_attack is None,
        },
    )


def _run_sis(case_name, length_bound, reduction_model, only_attack=None):
    if only_attack not in (None, "lattice"):
        raise SystemExit(f"attack_not_valid_for_sis:{only_attack}")
    dimension = BASELINE["ring_degree"]
    params = SIS.Parameters(
        n=BASELINE["kmsis"] * dimension,
        q=BASELINE["q"],
        length_bound=length_bound,
        m=(2 * BASELINE["m1"] + BASELINE["m2"]) * dimension,
        norm=2,
        tag=case_name,
    )
    print(f"INPUT:{case_name}:{params!r}", flush=True)
    started = time.perf_counter()
    results = SIS.estimate(
        params,
        red_cost_model=reduction_model,
        jobs=1,
        catch_exceptions=True,
        quiet=True,
    )
    elapsed = time.perf_counter() - started
    for attack_name in sorted(results):
        print(
            f"RAW:{case_name}:{attack_name}:{results[attack_name]!r}",
            flush=True,
        )
    missing = sorted(SIS_EXPECTED_ATTACKS.difference(results))
    finite = {
        name: _bits(result["rop"])
        for name, result in results.items()
        if result["rop"] != oo
    }
    _emit(
        f"SUMMARY:{case_name}",
        {
            "elapsed_seconds": elapsed,
            "expected_attack_count": len(SIS_EXPECTED_ATTACKS),
            "returned_attack_count": len(results),
            "missing_attacks": missing,
            "minimum_finite_attack": (
                min(finite, key=finite.get) if finite else None
            ),
            "minimum_finite_rop_bits": (
                min(finite.values()) if finite else None
            ),
        },
    )


def main():
    global BASELINE
    if len(sys.argv) > 5:
        raise SystemExit("usage:profile model [case] [attack]")
    profile_name = sys.argv[1] if len(sys.argv) >= 2 else "published"
    model_name = (
        sys.argv[2] if len(sys.argv) >= 3 else "adps16_quantum"
    )
    only_case = sys.argv[3] if len(sys.argv) >= 4 else None
    only_attack = sys.argv[4] if len(sys.argv) == 5 else None
    if profile_name not in PROFILES:
        raise SystemExit(
            "profile_must_be_one_of:" + ",".join(sorted(PROFILES))
        )
    BASELINE = PROFILES[profile_name]
    models = {
        "adps16_quantum": ADPS16(mode="quantum"),
        "laamospol14": RC.LaaMosPol14,
        "adps16_paranoid_stress": ADPS16(mode="paranoid"),
    }
    if model_name not in models:
        raise SystemExit(
            "model_must_be_one_of:" + ",".join(sorted(models))
        )
    canonical_input = {
        "baseline": BASELINE,
        "estimator_commit": ESTIMATOR_COMMIT,
        "model": model_name,
        "profile": profile_name,
        "upstream_commit": UPSTREAM_COMMIT,
    }
    encoded = json.dumps(
        canonical_input,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    _emit(
        "SCREEN",
        {
            **canonical_input,
            "authoritative_input_sha3_512": hashlib.sha3_512(
                encoded
            ).hexdigest(),
            "status_ceiling": "FEASIBILITY_ONLY",
        },
    )
    reduction_model = models[model_name]
    cases = {
        "hiding_mlwe": (
            _run_lwe,
            BASELINE["hiding_sd"],
        ),
        "simulatability_mlwe": (
            _run_lwe,
            BASELINE["simulation_sd"],
        ),
        "binding_msis": (
            _run_sis,
            BASELINE["binding_bound"],
        ),
        "knowledge_msis": (
            _run_sis,
            BASELINE["knowledge_bound"],
        ),
    }
    if only_case is not None and only_case not in cases:
        raise SystemExit("case_must_be_one_of:" + ",".join(sorted(cases)))
    selected_cases = (
        {only_case: cases[only_case]} if only_case is not None else cases
    )
    for case_name, (runner, case_parameter) in selected_cases.items():
        runner(
            case_name,
            case_parameter,
            reduction_model,
            only_attack=only_attack,
        )


main()
