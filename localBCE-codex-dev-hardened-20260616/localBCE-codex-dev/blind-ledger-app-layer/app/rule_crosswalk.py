from __future__ import annotations

import hashlib
import json
from typing import Dict


APP_LAYER_GATES = {
    "native_stark_binding": {
        "status": "canonical_requires_audited_native_stark_prover",
        "gates": {
            "G1": "member_id_present",
            "G2": "eligibility_active",
            "G3": "provider_npi_present",
            "G4": "provider_enrolled",
            "G5": "service_lines_present",
            "G6": "diagnosis_present",
            "G7": "prior_authorization_when_required",
            "G8A": "charge_valid",
            "G8B": "charge_within_allowable",
            "G9": "not_duplicate",
            "G10": "no_program_integrity_hold",
        },
    }
}

V9_TARGET = {
    "v9_target": {
        "status": "architecture_target_not_live_gate_contract",
        "requires_crosswalk_before_production": True,
    }
}


def build_rule_crosswalk() -> Dict[str, object]:
    return {
        "schema_version": "rule_crosswalk_v2_native_stark",
        "native_stark_binding": APP_LAYER_GATES["native_stark_binding"],
        "v9_target": V9_TARGET["v9_target"],
        "production_rule_contract": {
            "canonical_lane": "native_stark_binding",
            "legacy_claim_circuit_allowed_in_production": False,
            "v9_crosswalk_required_before_production": True,
        },
    }


def rule_crosswalk_hash() -> str:
    payload = json.dumps(build_rule_crosswalk(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
