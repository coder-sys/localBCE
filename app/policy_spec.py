from __future__ import annotations

import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_SPEC_PATH = REPO_ROOT / "ops" / "policy_spec_v1.yaml"


def load_policy_spec(path: Path | None = None) -> dict[str, Any]:
    spec_path = path or POLICY_SPEC_PATH
    return json.loads(spec_path.read_text(encoding="utf-8"))


def policy_gate_ids(path: Path | None = None) -> list[str]:
    spec = load_policy_spec(path)
    gates = spec.get("gates", [])
    if not isinstance(gates, list):
        raise ValueError("policy_spec_gates_must_be_list")
    return [str(gate["id"]) for gate in gates]
