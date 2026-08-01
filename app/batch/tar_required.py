from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from app.batch.stark_encoding import pack_felt_text

TAR_REQUIRED_POLICY_PATH = Path(__file__).resolve().parents[1] / "policy" / "tar_required_procedures_v1.json"


def load_default_tar_required_codes() -> tuple[str, ...]:
    payload = json.loads(TAR_REQUIRED_POLICY_PATH.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "blind_ledger_tar_required_procedures_v1":
        raise ValueError("tar_required_policy_schema_mismatch")
    codes = tuple(str(code).strip() for code in payload.get("tar_required_procedure_codes", []))
    if not codes or any(not code for code in codes):
        raise ValueError("tar_required_policy_empty")
    return codes


def _procedure_felt(procedure_code: str) -> int:
    return pack_felt_text(str(procedure_code).strip())


def is_tar_required(procedure_code: str, codes: Iterable[str] | None = None) -> bool:
    target = _procedure_felt(procedure_code)
    required = {_procedure_felt(code) for code in (tuple(codes) if codes is not None else load_default_tar_required_codes())}
    return target in required
