from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, List

from .models import AdjudicationResult, ProofBundle


REQUIRED_PROVENANCE_FIELDS = {"proof_system", "verifier_key_id", "proof_hash", "public_inputs"}


class ClaimsRegistry:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> List[Dict[str, object]]:
        if not self.path.exists():
            return []
        raw = self.path.read_text(encoding="utf-8")
        try:
            rows = json.loads(raw)
        except json.JSONDecodeError:
            self._quarantine_registry("corrupt_json", raw.encode("utf-8"))
            return []
        if not isinstance(rows, list):
            self._quarantine_registry("not_a_list", raw.encode("utf-8"))
            return []
        if any(not self._valid_row(row) for row in rows):
            self._quarantine_registry("missing_provenance", raw.encode("utf-8"))
            return []
        return rows

    def record(self, result: AdjudicationResult, proof: ProofBundle) -> Dict[str, object]:
        rows = self._load()
        entry = self.entry_for(result, proof)
        rows.append(entry)
        self._atomic_write(rows)
        return entry

    def entry_for(self, result: AdjudicationResult, proof: ProofBundle) -> Dict[str, object]:
        return {
            "claim_id": result.claim_id,
            "approved": result.approved,
            "denial_reason": result.denial_reason,
            "context_hash": proof.context_hash,
            "payable_amount": result.payable_amount,
            "proof_system": proof.proof_system,
            "verifier_key_id": proof.verifier_key_id,
            "proof_hash": proof.proof_hash(),
            "public_inputs": list(proof.public_inputs),
        }

    def _valid_row(self, row: object) -> bool:
        return isinstance(row, dict) and REQUIRED_PROVENANCE_FIELDS.issubset(row)

    def _atomic_write(self, rows: List[Dict[str, object]]) -> None:
        temp_path = self.path.with_name(self.path.name + ".tmp")
        temp_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        temp_path.replace(self.path)

    def _quarantine_registry(self, reason: str, raw: bytes) -> None:
        digest = hashlib.sha256(raw).hexdigest()[:16]
        quarantine = self.path.with_name(f"{self.path.name}.{reason}.{digest}.bak")
        counter = 1
        while quarantine.exists():
            quarantine = self.path.with_name(f"{self.path.name}.{reason}.{digest}.{counter}.bak")
            counter += 1
        self.path.replace(quarantine)
