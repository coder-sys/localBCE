from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List

from app.canonical_encoding import stable_private_hash


STUB_LABEL = "REAL BATCH PROOF REQUIRED - FAIL CLOSED / PENDING CRYPTO AUDIT"


@dataclass(frozen=True)
class BatchProofBundle:
    batch_id: str
    proof: str
    public_inputs: List[str]
    verifier_key_id: str
    status: str = STUB_LABEL


class BatchProverStub:
    """RISC Zero receipt placeholder only. No real proof is produced."""

    def prove(self, batch_id: str, public_inputs: List[str], verifier_key_id: str) -> BatchProofBundle:
        payload = json.dumps({"batch_id": batch_id, "public_inputs": public_inputs, "verifier_key_id": verifier_key_id}, sort_keys=True)
        proof = "BATCH_PROOF_STUB_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return BatchProofBundle(batch_id=batch_id, proof=proof, public_inputs=public_inputs, verifier_key_id=verifier_key_id)


class BatchVerifierStub:
    """Swappable verifier placeholder.

    It rejects by default so no demo path can pretend a real RISC Zero receipt
    was verified before the real prover/verifier and audit exist.
    """

    def verify(self, bundle: BatchProofBundle) -> bool:
        return False


class CPNAdapterStub:
    """Circle Payments Network managed-payments placeholder.

    Government and provider endpoints stay fiat-only. This stub does not move
    money and does not expose wallet concepts.
    """

    def submit_provider_payment(self, batch_id: str, provider_payment_key: str, amount_cents: int) -> Dict[str, object]:
        if amount_cents <= 0:
            raise ValueError("amount must be positive")
        settlement_ref = stable_private_hash(["CPN_STUB", batch_id, provider_payment_key, amount_cents])
        return {
            "rail": "CPN_MANAGED_PAYMENTS_STUB",
            "batch_id": batch_id,
            "provider_payment_key": provider_payment_key,
            "amount_cents": amount_cents,
            "settlement_ref": settlement_ref,
            "status": "stub_submitted",
        }
