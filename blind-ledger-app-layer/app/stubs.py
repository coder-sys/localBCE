from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Protocol

from .models import AdjudicationResult, ProofBundle, SharedContext


class ZKProver(Protocol):
    def prove(self, ctx: SharedContext, result: AdjudicationResult) -> ProofBundle: ...


class Verifier(Protocol):
    def verify(self, proof: ProofBundle) -> bool: ...


class PaymentBridge(Protocol):
    def trigger(self, claim_id: str, amount: float, recipient: str) -> Dict[str, object]: ...


class ZKProverStub:
    """ZK_PROVER_STUB satisfying the future prover interface."""

    def prove(self, ctx: SharedContext, result: AdjudicationResult) -> ProofBundle:
        payload = json.dumps({"ctx": ctx.to_dict(), "result": result.to_dict()}, sort_keys=True)
        context_hash = "0x" + hashlib.sha256(payload.encode()).hexdigest()
        proof = "0xSTUBPROOF" + hashlib.sha256((context_hash + ":proof").encode()).hexdigest()
        public_inputs = [context_hash, "0x01" if result.approved else "0x00"]
        return ProofBundle(
            proof=proof,
            public_inputs=public_inputs,
            context_hash=context_hash,
            stub=True,
            proof_system="LOCAL_STUB",
            verifier_key_id="LOCAL_STUB_V1",
        )


class VerifierStub:
    """VERIFIER_STUB for mock proof-shape validation only."""

    def verify(self, proof: ProofBundle) -> bool:
        return (
            proof.stub
            and proof.proof_system == "LOCAL_STUB"
            and proof.verifier_key_id == "LOCAL_STUB_V1"
            and proof.proof.startswith("0xSTUBPROOF")
            and len(proof.public_inputs) >= 2
        )


class CircleBridgeStub:
    """CIRCLE_BRIDGE_STUB: no real USDC transfer."""

    def trigger(self, claim_id: str, amount: float, recipient: str) -> Dict[str, object]:
        return {"bridge": "circle_stub", "claim_id": claim_id, "amount": amount, "recipient": recipient, "status": "mock_triggered"}


class FedNowBridgeStub:
    """FEDNOW_BRIDGE_STUB: no real settlement call."""

    def trigger(self, claim_id: str, amount: float, recipient: str) -> Dict[str, object]:
        return {"bridge": "fednow_stub", "claim_id": claim_id, "amount": amount, "recipient": recipient, "status": "mock_triggered"}
