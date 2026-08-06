from __future__ import annotations

from pathlib import Path
from typing import Dict

try:
    from fastapi import FastAPI
except Exception:  # pragma: no cover
    FastAPI = None

from .ingestion import parse_837
from .orchestrator import run_pipeline
from .shared_context import build_shared_context
from .rules_review_api import router as rules_review_router


if FastAPI:
    app = FastAPI(title="Blind Ledger App Layer", version="0.1.0")
    if rules_review_router is not None:
        app.include_router(rules_review_router)

    @app.get("/health")
    def health() -> Dict[str, object]:
        return {"status": "ok", "stubs": ["ZK_PROVER_STUB", "VERIFIER_STUB", "CIRCLE_BRIDGE_STUB", "FEDNOW_BRIDGE_STUB"]}

    @app.post("/claims/ingest")
    def ingest(payload: Dict[str, object]) -> Dict[str, object]:
        parsed = parse_837(str(payload.get("edi", "")))
        return {"accepted": parsed.accepted, "errors": parsed.errors, "segments": len(parsed.segments)}

    @app.post("/claims/adjudicate")
    def adjudicate_claim(payload: Dict[str, object]) -> Dict[str, object]:
        tmp = Path("demo_output") / "api_claim_input.json"
        tmp.parent.mkdir(parents=True, exist_ok=True)
        import json

        tmp.write_text(json.dumps(payload), encoding="utf-8")
        return run_pipeline(tmp, Path("demo_output"))

    @app.get("/dashboard/state")
    def dashboard_state() -> Dict[str, object]:
        import json

        path = Path("demo_output") / "dashboard_state.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
