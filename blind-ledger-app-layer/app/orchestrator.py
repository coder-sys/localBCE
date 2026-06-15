from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Dict

from .appeal_router import route_appeal
from .dashboard import update_dashboard_state, write_dashboard_html
from .generator_835 import generate_835
from .ingestion import parse_837
from .oracle_attestation import make_test_attestation
from .production_readiness import assert_production_ready
from .provider_alias import provider_payment_alias
from .registry import ClaimsRegistry
from .rules_engine_adapter import adjudicate
from .shared_context import build_shared_context
from .stubs import CircleBridgeStub, VerifierStub, ZKProverStub


def _claim_id_from_parsed(parsed) -> str:
    for segment in parsed.segments:
        if segment and segment[0] == "CLM" and len(segment) > 1:
            return str(segment[1])
    return "UNKNOWN"


def _dev_attestations_for_payload(parsed, flags: Dict[str, object]) -> list[object]:
    if os.environ.get("BL_DEV") != "1" or os.environ.get("BL_ENV", "").strip().lower() in {"prod", "production"}:
        return []
    claim_id = _claim_id_from_parsed(parsed)
    facts = {
        "eligibility_active": flags.get("eligibility_active", False),
        "provider_enrolled": flags.get("provider_enrolled", False),
        "provider_not_suspended": flags.get("provider_not_suspended", False),
        "not_deceased": flags.get("not_deceased", False),
    }
    return [make_test_attestation(fact, bool(value), source_id=f"DEV-{fact.upper()}", claim_id=claim_id) for fact, value in facts.items()]


def run_pipeline(input_path: Path, out_dir: Path) -> Dict[str, object]:
    try:
        assert_production_ready()
    except RuntimeError as exc:
        return {"accepted": False, "errors": [str(exc)]}
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    parsed = parse_837(payload.get("edi", ""))
    if not parsed.accepted:
        return {"accepted": False, "errors": parsed.errors}
    flags = payload.get("flags", {})
    if not isinstance(flags, dict):
        return {"accepted": False, "errors": ["invalid_flags"]}
    try:
        ctx = build_shared_context(
            parsed,
            flags,
            oracle_attestations=payload.get("oracle_attestations") or _dev_attestations_for_payload(parsed, flags),
        )
    except (RuntimeError, ValueError) as exc:
        return {"accepted": False, "errors": [str(exc)]}
    result = adjudicate(ctx)
    proof = ZKProverStub().prove(ctx, result)
    verified = VerifierStub().verify(proof)
    edi_835 = generate_835(ctx, result)
    appeal_track = route_appeal(result)
    appeal_queue = []
    if appeal_track != "none":
        appeal_queue.append({"claim_id": result.claim_id, "track": appeal_track, "denial_reason": result.denial_reason})
    out_dir.mkdir(parents=True, exist_ok=True)
    registry = ClaimsRegistry(out_dir / "claims_registry.json")
    existing_registry_rows = registry._load()
    registry_entry = registry.entry_for(result, proof) if verified else {}
    preview_rows = existing_registry_rows + ([registry_entry] if registry_entry else [])
    dashboard_state = update_dashboard_state(out_dir, preview_rows, appeal_queue)
    write_dashboard_html(Path(__file__).resolve().parents[1] / "dashboard" / "index.html")
    (out_dir / "shared_context.json").write_text(json.dumps(ctx.to_dict(), indent=2), encoding="utf-8")
    (out_dir / "adjudication_result.json").write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    (out_dir / "proof_bundle_stub.json").write_text(json.dumps(proof.to_dict(), indent=2), encoding="utf-8")
    (out_dir / "remittance_835.edi").write_text(edi_835, encoding="utf-8")
    if verified:
        registry_entry = registry.record(result, proof)
    payment = None
    if verified and result.approved:
        payment = CircleBridgeStub().trigger(result.claim_id, result.payable_amount, provider_payment_alias(ctx.provider.npi, ctx.provider.name))
    return {
        "accepted": True,
        "verified": verified,
        "decision": result.to_dict(),
        "registry": registry_entry,
        "payment_stub": payment,
        "appeal_track": appeal_track,
        "835_path": str(out_dir / "remittance_835.edi"),
        "dashboard_state": dashboard_state,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="sample_claim_input.json")
    parser.add_argument("--out", default="demo_output")
    args = parser.parse_args()
    out_dir = Path(args.out)
    result = run_pipeline(Path(args.input), out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "demo_result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
