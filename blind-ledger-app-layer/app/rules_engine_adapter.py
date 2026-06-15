from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from .models import AdjudicationResult, SharedContext
from .rules_engine_fallback import adjudicate as fallback_adjudicate


def adjudicate(ctx: SharedContext) -> AdjudicationResult:
    if os.environ.get("BL_FORCE_PYTHON_RULES_ENGINE") == "1":
        return fallback_adjudicate(ctx)
    cargo = shutil.which("cargo")
    crate = Path(__file__).resolve().parents[1] / "rules-engine-rust"
    if not cargo or not crate.exists():
        return fallback_adjudicate(ctx)
    try:
        proc = subprocess.run(
            [cargo, "run", "--quiet", "--", json.dumps(ctx.to_dict())],
            cwd=crate,
            text=True,
            capture_output=True,
            timeout=30,
            check=True,
        )
        data = json.loads(proc.stdout)
        from .models import GateResult

        return AdjudicationResult(
            claim_id=data["claim_id"],
            approved=data["approved"],
            denial_reason=data.get("denial_reason", ""),
            gates=[GateResult(**gate) for gate in data.get("gates", [])],
            carc=data.get("carc", ""),
            rarc=data.get("rarc", ""),
            total_charge=float(data.get("total_charge", 0)),
            payable_amount=float(data.get("payable_amount", 0)),
        )
    except Exception:
        return fallback_adjudicate(ctx)
