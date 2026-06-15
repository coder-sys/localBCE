from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Dict, List


def _approved_flag(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"false", "0", "no", "n", ""}:
            return False
        if normalized in {"true", "1", "yes", "y"}:
            return True
    return False


def update_dashboard_state(out_dir: Path, registry_rows: List[Dict[str, object]], appeal_queue: List[Dict[str, object]]) -> Dict[str, object]:
    approved = sum(1 for row in registry_rows if _approved_flag(row.get("approved")))
    denied = len(registry_rows) - approved
    denial_reasons = Counter(row.get("denial_reason") or "approved" for row in registry_rows)
    state = {
        "claims_processed": len(registry_rows),
        "approved": approved,
        "denied": denied,
        "denial_reasons": dict(denial_reasons),
        "appeal_queue": appeal_queue,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "dashboard_state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state


def write_dashboard_html(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Blind Ledger Claims Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; color: #222; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(140px, 1fr)); gap: 12px; }
    .card { border: 1px solid #ddd; border-radius: 8px; padding: 16px; background: #fafafa; }
    .value { font-size: 28px; font-weight: 700; }
    table { border-collapse: collapse; width: 100%; margin-top: 24px; }
    th, td { border-bottom: 1px solid #ddd; padding: 8px; text-align: left; }
  </style>
</head>
<body>
  <h1>Blind Ledger Claims Dashboard</h1>
  <div class="grid">
    <div class="card"><div>Processed</div><div id="processed" class="value">0</div></div>
    <div class="card"><div>Approved</div><div id="approved" class="value">0</div></div>
    <div class="card"><div>Denied</div><div id="denied" class="value">0</div></div>
    <div class="card"><div>Appeals</div><div id="appeals" class="value">0</div></div>
  </div>
  <h2>Denial Reasons</h2>
  <pre id="reasons"></pre>
  <h2>Appeal Queue</h2>
  <table><thead><tr><th>Claim</th><th>Track</th><th>Reason</th></tr></thead><tbody id="queue"></tbody></table>
  <script>
    fetch('../demo_output/dashboard_state.json').then(r => r.json()).then(s => {
      processed.textContent = s.claims_processed;
      approved.textContent = s.approved;
      denied.textContent = s.denied;
      appeals.textContent = s.appeal_queue.length;
      reasons.textContent = JSON.stringify(s.denial_reasons, null, 2);
      queue.innerHTML = s.appeal_queue.map(r => `<tr><td>${r.claim_id}</td><td>${r.track}</td><td>${r.denial_reason}</td></tr>`).join('');
    });
  </script>
</body>
</html>
""",
        encoding="utf-8",
    )
