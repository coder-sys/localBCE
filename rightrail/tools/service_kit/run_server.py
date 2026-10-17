"""Start the loopback-only synthetic staff workspace from the extracted kit."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from app.right_rail_financial_staff_server import main


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
