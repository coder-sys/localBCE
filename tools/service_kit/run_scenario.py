"""Run the one post-extraction synthetic service integration scenario."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.right_rail_financial_service_kit import SERVICE_SCENARIO  # noqa: E402  (the one owner of the name)


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromName(SERVICE_SCENARIO)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
