"""Run the one post-extraction synthetic service integration scenario."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

TEST_NAME = (
    "tests.test_right_rail_financial_staff_server.RightRailFinancialStaffWorkspaceTests."
    "test_service_kit_correction_lost_response_retry_and_shadow_restore"
)


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromName(TEST_NAME)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
