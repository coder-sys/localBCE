from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze_rightrail_workspaces.py"
SPEC = importlib.util.spec_from_file_location("rightrail_static_analysis", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
analysis = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = analysis
SPEC.loader.exec_module(analysis)


class RightRailWorkspaceStaticAnalysisTests(unittest.TestCase):
    def test_priority_order(self) -> None:
        self.assertEqual(analysis.priority("r067")[0], 1)
        self.assertEqual(analysis.priority("r068")[0], 2)
        self.assertEqual(analysis.priority("r001")[0], 3)
        self.assertEqual(analysis.priority("r003")[0], 4)
        self.assertEqual(analysis.priority("r023")[0], 5)

    def test_review_markers_are_static_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "candidate.py"
            source.write_text(
                "import subprocess\nimport requests\nsubprocess.run(['tool'])\nrequests.get('https://example.test')\n",
                encoding="utf-8",
            )
            findings, error = analysis.static_scan_file(source)
            self.assertIsNone(error)
            self.assertEqual(findings["process_execution"], 1)
            self.assertEqual(findings["network_access"], 1)

    def test_large_files_are_not_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "large.py"
            source.write_bytes(b"x" * (analysis.MAX_SCAN_BYTES + 1))
            findings, error = analysis.static_scan_file(source)
            self.assertFalse(findings)
            self.assertEqual(error, "too_large")


if __name__ == "__main__":
    unittest.main()
