#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import validate_openzeppelin_pin as pin


class OpenZeppelinPinTests(unittest.TestCase):
    def test_aggregate_covers_only_reviewed_git_tracked_sources(self) -> None:
        files = pin.tracked_source_files()
        self.assertGreater(len(files), 300)
        self.assertTrue(all(path.is_relative_to(pin.SOURCE) for path in files))
        self.assertTrue(all(path.is_file() for path in files))

        expected = json.loads(pin.PIN_PATH.read_text(encoding="utf-8"))["aggregate_sha256"]
        self.assertEqual(pin.aggregate(), expected)


if __name__ == "__main__":
    unittest.main()
