from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_rightrail_integration_catalog.py"
SPEC = importlib.util.spec_from_file_location("rightrail_catalog", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
catalog = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = catalog
SPEC.loader.exec_module(catalog)


class RightRailCatalogTests(unittest.TestCase):
    def test_classification_boundaries(self) -> None:
        self.assertEqual(catalog.base_disposition("w/r067/app/service.py")[0], "experimental_build")
        self.assertEqual(catalog.base_disposition("w/r003/Formal/State.lean")[0], "formal_reference")
        self.assertEqual(catalog.base_disposition("w/r020/build/tool.exe")[0], "unsafe_binary")
        self.assertEqual(catalog.base_disposition("root/AGENTS.reference.txt")[0], "audit_evidence")

    def test_duplicate_canonical_path_prefers_product_owner(self) -> None:
        self.assertEqual(
            catalog.canonical_duplicate_path(
                [
                    "w/r023/tools/verifier.py",
                    "long/f00001.py",
                    "w/r067/tools/verifier.py",
                ]
            ),
            "w/r067/tools/verifier.py",
        )

    def test_fixture_is_complete_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = {
                "w/r001/evidence.txt": b"evidence\n",
                "w/r067/app/service.py": b"print('candidate')\n",
                "long/copy.py": b"print('candidate')\n",
            }
            manifest = []
            for path, content in entries.items():
                destination = root.joinpath(*path.split("/"))
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
                manifest.append(
                    {
                        "path": path,
                        "original_path": f"workspace/{path}",
                        "bytes": len(content),
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                )
            (root / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
            (root / "WORKSPACES.json").write_text(
                json.dumps({"workspace/evidence": "w/r001", "workspace/financial": "w/r067"}),
                encoding="utf-8",
            )

            first = catalog.build_catalog(
                root,
                expected_manifest_entries=None,
                expected_workspaces=None,
            )
            second = catalog.build_catalog(
                root,
                expected_manifest_entries=None,
                expected_workspaces=None,
            )
            self.assertEqual(first.catalog_bytes, second.catalog_bytes)
            self.assertEqual(first.summary_bytes, second.summary_bytes)
            self.assertEqual(first.summary["manifest_entry_count"], 3)
            self.assertEqual(first.summary["unclassified_count"], 0)
            self.assertEqual(first.summary["duplicate_entry_count"], 1)
            self.assertEqual(first.summary["runtime_eligible_count"], 0)

    def test_hash_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "w" / "r001" / "evidence.txt"
            path.parent.mkdir(parents=True)
            path.write_text("changed", encoding="utf-8")
            (root / "MANIFEST.json").write_text(
                json.dumps(
                    [
                        {
                            "path": "w/r001/evidence.txt",
                            "original_path": "workspace/evidence.txt",
                            "bytes": 7,
                            "sha256": "0" * 64,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (root / "WORKSPACES.json").write_text(
                json.dumps({"workspace/evidence": "w/r001"}), encoding="utf-8"
            )
            result = catalog.build_catalog(
                root,
                expected_manifest_entries=None,
                expected_workspaces=None,
            )
            self.assertEqual(result.summary["integrity_failure_count"], 1)
            self.assertEqual(result.summary["integrity_failures"][0]["status"], "sha256_mismatch")


if __name__ == "__main__":
    unittest.main()
