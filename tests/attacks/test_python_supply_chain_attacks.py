from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
PINNED_LINE = re.compile(r"[a-z0-9][a-z0-9._-]*==[0-9][0-9A-Za-z.]* --hash=sha256:[0-9a-f]{64}")
DEVELOPMENT_PACKAGES = {"colorama", "iniconfig", "packaging", "pluggy", "pygments", "pytest"}

def _install_lines(name: str) -> list[str]:
    text = (ROOT / name).read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]

class PythonSupplyChainAttackTests(unittest.TestCase):
    def test_development_requirements_are_exact_and_hash_pinned(self) -> None:
        lines = _install_lines("requirements-dev.txt")
        for line in lines:
            with self.subTest(line=line):
                # One exact version and one SHA-256 per line; no index, link, include or VCS option.
                self.assertIsNotNone(PINNED_LINE.fullmatch(line))
        self.assertEqual({line.split("==", 1)[0] for line in lines}, DEVELOPMENT_PACKAGES)
        self.assertEqual(len(lines), len(DEVELOPMENT_PACKAGES))

    def test_python_sbom_reconciles_every_pinned_package_version_and_license(self) -> None:
        pins = dict(line.split(" ", 1)[0].split("==", 1) for line in _install_lines("requirements-dev.txt"))
        sbom = json.loads((ROOT / "docs/SBOM.python.spdx.json").read_text(encoding="utf-8"))
        packages = {
            package["name"]: package
            for package in sbom["packages"]
            if package["name"] != "blind-ledger-python-environment"
        }
        self.assertEqual(set(packages), set(pins))
        for name, package in packages.items():
            self.assertEqual(package["versionInfo"], pins[name])
            self.assertNotEqual(package["licenseDeclared"], "NOASSERTION")

    def test_production_has_no_python_dependency(self) -> None:
        self.assertEqual([], _install_lines("requirements.txt"))

    def test_readme_installs_offline_with_required_hashes_only(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("pip install -r requirements-dev.txt", readme)
        commands = [line for line in readme.splitlines() if "pip install" in line]
        self.assertTrue(commands)
        for command in commands:
            for option in ("--no-index", "--require-hashes", "--only-binary=:all:", "--no-deps", "-r requirements-dev.txt"):
                self.assertIn(option, command)

if __name__ == "__main__":
    unittest.main()
