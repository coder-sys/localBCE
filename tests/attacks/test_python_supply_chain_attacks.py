from __future__ import annotations

from pathlib import Path
import ast
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PythonSupplyChainAttackTests(unittest.TestCase):
    def test_release_has_complete_hashed_platform_locks(self) -> None:
        expected = {
            "requirements/locks/cp314-linux_x86_64-development.lock",
            "requirements/locks/cp314-linux_x86_64-production.lock",
            "requirements/locks/cp314-win_amd64-development.lock",
            "requirements/locks/cp314-win_amd64-production.lock",
        }
        observed = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "requirements" / "locks").glob("*.lock")
        } if (ROOT / "requirements" / "locks").is_dir() else set()
        self.assertEqual(expected, observed)
        for relative in sorted(expected):
            text = (ROOT / relative).read_text(encoding="utf-8")
            requirement_lines = [
                line for line in text.splitlines() if line and not line.startswith("#")
            ]
            self.assertGreaterEqual(len(requirement_lines), 18)
            self.assertTrue(all("==" in line and "--hash=sha256:" in line for line in requirement_lines))

        manifest = (ROOT / "requirements/locks/python-artifacts.lock.json").read_text(
            encoding="utf-8"
        )
        self.assertIn('"sha3_512":', manifest)
        self.assertIn('"cp314-win_amd64"', manifest)
        self.assertIn('"cp314-linux_x86_64"', manifest)

    def test_quickstart_cannot_resolve_dependencies_from_the_network(self) -> None:
        quickstart = (ROOT / "QUICKSTART.md").read_text(encoding="utf-8")
        self.assertNotIn("pip install -r requirements-dev.txt", quickstart)
        self.assertIn("tools.locked_python_dependencies", quickstart)

    def test_direct_manifests_are_not_installable_release_inputs(self) -> None:
        for name in ("requirements.txt", "requirements-dev.txt"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("NOT AN INSTALL LOCK", text)
            self.assertNotIn("-r requirements.txt", text)
            install_lines = [
                line for line in text.splitlines() if line and not line.startswith("#")
            ]
            self.assertEqual([], install_lines)

    def test_offline_installer_has_no_network_acquisition_import_or_entrypoint(self) -> None:
        path = ROOT / "tools/locked_python_dependencies.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        forbidden_modules = {"http.client", "requests", "socket", "urllib.request"}
        imports = set()
        function_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                function_names.add(node.name)
        self.assertTrue(forbidden_modules.isdisjoint(imports))
        self.assertTrue({"download", "fetch", "resolve"}.isdisjoint(function_names))


if __name__ == "__main__":
    unittest.main()
