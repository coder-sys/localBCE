from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import semantic_assurance_gate as gate


class SemanticAssuranceGateNegativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = gate._load_manifest()

    def _theorem_expectations(self) -> tuple[gate.DeclarationExpectation, ...]:
        theorem_source = self.manifest.candidate["theorem_source"]
        declaration_sources = self.manifest.candidate["declaration_sources"]
        return tuple(
            expectation
            for expectation in self.manifest.declarations
            if declaration_sources[expectation.name] == theorem_source
        )

    @staticmethod
    def _synthetic_source(
        expectations: tuple[gate.DeclarationExpectation, ...],
        *,
        omit: str | None = None,
        change: str | None = None,
    ) -> str:
        declarations = []
        for expectation in expectations:
            if expectation.name == omit:
                continue
            statement = "False" if expectation.name == change else expectation.source_statement
            declarations.append(f"theorem {expectation.name} : {statement} := by\n  trivial")
        return "\n\n".join(declarations) + "\n"

    def test_removed_required_theorem_reaches_declaration_presence_check(self) -> None:
        expectations = self._theorem_expectations()
        omitted = expectations[0].name
        with self.assertRaisesRegex(
            gate.AssuranceError,
            rf"required theorem declaration missing: \['{omitted}'\]",
        ):
            gate._parse_source_declarations(
                self._synthetic_source(expectations, omit=omitted), expectations
            )

    def test_changed_theorem_statement_reaches_statement_check(self) -> None:
        expectations = self._theorem_expectations()
        changed = expectations[0].name
        with self.assertRaisesRegex(gate.AssuranceError, "theorem statement changed"):
            gate._parse_source_declarations(
                self._synthetic_source(expectations, change=changed), expectations
            )

    def test_unapproved_transitive_axiom_reaches_axiom_closure_check(self) -> None:
        declarations = tuple(expectation.name for expectation in self.manifest.declarations)
        lines = []
        for index, name in enumerate(declarations):
            qualified = f"BlindLedger.Kernel.{name}"
            if index == 0:
                lines.append(
                    f"'{qualified}' depends on axioms: [propext, BlindLedger.injected_custom_axiom]"
                )
            else:
                lines.append(f"'{qualified}' does not depend on any axioms")
        with self.assertRaisesRegex(gate.AssuranceError, "unapproved axiom dependency"):
            gate._parse_axiom_output(
                ("\n".join(lines) + "\n").encode("ascii"),
                declarations,
                self.manifest.allowed_axioms,
            )

    def test_changed_candidate_source_identity_reaches_identity_check(self) -> None:
        before = (
            "a" * 64,
            (gate.FileIdentity("BlindLedger/Theorems.lean", 10, "b" * 64),),
        )
        after = (
            "c" * 64,
            (gate.FileIdentity("BlindLedger/Theorems.lean", 11, "d" * 64),),
        )
        with self.assertRaisesRegex(
            gate.AssuranceError, "candidate source identity changed during verification"
        ):
            gate._require_source_identity_unchanged(before, after)

    def test_changed_toolchain_identity_reaches_executable_digest_check(self) -> None:
        toolchain = deepcopy(self.manifest.toolchain)
        version = str(toolchain["descriptor"]).split(":", 1)[1]
        with tempfile.TemporaryDirectory(prefix="semantic-gate-toolchain-identity-") as temporary:
            home = Path(temporary)
            bindir = home / ".elan" / "toolchains" / f"leanprover--lean4---{version}" / "bin"
            bindir.mkdir(parents=True)
            for name, record in toolchain["executables"].items():
                content = f"synthetic {name}\n".encode("ascii")
                (bindir / f"{name}.exe").write_bytes(content)
                record["bytes"] = len(content)
                record["sha256"] = gate.hashlib.sha256(content).hexdigest()
            bad_toolchain = deepcopy(toolchain)
            bad_toolchain["executables"]["lean"]["sha256"] = "0" * 64
            staged = replace(self.manifest, toolchain=bad_toolchain)
            with patch.object(gate.Path, "home", return_value=home):
                with self.assertRaisesRegex(
                    gate.AssuranceError, "pinned lean executable identity changed"
                ):
                    gate._toolchain_paths(staged)

    def test_changed_toolchain_identity_during_execution_reaches_identity_check(self) -> None:
        with tempfile.TemporaryDirectory(prefix="semantic-gate-toolchain-runtime-") as temporary:
            path = Path(temporary) / "lean.exe"
            path.write_bytes(b"toolchain")
            before = {
                "lean": {
                    "path": str(path.resolve()),
                    "bytes": len(b"toolchain"),
                    "sha256": "0" * 64,
                }
            }
            with self.assertRaisesRegex(
                gate.AssuranceError,
                "pinned lean executable changed during execution",
            ):
                gate._require_toolchain_identity_unchanged({"lean": path}, before)

    def test_changed_native_artifact_identity_reaches_before_after_check(self) -> None:
        before = gate.FileIdentity("artifact.exe", 3, "a" * 64)
        after = gate.FileIdentity("artifact.exe", 4, "b" * 64)
        with self.assertRaisesRegex(
            gate.AssuranceError, "native artifact changed during execution"
        ):
            gate._require_identity_unchanged("native artifact", before, after)

    def test_source_scan_reports_the_actual_scanned_file_count(self) -> None:
        with tempfile.TemporaryDirectory(prefix="semantic-gate-source-scan-") as temporary:
            root = Path(temporary)
            (root / "one.lean").write_text("def one := 1\n", encoding="utf-8")
            (root / "two.toml").write_text("name = 'two'\n", encoding="utf-8")
            result = gate._check_forbidden_sources(
                root, ("one.lean", "two.toml"), self.manifest.forbidden_tokens
            )
        self.assertEqual(
            {"files_scanned": 2, "forbidden_token_matches": 0},
            result,
        )

    def test_source_scan_uses_manifest_token_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="semantic-gate-source-token-") as temporary:
            root = Path(temporary)
            (root / "source.lean").write_text("def forbidden_marker := 1\n", encoding="utf-8")
            with self.assertRaisesRegex(
                gate.AssuranceError, "forbidden source token 'forbidden_marker'"
            ):
                gate._check_forbidden_sources(
                    root, ("source.lean",), ("forbidden_marker",)
                )


if __name__ == "__main__":
    unittest.main()
