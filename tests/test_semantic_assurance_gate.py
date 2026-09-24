from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import semantic_assurance_gate as gate


class SemanticAssuranceGateNegativeTests(unittest.TestCase):
    CANDIDATE_ENVIRONMENT_VARIABLE = "BLIND_LEDGER_SEMANTIC_CANDIDATE"

    def setUp(self) -> None:
        self.manifest = gate._load_manifest()

    def _actual_candidate(self) -> Path:
        configured = os.environ.get(self.CANDIDATE_ENVIRONMENT_VARIABLE)
        self.assertTrue(
            configured,
            f"{self.CANDIDATE_ENVIRONMENT_VARIABLE} must name the verified external candidate",
        )
        candidate = Path(configured).resolve()
        self.assertTrue(candidate.is_dir(), f"actual candidate is absent: {candidate}")
        self.assertTrue((candidate / ".git").exists(), f"actual candidate is not Git: {candidate}")
        self.assertEqual(
            "",
            self._git_command(candidate, "status", "--porcelain", "--untracked-files=all"),
            f"actual candidate is dirty: {candidate}",
        )
        self.assertEqual(
            self.manifest.candidate["required_head"],
            self._git_command(candidate, "rev-parse", "HEAD"),
        )
        self.assertEqual(
            self.manifest.candidate["required_tree"],
            self._git_command(candidate, "rev-parse", "HEAD^{tree}"),
        )
        return candidate

    def test_missing_candidate_configuration_fails_closed(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(self.CANDIDATE_ENVIRONMENT_VARIABLE, None)
            with self.assertRaisesRegex(
                AssertionError,
                rf"{self.CANDIDATE_ENVIRONMENT_VARIABLE} must name the verified external candidate",
            ):
                self._actual_candidate()

    @staticmethod
    def _git_command(root: Path, *arguments: str) -> str:
        command = ["git", *arguments]
        result = subprocess.run(
            command,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"command failed exit={result.returncode}: {command!r}\n"
                f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
            )
        return result.stdout.strip()

    @classmethod
    def _git_mutation(cls, root: Path, *arguments: str) -> None:
        command = ["git", *arguments]
        result = subprocess.run(
            command,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(
                f"command failed exit={result.returncode}: {command!r}\n"
                f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
            )

    @classmethod
    def _commit_fixture(cls, root: Path, message: str) -> tuple[str, str]:
        cls._git_mutation(root, "add", "--all")
        cls._git_mutation(
            root,
            "-c",
            "user.name=semantic-assurance-test",
            "-c",
            "user.email=semantic-assurance-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            message,
        )
        return (
            cls._git_command(root, "rev-parse", "HEAD"),
            cls._git_command(root, "rev-parse", "HEAD^{tree}"),
        )

    @contextmanager
    def _fresh_candidate(self, mutation):
        actual = self._actual_candidate()
        with tempfile.TemporaryDirectory(prefix="semantic-gate-candidate-") as temporary:
            root = Path(temporary) / "candidate"
            self._git_mutation(
                Path(temporary),
                "clone",
                "--no-local",
                "--quiet",
                str(actual),
                str(root),
            )
            mutation(root)
            head = self._git_command(root, "rev-parse", "HEAD")
            tree = self._git_command(root, "rev-parse", "HEAD^{tree}")
            self.assertEqual(
                "",
                self._git_command(root, "status", "--porcelain", "--untracked-files=all"),
            )
            yield root, head, tree
        self.assertFalse(Path(temporary).exists())
        self.assertEqual(
            "",
            self._git_command(actual, "status", "--porcelain", "--untracked-files=all"),
        )
        print(f"INTEGRATION_FIXTURE_CLEANUP=PASS candidate_temp={temporary}")

    def _test_manifest_for(
        self,
        head: str,
        tree: str,
        *,
        source_files: tuple[str, ...] | None = None,
        forbidden_tokens: tuple[str, ...] | None = None,
    ) -> gate.Manifest:
        candidate_record = dict(self.manifest.candidate)
        candidate_record["required_head"] = head
        candidate_record["required_tree"] = tree
        if source_files is not None:
            candidate_record["source_files"] = list(source_files)
        return replace(
            self.manifest,
            candidate=candidate_record,
            forbidden_tokens=(
                self.manifest.forbidden_tokens
                if forbidden_tokens is None
                else forbidden_tokens
            ),
        )

    def _assert_production_identity_rejection(self, candidate: Path) -> str:
        with self.assertRaisesRegex(gate.AssuranceError, "candidate Git identity mismatch") as raised:
            gate.verify(candidate)
        reason = str(raised.exception)
        print(f"PRODUCTION_MANIFEST_REJECTION={reason}")
        return reason

    def _lean_dir(self, root: Path) -> Path:
        return root / Path(*self.manifest.candidate["lean_root"].split("/"))

    def _native_invocation(self, command) -> bool:
        return (
            len(command) >= 1
            and Path(str(command[0])).name.lower() == "blind_financial.exe"
            and list(command[1:]) == list(self.manifest.native["arguments"])
        )

    def _namespace(self) -> str:
        return str(self.manifest.candidate["namespace"])

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
            qualified = f"{self._namespace()}.{name}"
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
                self._namespace(),
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

    def test_real_removed_theorem_reaches_containing_declaration_gate(self) -> None:
        expectation = self._theorem_expectations()[0]

        def mutate(root: Path) -> None:
            source_path = self._lean_dir(root) / self.manifest.candidate["theorem_source"]
            source = source_path.read_text(encoding="utf-8")
            pattern = re.compile(
                rf"(?ms)^theorem {re.escape(expectation.name)}\b.*?(?=^theorem |\Z)"
            )
            matches = list(pattern.finditer(source))
            self.assertEqual(1, len(matches), expectation.name)
            source_path.write_text(
                source[: matches[0].start()] + source[matches[0].end() :],
                encoding="utf-8",
            )
            self._commit_fixture(root, "remove required theorem for verifier test")

        with self._fresh_candidate(mutate) as (candidate, head, tree):
            production_reason = self._assert_production_identity_rejection(candidate)
            test_manifest = self._test_manifest_for(head, tree)
            with self.assertRaisesRegex(
                gate.AssuranceError,
                rf"required theorem declaration missing: \['{expectation.name}'\]",
            ) as raised:
                gate._verify_candidate(candidate, test_manifest)
            print(
                "INTEGRATION_NEGATIVE "
                f"stage=declaration_presence mutation=removed_theorem name={expectation.name} "
                f"head={head} tree={tree} production={production_reason!r} "
                f"containing={str(raised.exception)!r}"
            )

    def test_real_changed_theorem_reaches_containing_statement_gate(self) -> None:
        (expectation,) = [
            item
            for item in self._theorem_expectations()
            if item.name == "assessCorrectionReuse_never_permits_external_dispatch"
        ]

        def mutate(root: Path) -> None:
            source_path = self._lean_dir(root) / self.manifest.candidate["theorem_source"]
            source = source_path.read_text(encoding="utf-8")
            old = "(assessCorrectionReuse request).externalDispatchPermitted = false := by"
            new = "(assessCorrectionReuse request).externalDispatchPermitted = true := by"
            self.assertEqual(1, source.count(old))
            source_path.write_text(source.replace(old, new, 1), encoding="utf-8")
            self._commit_fixture(root, "change required theorem statement for verifier test")

        with self._fresh_candidate(mutate) as (candidate, head, tree):
            production_reason = self._assert_production_identity_rejection(candidate)
            test_manifest = self._test_manifest_for(head, tree)
            with self.assertRaisesRegex(gate.AssuranceError, "theorem statement changed") as raised:
                gate._verify_candidate(candidate, test_manifest)
            print(
                "INTEGRATION_NEGATIVE "
                f"stage=declaration_statement mutation=changed_theorem name={expectation.name} "
                f"head={head} tree={tree} production={production_reason!r} "
                f"containing={str(raised.exception)!r}"
            )

    def test_real_transitive_custom_axiom_reaches_containing_axiom_gate(self) -> None:
        def mutate(root: Path) -> None:
            injected = self._lean_dir(root) / "BlindLedger" / "Injected.lean"
            injected.write_text(
                f"namespace {self._namespace()}\n\n"
                "axiom injected_custom_axiom : True\n\n"
                f"end {self._namespace()}\n",
                encoding="utf-8",
            )
            source_path = self._lean_dir(root) / self.manifest.candidate["theorem_source"]
            source = source_path.read_text(encoding="utf-8")
            first_import = "import BlindLedger.Financial.CorrectionTransition.Reuse\n"
            proof = "      .SYNTHETIC_RECORD_ONLY := by\n  rfl\n"
            self.assertEqual(1, source.count(first_import))
            self.assertEqual(1, source.count(proof))
            source = source.replace(
                first_import,
                first_import + "import BlindLedger.Injected\n",
                1,
            )
            source = source.replace(
                proof,
                "      .SYNTHETIC_RECORD_ONLY := by\n"
                "  have _h : True := injected_custom_axiom\n"
                "  rfl\n",
                1,
            )
            source_path.write_text(source, encoding="utf-8")
            self._commit_fixture(root, "introduce transitive custom axiom for verifier test")

        with self._fresh_candidate(mutate) as (candidate, head, tree):
            source_files = tuple(
                sorted(
                    (*self.manifest.candidate["source_files"], "BlindLedger/Injected.lean")
                )
            )
            forbidden_tokens = tuple(
                token for token in self.manifest.forbidden_tokens if token != "axiom"
            )
            test_manifest = self._test_manifest_for(
                head,
                tree,
                source_files=source_files,
                forbidden_tokens=forbidden_tokens,
            )
            with patch.object(
                gate, "_parse_axiom_output", wraps=gate._parse_axiom_output
            ) as parser_spy:
                with self.assertRaisesRegex(
                    gate.AssuranceError,
                    "unapproved axiom dependency for "
                    "canonicalActionPayload_dispatch_is_synthetic_record_only",
                ) as raised:
                    gate._verify_candidate(candidate, test_manifest)
            self.assertIsNotNone(parser_spy.call_args)
            axiom_output = parser_spy.call_args.args[0].decode("utf-8")
            self.assertIn(f"{self._namespace()}.injected_custom_axiom", axiom_output)
            print(
                "INTEGRATION_NEGATIVE "
                f"stage=axiom_closure mutation=transitive_custom_axiom head={head} tree={tree} "
                f"containing={str(raised.exception)!r}"
            )
            print("REAL_LEAN_AXIOM_OUTPUT_BEGIN")
            print(axiom_output, end="" if axiom_output.endswith("\n") else "\n")
            print("REAL_LEAN_AXIOM_OUTPUT_END")

    def test_real_source_change_during_verification_reaches_containing_identity_gate(self) -> None:
        def mutate(root: Path) -> None:
            del root

        with self._fresh_candidate(mutate) as (candidate, head, tree):
            source_path = self._lean_dir(candidate) / "BlindLedger" / "Sha3.lean"
            original_run = gate._run
            evidence: dict[str, str] = {}

            def run_and_mutate(command, *, cwd, timeout, env=None, input_bytes=b""):
                result = original_run(
                    command,
                    cwd=cwd,
                    timeout=timeout,
                    env=env,
                    input_bytes=input_bytes,
                )
                if not evidence and result.returncode == 0 and self._native_invocation(command):
                    before_head = self._git_command(candidate, "rev-parse", "HEAD")
                    before_tree = self._git_command(candidate, "rev-parse", "HEAD^{tree}")
                    with source_path.open("a", encoding="utf-8", newline="") as handle:
                        handle.write("\n-- real source identity mutation during verification\n")
                    after_head, after_tree = self._commit_fixture(
                        candidate, "mutate source identity during verifier test"
                    )
                    evidence.update(
                        before_head=before_head,
                        before_tree=before_tree,
                        after_head=after_head,
                        after_tree=after_tree,
                    )
                return result

            with patch.object(gate, "_run", side_effect=run_and_mutate):
                with self.assertRaisesRegex(
                    gate.AssuranceError,
                    "candidate source identity changed during verification",
                ) as raised:
                    gate._verify_candidate(candidate, self.manifest)
            self.assertEqual(head, evidence["before_head"])
            self.assertEqual(tree, evidence["before_tree"])
            self.assertNotEqual(head, evidence["after_head"])
            self.assertNotEqual(tree, evidence["after_tree"])
            print(
                "INTEGRATION_NEGATIVE "
                f"stage=source_identity mutation=real_committed_source_change "
                f"before={evidence['before_head']}/{evidence['before_tree']} "
                f"after={evidence['after_head']}/{evidence['after_tree']} "
                f"containing={str(raised.exception)!r}"
            )

    def test_real_artifact_change_during_verification_reaches_containing_identity_gate(self) -> None:
        with self._fresh_candidate(lambda root: None) as (candidate, head, tree):
            original_run = gate._run
            evidence: dict[str, gate.FileIdentity] = {}

            def run_and_mutate(command, *, cwd, timeout, env=None, input_bytes=b""):
                result = original_run(
                    command,
                    cwd=cwd,
                    timeout=timeout,
                    env=env,
                    input_bytes=input_bytes,
                )
                if not evidence and result.returncode == 0 and self._native_invocation(command):
                    artifact = Path(str(command[0]))
                    evidence["before"] = gate._file_identity(artifact, "real artifact before mutation")
                    with artifact.open("ab") as handle:
                        handle.write(b"\x00")
                    evidence["after"] = gate._file_identity(artifact, "real artifact after mutation")
                return result

            with patch.object(gate, "_run", side_effect=run_and_mutate):
                with self.assertRaisesRegex(
                    gate.AssuranceError,
                    "native artifact changed during execution",
                ) as raised:
                    gate._verify_candidate(candidate, self.manifest)
            self.assertEqual(evidence["before"].bytes + 1, evidence["after"].bytes)
            self.assertNotEqual(evidence["before"].sha256, evidence["after"].sha256)
            print(
                "INTEGRATION_NEGATIVE "
                f"stage=artifact_identity mutation=real_artifact_byte_append head={head} tree={tree} "
                f"before={evidence['before']!r} after={evidence['after']!r} "
                f"containing={str(raised.exception)!r}"
            )

    @contextmanager
    def _copied_toolchain(self):
        installed_root = (
            Path.home()
            / ".elan"
            / "toolchains"
            / "leanprover--lean4---v4.33.1"
        )
        installed_bin = installed_root / "bin"
        self.assertTrue(installed_bin.is_dir(), f"installed toolchain is absent: {installed_bin}")
        with tempfile.TemporaryDirectory(prefix="semantic-gate-toolchain-") as temporary:
            home = Path(temporary)
            copied_root = home / ".elan" / "toolchains" / installed_root.name
            copied_bin = copied_root / "bin"
            copied_bin.mkdir(parents=True)
            for executable in installed_bin.iterdir():
                if executable.is_file():
                    shutil.copy2(executable, copied_bin / executable.name)
            junctions = []
            try:
                for directory_name in ("lib", "include", "share", "src"):
                    link = copied_root / directory_name
                    result = subprocess.run(
                        [
                            "cmd.exe",
                            "/d",
                            "/c",
                            "mklink",
                            "/J",
                            str(link),
                            str(installed_root / directory_name),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=False,
                    )
                    if result.returncode != 0:
                        raise AssertionError(
                            f"junction creation failed exit={result.returncode}: "
                            f"stdout={result.stdout!r} stderr={result.stderr!r}"
                        )
                    junctions.append(link)
                yield home, copied_bin
            finally:
                for link in reversed(junctions):
                    if os.path.lexists(link):
                        link.rmdir()
        self.assertFalse(Path(temporary).exists())
        print(f"TOOLCHAIN_FIXTURE_CLEANUP=PASS temp={temporary}")

    def test_real_tool_change_during_verification_reaches_containing_identity_gate(self) -> None:
        if os.name != "nt" or platform.machine().lower() not in {"amd64", "x86_64"}:
            self.skipTest("copied Lean toolchain integration requires Windows x86_64")
        with self._fresh_candidate(lambda root: None) as (candidate, head, tree):
            with self._copied_toolchain() as (home, copied_bin):
                original_run = gate._run
                evidence: dict[str, gate.FileIdentity] = {}

                def run_and_mutate(command, *, cwd, timeout, env=None, input_bytes=b""):
                    result = original_run(
                        command,
                        cwd=cwd,
                        timeout=timeout,
                        env=env,
                        input_bytes=input_bytes,
                    )
                    if not evidence and result.returncode == 0 and self._native_invocation(command):
                        tool = copied_bin / "lean.exe"
                        evidence["before"] = gate._file_identity(tool, "real copied tool before mutation")
                        with tool.open("ab") as handle:
                            handle.write(b"\x00")
                        evidence["after"] = gate._file_identity(tool, "real copied tool after mutation")
                    return result

                with patch.object(gate.Path, "home", return_value=home), patch.object(
                    gate, "_run", side_effect=run_and_mutate
                ):
                    with self.assertRaisesRegex(
                        gate.AssuranceError,
                        "pinned lean executable changed during execution",
                    ) as raised:
                        gate._verify_candidate(candidate, self.manifest)
                self.assertEqual(evidence["before"].bytes + 1, evidence["after"].bytes)
                self.assertNotEqual(evidence["before"].sha256, evidence["after"].sha256)
                print(
                    "INTEGRATION_NEGATIVE "
                    f"stage=toolchain_identity mutation=real_copied_lean_byte_append "
                    f"head={head} tree={tree} before={evidence['before']!r} "
                    f"after={evidence['after']!r} containing={str(raised.exception)!r}"
                )


if __name__ == "__main__":
    unittest.main()
