"""Synthetic acceptance negatives; no live credentials or production data."""

from __future__ import annotations

from contextlib import redirect_stdout
from hashlib import sha256
import json
from io import BytesIO, StringIO
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

from tools import deployment_bundle as bundle
from tools import privacy_artifact_scan
from tools import project_acceptance as gate


def _roots() -> dict[str, gate.RootIdentity]:
    return {
        role: gate.RootIdentity(
            role=role,
            path=f"/synthetic/{directory}",
            head=gate.BASELINE_HEADS[role],
            tree="a" * 40,
            status_sha256="b" * 64,
            dirty=(),
            new_paths=(),
            new_modules=(),
            protected_changes=(),
        )
        for role, directory in gate.ACTIVE_ROOTS.items()
    }


def _with_dirty(
    roots: dict[str, gate.RootIdentity], role: str, path: str, *,
    new: bool = False, protected: bool = False,
) -> dict[str, gate.RootIdentity]:
    previous = roots[role]
    roots[role] = gate.RootIdentity(
        role=role,
        path=previous.path,
        head=previous.head,
        tree=previous.tree,
        status_sha256="c" * 64,
        dirty=((path, "d" * 64),),
        new_paths=(path,) if new else (),
        new_modules=(path,) if new else (),
        protected_changes=(path,) if protected else (),
    )
    return roots


def _evidence(roots: dict[str, gate.RootIdentity]) -> dict[str, dict[str, object]]:
    sources = {
        role: sha256(json.dumps(identity.as_record(), sort_keys=True).encode()).hexdigest()
        for role, identity in roots.items()
    }
    return {
        check: {
            "status": "PASS",
            "source_sha256": sources,
            "command": ["python", "-m", "unittest", "synthetic"],
            "exit_code": 0,
            "tests": 1,
            "raw_sha256": "e" * 64,
        }
        for check in gate.REQUIRED_FINANCIAL_CHECKS
    }


def _observed(roots: dict[str, gate.RootIdentity]) -> dict[str, dict[str, object]]:
    checks: dict[str, dict[str, object]] = {
        f"{role}:inventory_paths": {"status": "PASS"} for role in roots
    }
    checks["qualification:tracked_paths"] = {"status": "PASS"}
    checks["qualification:ops_authority"] = {"status": "PASS"}
    checks["qualification:acceptance_selftest"] = {"status": "PASS"}
    checks["qualification:deployment_bundle"] = {"status": "PASS_LOCAL_STRUCTURAL"}
    for role, identity in roots.items():
        if any(path.endswith(".md") for path, _ in identity.dirty) or any(
            path.endswith(".md") for path in identity.committed_changes
        ):
            checks[f"{role}:documentation"] = {"status": "PASS"}
    return checks


def _bundle_workspace(root: Path) -> Path:
    (root / "WORKSPACE_MAP.md").write_text("synthetic workspace\n", encoding="utf-8")
    work = root / "work"
    work.mkdir()
    for repository, directory in bundle.PROJECT_ROOTS.items():
        repo_root = work / directory
        repo_root.mkdir()
        for command in (
            ("git", "init", "-q"),
            ("git", "config", "user.email", "test@example.invalid"),
            ("git", "config", "user.name", "Synthetic Test"),
        ):
            subprocess.run(command, cwd=repo_root, check=True, capture_output=True)
        for spec in bundle.FILE_SPECS:
            if spec.repository != repository:
                continue
            source = repo_root.joinpath(*spec.path.split("/"))
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(f"synthetic:{spec.file_id}\n".encode("ascii"))
        subprocess.run(("git", "add", "-A"), cwd=repo_root, check=True, capture_output=True)
        subprocess.run(("git", "commit", "-qm", "synthetic baseline"), cwd=repo_root, check=True, capture_output=True)
    return root


def _run_evidence(check_id: str, source_identity: str) -> dict[str, object]:
    guard_stdout = (
        "PHYSICAL_PREFLIGHT free_bytes=3500000000 reserve_bytes=3221225472 "
        "reserve_floor_bytes=2190433321 target_start_floor_bytes=3221225472 "
        "effective_start_floor_bytes=3221225472 tolerance_percent=32\n"
        "CHILD_EXIT_STATUS label=child-exit-7 exit=7\n"
        "CLEANUP=PASS label=child-exit-7 owned_process_tree=empty\n"
        "CHILD_EXIT_STATUS label=child-exit-0 exit=0\n"
        "CLEANUP=PASS label=child-exit-0 owned_process_tree=empty\n"
        "CHILD_EXIT_CHECK exit7=7 exit0=0\n"
        "CHILD_EXIT_STATUS label=Command exit=0\n"
        "CLEANUP=PASS label=Command owned_process_tree=empty\n"
        "MUTEX=RELEASED name=Local\\BlindLedgerDirectMaskBuild20260907\n"
    ).encode("utf-8")
    return {
        "id": check_id,
        "status": "PASS",
        "source_identity_sha256": source_identity,
        "command": ["python", "-m", "unittest", "tests.test_project_acceptance"],
        "runner_id": "",
        "issuer_id": "",
        "revocation_snapshot_sha256": None,
        "signature": "",
        "issued_at_utc": "2026-01-01T00:00:00Z",
        "expires_at_utc": "9999-12-31T23:59:59Z",
        "tests": 1,
        "skipped": 0,
        "child_exit_code": 0,
        "outer_exit_code": 0,
        "guard_sha256": bundle.GUARD_SHA256,
        "target_start_floor_bytes": 3_221_225_472,
        "preflight_free_bytes": 3_500_000_000,
        "physical_free_floor_bytes": bundle.PHYSICAL_FREE_FLOOR_BYTES,
        "cleanup": "PASS",
        "mutex": "RELEASED",
        "command_stdout": b"Ran 1 test in 0.01s\nOK\n",
        "command_stderr": b"",
        "guard_stdout": guard_stdout,
        "guard_stderr": b"",
    }


class ProjectAcceptanceTests(unittest.TestCase):
    def test_valid_ordinary_document_change_passes_development_only(self) -> None:
        roots = _with_dirty(_roots(), "qualification", "docs/QUALIFICATION_GATE_V3_CANDIDATE.md")
        self.assertEqual("PASS_DEVELOPMENT", gate.assess(roots, observed_checks=_observed(roots))["status"])
        broader = gate.assess(roots, phase="integration", observed_checks=_observed(roots))
        self.assertEqual("INCOMPLETE", broader["status"])
        self.assertIn("trusted_runner_and_release_authorization_not_configured", broader["reasons"])

    def test_new_module_and_protected_requirement_change_need_review(self) -> None:
        roots = _with_dirty(_roots(), "provider", "provider_app/new_route.py", new=True)
        result = gate.assess(roots)
        self.assertIn("unclassified_new_paths", result["reasons"])
        self.assertIn("provider:provider_app/new_route.py", result["new_modules"])
        roots = _with_dirty(_roots(), "qualification", "tools/project_acceptance.py", protected=True)
        result = gate.assess(roots)
        self.assertIn("protected_changes_require_independent_review", result["reasons"])

    def test_missing_disabled_empty_and_stale_financial_checks_stay_incomplete(self) -> None:
        roots = _with_dirty(_roots(), "financial", "app/right_rail_financial_owner.py")
        missing = gate.assess(roots)
        self.assertEqual(4, len(missing["financial_checks"]))
        self.assertEqual({"MISSING"}, {item["status"] for item in missing["financial_checks"]})
        evidence = _evidence(roots)
        evidence["lean_transition_execution"]["status"] = "DISABLED"
        evidence["financial_atomic_commit_and_retry"]["tests"] = 0
        evidence["independent_expected_answers"]["source_sha256"] = {"financial": "f" * 64}
        result = gate.assess(roots, evidence)
        statuses = {item["id"]: item["status"] for item in result["financial_checks"]}
        self.assertEqual("FAILED", statuses["lean_transition_execution"])
        self.assertEqual("EMPTY", statuses["financial_atomic_commit_and_retry"])
        self.assertEqual("STALE", statuses["independent_expected_answers"])
        self.assertEqual("INCOMPLETE", result["status"])

    def test_supplied_green_metadata_cannot_self_certify(self) -> None:
        roots = _with_dirty(_roots(), "financial", "app/right_rail_financial_owner.py")
        result = gate.assess(roots, _evidence(roots))
        self.assertEqual("INCOMPLETE", result["status"])
        self.assertIn("supplied_check_records_unverified", result["reasons"])

    def test_committed_financial_change_still_requires_financial_checks(self) -> None:
        roots = _roots()
        original = roots["financial"]
        roots["financial"] = gate.RootIdentity(
            role=original.role,
            path=original.path,
            head="c" * 40,
            tree="d" * 40,
            status_sha256=original.status_sha256,
            dirty=(),
            new_paths=(),
            new_modules=(),
            protected_changes=(),
            committed_changes=("app/right_rail_financial_owner.py",),
        )
        result = gate.assess(roots, observed_checks=_observed(roots))
        self.assertEqual("INCOMPLETE", result["status"])
        self.assertEqual(4, len(result["financial_checks"]))
        self.assertEqual({"MISSING"}, {item["status"] for item in result["financial_checks"]})

    def test_financial_tool_and_existing_config_changes_do_not_pass(self) -> None:
        roots = _with_dirty(_roots(), "financial", "tools/right_rail_financial_cli.py")
        result = gate.assess(roots, observed_checks=_observed(roots))
        self.assertEqual(4, len(result["financial_checks"]))
        self.assertIn("required_financial_checks_incomplete", result["reasons"])
        roots = _with_dirty(_roots(), "provider", "pyproject.toml")
        result = gate.assess(roots, observed_checks=_observed(roots))
        self.assertIn("configuration_change_requires_applicable_check_review", result["reasons"])

    def test_ignored_source_candidate_blocks_development(self) -> None:
        roots = _roots()
        original = roots["provider"]
        roots["provider"] = gate.RootIdentity(
            role=original.role, path=original.path, head=original.head,
            tree=original.tree, status_sha256=original.status_sha256,
            dirty=(), new_paths=(), new_modules=(), protected_changes=(),
            ignored_candidates=("app/hidden.py",),
        )
        result = gate.assess(roots, observed_checks=_observed(roots))
        self.assertIn("ignored_source_or_config_requires_review", result["reasons"])

    def test_forbidden_synthetic_output_is_detected_by_existing_scanner(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightrail-privacy-fixture-") as directory:
            root = Path(directory)
            (root / "batch_package.json").write_text("{}", encoding="utf-8")
            findings = privacy_artifact_scan.scan_artifacts(root)
            self.assertTrue(any("forbidden_plaintext_filename" in item for item in findings), findings)

    def test_real_git_inventory_detects_new_module_and_dirty_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightrail-inventory-fixture-") as directory:
            root = Path(directory)
            for command in (
                ("git", "init", "-q"),
                ("git", "config", "user.email", "test@example.invalid"),
                ("git", "config", "user.name", "Synthetic Test"),
            ):
                subprocess.run(command, cwd=root, check=True, capture_output=True)
            (root / "known.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "AGENTS.md").write_text("preserve safety\n", encoding="utf-8")
            subprocess.run(("git", "add", "known.py", "AGENTS.md"), cwd=root, check=True, capture_output=True)
            subprocess.run(("git", "commit", "-qm", "baseline"), cwd=root, check=True, capture_output=True)
            baseline = subprocess.check_output(("git", "rev-parse", "HEAD"), cwd=root).decode().strip()
            (root / "known.py").write_text("VALUE = 2\n", encoding="utf-8")
            (root / "new.py").write_text("VALUE = 3\n", encoding="utf-8")
            identity = gate.inventory_root("synthetic", root, baseline)
            self.assertEqual(("new.py",), identity.new_modules)
            self.assertEqual(("new.py",), identity.new_paths)
            self.assertEqual({"known.py", "new.py"}, {path for path, _ in identity.dirty})
            self.assertEqual(sha256(b"VALUE = 2\n").hexdigest(), dict(identity.dirty)["known.py"])
            (root / "AGENTS.md").write_text("disable safety\n", encoding="utf-8")
            subprocess.run(("git", "add", "AGENTS.md"), cwd=root, check=True, capture_output=True)
            subprocess.run(("git", "commit", "-qm", "changed instructions"), cwd=root, check=True, capture_output=True)
            changed = gate.inventory_root("synthetic", root, baseline)
            self.assertIn("AGENTS.md", changed.protected_changes)
            (root / ".gitignore").write_text("hidden.py\n", encoding="utf-8")
            (root / "hidden.py").write_text("VALUE = 4\n", encoding="utf-8")
            ignored = gate.inventory_root("synthetic", root, baseline)
            self.assertIn("hidden.py", ignored.ignored_candidates)


class DeploymentBundleTests(unittest.TestCase):
    def test_bundle_is_deterministic_and_contains_real_source_payloads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightrail-bundle-") as directory:
            workspace = _bundle_workspace(Path(directory))
            first, report = bundle.build_candidate(workspace)
            second, second_report = bundle.build_candidate(workspace)
            self.assertEqual(first, second)
            self.assertEqual(report["archive_sha256"], second_report["archive_sha256"])
            validation = bundle.validate_bundle_bytes(first)
            self.assertTrue(validation["structural_valid"])
            self.assertEqual(report["archive_sha256"], validation["archive_sha256"])
            with zipfile.ZipFile(BytesIO(first)) as archive:
                manifest = json.loads(archive.read(bundle.MANIFEST_NAME))
                files = {row["id"]: row for row in manifest["files"]}
                owner_path = "payload/financial/app/right_rail_financial_owner.py"
                lean_path = "payload/engine/semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/Transition.lean"
                self.assertEqual(b"synthetic:financial.owner\n", archive.read(owner_path))
                self.assertEqual(b"synthetic:engine.transition\n", archive.read(lean_path))
                executable = files["engine.executable"]
                self.assertTrue(executable["present"])
                self.assertFalse(executable["included"])
                self.assertIsNone(executable["archive_path"])
                self.assertEqual(
                    {"proofSuiteId": None, "production_usable": False, "activation": False},
                    manifest["claims"],
                )
                self.assertEqual(7, manifest["compatibility"]["owner_default_schema_version"])
                self.assertIsNone(manifest["compatibility"]["selected_owner_schema_version"])
                self.assertEqual("NOT_RUN", manifest["phase_claims"]["developer_smoke"]["status"])
                self.assertEqual("BLOCKED", manifest["phase_claims"]["integration"]["status"])
                self.assertEqual("BLOCKED", manifest["phase_claims"]["release"]["status"])
                self.assertEqual("UNSELECTED", manifest["phase_claims"]["activation"]["status"])
                self.assertEqual(8, len(manifest["external_gates"]))

    def test_cli_verifies_archive_and_current_source_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightrail-bundle-verify-") as directory:
            workspace = _bundle_workspace(Path(directory))
            archive, _ = bundle.build_candidate(workspace)
            archive_path = Path(directory) / "candidate.zip"
            archive_path.write_bytes(archive)
            output = StringIO()
            with redirect_stdout(output):
                exit_code = bundle.main([
                    "--verify-bundle", str(archive_path),
                    "--workspace-root", str(workspace),
                ])
            result = json.loads(output.getvalue())
            self.assertEqual(0, exit_code)
            self.assertEqual("PASS_STRUCTURE_ONLY", result["status"])
            self.assertTrue(result["archive_validation"]["structural_valid"])
            self.assertTrue(result["live_source_validation"]["source_snapshot_matches"])

            archive_path.write_bytes(b"not a bundle")
            output = StringIO()
            with redirect_stdout(output):
                exit_code = bundle.main(["--verify-bundle", str(archive_path)])
            self.assertEqual(2, exit_code)
            self.assertEqual("BLOCKED", json.loads(output.getvalue())["status"])

    def test_archive_rejects_changed_payload_and_claims(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightrail-bundle-tamper-") as directory:
            workspace = _bundle_workspace(Path(directory))
            archive, _ = bundle.build_candidate(workspace)
            manifest, payloads = bundle._manifest_from_zip(archive)
            source_member = "payload/engine/semantic_kernel/lean/BlindLedger/Financial/CorrectionTransition/Transition.lean"
            payloads[source_member] += b"tamper"
            altered_payload = bundle._make_zip(bundle._canonical_json(manifest), payloads)
            with self.assertRaises(bundle.DeploymentBundleError):
                bundle.validate_bundle_bytes(altered_payload)

            manifest, payloads = bundle._manifest_from_zip(archive)
            manifest["claims"]["activation"] = True
            altered_claim = bundle._make_zip(bundle._canonical_json(manifest), payloads)
            with self.assertRaises(bundle.DeploymentBundleError):
                bundle.validate_bundle_bytes(altered_claim)

    def test_stale_empty_failed_and_skipped_evidence_stays_visible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightrail-bundle-evidence-") as directory:
            workspace = _bundle_workspace(Path(directory))
            initial, _ = bundle.build_candidate(workspace)
            manifest, _ = bundle._manifest_from_zip(initial)
            identity = manifest["source_identity_sha256"]
            smoke_failure = _run_evidence("developer_smoke.bundle_tests", identity)
            smoke_failure["status"] = "FAIL"
            failed = _run_evidence("engine.theorem_axiom_check", identity)
            failed["status"] = "FAIL"
            stale = _run_evidence("engine.executable_provenance", identity)
            stale["source_identity_sha256"] = "f" * 64
            empty = _run_evidence("engine.canonical_wire_vectors", identity)
            empty["tests"] = 0
            skipped = _run_evidence("state.atomic_adapter_integration", identity)
            skipped["skipped"] = 1

            archive, report = bundle.build_candidate(
                workspace,
                evidence_records=(smoke_failure, failed, stale, empty, skipped),
                evidence_evaluated_at_utc="2026-06-01T00:00:00.000000Z",
            )
            statuses = report["evidence_statuses"]
            self.assertEqual("FAILED", statuses["developer_smoke.bundle_tests"])
            self.assertEqual("FAILED", statuses["engine.theorem_axiom_check"])
            self.assertEqual("STALE", statuses["engine.executable_provenance"])
            self.assertEqual("EMPTY", statuses["engine.canonical_wire_vectors"])
            self.assertEqual("SKIPPED", statuses["state.atomic_adapter_integration"])
            validation = bundle.validate_bundle_bytes(archive)
            self.assertEqual("BLOCKED", validation["phase_claims"]["developer_smoke"]["status"])
            self.assertEqual("BLOCKED", validation["phase_claims"]["integration"]["status"])
            with zipfile.ZipFile(BytesIO(archive)) as zipped:
                self.assertEqual(
                    failed["command_stdout"],
                    zipped.read("evidence/engine.theorem_axiom_check/command_stdout.log"),
                )
                self.assertEqual(
                    failed["guard_stdout"],
                    zipped.read("evidence/engine.theorem_axiom_check/guard_stdout.log"),
                )

    def test_evidence_freshness_uses_an_explicit_reproducible_time(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightrail-bundle-evidence-time-") as directory:
            workspace = _bundle_workspace(Path(directory))
            initial, _ = bundle.build_candidate(workspace)
            manifest, _ = bundle._manifest_from_zip(initial)
            record = _run_evidence("developer_smoke.bundle_tests", manifest["source_identity_sha256"])
            record["expires_at_utc"] = "2026-05-31T23:59:59Z"
            with self.assertRaisesRegex(bundle.DeploymentBundleError, "explicit canonical"):
                bundle.build_candidate(workspace, evidence_records=(record,))

            evaluated_at = "2026-06-01T00:00:00.000000Z"
            first, report = bundle.build_candidate(
                workspace,
                evidence_records=(record,),
                evidence_evaluated_at_utc=evaluated_at,
            )
            second, _ = bundle.build_candidate(
                workspace,
                evidence_records=(record,),
                evidence_evaluated_at_utc=evaluated_at,
            )
            self.assertEqual(first, second)
            self.assertEqual("STALE", report["evidence_statuses"]["developer_smoke.bundle_tests"])
            self.assertEqual(evaluated_at, report["evidence_evaluated_at_utc"])
            validation = bundle.validate_bundle_bytes(first)
            self.assertEqual("STALE", validation["evidence_statuses"]["developer_smoke.bundle_tests"])

    def test_self_asserted_signature_does_not_close_release_or_integration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightrail-bundle-self-assert-") as directory:
            workspace = _bundle_workspace(Path(directory))
            initial, _ = bundle.build_candidate(workspace)
            manifest, _ = bundle._manifest_from_zip(initial)
            record = _run_evidence("developer_smoke.bundle_tests", manifest["source_identity_sha256"])
            record["runner_id"] = "self-asserted-runner"
            record["issuer_id"] = "self-asserted-issuer"
            record["signature"] = "self-asserted-signature"
            record["revocation_snapshot_sha256"] = "a" * 64
            archive, report = bundle.build_candidate(
                workspace,
                evidence_records=(record,),
                evidence_evaluated_at_utc="2026-06-01T00:00:00.000000Z",
            )
            self.assertEqual("RECORDED_UNVERIFIED", report["evidence_statuses"]["developer_smoke.bundle_tests"])
            validation = bundle.validate_bundle_bytes(archive)
            self.assertEqual("BLOCKED", validation["phase_claims"]["integration"]["status"])
            self.assertEqual("BLOCKED", validation["phase_claims"]["release"]["status"])

    def test_source_drift_keeps_unaffected_component_identities_usable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightrail-bundle-drift-") as directory:
            workspace = _bundle_workspace(Path(directory))
            archive, _ = bundle.build_candidate(workspace)
            financial_root = workspace / "work" / bundle.PROJECT_ROOTS["financial"]
            style = financial_root / "app" / "staff_workspace" / "staff.css"
            style.write_bytes(style.read_bytes() + b"changed\n")
            result = bundle.validate_live_sources(archive, workspace)
            self.assertFalse(result["source_snapshot_matches"])
            self.assertEqual("STALE", result["component_statuses"]["report"])
            self.assertEqual("USABLE_SOURCE_IDENTITY", result["component_statuses"]["state.owner"])
            self.assertEqual("USABLE_SOURCE_IDENTITY", result["component_statuses"]["engine.semantic_source"])
            self.assertEqual("BLOCKED", result["release_status"])

    def test_missing_required_source_blocks_assembly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rightrail-bundle-missing-") as directory:
            workspace = _bundle_workspace(Path(directory))
            engine_root = workspace / "work" / bundle.PROJECT_ROOTS["engine"]
            (engine_root / "semantic_kernel" / "lean" / "BlindLedger" / "Financial" / "CorrectionTransition" / "Runtime.lean").unlink()
            with self.assertRaisesRegex(bundle.DeploymentBundleError, "required source file is missing: engine.runtime"):
                bundle.build_candidate(workspace)


if __name__ == "__main__":
    unittest.main()
