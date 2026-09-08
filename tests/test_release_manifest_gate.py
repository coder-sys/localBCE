from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tools import build_release_archive as archive_builder
from tools import release_manifest_gate as gate


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def _committed_fixture():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        repository = root / "repository"
        repository.mkdir()
        files = {
            "README.md": b"# synthetic release fixture\n",
            "docs/DESIGN_IDEOLOGY.md": b"# canonical design fixture\n",
            "tools/release_manifest_gate.py": b"synthetic module bytes\n",
        }
        files.update(
            {
                relative: subprocess.check_output(
                    ["git", "show", f"HEAD:{relative}"],
                    cwd=REPOSITORY_ROOT,
                )
                for relative in gate.POLICY_INPUT_SHA256
            }
        )
        for relative, data in files.items():
            path = repository.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for command in (
            ["git", "init", "-q"],
            ["git", "config", "user.name", "lane-c-test"],
            ["git", "config", "user.email", "lane-c-test@example.invalid"],
            ["git", "config", "core.autocrlf", "false"],
            ["git", "add", "."],
            ["git", "commit", "-q", "-m", "fixture"],
        ):
            subprocess.run(command, cwd=repository, check=True, capture_output=True)
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        yield root, repository, files, revision


def _stage(repository: Path, source_root: Path, paths: tuple[str, ...]) -> None:
    for relative in paths:
        destination = source_root.joinpath(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(repository.joinpath(*relative.split("/")), destination)


class ReleaseManifestGateTests(unittest.TestCase):
    def test_cli_emits_only_a_deterministic_receipt(self) -> None:
        with _committed_fixture() as (root, repository, files, revision):
            stage = root / "stage"
            stage.mkdir()
            paths = tuple(files)
            _stage(repository, stage, paths)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tools.release_manifest_gate",
                    "--git-root",
                    str(repository),
                    "--source-root",
                    str(stage),
                    "--output",
                    str(stage / gate.SOURCE_MANIFEST_NAME),
                    "--revision",
                    revision,
                ],
                cwd=REPOSITORY_ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("", result.stderr)
            receipt = json.loads(result.stdout)
            self.assertEqual(gate.POLICY_VERSION, receipt["policy_version"])
            self.assertEqual(len(paths), receipt["payload_file_count"])

    def test_manifest_is_deterministic_and_builder_v2_compatible(self) -> None:
        with _committed_fixture() as (root, repository, files, revision):
            paths = tuple(files)
            stage_a = root / "stage-a"
            stage_b = root / "stage-b"
            stage_a.mkdir()
            stage_b.mkdir()
            _stage(repository, stage_a, paths)
            _stage(repository, stage_b, tuple(reversed(paths)))

            receipt_a = gate.generate_manifest(
                git_root=repository,
                source_root=stage_a,
                output_path=stage_a / gate.SOURCE_MANIFEST_NAME,
                revision=revision,
                selected_paths=tuple(reversed(paths)),
            )
            receipt_b = gate.generate_manifest(
                git_root=repository,
                source_root=stage_b,
                output_path=stage_b / gate.SOURCE_MANIFEST_NAME,
                revision=revision,
                selected_paths=paths,
            )
            raw_a = (stage_a / gate.SOURCE_MANIFEST_NAME).read_bytes()
            raw_b = (stage_b / gate.SOURCE_MANIFEST_NAME).read_bytes()
            self.assertEqual(raw_a, raw_b)
            self.assertEqual(receipt_a, receipt_b)

            document = json.loads(raw_a)
            self.assertEqual(
                {"archive_root", "files", "manifest_version"}, set(document)
            )
            self.assertEqual(2, document["manifest_version"])
            self.assertEqual(
                tuple(sorted(paths)), tuple(entry["path"] for entry in document["files"])
            )
            parsed_raw, archive_root, entries = archive_builder._read_manifest(
                stage_a / gate.SOURCE_MANIFEST_NAME
            )
            self.assertEqual(raw_a, parsed_raw)
            self.assertEqual("Blind-Ledger-Release", archive_root)
            self.assertEqual(document["files"], entries)

    def test_hash_and_size_are_from_exact_committed_blob_bytes(self) -> None:
        with _committed_fixture() as (root, repository, files, revision):
            paths = tuple(files)
            stage = root / "stage"
            stage.mkdir()
            _stage(repository, stage, paths)
            gate.generate_manifest(
                git_root=repository,
                source_root=stage,
                output_path=stage / gate.SOURCE_MANIFEST_NAME,
                revision=revision,
                selected_paths=paths,
            )
            document = json.loads((stage / gate.SOURCE_MANIFEST_NAME).read_text("utf-8"))
            for entry in document["files"]:
                data = files[entry["path"]]
                self.assertEqual(len(data), entry["size"])
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])

    def test_source_drift_and_missing_selection_fail_closed(self) -> None:
        with _committed_fixture() as (root, repository, files, revision):
            paths = tuple(files)
            stage = root / "stage"
            stage.mkdir()
            _stage(repository, stage, paths)
            (stage / "README.md").write_bytes(b"tampered\n")
            with self.assertRaisesRegex(gate.ManifestGateError, "do not match selected commit"):
                gate.generate_manifest(
                    git_root=repository,
                    source_root=stage,
                    output_path=stage / gate.SOURCE_MANIFEST_NAME,
                    revision=revision,
                    selected_paths=paths,
                )

            (stage / "README.md").write_bytes(files["README.md"])
            with self.assertRaisesRegex(gate.ManifestGateError, "does not exactly match"):
                gate.generate_manifest(
                    git_root=repository,
                    source_root=stage,
                    output_path=stage / gate.SOURCE_MANIFEST_NAME,
                    revision=revision,
                    selected_paths=paths + ("tools/missing.py",),
                )

    def test_dirty_checkout_revision_mismatch_and_stale_policy_fail_closed(self) -> None:
        with _committed_fixture() as (root, repository, files, revision):
            stage = root / "stage"
            stage.mkdir()
            paths = tuple(files)
            _stage(repository, stage, paths)
            (repository / "README.md").write_bytes(b"dirty\n")
            with self.assertRaisesRegex(gate.ManifestGateError, "dirty, untracked, or ignored"):
                gate.generate_manifest(
                    git_root=repository,
                    source_root=stage,
                    output_path=stage / gate.SOURCE_MANIFEST_NAME,
                    revision=revision,
                    selected_paths=paths,
                )

            (repository / "README.md").write_bytes(files["README.md"])
            with self.assertRaisesRegex(gate.ManifestGateError, "stale policy version"):
                gate.generate_manifest(
                    git_root=repository,
                    source_root=stage,
                    output_path=stage / gate.SOURCE_MANIFEST_NAME,
                    revision=revision,
                    selected_paths=paths,
                    policy_version="old-policy",
                )
            with self.assertRaises(gate.ManifestGateError):
                gate.generate_manifest(
                    git_root=repository,
                    source_root=stage,
                    output_path=stage / gate.SOURCE_MANIFEST_NAME,
                    revision="0" * 40,
                    selected_paths=paths,
                )

            (stage / gate.SOURCE_MANIFEST_NAME).write_bytes(b"stale")
            with self.assertRaisesRegex(gate.ManifestGateError, "stale release manifest"):
                gate.generate_manifest(
                    git_root=repository,
                    source_root=stage,
                    output_path=stage / gate.SOURCE_MANIFEST_NAME,
                    revision=revision,
                    selected_paths=paths,
                )

    def test_policy_input_identity_is_bound_to_the_reviewed_commit(self) -> None:
        with _committed_fixture() as (root, repository, files, revision):
            stage = root / "stage"
            stage.mkdir()
            paths = tuple(files)
            _stage(repository, stage, paths)
            (repository / ".archiveignore").write_bytes(b"changed policy\n")
            for command in (
                ["git", "add", ".archiveignore"],
                ["git", "commit", "-q", "-m", "policy drift"],
            ):
                subprocess.run(command, cwd=repository, check=True, capture_output=True)
            new_revision = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            with self.assertRaisesRegex(gate.ManifestGateError, "policy identity is stale"):
                gate.generate_manifest(
                    git_root=repository,
                    source_root=stage,
                    output_path=stage / gate.SOURCE_MANIFEST_NAME,
                    revision=new_revision,
                    selected_paths=paths,
                )

    def test_path_lanes_authority_allowlist_and_collisions_fail_closed(self) -> None:
        self.assertEqual(
            gate.PathLane.CURRENT_SOURCE,
            gate.classify_path("docs/DESIGN_IDEOLOGY.md").lane,
        )
        self.assertEqual(
            gate.PathLane.CURRENT_SOURCE,
            gate.classify_path(".gitattributes").lane,
        )
        self.assertEqual(
            gate.PathLane.EXCLUDED_GENERATED_PRIVATE,
            gate.classify_path("STATE.md").lane,
        )
        self.assertEqual(
            gate.PathLane.RETAINED_COMPATIBILITY,
            gate.classify_path("experiments/fixed_shape_claim_air/air_binary_ir.py").lane,
        )
        self.assertEqual(
            gate.PathLane.UNKNOWN,
            gate.classify_path("portal_shared/stale.py").lane,
        )
        for path in (
            "NEW_AUTHORITY.md",
            "DESIGN_IDEOLOGY.md",
            "docs/NEW_ARCHITECTURE.md",
        ):
            with self.subTest(path=path), self.assertRaisesRegex(
                gate.ManifestGateError, "tracked-path policy"
            ):
                gate.validate_tracked_paths([path])
        for path in (
            "CURRENT_TASK.md",
            "STATE.md",
            "_handoff_support/private.txt",
            "cache/generated.txt",
            "proof.json",
            "contracts/legacy.sol",
        ):
            with self.subTest(path=path), self.assertRaisesRegex(
                gate.ManifestGateError, "forbidden paths"
            ):
                gate.validate_release_paths([path])
        with self.assertRaisesRegex(gate.ManifestGateError, "duplicate or case"):
            gate.classify_paths(["tools/A.py", "tools/a.py"])
        for path in sorted(gate.RELEASE_SOURCE_ONLY_PATHS):
            with self.subTest(source_only=path):
                classification = gate.classify_path(path)
                self.assertEqual(gate.PathLane.SOURCE_ONLY, classification.lane)
                self.assertEqual(
                    "retained source/test-only nonrelease harness",
                    classification.reason,
                )
                self.assertEqual(
                    classification,
                    gate.validate_tracked_paths([path])[0],
                )
                with self.assertRaisesRegex(gate.ManifestGateError, "forbidden paths"):
                    gate.validate_release_paths([path])
        for path in sorted(gate.RELEASE_EXCLUDED_PATHS):
            with self.subTest(release_excluded=path):
                classification = gate.classify_path(path)
                self.assertEqual(
                    gate.PathLane.EXCLUDED_GENERATED_PRIVATE,
                    classification.lane,
                )
                self.assertEqual(gate.RELEASE_EXCLUSION_REASONS[path], classification.reason)
                with self.assertRaisesRegex(gate.ManifestGateError, "forbidden paths"):
                    gate.validate_release_paths([path])

    def test_default_release_selection_is_an_explicit_dependency_closure(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        selected = set(gate.default_release_selection(tracked))
        classifications = gate.validate_tracked_paths(tracked)
        retained = {
            item.path
            for item in classifications
            if item.lane is gate.PathLane.RETAINED_COMPATIBILITY
        }
        self.assertEqual(
            {
                "app/batch/__init__.py",
                "app/batch/poseidon.py",
            },
            set(gate.CURRENT_RELEASE_DEPENDENCY_PATHS),
        )
        self.assertEqual(set(gate.CURRENT_RELEASE_DEPENDENCY_PATHS), retained)
        self.assertTrue(retained <= selected)
        self.assertFalse(
            set(item.path for item in classifications if item.lane is gate.PathLane.SOURCE_ONLY)
            & selected
        )
        with self.assertRaisesRegex(
            gate.ManifestGateError, "outside the reviewed dependency closure"
        ):
            gate.default_release_selection(["app/batch/future_reference.py"])

    def test_release_selection_includes_builder_runtime_privacy_dependency(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        selected = set(gate.default_release_selection(tracked))
        helper = "tools/privacy_primitives.py"
        self.assertEqual(gate.PathLane.CURRENT_SOURCE, gate.classify_path(helper).lane)
        self.assertNotIn(helper, gate.RELEASE_EXCLUDED_PATHS)
        self.assertIn(helper, selected)

    def test_current_commit_tracked_tree_has_no_unknown_or_retired_paths(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        classifications = gate.validate_tracked_paths(tracked)
        self.assertTrue(classifications)
        self.assertEqual(
            gate.PathLane.CURRENT_SOURCE,
            gate.classify_path("docs/DESIGN_IDEOLOGY.md").lane,
        )

    def test_missing_roots_are_blockers(self) -> None:
        with self.assertRaisesRegex(gate.ManifestGateError, "git root"):
            gate.generate_manifest(
                git_root=Path("does-not-exist"),
                source_root=Path("does-not-exist-stage"),
                output_path=Path("does-not-exist-stage") / gate.SOURCE_MANIFEST_NAME,
                revision="0" * 40,
            )


if __name__ == "__main__":
    unittest.main()
