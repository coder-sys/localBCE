from __future__ import annotations

import base64
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import zipfile

from tools import build_release_archive as release


def _write_manifest(root: Path, files: dict[str, bytes]) -> Path:
    entries = []
    for relative, data in sorted(files.items()):
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    manifest = root / "APP_RELEASE_FILE_MANIFEST.json"
    manifest.write_text(
        json.dumps(
            {
                "archive_root": "Blind-Ledger-Release",
                "files": entries,
                "manifest_version": 2,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


class ReleaseArchiveTests(unittest.TestCase):
    def test_deterministic_build_and_readback(self) -> None:
        files = {
            "app/main.py": b"print('synthetic only')\n",
            "docs/README.md": b"# Release\n",
        }
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source_a = base / "source-a"
            source_b = base / "source-b"
            source_a.mkdir()
            source_b.mkdir()
            manifest_a = _write_manifest(source_a, files)
            manifest_b = _write_manifest(source_b, dict(reversed(list(files.items()))))
            now = time.time() + 3600
            for path in source_b.rglob("*"):
                if path.is_file():
                    os.utime(path, (now, now))
            output_a = base / "a.zip"
            output_b = base / "b.zip"
            receipt_a = release.build_release_archive(source_a, manifest_a, output_a)
            receipt_b = release.build_release_archive(source_b, manifest_b, output_b)

            self.assertEqual(output_a.read_bytes(), output_b.read_bytes())
            self.assertEqual(receipt_a, receipt_b)
            self.assertEqual(2, receipt_a["payload_file_count"])
            self.assertEqual(3, receipt_a["entry_count"])
            with zipfile.ZipFile(output_a) as archive:
                infos = archive.infolist()
                self.assertEqual(
                    [
                        "Blind-Ledger-Release/RELEASE_FILE_MANIFEST.json",
                        "Blind-Ledger-Release/app/main.py",
                        "Blind-Ledger-Release/docs/README.md",
                    ],
                    [item.filename for item in infos],
                )
                for info in infos:
                    self.assertEqual(release.FIXED_TIMESTAMP, info.date_time)
                    self.assertEqual(zipfile.ZIP_STORED, info.compress_type)
                    self.assertEqual(b"", info.extra)
                    self.assertEqual(b"", info.comment)

    def test_duplicate_json_key_and_unknown_schema_field_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            manifest.write_text(
                '{"archive_root":"safe","files":[],"files":[],"manifest_version":2}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(release.ReleaseArchiveError, "strict UTF-8 JSON"):
                release._read_manifest(manifest)
            manifest.write_text(
                json.dumps(
                    {
                        "archive_root": "safe",
                        "files": [],
                        "manifest_version": 2,
                        "unexpected": True,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(release.ReleaseArchiveError, "schema v2"):
                release._read_manifest(manifest)

    def test_unsafe_windows_and_archive_paths_are_rejected(self) -> None:
        invalid = [
            "../escape.txt",
            "/absolute.txt",
            "C:/drive.txt",
            "dir\\backslash.txt",
            "dir/name:stream",
            "dir/trailing. ",
            "CON.txt",
            "CONIN$.txt",
            "CONOUT$.txt",
            "COM¹.txt",
            "nested/NUL.data",
            "target/output.txt",
            "a/output.txt",
            "proofs/output.txt",
            "proof.json",
            "final_proof.json",
            "archive.zip",
            "payload.bin",
            "payload.tar.bz2",
            "payload.jar",
            "payload.xz",
            "payload.zst",
            "docs/safe\u202efdp.exe",
            "tar\u200bget/output.txt",
            release.EMBEDDED_MANIFEST_NAME,
            release.EMBEDDED_MANIFEST_NAME.casefold(),
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(release.ReleaseArchiveError):
                release._validate_relative_path(value)

    def test_unsorted_case_collision_hash_and_size_errors_are_rejected(self) -> None:
        cases = [
            [
                {"path": "b.txt", "sha256": "0" * 64, "size": 0},
                {"path": "a.txt", "sha256": "0" * 64, "size": 0},
            ],
            [
                {"path": "A.txt", "sha256": "0" * 64, "size": 0},
                {"path": "a.txt", "sha256": "0" * 64, "size": 0},
            ],
            [
                {"path": "A.txt", "sha256": "0" * 64, "size": 0},
                {"path": "Ａ.txt", "sha256": "0" * 64, "size": 0},
            ],
            [{"path": "a.txt", "sha256": "A" * 64, "size": 0}],
            [{"path": "a.txt", "sha256": "0" * 64, "size": -1}],
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            for entries in cases:
                with self.subTest(entries=entries):
                    manifest.write_text(
                        json.dumps(
                            {
                                "archive_root": "safe",
                                "files": entries,
                                "manifest_version": 2,
                            }
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaises(release.ReleaseArchiveError):
                        release._read_manifest(manifest)

    def test_manifest_version_must_be_an_integer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = Path(temporary) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "archive_root": "safe",
                        "files": [
                            {"path": "a.txt", "sha256": "0" * 64, "size": 0}
                        ],
                        "manifest_version": 2.0,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(release.ReleaseArchiveError, "version"):
                release._read_manifest(manifest)

    def test_unknown_file_missing_file_and_hash_drift_are_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            manifest = _write_manifest(source, {"app.txt": b"approved"})
            (source / "unknown.txt").write_text("unknown", encoding="utf-8")
            with self.assertRaisesRegex(release.ReleaseArchiveError, "unknown, or unlisted"):
                release.build_release_archive(source, manifest, base / "unknown.zip")
            (source / "unknown.txt").unlink()
            (source / "app.txt").write_bytes(b"tampered")
            with self.assertRaisesRegex(release.ReleaseArchiveError, "hash does not match"):
                release.build_release_archive(source, manifest, base / "tampered.zip")
            (source / "app.txt").unlink()
            with self.assertRaisesRegex(release.ReleaseArchiveError, "missing, unknown"):
                release.build_release_archive(source, manifest, base / "missing.zip")

    def test_output_inside_source_and_overwrite_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            manifest = _write_manifest(source, {"file.txt": b"approved"})
            with self.assertRaisesRegex(release.ReleaseArchiveError, "outside the source root"):
                release.build_release_archive(source, manifest, source / "release.zip")
            output = base / "release.zip"
            output.write_bytes(b"existing")
            with self.assertRaisesRegex(release.ReleaseArchiveError, "already exists"):
                release.build_release_archive(source, manifest, output)

    def test_hardlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            manifest = _write_manifest(source, {"file.txt": b"approved"})
            outside = base / "hardlink.txt"
            try:
                os.link(source / "file.txt", outside)
            except OSError as exc:
                self.skipTest(f"hardlinks unavailable: {exc}")
            with self.assertRaisesRegex(release.ReleaseArchiveError, "hardlinked"):
                release.build_release_archive(source, manifest, base / "release.zip")

    def test_directory_enumeration_error_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def failed_walk(*_args: object, **kwargs: object):
                kwargs["onerror"](PermissionError("denied"))
                return iter(())

            with mock.patch.object(release.os, "walk", side_effect=failed_walk):
                with self.assertRaisesRegex(release.ReleaseArchiveError, "enumeration failed"):
                    release._inventory_source(root)

    def test_truncated_archive_fails_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "truncated.zip"
            path.write_bytes(b"PK\x03\x04")
            with self.assertRaisesRegex(
                release.ReleaseArchiveError, "canonical deterministic ZIP|read back"
            ):
                release._verify_archive(
                    path,
                    archive_root="safe",
                    manifest_bytes=b"{}",
                    captured=[],
                )

    def test_prefix_and_trailing_bytes_fail_canonical_readback(self) -> None:
        canonical = release._render_archive(
            archive_root="safe", manifest_bytes=b"{}", captured=[]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data in (
                ("prefix.zip", b"HIDDEN" + canonical),
                ("trailer.zip", canonical + b"HIDDEN"),
            ):
                path = root / name
                path.write_bytes(data)
                with self.subTest(name=name), self.assertRaisesRegex(
                    release.ReleaseArchiveError,
                    "canonical deterministic ZIP|exceeds the size limit",
                ):
                    release._verify_archive(
                        path,
                        archive_root="safe",
                        manifest_bytes=b"{}",
                        captured=[],
                    )

    def test_output_created_during_publish_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            manifest = _write_manifest(source, {"file.txt": b"approved"})
            output = base / "release.zip"
            real_link = os.link

            def racing_link(source_path: object, destination: object, **kwargs: object):
                Path(destination).write_bytes(b"victim-created-during-race")
                return real_link(source_path, destination, **kwargs)

            with mock.patch.object(release.os, "link", side_effect=racing_link):
                with self.assertRaisesRegex(release.ReleaseArchiveError, "already exists"):
                    release.build_release_archive(source, manifest, output)
            self.assertEqual(b"victim-created-during-race", output.read_bytes())

    def test_post_verify_swap_cannot_produce_a_success_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            manifest = _write_manifest(source, {"file.txt": b"approved"})
            output = base / "release.zip"
            real_verify = release._verify_archive
            calls = 0

            def swapping_verify(path: Path, **kwargs: object) -> None:
                nonlocal calls
                real_verify(path, **kwargs)
                calls += 1
                if calls == 2:
                    output.unlink()
                    output.write_bytes(b"tampered-after-verification")

            with mock.patch.object(release, "_verify_archive", side_effect=swapping_verify):
                with self.assertRaisesRegex(
                    release.ReleaseArchiveError, "cleanup or output custody"
                ):
                    release.build_release_archive(source, manifest, output)
            self.assertEqual(b"tampered-after-verification", output.read_bytes())

    def test_encoded_container_and_private_material_fail_exact_payload_gate(self) -> None:
        payloads = [
            b"504b030414000000",
            base64.b64encode(b"-----BEGIN PRIVATE KEY-----\nsynthetic"),
            base64.a85encode(b"PK\x03\x04synthetic"),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for index, payload in enumerate(payloads):
                with self.subTest(index=index):
                    source = base / f"source-{index}"
                    source.mkdir()
                    manifest = _write_manifest(source, {"payload.txt": payload})
                    with self.assertRaisesRegex(
                        release.ReleaseArchiveError, "encoded opaque or private material"
                    ):
                        release.build_release_archive(
                            source, manifest, base / f"release-{index}.zip"
                        )

    def test_continuation_mandate_allows_only_the_pinned_operational_workspace_path(self) -> None:
        pinned = release._PINNED_WORKSPACE_PATH
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            manifest = _write_manifest(
                source,
                {"CONTINUATION_MANDATE.md": f"workspace={pinned}\n".encode("utf-8")},
            )
            receipt = release.build_release_archive(source, manifest, base / "release.zip")
            self.assertEqual(2, receipt["entry_count"])

            other = base / "other"
            other.mkdir()
            other_manifest = _write_manifest(
                other,
                {
                    "CONTINUATION_MANDATE.md": (
                        b"workspace=C:\\Users\\someone-else\\private\\checkout\n"
                    )
                },
            )
            with self.assertRaisesRegex(
                release.ReleaseArchiveError, "structural privacy gate"
            ):
                release.build_release_archive(other, other_manifest, base / "other.zip")

    def test_canonical_standard_and_urlsafe_base64_variants_are_rejected(self) -> None:
        private_payload = b"PK\x03\x04\x00>\xfc"
        standard = base64.b64encode(private_payload)
        urlsafe = base64.urlsafe_b64encode(private_payload)
        self.assertIn(b"+", standard)
        self.assertIn(b"/", standard)
        self.assertIn(b"-", urlsafe)
        self.assertIn(b"_", urlsafe)
        payloads = [
            standard,
            standard.rstrip(b"="),
            urlsafe,
            urlsafe.rstrip(b"="),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for index, payload in enumerate(payloads):
                with self.subTest(index=index, payload=payload):
                    source = base / f"source-base64-{index}"
                    source.mkdir()
                    manifest = _write_manifest(source, {"payload.txt": payload})
                    with self.assertRaisesRegex(
                        release.ReleaseArchiveError, "encoded opaque or private material"
                    ):
                        release.build_release_archive(
                            source, manifest, base / f"release-base64-{index}.zip"
                        )

    def test_base64_decoder_requires_one_canonical_alphabet_and_round_trip(self) -> None:
        private_payload = b"PK\x03\x04\x00>\xfc"
        standard = base64.b64encode(private_payload).decode("ascii")
        urlsafe = base64.urlsafe_b64encode(private_payload).decode("ascii")
        for encoded in (
            standard,
            standard.rstrip("="),
            urlsafe,
            urlsafe.rstrip("="),
        ):
            with self.subTest(encoded=encoded):
                self.assertEqual(
                    private_payload, release._decode_canonical_base64(encoded)
                )

        malformed = (
            "UEsDBAA+_A==",
            "UEsDBAA-_A===",
            "UEsDB=AA-_A==",
            "UEsDBAA-_A=",
            "YR==",
            "AAAAA",
        )
        for encoded in malformed:
            with self.subTest(encoded=encoded):
                self.assertIsNone(release._decode_canonical_base64(encoded))

    def test_benign_canonical_base64_remains_allowed(self) -> None:
        benign = b"ordinary release documentation"
        for encoded in (
            base64.b64encode(benign).decode("ascii"),
            base64.b64encode(benign).decode("ascii").rstrip("="),
            base64.urlsafe_b64encode(benign).decode("ascii"),
            base64.urlsafe_b64encode(benign).decode("ascii").rstrip("="),
        ):
            with self.subTest(encoded=encoded):
                self.assertFalse(release._contains_forbidden_encoded_payload(encoded))

    def test_cli_failure_does_not_emit_private_paths_or_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root.parent / "never-created.zip"
            stderr = io.StringIO()
            arguments = [
                "build_release_archive",
                "--source-root",
                str(root),
                "--manifest",
                str(root / release.SOURCE_MANIFEST_NAME),
                "--output",
                str(output),
            ]
            with mock.patch.object(release.sys, "argv", arguments), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    release.main()
            rendered = stderr.getvalue()
        self.assertEqual(1, raised.exception.code)
        self.assertIn("release_status=blocked", rendered)
        self.assertNotIn(str(root), rendered)
        self.assertNotIn("Traceback", rendered)


if __name__ == "__main__":
    unittest.main()
