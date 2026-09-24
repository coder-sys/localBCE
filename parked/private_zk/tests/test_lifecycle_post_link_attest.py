from __future__ import annotations

import hashlib
import importlib.util
import io
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
ATTESTER_PATH = REPO_ROOT / "semantic_kernel" / "rust" / "post_link_attest.py"
SPEC = importlib.util.spec_from_file_location("lifecycle_post_link_attest", ATTESTER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load Lifecycle post-link attester")
attester = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = attester
SPEC.loader.exec_module(attester)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tar_bytes(entries: list[tuple[str, bytes, bytes | None]]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload, member_type in entries:
            info = tarfile.TarInfo(name)
            if member_type is not None:
                info.type = member_type
                info.linkname = "target.obj"
                info.size = 0
                archive.addfile(info)
            else:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return stream.getvalue()


class LifecyclePostLinkAttestationTests(unittest.TestCase):
    def test_build_script_pins_attester_source_bytes(self) -> None:
        build_source = (REPO_ROOT / "semantic_kernel" / "rust" / "build.rs").read_text(encoding="utf-8")
        matches = re.findall(r'\("post_link_attest\.py", "([0-9a-f]{64})"\)', build_source)
        self.assertEqual(matches, [_sha256(ATTESTER_PATH.read_bytes())])

    def test_build_environment_accepts_only_the_pinned_project_cargo_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rust_root = root / "checkout" / "semantic_kernel" / "rust"
            project_config = rust_root / ".cargo" / "config.toml"
            project_config.parent.mkdir(parents=True)
            project_config.write_bytes((REPO_ROOT / "semantic_kernel" / "rust" / ".cargo" / "config.toml").read_bytes())
            cargo_home = root / "cargo-home"
            environment = {"CARGO_HOME": str(cargo_home)}
            with patch.object(attester, "RUST_ROOT", rust_root):
                configuration = attester._check_build_environment(environment)

            self.assertEqual(configuration["cargo_home"], str(cargo_home))
            self.assertEqual(configuration["files"], [{
                "file": str(project_config),
                "length": project_config.stat().st_size,
                "sha256": _sha256(project_config.read_bytes()),
            }])
            self.assertIn(str(cargo_home / "config.toml"), configuration["searched_paths"])

    def test_build_environment_rejects_cargo_home_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rust_root = root / "checkout" / "semantic_kernel" / "rust"
            project_config = rust_root / ".cargo" / "config.toml"
            project_config.parent.mkdir(parents=True)
            project_config.write_bytes((REPO_ROOT / "semantic_kernel" / "rust" / ".cargo" / "config.toml").read_bytes())
            cargo_home = root / "cargo-home"
            cargo_home.mkdir()
            (cargo_home / "config.toml").write_text('[build]\nrustc-wrapper = "unreviewed-wrapper"\n', encoding="utf-8")
            with patch.object(attester, "RUST_ROOT", rust_root):
                with self.assertRaisesRegex(attester.AttestationError, "unreviewed Cargo configuration file"):
                    attester._check_build_environment({"CARGO_HOME": str(cargo_home)})

    def test_build_environment_rejects_ancestor_cargo_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rust_root = root / "checkout" / "semantic_kernel" / "rust"
            project_config = rust_root / ".cargo" / "config.toml"
            project_config.parent.mkdir(parents=True)
            project_config.write_bytes((REPO_ROOT / "semantic_kernel" / "rust" / ".cargo" / "config.toml").read_bytes())
            ancestor_config = root / "checkout" / ".cargo" / "config"
            ancestor_config.parent.mkdir(parents=True)
            ancestor_config.write_text('[build]\nrustc-wrapper = "unreviewed-wrapper"\n', encoding="utf-8")
            cargo_home = root / "cargo-home"
            with patch.object(attester, "RUST_ROOT", rust_root):
                with self.assertRaisesRegex(attester.AttestationError, "unreviewed Cargo configuration file"):
                    attester._check_build_environment({"CARGO_HOME": str(cargo_home)})

    def test_build_environment_rejects_cargo_profile_build_override(self) -> None:
        with self.assertRaisesRegex(
            attester.AttestationError,
            "CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_OPT_LEVEL",
        ):
            attester._check_build_environment({
                "CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_OPT_LEVEL": "1",
            })

    def test_source_manifest_parser_requires_sorted_unique_canonical_records(self) -> None:
        body = b"blind-ledger-lifecycle-source-manifest-v2\nlean/A.lean\t1\t3\t" + _sha256(b"abc").encode() + b"\n"
        records = attester.parse_source_manifest(body)
        self.assertEqual([(item.path, item.count, item.length) for item in records], [("lean/A.lean", 1, 3)])

        bad_manifests = (
            body + body.splitlines(keepends=True)[1],
            b"blind-ledger-lifecycle-source-manifest-v2\n"
            + b"lean/B.lean\t1\t1\t" + _sha256(b"b").encode() + b"\n"
            + b"lean/A.lean\t1\t1\t" + _sha256(b"a").encode() + b"\n",
            b"blind-ledger-lifecycle-source-manifest-v2\nlean/../A.lean\t1\t3\t" + _sha256(b"abc").encode() + b"\n",
            b"blind-ledger-lifecycle-source-manifest-v2\nlean/A.lean\t1\t3\t" + b"A" * 64 + b"\n",
        )
        for malformed in bad_manifests:
            with self.subTest(malformed=malformed), self.assertRaises(attester.AttestationError):
                attester.parse_source_manifest(malformed)

    def test_prelink_receipt_requires_exact_ordered_fields_and_valid_hashes(self) -> None:
        digest = _sha256(b"artifact")
        rows = [f"source_manifest\t{digest}\t7"]
        rows.extend(f"{name}\t7\t{digest}" for name in (
            "lifecycle_kernel_object",
            "lifecycle_object",
            "model_object",
            "sha3_object",
            "manifest_object",
            "lifecycle_archive",
        ))
        receipt = ("blind-ledger-lifecycle-build-receipt-v2\n" + "\n".join(rows) + "\n").encode("ascii")
        parsed = attester.parse_build_receipt(receipt)
        self.assertEqual(parsed["source_manifest"], (7, digest))
        self.assertEqual(parsed["lifecycle_archive"], (7, digest))
        with self.assertRaises(attester.AttestationError):
            attester.parse_build_receipt(receipt.replace(digest.encode(), b"z" * 64, 1))

    def test_embedded_manifest_requires_matching_digest_and_one_occurrence(self) -> None:
        manifest = b"blind-ledger-lifecycle-source-manifest-v2\nlean/A.lean\t1\t1\t" + _sha256(b"x").encode() + b"\n"
        digest = _sha256(manifest)
        attester.verify_embedded_manifest(b"prefix" + manifest + b"suffix", manifest, digest)
        with self.assertRaisesRegex(attester.AttestationError, "digest mismatch"):
            attester.verify_embedded_manifest(b"prefix" + manifest, manifest, "0" * 64)
        with self.assertRaisesRegex(attester.AttestationError, "occurs more than once"):
            attester.verify_embedded_manifest(manifest + manifest, manifest, digest)

    def test_adapter_provenance_line_uses_actual_manifest_and_executable_bytes(self) -> None:
        manifest_sha256 = _sha256(b"source manifest bytes")
        executable = b"linked lifecycle executable bytes"
        expected = (
            "BL-LIFECYCLE-PROVENANCE/1;"
            f"manifest_sha256={manifest_sha256};"
            f"exe_size={len(executable)};"
            f"exe_sha256={_sha256(executable)}\n"
        )
        self.assertEqual(attester._adapter_provenance_line(manifest_sha256, executable), expected)
        with self.assertRaisesRegex(attester.AttestationError, "derive adapter provenance"):
            attester._adapter_provenance_line("0" * 64, b"")

    def test_link_argument_manifest_binds_exact_order_and_reproducer_switch(self) -> None:
        arguments = attester.parse_link_argument_manifest(attester.expected_link_argument_manifest())
        self.assertEqual(arguments[0], "-Btoolchain/bin")
        self.assertIn("-Wl,--reproduce=OUT_DIR:lifecycle_link_repro.v1.tar", arguments)
        with self.assertRaises(attester.AttestationError):
            attester.parse_link_argument_manifest(attester.expected_link_argument_manifest().replace(b"libgmp.a", b"libbad.a", 1))

    def test_lld_response_parser_accepts_only_pinned_mingw_coff_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "libknown.a"
            source.write_bytes(b"static-link-input")
            path_row = attester._lld_reproducer_name(source)
            valid = f"-lldmingw\n/out:lifecycle.exe\n{path_row}\n".encode("ascii")
            self.assertEqual(attester.parse_lld_response_inputs(valid), [path_row])
            spaced_source = root / "lib known.a"
            spaced_source.write_bytes(b"quoted-input")
            spaced_row = attester._lld_reproducer_name(spaced_source)
            quoted = f'-lldmingw\n/out:lifecycle.exe\n"{spaced_row}"\n'.encode("ascii")
            self.assertEqual(attester.parse_lld_response_inputs(quoted), [spaced_row])

            malformed = (
                valid.replace(b"-lldmingw", b"--chroot .", 1),
                valid.replace(b"-lldmingw", b"@nested.rsp", 1),
                valid.replace(path_row.encode("ascii"), b"relative/libknown.a"),
                valid.replace(b"/out:lifecycle.exe", b"/out:\"unterminated", 1),
                valid.replace(b"-lldmingw", b"-lldmingw\n-lldmingw", 1),
                valid.replace(b"\n", b"\r\n"),
            )
            for response in malformed:
                with self.subTest(response=response[:64]), self.assertRaises(attester.AttestationError):
                    attester.parse_lld_response_inputs(response)

    def test_reproducer_rejects_traversal_symlink_and_duplicate_members(self) -> None:
        malformed = (
            _tar_bytes([(attester.RESPONSE_NAME, b"args", None), ("../outside.obj", b"x", None)]),
            _tar_bytes([(attester.RESPONSE_NAME, b"args", None), ("alias.obj", b"", tarfile.SYMTYPE)]),
            _tar_bytes([(attester.RESPONSE_NAME, b"args", None), ("alias.obj", b"", tarfile.LNKTYPE)]),
            _tar_bytes([
                (attester.RESPONSE_NAME, b"args", None),
                ("same.obj", b"first", None),
                ("same.obj", b"second", None),
            ]),
        )
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "reproducer.tar"
            for data in malformed:
                archive_path.write_bytes(data)
                with self.subTest(size=len(data)), self.assertRaises(attester.AttestationError):
                    attester.read_lld_reproducer(archive_path)

    def test_reproducer_input_mapping_accepts_only_exact_known_inputs(self) -> None:
        payload = b"static-link-input"
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "libknown.a"
            source.write_bytes(payload)
            candidate = attester.FileIdentity(
                source,
                "arg[0]=toolchain/lib/libknown.a",
                "explicit-link-argument",
                len(payload),
                _sha256(payload),
            )
            archive_path = Path(temporary) / "reproducer.tar"
            archive_path.write_bytes(_tar_bytes([
                (attester.RESPONSE_NAME, b"--out=life.exe", None),
                (attester._lld_reproducer_name(source), payload, None),
            ]))
            members = attester.read_lld_reproducer(archive_path)
            mapped = attester.match_reproducer_inputs(members, [candidate], [candidate])
            self.assertEqual([(member.name, identity.identity) for member, identity in mapped], [
                (attester._lld_reproducer_name(source), "arg[0]=toolchain/lib/libknown.a")
            ])
            response = f"-lldmingw\n{attester._lld_reproducer_name(source)}\n".encode("ascii")
            response_inputs = attester.parse_lld_response_inputs(response)
            ordered = attester.verify_response_references(response_inputs, [candidate], mapped, [candidate])
            self.assertEqual([(member.name, identity.identity) for member, identity in ordered], [
                (attester._lld_reproducer_name(source), "arg[0]=toolchain/lib/libknown.a")
            ])
            with self.assertRaisesRegex(attester.AttestationError, "uncaptured input path"):
                attester.verify_response_references(
                    [attester._lld_reproducer_name(source).replace("libknown.a", "libother.a")],
                    [candidate],
                    mapped,
                    [candidate],
                )
            unknown = attester.ArchiveMember("C/inputs/libunknown.a", False, len(payload), _sha256(payload))
            with self.assertRaisesRegex(attester.AttestationError, "unknown LLD link input"):
                attester.match_reproducer_inputs([members[0], unknown], [candidate], [candidate])

    def test_response_order_matches_captured_paths_and_explicit_library_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identities = []
            mapped = []
            names = []
            for index, name in enumerate(("libfirst.a", "libsecond.a")):
                payload = f"payload-{index}".encode("ascii")
                path = root / name
                path.write_bytes(payload)
                item = attester.FileIdentity(
                    path,
                    f"arg[{index}]=toolchain/lib/{name}",
                    "explicit-link-argument",
                    len(payload),
                    _sha256(payload),
                )
                member = attester.ArchiveMember(
                    attester._lld_reproducer_name(path),
                    False,
                    len(payload),
                    _sha256(payload),
                )
                identities.append(item)
                mapped.append((member, item))
                names.append(attester._lld_reproducer_name(path))

            with self.assertRaisesRegex(attester.AttestationError, "input order differs"):
                attester.verify_response_references(
                    [names[1], names[0]],
                    identities,
                    mapped,
                    identities,
                )

    def test_reproducer_snapshot_binds_an_input_removed_after_link(self) -> None:
        payload = b"captured-rustc-temporary-object"
        with tempfile.TemporaryDirectory() as temporary:
            missing_path = Path(temporary) / "symbols.o"
            name = attester._lld_reproducer_name(missing_path)
            member = attester.ArchiveMember(name, False, len(payload), _sha256(payload))
            captured = attester.FileIdentity(
                missing_path,
                f"lld-response-capture[0]={name}",
                "lld-response-capture",
                len(payload),
                _sha256(payload),
            )
            ordered = attester.verify_response_references(
                [name],
                [captured],
                [(member, captured)],
                [],
            )
            self.assertEqual([(item.name, identity.sha256) for item, identity in ordered], [
                (name, _sha256(payload))
            ])

    def test_explicit_link_input_must_match_its_prelink_source_identity(self) -> None:
        payload = b"pinned-static-library"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "libknown.a"
            path.write_bytes(payload)
            source_record = attester.SourceRecord(
                "link-input/support/libknown.a",
                1,
                len(payload),
                _sha256(payload),
            )
            item = attester.FileIdentity(
                path,
                "arg[0]=toolchain/lib/libknown.a",
                "explicit-link-argument",
                len(payload),
                _sha256(payload),
            )
            attester.verify_explicit_link_input_identities(
                [item],
                {source_record.path: source_record},
                {},
            )
            swapped = attester.FileIdentity(
                path,
                item.identity,
                item.category,
                item.length,
                "0" * 64,
            )
            with self.assertRaisesRegex(attester.AttestationError, "pre-link identity"):
                attester.verify_explicit_link_input_identities(
                    [swapped],
                    {source_record.path: source_record},
                    {},
                )

    def test_reproducer_input_mapping_rejects_missing_explicit_archive(self) -> None:
        payload = b"static-link-input"
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "libknown.a"
            source.write_bytes(payload)
            candidate = attester.FileIdentity(
                source,
                "arg[0]=toolchain/lib/libknown.a",
                "explicit-link-argument",
                len(payload),
                _sha256(payload),
            )
            response = attester.ArchiveMember(attester.RESPONSE_NAME, False, 4, _sha256(b"args"), b"args")
            with self.assertRaisesRegex(attester.AttestationError, "explicit link arguments absent"):
                attester.match_reproducer_inputs([response], [candidate], [candidate])


if __name__ == "__main__":
    unittest.main()
