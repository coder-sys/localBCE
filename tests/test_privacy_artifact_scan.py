from __future__ import annotations

import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.privacy_artifact_scan import main as privacy_scan_main
from tools.privacy_artifact_scan import scan_artifacts


def _synthetic_envelope(**overrides: object) -> dict[str, object]:
    envelope: dict[str, object] = {
        "schema_version": 2,
        "algorithm": "AES-256-GCM",
        "key_wrap_algorithm": "RSA-OAEP-SHA256-CONTEXT-V2",
        "wrapping_key_id": "synthetic-key-1",
        "agency_id": "synthetic-agency",
        "package_sha256": "a" * 64,
        "witness_sha256": "b" * 64,
        "claim_count": 1,
        "created_at": "2026-07-13T00:00:00+00:00",
        "retain_until": "2099-01-01T00:00:00+00:00",
        "authorization_scheme": "ecdsa-p256-sha256",
        "authorization_key_id": "synthetic-signing-key",
        "authorized_principal": "synthetic-operator@example.invalid",
        "authorization_signature_b64": base64.b64encode(b"s" * 72).decode("ascii"),
        "nonce_b64": base64.b64encode(b"n" * 12).decode("ascii"),
        "wrapped_key_b64": base64.b64encode(b"w" * 384).decode("ascii"),
        "ciphertext_b64": base64.b64encode(b"synthetic-ciphertext").decode("ascii"),
    }
    envelope.update(overrides)
    envelope["envelope_sha256"] = hashlib.sha256(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return envelope


class PrivacyArtifactScanTests(unittest.TestCase):
    def test_empty_artifact_directory_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            self.assertEqual([], scan_artifacts(Path(temporary)))

    def test_cli_accepts_documented_repo_root_option(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            with patch("sys.argv", ["privacy_artifact_scan.py", "--repo-root", temporary]):
                with redirect_stdout(output):
                    privacy_scan_main()
        self.assertEqual("privacy_findings=0\n", output.getvalue())

    def test_plaintext_witness_and_claim_structures_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "batch_package.json").write_text(
                json.dumps(
                    {
                        "witness": {
                            "serialized_arguments_hex_json": ["0x1234"],
                            "claims": [{"raw_edi": "ISA*..."}],
                        }
                    }
                ),
                encoding="utf-8",
            )
            findings = scan_artifacts(root)
        self.assertTrue(any("forbidden_plaintext_filename" in item for item in findings))
        self.assertEqual(
            4,
            sum("forbidden_json_key" in item for item in findings),
        )

    def test_ciphertext_envelope_requires_authenticated_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            envelope = _synthetic_envelope()
            (root / "witness.envelope.json").write_text(
                json.dumps(envelope),
                encoding="utf-8",
            )
            findings = scan_artifacts(root)
        self.assertTrue(
            any("unapproved_json_artifact_schema" in item for item in findings)
        )

    def test_forged_or_invalid_envelopes_never_pass_the_artifact_gate(self) -> None:
        cases = [
            _synthetic_envelope(
                ciphertext_b64=base64.b64encode(
                    b'{"patient_id":"SYNTHETIC-001"}'
                ).decode("ascii")
            ),
            _synthetic_envelope(schema_version=True),
            _synthetic_envelope(
                agency_id=" invalid agency ", retain_until="not-a-timestamp"
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, envelope in enumerate(cases):
                (root / f"case-{index}.json").write_text(
                    json.dumps(envelope), encoding="utf-8"
                )
            findings = scan_artifacts(root)
        self.assertGreaterEqual(len(findings), len(cases))

    def test_malformed_duplicate_and_non_utf_json_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "malformed.json").write_text('{"ok":', encoding="utf-8")
            (root / "duplicate.json").write_text(
                '{"proof": 1, "proof": 2}', encoding="utf-8"
            )
            (root / "binary.json").write_bytes(b"\xff\x00\xfe")
            findings = scan_artifacts(root)
        self.assertTrue(any("json_malformed" in item for item in findings))
        self.assertTrue(any("json_duplicate_key" in item for item in findings))
        self.assertTrue(any("json_not_utf8_or_utf16" in item for item in findings))

    def test_uppercase_filename_and_normalized_key_cannot_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "BATCH_PACKAGE.JSON").write_text(
                json.dumps({"Prior-Authorization": "secret"}), encoding="utf-8"
            )
            findings = scan_artifacts(root)
        self.assertTrue(any("forbidden_plaintext_filename" in item for item in findings))
        self.assertTrue(any("forbidden_json_key" in item for item in findings))

    def test_unicode_camelcase_and_extended_sensitive_keys_cannot_bypass(self) -> None:
        keys = [
            "patient\u2010id",
            "patient\u200bid",
            "ｐａｔｉｅｎｔ＿ｉｄ",
            "patientId",
            "memberId",
            "rawEdi",
            "diagnosisCode",
            "priorAuthorizationId",
            "witnessData",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "metadata.json").write_text(
                json.dumps({key: "synthetic" for key in keys}), encoding="utf-8"
            )
            findings = scan_artifacts(root)
        self.assertEqual(
            len(keys), sum("forbidden_json_key" in item for item in findings)
        )
        self.assertTrue(any("unapproved_json_artifact_schema" in item for item in findings))

    def test_sensitive_names_and_fullwidth_forbidden_filename_cannot_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "patient_id=synthetic"
            directory.mkdir()
            (directory / "member_id=synthetic.txt").write_text("safe", encoding="utf-8")
            (root / "batch_package．json").write_text("{}", encoding="utf-8")
            findings = scan_artifacts(root)
        rendered = "\n".join(findings)
        self.assertIn("sensitive_plaintext_assignment", rendered)
        self.assertIn("forbidden_plaintext_filename", rendered)

    def test_json_string_and_text_payloads_are_reported_without_echoing_values(self) -> None:
        secret = "M123456789"
        edi = (
            "ST*837*0001~CLM*CLAIM-1*125.00~"
            "NM1*IL*1*DOE*JANE****MI*M123456789~"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "metadata.json").write_text(
                json.dumps({"note": f"member_id={secret}"}), encoding="utf-8"
            )
            (root / "prover.log").write_text(edi, encoding="utf-8")
            findings = scan_artifacts(root)
        rendered = "\n".join(findings)
        self.assertIn("sensitive_plaintext_assignment", rendered)
        self.assertIn("plaintext_x12_837", rendered)
        self.assertNotIn(secret, rendered)

    def test_host_paths_private_keys_and_artifact_references_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "paths.txt").write_text(
                "C:\\Users\\alice\\proof.json\n"
                "`/home/alice/proof.json`\n"
                "file:///private/proof.json\n"
                "batch_main_args.json\n"
                "-----BEGIN PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            findings = scan_artifacts(root)
        rendered = "\n".join(findings)
        self.assertIn("host_private_path", rendered)
        self.assertIn("forbidden_artifact_reference", rendered)
        self.assertIn("private_key_material", rendered)

    def test_encrypted_private_key_and_encoded_container_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "encrypted-key.txt").write_text(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            (root / "encoded.txt").write_text(
                "UEsDBBQAAAAIAAAAAAAAAAAAAAAAAAAAAAAA",
                encoding="utf-8",
            )
            findings = scan_artifacts(root)
        rendered = "\n".join(findings)
        self.assertIn("private_key_material", rendered)
        self.assertIn("encoded_container_not_privacy_scanned", rendered)

    def test_alternate_encodings_and_secret_markers_fail_closed(self) -> None:
        payloads = {
            "split-base64.txt": "UEsDB\nBQAAAAIAAAAA",
            "hex.txt": "504b030414000000",
            "ascii85.txt": "6=FqH3&N",
            "pgp.txt": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "age.txt": "AGE-SECRET-KEY-1SYNTHETIC",
            "root-path.txt": "/root/synthetic/proof.json",
            "private-tmp.txt": "/private/tmp/synthetic/proof.json",
            "environment.txt": "%USERPROFILE%\\synthetic\\proof.json",
            "encoded-url.txt": "file%3A%2F%2F%2Fsynthetic%2Fproof.json",
            "escaped-json.txt": r'{\"patient_id\":\"synthetic\"}',
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in payloads.items():
                (root / name).write_text(value, encoding="utf-8")
            findings = scan_artifacts(root)
        self.assertEqual(
            len(payloads),
            sum("unapproved_text_artifact_present" in item for item in findings),
        )

    def test_arbitrary_text_is_rejected_even_when_content_looks_benign(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "notes.txt").write_text(
                "https://example.com/Users/alice\n"
                "ops/native_stark_public_inputs_v2.json\n",
                encoding="utf-8",
            )
            findings = scan_artifacts(root)
        self.assertTrue(any("unapproved_text_artifact_present" in item for item in findings))

    def test_unscanned_directory_and_opaque_file_are_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            (target / "hidden.txt").write_text("harmless", encoding="utf-8")
            (root / "proof.bin").write_bytes(b"\x00\xff\x01")
            findings = scan_artifacts(root)
        rendered = "\n".join(findings)
        self.assertIn("unscanned_directory_present", rendered)
        self.assertIn("opaque_file_not_privacy_scanned", rendered)

    def test_malformed_host_cache_directory_is_not_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated = root / "C\uf03aUserssynthetic"
            generated.mkdir()
            (generated / "metadata.json").write_text(
                json.dumps({"patient_id": "must-not-be-echoed"}), encoding="utf-8"
            )
            findings = scan_artifacts(root)
        self.assertEqual(1, len(findings))
        self.assertIn("unscanned_directory_present", findings[0])
        self.assertNotIn("synthetic", findings[0])

    def test_utf16_text_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "windows.log").write_bytes(
                "C:\\Users\\alice\\proof.json".encode("utf-16")
            )
            findings = scan_artifacts(root)
        self.assertTrue(any("host_private_path" in item for item in findings))

    def test_unreadable_json_is_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "record.json").write_text("{}", encoding="utf-8")
            with patch.object(Path, "open", side_effect=PermissionError):
                findings = scan_artifacts(root)
        self.assertTrue(any("json_unreadable" in item for item in findings))

    def test_diagnostics_do_not_echo_sensitive_filenames_or_json_keys(self) -> None:
        sensitive_filename = "patient-Jane-Doe-M123.bin"
        sensitive_key = "Jane_Doe_M123"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / sensitive_filename).write_bytes(b"\x00\xff")
            (root / "metadata.json").write_text(
                json.dumps({sensitive_key: "patient_id=M123"}), encoding="utf-8"
            )
            findings = scan_artifacts(root)
        rendered = "\n".join(findings)
        self.assertNotIn(sensitive_filename, rendered)
        self.assertNotIn(sensitive_key, rendered)
        self.assertIn("opaque_file_not_privacy_scanned", rendered)
        self.assertIn("sensitive_plaintext_assignment", rendered)


if __name__ == "__main__":
    unittest.main()
