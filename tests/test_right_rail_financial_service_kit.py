from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from app.right_rail_financial_staff_server import _STATIC_FILES
from tools.right_rail_financial_service_kit import (
    EXPECTED_PYTHON_EXE_SHA256,
    KIT_CLAIMS,
    KIT_SCHEMA,
    RUNTIME_EXE,
    RETIRED_PIN_REGISTRY,
    STATE_FILES,
    KitError,
    _check_names,
    _check_contents,
    _check_guard_log,
    _check_retired_pins,
    _check_runtime_member,
    _manifest_files,
    _strict_canonical_json,
)


class FinancialServiceKitManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.interpreter_size = 1_234_567
        self.members = {RUNTIME_EXE: (self.interpreter_size, EXPECTED_PYTHON_EXE_SHA256)}

    def test_receipt_json_requires_canonical_bytes(self) -> None:
        self.assertEqual(_strict_canonical_json(b'{"schema":"v2"}', "receipt"), {"schema": "v2"})
        with self.assertRaisesRegex(KitError, "json_not_canonical:receipt"):
            _strict_canonical_json(b'{ "schema": "v2"}\n', "receipt")

    def test_manifest_binds_the_pinned_runtime_member(self) -> None:
        size, digest = _check_runtime_member(self.members)
        self.assertEqual(digest, EXPECTED_PYTHON_EXE_SHA256)
        self.assertEqual(size, self.interpreter_size)

    def test_manifest_rejects_a_self_consistent_unpinned_interpreter_member(self) -> None:
        self.members[RUNTIME_EXE] = (self.interpreter_size, "A" * 64)
        with self.assertRaisesRegex(KitError, "kit_python_executable_member_pin"):
            _check_runtime_member(self.members)

    def test_manifest_rejects_non_integer_interpreter_size(self) -> None:
        self.members[RUNTIME_EXE] = (True, EXPECTED_PYTHON_EXE_SHA256)
        with self.assertRaisesRegex(KitError, "kit_python_executable_member_pin"):
            _check_runtime_member(self.members)

    def test_manifest_rejects_missing_interpreter_member(self) -> None:
        with self.assertRaisesRegex(KitError, "kit_python_executable_member_pin"):
            _check_runtime_member({})

    def test_archive_names_reject_traversal_and_portable_collisions(self) -> None:
        for bad in ("../x", "/abs", "a/../b", "a\\b", "C:x", "aux.txt", "a/", "trail. "):
            with self.subTest(name=bad), self.assertRaises(KitError):
                _check_names([bad])
        with self.assertRaisesRegex(KitError, "archive_path_portable_collision"):
            _check_names(["README.md", "readme.md"])
        with self.assertRaisesRegex(KitError, "archive_file_directory_collision"):
            _check_names(["a", "a/b"])

    def test_manifest_claims_are_exact_including_json_types(self) -> None:
        entry = {"path": "a", "sha256": "0" * 64, "size_bytes": 1}
        self.assertEqual(
            _manifest_files({"claims": KIT_CLAIMS, "files": [entry], "schema": KIT_SCHEMA}),
            {"a": (1, "0" * 64)},
        )
        with self.assertRaisesRegex(KitError, "kit_claims_pin"):
            _manifest_files({"claims": {**KIT_CLAIMS, "activation": 0}, "files": [entry], "schema": KIT_SCHEMA})
        with self.assertRaisesRegex(KitError, "kit_manifest_entry_value"):
            _manifest_files({"claims": KIT_CLAIMS, "files": [{**entry, "size_bytes": True}], "schema": KIT_SCHEMA})

    def test_kit_ships_every_file_the_staff_server_serves(self) -> None:
        # staff.js boots from /interaction-model.json; a kit without it serves a broken UI.
        self.assertLessEqual({"app/" + path for path, _type in _STATIC_FILES.values()}, set(STATE_FILES))

    def test_kit_requires_the_exact_retired_engine_registry(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertIn(RETIRED_PIN_REGISTRY, STATE_FILES)
        files = {path: (root / path).read_bytes() for path in (RETIRED_PIN_REGISTRY, "app/right_rail_financial_owner_independent.py")}
        _check_retired_pins(files.__getitem__)
        files[RETIRED_PIN_REGISTRY] += b"\n"
        with self.assertRaisesRegex(KitError, "^kit_retired_pins_mismatch$"):
            _check_retired_pins(files.__getitem__)
        with self.assertRaisesRegex(KitError, "^kit_state_source_inventory$"):
            _check_contents({p: (0, "0" * 64) for p in STATE_FILES if p != RETIRED_PIN_REGISTRY}, files.__getitem__)

    @staticmethod
    def _guard_log() -> str:
        # Independent v4 record fixture: producer emits CRLF on Windows.
        records = [
            "RESOURCE_POLICY version=v4 owner_waiver_effective=2026-09-23 process_tree_memory_cap=WAIVED_UNTIL_REVOKED "
            "physical_reserve_bytes=3221225472 physical_free_floor_bytes=2190433321 target_start_floor_bytes=4190433321 "
            "effective_start_floor_bytes=4190433321 tolerance_percent=32 process_tree_sampling=ENABLED cleanup=ENABLED "
            r"mutex=Local\BlindLedgerDirectMaskBuild20260907 activation=NONE",
            "PHYSICAL_PREFLIGHT free_bytes=5000000000 reserve_bytes=3221225472 reserve_floor_bytes=2190433321 "
            "target_start_floor_bytes=4190433321 effective_start_floor_bytes=4190433321 tolerance_percent=32",
        ]
        for label, code in (("child-exit-7", 7), ("child-exit-0", 0), ("Command", 0)):
            records += [
                f"CHILD_EXIT_STATUS label={label} exit={code}",
                f"LIVE_PHYSICAL_SUMMARY label={label} samples=1 min_free_bytes=3000000000 reserve_bytes=3221225472 "
                "peak_working_set_bytes=1000000 peak_private_bytes=2000000 reserve_floor_bytes=2190433321 tolerance_percent=32",
                f"CLEANUP=PASS label={label} owned_process_tree=empty",
            ]
        records += ["CHILD_EXIT_CHECK exit7=7 exit0=0", r"MUTEX=RELEASED name=Local\BlindLedgerDirectMaskBuild20260907"]
        return "\n".join(records) + "\n"

    def test_guard_log_accepts_lf_and_crlf_without_changing_policy(self) -> None:
        for ending in ("\n", "\r\n"):
            with self.subTest(ending=repr(ending)):
                _check_guard_log(self._guard_log().replace("\n", ending).encode("ascii"), 4_190_433_321, 3_000_000_000)

    def test_guard_log_rejects_adverse_records_with_either_line_ending(self) -> None:
        valid = self._guard_log()
        mutations = (
            ("activation=NONE", "activation=YES", "policy_mismatch"),
            ("tolerance_percent=32", "tolerance_percent=33", "policy_mismatch"),
            ("free_bytes=5000000000", "free_bytes=4190433320", "preflight_mismatch"),
            ("CHILD_EXIT_CHECK exit7=7 exit0=0", "CHILD_EXIT_CHECK exit7=0 exit0=0", "self_test_check"),
            ("CHILD_EXIT_STATUS label=Command exit=0", "CHILD_EXIT_STATUS label=Command exit=1", "target_child_status"),
            ("CLEANUP=PASS label=Command owned_process_tree=empty\n", "", "cleanup_inventory"),
            ("owned_process_tree=empty", "owned_process_tree=remaining", "cleanup_inventory"),
            ("samples=1", "samples=0", "summary_invalid"),
            ("min_free_bytes=3000000000", "min_free_bytes=2190433320", "summary_invalid"),
            ("min_free_bytes=3000000000", "min_free_bytes=3000000001", "minimum_free_mismatch"),
            ("MUTEX=RELEASED", "MUTEX=UNKNOWN", "mutex_release"),
            ("RESOURCE_POLICY ", "RESOURCE_POLICY unknown=1 ", "policy_mismatch"),
        )
        for ending in ("\n", "\r\n"):
            for old, new, code in mutations:
                with self.subTest(ending=repr(ending), mutation=code, old=old):
                    raw = valid.replace(old, new).replace("\n", ending).encode("ascii")
                    with self.assertRaisesRegex(KitError, "^engine_guard_log_" + code + "$"):
                        _check_guard_log(raw, 4_190_433_321, 3_000_000_000)
            for marker in ("RUNNER_FAILURE reason=bad", "CLEANUP=FAIL label=Command", "MUTEX=HELD_UNTIL_PROCESS_EXIT"):
                with self.subTest(ending=repr(ending), marker=marker):
                    with self.assertRaisesRegex(KitError, "^engine_guard_log_failure_marker$"):
                        _check_guard_log((valid + marker + "\n").replace("\n", ending).encode("ascii"), 4_190_433_321, 3_000_000_000)
            with self.subTest(ending=repr(ending), duplicate="policy"):
                with self.assertRaisesRegex(KitError, "^engine_guard_log_policy_mismatch$"):
                    _check_guard_log((valid + valid.splitlines()[0] + "\n").replace("\n", ending).encode("ascii"), 4_190_433_321, 3_000_000_000)
        with self.assertRaisesRegex(KitError, "^engine_guard_log_policy_mismatch$"):
            _check_guard_log(valid.replace("\n", "\r\r\n").encode("ascii"), 4_190_433_321, 3_000_000_000)

    def test_release_raw_process_returns_one_result_and_exact_bytes(self) -> None:
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh, "PowerShell 7 is required for the release producer regression")
        source = Path(__file__).resolve().parents[1] / "tools/build_financial_correction_release.ps1"
        lean_root = source.parents[1] / "lean"
        source_files = []
        for path in lean_root.rglob("*"):
            relative = path.relative_to(lean_root)
            if not path.is_file() or {".git", ".lake"}.intersection(relative.parts):
                continue
            if path.suffix != ".lean" and relative.as_posix() not in ("lakefile.toml", "lake-manifest.json", "lean-toolchain"):
                continue
            raw = path.read_bytes()
            source_files.append({"path": "engine/source/" + relative.as_posix(),
                                 "sha256": hashlib.sha256(raw).hexdigest().upper(), "size_bytes": len(raw)})
        expected_manifest = json.dumps({"files": sorted(source_files, key=lambda row: row["path"]),
                                        "schema": "RR/LEAN-ENGINE/SOURCE-MANIFEST/v1"},
                                       sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        harness = r"""
param([string]$Source, [string]$Executable, [string]$Child, [string]$Work, [string]$LeanRoot, [string]$InputBase64)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'producer_parse_error' }
foreach ($name in @('Invoke-RawProcess', 'Get-Sha256FromBytes', 'Write-FileCreateNew', 'Test-ByteArraysEqual', 'Write-RawChildBytes',
    'New-SourceManifestSnapshot', 'Get-SelectedSourcePaths', 'Get-RegularFileIdentity', 'Assert-NoReparsePathChain',
    'ConvertTo-JsonString', 'ConvertTo-CanonicalJsonText')) {
    $functions = @($ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true))
    if ($functions.Count -ne 1) { throw 'raw_process_function_count' }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
foreach ($name in @('SourceManifestSchema', 'Utf8Strict', 'RequiredSourcePaths')) {
    $assignments = @($ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq ('$script:' + $name)
    }, $true))
    if ($assignments.Count -ne 1) { throw 'producer_constant_count' }
    . ([scriptblock]::Create($assignments[0].Extent.Text))
}
$invoke = @{ Executable=$Executable; ArgumentList=@('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $Child); WorkingDirectory=$Work }
if ($PSBoundParameters.ContainsKey('InputBase64')) { $invoke['InputBytes'] = [Convert]::FromBase64String($InputBase64) }
$results = @(Invoke-RawProcess @invoke)
$record = [ordered]@{ count=$results.Count }
if ($results.Count -eq 1) {
    $record['exit_code'] = $results[0].ExitCode
    $record['stdout'] = [Convert]::ToBase64String($results[0].StdoutBytes)
    $record['stderr'] = [Convert]::ToBase64String($results[0].StderrBytes)
}
$empty = [byte[]]@()
$record['empty_stream_output_count'] = @(Write-RawChildBytes -Stream stdout -Bytes $empty; Write-RawChildBytes -Stream stderr -Bytes $empty).Count
$emptyPath = Join-Path $Work 'empty.log'
$record['empty_file_output_count'] = @(Write-FileCreateNew -Path $emptyPath -Bytes $empty).Count
$record['existing_file_refused'] = $false
try { Write-FileCreateNew -Path $emptyPath -Bytes ([byte[]]@(1)) }
catch { $record['existing_file_refused'] = $true }
$record['empty_file_size'] = (Get-Item -LiteralPath $emptyPath).Length
$record['empty_file_bytes'] = [Convert]::ToBase64String([IO.File]::ReadAllBytes($emptyPath))
$record['empty_sha256'] = Get-Sha256FromBytes -Bytes $empty
$record['empty_equal'] = Test-ByteArraysEqual -Left $empty -Right $empty
$record['empty_vs_byte'] = Test-ByteArraysEqual -Left $empty -Right ([byte[]]@(0))
$manifest = New-SourceManifestSnapshot -Root $LeanRoot
$record['source_manifest'] = [Convert]::ToBase64String($manifest.Bytes)
[Console]::Out.Write((ConvertTo-Json -InputObject $record -Compress))
"""
        emit = """
[Console]::OpenStandardOutput().Write([byte[]]@(0, 65, 255, 13, 10), 0, 5)
[Console]::OpenStandardError().Write([byte[]]@(128, 69, 0, 10), 0, 4)
exit 7
"""
        echo = """
$bytes = [IO.MemoryStream]::new()
$read = [Console]::OpenStandardInput().CopyToAsync($bytes)
if (-not $read.Wait(5000)) { [Environment]::Exit(9) }
$output = $bytes.ToArray()
[Console]::OpenStandardOutput().Write($output, 0, $output.Length)
exit 0
"""
        stdin = b"\x00input\xff\r\nline\n\x80"
        with tempfile.TemporaryDirectory(prefix="rightrail-raw-process-") as directory:
            script = Path(directory) / "invoke.ps1"
            script.write_text(harness, encoding="utf-8")
            for child, input_bytes, exit_code, stdout, stderr in (
                (emit, None, 7, b"\x00A\xff\r\n", b"\x80E\x00\n"),
                (echo, stdin, 0, stdin, b""),
            ):
                with self.subTest(exit_code=exit_code):
                    work = Path(directory) / str(exit_code)
                    work.mkdir()
                    encoded = base64.b64encode(child.encode("utf-16-le")).decode("ascii")
                    command = [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script),
                               "-Source", str(source), "-Executable", pwsh, "-Child", encoded, "-Work", str(work),
                               "-LeanRoot", str(lean_root)]
                    if input_bytes is not None:
                        command += ["-InputBase64", base64.b64encode(input_bytes).decode("ascii")]
                    result = subprocess.run(command, capture_output=True, timeout=20, cwd=directory)
                    self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                    self.assertEqual(result.stderr, b"")
                    record = json.loads(result.stdout)
                    self.assertEqual(record["count"], 1, record)
                    self.assertEqual(record["exit_code"], exit_code)
                    self.assertEqual(base64.b64decode(record["stdout"], validate=True), stdout)
                    self.assertEqual(base64.b64decode(record["stderr"], validate=True), stderr)
                    self.assertEqual(result.stdout, json.dumps(record, separators=(",", ":")).encode("ascii"))
                    self.assertEqual(record["empty_stream_output_count"], 0)
                    self.assertEqual(record["empty_file_output_count"], 0)
                    self.assertIs(record["existing_file_refused"], True)
                    self.assertEqual(record["empty_file_size"], 0)
                    self.assertEqual(base64.b64decode(record["empty_file_bytes"], validate=True), b"")
                    self.assertEqual(record["empty_sha256"], "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
                    self.assertIs(record["empty_equal"], True)
                    self.assertIs(record["empty_vs_byte"], False)
                    self.assertEqual(base64.b64decode(record["source_manifest"], validate=True), expected_manifest)


if __name__ == "__main__":
    unittest.main()
