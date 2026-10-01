"""Release-producer regression, shelved with the producer (not run by the suite; see README.md)."""

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class ReleaseProducerTests(unittest.TestCase):
    def test_release_raw_process_returns_one_result_and_exact_bytes(self) -> None:
        pwsh = shutil.which("pwsh")
        self.assertIsNotNone(pwsh, "PowerShell 7 is required for the release producer regression")
        source = Path(__file__).resolve().parent / "build_financial_correction_release.ps1"
        lean_root = source.parents[2] / "lean"
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
