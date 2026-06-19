param(
    [string]$ZipPath = "$env:USERPROFILE\Downloads\localBCE-codex-dev-hardened-20260616.zip"
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BadPatterns = @(
    '(^|[\\/])node_modules([\\/]|$)',
    '(^|[\\/])target([\\/]|$)',
    '(^|[\\/])\.pytest_cache([\\/]|$)',
    '(^|[\\/])__pycache__([\\/]|$)',
    '(^|[\\/])out([\\/]|$)',
    '(^|[\\/])cache([\\/]|$)',
    '(^|[\\/])broadcast([\\/]|$)',
    '(^|[\\/])nullifier_runtime([\\/]|$)',
    '(^|[\\/])build_nullifier([\\/]|$)',
    '(^|[\\/])keys_nullifier([\\/]|$)',
    '(^|[\\/])zk([\\/]|$)',
    ('(^|[\\/])zk-' + 'production' + '-binding([\\/]|$)'),
    ('(^|[\\/])zk-' + 'sp' + '1([\\/]|$)'),
    ('Generated' + 'Claim' + 'Verifier\.sol$'),
    ('Claim' + 'Verifier' + 'Adapter\.sol$'),
    ('Batch' + 'Gr' + 'oth' + '16VerifierAdapter\.sol$'),
    'BatchStubVerifier\.sol$',
    'MockNativeStarkVerifier\.sol$',
    'DeployMockNativeStarkSettlement\.s\.sol$',
    'deploy_mock_native_stark_settlement\.ps1$',
    'verifier_artifact_pin\.mock\.json$',
    '(^|[\\/])app[\\/]api\.py$',
    '(^|[\\/])app[\\/]orchestrator\.py$',
    '(^|[\\/])app[\\/]registry\.py$',
    '(^|[\\/])app[\\/]stubs\.py$',
    '(^|[\\/])app[\\/]decision_attestation\.py$',
    '(^|[\\/])app[\\/]dashboard\.py$',
    '(^|[\\/])dashboard([\\/]|$)',
    '\.wtns$',
    ('\.z' + 'key$'),
    ('\.p' + 'tau$'),
    ('\.r' + '1cs$'),
    '\.sym$',
    'pnpm-lock\.yaml$',
    'pnpm-workspace\.yaml$'
)

$bad = @()
Get-ChildItem -LiteralPath $RepoRoot -Recurse -Force | ForEach-Object {
    $rel = $_.FullName.Substring($RepoRoot.Length).TrimStart('\', '/')
    foreach ($pattern in $BadPatterns) {
        if ($rel -match $pattern) {
            $bad += $rel
            break
        }
    }
}
if ($bad.Count -gt 0) {
    $bad | ForEach-Object { Write-Error "Bloat entry present before zip: $_" }
    throw "Refusing to build bloated release zip."
}

if (Test-Path -LiteralPath $ZipPath) {
    Remove-Item -LiteralPath $ZipPath -Force
}
Compress-Archive -Path $RepoRoot -DestinationPath $ZipPath -CompressionLevel Optimal -Force

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
try {
    $zipBad = @()
    foreach ($entry in $archive.Entries) {
        $name = $entry.FullName
        foreach ($pattern in $BadPatterns) {
            if ($name -match $pattern) {
                $zipBad += $name
                break
            }
        }
    }
    if ($zipBad.Count -gt 0) {
        $zipBad | ForEach-Object { Write-Error "Bloat entry present in zip: $_" }
        throw "Release zip failed bloat inspection."
    }
}
finally {
    $archive.Dispose()
}

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $ZipPath
[pscustomobject]@{
    ZipPath = $ZipPath
    SizeBytes = (Get-Item -LiteralPath $ZipPath).Length
    SHA256 = $hash.Hash
} | Format-List
