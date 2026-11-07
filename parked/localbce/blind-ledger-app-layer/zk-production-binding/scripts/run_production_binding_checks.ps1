param(
    [string]$RepoRoot = "C:\Users\neers\Documents\Codex\blind-ledger-app-layer"
)

$ErrorActionPreference = "Stop"

$node = "C:\Users\neers\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
$circom = Join-Path $RepoRoot "toolchains\circom\bin\circom.exe"
$snarkjs = Join-Path $RepoRoot "zk\node_modules\snarkjs\build\cli.cjs"
$circuit = Join-Path $RepoRoot "zk-production-binding\circuits\production_binding_v0.circom"
$build = Join-Path $RepoRoot "zk-production-binding\build"
$inputs = Join-Path $RepoRoot "zk-production-binding\inputs"
$report = Join-Path $RepoRoot "zk-production-binding\production_binding_run_report.json"

New-Item -ItemType Directory -Force -Path $build | Out-Null
Remove-Item -Recurse -Force (Join-Path $build "*") -ErrorAction SilentlyContinue

& $node (Join-Path $RepoRoot "zk-production-binding\scripts\make_production_binding_inputs.js")
& $circom $circuit --r1cs --wasm --sym -o $build

$wasm = Join-Path $build "production_binding_v0_js\production_binding_v0.wasm"
$r1cs = Join-Path $build "production_binding_v0.r1cs"

$cases = @(
    @{ name = "approved"; file = "approved.json"; expect = "pass" },
    @{ name = "duplicate_denied"; file = "duplicate_denied.json"; expect = "pass" },
    @{ name = "tampered_oracle_root"; file = "tampered_oracle_root.json"; expect = "fail" },
    @{ name = "fee_too_low_forced_approved"; file = "fee_too_low_forced_approved.json"; expect = "fail" },
    @{ name = "recipient_swap"; file = "recipient_swap.json"; expect = "fail" }
)

$results = @()
foreach ($case in $cases) {
    $inputPath = Join-Path $inputs $case.file
    $wtns = Join-Path $build "$($case.name).wtns"
    $stdout = Join-Path $build "$($case.name).stdout.txt"
    $stderr = Join-Path $build "$($case.name).stderr.txt"
    $ok = $true
    try {
        & $node $snarkjs wtns calculate $wasm $inputPath $wtns > $stdout 2> $stderr
        & $node $snarkjs wtns check $r1cs $wtns >> $stdout 2>> $stderr
    } catch {
        $ok = $false
    }
    $actual = if ($ok) { "pass" } else { "fail" }
    $results += [pscustomobject]@{
        case = $case.name
        expected = $case.expect
        actual = $actual
        matched = ($actual -eq $case.expect)
    }
}

$infoText = & $node $snarkjs r1cs info $r1cs 2>&1
$json = [pscustomobject]@{
    circuit = "zk-production-binding/circuits/production_binding_v0.circom"
    status = "compiled-circuit-local-witness-checks-pending-crypto-audit"
    tooling = [pscustomobject]@{
        circom = (& $circom --version)
        node = (& $node --version)
        snarkjs = "0.7.6"
    }
    r1cs_info = ($infoText -join "`n")
    cases = $results
    caveats = @(
        "This is a Circom production-binding circuit, not a native STARK/Cairo circuit.",
        "It binds the raw-claim digest, oracle facts root, fee root, result, payment, nullifier transition, ruleset root, and combined commitment.",
        "It does not parse raw 837 text in-circuit.",
        "It does not verify Ed25519 oracle signatures in-circuit; signed-oracle governance remains outside this circuit in the app harness.",
        "Ceiling label: soundness-checked by compile/witness tests, PENDING CRYPTOGRAPHIC AUDIT."
    )
}

$json | ConvertTo-Json -Depth 8 | Set-Content -Path $report -Encoding UTF8
$failed = $results | Where-Object { -not $_.matched }
if ($failed.Count -gt 0) {
    Write-Error "production binding checks did not match expected pass/fail outcomes"
}

Write-Output ($json | ConvertTo-Json -Depth 8)
