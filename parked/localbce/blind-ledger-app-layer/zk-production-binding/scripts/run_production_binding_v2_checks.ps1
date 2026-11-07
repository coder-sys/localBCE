param(
    [string]$RepoRoot = "C:\Users\neers\Documents\Codex\blind-ledger-app-layer"
)

$ErrorActionPreference = "Stop"

$node = "C:\Users\neers\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
$circom = Join-Path $RepoRoot "toolchains\circom\bin\circom.exe"
$snarkjs = Join-Path $RepoRoot "zk\node_modules\snarkjs\build\cli.cjs"
$circuit = Join-Path $RepoRoot "zk-production-binding\circuits\production_binding_v2.circom"
$build = Join-Path $RepoRoot "zk-production-binding\build-v2"
$inputs = Join-Path $RepoRoot "zk-production-binding\inputs-v2"
$report = Join-Path $RepoRoot "zk-production-binding\production_binding_v2_run_report.json"

New-Item -ItemType Directory -Force -Path $build | Out-Null
Remove-Item -Recurse -Force (Join-Path $build "*") -ErrorAction SilentlyContinue

& $node (Join-Path $RepoRoot "zk-production-binding\scripts\make_production_binding_v2_inputs.js")
& $circom $circuit --r1cs --wasm --sym -o $build

$wasm = Join-Path $build "production_binding_v2_js\production_binding_v2.wasm"
$r1cs = Join-Path $build "production_binding_v2.r1cs"

$cases = @(
    @{ name = "approved"; file = "approved.json"; expect = "pass" },
    @{ name = "ineligible_denied"; file = "ineligible_denied.json"; expect = "pass" },
    @{ name = "fabricated_oracle_facts"; file = "fabricated_oracle_facts.json"; expect = "fail" },
    @{ name = "fake_fee_ceiling"; file = "fake_fee_ceiling.json"; expect = "fail" },
    @{ name = "raw_hash_double_pay_attempt"; file = "raw_hash_double_pay_attempt.json"; expect = "fail" },
    @{ name = "member_swap_collision_attempt"; file = "member_swap_collision_attempt.json"; expect = "fail" },
    @{ name = "procedure_substitution_attempt"; file = "procedure_substitution_attempt.json"; expect = "fail" },
    @{ name = "recipient_redirect"; file = "recipient_redirect.json"; expect = "fail" },
    @{ name = "prior_auth_bypass"; file = "prior_auth_bypass.json"; expect = "fail" },
    @{ name = "duplicate_replay_forged_nonmembership"; file = "duplicate_replay_forged_nonmembership.json"; expect = "fail" },
    @{ name = "overwide_amount"; file = "overwide_amount.json"; expect = "fail" }
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
    circuit = "zk-production-binding/circuits/production_binding_v2.circom"
    status = "compiled-circuit-claim-source-and-membership-binding-checks-pending-crypto-audit"
    tooling = [pscustomobject]@{
        circom = (& $circom --version)
        node = (& $node --version)
        snarkjs = "0.7.6"
    }
    r1cs_info = ($infoText -join "`n")
    cases = $results
    closed_findings = @(
        "normalized claim facts require Merkle inclusion under claimSourceRoot",
        "nullifier is derived from the claim source leaf plus member/provider/service/procedure identity",
        "oracle facts require Merkle inclusion under oracleFactsRoot",
        "fee allowed amount and priorAuthRequired require Merkle inclusion under feeScheduleRoot",
        "recipientField requires Merkle inclusion under addressBookRoot",
        "nullifier is derived from claim facts and inserted through a sparse empty-slot transition",
        "payment amount equals governed allowed amount on approval",
        "amount/date values have 32-bit range constraints"
    )
    caveats = @(
        "This is still Circom/Groth16-oriented, not end-to-end post-quantum.",
        "The verifier/contract must pin claimSourceRoot, oracleFactsRoot, feeScheduleRoot, addressBookRoot, rulesetRoot, and nullifierRootBefore to governed on-chain state.",
        "The nullifier transition is an auditable sparse-slot/indexed construction, but still pending external cryptographic audit.",
        "The circuit prevents duplicate approval by making replayed nullifier proofs invalid; it does not separately produce a duplicate-denial proof in this v2 lane.",
        "The circuit proves membership against a trusted parsed-claim root; it still does not parse raw 837 bytes inside Circom."
    )
}

$json | ConvertTo-Json -Depth 8 | Set-Content -Path $report -Encoding UTF8
$failed = $results | Where-Object { -not $_.matched }
if ($failed.Count -gt 0) {
    Write-Error "production binding v2 checks did not match expected pass/fail outcomes"
}

Write-Output ($json | ConvertTo-Json -Depth 8)
