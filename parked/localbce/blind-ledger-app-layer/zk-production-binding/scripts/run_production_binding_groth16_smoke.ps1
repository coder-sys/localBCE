param(
    [string]$RepoRoot = "C:\Users\neers\Documents\Codex\blind-ledger-app-layer"
)

$ErrorActionPreference = "Stop"

$node = "C:\Users\neers\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
$snarkjs = Join-Path $RepoRoot "zk\node_modules\snarkjs\build\cli.cjs"
$build = Join-Path $RepoRoot "zk-production-binding\build"
$r1cs = Join-Path $build "production_binding_v0.r1cs"
$wtns = Join-Path $build "approved.wtns"
$report = Join-Path $RepoRoot "zk-production-binding\production_binding_proof_report.json"

if (-not (Test-Path $r1cs) -or -not (Test-Path $wtns)) {
    & (Join-Path $RepoRoot "zk-production-binding\scripts\run_production_binding_checks.ps1") -RepoRoot $RepoRoot | Out-Null
}

$pot0 = Join-Path $build "pot13_0000.ptau"
$pot1 = Join-Path $build "pot13_0001.ptau"
$potFinal = Join-Path $build "pot13_final.ptau"
$zkey0 = Join-Path $build "production_binding_0000.zkey"
$zkeyFinal = Join-Path $build "production_binding_final.zkey"
$verificationKey = Join-Path $build "verification_key.json"
$proof = Join-Path $build "approved_proof.json"
$public = Join-Path $build "approved_public.json"
$tamperedPublic = Join-Path $build "tampered_public_decision.json"

$start = Get-Date
& $node $snarkjs powersoftau new bn128 13 $pot0
& $node $snarkjs powersoftau contribute $pot0 $pot1 --name="local production binding test contribution" -e="local deterministic non-production entropy"
& $node $snarkjs powersoftau prepare phase2 $pot1 $potFinal
& $node $snarkjs groth16 setup $r1cs $potFinal $zkey0
& $node $snarkjs zkey contribute $zkey0 $zkeyFinal --name="local zkey contribution" -e="local deterministic non-production zkey entropy"
& $node $snarkjs zkey export verificationkey $zkeyFinal $verificationKey
& $node $snarkjs groth16 prove $zkeyFinal $wtns $proof $public
$verifyOutput = & $node $snarkjs groth16 verify $verificationKey $public $proof 2>&1
$verifyExit = $LASTEXITCODE

@'
const fs = require("fs");
const values = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
values[11] = values[11] === "1" ? "0" : "1";
fs.writeFileSync(process.argv[3], JSON.stringify(values, null, 2));
'@ | & $node - $public $tamperedPublic

$tamperOutput = & $node $snarkjs groth16 verify $verificationKey $tamperedPublic $proof 2>&1
$tamperExit = $LASTEXITCODE
$elapsed = ((Get-Date) - $start).TotalSeconds

$json = [pscustomobject]@{
    status = "groth16-smoke-proof-generated-and-verified-pending-crypto-audit"
    caveat = "This smoke proof is Groth16 over the Circom production-binding circuit. It is not post-quantum and the local setup is not a production ceremony."
    elapsed_seconds = [math]::Round($elapsed, 3)
    approved_proof = [pscustomobject]@{
        verify_exit_code = $verifyExit
        verify_output = ($verifyOutput -join "`n")
        proof_size_bytes = (Get-Item $proof).Length
        proof_sha256 = (Get-FileHash -Algorithm SHA256 $proof).Hash
        public_sha256 = (Get-FileHash -Algorithm SHA256 $public).Hash
    }
    tampered_public_decision = [pscustomobject]@{
        expected = "reject"
        verify_exit_code = $tamperExit
        verify_output = ($tamperOutput -join "`n")
        rejected = ($tamperExit -ne 0)
    }
}

$json | ConvertTo-Json -Depth 8 | Set-Content -Path $report -Encoding UTF8
Write-Output ($json | ConvertTo-Json -Depth 8)
