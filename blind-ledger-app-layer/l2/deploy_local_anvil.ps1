param(
    [string]$RpcUrl = "http://127.0.0.1:8546",
    [string]$PrivateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Contracts = Join-Path $Root "contracts"
$Forge = Join-Path $Root "toolchains\foundry\bin\forge.exe"
$OutDir = Join-Path $Root "l2\deployments"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Deploy-Contract {
    param(
        [string]$Name,
        [string]$Target,
        [string[]]$ConstructorArgs = @()
    )

    $cmd = @(
        "create",
        $Target,
        "--rpc-url", $RpcUrl,
        "--private-key", $PrivateKey,
        "--broadcast"
    ) + $ConstructorArgs

    $output = & $Forge @cmd 2>&1
    $text = $output | Out-String
    $text | Set-Content -Encoding utf8 (Join-Path $OutDir "$Name.log")
    $match = [regex]::Match($text, "Deployed to:\s*(0x[a-fA-F0-9]{40})")
    $address = if ($match.Success) { $match.Groups[1].Value } else { $null }
    if (-not $address) {
        throw "Could not parse deployment address for $Name. See l2\deployments\$Name.log"
    }
    return $address
}

Push-Location $Contracts
try {
    & $Forge build | Out-File -Encoding utf8 (Join-Path $OutDir "forge-build.log")

    $verifier = Deploy-Contract "Groth16Verifier" "src/GeneratedClaimVerifier.sol:Groth16Verifier"
    $adapter = Deploy-Contract "ClaimVerifierAdapter" "src/ClaimVerifierAdapter.sol:ClaimVerifierAdapter" @("--constructor-args", $verifier)
    $claims = Deploy-Contract "ClaimsRegistry" "src/ClaimsRegistry.sol:ClaimsRegistry" @("--constructor-args", $adapter)
    $circle = Deploy-Contract "CircleBridgeStub" "src/IBridge.sol:CircleBridgeStub"
    $payment = Deploy-Contract "PaymentTrigger" "src/PaymentTrigger.sol:PaymentTrigger" @("--constructor-args", $circle)
    $governance = Deploy-Contract "GovernanceRegistry" "src/GovernanceRegistry.sol:GovernanceRegistry"

    $deployment = [ordered]@{
        label = "LOCAL DEVNET ONLY"
        rpc_url = $RpcUrl
        verifier = $verifier
        verifier_adapter = $adapter
        claims_registry = $claims
        circle_bridge_stub = $circle
        payment_trigger = $payment
        governance_registry = $governance
        production_note = "Production L2 operation is devops: sequencer/proposer nodes, L1 settlement, monitoring, key management, and incident response."
    }
    $deployment | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $OutDir "local_anvil_deployment.json")
    $deployment | ConvertTo-Json -Depth 5
}
finally {
    Pop-Location
}
