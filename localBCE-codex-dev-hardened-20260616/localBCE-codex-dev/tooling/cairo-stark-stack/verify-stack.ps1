$ErrorActionPreference = "Stop"

$ScarbBin = Join-Path $env:USERPROFILE ".scarb\2.18.0\bin"
if (Test-Path (Join-Path $ScarbBin "scarb.exe")) {
    $env:Path = "$ScarbBin;$env:Path"
}

Write-Host "== Tool versions =="
foreach ($cmd in @("scarb", "cargo", "rustc", "forge", "cast", "anvil", "solc")) {
    $found = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "[OK] $cmd -> $($found.Source)"
        & $cmd --version 2>$null | Select-Object -First 1
    } else {
        Write-Host "[MISSING] $cmd"
    }
}

Write-Host "== Cairo binding =="
Push-Location (Join-Path $PSScriptRoot "..\..\blind-ledger-app-layer\zk-cairo-sharp")
try {
    scarb build
    scarb test
}
finally {
    Pop-Location
}

Write-Host "== Full buildable check =="
Push-Location (Join-Path $PSScriptRoot "..\..")
try {
    .\scripts\run_buildable_checks.ps1
}
finally {
    Pop-Location
}
