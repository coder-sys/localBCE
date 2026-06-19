param(
    [switch]$SkipRust,
    [switch]$SkipForge
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Body
    )
    Write-Host "== $Name =="
    & $Body
}

Invoke-Step "Operational readiness manifests" {
    Push-Location $RepoRoot
    try { python scripts\validate_operational_readiness.py }
    finally { Pop-Location }
}

Invoke-Step "App-layer Python tests" {
    Push-Location (Join-Path $RepoRoot "blind-ledger-app-layer")
    try { python -m pytest -q }
    finally { Pop-Location }
}

Invoke-Step "KG Python tests" {
    Push-Location (Join-Path $RepoRoot "gov-rules-kg-prototype")
    try {
        $env:PYTHONPATH = "src"
        python -m pytest tests\test_legal_grade_foundation.py -q
    }
    finally { Pop-Location }
}

Invoke-Step "Cairo binding build and tests" {
    Push-Location (Join-Path $RepoRoot "blind-ledger-app-layer\zk-cairo-sharp")
    try {
        $ScarbBin = Join-Path $env:USERPROFILE ".scarb\2.18.0\bin"
        if (Test-Path (Join-Path $ScarbBin "scarb.exe")) {
            $env:Path = "$ScarbBin;$env:Path"
        }
        scarb build
        scarb test
    }
    finally { Pop-Location }
}

if (-not $SkipForge) {
    Invoke-Step "App-layer Forge tests" {
        Push-Location (Join-Path $RepoRoot "blind-ledger-app-layer\contracts")
        try { forge test }
        finally { Pop-Location }
    }
}

if (-not $SkipRust) {
    Invoke-Step "Rules engine Rust tests" {
        Push-Location (Join-Path $RepoRoot "blind-ledger-app-layer\rules-engine-rust")
        try {
            $env:CARGO_TARGET_DIR = Join-Path $env:TEMP "blind-ledger-rules-engine-target"
            cargo +1.96.0-x86_64-pc-windows-msvc test --lib --bins --tests
        }
        finally { Pop-Location }
    }
    Invoke-Step "STARK Rust tests without doctests" {
        Push-Location (Join-Path $RepoRoot "blind-ledger-app-layer\zk-stark")
        try {
            $env:CARGO_TARGET_DIR = Join-Path $env:TEMP "blind-ledger-zk-stark-target"
            cargo test --lib --bins --tests
        }
        finally { Pop-Location }
    }
}
