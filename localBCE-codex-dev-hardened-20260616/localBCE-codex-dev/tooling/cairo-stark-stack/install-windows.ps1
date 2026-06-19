param(
    [string]$ScarbVersion = "2.18.0",
    [switch]$SkipScarb
)

$ErrorActionPreference = "Stop"

function Add-UserPath {
    param([Parameter(Mandatory = $true)][string]$PathToAdd)
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($userPath -split ";") -notcontains $PathToAdd) {
        [Environment]::SetEnvironmentVariable("Path", ($userPath.TrimEnd(";") + ";" + $PathToAdd), "User")
    }
    $env:Path = "$PathToAdd;$env:Path"
}

function Install-Scarb {
    param([Parameter(Mandatory = $true)][string]$Version)

    $base = "https://github.com/software-mansion/scarb/releases/download/v$Version"
    $zipName = "scarb-v$Version-x86_64-pc-windows-msvc.zip"
    $downloadDir = Join-Path $env:TEMP "blind-ledger-scarb-$Version"
    $installRoot = Join-Path $env:USERPROFILE ".scarb"
    $installDir = Join-Path $installRoot $Version
    $zipPath = Join-Path $downloadDir $zipName
    $checksumsPath = Join-Path $downloadDir "checksums.sha256"

    New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null
    New-Item -ItemType Directory -Force -Path $installRoot | Out-Null
    Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $checksumsPath -Force -ErrorAction SilentlyContinue

    curl.exe -L --retry 5 --retry-delay 2 --connect-timeout 30 -o $zipPath "$base/$zipName"
    curl.exe -L --retry 5 --retry-delay 2 --connect-timeout 30 -o $checksumsPath "$base/checksums.sha256"

    $expectedLine = Get-Content -LiteralPath $checksumsPath | Where-Object { $_ -match [regex]::Escape($zipName) } | Select-Object -First 1
    if (-not $expectedLine) {
        throw "No checksum entry found for $zipName"
    }
    $expected = $expectedLine.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)[0].ToUpperInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToUpperInvariant()
    if ($actual -ne $expected) {
        throw "Scarb checksum mismatch. Expected $expected, got $actual"
    }

    if (Test-Path -LiteralPath $installDir) {
        Remove-Item -LiteralPath $installDir -Recurse -Force
    }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $installRoot -Force
    $expanded = Get-ChildItem -LiteralPath $installRoot -Directory | Where-Object { $_.Name -like "scarb-v$Version*" } | Select-Object -First 1
    if (-not $expanded) {
        throw "Scarb archive did not extract to the expected directory"
    }
    if ($expanded.FullName -ne $installDir) {
        Move-Item -LiteralPath $expanded.FullName -Destination $installDir
    }

    $bin = Join-Path $installDir "bin"
    $scarb = Join-Path $bin "scarb.exe"
    if (-not (Test-Path -LiteralPath $scarb)) {
        throw "Missing scarb.exe at $scarb"
    }
    Add-UserPath $bin
    & $scarb --version
}

if (-not $SkipScarb) {
    Install-Scarb -Version $ScarbVersion
}

Write-Host ""
Write-Host "Checking local stack..."
foreach ($cmd in @("scarb", "cargo", "rustc", "forge", "cast", "anvil", "solc")) {
    $found = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "[OK] $cmd -> $($found.Source)"
    } else {
        Write-Host "[MISSING] $cmd"
    }
}

Write-Host ""
Write-Host "For Starknet Foundry on Windows, use WSL/Ubuntu:"
Write-Host "  bash tooling/cairo-stark-stack/install-wsl-ubuntu.sh"
Write-Host ""
Write-Host "Then verify the repo:"
Write-Host "  .\tooling\cairo-stark-stack\verify-stack.ps1"
