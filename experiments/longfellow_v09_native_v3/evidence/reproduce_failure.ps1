param(
  [Parameter(Mandatory = $true)][string]$UpstreamRoot,
  [string]$PatchedRoot = 'C:\Temp\longfellow-v09-native-v3-reproduction-source',
  [string]$BuildRoot = 'C:\Temp\longfellow-v09-native-v3-reproduction-build',
  [string]$Artifact = 'C:\Temp\longfellow-v09-native-v3-reproduction.bin'
)

$ErrorActionPreference = 'Stop'
$experimentRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$prepare = Join-Path $experimentRoot 'prepare_pinned_source.ps1'
$measure = Join-Path $experimentRoot 'evidence\measure_prover.ps1'

foreach ($path in @($PatchedRoot, $BuildRoot)) {
  if (Test-Path -LiteralPath $path) {
    throw "refusing to reuse existing reproduction target: $path"
  }
}

Write-Output "REPRO_EXPERIMENT_ROOT=$experimentRoot"
Write-Output "REPRO_UPSTREAM_ROOT=$UpstreamRoot"
Write-Output "REPRO_PATCHED_ROOT=$PatchedRoot"
Write-Output "REPRO_BUILD_ROOT=$BuildRoot"
Write-Output 'REPRO_COMMAND=prepare_pinned_source.ps1'
& powershell -NoProfile -ExecutionPolicy Bypass -File $prepare `
  -UpstreamRoot $UpstreamRoot -PatchFile (Join-Path $experimentRoot 'patches\sha3_512_circuit.patch') `
  -PatchedRoot $PatchedRoot
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output 'REPRO_COMMAND=cmake configure Visual Studio 17 2022 x64 C++20'
& cmake -S $experimentRoot -B $BuildRoot -G 'Visual Studio 17 2022' -A x64 `
  "-DLONGFELLOW_SOURCE=$PatchedRoot"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output 'REPRO_COMMAND=cmake build longfellow_native_v3_prover Release parallel=2'
& cmake --build $BuildRoot --config Release --target longfellow_native_v3_prover --parallel 2
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output 'REPRO_COMMAND=process-tree measurement cap=5000000000'
& powershell -NoProfile -ExecutionPolicy Bypass -File $measure `
  -ProverExe (Join-Path $BuildRoot 'Release\longfellow_native_v3_prover.exe') `
  -Artifact $Artifact `
  -StdoutPath "$Artifact.stdout.txt" `
  -StderrPath "$Artifact.stderr.txt" `
  -WorkingSetCap 5000000000
$measurementExit = $LASTEXITCODE
Write-Output "REPRO_MEASUREMENT_EXIT=$measurementExit"
if ($measurementExit -eq 10) {
  Write-Output 'REPRO_DISPOSITION=ENGINEERING_RED_RESOURCE_GATE'
}
exit $measurementExit
