param(
  [string]$ProverExe = 'C:\Temp\longfellow-v09-native-v3-relation-build\Release\longfellow_native_v3_prover.exe',
  [string]$Artifact = 'C:\Temp\longfellow-v09-native-v3-case0-reproduction.bin',
  [string]$StdoutPath = 'C:\Temp\longfellow-v09-native-v3-case0-reproduction.stdout.txt',
  [string]$StderrPath = 'C:\Temp\longfellow-v09-native-v3-case0-reproduction.stderr.txt',
  [int64]$WorkingSetCap = 5000000000
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ProverExe)) {
  throw "prover executable missing: $ProverExe"
}
foreach ($path in @($Artifact, $StdoutPath, $StderrPath)) {
  if (Test-Path -LiteralPath $path) {
    Remove-Item -LiteralPath $path -Force
  }
}

function Get-ProcessTreeIds([int]$RootId) {
  $all = @(Get-CimInstance Win32_Process)
  $ids = New-Object System.Collections.Generic.HashSet[int]
  [void]$ids.Add($RootId)
  $changed = $true
  while ($changed) {
    $changed = $false
    foreach ($process in $all) {
      if ($ids.Contains([int]$process.ParentProcessId) -and
          -not $ids.Contains([int]$process.ProcessId)) {
        [void]$ids.Add([int]$process.ProcessId)
        $changed = $true
      }
    }
  }
  return @($ids | ForEach-Object { [int]$_ })
}

$process = Start-Process -FilePath $ProverExe -ArgumentList @($Artifact, '0') `
  -WindowStyle Hidden -RedirectStandardOutput $StdoutPath `
  -RedirectStandardError $StderrPath -PassThru
$rootId = $process.Id
Write-Output "PROVER_MONITOR_START pid=$rootId"

$peakWorking = [int64]0
$peakPrivate = [int64]0
$samples = 0
$aborted = $false
$timedOut = $false
$perProcess = @{}

while ($true) {
  $ids = @(Get-ProcessTreeIds $rootId)
  $working = [int64]0
  $private = [int64]0
  $live = 0
  foreach ($id in $ids) {
    $current = Get-Process -Id $id -ErrorAction SilentlyContinue
    if ($null -ne $current) {
      $live++
      $working += [int64]$current.WorkingSet64
      $private += [int64]$current.PrivateMemorySize64
      if (-not $perProcess.ContainsKey($id)) {
        $perProcess[$id] = @{
          Name = $current.ProcessName
          PeakWorking = [int64]0
          PeakPrivate = [int64]0
        }
      }
      if ($current.WorkingSet64 -gt $perProcess[$id].PeakWorking) {
        $perProcess[$id].PeakWorking = [int64]$current.WorkingSet64
      }
      if ($current.PrivateMemorySize64 -gt $perProcess[$id].PeakPrivate) {
        $perProcess[$id].PeakPrivate = [int64]$current.PrivateMemorySize64
      }
    }
  }
  if ($working -gt $peakWorking) { $peakWorking = $working }
  if ($private -gt $peakPrivate) { $peakPrivate = $private }
  Write-Output "PROVER_SAMPLE n=$samples tree=$($ids.Count) live=$live working=$working private=$private"
  $samples++

  if ($working -gt $WorkingSetCap) {
    Write-Output "RESOURCE_ABORT_REQUIRED working=$working cap=$WorkingSetCap"
    $aborted = $true
    foreach ($id in ($ids | Sort-Object -Descending)) {
      Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
    }
    break
  }

  if ($null -eq (Get-Process -Id $rootId -ErrorAction SilentlyContinue)) {
    break
  }
  if ($samples -ge 600) {
    Write-Output 'RESOURCE_MONITOR_TIMEOUT'
    $timedOut = $true
    foreach ($id in ($ids | Sort-Object -Descending)) {
      Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
    }
    break
  }
  Start-Sleep -Milliseconds 2000
}

Start-Sleep -Milliseconds 500
foreach ($record in ($perProcess.GetEnumerator() | Sort-Object Name, Key)) {
  Write-Output ("PROCESS_PEAK pid={0} name={1} working={2} private={3}" -f `
    $record.Key, $record.Value.Name, $record.Value.PeakWorking, $record.Value.PeakPrivate)
}
$artifactExists = Test-Path -LiteralPath $Artifact
Write-Output ("PROVER_MONITOR_END aborted={0} timed_out={1} peak_working={2} peak_private={3} samples={4} artifact_exists={5}" -f `
  $aborted, $timedOut, $peakWorking, $peakPrivate, $samples, $artifactExists)
Write-Output '---STDOUT---'
if (Test-Path -LiteralPath $StdoutPath) { Get-Content -LiteralPath $StdoutPath -Raw }
Write-Output '---STDERR---'
if (Test-Path -LiteralPath $StderrPath) { Get-Content -LiteralPath $StderrPath -Raw }

if ($aborted -and $peakWorking -gt $WorkingSetCap) { exit 10 }
if ($timedOut) { exit 12 }
if ($artifactExists) { exit 11 }
exit 0
