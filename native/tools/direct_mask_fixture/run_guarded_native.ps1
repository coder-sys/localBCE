param(
  [Parameter(Mandatory = $true)][string]$CommandPath,
  [Parameter(Mandatory = $true)][string]$RunSuffix,
  [Parameter(Mandatory = $true)][string]$Label,
  [string[]]$CommandArguments = @()
)

$ErrorActionPreference = 'Stop'
$Root = 'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-direct-mask-filter-native-20260912'
$BuildRoot = Join-Path $Root 'build-filter-native'
$MutexName = 'Local\BlindLedgerDirectMaskBuild20260907'
[uint64]$PhysicalReserveBytes = 1073741824
[uint64]$ProcessTreeCapBytes = 5000000000
$PollMilliseconds = 250
$stdoutPath = Join-Path $BuildRoot ("guarded-{0}-{1}.stdout.log" -f $Label.ToLowerInvariant(), $RunSuffix)
$stderrPath = Join-Path $BuildRoot ("guarded-{0}-{1}.stderr.log" -f $Label.ToLowerInvariant(), $RunSuffix)

if (-not (Test-Path -LiteralPath $BuildRoot -PathType Container)) { throw "missing build root: $BuildRoot" }
if (-not (Test-Path -LiteralPath $CommandPath -PathType Leaf)) { throw "missing command: $CommandPath" }
if ((Test-Path -LiteralPath $stdoutPath) -or (Test-Path -LiteralPath $stderrPath)) {
  throw "refusing to overwrite guard logs: $RunSuffix"
}

function Get-TreeRecords([int]$RootPid) {
  $records = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
  $ids = New-Object 'System.Collections.Generic.HashSet[int]'
  [void]$ids.Add($RootPid)
  do {
    $changed = $false
    foreach ($record in $records) {
      if ($ids.Contains([int]$record.ParentProcessId) -and $ids.Add([int]$record.ProcessId)) {
        $changed = $true
      }
    }
  } while ($changed)
  return @($records | Where-Object { $ids.Contains([int]$_.ProcessId) })
}

function Get-Sample([int]$RootPid) {
  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  if ($null -eq $os.FreePhysicalMemory) { throw 'free physical memory was unavailable' }
  $records = @(Get-TreeRecords $RootPid)
  [uint64]$working = 0
  [uint64]$private = 0
  foreach ($record in $records) {
    if ($null -eq $record.WorkingSetSize -or $null -eq $record.PrivatePageCount) {
      throw "incomplete memory observation for PID $($record.ProcessId)"
    }
    $working += [uint64]$record.WorkingSetSize
    $private += [uint64]$record.PrivatePageCount
  }
  [pscustomobject]@{
    FreePhysicalBytes = [uint64]$os.FreePhysicalMemory * 1024
    WorkingSetBytes = $working
    PrivateBytes = $private
    ProcessCount = $records.Count
  }
}

function Stop-Tree([int]$RootPid) {
  $records = @(Get-TreeRecords $RootPid)
  foreach ($record in @($records | Sort-Object @{Expression = { [int]$_.ProcessId }; Descending = $true})) {
    try { Stop-Process -Id ([int]$record.ProcessId) -Force -ErrorAction Stop }
    catch { if (Get-Process -Id ([int]$record.ProcessId) -ErrorAction SilentlyContinue) {
        throw "failed to stop owned PID $($record.ProcessId): $($_.Exception.Message)" } }
  }
}

function Ensure-Stopped([int]$RootPid) {
  for ($attempt = 0; $attempt -lt 120; ++$attempt) {
    $remaining = @(Get-TreeRecords $RootPid)
    if ($remaining.Count -eq 0) { return }
    if ($attempt -eq 0) { Stop-Tree $RootPid }
    Start-Sleep -Milliseconds $PollMilliseconds
  }
  throw "owned process tree cleanup unresolved"
}

function Quote-Argument([string]$Argument) {
  if ($Argument -notmatch '[\s"]') { return $Argument }
  return '"' + $Argument.Replace('"', '\"') + '"'
}

$mutex = New-Object System.Threading.Mutex($false, $MutexName)
$mutexAcquired = $false
$process = $null
$rootPid = 0
$stdoutTask = $null
$stderrTask = $null
$exitStatus = 1
$failure = $null
$cleanupFailure = $null

try {
  if (-not $mutex.WaitOne(0)) { throw "mutex is already held: $MutexName" }
  $mutexAcquired = $true
  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  [uint64]$preflightFree = [uint64]$os.FreePhysicalMemory * 1024
  Write-Output "PHYSICAL_PREFLIGHT free_bytes=$preflightFree reserve_bytes=$PhysicalReserveBytes"
  if ($preflightFree -lt $PhysicalReserveBytes) { throw 'physical-memory preflight below reserve' }

  $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $CommandPath
  $startInfo.WorkingDirectory = $BuildRoot
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $startInfo.Arguments = [string]::Join(' ', @($CommandArguments | ForEach-Object { Quote-Argument $_ }))
  $process = [System.Diagnostics.Process]::new()
  $process.StartInfo = $startInfo
  if (-not $process.Start()) { throw "process start returned false for $Label" }
  $rootPid = [int]$process.Id
  Write-Output "LAUNCH label=$Label pid=$rootPid command=$CommandPath"
  $stdoutTask = $process.StandardOutput.ReadToEndAsync()
  $stderrTask = $process.StandardError.ReadToEndAsync()
  $sampleCount = 0
  [uint64]$minimumFree = [uint64]::MaxValue
  [uint64]$peakWorking = 0
  [uint64]$peakPrivate = 0
  while ($true) {
    $sample = Get-Sample $rootPid
    ++$sampleCount
    if ($sample.FreePhysicalBytes -lt $minimumFree) { $minimumFree = $sample.FreePhysicalBytes }
    if ($sample.WorkingSetBytes -gt $peakWorking) { $peakWorking = $sample.WorkingSetBytes }
    if ($sample.PrivateBytes -gt $peakPrivate) { $peakPrivate = $sample.PrivateBytes }
    Write-Output ("LIVE_SAMPLE label={0} index={1} free_bytes={2} working_set_bytes={3} private_bytes={4} process_count={5}" -f $Label, $sampleCount, $sample.FreePhysicalBytes, $sample.WorkingSetBytes, $sample.PrivateBytes, $sample.ProcessCount)
    if ($sample.FreePhysicalBytes -lt $PhysicalReserveBytes) { throw "free physical memory below reserve" }
    if ($sample.WorkingSetBytes -ge $ProcessTreeCapBytes -or $sample.PrivateBytes -ge $ProcessTreeCapBytes) { throw "process tree reached memory cap" }
    if ($sample.ProcessCount -eq 0) { break }
    Start-Sleep -Milliseconds $PollMilliseconds
  }
  if (-not $process.HasExited) { $process.WaitForExit() }
  $process.Refresh()
  $exitStatus = [int]$process.ExitCode
  Write-Output "CHILD_EXIT_STATUS label=$Label exit=$exitStatus"
  Write-Output ("LIVE_PHYSICAL_SUMMARY label={0} samples={1} min_free_bytes={2} reserve_bytes={3} peak_working_set_bytes={4} peak_private_bytes={5}" -f $Label, $sampleCount, $minimumFree, $PhysicalReserveBytes, $peakWorking, $peakPrivate)
  if ($exitStatus -ne 0) { throw "$Label child exited $exitStatus" }
} catch {
  $failure = $_.Exception.Message
  Write-Output "GUARD_STOP label=$Label reason=$failure"
  if ($rootPid -ne 0) { try { Stop-Tree $rootPid } catch { $cleanupFailure = $_.Exception.Message } }
} finally {
  if ($rootPid -ne 0) { try { Ensure-Stopped $rootPid } catch { $cleanupFailure = $_.Exception.Message } }
  if ($null -ne $stdoutTask) {
    try {
      [IO.File]::WriteAllText($stdoutPath, $stdoutTask.GetAwaiter().GetResult())
      [IO.File]::WriteAllText($stderrPath, $stderrTask.GetAwaiter().GetResult())
    } catch { $cleanupFailure = "output capture failed: $($_.Exception.Message)" }
  }
  if ($null -ne $cleanupFailure) { Write-Output "CLEANUP=FAIL label=$Label reason=$cleanupFailure" }
  else { Write-Output "CLEANUP=PASS label=$Label owned_process_tree=empty" }
  if ($mutexAcquired) { [void]$mutex.ReleaseMutex(); $mutex.Dispose(); Write-Output "MUTEX=RELEASED name=$MutexName" }
  else { $mutex.Dispose() }
}

if ($null -ne $cleanupFailure -or $null -ne $failure) { exit 1 }
exit $exitStatus
