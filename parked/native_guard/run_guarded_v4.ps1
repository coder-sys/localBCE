param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('Configure', 'Build', 'CTest', 'Command')]
  [string]$Mode,
  [Parameter(Mandatory = $true)]
  [string]$RunSuffix,
  [string]$CTestRegex = '^(direct_mask_fixture_probe)$',
  [string]$CommandPath = '',
  [string[]]$CommandArguments = @(),
  [Parameter(Mandatory = $true)]
  [uint64]$MinimumStartFreeBytes
)

$ErrorActionPreference = 'Stop'

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$ChildDirectory = Split-Path -Parent $ScriptDirectory
$BuildRoot = $ScriptDirectory
$BuildDirectory = Join-Path $BuildRoot 'acceleration-correction'
$SourceDirectory = $ChildDirectory
$FixtureSourceDirectory = Join-Path $SourceDirectory 'tools\direct_mask_fixture'
$VoleSourceDirectory = Join-Path $SourceDirectory 'tools\direct_mask_vole'
$PipelineSourceDirectory = Join-Path $SourceDirectory 'tools\direct_mask_pipeline'
$FaestSourceDirectory = 'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-direct-mask-source-auth-20260908\vendor\faest-ref'
$MldsaRoot = 'C:\Users\neers\Documents\Codex\2026-08-31\blind-zkbpp-c-profile11-extmu-v1'
$DmcSourceDirectory = 'C:\Users\neers\Documents\Codex\2026-09-04\blind-ledger-astra-driver-v1\work\pq-aes-circuit-export-20260907\tools\direct_mask_circuit'
$PmbBuildDirectory = 'C:\Users\neers\Documents\Codex\2026-09-04\pmb-20260908'
$MutexName = 'Local\BlindLedgerDirectMaskBuild20260907'
$PhysicalReserveBytes = [uint64]3221225472
$PhysicalReserveTolerancePercent = 32
$PhysicalReserveFloorBytes = [uint64][Math]::Ceiling($PhysicalReserveBytes * (100 - $PhysicalReserveTolerancePercent) / 100)
$PollMilliseconds = 250
$CMakePath = 'C:\Program Files\CMake\bin\cmake.exe'
$CTestPath = 'C:\Program Files\CMake\bin\ctest.exe'
$BuildLogStdoutPath = Join-Path $BuildRoot ("guarded-{0}-{1}.stdout.log" -f $Mode.ToLowerInvariant(), $RunSuffix)
$BuildLogStderrPath = Join-Path $BuildRoot ("guarded-{0}-{1}.stderr.log" -f $Mode.ToLowerInvariant(), $RunSuffix)
$script:GuardLastExitStatus = $null
$script:GuardLastCleanupFailure = $null
[uint64]$EffectiveStartFloorBytes = $PhysicalReserveFloorBytes
if ($MinimumStartFreeBytes -gt $EffectiveStartFloorBytes) {
  $EffectiveStartFloorBytes = $MinimumStartFreeBytes
}
Write-Output ("RESOURCE_POLICY version=v4 owner_waiver_effective=2026-09-23 process_tree_memory_cap=WAIVED_UNTIL_REVOKED physical_reserve_bytes={0} physical_free_floor_bytes={1} target_start_floor_bytes={2} effective_start_floor_bytes={3} tolerance_percent={4} process_tree_sampling=ENABLED cleanup=ENABLED mutex={5} activation=NONE" -f
  $PhysicalReserveBytes, $PhysicalReserveFloorBytes, $MinimumStartFreeBytes,
  $EffectiveStartFloorBytes, $PhysicalReserveTolerancePercent, $MutexName)

if (-not (Test-Path -LiteralPath $BuildRoot -PathType Container)) {
  throw "missing exact generated build directory: $BuildRoot"
}
if (-not (Test-Path -LiteralPath $BuildDirectory -PathType Container)) {
  New-Item -ItemType Directory -Path $BuildDirectory -Force | Out-Null
}
if (-not (Test-Path -LiteralPath $SourceDirectory -PathType Container)) {
  throw "missing child source directory: $SourceDirectory"
}
if (-not (Test-Path -LiteralPath $FixtureSourceDirectory -PathType Container)) {
  throw "missing fixture CMake source directory: $FixtureSourceDirectory"
}
if (-not (Test-Path -LiteralPath $CMakePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $CTestPath -PathType Leaf)) {
  throw 'pinned CMake/CTest executables are unavailable'
}
if ((Test-Path -LiteralPath $BuildLogStdoutPath -PathType Leaf) -or
    (Test-Path -LiteralPath $BuildLogStderrPath -PathType Leaf)) {
  throw "refusing to overwrite runner logs for $Mode/$RunSuffix"
}

function Get-ProcessTreeRecords {
  param([Parameter(Mandatory = $true)][int]$RootPid)

  $records = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
  $ids = New-Object 'System.Collections.Generic.HashSet[int]'
  [void]$ids.Add($RootPid)
  do {
    $changed = $false
    foreach ($record in $records) {
      if ($ids.Contains([int]$record.ParentProcessId) -and
          $ids.Add([int]$record.ProcessId)) {
        $changed = $true
      }
    }
  } while ($changed)
  return @($records | Where-Object { $ids.Contains([int]$_.ProcessId) })
}

function Get-LiveSample {
  param([Parameter(Mandatory = $true)][int]$RootPid)

  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  if ($null -eq $os -or $null -eq $os.FreePhysicalMemory) {
    throw 'Win32_OperatingSystem free physical memory was unavailable'
  }
  $records = @(Get-ProcessTreeRecords -RootPid $RootPid)
  [uint64]$workingSetBytes = 0
  [uint64]$privateBytes = 0
  foreach ($record in $records) {
    if ($null -eq $record.WorkingSetSize -or $null -eq $record.PrivatePageCount) {
      throw "process memory observation was incomplete for PID $($record.ProcessId)"
    }
    $workingSetBytes += [uint64]$record.WorkingSetSize
    $privateBytes += [uint64]$record.PrivatePageCount
  }
  [pscustomobject]@{
    FreePhysicalBytes = [uint64]$os.FreePhysicalMemory * 1024
    WorkingSetBytes = $workingSetBytes
    PrivateBytes = $privateBytes
    ProcessCount = $records.Count
  }
}

function Stop-OwnedProcessTree {
  param([Parameter(Mandatory = $true)][int]$RootPid)

  $records = @(Get-ProcessTreeRecords -RootPid $RootPid)
  foreach ($record in @($records | Sort-Object @{Expression = { [int]$_.ProcessId }; Descending = $true})) {
    try {
      Stop-Process -Id ([int]$record.ProcessId) -Force -ErrorAction Stop
    } catch {
      if (Get-Process -Id ([int]$record.ProcessId) -ErrorAction SilentlyContinue) {
        throw "failed to stop owned PID $($record.ProcessId): $($_.Exception.Message)"
      }
    }
  }
}

function Ensure-OwnedProcessTreeStopped {
  param([Parameter(Mandatory = $true)][int]$RootPid)

  for ($attempt = 0; $attempt -lt 120; ++$attempt) {
    $remaining = @(Get-ProcessTreeRecords -RootPid $RootPid)
    if ($remaining.Count -eq 0) {
      return
    }
    if ($attempt -eq 0) {
      Stop-OwnedProcessTree -RootPid $RootPid
    }
    Start-Sleep -Milliseconds $PollMilliseconds
  }
  $remaining = @(Get-ProcessTreeRecords -RootPid $RootPid)
  throw "owned process tree cleanup unresolved; remaining=$($remaining.Count)"
}

function ConvertTo-WindowsProcessArgument {
  param([Parameter(Mandatory = $true)][string]$Argument)

  if ($Argument -notmatch '[\s"]') {
    return $Argument
  }
  return '"' + $Argument.Replace('"', '\"') + '"'
}

function Invoke-GuardedCommand {
  param(
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][string]$CommandPath,
    [string[]]$CommandArguments,
    [string]$RedirectOutput = '',
    [string]$RedirectError = ''
  )

  $process = $null
  $rootPid = 0
  $commandFailure = $null
  $cleanupFailure = $null
  $stdoutTask = $null
  $stderrTask = $null
  $sampleCount = 0
  [uint64]$minimumFreePhysicalBytes = [uint64]::MaxValue
  [uint64]$peakWorkingSetBytes = 0
  [uint64]$peakPrivateBytes = 0
  $script:GuardLastExitStatus = $null
  $script:GuardLastCleanupFailure = $null

  try {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $CommandPath
    $startInfo.WorkingDirectory = $BuildDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $quotedArguments = @(foreach ($argument in $CommandArguments) {
      ConvertTo-WindowsProcessArgument -Argument $argument
    })
    if ($quotedArguments.Count -eq 0) {
      $startInfo.Arguments = ''
    } else {
      $startInfo.Arguments = [string]::Join(' ', $quotedArguments)
    }
    if (-not [string]::IsNullOrWhiteSpace($RedirectOutput)) {
      $startInfo.RedirectStandardOutput = $true
      $startInfo.RedirectStandardError = $true
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
      throw "process start returned false for $Label"
    }
    $rootPid = [int]$process.Id
    Write-Output "LAUNCH label=$Label pid=$rootPid command=$CommandPath"

    if (-not [string]::IsNullOrWhiteSpace($RedirectOutput)) {
      $stdoutTask = $process.StandardOutput.ReadToEndAsync()
      $stderrTask = $process.StandardError.ReadToEndAsync()
    }

    while ($true) {
      $sample = Get-LiveSample -RootPid $rootPid
      ++$sampleCount
      if ($sample.FreePhysicalBytes -lt $minimumFreePhysicalBytes) {
        $minimumFreePhysicalBytes = $sample.FreePhysicalBytes
      }
      if ($sample.WorkingSetBytes -gt $peakWorkingSetBytes) {
        $peakWorkingSetBytes = $sample.WorkingSetBytes
      }
      if ($sample.PrivateBytes -gt $peakPrivateBytes) {
        $peakPrivateBytes = $sample.PrivateBytes
      }
      Write-Output ("LIVE_SAMPLE label={0} index={1} free_bytes={2} working_set_bytes={3} private_bytes={4} process_count={5}" -f `
        $Label, $sampleCount, $sample.FreePhysicalBytes, $sample.WorkingSetBytes,
        $sample.PrivateBytes, $sample.ProcessCount)

      if ($sample.FreePhysicalBytes -lt $PhysicalReserveFloorBytes) {
        throw "free physical memory below reserve floor during ${Label}: $($sample.FreePhysicalBytes) < $PhysicalReserveFloorBytes"
      }
      if ($sample.ProcessCount -eq 0) {
        break
      }
      Start-Sleep -Milliseconds $PollMilliseconds
    }

    if (-not $process.HasExited) {
      $process.WaitForExit()
    }
    $process.Refresh()
    $exitProperty = $process.ExitCode
    if ($null -eq $exitProperty) {
      throw "non-null ExitCode was unavailable for $Label"
    }
    $script:GuardLastExitStatus = [int]$exitProperty
    Write-Output "CHILD_EXIT_STATUS label=$Label exit=$($script:GuardLastExitStatus)"
  } catch {
    $commandFailure = $_.Exception.Message
    Write-Output "GUARD_STOP label=$Label reason=$commandFailure"
    if ($rootPid -ne 0) {
      try {
        Stop-OwnedProcessTree -RootPid $rootPid
      } catch {
        $cleanupFailure = "guard stop failed: $($_.Exception.Message)"
        Write-Output "CLEANUP_STOP_FAILURE label=$Label reason=$cleanupFailure"
      }
    }
  } finally {
    if ($rootPid -ne 0) {
      try {
        Ensure-OwnedProcessTreeStopped -RootPid $rootPid
      } catch {
        $cleanupFailure = "cleanup failed: $($_.Exception.Message)"
      }
    }
    if ($null -ne $stdoutTask) {
      try {
        $stdoutText = $stdoutTask.GetAwaiter().GetResult()
        $stderrText = $stderrTask.GetAwaiter().GetResult()
        [System.IO.File]::WriteAllText($RedirectOutput, $stdoutText)
        [System.IO.File]::WriteAllText($RedirectError, $stderrText)
      } catch {
        $cleanupFailure = "redirected output capture failed: $($_.Exception.Message)"
      }
    }
    if ($sampleCount -gt 0) {
      Write-Output ("LIVE_PHYSICAL_SUMMARY label={0} samples={1} min_free_bytes={2} reserve_bytes={3} peak_working_set_bytes={4} peak_private_bytes={5} reserve_floor_bytes={6} tolerance_percent={7}" -f `
        $Label, $sampleCount, $minimumFreePhysicalBytes, $PhysicalReserveBytes,
        $peakWorkingSetBytes, $peakPrivateBytes, $PhysicalReserveFloorBytes, $PhysicalReserveTolerancePercent)
    } else {
      Write-Output "LIVE_PHYSICAL_SUMMARY label=$Label samples=0"
    }
    if ($null -ne $cleanupFailure) {
      $script:GuardLastCleanupFailure = $cleanupFailure
      Write-Output "CLEANUP=FAIL label=$Label reason=$cleanupFailure"
    } else {
      Write-Output "CLEANUP=PASS label=$Label owned_process_tree=empty"
    }
  }

  if ($null -ne $script:GuardLastCleanupFailure) {
    throw $script:GuardLastCleanupFailure
  }
  if ($null -ne $commandFailure) {
    throw $commandFailure
  }
}

$mutex = New-Object System.Threading.Mutex($false, $MutexName)
$mutexAcquired = $false
$runnerFailure = $null
$runnerExitStatus = 1
$cleanupFailure = $null

try {
  if (-not $mutex.WaitOne(0)) {
    throw "mutex is already held: $MutexName"
  }
  $mutexAcquired = $true

  $preflight = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
  if ($null -eq $preflight -or $null -eq $preflight.FreePhysicalMemory) {
    throw 'physical-memory preflight was unavailable'
  }
  [uint64]$preflightFree = [uint64]$preflight.FreePhysicalMemory * 1024
  Write-Output "PHYSICAL_PREFLIGHT free_bytes=$preflightFree reserve_bytes=$PhysicalReserveBytes reserve_floor_bytes=$PhysicalReserveFloorBytes target_start_floor_bytes=$MinimumStartFreeBytes effective_start_floor_bytes=$EffectiveStartFloorBytes tolerance_percent=$PhysicalReserveTolerancePercent"
  if ($preflightFree -lt $PhysicalReserveFloorBytes) {
    throw 'physical-memory preflight below the required reserve floor'
  }
  if ($preflightFree -lt $MinimumStartFreeBytes) {
    throw 'physical-memory preflight below the target-specific start floor'
  }

  Invoke-GuardedCommand -Label 'child-exit-7' -CommandPath 'cmd.exe' `
    -CommandArguments @('/c', 'exit', '7')
  $exit7 = $script:GuardLastExitStatus
  Invoke-GuardedCommand -Label 'child-exit-0' -CommandPath 'cmd.exe' `
    -CommandArguments @('/c', 'exit', '0')
  $exit0 = $script:GuardLastExitStatus
  Write-Output "CHILD_EXIT_CHECK exit7=$exit7 exit0=$exit0"
  if ($exit7 -ne 7 -or $exit0 -ne 0) {
    throw "child exit propagation failed: exit7=$exit7 exit0=$exit0"
  }

  if ($Mode -eq 'Configure') {
    $commandPath = $CMakePath
    $commandArguments = @(
      '-S', $FixtureSourceDirectory,
      '-B', $BuildDirectory,
      '-G', 'Visual Studio 17 2022',
      '-A', 'x64',
      ('-DPMB_BUILD_DIR=' + $PmbBuildDirectory),
      ('-DFAEST_REF_DIR=' + $FaestSourceDirectory),
      ('-DDMV_SOURCE_DIR=' + $VoleSourceDirectory),
      ('-DMLDSA_ROOT=' + $MldsaRoot),
      '-DBUILD_TESTING=ON')
  } elseif ($Mode -eq 'Build') {
    $commandPath = $CMakePath
    $commandArguments = @(
      '--build', $BuildDirectory,
      '--config', 'Release',
      '--target', 'direct_mask_fixture_source',
      'direct_mask_fixture_public_key',
      'direct_mask_fixture_probe',
      '--', '/m:1', '/nologo')
  } elseif ($Mode -eq 'CTest') {
    $commandPath = $CTestPath
    $commandArguments = @(
      '--test-dir', $BuildDirectory,
      '-C', 'Release',
      '-R', $CTestRegex,
      '-V', '--output-on-failure')
  } else {
    if ([string]::IsNullOrWhiteSpace($CommandPath)) {
      throw 'Command mode requires -CommandPath'
    }
    $commandPath = $CommandPath
    $commandArguments = $CommandArguments
  }

  Invoke-GuardedCommand -Label $Mode -CommandPath $commandPath `
    -CommandArguments $commandArguments -RedirectOutput $BuildLogStdoutPath `
    -RedirectError $BuildLogStderrPath
  $mainExit = $script:GuardLastExitStatus
  if ($mainExit -ne 0) {
    throw "$Mode child exited $mainExit"
  }

  if ($Mode -in @('Configure', 'Build')) {
    $outputText = ''
    if (Test-Path -LiteralPath $BuildLogStdoutPath -PathType Leaf) {
      $outputText += Get-Content -LiteralPath $BuildLogStdoutPath -Raw
    }
    if (Test-Path -LiteralPath $BuildLogStderrPath -PathType Leaf) {
      $outputText += Get-Content -LiteralPath $BuildLogStderrPath -Raw
    }
    if ($outputText -match '(?im)CMake Error:|(^|\s)(?:fatal )?error (?:C\d+|LNK\d+)|FileTracker : error|Build FAILED|FAILED:') {
      Write-Output "BUILD_LOG_FAILURE=TRUE mode=$Mode"
      throw "$Mode output contained a build/configure failure marker"
    }
    Write-Output "BUILD_LOG_FAILURE=FALSE mode=$Mode"
  }
  $runnerExitStatus = 0
} catch {
  $runnerFailure = $_.Exception.Message
  Write-Output "RUNNER_FAILURE reason=$runnerFailure"
  $runnerExitStatus = 1
} finally {
  if ($null -ne $script:GuardLastCleanupFailure) {
    $cleanupFailure = $script:GuardLastCleanupFailure
  }
  if ($null -ne $cleanupFailure) {
    Write-Output "CLEANUP=FAIL reason=$cleanupFailure"
    $runnerExitStatus = 1
  }
  if ($mutexAcquired -and $null -eq $cleanupFailure) {
    [void]$mutex.ReleaseMutex()
    $mutex.Dispose()
    Write-Output "MUTEX=RELEASED name=$MutexName"
  } elseif ($mutexAcquired) {
    $mutex.Dispose()
    Write-Output "MUTEX=HELD_UNTIL_PROCESS_EXIT name=$MutexName"
  } else {
    $mutex.Dispose()
  }
}

exit $runnerExitStatus
