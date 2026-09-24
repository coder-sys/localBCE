param(
  [Parameter(Mandatory = $true)][string]$AttributionExe,
  [Parameter(Mandatory = $true)][string]$JsonPath,
  [int]$EndpointCount = 4,
  [int64]$WorkingSetCap = 4500000000,
  [int]$SampleMilliseconds = 100
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $AttributionExe)) {
  throw "attribution executable missing: $AttributionExe"
}
if (Test-Path -LiteralPath $JsonPath) {
  throw "refusing to overwrite shape ledger: $JsonPath"
}
if ($EndpointCount -lt 0 -or $EndpointCount -gt 4) {
  throw "endpoint count must be between 0 and 4: $EndpointCount"
}
if ($SampleMilliseconds -lt 20) {
  throw 'sample interval must be at least 20 milliseconds'
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

function Get-DirectoryBytes([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return [int64]0 }
  $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue)
  if ($files.Count -eq 0) { return [int64]0 }
  $sum = ($files | Measure-Object -Property Length -Sum).Sum
  return [int64]$sum
}

function Get-PagefileState {
  try {
    $os = Get-CimInstance Win32_OperatingSystem
    $size = [int64]$os.SizeStoredInPagingFiles * 1024
    $free = [int64]$os.FreeSpaceInPagingFiles * 1024
    $used = [Math]::Max([int64]0, $size - $free)
    return [ordered]@{
      available = $true
      size_bytes = $size
      free_bytes = $free
      used_bytes = $used
    }
  } catch {
    return [ordered]@{
      available = $false
      size_bytes = [int64]0
      free_bytes = [int64]0
      used_bytes = [int64]0
      error = $_.Exception.Message
    }
  }
}

function Get-Phase([string]$StderrPath) {
  if (-not (Test-Path -LiteralPath $StderrPath)) { return 'startup' }
  $raw = Get-Content -LiteralPath $StderrPath -Raw -ErrorAction SilentlyContinue
  if ($raw -match 'RELATION_BUILD phase=complete') { return 'complete' }
  if ($raw -match 'RELATION_BUILD phase=mkcircuit') { return 'mkcircuit' }
  if ($raw -match 'RELATION_BUILD phase=sha3') { return 'sha3' }
  if ($raw -match 'RELATION_BUILD phase=assertions') { return 'assertions' }
  if ($raw -match 'RELATION_BUILD phase=private') { return 'private' }
  if ($raw -match 'RELATION_BUILD phase=public') { return 'public' }
  return 'startup'
}

$runRoot = Join-Path 'C:\Temp' ('longfellow-v09-native-v3-source-assertion-shape-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runRoot | Out-Null
$oldTemp = $env:TEMP
$oldTmp = $env:TMP
$env:TEMP = $runRoot
$env:TMP = $runRoot
$results = @()
$cleanup = $false

function Write-Ledger([bool]$Complete) {
  $ledger = [ordered]@{
    schema = 'longfellow-v09-native-v3-source-assertion-shape-v1'
    attribution_executable = [string]$AttributionExe
    absolute_preproof_cap = [int64]$WorkingSetCap
    sample_ms = [int]$SampleMilliseconds
    endpoint_count = [int]$EndpointCount
    complete = [bool]$Complete
    stages = @($results)
  }
  $json = ConvertTo-Json -InputObject $ledger -Depth 30
  [IO.File]::WriteAllText($JsonPath, $json, [Text.UTF8Encoding]::new($false))
}

try {
  for ($stage = 0; $stage -le $EndpointCount; $stage++) {
    $stdoutPath = Join-Path $runRoot ("stage-{0}.stdout.txt" -f $stage)
    $stderrPath = Join-Path $runRoot ("stage-{0}.stderr.txt" -f $stage)
    $started = [DateTime]::UtcNow
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $AttributionExe -ArgumentList @([string]$stage) `
      -WindowStyle Hidden -RedirectStandardOutput $stdoutPath `
      -RedirectStandardError $stderrPath -PassThru
    $rootId = $process.Id
    $knownIds = New-Object System.Collections.Generic.HashSet[int]
    [void]$knownIds.Add($rootId)
    $peakWorking = [int64]0
    $peakPrivate = [int64]0
    $peakPagefile = [int64]0
    $scratchPeak = [int64]0
    $osPagefileStart = Get-PagefileState
    $osPagefilePeak = [int64]$osPagefileStart.used_bytes
    $samples = 0
    $aborted = $false
    $telemetryComplete = $true
    $observedPagefileIds = New-Object System.Collections.Generic.HashSet[int]
    $perProcess = @{}
    $phasePeaks = @{}
    while ($true) {
      $rootAlive = $null -ne (Get-Process -Id $rootId -ErrorAction SilentlyContinue)
      $ids = @(Get-ProcessTreeIds $rootId)
      foreach ($id in $ids) { [void]$knownIds.Add($id) }
      $working = [int64]0
      $private = [int64]0
      $pagefile = [int64]0
      foreach ($id in $ids) {
        $current = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($null -ne $current) {
          $working += [int64]$current.WorkingSet64
          $private += [int64]$current.PrivateMemorySize64
          $cim = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $id) -ErrorAction SilentlyContinue
          $processPagefile = [int64]0
          if ($null -ne $cim -and $null -ne $cim.PageFileUsage) {
            $processPagefile = [int64]$cim.PageFileUsage * 1024
            [void]$observedPagefileIds.Add([int]$id)
          }
          $pagefile += $processPagefile
          if (-not $perProcess.ContainsKey($id)) {
            $perProcess[$id] = [ordered]@{
              name = $current.ProcessName
              peak_working = [int64]0
              peak_private = [int64]0
              peak_pagefile = [int64]0
            }
          }
          if ($current.WorkingSet64 -gt $perProcess[$id].peak_working) {
            $perProcess[$id].peak_working = [int64]$current.WorkingSet64
          }
          if ($current.PrivateMemorySize64 -gt $perProcess[$id].peak_private) {
            $perProcess[$id].peak_private = [int64]$current.PrivateMemorySize64
          }
          if ($processPagefile -gt $perProcess[$id].peak_pagefile) {
            $perProcess[$id].peak_pagefile = $processPagefile
          }
        }
      }
      if ($working -gt $peakWorking) { $peakWorking = $working }
      if ($private -gt $peakPrivate) { $peakPrivate = $private }
      if ($pagefile -gt $peakPagefile) { $peakPagefile = $pagefile }
      $scratch = Get-DirectoryBytes $runRoot
      if ($scratch -gt $scratchPeak) { $scratchPeak = $scratch }
      $osPagefile = Get-PagefileState
      if (-not $osPagefile.available) { $telemetryComplete = $false }
      if ([int64]$osPagefile.used_bytes -gt $osPagefilePeak) {
        $osPagefilePeak = [int64]$osPagefile.used_bytes
      }
      $phase = Get-Phase $stderrPath
      if (-not $phasePeaks.ContainsKey($phase)) {
        $phasePeaks[$phase] = [ordered]@{
          peak_working = [int64]0
          peak_private = [int64]0
          peak_pagefile = [int64]0
          peak_scratch = [int64]0
          samples = 0
        }
      }
      if ($working -gt $phasePeaks[$phase].peak_working) {
        $phasePeaks[$phase].peak_working = $working
      }
      if ($private -gt $phasePeaks[$phase].peak_private) {
        $phasePeaks[$phase].peak_private = $private
      }
      if ($pagefile -gt $phasePeaks[$phase].peak_pagefile) {
        $phasePeaks[$phase].peak_pagefile = $pagefile
      }
      if ($scratch -gt $phasePeaks[$phase].peak_scratch) {
        $phasePeaks[$phase].peak_scratch = $scratch
      }
      $phasePeaks[$phase].samples++
      $samples++
      if ([Math]::Max($working, $private) -gt $WorkingSetCap) {
        $aborted = $true
        foreach ($id in ($ids | Sort-Object -Descending)) {
          Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
        }
        break
      }
      if (-not $rootAlive) { break }
      Start-Sleep -Milliseconds $SampleMilliseconds
    }
    $stopwatch.Stop()
    if ($null -ne $process) { try { $process.Refresh() } catch { } }
    $exitCode = try { [int]$process.ExitCode } catch { -1 }
    $stdout = if (Test-Path -LiteralPath $stdoutPath) {
      Get-Content -LiteralPath $stdoutPath -Raw
    } else { '' }
    $stderr = if (Test-Path -LiteralPath $stderrPath) {
      Get-Content -LiteralPath $stderrPath -Raw
    } else { '' }
    $shape = $null
    try { $shape = ([string]$stdout).Trim() | ConvertFrom-Json } catch { $telemetryComplete = $false }
    if ($null -eq $shape -or $shape.shape_only -ne $true -or
        $null -eq $shape.self_peak_working -or
        $null -eq $shape.self_peak_private -or
        $null -eq $shape.self_peak_pagefile) {
      $telemetryComplete = $false
    } else {
      if ([int64]$shape.self_peak_working -gt $peakWorking) {
        $peakWorking = [int64]$shape.self_peak_working
      }
      if ([int64]$shape.self_peak_private -gt $peakPrivate) {
        $peakPrivate = [int64]$shape.self_peak_private
      }
      if ([int64]$shape.self_peak_pagefile -gt $peakPagefile) {
        $peakPagefile = [int64]$shape.self_peak_pagefile
      }
      [void]$observedPagefileIds.Add([int]$rootId)
    }
    $osPagefileEnd = Get-PagefileState
    if (-not $osPagefileEnd.available) { $telemetryComplete = $false }
    $pagefileGrowth = [int64]$osPagefileEnd.used_bytes - [int64]$osPagefileStart.used_bytes
    $processRecords = @(
      foreach ($entry in ($perProcess.GetEnumerator() | Sort-Object Key)) {
        [ordered]@{
          pid = [int]$entry.Key
          name = $entry.Value.name
          peak_working = [int64]$entry.Value.peak_working
          peak_private = [int64]$entry.Value.peak_private
          peak_pagefile = [int64]$entry.Value.peak_pagefile
        }
      }
    )
    if ($processRecords.Count -eq 0 -and $null -ne $shape) {
      $processRecords = @([ordered]@{
        pid = [int]$rootId
        name = [IO.Path]::GetFileNameWithoutExtension($AttributionExe)
        peak_working = [int64]$shape.self_peak_working
        peak_private = [int64]$shape.self_peak_private
        peak_pagefile = [int64]$shape.self_peak_pagefile
      })
    }
    $treeIdValues = @($knownIds | ForEach-Object { [int]$_ } | Sort-Object)
    foreach ($id in $treeIdValues) {
      if (-not $observedPagefileIds.Contains([int]$id)) {
        $telemetryComplete = $false
      }
    }
    $results += ,([ordered]@{
      stage = $stage
      started_utc = [string]$started
      wall_ms = [int64]$stopwatch.ElapsedMilliseconds
      exit = $exitCode
      aborted_at_cap = $aborted
      telemetry_complete = $telemetryComplete
      process_tree_complete = ($treeIdValues -contains $rootId)
      sample_ms = $SampleMilliseconds
      samples = $samples
      tree_process_ids = $treeIdValues
      peak_working = $peakWorking
      peak_private = $peakPrivate
      peak_pagefile = $peakPagefile
      scratch_peak_bytes = $scratchPeak
      os_pagefile_start = $osPagefileStart
      os_pagefile_end = $osPagefileEnd
      os_pagefile_peak_used = $osPagefilePeak
      os_pagefile_growth = $pagefileGrowth
      phase_peaks = $phasePeaks
      processes = $processRecords
      stdout = $stdout
      stderr = $stderr
      shape = $shape
    })
    Write-Ledger $false
    Write-Output ("SOURCE_ASSERTION_ATTRIBUTION_STAGE stage={0} exit={1} peak_working={2} peak_private={3} peak_pagefile={4} scratch_peak={5} wall_ms={6}" -f `
      $stage, $exitCode, $peakWorking, $peakPrivate, $peakPagefile, $scratchPeak,
      $stopwatch.ElapsedMilliseconds)
  }
  Write-Ledger $true
  $cleanup = $true
}
finally {
  $env:TEMP = $oldTemp
  $env:TMP = $oldTmp
  if (Test-Path -LiteralPath $runRoot) {
    Remove-Item -LiteralPath $runRoot -Recurse -Force
  }
}

Write-Output ("SOURCE_ASSERTION_SHAPE_LEDGER={0}" -f $JsonPath)
Write-Output ("SOURCE_ASSERTION_TEMP_CLEANUP={0}" -f $cleanup)
if (-not $cleanup) { exit 3 }
