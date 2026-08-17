param(
  [Parameter(Mandatory = $true)][string]$AttributionExe,
  [Parameter(Mandatory = $true)][string]$JsonPath,
  [int]$StageCount = -1,
  [int]$StageStart = 0,
  [int64]$WorkingSetCap = 5000000000,
  [int]$SampleMilliseconds = 100
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $AttributionExe)) {
  throw "attribution executable missing: $AttributionExe"
}
if (Test-Path -LiteralPath $JsonPath) {
  throw "refusing to overwrite attribution ledger: $JsonPath"
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

function Get-CurrentPhase([string]$StderrPath) {
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

$stageLimit = if ($StageCount -lt 0) { 18 } else { $StageCount }
if ($stageLimit -lt 0 -or $stageLimit -gt 18) {
  throw "stage count must be between 0 and 18: $stageLimit"
}
if ($StageStart -lt 0 -or $StageStart -gt $stageLimit) {
  throw ("stage start must be between 0 and stage limit {0}: {1}" -f $stageLimit, $StageStart)
}

$runRoot = Join-Path 'C:\Temp' ('longfellow-v09-native-v3-attribution-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runRoot | Out-Null
$results = @()
$cleanup = $false

function Write-Ledger([bool]$Complete) {
  $stageObjects = @(
    foreach ($stageRecord in @($results)) {
      [ordered]@{
        stage = [int]$stageRecord.stage
        started_utc = [string]$stageRecord.started_utc
        wall_ms = [int64]$stageRecord.wall_ms
        exit = [int]$stageRecord.exit
        aborted_at_cap = [bool]$stageRecord.aborted_at_cap
        telemetry_exceeded_cap = [bool]$stageRecord.telemetry_exceeded_cap
        sample_ms = [int]$stageRecord.sample_ms
        samples = [int]$stageRecord.samples
        tree_process_ids_json = [string]$stageRecord.tree_process_ids_json
        peak_working = [int64]$stageRecord.peak_working
        peak_private = [int64]$stageRecord.peak_private
        phase_peaks_json = [string]$stageRecord.phase_peaks_json
        processes_json = [string]$stageRecord.processes_json
        stdout = [string]$stageRecord.stdout
        stderr = [string]$stageRecord.stderr
        shape_json = [string]$stageRecord.shape_json
      }
    }
  )
  $ledger = [ordered]@{
    schema = 'longfellow-v09-native-v3-hash-dag-attribution-v1'
    attribution_executable = [string]$AttributionExe
    working_set_cap = [int64]$WorkingSetCap
    sample_ms = [int]$SampleMilliseconds
    stage_start = [int]$StageStart
    stage_count = [int]($stageLimit - $StageStart + 1)
    complete = [bool]$Complete
    stages = $stageObjects
  }
  $json = ConvertTo-Json -InputObject $ledger -Depth 20
  [IO.File]::WriteAllText($JsonPath, $json, [Text.UTF8Encoding]::new($false))
}

try {
  for ($stage = $StageStart; $stage -le $stageLimit; $stage++) {
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
    $samples = 0
    $aborted = $false
    $perProcess = @{}
    $phasePeaks = @{}
    while ($true) {
      if (Test-Path -LiteralPath $stdoutPath) {
        $completedOutput = Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
        if ($completedOutput -match '"shape_only":true') { break }
      }
      $rootAlive = $null -ne (Get-Process -Id $rootId -ErrorAction SilentlyContinue)
      $ids = @(Get-ProcessTreeIds $rootId)
      foreach ($id in $ids) { [void]$knownIds.Add($id) }
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
            $perProcess[$id] = [ordered]@{
              name = $current.ProcessName
              peak_working = [int64]0
              peak_private = [int64]0
            }
          }
          if ($current.WorkingSet64 -gt $perProcess[$id].peak_working) {
            $perProcess[$id].peak_working = [int64]$current.WorkingSet64
          }
          if ($current.PrivateMemorySize64 -gt $perProcess[$id].peak_private) {
            $perProcess[$id].peak_private = [int64]$current.PrivateMemorySize64
          }
        }
      }
      if ($working -gt $peakWorking) { $peakWorking = $working }
      if ($private -gt $peakPrivate) { $peakPrivate = $private }
      $phase = Get-CurrentPhase $stderrPath
      if (-not $phasePeaks.ContainsKey($phase)) {
        $phasePeaks[$phase] = [ordered]@{
          peak_working = [int64]0
          peak_private = [int64]0
          samples = 0
        }
      }
      if ($working -gt $phasePeaks[$phase].peak_working) {
        $phasePeaks[$phase].peak_working = $working
      }
      if ($private -gt $phasePeaks[$phase].peak_private) {
        $phasePeaks[$phase].peak_private = $private
      }
      $phasePeaks[$phase].samples++
      $samples++

      if ($working -gt $WorkingSetCap) {
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
    if ($null -ne $process) {
      try { $process.Refresh() } catch { }
    }
    $exitCode = try { [int]$process.ExitCode } catch { -1 }
    $stdout = if (Test-Path -LiteralPath $stdoutPath) {
      Get-Content -LiteralPath $stdoutPath -Raw
    } else { '' }
    $stderr = if (Test-Path -LiteralPath $stderrPath) {
      Get-Content -LiteralPath $stderrPath -Raw
    } else { '' }
    $shape = $null
    try { $shape = ([string]$stdout).Trim() | ConvertFrom-Json } catch { }
    $telemetryExceededCap = $false
    if ($null -ne $shape -and
        $null -ne $shape.self_peak_working -and
        $null -ne $shape.self_peak_private) {
      if ([int64]$shape.self_peak_working -gt $WorkingSetCap) {
        $telemetryExceededCap = $true
      }
      if ([int64]$shape.self_peak_working -gt $peakWorking) {
        $peakWorking = [int64]$shape.self_peak_working
      }
      if ([int64]$shape.self_peak_private -gt $peakPrivate) {
        $peakPrivate = [int64]$shape.self_peak_private
      }
      if (-not $phasePeaks.ContainsKey('complete')) {
        $phasePeaks['complete'] = [ordered]@{
          peak_working = [int64]0
          peak_private = [int64]0
          samples = 0
        }
      }
      if ($peakWorking -gt $phasePeaks['complete'].peak_working) {
        $phasePeaks['complete'].peak_working = $peakWorking
      }
      if ($peakPrivate -gt $phasePeaks['complete'].peak_private) {
        $phasePeaks['complete'].peak_private = $peakPrivate
      }
    }
    $processRecords = @(
      foreach ($entry in ($perProcess.GetEnumerator() | Sort-Object Key)) {
        [ordered]@{
          pid = [int]$entry.Key
          name = $entry.Value.name
          peak_working = [int64]$entry.Value.peak_working
          peak_private = [int64]$entry.Value.peak_private
        }
      }
    )
    if ($processRecords.Count -eq 0 -and $null -ne $shape) {
      $fallbackName = [IO.Path]::GetFileNameWithoutExtension($AttributionExe)
      $processRecords = @([ordered]@{
        pid = [int]$rootId
        name = $fallbackName
        peak_working = [int64]$shape.self_peak_working
        peak_private = [int64]$shape.self_peak_private
      })
    }
    $treeIdValues = @($knownIds | ForEach-Object { [int]$_ } | Sort-Object)
    $treeIdsJson = '[' + ($treeIdValues -join ',') + ']'
    $startedUtcText = [string]$started
    $elapsedMs = if ($null -ne $stopwatch) {
      [int64]$stopwatch.ElapsedMilliseconds
    } else { [int64]0 }
    $phasePeaksText = [string]($phasePeaks | ConvertTo-Json -Depth 10 -Compress)
    $processRecordsText = [string]($processRecords | ConvertTo-Json -Depth 10 -Compress)
    $shapeText = [string]$stdout
    $results += ,([ordered]@{
      stage = $stage
      started_utc = $startedUtcText
      wall_ms = $elapsedMs
      exit = $exitCode
      aborted_at_cap = $aborted
      telemetry_exceeded_cap = $telemetryExceededCap
      sample_ms = $SampleMilliseconds
      samples = $samples
      tree_process_ids_json = $treeIdsJson
      peak_working = $peakWorking
      peak_private = $peakPrivate
      phase_peaks_json = $phasePeaksText
      processes_json = $processRecordsText
      stdout = $stdout
      stderr = $stderr
      shape_json = $shapeText.Trim()
    })
    Write-Ledger $false
    Write-Output ("ATTRIBUTION_STAGE stage={0} exit={1} peak_working={2} peak_private={3} wall_ms={4}" -f `
      $stage, $exitCode, $peakWorking, $peakPrivate, $stopwatch.ElapsedMilliseconds)
  }
  Write-Ledger $true
  $cleanup = $true
}
finally {
  if (Test-Path -LiteralPath $runRoot) {
    Remove-Item -LiteralPath $runRoot -Recurse -Force
  }
}

Write-Output ("ATTRIBUTION_LEDGER={0}" -f $JsonPath)
Write-Output ("ATTRIBUTION_TEMP_CLEANUP={0}" -f $cleanup)
if (-not $cleanup) { exit 3 }
