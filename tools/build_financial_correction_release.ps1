#requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'Build')]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Build')][string]$EngineRoot,
    [Parameter(Mandatory = $true, ParameterSetName = 'Build')][string]$VectorSourceDirectory,
    [Parameter(Mandatory = $true, ParameterSetName = 'Build')][UInt64]$MinimumStartFreeBytes,
    [Parameter(Mandatory = $true, ParameterSetName = 'Build')][string]$DirectLaneGrantReference,
    [Parameter(ParameterSetName = 'Build')][string]$GuardPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Build')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')][string]$OutputDirectory,
    [Parameter(Mandatory = $true, ParameterSetName = 'Build')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')][string]$LakeExecutable,
    [Parameter(Mandatory = $true, ParameterSetName = 'Build')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')][string]$LeanExecutable,
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')][switch]$GuardedChild,
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')][string]$StageLeanRoot,
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')][int]$IgnoredVectorEntryCount,
    [Parameter(Mandatory = $true, ParameterSetName = 'Child')][string]$IgnoredVectorNamesBase64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ReceiptSchema = 'RR/LEAN-ENGINE/BUILD-RECEIPT/v2'
$script:SourceManifestSchema = 'RR/LEAN-ENGINE/SOURCE-MANIFEST/v1'
$script:TargetName = 'blind_financial_correction'
$script:GuardSha256 = '57F9EC8AEFE1D0E281B3BB0D76F2F057C8295F99AFDD04305DFC777703ED99FB'
$script:GuardPhysicalFloorBytes = [UInt64]2190433321
$script:LeanCompilerStartFloorBytes = [UInt64]4190433321
$script:Utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)
$script:PinnedVectorSpecs = @(
    [pscustomobject]@{ SourceName = 'request.bin'; OutputName = 'request.bin'; Sha256 = '13F832E80B93CC55D17ADD29470A2CD789CFCED1CBCF5A055FCBA3ECB927B537' },
    [pscustomobject]@{ SourceName = 'result.expected.bin'; OutputName = 'result.expected.bin'; Sha256 = '312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E' },
    [pscustomobject]@{ SourceName = 'reuse-request.bin'; OutputName = 'reuse-request.bin'; Sha256 = 'DD7DDC27FEEDFDFD26540AB6B1F7D37E6BE49768583FB1EA3AB02F85C8390DC6' },
    [pscustomobject]@{ SourceName = 'reuse-result.expected.bin'; OutputName = 'reuse-result.expected.bin'; Sha256 = '8C50EC33F30B520CC7452C3618577228B6B51B59B68A1935549461FAD2615379' }
)
$script:RequiredSourcePaths = [string[]]@(
    'BlindLedger\Financial\CorrectionTransition\Transition.lean',
    'BlindLedger\Financial\CorrectionTransition\Runtime.lean',
    'BlindLedger\Financial\CorrectionTransitionCli.lean',
    'lakefile.toml',
    'lake-manifest.json',
    'lean-toolchain'
)

function Get-Sha256FromBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToHexString($sha.ComputeHash($Bytes)).ToUpperInvariant() }
    finally { $sha.Dispose() }
}

function Get-RegularFileIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer) { throw "expected regular file: $Path" }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "refusing reparse-point file: $Path" }
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $sizeBefore = [Int64]$stream.Length
        $digest = [Convert]::ToHexString($sha.ComputeHash($stream)).ToUpperInvariant()
        $sizeAfter = [Int64]$stream.Length
        if ($sizeBefore -ne $sizeAfter) { throw "file size changed while hashing: $Path" }
        return [pscustomobject]@{ SizeBytes = $sizeAfter; Sha256 = $digest }
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Read-RegularFileBytes {
    param([Parameter(Mandatory = $true)][string]$Path)
    $null = Get-RegularFileIdentity -Path $Path
    return ,([System.IO.File]::ReadAllBytes($Path))
}

function Write-FileCreateNew {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][byte[]]$Bytes)
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

function Copy-FileCreateNew {
    param([Parameter(Mandatory = $true)][string]$SourcePath, [Parameter(Mandatory = $true)][string]$DestinationPath)
    [System.IO.File]::Copy($SourcePath, $DestinationPath, $false)
}

function Assert-NoReparsePathChain {
    param([Parameter(Mandatory = $true)][string]$Path)
    $cursor = [System.IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($cursor)) {
        if ([System.IO.File]::Exists($cursor) -or [System.IO.Directory]::Exists($cursor)) {
            $attributes = [System.IO.File]::GetAttributes($cursor)
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "refusing path through reparse point: $cursor" }
        }
        $parent = [System.IO.Directory]::GetParent($cursor)
        if ($null -eq $parent -or $parent.FullName -eq $cursor) { break }
        $cursor = $parent.FullName
    }
}

function Test-PathInside {
    param([Parameter(Mandatory = $true)][string]$Candidate, [Parameter(Mandatory = $true)][string]$Root)
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    return $candidateFull.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase) -or
        $candidateFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-JsonString {
    param([Parameter(Mandatory = $true)][string]$Value)
    $builder = [System.Text.StringBuilder]::new()
    $null = $builder.Append([char]34)
    for ($index = 0; $index -lt $Value.Length; $index++) {
        $character = $Value[$index]
        $code = [Int32][char]$character
        if ($code -eq 34) { $null = $builder.Append([char]92).Append([char]34) }
        elseif ($code -eq 92) { $null = $builder.Append([char]92).Append([char]92) }
        elseif ($code -eq 8) { $null = $builder.Append('\b') }
        elseif ($code -eq 12) { $null = $builder.Append('\f') }
        elseif ($code -eq 10) { $null = $builder.Append('\n') }
        elseif ($code -eq 13) { $null = $builder.Append('\r') }
        elseif ($code -eq 9) { $null = $builder.Append('\t') }
        elseif ($code -lt 32) { $null = $builder.Append('\u').Append($code.ToString('x4', [Globalization.CultureInfo]::InvariantCulture)) }
        elseif ([char]::IsHighSurrogate($character)) {
            if ($index + 1 -ge $Value.Length -or -not [char]::IsLowSurrogate($Value[$index + 1])) { throw 'canonical JSON input contains an unpaired high surrogate' }
            $low = [Int32][char]$Value[$index + 1]
            $null = $builder.Append('\u').Append($code.ToString('x4', [Globalization.CultureInfo]::InvariantCulture))
            $null = $builder.Append('\u').Append($low.ToString('x4', [Globalization.CultureInfo]::InvariantCulture))
            $index++
        } elseif ([char]::IsLowSurrogate($character)) { throw 'canonical JSON input contains an unpaired low surrogate' }
        elseif ($code -gt 127) { $null = $builder.Append('\u').Append($code.ToString('x4', [Globalization.CultureInfo]::InvariantCulture)) }
        else { $null = $builder.Append($character) }
    }
    $null = $builder.Append([char]34)
    return $builder.ToString()
}

function ConvertTo-CanonicalJsonText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return ConvertTo-JsonString -Value $Value }
    if ($Value -is [bool]) { if ($Value) { return 'true' }; return 'false' }
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = [string[]]@($Value.Keys)
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($key in $keys) { $parts.Add((ConvertTo-JsonString -Value $key) + ':' + (ConvertTo-CanonicalJsonText -Value $Value[$key])) }
        return '{' + [string]::Join(',', $parts.ToArray()) + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) { $parts.Add((ConvertTo-CanonicalJsonText -Value $item)) }
        return '[' + [string]::Join(',', $parts.ToArray()) + ']'
    }
    $typeCode = [System.Type]::GetTypeCode($Value.GetType())
    if ($typeCode -in @([System.TypeCode]::SByte, [System.TypeCode]::Byte, [System.TypeCode]::Int16, [System.TypeCode]::UInt16, [System.TypeCode]::Int32, [System.TypeCode]::UInt32, [System.TypeCode]::Int64, [System.TypeCode]::UInt64)) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    throw "unsupported canonical JSON value type: $($Value.GetType().FullName)"
}

function Get-SelectedSourcePaths {
    param([Parameter(Mandatory = $true)][string]$Root)
    if (-not [System.IO.Directory]::Exists($Root)) { throw "Lean source root is missing: $Root" }
    Assert-NoReparsePathChain -Path $Root
    $requiredConfig = @('lean-toolchain', 'lakefile.toml', 'lake-manifest.json')
    foreach ($name in $requiredConfig) {
        $path = Join-Path $Root $name
        if (-not [System.IO.File]::Exists($path)) { throw "required Lean build input is missing: $path" }
        $null = Get-RegularFileIdentity -Path $path
    }

    $paths = [System.Collections.Generic.List[string]]::new()
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $name = [System.IO.Path]::GetFileName($entry)
            $attributes = [System.IO.File]::GetAttributes($entry)
            $isDirectory = ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0
            if ($isDirectory) {
                if ($name -in @('.git', '.lake')) { continue }
                if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "refusing Lean source directory reparse point: $entry" }
                $pending.Push($entry)
                continue
            }
            $relative = [System.IO.Path]::GetRelativePath($Root, $entry)
            $isRootConfig = [string]::IsNullOrEmpty([System.IO.Path]::GetDirectoryName($relative)) -and $relative -cin $requiredConfig
            $isLeanSource = $relative.EndsWith('.lean', [System.StringComparison]::Ordinal)
            if ($isRootConfig -or $isLeanSource) {
                if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "refusing Lean source file reparse point: $entry" }
                $paths.Add($relative)
            }
        }
    }
    $array = [string[]]$paths.ToArray()
    $pathSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($relative in $array) { [void]$pathSet.Add($relative) }
    foreach ($required in $script:RequiredSourcePaths) {
        if (-not $pathSet.Contains($required)) { throw "required correction-transition source is missing: $required" }
    }
    [Array]::Sort($array, [System.StringComparer]::Ordinal)
    return ,$array
}

function New-SourceManifestSnapshot {
    param([Parameter(Mandatory = $true)][string]$Root)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($relative in (Get-SelectedSourcePaths -Root $Root)) {
        $identity = Get-RegularFileIdentity -Path (Join-Path $Root $relative)
        $rows.Add([ordered]@{ path = 'engine/source/' + $relative.Replace('\', '/'); sha256 = $identity.Sha256; size_bytes = [Int64]$identity.SizeBytes })
    }
    $manifest = [ordered]@{ files = $rows.ToArray(); schema = $script:SourceManifestSchema }
    $bytes = $script:Utf8Strict.GetBytes((ConvertTo-CanonicalJsonText -Value $manifest))
    return [pscustomobject]@{ Rows = $rows.ToArray(); Bytes = $bytes; Sha256 = Get-Sha256FromBytes -Bytes $bytes }
}

function Write-StagedSourceSnapshot {
    param([Parameter(Mandatory = $true)][string]$SourceRoot, [Parameter(Mandatory = $true)][string]$StageRoot, [Parameter(Mandatory = $true)][object[]]$Rows)
    if ([System.IO.Directory]::Exists($StageRoot) -or [System.IO.File]::Exists($StageRoot)) { throw "refusing pre-existing stage root: $StageRoot" }
    [System.IO.Directory]::CreateDirectory($StageRoot) | Out-Null
    foreach ($row in $Rows) {
        $relative = ([string]$row.path).Substring('engine/source/'.Length).Replace('/', '\')
        $sourcePath = Join-Path $SourceRoot $relative
        $destinationPath = Join-Path $StageRoot $relative
        [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($destinationPath)) | Out-Null
        Copy-FileCreateNew -SourcePath $sourcePath -DestinationPath $destinationPath
        $copied = Get-RegularFileIdentity -Path $destinationPath
        if ($copied.SizeBytes -ne [Int64]$row.size_bytes -or $copied.Sha256 -ne [string]$row.sha256) { throw "staged Lean source identity mismatch: $relative" }
    }
}

function Invoke-RawProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [AllowNull()][byte[]]$InputBytes = $null,
        [hashtable]$EnvironmentOverrides = @{},
        [string[]]$ClearEnvironmentVariables = @()
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $null -ne $InputBytes
    foreach ($argument in $ArgumentList) { [void]$startInfo.ArgumentList.Add([string]$argument) }
    foreach ($name in $ClearEnvironmentVariables) { [void]$startInfo.Environment.Remove($name) }
    foreach ($name in $EnvironmentOverrides.Keys) { $startInfo.Environment[[string]$name] = [string]$EnvironmentOverrides[$name] }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stdout = [System.IO.MemoryStream]::new()
    $stderr = [System.IO.MemoryStream]::new()
    try {
        if (-not $process.Start()) { throw "failed to start process: $Executable" }
        $stdoutTask = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrTask = $process.StandardError.BaseStream.CopyToAsync($stderr)
        if ($null -ne $InputBytes) {
            $stdin = $process.StandardInput.BaseStream
            if ($InputBytes.Length -gt 0) { $stdin.Write($InputBytes, 0, $InputBytes.Length); $stdin.Flush() }
            $process.StandardInput.Close()
        }
        $process.WaitForExit()
        $stdoutTask.GetAwaiter().GetResult()
        $stderrTask.GetAwaiter().GetResult()
        return [pscustomobject]@{ ExitCode = [Int32]$process.ExitCode; StdoutBytes = $stdout.ToArray(); StderrBytes = $stderr.ToArray() }
    } finally {
        $stderr.Dispose()
        $stdout.Dispose()
        $process.Dispose()
    }
}

function Read-StrictUtf8Text {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes, [Parameter(Mandatory = $true)][string]$Label)
    try { return $script:Utf8Strict.GetString($Bytes) }
    catch { throw "$Label is not valid UTF-8" }
}

function Remove-FinalCrLf {
    param([Parameter(Mandatory = $true)][string]$Text)
    return $Text.TrimEnd([char[]]@([char]13, [char]10))
}

function Test-ByteArraysEqual {
    param([Parameter(Mandatory = $true)][byte[]]$Left, [Parameter(Mandatory = $true)][byte[]]$Right)
    if ($Left.Length -ne $Right.Length) { return $false }
    for ($index = 0; $index -lt $Left.Length; $index++) { if ($Left[$index] -ne $Right[$index]) { return $false } }
    return $true
}

function Get-UniqueCapture {
    param([Parameter(Mandatory = $true)][string]$Text, [Parameter(Mandatory = $true)][string]$Pattern, [Parameter(Mandatory = $true)][string]$Label)
    $matches = [System.Text.RegularExpressions.Regex]::Matches($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
    if ($matches.Count -ne 1) { throw "expected exactly one $Label record; found $($matches.Count)" }
    return $matches[0]
}

function Get-UniqueMarkerValue {
    param([Parameter(Mandatory = $true)][string]$Text, [Parameter(Mandatory = $true)][string]$Name)
    $pattern = '^(?:' + [System.Text.RegularExpressions.Regex]::Escape($Name) + ')=([^\r\n]*)\r?$'
    $match = Get-UniqueCapture -Text $Text -Pattern $pattern -Label $Name
    return $match.Groups[1].Value
}

function Get-UniqueMarkerInt32 {
    param([Parameter(Mandatory = $true)][string]$Text, [Parameter(Mandatory = $true)][string]$Name)
    $value = Get-UniqueMarkerValue -Text $Text -Name $Name
    try { return [Int32]::Parse($value, [Globalization.CultureInfo]::InvariantCulture) }
    catch { throw "invalid integer marker: $Name" }
}

function ConvertFrom-GuardFields {
    param([Parameter(Mandatory = $true)][string]$Line)
    $fields = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
    foreach ($token in ($Line -split '\s+')) {
        $match = [System.Text.RegularExpressions.Regex]::Match($token, '^(?<key>[A-Za-z0-9_]+)=(?<value>\S+)$')
        if (-not $match.Success) { throw 'v4 guard record contains an invalid field' }
        $key = $match.Groups['key'].Value
        if ($fields.ContainsKey($key)) { throw "v4 guard record repeats a field: $key" }
        $fields.Add($key, $match.Groups['value'].Value)
    }
    return ,$fields
}

function Assert-LakeDependencyClosure {
    param([Parameter(Mandatory = $true)][string]$StageRoot)
    $lakefileText = Read-StrictUtf8Text -Bytes (Read-RegularFileBytes -Path (Join-Path $StageRoot 'lakefile.toml')) -Label 'lakefile.toml'
    if ($lakefileText.IndexOf([char]92) -ge 0 -or [System.Text.RegularExpressions.Regex]::IsMatch($lakefileText, '(?i)\brequire\b')) {
        throw 'staged Lake configuration may declare an external package requirement'
    }

    $manifestBytes = Read-RegularFileBytes -Path (Join-Path $StageRoot 'lake-manifest.json')
    $manifestText = Read-StrictUtf8Text -Bytes $manifestBytes -Label 'lake-manifest.json'
    if ($manifestText.Length -gt 0 -and [Int32][char]$manifestText[0] -eq 0xFEFF) { throw 'Lake manifest must not contain a UTF-8 BOM' }
    $document = $null
    try {
        $document = [System.Text.Json.JsonDocument]::Parse($manifestText)
        $root = $document.RootElement
        if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'Lake manifest root must be a JSON object' }

        $packagesFound = $false
        foreach ($property in $root.EnumerateObject()) {
            if ($property.Name -ceq 'packages') {
                if ($packagesFound) { throw 'Lake manifest repeats the packages property' }
                $packagesFound = $true
                if ($property.Value.ValueKind -ne [System.Text.Json.JsonValueKind]::Array -or $property.Value.GetArrayLength() -ne 0) {
                    throw 'Lake manifest must declare an empty packages array'
                }
            }
        }
        if (-not $packagesFound) { throw 'Lake manifest packages array is missing' }

        $pending = [System.Collections.Generic.Stack[System.Text.Json.JsonElement]]::new()
        $pending.Push($root)
        while ($pending.Count -gt 0) {
            $element = $pending.Pop()
            if ($element.ValueKind -eq [System.Text.Json.JsonValueKind]::Object) {
                $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                foreach ($property in $element.EnumerateObject()) {
                    if (-not $seen.Add($property.Name)) { throw 'Lake manifest contains a duplicate JSON property' }
                    $pending.Push($property.Value)
                }
            } elseif ($element.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) {
                foreach ($item in $element.EnumerateArray()) { $pending.Push($item) }
            }
        }
    } catch {
        throw "staged Lake dependency lock is not closed, valid, or unambiguous: $($_.Exception.Message)"
    } finally {
        if ($null -ne $document) { $document.Dispose() }
    }
}

function Get-GuardUInt64 {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.Dictionary[string, string]]$Fields,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if (-not $Fields.ContainsKey($Name) -or $Fields[$Name] -notmatch '^(?:0|[1-9][0-9]*)$') {
        throw "v4 guard record contains an invalid unsigned integer: $Name"
    }
    try { return [UInt64]::Parse($Fields[$Name], [Globalization.CultureInfo]::InvariantCulture) }
    catch { throw "v4 guard unsigned integer is out of range: $Name" }
}

function Get-V4GuardEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][UInt64]$ExpectedStartFreeBytes
    )
    if ($Text -match '(?m)^(?:RUNNER_FAILURE|GUARD_STOP|CLEANUP_STOP_FAILURE|CLEANUP=FAIL|MUTEX=HELD_UNTIL_PROCESS_EXIT)(?:[=\s]|$)') {
        throw 'v4 guard reported a runner, child, cleanup, or mutex failure'
    }

    $policyMatch = Get-UniqueCapture -Text $Text -Pattern '^RESOURCE_POLICY (?<fields>[^\r\n]+)\r?$' -Label 'v4 resource policy'
    $policy = ConvertFrom-GuardFields -Line $policyMatch.Groups['fields'].Value
    $expectedPolicy = @{
        version = 'v4'
        owner_waiver_effective = '2026-09-23'
        process_tree_memory_cap = 'WAIVED_UNTIL_REVOKED'
        physical_reserve_bytes = '3221225472'
        physical_free_floor_bytes = $script:GuardPhysicalFloorBytes.ToString([Globalization.CultureInfo]::InvariantCulture)
        target_start_floor_bytes = $ExpectedStartFreeBytes.ToString([Globalization.CultureInfo]::InvariantCulture)
        effective_start_floor_bytes = $ExpectedStartFreeBytes.ToString([Globalization.CultureInfo]::InvariantCulture)
        tolerance_percent = '32'
        process_tree_sampling = 'ENABLED'
        cleanup = 'ENABLED'
        mutex = 'Local\BlindLedgerDirectMaskBuild20260907'
        activation = 'NONE'
    }
    if ($policy.Count -ne $expectedPolicy.Count) { throw 'v4 resource policy field set is not exact' }
    foreach ($name in $expectedPolicy.Keys) {
        if (-not $policy.ContainsKey($name) -or $policy[$name] -cne [string]$expectedPolicy[$name]) {
            throw "v4 resource policy field does not match the current contract: $name"
        }
    }

    $preflightMatch = Get-UniqueCapture -Text $Text -Pattern '^PHYSICAL_PREFLIGHT (?<fields>[^\r\n]+)\r?$' -Label 'v4 physical preflight'
    $preflight = ConvertFrom-GuardFields -Line $preflightMatch.Groups['fields'].Value
    $expectedPreflightNames = [string[]]@('free_bytes', 'reserve_bytes', 'reserve_floor_bytes', 'target_start_floor_bytes', 'effective_start_floor_bytes', 'tolerance_percent')
    if ($preflight.Count -ne $expectedPreflightNames.Length) { throw 'v4 physical preflight field set is not exact' }
    foreach ($name in $expectedPreflightNames) {
        if (-not $preflight.ContainsKey($name)) { throw "v4 physical preflight field is missing: $name" }
    }
    $preflightFree = Get-GuardUInt64 -Fields $preflight -Name 'free_bytes'
    $preflightReserve = Get-GuardUInt64 -Fields $preflight -Name 'reserve_bytes'
    $preflightFloor = Get-GuardUInt64 -Fields $preflight -Name 'reserve_floor_bytes'
    $preflightStart = Get-GuardUInt64 -Fields $preflight -Name 'target_start_floor_bytes'
    $preflightEffective = Get-GuardUInt64 -Fields $preflight -Name 'effective_start_floor_bytes'
    $preflightTolerance = Get-GuardUInt64 -Fields $preflight -Name 'tolerance_percent'
    if ($preflightFree -lt $ExpectedStartFreeBytes -or $preflightFree -lt $script:GuardPhysicalFloorBytes -or
        $preflightReserve -ne [UInt64]3221225472 -or $preflightFloor -ne $script:GuardPhysicalFloorBytes -or
        $preflightStart -ne $ExpectedStartFreeBytes -or $preflightEffective -ne $ExpectedStartFreeBytes -or
        $preflightTolerance -ne [UInt64]32) {
        throw 'v4 physical preflight does not meet the exact producer thresholds'
    }

    $checkMatch = Get-UniqueCapture -Text $Text -Pattern '^CHILD_EXIT_CHECK (?<record>[^\r\n]+)\r?$' -Label 'v4 child-exit self-test'
    if ($checkMatch.Groups['record'].Value -cne 'exit7=7 exit0=0') { throw 'v4 child-exit self-test record is not exact' }

    $expectedStatusRecords = [string[]]@('label=child-exit-7 exit=7', 'label=child-exit-0 exit=0', 'label=Command exit=0')
    $statusMatches = [System.Text.RegularExpressions.Regex]::Matches($Text, '(?m)^CHILD_EXIT_STATUS (?<record>[^\r\n]+)\r?$')
    if ($statusMatches.Count -ne $expectedStatusRecords.Length) { throw 'v4 child exit record inventory is not exact' }
    for ($index = 0; $index -lt $expectedStatusRecords.Length; $index++) {
        if ($statusMatches[$index].Groups['record'].Value -cne $expectedStatusRecords[$index]) { throw 'v4 child exit record differs from the expected self-tests and target' }
    }

    $expectedCleanupRecords = [string[]]@(
        'PASS label=child-exit-7 owned_process_tree=empty',
        'PASS label=child-exit-0 owned_process_tree=empty',
        'PASS label=Command owned_process_tree=empty'
    )
    $cleanupMatches = [System.Text.RegularExpressions.Regex]::Matches($Text, '(?m)^CLEANUP=(?<record>[^\r\n]+)\r?$')
    if ($cleanupMatches.Count -ne $expectedCleanupRecords.Length) { throw 'v4 cleanup record inventory is not exact' }
    for ($index = 0; $index -lt $expectedCleanupRecords.Length; $index++) {
        if ($cleanupMatches[$index].Groups['record'].Value -cne $expectedCleanupRecords[$index]) { throw 'v4 cleanup record is not a passing empty-tree record' }
    }

    $expectedLabels = [string[]]@('child-exit-7', 'child-exit-0', 'Command')
    $summaryMatches = [System.Text.RegularExpressions.Regex]::Matches($Text, '(?m)^LIVE_PHYSICAL_SUMMARY (?<record>[^\r\n]+)\r?$')
    if ($summaryMatches.Count -ne $expectedLabels.Length) { throw 'v4 live physical summary inventory is not exact' }
    $minimumFree = [UInt64]::MaxValue
    $expectedSummaryNames = [string[]]@('label', 'samples', 'min_free_bytes', 'reserve_bytes', 'peak_working_set_bytes', 'peak_private_bytes', 'reserve_floor_bytes', 'tolerance_percent')
    for ($index = 0; $index -lt $expectedLabels.Length; $index++) {
        $summary = ConvertFrom-GuardFields -Line $summaryMatches[$index].Groups['record'].Value
        if ($summary.Count -ne $expectedSummaryNames.Length) { throw 'v4 live summary field set is not exact' }
        foreach ($name in $expectedSummaryNames) {
            if (-not $summary.ContainsKey($name)) { throw "v4 live summary field is missing: $name" }
        }
        if ($summary['label'] -cne $expectedLabels[$index]) { throw 'v4 live summary label inventory is not exact' }
        $sampleCount = Get-GuardUInt64 -Fields $summary -Name 'samples'
        $summaryMinimum = Get-GuardUInt64 -Fields $summary -Name 'min_free_bytes'
        $summaryReserve = Get-GuardUInt64 -Fields $summary -Name 'reserve_bytes'
        $null = Get-GuardUInt64 -Fields $summary -Name 'peak_working_set_bytes'
        $null = Get-GuardUInt64 -Fields $summary -Name 'peak_private_bytes'
        $summaryFloor = Get-GuardUInt64 -Fields $summary -Name 'reserve_floor_bytes'
        $summaryTolerance = Get-GuardUInt64 -Fields $summary -Name 'tolerance_percent'
        if ($sampleCount -le 0 -or $summaryMinimum -lt $script:GuardPhysicalFloorBytes -or
            $summaryReserve -ne [UInt64]3221225472 -or $summaryFloor -ne $script:GuardPhysicalFloorBytes -or
            $summaryTolerance -ne [UInt64]32) {
            throw 'v4 live physical summary fails its floor or sampling contract'
        }
        if ($summaryMinimum -lt $minimumFree) { $minimumFree = $summaryMinimum }
    }

    $mutexMatch = Get-UniqueCapture -Text $Text -Pattern '^MUTEX=(?<record>[^\r\n]+)\r?$' -Label 'v4 mutex release'
    if ($mutexMatch.Groups['record'].Value -cne 'RELEASED name=Local\BlindLedgerDirectMaskBuild20260907') { throw 'v4 mutex was not released under the expected identity' }
    return [pscustomobject]@{
        MinimumStartFreeBytes = $preflightStart
        MinimumFreeBytes = $minimumFree
        SelfTestExit7 = [Int32]7
        SelfTestExit0 = [Int32]0
        ChildExitCode = [Int32]0
        Cleanup = 'PASS'
        Mutex = 'RELEASED'
    }
}

function Write-RawChildBytes {
    param([Parameter(Mandatory = $true)][ValidateSet('stdout', 'stderr')][string]$Stream, [Parameter(Mandatory = $true)][byte[]]$Bytes)
    if ($Stream -eq 'stdout') { $target = [Console]::OpenStandardOutput() }
    else { $target = [Console]::OpenStandardError() }
    if ($Bytes.Length -gt 0) { $target.Write($Bytes, 0, $Bytes.Length); $target.Flush() }
}

function Write-ChildMarker {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-RawChildBytes -Stream stdout -Bytes $script:Utf8Strict.GetBytes($Text + [Environment]::NewLine)
}

function Write-ChildNativeOutput {
    param([Parameter(Mandatory = $true)][string]$Label, [Parameter(Mandatory = $true)][object]$Result)
    Write-ChildMarker -Text "ENGINE_PRODUCER_NATIVE_BEGIN=$Label"
    Write-RawChildBytes -Stream stdout -Bytes ([byte[]]$Result.StdoutBytes)
    if ($Result.StdoutBytes.Length -gt 0 -and $Result.StdoutBytes[-1] -ne 10 -and $Result.StdoutBytes[-1] -ne 13) { Write-RawChildBytes -Stream stdout -Bytes ([byte[]]@(10)) }
    Write-RawChildBytes -Stream stderr -Bytes ([byte[]]$Result.StderrBytes)
    if ($Result.StderrBytes.Length -gt 0 -and $Result.StderrBytes[-1] -ne 10 -and $Result.StderrBytes[-1] -ne 13) { Write-RawChildBytes -Stream stderr -Bytes ([byte[]]@(10)) }
    Write-ChildMarker -Text "ENGINE_PRODUCER_NATIVE_END=$Label"
}

function Invoke-VectorOperation {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('TRANSITION', 'REUSE')][string]$Name,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string]$StageRoot,
        [Parameter(Mandatory = $true)][string]$VectorRoot,
        [Parameter(Mandatory = $true)][string]$RequestName,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [Parameter(Mandatory = $true)][string]$ActualName,
        [Parameter(Mandatory = $true)][string]$OperationArgument,
        [Parameter(Mandatory = $true)][string]$RequestSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $requestBytes = Read-RegularFileBytes -Path (Join-Path $VectorRoot $RequestName)
    $expectedBytes = Read-RegularFileBytes -Path (Join-Path $VectorRoot $ExpectedName)
    if ((Get-Sha256FromBytes -Bytes $requestBytes) -ne $RequestSha256 -or (Get-Sha256FromBytes -Bytes $expectedBytes) -ne $ExpectedSha256) { throw "$Name vector inputs changed before execution" }
    $toolchainBin = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($LakeExecutable))
    $pathValue = $toolchainBin + [System.IO.Path]::PathSeparator + [Environment]::GetEnvironmentVariable('PATH')
    $processResult = Invoke-RawProcess -Executable $Executable -ArgumentList @($OperationArgument) -WorkingDirectory $StageRoot -InputBytes $requestBytes -EnvironmentOverrides @{ PATH = $pathValue } -ClearEnvironmentVariables @('LEAN_PATH', 'LEAN_SRC_PATH', 'LEAN_SYSROOT', 'ELAN_TOOLCHAIN')
    $actualBytes = [byte[]]$processResult.StdoutBytes
    Write-FileCreateNew -Path (Join-Path $VectorRoot $ActualName) -Bytes $actualBytes
    $actualHash = Get-Sha256FromBytes -Bytes $actualBytes
    $matchesExpected = Test-ByteArraysEqual -Left $actualBytes -Right $expectedBytes
    Write-RawChildBytes -Stream stderr -Bytes ([byte[]]$processResult.StderrBytes)
    $prefix = 'ENGINE_PRODUCER_' + $Name + '_'
    Write-ChildMarker -Text ($prefix + 'EXIT_CODE=' + $processResult.ExitCode)
    Write-ChildMarker -Text ($prefix + 'OUTPUT_SIZE=' + $actualBytes.Length)
    Write-ChildMarker -Text ($prefix + 'OUTPUT_SHA256=' + $actualHash)
    Write-ChildMarker -Text ($prefix + 'OUTPUT_MATCH=' + $matchesExpected.ToString().ToLowerInvariant())
    return [pscustomobject]@{ ExitCode = [Int32]$processResult.ExitCode; OutputMatches = [bool]$matchesExpected }
}

function Invoke-GuardedChild {
    if ($IgnoredVectorEntryCount -lt 0) { throw 'ignored vector entry count cannot be negative' }
    if ($IgnoredVectorNamesBase64 -notmatch '^[A-Za-z0-9+/]*={0,2}$') { throw 'ignored vector entry names are not base64' }
    $stageFull = [System.IO.Path]::GetFullPath($StageLeanRoot)
    $outputFull = [System.IO.Path]::GetFullPath($OutputDirectory)
    $stageItem = Get-Item -LiteralPath $stageFull -Force -ErrorAction Stop
    if (-not $stageItem.PSIsContainer) { throw 'staged Lean root is not a directory' }
    Assert-NoReparsePathChain -Path $stageFull
    $toolchainRaw = Read-RegularFileBytes -Path (Join-Path $stageFull 'lean-toolchain')
    $toolchain = Remove-FinalCrLf -Text (Read-StrictUtf8Text -Bytes $toolchainRaw -Label 'lean-toolchain')
    if ([string]::IsNullOrWhiteSpace($toolchain)) { throw 'lean-toolchain is empty' }
    $versionMatch = [System.Text.RegularExpressions.Regex]::Match($toolchain, ':(?:v)?(?<version>[0-9]+\.[0-9]+\.[0-9]+)$')
    if (-not $versionMatch.Success) { throw 'lean-toolchain does not end in an explicit semantic version' }
    $expectedLeanVersion = $versionMatch.Groups['version'].Value
    $toolchainBin = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($LakeExecutable))
    if (-not $toolchainBin.Equals([System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($LeanExecutable)), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Lake and Lean executables must come from the same bin directory'
    }
    $environment = @{ PATH = $toolchainBin + [System.IO.Path]::PathSeparator + [Environment]::GetEnvironmentVariable('PATH') }
    $clearEnvironment = @('LEAN_PATH', 'LEAN_SRC_PATH', 'LEAN_SYSROOT', 'ELAN_TOOLCHAIN')

    Write-ChildMarker -Text 'ENGINE_PRODUCER_CHILD_BEGIN=v2'
    Write-ChildMarker -Text 'ENGINE_PRODUCER_VECTOR_SOURCE_SELECTED=4'
    Write-ChildMarker -Text "ENGINE_PRODUCER_VECTOR_SOURCE_IGNORED_COUNT=$IgnoredVectorEntryCount"
    Write-ChildMarker -Text "ENGINE_PRODUCER_VECTOR_SOURCE_IGNORED_NAMES_BASE64=$IgnoredVectorNamesBase64"
    Write-ChildMarker -Text 'ENGINE_PRODUCER_VECTOR_SOURCE_IGNORED_REASON=only pinned request and expected files are used; previous actual outputs are untrusted and recomputed, other entries are not inputs'

    $lakeVersionResult = Invoke-RawProcess -Executable $LakeExecutable -ArgumentList @('--version') -WorkingDirectory $stageFull -EnvironmentOverrides $environment -ClearEnvironmentVariables $clearEnvironment
    Write-ChildNativeOutput -Label 'lake-version' -Result $lakeVersionResult
    $lakeVersion = Remove-FinalCrLf -Text (Read-StrictUtf8Text -Bytes $lakeVersionResult.StdoutBytes -Label 'lake --version stdout')
    Write-ChildMarker -Text ('ENGINE_PRODUCER_LAKE_VERSION_BASE64=' + [Convert]::ToBase64String($script:Utf8Strict.GetBytes($lakeVersion)))
    if ($lakeVersionResult.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($lakeVersion) -or $lakeVersion.Length -gt 2048 -or
        [System.Text.RegularExpressions.Regex]::IsMatch($lakeVersion, '[\x00-\x1F\x7F]')) {
        throw "Lake version probe failed or returned noncanonical text with exit $($lakeVersionResult.ExitCode)"
    }

    $leanVersionResult = Invoke-RawProcess -Executable $LeanExecutable -ArgumentList @('--version') -WorkingDirectory $stageFull -EnvironmentOverrides $environment -ClearEnvironmentVariables $clearEnvironment
    Write-ChildNativeOutput -Label 'lean-version' -Result $leanVersionResult
    $leanVersion = Remove-FinalCrLf -Text (Read-StrictUtf8Text -Bytes $leanVersionResult.StdoutBytes -Label 'lean --version stdout')
    Write-ChildMarker -Text ('ENGINE_PRODUCER_LEAN_VERSION_BASE64=' + [Convert]::ToBase64String($script:Utf8Strict.GetBytes($leanVersion)))
    if ($leanVersionResult.ExitCode -ne 0 -or -not $leanVersion.Contains($expectedLeanVersion, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Lean version does not match the staged toolchain lock: $expectedLeanVersion"
    }

    $stageLakeDirectory = Join-Path $stageFull '.lake'
    if ([System.IO.Directory]::Exists($stageLakeDirectory) -or [System.IO.File]::Exists($stageLakeDirectory)) { throw 'fresh build stage unexpectedly contains .lake before compilation' }
    Assert-LakeDependencyClosure -StageRoot $stageFull
    $lakeBuildResult = Invoke-RawProcess -Executable $LakeExecutable -ArgumentList @('build', $script:TargetName) -WorkingDirectory $stageFull -EnvironmentOverrides $environment -ClearEnvironmentVariables $clearEnvironment
    Write-ChildNativeOutput -Label 'lake-build' -Result $lakeBuildResult
    Write-ChildMarker -Text "ENGINE_PRODUCER_LAKE_BUILD_EXIT_CODE=$($lakeBuildResult.ExitCode)"
    if ($lakeBuildResult.ExitCode -ne 0) { throw "lake build failed with exit $($lakeBuildResult.ExitCode)" }

    $builtExecutable = Join-Path $stageFull '.lake\build\bin\blind_financial_correction.exe'
    $builtIdentity = Get-RegularFileIdentity -Path $builtExecutable
    if ($builtIdentity.SizeBytes -le 0) { throw 'freshly built executable is empty' }
    $vectorRoot = Join-Path $outputFull 'vectors'
    $transition = Invoke-VectorOperation -Name TRANSITION -Executable $builtExecutable -StageRoot $stageFull -VectorRoot $vectorRoot -RequestName 'request.bin' -ExpectedName 'result.expected.bin' -ActualName 'result.actual.bin' -OperationArgument '--apply-correction-transition' -RequestSha256 '13F832E80B93CC55D17ADD29470A2CD789CFCED1CBCF5A055FCBA3ECB927B537' -ExpectedSha256 '312AB06C76D6F6F2F40CF93F9EE37DA328161B733FE7D5567E0694B85D3AE18E'
    $reuse = Invoke-VectorOperation -Name REUSE -Executable $builtExecutable -StageRoot $stageFull -VectorRoot $vectorRoot -RequestName 'reuse-request.bin' -ExpectedName 'reuse-result.expected.bin' -ActualName 'reuse-result.actual.bin' -OperationArgument '--assess-correction-reuse' -RequestSha256 'DD7DDC27FEEDFDFD26540AB6B1F7D37E6BE49768583FB1EA3AB02F85C8390DC6' -ExpectedSha256 '8C50EC33F30B520CC7452C3618577228B6B51B59B68A1935549461FAD2615379'
    if ($transition.ExitCode -ne 0 -or -not $transition.OutputMatches -or $reuse.ExitCode -ne 0 -or -not $reuse.OutputMatches) {
        Write-ChildMarker -Text 'ENGINE_PRODUCER_CHILD_RESULT=FAIL'
        return 1
    }
    Write-ChildMarker -Text 'ENGINE_PRODUCER_CHILD_RESULT=PASS'
    return 0
}

function ConvertTo-PowerShellLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Invoke-GitRaw {
    param([Parameter(Mandatory = $true)][string]$GitPath, [Parameter(Mandatory = $true)][string]$EngineRootFull, [Parameter(Mandatory = $true)][string[]]$GitArguments)
    $arguments = [System.Collections.Generic.List[string]]::new()
    $arguments.Add('-C')
    $arguments.Add($EngineRootFull)
    foreach ($argument in $GitArguments) { $arguments.Add($argument) }
    $result = Invoke-RawProcess -Executable $GitPath -ArgumentList $arguments.ToArray() -WorkingDirectory $EngineRootFull
    if ($result.ExitCode -ne 0 -or $result.StderrBytes.Length -ne 0) {
        if ($result.StderrBytes.Length -gt 0) { [Console]::Error.Write($script:Utf8Strict.GetString($result.StderrBytes)) }
        throw "Git provenance command failed: $($GitArguments -join ' ') (exit $($result.ExitCode))"
    }
    return ,([byte[]]$result.StdoutBytes)
}

function Get-GitSnapshot {
    param([Parameter(Mandatory = $true)][string]$GitPath, [Parameter(Mandatory = $true)][string]$EngineRootFull)
    $headBytes = Invoke-GitRaw -GitPath $GitPath -EngineRootFull $EngineRootFull -GitArguments @('rev-parse', 'HEAD')
    $treeBytes = Invoke-GitRaw -GitPath $GitPath -EngineRootFull $EngineRootFull -GitArguments @('rev-parse', 'HEAD^{tree}')
    $statusBytes = Invoke-GitRaw -GitPath $GitPath -EngineRootFull $EngineRootFull -GitArguments @('status', '--porcelain=v1', '-z', '--untracked-files=all')
    $head = Remove-FinalCrLf -Text (Read-StrictUtf8Text -Bytes $headBytes -Label 'git rev-parse HEAD')
    $tree = Remove-FinalCrLf -Text (Read-StrictUtf8Text -Bytes $treeBytes -Label 'git rev-parse HEAD tree')
    if ($head -notmatch '^[0-9a-f]{40}$' -or $tree -notmatch '^[0-9a-f]{40}$') { throw 'Git returned a noncanonical full commit or tree id' }
    return [pscustomobject]@{ Head = $head; Tree = $tree; StatusBytes = $statusBytes; StatusSha256 = Get-Sha256FromBytes -Bytes $statusBytes }
}

function Get-VectorDirectoryInventory {
    param([Parameter(Mandatory = $true)][string]$Directory)
    if (-not [System.IO.Directory]::Exists($Directory)) { throw "vector source directory is missing: $Directory" }
    Assert-NoReparsePathChain -Path $Directory
    $entries = @(Get-ChildItem -LiteralPath $Directory -Force -ErrorAction Stop)
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $entries) { $names.Add([string]$entry.Name) }
    $allNames = [string[]]$names.ToArray()
    [Array]::Sort($allNames, [System.StringComparer]::Ordinal)
    $selected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($spec in $script:PinnedVectorSpecs) { [void]$selected.Add([string]$spec.SourceName) }
    foreach ($spec in $script:PinnedVectorSpecs) {
        if (-not ($allNames -ccontains [string]$spec.SourceName)) { throw "required pinned vector input is missing: $($spec.SourceName)" }
    }
    $ignored = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $allNames) { if (-not $selected.Contains($name)) { $ignored.Add($name) } }
    return [pscustomobject]@{ AllNames = $allNames; IgnoredNames = [string[]]$ignored.ToArray() }
}

function Get-SourceManifestEntry {
    param([Parameter(Mandatory = $true)][object]$Manifest, [Parameter(Mandatory = $true)][string]$Path)
    $matches = @($Manifest.Rows | Where-Object { [string]$_.path -ceq $Path })
    if ($matches.Count -ne 1) { throw "source manifest must contain exactly one $Path entry" }
    return $matches[0]
}

function Copy-InputsAndRecord {
    param([Parameter(Mandatory = $true)][string]$VectorSourceFull, [Parameter(Mandatory = $true)][string]$VectorOutputRoot)
    $identities = @{}
    foreach ($spec in $script:PinnedVectorSpecs) {
        $source = Join-Path $VectorSourceFull $spec.SourceName
        $identity = Get-RegularFileIdentity -Path $source
        if ($identity.Sha256 -ne $spec.Sha256) { throw "pinned vector source hash mismatch: $($spec.SourceName)" }
        $bytes = Read-RegularFileBytes -Path $source
        $actualHash = Get-Sha256FromBytes -Bytes $bytes
        if ($actualHash -ne $spec.Sha256) { throw "pinned vector source changed while reading: $($spec.SourceName)" }
        Write-FileCreateNew -Path (Join-Path $VectorOutputRoot $spec.OutputName) -Bytes $bytes
        $identities[$spec.SourceName] = [pscustomobject]@{ SizeBytes = [Int64]$bytes.Length; Sha256 = $actualHash; OutputName = [string]$spec.OutputName }
    }
    return $identities
}

function Write-AtomicCreateOnly {
    param([Parameter(Mandatory = $true)][string]$DestinationPath, [Parameter(Mandatory = $true)][byte[]]$Bytes)
    if ([System.IO.File]::Exists($DestinationPath) -or [System.IO.Directory]::Exists($DestinationPath)) { throw "refusing to overwrite receipt: $DestinationPath" }
    $temporary = Join-Path ([System.IO.Path]::GetDirectoryName($DestinationPath)) ('.engine-build-receipt.' + [Guid]::NewGuid().ToString('N') + '.tmp')
    Write-FileCreateNew -Path $temporary -Bytes $Bytes
    $readback = Read-RegularFileBytes -Path $temporary
    if (-not (Test-ByteArraysEqual -Left $Bytes -Right $readback)) { throw 'temporary receipt readback mismatch' }
    [System.IO.File]::Move($temporary, $DestinationPath)
}

function Assert-EngineReleaseInventoryBeforeReceipt {
    param([Parameter(Mandatory = $true)][string]$ReleaseRoot)
    $expectedFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($name in @(
        'blind_financial_correction.exe', 'source-manifest.json',
        'vectors/request.bin', 'vectors/result.expected.bin', 'vectors/result.actual.bin',
        'vectors/reuse-request.bin', 'vectors/reuse-result.expected.bin', 'vectors/reuse-result.actual.bin',
        'logs/child.stdout.log', 'logs/child.stderr.log', 'logs/guard.stdout.log', 'logs/guard.stderr.log'
    )) { [void]$expectedFiles.Add($name) }
    $expectedDirectories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($name in @('vectors', 'logs', 'provenance')) { [void]$expectedDirectories.Add($name) }

    $actualFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $actualDirectories = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in (Get-ChildItem -LiteralPath $ReleaseRoot -Recurse -Force -ErrorAction Stop)) {
        $attributes = [System.IO.File]::GetAttributes($entry.FullName)
        if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "release inventory contains a reparse point: $($entry.FullName)" }
        $relative = [System.IO.Path]::GetRelativePath($ReleaseRoot, $entry.FullName).Replace('\', '/')
        if ($entry.PSIsContainer) {
            [void]$actualDirectories.Add($relative)
        } else {
            $null = Get-RegularFileIdentity -Path $entry.FullName
            [void]$actualFiles.Add($relative)
        }
    }
    if ($actualFiles.Count -ne $expectedFiles.Count -or $actualDirectories.Count -ne $expectedDirectories.Count) {
        throw 'producer output does not match the exact Release consumer file and directory inventory'
    }
    foreach ($name in $expectedFiles) { if (-not $actualFiles.Contains($name)) { throw "producer output is missing a Release consumer file: $name" } }
    foreach ($name in $actualFiles) { if (-not $expectedFiles.Contains($name)) { throw "producer output contains an unrecognized Release consumer file: $name" } }
    foreach ($name in $expectedDirectories) { if (-not $actualDirectories.Contains($name)) { throw "producer output is missing a Release consumer directory: $name" } }
    foreach ($name in $actualDirectories) { if (-not $expectedDirectories.Contains($name)) { throw "producer output contains an unrecognized Release consumer directory: $name" } }
}

function Invoke-ParentProducer {
    if ($MinimumStartFreeBytes -lt $script:LeanCompilerStartFloorBytes) { throw "Lean build start floor must be at least $($script:LeanCompilerStartFloorBytes) bytes" }
    if ([string]::IsNullOrWhiteSpace($DirectLaneGrantReference) -or $DirectLaneGrantReference.Length -gt 2048 -or
        [System.Text.RegularExpressions.Regex]::IsMatch($DirectLaneGrantReference, '[\x00-\x1F\x7F]')) {
        throw 'a nonempty printable Driver lane-grant reference of at most 2048 characters is required'
    }

    $engineFull = [System.IO.Path]::GetFullPath($EngineRoot)
    $sourceRoot = Join-Path $engineFull 'lean'
    $scriptFull = [System.IO.Path]::GetFullPath($PSCommandPath)
    $expectedScript = [System.IO.Path]::GetFullPath((Join-Path $engineFull 'tools\build_financial_correction_release.ps1'))
    if (-not $scriptFull.Equals($expectedScript, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'producer must run from the authorized Engine tools path' }
    Assert-NoReparsePathChain -Path $engineFull
    if (-not [System.IO.Directory]::Exists($sourceRoot)) { throw "Lean source root is missing: $sourceRoot" }
    $outputFull = [System.IO.Path]::GetFullPath($OutputDirectory)
    if (Test-PathInside -Candidate $outputFull -Root $engineFull) { throw 'producer output must be outside the Engine checkout' }
    if ([System.IO.File]::Exists($outputFull) -or [System.IO.Directory]::Exists($outputFull)) { throw "producer output directory must be new: $outputFull" }
    $outputParent = [System.IO.Path]::GetDirectoryName($outputFull)
    if (-not [System.IO.Directory]::Exists($outputParent)) { throw "producer output parent must already exist: $outputParent" }
    Assert-NoReparsePathChain -Path $outputParent

    $vectorSourceFull = [System.IO.Path]::GetFullPath($VectorSourceDirectory)
    Assert-NoReparsePathChain -Path $vectorSourceFull
    if (Test-PathInside -Candidate $outputFull -Root $vectorSourceFull) { throw 'producer output must not be inside the vector source directory' }

    $driverRoot = [System.IO.Directory]::GetParent([System.IO.Directory]::GetParent($engineFull).FullName).FullName
    $expectedGuard = Join-Path $driverRoot 'work\pq-wide-seed-native-20260913\build-filter-native\run_guarded_v4.ps1'
    $guardFull = if ([string]::IsNullOrWhiteSpace($GuardPath)) { $expectedGuard } else { [System.IO.Path]::GetFullPath($GuardPath) }
    if (-not [System.IO.File]::Exists($guardFull)) { throw "v4 guard is missing: $guardFull" }
    $guardIdentity = Get-RegularFileIdentity -Path $guardFull
    if ($guardIdentity.Sha256 -ne $script:GuardSha256) { throw 'v4 guard SHA-256 mismatch' }
    $guardDirectory = [System.IO.Path]::GetDirectoryName($guardFull)
    if (Test-PathInside -Candidate $outputFull -Root $guardDirectory) { throw 'producer output must not be inside the guarded build root' }

    $lakeFull = [System.IO.Path]::GetFullPath($LakeExecutable)
    $leanFull = [System.IO.Path]::GetFullPath($LeanExecutable)
    if (-not [System.IO.Path]::IsPathRooted($LakeExecutable) -or -not [System.IO.Path]::IsPathRooted($LeanExecutable)) { throw 'Lake and Lean executable paths must be absolute' }
    if ([System.IO.Path]::GetFileName($lakeFull) -ine 'lake.exe' -or [System.IO.Path]::GetFileName($leanFull) -ine 'lean.exe') { throw 'Lake and Lean must be the actual lake.exe and lean.exe files' }
    if (-not [System.IO.Path]::GetDirectoryName($lakeFull).Equals([System.IO.Path]::GetDirectoryName($leanFull), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Lake and Lean executables must come from the same bin directory'
    }
    $lakeIdentity = Get-RegularFileIdentity -Path $lakeFull
    $leanIdentity = Get-RegularFileIdentity -Path $leanFull

    $gitCommand = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $gitPath = [System.IO.Path]::GetFullPath($gitCommand.Source)
    $gitBefore = Get-GitSnapshot -GitPath $gitPath -EngineRootFull $engineFull
    $producerIdentity = Get-RegularFileIdentity -Path $scriptFull

    [System.IO.Directory]::CreateDirectory($outputFull) | Out-Null
    $vectorsOutput = Join-Path $outputFull 'vectors'
    $logsOutput = Join-Path $outputFull 'logs'
    $provenanceOutput = Join-Path $outputFull 'provenance'
    $stageRoot = Join-Path $outputParent ('.engine-build-stage-' + [Guid]::NewGuid().ToString('N'))
    if ([System.IO.Directory]::Exists($stageRoot) -or [System.IO.File]::Exists($stageRoot)) { throw 'refusing a pre-existing isolated build stage' }
    $stageLeanRoot = Join-Path $stageRoot 'lean'
    [System.IO.Directory]::CreateDirectory($vectorsOutput) | Out-Null
    [System.IO.Directory]::CreateDirectory($logsOutput) | Out-Null
    [System.IO.Directory]::CreateDirectory($provenanceOutput) | Out-Null

    $sourceManifest = New-SourceManifestSnapshot -Root $sourceRoot
    Write-StagedSourceSnapshot -SourceRoot $sourceRoot -StageRoot $stageLeanRoot -Rows $sourceManifest.Rows
    $stageManifest = New-SourceManifestSnapshot -Root $stageLeanRoot
    if (-not (Test-ByteArraysEqual -Left $sourceManifest.Bytes -Right $stageManifest.Bytes)) { throw 'staged source-manifest differs from the captured Engine source-manifest' }
    $sourceManifestAfterStage = New-SourceManifestSnapshot -Root $sourceRoot
    if (-not (Test-ByteArraysEqual -Left $sourceManifest.Bytes -Right $sourceManifestAfterStage.Bytes)) { throw 'Engine Lean sources changed while staging' }
    Write-FileCreateNew -Path (Join-Path $outputFull 'source-manifest.json') -Bytes $sourceManifest.Bytes

    $vectorInventory = Get-VectorDirectoryInventory -Directory $vectorSourceFull
    $ignoredNamesJson = ConvertTo-CanonicalJsonText -Value $vectorInventory.IgnoredNames
    $ignoredNamesBase64 = [Convert]::ToBase64String($script:Utf8Strict.GetBytes($ignoredNamesJson))
    if ($ignoredNamesBase64.Length -gt 8192) { throw 'vector fixture directory contains too many ignored entries to record safely' }
    $vectorIdentities = Copy-InputsAndRecord -VectorSourceFull $vectorSourceFull -VectorOutputRoot $vectorsOutput

    $toolchainEntry = Get-SourceManifestEntry -Manifest $sourceManifest -Path 'engine/source/lean-toolchain'
    $lakefileEntry = Get-SourceManifestEntry -Manifest $sourceManifest -Path 'engine/source/lakefile.toml'
    $lakeManifestEntry = Get-SourceManifestEntry -Manifest $sourceManifest -Path 'engine/source/lake-manifest.json'
    $toolchainRaw = Read-RegularFileBytes -Path (Join-Path $sourceRoot 'lean-toolchain')
    $leanToolchainText = Remove-FinalCrLf -Text (Read-StrictUtf8Text -Bytes $toolchainRaw -Label 'lean-toolchain')
    if ([string]::IsNullOrWhiteSpace($leanToolchainText)) { throw 'lean-toolchain string is empty' }

    $runSuffix = 'financial-correction-' + [Guid]::NewGuid().ToString('N')
    $guardChildStdout = Join-Path $guardDirectory ("guarded-command-{0}.stdout.log" -f $runSuffix)
    $guardChildStderr = Join-Path $guardDirectory ("guarded-command-{0}.stderr.log" -f $runSuffix)
    if ([System.IO.File]::Exists($guardChildStdout) -or [System.IO.File]::Exists($guardChildStderr)) { throw 'refusing a v4 guard run suffix whose child logs already exist' }

    $pwshCommand = Get-Command pwsh -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $pwshPath = [System.IO.Path]::GetFullPath($pwshCommand.Source)
    $childArguments = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in @('-NoLogo', '-NoProfile', '-File', $scriptFull, '-GuardedChild', '-OutputDirectory', $outputFull, '-LakeExecutable', $lakeFull, '-LeanExecutable', $leanFull, '-StageLeanRoot', $stageLeanRoot, '-IgnoredVectorEntryCount', [string]$vectorInventory.IgnoredNames.Length, '-IgnoredVectorNamesBase64', $ignoredNamesBase64)) {
        $childArguments.Add([string]$argument)
    }
    $childArgumentLiterals = [System.Collections.Generic.List[string]]::new()
    foreach ($argument in $childArguments) { $childArgumentLiterals.Add((ConvertTo-PowerShellLiteral -Value $argument)) }
    $childArrayExpression = '@(' + [string]::Join(',', $childArgumentLiterals.ToArray()) + ')'
    $guardCommand = '& ' + (ConvertTo-PowerShellLiteral -Value $guardFull) +
        ' -Mode Command -RunSuffix ' + (ConvertTo-PowerShellLiteral -Value $runSuffix) +
        ' -CommandPath ' + (ConvertTo-PowerShellLiteral -Value $pwshPath) +
        ' -CommandArguments ' + $childArrayExpression +
        ' -MinimumStartFreeBytes ' + $MinimumStartFreeBytes.ToString([Globalization.CultureInfo]::InvariantCulture)

    $guardResult = Invoke-RawProcess -Executable $pwshPath -ArgumentList @('-NoLogo', '-NoProfile', '-Command', $guardCommand) -WorkingDirectory $guardDirectory
    Write-FileCreateNew -Path (Join-Path $logsOutput 'guard.stdout.log') -Bytes ([byte[]]$guardResult.StdoutBytes)
    Write-FileCreateNew -Path (Join-Path $logsOutput 'guard.stderr.log') -Bytes ([byte[]]$guardResult.StderrBytes)
    if ([System.IO.File]::Exists($guardChildStdout)) { Copy-FileCreateNew -SourcePath $guardChildStdout -DestinationPath (Join-Path $logsOutput 'child.stdout.log') }
    if ([System.IO.File]::Exists($guardChildStderr)) { Copy-FileCreateNew -SourcePath $guardChildStderr -DestinationPath (Join-Path $logsOutput 'child.stderr.log') }
    if ($guardResult.ExitCode -ne 0) { throw "v4 guard outer process failed with exit $($guardResult.ExitCode); raw logs were retained" }
    if (-not [System.IO.File]::Exists((Join-Path $logsOutput 'child.stdout.log')) -or -not [System.IO.File]::Exists((Join-Path $logsOutput 'child.stderr.log'))) {
        throw 'v4 guard did not produce both child stream logs; raw guard logs were retained'
    }

    $guardText = Read-StrictUtf8Text -Bytes ([byte[]]$guardResult.StdoutBytes) -Label 'v4 guard stdout'
    $childStdoutPath = Join-Path $logsOutput 'child.stdout.log'
    $childStderrPath = Join-Path $logsOutput 'child.stderr.log'
    $childStdoutBytes = Read-RegularFileBytes -Path $childStdoutPath
    $childStderrBytes = Read-RegularFileBytes -Path $childStderrPath
    $childText = Read-StrictUtf8Text -Bytes $childStdoutBytes -Label 'guarded child stdout'
    $guardEvidence = Get-V4GuardEvidence -Text $guardText -ExpectedStartFreeBytes $MinimumStartFreeBytes
    $selfTestExit7 = $guardEvidence.SelfTestExit7
    $selfTestExit0 = $guardEvidence.SelfTestExit0
    $guardChildExit = $guardEvidence.ChildExitCode
    $preflightStart = $guardEvidence.MinimumStartFreeBytes
    $minimumFree = $guardEvidence.MinimumFreeBytes

    if ((Get-UniqueMarkerValue -Text $childText -Name 'ENGINE_PRODUCER_CHILD_BEGIN') -cne 'v2') { throw 'guarded child did not identify the v2 producer protocol' }
    $loggedIgnoredCount = Get-UniqueMarkerInt32 -Text $childText -Name 'ENGINE_PRODUCER_VECTOR_SOURCE_IGNORED_COUNT'
    $loggedIgnoredNames = Get-UniqueMarkerValue -Text $childText -Name 'ENGINE_PRODUCER_VECTOR_SOURCE_IGNORED_NAMES_BASE64'
    $loggedIgnoredReason = Get-UniqueMarkerValue -Text $childText -Name 'ENGINE_PRODUCER_VECTOR_SOURCE_IGNORED_REASON'
    $expectedIgnoredReason = 'only pinned request and expected files are used; previous actual outputs are untrusted and recomputed, other entries are not inputs'
    if ($loggedIgnoredCount -ne $vectorInventory.IgnoredNames.Length -or $loggedIgnoredNames -cne $ignoredNamesBase64 -or $loggedIgnoredReason -cne $expectedIgnoredReason) {
        throw 'guarded child vector-source skip record differs from the captured fixture inventory'
    }

    $lakeBuildExit = Get-UniqueMarkerInt32 -Text $childText -Name 'ENGINE_PRODUCER_LAKE_BUILD_EXIT_CODE'
    $transitionExit = Get-UniqueMarkerInt32 -Text $childText -Name 'ENGINE_PRODUCER_TRANSITION_EXIT_CODE'
    $reuseExit = Get-UniqueMarkerInt32 -Text $childText -Name 'ENGINE_PRODUCER_REUSE_EXIT_CODE'
    $transitionMatches = Get-UniqueMarkerValue -Text $childText -Name 'ENGINE_PRODUCER_TRANSITION_OUTPUT_MATCH'
    $reuseMatches = Get-UniqueMarkerValue -Text $childText -Name 'ENGINE_PRODUCER_REUSE_OUTPUT_MATCH'
    $lakeVersionBase64 = Get-UniqueMarkerValue -Text $childText -Name 'ENGINE_PRODUCER_LAKE_VERSION_BASE64'
    $leanVersionBase64 = Get-UniqueMarkerValue -Text $childText -Name 'ENGINE_PRODUCER_LEAN_VERSION_BASE64'
    try {
        $lakeVersion = Remove-FinalCrLf -Text (Read-StrictUtf8Text -Bytes ([Convert]::FromBase64String($lakeVersionBase64)) -Label 'captured Lake version')
        $leanVersion = Remove-FinalCrLf -Text (Read-StrictUtf8Text -Bytes ([Convert]::FromBase64String($leanVersionBase64)) -Label 'captured Lean version')
    } catch { throw 'guarded child version record is malformed' }
    $lockVersionMatch = [System.Text.RegularExpressions.Regex]::Match($leanToolchainText, ':(?:v)?(?<version>[0-9]+\.[0-9]+\.[0-9]+)$')
    if (-not $lockVersionMatch.Success -or -not $leanVersion.Contains($lockVersionMatch.Groups['version'].Value, [System.StringComparison]::OrdinalIgnoreCase) -or [string]::IsNullOrWhiteSpace($lakeVersion)) {
        throw 'observed Lake/Lean version does not bind to the staged toolchain lock'
    }
    if ($lakeBuildExit -ne 0 -or $transitionExit -ne 0 -or $reuseExit -ne 0 -or $transitionMatches -cne 'true' -or $reuseMatches -cne 'true' -or $guardChildExit -ne 0) {
        throw 'guarded build or fresh executable vector check failed'
    }

    $stageExecutable = Join-Path $stageLeanRoot '.lake\build\bin\blind_financial_correction.exe'
    $artifactOutput = Join-Path $outputFull 'blind_financial_correction.exe'
    Copy-FileCreateNew -SourcePath $stageExecutable -DestinationPath $artifactOutput
    $artifactIdentity = Get-RegularFileIdentity -Path $artifactOutput
    if ($artifactIdentity.SizeBytes -le 0) { throw 'copied correction executable is empty' }

    foreach ($spec in $script:PinnedVectorSpecs) {
        $sourceIdentity = Get-RegularFileIdentity -Path (Join-Path $vectorSourceFull $spec.SourceName)
        if ($sourceIdentity.Sha256 -ne $spec.Sha256 -or $sourceIdentity.Sha256 -ne $vectorIdentities[$spec.SourceName].Sha256) {
            throw "vector source changed during guarded build: $($spec.SourceName)"
        }
        $outputIdentity = Get-RegularFileIdentity -Path (Join-Path $vectorsOutput $vectorIdentities[$spec.SourceName].OutputName)
        if ($outputIdentity.Sha256 -ne $spec.Sha256) { throw "copied vector input changed during guarded build: $($spec.SourceName)" }
    }

    $transitionActual = Get-RegularFileIdentity -Path (Join-Path $vectorsOutput 'result.actual.bin')
    $transitionExpected = Get-RegularFileIdentity -Path (Join-Path $vectorsOutput 'result.expected.bin')
    $reuseActual = Get-RegularFileIdentity -Path (Join-Path $vectorsOutput 'reuse-result.actual.bin')
    $reuseExpected = Get-RegularFileIdentity -Path (Join-Path $vectorsOutput 'reuse-result.expected.bin')
    if ($transitionActual.SizeBytes -ne $transitionExpected.SizeBytes -or $transitionActual.Sha256 -ne $transitionExpected.Sha256 -or
        $reuseActual.SizeBytes -ne $reuseExpected.SizeBytes -or $reuseActual.Sha256 -ne $reuseExpected.Sha256) {
        throw 'fresh transition or reuse output does not match its pinned expected vector'
    }

    $sourceManifestFinal = New-SourceManifestSnapshot -Root $sourceRoot
    $stageManifestFinal = New-SourceManifestSnapshot -Root $stageLeanRoot
    if (-not (Test-ByteArraysEqual -Left $sourceManifest.Bytes -Right $sourceManifestFinal.Bytes) -or
        -not (Test-ByteArraysEqual -Left $sourceManifest.Bytes -Right $stageManifestFinal.Bytes)) {
        throw 'Engine source or staged build inputs changed during the guarded build'
    }
    $scriptIdentityFinal = Get-RegularFileIdentity -Path $scriptFull
    $guardIdentityFinal = Get-RegularFileIdentity -Path $guardFull
    $lakeIdentityFinal = Get-RegularFileIdentity -Path $lakeFull
    $leanIdentityFinal = Get-RegularFileIdentity -Path $leanFull
    if ($scriptIdentityFinal.Sha256 -ne $producerIdentity.Sha256 -or $guardIdentityFinal.Sha256 -ne $script:GuardSha256 -or
        $lakeIdentityFinal.Sha256 -ne $lakeIdentity.Sha256 -or $leanIdentityFinal.Sha256 -ne $leanIdentity.Sha256) {
        throw 'producer, guard, Lake, or Lean executable changed during the run'
    }

    $vectorInventoryFinal = Get-VectorDirectoryInventory -Directory $vectorSourceFull
    $inventoryBeforeBytes = $script:Utf8Strict.GetBytes((ConvertTo-CanonicalJsonText -Value $vectorInventory.AllNames))
    $inventoryAfterBytes = $script:Utf8Strict.GetBytes((ConvertTo-CanonicalJsonText -Value $vectorInventoryFinal.AllNames))
    if (-not (Test-ByteArraysEqual -Left $inventoryBeforeBytes -Right $inventoryAfterBytes)) { throw 'vector fixture directory entries changed during the guarded build' }

    $gitAfter = Get-GitSnapshot -GitPath $gitPath -EngineRootFull $engineFull
    if ($gitAfter.Head -cne $gitBefore.Head -or $gitAfter.Tree -cne $gitBefore.Tree -or
        -not (Test-ByteArraysEqual -Left $gitBefore.StatusBytes -Right $gitAfter.StatusBytes)) {
        throw 'Engine Git state changed during the guarded build'
    }

    $guardStdoutIdentity = Get-RegularFileIdentity -Path (Join-Path $logsOutput 'guard.stdout.log')
    $guardStderrIdentity = Get-RegularFileIdentity -Path (Join-Path $logsOutput 'guard.stderr.log')
    $childStdoutIdentity = Get-RegularFileIdentity -Path (Join-Path $logsOutput 'child.stdout.log')
    $childStderrIdentity = Get-RegularFileIdentity -Path (Join-Path $logsOutput 'child.stderr.log')
    Assert-EngineReleaseInventoryBeforeReceipt -ReleaseRoot $outputFull

    $receipt = [ordered]@{
        direct_lane_grant_reference = $DirectLaneGrantReference
        engine_git_head = $gitBefore.Head
        engine_git_status_sha256 = $gitBefore.StatusSha256
        engine_git_tree = $gitBefore.Tree
        engine_source_manifest_sha256 = $sourceManifest.Sha256
        executable_sha256 = $artifactIdentity.Sha256
        executable_size_bytes = [Int64]$artifactIdentity.SizeBytes
        guard_child_exit_code = [Int32]$guardChildExit
        guard_cleanup = 'PASS'
        guard_minimum_free_bytes = [UInt64]$minimumFree
        guard_minimum_start_free_bytes = [UInt64]$preflightStart
        guard_mutex = 'RELEASED'
        guard_outer_exit_code = [Int32]$guardResult.ExitCode
        guard_self_test_exit0 = [Int32]$selfTestExit0
        guard_self_test_exit7 = [Int32]$selfTestExit7
        guard_stderr_sha256 = $guardStderrIdentity.Sha256
        guard_stdout_sha256 = $guardStdoutIdentity.Sha256
        guard_wrapper_sha256 = $script:GuardSha256
        lake_build_exit_code = [Int32]$lakeBuildExit
        lake_executable_sha256 = $lakeIdentity.Sha256
        lake_manifest_sha256 = [string]$lakeManifestEntry.sha256
        lake_version = $lakeVersion
        lakefile_sha256 = [string]$lakefileEntry.sha256
        lean_executable_sha256 = $leanIdentity.Sha256
        lean_toolchain = $leanToolchainText
        lean_toolchain_sha256 = [string]$toolchainEntry.sha256
        producer_script_sha256 = $producerIdentity.Sha256
        request_vector_sha256 = [string]$vectorIdentities['request.bin'].Sha256
        reuse_request_vector_sha256 = [string]$vectorIdentities['reuse-request.bin'].Sha256
        reuse_result_vector_sha256 = $reuseActual.Sha256
        reuse_vector_exit_code = [Int32]$reuseExit
        result_vector_sha256 = $transitionActual.Sha256
        schema = $script:ReceiptSchema
        status = 'PASS'
        stderr_sha256 = $childStderrIdentity.Sha256
        stdout_sha256 = $childStdoutIdentity.Sha256
        target = $script:TargetName
        transition_vector_exit_code = [Int32]$transitionExit
    }

    $expectedKeys = [string[]]@(
        'direct_lane_grant_reference', 'engine_git_head', 'engine_git_status_sha256', 'engine_git_tree',
        'engine_source_manifest_sha256', 'executable_sha256', 'executable_size_bytes',
        'guard_child_exit_code', 'guard_cleanup', 'guard_minimum_free_bytes', 'guard_minimum_start_free_bytes',
        'guard_mutex', 'guard_outer_exit_code', 'guard_self_test_exit0', 'guard_self_test_exit7',
        'guard_stderr_sha256', 'guard_stdout_sha256', 'guard_wrapper_sha256', 'lake_build_exit_code',
        'lake_executable_sha256', 'lake_manifest_sha256', 'lake_version', 'lakefile_sha256',
        'lean_executable_sha256', 'lean_toolchain', 'lean_toolchain_sha256', 'producer_script_sha256',
        'request_vector_sha256', 'reuse_request_vector_sha256', 'reuse_result_vector_sha256',
        'reuse_vector_exit_code', 'result_vector_sha256', 'schema', 'status', 'stderr_sha256',
        'stdout_sha256', 'target', 'transition_vector_exit_code'
    )
    $actualKeys = [string[]]@($receipt.Keys)
    [Array]::Sort($expectedKeys, [System.StringComparer]::Ordinal)
    [Array]::Sort($actualKeys, [System.StringComparer]::Ordinal)
    if ($receipt.Count -ne 38 -or [string]::Join('|', $actualKeys) -cne [string]::Join('|', $expectedKeys)) { throw 'receipt field set is not the exact 38-key v2 contract' }

    foreach ($name in @(
        'engine_source_manifest_sha256', 'executable_sha256', 'engine_git_status_sha256',
        'guard_stderr_sha256', 'guard_stdout_sha256', 'guard_wrapper_sha256',
        'lake_executable_sha256', 'lake_manifest_sha256', 'lakefile_sha256', 'lean_executable_sha256',
        'lean_toolchain_sha256', 'producer_script_sha256', 'request_vector_sha256',
        'reuse_request_vector_sha256', 'reuse_result_vector_sha256', 'result_vector_sha256',
        'stderr_sha256', 'stdout_sha256'
    )) {
        if ([string]$receipt[$name] -notmatch '^[0-9A-F]{64}$') { throw "receipt contains an invalid SHA-256 field: $name" }
    }
    if ($receipt.schema -cne $script:ReceiptSchema -or $receipt.status -cne 'PASS' -or $receipt.target -cne $script:TargetName -or
        $receipt.executable_size_bytes -le 0 -or $receipt.guard_outer_exit_code -ne 0 -or $receipt.guard_child_exit_code -ne 0 -or
        $receipt.lake_build_exit_code -ne 0 -or $receipt.transition_vector_exit_code -ne 0 -or $receipt.reuse_vector_exit_code -ne 0 -or
        $receipt.guard_self_test_exit7 -ne 7 -or $receipt.guard_self_test_exit0 -ne 0 -or
        $receipt.guard_minimum_start_free_bytes -lt $script:LeanCompilerStartFloorBytes -or
        $receipt.guard_minimum_free_bytes -lt $script:GuardPhysicalFloorBytes -or $receipt.guard_cleanup -cne 'PASS' -or $receipt.guard_mutex -cne 'RELEASED' -or
        [string]::IsNullOrWhiteSpace([string]$receipt.direct_lane_grant_reference) -or [string]::IsNullOrWhiteSpace([string]$receipt.lean_toolchain) -or
        [string]::IsNullOrWhiteSpace([string]$receipt.lake_version)) {
        throw 'receipt values do not satisfy the v2 producer contract'
    }

    $receiptBytes = $script:Utf8Strict.GetBytes((ConvertTo-CanonicalJsonText -Value $receipt))
    $receiptSha256 = Get-Sha256FromBytes -Bytes $receiptBytes
    $receiptPath = Join-Path $provenanceOutput 'engine-build-receipt.json'
    Write-AtomicCreateOnly -DestinationPath $receiptPath -Bytes $receiptBytes
    Write-Output "SOURCE_MANIFEST files=$($sourceManifest.Rows.Length) sha256=$($sourceManifest.Sha256)"
    Write-Output "VECTOR_SOURCE selected=4 ignored=$($vectorInventory.IgnoredNames.Length) reason=previous actual outputs are not trusted and are recomputed; unrelated entries are not inputs"
    Write-Output "ENGINE_ARTIFACT bytes=$($artifactIdentity.SizeBytes) sha256=$($artifactIdentity.Sha256)"
    Write-Output "BUILD_RECEIPT schema=$($script:ReceiptSchema) fields=38 sha256=$receiptSha256 path=$receiptPath"
}

if ($PSCmdlet.ParameterSetName -eq 'Child') {
    try {
        $childCode = Invoke-GuardedChild
        exit [Int32]$childCode
    } catch {
        [Console]::Error.WriteLine("ENGINE_PRODUCER_CHILD_FAILURE=$($_.Exception.Message)")
        exit 1
    }
}

try {
    Invoke-ParentProducer
} catch {
    [Console]::Error.WriteLine("ENGINE_PRODUCER_FAILURE=$($_.Exception.Message)")
    exit 1
}
