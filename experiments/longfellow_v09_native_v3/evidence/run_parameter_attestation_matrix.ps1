param(
  [Parameter(Mandatory = $true)][string]$ProducerExe,
  [Parameter(Mandatory = $true)][string]$VerifierExe,
  [Parameter(Mandatory = $true)][string]$Root
)

$ErrorActionPreference = 'Stop'

function Copy-Bytes([byte[]]$Bytes) {
  $copy = New-Object byte[] $Bytes.Length
  [Array]::Copy($Bytes, $copy, $Bytes.Length)
  return ,$copy
}

function Put-U16([byte[]]$Bytes, [int]$Offset, [int]$Value) {
  $Bytes[$Offset] = [byte](($Value -shr 8) -band 0xff)
  $Bytes[$Offset + 1] = [byte]($Value -band 0xff)
}

function Put-U32([byte[]]$Bytes, [int]$Offset, [int]$Value) {
  $Bytes[$Offset] = [byte](($Value -shr 24) -band 0xff)
  $Bytes[$Offset + 1] = [byte](($Value -shr 16) -band 0xff)
  $Bytes[$Offset + 2] = [byte](($Value -shr 8) -band 0xff)
  $Bytes[$Offset + 3] = [byte]($Value -band 0xff)
}

function Get-Fields([byte[]]$Bytes) {
  $bodyEnd = $Bytes.Length - 64
  $offset = 16
  $fields = @()
  for ($index = 0; $index -lt 24; $index++) {
    $start = $offset
    $id = ($Bytes[$offset] -shl 8) -bor $Bytes[$offset + 1]
    $offset += 2
    $type = $Bytes[$offset]
    $offset += 1
    $length = ($Bytes[$offset] -shl 24) -bor
      ($Bytes[$offset + 1] -shl 16) -bor
      ($Bytes[$offset + 2] -shl 8) -bor $Bytes[$offset + 3]
    $offset += 4
    $payload = $offset
    $offset += $length
    $fields += [pscustomobject]@{
      Id = $id; TypeOffset = $payload - 5; LengthOffset = $payload - 4
      Payload = $payload; Length = $length; Start = $start; End = $offset
    }
  }
  if ($offset -ne $bodyEnd) { throw 'baseline field layout did not consume the record body' }
  return $fields
}

function Invoke-Verifier([string]$Path) {
  $preference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  $output = @(& $VerifierExe $Path 2>&1)
  $exit = $LASTEXITCODE
  $ErrorActionPreference = $preference
  return [pscustomobject]@{ Exit = $exit; Output = $output }
}

if (Test-Path -LiteralPath $Root) {
  if (@(Get-ChildItem -LiteralPath $Root -Force).Count -ne 0) {
    throw "matrix root exists and is nonempty: $Root"
  }
} else {
  New-Item -ItemType Directory -Path $Root | Out-Null
}

$baseline = Join-Path $Root 'baseline.bin'
$preference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$producerOutput = @(& $ProducerExe $baseline 2>&1)
$producerExit = $LASTEXITCODE
$ErrorActionPreference = $preference
$producerOutput | Write-Output
if ($producerExit -ne 0) { throw "producer failed with exit=$producerExit" }
$baselineBytes = [IO.File]::ReadAllBytes($baseline)
$baselineHash = (Get-FileHash -LiteralPath $baseline -Algorithm SHA256).Hash
$baselineResult = Invoke-Verifier $baseline
if ($baselineResult.Exit -ne 0) {
  $baselineResult.Output | Write-Output
  throw 'canonical verifier rejected the producer record'
}
$baselineResult.Output | Write-Output
Write-Output "PARAMETER_ATTESTATION_BASELINE bytes=$($baselineBytes.Length) sha256=$baselineHash"

$fields = Get-Fields $baselineBytes
$mutations = [ordered]@{}
$mutations['field_family_drift'] = {
  $b = Copy-Bytes $baselineBytes; $b[$fields[0].Payload] = $b[$fields[0].Payload] -bxor 1; $b
}
$mutations['field_type_drift'] = {
  $b = Copy-Bytes $baselineBytes; $b[$fields[0].TypeOffset] = 2; $b
}
$mutations['rate_drift'] = {
  $b = Copy-Bytes $baselineBytes; $b[$fields[3].Payload + 3] = 5; $b
}
$mutations['query_drift'] = {
  $b = Copy-Bytes $baselineBytes; $b[$fields[4].Payload + 3] = 190; $b
}
$mutations['transcript_version_drift'] = {
  $b = Copy-Bytes $baselineBytes; $b[$fields[6].Payload + 3] = 7; $b
}
$mutations['circuit_id_drift'] = {
  $b = Copy-Bytes $baselineBytes; $b[$fields[13].Payload] = $b[$fields[13].Payload] -bxor 1; $b
}
$mutations['dimension_drift'] = {
  $b = Copy-Bytes $baselineBytes; $b[$fields[14].Payload + 7] = $b[$fields[14].Payload + 7] -bxor 1; $b
}
$mutations['source_identity_drift'] = {
  $b = Copy-Bytes $baselineBytes; $b[$fields[23].Payload] = $b[$fields[23].Payload] -bxor 1; $b
}
$mutations['wrong_magic'] = {
  $b = Copy-Bytes $baselineBytes; $b[0] = $b[0] -bxor 1; $b
}
$mutations['wrong_version'] = {
  $b = Copy-Bytes $baselineBytes; $b[11] = 2; $b
}
$mutations['wrong_field_count'] = {
  $b = Copy-Bytes $baselineBytes; Put-U32 $b 12 23; $b
}
$mutations['unknown_field'] = {
  $b = Copy-Bytes $baselineBytes; Put-U16 $b $fields[0].Start 999; $b
}
$mutations['duplicate_field'] = {
  $b = Copy-Bytes $baselineBytes; Put-U16 $b $fields[1].Start 1; $b
}
$mutations['reordered_field'] = {
  $b = Copy-Bytes $baselineBytes; Put-U16 $b $fields[0].Start 2; $b
}
$mutations['identity_drift'] = {
  $b = Copy-Bytes $baselineBytes; $b[$b.Length - 1] = $b[$b.Length - 1] -bxor 1; $b
}
$mutations['truncated'] = {
  $b = New-Object byte[] ($baselineBytes.Length - 1); [Array]::Copy($baselineBytes, $b, $b.Length); $b
}
$mutations['trailing'] = {
  $b = New-Object byte[] ($baselineBytes.Length + 1); [Array]::Copy($baselineBytes, $b, $baselineBytes.Length); $b[$b.Length - 1] = 0; $b
}

$passed = 0
foreach ($entry in $mutations.GetEnumerator()) {
  $path = Join-Path $Root ("mutation-" + $entry.Key + '.bin')
  $bytes = & $entry.Value
  [IO.File]::WriteAllBytes($path, [byte[]]$bytes)
  $result = Invoke-Verifier $path
  if ($result.Exit -eq 0) {
    $result.Output | Write-Output
    throw "mutation was accepted: $($entry.Key)"
  }
  $decisive = @($result.Output | Where-Object { $_ -match 'PARAMETER_ATTESTATION_VERIFIER_REJECT' })
  if ($decisive.Count -eq 0) {
    $result.Output | Write-Output
    throw "mutation had no decisive verifier rejection: $($entry.Key)"
  }
  Write-Output ("PARAMETER_ATTESTATION_MUTATION_REJECT name={0} exit={1} {2}" -f
    $entry.Key, $result.Exit, ($decisive -join ' '))
  $passed++
}
Write-Output "PARAMETER_ATTESTATION_MATRIX_PASS cases=$passed total=$($mutations.Count) proof_invocations=0 state_mutations=0"
