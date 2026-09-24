param(
  [Parameter(Mandatory = $true)][string]$UpstreamRoot,
  [Parameter(Mandatory = $true)][string]$PatchFile,
  [Parameter(Mandatory = $true)][string]$PatchedRoot
)

$ErrorActionPreference = 'Stop'
$expectedCommit = 'fe83ec6c4efa5f98bc2439c8b06e5eccd153aca0'
$expectedTree = '829f5dd115f3b5bdd77dc57c72293a5ccc3ca244'
$expectedRemote = 'https://github.com/google/longfellow-zk.git'

if (-not (Test-Path -LiteralPath $UpstreamRoot)) { throw "upstream root missing" }
if (-not (Test-Path -LiteralPath $PatchFile)) { throw "patch file missing" }
$remote = (& git -C $UpstreamRoot remote get-url origin).Trim()
if ($remote -ne $expectedRemote) { throw "unexpected upstream remote: $remote" }
$commit = (& git -C $UpstreamRoot rev-parse --verify HEAD).Trim()
if ($commit -ne $expectedCommit) { throw "unexpected upstream commit: $commit" }
$tree = (& git -C $UpstreamRoot rev-parse --verify 'HEAD^{tree}').Trim()
if ($tree -ne $expectedTree) { throw "unexpected upstream tree: $tree" }
$status = (& git -C $UpstreamRoot status --porcelain=v1 | Out-String).Trim()
if ($status) {
  throw "upstream clone is dirty"
}
if (Test-Path -LiteralPath $PatchedRoot) {
  throw "refusing to reuse existing patched source: $PatchedRoot"
}

$parent = Split-Path -Parent $PatchedRoot
New-Item -ItemType Directory -Force -Path $parent | Out-Null
& git -C $UpstreamRoot worktree add --detach $PatchedRoot $expectedCommit
if ($LASTEXITCODE -ne 0) { throw "git worktree add failed: $LASTEXITCODE" }
& git -C $PatchedRoot apply --unidiff-zero --whitespace=error $PatchFile
if ($LASTEXITCODE -ne 0) { throw "git apply failed: $LASTEXITCODE" }
Write-Output "PATCHED_SOURCE_READY commit=$expectedCommit tree_before=$expectedTree"
