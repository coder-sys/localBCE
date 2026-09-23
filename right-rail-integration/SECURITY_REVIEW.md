# RightRail Archive Security Review

## Current Finding

On September 20, 2026, the Phase 1 byte-verification pass attempted to read two
manifest paths containing the same preserved executable bytes. Microsoft
Defender blocked and quarantined both files as:

```text
Trojan:Win32/Wacatac.B!ml
Threat ID: 2147735505
Severity ID: 5
Category ID: 8
```

Defender reported `ActionSuccess=True`, `IsActive=False`, and
`DidThreatExecute=False`.

Affected manifest records:

```text
long/f04372.exe
w/r023/build-performance/q/Release/dm_pipeline_verifier_cli.exe
```

Both records declare:

```text
bytes: 240640
sha256: f4448247db02c074c721fbb857eb2dea32a7c24ffbdeb4427e2f318c6b3f0c48
```

The two paths are exact manifest duplicates of a preserved
`dm_pipeline_verifier_cli.exe` build artifact. They are not localBCE runtime
dependencies and were never executed by the integration process.

## Required Disposition

- Do not restore, allowlist, execute, or commit either binary.
- Do not execute other preserved RightRail binaries.
- Keep both entries classified as `unsafe_binary`; their current byte-integrity
  status is `missing` because quarantine removed them.
- Obtain a clean source-only replacement bundle or independent malware-analysis
  report before running any RightRail workspace.
- Rebuild required executable behavior from reviewed source in an isolated,
  network-restricted environment.
- Keep the full archive integrity gate failed until the replacement bytes are
  independently verified against an approved source manifest.

This finding does not establish that the corresponding source code is malicious,
but it prevents the archive from being treated as a trusted executable input.
