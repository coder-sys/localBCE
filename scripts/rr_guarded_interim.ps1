<#
INTERIM STAND-IN for RightRail's guarded wrapper. NOT `C:/Users/neers/rrb/tools/rr_guarded.ps1` (v7).

RightRail CONST X.2 says heavy runs (builds, tests, provers) on a laptop go only through that wrapper,
under limits named in a driver-root AGENTS.md that is not in this repository. Neither exists on this
machine. On 2026-11-08 the project owner approved writing this stand-in (overriding
RIGHTRAIL_BASE_PLAN.md section 7 decision 1). Its limits are this repository's own, not the real
guard's: every run it logs says so. Replace it with the real wrapper as soon as that is available.

Interface (matching the calls in rightrail/tools/tcb_pin.ps1 and its docs):
  -Worktree DIR   directory the command runs in
  -Suffix NAME    run label, used in the log file name
  -MinFree BYTES  refuse to start unless at least this much physical memory is free
  -Modules M...   run `python -m unittest M...` in DIR, or
  -Exe PATH -ArgList A...   run PATH with arguments
Limits enforced:
  - a Windows job object holds the whole process tree; it is killed when the guard exits, and its
    total committed memory is capped at -JobMemoryMB (default 6144)
  - a watchdog kills the tree if free physical memory falls below -KillBelowMB (default 1024)
  - a wall-clock timeout, -TimeoutMinutes (default 60)
  - the child runs at BelowNormal priority
Exit code: the command's own, or 90 refused (memory floor), 91 killed (memory watchdog),
92 killed (timeout), 93 guard error. Log: %LOCALAPPDATA%\rr_guarded_interim\logs\<time>-<suffix>.log
#>
[CmdletBinding(DefaultParameterSetName = 'Modules')]
param(
    [Parameter(Mandatory = $true)][string]$Worktree,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9._-]{1,80}$')][string]$Suffix,
    [Parameter(Mandatory = $true)][UInt64]$MinFree,
    [Parameter(Mandatory = $true, ParameterSetName = 'Modules')][string[]]$Modules,
    [Parameter(ParameterSetName = 'Modules')][string]$Python = 'python',
    [Parameter(Mandatory = $true, ParameterSetName = 'Exe')][string]$Exe,
    [Parameter(ParameterSetName = 'Exe')][string[]]$ArgList = @(),
    [ValidateRange(256, 65536)][int]$JobMemoryMB = 6144,
    [ValidateRange(256, 16384)][int]$KillBelowMB = 1024,
    [ValidateRange(1, 1440)][int]$TimeoutMinutes = 60
)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class RrGuardInterim {
    [StructLayout(LayoutKind.Sequential)]
    struct MEMORYSTATUSEX { public uint dwLength, dwMemoryLoad; public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile,
        ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);

    [StructLayout(LayoutKind.Sequential)]
    struct BASIC { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit;
        public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)]
    struct IOC { public ulong a, b, c, d, e, f; }
    [StructLayout(LayoutKind.Sequential)]
    struct EXTENDED { public BASIC Basic; public IOC Io; public UIntPtr ProcessMemoryLimit, JobMemoryLimit,
        PeakProcessMemoryUsed, PeakJobMemoryUsed; }
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr a, string n);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr j, int c, ref EXTENDED i, uint l);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool QueryInformationJobObject(IntPtr j, int c, ref EXTENDED i, uint l, IntPtr r);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr j, IntPtr p);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateJobObject(IntPtr j, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);

    public static ulong FreePhysical() {
        var m = new MEMORYSTATUSEX(); m.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
        if (!GlobalMemoryStatusEx(ref m)) throw new InvalidOperationException("GlobalMemoryStatusEx failed");
        return m.ullAvailPhys;
    }

    public static int Run(string file, string args, string dir, string logPath, ulong jobBytes, ulong killBelow,
                          int timeoutMs, StringBuilder note) {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new InvalidOperationException("CreateJobObject failed");
        var info = new EXTENDED();
        // KILL_ON_JOB_CLOSE | JOB_MEMORY | DIE_ON_UNHANDLED_EXCEPTION
        info.Basic.LimitFlags = 0x2000 | 0x200 | 0x400;
        info.JobMemoryLimit = new UIntPtr(jobBytes);
        if (!SetInformationJobObject(job, 9, ref info, (uint)Marshal.SizeOf(typeof(EXTENDED))))
            throw new InvalidOperationException("SetInformationJobObject failed: " + Marshal.GetLastWin32Error());
        using (var log = new StreamWriter(logPath, true, new UTF8Encoding(false))) {
            log.AutoFlush = true;
            var gate = new object();
            var psi = new ProcessStartInfo(file, args) { WorkingDirectory = dir, UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            var p = new Process { StartInfo = psi };
            p.OutputDataReceived += (s, e) => { if (e.Data != null) lock (gate) log.WriteLine(e.Data); };
            p.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (gate) log.WriteLine(e.Data); };
            p.Start();
            if (!AssignProcessToJobObject(job, p.Handle)) {
                try { p.Kill(); } catch { }
                throw new InvalidOperationException("AssignProcessToJobObject failed: " + Marshal.GetLastWin32Error());
            }
            try { p.PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }
            p.BeginOutputReadLine(); p.BeginErrorReadLine();
            var sw = Stopwatch.StartNew();
            int code = -1;
            while (true) {
                if (p.WaitForExit(1000)) { p.WaitForExit(); code = p.ExitCode; break; }
                if (FreePhysical() < killBelow) { TerminateJobObject(job, 91); p.WaitForExit(); code = 91;
                    note.Append("killed: free physical memory fell below the watchdog floor"); break; }
                if (sw.ElapsedMilliseconds > timeoutMs) { TerminateJobObject(job, 92); p.WaitForExit(); code = 92;
                    note.Append("killed: timeout"); break; }
            }
            if (QueryInformationJobObject(job, 9, ref info, (uint)Marshal.SizeOf(typeof(EXTENDED)), IntPtr.Zero))
                note.Append((note.Length > 0 ? "; " : "") + "peak job memory MB " + (info.PeakJobMemoryUsed.ToUInt64() / 1048576));
            TerminateJobObject(job, 0);   // nothing outlives the guard
            CloseHandle(job);
            return code;
        }
    }
}
'@

function Join-Args([string[]]$items) {
    ($items | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '(\\*)"', '$1$1\"') + '"' } else { $_ } }) -join ' '
}

$logDir = Join-Path $env:LOCALAPPDATA 'rr_guarded_interim\logs'
New-Item -ItemType Directory -Force $logDir | Out-Null
$log = Join-Path $logDir ("{0}-{1}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $Suffix)
$work = (Resolve-Path -LiteralPath $Worktree).Path
if ($PSCmdlet.ParameterSetName -eq 'Modules') { $file = $Python; $argLine = Join-Args (@('-m', 'unittest') + $Modules) }
else { $file = $Exe; $argLine = Join-Args $ArgList }

$free = [RrGuardInterim]::FreePhysical()
$header = @(
    "rr_guarded_interim: INTERIM STAND-IN, not RightRail's rr_guarded.ps1 (v7); limits are this repository's own.",
    "run: $Suffix in $work",
    "command: $file $argLine",
    ("limits: MinFree={0} JobMemoryMB={1} KillBelowMB={2} TimeoutMinutes={3}; free at start={4}" -f $MinFree, $JobMemoryMB, $KillBelowMB, $TimeoutMinutes, $free)
)
[IO.File]::WriteAllLines($log, $header, (New-Object Text.UTF8Encoding $false))
$header | ForEach-Object { Write-Host $_ }
if ($free -lt $MinFree) {
    $msg = "REFUSED: free physical memory $free < MinFree $MinFree"
    Add-Content -LiteralPath $log -Value $msg -Encoding UTF8
    Write-Host $msg
    Write-Host "log: $log"
    exit 90
}
$note = New-Object Text.StringBuilder
try {
    $code = [RrGuardInterim]::Run($file, $argLine, $work, $log, [UInt64]$JobMemoryMB * 1MB, [UInt64]$KillBelowMB * 1MB,
                                  $TimeoutMinutes * 60000, $note)
} catch {
    $code = 93
    [void]$note.Append("guard error: $($_.Exception.Message)")
}
$summary = "exit $code" + $(if ($note.Length) { " ($note)" } else { '' })
Add-Content -LiteralPath $log -Value $summary -Encoding UTF8
Write-Host $summary
Write-Host "log: $log"
exit $code
