<#
  RightRail one-command guarded runner.

  Usage: powershell -NoProfile -ExecutionPolicy Bypass -File native\guard\run.ps1 -Suite <name> [-WaitSeconds 1800]

  Agents pass only a suite name; program, args, env, cwd, class, floors, timeout
  and failure patterns come from native\guard\suites.json. Pinned artifacts come
  from native\guard\pins.json. Every invocation creates work\runs\<run_id>\ and
  appends exactly one line to work\runs\results.jsonl.

  Hard floors (never lowered here): physical-free floor 2,190,433,321 bytes and
  nominal reserve 3,221,225,472 bytes, identical to run_guarded_v4.ps1.

  Exit codes: 0 PASS, 1 FAIL, 2 GUARD_STOP, 3 HARNESS_ERROR or INVALID.
#>
param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')]
  [string]$Suite,
  [ValidateRange(0, 86400)]
  [int]$WaitSeconds = 1800
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# ---------------------------------------------------------------- constants
$SchemaResults = 'rightrail-guard-run/v1'
$SchemaSuites = 'rightrail-guard-suites/v1'
$NominalReserveBytes = [uint64]3221225472
$PhysicalFloorBytes = [uint64]2190433321
if ([uint64][Math]::Ceiling([double]$NominalReserveBytes * 68 / 100) -ne $PhysicalFloorBytes) {
  Write-Output 'HARNESS_ERROR floor constant does not equal ceil(0.68 * nominal reserve)'
  exit 3
}
$PollMilliseconds = 250
$MutexName = 'Local\BlindLedgerDirectMaskBuild20260907'
$ResultsMutexName = 'Local\RightRailGuardResultsJsonl'
$GuardPath = $PSCommandPath
$GuardDir = Split-Path -Parent $GuardPath
$Trunk = (Resolve-Path -LiteralPath (Join-Path $GuardDir '..\..')).Path
$SuitesPath = Join-Path $GuardDir 'suites.json'
$PinsPath = Join-Path $GuardDir 'pins.json'
$RunsRoot = Join-Path $Trunk 'work\runs'
$ResultsPath = Join-Path $RunsRoot 'results.jsonl'
$SystemDir = [Environment]::SystemDirectory
$CmdExe = Join-Path $SystemDir 'cmd.exe'

# ---------------------------------------------------------------- native layer
$native = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public sealed class RightRailGuardLaunch
{
  public IntPtr Job;
  public IntPtr Process;
  public int Pid;
}

public static class RightRailGuardNative
{
  [StructLayout(LayoutKind.Sequential)]
  private struct MEMORYSTATUSEX
  {
    public uint dwLength; public uint dwMemoryLoad; public ulong ullTotalPhys; public ulong ullAvailPhys;
    public ulong ullTotalPageFile; public ulong ullAvailPageFile; public ulong ullTotalVirtual;
    public ulong ullAvailVirtual; public ulong ullAvailExtendedVirtual;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
  {
    public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags;
    public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit;
    public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct IO_COUNTERS
  {
    public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount;
    public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
  {
    public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo;
    public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit;
    public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
  {
    public long TotalUserTime; public long TotalKernelTime; public long ThisPeriodTotalUserTime;
    public long ThisPeriodTotalKernelTime; public uint TotalPageFaultCount; public uint TotalProcesses;
    public uint ActiveProcesses; public uint TotalTerminatedProcesses;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct STARTUPINFO
  {
    public int cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle;
    public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars;
    public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow;
    public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput;
    public IntPtr hStdError;
  }

  [StructLayout(LayoutKind.Sequential)]
  private struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }

  [StructLayout(LayoutKind.Sequential)]
  private struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

  [StructLayout(LayoutKind.Sequential)]
  private struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public int bInheritHandle; }

  private const int JobObjectBasicAccountingInformation = 1;
  private const int JobObjectExtendedLimitInformation = 9;
  private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
  private const uint CREATE_SUSPENDED = 0x00000004;
  private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
  private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
  private const uint CREATE_NO_WINDOW = 0x08000000;
  private const int STARTF_USESTDHANDLES = 0x00000100;
  private const uint GENERIC_READ = 0x80000000;
  private const uint GENERIC_WRITE = 0x40000000;
  private const uint FILE_SHARE_READ = 0x1;
  private const uint FILE_SHARE_WRITE = 0x2;
  private const uint CREATE_NEW = 1;
  private const uint OPEN_EXISTING = 3;
  private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
  private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = new IntPtr(0x00020002);
  private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
  private const uint WAIT_OBJECT_0 = 0;
  private const uint WAIT_TIMEOUT = 0x102;

  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool SetInformationJobObject(IntPtr hJob, int cls, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint len);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool QueryInformationJobObject(IntPtr hJob, int cls, out JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint len, IntPtr ret);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool QueryInformationJobObject(IntPtr hJob, int cls, out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info, uint len, IntPtr ret);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta,
    [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, IntPtr env, string cwd,
    ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern uint ResumeThread(IntPtr hThread);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool TerminateProcess(IntPtr hProcess, uint code);
  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetExitCodeProcess(IntPtr h, out uint code);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  private static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES sa,
    uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr, IntPtr value,
    IntPtr size, IntPtr prev, IntPtr retSize);
  [DllImport("kernel32.dll", SetLastError = true)]
  private static extern void DeleteProcThreadAttributeList(IntPtr list);
  [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool result);
  [DllImport("kernel32.dll")]
  private static extern IntPtr GetCurrentProcess();

  private static Win32Exception Fail(string stage)
  {
    int error = Marshal.GetLastWin32Error();
    return new Win32Exception(error, stage + " failed (Win32 error " + error + ")");
  }

  public static ulong AvailablePhysicalBytes()
  {
    MEMORYSTATUSEX s = new MEMORYSTATUSEX();
    s.dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX));
    if (!GlobalMemoryStatusEx(ref s)) { throw Fail("GlobalMemoryStatusEx"); }
    return s.ullAvailPhys;
  }

  public static bool CurrentProcessInJob()
  {
    bool inJob;
    if (!IsProcessInJob(GetCurrentProcess(), IntPtr.Zero, out inJob)) { throw Fail("IsProcessInJob"); }
    return inJob;
  }

  private static IntPtr OpenInheritable(string path, bool write, bool createNew)
  {
    SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
    sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
    sa.bInheritHandle = 1;
    IntPtr h = CreateFileW(path, write ? GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
      ref sa, createNew ? CREATE_NEW : OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
    if (h == INVALID_HANDLE_VALUE) { throw Fail("CreateFileW(" + path + ")"); }
    return h;
  }

  // stdoutPath/stderrPath null => NUL device; otherwise created with CREATE_NEW (never overwrites).
  public static RightRailGuardLaunch Launch(string app, string commandLine, string cwd, string envBlock,
    string stdoutPath, string stderrPath)
  {
    IntPtr job = IntPtr.Zero, hIn = IntPtr.Zero, hOut = IntPtr.Zero, hErr = IntPtr.Zero;
    IntPtr attrList = IntPtr.Zero, handleArray = IntPtr.Zero, env = IntPtr.Zero;
    bool attrInit = false;
    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
    bool created = false;
    try
    {
      job = CreateJobObjectW(IntPtr.Zero, null);
      if (job == IntPtr.Zero) { throw Fail("CreateJobObjectW"); }
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
      limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits,
          (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
      { throw Fail("SetInformationJobObject(KILL_ON_JOB_CLOSE)"); }

      hIn = OpenInheritable("NUL", false, false);
      hOut = stdoutPath == null ? OpenInheritable("NUL", true, false) : OpenInheritable(stdoutPath, true, true);
      hErr = stderrPath == null ? OpenInheritable("NUL", true, false) : OpenInheritable(stderrPath, true, true);

      IntPtr size = IntPtr.Zero;
      InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
      attrList = Marshal.AllocHGlobal(size);
      if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref size)) { throw Fail("InitializeProcThreadAttributeList"); }
      attrInit = true;
      handleArray = Marshal.AllocHGlobal(IntPtr.Size * 3);
      Marshal.WriteIntPtr(handleArray, 0, hIn);
      Marshal.WriteIntPtr(handleArray, IntPtr.Size, hOut);
      Marshal.WriteIntPtr(handleArray, IntPtr.Size * 2, hErr);
      if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handleArray,
          new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero))
      { throw Fail("UpdateProcThreadAttribute(HANDLE_LIST)"); }

      STARTUPINFOEX si = new STARTUPINFOEX();
      si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
      si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
      si.StartupInfo.hStdInput = hIn;
      si.StartupInfo.hStdOutput = hOut;
      si.StartupInfo.hStdError = hErr;
      si.lpAttributeList = attrList;

      env = Marshal.StringToHGlobalUni(envBlock);
      StringBuilder cmd = new StringBuilder(commandLine);
      uint flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW;
      if (!CreateProcessW(app, cmd, IntPtr.Zero, IntPtr.Zero, true, flags, env, cwd, ref si, out pi))
      { throw Fail("CreateProcessW(suspended)"); }
      created = true;

      if (!AssignProcessToJobObject(job, pi.hProcess))
      {
        int error = Marshal.GetLastWin32Error();
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        throw new Win32Exception(error, "AssignProcessToJobObject failed (Win32 error " + error +
          "); nested job assignment refused; suspended child terminated; refusing to run unguarded");
      }
      if (ResumeThread(pi.hThread) == 0xFFFFFFFF)
      {
        int error = Marshal.GetLastWin32Error();
        TerminateJobObject(job, 1);
        throw new Win32Exception(error, "ResumeThread failed (Win32 error " + error + ")");
      }
      CloseHandle(pi.hThread);
      pi.hThread = IntPtr.Zero;

      RightRailGuardLaunch result = new RightRailGuardLaunch();
      result.Job = job; result.Process = pi.hProcess; result.Pid = pi.dwProcessId;
      job = IntPtr.Zero; pi.hProcess = IntPtr.Zero;
      return result;
    }
    finally
    {
      if (hIn != IntPtr.Zero && hIn != INVALID_HANDLE_VALUE) { CloseHandle(hIn); }
      if (hOut != IntPtr.Zero && hOut != INVALID_HANDLE_VALUE) { CloseHandle(hOut); }
      if (hErr != IntPtr.Zero && hErr != INVALID_HANDLE_VALUE) { CloseHandle(hErr); }
      if (attrInit) { DeleteProcThreadAttributeList(attrList); }
      if (attrList != IntPtr.Zero) { Marshal.FreeHGlobal(attrList); }
      if (handleArray != IntPtr.Zero) { Marshal.FreeHGlobal(handleArray); }
      if (env != IntPtr.Zero) { Marshal.FreeHGlobal(env); }
      if (created && pi.hThread != IntPtr.Zero) { CloseHandle(pi.hThread); }
      if (created && pi.hProcess != IntPtr.Zero) { CloseHandle(pi.hProcess); }
      if (job != IntPtr.Zero) { CloseHandle(job); }
    }
  }

  public static bool WaitExited(IntPtr process, uint ms)
  {
    uint r = WaitForSingleObject(process, ms);
    if (r == WAIT_OBJECT_0) { return true; }
    if (r == WAIT_TIMEOUT) { return false; }
    throw Fail("WaitForSingleObject");
  }

  public static uint ActiveProcesses(IntPtr job)
  {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a;
    if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, out a,
        (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), IntPtr.Zero))
    { throw Fail("QueryInformationJobObject(BasicAccounting)"); }
    return a.ActiveProcesses;
  }

  public static uint TotalProcesses(IntPtr job)
  {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION a;
    if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, out a,
        (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), IntPtr.Zero))
    { throw Fail("QueryInformationJobObject(BasicAccounting)"); }
    return a.TotalProcesses;
  }

  public static ulong PeakJobMemoryUsed(IntPtr job)
  {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION x;
    if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation, out x,
        (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)), IntPtr.Zero))
    { throw Fail("QueryInformationJobObject(ExtendedLimit)"); }
    return x.PeakJobMemoryUsed.ToUInt64();
  }

  public static void Terminate(IntPtr job, uint code)
  {
    if (!TerminateJobObject(job, code)) { throw Fail("TerminateJobObject"); }
  }

  public static long ExitCode(IntPtr process)
  {
    uint code;
    if (!GetExitCodeProcess(process, out code)) { throw Fail("GetExitCodeProcess"); }
    if (code == 259) { return -1; }
    return (long)code;
  }

  public static void Close(IntPtr h)
  {
    if (h != IntPtr.Zero && !CloseHandle(h)) { throw Fail("CloseHandle"); }
  }
}
'@

# ---------------------------------------------------------------- run state
$script:GuardLines = New-Object System.Collections.Generic.List[string]
$script:GuardLog = $null
$R = [ordered]@{
  schema = $SchemaResults
  run_id = $null
  suite = $Suite
  suite_sha256 = $null
  guard_sha256 = $null
  head = $null
  tree = $null
  status_digest_pre = $null
  status_digest_post = $null
  pins_ok = $null
  free_start = $null
  min_free = $null
  floor = $PhysicalFloorBytes
  start_floor = $null
  nominal_reserve = $NominalReserveBytes
  peak_job_bytes = $null
  selftest = [ordered]@{ status = 'NOT_RUN'; exit7 = $null; exit0 = $null }
  child_exit = $null
  cleanup = 'NOT_LAUNCHED'
  mutex = 'NOT_ATTEMPTED'
  verdict = $null
  reason = $null
  started_utc = $null
  ended_utc = $null
  log_sha256s = [ordered]@{}
}
$script:Verdict = $null
$script:Reason = $null
$script:CleanupFailed = $false
$script:AnyTerminated = $false
$script:Launched = $false
$script:GitExe = $null
[uint64]$script:MinFree = [uint64]::MaxValue

function Write-Guard([string]$Line) {
  [Console]::Out.WriteLine($Line)
  if ($null -ne $script:GuardLog) { $script:GuardLog.WriteLine($Line); $script:GuardLog.Flush() }
  else { $script:GuardLines.Add($Line) }
}

function Set-Verdict([string]$Verdict, [string]$Reason) {
  # Precedence: HARNESS_ERROR > INVALID > GUARD_STOP > FAIL > PASS. First reason at the top rank wins.
  $rank = @{ 'PASS' = 0; 'FAIL' = 1; 'GUARD_STOP' = 2; 'INVALID' = 3; 'HARNESS_ERROR' = 4 }
  if ($null -eq $script:Verdict -or $rank[$Verdict] -gt $rank[$script:Verdict]) {
    $script:Verdict = $Verdict
    $script:Reason = $Reason
  }
  Write-Guard ("VERDICT_EVENT verdict={0} reason={1}" -f $Verdict, $Reason)
}

function Get-FileSha256([string]$Path) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try { return ([BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '') } finally { $fs.Dispose() }
  } finally { $sha.Dispose() }
}

function Get-BytesSha256([byte[]]$Bytes) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') } finally { $sha.Dispose() }
}

function Resolve-RepoPath([string]$Relative, [string]$What) {
  if ([string]::IsNullOrEmpty($Relative) -or [System.IO.Path]::IsPathRooted($Relative)) {
    throw "$What must be a non-empty repo-relative path: '$Relative'"
  }
  foreach ($segment in ($Relative -split '[\\/]')) {
    if ($segment -eq '..') { throw "$What must not contain '..': '$Relative'" }
  }
  $full = [System.IO.Path]::GetFullPath((Join-Path $Trunk $Relative))
  if (-not ($full + '\').StartsWith($Trunk.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "$What escapes the trunk: '$Relative'"
  }
  return $full
}

function Resolve-Program([string]$Program) {
  if ([System.IO.Path]::IsPathRooted($Program)) { $path = $Program }
  elseif ($Program -match '^[A-Za-z0-9_.-]+\.exe$') { $path = Join-Path $SystemDir $Program }
  else { throw "program must be an absolute path or a bare System32 .exe name: '$Program'" }
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "program not found: $path" }
  return $path
}

function ConvertTo-ArgvToken([string]$Arg) {
  if ($Arg.Length -gt 0 -and $Arg -notmatch '[\s"]') { return $Arg }
  $sb = New-Object System.Text.StringBuilder
  [void]$sb.Append('"')
  $backslashes = 0
  foreach ($ch in $Arg.ToCharArray()) {
    if ($ch -eq '\') { $backslashes++; continue }
    if ($ch -eq '"') { [void]$sb.Append('\' * (2 * $backslashes + 1)); [void]$sb.Append('"') }
    else { [void]$sb.Append('\' * $backslashes); [void]$sb.Append($ch) }
    $backslashes = 0
  }
  [void]$sb.Append('\' * (2 * $backslashes))
  [void]$sb.Append('"')
  return $sb.ToString()
}

function New-EnvironmentBlock($Overrides) {
  $map = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
  $current = [Environment]::GetEnvironmentVariables()
  foreach ($key in $current.Keys) { $map[[string]$key] = [string]$current[$key] }
  foreach ($key in $Overrides.Keys) { $map[$key] = $Overrides[$key] }
  $sb = New-Object System.Text.StringBuilder
  foreach ($pair in $map.GetEnumerator()) { [void]$sb.Append($pair.Key).Append('=').Append($pair.Value).Append([char]0) }
  [void]$sb.Append([char]0)
  return $sb.ToString()
}

function Get-FreeBytes {
  [uint64]$free = [RightRailGuardNative]::AvailablePhysicalBytes()
  if ($free -lt $script:MinFree) { $script:MinFree = $free }
  return $free
}

function Test-StartFloor([string]$Stage, [uint64]$StartFloor) {
  $free = Get-FreeBytes
  $R.free_start = $free
  Write-Guard ("PHYSICAL_CHECK stage={0} api=GlobalMemoryStatusEx.ullAvailPhys free_bytes={1} floor_bytes={2} effective_start_floor_bytes={3} nominal_reserve_bytes={4}" -f `
    $Stage, $free, $PhysicalFloorBytes, $StartFloor, $NominalReserveBytes)
  if ($free -lt $StartFloor) {
    Set-Verdict 'GUARD_STOP' ("free physical memory {0} below effective start floor {1} at {2}; nothing launched" -f $free, $StartFloor, $Stage)
    return $false
  }
  return $true
}

function Invoke-Git([string[]]$GitArgs) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $script:GitExe
  $psi.Arguments = [string]::Join(' ', @($GitArgs | ForEach-Object { ConvertTo-ArgvToken $_ }))
  $psi.WorkingDirectory = $Trunk
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  try {
    $ms = New-Object System.IO.MemoryStream
    $errTask = $p.StandardError.ReadToEndAsync()
    $p.StandardOutput.BaseStream.CopyTo($ms)
    if (-not $p.WaitForExit(120000)) { $p.Kill(); throw "git $($GitArgs -join ' ') timed out" }
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "git $($GitArgs -join ' ') exited $($p.ExitCode): $($errTask.Result.Trim())" }
    return ,$ms.ToArray()
  } finally { $p.Dispose() }
}

function Get-GitIdentity {
  $head = [Text.Encoding]::ASCII.GetString((Invoke-Git @('rev-parse', 'HEAD'))).Trim()
  $tree = [Text.Encoding]::ASCII.GetString((Invoke-Git @('rev-parse', 'HEAD^{tree}'))).Trim()
  $status = Get-BytesSha256 (Invoke-Git @('--no-optional-locks', 'status', '--porcelain'))
  return [ordered]@{ head = $head; tree = $tree; status = $status }
}

function Get-FileIdentity($Pins) {
  $id = [ordered]@{ guard = (Get-FileSha256 $GuardPath); suites = (Get-FileSha256 $SuitesPath); pins_file = (Get-FileSha256 $PinsPath); pins_ok = $true; pins = @() }
  foreach ($pin in $Pins) {
    $full = Resolve-RepoPath $pin.path 'pin path'
    if (Test-Path -LiteralPath $full -PathType Leaf) { $actual = Get-FileSha256 $full } else { $actual = 'MISSING' }
    $ok = ($actual -eq $pin.sha256.ToUpperInvariant())
    if (-not $ok) { $id.pins_ok = $false }
    $id.pins += ("{0}={1}:{2}" -f $pin.path, $actual, $(if ($ok) { 'OK' } else { 'MISMATCH expected ' + $pin.sha256 }))
  }
  return $id
}

function Read-Json([string]$Path) {
  $text = [System.IO.File]::ReadAllText($Path, (New-Object System.Text.UTF8Encoding($false, $true)))
  return ($text | ConvertFrom-Json)
}

function Test-Integer($Value) { return ($Value -is [int] -or $Value -is [long]) }

function Get-Suite([string]$Name) {
  $doc = Read-Json $SuitesPath
  if ($doc.schema -ne $SchemaSuites) { throw "suites.json schema must be '$SchemaSuites'" }
  $entry = $doc.suites.PSObject.Properties[$Name]
  if ($null -eq $entry) { throw "unknown suite '$Name'" }
  $s = $entry.Value
  $allowed = @('class', 'cwd', 'program', 'args', 'env', 'start_floor_bytes', 'timeout_seconds', 'failure_patterns', 'note')
  foreach ($p in $s.PSObject.Properties) { if ($allowed -notcontains $p.Name) { throw "suite '$Name' has unknown key '$($p.Name)'" } }
  foreach ($k in @('class', 'cwd', 'program', 'args', 'env', 'start_floor_bytes', 'timeout_seconds')) {
    if ($null -eq $s.PSObject.Properties[$k]) { throw "suite '$Name' missing key '$k'" }
  }
  if (@('heavy', 'light') -notcontains $s.class) { throw "suite '$Name' class must be heavy|light" }
  if (-not (Test-Integer $s.start_floor_bytes) -or $s.start_floor_bytes -lt 0) { throw "suite '$Name' start_floor_bytes must be a non-negative integer" }
  if (-not (Test-Integer $s.timeout_seconds) -or $s.timeout_seconds -lt 1 -or $s.timeout_seconds -gt 86400) { throw "suite '$Name' timeout_seconds must be 1..86400" }
  $argsList = @()
  foreach ($a in @($s.args)) { if ($a -isnot [string]) { throw "suite '$Name' args must be strings" }; $argsList += $a }
  $envMap = [ordered]@{}
  foreach ($p in $s.env.PSObject.Properties) {
    if ($p.Name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or $p.Value -isnot [string] -or $p.Value.Contains([string][char]0)) { throw "suite '$Name' env entry '$($p.Name)' invalid" }
    $envMap[$p.Name] = $p.Value
  }
  $patterns = @()
  if ($null -ne $s.PSObject.Properties['failure_patterns']) {
    foreach ($pat in @($s.failure_patterns)) {
      if ($pat -isnot [string]) { throw "suite '$Name' failure_patterns must be strings" }
      [void][regex]::new($pat)
      $patterns += $pat
    }
  }
  return [ordered]@{
    class = [string]$s.class; cwd = (Resolve-RepoPath $s.cwd 'suite cwd'); program = (Resolve-Program $s.program)
    args = $argsList; env = $envMap; start_floor = [uint64]$s.start_floor_bytes; timeout = [int]$s.timeout_seconds; patterns = $patterns
  }
}

function Get-Pins {
  $pins = @(Read-Json $PinsPath)
  foreach ($pin in $pins) {
    if ($null -eq $pin.PSObject.Properties['path'] -or $null -eq $pin.PSObject.Properties['sha256'] -or
        $pin.sha256 -notmatch '^[0-9A-Fa-f]{64}$') { throw 'pins.json entries must be {path, sha256}' }
  }
  return $pins
}

# One launch inside a fresh Job Object. Returns an ordered result; never throws.
function Invoke-InJob([string]$Label, [string]$Program, [string[]]$ArgList, [string]$Cwd, [string]$EnvBlock,
                      [string]$StdoutPath, [string]$StderrPath, [int]$TimeoutSeconds) {
  $res = [ordered]@{ label = $Label; exit = $null; stop = $null; harness = $null; cleanup = $null; peak = $null; samples = 0; total_processes = $null }
  $cmdLine = (ConvertTo-ArgvToken $Program)
  foreach ($a in $ArgList) { $cmdLine += ' ' + (ConvertTo-ArgvToken $a) }
  $launch = $null
  try {
    $launch = [RightRailGuardNative]::Launch($Program, $cmdLine, $Cwd, $EnvBlock, $StdoutPath, $StderrPath)
  } catch {
    $e = $_.Exception; while ($null -ne $e.InnerException) { $e = $e.InnerException }
    $res.harness = "launch: $($e.Message)"
    $res.cleanup = 'NOT_LAUNCHED'
    Write-Guard ("LAUNCH_FAILED label={0} reason={1}" -f $Label, $res.harness)
    return $res
  }
  $script:Launched = $true
  Write-Guard ("LAUNCH label={0} pid={1} job=KILL_ON_JOB_CLOSE program={2} cwd={3}" -f $Label, $launch.Pid, $Program, $Cwd)
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $exited = $false
  try {
    while ($true) {
      $free = Get-FreeBytes
      $res.samples++
      if (($res.samples % 40) -eq 1) {
        Write-Guard ("LIVE_SAMPLE label={0} index={1} free_bytes={2} active_processes={3}" -f $Label, $res.samples, $free, [RightRailGuardNative]::ActiveProcesses($launch.Job))
      }
      if ($free -lt $PhysicalFloorBytes) { $res.stop = "free physical memory $free below floor $PhysicalFloorBytes"; break }
      if ($sw.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $res.stop = "timeout after $TimeoutSeconds s"; break }
      if ([RightRailGuardNative]::WaitExited($launch.Process, $PollMilliseconds)) { $exited = $true; break }
    }
  } catch {
    $res.harness = "monitor: $($_.Exception.Message)"
  } finally {
    $terminated = $false
    try {
      if ($null -ne $res.stop -or $null -ne $res.harness) {
        Write-Guard ("GUARD_STOP label={0} reason={1}" -f $Label, $(if ($null -ne $res.stop) { $res.stop } else { $res.harness }))
        [RightRailGuardNative]::Terminate($launch.Job, [uint32]900); $terminated = $true
      } else {
        for ($i = 0; $i -lt 20 -and [RightRailGuardNative]::ActiveProcesses($launch.Job) -ne 0; $i++) { Start-Sleep -Milliseconds $PollMilliseconds }
        $left = [RightRailGuardNative]::ActiveProcesses($launch.Job)
        if ($left -ne 0) {
          Write-Guard ("LEFTOVER_PROCESSES label={0} active={1} action=TerminateJobObject" -f $Label, $left)
          [RightRailGuardNative]::Terminate($launch.Job, [uint32]901); $terminated = $true
        }
      }
      for ($i = 0; $i -lt 40 -and [RightRailGuardNative]::ActiveProcesses($launch.Job) -ne 0; $i++) { Start-Sleep -Milliseconds $PollMilliseconds }
      $active = [RightRailGuardNative]::ActiveProcesses($launch.Job)
      $res.peak = [RightRailGuardNative]::PeakJobMemoryUsed($launch.Job)
      $res.total_processes = [RightRailGuardNative]::TotalProcesses($launch.Job)
      if ([RightRailGuardNative]::WaitExited($launch.Process, 5000)) {
        $code = [RightRailGuardNative]::ExitCode($launch.Process)
        if ($code -ge 0) { $res.exit = $code }
      }
      if ($active -eq 0) { $res.cleanup = $(if ($terminated) { 'PASS_TERMINATED' } else { 'PASS' }) }
      else { $res.cleanup = "FAIL active_processes=$active" }
    } catch {
      $res.cleanup = "FAIL $($_.Exception.Message)"
    }
    try { [RightRailGuardNative]::Close($launch.Process) } catch { $res.cleanup = "FAIL close process: $($_.Exception.Message)" }
    try { [RightRailGuardNative]::Close($launch.Job) } catch { $res.cleanup = "FAIL close job: $($_.Exception.Message)" }
    if ($terminated) { $script:AnyTerminated = $true }
    if ($res.cleanup -like 'FAIL*') { $script:CleanupFailed = $true }
    Write-Guard ("JOB_RESULT label={0} exit={1} samples={2} peak_job_bytes={3} total_processes={4} cleanup={5} elapsed_ms={6}" -f `
      $Label, $res.exit, $res.samples, $res.peak, $res.total_processes, $res.cleanup, $sw.ElapsedMilliseconds)
  }
  return $res
}

# ---------------------------------------------------------------- main
$mutex = $null
$mutexHeld = $false
$pins = @()
$suiteDef = $null
$exitCode = 3
try {
  $R.started_utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  $R.run_id = '{0}-{1}-{2}' -f $Suite, [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'), $PID
  $runDir = Join-Path $RunsRoot $R.run_id
  if (-not (Test-Path -LiteralPath $RunsRoot -PathType Container)) { [void][System.IO.Directory]::CreateDirectory($RunsRoot) }
  if (Test-Path -LiteralPath $runDir) { throw "run directory already exists: $runDir" }
  [void][System.IO.Directory]::CreateDirectory($runDir)
  $script:GuardLog = New-Object System.IO.StreamWriter((New-Object System.IO.FileStream((Join-Path $runDir 'guard.log'), 'CreateNew', 'Write', 'Read')), (New-Object System.Text.UTF8Encoding($false)))
  foreach ($line in $script:GuardLines) { $script:GuardLog.WriteLine($line) }

  Write-Guard ("RUN run_id={0} suite={1} trunk={2} wait_seconds={3}" -f $R.run_id, $Suite, $Trunk, $WaitSeconds)
  Write-Guard ("RESOURCE_POLICY runner=run.ps1 physical_free_floor_bytes={0} nominal_reserve_bytes={1} poll_ms={2} memory_api=GlobalMemoryStatusEx containment=JobObject(KILL_ON_JOB_CLOSE) mutex={3}" -f `
    $PhysicalFloorBytes, $NominalReserveBytes, $PollMilliseconds, $MutexName)

  Add-Type -TypeDefinition $native -Language CSharp
  Write-Guard ("HOST outer_job={0} ps_version={1} x64={2}" -f [RightRailGuardNative]::CurrentProcessInJob(), $PSVersionTable.PSVersion, [Environment]::Is64BitProcess)

  # Identity (in-process reads only; no child process yet).
  $R.guard_sha256 = Get-FileSha256 $GuardPath
  $R.suite_sha256 = Get-FileSha256 $SuitesPath
  $pins = Get-Pins
  $suiteDef = Get-Suite $Suite
  $R.start_floor =$(if ($suiteDef.start_floor -gt $PhysicalFloorBytes) { $suiteDef.start_floor } else { $PhysicalFloorBytes })
  Write-Guard ("SUITE name={0} class={1} program={2} program_sha256={3} args={4} cwd={5} timeout_seconds={6} start_floor_bytes={7} failure_patterns={8}" -f `
    $Suite, $suiteDef.class, $suiteDef.program, (Get-FileSha256 $suiteDef.program), ($suiteDef.args -join ' '), $suiteDef.cwd, $suiteDef.timeout, $R.start_floor, $suiteDef.patterns.Count)
  $idPre = Get-FileIdentity $pins
  Write-Guard ("IDENTITY_PRE guard_sha256={0} suites_sha256={1} pins_json_sha256={2}" -f $idPre.guard, $idPre.suites, $idPre.pins_file)
  foreach ($p in $idPre.pins) { Write-Guard "PIN_PRE $p" }
  $R.pins_ok = $idPre.pins_ok
  if (-not $idPre.pins_ok) { Set-Verdict 'INVALID' 'pinned artifact mismatch before launch' }

  if ($null -eq $script:Verdict -and (Test-StartFloor 'preflight' $R.start_floor)) {
    # Mutex (heavy only), polled up to -WaitSeconds.
    if ($suiteDef.class -eq 'heavy') {
      $mutex = New-Object System.Threading.Mutex($false, $MutexName)
      $deadline = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
      while (-not $mutexHeld) {
        try {
          if ($mutex.WaitOne(1000)) { $mutexHeld = $true; $R.mutex = 'ACQUIRED' }
        } catch [System.Threading.AbandonedMutexException] {
          $mutexHeld = $true; $R.mutex = 'ACQUIRED_ABANDONED'
        }
        if (-not $mutexHeld -and [DateTime]::UtcNow -ge $deadline) { break }
      }
      Write-Guard ("MUTEX name={0} state={1}" -f $MutexName, $(if ($mutexHeld) { $R.mutex } else { 'WAIT_TIMEOUT' }))
      if (-not $mutexHeld) { $R.mutex = 'WAIT_TIMEOUT'; Set-Verdict 'GUARD_STOP' "mutex $MutexName not acquired within $WaitSeconds s" }
    } else {
      $R.mutex = 'NOT_REQUIRED_LIGHT'
    }

    if ($null -eq $script:Verdict -and (Test-StartFloor 'post-mutex' $R.start_floor)) {
      $script:GitExe = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
      $gitPre = Get-GitIdentity
      $R.head = $gitPre.head; $R.tree = $gitPre.tree; $R.status_digest_pre = $gitPre.status
      Write-Guard ("GIT_PRE head={0} tree={1} status_porcelain_sha256={2} git={3}" -f $gitPre.head, $gitPre.tree, $gitPre.status, $script:GitExe)

      $selfEnv = New-EnvironmentBlock ([ordered]@{})
      $s7 = Invoke-InJob 'selftest-exit-7' $CmdExe @('/c', 'exit', '7') $Trunk $selfEnv $null $null 30
      $s0 = Invoke-InJob 'selftest-exit-0' $CmdExe @('/c', 'exit', '0') $Trunk $selfEnv $null $null 30
      $R.selftest.exit7 = $s7.exit; $R.selftest.exit0 = $s0.exit
      foreach ($s in @($s7, $s0)) {
        if ($null -ne $s.harness) { Set-Verdict 'HARNESS_ERROR' "self-test $($s.label): $($s.harness)" }
        elseif ($null -ne $s.stop) { Set-Verdict 'GUARD_STOP' "self-test $($s.label): $($s.stop)" }
      }
      $R.selftest.status = $(if ($s7.exit -eq 7 -and $s0.exit -eq 0 -and $s7.cleanup -like 'PASS*' -and $s0.cleanup -like 'PASS*') { 'PASS' } else { 'FAIL' })
      Write-Guard ("SELFTEST exit7={0} exit0={1} status={2}" -f $s7.exit, $s0.exit, $R.selftest.status)
      if ($R.selftest.status -ne 'PASS') { Set-Verdict 'HARNESS_ERROR' "self-test failed: exit7=$($s7.exit) exit0=$($s0.exit)" }

      if ($null -eq $script:Verdict -and (Test-StartFloor 'pre-launch' $R.start_floor)) {
        $stdoutPath = Join-Path $runDir 'stdout.log'
        $stderrPath = Join-Path $runDir 'stderr.log'
        $main = Invoke-InJob "suite-$Suite" $suiteDef.program $suiteDef.args $suiteDef.cwd (New-EnvironmentBlock $suiteDef.env) $stdoutPath $stderrPath $suiteDef.timeout
        $R.child_exit = $main.exit
        $R.peak_job_bytes = $main.peak
        if ($null -ne $main.harness) { Set-Verdict 'HARNESS_ERROR' "suite: $($main.harness)" }
        elseif ($null -ne $main.stop) { Set-Verdict 'GUARD_STOP' "suite: $($main.stop)" }
        elseif ($null -eq $main.exit) { Set-Verdict 'HARNESS_ERROR' 'suite exit code unavailable' }
        elseif ($main.exit -ne 0) { Set-Verdict 'FAIL' "suite exited $($main.exit)" }
        else {
          $matched = $null
          if ($suiteDef.patterns.Count -gt 0) {
            $text = ''
            foreach ($p in @($stdoutPath, $stderrPath)) { if (Test-Path -LiteralPath $p) { $text += [System.IO.File]::ReadAllText($p) + "`n" } }
            foreach ($pat in $suiteDef.patterns) { if ([regex]::IsMatch($text, $pat, 'Multiline')) { $matched = $pat; break } }
          }
          Write-Guard ("FAILURE_PATTERNS checked={0} matched={1}" -f $suiteDef.patterns.Count, $(if ($null -ne $matched) { $matched } else { 'none' }))
          if ($null -ne $matched) { Set-Verdict 'FAIL' "log matched failure pattern: $matched" }
          else { Set-Verdict 'PASS' 'suite exited 0' }
        }
      }

      # Post identity.
      $gitPost = Get-GitIdentity
      $R.status_digest_post = $gitPost.status
      Write-Guard ("GIT_POST head={0} tree={1} status_porcelain_sha256={2}" -f $gitPost.head, $gitPost.tree, $gitPost.status)
      if ($gitPost.head -ne $gitPre.head -or $gitPost.tree -ne $gitPre.tree) { Set-Verdict 'INVALID' 'git HEAD/tree changed during run' }
      if ($gitPost.status -ne $gitPre.status) { Set-Verdict 'INVALID' 'git status --porcelain digest changed during run' }
    }
  }

  $idPost = Get-FileIdentity $pins
  Write-Guard ("IDENTITY_POST guard_sha256={0} suites_sha256={1} pins_json_sha256={2} pins_ok={3}" -f $idPost.guard, $idPost.suites, $idPost.pins_file, $idPost.pins_ok)
  if ($idPost.guard -ne $idPre.guard -or $idPost.suites -ne $idPre.suites -or $idPost.pins_file -ne $idPre.pins_file) { Set-Verdict 'INVALID' 'guard/suites/pins file changed during run' }
  if (-not $idPost.pins_ok) { $R.pins_ok = $false; Set-Verdict 'INVALID' 'pinned artifact mismatch after run' }
} catch {
  $e = $_.Exception; while ($null -ne $e.InnerException) { $e = $e.InnerException }
  Set-Verdict 'HARNESS_ERROR' ("{0}" -f $e.Message)
} finally {
  if ($script:CleanupFailed) {
    Set-Verdict 'HARNESS_ERROR' 'job cleanup failed; ActiveProcesses did not reach 0'
  }
  if ($script:Launched) {
    $R.cleanup = $(if ($script:CleanupFailed) { 'FAIL' } elseif ($script:AnyTerminated) { 'PASS_TERMINATED' } else { 'PASS' })
  }
  if ($null -ne $mutex) {
    if ($mutexHeld -and -not $script:CleanupFailed) {
      $mutex.ReleaseMutex(); $R.mutex = $R.mutex + '_RELEASED'
    } elseif ($mutexHeld) {
      $R.mutex = 'HELD_UNTIL_PROCESS_EXIT'
    }
    if (-not $script:CleanupFailed) { $mutex.Dispose() }
  }
  if ($script:MinFree -ne [uint64]::MaxValue) { $R.min_free = $script:MinFree }
  if ($null -eq $script:Verdict) { $script:Verdict = 'HARNESS_ERROR'; $script:Reason = 'no verdict reached' }
  $R.verdict = $script:Verdict
  $R.reason = $script:Reason
  $R.ended_utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  Write-Guard ("FINAL verdict={0} reason={1} cleanup={2} mutex={3}" -f $R.verdict, $R.reason, $R.cleanup, $R.mutex)
  if ($null -ne $script:GuardLog) { $script:GuardLog.Dispose(); $script:GuardLog = $null }

  $exitCode = switch ($R.verdict) { 'PASS' { 0 } 'FAIL' { 1 } 'GUARD_STOP' { 2 } default { 3 } }
  try {
    if ($null -ne $R.run_id) {
      $runDir = Join-Path $RunsRoot $R.run_id
      foreach ($name in @('stdout.log', 'stderr.log', 'guard.log')) {
        $p = Join-Path $runDir $name
        if (Test-Path -LiteralPath $p -PathType Leaf) { $R.log_sha256s[$name] = Get-FileSha256 $p }
      }
    }
    $json = ($R | ConvertTo-Json -Compress -Depth 6)
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json + "`n")
    $rm = New-Object System.Threading.Mutex($false, $ResultsMutexName)
    $rmHeld = $false
    try {
      try { $rmHeld = $rm.WaitOne(30000) } catch [System.Threading.AbandonedMutexException] { $rmHeld = $true }
      if (-not $rmHeld) { throw 'results.jsonl lock not acquired within 30 s' }
      $fs = New-Object System.IO.FileStream($ResultsPath, 'Append', 'Write', 'Read')
      try { $fs.Write($bytes, 0, $bytes.Length); $fs.Flush($true) } finally { $fs.Dispose() }
    } finally { if ($rmHeld) { $rm.ReleaseMutex() }; $rm.Dispose() }
    [Console]::Out.WriteLine("RESULT $json")
  } catch {
    [Console]::Out.WriteLine("HARNESS_ERROR results.jsonl append failed: $($_.Exception.Message)")
    $exitCode = 3
  }
}
exit $exitCode
