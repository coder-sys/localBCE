#include <windows.h>
#include <bcrypt.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <array>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {

constexpr unsigned long long kSafetyMemoryCap = 4500000000ULL;

struct Peak {
  SIZE_T working = 0;
  SIZE_T private_bytes = 0;
  SIZE_T pagefile = 0;
  DWORD parent = 0;
};

struct ProcEntry {
  DWORD parent = 0;
  std::wstring name;
};

std::string WinError(DWORD error = GetLastError()) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "%lu", static_cast<unsigned long>(error));
  return buffer;
}

std::wstring Quote(const std::wstring& value) {
  std::wstring output = L"\"";
  for (wchar_t ch : value) {
    if (ch == L'\"') output.push_back(L'\\');
    output.push_back(ch);
  }
  output.push_back(L'\"');
  return output;
}

std::vector<DWORD> Descendants(DWORD root, std::map<DWORD, ProcEntry>& entries) {
  std::vector<DWORD> result{root};
  for (size_t index = 0; index < result.size(); ++index) {
    const DWORD parent = result[index];
    for (const auto& [pid, entry] : entries) {
      if (entry.parent == parent &&
          std::find(result.begin(), result.end(), pid) == result.end()) {
        result.push_back(pid);
      }
    }
  }
  return result;
}

bool SampleProcesses(DWORD root, std::map<DWORD, Peak>& peaks,
                     size_t& sample_count, size_t& snapshot_failures,
                     size_t& open_failures, size_t& info_failures,
                     std::set<DWORD>& seen_processes) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    ++snapshot_failures;
    return false;
  }
  std::map<DWORD, ProcEntry> entries;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (!Process32FirstW(snapshot, &entry)) {
    ++snapshot_failures;
    CloseHandle(snapshot);
    return false;
  }
  do {
    entries.emplace(entry.th32ProcessID,
                    ProcEntry{entry.th32ParentProcessID, entry.szExeFile});
  } while (Process32NextW(snapshot, &entry));
  CloseHandle(snapshot);
  const std::vector<DWORD> pids = Descendants(root, entries);
  for (DWORD pid : pids) {
    seen_processes.insert(pid);
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                 FALSE, pid);
    if (!process) {
      ++open_failures;
      continue;
    }
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (GetProcessMemoryInfo(process,
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                             sizeof(counters))) {
      Peak& peak = peaks[pid];
      peak.parent = entries.count(pid) ? entries[pid].parent : 0;
      peak.working = (std::max)(peak.working, counters.WorkingSetSize);
      peak.private_bytes = (std::max)(peak.private_bytes, counters.PrivateUsage);
      peak.pagefile = (std::max)(peak.pagefile, counters.PagefileUsage);
    } else {
      ++info_failures;
    }
    CloseHandle(process);
  }
  ++sample_count;
  return true;
}

uintmax_t ScratchBytes(const std::filesystem::path& root) {
  uintmax_t total = 0;
  std::error_code error;
  if (!std::filesystem::exists(root, error)) return 0;
  for (const auto& item : std::filesystem::recursive_directory_iterator(root, error)) {
    if (error) break;
    if (item.is_regular_file(error)) total += item.file_size(error);
  }
  return total;
}

std::string ReadText(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(input),
                     std::istreambuf_iterator<char>());
}

bool Sha256File(const std::filesystem::path& path, std::array<uint8_t, 32>& digest) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) !=
      0) {
    return false;
  }
  bool ok = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) == 0;
  std::ifstream input(path, std::ios::binary);
  // Keep the chunk off the default Windows thread stack. The runner must not
  // fail after a successful child attempt while finalizing artifact evidence.
  std::vector<char> buffer(1024 * 1024);
  while (ok && input) {
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize count = input.gcount();
    if (count > 0) {
      ok = BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()),
                          static_cast<ULONG>(count), 0) == 0;
    }
  }
  if (ok) {
    ok = BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) ==
         0;
  }
  if (hash) BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  return ok && input.eof();
}

std::string Hex(const std::array<uint8_t, 32>& bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string output;
  output.reserve(bytes.size() * 2);
  for (uint8_t byte : bytes) {
    output.push_back(kHex[byte >> 4]);
    output.push_back(kHex[byte & 0xf]);
  }
  return output;
}

void PrintPeaks(const std::map<DWORD, Peak>& peaks) {
  for (const auto& [pid, peak] : peaks) {
    std::printf("SOURCE_ASSERTION_PROVER_PROCESS pid=%lu parent=%lu "
                "peak_working_set_bytes=%zu peak_private_usage_bytes=%zu "
                "peak_pagefile_usage_bytes=%zu\n",
                static_cast<unsigned long>(pid),
                static_cast<unsigned long>(peak.parent), peak.working,
                peak.private_bytes, peak.pagefile);
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 4) {
    std::fprintf(stderr,
                 "usage: longfellow_source_assertion_prover_runner "
                 "PROVER ARTIFACT SCRATCH\n");
    return 2;
  }
  const std::filesystem::path prover_path = argv[1];
  const std::filesystem::path artifact_path = argv[2];
  const std::filesystem::path scratch_path = argv[3];
  std::error_code directory_error;
  std::filesystem::create_directories(scratch_path, directory_error);
  if (directory_error) {
    std::fprintf(stderr,
                 "SOURCE_ASSERTION_PROVER_RUNNER_SETUP_FAIL stage=scratch error=%s\n",
                 directory_error.message().c_str());
    return 2;
  }
  const std::filesystem::path stdout_path = scratch_path / "prover.stdout.log";
  const std::filesystem::path stderr_path = scratch_path / "prover.stderr.log";

  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;
  HANDLE child_stdout = CreateFileW(stdout_path.wstring().c_str(), GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  HANDLE child_stderr = CreateFileW(stderr_path.wstring().c_str(), GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  HANDLE child_stdin = CreateFileW(L"NUL", GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (child_stdout == INVALID_HANDLE_VALUE || child_stderr == INVALID_HANDLE_VALUE ||
      child_stdin == INVALID_HANDLE_VALUE) {
    std::fprintf(stderr,
                 "SOURCE_ASSERTION_PROVER_RUNNER_SETUP_FAIL stage=log-handles "
                 "error=%s\n",
                 WinError().c_str());
    if (child_stdout != INVALID_HANDLE_VALUE) CloseHandle(child_stdout);
    if (child_stderr != INVALID_HANDLE_VALUE) CloseHandle(child_stderr);
    if (child_stdin != INVALID_HANDLE_VALUE) CloseHandle(child_stdin);
    return 2;
  }

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) {
    std::fprintf(stderr,
                 "SOURCE_ASSERTION_PROVER_RUNNER_SETUP_FAIL stage=job-create "
                 "error=%s\n",
                 WinError().c_str());
    CloseHandle(child_stdout);
    CloseHandle(child_stderr);
    CloseHandle(child_stdin);
    return 2;
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY |
                                            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  limits.JobMemoryLimit = kSafetyMemoryCap;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                               sizeof(limits))) {
    std::fprintf(stderr,
                 "SOURCE_ASSERTION_PROVER_RUNNER_SETUP_FAIL stage=job-limit "
                 "error=%s cap=%llu\n",
                 WinError().c_str(), kSafetyMemoryCap);
    CloseHandle(job);
    CloseHandle(child_stdout);
    CloseHandle(child_stderr);
    CloseHandle(child_stdin);
    return 2;
  }

  std::wstring command = Quote(prover_path.wstring()) + L" " +
                         Quote(artifact_path.wstring());
  std::vector<wchar_t> command_line(command.begin(), command.end());
  command_line.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = child_stdin;
  startup.hStdOutput = child_stdout;
  startup.hStdError = child_stderr;
  PROCESS_INFORMATION process_info{};
  if (!CreateProcessW(nullptr, command_line.data(), nullptr, nullptr, TRUE,
                      CREATE_SUSPENDED | CREATE_NO_WINDOW |
                          CREATE_UNICODE_ENVIRONMENT,
                      nullptr, nullptr, &startup, &process_info)) {
    std::fprintf(stderr,
                 "SOURCE_ASSERTION_PROVER_RUNNER_SETUP_FAIL stage=create-process "
                 "error=%s\n",
                 WinError().c_str());
    CloseHandle(job);
    CloseHandle(child_stdout);
    CloseHandle(child_stderr);
    CloseHandle(child_stdin);
    return 2;
  }
  if (!AssignProcessToJobObject(job, process_info.hProcess)) {
    std::fprintf(stderr,
                 "SOURCE_ASSERTION_PROVER_RUNNER_SETUP_FAIL stage=job-assign "
                 "error=%s\n",
                 WinError().c_str());
    TerminateProcess(process_info.hProcess, 0xE001);
    WaitForSingleObject(process_info.hProcess, INFINITE);
    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    CloseHandle(job);
    CloseHandle(child_stdout);
    CloseHandle(child_stderr);
    CloseHandle(child_stdin);
    return 2;
  }
  if (ResumeThread(process_info.hThread) == static_cast<DWORD>(-1)) {
    std::fprintf(stderr,
                 "SOURCE_ASSERTION_PROVER_RUNNER_SETUP_FAIL stage=resume "
                 "error=%s\n",
                 WinError().c_str());
    TerminateProcess(process_info.hProcess, 0xE002);
    WaitForSingleObject(process_info.hProcess, INFINITE);
    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    CloseHandle(job);
    CloseHandle(child_stdout);
    CloseHandle(child_stderr);
    CloseHandle(child_stdin);
    return 2;
  }

  std::printf("SOURCE_ASSERTION_PROVER_RUNNER attempt=1 attempts_total=1 "
              "job_commit_cap_bytes=%llu hard_cap_bytes=5000000000 "
              "enforcement=job-object-commit-limit\n",
              kSafetyMemoryCap);
  const auto start = std::chrono::steady_clock::now();
  std::map<DWORD, Peak> peaks;
  size_t samples = 0;
  size_t snapshot_failures = 0;
  size_t open_failures = 0;
  size_t info_failures = 0;
  size_t wait_failures = 0;
  std::set<DWORD> seen_processes;
  for (;;) {
    SampleProcesses(process_info.dwProcessId, peaks, samples,
                    snapshot_failures, open_failures, info_failures,
                    seen_processes);
    const DWORD wait = WaitForSingleObject(process_info.hProcess, 250);
    if (wait == WAIT_OBJECT_0) break;
    if (wait == WAIT_FAILED) {
      ++wait_failures;
      break;
    }
  }
  SampleProcesses(process_info.dwProcessId, peaks, samples,
                  snapshot_failures, open_failures, info_failures,
                  seen_processes);
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - start)
                           .count();
  DWORD exit_code = 0;
  GetExitCodeProcess(process_info.hProcess, &exit_code);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION after{};
  bool job_query = QueryInformationJobObject(
      job, JobObjectExtendedLimitInformation, &after, sizeof(after), nullptr) != FALSE;
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
  bool accounting_query = QueryInformationJobObject(
      job, JobObjectBasicAccountingInformation, &accounting,
      sizeof(accounting), nullptr) != FALSE;
  const size_t job_total_processes =
      accounting_query ? static_cast<size_t>(accounting.TotalProcesses) : 0;
  const bool process_tree_complete =
      job_query && accounting_query && samples > 0 &&
      snapshot_failures == 0 && open_failures == 0 && info_failures == 0 &&
      wait_failures == 0 &&
      job_total_processes == seen_processes.size();
  const bool telemetry_complete = process_tree_complete;
  const bool cap_breached =
      job_query && after.PeakJobMemoryUsed >= kSafetyMemoryCap;
  CloseHandle(process_info.hThread);
  CloseHandle(process_info.hProcess);
  CloseHandle(child_stdout);
  CloseHandle(child_stderr);
  CloseHandle(child_stdin);

  const bool artifact_present = std::filesystem::is_regular_file(artifact_path);
  uintmax_t artifact_size = artifact_present ? std::filesystem::file_size(artifact_path)
                                            : 0;
  std::array<uint8_t, 32> artifact_hash{};
  const bool artifact_hash_ok = artifact_present && Sha256File(artifact_path, artifact_hash);
  std::printf("SOURCE_ASSERTION_PROVER_RESOURCE peak_job_commit_bytes=%zu "
              "peak_process_commit_bytes=%zu sampled_processes=%zu "
              "job_total_processes=%zu observed_processes=%zu samples=%zu "
              "telemetry_complete=%d process_tree_complete=%d "
              "snapshot_failures=%zu open_process_failures=%zu "
              "memory_info_failures=%zu wait_failures=%zu "
              "pagefile_growth_evidence=unavailable "
              "final_scratch_bytes=%llu wall_ms=%lld\n",
               job_query ? after.PeakJobMemoryUsed : 0,
               job_query ? after.PeakProcessMemoryUsed : 0,
               peaks.size(),
               job_total_processes,
               seen_processes.size(),
               samples, telemetry_complete ? 1 : 0,
               process_tree_complete ? 1 : 0,
               snapshot_failures, open_failures, info_failures, wait_failures,
               static_cast<unsigned long long>(ScratchBytes(scratch_path)),
               static_cast<long long>(elapsed));
  PrintPeaks(peaks);
  std::printf("SOURCE_ASSERTION_PROVER_OUTPUT exit_code=%lu cap_breached=%d "
              "artifact_present=%d artifact_size=%llu artifact_hash_ok=%d "
              "artifact_sha256=%s\n",
              static_cast<unsigned long>(exit_code), cap_breached ? 1 : 0,
              artifact_present ? 1 : 0,
              static_cast<unsigned long long>(artifact_size),
              artifact_hash_ok ? 1 : 0,
              artifact_hash_ok ? Hex(artifact_hash).c_str() : "none");
  std::printf("SOURCE_ASSERTION_PROVER_CHILD_STDOUT_BEGIN\n%s"
              "SOURCE_ASSERTION_PROVER_CHILD_STDOUT_END\n",
              ReadText(stdout_path).c_str());
  std::printf("SOURCE_ASSERTION_PROVER_CHILD_STDERR_BEGIN\n%s"
              "SOURCE_ASSERTION_PROVER_CHILD_STDERR_END\n",
              ReadText(stderr_path).c_str());
  CloseHandle(job);
  std::printf("SOURCE_ASSERTION_PROVER_ATTEMPT_COUNT=1\n");
  return !cap_breached && exit_code == 0 && artifact_present && artifact_hash_ok &&
                 telemetry_complete
             ? 0
             : 1;
}
