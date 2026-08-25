#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr uint64_t kHardCapBytes = 5000000000ULL;
// The job cap is intentionally below the requested hard gate so a delayed
// working-set sample cannot overshoot the externally stated ceiling.
constexpr uint64_t kSafetyJobCommitCapBytes = 4500000000ULL;
constexpr DWORD kSampleMilliseconds = 100;

struct ProcessPeak {
  DWORD pid = 0;
  DWORD parent_pid = 0;
  size_t samples = 0;
  size_t failures = 0;
  uint64_t peak_working_set = 0;
  uint64_t peak_private_commit = 0;
};

struct JobPeak {
  uint64_t peak_job_commit = 0;
  uint64_t peak_process_commit = 0;
  bool query_ok = true;
};

struct JobCensus {
  uint64_t last_total_processes = 0;
  uint64_t last_active_processes = 0;
  uint64_t peak_total_processes = 0;
  uint64_t peak_active_processes = 0;
  size_t accounting_queries = 0;
  size_t accounting_failures = 0;
  size_t process_id_queries = 0;
  size_t process_id_failures = 0;
  std::set<DWORD> seen_process_ids;
  bool last_accounting_ok = false;
  bool last_process_id_query_ok = false;
};

std::string Quote(const std::string& value) {
  std::string output = "\"";
  for (char ch : value) {
    if (ch == '"') output += "\\\"";
    else output.push_back(ch);
  }
  output += "\"";
  return output;
}

std::vector<std::pair<DWORD, DWORD>> ProcessSnapshot() {
  std::vector<std::pair<DWORD, DWORD>> output;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return output;
  PROCESSENTRY32 entry{};
  entry.dwSize = sizeof(entry);
  if (Process32First(snapshot, &entry)) {
    do {
      output.emplace_back(entry.th32ProcessID, entry.th32ParentProcessID);
    } while (Process32Next(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return output;
}

std::map<DWORD, DWORD> Descendants(DWORD root) {
  const auto snapshot = ProcessSnapshot();
  std::map<DWORD, DWORD> output;
  output[root] = 0;
  bool changed = true;
  while (changed) {
    changed = false;
    for (const auto& [pid, parent] : snapshot) {
      if (output.count(parent) != 0 && output.count(pid) == 0) {
        output[pid] = parent;
        changed = true;
      }
    }
  }
  return output;
}

bool SampleProcess(ProcessPeak& peak) {
  HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                                   PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE, peak.pid);
  if (process == nullptr) {
    ++peak.failures;
    return false;
  }
  PROCESS_MEMORY_COUNTERS_EX counters{};
  counters.cb = sizeof(counters);
  const BOOL ok = GetProcessMemoryInfo(
      process, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
      sizeof(counters));
  CloseHandle(process);
  if (!ok) {
    ++peak.failures;
    return false;
  }
  ++peak.samples;
  peak.peak_working_set =
      std::max<uint64_t>(peak.peak_working_set, counters.PeakWorkingSetSize);
  // PrivateUsage is a committed/private metric. It is not PagefileUsage.
  peak.peak_private_commit =
      std::max<uint64_t>(peak.peak_private_commit, counters.PrivateUsage);
  return true;
}

JobPeak SampleJob(HANDLE job, JobPeak peak) {
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
  if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &info, sizeof(info), nullptr)) {
    peak.query_ok = false;
    return peak;
  }
  // PeakJobMemoryUsed and PeakProcessMemoryUsed are committed-memory metrics.
  peak.peak_job_commit =
      std::max<uint64_t>(peak.peak_job_commit, info.PeakJobMemoryUsed);
  peak.peak_process_commit =
      std::max<uint64_t>(peak.peak_process_commit,
                         info.PeakProcessMemoryUsed);
  return peak;
}

bool SampleJobCensus(HANDLE job, JobCensus& census) {
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
  ++census.accounting_queries;
  if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                                 &accounting, sizeof(accounting), nullptr)) {
    ++census.accounting_failures;
    census.last_accounting_ok = false;
    census.last_process_id_query_ok = false;
    return false;
  }
  census.last_total_processes = accounting.TotalProcesses;
  census.last_active_processes = accounting.ActiveProcesses;
  census.peak_total_processes =
      std::max<uint64_t>(census.peak_total_processes,
                         accounting.TotalProcesses);
  census.peak_active_processes =
      std::max<uint64_t>(census.peak_active_processes,
                         accounting.ActiveProcesses);
  census.last_accounting_ok = true;

  // The Job Object process-id list is the race-free membership source for
  // assigned processes.  Toolhelp remains only a per-process diagnostic; it
  // is never sufficient to establish complete-tree coverage.
  size_t buffer_bytes = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) +
                        sizeof(ULONG_PTR) * 15;
  std::vector<uint8_t> buffer(buffer_bytes);
  DWORD return_bytes = 0;
  bool listed = false;
  for (size_t attempt = 0; attempt != 8; ++attempt) {
    return_bytes = 0;
    if (QueryInformationJobObject(job, JobObjectBasicProcessIdList,
                                  buffer.data(),
                                  static_cast<DWORD>(buffer.size()),
                                  &return_bytes)) {
      listed = true;
      break;
    }
    const DWORD error = GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER && error != ERROR_MORE_DATA) break;
    const size_t required = return_bytes > buffer.size()
                                ? static_cast<size_t>(return_bytes)
                                : buffer.size() * 2;
    if (required <= buffer.size() || required > (1u << 20)) break;
    buffer.resize(required);
  }
  ++census.process_id_queries;
  if (!listed || buffer.size() < sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST)) {
    ++census.process_id_failures;
    census.last_process_id_query_ok = false;
    return false;
  }
  const auto* process_ids =
      reinterpret_cast<const JOBOBJECT_BASIC_PROCESS_ID_LIST*>(buffer.data());
  const size_t header_bytes =
      offsetof(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList);
  const size_t ids = process_ids->NumberOfProcessIdsInList;
  if (ids > (buffer.size() - header_bytes) / sizeof(ULONG_PTR) ||
      ids > process_ids->NumberOfAssignedProcesses) {
    ++census.process_id_failures;
    census.last_process_id_query_ok = false;
    return false;
  }
  for (size_t index = 0; index != ids; ++index) {
    const ULONG_PTR value = process_ids->ProcessIdList[index];
    if (value <= static_cast<ULONG_PTR>(UINT32_MAX)) {
      census.seen_process_ids.insert(static_cast<DWORD>(value));
    }
  }
  census.last_process_id_query_ok = true;
  return true;
}

uint64_t ScratchBytes(const std::filesystem::path& root, bool& ok) {
  ok = true;
  uint64_t total = 0;
  std::error_code error;
  if (!std::filesystem::exists(root, error)) return 0;
  if (error) {
    ok = false;
    return 0;
  }
  std::filesystem::recursive_directory_iterator iterator(
      root, std::filesystem::directory_options::skip_permission_denied, error);
  const std::filesystem::recursive_directory_iterator end;
  while (iterator != end) {
    if (error) {
      ok = false;
      error.clear();
      iterator.increment(error);
      continue;
    }
    if (iterator->is_regular_file(error)) {
      const uint64_t size = iterator->file_size(error);
      if (error || size > UINT64_MAX - total) {
        ok = false;
        error.clear();
      } else {
        total += size;
      }
    }
    iterator.increment(error);
  }
  if (error) ok = false;
  return total;
}

void PrintProcessPeaks(const std::map<DWORD, ProcessPeak>& peaks) {
  for (const auto& [pid, peak] : peaks) {
    std::printf("MINIMAL_CLEARANCE_RUNNER_PROCESS pid=%lu parent_pid=%lu "
                "samples=%zu failures=%zu peak_working_set_bytes=%llu "
                "peak_private_commit_bytes=%llu\n",
                static_cast<unsigned long>(pid),
                static_cast<unsigned long>(peak.parent_pid), peak.samples,
                peak.failures,
                static_cast<unsigned long long>(peak.peak_working_set),
                static_cast<unsigned long long>(peak.peak_private_commit));
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 4 && argc != 5) {
    std::fprintf(stderr,
                 "usage: longfellow_minimal_clearance_prover_runner "
                 "PROVER ARTIFACT SCRATCH [CASE A|B]\n");
    return 2;
  }
  if (argc == 5 && std::string(argv[4]) != "A" &&
      std::string(argv[4]) != "B") {
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_RUNNER_REJECT reason=case-selector\n");
    return 2;
  }
  const std::filesystem::path scratch = argv[3];
  std::error_code scratch_error;
  std::filesystem::create_directories(scratch, scratch_error);
  if (scratch_error) {
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_RUNNER_REJECT reason=scratch-create\n");
    return 2;
  }
  std::string command = Quote(argv[1]) + " " + Quote(argv[2]);
  if (argc == 5) command += " --case " + Quote(argv[4]);
  std::vector<char> command_line(command.begin(), command.end());
  command_line.push_back('\0');

  HANDLE job = CreateJobObjectA(nullptr, nullptr);
  if (job == nullptr) {
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_RUNNER_REJECT reason=create-job\n");
    return 2;
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                            JOB_OBJECT_LIMIT_JOB_MEMORY;
  limits.JobMemoryLimit = kSafetyJobCommitCapBytes;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits,
                               sizeof(limits))) {
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_RUNNER_REJECT reason=set-job-limit\n");
    CloseHandle(job);
    return 2;
  }

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process_info{};
  if (!CreateProcessA(nullptr, command_line.data(), nullptr, nullptr, FALSE,
                      CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr,
                      &startup, &process_info)) {
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_RUNNER_REJECT reason=create-process\n");
    CloseHandle(job);
    return 2;
  }
  if (!AssignProcessToJobObject(job, process_info.hProcess)) {
    std::fprintf(stderr,
                 "MINIMAL_CLEARANCE_RUNNER_REJECT reason=assign-job\n");
    TerminateProcess(process_info.hProcess, 3);
    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    CloseHandle(job);
    return 2;
  }

  const DWORD root_pid = process_info.dwProcessId;
  std::map<DWORD, ProcessPeak> peaks;
  JobPeak job_peak;
  JobCensus job_census;
  size_t sample_failures = 0;
  size_t scratch_sample_failures = 0;
  uint64_t scratch_peak = 0;
  bool gate_killed = false;
  const char* gate_reason = "none";
  std::printf("MINIMAL_CLEARANCE_RUNNER_START root_pid=%lu hard_cap_bytes=%llu "
              "safety_job_commit_cap_bytes=%llu sample_ms=%lu job_object=1 "
              "proof_invocations=1\n",
              static_cast<unsigned long>(root_pid),
              static_cast<unsigned long long>(kHardCapBytes),
              static_cast<unsigned long long>(kSafetyJobCommitCapBytes),
              static_cast<unsigned long>(kSampleMilliseconds));
  ResumeThread(process_info.hThread);

  bool running = true;
  while (running) {
    const DWORD wait = WaitForSingleObject(process_info.hProcess,
                                           kSampleMilliseconds);
    // Do not attempt to reopen members after the root has exited.  The final
    // Job Object census below accounts for all assigned members, while a
    // post-exit OpenProcess failure would be a sampling artifact rather than
    // evidence that the census missed a process.
    if (wait == WAIT_TIMEOUT) {
      const auto descendants = Descendants(root_pid);
      for (const auto& [pid, parent] : descendants) {
        auto [it, inserted] = peaks.emplace(pid, ProcessPeak{pid, parent});
        if (!SampleProcess(it->second)) ++sample_failures;
      }
    }
    job_peak = SampleJob(job, job_peak);
    if (wait != WAIT_OBJECT_0 && !SampleJobCensus(job, job_census)) {
      gate_killed = true;
      gate_reason = "job-census-failure";
    }
    if (wait == WAIT_TIMEOUT) {
      for (const DWORD pid : job_census.seen_process_ids) {
        auto [it, inserted] = peaks.emplace(pid, ProcessPeak{pid, 0});
        if (!SampleProcess(it->second)) ++sample_failures;
      }
    }
    bool scratch_ok = false;
    scratch_peak = std::max(scratch_peak, ScratchBytes(scratch, scratch_ok));
    if (!scratch_ok) ++scratch_sample_failures;
    if (!job_peak.query_ok) {
      gate_killed = true;
      gate_reason = "job-query-failure";
    }
    if (job_peak.peak_job_commit >= kSafetyJobCommitCapBytes) {
      gate_killed = true;
      gate_reason = "safety-job-commit-cap";
    }
    for (const auto& [pid, peak] : peaks) {
      if (peak.peak_working_set >= kHardCapBytes ||
          peak.peak_private_commit >= kHardCapBytes) {
        gate_killed = true;
        gate_reason = "process-memory-hard-cap";
      }
    }
    if (gate_killed) {
      TerminateJobObject(job, 0xC0000409);
      WaitForSingleObject(process_info.hProcess, INFINITE);
      running = false;
    } else if (wait == WAIT_OBJECT_0) {
      running = false;
    } else if (wait == WAIT_FAILED) {
      gate_killed = true;
      gate_reason = "wait-failure";
      TerminateJobObject(job, 0xC0000409);
      WaitForSingleObject(process_info.hProcess, INFINITE);
      running = false;
    }
  }

  // One final job/scratch sample captures post-exit accounting. A process
  // observed only after exit is still counted as uncovered below.
  job_peak = SampleJob(job, job_peak);
  if (!SampleJobCensus(job, job_census)) {
    gate_killed = true;
    gate_reason = "job-census-failure";
  }
  bool scratch_ok = false;
  scratch_peak = std::max(scratch_peak, ScratchBytes(scratch, scratch_ok));
  if (!scratch_ok) ++scratch_sample_failures;
  DWORD exit_code = 0xffffffff;
  GetExitCodeProcess(process_info.hProcess, &exit_code);
  CloseHandle(process_info.hThread);
  CloseHandle(process_info.hProcess);

  size_t unsampled = 0;
  for (const auto& [pid, peak] : peaks) {
    if (peak.samples == 0) ++unsampled;
  }
  const bool job_census_complete =
      job_census.accounting_failures == 0 &&
      job_census.process_id_failures == 0 &&
      job_census.last_accounting_ok && job_census.last_process_id_query_ok &&
      job_census.last_active_processes == 0 &&
      job_census.last_total_processes != 0 &&
      job_census.last_total_processes == job_census.seen_process_ids.size();
  const bool process_tree_complete =
      job_peak.query_ok && sample_failures == 0 && unsampled == 0 &&
      scratch_sample_failures == 0 && job_census_complete;
  PrintProcessPeaks(peaks);
  std::printf("MINIMAL_CLEARANCE_RUNNER_SUMMARY exit_code=%lu "
              "gate_killed=%d gate_reason=%s job_assigned=1 "
              "process_tree_complete=%d observed_processes=%zu "
              "unsampled_processes=%zu sample_failures=%zu "
              "job_total_processes=%llu job_active_processes=%llu "
              "job_peak_total_processes=%llu job_peak_active_processes=%llu "
              "job_census_complete=%d job_census_accounting_failures=%zu "
              "job_census_process_id_failures=%zu "
              "peak_working_set_bytes=%llu peak_private_commit_bytes=%llu "
              "peak_job_commit_bytes=%llu peak_process_commit_bytes=%llu "
              "scratch_peak_bytes_observed=%llu scratch_sample_failures=%zu "
              "pagefile_growth_signal=unmeasured proof_invocations=1\n",
              static_cast<unsigned long>(exit_code), gate_killed ? 1 : 0,
              gate_reason, process_tree_complete ? 1 : 0, peaks.size(),
              unsampled, sample_failures,
              static_cast<unsigned long long>(job_census.last_total_processes),
              static_cast<unsigned long long>(job_census.last_active_processes),
              static_cast<unsigned long long>(job_census.peak_total_processes),
              static_cast<unsigned long long>(job_census.peak_active_processes),
              job_census_complete ? 1 : 0, job_census.accounting_failures,
              job_census.process_id_failures,
              static_cast<unsigned long long>([&]() {
                uint64_t value = 0;
                for (const auto& [pid, peak] : peaks)
                  value = std::max(value, peak.peak_working_set);
                return value;
              }()),
              static_cast<unsigned long long>([&]() {
                uint64_t value = 0;
                for (const auto& [pid, peak] : peaks)
                  value = std::max(value, peak.peak_private_commit);
                return value;
              }()),
              static_cast<unsigned long long>(job_peak.peak_job_commit),
              static_cast<unsigned long long>(job_peak.peak_process_commit),
              static_cast<unsigned long long>(scratch_peak),
              scratch_sample_failures);
  CloseHandle(job);
  if (gate_killed || !process_tree_complete) return 3;
  return static_cast<int>(exit_code);
}
