/* SPDX-License-Identifier: MIT */

/*
 * Bounded, non-activating child-process measurement harness.  It captures and
 * discards child output, reports stable phase/resource records, and never
 * treats a structural fixture as a verified direct-mask proof.
 */

#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <fileapi.h>
#include <handleapi.h>
#include <jobapi2.h>
#include <processthreadsapi.h>
#include <synchapi.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#endif

#define DM_DRIVER_DEFAULT_WALL_MS UINT64_C(5000)
#define DM_DRIVER_DEFAULT_OUTPUT_BYTES UINT64_C(1048576)

typedef struct dm_driver_options_t {
  uint64_t max_wall_ms;
  uint64_t max_output_bytes;
  int child_index;
} dm_driver_options_t;

typedef struct dm_driver_result_t {
  int exit_code;
  int timed_out;
  int output_limited;
  uint64_t stdout_bytes;
  uint64_t stderr_bytes;
  uint64_t user_ns;
  uint64_t kernel_ns;
  uint64_t wall_ns;
  uint64_t peak_tree_bytes;
  uint64_t total_tree_processes;
  int whole_tree_accounting;
} dm_driver_result_t;

static int parse_u64(const char* text, uint64_t* value) {
  if (text == NULL || *text == '\0') {
    return 0;
  }
  char* end = NULL;
  errno = 0;
  const unsigned long long parsed = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0') {
    return 0;
  }
  *value = (uint64_t)parsed;
  return 1;
}
static int parse_options(int argc, char** argv, dm_driver_options_t* options) {
  options->max_wall_ms = DM_DRIVER_DEFAULT_WALL_MS;
  options->max_output_bytes = DM_DRIVER_DEFAULT_OUTPUT_BYTES;
  options->child_index = 1;
  while (options->child_index < argc) {
    if (strcmp(argv[options->child_index], "--max-wall-ms") == 0) {
      if (options->child_index + 1 >= argc ||
          !parse_u64(argv[options->child_index + 1], &options->max_wall_ms) ||
          options->max_wall_ms == 0 || options->max_wall_ms > UINT64_C(600000)) {
        return 0;
      }
      options->child_index += 2;
    } else if (strcmp(argv[options->child_index], "--max-output-bytes") == 0) {
      if (options->child_index + 1 >= argc ||
          !parse_u64(argv[options->child_index + 1], &options->max_output_bytes) ||
          options->max_output_bytes == 0 || options->max_output_bytes > UINT64_C(1073741824)) {
        return 0;
      }
      options->child_index += 2;
    } else {
      break;
    }
  }
  return options->child_index < argc;
}

#if defined(_WIN32)

static uint64_t qpc_ns(void) {
  LARGE_INTEGER frequency;
  LARGE_INTEGER counter;
  if (!QueryPerformanceFrequency(&frequency) || !QueryPerformanceCounter(&counter) ||
      frequency.QuadPart <= 0) {
    return 0;
  }
  const uint64_t ticks = (uint64_t)counter.QuadPart;
  const uint64_t ticks_per_second = (uint64_t)frequency.QuadPart;
  const uint64_t seconds = ticks / ticks_per_second;
  const uint64_t remainder = ticks % ticks_per_second;
  if (seconds > UINT64_MAX / UINT64_C(1000000000)) {
    return UINT64_MAX;
  }
  const uint64_t whole_ns = seconds * UINT64_C(1000000000);
  const uint64_t remainder_ns =
      (uint64_t)((long double)remainder * 1000000000.0L / (long double)ticks_per_second);
  return remainder_ns > UINT64_MAX - whole_ns ? UINT64_MAX : whole_ns + remainder_ns;
}

static uint64_t large_time_ns(const LARGE_INTEGER* value) {
  return value->QuadPart < 0 ? 0 : (uint64_t)value->QuadPart * UINT64_C(100);
}

static int append_command_arg(char* command, size_t capacity, size_t* used, const char* argument) {
  if (argument == NULL) {
    return 0;
  }
  if (*used + 3u >= capacity) {
    return 0;
  }
  command[(*used)++] = '"';
  for (const char* cursor = argument; *cursor != '\0'; ++cursor) {
    if (*cursor == '"' || *cursor == '\\') {
      if (*used + 2u >= capacity) {
        return 0;
      }
      command[(*used)++] = '\\';
    }
    if (*used + 1u >= capacity) {
      return 0;
    }
    command[(*used)++] = *cursor;
  }
  if (*used + 2u >= capacity) {
    return 0;
  }
  command[(*used)++] = '"';
  command[(*used)++] = ' ';
  command[*used] = '\0';
  return 1;
}

static int open_temp_output(char path[MAX_PATH], HANDLE* child_handle, HANDLE* parent_handle) {
  char temp_path[MAX_PATH];
  if (GetTempPathA(sizeof(temp_path), temp_path) == 0 ||
      GetTempFileNameA(temp_path, "dmw", 0, path) == 0) {
    return 0;
  }
  SECURITY_ATTRIBUTES child_security = {sizeof(child_security), NULL, TRUE};
  *child_handle = CreateFileA(path, GENERIC_WRITE | GENERIC_READ,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              &child_security, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
  if (*child_handle == INVALID_HANDLE_VALUE) {
    DeleteFileA(path);
    return 0;
  }
  SECURITY_ATTRIBUTES parent_security = {sizeof(parent_security), NULL, FALSE};
  *parent_handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               &parent_security, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY, NULL);
  if (*parent_handle == INVALID_HANDLE_VALUE) {
    CloseHandle(*child_handle);
    DeleteFileA(path);
    return 0;
  }
  return 1;
}

static uint64_t file_size_bytes(HANDLE handle) {
  LARGE_INTEGER size;
  if (!GetFileSizeEx(handle, &size) || size.QuadPart < 0) {
    return UINT64_MAX;
  }
  return (uint64_t)size.QuadPart;
}

static int run_child_windows(int argc, char** argv, const dm_driver_options_t* options,
                             dm_driver_result_t* result) {
  char command[32768];
  size_t command_used = 0;
  for (int index = options->child_index; index < argc; ++index) {
    if (!append_command_arg(command, sizeof(command), &command_used, argv[index])) {
      return 0;
    }
  }
  if (command_used != 0) {
    command[command_used - 1u] = '\0';
  }

  char stdout_path[MAX_PATH] = {0};
  char stderr_path[MAX_PATH] = {0};
  HANDLE child_stdout = INVALID_HANDLE_VALUE;
  HANDLE parent_stdout = INVALID_HANDLE_VALUE;
  HANDLE child_stderr = INVALID_HANDLE_VALUE;
  HANDLE parent_stderr = INVALID_HANDLE_VALUE;
  if (!open_temp_output(stdout_path, &child_stdout, &parent_stdout) ||
      !open_temp_output(stderr_path, &child_stderr, &parent_stderr)) {
    if (child_stdout != INVALID_HANDLE_VALUE) {
      CloseHandle(child_stdout);
    }
    if (parent_stdout != INVALID_HANDLE_VALUE) {
      CloseHandle(parent_stdout);
    }
    DeleteFileA(stdout_path);
    return 0;
  }

  SECURITY_ATTRIBUTES process_security = {sizeof(process_security), NULL, TRUE};
  HANDLE child_stdin = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   &process_security, OPEN_EXISTING, 0, NULL);
  if (child_stdin == INVALID_HANDLE_VALUE) {
    CloseHandle(child_stdout);
    CloseHandle(parent_stdout);
    CloseHandle(child_stderr);
    CloseHandle(parent_stderr);
    DeleteFileA(stdout_path);
    DeleteFileA(stderr_path);
    return 0;
  }

  STARTUPINFOA startup;
  PROCESS_INFORMATION process;
  memset(&startup, 0, sizeof(startup));
  memset(&process, 0, sizeof(process));
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = child_stdin;
  startup.hStdOutput = child_stdout;
  startup.hStdError = child_stderr;

  HANDLE job = CreateJobObjectA(NULL, NULL);
  if (job == NULL) {
    CloseHandle(child_stdin);
    CloseHandle(child_stdout);
    CloseHandle(parent_stdout);
    CloseHandle(child_stderr);
    CloseHandle(parent_stderr);
    DeleteFileA(stdout_path);
    DeleteFileA(stderr_path);
    return 0;
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
  memset(&limits, 0, sizeof(limits));
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
    CloseHandle(job);
    CloseHandle(child_stdin);
    CloseHandle(child_stdout);
    CloseHandle(parent_stdout);
    CloseHandle(child_stderr);
    CloseHandle(parent_stderr);
    DeleteFileA(stdout_path);
    DeleteFileA(stderr_path);
    return 0;
  }

  const DWORD creation_flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
  const BOOL created = CreateProcessA(NULL, command, &process_security, NULL, TRUE, creation_flags,
                                      NULL, NULL, &startup, &process);
  CloseHandle(child_stdin);
  CloseHandle(child_stdout);
  CloseHandle(child_stderr);
  if (!created || !AssignProcessToJobObject(job, process.hProcess)) {
    if (created) {
      TerminateJobObject(job, 1);
      CloseHandle(process.hThread);
      CloseHandle(process.hProcess);
    }
    CloseHandle(job);
    CloseHandle(parent_stdout);
    CloseHandle(parent_stderr);
    DeleteFileA(stdout_path);
    DeleteFileA(stderr_path);
    return 0;
  }
  ResumeThread(process.hThread);

  const uint64_t start_ns = qpc_ns();
  int finished = 0;
  while (!finished) {
    const DWORD wait_status = WaitForSingleObject(process.hProcess, 20);
    const uint64_t now_ns = qpc_ns();
    const uint64_t elapsed_ns = now_ns >= start_ns ? now_ns - start_ns : 0;
    const uint64_t stdout_bytes = file_size_bytes(parent_stdout);
    const uint64_t stderr_bytes = file_size_bytes(parent_stderr);
    const int output_overflow = stdout_bytes == UINT64_MAX || stderr_bytes == UINT64_MAX ||
                                stderr_bytes > UINT64_MAX - stdout_bytes;
    const uint64_t output_bytes = output_overflow ? UINT64_MAX : stdout_bytes + stderr_bytes;
    if (output_overflow || output_bytes > options->max_output_bytes ||
        elapsed_ns > options->max_wall_ms * UINT64_C(1000000)) {
      result->timed_out = elapsed_ns > options->max_wall_ms * UINT64_C(1000000);
      result->output_limited = output_bytes > options->max_output_bytes;
      TerminateJobObject(job, result->output_limited ? 2 : 3);
      WaitForSingleObject(process.hProcess, 30000);
      break;
    }
    if (wait_status == WAIT_OBJECT_0) {
      finished = 1;
    } else if (wait_status != WAIT_TIMEOUT) {
      TerminateJobObject(job, 4);
      WaitForSingleObject(process.hProcess, 30000);
      break;
    }
  }
  WaitForSingleObject(process.hProcess, 30000);
  FILETIME creation_time, exit_time, kernel_time, user_time;
  memset(&creation_time, 0, sizeof(creation_time));
  memset(&exit_time, 0, sizeof(exit_time));
  memset(&kernel_time, 0, sizeof(kernel_time));
  memset(&user_time, 0, sizeof(user_time));
  GetProcessTimes(process.hProcess, &creation_time, &exit_time, &kernel_time, &user_time);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION usage;
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
  memset(&usage, 0, sizeof(usage));
  memset(&accounting, 0, sizeof(accounting));
  const BOOL have_usage = QueryInformationJobObject(job, JobObjectExtendedLimitInformation,
                                                    &usage, sizeof(usage), NULL);
  const BOOL have_accounting = QueryInformationJobObject(
      job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL);
  DWORD exit_code = 1;
  GetExitCodeProcess(process.hProcess, &exit_code);
  result->exit_code = (int)exit_code;
  result->stdout_bytes = file_size_bytes(parent_stdout);
  result->stderr_bytes = file_size_bytes(parent_stderr);
  result->user_ns = have_accounting ? large_time_ns(&accounting.TotalUserTime) : UINT64_MAX;
  result->kernel_ns = have_accounting ? large_time_ns(&accounting.TotalKernelTime) : UINT64_MAX;
  result->peak_tree_bytes = have_usage ? (uint64_t)usage.PeakJobMemoryUsed : UINT64_MAX;
  result->total_tree_processes = have_accounting ? accounting.TotalProcesses : 0;
  const uint64_t end_ns = qpc_ns();
  result->wall_ns = end_ns >= start_ns ? end_ns - start_ns : 0;
  result->whole_tree_accounting = have_usage && have_accounting;

  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  CloseHandle(job);
  CloseHandle(parent_stdout);
  CloseHandle(parent_stderr);
  DeleteFileA(stdout_path);
  DeleteFileA(stderr_path);
  return 1;
}

#else

static uint64_t monotonic_ns(void) {
  struct timespec timestamp;
  if (clock_gettime(CLOCK_MONOTONIC, &timestamp) != 0) {
    return 0;
  }
  return (uint64_t)timestamp.tv_sec * UINT64_C(1000000000) + (uint64_t)timestamp.tv_nsec;
}

static uint64_t file_size_fd(int fd) {
  struct stat status;
  return fstat(fd, &status) == 0 && status.st_size >= 0 ? (uint64_t)status.st_size : UINT64_MAX;
}

static int run_child_posix(int argc, char** argv, const dm_driver_options_t* options,
                           dm_driver_result_t* result) {
  char stdout_template[] = "/tmp/dm-wire-out-XXXXXX";
  char stderr_template[] = "/tmp/dm-wire-err-XXXXXX";
  const int stdout_fd = mkstemp(stdout_template);
  const int stderr_fd = mkstemp(stderr_template);
  if (stdout_fd < 0 || stderr_fd < 0) {
    if (stdout_fd >= 0) close(stdout_fd);
    if (stderr_fd >= 0) close(stderr_fd);
    unlink(stdout_template);
    unlink(stderr_template);
    return 0;
  }
  pid_t child = fork();
  if (child < 0) {
    close(stdout_fd);
    close(stderr_fd);
    unlink(stdout_template);
    unlink(stderr_template);
    return 0;
  }
  (void)setpgid(child, child);
  if (child == 0) {
    setpgid(0, 0);
    dup2(stdout_fd, STDOUT_FILENO);
    dup2(stderr_fd, STDERR_FILENO);
    close(stdout_fd);
    close(stderr_fd);
    execvp(argv[options->child_index], &argv[options->child_index]);
    _exit(127);
  }
  close(stdout_fd);
  close(stderr_fd);
  const uint64_t start_ns = monotonic_ns();
  int child_status = 0;
  struct rusage child_usage;
  memset(&child_usage, 0, sizeof(child_usage));
  int have_child_usage = 0;
  int finished = 0;
  while (!finished) {
    const pid_t waited = wait4(child, &child_status, WNOHANG, &child_usage);
    const uint64_t now_ns = monotonic_ns();
    if (waited == child) {
      finished = 1;
      have_child_usage = 1;
      break;
    }
    const int out_probe = open(stdout_template, O_RDONLY);
    const int err_probe = open(stderr_template, O_RDONLY);
    const uint64_t out_size = file_size_fd(out_probe);
    const uint64_t err_size = file_size_fd(err_probe);
    if (out_probe >= 0) close(out_probe);
    if (err_probe >= 0) close(err_probe);
    const int output_overflow = out_size == UINT64_MAX || err_size == UINT64_MAX ||
                                err_size > UINT64_MAX - out_size;
    const uint64_t output_total = output_overflow ? UINT64_MAX : out_size + err_size;
    if ((now_ns >= start_ns && now_ns - start_ns > options->max_wall_ms * UINT64_C(1000000)) ||
        output_overflow || output_total > options->max_output_bytes) {
      result->timed_out = now_ns >= start_ns &&
                          now_ns - start_ns > options->max_wall_ms * UINT64_C(1000000);
      result->output_limited = output_total > options->max_output_bytes;
      kill(-child, SIGKILL);
      if (wait4(child, &child_status, 0, &child_usage) == child) {
        have_child_usage = 1;
      }
      finished = 1;
      break;
    }
    if (waited < 0 && errno != EINTR) {
      kill(-child, SIGKILL);
      if (wait4(child, &child_status, 0, &child_usage) == child) {
        have_child_usage = 1;
      }
      finished = 1;
      break;
    }
    struct timespec pause_time = {0, 20000000};
    nanosleep(&pause_time, NULL);
  }
  int out_fd = open(stdout_template, O_RDONLY);
  int err_fd = open(stderr_template, O_RDONLY);
  result->stdout_bytes = file_size_fd(out_fd);
  result->stderr_bytes = file_size_fd(err_fd);
  if (out_fd >= 0) close(out_fd);
  if (err_fd >= 0) close(err_fd);
  result->wall_ns = monotonic_ns() - start_ns;
  result->user_ns = have_child_usage
                        ? (uint64_t)child_usage.ru_utime.tv_sec * UINT64_C(1000000000) +
                              (uint64_t)child_usage.ru_utime.tv_usec * UINT64_C(1000)
                        : UINT64_MAX;
  result->kernel_ns = have_child_usage
                          ? (uint64_t)child_usage.ru_stime.tv_sec * UINT64_C(1000000000) +
                                (uint64_t)child_usage.ru_stime.tv_usec * UINT64_C(1000)
                          : UINT64_MAX;
  result->peak_tree_bytes = have_child_usage ? (uint64_t)child_usage.ru_maxrss * UINT64_C(1024)
                                              : UINT64_MAX;
  result->total_tree_processes = 1;
  result->whole_tree_accounting = 0;
  result->exit_code = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : 128 + WTERMSIG(child_status);
  unlink(stdout_template);
  unlink(stderr_template);
  return 1;
}

#endif

int main(int argc, char** argv) {
  dm_driver_options_t options;
  dm_driver_result_t result;
  memset(&result, 0, sizeof(result));
  result.exit_code = -1;
  if (argc < 2 || !parse_options(argc, argv, &options)) {
    fprintf(stderr, "usage: direct_mask_driver [--max-wall-ms N] [--max-output-bytes N] child [args...]\n");
    return 2;
  }
#if defined(_WIN32)
  const int launched = run_child_windows(argc, argv, &options, &result);
#else
  const int launched = run_child_posix(argc, argv, &options, &result);
#endif
  if (!launched) {
    printf("DM_DRIVER phase=setup status=error code=child_launch_or_capture_failed\n");
    return 2;
  }
  printf("DM_DRIVER phase=process status=%s exit_code=%d timed_out=%s output_limited=%s\n",
         result.exit_code == 0 && !result.timed_out && !result.output_limited ? "PASS" : "FAIL",
         result.exit_code, result.timed_out ? "true" : "false",
         result.output_limited ? "true" : "false");
  printf("DM_DRIVER phase=resources stdout_bytes=%" PRIu64 " stderr_bytes=%" PRIu64
         " cpu_user_ns=%" PRIu64 " cpu_kernel_ns=%" PRIu64 " wall_ns=%" PRIu64
         " peak_tree_bytes=%" PRIu64 " total_tree_processes=%" PRIu64
         " whole_tree_accounting=%s\n",
         result.stdout_bytes, result.stderr_bytes, result.user_ns, result.kernel_ns, result.wall_ns,
         result.peak_tree_bytes, result.total_tree_processes,
         result.whole_tree_accounting ? "true" : "false");
  printf("DM_DRIVER phase=private_output status=discarded stdout_forwarded=false stderr_forwarded=false "
         "proof_verification=not_run\n");
  return result.exit_code == 0 && !result.timed_out && !result.output_limited ? 0 : 1;
}
