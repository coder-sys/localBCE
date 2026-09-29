/* SPDX-License-Identifier: MIT */

#ifdef _WIN32

#include "direct_mask_fixture.h"

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void store_u32_le(uint8_t bytes[4], uint32_t value) {
  for (size_t index = 0u; index != 4u; ++index) {
    bytes[index] = (uint8_t)(value & UINT32_C(0xff));
    value >>= 8;
  }
}

static void store_u64_le(uint8_t bytes[8], uint64_t value) {
  for (size_t index = 0u; index != 8u; ++index) {
    bytes[index] = (uint8_t)(value & UINT64_C(0xff));
    value >>= 8;
  }
}

static wchar_t* utf8_to_wide(const char* text) {
  int length;
  wchar_t* result;

  length = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
  if (length <= 0) {
    return NULL;
  }
  result = (wchar_t*)calloc((size_t)length, sizeof(*result));
  if (result == NULL ||
      MultiByteToWideChar(CP_UTF8, 0, text, -1, result, length) <= 0) {
    free(result);
    return NULL;
  }
  return result;
}

static int read_pipe_all(HANDLE pipe, uint8_t** output, size_t* output_bytes) {
  uint8_t* buffer = NULL;
  size_t used = 0u;
  size_t capacity = 0u;

  if (pipe == NULL || output == NULL || output_bytes == NULL) {
    return 0;
  }
  for (;;) {
    uint8_t chunk[4096];
    DWORD received = 0u;
    if (!ReadFile(pipe, chunk, (DWORD)sizeof(chunk), &received, NULL)) {
      if (GetLastError() == ERROR_BROKEN_PIPE) {
        break;
      }
      free(buffer);
      return 0;
    }
    if (received == 0u) {
      break;
    }
    if (used > SIZE_MAX - (size_t)received) {
      free(buffer);
      return 0;
    }
    if (used + (size_t)received > capacity) {
      size_t next = capacity == 0u ? 4096u : capacity;
      while (next < used + (size_t)received) {
        if (next > SIZE_MAX / 2u) {
          free(buffer);
          return 0;
        }
        next *= 2u;
      }
      {
        uint8_t* grown = (uint8_t*)realloc(buffer, next);
        if (grown == NULL) {
          free(buffer);
          return 0;
        }
        buffer = grown;
        capacity = next;
      }
    }
    memcpy(buffer + used, chunk, received);
    used += (size_t)received;
  }
  *output = buffer;
  *output_bytes = used;
  return 1;
}

typedef enum fixture_cli_case_mode_t {
  FIXTURE_CLI_NORMAL = 0,
  FIXTURE_CLI_TIMEOUT_NEGATIVE = 1,
  FIXTURE_CLI_CLOSE_FAILURE_NEGATIVE = 2
} fixture_cli_case_mode_t;

typedef struct fixture_cli_case_state_t {
  int actual_cleanup_ok;
  int unresolved_ownership;
  int child_exit_confirmed;
  int cleanup_failure_detected;
  int injected_close_failure_detected;
  int original_failure;
  DWORD exit_code;
  char original_reason[160];
  char cleanup_reason[160];
} fixture_cli_case_state_t;

typedef struct fixture_cli_case_result_t {
  int passed;
  int stop_remaining;
  fixture_cli_case_state_t state;
  size_t stdout_length;
  size_t stderr_length;
} fixture_cli_case_result_t;

static void format_reason(char* destination, size_t capacity,
                          const char* reason, DWORD error) {
  if (capacity == 0u) {
    return;
  }
  (void)snprintf(destination, capacity, "%s(error=%lu)", reason,
                 (unsigned long)error);
  destination[capacity - 1u] = '\0';
}

static void record_original_failure(fixture_cli_case_state_t* state,
                                    const char* reason, DWORD error) {
  if (!state->original_failure) {
    state->original_failure = 1;
    format_reason(state->original_reason, sizeof(state->original_reason),
                  reason, error);
  }
}

static void record_cleanup_failure(fixture_cli_case_state_t* state,
                                   const char* reason, DWORD error,
                                   int actual_handle) {
  state->cleanup_failure_detected = 1;
  if (actual_handle) {
    state->actual_cleanup_ok = 0;
    state->unresolved_ownership = 1;
  }
  if (state->cleanup_reason[0] == '\0') {
    format_reason(state->cleanup_reason, sizeof(state->cleanup_reason), reason,
                  error);
  }
}

/* On failure, the slot remains non-NULL so an owned identity is not lost. */
static int close_owned_handle(HANDLE* slot, const char* name,
                              fixture_cli_case_state_t* state, int injected) {
  HANDLE handle;
  DWORD error;

  if (slot == NULL || *slot == NULL) {
    return 1;
  }
  handle = *slot;
  if (!CloseHandle(handle)) {
    error = GetLastError();
    record_cleanup_failure(state, name, error, injected == 0);
    if (injected != 0) {
      state->injected_close_failure_detected = 1;
    }
    return 0;
  }
  *slot = NULL;
  return 1;
}

static int observe_process_exit(HANDLE process, DWORD timeout_ms,
                               DWORD* exit_code,
                               fixture_cli_case_state_t* state,
                               int initial_wait, const char* wait_reason) {
  DWORD wait_status;
  DWORD error;

  wait_status = WaitForSingleObject(process, timeout_ms);
  if (wait_status == WAIT_OBJECT_0) {
    if (!GetExitCodeProcess(process, exit_code)) {
      error = GetLastError();
      if (initial_wait != 0) {
        record_original_failure(state, "exit_code_query_failed", error);
      } else {
        record_cleanup_failure(state, "post_termination_exit_code_query_failed",
                               error, 1);
      }
      return 0;
    }
    state->child_exit_confirmed = 1;
    state->exit_code = *exit_code;
    return 1;
  }
  error = wait_status == WAIT_FAILED ? GetLastError() : WAIT_TIMEOUT;
  if (initial_wait != 0) {
    record_original_failure(state, wait_reason, error);
  } else {
    record_cleanup_failure(state, wait_reason, error, 1);
  }
  return 0;
}

static void terminate_and_confirm(HANDLE process, DWORD* exit_code,
                                  fixture_cli_case_state_t* state) {
  DWORD error;

  if (!TerminateProcess(process, 3u)) {
    error = GetLastError();
    record_cleanup_failure(state, "terminate_process_failed", error, 1);
  }
  if (!state->child_exit_confirmed &&
      !observe_process_exit(process, 60000u, exit_code, state, 0,
                            "post_termination_wait_failed")) {
    state->unresolved_ownership = 1;
  }
}

static void mark_unclosed_actual_handle(HANDLE handle, const char* name,
                                        fixture_cli_case_state_t* state) {
  if (handle != NULL) {
    record_cleanup_failure(state, name, ERROR_INVALID_HANDLE, 1);
  }
}

static int run_case(const wchar_t* executable, const char* label,
                    const uint8_t* input, size_t input_bytes, int extra_arg,
                    fixture_cli_case_mode_t mode,
                    fixture_cli_case_result_t* result) {
  SECURITY_ATTRIBUTES security;
  STARTUPINFOW startup;
  PROCESS_INFORMATION process_info;
  HANDLE child_stdin_read = NULL;
  HANDLE parent_stdin_write = NULL;
  HANDLE parent_stdout_read = NULL;
  HANDLE child_stdout_write = NULL;
  HANDLE parent_stderr_read = NULL;
  HANDLE child_stderr_write = NULL;
  HANDLE injected_close_failure_handle = NULL;
  wchar_t* command_line = NULL;
  size_t command_chars;
  uint8_t* stdout_bytes = NULL;
  uint8_t* stderr_bytes = NULL;
  DWORD written = 0u;
  DWORD exit_code = 0u;
  int output_read_ok = 0;
  int input_write_ok = 1;
  int wait_completed = 0;
  int ok = 0;

  memset(result, 0, sizeof(*result));
  result->state.actual_cleanup_ok = 1;
  memset(&security, 0, sizeof(security));
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;
  memset(&startup, 0, sizeof(startup));
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  memset(&process_info, 0, sizeof(process_info));

  command_chars = wcslen(executable) + (extra_arg ? 16u : 4u);
  command_line = (wchar_t*)calloc(command_chars, sizeof(*command_line));
  if (command_line == NULL) {
    record_original_failure(&result->state, "command_line_allocation_failed",
                            ERROR_NOT_ENOUGH_MEMORY);
    goto cleanup;
  }
  if (extra_arg != 0) {
    if (swprintf(command_line, command_chars, L"\"%ls\" extra", executable) <
        0) {
      record_original_failure(&result->state, "command_line_format_failed",
                              ERROR_INVALID_PARAMETER);
      goto cleanup;
    }
  } else if (swprintf(command_line, command_chars, L"\"%ls\"", executable) <
             0) {
    record_original_failure(&result->state, "command_line_format_failed",
                            ERROR_INVALID_PARAMETER);
    goto cleanup;
  }

  if (!CreatePipe(&child_stdin_read, &parent_stdin_write, &security, 0)) {
    record_original_failure(&result->state, "stdin_pipe_create_failed",
                            GetLastError());
    goto cleanup;
  }
  if (!SetHandleInformation(parent_stdin_write, HANDLE_FLAG_INHERIT, 0)) {
    record_original_failure(&result->state, "stdin_pipe_inherit_failed",
                            GetLastError());
    goto cleanup;
  }
  if (!CreatePipe(&parent_stdout_read, &child_stdout_write, &security, 0)) {
    record_original_failure(&result->state, "stdout_pipe_create_failed",
                            GetLastError());
    goto cleanup;
  }
  if (!SetHandleInformation(parent_stdout_read, HANDLE_FLAG_INHERIT, 0)) {
    record_original_failure(&result->state, "stdout_pipe_inherit_failed",
                            GetLastError());
    goto cleanup;
  }
  if (!CreatePipe(&parent_stderr_read, &child_stderr_write, &security, 0)) {
    record_original_failure(&result->state, "stderr_pipe_create_failed",
                            GetLastError());
    goto cleanup;
  }
  if (!SetHandleInformation(parent_stderr_read, HANDLE_FLAG_INHERIT, 0)) {
    record_original_failure(&result->state, "stderr_pipe_inherit_failed",
                            GetLastError());
    goto cleanup;
  }

  startup.hStdInput = child_stdin_read;
  startup.hStdOutput = child_stdout_write;
  startup.hStdError = child_stderr_write;
  if (!CreateProcessW(NULL, command_line, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                      NULL, NULL, &startup, &process_info)) {
    record_original_failure(&result->state, "create_process_failed",
                            GetLastError());
    goto cleanup;
  }

  (void)close_owned_handle(&child_stdin_read, "child_stdin_close_failed",
                           &result->state, 0);
  (void)close_owned_handle(&child_stdout_write,
                           "child_stdout_close_failed", &result->state, 0);
  (void)close_owned_handle(&child_stderr_write,
                           "child_stderr_close_failed", &result->state, 0);

  if (input_bytes > (size_t)UINT32_MAX) {
    record_original_failure(&result->state, "input_too_large", ERROR_ARITHMETIC_OVERFLOW);
    input_write_ok = 0;
  } else if (input_bytes != 0u &&
             (!WriteFile(parent_stdin_write, input, (DWORD)input_bytes,
                         &written, NULL) || written != (DWORD)input_bytes)) {
    record_original_failure(&result->state, "input_write_failed",
                            GetLastError());
    input_write_ok = 0;
  }

  if (mode != FIXTURE_CLI_TIMEOUT_NEGATIVE || input_write_ok == 0) {
    (void)close_owned_handle(&parent_stdin_write,
                             "parent_stdin_close_failed", &result->state, 0);
  }

  if (process_info.hProcess != NULL) {
    if (input_write_ok == 0) {
      terminate_and_confirm(process_info.hProcess, &exit_code, &result->state);
    } else if (mode == FIXTURE_CLI_TIMEOUT_NEGATIVE) {
      wait_completed = observe_process_exit(
          process_info.hProcess, 0u, &exit_code, &result->state, 1,
          "injected_timeout");
      (void)close_owned_handle(&parent_stdin_write,
                               "parent_stdin_close_failed", &result->state, 0);
      if (!wait_completed) {
        terminate_and_confirm(process_info.hProcess, &exit_code,
                              &result->state);
      }
    } else {
      wait_completed = observe_process_exit(
          process_info.hProcess, 60000u, &exit_code, &result->state, 1,
          "wait_timeout_or_failure");
      if (!wait_completed) {
        terminate_and_confirm(process_info.hProcess, &exit_code,
                              &result->state);
      }
    }
  }

  if (result->state.child_exit_confirmed && child_stdout_write == NULL &&
      child_stderr_write == NULL && parent_stdout_read != NULL &&
      parent_stderr_read != NULL) {
    output_read_ok =
        read_pipe_all(parent_stdout_read, &stdout_bytes,
                      &result->stdout_length) &&
        read_pipe_all(parent_stderr_read, &stderr_bytes,
                      &result->stderr_length);
    if (!output_read_ok) {
      record_original_failure(&result->state, "stdio_read_failed",
                              GetLastError());
    }
  } else if (result->state.child_exit_confirmed) {
    record_cleanup_failure(&result->state, "child_pipe_identity_retained",
                           ERROR_INVALID_HANDLE, 1);
  }

  (void)close_owned_handle(&parent_stdout_read,
                           "parent_stdout_close_failed", &result->state, 0);
  (void)close_owned_handle(&parent_stderr_read,
                           "parent_stderr_close_failed", &result->state, 0);
  (void)close_owned_handle(&parent_stdin_write,
                           "parent_stdin_close_failed", &result->state, 0);

  if (result->state.child_exit_confirmed) {
    (void)close_owned_handle(&process_info.hThread,
                             "process_thread_close_failed", &result->state, 0);
    (void)close_owned_handle(&process_info.hProcess,
                             "process_identity_close_failed", &result->state,
                             0);
  } else {
    mark_unclosed_actual_handle(process_info.hThread,
                                "process_thread_exit_unconfirmed",
                                &result->state);
    mark_unclosed_actual_handle(process_info.hProcess,
                                "process_identity_exit_unconfirmed",
                                &result->state);
  }

  if (mode == FIXTURE_CLI_CLOSE_FAILURE_NEGATIVE) {
    /* Close a real event, then pass its stale handle through the checked-close
       path. The second CloseHandle is a deterministic injected failure and no
       kernel resource remains owned by this test case. */
    injected_close_failure_handle = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (injected_close_failure_handle == NULL) {
      record_original_failure(&result->state, "injected_close_failure_setup",
                              GetLastError());
    } else if (!CloseHandle(injected_close_failure_handle)) {
      record_original_failure(&result->state,
                              "injected_close_failure_setup_close",
                              GetLastError());
    } else {
      (void)close_owned_handle(&injected_close_failure_handle,
                               "injected_close_failure", &result->state, 1);
    }
  }

cleanup:
  if (process_info.hProcess == NULL && process_info.hThread == NULL) {
    (void)close_owned_handle(&child_stdin_read, "child_stdin_close_failed",
                             &result->state, 0);
    (void)close_owned_handle(&child_stdout_write,
                             "child_stdout_close_failed", &result->state, 0);
    (void)close_owned_handle(&child_stderr_write,
                             "child_stderr_close_failed", &result->state, 0);
    (void)close_owned_handle(&parent_stdin_write,
                             "parent_stdin_close_failed", &result->state, 0);
    (void)close_owned_handle(&parent_stdout_read,
                             "parent_stdout_close_failed", &result->state, 0);
    (void)close_owned_handle(&parent_stderr_read,
                             "parent_stderr_close_failed", &result->state, 0);
  }

  if (result->state.child_exit_confirmed == 0) {
    mark_unclosed_actual_handle(process_info.hProcess,
                                "process_identity_exit_unconfirmed",
                                &result->state);
  }
  if (result->state.unresolved_ownership != 0) {
    result->stop_remaining = 1;
  }

  if (mode == FIXTURE_CLI_NORMAL) {
    ok = result->state.original_failure == 0 &&
         result->state.child_exit_confirmed != 0 &&
         result->state.actual_cleanup_ok != 0 &&
         result->state.unresolved_ownership == 0 &&
         output_read_ok != 0 && result->state.cleanup_failure_detected == 0 &&
         result->state.exit_code == 2u && result->stdout_length == 0u &&
         result->stderr_length == 0u;
    printf("CASE %s %s exit=%lu stdout=%zu stderr=%zu child_exit=%s "
           "cleanup=%s failure=%s cleanup_failure=%s\n",
           label, ok ? "PASS" : "FAIL", (unsigned long)result->state.exit_code,
           result->stdout_length, result->stderr_length,
           result->state.child_exit_confirmed != 0 ? "PASS" : "FAIL",
           result->state.actual_cleanup_ok != 0 ? "PASS" : "FAIL",
           result->state.original_failure != 0 ? result->state.original_reason
                                               : "none",
           result->state.cleanup_failure_detected != 0
               ? result->state.cleanup_reason
               : "none");
  } else if (mode == FIXTURE_CLI_TIMEOUT_NEGATIVE) {
    ok = result->state.original_failure != 0 &&
         strstr(result->state.original_reason, "injected_timeout") != NULL &&
         result->state.child_exit_confirmed != 0 &&
         result->state.actual_cleanup_ok != 0 &&
         result->state.unresolved_ownership == 0 && output_read_ok != 0 &&
         result->stdout_length == 0u && result->stderr_length == 0u;
    printf("NEGATIVE_CASE %s %s timeout_detected=%s exit=%lu stdout=%zu "
           "stderr=%zu child_exit=%s cleanup=%s failure=%s\n",
           label, ok ? "PASS" : "FAIL",
           result->state.original_failure != 0 ? "PASS" : "FAIL",
           (unsigned long)result->state.exit_code, result->stdout_length,
           result->stderr_length,
           result->state.child_exit_confirmed != 0 ? "PASS" : "FAIL",
           result->state.actual_cleanup_ok != 0 ? "PASS" : "FAIL",
           result->state.original_failure != 0 ? result->state.original_reason
                                               : "none");
  } else {
    ok = result->state.injected_close_failure_detected != 0 &&
         result->state.child_exit_confirmed != 0 &&
         result->state.actual_cleanup_ok != 0 &&
         result->state.unresolved_ownership == 0 && output_read_ok != 0 &&
         result->stdout_length == 0u && result->stderr_length == 0u;
    result->stop_remaining = 1;
    printf("NEGATIVE_CASE %s %s expected_cleanup_failure=1 detected=%s "
           "actual_cleanup=%s child_exit=%s stop_remaining=1\n",
           label, ok ? "PASS" : "FAIL",
           result->state.injected_close_failure_detected != 0 ? "PASS"
                                                              : "FAIL",
           result->state.actual_cleanup_ok != 0 ? "PASS" : "FAIL",
           result->state.child_exit_confirmed != 0 ? "PASS" : "FAIL");
  }

  free(stdout_bytes);
  free(stderr_bytes);
  free(command_line);
  result->passed = ok;
  return ok;
}

int main(int argc, char** argv) {
  uint8_t request[DM_FIXTURE_REQUEST_BYTES];
  uint8_t mutated[DM_FIXTURE_REQUEST_BYTES + 1u];
  wchar_t* executable = NULL;
  fixture_cli_case_result_t outcome;
  unsigned cases = 0u;
  unsigned failures = 0u;
  unsigned skipped = 0u;

  if (argc != 2) {
    fprintf(stderr, "usage: direct_mask_fixture_cli_test source_executable\n");
    return 2;
  }
  executable = utf8_to_wide(argv[1]);
  if (executable == NULL) {
    return 2;
  }
  memset(request, 0, sizeof(request));
  memcpy(request, DM_FIXTURE_REQUEST_MAGIC, DM_FIXTURE_REQUEST_MAGIC_BYTES);
  store_u64_le(request + DM_FIXTURE_REQUEST_EPOCH_OFFSET,
               DM_FIXTURE_KEY_EPOCH);
  store_u32_le(request + DM_FIXTURE_REQUEST_RETRIES_OFFSET,
               DM_FIXTURE_MAX_FINAL_RETRIES);
  request[DM_FIXTURE_REQUEST_U_OFFSET] = 0xa5u;

#define RUN(label, bytes, length, extra, mode, remaining)                    \
  do {                                                                         \
    ++cases;                                                                   \
    if (!run_case(executable, (label), (bytes), (length), (extra), (mode),    \
                  &outcome)) {                                                \
      ++failures;                                                              \
    }                                                                          \
    if (outcome.stop_remaining != 0) {                                         \
      skipped += (remaining);                                                  \
      printf("STOP remaining_case_loop=1 skipped=%u reason=cleanup_failure_"    \
             "or_unresolved_ownership\n",                                       \
             (remaining));                                                     \
      goto cases_done;                                                         \
    }                                                                          \
  } while (0)

  memcpy(mutated, request, sizeof(request));
  mutated[0] ^= 1u;
  RUN("wrong-magic", mutated, sizeof(request), 0, FIXTURE_CLI_NORMAL, 12u);
  memcpy(mutated, request, sizeof(request));
  memset(mutated + DM_FIXTURE_REQUEST_EPOCH_OFFSET, 0, 8u);
  RUN("epoch-zero", mutated, sizeof(request), 0, FIXTURE_CLI_NORMAL, 11u);
  memcpy(mutated, request, sizeof(request));
  store_u64_le(mutated + DM_FIXTURE_REQUEST_EPOCH_OFFSET, UINT64_C(2));
  RUN("epoch-two", mutated, sizeof(request), 0, FIXTURE_CLI_NORMAL, 10u);
  memcpy(mutated, request, sizeof(request));
  memset(mutated + DM_FIXTURE_REQUEST_RETRIES_OFFSET, 0, 4u);
  RUN("retry-zero", mutated, sizeof(request), 0, FIXTURE_CLI_NORMAL, 9u);
  memcpy(mutated, request, sizeof(request));
  store_u32_le(mutated + DM_FIXTURE_REQUEST_RETRIES_OFFSET, 4095u);
  RUN("retry-other", mutated, sizeof(request), 0, FIXTURE_CLI_NORMAL, 8u);
  memcpy(mutated, request, sizeof(request));
  memset(mutated + DM_FIXTURE_REQUEST_U_OFFSET, 0,
         DM_SOURCE_PROOF_U_BYTES);
  RUN("zero-U", mutated, sizeof(request), 0, FIXTURE_CLI_NORMAL, 7u);
  RUN("short", request, sizeof(request) - 1u, 0, FIXTURE_CLI_NORMAL, 6u);
  memcpy(mutated, request, sizeof(request));
  mutated[sizeof(request)] = 0x5au;
  RUN("extra-byte", mutated, sizeof(request) + 1u, 0, FIXTURE_CLI_NORMAL,
      5u);
  RUN("unexpected-argument", NULL, 0u, 1, FIXTURE_CLI_NORMAL, 4u);
  RUN("argv-count-one-empty-stdin", NULL, 0u, 0, FIXTURE_CLI_NORMAL, 3u);
  RUN("timeout-termination", NULL, 0u, 0, FIXTURE_CLI_TIMEOUT_NEGATIVE, 2u);
  RUN("close-failure", NULL, 0u, 0, FIXTURE_CLI_CLOSE_FAILURE_NEGATIVE,
      1u);

#undef RUN

cases_done:
  free(executable);
  printf("COVERAGE stdio_fault_injection=DEFERRED reason=pipe_fault_seam_not_"
         "injected positive_output=DEFERRED reason=valid_source_producer_"
         "invocation_reserved\n");
  printf("STATUS NON_ACTIVATING_DIRECT_MASK_FIXTURE_CLI cases=%u failures=%u "
         "skipped=%u\n",
         cases, failures, skipped);
  return failures == 0u ? 0 : 1;
}

#else
int main(void) { return 2; }
#endif
