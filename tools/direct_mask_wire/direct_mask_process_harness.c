/* SPDX-License-Identifier: MIT */

/*
 * Windows-only, non-activating process boundary test.  It connects one private source-bound
 * prover to one witness-free verifier through bounded anonymous pipes, retains no proof files,
 * and never forwards child output.  This is an integration lower bound, not a production
 * qualification or a substitute for the repository's formal/privacy gates.
 */

#define WIN32_LEAN_AND_MEAN
#include "direct_mask_wire.h"

#include <windows.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DM_PROCESS_MAX_WALL_MS UINT64_C(60000)
#define DM_PROCESS_MEMORY_LIMIT_BYTES UINT64_C(5368709120)
#define DM_PROCESS_PHYSICAL_RESERVE_BYTES UINT64_C(1073741824)
#define DM_PROCESS_MUTEX_NAME "Local\\BlindLedgerDirectMaskWireHarness"

/*
 * This is the exact state-owned request for the synthetic profile.  It is intentionally a
 * statement-only constant: no root, witness, native materializer, or proof bytes are present.
 */
static const uint8_t dm_independent_request[DM_WIRE_STATEMENT_BYTES] = {
  0x53, 0x42, 0x41, 0x31, 0x2D, 0x53, 0x52, 0x43, 0x2D, 0x43, 0x4D, 0x54, 0x2D, 0x76, 0x31, 0x00,
  0x17, 0x00, 0x00, 0x00, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x2D, 0x6D, 0x61, 0x73, 0x6B, 0x2D,
  0x72, 0x65, 0x6C, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2D, 0x76, 0x31, 0x01, 0x02, 0x03, 0x04, 0x05,
  0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
  0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
  0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
  0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x05, 0x10, 0x1B, 0x26, 0x31,
  0x3C, 0x47, 0x52, 0x5D, 0x68, 0x73, 0x7E, 0x89, 0x94, 0x9F, 0xAA, 0xB5, 0xC0, 0xCB, 0xD6, 0xE1,
  0xEC, 0xF7, 0x02, 0x0D, 0x18, 0x23, 0x2E, 0x39, 0x44, 0x4F, 0x5A, 0x65, 0x70, 0x7B, 0x86, 0x91,
  0x9C, 0xA7, 0xB2, 0xBD, 0xC8, 0xD3, 0xDE, 0xE9, 0xF4, 0xFF, 0x0A, 0x15, 0x20, 0x2B, 0x36, 0x41,
  0x4C, 0x57, 0x62, 0x6D, 0x78, 0x83, 0x8E, 0x99, 0xA4, 0xAF, 0xBA, 0xC5, 0xD0, 0xDB, 0xE6, 0xF1,
  0xFC, 0x07, 0x12, 0x1D, 0x28, 0x33, 0x3E, 0x49, 0x54, 0x5F, 0x6A, 0x75, 0x80, 0x8B, 0x96, 0xA1,
  0xAC, 0xB7, 0xC2, 0xCD, 0xD8, 0xE3, 0xEE, 0xF9, 0x04, 0x0F, 0x1A, 0xFE, 0x97, 0xAD, 0x3F, 0x8A,
  0xA1, 0xFB, 0x87, 0x38, 0x62, 0x9C, 0xD1, 0xCB, 0x73, 0xE3, 0x11, 0xA7, 0x7B, 0xDF, 0xEB, 0x20,
  0xD3, 0x6E, 0x8A, 0x79, 0xF6, 0x6B, 0x06, 0x1C, 0xAF, 0x5A, 0x43, 0xD2, 0x6F, 0x62, 0x28, 0xE8,
  0x22, 0xE3, 0x80, 0x68, 0x7A, 0x93, 0x72, 0x20, 0xBF, 0x95, 0xC3, 0xCE, 0x7E, 0xD5, 0xDF, 0x1F,
  0xDB, 0x47, 0x11, 0x43, 0x77, 0x36, 0x97, 0x0D, 0xA6, 0x01, 0x9A, 0x69, 0x93, 0x63, 0x9C, 0x5D,
  0x2F, 0xD5, 0xEE, 0xB8, 0x16, 0xBC, 0x5E, 0x79, 0x39, 0x88, 0xF8, 0xD0, 0x69, 0x0D, 0x03, 0x9B,
  0xFC, 0x06, 0xF9, 0x11, 0x5F, 0x1C, 0x12, 0x64, 0xD9, 0xE5, 0xA8, 0x50, 0x69, 0x1E, 0x69, 0xFD,
  0x7E, 0x25, 0x2C, 0xF8, 0x92, 0xFE, 0xE2, 0xFE, 0x2B, 0x65, 0x0B, 0xC4, 0x28, 0xD3, 0xE2, 0x2E,
  0xF6, 0x6B, 0x62, 0xBA, 0x24, 0xFA, 0x01, 0x93, 0x85, 0x85, 0xAF, 0xE1, 0xF4, 0x94, 0x3D, 0xE2,
  0x3A, 0xE0, 0x4D, 0x5F, 0x03, 0xE2, 0x09, 0xE8, 0x4E, 0x8D, 0x47, 0x89, 0x72, 0x94, 0xB7, 0x56,
  0xA3, 0xB2, 0x84, 0xE7, 0x22, 0x65, 0x8A, 0xF9, 0x0E, 0x1F, 0x71, 0x58, 0x57, 0x9C, 0x7E, 0xC0,
  0x88, 0x2D, 0xF9, 0x69, 0xC4, 0xA4, 0x30, 0xC0, 0x10, 0xF1, 0x98, 0xED, 0x1B, 0xE2, 0x46, 0xC8,
  0x0C, 0xEE, 0x23, 0xFD, 0x27, 0x07, 0xE8, 0x56, 0x52, 0x55, 0x70, 0xBE, 0xC3, 0xCE, 0x55, 0x7B,
  0xE8, 0x58, 0x58, 0x9D, 0xAA, 0x47, 0xFB, 0xB9, 0x1A, 0x03, 0x87, 0x0A, 0xDF, 0x40, 0x19, 0x39,
  0x23, 0x20, 0xEC, 0xC0, 0x32, 0x17, 0x85, 0x6B, 0xB7, 0x7F, 0xC0, 0xD4, 0xC5, 0xFB, 0x30, 0x4F,
  0x96, 0x16, 0x72, 0x56, 0x12, 0x84, 0x84, 0xF6, 0x60, 0x9B, 0x89, 0x2F, 0x27, 0x55, 0x3F, 0xB5,
  0x26, 0x7D, 0xF5, 0xE1, 0x37, 0xFD, 0x08, 0x82, 0x07, 0x91, 0x01, 0x95, 0x21, 0x03, 0x43, 0x26,
  0x7D, 0x57, 0xCB, 0x2C, 0x32, 0xC3, 0x40, 0xB7, 0x64, 0x6C, 0xD7, 0x33, 0x6B, 0x1C, 0x03, 0x35,
  0xCB, 0x10, 0x35, 0xA2, 0xA8, 0x6B, 0xD0, 0x03, 0x41, 0xEC, 0x18, 0x43, 0xC6, 0xB7, 0x55, 0x35,
  0x92, 0x8C, 0x56, 0xD6, 0x08, 0xFA, 0x5F, 0x06, 0x8F, 0x15, 0x1E, 0x27, 0x17, 0x2D, 0x56, 0x24,
  0xDF, 0x64, 0x3B, 0x25, 0x04, 0x50, 0xF9, 0x35, 0xC3, 0x24, 0x89, 0x06, 0xBB, 0x6D, 0x34, 0x1E,
  0x01, 0x30, 0x01, 0x0D, 0x7F, 0x71, 0xF2, 0x0E, 0x0E, 0x0D, 0x38, 0x99, 0x1C, 0xC9, 0x38, 0x3B,
  0x3C, 0x04, 0x90, 0xF7, 0x2F, 0x56, 0x98, 0x29, 0x7A, 0x96, 0x93, 0xC3, 0xC4, 0x05, 0x4C, 0x44,
  0x55, 0x6B, 0x23, 0xBA, 0x05, 0xE9, 0x83, 0xF5, 0x03, 0xAB, 0x2E, 0xD6, 0x21, 0xCE, 0x12, 0xB1,
  0xCB, 0x4B, 0x11, 0x0D, 0x1A, 0x99, 0x1A, 0xBA, 0x14, 0x4D, 0x09, 0xCF, 0x59, 0x50, 0x59, 0x07,
  0x91, 0x99, 0xC6, 0xF1, 0x11, 0x91, 0x45, 0xF1, 0x73, 0x6F, 0xC4, 0x46, 0x4E, 0x04, 0x75, 0xBB,
  0x08, 0x44, 0x10, 0xCE, 0xEC, 0xC5, 0xE0, 0x5F, 0x8C, 0xEC, 0xE2, 0x01, 0xF3, 0x0D, 0x66, 0x0F,
  0xBE, 0x9C, 0x9A, 0xE9, 0xEF, 0x3A, 0x83, 0xD0, 0xB5, 0x6B, 0x12, 0xAA, 0xF2, 0xF3, 0x17, 0x14,
  0x32, 0x78, 0x9C, 0x47, 0xBF, 0xD4, 0xF6, 0x47, 0x5F, 0xA3, 0x39, 0x44, 0x45, 0x43, 0x70, 0x39,
  0x54, 0x01, 0xFD, 0x78, 0x4E, 0x24, 0xC7, 0x13, 0x36, 0xC0, 0xA0, 0x36, 0x59, 0xCA, 0xD5, 0x33,
  0x69, 0xEE, 0xAE, 0xEE, 0x5C, 0x1E, 0xA5, 0xD9, 0x93, 0x9D, 0x0E, 0x64, 0xC4, 0x2F, 0xE9, 0x28,
  0x95, 0x5A, 0x1B, 0xB3, 0x5B, 0x60, 0xB9, 0x57, 0x82, 0xE3, 0x7F, 0xF8, 0xA8, 0xDC, 0xD6, 0xF7,
  0x9A, 0x3F, 0x5E, 0xA5, 0x21, 0xDA, 0x2F, 0x48, 0xFC, 0xB1, 0xD0, 0x21, 0x86, 0x88, 0x98, 0xFE,
  0x16, 0x49, 0x01, 0xBE, 0x12, 0x15, 0x66, 0x7F, 0x27, 0x0B, 0xE1, 0x38, 0xFE, 0x2F, 0x80, 0x8E,
  0x65, 0x15, 0x7C, 0x6E, 0x7D, 0xD2, 0xDB, 0x4C, 0x05, 0x04, 0x5E, 0x9D, 0xFE, 0x39, 0x30, 0x72,
  0x73, 0x8F, 0x9E, 0x2E, 0x7C, 0xCD, 0x79, 0x0F, 0xC1, 0xAC, 0xF9, 0x5C, 0x0F, 0x23, 0x8F, 0x35,
  0xE0, 0x6C, 0x82, 0x11, 0xF4, 0x32, 0x9E, 0x1D, 0x47, 0xCD, 0x36, 0xC2, 0x4F, 0x59, 0x18, 0xCB,
  0x23, 0xA0, 0xE8, 0x59, 0x95, 0x27, 0x2F, 0xCA, 0x2F, 0x97, 0x8F, 0x0F, 0x66, 0x94, 0xCC, 0x11,
  0x26, 0xD2, 0xB4, 0xDC, 0x8A, 0xFC, 0xB5, 0x37, 0x1B, 0xCD, 0x2E, 0x2E, 0x99, 0xD8, 0x65, 0x8F,
  0x63, 0xA1, 0xF1, 0xCD, 0x1B, 0x17, 0xD6, 0x72, 0xC9, 0x07, 0x28, 0x7B, 0xE8, 0x15, 0x28, 0x58,
  0x7E, 0xEF, 0x21, 0xFD, 0xF0, 0x35, 0x28, 0xA1, 0x3B, 0x7D, 0x78, 0x7D, 0x01, 0x20, 0x4C, 0x36,
  0x16, 0x82, 0x1D, 0x71, 0xB0, 0xA4, 0xCE, 0x1F, 0x9D, 0x8C, 0xFE, 0x7C, 0x18, 0x06, 0x0B, 0x4A,
  0x8B, 0xEA, 0x35, 0x23, 0x18, 0x1E, 0xF8, 0xE6, 0x19, 0x96, 0xE3, 0x10, 0x6D, 0x19, 0x1D, 0xAF,
  0x0D, 0xF6, 0x75, 0x79, 0xE0, 0xDE, 0xE6, 0xF0, 0x0D, 0x90, 0x1B, 0x1F, 0xF1, 0x42, 0xC9, 0xCB,
  0xD5, 0x3C, 0x0B, 0x38, 0xD0, 0x5B, 0xC4, 0xCF, 0x0F, 0x3C, 0xCD, 0x82, 0x0B, 0xC2, 0x0E, 0xD0,
  0x8B, 0xD8, 0xA6, 0x00, 0xCC, 0x67, 0x3E, 0x6E, 0x58, 0x61, 0x5D, 0x72, 0x3B, 0xA9, 0x6D, 0x71,
  0x1B, 0x32, 0x53, 0x5D, 0x92, 0x0E, 0xA5, 0x85, 0xDF, 0xC1, 0x0B, 0xF3, 0x04, 0xEC, 0xFE, 0x10,
  0xB5, 0x9D, 0x89, 0x38, 0xD8, 0x20, 0xE0, 0x5A, 0x67, 0xE2, 0xB0, 0x5D, 0xE7, 0x59, 0x9B, 0x36,
  0x50, 0xF3, 0xC4, 0xF3, 0xF6, 0x83, 0x84, 0xA3, 0xDE, 0x62, 0x93, 0xEC, 0x61, 0xC0, 0xC9, 0x47,
  0x82, 0x3E, 0x16, 0x88, 0xE2, 0x50, 0xA1, 0x4D, 0x8F, 0xCF, 0x7C, 0xD8, 0xFD, 0x46, 0x71, 0x1E,
  0xE7, 0x72, 0x27, 0xE0, 0x9E, 0x36, 0xD4, 0xF3, 0xE6, 0x73, 0x19, 0x87, 0x08, 0x8C, 0xF6, 0xA5,
  0xBE, 0x43, 0x84, 0x9B, 0x6D, 0x33, 0x36, 0xDC, 0x60, 0xBC, 0x13, 0x7B, 0x2E, 0x07, 0x00, 0x92,
  0x67, 0x23, 0x07, 0xC9, 0x8B, 0xFC, 0x4C, 0x90, 0xED, 0xFD, 0x26, 0x27, 0x67, 0xF7, 0x1D, 0xA0,
  0x35, 0x96, 0x58, 0x4B, 0x2F, 0xCE, 0x60, 0x1E, 0x97, 0xF8, 0xDA, 0x01, 0xD7, 0x3B, 0x5E, 0x00,
  0xEA, 0xEE, 0x6D, 0x3A, 0x45, 0x95, 0x1E, 0x24, 0x17, 0x12, 0xDD, 0xD7, 0x4F, 0xE3, 0x7C, 0x9A,
  0x84, 0x0F, 0x1E, 0x8A, 0xBE, 0x13, 0x00, 0x42, 0xBA, 0xE6, 0xE4, 0x81, 0xEB, 0x52, 0x22, 0x8E,
  0x01, 0xE4, 0x9D, 0x11, 0xEC, 0x5C, 0xCF, 0x55, 0x4F, 0x00, 0xC5, 0x00, 0x01, 0x00, 0x00, 0x03,
  0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0xE5,
  0x00, 0x00, 0x00, 0x78, 0xE8, 0x01, 0x00, 0xC8, 0xA0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
  0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
};

typedef struct dm_process_result_t {
  DWORD exit_code;
  size_t output_bytes;
  uint64_t user_ns;
  uint64_t kernel_ns;
  uint64_t wall_ns;
  uint64_t peak_tree_bytes;
  uint64_t total_tree_processes;
  int launched;
  int timed_out;
  int output_limited;
  int timer_error;
  int io_error;
  int resource_error;
  int whole_tree_accounting;
} dm_process_result_t;

typedef struct dm_spawn_t {
  PROCESS_INFORMATION process;
  HANDLE job;
  HANDLE parent_input;
  HANDLE parent_output;
} dm_spawn_t;

static void secure_clear(void* pointer, size_t bytes) {
  if (pointer == NULL) {
    return;
  }
  volatile uint8_t* cursor = (volatile uint8_t*)pointer;
  while (bytes-- != 0) {
    *cursor++ = 0;
  }
}

static int qpc_now(uint64_t* output) {
  LARGE_INTEGER frequency;
  LARGE_INTEGER counter;
  if (output == NULL || !QueryPerformanceFrequency(&frequency) ||
      !QueryPerformanceCounter(&counter) || frequency.QuadPart <= 0 || counter.QuadPart < 0) {
    return 0;
  }
  const uint64_t ticks = (uint64_t)counter.QuadPart;
  const uint64_t per_second = (uint64_t)frequency.QuadPart;
  const uint64_t seconds = ticks / per_second;
  const uint64_t remainder = ticks % per_second;
  if (seconds > UINT64_MAX / UINT64_C(1000000000)) {
    return 0;
  }
  const uint64_t whole = seconds * UINT64_C(1000000000);
  const uint64_t fractional =
      (uint64_t)((long double)remainder * 1000000000.0L / (long double)per_second);
  if (fractional > UINT64_MAX - whole) {
    return 0;
  }
  *output = whole + fractional;
  return 1;
}

static uint64_t filetime_ns(const FILETIME* value) {
  ULARGE_INTEGER ticks;
  ticks.LowPart = value->dwLowDateTime;
  ticks.HighPart = value->dwHighDateTime;
  return ticks.QuadPart > UINT64_MAX / 100u ? UINT64_MAX : ticks.QuadPart * 100u;
}

static uint64_t large_integer_ns(const LARGE_INTEGER* value) {
  if (value == NULL || value->QuadPart < 0) {
    return 0;
  }
  const uint64_t ticks = (uint64_t)value->QuadPart;
  return ticks > UINT64_MAX / 100u ? UINT64_MAX : ticks * 100u;
}

static void close_handle(HANDLE* handle) {
  if (handle != NULL && *handle != NULL && *handle != INVALID_HANDLE_VALUE) {
    CloseHandle(*handle);
    *handle = NULL;
  }
}

static void clear_spawn(dm_spawn_t* spawn) {
  if (spawn == NULL) {
    return;
  }
  close_handle(&spawn->parent_input);
  close_handle(&spawn->parent_output);
  close_handle(&spawn->process.hThread);
  close_handle(&spawn->process.hProcess);
  close_handle(&spawn->job);
  memset(spawn, 0, sizeof(*spawn));
}

static HANDLE make_job(void) {
  HANDLE job = CreateJobObjectA(NULL, NULL);
  if (job == NULL) {
    return NULL;
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
  memset(&limits, 0, sizeof(limits));
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                            JOB_OBJECT_LIMIT_JOB_MEMORY;
  limits.JobMemoryLimit = (SIZE_T)DM_PROCESS_MEMORY_LIMIT_BYTES;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
    close_handle(&job);
    return NULL;
  }
  return job;
}

static int make_command_line(char* output, size_t capacity, const char* program, const char* argument) {
  if (output == NULL || capacity == 0 || program == NULL || strchr(program, '"') != NULL) {
    return 0;
  }
  const int written = argument == NULL
                          ? _snprintf_s(output, capacity, _TRUNCATE, "\"%s\"", program)
                          : _snprintf_s(output, capacity, _TRUNCATE, "\"%s\" %s", program, argument);
  return written >= 0 && (size_t)written < capacity;
}

static int initialize_handle_list(STARTUPINFOEXA* startup, HANDLE handles[3],
                                  void** attribute_storage) {
  if (startup == NULL || handles == NULL || attribute_storage == NULL) {
    return 0;
  }
  SIZE_T attribute_bytes = 0;
  InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_bytes);
  if (attribute_bytes == 0) {
    return 0;
  }
  void* storage = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attribute_bytes);
  if (storage == NULL ||
      !InitializeProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)storage, 1, 0,
                                          &attribute_bytes) ||
      !UpdateProcThreadAttribute((LPPROC_THREAD_ATTRIBUTE_LIST)storage, 0,
                                 PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles,
                                 3u * sizeof(handles[0]), NULL, NULL)) {
    if (storage != NULL) {
      HeapFree(GetProcessHeap(), 0, storage);
    }
    return 0;
  }
  startup->lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)storage;
  *attribute_storage = storage;
  return 1;
}

static void destroy_handle_list(void* attribute_storage) {
  if (attribute_storage != NULL) {
    DeleteProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)attribute_storage);
    HeapFree(GetProcessHeap(), 0, attribute_storage);
  }
}

static int spawn_process(const char* program, const char* argument, int capture_output,
                         dm_spawn_t* spawn) {
  if (program == NULL || spawn == NULL) {
    return 0;
  }
  memset(spawn, 0, sizeof(*spawn));
  HANDLE child_input = NULL;
  HANDLE child_output = NULL;
  HANDLE child_error = NULL;
  HANDLE parent_input = NULL;
  HANDLE parent_output = NULL;
  HANDLE nul_error = NULL;
  SECURITY_ATTRIBUTES security = {sizeof(security), NULL, TRUE};
  if (capture_output) {
    if (!CreatePipe(&parent_output, &child_output, &security, 0) ||
        !SetHandleInformation(parent_output, HANDLE_FLAG_INHERIT, 0)) {
      close_handle(&parent_output);
      close_handle(&child_output);
      return 0;
    }
  } else {
    if (!CreatePipe(&child_input, &parent_input, &security, 0) ||
        !SetHandleInformation(parent_input, HANDLE_FLAG_INHERIT, 0)) {
      close_handle(&child_input);
      close_handle(&parent_input);
      return 0;
    }
  }
  SECURITY_ATTRIBUTES nul_security = {sizeof(nul_security), NULL, TRUE};
  HANDLE nul_read = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &nul_security, OPEN_EXISTING, 0, NULL);
  HANDLE nul_write = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 &nul_security, OPEN_EXISTING, 0, NULL);
  if (!capture_output) {
    nul_error = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            &nul_security, OPEN_EXISTING, 0, NULL);
  }
  if (nul_read == INVALID_HANDLE_VALUE || nul_write == INVALID_HANDLE_VALUE ||
      (!capture_output && nul_error == INVALID_HANDLE_VALUE)) {
    close_handle(&nul_read);
    close_handle(&nul_write);
    close_handle(&nul_error);
    close_handle(&child_input);
    close_handle(&child_output);
    close_handle(&parent_input);
    close_handle(&parent_output);
    return 0;
  }
  if (capture_output) {
    child_input = nul_read;
    nul_read = NULL;
    child_error = nul_write;
    nul_write = NULL;
  } else {
    child_output = nul_write;
    nul_write = NULL;
    child_error = nul_error;
    nul_error = NULL;
    close_handle(&nul_read);
  }
  HANDLE handle_list[3] = {child_input, child_output, child_error};
  for (size_t index = 0; index != 3u; ++index) {
    if (handle_list[index] == NULL || handle_list[index] == INVALID_HANDLE_VALUE) {
      close_handle(&nul_read);
      close_handle(&nul_write);
      close_handle(&nul_error);
      close_handle(&child_input);
      close_handle(&child_output);
      close_handle(&child_error);
      close_handle(&parent_input);
      close_handle(&parent_output);
      return 0;
    }
  }
  HANDLE job = make_job();
  if (job == NULL) {
    close_handle(&nul_read);
    close_handle(&nul_write);
    close_handle(&nul_error);
    close_handle(&child_input);
    close_handle(&child_output);
    close_handle(&child_error);
    close_handle(&parent_input);
    close_handle(&parent_output);
    return 0;
  }
  char command[32768];
  if (!make_command_line(command, sizeof(command), program, argument)) {
    close_handle(&job);
    close_handle(&nul_read);
    close_handle(&nul_write);
    close_handle(&nul_error);
    close_handle(&child_input);
    close_handle(&child_output);
    close_handle(&child_error);
    close_handle(&parent_input);
    close_handle(&parent_output);
    return 0;
  }
  STARTUPINFOEXA startup;
  PROCESS_INFORMATION process;
  memset(&startup, 0, sizeof(startup));
  memset(&process, 0, sizeof(process));
  startup.StartupInfo.cb = sizeof(startup.StartupInfo);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = child_input;
  startup.StartupInfo.hStdOutput = child_output;
  startup.StartupInfo.hStdError = child_error;
  void* attribute_storage = NULL;
  if (!initialize_handle_list(&startup, handle_list, &attribute_storage)) {
    close_handle(&job);
    close_handle(&nul_read);
    close_handle(&nul_write);
    close_handle(&nul_error);
    close_handle(&child_input);
    close_handle(&child_output);
    close_handle(&child_error);
    close_handle(&parent_input);
    close_handle(&parent_output);
    return 0;
  }
  const BOOL created = CreateProcessA(NULL, command, NULL, NULL, TRUE,
                                      EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
                                      NULL, NULL, &startup.StartupInfo, &process);
  destroy_handle_list(attribute_storage);
  close_handle(&nul_read);
  close_handle(&nul_write);
  close_handle(&nul_error);
  close_handle(&child_input);
  close_handle(&child_output);
  close_handle(&child_error);
  if (!created) {
    close_handle(&job);
    close_handle(&parent_input);
    close_handle(&parent_output);
    return 0;
  }
  if (!AssignProcessToJobObject(job, process.hProcess)) {
    TerminateProcess(process.hProcess, 4);
    WaitForSingleObject(process.hProcess, 30000);
    close_handle(&process.hThread);
    close_handle(&process.hProcess);
    close_handle(&job);
    close_handle(&parent_input);
    close_handle(&parent_output);
    return 0;
  }
  if (ResumeThread(process.hThread) == (DWORD)-1) {
    TerminateJobObject(job, 5);
    WaitForSingleObject(process.hProcess, 30000);
    close_handle(&process.hThread);
    close_handle(&process.hProcess);
    close_handle(&job);
    close_handle(&parent_input);
    close_handle(&parent_output);
    return 0;
  }
  spawn->process = process;
  spawn->job = job;
  spawn->parent_input = parent_input;
  spawn->parent_output = parent_output;
  return 1;
}

static void terminate_spawn(dm_spawn_t* spawn, DWORD code) {
  if (spawn == NULL || spawn->process.hProcess == NULL) {
    return;
  }
  if (spawn->job != NULL && !TerminateJobObject(spawn->job, code)) {
    TerminateProcess(spawn->process.hProcess, code);
  }
  WaitForSingleObject(spawn->process.hProcess, 30000);
}

static void collect_metrics(dm_spawn_t* spawn, uint64_t start_ns, dm_process_result_t* result) {
  if (spawn == NULL || result == NULL) {
    return;
  }
  FILETIME creation_time;
  FILETIME exit_time;
  FILETIME kernel_time;
  FILETIME user_time;
  memset(&creation_time, 0, sizeof(creation_time));
  memset(&exit_time, 0, sizeof(exit_time));
  memset(&kernel_time, 0, sizeof(kernel_time));
  memset(&user_time, 0, sizeof(user_time));
  if (!GetProcessTimes(spawn->process.hProcess, &creation_time, &exit_time, &kernel_time,
                       &user_time)) {
    result->resource_error = 1;
  } else {
    result->user_ns = filetime_ns(&user_time);
    result->kernel_ns = filetime_ns(&kernel_time);
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION usage;
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
  memset(&usage, 0, sizeof(usage));
  memset(&accounting, 0, sizeof(accounting));
  const BOOL have_usage = QueryInformationJobObject(spawn->job, JobObjectExtendedLimitInformation,
                                                    &usage, sizeof(usage), NULL);
  const BOOL have_accounting = QueryInformationJobObject(
      spawn->job, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), NULL);
  if (!have_usage || !have_accounting) {
    result->resource_error = 1;
  } else {
    result->peak_tree_bytes = (uint64_t)usage.PeakJobMemoryUsed;
    result->total_tree_processes = accounting.TotalProcesses;
    result->user_ns = large_integer_ns(&accounting.TotalUserTime);
    result->kernel_ns = large_integer_ns(&accounting.TotalKernelTime);
    result->whole_tree_accounting = 1;
  }
  DWORD exit_code = 1;
  if (!GetExitCodeProcess(spawn->process.hProcess, &exit_code)) {
    result->resource_error = 1;
  }
  result->exit_code = exit_code;
  uint64_t end_ns = 0;
  if (!qpc_now(&end_ns) || end_ns < start_ns) {
    result->timer_error = 1;
  } else {
    result->wall_ns = end_ns - start_ns;
  }
}

static int monitor_process(dm_spawn_t* spawn, uint64_t start_ns, uint8_t* output,
                           size_t output_capacity, dm_process_result_t* result) {
  if (spawn == NULL || result == NULL) {
    return 0;
  }
  size_t captured = 0;
  int finished = 0;
  while (!finished) {
    const DWORD wait_status = WaitForSingleObject(spawn->process.hProcess, 0);
    if (wait_status == WAIT_FAILED) {
      result->io_error = 1;
      terminate_spawn(spawn, 6);
      break;
    }
    if (spawn->parent_output != NULL) {
      DWORD available = 0;
      if (!PeekNamedPipe(spawn->parent_output, NULL, 0, NULL, &available, NULL)) {
        if (wait_status == WAIT_OBJECT_0) {
          finished = 1;
          break;
        }
        result->io_error = 1;
        terminate_spawn(spawn, 7);
        break;
      }
      if (available != 0) {
        if ((size_t)available > output_capacity - captured || output == NULL) {
          result->output_limited = 1;
          terminate_spawn(spawn, 8);
          break;
        }
        DWORD received = 0;
        if (!ReadFile(spawn->parent_output, output + captured, available, &received, NULL) ||
            received == 0) {
          result->io_error = 1;
          terminate_spawn(spawn, 9);
          break;
        }
        captured += received;
        continue;
      }
    }
    if (wait_status == WAIT_OBJECT_0) {
      finished = 1;
      break;
    }
    uint64_t now_ns = 0;
    if (!qpc_now(&now_ns) || now_ns < start_ns) {
      result->timer_error = 1;
      terminate_spawn(spawn, 10);
      break;
    }
    if (now_ns - start_ns > DM_PROCESS_MAX_WALL_MS * UINT64_C(1000000)) {
      result->timed_out = 1;
      terminate_spawn(spawn, 11);
      break;
    }
    Sleep(10);
  }
  if (spawn->parent_output != NULL && !result->output_limited && !result->io_error) {
    for (;;) {
      DWORD available = 0;
      if (!PeekNamedPipe(spawn->parent_output, NULL, 0, NULL, &available, NULL)) {
        break;
      }
      if (available == 0) {
        break;
      }
      if ((size_t)available > output_capacity - captured || output == NULL) {
        result->output_limited = 1;
        break;
      }
      DWORD received = 0;
      if (!ReadFile(spawn->parent_output, output + captured, available, &received, NULL) ||
          received == 0) {
        result->io_error = 1;
        break;
      }
      captured += received;
    }
  }
  result->output_bytes = captured;
  collect_metrics(spawn, start_ns, result);
  return 1;
}

static int run_process_capture(const char* program, const char* argument, uint8_t* output,
                               size_t output_capacity, dm_process_result_t* result) {
  if (result == NULL) {
    return 0;
  }
  memset(result, 0, sizeof(*result));
  result->exit_code = UINT32_MAX;
  uint64_t start_ns = 0;
  if (!qpc_now(&start_ns)) {
    result->timer_error = 1;
    return 0;
  }
  dm_spawn_t spawn;
  if (!spawn_process(program, argument, 1, &spawn)) {
    return 0;
  }
  result->launched = 1;
  const int monitored = monitor_process(&spawn, start_ns, output, output_capacity, result);
  clear_spawn(&spawn);
  return monitored;
}

static int write_all_pipe(HANDLE pipe, const uint8_t* input, size_t length) {
  if (pipe == NULL || input == NULL || length == 0) {
    return 0;
  }
  while (length != 0) {
    const DWORD chunk = length > UINT32_MAX ? UINT32_MAX : (DWORD)length;
    DWORD written = 0;
    if (!WriteFile(pipe, input, chunk, &written, NULL) || written == 0) {
      return 0;
    }
    input += written;
    length -= written;
  }
  return 1;
}

typedef struct dm_pipe_writer_t {
  HANDLE pipe;
  const uint8_t* input;
  size_t input_length;
  int success;
} dm_pipe_writer_t;

static DWORD WINAPI write_pipe_thread(void* parameter) {
  dm_pipe_writer_t* writer = (dm_pipe_writer_t*)parameter;
  if (writer == NULL) {
    return 1;
  }
  writer->success = write_all_pipe(writer->pipe, writer->input, writer->input_length);
  return writer->success ? 0 : 1;
}

static int wait_for_pipe_writer(dm_spawn_t* spawn, dm_pipe_writer_t* writer,
                                HANDLE writer_thread, uint64_t start_ns,
                                dm_process_result_t* result) {
  if (spawn == NULL || writer == NULL || writer_thread == NULL || result == NULL) {
    return 0;
  }
  int writer_finished = 0;
  int process_finished = 0;
  while (!writer_finished && !process_finished) {
    const DWORD writer_wait = WaitForSingleObject(writer_thread, 0);
    if (writer_wait == WAIT_OBJECT_0) {
      writer_finished = 1;
      break;
    }
    if (writer_wait == WAIT_FAILED) {
      result->resource_error = 1;
      break;
    }
    const DWORD process_wait = WaitForSingleObject(spawn->process.hProcess, 0);
    if (process_wait == WAIT_OBJECT_0) {
      process_finished = 1;
      result->io_error = 1;
      break;
    }
    if (process_wait == WAIT_FAILED) {
      result->io_error = 1;
      break;
    }
    uint64_t now_ns = 0;
    if (!qpc_now(&now_ns) || now_ns < start_ns) {
      result->timer_error = 1;
      break;
    }
    if (now_ns - start_ns > DM_PROCESS_MAX_WALL_MS * UINT64_C(1000000)) {
      result->timed_out = 1;
      break;
    }
    Sleep(10);
  }
  if (!writer_finished) {
    terminate_spawn(spawn, 12);
    CancelSynchronousIo(writer_thread);
    close_handle(&spawn->parent_input);
    if (WaitForSingleObject(writer_thread, 30000) != WAIT_OBJECT_0) {
      result->resource_error = 1;
      /* The writer owns no process state and is blocked only in the bounded pipe write.  If the
       * documented synchronous-I/O cancellation did not stop it, terminate this test helper
       * before its stack context goes out of scope. */
      TerminateThread(writer_thread, 15);
      if (WaitForSingleObject(writer_thread, 30000) != WAIT_OBJECT_0) {
        result->resource_error = 1;
      }
    }
    return 0;
  }
  close_handle(&spawn->parent_input);
  if (!writer->success) {
    result->io_error = 1;
    terminate_spawn(spawn, 13);
    return 0;
  }
  return 1;
}

static int run_process_input(const char* program, const uint8_t* input, size_t input_length,
                             dm_process_result_t* result) {
  if (result == NULL || input == NULL || input_length == 0) {
    return 0;
  }
  memset(result, 0, sizeof(*result));
  result->exit_code = UINT32_MAX;
  uint64_t start_ns = 0;
  if (!qpc_now(&start_ns)) {
    result->timer_error = 1;
    return 0;
  }
  dm_spawn_t spawn;
  if (!spawn_process(program, NULL, 0, &spawn)) {
    return 0;
  }
  result->launched = 1;
  dm_pipe_writer_t writer = {spawn.parent_input, input, input_length, 0};
  HANDLE writer_thread = CreateThread(NULL, 0, write_pipe_thread, &writer, 0, NULL);
  if (writer_thread == NULL) {
    result->resource_error = 1;
    terminate_spawn(&spawn, 14);
    close_handle(&spawn.parent_input);
    const int monitored = monitor_process(&spawn, start_ns, NULL, 0, result);
    clear_spawn(&spawn);
    (void)monitored;
    return 0;
  }
  const int input_ok = wait_for_pipe_writer(&spawn, &writer, writer_thread, start_ns, result);
  close_handle(&writer_thread);
  const int monitored = monitor_process(&spawn, start_ns, NULL, 0, result);
  clear_spawn(&spawn);
  return monitored && input_ok;
}

static void print_process_result(const char* role, const dm_process_result_t* result) {
  printf("PROCESS_ROLE role=%s launch=%s exit_code=%lu timed_out=%s output_limited=%s "
         "timer_error=%s io_error=%s resource_error=%s output_bytes=%zu user_ns=%" PRIu64
         " kernel_ns=%" PRIu64 " wall_ns=%" PRIu64 " peak_tree_bytes=%" PRIu64
         " memory_limit_bytes=%" PRIu64 " total_tree_processes=%" PRIu64
         " whole_tree_accounting=%s\n",
         role, result->launched ? "true" : "false", (unsigned long)result->exit_code,
         result->timed_out ? "true" : "false", result->output_limited ? "true" : "false",
         result->timer_error ? "true" : "false", result->io_error ? "true" : "false",
         result->resource_error ? "true" : "false", result->output_bytes, result->user_ns,
         result->kernel_ns, result->wall_ns, result->peak_tree_bytes,
         DM_PROCESS_MEMORY_LIMIT_BYTES, result->total_tree_processes,
         result->whole_tree_accounting ? "true" : "false");
}

typedef enum dm_case_kind_t {
  DM_CASE_SHORT,
  DM_CASE_EXTRA,
  DM_CASE_HEADER,
  DM_CASE_X,
  DM_CASE_CONTEXT,
  DM_CASE_NU,
  DM_CASE_BODY,
  DM_CASE_DEGREE,
  DM_CASE_DIM,
  DM_CASE_REPLAY,
} dm_case_kind_t;

enum {
  DM_PROCESS_VERIFIER_EXIT_IO = 20,
  DM_PROCESS_VERIFIER_EXIT_EXTRA = 21,
  DM_PROCESS_VERIFIER_EXIT_DECODE = 23,
  DM_PROCESS_VERIFIER_EXIT_VERIFY = 24,
};

typedef struct dm_negative_case_t {
  const char* name;
  dm_case_kind_t kind;
  DWORD expected_exit_code;
} dm_negative_case_t;

static void make_case_input(uint8_t* output, size_t* output_length, const uint8_t* payload,
                            dm_case_kind_t kind) {
  memcpy(output, payload, DM_WIRE_STATEMENT_BYTES + DM_WIRE_FRAME_BYTES);
  *output_length = DM_WIRE_STATEMENT_BYTES + DM_WIRE_FRAME_BYTES;
  const size_t frame = DM_WIRE_STATEMENT_BYTES;
  switch (kind) {
    case DM_CASE_SHORT:
      *output_length -= 1u;
      break;
    case DM_CASE_EXTRA:
      output[*output_length] = 0;
      ++*output_length;
      break;
    case DM_CASE_HEADER:
      output[frame] ^= 0x80u;
      break;
    case DM_CASE_X:
      output[frame + DM_WIRE_HEADER_BYTES] ^= 1u;
      break;
    case DM_CASE_CONTEXT:
      output[DM_WIRE_SOURCE_SUITE_BYTES + 4u + DM_WIRE_RELATION_ID_BYTES] ^= 1u;
      break;
    case DM_CASE_NU:
      output[frame + DM_WIRE_HEADER_BYTES + DM_WIRE_STATEMENT_BYTES] ^= 1u;
      break;
    case DM_CASE_BODY:
      output[frame + DM_WIRE_HEADER_BYTES + DM_WIRE_STATEMENT_BYTES + DM_WIRE_NU_BYTES +
             DM_WIRE_NONCE_COUNT * DM_WIRE_NONCE_BYTES + DM_WIRE_M1_BYTES] ^= 1u;
      break;
    case DM_CASE_DEGREE:
      output[frame + 16u] = 2u;
      break;
    case DM_CASE_DIM:
      output[frame + 20u] ^= 1u;
      break;
    case DM_CASE_REPLAY:
      output[DM_WIRE_SOURCE_SUITE_BYTES + 4u + DM_WIRE_RELATION_ID_BYTES +
             DM_WIRE_CONTEXT_BYTES] ^= 1u;
      break;
  }
}

static int acceptable_runtime(const dm_process_result_t* result) {
  return result != NULL && result->launched && !result->timed_out && !result->output_limited &&
         !result->timer_error && !result->io_error && !result->resource_error &&
         result->whole_tree_accounting;
}

int main(int argc, char** argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: direct_mask_process_harness prover verifier\n");
    return 2;
  }
  MEMORYSTATUSEX memory;
  memset(&memory, 0, sizeof(memory));
  memory.dwLength = sizeof(memory);
  if (!GlobalMemoryStatusEx(&memory) ||
      memory.ullAvailPhys < DM_PROCESS_PHYSICAL_RESERVE_BYTES) {
    printf("PROCESS_SETUP status=resource_reserve_failed required_bytes=%" PRIu64 "\n",
           DM_PROCESS_PHYSICAL_RESERVE_BYTES);
    return 2;
  }
  HANDLE mutex = CreateMutexA(NULL, FALSE, DM_PROCESS_MUTEX_NAME);
  if (mutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
    printf("PROCESS_SETUP status=mutex_unavailable\n");
    close_handle(&mutex);
    return 2;
  }

  const size_t payload_bytes = DM_WIRE_STATEMENT_BYTES + DM_WIRE_FRAME_BYTES;
  uint64_t combined_start = 0;
  const int combined_timer_start = qpc_now(&combined_start);
  dm_process_result_t prover_result;
  dm_process_result_t verifier_result;
  memset(&prover_result, 0, sizeof(prover_result));
  memset(&verifier_result, 0, sizeof(verifier_result));
  prover_result.exit_code = UINT32_MAX;
  verifier_result.exit_code = UINT32_MAX;
  uint8_t* payload = (uint8_t*)calloc(payload_bytes + 1u, 1);
  uint8_t* case_input = (uint8_t*)calloc(payload_bytes + 1u, 1);
  int passed = combined_timer_start && payload != NULL && case_input != NULL;
  int cleanup_ok = 0;
  if (!passed) {
    printf("PROCESS_SETUP status=allocation_failed\n");
    goto cleanup;
  }

  if (!run_process_capture(argv[1], NULL, payload, payload_bytes + 1u, &prover_result)) {
    passed = 0;
  }
  print_process_result("prover", &prover_result);
  if (!acceptable_runtime(&prover_result) || prover_result.exit_code != 0 ||
      prover_result.output_bytes != payload_bytes) {
    passed = 0;
  }

  const int request_matches =
      prover_result.output_bytes == payload_bytes &&
      memcmp(payload, dm_independent_request, DM_WIRE_STATEMENT_BYTES) == 0;
  printf("PROCESS_REQUEST source=independent_state_constant request_bytes=%zu frame_bytes=%zu "
         "matches_prover_statement=%s witness_bytes_to_verifier=0\n",
         (size_t)DM_WIRE_STATEMENT_BYTES, (size_t)DM_WIRE_FRAME_BYTES,
         request_matches ? "true" : "false");
  if (!request_matches) {
    passed = 0;
  } else {
    /* Retain the prover's frame, but replace its embedded statement with the independently
     * supplied state request before writing verifier stdin. */
    memcpy(payload, dm_independent_request, DM_WIRE_STATEMENT_BYTES);
  }

  if (!passed || !run_process_input(argv[2], payload, payload_bytes, &verifier_result)) {
    passed = 0;
  }
  print_process_result("verifier_positive", &verifier_result);
  if (!acceptable_runtime(&verifier_result) || verifier_result.exit_code != 0) {
    passed = 0;
  }

  const dm_negative_case_t cases[] = {
      {"short", DM_CASE_SHORT, DM_PROCESS_VERIFIER_EXIT_IO},
      {"extra", DM_CASE_EXTRA, DM_PROCESS_VERIFIER_EXIT_EXTRA},
      {"header", DM_CASE_HEADER, DM_PROCESS_VERIFIER_EXIT_DECODE},
      {"x", DM_CASE_X, DM_PROCESS_VERIFIER_EXIT_DECODE},
      {"context", DM_CASE_CONTEXT, DM_PROCESS_VERIFIER_EXIT_DECODE},
      {"nu", DM_CASE_NU, DM_PROCESS_VERIFIER_EXIT_DECODE},
      {"body", DM_CASE_BODY, DM_PROCESS_VERIFIER_EXIT_VERIFY},
      {"degree", DM_CASE_DEGREE, DM_PROCESS_VERIFIER_EXIT_DECODE},
      {"dim", DM_CASE_DIM, DM_PROCESS_VERIFIER_EXIT_DECODE},
      {"replay_request", DM_CASE_REPLAY, DM_PROCESS_VERIFIER_EXIT_DECODE},
  };
  for (size_t index = 0; index != sizeof(cases) / sizeof(cases[0]); ++index) {
    size_t case_length = 0;
    make_case_input(case_input, &case_length, payload, cases[index].kind);
    dm_process_result_t negative_result;
    const int ran = run_process_input(argv[2], case_input, case_length, &negative_result);
    const int negative_pass = ran && acceptable_runtime(&negative_result) &&
                              negative_result.exit_code == cases[index].expected_exit_code;
    printf("PROCESS_CASE name=%s status=%s expected_exit=%lu exit_code=%lu input_bytes=%zu "
           "wall_ns=%" PRIu64 " peak_tree_bytes=%" PRIu64 " whole_tree_accounting=%s\n",
           cases[index].name, negative_pass ? "PASS" : "FAIL",
           (unsigned long)cases[index].expected_exit_code,
           (unsigned long)negative_result.exit_code, case_length, negative_result.wall_ns,
           negative_result.peak_tree_bytes,
           negative_result.whole_tree_accounting ? "true" : "false");
    passed = passed && negative_pass;
    secure_clear(case_input, payload_bytes + 1u);
  }

  uint8_t retry_output[1] = {0};
  dm_process_result_t retry_result;
  const int retry_ran = run_process_capture(argv[1], "--retry-failure", retry_output,
                                            sizeof(retry_output), &retry_result);
  print_process_result("prover_retry_failure", &retry_result);
  const int retry_pass = retry_ran && acceptable_runtime(&retry_result) &&
                         retry_result.exit_code == 41 && retry_result.output_bytes == 0;
  printf("PROCESS_CASE name=retry_failure status=%s expected_exit=41\n",
         retry_pass ? "PASS" : "FAIL");
  passed = passed && retry_pass;
  secure_clear(retry_output, sizeof(retry_output));

cleanup:
  secure_clear(payload, payload_bytes + 1u);
  secure_clear(case_input, payload_bytes + 1u);
  free(payload);
  free(case_input);
  cleanup_ok = 1;
  printf("PROCESS_CLEANUP private_buffers_cleared=%s proof_buffer_released=%s "
         "statement_buffer_released=%s child_output_forwarded=false persisted_private_artifacts=false\n",
         cleanup_ok ? "true" : "false", cleanup_ok ? "true" : "false",
         cleanup_ok ? "true" : "false");

  uint64_t combined_end = 0;
  const int combined_timer_end = qpc_now(&combined_end);
  if (!combined_timer_start || !combined_timer_end || combined_end < combined_start) {
    passed = 0;
    printf("PROCESS_COMBINED timer_error=true parent_scope=prover+transfer+verifier+cleanup\n");
  } else {
    const uint64_t combined_wall = combined_end - combined_start;
    const uint64_t combined_peak = prover_result.peak_tree_bytes > verifier_result.peak_tree_bytes
                                       ? prover_result.peak_tree_bytes
                                       : verifier_result.peak_tree_bytes;
    const int stages_enclosed = prover_result.launched && verifier_result.launched &&
                                combined_wall >= prover_result.wall_ns &&
                                combined_wall >= verifier_result.wall_ns;
    if (!stages_enclosed) {
      passed = 0;
    }
    printf("PROCESS_COMBINED status=%s wall_ns=%" PRIu64
           " user_ns=%" PRIu64 " kernel_ns=%" PRIu64 " peak_tree_bytes=%" PRIu64
           " total_tree_processes=%" PRIu64 " whole_tree_accounting=%s "
           "parent_monotonic=true stages_enclosed=%s "
           "parent_scope=prover+transfer+verifier+cleanup\n",
           passed && stages_enclosed ? "PASS" : "FAIL", combined_wall,
           prover_result.user_ns + verifier_result.user_ns,
           prover_result.kernel_ns + verifier_result.kernel_ns, combined_peak,
           prover_result.total_tree_processes + verifier_result.total_tree_processes,
           (prover_result.whole_tree_accounting && verifier_result.whole_tree_accounting) ? "true"
                                                                                           : "false",
           stages_enclosed ? "true" : "false");
  }
  printf("PROCESS_PIPELINE status=%s cases=%zu skips=0 child_output_forwarded=false "
         "persisted_private_artifacts=false\n",
         passed && cleanup_ok ? "PASS" : "FAIL", sizeof(cases) / sizeof(cases[0]) + 2u);

  close_handle(&mutex);
  return passed && cleanup_ok ? 0 : 1;
}
