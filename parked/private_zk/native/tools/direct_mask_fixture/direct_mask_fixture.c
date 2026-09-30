/* SPDX-License-Identifier: MIT */

#include "direct_mask_fixture.h"

#include "fixture_public_key.h"

#include <limits.h>
#include <string.h>

static const uint64_t k_fixture_lower = UINT64_C(0x1122334455667788);
static const uint64_t k_fixture_upper = UINT64_C(0xddeeff0011223344);

static uint32_t dm_fixture_load_u32_le(const uint8_t bytes[4]) {
  return ((uint32_t)bytes[0]) | ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t dm_fixture_load_u64_le(const uint8_t bytes[8]) {
  uint64_t value = 0u;
  for (size_t index = 0u; index != 8u; ++index) {
    value |= (uint64_t)bytes[index] << (8u * index);
  }
  return value;
}

static void dm_fixture_store_u32_le(uint8_t bytes[4], uint32_t value) {
  for (size_t index = 0u; index != 4u; ++index) {
    bytes[index] = (uint8_t)(value & UINT32_C(0xff));
    value >>= 8;
  }
}

static void dm_fixture_store_u64_le(uint8_t bytes[8], uint64_t value) {
  for (size_t index = 0u; index != 8u; ++index) {
    bytes[index] = (uint8_t)(value & UINT64_C(0xff));
    value >>= 8;
  }
}

static int dm_fixture_nonzero(const uint8_t* bytes, size_t length) {
  uint8_t accumulator = 0u;
  if (bytes == NULL) {
    return 0;
  }
  for (size_t index = 0u; index != length; ++index) {
    accumulator |= bytes[index];
  }
  return accumulator != 0u;
}

static int dm_fixture_span_end(const void* pointer, size_t bytes,
                              uintptr_t* end) {
  const uintptr_t start = (uintptr_t)pointer;
  const size_t effective_bytes = bytes == 0u ? 1u : bytes;

  if (pointer == NULL || end == NULL ||
      (uintmax_t)effective_bytes > (uintmax_t)UINTPTR_MAX - start) {
    return 0;
  }
  *end = start + (uintptr_t)effective_bytes;
  return 1;
}

static int dm_fixture_spans_overlap(const void* lhs, size_t lhs_bytes,
                                    const void* rhs, size_t rhs_bytes) {
  uintptr_t lhs_end;
  uintptr_t rhs_end;

  if (lhs == NULL || rhs == NULL) {
    return 0;
  }
  if (!dm_fixture_span_end(lhs, lhs_bytes, &lhs_end) ||
      !dm_fixture_span_end(rhs, rhs_bytes, &rhs_end)) {
    return 1;
  }
  return (uintptr_t)lhs < rhs_end && (uintptr_t)rhs < lhs_end;
}

void dm_fixture_secure_clear(void* pointer, size_t bytes) {
  volatile uint8_t* cursor = (volatile uint8_t*)pointer;
  if (cursor == NULL) {
    return;
  }
  while (bytes != 0u) {
    *cursor++ = 0u;
    --bytes;
  }
}

int dm_fixture_cli_args_valid(int argc) { return argc == 1; }

void dm_fixture_fill_seed(uint8_t seed[DM_FIXTURE_SEED_BYTES]) {
  if (seed == NULL) {
    return;
  }
  for (size_t index = 0u; index != DM_FIXTURE_SEED_BYTES; ++index) {
    seed[index] = (uint8_t)index;
  }
}

void dm_fixture_fill_values(uint8_t values_le[DM_SOURCE_PROOF_VALUES_BYTES]) {
  if (values_le == NULL) {
    return;
  }
  for (size_t index = 0u; index != DM_SOURCE_PROOF_VALUE_COUNT; ++index) {
    dm_fixture_store_u64_le(values_le + 8u * index,
                            index % 2u == 0u ? k_fixture_lower : k_fixture_upper);
  }
}

int dm_fixture_request_parse(const uint8_t* input, size_t input_bytes,
                             dm_fixture_request_view_t* view) {
  dm_fixture_request_view_t candidate;

  if (view == NULL ||
      dm_fixture_spans_overlap(input, input_bytes, view, sizeof(*view))) {
    return 0;
  }
  memset(&candidate, 0, sizeof(candidate));
  if (input == NULL || input_bytes != DM_FIXTURE_REQUEST_BYTES ||
      memcmp(input, DM_FIXTURE_REQUEST_MAGIC,
             DM_FIXTURE_REQUEST_MAGIC_BYTES) != 0) {
    memset(view, 0, sizeof(*view));
    return 0;
  }
  candidate.key_epoch =
      dm_fixture_load_u64_le(input + DM_FIXTURE_REQUEST_EPOCH_OFFSET);
  candidate.max_final_retries = dm_fixture_load_u32_le(
      input + DM_FIXTURE_REQUEST_RETRIES_OFFSET);
  if (candidate.key_epoch != DM_FIXTURE_KEY_EPOCH ||
      candidate.max_final_retries == 0u ||
      candidate.max_final_retries > DM_FIXTURE_MAX_FINAL_RETRIES ||
      !dm_fixture_nonzero(input + DM_FIXTURE_REQUEST_U_OFFSET,
                           DM_SOURCE_PROOF_U_BYTES)) {
    memset(view, 0, sizeof(*view));
    return 0;
  }
  memcpy(candidate.context, input + DM_FIXTURE_REQUEST_CONTEXT_OFFSET,
         sizeof(candidate.context));
  memcpy(candidate.U, input + DM_FIXTURE_REQUEST_U_OFFSET,
         sizeof(candidate.U));
  *view = candidate;
  return 1;
}

int dm_fixture_public_key_matches(const uint8_t* derived_public_key) {
  return derived_public_key != NULL &&
         memcmp(derived_public_key, dm_fixture_frozen_public_key,
                DM_FIXTURE_PUBLIC_KEY_BYTES) == 0;
}

int dm_fixture_construct_source_input(
    const dm_fixture_request_view_t* request, const uint8_t* secret_key,
    size_t secret_key_bytes, uint8_t* source_input, size_t source_input_bytes) {
  const size_t clear_bytes = source_input_bytes < DM_PIPELINE_SOURCE_INPUT_BYTES
                                 ? source_input_bytes
                                 : DM_PIPELINE_SOURCE_INPUT_BYTES;

  if (request == NULL || secret_key == NULL || source_input == NULL ||
      dm_fixture_spans_overlap(request, sizeof(*request), source_input,
                                source_input_bytes) ||
      dm_fixture_spans_overlap(secret_key, secret_key_bytes, source_input,
                                source_input_bytes)) {
    return 0;
  }
  dm_fixture_secure_clear(source_input, clear_bytes);
  if (secret_key_bytes != DM_FIXTURE_SECRET_KEY_BYTES ||
      source_input_bytes != DM_PIPELINE_SOURCE_INPUT_BYTES) {
    return 0;
  }
  memcpy(source_input + DM_PIPELINE_SOURCE_MAGIC_OFFSET,
         DM_PIPELINE_SOURCE_MAGIC, DM_PIPELINE_MAGIC_BYTES);
  dm_fixture_store_u64_le(source_input + DM_PIPELINE_SOURCE_EPOCH_OFFSET,
                          request->key_epoch);
  dm_fixture_store_u32_le(source_input + DM_PIPELINE_SOURCE_RETRIES_OFFSET,
                          request->max_final_retries);
  memcpy(source_input + DM_PIPELINE_SOURCE_CONTEXT_OFFSET, request->context,
         sizeof(request->context));
  memcpy(source_input + DM_PIPELINE_SOURCE_U_OFFSET, request->U,
         sizeof(request->U));
  dm_fixture_fill_values(source_input + DM_PIPELINE_SOURCE_VALUES_OFFSET);
  memcpy(source_input + DM_PIPELINE_SOURCE_SECRET_KEY_OFFSET, secret_key,
         DM_FIXTURE_SECRET_KEY_BYTES);
  return 1;
}

dm_pipeline_status_t dm_fixture_run_bound_source(
    const dm_fixture_request_view_t* request, const uint8_t* secret_key,
    size_t secret_key_bytes, const uint8_t* derived_public_key,
    const uint8_t* expected_public_key, uint8_t* capsule, size_t capsule_bytes,
    dm_fixture_source_process_fn process_fn) {
  uint8_t source_input[DM_PIPELINE_SOURCE_INPUT_BYTES];
  dm_pipeline_status_t result = DM_PIPELINE_INTERNAL;

  memset(source_input, 0, sizeof(source_input));
  if (request == NULL || secret_key == NULL || derived_public_key == NULL ||
      expected_public_key == NULL || capsule == NULL || process_fn == NULL ||
      capsule_bytes != DM_PIPELINE_CAPSULE_BYTES ||
      memcmp(derived_public_key, expected_public_key,
             DM_FIXTURE_PUBLIC_KEY_BYTES) != 0) {
    dm_fixture_secure_clear(source_input, sizeof(source_input));
    return result;
  }
  if (!dm_fixture_construct_source_input(
          request, secret_key, secret_key_bytes, source_input,
          sizeof(source_input))) {
    dm_fixture_secure_clear(source_input, sizeof(source_input));
    return result;
  }
  result = process_fn(source_input, sizeof(source_input), capsule,
                      capsule_bytes);
  dm_fixture_secure_clear(source_input, sizeof(source_input));
  return result;
}
