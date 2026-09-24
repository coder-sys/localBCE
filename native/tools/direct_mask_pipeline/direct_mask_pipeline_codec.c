/* SPDX-License-Identifier: MIT */

#include "direct_mask_pipeline.h"

#include <limits.h>
#include <string.h>

void dm_pipeline_secure_clear(void* pointer, size_t bytes) {
  volatile uint8_t* cursor = (volatile uint8_t*)pointer;
  if (cursor == NULL) {
    return;
  }
  while (bytes != 0u) {
    *cursor++ = 0u;
    --bytes;
  }
}

static uint32_t dm_pipeline_load_u32_le(const uint8_t bytes[4]) {
  return ((uint32_t)bytes[0]) | ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t dm_pipeline_load_u64_le(const uint8_t bytes[8]) {
  uint64_t value = 0u;
  for (size_t index = 0u; index != 8u; ++index) {
    value |= (uint64_t)bytes[index] << (8u * index);
  }
  return value;
}

static void dm_pipeline_store_u64_le(uint8_t bytes[8], uint64_t value) {
  for (size_t index = 0u; index != 8u; ++index) {
    bytes[index] = (uint8_t)(value & UINT64_C(0xff));
    value >>= 8;
  }
}

static int dm_pipeline_all_zero(const uint8_t* bytes, size_t length) {
  uint8_t accumulator = 0u;
  if (bytes == NULL) {
    return 1;
  }
  for (size_t index = 0u; index != length; ++index) {
    accumulator |= bytes[index];
  }
  return accumulator == 0u;
}

static int dm_pipeline_span_end(const void* pointer, size_t bytes,
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

static int dm_pipeline_spans_overlap(const void* lhs, size_t lhs_bytes,
                                     const void* rhs, size_t rhs_bytes) {
  uintptr_t lhs_end;
  uintptr_t rhs_end;

  if (lhs == NULL || rhs == NULL) {
    return 0;
  }
  if (!dm_pipeline_span_end(lhs, lhs_bytes, &lhs_end) ||
      !dm_pipeline_span_end(rhs, rhs_bytes, &rhs_end)) {
    return 1;
  }
  return (uintptr_t)lhs < rhs_end && (uintptr_t)rhs < lhs_end;
}

int dm_pipeline_source_input_parse(
    const uint8_t* input, size_t input_bytes,
    dm_pipeline_source_input_view_t* view) {
  dm_pipeline_source_input_view_t candidate;

  if (view == NULL) {
    return 0;
  }
  if (dm_pipeline_spans_overlap(input, input_bytes, view, sizeof(*view))) {
    return 0;
  }
  memset(&candidate, 0, sizeof(candidate));
  if (input == NULL || input_bytes != DM_PIPELINE_SOURCE_INPUT_BYTES ||
      memcmp(input + DM_PIPELINE_SOURCE_MAGIC_OFFSET, DM_PIPELINE_SOURCE_MAGIC,
             DM_PIPELINE_MAGIC_BYTES) != 0) {
    memset(view, 0, sizeof(*view));
    return 0;
  }

  candidate.key_epoch =
      dm_pipeline_load_u64_le(input + DM_PIPELINE_SOURCE_EPOCH_OFFSET);
  candidate.max_final_retries = dm_pipeline_load_u32_le(
      input + DM_PIPELINE_SOURCE_RETRIES_OFFSET);
  if (candidate.key_epoch == 0u || candidate.max_final_retries == 0u ||
      candidate.max_final_retries > DM_PIPELINE_MAX_FINAL_RETRIES ||
      dm_pipeline_all_zero(input + DM_PIPELINE_SOURCE_U_OFFSET,
                           DM_SOURCE_PROOF_U_BYTES)) {
    memset(view, 0, sizeof(*view));
    return 0;
  }

  candidate.context = input + DM_PIPELINE_SOURCE_CONTEXT_OFFSET;
  candidate.U = input + DM_PIPELINE_SOURCE_U_OFFSET;
  candidate.values_le = input + DM_PIPELINE_SOURCE_VALUES_OFFSET;
  candidate.secret_key = input + DM_PIPELINE_SOURCE_SECRET_KEY_OFFSET;
  *view = candidate;
  return 1;
}

int dm_pipeline_capsule_decode(const uint8_t* capsule, size_t capsule_bytes,
                               dm_pipeline_capsule_view_t* view) {
  dm_pipeline_capsule_view_t candidate;

  if (view == NULL) {
    return 0;
  }
  if (dm_pipeline_spans_overlap(capsule, capsule_bytes, view, sizeof(*view))) {
    return 0;
  }
  memset(&candidate, 0, sizeof(candidate));
  if (capsule == NULL || capsule_bytes != DM_PIPELINE_CAPSULE_BYTES ||
      memcmp(capsule + DM_PIPELINE_CAPSULE_MAGIC_OFFSET,
             DM_PIPELINE_CAPSULE_MAGIC, DM_PIPELINE_MAGIC_BYTES) != 0) {
    memset(view, 0, sizeof(*view));
    return 0;
  }
  candidate.presented_key_epoch =
      dm_pipeline_load_u64_le(capsule + DM_PIPELINE_CAPSULE_EPOCH_OFFSET);
  if (candidate.presented_key_epoch == 0u) {
    memset(view, 0, sizeof(*view));
    return 0;
  }
  candidate.signature = capsule + DM_PIPELINE_CAPSULE_SIGNATURE_OFFSET;
  candidate.frame = capsule + DM_PIPELINE_CAPSULE_FRAME_OFFSET;
  *view = candidate;
  return 1;
}

int dm_pipeline_verifier_input_parse(
    const uint8_t* input, size_t input_bytes,
    dm_pipeline_verifier_input_view_t* view) {
  dm_pipeline_capsule_view_t capsule_view;
  dm_pipeline_verifier_input_view_t candidate;

  if (view == NULL) {
    return 0;
  }
  if (dm_pipeline_spans_overlap(input, input_bytes, view, sizeof(*view))) {
    return 0;
  }
  memset(&candidate, 0, sizeof(candidate));
  memset(&capsule_view, 0, sizeof(capsule_view));
  if (input == NULL || input_bytes != DM_PIPELINE_VERIFIER_INPUT_BYTES ||
      memcmp(input + DM_PIPELINE_VERIFIER_MAGIC_OFFSET,
             DM_PIPELINE_VERIFIER_MAGIC, DM_PIPELINE_MAGIC_BYTES) != 0) {
    memset(view, 0, sizeof(*view));
    return 0;
  }
  candidate.expected_key_epoch =
      dm_pipeline_load_u64_le(input + DM_PIPELINE_VERIFIER_EPOCH_OFFSET);
  if (candidate.expected_key_epoch == 0u ||
      dm_pipeline_all_zero(input + DM_PIPELINE_VERIFIER_U_OFFSET,
                           DM_SOURCE_AUTH_U_BYTES) ||
      dm_pipeline_all_zero(input + DM_PIPELINE_VERIFIER_PUBLIC_KEY_OFFSET,
                           DM_SOURCE_AUTH_PUBLIC_KEY_BYTES) ||
      !dm_pipeline_capsule_decode(
          input + DM_PIPELINE_VERIFIER_CAPSULE_OFFSET,
           DM_PIPELINE_CAPSULE_BYTES, &capsule_view)) {
    memset(view, 0, sizeof(*view));
    return 0;
  }

  candidate.expected_context = input + DM_PIPELINE_VERIFIER_CONTEXT_OFFSET;
  candidate.expected_U = input + DM_PIPELINE_VERIFIER_U_OFFSET;
  candidate.trusted_public_key = input + DM_PIPELINE_VERIFIER_PUBLIC_KEY_OFFSET;
  candidate.capsule = input + DM_PIPELINE_VERIFIER_CAPSULE_OFFSET;
  *view = candidate;
  return 1;
}

int dm_pipeline_capsule_encode(uint8_t* capsule, size_t capsule_bytes,
                               const dm_source_proof_output_t* output) {
  const size_t clear_bytes =
      capsule_bytes < DM_PIPELINE_CAPSULE_BYTES ? capsule_bytes
                                                : DM_PIPELINE_CAPSULE_BYTES;

  if (capsule == NULL) {
    return 0;
  }
  if (output == NULL) {
    dm_pipeline_secure_clear(capsule, clear_bytes);
    return 0;
  }
  if (dm_pipeline_spans_overlap(capsule, DM_PIPELINE_CAPSULE_BYTES, output,
                                sizeof(*output))) {
    return 0;
  }

  dm_pipeline_secure_clear(capsule, clear_bytes);
  if (capsule_bytes != DM_PIPELINE_CAPSULE_BYTES) {
    return 0;
  }
  if (output->key_epoch == 0u) {
    return 0;
  }
  memcpy(capsule + DM_PIPELINE_CAPSULE_MAGIC_OFFSET, DM_PIPELINE_CAPSULE_MAGIC,
         DM_PIPELINE_MAGIC_BYTES);
  dm_pipeline_store_u64_le(capsule + DM_PIPELINE_CAPSULE_EPOCH_OFFSET,
                           output->key_epoch);
  memcpy(capsule + DM_PIPELINE_CAPSULE_SIGNATURE_OFFSET, output->signature,
         DM_SOURCE_PROOF_SIGNATURE_BYTES);
  memcpy(capsule + DM_PIPELINE_CAPSULE_FRAME_OFFSET, output->frame,
         DM_SOURCE_PROOF_FRAME_BYTES);
  return 1;
}

int dm_pipeline_cli_args_valid(int argc) { return argc == 1; }
