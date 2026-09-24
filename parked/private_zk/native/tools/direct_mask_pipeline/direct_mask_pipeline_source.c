/* SPDX-License-Identifier: MIT */

#include "direct_mask_pipeline.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

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

static dm_pipeline_status_t dm_pipeline_map_producer_status(
    dm_source_proof_status_t status) {
  switch (status) {
    case DM_SOURCE_PROOF_ERR_ARGUMENT:
    case DM_SOURCE_PROOF_ERR_SIZE:
    case DM_SOURCE_PROOF_ERR_INPUT_ALIAS:
    case DM_SOURCE_PROOF_ERR_OUTPUT_ALIAS:
    case DM_SOURCE_PROOF_ERR_ALLOCATION:
    case DM_SOURCE_PROOF_ERR_CSPRNG:
      return DM_PIPELINE_INTERNAL;
    case DM_SOURCE_PROOF_OK:
      return DM_PIPELINE_ACCEPT;
    default:
      return DM_PIPELINE_REJECT;
  }
}

dm_pipeline_status_t dm_pipeline_source_process(
    const uint8_t* input, size_t input_bytes, uint8_t* capsule,
    size_t capsule_bytes) {
  dm_pipeline_source_input_view_t input_view;
  dm_source_proof_output_t* producer_output = NULL;
  dm_source_proof_status_t producer_status;
  dm_pipeline_status_t result = DM_PIPELINE_INTERNAL;
  const size_t clear_bytes =
      capsule_bytes < DM_PIPELINE_CAPSULE_BYTES ? capsule_bytes
                                                : DM_PIPELINE_CAPSULE_BYTES;

  /* An output/input alias must be rejected before the output clear. */
  if (capsule == NULL) {
    return DM_PIPELINE_INTERNAL;
  }
  if (dm_pipeline_spans_overlap(input, input_bytes, capsule, capsule_bytes)) {
    return DM_PIPELINE_INTERNAL;
  }
  /* Capacity is a transport invariant.  Reject it before parsing, allocation,
   * or the producer can acquire randomness or perform proof work. */
  if (capsule_bytes != DM_PIPELINE_CAPSULE_BYTES) {
    dm_pipeline_secure_clear(
        capsule, capsule_bytes < DM_PIPELINE_CAPSULE_BYTES ? capsule_bytes
                                                           : DM_PIPELINE_CAPSULE_BYTES);
    return DM_PIPELINE_INTERNAL;
  }
  dm_pipeline_secure_clear(capsule, clear_bytes);

  if (!dm_pipeline_source_input_parse(input, input_bytes, &input_view)) {
    return DM_PIPELINE_MALFORMED;
  }

  producer_output = (dm_source_proof_output_t*)calloc(1u, sizeof(*producer_output));
  if (producer_output == NULL) {
    return DM_PIPELINE_INTERNAL;
  }

  producer_status = dm_source_proof_generate(
      input_view.context, DM_SOURCE_PROOF_CONTEXT_BYTES, input_view.U,
      DM_SOURCE_PROOF_U_BYTES, input_view.values_le,
      DM_SOURCE_PROOF_VALUES_BYTES, input_view.secret_key,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, input_view.key_epoch,
      input_view.max_final_retries, producer_output);
  result = dm_pipeline_map_producer_status(producer_status);
  if (producer_status == DM_SOURCE_PROOF_OK) {
    if (producer_output->key_epoch != input_view.key_epoch ||
        !dm_pipeline_capsule_encode(capsule, capsule_bytes, producer_output)) {
      result = DM_PIPELINE_INTERNAL;
    }
  }

  dm_source_proof_output_clear(producer_output);
  dm_pipeline_secure_clear(producer_output, sizeof(*producer_output));
  free(producer_output);
  return result;
}
