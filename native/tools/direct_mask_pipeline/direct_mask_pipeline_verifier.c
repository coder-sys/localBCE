/* SPDX-License-Identifier: MIT */

#include "direct_mask_pipeline.h"

#include <string.h>

static dm_pipeline_status_t dm_pipeline_map_verifier_status(
    dm_authenticated_proof_status_t status) {
  switch (status) {
    case DM_AUTHENTICATED_PROOF_OK:
      return DM_PIPELINE_ACCEPT;
    case DM_AUTHENTICATED_PROOF_ERR_ARGUMENT:
    case DM_AUTHENTICATED_PROOF_ERR_INPUT_ALIAS:
    case DM_AUTHENTICATED_PROOF_ERR_OUTPUT_ALIAS:
    case DM_AUTHENTICATED_PROOF_ERR_ALLOCATION:
      return DM_PIPELINE_INTERNAL;
    default:
      return DM_PIPELINE_REJECT;
  }
}

dm_pipeline_status_t dm_pipeline_verifier_process(const uint8_t* input,
                                                  size_t input_bytes) {
  dm_pipeline_verifier_input_view_t input_view;
  dm_pipeline_capsule_view_t capsule_view;
  dm_source_auth_request_t request;
  dm_authenticated_proof_verified_t verified;
  uint8_t canonical_x[DM_SOURCE_AUTH_X_BYTES];
  dm_authenticated_proof_status_t verifier_status;
  dm_pipeline_status_t result;

  memset(&input_view, 0, sizeof(input_view));
  memset(&capsule_view, 0, sizeof(capsule_view));
  memset(&request, 0, sizeof(request));
  memset(&verified, 0, sizeof(verified));
  memset(canonical_x, 0, sizeof(canonical_x));

  if (!dm_pipeline_verifier_input_parse(input, input_bytes, &input_view) ||
      !dm_pipeline_capsule_decode(input_view.capsule,
                                  DM_PIPELINE_CAPSULE_BYTES,
                                  &capsule_view)) {
    return DM_PIPELINE_MALFORMED;
  }

  /* x is copied from the fixed DMV3 frame into separate bounded storage.  It
   * is never taken from an outer duplicate or derived from expected values. */
  memcpy(canonical_x,
         capsule_view.frame + DM_PIPELINE_FRAME_X_OFFSET,
         sizeof(canonical_x));

  dm_source_auth_request_init(&request);
  memcpy(request.expected_context, input_view.expected_context,
         sizeof(request.expected_context));
  memcpy(request.expected_U, input_view.expected_U, sizeof(request.expected_U));
  memcpy(request.trusted_public_key, input_view.trusted_public_key,
         sizeof(request.trusted_public_key));
  request.expected_key_epoch = input_view.expected_key_epoch;

  verifier_status = dm_authenticated_proof_verify(
      &request, capsule_view.presented_key_epoch, canonical_x,
      sizeof(canonical_x), capsule_view.signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, capsule_view.frame,
      DM_SOURCE_PROOF_FRAME_BYTES, &verified);
  result = dm_pipeline_map_verifier_status(verifier_status);

  dm_authenticated_proof_verified_clear(&verified);
  dm_source_auth_request_clear(&request);
  dm_pipeline_secure_clear(canonical_x, sizeof(canonical_x));
  dm_pipeline_secure_clear(&capsule_view, sizeof(capsule_view));
  dm_pipeline_secure_clear(&input_view, sizeof(input_view));
  return result;
}
