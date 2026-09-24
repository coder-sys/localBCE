/* SPDX-License-Identifier: MIT */

#include "direct_mask_authenticated_proof.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static void dm_authenticated_proof_wipe(void* pointer, size_t length) {
  volatile uint8_t* bytes = (volatile uint8_t*)pointer;
  if (bytes == NULL) {
    return;
  }
  while (length != 0u) {
    *bytes++ = 0u;
    --length;
  }
}

/* Overflow is conservatively classified as an alias so no destructive clear
 * can be attempted for an unrepresentable advertised span. */
static int dm_authenticated_proof_spans_overlap(const void* lhs, size_t lhs_bytes,
                                                const void* rhs, size_t rhs_bytes) {
  uintptr_t lhs_start;
  uintptr_t rhs_start;

  if (lhs == NULL || rhs == NULL || lhs_bytes == 0u || rhs_bytes == 0u) {
    return 0;
  }
  lhs_start = (uintptr_t)lhs;
  rhs_start = (uintptr_t)rhs;
  if ((uintmax_t)lhs_bytes > (uintmax_t)UINTPTR_MAX - (uintmax_t)lhs_start ||
      (uintmax_t)rhs_bytes > (uintmax_t)UINTPTR_MAX - (uintmax_t)rhs_start) {
    return 1;
  }
  return lhs_start < rhs_start + (uintptr_t)rhs_bytes &&
         rhs_start < lhs_start + (uintptr_t)lhs_bytes;
}

static size_t dm_authenticated_proof_alias_bytes(size_t requested) {
  return requested == 0u ? 1u : requested;
}

static int dm_authenticated_proof_output_alias(
    const dm_authenticated_proof_verified_t* verified,
    const dm_source_auth_request_t* request, const uint8_t* canonical_x,
    size_t canonical_x_bytes, const uint8_t* signature, size_t signature_bytes,
    const uint8_t* frame, size_t frame_bytes) {
  if (verified == NULL) {
    return 0;
  }
  return dm_authenticated_proof_spans_overlap(
             verified, sizeof(*verified), request,
             request == NULL ? 0u : sizeof(*request)) ||
         dm_authenticated_proof_spans_overlap(
             verified, sizeof(*verified), canonical_x,
             dm_authenticated_proof_alias_bytes(canonical_x_bytes)) ||
         dm_authenticated_proof_spans_overlap(
             verified, sizeof(*verified), signature,
             dm_authenticated_proof_alias_bytes(signature_bytes)) ||
         dm_authenticated_proof_spans_overlap(
             verified, sizeof(*verified), frame,
             dm_authenticated_proof_alias_bytes(frame_bytes));
}

static int dm_authenticated_proof_input_alias(
    const dm_source_auth_request_t* request, const uint8_t* canonical_x,
    size_t canonical_x_bytes, const uint8_t* signature, size_t signature_bytes,
    const uint8_t* frame, size_t frame_bytes) {
  const size_t x_bytes = dm_authenticated_proof_alias_bytes(canonical_x_bytes);
  const size_t sig_bytes = dm_authenticated_proof_alias_bytes(signature_bytes);
  const size_t proof_bytes = dm_authenticated_proof_alias_bytes(frame_bytes);

  if (request != NULL &&
      (dm_authenticated_proof_spans_overlap(request, sizeof(*request), canonical_x,
                                            x_bytes) ||
       dm_authenticated_proof_spans_overlap(request, sizeof(*request), signature,
                                            sig_bytes) ||
       dm_authenticated_proof_spans_overlap(request, sizeof(*request), frame,
                                            proof_bytes))) {
    return 1;
  }
  return dm_authenticated_proof_spans_overlap(canonical_x, x_bytes, signature,
                                               sig_bytes) ||
         dm_authenticated_proof_spans_overlap(canonical_x, x_bytes, frame,
                                               proof_bytes) ||
         dm_authenticated_proof_spans_overlap(signature, sig_bytes, frame,
                                               proof_bytes);
}

const char* dm_authenticated_proof_status_name(
    dm_authenticated_proof_status_t status) {
  switch (status) {
    case DM_AUTHENTICATED_PROOF_OK:
      return "ok";
    case DM_AUTHENTICATED_PROOF_ERR_ARGUMENT:
      return "argument";
    case DM_AUTHENTICATED_PROOF_ERR_SIZE:
      return "size";
    case DM_AUTHENTICATED_PROOF_ERR_INPUT_ALIAS:
      return "input-alias";
    case DM_AUTHENTICATED_PROOF_ERR_OUTPUT_ALIAS:
      return "output-alias";
    case DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH:
      return "source-auth";
    case DM_AUTHENTICATED_PROOF_ERR_STATEMENT:
      return "statement";
    case DM_AUTHENTICATED_PROOF_ERR_DECODE:
      return "decode";
    case DM_AUTHENTICATED_PROOF_ERR_PROOF:
      return "proof";
    case DM_AUTHENTICATED_PROOF_ERR_ALLOCATION:
      return "allocation";
    default:
      return "unknown";
  }
}

void dm_authenticated_proof_verified_clear(
    dm_authenticated_proof_verified_t* verified) {
  if (verified != NULL) {
    dm_authenticated_proof_wipe(verified, sizeof(*verified));
  }
}

dm_authenticated_proof_status_t dm_authenticated_proof_verify(
    const dm_source_auth_request_t* request, uint64_t presented_key_epoch,
    const uint8_t* canonical_x, size_t canonical_x_bytes,
    const uint8_t* signature, size_t signature_bytes,
    const uint8_t* frame, size_t frame_bytes,
    dm_authenticated_proof_verified_t* verified) {
  dm_source_auth_verified_t source_verified;
  dm_wire_statement_t statement;
  dm_wire_proof_t proof;
  uint8_t* frame_owned = NULL;
  dm_source_auth_status_t source_status;
  dm_wire_status_t wire_status;
  dm_authenticated_proof_status_t result = DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;

  memset(&source_verified, 0, sizeof(source_verified));
  memset(&statement, 0, sizeof(statement));
  dm_wire_proof_init(&proof);

  /* Every possible destructive output operation follows these checks. */
  if (verified == NULL) {
    dm_wire_proof_clear(&proof);
    dm_authenticated_proof_wipe(&statement, sizeof(statement));
    dm_source_auth_verified_clear(&source_verified);
    return DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
  }
  if (dm_authenticated_proof_output_alias(
          verified, request, canonical_x, canonical_x_bytes, signature,
           signature_bytes, frame, frame_bytes)) {
    dm_wire_proof_clear(&proof);
    dm_authenticated_proof_wipe(&statement, sizeof(statement));
    dm_source_auth_verified_clear(&source_verified);
    return DM_AUTHENTICATED_PROOF_ERR_OUTPUT_ALIAS;
  }
  if (dm_authenticated_proof_input_alias(request, canonical_x, canonical_x_bytes,
                                          signature, signature_bytes, frame,
                                          frame_bytes)) {
    dm_authenticated_proof_verified_clear(verified);
    dm_wire_proof_clear(&proof);
    dm_authenticated_proof_wipe(&statement, sizeof(statement));
    dm_source_auth_verified_clear(&source_verified);
    return DM_AUTHENTICATED_PROOF_ERR_INPUT_ALIAS;
  }

  dm_authenticated_proof_verified_clear(verified);
  if (request == NULL || canonical_x == NULL || signature == NULL || frame == NULL) {
    goto cleanup;
  }
  /* This check is intentionally before source-auth snapshots and wire parsing. */
  if (canonical_x_bytes != DM_SOURCE_AUTH_X_BYTES ||
      signature_bytes != DM_SOURCE_AUTH_SIGNATURE_BYTES ||
      frame_bytes != DM_AUTHENTICATED_PROOF_FRAME_BYTES) {
    result = DM_AUTHENTICATED_PROOF_ERR_SIZE;
    goto cleanup;
  }

  /* Take exactly one bounded owned frame snapshot after all caller-span
   * checks.  No raw caller frame pointer is used below this boundary. */
  frame_owned = (uint8_t*)malloc(DM_AUTHENTICATED_PROOF_FRAME_BYTES);
  if (frame_owned == NULL) {
    result = DM_AUTHENTICATED_PROOF_ERR_ALLOCATION;
    goto cleanup;
  }
  memcpy(frame_owned, frame, DM_AUTHENTICATED_PROOF_FRAME_BYTES);

  source_status = dm_source_auth_verify(
      request, presented_key_epoch, canonical_x, canonical_x_bytes, signature,
      signature_bytes, &source_verified);
  if (source_status != DM_SOURCE_AUTH_OK ||
      source_verified.authentication != DM_SOURCE_AUTH_AUTHENTICATED ||
      source_verified.key_epoch != presented_key_epoch) {
    result = DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH;
    goto cleanup;
  }

  /* The statement pointers below point only into the owned source snapshot. */
  wire_status = dm_wire_statement_decode(
      &statement, source_verified.canonical_x, DM_SOURCE_AUTH_X_BYTES);
  if (wire_status != DM_WIRE_OK) {
    result = DM_AUTHENTICATED_PROOF_ERR_STATEMENT;
    goto cleanup;
  }

  /* dm_wire_decode checks that the frame's serialized statement is byte-for-byte
   * equal to this source-authenticated statement before accepting proof bytes. */
  wire_status = dm_wire_decode(&proof, &statement, frame_owned,
                                DM_AUTHENTICATED_PROOF_FRAME_BYTES);
  if (wire_status != DM_WIRE_OK) {
    result = DM_AUTHENTICATED_PROOF_ERR_DECODE;
    goto cleanup;
  }
  wire_status = dm_wire_verify_kernel(&proof, &statement);
  if (wire_status != DM_WIRE_OK) {
    result = DM_AUTHENTICATED_PROOF_ERR_PROOF;
    goto cleanup;
  }

  memcpy(verified->canonical_x, source_verified.canonical_x,
         sizeof(verified->canonical_x));
  verified->key_epoch = source_verified.key_epoch;
  result = DM_AUTHENTICATED_PROOF_OK;

cleanup:
  dm_wire_proof_clear(&proof);
  dm_authenticated_proof_wipe(&statement, sizeof(statement));
  dm_source_auth_verified_clear(&source_verified);
  if (frame_owned != NULL) {
    dm_authenticated_proof_wipe(frame_owned,
                                DM_AUTHENTICATED_PROOF_FRAME_BYTES);
    free(frame_owned);
  }
  if (result != DM_AUTHENTICATED_PROOF_OK) {
    dm_authenticated_proof_verified_clear(verified);
  }
  return result;
}
