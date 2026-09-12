/* SPDX-License-Identifier: MIT */
#ifndef BLIND_LEDGER_DIRECT_MASK_SOURCE_PROOF_H
#define BLIND_LEDGER_DIRECT_MASK_SOURCE_PROOF_H

/*
 * Non-activating source-owned producer for the current direct-mask relation.
 * The producer owns no policy, state, directive, transport, counter, or
 * source-truth authority.  It returns only one volatile proof package for a
 * caller-supplied operation epoch.
 */

#include <stddef.h>
#include <stdint.h>

#include "../direct_mask_source_auth/direct_mask_source_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DM_SOURCE_PROOF_CONTEXT_BYTES 64u
#define DM_SOURCE_PROOF_U_BYTES 96u
#define DM_SOURCE_PROOF_VALUE_COUNT 100u
#define DM_SOURCE_PROOF_VALUES_BYTES (DM_SOURCE_PROOF_VALUE_COUNT * 8u)
#define DM_SOURCE_PROOF_CANONICAL_X_BYTES DM_SOURCE_AUTH_X_BYTES
#define DM_SOURCE_PROOF_SIGNATURE_BYTES DM_SOURCE_AUTH_SIGNATURE_BYTES
#define DM_SOURCE_PROOF_FRAME_BYTES 534370u
#define DM_SOURCE_PROOF_SECRET_KEY_BYTES DM_SOURCE_AUTH_SECRET_KEY_BYTES

typedef enum dm_source_proof_status_t {
  DM_SOURCE_PROOF_OK = 0,
  DM_SOURCE_PROOF_ERR_ARGUMENT = -1,
  DM_SOURCE_PROOF_ERR_SIZE = -2,
  DM_SOURCE_PROOF_ERR_INPUT_ALIAS = -3,
  DM_SOURCE_PROOF_ERR_OUTPUT_ALIAS = -4,
  DM_SOURCE_PROOF_ERR_KEY_EPOCH = -5,
  DM_SOURCE_PROOF_ERR_RETRY = -6,
  DM_SOURCE_PROOF_ERR_RANGE = -7,
  DM_SOURCE_PROOF_ERR_CSPRNG = -8,
  DM_SOURCE_PROOF_ERR_WITNESS = -9,
  DM_SOURCE_PROOF_ERR_STATEMENT = -10,
  DM_SOURCE_PROOF_ERR_PROOF = -11,
  DM_SOURCE_PROOF_ERR_ENCODING = -12,
  DM_SOURCE_PROOF_ERR_SIGNATURE = -13,
  DM_SOURCE_PROOF_ERR_ALLOCATION = -14,
} dm_source_proof_status_t;

/*
 * The successful package is caller-owned storage containing volatile source
 * and proof material.  It must not enter State, WAL, receipts, logs, backups,
 * or another downstream authority.  Clear it as soon as its bounded use ends.
 */
typedef struct dm_source_proof_output_t {
  uint8_t canonical_x[DM_SOURCE_PROOF_CANONICAL_X_BYTES];
  uint8_t signature[DM_SOURCE_PROOF_SIGNATURE_BYTES];
  uint8_t frame[DM_SOURCE_PROOF_FRAME_BYTES];
  uint64_t key_epoch;
} dm_source_proof_output_t;

const char* dm_source_proof_status_name(dm_source_proof_status_t status);

void dm_source_proof_output_clear(dm_source_proof_output_t* output);

/*
 * Build one fresh source-authenticated proof package synchronously.
 *
 * context, U, and values_le are caller-owned fixed spans.  values_le contains
 * 100 little-endian uint64 values and every value must be within the inclusive
 * relation bounds.  secret_key is borrowed for the call and must contain the
 * exact 4,896-byte ML-DSA-87 secret key.  key_epoch and max_final_retries are
 * both explicitly positive.  All advertised spans must remain valid and
 * unchanged until return.
 *
 * Cheap null, exact-size, epoch, retry, range, and alias checks run before OS
 * randomness, signing, witness materialization, or proof generation.  On an
 * ordinary failure a disjoint output is cleared in full.  An output alias is
 * rejected before any clear so a live input is never destroyed; input-input
 * aliases clear the disjoint output and return an error.
 */
dm_source_proof_status_t dm_source_proof_generate(
    const uint8_t* context, size_t context_bytes, const uint8_t* U,
    size_t U_bytes, const uint8_t* values_le, size_t values_le_bytes,
    const uint8_t* secret_key, size_t secret_key_bytes, uint64_t key_epoch,
    uint32_t max_final_retries, dm_source_proof_output_t* output);

#ifdef __cplusplus
}
#endif

#endif /* BLIND_LEDGER_DIRECT_MASK_SOURCE_PROOF_H */
