/* SPDX-License-Identifier: MIT */
#ifndef BLIND_LEDGER_DIRECT_MASK_PIPELINE_H
#define BLIND_LEDGER_DIRECT_MASK_PIPELINE_H

/*
 * Non-activating transport candidate for the accepted direct-mask producer
 * and independently verified authenticated-proof seam.  This boundary owns
 * only fixed-size parsing, transport binding, and quiet process result
 * classification.  It owns no source truth, policy, state, custody, or
 * activation authority.
 */

#include <stddef.h>
#include <stdint.h>

#include "../direct_mask_authenticated_proof/direct_mask_authenticated_proof.h"
#include "../direct_mask_source_proof/direct_mask_source_proof.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DM_PIPELINE_MAGIC_BYTES 8u
#define DM_PIPELINE_SOURCE_MAGIC "DMSI0001"
#define DM_PIPELINE_CAPSULE_MAGIC "DMSP0001"
#define DM_PIPELINE_VERIFIER_MAGIC "DMVI0001"

#define DM_PIPELINE_SOURCE_MAGIC_OFFSET 0u
#define DM_PIPELINE_SOURCE_EPOCH_OFFSET 8u
#define DM_PIPELINE_SOURCE_RETRIES_OFFSET 16u
#define DM_PIPELINE_SOURCE_CONTEXT_OFFSET 20u
#define DM_PIPELINE_SOURCE_U_OFFSET 84u
#define DM_PIPELINE_SOURCE_VALUES_OFFSET 180u
#define DM_PIPELINE_SOURCE_SECRET_KEY_OFFSET 980u
#define DM_PIPELINE_SOURCE_INPUT_BYTES 5876u

#define DM_PIPELINE_CAPSULE_MAGIC_OFFSET 0u
#define DM_PIPELINE_CAPSULE_EPOCH_OFFSET 8u
#define DM_PIPELINE_CAPSULE_SIGNATURE_OFFSET 16u
#define DM_PIPELINE_CAPSULE_FRAME_OFFSET \
  (DM_PIPELINE_CAPSULE_SIGNATURE_OFFSET + DM_SOURCE_PROOF_SIGNATURE_BYTES)
#define DM_PIPELINE_CAPSULE_BYTES \
  (DM_PIPELINE_CAPSULE_FRAME_OFFSET + DM_SOURCE_PROOF_FRAME_BYTES)

#define DM_PIPELINE_VERIFIER_MAGIC_OFFSET 0u
#define DM_PIPELINE_VERIFIER_EPOCH_OFFSET 8u
#define DM_PIPELINE_VERIFIER_CONTEXT_OFFSET 16u
#define DM_PIPELINE_VERIFIER_U_OFFSET 80u
#define DM_PIPELINE_VERIFIER_PUBLIC_KEY_OFFSET 176u
#define DM_PIPELINE_VERIFIER_CAPSULE_OFFSET \
  (DM_PIPELINE_VERIFIER_PUBLIC_KEY_OFFSET + DM_SOURCE_AUTH_PUBLIC_KEY_BYTES)
#define DM_PIPELINE_VERIFIER_INPUT_BYTES \
  (DM_PIPELINE_VERIFIER_CAPSULE_OFFSET + DM_PIPELINE_CAPSULE_BYTES)

#define DM_PIPELINE_FRAME_X_OFFSET DM_WIRE_HEADER_BYTES
#define DM_PIPELINE_MAX_FINAL_RETRIES DMV_MAX_FINAL_RETRIES

#if DM_SOURCE_PROOF_CANONICAL_X_BYTES != 1147u
#error "the pipeline requires the pinned 1147-byte canonical x"
#endif
#if DM_SOURCE_PROOF_SIGNATURE_BYTES != 4627u
#error "the pipeline requires the pinned 4627-byte signature"
#endif
#if DM_SOURCE_PROOF_FRAME_BYTES != DM_WIRE_FRAME_BYTES
#error "the pipeline requires the DMV3 wire frame"
#endif
#if DM_SOURCE_PROOF_SECRET_KEY_BYTES != 4896u
#error "the pipeline requires the pinned 4896-byte secret key"
#endif

_Static_assert(DM_PIPELINE_SOURCE_CONTEXT_OFFSET +
                   DM_SOURCE_PROOF_CONTEXT_BYTES ==
               DM_PIPELINE_SOURCE_U_OFFSET,
               "source context offset must precede U");
_Static_assert(DM_PIPELINE_SOURCE_U_OFFSET + DM_SOURCE_PROOF_U_BYTES ==
                   DM_PIPELINE_SOURCE_VALUES_OFFSET,
               "source U offset must precede values");
_Static_assert(DM_PIPELINE_SOURCE_VALUES_OFFSET +
                   DM_SOURCE_PROOF_VALUES_BYTES ==
               DM_PIPELINE_SOURCE_SECRET_KEY_OFFSET,
               "source values offset must precede secret key");
_Static_assert(DM_PIPELINE_SOURCE_SECRET_KEY_OFFSET +
                   DM_SOURCE_PROOF_SECRET_KEY_BYTES ==
               DM_PIPELINE_SOURCE_INPUT_BYTES,
               "source input size must be exact");
_Static_assert(DM_PIPELINE_CAPSULE_SIGNATURE_OFFSET +
                   DM_SOURCE_PROOF_SIGNATURE_BYTES ==
               DM_PIPELINE_CAPSULE_FRAME_OFFSET,
               "capsule signature offset must precede frame");
_Static_assert(DM_PIPELINE_CAPSULE_FRAME_OFFSET + DM_SOURCE_PROOF_FRAME_BYTES ==
                   DM_PIPELINE_CAPSULE_BYTES,
               "capsule size must be exact");
_Static_assert(DM_PIPELINE_VERIFIER_PUBLIC_KEY_OFFSET +
                   DM_SOURCE_AUTH_PUBLIC_KEY_BYTES ==
               DM_PIPELINE_VERIFIER_CAPSULE_OFFSET,
               "verifier key offset must precede capsule");
_Static_assert(DM_PIPELINE_VERIFIER_CAPSULE_OFFSET +
                   DM_PIPELINE_CAPSULE_BYTES ==
               DM_PIPELINE_VERIFIER_INPUT_BYTES,
               "verifier input size must be exact");
_Static_assert(DM_PIPELINE_FRAME_X_OFFSET + DM_SOURCE_AUTH_X_BYTES <=
                   DM_SOURCE_PROOF_FRAME_BYTES,
               "canonical x must fit after the fixed frame header");

typedef enum dm_pipeline_status_t {
  DM_PIPELINE_ACCEPT = 0,
  DM_PIPELINE_REJECT = 1,
  DM_PIPELINE_MALFORMED = 2,
  DM_PIPELINE_INTERNAL = 3,
} dm_pipeline_status_t;

typedef struct dm_pipeline_source_input_view_t {
  const uint8_t* context;
  const uint8_t* U;
  const uint8_t* values_le;
  const uint8_t* secret_key;
  uint64_t key_epoch;
  uint32_t max_final_retries;
} dm_pipeline_source_input_view_t;

typedef struct dm_pipeline_capsule_view_t {
  const uint8_t* signature;
  const uint8_t* frame;
  uint64_t presented_key_epoch;
} dm_pipeline_capsule_view_t;

typedef struct dm_pipeline_verifier_input_view_t {
  const uint8_t* expected_context;
  const uint8_t* expected_U;
  const uint8_t* trusted_public_key;
  const uint8_t* capsule;
  uint64_t expected_key_epoch;
} dm_pipeline_verifier_input_view_t;

/* Wipes volatile caller-owned bytes without being optimized away. */
void dm_pipeline_secure_clear(void* pointer, size_t bytes);

/* The two binary CLIs accept exactly one process argument (argv[0]). */
int dm_pipeline_cli_args_valid(int argc);

/* Fixed-size, explicit little-endian grammar decoders. */
int dm_pipeline_source_input_parse(
    const uint8_t* input, size_t input_bytes,
    dm_pipeline_source_input_view_t* view);
int dm_pipeline_capsule_decode(const uint8_t* capsule, size_t capsule_bytes,
                               dm_pipeline_capsule_view_t* view);
int dm_pipeline_verifier_input_parse(
    const uint8_t* input, size_t input_bytes,
    dm_pipeline_verifier_input_view_t* view);

/* Encode one producer output without duplicating canonical x outside DMV3. */
int dm_pipeline_capsule_encode(uint8_t* capsule, size_t capsule_bytes,
                               const dm_source_proof_output_t* output);

/* These are the exact core entrypoints used by the two CLIs and the probe. */
dm_pipeline_status_t dm_pipeline_source_process(
    const uint8_t* input, size_t input_bytes, uint8_t* capsule,
    size_t capsule_bytes);
dm_pipeline_status_t dm_pipeline_verifier_process(const uint8_t* input,
                                                  size_t input_bytes);

#ifdef __cplusplus
}
#endif

#endif /* BLIND_LEDGER_DIRECT_MASK_PIPELINE_H */
