/* SPDX-License-Identifier: MIT */
#ifndef BLIND_LEDGER_DIRECT_MASK_FIXTURE_H
#define BLIND_LEDGER_DIRECT_MASK_FIXTURE_H

#include <stddef.h>
#include <stdint.h>

#include "../direct_mask_pipeline/direct_mask_pipeline.h"
#include "blind_source_auth_mldsa87_v1.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DM_FIXTURE_REQUEST_MAGIC_BYTES 8u
#define DM_FIXTURE_REQUEST_MAGIC "DMSR0001"
#define DM_FIXTURE_REQUEST_EPOCH_OFFSET 8u
#define DM_FIXTURE_REQUEST_RETRIES_OFFSET 16u
#define DM_FIXTURE_REQUEST_CONTEXT_OFFSET 20u
#define DM_FIXTURE_REQUEST_U_OFFSET 84u
#define DM_FIXTURE_REQUEST_BYTES 180u
#define DM_FIXTURE_KEY_EPOCH UINT64_C(1)
#define DM_FIXTURE_MAX_FINAL_RETRIES DMV_MAX_FINAL_RETRIES
#define DM_FIXTURE_SEED_BYTES BLIND_SOURCE_AUTH_MLDSA87_V1_SEED_BYTES
#define DM_FIXTURE_PUBLIC_KEY_BYTES BLIND_SOURCE_AUTH_MLDSA87_V1_PUBLIC_KEY_BYTES
#define DM_FIXTURE_SECRET_KEY_BYTES BLIND_SOURCE_AUTH_MLDSA87_V1_SECRET_KEY_BYTES

typedef struct dm_fixture_request_view_t {
  uint64_t key_epoch;
  uint32_t max_final_retries;
  uint8_t context[DM_SOURCE_PROOF_CONTEXT_BYTES];
  uint8_t U[DM_SOURCE_PROOF_U_BYTES];
} dm_fixture_request_view_t;

typedef dm_pipeline_status_t (*dm_fixture_source_process_fn)(
    const uint8_t* input, size_t input_bytes, uint8_t* capsule,
    size_t capsule_bytes);

void dm_fixture_secure_clear(void* pointer, size_t bytes);
int dm_fixture_cli_args_valid(int argc);
void dm_fixture_fill_seed(uint8_t seed[DM_FIXTURE_SEED_BYTES]);
void dm_fixture_fill_values(uint8_t values_le[DM_SOURCE_PROOF_VALUES_BYTES]);
int dm_fixture_request_parse(const uint8_t* input, size_t input_bytes,
                             dm_fixture_request_view_t* view);
int dm_fixture_public_key_matches(const uint8_t* derived_public_key);
int dm_fixture_construct_source_input(
    const dm_fixture_request_view_t* request, const uint8_t* secret_key,
    size_t secret_key_bytes, uint8_t* source_input, size_t source_input_bytes);

/*
 * The key-binding gate is shared by the real appliance and the test-only
 * callback probe.  A mismatched expected key returns before the callback; the
 * callback is the one and only producer call on the success path.
 */
dm_pipeline_status_t dm_fixture_run_bound_source(
    const dm_fixture_request_view_t* request, const uint8_t* secret_key,
    size_t secret_key_bytes, const uint8_t* derived_public_key,
    const uint8_t* expected_public_key, uint8_t* capsule, size_t capsule_bytes,
    dm_fixture_source_process_fn process_fn);

#ifdef __cplusplus
}
#endif

#endif /* BLIND_LEDGER_DIRECT_MASK_FIXTURE_H */
