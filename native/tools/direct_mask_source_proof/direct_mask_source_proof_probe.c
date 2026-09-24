/* SPDX-License-Identifier: MIT */

/* Focused, non-activating source-producer probe. */

#include "direct_mask_source_proof.h"

#include "aes.h"
#include "blind_source_auth_mldsa87_v1.h"
#include "direct_mask_authenticated_proof.h"
#include "direct_mask_native.h"
#include "direct_mask_vole.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DM_SOURCE_PROOF_U_RESAMPLE_LIMIT 4u

static unsigned dm_source_proof_checks;
static unsigned dm_source_proof_failures;
static int dm_source_proof_fresh_proof;
static int dm_source_proof_cheap_first;
static dm_wire_status_t dm_source_proof_m3_decode = DM_WIRE_ERR_ARGUMENT;
static dm_wire_status_t dm_source_proof_m3_kernel = DM_WIRE_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_source_proof_m3_joint =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_source_proof_bad_signature =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_source_proof_bad_request =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_source_proof_bad_u =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_source_proof_bad_epoch =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_source_proof_bad_key =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_source_proof_short_frame =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_source_proof_extra_frame =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_source_proof_zero_frame =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_source_proof_bad_header =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;

#define CHECK(label, expression)                                                \
  do {                                                                          \
    ++dm_source_proof_checks;                                                   \
    if (!(expression)) {                                                        \
      ++dm_source_proof_failures;                                              \
      fprintf(stderr, "FAIL %s\n", (label));                                  \
    }                                                                           \
  } while (0)

static void secure_clear(void* pointer, size_t bytes) {
  volatile uint8_t* cursor = (volatile uint8_t*)pointer;
  if (cursor == NULL) {
    return;
  }
  while (bytes != 0u) {
    *cursor++ = 0u;
    --bytes;
  }
}

static int all_zero(const uint8_t* bytes, size_t length) {
  uint8_t accumulator = 0u;
  if (bytes == NULL) {
    return 0;
  }
  for (size_t index = 0; index != length; ++index) {
    accumulator |= bytes[index];
  }
  return accumulator == 0u;
}

static int output_is_clear(const dm_source_proof_output_t* output) {
  return output != NULL && all_zero((const uint8_t*)output, sizeof(*output));
}

static int verified_is_clear(
    const dm_authenticated_proof_verified_t* verified) {
  return verified != NULL && all_zero((const uint8_t*)verified, sizeof(*verified));
}

static void store_u64_le(uint8_t output[8], uint64_t value) {
  for (size_t index = 0; index != 8u; ++index) {
    output[index] = (uint8_t)(value & UINT64_C(0xff));
    value >>= 8;
  }
}

static void fill_values(uint8_t values_le[DM_SOURCE_PROOF_VALUES_BYTES]) {
  for (size_t index = 0; index != DM_SOURCE_PROOF_VALUE_COUNT; ++index) {
    const uint64_t value = (index & 1u) == 0u ? DMK_LOWER : DMK_UPPER;
    store_u64_le(values_le + 8u * index, value);
  }
}

static void run_cheap_api_checks(
    const uint8_t* context, const uint8_t* U, const uint8_t* values_le,
    const uint8_t* secret_key, uint64_t key_epoch,
    dm_source_proof_output_t* output) {
  uint8_t context_extra[DM_SOURCE_PROOF_CONTEXT_BYTES + 1u];
  uint8_t U_extra[DM_SOURCE_PROOF_U_BYTES + 1u];
  uint8_t values_extra[DM_SOURCE_PROOF_VALUES_BYTES + 1u];
  uint8_t key_extra[DM_SOURCE_PROOF_SECRET_KEY_BYTES + 1u];
  uint8_t values_bad[DM_SOURCE_PROOF_VALUES_BYTES];
  uint8_t zero_U[DM_SOURCE_PROOF_U_BYTES];
  uint8_t alias_input[DM_SOURCE_PROOF_VALUES_BYTES];
  uint8_t alias_before[DM_SOURCE_PROOF_CONTEXT_BYTES];
  uint8_t context_before[DM_SOURCE_PROOF_CONTEXT_BYTES];
  uint8_t U_before[DM_SOURCE_PROOF_U_BYTES];
  uint8_t values_before[DM_SOURCE_PROOF_VALUES_BYTES];
  uint8_t secret_key_before[DM_SOURCE_PROOF_SECRET_KEY_BYTES];
  uint8_t output_alias_key_before[DM_SOURCE_PROOF_SECRET_KEY_BYTES];
  uint8_t input_key_backing[DM_SOURCE_PROOF_SECRET_KEY_BYTES];
  uint8_t input_key_before[DM_SOURCE_PROOF_SECRET_KEY_BYTES];
  const size_t range_indices[] = {0u, 50u, 99u};
  dm_source_proof_status_t status;

  memset(context_extra, 0x11, sizeof(context_extra));
  memset(U_extra, 0x22, sizeof(U_extra));
  memset(values_extra, 0x33, sizeof(values_extra));
  memset(key_extra, 0x44, sizeof(key_extra));
  memset(zero_U, 0, sizeof(zero_U));
  memcpy(values_bad, values_le, sizeof(values_bad));
  memset(alias_input, 0x55, sizeof(alias_input));
  memcpy(context_before, context, sizeof(context_before));
  memcpy(U_before, U, sizeof(U_before));
  memcpy(values_before, values_le, sizeof(values_before));
  memcpy(secret_key_before, secret_key, sizeof(secret_key_before));
  memset(input_key_backing, 0x6d, sizeof(input_key_backing));
  memcpy(input_key_before, input_key_backing, sizeof(input_key_before));

  memset(output, 0xa5, sizeof(*output));
  dm_source_proof_output_clear(output);
  CHECK("output clear clears full output", output_is_clear(output));
  dm_source_proof_output_clear(output);
  CHECK("output clear is idempotent", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      NULL, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, secret_key,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES, output);
  CHECK("NULL context returns argument", status == DM_SOURCE_PROOF_ERR_ARGUMENT);
  CHECK("NULL context clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, NULL, DM_SOURCE_PROOF_U_BYTES,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, secret_key,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES, output);
  CHECK("NULL U returns argument", status == DM_SOURCE_PROOF_ERR_ARGUMENT);
  CHECK("NULL U clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES, NULL,
      DM_SOURCE_PROOF_VALUES_BYTES, secret_key, DM_SOURCE_PROOF_SECRET_KEY_BYTES,
      key_epoch, DMV_MAX_FINAL_RETRIES, output);
  CHECK("NULL values returns argument", status == DM_SOURCE_PROOF_ERR_ARGUMENT);
  CHECK("NULL values clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, NULL,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES, output);
  CHECK("NULL secret key returns argument", status == DM_SOURCE_PROOF_ERR_ARGUMENT);
  CHECK("NULL secret key clears output", output_is_clear(output));

  CHECK("NULL output returns argument",
        dm_source_proof_generate(
            context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
            values_le, DM_SOURCE_PROOF_VALUES_BYTES, secret_key,
            DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES,
            NULL) == DM_SOURCE_PROOF_ERR_ARGUMENT);

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context_extra, DM_SOURCE_PROOF_CONTEXT_BYTES - 1u, U,
      DM_SOURCE_PROOF_U_BYTES, values_le, DM_SOURCE_PROOF_VALUES_BYTES,
      secret_key, DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch,
      DMV_MAX_FINAL_RETRIES, output);
  CHECK("short context returns size", status == DM_SOURCE_PROOF_ERR_SIZE);
  CHECK("short context clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context_extra, DM_SOURCE_PROOF_CONTEXT_BYTES + 1u, U,
      DM_SOURCE_PROOF_U_BYTES, values_le, DM_SOURCE_PROOF_VALUES_BYTES,
      secret_key, DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch,
      DMV_MAX_FINAL_RETRIES, output);
  CHECK("extra context returns size", status == DM_SOURCE_PROOF_ERR_SIZE);
  CHECK("extra context clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U_extra, DM_SOURCE_PROOF_U_BYTES - 1u,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, secret_key,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES, output);
  CHECK("short U returns size", status == DM_SOURCE_PROOF_ERR_SIZE);
  CHECK("short U clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U_extra, DM_SOURCE_PROOF_U_BYTES + 1u,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, secret_key,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES, output);
  CHECK("extra U returns size", status == DM_SOURCE_PROOF_ERR_SIZE);
  CHECK("extra U clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
      values_extra, DM_SOURCE_PROOF_VALUES_BYTES - 1u, secret_key,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES, output);
  CHECK("short values returns size", status == DM_SOURCE_PROOF_ERR_SIZE);
  CHECK("short values clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
      values_extra, DM_SOURCE_PROOF_VALUES_BYTES + 1u, secret_key,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES, output);
  CHECK("extra values returns size", status == DM_SOURCE_PROOF_ERR_SIZE);
  CHECK("extra values clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, key_extra,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES - 1u, key_epoch, DMV_MAX_FINAL_RETRIES,
      output);
  CHECK("short secret key returns size", status == DM_SOURCE_PROOF_ERR_SIZE);
  CHECK("short secret key clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, key_extra,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES + 1u, key_epoch, DMV_MAX_FINAL_RETRIES,
      output);
  CHECK("extra secret key returns size", status == DM_SOURCE_PROOF_ERR_SIZE);
  CHECK("extra secret key clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, zero_U, sizeof(zero_U), values_le,
      DM_SOURCE_PROOF_VALUES_BYTES, secret_key, DM_SOURCE_PROOF_SECRET_KEY_BYTES,
      key_epoch, DMV_MAX_FINAL_RETRIES, output);
  CHECK("zero U returns statement", status == DM_SOURCE_PROOF_ERR_STATEMENT);
  CHECK("zero U clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, secret_key,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, 0u, DMV_MAX_FINAL_RETRIES, output);
  CHECK("zero epoch returns key-epoch", status == DM_SOURCE_PROOF_ERR_KEY_EPOCH);
  CHECK("zero epoch clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, secret_key,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, 0u, output);
  CHECK("zero retries returns retry", status == DM_SOURCE_PROOF_ERR_RETRY);
  CHECK("zero retries clears output", output_is_clear(output));

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, secret_key,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES + 1u,
      output);
  CHECK("excess retries returns retry", status == DM_SOURCE_PROOF_ERR_RETRY);
  CHECK("excess retries clears output", output_is_clear(output));

  for (size_t range_case = 0u;
       range_case < sizeof(range_indices) / sizeof(range_indices[0]);
       ++range_case) {
    const size_t index = range_indices[range_case];
    memcpy(values_bad, values_le, sizeof(values_bad));
    store_u64_le(values_bad + 8u * index, DMK_LOWER - UINT64_C(1));
    memset(output, 0xa5, sizeof(*output));
    status = dm_source_proof_generate(
        context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
        values_bad, sizeof(values_bad), secret_key,
        DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES,
        output);
    CHECK("below-range value returns range", status == DM_SOURCE_PROOF_ERR_RANGE);
    CHECK("below-range value clears full output", output_is_clear(output));

    memcpy(values_bad, values_le, sizeof(values_bad));
    store_u64_le(values_bad + 8u * index, DMK_UPPER + UINT64_C(1));
    memset(output, 0xa5, sizeof(*output));
    status = dm_source_proof_generate(
        context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
        values_bad, sizeof(values_bad), secret_key,
        DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES,
        output);
    CHECK("above-range value returns range", status == DM_SOURCE_PROOF_ERR_RANGE);
    CHECK("above-range value clears full output", output_is_clear(output));
  }

  CHECK("ordinary failures preserve full context",
        memcmp(context, context_before, sizeof(context_before)) == 0);
  CHECK("ordinary failures preserve full U",
        memcmp(U, U_before, sizeof(U_before)) == 0);
  CHECK("ordinary failures preserve full values",
        memcmp(values_le, values_before, sizeof(values_before)) == 0);
  CHECK("ordinary failures preserve full secret key",
        memcmp(secret_key, secret_key_before, sizeof(secret_key_before)) == 0);

  memset(output, 0xa5, sizeof(*output));
  status = dm_source_proof_generate(
      alias_input, DM_SOURCE_PROOF_CONTEXT_BYTES, alias_input,
      DM_SOURCE_PROOF_U_BYTES, values_le, DM_SOURCE_PROOF_VALUES_BYTES,
      secret_key, DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch,
      DMV_MAX_FINAL_RETRIES, output);
  CHECK("input-input alias returns input-alias",
        status == DM_SOURCE_PROOF_ERR_INPUT_ALIAS);
  CHECK("input-input alias clears disjoint output", output_is_clear(output));

  memset(output, 0x5a, sizeof(*output));
  memcpy(alias_before, (const uint8_t*)output, sizeof(alias_before));
  status = dm_source_proof_generate(
      (const uint8_t*)output, DM_SOURCE_PROOF_CONTEXT_BYTES, NULL,
      DM_SOURCE_PROOF_U_BYTES, values_le, DM_SOURCE_PROOF_VALUES_BYTES,
      secret_key, DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch,
      DMV_MAX_FINAL_RETRIES, output);
  CHECK("output/context alias returns output-alias",
        status == DM_SOURCE_PROOF_ERR_OUTPUT_ALIAS);
  CHECK("output/context alias preserves live input",
        memcmp(alias_before, (const uint8_t*)output, sizeof(alias_before)) == 0);

  memset(output, 0x5a, sizeof(*output));
  {
    uint8_t* output_alias_key =
        (uint8_t*)output + sizeof(*output) -
        DM_SOURCE_PROOF_SECRET_KEY_BYTES;
    memset(output_alias_key, 0x6e, DM_SOURCE_PROOF_SECRET_KEY_BYTES);
    memcpy(output_alias_key_before, output_alias_key,
           sizeof(output_alias_key_before));
    status = dm_source_proof_generate(
        context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
        values_le, DM_SOURCE_PROOF_VALUES_BYTES, output_alias_key,
        DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch, DMV_MAX_FINAL_RETRIES,
        output);
    CHECK("output/secret-key alias returns output-alias",
          status == DM_SOURCE_PROOF_ERR_OUTPUT_ALIAS);
    CHECK("output/secret-key alias preserves full key",
          memcmp(output_alias_key_before, output_alias_key,
                 sizeof(output_alias_key_before)) == 0);
  }

  memset(output, 0xa5, sizeof(*output));
  memcpy(input_key_before, input_key_backing, sizeof(input_key_before));
  status = dm_source_proof_generate(
      input_key_backing, DM_SOURCE_PROOF_CONTEXT_BYTES, U,
      DM_SOURCE_PROOF_U_BYTES, values_le, DM_SOURCE_PROOF_VALUES_BYTES,
      input_key_backing, DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch,
      DMV_MAX_FINAL_RETRIES, output);
  CHECK("input/secret-key alias returns input-alias",
        status == DM_SOURCE_PROOF_ERR_INPUT_ALIAS);
  CHECK("input/secret-key alias clears disjoint output", output_is_clear(output));
  CHECK("input/secret-key alias preserves full backing",
        memcmp(input_key_before, input_key_backing,
               sizeof(input_key_before)) == 0);

  CHECK("cheap cases preserve full caller spans",
        memcmp(context, context_before, sizeof(context_before)) == 0 &&
            memcmp(U, U_before, sizeof(U_before)) == 0 &&
            memcmp(values_le, values_before, sizeof(values_before)) == 0 &&
            memcmp(secret_key, secret_key_before,
                   sizeof(secret_key_before)) == 0);

  secure_clear(alias_before, sizeof(alias_before));
  secure_clear(input_key_before, sizeof(input_key_before));
  secure_clear(input_key_backing, sizeof(input_key_backing));
  secure_clear(output_alias_key_before, sizeof(output_alias_key_before));
  secure_clear(secret_key_before, sizeof(secret_key_before));
  secure_clear(values_before, sizeof(values_before));
  secure_clear(U_before, sizeof(U_before));
  secure_clear(context_before, sizeof(context_before));
  secure_clear(zero_U, sizeof(zero_U));
  secure_clear(alias_input, sizeof(alias_input));
  secure_clear(values_bad, sizeof(values_bad));
  secure_clear(key_extra, sizeof(key_extra));
  secure_clear(values_extra, sizeof(values_extra));
  secure_clear(U_extra, sizeof(U_extra));
  secure_clear(context_extra, sizeof(context_extra));
  dm_source_proof_cheap_first = 1;
}

static int run_probe(void) {
  const uint64_t key_epoch = UINT64_C(0x0102030405060708);
  uint8_t context[DM_SOURCE_PROOF_CONTEXT_BYTES];
  uint8_t U[DM_SOURCE_PROOF_U_BYTES];
  uint8_t values_le[DM_SOURCE_PROOF_VALUES_BYTES];
  uint8_t seed[BLIND_SOURCE_AUTH_MLDSA87_V1_SEED_BYTES];
  uint8_t secret_key[DM_SOURCE_PROOF_SECRET_KEY_BYTES];
  uint8_t public_key[DM_SOURCE_AUTH_PUBLIC_KEY_BYTES];
  uint8_t signature_bad[DM_SOURCE_PROOF_SIGNATURE_BYTES];
  uint8_t context_before[DM_SOURCE_PROOF_CONTEXT_BYTES];
  uint8_t U_before[DM_SOURCE_PROOF_U_BYTES];
  uint8_t values_before[DM_SOURCE_PROOF_VALUES_BYTES];
  uint8_t secret_key_before[DM_SOURCE_PROOF_SECRET_KEY_BYTES];
  uint8_t* frame_mutated = NULL;
  uint8_t* frame_extra = NULL;
  dm_source_proof_output_t* output = NULL;
  dm_source_auth_request_t request;
  dm_source_auth_request_t request_bad;
  dm_authenticated_proof_verified_t verified;
  dm_wire_statement_t statement;
  dm_wire_proof_t stage_proof;
  dm_source_proof_status_t producer_status;
  size_t m3_offset;
  int setup_ok = 0;

  memset(context, 0, sizeof(context));
  memset(U, 0, sizeof(U));
  memset(values_le, 0, sizeof(values_le));
  memset(seed, 0, sizeof(seed));
  memset(secret_key, 0, sizeof(secret_key));
  memset(public_key, 0, sizeof(public_key));
  memset(signature_bad, 0, sizeof(signature_bad));
  memset(context_before, 0, sizeof(context_before));
  memset(U_before, 0, sizeof(U_before));
  memset(values_before, 0, sizeof(values_before));
  memset(secret_key_before, 0, sizeof(secret_key_before));
  dm_source_auth_request_init(&request);
  memset(&request_bad, 0, sizeof(request_bad));
  memset(&verified, 0, sizeof(verified));
  memset(&statement, 0, sizeof(statement));
  dm_wire_proof_init(&stage_proof);

  output = (dm_source_proof_output_t*)calloc(1u, sizeof(*output));
  frame_mutated = (uint8_t*)malloc(DM_SOURCE_PROOF_FRAME_BYTES);
  frame_extra = (uint8_t*)malloc(DM_SOURCE_PROOF_FRAME_BYTES + 1u);
  if (output == NULL || frame_mutated == NULL || frame_extra == NULL) {
    CHECK("probe storage allocation", 0);
    goto cleanup;
  }

  /* Cheap cases are deliberately executed before any valid proof setup. */
  fill_values(values_le);
  memset(context, 0x17, sizeof(context));
  memset(U, 0x29, sizeof(U));
  memset(secret_key, 0x3b, sizeof(secret_key));
  run_cheap_api_checks(context, U, values_le, secret_key, key_epoch, output);
  if (dm_source_proof_failures != 0u) {
    goto cleanup;
  }

  if (dm_wire_os_random_bytes(NULL, context, sizeof(context)) != 0 ||
      dm_wire_os_random_bytes(NULL, seed, sizeof(seed)) != 0) {
    CHECK("fresh OS context/ML-DSA seed", 0);
    goto cleanup;
  }
  {
    int nonzero_U = 0;
    for (unsigned attempt = 0u; attempt < DM_SOURCE_PROOF_U_RESAMPLE_LIMIT;
         ++attempt) {
      if (dm_wire_os_random_bytes(NULL, U, sizeof(U)) != 0) {
        CHECK("fresh OS U", 0);
        goto cleanup;
      }
      if (!all_zero(U, sizeof(U))) {
        nonzero_U = 1;
        break;
      }
    }
    CHECK("fresh OS U is nonzero", nonzero_U != 0);
    if (nonzero_U == 0) {
      goto cleanup;
    }
  }
  fill_values(values_le);
  if (blind_source_auth_mldsa87_v1_keypair_from_seed(
          public_key, sizeof(public_key), secret_key, sizeof(secret_key), seed,
          sizeof(seed)) != BLIND_SOURCE_AUTH_MLDSA87_V1_OK) {
    CHECK("fresh ML-DSA key setup", 0);
    goto cleanup;
  }

  memcpy(request.expected_context, context, sizeof(request.expected_context));
  memcpy(request.expected_U, U, sizeof(request.expected_U));
  memcpy(request.trusted_public_key, public_key, sizeof(public_key));
  request.expected_key_epoch = key_epoch;

  memcpy(context_before, context, sizeof(context_before));
  memcpy(U_before, U, sizeof(U_before));
  memcpy(values_before, values_le, sizeof(values_before));
  memcpy(secret_key_before, secret_key, sizeof(secret_key_before));
  producer_status = dm_source_proof_generate(
      context, sizeof(context), U, sizeof(U), values_le, sizeof(values_le),
      secret_key, sizeof(secret_key), key_epoch, DMV_MAX_FINAL_RETRIES, output);
  CHECK("one fresh source-owned proof package", producer_status == DM_SOURCE_PROOF_OK);
  if (producer_status != DM_SOURCE_PROOF_OK) {
    goto cleanup;
  }
  dm_source_proof_fresh_proof = 1;

  CHECK("producer preserves full context",
        memcmp(context, context_before, sizeof(context_before)) == 0);
  CHECK("producer preserves full U",
        memcmp(U, U_before, sizeof(U_before)) == 0);
  CHECK("producer preserves full values",
        memcmp(values_le, values_before, sizeof(values_before)) == 0);
  CHECK("producer preserves full secret key",
        memcmp(secret_key, secret_key_before, sizeof(secret_key_before)) == 0);
  secure_clear(secret_key_before, sizeof(secret_key_before));
  secure_clear(values_before, sizeof(values_before));
  secure_clear(U_before, sizeof(U_before));
  secure_clear(context_before, sizeof(context_before));

  /* The caller-owned source inputs/key are destroyed before verification. */
  secure_clear(secret_key, sizeof(secret_key));
  secure_clear(seed, sizeof(seed));
  secure_clear(values_le, sizeof(values_le));
  secure_clear(U, sizeof(U));
  secure_clear(context, sizeof(context));

  CHECK("producer output epoch", output->key_epoch == key_epoch);
  CHECK("joint verifier accepts producer package",
        dm_authenticated_proof_verify(
            &request, key_epoch, output->canonical_x,
            sizeof(output->canonical_x), output->signature,
            sizeof(output->signature), output->frame, sizeof(output->frame),
            &verified) == DM_AUTHENTICATED_PROOF_OK);
  CHECK("joint verifier returns producer x",
        memcmp(verified.canonical_x, output->canonical_x,
               sizeof(output->canonical_x)) == 0);
  CHECK("joint verifier returns producer epoch", verified.key_epoch == key_epoch);
  dm_authenticated_proof_verified_clear(&verified);

  if (dm_wire_statement_decode(&statement, output->canonical_x,
                               sizeof(output->canonical_x)) != DM_WIRE_OK) {
    CHECK("decode producer statement for attacks", 0);
    goto cleanup;
  }
  m3_offset = DM_WIRE_HEADER_BYTES + DM_WIRE_STATEMENT_BYTES + DM_WIRE_NU_BYTES +
              DM_WIRE_NONCE_COUNT * DM_WIRE_NONCE_BYTES + DM_WIRE_M1_BYTES +
              DM_WIRE_M2_BYTES;
  CHECK("m3 offset is inside exact frame",
        m3_offset + DM_WIRE_M3_BYTES <= sizeof(output->frame));

  memcpy(frame_mutated, output->frame, sizeof(output->frame));
  frame_mutated[m3_offset] ^= 0x01u;
  dm_source_proof_m3_decode =
      dm_wire_decode(&stage_proof, &statement, frame_mutated,
                     sizeof(output->frame));
  dm_source_proof_m3_kernel =
      dm_source_proof_m3_decode == DM_WIRE_OK
          ? dm_wire_verify_kernel(&stage_proof, &statement)
          : DM_WIRE_ERR_ARGUMENT;
  dm_wire_proof_clear(&stage_proof);
  memset(&verified, 0xa5, sizeof(verified));
  dm_source_proof_m3_joint = dm_authenticated_proof_verify(
      &request, key_epoch, output->canonical_x, sizeof(output->canonical_x),
      output->signature, sizeof(output->signature), frame_mutated,
      sizeof(output->frame), &verified);
  CHECK("m3 mutation remains decode-valid",
        dm_source_proof_m3_decode == DM_WIRE_OK);
  CHECK("m3 mutation fails independent kernel",
        dm_source_proof_m3_kernel != DM_WIRE_OK);
  CHECK("m3 mutation maps to proof failure",
        dm_source_proof_m3_joint == DM_AUTHENTICATED_PROOF_ERR_PROOF);
  CHECK("m3 mutation clears joint output", verified_is_clear(&verified));

  memset(frame_mutated, 0, sizeof(output->frame));
  memset(&verified, 0xa5, sizeof(verified));
  dm_source_proof_zero_frame = dm_authenticated_proof_verify(
      &request, key_epoch, output->canonical_x, sizeof(output->canonical_x),
      output->signature, sizeof(output->signature), frame_mutated,
      sizeof(output->frame), &verified);
  CHECK("all-zero frame maps to decode", dm_source_proof_zero_frame ==
                                             DM_AUTHENTICATED_PROOF_ERR_DECODE);
  CHECK("all-zero frame clears output", verified_is_clear(&verified));

  memcpy(frame_mutated, output->frame, sizeof(output->frame));
  frame_mutated[0] ^= 0x01u;
  memset(&verified, 0xa5, sizeof(verified));
  dm_source_proof_bad_header = dm_authenticated_proof_verify(
      &request, key_epoch, output->canonical_x, sizeof(output->canonical_x),
      output->signature, sizeof(output->signature), frame_mutated,
      sizeof(output->frame), &verified);
  CHECK("bad frame header maps to decode", dm_source_proof_bad_header ==
                                               DM_AUTHENTICATED_PROOF_ERR_DECODE);
  CHECK("bad frame header clears output", verified_is_clear(&verified));

  memcpy(frame_mutated, output->frame, sizeof(output->frame));
  frame_mutated[sizeof(output->frame) - 1u] ^= 0x01u;
  memset(&verified, 0xa5, sizeof(verified));
  CHECK("proof body corruption rejects",
        dm_authenticated_proof_verify(
            &request, key_epoch, output->canonical_x,
            sizeof(output->canonical_x), output->signature,
            sizeof(output->signature), frame_mutated, sizeof(output->frame),
            &verified) != DM_AUTHENTICATED_PROOF_OK);
  CHECK("proof body corruption clears output", verified_is_clear(&verified));

  memset(&verified, 0xa5, sizeof(verified));
  dm_source_proof_short_frame = dm_authenticated_proof_verify(
      &request, key_epoch, output->canonical_x, sizeof(output->canonical_x),
      output->signature, sizeof(output->signature), output->frame,
      sizeof(output->frame) - 1u, &verified);
  CHECK("short frame returns size", dm_source_proof_short_frame ==
                                         DM_AUTHENTICATED_PROOF_ERR_SIZE);
  CHECK("short frame clears output", verified_is_clear(&verified));

  memcpy(frame_extra, output->frame, sizeof(output->frame));
  frame_extra[sizeof(output->frame)] = 0u;
  memset(&verified, 0xa5, sizeof(verified));
  dm_source_proof_extra_frame = dm_authenticated_proof_verify(
      &request, key_epoch, output->canonical_x, sizeof(output->canonical_x),
      output->signature, sizeof(output->signature), frame_extra,
      sizeof(output->frame) + 1u, &verified);
  CHECK("extra frame returns size", dm_source_proof_extra_frame ==
                                         DM_AUTHENTICATED_PROOF_ERR_SIZE);
  CHECK("extra frame clears output", verified_is_clear(&verified));

  memcpy(signature_bad, output->signature, sizeof(signature_bad));
  signature_bad[0] ^= 0x01u;
  memset(&verified, 0xa5, sizeof(verified));
  dm_source_proof_bad_signature = dm_authenticated_proof_verify(
      &request, key_epoch, output->canonical_x, sizeof(output->canonical_x),
      signature_bad, sizeof(signature_bad), output->frame,
      sizeof(output->frame), &verified);
  CHECK("bad signature maps to source-auth",
        dm_source_proof_bad_signature == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("bad signature clears output", verified_is_clear(&verified));

  memcpy(&request_bad, &request, sizeof(request_bad));
  request_bad.expected_context[0] ^= 0x01u;
  memset(&verified, 0xa5, sizeof(verified));
  dm_source_proof_bad_request = dm_authenticated_proof_verify(
      &request_bad, key_epoch, output->canonical_x, sizeof(output->canonical_x),
      output->signature, sizeof(output->signature), output->frame,
      sizeof(output->frame), &verified);
  CHECK("changed request context maps to source-auth",
        dm_source_proof_bad_request == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("changed request context clears output", verified_is_clear(&verified));

  memcpy(&request_bad, &request, sizeof(request_bad));
  request_bad.expected_U[0] ^= 0x01u;
  memset(&verified, 0xa5, sizeof(verified));
  dm_source_proof_bad_u = dm_authenticated_proof_verify(
      &request_bad, key_epoch, output->canonical_x, sizeof(output->canonical_x),
      output->signature, sizeof(output->signature), output->frame,
      sizeof(output->frame), &verified);
  CHECK("changed request U maps to source-auth",
        dm_source_proof_bad_u == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("changed request U clears output", verified_is_clear(&verified));

  memset(&verified, 0xa5, sizeof(verified));
  dm_source_proof_bad_epoch = dm_authenticated_proof_verify(
      &request, key_epoch + 1u, output->canonical_x, sizeof(output->canonical_x),
      output->signature, sizeof(output->signature), output->frame,
      sizeof(output->frame), &verified);
  CHECK("wrong epoch maps to source-auth",
        dm_source_proof_bad_epoch == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("wrong epoch clears output", verified_is_clear(&verified));

  memcpy(&request_bad, &request, sizeof(request_bad));
  request_bad.trusted_public_key[0] ^= 0x01u;
  memset(&verified, 0xa5, sizeof(verified));
  dm_source_proof_bad_key = dm_authenticated_proof_verify(
      &request_bad, key_epoch, output->canonical_x, sizeof(output->canonical_x),
      output->signature, sizeof(output->signature), output->frame,
      sizeof(output->frame), &verified);
  CHECK("wrong trusted key maps to source-auth",
        dm_source_proof_bad_key == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("wrong trusted key clears output", verified_is_clear(&verified));

  setup_ok = 1;

cleanup:
  if (!setup_ok && dm_source_proof_fresh_proof != 0) {
    dm_source_proof_fresh_proof = 0;
  }
  dm_source_proof_output_clear(output);
  dm_authenticated_proof_verified_clear(&verified);
  dm_source_auth_request_clear(&request);
  dm_source_auth_request_clear(&request_bad);
  dm_wire_proof_clear(&stage_proof);
  if (frame_extra != NULL) {
    secure_clear(frame_extra, DM_SOURCE_PROOF_FRAME_BYTES + 1u);
    free(frame_extra);
  }
  if (frame_mutated != NULL) {
    secure_clear(frame_mutated, DM_SOURCE_PROOF_FRAME_BYTES);
    free(frame_mutated);
  }
  if (output != NULL) {
    secure_clear(output, sizeof(*output));
    free(output);
  }
  secure_clear(signature_bad, sizeof(signature_bad));
  secure_clear(public_key, sizeof(public_key));
  secure_clear(secret_key, sizeof(secret_key));
  secure_clear(seed, sizeof(seed));
  secure_clear(secret_key_before, sizeof(secret_key_before));
  secure_clear(values_before, sizeof(values_before));
  secure_clear(U_before, sizeof(U_before));
  secure_clear(context_before, sizeof(context_before));
  secure_clear(values_le, sizeof(values_le));
  secure_clear(U, sizeof(U));
  secure_clear(context, sizeof(context));
  secure_clear(&statement, sizeof(statement));
  return dm_source_proof_failures == 0u ? 0 : 1;
}

int main(void) {
  const int result = run_probe();
  printf("STATUS NON_ACTIVATING_DIRECT_MASK_SOURCE_PROOF\n");
  printf("CANONICAL_X_BYTES=%u SIGNATURE_BYTES=%u FRAME_BYTES=%u\n",
         DM_SOURCE_PROOF_CANONICAL_X_BYTES, DM_SOURCE_PROOF_SIGNATURE_BYTES,
         DM_SOURCE_PROOF_FRAME_BYTES);
  printf("FRESH_TRUE_SYNTHETIC_PROOF=%s\n",
         dm_source_proof_fresh_proof ? "TRUE" : "FALSE");
  printf("CHEAP_INPUT_CASES_BEFORE_PROOF=%s\n",
         dm_source_proof_cheap_first ? "TRUE" : "FALSE");
  printf("OBSERVED_M3_DECODE=%s M3_KERNEL=%s M3_JOINT=%s\n",
         dm_wire_status_name(dm_source_proof_m3_decode),
         dm_wire_status_name(dm_source_proof_m3_kernel),
         dm_authenticated_proof_status_name(dm_source_proof_m3_joint));
  printf("OBSERVED_BAD_SIGNATURE=%s BAD_REQUEST=%s BAD_U=%s BAD_EPOCH=%s BAD_KEY=%s\n",
          dm_authenticated_proof_status_name(dm_source_proof_bad_signature),
          dm_authenticated_proof_status_name(dm_source_proof_bad_request),
          dm_authenticated_proof_status_name(dm_source_proof_bad_u),
          dm_authenticated_proof_status_name(dm_source_proof_bad_epoch),
          dm_authenticated_proof_status_name(dm_source_proof_bad_key));
  printf("OBSERVED_SHORT_FRAME=%s EXTRA_FRAME=%s ZERO_FRAME=%s BAD_HEADER=%s\n",
         dm_authenticated_proof_status_name(dm_source_proof_short_frame),
         dm_authenticated_proof_status_name(dm_source_proof_extra_frame),
         dm_authenticated_proof_status_name(dm_source_proof_zero_frame),
         dm_authenticated_proof_status_name(dm_source_proof_bad_header));
  printf("PRODUCER_FLOW=OS_ROOT_NATIVE_WITNESS_WIRE_PROOF_SOURCE_SIGNATURE\n");
  printf("OUTPUT_OWNS_X_SIGNATURE_FRAME_AND_EPOCH_ONLY=TRUE\n");
  printf("NO_DIRECTIVE_STATE_SOURCE_TRUTH_OR_ACTIVATION_CLAIM=TRUE\n");
  printf("CHECK_COUNT=%u FAILED=%u\n", dm_source_proof_checks,
         dm_source_proof_failures);
  printf("ALL_TESTS=%s\n", dm_source_proof_failures == 0u ? "PASS" : "FAIL");
  return result;
}
