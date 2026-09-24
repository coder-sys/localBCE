/* SPDX-License-Identifier: MIT */

/* Focused non-activating probe for the exact source/verifier entrypoints. */

#include "direct_mask_pipeline.h"

#include "blind_source_auth_mldsa87_v1.h"
#include "direct_mask_kernel.h"
#include "direct_mask_vole.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DM_PIPELINE_U_RESAMPLE_LIMIT 4u
#define DM_PIPELINE_PARSER_ALIAS_OFFSET 8u

static unsigned dm_pipeline_checks;
static unsigned dm_pipeline_failures;
static int dm_pipeline_fresh_proof;
static int dm_pipeline_cheap_first;
static int dm_pipeline_old_version_rejected;
static dm_authenticated_proof_status_t dm_pipeline_bad_context =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_pipeline_bad_U =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_pipeline_bad_key =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_pipeline_bad_epoch =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_pipeline_bad_capsule_epoch =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_pipeline_bad_signature =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_pipeline_bad_header =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_pipeline_bad_x =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_pipeline_bad_m3 =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;

#define CHECK(label, expression)                                                \
  do {                                                                          \
    ++dm_pipeline_checks;                                                       \
    if (!(expression)) {                                                        \
      ++dm_pipeline_failures;                                                   \
      fprintf(stderr, "FAIL %s\n", (label));                                  \
    }                                                                           \
  } while (0)

static void secure_clear(void* pointer, size_t bytes) {
  dm_pipeline_secure_clear(pointer, bytes);
}

static int all_zero(const uint8_t* bytes, size_t length) {
  uint8_t accumulator = 0u;
  if (bytes == NULL) {
    return 0;
  }
  for (size_t index = 0u; index != length; ++index) {
    accumulator |= bytes[index];
  }
  return accumulator == 0u;
}

static int all_byte(const uint8_t* bytes, size_t length, uint8_t value) {
  if (bytes == NULL) {
    return 0;
  }
  for (size_t index = 0u; index != length; ++index) {
    if (bytes[index] != value) {
      return 0;
    }
  }
  return 1;
}

static void store_u32_le(uint8_t output[4], uint32_t value) {
  for (size_t index = 0u; index != 4u; ++index) {
    output[index] = (uint8_t)(value & UINT32_C(0xff));
    value >>= 8;
  }
}

static void store_u64_le(uint8_t output[8], uint64_t value) {
  for (size_t index = 0u; index != 8u; ++index) {
    output[index] = (uint8_t)(value & UINT64_C(0xff));
    value >>= 8;
  }
}

static void fill_values(uint8_t values_le[DM_SOURCE_PROOF_VALUES_BYTES]) {
  for (size_t index = 0u; index != DM_SOURCE_PROOF_VALUE_COUNT; ++index) {
    const uint64_t value = (index & 1u) == 0u ? DMK_LOWER : DMK_UPPER;
    store_u64_le(values_le + 8u * index, value);
  }
}

static void make_source_input(uint8_t* input, uint64_t key_epoch,
                              uint32_t max_final_retries,
                              const uint8_t* context, const uint8_t* U,
                              const uint8_t* values_le,
                              const uint8_t* secret_key) {
  memcpy(input + DM_PIPELINE_SOURCE_MAGIC_OFFSET, DM_PIPELINE_SOURCE_MAGIC,
         DM_PIPELINE_MAGIC_BYTES);
  store_u64_le(input + DM_PIPELINE_SOURCE_EPOCH_OFFSET, key_epoch);
  store_u32_le(input + DM_PIPELINE_SOURCE_RETRIES_OFFSET,
               max_final_retries);
  memcpy(input + DM_PIPELINE_SOURCE_CONTEXT_OFFSET, context,
         DM_SOURCE_PROOF_CONTEXT_BYTES);
  memcpy(input + DM_PIPELINE_SOURCE_U_OFFSET, U, DM_SOURCE_PROOF_U_BYTES);
  memcpy(input + DM_PIPELINE_SOURCE_VALUES_OFFSET, values_le,
         DM_SOURCE_PROOF_VALUES_BYTES);
  memcpy(input + DM_PIPELINE_SOURCE_SECRET_KEY_OFFSET, secret_key,
         DM_SOURCE_PROOF_SECRET_KEY_BYTES);
}

static void make_verifier_input(uint8_t* input, uint64_t expected_key_epoch,
                                const uint8_t* context, const uint8_t* U,
                                const uint8_t* public_key,
                                const uint8_t* capsule) {
  memcpy(input + DM_PIPELINE_VERIFIER_MAGIC_OFFSET,
         DM_PIPELINE_VERIFIER_MAGIC, DM_PIPELINE_MAGIC_BYTES);
  store_u64_le(input + DM_PIPELINE_VERIFIER_EPOCH_OFFSET, expected_key_epoch);
  memcpy(input + DM_PIPELINE_VERIFIER_CONTEXT_OFFSET, context,
         DM_SOURCE_AUTH_CONTEXT_BYTES);
  memcpy(input + DM_PIPELINE_VERIFIER_U_OFFSET, U, DM_SOURCE_AUTH_U_BYTES);
  memcpy(input + DM_PIPELINE_VERIFIER_PUBLIC_KEY_OFFSET, public_key,
         DM_SOURCE_AUTH_PUBLIC_KEY_BYTES);
  memcpy(input + DM_PIPELINE_VERIFIER_CAPSULE_OFFSET, capsule,
         DM_PIPELINE_CAPSULE_BYTES);
}

static dm_authenticated_proof_status_t direct_joint_status(
    const uint8_t* verifier_input) {
  dm_pipeline_verifier_input_view_t input_view;
  dm_pipeline_capsule_view_t capsule_view;
  dm_source_auth_request_t request;
  dm_authenticated_proof_verified_t verified;
  uint8_t canonical_x[DM_SOURCE_AUTH_X_BYTES];
  dm_authenticated_proof_status_t status =
      DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;

  memset(&input_view, 0, sizeof(input_view));
  memset(&capsule_view, 0, sizeof(capsule_view));
  memset(&request, 0, sizeof(request));
  memset(&verified, 0, sizeof(verified));
  memset(canonical_x, 0, sizeof(canonical_x));
  if (!dm_pipeline_verifier_input_parse(verifier_input,
                                        DM_PIPELINE_VERIFIER_INPUT_BYTES,
                                        &input_view) ||
      !dm_pipeline_capsule_decode(input_view.capsule,
                                  DM_PIPELINE_CAPSULE_BYTES,
                                  &capsule_view)) {
    return status;
  }

  dm_source_auth_request_init(&request);
  memcpy(request.expected_context, input_view.expected_context,
         sizeof(request.expected_context));
  memcpy(request.expected_U, input_view.expected_U, sizeof(request.expected_U));
  memcpy(request.trusted_public_key, input_view.trusted_public_key,
         sizeof(request.trusted_public_key));
  request.expected_key_epoch = input_view.expected_key_epoch;
  memcpy(canonical_x,
         capsule_view.frame + DM_PIPELINE_FRAME_X_OFFSET,
         sizeof(canonical_x));
  status = dm_authenticated_proof_verify(
      &request, capsule_view.presented_key_epoch, canonical_x,
      sizeof(canonical_x), capsule_view.signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, capsule_view.frame,
      DM_SOURCE_PROOF_FRAME_BYTES, &verified);

  dm_authenticated_proof_verified_clear(&verified);
  dm_source_auth_request_clear(&request);
  secure_clear(canonical_x, sizeof(canonical_x));
  secure_clear(&capsule_view, sizeof(capsule_view));
  secure_clear(&input_view, sizeof(input_view));
  return status;
}

static void check_verifier_mutation(
    const char* label, uint8_t* candidate, uint8_t* before,
    dm_authenticated_proof_status_t* observed) {
  dm_pipeline_status_t result;
  memcpy(before, candidate, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  result = dm_pipeline_verifier_process(candidate,
                                        DM_PIPELINE_VERIFIER_INPUT_BYTES);
  CHECK(label, result == DM_PIPELINE_REJECT);
  CHECK("verifier preserves full input on rejection",
        memcmp(candidate, before, DM_PIPELINE_VERIFIER_INPUT_BYTES) == 0);
  if (observed != NULL) {
    *observed = direct_joint_status(candidate);
  }
}

static int run_cheap_checks(uint8_t* source_input, uint8_t* source_extra,
                            uint8_t* verifier_input, uint8_t* capsule,
                            dm_source_proof_output_t* fake_output,
                            dm_source_proof_output_t* producer_alias,
                            uint8_t* input_key_backing,
                            uint8_t* alias_storage, uint8_t* parser_alias_storage,
                            uint8_t* parser_alias_before,
                            uint64_t key_epoch) {
  uint8_t context[DM_SOURCE_PROOF_CONTEXT_BYTES];
  uint8_t U[DM_SOURCE_PROOF_U_BYTES];
  uint8_t values_le[DM_SOURCE_PROOF_VALUES_BYTES];
  uint8_t secret_key[DM_SOURCE_PROOF_SECRET_KEY_BYTES];
  uint8_t source_before[DM_PIPELINE_SOURCE_INPUT_BYTES];
  uint8_t alias_before[DM_PIPELINE_SOURCE_INPUT_BYTES];
  uint8_t key_before[DM_SOURCE_PROOF_SECRET_KEY_BYTES];
  uint8_t* secret_key_alias;
  dm_pipeline_source_input_view_t source_view;
  dm_pipeline_verifier_input_view_t verifier_view;
  dm_pipeline_capsule_view_t capsule_view;
  dm_source_proof_status_t producer_status;
  dm_pipeline_status_t pipeline_status;

  memset(context, 0x11, sizeof(context));
  memset(U, 0x22, sizeof(U));
  memset(values_le, 0, sizeof(values_le));
  fill_values(values_le);
  memset(secret_key, 0x33, sizeof(secret_key));
  make_source_input(source_input, key_epoch, DM_PIPELINE_MAX_FINAL_RETRIES,
                    context, U, values_le, secret_key);
  memcpy(source_before, source_input, sizeof(source_before));
  memcpy(source_extra, source_input, DM_PIPELINE_SOURCE_INPUT_BYTES);
  source_extra[DM_PIPELINE_SOURCE_INPUT_BYTES] = 0x7fu;

  CHECK("source parser accepts exact grammar",
        dm_pipeline_source_input_parse(source_input,
                                       DM_PIPELINE_SOURCE_INPUT_BYTES,
                                       &source_view));
  CHECK("source u64 little-endian decode",
        source_view.key_epoch == key_epoch);
  CHECK("source u32 little-endian decode",
        source_view.max_final_retries == DM_PIPELINE_MAX_FINAL_RETRIES);
  CHECK("source parser exposes fixed offsets",
        source_view.context == source_input + DM_PIPELINE_SOURCE_CONTEXT_OFFSET &&
            source_view.U == source_input + DM_PIPELINE_SOURCE_U_OFFSET &&
            source_view.values_le == source_input + DM_PIPELINE_SOURCE_VALUES_OFFSET &&
            source_view.secret_key ==
                source_input + DM_PIPELINE_SOURCE_SECRET_KEY_OFFSET);
  CHECK("source parser rejects NULL", !dm_pipeline_source_input_parse(
                                           NULL, DM_PIPELINE_SOURCE_INPUT_BYTES,
                                           &source_view));
  CHECK("source parser rejects short", !dm_pipeline_source_input_parse(
                                            source_input,
                                            DM_PIPELINE_SOURCE_INPUT_BYTES - 1u,
                                            &source_view));
  CHECK("source parser rejects extra", !dm_pipeline_source_input_parse(
                                             source_extra,
                                             DM_PIPELINE_SOURCE_INPUT_BYTES + 1u,
                                             &source_view));
  memset(&source_view, 0xa6, sizeof(source_view));
  CHECK("source parser rejects partial epoch atomically",
        !dm_pipeline_source_input_parse(
            source_input, DM_PIPELINE_SOURCE_EPOCH_OFFSET + 4u, &source_view) &&
            all_zero((const uint8_t*)&source_view, sizeof(source_view)));
  memset(&source_view, 0xa6, sizeof(source_view));
  CHECK("source parser rejects non-NULL zero length",
        !dm_pipeline_source_input_parse(source_input, 0u, &source_view) &&
            all_zero((const uint8_t*)&source_view, sizeof(source_view)));

  memset(parser_alias_storage, 0x5bu,
         DM_PIPELINE_VERIFIER_INPUT_BYTES +
             sizeof(dm_pipeline_verifier_input_view_t) +
             DM_PIPELINE_PARSER_ALIAS_OFFSET);
  memcpy(parser_alias_storage, source_input, DM_PIPELINE_SOURCE_INPUT_BYTES);
  memcpy(parser_alias_before, parser_alias_storage,
         DM_PIPELINE_VERIFIER_INPUT_BYTES +
             sizeof(dm_pipeline_verifier_input_view_t) +
             DM_PIPELINE_PARSER_ALIAS_OFFSET);
  CHECK("source parser rejects valid-backed partial view alias",
        !dm_pipeline_source_input_parse(
            parser_alias_storage, DM_PIPELINE_SOURCE_INPUT_BYTES,
            (dm_pipeline_source_input_view_t*)(parser_alias_storage +
                                               DM_PIPELINE_PARSER_ALIAS_OFFSET)) &&
            memcmp(parser_alias_storage, parser_alias_before,
                   DM_PIPELINE_VERIFIER_INPUT_BYTES +
                       sizeof(dm_pipeline_verifier_input_view_t) +
                       DM_PIPELINE_PARSER_ALIAS_OFFSET) == 0);

  memset(fake_output, 0, sizeof(*fake_output));
  memset(fake_output->canonical_x, 0xa1, sizeof(fake_output->canonical_x));
  memset(fake_output->signature, 0xa2, sizeof(fake_output->signature));
  memset(fake_output->frame, 0xa3, sizeof(fake_output->frame));
  fake_output->key_epoch = key_epoch;
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES);
  CHECK("capsule exact encode", dm_pipeline_capsule_encode(
                                     capsule, DM_PIPELINE_CAPSULE_BYTES,
                                     fake_output));
  CHECK("capsule magic has no NUL suffix",
        memcmp(capsule, DM_PIPELINE_CAPSULE_MAGIC, DM_PIPELINE_MAGIC_BYTES) == 0);
  CHECK("capsule epoch is little-endian",
        capsule[DM_PIPELINE_CAPSULE_EPOCH_OFFSET] == 0x08u &&
            capsule[DM_PIPELINE_CAPSULE_EPOCH_OFFSET + 1u] == 0x07u &&
            capsule[DM_PIPELINE_CAPSULE_EPOCH_OFFSET + 7u] == 0x01u);
  CHECK("capsule has no redundant x",
        memcmp(capsule + DM_PIPELINE_CAPSULE_SIGNATURE_OFFSET,
               fake_output->signature, DM_SOURCE_PROOF_SIGNATURE_BYTES) == 0 &&
            memcmp(capsule + DM_PIPELINE_CAPSULE_FRAME_OFFSET,
                   fake_output->frame, DM_SOURCE_PROOF_FRAME_BYTES) == 0);
  CHECK("capsule parser accepts exact offsets",
        dm_pipeline_capsule_decode(capsule, DM_PIPELINE_CAPSULE_BYTES,
                                   &capsule_view));
  CHECK("capsule parser returns epoch and borrowed spans",
        capsule_view.presented_key_epoch == key_epoch &&
            capsule_view.signature ==
                capsule + DM_PIPELINE_CAPSULE_SIGNATURE_OFFSET &&
            capsule_view.frame == capsule + DM_PIPELINE_CAPSULE_FRAME_OFFSET);
  CHECK("capsule parser rejects NULL", !dm_pipeline_capsule_decode(
                                             NULL, DM_PIPELINE_CAPSULE_BYTES,
                                             &capsule_view));
  CHECK("capsule parser rejects short", !dm_pipeline_capsule_decode(
                                               capsule,
                                               DM_PIPELINE_CAPSULE_BYTES - 1u,
                                               &capsule_view));
  memset(&capsule_view, 0xa6, sizeof(capsule_view));
  CHECK("capsule parser rejects extra with cleared view",
        !dm_pipeline_capsule_decode(capsule, DM_PIPELINE_CAPSULE_BYTES + 1u,
                                    &capsule_view) &&
            all_zero((const uint8_t*)&capsule_view, sizeof(capsule_view)));
  memset(&capsule_view, 0xa6, sizeof(capsule_view));
  CHECK("capsule parser rejects non-NULL zero length",
        !dm_pipeline_capsule_decode(capsule, 0u, &capsule_view) &&
            all_zero((const uint8_t*)&capsule_view, sizeof(capsule_view)));
  memset(parser_alias_storage, 0x5cu,
         DM_PIPELINE_VERIFIER_INPUT_BYTES +
             sizeof(dm_pipeline_verifier_input_view_t) +
             DM_PIPELINE_PARSER_ALIAS_OFFSET);
  memcpy(parser_alias_storage, capsule, DM_PIPELINE_CAPSULE_BYTES);
  memcpy(parser_alias_before, parser_alias_storage,
         DM_PIPELINE_VERIFIER_INPUT_BYTES +
             sizeof(dm_pipeline_verifier_input_view_t) +
             DM_PIPELINE_PARSER_ALIAS_OFFSET);
  CHECK("capsule parser rejects valid-backed partial view alias",
        !dm_pipeline_capsule_decode(
            parser_alias_storage, DM_PIPELINE_CAPSULE_BYTES,
            (dm_pipeline_capsule_view_t*)(parser_alias_storage +
                                          DM_PIPELINE_PARSER_ALIAS_OFFSET)) &&
            memcmp(parser_alias_storage, parser_alias_before,
                   DM_PIPELINE_VERIFIER_INPUT_BYTES +
                       sizeof(dm_pipeline_verifier_input_view_t) +
                       DM_PIPELINE_PARSER_ALIAS_OFFSET) == 0);

  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES + 1u);
  CHECK("capsule short capacity rejects",
        !dm_pipeline_capsule_encode(capsule, DM_PIPELINE_CAPSULE_BYTES - 1u,
                                    fake_output));
  CHECK("capsule short capacity clears only advertised bytes",
        all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES - 1u) &&
            capsule[DM_PIPELINE_CAPSULE_BYTES - 1u] == 0xa5u &&
            capsule[DM_PIPELINE_CAPSULE_BYTES] == 0xa5u);
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES + 1u);
  CHECK("capsule extra capacity rejects",
        !dm_pipeline_capsule_encode(capsule, DM_PIPELINE_CAPSULE_BYTES + 1u,
                                    fake_output));
  CHECK("capsule extra capacity clears only full extent",
        all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES) &&
            capsule[DM_PIPELINE_CAPSULE_BYTES] == 0xa5u);
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES + 1u);
  CHECK("capsule NULL output exact capacity rejects",
        !dm_pipeline_capsule_encode(capsule, DM_PIPELINE_CAPSULE_BYTES, NULL));
  CHECK("capsule NULL output exact capacity clears only full extent",
        all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES) &&
            capsule[DM_PIPELINE_CAPSULE_BYTES] == 0xa5u);
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES + 1u);
  CHECK("capsule NULL output short capacity rejects",
        !dm_pipeline_capsule_encode(capsule, DM_PIPELINE_CAPSULE_BYTES - 1u,
                                    NULL));
  CHECK("capsule NULL output short capacity clears only advertised extent",
        all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES - 1u) &&
            capsule[DM_PIPELINE_CAPSULE_BYTES - 1u] == 0xa5u &&
            capsule[DM_PIPELINE_CAPSULE_BYTES] == 0xa5u);
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES + 1u);
  CHECK("capsule NULL output extra capacity rejects",
        !dm_pipeline_capsule_encode(capsule, DM_PIPELINE_CAPSULE_BYTES + 1u,
                                    NULL));
  CHECK("capsule NULL output extra capacity clears only full extent",
        all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES) &&
            capsule[DM_PIPELINE_CAPSULE_BYTES] == 0xa5u);
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES + 1u);
  CHECK("capsule NULL output zero capacity rejects without writing",
        !dm_pipeline_capsule_encode(capsule, 0u, NULL) &&
            all_byte(capsule, DM_PIPELINE_CAPSULE_BYTES + 1u, 0xa5u));
  memset(producer_alias, 0xb6, sizeof(*producer_alias));
  memcpy(parser_alias_before, producer_alias, sizeof(*producer_alias));
  CHECK("capsule output alias rejects before clear",
        !dm_pipeline_capsule_encode((uint8_t*)producer_alias,
                                    DM_PIPELINE_CAPSULE_BYTES,
                                    producer_alias) &&
            memcmp(producer_alias, parser_alias_before,
                   sizeof(*producer_alias)) == 0);

  source_input[DM_PIPELINE_SOURCE_MAGIC_OFFSET] = 'X';
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES);
  pipeline_status = dm_pipeline_source_process(
      source_input, DM_PIPELINE_SOURCE_INPUT_BYTES, capsule,
      DM_PIPELINE_CAPSULE_BYTES);
  CHECK("bad source magic is malformed", pipeline_status == DM_PIPELINE_MALFORMED);
  CHECK("bad source magic clears output", all_zero(capsule,
                                                    DM_PIPELINE_CAPSULE_BYTES));
  memcpy(source_input, source_before, sizeof(source_before));

  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES);
  CHECK("short source process is malformed",
        dm_pipeline_source_process(source_input,
                                    DM_PIPELINE_SOURCE_INPUT_BYTES - 1u,
                                    capsule, DM_PIPELINE_CAPSULE_BYTES) ==
            DM_PIPELINE_MALFORMED);
  CHECK("short source process clears output",
        all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES));
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES);
  CHECK("extra source process is malformed",
        dm_pipeline_source_process(source_extra,
                                    DM_PIPELINE_SOURCE_INPUT_BYTES + 1u,
                                    capsule, DM_PIPELINE_CAPSULE_BYTES) ==
            DM_PIPELINE_MALFORMED);
  CHECK("extra source process clears output",
        all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES));
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES);
  CHECK("NULL source process is malformed",
        dm_pipeline_source_process(NULL, DM_PIPELINE_SOURCE_INPUT_BYTES,
                                    capsule, DM_PIPELINE_CAPSULE_BYTES) ==
            DM_PIPELINE_MALFORMED);
  CHECK("NULL source process clears output",
        all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES));

  store_u64_le(source_input + DM_PIPELINE_SOURCE_EPOCH_OFFSET, 0u);
  CHECK("zero source epoch is malformed",
        !dm_pipeline_source_input_parse(source_input,
                                        DM_PIPELINE_SOURCE_INPUT_BYTES,
                                        &source_view));
  memcpy(source_input, source_before, sizeof(source_before));
  memset(source_input + DM_PIPELINE_SOURCE_U_OFFSET, 0,
         DM_SOURCE_PROOF_U_BYTES);
  CHECK("zero source U is malformed",
        !dm_pipeline_source_input_parse(source_input,
                                        DM_PIPELINE_SOURCE_INPUT_BYTES,
                                        &source_view));
  memcpy(source_input, source_before, sizeof(source_before));
  store_u32_le(source_input + DM_PIPELINE_SOURCE_RETRIES_OFFSET, 0u);
  CHECK("zero source retry bound is malformed",
        !dm_pipeline_source_input_parse(source_input,
                                        DM_PIPELINE_SOURCE_INPUT_BYTES,
                                        &source_view));
  memcpy(source_input, source_before, sizeof(source_before));
  store_u32_le(source_input + DM_PIPELINE_SOURCE_RETRIES_OFFSET,
               DM_PIPELINE_MAX_FINAL_RETRIES + 1u);
  CHECK("excess source retry bound is malformed",
        !dm_pipeline_source_input_parse(source_input,
                                        DM_PIPELINE_SOURCE_INPUT_BYTES,
                                        &source_view));
  memcpy(source_input, source_before, sizeof(source_before));

  CHECK("fake capsule re-encodes for verifier grammar",
        dm_pipeline_capsule_encode(capsule, DM_PIPELINE_CAPSULE_BYTES,
                                   fake_output));
  make_verifier_input(verifier_input, key_epoch, context, U, secret_key, capsule);
  CHECK("verifier parser accepts fixed grammar",
        dm_pipeline_verifier_input_parse(verifier_input,
                                         DM_PIPELINE_VERIFIER_INPUT_BYTES,
                                         &verifier_view));
  CHECK("verifier u64 little-endian decode",
        verifier_view.expected_key_epoch == key_epoch);
  CHECK("verifier parser exposes fixed offsets",
        verifier_view.expected_context ==
                verifier_input + DM_PIPELINE_VERIFIER_CONTEXT_OFFSET &&
            verifier_view.expected_U ==
                verifier_input + DM_PIPELINE_VERIFIER_U_OFFSET &&
            verifier_view.trusted_public_key ==
                verifier_input + DM_PIPELINE_VERIFIER_PUBLIC_KEY_OFFSET &&
            verifier_view.capsule ==
                verifier_input + DM_PIPELINE_VERIFIER_CAPSULE_OFFSET);
  CHECK("verifier parser rejects NULL", !dm_pipeline_verifier_input_parse(
                                               NULL,
                                               DM_PIPELINE_VERIFIER_INPUT_BYTES,
                                               &verifier_view));
  CHECK("verifier parser rejects short", !dm_pipeline_verifier_input_parse(
                                                 verifier_input,
                                                 DM_PIPELINE_VERIFIER_INPUT_BYTES - 1u,
                                                 &verifier_view));
  memset(&verifier_view, 0xa6, sizeof(verifier_view));
  CHECK("verifier parser rejects partial epoch atomically",
        !dm_pipeline_verifier_input_parse(
            verifier_input, DM_PIPELINE_VERIFIER_EPOCH_OFFSET + 4u,
            &verifier_view) &&
            all_zero((const uint8_t*)&verifier_view, sizeof(verifier_view)));
  memset(&verifier_view, 0xa6, sizeof(verifier_view));
  CHECK("verifier parser rejects non-NULL zero length",
        !dm_pipeline_verifier_input_parse(verifier_input, 0u, &verifier_view) &&
            all_zero((const uint8_t*)&verifier_view, sizeof(verifier_view)));
  memset(parser_alias_storage, 0x5du,
         DM_PIPELINE_VERIFIER_INPUT_BYTES +
             sizeof(dm_pipeline_verifier_input_view_t) +
             DM_PIPELINE_PARSER_ALIAS_OFFSET);
  memcpy(parser_alias_storage, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  memcpy(parser_alias_before, parser_alias_storage,
         DM_PIPELINE_VERIFIER_INPUT_BYTES +
             sizeof(dm_pipeline_verifier_input_view_t) +
             DM_PIPELINE_PARSER_ALIAS_OFFSET);
  CHECK("verifier parser rejects valid-backed partial view alias",
        !dm_pipeline_verifier_input_parse(
            parser_alias_storage, DM_PIPELINE_VERIFIER_INPUT_BYTES,
            (dm_pipeline_verifier_input_view_t*)(parser_alias_storage +
                                                 DM_PIPELINE_PARSER_ALIAS_OFFSET)) &&
            memcmp(parser_alias_storage, parser_alias_before,
                   DM_PIPELINE_VERIFIER_INPUT_BYTES +
                       sizeof(dm_pipeline_verifier_input_view_t) +
                       DM_PIPELINE_PARSER_ALIAS_OFFSET) == 0);
  memcpy(alias_storage, source_input, DM_PIPELINE_SOURCE_INPUT_BYTES);
  memcpy(alias_before, alias_storage, sizeof(alias_before));
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES);
  CHECK("pipeline input/output alias rejects before clear",
        dm_pipeline_source_process(alias_storage,
                                   DM_PIPELINE_SOURCE_INPUT_BYTES, alias_storage,
                                   DM_PIPELINE_CAPSULE_BYTES) ==
            DM_PIPELINE_INTERNAL);
  CHECK("pipeline alias preserves input prefix",
        memcmp(alias_storage, alias_before, sizeof(alias_before)) == 0);

  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES + 1u);
  memset(source_input + DM_PIPELINE_SOURCE_U_OFFSET, 0,
         DM_SOURCE_PROOF_U_BYTES);
  CHECK("source wrong capacity precedes parse and producer",
        dm_pipeline_source_process(source_input,
                                    DM_PIPELINE_SOURCE_INPUT_BYTES, capsule,
                                    DM_PIPELINE_CAPSULE_BYTES - 1u) ==
            DM_PIPELINE_INTERNAL);
  CHECK("source wrong capacity clears only advertised bytes",
        all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES - 1u) &&
            capsule[DM_PIPELINE_CAPSULE_BYTES - 1u] == 0xa5u &&
            capsule[DM_PIPELINE_CAPSULE_BYTES] == 0xa5u);
  memcpy(source_input, source_before, sizeof(source_before));
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES + 1u);
  CHECK("source extra capacity rejects before producer",
        dm_pipeline_source_process(source_input,
                                    DM_PIPELINE_SOURCE_INPUT_BYTES, capsule,
                                    DM_PIPELINE_CAPSULE_BYTES + 1u) ==
            DM_PIPELINE_INTERNAL);
  CHECK("source extra capacity clears only full extent",
        all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES) &&
            capsule[DM_PIPELINE_CAPSULE_BYTES] == 0xa5u);
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES + 1u);
  CHECK("source non-NULL zero-length alias rejects before clear",
        dm_pipeline_source_process(capsule, 0u, capsule,
                                    DM_PIPELINE_CAPSULE_BYTES) ==
            DM_PIPELINE_INTERNAL &&
            all_byte(capsule, DM_PIPELINE_CAPSULE_BYTES + 1u, 0xa5u));
  memset(capsule, 0xa5, DM_PIPELINE_CAPSULE_BYTES + 1u);
  CHECK("source disjoint zero-length input is malformed and clears",
        dm_pipeline_source_process(source_input, 0u, capsule,
                                    DM_PIPELINE_CAPSULE_BYTES) ==
            DM_PIPELINE_MALFORMED &&
            all_zero(capsule, DM_PIPELINE_CAPSULE_BYTES) &&
            capsule[DM_PIPELINE_CAPSULE_BYTES] == 0xa5u);
  CHECK("CLI accepts only argv[0]",
        !dm_pipeline_cli_args_valid(0) && dm_pipeline_cli_args_valid(1) &&
            !dm_pipeline_cli_args_valid(2));

  memset(producer_alias, 0xa5, sizeof(*producer_alias));
  memcpy(alias_before, producer_alias, sizeof(alias_before));
  producer_status = dm_source_proof_generate(
      (const uint8_t*)producer_alias, DM_SOURCE_PROOF_CONTEXT_BYTES, U,
      DM_SOURCE_PROOF_U_BYTES, values_le, DM_SOURCE_PROOF_VALUES_BYTES,
      secret_key, DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch,
      DM_PIPELINE_MAX_FINAL_RETRIES, producer_alias);
  CHECK("producer output/context alias rejects", producer_status ==
                                                    DM_SOURCE_PROOF_ERR_OUTPUT_ALIAS);
  CHECK("producer output/context alias preserves input",
        memcmp(alias_before, producer_alias, sizeof(alias_before)) == 0);

  secret_key_alias = (uint8_t*)producer_alias + sizeof(*producer_alias) -
                     DM_SOURCE_PROOF_SECRET_KEY_BYTES;
  memset(producer_alias, 0xa5, sizeof(*producer_alias));
  memset(secret_key_alias, 0x6d, DM_SOURCE_PROOF_SECRET_KEY_BYTES);
  memcpy(key_before, secret_key_alias, sizeof(key_before));
  producer_status = dm_source_proof_generate(
      context, DM_SOURCE_PROOF_CONTEXT_BYTES, U, DM_SOURCE_PROOF_U_BYTES,
      values_le, DM_SOURCE_PROOF_VALUES_BYTES, secret_key_alias,
      DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch,
      DM_PIPELINE_MAX_FINAL_RETRIES, producer_alias);
  CHECK("producer output/secret-key alias rejects", producer_status ==
                                                         DM_SOURCE_PROOF_ERR_OUTPUT_ALIAS);
  CHECK("producer output/secret-key alias preserves full key",
        memcmp(key_before, secret_key_alias, sizeof(key_before)) == 0);

  memset(input_key_backing, 0x6e, DM_SOURCE_PROOF_SECRET_KEY_BYTES);
  memset(producer_alias, 0xa5, sizeof(*producer_alias));
  producer_status = dm_source_proof_generate(
      input_key_backing, DM_SOURCE_PROOF_CONTEXT_BYTES, U,
      DM_SOURCE_PROOF_U_BYTES, values_le, DM_SOURCE_PROOF_VALUES_BYTES,
      input_key_backing, DM_SOURCE_PROOF_SECRET_KEY_BYTES, key_epoch,
      DM_PIPELINE_MAX_FINAL_RETRIES, producer_alias);
  CHECK("producer input/secret-key alias rejects", producer_status ==
                                                         DM_SOURCE_PROOF_ERR_INPUT_ALIAS);
  CHECK("producer input/secret-key alias clears output",
        all_zero((const uint8_t*)producer_alias, sizeof(*producer_alias)));
  CHECK("producer input/secret-key alias preserves full backing",
        all_byte(input_key_backing, DM_SOURCE_PROOF_SECRET_KEY_BYTES, 0x6e));

  CHECK("cheap cases preserve source input",
        memcmp(source_input, source_before, sizeof(source_before)) == 0);
  dm_pipeline_cheap_first = 1;
  secure_clear(&verifier_view, sizeof(verifier_view));
  secure_clear(&capsule_view, sizeof(capsule_view));
  secure_clear(key_before, sizeof(key_before));
  secure_clear(alias_before, sizeof(alias_before));
  secure_clear(source_before, sizeof(source_before));
  secure_clear(secret_key, sizeof(secret_key));
  secure_clear(values_le, sizeof(values_le));
  secure_clear(U, sizeof(U));
  secure_clear(context, sizeof(context));
  return dm_pipeline_failures == 0u ? 1 : 0;
}

static int run_probe(void) {
  const uint64_t key_epoch = UINT64_C(0x0102030405060708);
  uint8_t context[DM_SOURCE_PROOF_CONTEXT_BYTES];
  uint8_t U[DM_SOURCE_PROOF_U_BYTES];
  uint8_t values_le[DM_SOURCE_PROOF_VALUES_BYTES];
  uint8_t seed[BLIND_SOURCE_AUTH_MLDSA87_V1_SEED_BYTES];
  uint8_t secret_key[DM_SOURCE_PROOF_SECRET_KEY_BYTES];
  uint8_t public_key[DM_SOURCE_AUTH_PUBLIC_KEY_BYTES];
  uint8_t* source_input = NULL;
  uint8_t* source_before = NULL;
  uint8_t* source_extra = NULL;
  uint8_t* verifier_input = NULL;
  uint8_t* verifier_before = NULL;
  uint8_t* verifier_bad = NULL;
  uint8_t* capsule = NULL;
  uint8_t* alias_storage = NULL;
  uint8_t* parser_alias_storage = NULL;
  uint8_t* parser_alias_before = NULL;
  uint8_t* input_key_backing = NULL;
  dm_source_proof_output_t* fake_output = NULL;
  dm_source_proof_output_t* producer_alias = NULL;
  dm_pipeline_status_t pipeline_status;
  dm_pipeline_capsule_view_t capsule_view;
  size_t m3_offset;
  int nonzero_U = 0;
  int result = 0;

  memset(context, 0, sizeof(context));
  memset(U, 0, sizeof(U));
  memset(values_le, 0, sizeof(values_le));
  memset(seed, 0, sizeof(seed));
  memset(secret_key, 0, sizeof(secret_key));
  memset(public_key, 0, sizeof(public_key));
  memset(&capsule_view, 0, sizeof(capsule_view));

  source_input = (uint8_t*)calloc(1u, DM_PIPELINE_SOURCE_INPUT_BYTES);
  source_before = (uint8_t*)calloc(1u, DM_PIPELINE_SOURCE_INPUT_BYTES);
  source_extra = (uint8_t*)calloc(1u, DM_PIPELINE_SOURCE_INPUT_BYTES + 1u);
  verifier_input = (uint8_t*)calloc(1u, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_before = (uint8_t*)calloc(1u, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad =
      (uint8_t*)calloc(1u, DM_PIPELINE_VERIFIER_INPUT_BYTES + 1u);
  capsule = (uint8_t*)calloc(1u, DM_PIPELINE_CAPSULE_BYTES + 1u);
  alias_storage = (uint8_t*)calloc(1u, DM_PIPELINE_CAPSULE_BYTES);
  parser_alias_storage = (uint8_t*)calloc(
      1u, DM_PIPELINE_VERIFIER_INPUT_BYTES +
              sizeof(dm_pipeline_verifier_input_view_t) +
              DM_PIPELINE_PARSER_ALIAS_OFFSET);
  parser_alias_before = (uint8_t*)calloc(
      1u, DM_PIPELINE_VERIFIER_INPUT_BYTES +
              sizeof(dm_pipeline_verifier_input_view_t) +
              DM_PIPELINE_PARSER_ALIAS_OFFSET);
  input_key_backing =
      (uint8_t*)calloc(1u, DM_SOURCE_PROOF_SECRET_KEY_BYTES);
  fake_output = (dm_source_proof_output_t*)calloc(1u, sizeof(*fake_output));
  producer_alias =
      (dm_source_proof_output_t*)calloc(1u, sizeof(*producer_alias));
  if (source_input == NULL || source_before == NULL || source_extra == NULL ||
      verifier_input == NULL || verifier_before == NULL || verifier_bad == NULL ||
      capsule == NULL || alias_storage == NULL || parser_alias_storage == NULL ||
      parser_alias_before == NULL || input_key_backing == NULL ||
      fake_output == NULL || producer_alias == NULL) {
    CHECK("fixed probe storage allocation", 0);
    result = 1;
    goto cleanup;
  }

  /* All parser, offset, and alias checks run before the only fresh proof. */
  if (!run_cheap_checks(source_input, source_extra, verifier_input, capsule,
                        fake_output, producer_alias, input_key_backing,
                        alias_storage, parser_alias_storage,
                        parser_alias_before, key_epoch)) {
    result = 1;
    goto cleanup;
  }

  if (dm_wire_os_random_bytes(NULL, context, sizeof(context)) != 0 ||
      dm_wire_os_random_bytes(NULL, seed, sizeof(seed)) != 0) {
    CHECK("fresh OS context and key seed", 0);
    result = 1;
    goto cleanup;
  }
  for (unsigned attempt = 0u; attempt < DM_PIPELINE_U_RESAMPLE_LIMIT;
       ++attempt) {
    if (dm_wire_os_random_bytes(NULL, U, sizeof(U)) != 0) {
      CHECK("fresh OS U", 0);
      result = 1;
      goto cleanup;
    }
    if (!all_zero(U, sizeof(U))) {
      nonzero_U = 1;
      break;
    }
  }
  CHECK("fresh verifier U is nonzero", nonzero_U != 0);
  if (!nonzero_U) {
    result = 1;
    goto cleanup;
  }
  fill_values(values_le);
  if (blind_source_auth_mldsa87_v1_keypair_from_seed(
          public_key, sizeof(public_key), secret_key, sizeof(secret_key), seed,
          sizeof(seed)) != BLIND_SOURCE_AUTH_MLDSA87_V1_OK) {
    CHECK("ephemeral OS-seeded ML-DSA key setup", 0);
    result = 1;
    goto cleanup;
  }
  make_source_input(source_input, key_epoch, DM_PIPELINE_MAX_FINAL_RETRIES,
                    context, U, values_le, secret_key);
  memcpy(source_before, source_input, DM_PIPELINE_SOURCE_INPUT_BYTES);

  pipeline_status = dm_pipeline_source_process(
      source_input, DM_PIPELINE_SOURCE_INPUT_BYTES, capsule,
      DM_PIPELINE_CAPSULE_BYTES);
  CHECK("one fresh source capsule", pipeline_status == DM_PIPELINE_ACCEPT);
  if (pipeline_status != DM_PIPELINE_ACCEPT) {
    result = 1;
    goto cleanup;
  }
  dm_pipeline_fresh_proof = 1;
  CHECK("source process preserves full input",
        memcmp(source_input, source_before, DM_PIPELINE_SOURCE_INPUT_BYTES) == 0);
  CHECK("source capsule parses after generation",
        dm_pipeline_capsule_decode(capsule, DM_PIPELINE_CAPSULE_BYTES,
                                   &capsule_view));

  make_verifier_input(verifier_input, key_epoch, context, U, public_key,
                      capsule);
  secure_clear(source_input, DM_PIPELINE_SOURCE_INPUT_BYTES);
  secure_clear(source_before, DM_PIPELINE_SOURCE_INPUT_BYTES);
  secure_clear(secret_key, sizeof(secret_key));
  secure_clear(seed, sizeof(seed));
  secure_clear(values_le, sizeof(values_le));
  secure_clear(U, sizeof(U));
  secure_clear(context, sizeof(context));
  secure_clear(public_key, sizeof(public_key));

  CHECK("joint verifier entrypoint accepts capsule",
        dm_pipeline_verifier_process(verifier_input,
                                     DM_PIPELINE_VERIFIER_INPUT_BYTES) ==
            DM_PIPELINE_ACCEPT);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad[DM_PIPELINE_VERIFIER_CONTEXT_OFFSET] ^= 0x01u;
  check_verifier_mutation("wrong expected context rejects", verifier_bad,
                          verifier_before, &dm_pipeline_bad_context);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad[DM_PIPELINE_VERIFIER_U_OFFSET] ^= 0x01u;
  check_verifier_mutation("wrong expected U rejects", verifier_bad,
                          verifier_before, &dm_pipeline_bad_U);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad[DM_PIPELINE_VERIFIER_PUBLIC_KEY_OFFSET] ^= 0x01u;
  check_verifier_mutation("wrong trusted key rejects", verifier_bad,
                          verifier_before, &dm_pipeline_bad_key);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  store_u64_le(verifier_bad + DM_PIPELINE_VERIFIER_EPOCH_OFFSET,
               key_epoch + UINT64_C(1));
  check_verifier_mutation("wrong expected epoch rejects", verifier_bad,
                          verifier_before, &dm_pipeline_bad_epoch);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad[DM_PIPELINE_VERIFIER_CAPSULE_OFFSET +
               DM_PIPELINE_CAPSULE_EPOCH_OFFSET] ^= 0x01u;
  check_verifier_mutation("changed capsule epoch rejects", verifier_bad,
                          verifier_before, &dm_pipeline_bad_capsule_epoch);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad[DM_PIPELINE_VERIFIER_CAPSULE_OFFSET +
               DM_PIPELINE_CAPSULE_SIGNATURE_OFFSET] ^= 0x01u;
  check_verifier_mutation("changed capsule signature rejects", verifier_bad,
                          verifier_before, &dm_pipeline_bad_signature);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad[DM_PIPELINE_VERIFIER_CAPSULE_OFFSET +
               DM_PIPELINE_CAPSULE_FRAME_OFFSET] ^= 0x01u;
  check_verifier_mutation("changed frame header rejects", verifier_bad,
                          verifier_before, &dm_pipeline_bad_header);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  memcpy(verifier_bad + DM_PIPELINE_VERIFIER_CAPSULE_OFFSET +
             DM_PIPELINE_CAPSULE_FRAME_OFFSET,
         "DMV1", 4u);
  memcpy(verifier_before, verifier_bad, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  const dm_pipeline_status_t old_version_status = dm_pipeline_verifier_process(
      verifier_bad, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  dm_pipeline_old_version_rejected =
      old_version_status == DM_PIPELINE_REJECT &&
      memcmp(verifier_bad, verifier_before, DM_PIPELINE_VERIFIER_INPUT_BYTES) == 0;
  CHECK("legacy DMV1 frame rejects", old_version_status == DM_PIPELINE_REJECT);
  CHECK("legacy DMV1 rejection preserves input",
        memcmp(verifier_bad, verifier_before, DM_PIPELINE_VERIFIER_INPUT_BYTES) == 0);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad[DM_PIPELINE_VERIFIER_CAPSULE_OFFSET +
               DM_PIPELINE_CAPSULE_FRAME_OFFSET + DM_PIPELINE_FRAME_X_OFFSET] ^= 0x01u;
  check_verifier_mutation("embedded x binding rejects", verifier_bad,
                          verifier_before, &dm_pipeline_bad_x);

  m3_offset = DM_PIPELINE_FRAME_X_OFFSET + DM_WIRE_STATEMENT_BYTES +
              DM_WIRE_NU_BYTES + DM_WIRE_NONCE_COUNT * DM_WIRE_NONCE_BYTES +
              DM_WIRE_M1_BYTES + DM_WIRE_M2_BYTES;
  CHECK("m3 offset is inside exact frame",
        m3_offset + DM_WIRE_M3_BYTES <= DM_SOURCE_PROOF_FRAME_BYTES);
  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad[DM_PIPELINE_VERIFIER_CAPSULE_OFFSET +
               DM_PIPELINE_CAPSULE_FRAME_OFFSET + m3_offset] ^= 0x01u;
  check_verifier_mutation("well-formed m3 mutation rejects", verifier_bad,
                          verifier_before, &dm_pipeline_bad_m3);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad[DM_PIPELINE_VERIFIER_MAGIC_OFFSET] = 'X';
  memcpy(verifier_before, verifier_bad, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  CHECK("bad verifier magic is malformed",
        dm_pipeline_verifier_process(verifier_bad,
                                     DM_PIPELINE_VERIFIER_INPUT_BYTES) ==
            DM_PIPELINE_MALFORMED);
  CHECK("bad verifier magic preserves input",
        memcmp(verifier_bad, verifier_before, DM_PIPELINE_VERIFIER_INPUT_BYTES) == 0);
  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  CHECK("short verifier input is malformed",
        dm_pipeline_verifier_process(verifier_bad,
                                     DM_PIPELINE_VERIFIER_INPUT_BYTES - 1u) ==
            DM_PIPELINE_MALFORMED);
  CHECK("extra verifier input is malformed",
        dm_pipeline_verifier_process(verifier_bad,
                                     DM_PIPELINE_VERIFIER_INPUT_BYTES + 1u) ==
            DM_PIPELINE_MALFORMED);
  CHECK("NULL verifier input is malformed",
        dm_pipeline_verifier_process(NULL, DM_PIPELINE_VERIFIER_INPUT_BYTES) ==
            DM_PIPELINE_MALFORMED);

  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  store_u64_le(verifier_bad + DM_PIPELINE_VERIFIER_EPOCH_OFFSET, 0u);
  CHECK("zero verifier epoch is malformed",
        dm_pipeline_verifier_process(verifier_bad,
                                     DM_PIPELINE_VERIFIER_INPUT_BYTES) ==
            DM_PIPELINE_MALFORMED);
  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  memset(verifier_bad + DM_PIPELINE_VERIFIER_U_OFFSET, 0,
         DM_SOURCE_AUTH_U_BYTES);
  CHECK("zero verifier U is malformed",
        dm_pipeline_verifier_process(verifier_bad,
                                     DM_PIPELINE_VERIFIER_INPUT_BYTES) ==
            DM_PIPELINE_MALFORMED);
  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  memset(verifier_bad + DM_PIPELINE_VERIFIER_PUBLIC_KEY_OFFSET, 0,
         DM_SOURCE_AUTH_PUBLIC_KEY_BYTES);
  CHECK("zero trusted key is malformed",
        dm_pipeline_verifier_process(verifier_bad,
                                     DM_PIPELINE_VERIFIER_INPUT_BYTES) ==
            DM_PIPELINE_MALFORMED);
  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  verifier_bad[DM_PIPELINE_VERIFIER_CAPSULE_OFFSET +
               DM_PIPELINE_CAPSULE_MAGIC_OFFSET] = 'X';
  CHECK("bad capsule magic is malformed",
        dm_pipeline_verifier_process(verifier_bad,
                                     DM_PIPELINE_VERIFIER_INPUT_BYTES) ==
            DM_PIPELINE_MALFORMED);
  memcpy(verifier_bad, verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
  store_u64_le(verifier_bad + DM_PIPELINE_VERIFIER_CAPSULE_OFFSET +
                   DM_PIPELINE_CAPSULE_EPOCH_OFFSET,
               0u);
  CHECK("zero capsule epoch is malformed",
        dm_pipeline_verifier_process(verifier_bad,
                                     DM_PIPELINE_VERIFIER_INPUT_BYTES) ==
            DM_PIPELINE_MALFORMED);

  CHECK("context rejection is source-auth",
        dm_pipeline_bad_context == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("U rejection is source-auth",
        dm_pipeline_bad_U == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("key rejection is source-auth",
        dm_pipeline_bad_key == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("epoch rejection is source-auth",
        dm_pipeline_bad_epoch == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("capsule epoch rejection is source-auth",
        dm_pipeline_bad_capsule_epoch == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("signature rejection is source-auth",
        dm_pipeline_bad_signature == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("frame header rejection is decode",
        dm_pipeline_bad_header == DM_AUTHENTICATED_PROOF_ERR_DECODE);
  CHECK("embedded x rejection is source-auth",
        dm_pipeline_bad_x == DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("m3 mutation reaches proof rejection",
        dm_pipeline_bad_m3 == DM_AUTHENTICATED_PROOF_ERR_PROOF);

cleanup:
  secure_clear(&capsule_view, sizeof(capsule_view));
  secure_clear(public_key, sizeof(public_key));
  secure_clear(secret_key, sizeof(secret_key));
  secure_clear(seed, sizeof(seed));
  secure_clear(values_le, sizeof(values_le));
  secure_clear(U, sizeof(U));
  secure_clear(context, sizeof(context));
  if (producer_alias != NULL) {
    secure_clear(producer_alias, sizeof(*producer_alias));
    free(producer_alias);
  }
  if (fake_output != NULL) {
    secure_clear(fake_output, sizeof(*fake_output));
    free(fake_output);
  }
  if (input_key_backing != NULL) {
    secure_clear(input_key_backing, DM_SOURCE_PROOF_SECRET_KEY_BYTES);
    free(input_key_backing);
  }
  if (alias_storage != NULL) {
    secure_clear(alias_storage, DM_PIPELINE_CAPSULE_BYTES);
    free(alias_storage);
  }
  if (parser_alias_before != NULL) {
    secure_clear(parser_alias_before,
                 DM_PIPELINE_VERIFIER_INPUT_BYTES +
                     sizeof(dm_pipeline_verifier_input_view_t) +
                     DM_PIPELINE_PARSER_ALIAS_OFFSET);
    free(parser_alias_before);
  }
  if (parser_alias_storage != NULL) {
    secure_clear(parser_alias_storage,
                 DM_PIPELINE_VERIFIER_INPUT_BYTES +
                     sizeof(dm_pipeline_verifier_input_view_t) +
                     DM_PIPELINE_PARSER_ALIAS_OFFSET);
    free(parser_alias_storage);
  }
  if (capsule != NULL) {
    secure_clear(capsule, DM_PIPELINE_CAPSULE_BYTES + 1u);
    free(capsule);
  }
  if (verifier_bad != NULL) {
    secure_clear(verifier_bad, DM_PIPELINE_VERIFIER_INPUT_BYTES + 1u);
    free(verifier_bad);
  }
  if (verifier_before != NULL) {
    secure_clear(verifier_before, DM_PIPELINE_VERIFIER_INPUT_BYTES);
    free(verifier_before);
  }
  if (verifier_input != NULL) {
    secure_clear(verifier_input, DM_PIPELINE_VERIFIER_INPUT_BYTES);
    free(verifier_input);
  }
  if (source_extra != NULL) {
    secure_clear(source_extra, DM_PIPELINE_SOURCE_INPUT_BYTES + 1u);
    free(source_extra);
  }
  if (source_before != NULL) {
    secure_clear(source_before, DM_PIPELINE_SOURCE_INPUT_BYTES);
    free(source_before);
  }
  if (source_input != NULL) {
    secure_clear(source_input, DM_PIPELINE_SOURCE_INPUT_BYTES);
    free(source_input);
  }
  return result;
}

int main(void) {
  const int result = run_probe();
  printf("STATUS NON_ACTIVATING_DIRECT_MASK_PIPELINE\n");
  printf("SOURCE_INPUT_BYTES=%u CAPSULE_BYTES=%u VERIFIER_INPUT_BYTES=%u\n",
         DM_PIPELINE_SOURCE_INPUT_BYTES, DM_PIPELINE_CAPSULE_BYTES,
         DM_PIPELINE_VERIFIER_INPUT_BYTES);
  printf("ONE_FRESH_SOURCE_PROOF=%s\n",
         dm_pipeline_fresh_proof ? "TRUE" : "FALSE");
  printf("CHEAP_CASES_BEFORE_PROOF=%s\n",
         dm_pipeline_cheap_first ? "TRUE" : "FALSE");
  printf("OBSERVED_CONTEXT=%s U=%s KEY=%s EPOCH=%s CAPSULE_EPOCH=%s SIGNATURE=%s\n",
         dm_authenticated_proof_status_name(dm_pipeline_bad_context),
         dm_authenticated_proof_status_name(dm_pipeline_bad_U),
         dm_authenticated_proof_status_name(dm_pipeline_bad_key),
         dm_authenticated_proof_status_name(dm_pipeline_bad_epoch),
         dm_authenticated_proof_status_name(dm_pipeline_bad_capsule_epoch),
         dm_authenticated_proof_status_name(dm_pipeline_bad_signature));
  printf("OBSERVED_HEADER=%s EMBEDDED_X=%s M3=%s\n",
         dm_authenticated_proof_status_name(dm_pipeline_bad_header),
         dm_authenticated_proof_status_name(dm_pipeline_bad_x),
         dm_authenticated_proof_status_name(dm_pipeline_bad_m3));
  printf("MIXED_VERSION_REJECTED=%s\n",
         dm_pipeline_old_version_rejected ? "TRUE" : "FALSE");
  printf("SOURCE_OUTPUT_HAS_ONLY_SIGNATURE_AND_FRAME=TRUE\n");
  printf("VERIFIER_OWNS_NO_SOURCE_TRUTH_OR_STATE=TRUE\n");
  printf("CHECK_COUNT=%u FAILED=%u\n", dm_pipeline_checks,
         dm_pipeline_failures);
  printf("ALL_TESTS=%s\n", result == 0 && dm_pipeline_failures == 0u
                              ? "PASS"
                              : "FAIL");
  return result == 0 && dm_pipeline_failures == 0u ? 0 : 1;
}
