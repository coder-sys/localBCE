/* SPDX-License-Identifier: MIT */

#include "direct_mask_fixture.h"
#include "fixture_public_key.h"

#include <stdio.h>
#include <string.h>

static uint32_t load_u32_le(const uint8_t bytes[4]) {
  return ((uint32_t)bytes[0]) | ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t load_u64_le(const uint8_t bytes[8]) {
  uint64_t value = 0u;
  for (size_t index = 0u; index != 8u; ++index) {
    value |= (uint64_t)bytes[index] << (8u * index);
  }
  return value;
}

static void store_u32_le(uint8_t bytes[4], uint32_t value) {
  for (size_t index = 0u; index != 4u; ++index) {
    bytes[index] = (uint8_t)(value & UINT32_C(0xff));
    value >>= 8;
  }
}

static void store_u64_le(uint8_t bytes[8], uint64_t value) {
  for (size_t index = 0u; index != 8u; ++index) {
    bytes[index] = (uint8_t)(value & UINT64_C(0xff));
    value >>= 8;
  }
}

static int make_request(uint8_t request[DM_FIXTURE_REQUEST_BYTES]) {
  memset(request, 0, DM_FIXTURE_REQUEST_BYTES);
  memcpy(request, DM_FIXTURE_REQUEST_MAGIC, DM_FIXTURE_REQUEST_MAGIC_BYTES);
  store_u64_le(request + DM_FIXTURE_REQUEST_EPOCH_OFFSET,
               DM_FIXTURE_KEY_EPOCH);
  store_u32_le(request + DM_FIXTURE_REQUEST_RETRIES_OFFSET,
               DM_FIXTURE_MAX_FINAL_RETRIES);
  request[DM_FIXTURE_REQUEST_U_OFFSET] = 0xa5u;
  return 1;
}

static unsigned fake_process_calls;
static int fake_process_input_ok;

static dm_pipeline_status_t fake_process(
    const uint8_t* input, size_t input_bytes, uint8_t* capsule,
    size_t capsule_bytes) {
  ++fake_process_calls;
  fake_process_input_ok =
      input != NULL && input_bytes == DM_PIPELINE_SOURCE_INPUT_BYTES &&
      capsule != NULL && capsule_bytes == DM_PIPELINE_CAPSULE_BYTES &&
      memcmp(input, DM_PIPELINE_SOURCE_MAGIC, DM_PIPELINE_MAGIC_BYTES) == 0;
  return DM_PIPELINE_REJECT;
}

static int check(int condition, const char* label, unsigned* failures) {
  if (condition) {
    printf("PASS %s\n", label);
    return 1;
  }
  printf("FAIL %s\n", label);
  ++*failures;
  return 0;
}

int main(void) {
  uint8_t request[DM_FIXTURE_REQUEST_BYTES];
  uint8_t mutated[DM_FIXTURE_REQUEST_BYTES + 1u];
  uint8_t seed[DM_FIXTURE_SEED_BYTES];
  uint8_t public_key[DM_FIXTURE_PUBLIC_KEY_BYTES];
  uint8_t secret_key[DM_FIXTURE_SECRET_KEY_BYTES];
  uint8_t source_input[DM_PIPELINE_SOURCE_INPUT_BYTES];
  uint8_t capsule[DM_PIPELINE_CAPSULE_BYTES];
  uint8_t wrong_public_key[DM_FIXTURE_PUBLIC_KEY_BYTES];
  dm_fixture_request_view_t view;
  unsigned failures = 0u;
  unsigned cases = 0u;
  dm_pipeline_status_t status;

  memset(request, 0, sizeof(request));
  memset(mutated, 0, sizeof(mutated));
  memset(seed, 0, sizeof(seed));
  memset(public_key, 0, sizeof(public_key));
  memset(secret_key, 0, sizeof(secret_key));
  memset(source_input, 0, sizeof(source_input));
  memset(capsule, 0, sizeof(capsule));
  memset(wrong_public_key, 0, sizeof(wrong_public_key));
  memset(&view, 0, sizeof(view));

  make_request(request);
  ++cases;
  check(dm_fixture_request_parse(request, sizeof(request), &view),
        "parser accepts exact request with zero context", &failures);
  ++cases;
  check(view.key_epoch == DM_FIXTURE_KEY_EPOCH &&
            view.max_final_retries == DM_FIXTURE_MAX_FINAL_RETRIES &&
            view.context[0] == 0u && view.U[0] == 0xa5u,
        "parser commits epoch cap context and U", &failures);

  memcpy(mutated, request, sizeof(request));
  mutated[0] ^= 0x01u;
  ++cases;
  check(!dm_fixture_request_parse(mutated, sizeof(request), &view),
        "parser rejects wrong magic", &failures);
  memcpy(mutated, request, sizeof(request));
  memset(mutated + DM_FIXTURE_REQUEST_EPOCH_OFFSET, 0, 8u);
  ++cases;
  check(!dm_fixture_request_parse(mutated, sizeof(request), &view),
        "parser rejects epoch zero", &failures);
  memcpy(mutated, request, sizeof(request));
  store_u64_le(mutated + DM_FIXTURE_REQUEST_EPOCH_OFFSET, UINT64_C(2));
  ++cases;
  check(!dm_fixture_request_parse(mutated, sizeof(request), &view),
        "parser rejects non-one epoch", &failures);
  memcpy(mutated, request, sizeof(request));
  memset(mutated + DM_FIXTURE_REQUEST_RETRIES_OFFSET, 0, 4u);
  ++cases;
  check(!dm_fixture_request_parse(mutated, sizeof(request), &view),
        "parser rejects retry cap zero", &failures);
  memcpy(mutated, request, sizeof(request));
  mutated[DM_FIXTURE_REQUEST_RETRIES_OFFSET + 0u] = 0xffu;
  mutated[DM_FIXTURE_REQUEST_RETRIES_OFFSET + 1u] = 0x0fu;
  mutated[DM_FIXTURE_REQUEST_RETRIES_OFFSET + 2u] = 0xffu;
  mutated[DM_FIXTURE_REQUEST_RETRIES_OFFSET + 3u] = 0xffu;
  ++cases;
  check(!dm_fixture_request_parse(mutated, sizeof(request), &view),
        "parser rejects retry cap above maximum", &failures);
  memcpy(mutated, request, sizeof(request));
  store_u32_le(mutated + DM_FIXTURE_REQUEST_RETRIES_OFFSET, 4096u);
  ++cases;
  check(dm_fixture_request_parse(mutated, sizeof(request), &view) &&
            view.max_final_retries == 4096u,
        "parser accepts a smaller bounded retry cap", &failures);
  memcpy(mutated, request, sizeof(request));
  memset(mutated + DM_FIXTURE_REQUEST_U_OFFSET, 0,
         DM_SOURCE_PROOF_U_BYTES);
  ++cases;
  check(!dm_fixture_request_parse(mutated, sizeof(request), &view),
        "parser rejects zero U", &failures);
  ++cases;
  check(!dm_fixture_request_parse(request, sizeof(request) - 1u, &view),
        "parser rejects short request", &failures);
  memcpy(mutated, request, sizeof(request));
  mutated[sizeof(request)] = 0x5au;
  ++cases;
  check(!dm_fixture_request_parse(mutated, sizeof(request) + 1u, &view),
        "parser rejects extra request byte", &failures);
  ++cases;
  check(dm_fixture_request_parse(request, sizeof(request), &view),
        "parser restores valid request view", &failures);

  dm_fixture_fill_seed(seed);
  ++cases;
  check(blind_source_auth_mldsa87_v1_keypair_from_seed(
            public_key, sizeof(public_key), secret_key, sizeof(secret_key),
            seed, sizeof(seed)) == BLIND_SOURCE_AUTH_MLDSA87_V1_OK,
        "fixed public seed derives keypair", &failures);
  ++cases;
  check(dm_fixture_public_key_matches(public_key),
        "derived public key matches frozen fixture", &failures);

  ++cases;
  check(dm_fixture_construct_source_input(
            &view, secret_key, sizeof(secret_key), source_input,
            sizeof(source_input)),
        "DMSI source input construction succeeds", &failures);
  ++cases;
  check(memcmp(source_input, DM_PIPELINE_SOURCE_MAGIC,
               DM_PIPELINE_MAGIC_BYTES) == 0 &&
            load_u64_le(source_input + DM_PIPELINE_SOURCE_EPOCH_OFFSET) == 1u &&
            load_u32_le(source_input + DM_PIPELINE_SOURCE_RETRIES_OFFSET) ==
                DM_FIXTURE_MAX_FINAL_RETRIES &&
            memcmp(source_input + DM_PIPELINE_SOURCE_CONTEXT_OFFSET,
                   view.context, sizeof(view.context)) == 0 &&
            memcmp(source_input + DM_PIPELINE_SOURCE_U_OFFSET, view.U,
                   sizeof(view.U)) == 0,
        "DMSI public offsets preserve request bytes", &failures);
  ++cases;
  check(load_u64_le(source_input + DM_PIPELINE_SOURCE_VALUES_OFFSET) ==
                UINT64_C(0x1122334455667788) &&
            load_u64_le(source_input + DM_PIPELINE_SOURCE_VALUES_OFFSET + 8u) ==
                UINT64_C(0xddeeff0011223344) &&
            load_u64_le(source_input + DM_PIPELINE_SOURCE_VALUES_OFFSET +
                        8u * 99u) == UINT64_C(0xddeeff0011223344),
        "DMSI witness values use exact alternating little-endian encoding",
        &failures);
  ++cases;
  check(memcmp(source_input + DM_PIPELINE_SOURCE_SECRET_KEY_OFFSET, secret_key,
               sizeof(secret_key)) == 0,
        "DMSI secret key begins at offset 980", &failures);

  fake_process_calls = 0u;
  fake_process_input_ok = 0;
  memset(capsule, 0, sizeof(capsule));
  ++cases;
  status = dm_fixture_run_bound_source(
      &view, secret_key, sizeof(secret_key), public_key,
      dm_fixture_frozen_public_key, capsule, sizeof(capsule), fake_process);
  check(status == DM_PIPELINE_REJECT && fake_process_calls == 1u &&
            fake_process_input_ok != 0,
        "matching key invokes exactly one test callback after construction",
        &failures);

  memcpy(wrong_public_key, dm_fixture_frozen_public_key,
         sizeof(wrong_public_key));
  wrong_public_key[0] ^= 0x01u;
  fake_process_calls = 0u;
  ++cases;
  status = dm_fixture_run_bound_source(
      &view, secret_key, sizeof(secret_key), public_key, wrong_public_key,
      capsule, sizeof(capsule), fake_process);
  check(status == DM_PIPELINE_INTERNAL && fake_process_calls == 0u,
        "wrong public key rejects before producer callback", &failures);

  dm_fixture_secure_clear(wrong_public_key, sizeof(wrong_public_key));
  dm_fixture_secure_clear(capsule, sizeof(capsule));
  dm_fixture_secure_clear(source_input, sizeof(source_input));
  dm_fixture_secure_clear(secret_key, sizeof(secret_key));
  dm_fixture_secure_clear(public_key, sizeof(public_key));
  dm_fixture_secure_clear(seed, sizeof(seed));
  dm_fixture_secure_clear(&view, sizeof(view));
  dm_fixture_secure_clear(mutated, sizeof(mutated));
  dm_fixture_secure_clear(request, sizeof(request));
  printf("STATUS NON_ACTIVATING_DIRECT_MASK_FIXTURE_PROBE cases=%u failures=%u\n",
         cases, failures);
  return failures == 0u ? 0 : 1;
}
