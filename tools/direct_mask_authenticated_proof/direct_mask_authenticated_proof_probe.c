/* SPDX-License-Identifier: MIT */

/* Focused, non-activating composition probe. */

#include "direct_mask_authenticated_proof.h"

#include "aes.h"
#include "blind_source_auth_mldsa87_v1.h"
#include "direct_mask_native.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned dm_authenticated_proof_checks;
static unsigned dm_authenticated_proof_failures;
static int dm_authenticated_proof_fresh_proof;
static int dm_authenticated_proof_cheap_first;
static dm_wire_status_t dm_authenticated_proof_m3_decode = DM_WIRE_ERR_ARGUMENT;
static dm_wire_status_t dm_authenticated_proof_m3_kernel = DM_WIRE_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_authenticated_proof_m3_joint =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_authenticated_proof_xb_joint =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_authenticated_proof_zero_frame =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_authenticated_proof_bad_header =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_authenticated_proof_bad_signature =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;
static dm_authenticated_proof_status_t dm_authenticated_proof_bad_context =
    DM_AUTHENTICATED_PROOF_ERR_ARGUMENT;

#define CHECK(label, expression)                                                   \
  do {                                                                             \
    ++dm_authenticated_proof_checks;                                               \
    if (!(expression)) {                                                           \
      ++dm_authenticated_proof_failures;                                           \
      fprintf(stderr, "FAIL %s\n", (label));                                     \
    }                                                                              \
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

static void fill_bytes(uint8_t* bytes, size_t length, uint8_t seed) {
  for (size_t index = 0; index != length; ++index) {
    bytes[index] = (uint8_t)(seed + (uint8_t)(index * 29u) +
                             (uint8_t)(index >> 3));
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

static int verified_is_clear(const dm_authenticated_proof_verified_t* verified) {
  return verified != NULL &&
         all_zero((const uint8_t*)verified, sizeof(*verified));
}

typedef union dm_alias_storage_t {
  uint64_t alignment;
  uint8_t bytes[DM_SOURCE_AUTH_X_BYTES +
                sizeof(dm_authenticated_proof_verified_t) + 16u];
} dm_alias_storage_t;

static void make_instance(dmk_instance* instance,
                          const uint8_t root[DMN_ROOT_BYTES]) {
  static const uint8_t source_suite[DM_WIRE_SOURCE_SUITE_BYTES] = {
      'S', 'B', 'A', '1', '-', 'S', 'R', 'C', '-', 'C', 'M', 'T', '-', 'v', '1', 0,
  };
  uint8_t g0[DMN_G0_BYTES];
  uint8_t g1[DMN_G1_BYTES];
  const uint8_t zero_iv[16] = {0};
  uint8_t iv_2pow127[16] = {0};

  memset(instance, 0, sizeof(*instance));
  memcpy(instance->source_suite, source_suite, sizeof(source_suite));
  for (unsigned index = 0; index != sizeof(instance->context); ++index) {
    instance->context[index] = (uint8_t)(index + 1u);
  }
  for (unsigned index = 0; index != sizeof(instance->U); ++index) {
    instance->U[index] = (uint8_t)(index * 11u + 5u);
  }
  iv_2pow127[15] = 0x80u;
  prg_4_lambda(root, zero_iv, 0, g0, 256);
  prg(g0, iv_2pow127, 0, g1, 256, sizeof(instance->C));

  bf768_t product;
  bf768_t z;
  bf256_t k;
  bf768_load(&product, instance->U);
  bf256_load(&k, g0);
  bf768_mul_256_inplace(&product, &k);
  bf768_load(&z, g0 + DM_WIRE_FIELD_BYTES);
  bf768_add_inplace(&product, &z);
  bf768_store(instance->T, &product);
  secure_clear(&product, sizeof(product));
  secure_clear(&z, sizeof(z));
  secure_clear(&k, sizeof(k));

  for (unsigned index = 0; index != sizeof(instance->C); ++index) {
    const uint64_t value = (index / 8u) & 1u ? DMK_UPPER : DMK_LOWER;
    instance->C[index] = (uint8_t)(g1[index] ^
                                   (uint8_t)(value >> (8u * (index % 8u))));
  }
  secure_clear(g0, sizeof(g0));
  secure_clear(g1, sizeof(g1));
  secure_clear(iv_2pow127, sizeof(iv_2pow127));
}

static void make_statement(const dmk_instance* instance,
                           dm_wire_statement_t* statement) {
  static const uint8_t relation_id[] = "direct-mask-relation-v1";

  memset(statement, 0, sizeof(*statement));
  memcpy(statement->source_suite, instance->source_suite,
         DM_WIRE_SOURCE_SUITE_BYTES);
  statement->relation_id = relation_id;
  statement->relation_id_bytes = (uint32_t)(sizeof(relation_id) - 1u);
  statement->context = instance->context;
  statement->U = instance->U;
  statement->T = instance->T;
  statement->C = instance->C;
  statement->descriptor.field_bits = DMV_LAMBDA;
  statement->descriptor.degree = DMV_DEGREE;
  statement->descriptor.tau = DMV_TAU;
  statement->descriptor.w_grind = DMV_W_GRIND;
  statement->descriptor.short_challenge_bits = DMV_SHORT_CHALLENGE_BITS;
  statement->descriptor.open_budget = DMV_T_OPEN;
  statement->descriptor.witness_bits = DMK_WITNESS_BITS;
  statement->descriptor.constraints = DMK_CONSTRAINTS;
  statement->descriptor.padding_bits = 0u;
  statement->descriptor.mask_count = DMK_MASK_COUNT;
  statement->descriptor.nonce_bits = 8u * DMV_NONCE_BYTES;
  statement->descriptor.challenge_mode = 1u;
}

static void unpack_witness(const dmn_packed_witness* packed, uint8_t* bits) {
  for (size_t bit = 0; bit != packed->bit_count; ++bit) {
    bits[bit] = (uint8_t)((packed->bytes[bit / 8u] >> (bit % 8u)) & 1u);
  }
}

static void run_cheap_api_checks(
    const dm_source_auth_request_t* request, uint64_t key_epoch, uint8_t* x,
    uint8_t* x_extra, uint8_t* signature, uint8_t* signature_extra,
    uint8_t* frame, uint8_t* frame_extra, size_t frame_bytes,
    dm_authenticated_proof_verified_t* verified) {
  dm_authenticated_proof_status_t status;
  dm_alias_storage_t alias_storage;
  uint8_t alias_before[sizeof(alias_storage.bytes)];

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      NULL, key_epoch, x, DM_SOURCE_AUTH_X_BYTES, signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, frame, frame_bytes, verified);
  CHECK("NULL request returns argument", status == DM_AUTHENTICATED_PROOF_ERR_ARGUMENT);
  CHECK("NULL request clears output", verified_is_clear(verified));

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, NULL, DM_SOURCE_AUTH_X_BYTES, signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, frame, frame_bytes, verified);
  CHECK("NULL canonical x returns argument", status == DM_AUTHENTICATED_PROOF_ERR_ARGUMENT);
  CHECK("NULL canonical x clears output", verified_is_clear(verified));

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, x, DM_SOURCE_AUTH_X_BYTES, NULL,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, frame, frame_bytes, verified);
  CHECK("NULL signature returns argument", status == DM_AUTHENTICATED_PROOF_ERR_ARGUMENT);
  CHECK("NULL signature clears output", verified_is_clear(verified));

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, x, DM_SOURCE_AUTH_X_BYTES, signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, NULL, frame_bytes, verified);
  CHECK("NULL frame returns argument", status == DM_AUTHENTICATED_PROOF_ERR_ARGUMENT);
  CHECK("NULL frame clears output", verified_is_clear(verified));

  CHECK("NULL output returns argument",
        dm_authenticated_proof_verify(
            request, key_epoch, x, DM_SOURCE_AUTH_X_BYTES, signature,
            DM_SOURCE_AUTH_SIGNATURE_BYTES, frame, frame_bytes, NULL) ==
            DM_AUTHENTICATED_PROOF_ERR_ARGUMENT);

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, x_extra, DM_SOURCE_AUTH_X_BYTES - 1u, signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, frame, frame_bytes, verified);
  CHECK("short canonical x returns size", status == DM_AUTHENTICATED_PROOF_ERR_SIZE);
  CHECK("short canonical x clears output", verified_is_clear(verified));

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, x_extra, DM_SOURCE_AUTH_X_BYTES + 1u, signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, frame, frame_bytes, verified);
  CHECK("extra canonical x returns size", status == DM_AUTHENTICATED_PROOF_ERR_SIZE);
  CHECK("extra canonical x clears output", verified_is_clear(verified));

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, x, DM_SOURCE_AUTH_X_BYTES, signature_extra,
      DM_SOURCE_AUTH_SIGNATURE_BYTES - 1u, frame, frame_bytes, verified);
  CHECK("short signature returns size", status == DM_AUTHENTICATED_PROOF_ERR_SIZE);
  CHECK("short signature clears output", verified_is_clear(verified));

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, x, DM_SOURCE_AUTH_X_BYTES, signature_extra,
      DM_SOURCE_AUTH_SIGNATURE_BYTES + 1u, frame, frame_bytes, verified);
  CHECK("extra signature returns size", status == DM_AUTHENTICATED_PROOF_ERR_SIZE);
  CHECK("extra signature clears output", verified_is_clear(verified));

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, x, DM_SOURCE_AUTH_X_BYTES, signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, frame, frame_bytes - 1u, verified);
  CHECK("short frame returns size", status == DM_AUTHENTICATED_PROOF_ERR_SIZE);
  CHECK("short frame clears output", verified_is_clear(verified));

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, x, DM_SOURCE_AUTH_X_BYTES, signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, frame_extra, frame_bytes + 1u, verified);
  CHECK("extra frame returns size", status == DM_AUTHENTICATED_PROOF_ERR_SIZE);
  CHECK("extra frame clears output", verified_is_clear(verified));

  memset(&alias_storage, 0x5a, sizeof(alias_storage));
  memcpy(alias_storage.bytes, x, DM_SOURCE_AUTH_X_BYTES);
  memcpy(alias_before, alias_storage.bytes, sizeof(alias_before));
  status = dm_authenticated_proof_verify(
      request, key_epoch, alias_storage.bytes, DM_SOURCE_AUTH_X_BYTES, signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, NULL, frame_bytes,
      (dm_authenticated_proof_verified_t*)alias_storage.bytes);
  CHECK("output/input alias with NULL frame returns output-alias",
        status == DM_AUTHENTICATED_PROOF_ERR_OUTPUT_ALIAS);
  CHECK("output/input alias with NULL frame preserves input",
        memcmp(alias_storage.bytes, alias_before, sizeof(alias_before)) == 0);
  secure_clear(alias_before, sizeof(alias_before));
  secure_clear(&alias_storage, sizeof(alias_storage));

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, frame, DM_SOURCE_AUTH_X_BYTES, signature,
      DM_SOURCE_AUTH_SIGNATURE_BYTES, frame, frame_bytes, verified);
  CHECK("input/input alias returns input-alias",
        status == DM_AUTHENTICATED_PROOF_ERR_INPUT_ALIAS);
  CHECK("input/input alias clears disjoint output", verified_is_clear(verified));

  memset(verified, 0xa5, sizeof(*verified));
  status = dm_authenticated_proof_verify(
      request, key_epoch, (const uint8_t*)request, DM_SOURCE_AUTH_X_BYTES,
      signature, DM_SOURCE_AUTH_SIGNATURE_BYTES, frame, frame_bytes, verified);
  CHECK("request/input alias returns input-alias",
        status == DM_AUTHENTICATED_PROOF_ERR_INPUT_ALIAS);
  CHECK("request/input alias clears disjoint output", verified_is_clear(verified));

  dm_authenticated_proof_cheap_first = 1;
}

static int run_probe(void) {
  static const uint8_t root[DMN_ROOT_BYTES] = {
      0x03u, 0x0au, 0x11u, 0x18u, 0x1fu, 0x26u, 0x2du, 0x34u,
      0x3bu, 0x42u, 0x49u, 0x50u, 0x57u, 0x5eu, 0x65u, 0x6cu,
      0x73u, 0x7au, 0x81u, 0x88u, 0x8fu, 0x96u, 0x9du, 0xa4u,
      0xabu, 0xb2u, 0xb9u, 0xc0u, 0xc7u, 0xceu, 0xd5u, 0xdcu,
  };
  const uint64_t key_epoch = UINT64_C(0x0102030405060708);
  dmk_instance instance;
  dm_wire_statement_t statement;
  dm_wire_proof_t proof;
  dm_wire_proof_t stage_proof;
  dm_source_auth_request_t request;
  dm_source_auth_request_t request_mutated;
  dm_source_auth_verified_t source_verified_b;
  dm_authenticated_proof_verified_t verified;
  dmn_packed_witness packed;
  uint8_t seed[BLIND_SOURCE_AUTH_MLDSA87_V1_SEED_BYTES];
  uint8_t secret_key[DM_SOURCE_AUTH_SECRET_KEY_BYTES];
  uint8_t public_key[DM_SOURCE_AUTH_PUBLIC_KEY_BYTES];
  uint8_t signature[DM_SOURCE_AUTH_SIGNATURE_BYTES];
  uint8_t signature_b[DM_SOURCE_AUTH_SIGNATURE_BYTES];
  uint8_t signature_mutated[DM_SOURCE_AUTH_SIGNATURE_BYTES];
  uint8_t x[DM_SOURCE_AUTH_X_BYTES];
  uint8_t x_extra[DM_SOURCE_AUTH_X_BYTES + 1u];
  uint8_t signature_extra[DM_SOURCE_AUTH_SIGNATURE_BYTES + 1u];
  uint8_t x_owned_snapshot[DM_SOURCE_AUTH_X_BYTES];
  uint8_t x_mutated[DM_SOURCE_AUTH_X_BYTES];
  uint8_t* witness_bits = NULL;
  uint8_t* frame = NULL;
  uint8_t* frame_mutated = NULL;
  uint8_t* frame_extra = NULL;
  dm_alias_storage_t alias_storage;
  uint8_t alias_before[sizeof(alias_storage.bytes)];
  size_t frame_bytes = DM_AUTHENTICATED_PROOF_FRAME_BYTES;
  size_t written = 0u;
  size_t t_offset = DM_WIRE_SOURCE_SUITE_BYTES + 4u +
                    DM_WIRE_RELATION_ID_BYTES + DM_WIRE_CONTEXT_BYTES +
                    DM_WIRE_U_BYTES;
  size_t m3_offset = DM_WIRE_HEADER_BYTES + DM_WIRE_STATEMENT_BYTES +
                     DM_WIRE_NU_BYTES +
                     DM_WIRE_NONCE_COUNT * DM_WIRE_NONCE_BYTES +
                     DM_WIRE_M1_BYTES + DM_WIRE_M2_BYTES;
  int setup_ok = 0;

  memset(&instance, 0, sizeof(instance));
  memset(&statement, 0, sizeof(statement));
  dm_wire_proof_init(&proof);
  dm_wire_proof_init(&stage_proof);
  dm_source_auth_request_init(&request);
  memset(&request_mutated, 0, sizeof(request_mutated));
  memset(&source_verified_b, 0, sizeof(source_verified_b));
  memset(&verified, 0, sizeof(verified));
  memset(&packed, 0, sizeof(packed));
  memset(seed, 0, sizeof(seed));
  memset(secret_key, 0, sizeof(secret_key));
  memset(public_key, 0, sizeof(public_key));
  memset(signature, 0, sizeof(signature));
  memset(signature_b, 0, sizeof(signature_b));
  memset(signature_mutated, 0, sizeof(signature_mutated));
  memset(x, 0, sizeof(x));
  memset(x_extra, 0, sizeof(x_extra));
  memset(signature_extra, 0, sizeof(signature_extra));
  memset(x_owned_snapshot, 0, sizeof(x_owned_snapshot));
  memset(x_mutated, 0, sizeof(x_mutated));
  memset(&alias_storage, 0, sizeof(alias_storage));
  memset(alias_before, 0, sizeof(alias_before));

  fill_bytes(x, sizeof(x), 0x11u);
  fill_bytes(x_extra, sizeof(x_extra), 0x21u);
  fill_bytes(signature, sizeof(signature), 0x31u);
  fill_bytes(signature_extra, sizeof(signature_extra), 0x41u);
  frame = (uint8_t*)malloc(DM_AUTHENTICATED_PROOF_FRAME_BYTES);
  frame_mutated = (uint8_t*)malloc(DM_AUTHENTICATED_PROOF_FRAME_BYTES);
  frame_extra = (uint8_t*)malloc(DM_AUTHENTICATED_PROOF_FRAME_BYTES + 1u);
  if (frame == NULL || frame_mutated == NULL || frame_extra == NULL) {
    CHECK("cheap-first frame allocations", 0);
    goto cleanup;
  }
  fill_bytes(frame, DM_AUTHENTICATED_PROOF_FRAME_BYTES, 0x51u);
  fill_bytes(frame_mutated, DM_AUTHENTICATED_PROOF_FRAME_BYTES, 0x61u);
  fill_bytes(frame_extra, DM_AUTHENTICATED_PROOF_FRAME_BYTES + 1u, 0x71u);
  run_cheap_api_checks(&request, key_epoch, x, x_extra, signature,
                       signature_extra, frame, frame_extra, frame_bytes,
                       &verified);
  if (dm_authenticated_proof_failures != 0u) {
    goto cleanup;
  }

  make_instance(&instance, root);
  memcpy(request.expected_context, instance.context,
         sizeof(request.expected_context));
  memcpy(request.expected_U, instance.U, sizeof(request.expected_U));
  request.expected_key_epoch = key_epoch;
  fill_bytes(seed, sizeof(seed), 0x60u);

  if (blind_source_auth_mldsa87_v1_keypair_from_seed(
          public_key, sizeof(public_key), secret_key, sizeof(secret_key), seed,
          sizeof(seed)) != BLIND_SOURCE_AUTH_MLDSA87_V1_OK) {
    CHECK("deterministic probe key setup", 0);
    goto cleanup;
  }
  memcpy(request.trusted_public_key, public_key, sizeof(public_key));
  make_statement(&instance, &statement);
  if (dm_wire_statement_encode(x, sizeof(x), &statement) != DM_WIRE_OK) {
    CHECK("canonical x encoding", 0);
    goto cleanup;
  }
  if (dmn_extend(&instance, root, &packed) != DMN_OK ||
      packed.byte_count != DMN_PACKED_WITNESS_BYTES ||
      packed.bit_count != DMN_PACKED_WITNESS_BITS) {
    CHECK("native synthetic witness", 0);
    goto cleanup;
  }
  witness_bits = (uint8_t*)calloc(DMK_WITNESS_BITS, 1u);
  if (witness_bits == NULL) {
    CHECK("witness allocation", 0);
    goto cleanup;
  }
  unpack_witness(&packed, witness_bits);
  if (dm_source_auth_sign(signature, sizeof(signature), secret_key,
                          sizeof(secret_key), key_epoch, x, sizeof(x)) !=
      DM_SOURCE_AUTH_OK) {
    CHECK("source signature setup", 0);
    goto cleanup;
  }

  if (dm_wire_prove_kernel_os(&proof, &statement, witness_bits,
                              DMK_WITNESS_BITS, DMV_MAX_FINAL_RETRIES) !=
          DM_WIRE_OK ||
      dm_wire_proof_size(&proof, &statement, &frame_bytes) != DM_WIRE_OK ||
      frame_bytes != DM_AUTHENTICATED_PROOF_FRAME_BYTES) {
    CHECK("one fresh true synthetic proof", 0);
    goto cleanup;
  }
  dm_authenticated_proof_fresh_proof = 1;
  if (dm_wire_encode(&proof, &statement, frame, frame_bytes, &written) !=
          DM_WIRE_OK ||
      written != DM_AUTHENTICATED_PROOF_FRAME_BYTES) {
    CHECK("proof frame encoding", 0);
    goto cleanup;
  }
  setup_ok = 1;
  CHECK("joint source-authenticated proof verifies",
        dm_authenticated_proof_verify(
            &request, key_epoch, x, sizeof(x), signature, sizeof(signature),
            frame, frame_bytes, &verified) == DM_AUTHENTICATED_PROOF_OK);
  CHECK("joint result owns exact x",
        memcmp(verified.canonical_x, x, sizeof(x)) == 0);
  CHECK("joint result owns epoch", verified.key_epoch == key_epoch);

  memcpy(x_owned_snapshot, verified.canonical_x, sizeof(x_owned_snapshot));
  x[0] ^= 0x01u;
  CHECK("joint result owns x after caller mutation",
        memcmp(verified.canonical_x, x_owned_snapshot,
               sizeof(x_owned_snapshot)) == 0);
  x[0] ^= 0x01u;

  memcpy(x_mutated, x, sizeof(x_mutated));
  memcpy(signature_mutated, signature, sizeof(signature_mutated));
  memcpy(frame_mutated, frame, frame_bytes);

  memset(&verified, 0xa5, sizeof(verified));
  frame_mutated[DM_WIRE_HEADER_BYTES] ^= 0x01u;
  CHECK("frame embedded x mutation rejects",
        dm_authenticated_proof_verify(
            &request, key_epoch, x, sizeof(x), signature, sizeof(signature),
            frame_mutated, frame_bytes, &verified) ==
            DM_AUTHENTICATED_PROOF_ERR_DECODE);
  CHECK("frame mutation clears joint output", verified_is_clear(&verified));
  memcpy(frame_mutated, frame, frame_bytes);

  frame_mutated[m3_offset] ^= 0x01u;
  dm_authenticated_proof_m3_decode =
      dm_wire_decode(&stage_proof, &statement, frame_mutated, frame_bytes);
  dm_authenticated_proof_m3_kernel =
      dm_authenticated_proof_m3_decode == DM_WIRE_OK
          ? dm_wire_verify_kernel(&stage_proof, &statement)
          : DM_WIRE_ERR_ARGUMENT;
  dm_wire_proof_clear(&stage_proof);
  CHECK("serialized m3 mutation remains decode-valid",
        dm_authenticated_proof_m3_decode == DM_WIRE_OK);
  CHECK("serialized m3 mutation fails kernel verification",
        dm_authenticated_proof_m3_kernel != DM_WIRE_OK);
  memset(&verified, 0xa5, sizeof(verified));
  dm_authenticated_proof_m3_joint = dm_authenticated_proof_verify(
      &request, key_epoch, x, sizeof(x), signature, sizeof(signature),
      frame_mutated, frame_bytes, &verified);
  CHECK("serialized m3 mutation maps to proof failure",
        dm_authenticated_proof_m3_joint == DM_AUTHENTICATED_PROOF_ERR_PROOF);
  CHECK("serialized m3 mutation clears joint output",
        verified_is_clear(&verified));
  memcpy(frame_mutated, frame, frame_bytes);

  memset(&verified, 0xa5, sizeof(verified));
  frame_mutated[frame_bytes - 1u] ^= 0x01u;
  CHECK("proof body mutation rejects",
        dm_authenticated_proof_verify(
            &request, key_epoch, x, sizeof(x), signature, sizeof(signature),
            frame_mutated, frame_bytes, &verified) != DM_AUTHENTICATED_PROOF_OK);
  CHECK("proof mutation clears joint output", verified_is_clear(&verified));
  memcpy(frame_mutated, frame, frame_bytes);

  memset(frame_mutated, 0, frame_bytes);
  memset(&verified, 0xa5, sizeof(verified));
  dm_authenticated_proof_zero_frame = dm_authenticated_proof_verify(
      &request, key_epoch, x, sizeof(x), signature, sizeof(signature),
      frame_mutated, frame_bytes, &verified);
  CHECK("all-zero frame maps to decode failure",
        dm_authenticated_proof_zero_frame == DM_AUTHENTICATED_PROOF_ERR_DECODE);
  CHECK("all-zero frame clears joint output", verified_is_clear(&verified));

  memcpy(frame_mutated, frame, frame_bytes);
  frame_mutated[0] ^= 0x01u;
  memset(&verified, 0xa5, sizeof(verified));
  dm_authenticated_proof_bad_header = dm_authenticated_proof_verify(
      &request, key_epoch, x, sizeof(x), signature, sizeof(signature),
      frame_mutated, frame_bytes, &verified);
  CHECK("malformed frame header maps to decode failure",
        dm_authenticated_proof_bad_header == DM_AUTHENTICATED_PROOF_ERR_DECODE);
  CHECK("malformed frame header clears joint output",
        verified_is_clear(&verified));
  memcpy(frame_mutated, frame, frame_bytes);

  memcpy(x_mutated, x, sizeof(x_mutated));
  x_mutated[t_offset] ^= 0x01u;
  CHECK("fresh source signature for mutated T",
        dm_source_auth_sign(signature_b, sizeof(signature_b), secret_key,
                            sizeof(secret_key), key_epoch, x_mutated,
                            sizeof(x_mutated)) == DM_SOURCE_AUTH_OK);
  CHECK("source auth accepts mutated T and fresh signature",
        dm_source_auth_verify(
            &request, key_epoch, x_mutated, sizeof(x_mutated), signature_b,
            sizeof(signature_b), &source_verified_b) == DM_SOURCE_AUTH_OK &&
            source_verified_b.authentication == DM_SOURCE_AUTH_AUTHENTICATED &&
            source_verified_b.key_epoch == key_epoch &&
            memcmp(source_verified_b.canonical_x, x_mutated,
                   sizeof(x_mutated)) == 0);
  dm_source_auth_verified_clear(&source_verified_b);
  memset(&verified, 0xa5, sizeof(verified));
  dm_authenticated_proof_xb_joint = dm_authenticated_proof_verify(
      &request, key_epoch, x_mutated, sizeof(x_mutated), signature_b,
      sizeof(signature_b), frame, frame_bytes, &verified);
  CHECK("mutated-T source-authenticated frame-A maps to decode failure",
        dm_authenticated_proof_xb_joint == DM_AUTHENTICATED_PROOF_ERR_DECODE);
  CHECK("mutated-T frame-A clears joint output", verified_is_clear(&verified));

  memset(&verified, 0xa5, sizeof(verified));
  signature_mutated[0] ^= 0x01u;
  dm_authenticated_proof_bad_signature = dm_authenticated_proof_verify(
      &request, key_epoch, x, sizeof(x), signature_mutated,
      sizeof(signature_mutated), frame, frame_bytes, &verified);
  CHECK("valid proof with bad signature maps to source-auth failure",
        dm_authenticated_proof_bad_signature ==
            DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("bad signature clears joint output", verified_is_clear(&verified));

  memcpy(&request_mutated, &request, sizeof(request_mutated));
  request_mutated.expected_context[0] ^= 0x01u;
  memset(&verified, 0xa5, sizeof(verified));
  dm_authenticated_proof_bad_context = dm_authenticated_proof_verify(
      &request_mutated, key_epoch, x, sizeof(x), signature, sizeof(signature),
      frame, frame_bytes, &verified);
  CHECK("changed expected context maps to source-auth failure",
        dm_authenticated_proof_bad_context ==
            DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("changed expected context clears joint output",
        verified_is_clear(&verified));

  memset(&verified, 0xa5, sizeof(verified));
  CHECK("epoch mismatch maps to source-auth failure",
        dm_authenticated_proof_verify(
            &request, key_epoch + 1u, x, sizeof(x), signature, sizeof(signature),
            frame, frame_bytes, &verified) ==
            DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH);
  CHECK("epoch mismatch clears joint output", verified_is_clear(&verified));

  memset(&alias_storage, 0x5a, sizeof(alias_storage));
  memcpy(alias_storage.bytes, x, sizeof(x));
  memcpy(alias_before, alias_storage.bytes, sizeof(alias_before));
  memset(&verified, 0xa5, sizeof(verified));
  CHECK("output/input alias rejects before clear",
        dm_authenticated_proof_verify(
            &request, key_epoch, alias_storage.bytes, sizeof(x), signature,
            sizeof(signature), frame, frame_bytes,
            (dm_authenticated_proof_verified_t*)alias_storage.bytes) ==
            DM_AUTHENTICATED_PROOF_ERR_OUTPUT_ALIAS);
  CHECK("output/input alias preserves live input",
        memcmp(alias_storage.bytes, alias_before, sizeof(alias_before)) == 0);
  secure_clear(alias_before, sizeof(alias_before));
  secure_clear(&alias_storage, sizeof(alias_storage));

  memset(&verified, 0xa5, sizeof(verified));
  CHECK("request/x input alias rejects",
        dm_authenticated_proof_verify(
            &request, key_epoch, (const uint8_t*)&request, sizeof(x), signature,
            sizeof(signature), frame, frame_bytes, &verified) ==
            DM_AUTHENTICATED_PROOF_ERR_INPUT_ALIAS);
  CHECK("request/x input alias clears output", verified_is_clear(&verified));

  /* The cheap API cases above run before keypair, witness, and proof setup. */
  CHECK("cheap API cases ran before proof setup", dm_authenticated_proof_cheap_first);

cleanup:
  if (!setup_ok) {
    /* Preserve a decisive setup failure in the raw probe output. */
    dm_authenticated_proof_fresh_proof = 0;
  }
  dm_authenticated_proof_verified_clear(&verified);
  dm_source_auth_request_clear(&request);
  dm_source_auth_request_clear(&request_mutated);
  dm_source_auth_verified_clear(&source_verified_b);
  dm_wire_proof_clear(&proof);
  dm_wire_proof_clear(&stage_proof);
  dmn_clear(&packed);
  if (frame_extra != NULL) {
    secure_clear(frame_extra, frame_bytes + 1u);
    free(frame_extra);
  }
  if (frame_mutated != NULL) {
    secure_clear(frame_mutated, frame_bytes);
    free(frame_mutated);
  }
  if (frame != NULL) {
    secure_clear(frame, frame_bytes);
    free(frame);
  }
  if (witness_bits != NULL) {
    secure_clear(witness_bits, DMK_WITNESS_BITS);
    free(witness_bits);
  }
  secure_clear(signature_mutated, sizeof(signature_mutated));
  secure_clear(signature_b, sizeof(signature_b));
  secure_clear(signature_extra, sizeof(signature_extra));
  secure_clear(signature, sizeof(signature));
  secure_clear(secret_key, sizeof(secret_key));
  secure_clear(public_key, sizeof(public_key));
  secure_clear(seed, sizeof(seed));
  secure_clear(x_owned_snapshot, sizeof(x_owned_snapshot));
  secure_clear(x_extra, sizeof(x_extra));
  secure_clear(x_mutated, sizeof(x_mutated));
  secure_clear(x, sizeof(x));
  secure_clear(alias_before, sizeof(alias_before));
  secure_clear(&alias_storage, sizeof(alias_storage));
  secure_clear(&statement, sizeof(statement));
  secure_clear(&instance, sizeof(instance));
  return dm_authenticated_proof_failures == 0u ? 0 : 1;
}

int main(void) {
  const int result = run_probe();
  printf("STATUS NON_ACTIVATING_DIRECT_MASK_AUTHENTICATED_PROOF\n");
  printf("FRAME_BYTES=%u EXACT_FIXED_FRAME=TRUE\n",
         DM_AUTHENTICATED_PROOF_FRAME_BYTES);
  printf("FRESH_TRUE_SYNTHETIC_PROOF=%s\n",
         dm_authenticated_proof_fresh_proof ? "TRUE" : "FALSE");
  printf("CHEAP_API_CASES_BEFORE_PROOF=%s\n",
         dm_authenticated_proof_cheap_first ? "TRUE" : "FALSE");
  printf("OBSERVED_M3_DECODE=%s M3_KERNEL=%s M3_JOINT=%s\n",
         dm_wire_status_name(dm_authenticated_proof_m3_decode),
         dm_wire_status_name(dm_authenticated_proof_m3_kernel),
         dm_authenticated_proof_status_name(dm_authenticated_proof_m3_joint));
  printf("OBSERVED_XB_JOINT=%s ZERO_FRAME=%s BAD_HEADER=%s BAD_SIGNATURE=%s BAD_CONTEXT=%s\n",
         dm_authenticated_proof_status_name(dm_authenticated_proof_xb_joint),
         dm_authenticated_proof_status_name(dm_authenticated_proof_zero_frame),
         dm_authenticated_proof_status_name(dm_authenticated_proof_bad_header),
         dm_authenticated_proof_status_name(dm_authenticated_proof_bad_signature),
         dm_authenticated_proof_status_name(dm_authenticated_proof_bad_context));
  printf("JOINT_BINDING=SOURCE_SIGNATURE_AND_DM_WIRE_DECODE_KERNEL_SAME_OWNED_X\n");
  printf("RESULT_OWNS_X_AND_EPOCH_ONLY=TRUE\n");
  printf("NO_DIRECTIVE_STATE_SOURCE_TRUTH_OR_ACTIVATION_CLAIM=TRUE\n");
  printf("CHECK_COUNT=%u FAILED=%u\n", dm_authenticated_proof_checks,
         dm_authenticated_proof_failures);
  printf("ALL_TESTS=%s\n", dm_authenticated_proof_failures == 0u ? "PASS" : "FAIL");
  return result;
}
