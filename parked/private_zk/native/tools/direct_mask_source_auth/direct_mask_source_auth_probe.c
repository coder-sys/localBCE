/* SPDX-License-Identifier: MIT */

#include "direct_mask_source_auth.h"

#include <stdio.h>
#include <string.h>

#include "blind_source_auth_mldsa87_v1.h"

static unsigned dm_source_auth_checks;
static unsigned dm_source_auth_failures;

#define CHECK(label, expression)                                                   \
  do {                                                                             \
    ++dm_source_auth_checks;                                                       \
    if (!(expression)) {                                                           \
      ++dm_source_auth_failures;                                                   \
      fprintf(stderr, "FAIL %s\n", (label));                                     \
    }                                                                              \
  } while (0)

static void wipe(void* pointer, size_t length) {
  volatile uint8_t* bytes = (volatile uint8_t*)pointer;
  if (bytes == NULL) {
    return;
  }
  while (length != 0u) {
    *bytes++ = 0u;
    --length;
  }
}

static void fill_bytes(uint8_t* bytes, size_t length, uint8_t seed) {
  for (size_t index = 0; index != length; ++index) {
    bytes[index] = (uint8_t)(seed + (uint8_t)index);
  }
}

static void store_u64_le(uint8_t output[8], uint64_t value) {
  for (size_t index = 0; index != 8u; ++index) {
    output[index] = (uint8_t)(value & UINT64_C(0xff));
    value >>= 8;
  }
}

static void make_source_message(uint8_t message[DM_SOURCE_AUTH_MESSAGE_BYTES],
                                uint64_t key_epoch,
                                const uint8_t x[DM_SOURCE_AUTH_X_BYTES]) {
  static const uint8_t domain[DM_SOURCE_AUTH_DOMAIN_BYTES] = {
      'B', 'L', '/', 'D', 'M', '/', 'S', 'O', 'U', 'R', 'C', 'E', '-',
      'A', 'U', 'T', 'H', '/', 'v', '1',
  };
  memcpy(message, domain, sizeof(domain));
  store_u64_le(message + sizeof(domain), key_epoch);
  memcpy(message + sizeof(domain) + DM_SOURCE_AUTH_KEY_EPOCH_BYTES,
         x, DM_SOURCE_AUTH_X_BYTES);
}

static void make_statement(dm_wire_statement_t* statement,
                           const dm_source_auth_request_t* request,
                           const uint8_t* context, const uint8_t* U,
                           const uint8_t* T, const uint8_t* C) {
  memset(statement, 0, sizeof(*statement));
  memcpy(statement->source_suite, request->expected_source_suite,
         DM_WIRE_SOURCE_SUITE_BYTES);
  statement->relation_id = request->expected_relation_id;
  statement->relation_id_bytes = DM_WIRE_RELATION_ID_BYTES;
  statement->context = context;
  statement->U = U;
  statement->T = T;
  statement->C = C;
  statement->descriptor = request->expected_descriptor;
}

static int all_zero(const uint8_t* bytes, size_t length) {
  uint8_t accumulator = 0u;
  for (size_t index = 0; index != length; ++index) {
    accumulator |= bytes[index];
  }
  return accumulator == 0u;
}

static int prefix_zero(const uint8_t* bytes, size_t length) {
  return all_zero(bytes, length);
}

static int verified_is_clear(const dm_source_auth_verified_t* verified) {
  return all_zero(verified->canonical_x, sizeof(verified->canonical_x)) &&
         verified->key_epoch == 0u &&
         verified->authentication == DM_SOURCE_AUTH_UNAUTHENTICATED;
}

int main(void) {
  static const uint64_t key_epoch = UINT64_C(0x0102030405060708);
  uint8_t context[DM_SOURCE_AUTH_CONTEXT_BYTES];
  uint8_t U[DM_SOURCE_AUTH_U_BYTES];
  uint8_t T[DM_WIRE_T_BYTES];
  uint8_t C[DM_WIRE_C_BYTES];
  uint8_t x[DM_SOURCE_AUTH_X_BYTES];
  uint8_t x_mutated[DM_SOURCE_AUTH_X_BYTES];
  uint8_t short_x[DM_SOURCE_AUTH_X_BYTES - 1u];
  uint8_t extra_x[DM_SOURCE_AUTH_X_BYTES + 1u];
  uint8_t signature[DM_SOURCE_AUTH_SIGNATURE_BYTES];
  uint8_t signature_second[DM_SOURCE_AUTH_SIGNATURE_BYTES];
  uint8_t signature_mutated[DM_SOURCE_AUTH_SIGNATURE_BYTES];
  uint8_t short_signature[DM_SOURCE_AUTH_SIGNATURE_BYTES];
  uint8_t extra_signature[DM_SOURCE_AUTH_SIGNATURE_BYTES + 1u];
  uint8_t short_secret_key[DM_SOURCE_AUTH_SECRET_KEY_BYTES - 1u];
  uint8_t extra_secret_key[DM_SOURCE_AUTH_SECRET_KEY_BYTES + 1u];
  uint8_t wrong_message[DM_SOURCE_AUTH_MESSAGE_BYTES];
  uint8_t wrong_message_with_nul[DM_SOURCE_AUTH_MESSAGE_BYTES + 1u];
  uint8_t test_randomizer[DM_SOURCE_AUTH_RANDOMIZER_BYTES];
  uint8_t public_key[DM_SOURCE_AUTH_PUBLIC_KEY_BYTES];
  uint8_t secret_key[DM_SOURCE_AUTH_SECRET_KEY_BYTES];
  uint8_t seed[BLIND_SOURCE_AUTH_MLDSA87_V1_SEED_BYTES];
  uint8_t alias_buffer[DM_SOURCE_AUTH_SIGNATURE_BYTES];
  uint8_t alias_before[DM_SOURCE_AUTH_SIGNATURE_BYTES];
  uint8_t alias_key_storage[DM_SOURCE_AUTH_SECRET_KEY_BYTES];
  uint8_t alias_key_before[DM_SOURCE_AUTH_SECRET_KEY_BYTES];
  uint8_t verified_before[sizeof(dm_source_auth_verified_t)];
  dm_wire_statement_t statement;
  dm_source_auth_request_t request;
  dm_source_auth_verified_t verified;
  dm_source_auth_verified_t alias_verified;
  dm_source_auth_status_t status;
  blind_source_auth_mldsa87_v1_status keygen_status;
  size_t t_offset = DM_WIRE_SOURCE_SUITE_BYTES + 4u + DM_WIRE_RELATION_ID_BYTES +
                    DM_WIRE_CONTEXT_BYTES + DM_WIRE_U_BYTES;
  size_t c_offset = t_offset + DM_WIRE_T_BYTES;

  memset(context, 0, sizeof(context));
  memset(U, 0, sizeof(U));
  memset(T, 0, sizeof(T));
  memset(C, 0, sizeof(C));
  memset(x, 0, sizeof(x));
  memset(x_mutated, 0, sizeof(x_mutated));
  memset(short_x, 0, sizeof(short_x));
  memset(extra_x, 0, sizeof(extra_x));
  memset(signature, 0, sizeof(signature));
  memset(signature_second, 0, sizeof(signature_second));
  memset(signature_mutated, 0, sizeof(signature_mutated));
  memset(short_signature, 0, sizeof(short_signature));
  memset(extra_signature, 0, sizeof(extra_signature));
  memset(short_secret_key, 0, sizeof(short_secret_key));
  memset(extra_secret_key, 0, sizeof(extra_secret_key));
  memset(wrong_message, 0, sizeof(wrong_message));
  memset(wrong_message_with_nul, 0, sizeof(wrong_message_with_nul));
  memset(test_randomizer, 0, sizeof(test_randomizer));
  memset(public_key, 0, sizeof(public_key));
  memset(secret_key, 0, sizeof(secret_key));
  memset(seed, 0, sizeof(seed));
  memset(alias_buffer, 0, sizeof(alias_buffer));
  memset(alias_before, 0, sizeof(alias_before));
  memset(alias_key_storage, 0, sizeof(alias_key_storage));
  memset(alias_key_before, 0, sizeof(alias_key_before));
  memset(verified_before, 0, sizeof(verified_before));
  memset(&statement, 0, sizeof(statement));
  memset(&request, 0, sizeof(request));
  memset(&verified, 0, sizeof(verified));
  memset(&alias_verified, 0, sizeof(alias_verified));

  fill_bytes(context, sizeof(context), 0x10u);
  fill_bytes(U, sizeof(U), 0x80u);
  fill_bytes(T, sizeof(T), 0x20u);
  fill_bytes(C, sizeof(C), 0x40u);
  fill_bytes(seed, sizeof(seed), 0x60u);
  fill_bytes(test_randomizer, sizeof(test_randomizer), 0xb0u);

  dm_source_auth_request_init(&request);
  memcpy(request.expected_context, context, sizeof(context));
  memcpy(request.expected_U, U, sizeof(U));
  request.expected_key_epoch = key_epoch;

  make_statement(&statement, &request, context, U, T, C);
  status = dm_wire_statement_encode(x, sizeof(x), &statement) == DM_WIRE_OK
               ? DM_SOURCE_AUTH_OK
               : DM_SOURCE_AUTH_ERR_CANONICAL_X;
  CHECK("canonical statement encoding", status == DM_SOURCE_AUTH_OK);

  keygen_status = blind_source_auth_mldsa87_v1_keypair_from_seed(
      public_key, sizeof(public_key), secret_key, sizeof(secret_key), seed,
      sizeof(seed));
  CHECK("probe-only deterministic keygen", keygen_status == BLIND_SOURCE_AUTH_MLDSA87_V1_OK);
  CHECK("keygen public key nonzero", !all_zero(public_key, sizeof(public_key)));
  CHECK("keygen secret key nonzero", !all_zero(secret_key, sizeof(secret_key)));
  memcpy(request.trusted_public_key, public_key, sizeof(public_key));
  memcpy(short_secret_key, secret_key, sizeof(short_secret_key));
  memcpy(extra_secret_key, secret_key, sizeof(secret_key));
  extra_secret_key[sizeof(secret_key)] = 0xa5u;

  status = dm_source_auth_sign(signature, sizeof(signature), secret_key,
                               sizeof(secret_key), key_epoch, x, sizeof(x));
  CHECK("source sign", status == DM_SOURCE_AUTH_OK);
  CHECK("source signature nonzero", !all_zero(signature, sizeof(signature)));
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("source verify", status == DM_SOURCE_AUTH_OK);
  CHECK("verified authentication", verified.authentication == DM_SOURCE_AUTH_AUTHENTICATED);
  CHECK("verified epoch", verified.key_epoch == key_epoch);
  CHECK("verified owns exact x", memcmp(verified.canonical_x, x, sizeof(x)) == 0);
  memcpy(verified_before, &verified, sizeof(verified));

  status = dm_source_auth_sign(signature_second, sizeof(signature_second), secret_key,
                               sizeof(secret_key), key_epoch, x, sizeof(x));
  CHECK("fresh OS randomizer sign", status == DM_SOURCE_AUTH_OK);
  CHECK("fresh signatures differ", memcmp(signature, signature_second,
                                           sizeof(signature)) != 0);

  memset(&verified, 0xa5, sizeof(verified));
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x),
                                 signature_second, sizeof(signature_second),
                                 &verified);
  CHECK("second fresh signature verifies", status == DM_SOURCE_AUTH_OK);
  CHECK("second fresh signature owns exact x",
        status == DM_SOURCE_AUTH_OK &&
            memcmp(verified.canonical_x, x, sizeof(x)) == 0);
  CHECK("second fresh signature returns epoch",
        status == DM_SOURCE_AUTH_OK &&
            verified.key_epoch == key_epoch &&
            verified.authentication == DM_SOURCE_AUTH_AUTHENTICATED);

  memcpy(short_signature, signature, sizeof(signature));
  memset(&verified, 0xa5, sizeof(verified));
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x),
                                 short_signature,
                                 DM_SOURCE_AUTH_SIGNATURE_BYTES - 1u,
                                 &verified);
  CHECK("verify short signature span rejects", status == DM_SOURCE_AUTH_ERR_SIZE);
  CHECK("verify short signature span clears output", verified_is_clear(&verified));

  memset(extra_signature, 0xa5, sizeof(extra_signature));
  memcpy(extra_signature, signature, sizeof(signature));
  memset(&verified, 0xa5, sizeof(verified));
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x),
                                 extra_signature,
                                 DM_SOURCE_AUTH_SIGNATURE_BYTES + 1u,
                                 &verified);
  CHECK("verify extra signature span rejects", status == DM_SOURCE_AUTH_ERR_SIZE);
  CHECK("verify extra signature span clears output", verified_is_clear(&verified));

  memcpy(short_x, x, sizeof(short_x));
  memset(signature_mutated, 0xa5, sizeof(signature_mutated));
  status = dm_source_auth_sign(signature_mutated, sizeof(signature_mutated), secret_key,
                               sizeof(secret_key), key_epoch, short_x, sizeof(short_x));
  CHECK("short x rejects", status == DM_SOURCE_AUTH_ERR_SIZE);
  CHECK("short x clears full valid output", all_zero(signature_mutated,
                                                     sizeof(signature_mutated)));

  memcpy(extra_x, x, sizeof(x));
  extra_x[sizeof(x)] = 0xa5u;
  memset(signature_mutated, 0xa5, sizeof(signature_mutated));
  status = dm_source_auth_sign(signature_mutated, sizeof(signature_mutated), secret_key,
                               sizeof(secret_key), key_epoch, extra_x, sizeof(extra_x));
  CHECK("extra x rejects", status == DM_SOURCE_AUTH_ERR_SIZE);
  CHECK("extra x clears full valid output", all_zero(signature_mutated,
                                                      sizeof(signature_mutated)));

  memset(short_signature, 0xa5, sizeof(short_signature));
  status = dm_source_auth_sign(short_signature, DM_SOURCE_AUTH_SIGNATURE_BYTES - 1u,
                               secret_key, sizeof(secret_key), key_epoch, x, sizeof(x));
  CHECK("short signature span rejects", status == DM_SOURCE_AUTH_ERR_SIZE);
  CHECK("short signature span clears only advertised bytes",
        prefix_zero(short_signature, DM_SOURCE_AUTH_SIGNATURE_BYTES - 1u) &&
            short_signature[DM_SOURCE_AUTH_SIGNATURE_BYTES - 1u] == 0xa5u);

  memset(extra_signature, 0xa5, sizeof(extra_signature));
  status = dm_source_auth_sign(extra_signature, DM_SOURCE_AUTH_SIGNATURE_BYTES + 1u,
                               secret_key, sizeof(secret_key), key_epoch, x, sizeof(x));
  CHECK("extra signature span rejects", status == DM_SOURCE_AUTH_ERR_SIZE);
  CHECK("extra signature span is bounded",
        prefix_zero(extra_signature, DM_SOURCE_AUTH_SIGNATURE_BYTES) &&
            extra_signature[DM_SOURCE_AUTH_SIGNATURE_BYTES] == 0xa5u);

  memset(&verified, 0xa5, sizeof(verified));
  status = dm_source_auth_verify(&request, key_epoch, short_x, sizeof(short_x),
                                 signature, sizeof(signature), &verified);
  CHECK("verify short x span rejects", status == DM_SOURCE_AUTH_ERR_SIZE);
  CHECK("verify short x span clears output", verified_is_clear(&verified));

  memset(&verified, 0xa5, sizeof(verified));
  status = dm_source_auth_verify(&request, key_epoch, extra_x, sizeof(extra_x),
                                 signature, sizeof(signature), &verified);
  CHECK("verify extra x span rejects", status == DM_SOURCE_AUTH_ERR_SIZE);
  CHECK("verify extra x span clears output", verified_is_clear(&verified));

  memset(signature_mutated, 0xa5, sizeof(signature_mutated));
  status = dm_source_auth_sign(signature_mutated, sizeof(signature_mutated),
                               short_secret_key, sizeof(short_secret_key),
                               key_epoch, x, sizeof(x));
  CHECK("short secret key span rejects", status == DM_SOURCE_AUTH_ERR_SIZE);
  CHECK("short secret key span clears output",
        all_zero(signature_mutated, sizeof(signature_mutated)));

  memset(signature_mutated, 0xa5, sizeof(signature_mutated));
  status = dm_source_auth_sign(signature_mutated, sizeof(signature_mutated),
                               extra_secret_key, sizeof(extra_secret_key),
                               key_epoch, x, sizeof(x));
  CHECK("extra secret key span rejects", status == DM_SOURCE_AUTH_ERR_SIZE);
  CHECK("extra secret key span clears output",
        all_zero(signature_mutated, sizeof(signature_mutated)));

  memcpy(x_mutated, x, sizeof(x_mutated));
  x_mutated[t_offset] ^= 0x01u;
  status = dm_source_auth_verify(&request, key_epoch, x_mutated, sizeof(x_mutated),
                                 signature, sizeof(signature), &verified);
  CHECK("T mutation rejects signature", status == DM_SOURCE_AUTH_ERR_SIGNATURE);
  CHECK("T mutation clears output", verified_is_clear(&verified));

  memcpy(x_mutated, x, sizeof(x_mutated));
  x_mutated[c_offset] ^= 0x01u;
  status = dm_source_auth_verify(&request, key_epoch, x_mutated, sizeof(x_mutated),
                                 signature, sizeof(signature), &verified);
  CHECK("C mutation rejects signature", status == DM_SOURCE_AUTH_ERR_SIGNATURE);
  CHECK("C mutation clears output", verified_is_clear(&verified));

  memcpy(signature_mutated, signature, sizeof(signature_mutated));
  signature_mutated[0] ^= 0x01u;
  memset(&verified, 0xa5, sizeof(verified));
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature_mutated,
                                 sizeof(signature_mutated), &verified);
  CHECK("signature mutation rejects", status == DM_SOURCE_AUTH_ERR_SIGNATURE);
  CHECK("signature failure clears output", verified_is_clear(&verified));

  status = dm_source_auth_verify(&request, key_epoch + 1u, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("epoch mismatch rejects before authentication",
        status == DM_SOURCE_AUTH_ERR_KEY_EPOCH);
  CHECK("epoch mismatch clears output", verified_is_clear(&verified));

  request.expected_context[0] ^= 0x01u;
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("context mismatch rejects", status == DM_SOURCE_AUTH_ERR_CONTEXT);
  CHECK("context mismatch clears output", verified_is_clear(&verified));
  request.expected_context[0] ^= 0x01u;

  request.expected_U[0] ^= 0x01u;
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("U mismatch rejects", status == DM_SOURCE_AUTH_ERR_U);
  CHECK("U mismatch clears output", verified_is_clear(&verified));
  request.expected_U[0] ^= 0x01u;

  memset(request.expected_U, 0, sizeof(request.expected_U));
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("zero expected U rejects", status == DM_SOURCE_AUTH_ERR_U);
  CHECK("zero expected U clears output", verified_is_clear(&verified));
  memcpy(request.expected_U, U, sizeof(request.expected_U));

  request.expected_source_suite[0] ^= 0x01u;
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("suite mismatch rejects", status == DM_SOURCE_AUTH_ERR_REQUEST);
  request.expected_source_suite[0] ^= 0x01u;

  request.expected_relation_id[0] ^= 0x01u;
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("relation mismatch rejects", status == DM_SOURCE_AUTH_ERR_REQUEST);
  request.expected_relation_id[0] ^= 0x01u;

  request.expected_descriptor.degree ^= 0x01u;
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("descriptor mismatch rejects", status == DM_SOURCE_AUTH_ERR_REQUEST);
  request.expected_descriptor.degree ^= 0x01u;

  memcpy(x_mutated, x, sizeof(x_mutated));
  x_mutated[c_offset + DM_WIRE_C_BYTES] ^= 0x01u;
  status = dm_source_auth_verify(&request, key_epoch, x_mutated, sizeof(x_mutated),
                                 signature, sizeof(signature), &verified);
  CHECK("malformed canonical descriptor rejects", status == DM_SOURCE_AUTH_ERR_CANONICAL_X);
  CHECK("malformed descriptor clears output", verified_is_clear(&verified));

  memcpy(x_mutated, x, sizeof(x_mutated));
  memset(x_mutated + DM_WIRE_SOURCE_SUITE_BYTES + 4u + DM_WIRE_RELATION_ID_BYTES +
             DM_WIRE_CONTEXT_BYTES,
         0, DM_WIRE_U_BYTES);
  status = dm_source_auth_verify(&request, key_epoch, x_mutated, sizeof(x_mutated),
                                 signature, sizeof(signature), &verified);
  CHECK("zero canonical U rejects", status == DM_SOURCE_AUTH_ERR_CANONICAL_X);
  CHECK("zero canonical U clears output", verified_is_clear(&verified));

  request.expected_key_epoch = key_epoch + 1u;
  status = dm_source_auth_verify(&request, key_epoch + 1u, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("changed epoch under old signature rejects", status == DM_SOURCE_AUTH_ERR_SIGNATURE);
  CHECK("changed epoch clears output", verified_is_clear(&verified));
  request.expected_key_epoch = key_epoch;

  request.trusted_public_key[0] ^= 0x01u;
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("wrong registered key rejects", status == DM_SOURCE_AUTH_ERR_SIGNATURE);
  CHECK("wrong registered key clears output", verified_is_clear(&verified));
  request.trusted_public_key[0] ^= 0x01u;

  request.expected_key_epoch = 0u;
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature,
                                 sizeof(signature), &verified);
  CHECK("zero expected epoch rejects", status == DM_SOURCE_AUTH_ERR_KEY_EPOCH);
  request.expected_key_epoch = key_epoch;

  memcpy(x_mutated, x, sizeof(x_mutated));
  x_mutated[0] ^= 0x01u;
  status = dm_source_auth_sign(signature_mutated, sizeof(signature_mutated), secret_key,
                               sizeof(secret_key), key_epoch, x_mutated,
                               sizeof(x_mutated));
  CHECK("noncanonical suite cannot be signed", status == DM_SOURCE_AUTH_ERR_CANONICAL_X);
  CHECK("noncanonical sign clears signature", all_zero(signature_mutated,
                                                        sizeof(signature_mutated)));

  status = dm_source_auth_sign(signature_mutated, sizeof(signature_mutated), secret_key,
                               sizeof(secret_key), 0u, x, sizeof(x));
  CHECK("zero signing epoch rejects", status == DM_SOURCE_AUTH_ERR_KEY_EPOCH);
  CHECK("zero epoch clears signature", all_zero(signature_mutated,
                                                 sizeof(signature_mutated)));

  make_source_message(wrong_message, key_epoch, x);
  wrong_message[0] ^= 0x01u;
  status = blind_source_auth_mldsa87_v1_sign_hedged(
      signature_mutated, sizeof(signature_mutated), secret_key, sizeof(secret_key),
      wrong_message, sizeof(wrong_message), test_randomizer, sizeof(test_randomizer)) ==
               BLIND_SOURCE_AUTH_MLDSA87_V1_OK
           ? DM_SOURCE_AUTH_OK
           : DM_SOURCE_AUTH_ERR_CRYPTO;
  CHECK("independently signed wrong-domain message", status == DM_SOURCE_AUTH_OK);
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature_mutated,
                                 sizeof(signature_mutated), &verified);
  CHECK("wrong-domain message rejects", status == DM_SOURCE_AUTH_ERR_SIGNATURE);

  make_source_message(wrong_message, key_epoch, x);
  wrong_message[DM_SOURCE_AUTH_DOMAIN_BYTES - 1u] = 0u;
  status = blind_source_auth_mldsa87_v1_sign_hedged(
      signature_mutated, sizeof(signature_mutated), secret_key, sizeof(secret_key),
      wrong_message, sizeof(wrong_message), test_randomizer, sizeof(test_randomizer)) ==
               BLIND_SOURCE_AUTH_MLDSA87_V1_OK
           ? DM_SOURCE_AUTH_OK
           : DM_SOURCE_AUTH_ERR_CRYPTO;
  CHECK("independently signed wrong-NUL-domain message", status == DM_SOURCE_AUTH_OK);
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature_mutated,
                                 sizeof(signature_mutated), &verified);
  CHECK("wrong-NUL-domain message rejects", status == DM_SOURCE_AUTH_ERR_SIGNATURE);

  make_source_message(wrong_message_with_nul, key_epoch, x);
  memmove(wrong_message_with_nul + DM_SOURCE_AUTH_DOMAIN_BYTES + 1u,
          wrong_message_with_nul + DM_SOURCE_AUTH_DOMAIN_BYTES,
          DM_SOURCE_AUTH_KEY_EPOCH_BYTES + DM_SOURCE_AUTH_X_BYTES);
  wrong_message_with_nul[DM_SOURCE_AUTH_DOMAIN_BYTES] = 0u;
  status = blind_source_auth_mldsa87_v1_sign_hedged(
      signature_mutated, sizeof(signature_mutated), secret_key, sizeof(secret_key),
      wrong_message_with_nul, sizeof(wrong_message_with_nul), test_randomizer,
      sizeof(test_randomizer)) == BLIND_SOURCE_AUTH_MLDSA87_V1_OK
               ? DM_SOURCE_AUTH_OK
               : DM_SOURCE_AUTH_ERR_CRYPTO;
  CHECK("independently signed shifted-NUL serialization", status == DM_SOURCE_AUTH_OK);
  memset(&verified, 0xa5, sizeof(verified));
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature_mutated,
                                 sizeof(signature_mutated), &verified);
  CHECK("shifted-NUL serialization rejects", status == DM_SOURCE_AUTH_ERR_SIGNATURE);
  CHECK("shifted-NUL serialization clears output", verified_is_clear(&verified));

  make_source_message(wrong_message, key_epoch, x);
  for (size_t index = 0; index != DM_SOURCE_AUTH_KEY_EPOCH_BYTES; ++index) {
    wrong_message[DM_SOURCE_AUTH_DOMAIN_BYTES + index] =
        (uint8_t)(key_epoch >> (8u * (DM_SOURCE_AUTH_KEY_EPOCH_BYTES - 1u - index)));
  }
  status = blind_source_auth_mldsa87_v1_sign_hedged(
      signature_mutated, sizeof(signature_mutated), secret_key, sizeof(secret_key),
      wrong_message, sizeof(wrong_message), test_randomizer, sizeof(test_randomizer)) ==
               BLIND_SOURCE_AUTH_MLDSA87_V1_OK
           ? DM_SOURCE_AUTH_OK
           : DM_SOURCE_AUTH_ERR_CRYPTO;
  CHECK("independently signed wrong-byte-order epoch", status == DM_SOURCE_AUTH_OK);
  status = dm_source_auth_verify(&request, key_epoch, x, sizeof(x), signature_mutated,
                                 sizeof(signature_mutated), &verified);
  CHECK("wrong-byte-order epoch rejects", status == DM_SOURCE_AUTH_ERR_SIGNATURE);

  memset(alias_buffer, 0x5a, sizeof(alias_buffer));
  memcpy(alias_buffer, x, sizeof(x));
  memcpy(alias_before, alias_buffer, sizeof(alias_buffer));
  status = dm_source_auth_sign(alias_buffer, sizeof(alias_buffer), secret_key,
                               sizeof(secret_key), key_epoch, alias_buffer,
                               sizeof(x));
  CHECK("sign output/input alias rejects", status == DM_SOURCE_AUTH_ERR_OUTPUT_ALIAS);
  CHECK("sign alias preserves live input", memcmp(alias_buffer, alias_before,
                                                   sizeof(alias_buffer)) == 0);

  memcpy(alias_key_storage, secret_key, sizeof(alias_key_storage));
  memcpy(alias_key_before, alias_key_storage, sizeof(alias_key_before));
  status = dm_source_auth_sign(alias_key_storage, sizeof(signature), alias_key_storage,
                               sizeof(alias_key_storage), key_epoch, NULL, sizeof(x));
  CHECK("NULL canonical x plus key/output alias rejects",
        status == DM_SOURCE_AUTH_ERR_OUTPUT_ALIAS);
  CHECK("NULL canonical x alias preserves key",
        memcmp(alias_key_storage, alias_key_before, sizeof(alias_key_storage)) == 0);

  memcpy(alias_buffer, x, sizeof(x));
  memset(alias_buffer + sizeof(x), 0x5a, sizeof(alias_buffer) - sizeof(x));
  memcpy(alias_before, alias_buffer, sizeof(alias_before));
  status = dm_source_auth_sign(alias_buffer, sizeof(alias_buffer), NULL,
                               sizeof(secret_key), key_epoch, alias_buffer, sizeof(x));
  CHECK("NULL secret key plus x/output alias rejects",
        status == DM_SOURCE_AUTH_ERR_OUTPUT_ALIAS);
  CHECK("NULL secret key alias preserves x",
        memcmp(alias_buffer, alias_before, sizeof(alias_buffer)) == 0);

  memset(&alias_verified, 0x5a, sizeof(alias_verified));
  memcpy(alias_before, &alias_verified, sizeof(alias_verified));
  status = dm_source_auth_verify(&request, key_epoch, (uint8_t*)&alias_verified,
                                 sizeof(x), signature, sizeof(signature),
                                 &alias_verified);
  CHECK("verify output/input alias rejects", status == DM_SOURCE_AUTH_ERR_OUTPUT_ALIAS);
  CHECK("verify alias preserves live input", memcmp(&alias_verified, alias_before,
                                                     sizeof(alias_verified)) == 0);

  memset(&verified, 0xa5, sizeof(verified));
  status = dm_source_auth_verify(&request, key_epoch, (uint8_t*)&request,
                                 sizeof(x), signature, sizeof(signature), &verified);
  CHECK("verify input-input alias rejects", status == DM_SOURCE_AUTH_ERR_INPUT_ALIAS);
  CHECK("verify input-input alias clears disjoint output", verified_is_clear(&verified));

  memcpy(x_mutated, x, sizeof(x_mutated));
  memset(&verified, 0xa5, sizeof(verified));
  status = dm_source_auth_verify(&request, key_epoch, x_mutated, sizeof(x_mutated),
                                 signature, sizeof(signature), &verified);
  CHECK("owned output remains valid after input storage is separate",
        status == DM_SOURCE_AUTH_OK);
  memset(x_mutated, 0, sizeof(x_mutated));
  memset(signature_mutated, 0, sizeof(signature_mutated));
  request.expected_context[0] ^= 0x7fu;
  CHECK("owned x snapshot survives input mutation",
        memcmp(verified.canonical_x, verified_before, sizeof(verified.canonical_x)) == 0);
  request.expected_context[0] ^= 0x7fu;

  dm_source_auth_verified_clear(&verified);
  dm_source_auth_request_clear(&request);
  wipe(&alias_verified, sizeof(alias_verified));
  wipe(&statement, sizeof(statement));
  wipe(seed, sizeof(seed));
  wipe(secret_key, sizeof(secret_key));
  wipe(public_key, sizeof(public_key));
  wipe(signature_mutated, sizeof(signature_mutated));
  wipe(signature_second, sizeof(signature_second));
  wipe(signature, sizeof(signature));
  wipe(extra_signature, sizeof(extra_signature));
  wipe(short_signature, sizeof(short_signature));
  wipe(extra_secret_key, sizeof(extra_secret_key));
  wipe(short_secret_key, sizeof(short_secret_key));
  wipe(test_randomizer, sizeof(test_randomizer));
  wipe(wrong_message, sizeof(wrong_message));
  wipe(wrong_message_with_nul, sizeof(wrong_message_with_nul));
  wipe(alias_key_before, sizeof(alias_key_before));
  wipe(alias_key_storage, sizeof(alias_key_storage));
  wipe(x_mutated, sizeof(x_mutated));
  wipe(extra_x, sizeof(extra_x));
  wipe(short_x, sizeof(short_x));
  wipe(x, sizeof(x));
  wipe(C, sizeof(C));
  wipe(T, sizeof(T));
  wipe(U, sizeof(U));
  wipe(context, sizeof(context));

  printf("STATUS NON_ACTIVATING_DIRECT_MASK_SOURCE_AUTH\n");
  printf("STORE_CLASS DISPOSABLE_SYNTHETIC_FIXTURE_NOT_CUSTODY_QUALIFIED\n");
  printf("MESSAGE_BINDING DOMAIN20_NO_NUL_EPOCH_LE64_X1147\n");
  printf("SOURCE_OWNS_FRESH_OS_CSPRNG_RANDOMIZER=TRUE\n");
  printf("TEST_KEYGEN_DETERMINISTIC_PROBE_ONLY=TRUE\n");
  printf("VERIFIER_RETURNS_OWNED_AUTHENTICATED_X_ONLY=TRUE\n");
  printf("NO_PROOF_DISPOSITION_STATE_OR_SOURCE_TRUTH_CLAIM=TRUE\n");
  printf("CHECK_COUNT=%u FAILED=%u\n", dm_source_auth_checks,
         dm_source_auth_failures);
  printf("ALL_TESTS=%s\n", dm_source_auth_failures == 0u ? "PASS" : "FAIL");
  return dm_source_auth_failures == 0u ? 0 : 1;
}
