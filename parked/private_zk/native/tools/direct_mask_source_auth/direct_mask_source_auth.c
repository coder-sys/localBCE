/* SPDX-License-Identifier: MIT */

#include "direct_mask_source_auth.h"

#include <limits.h>
#include <string.h>

#include "blind_source_auth_mldsa87_v1.h"

static const uint8_t dm_source_auth_domain[DM_SOURCE_AUTH_DOMAIN_BYTES] = {
    'B', 'L', '/', 'D', 'M', '/', 'S', 'O', 'U', 'R', 'C', 'E', '-',
    'A', 'U', 'T', 'H', '/', 'v', '1',
};

static const uint8_t dm_source_auth_suite[DM_WIRE_SOURCE_SUITE_BYTES] = {
    'S', 'B', 'A', '1', '-', 'S', 'R', 'C', '-', 'C', 'M', 'T', '-', 'v', '1', 0,
};

static const uint8_t dm_source_auth_relation[DM_WIRE_RELATION_ID_BYTES] = {
    'd', 'i', 'r', 'e', 'c', 't', '-', 'm', 'a', 's', 'k', '-', 'r', 'e', 'l',
    'a', 't', 'i', 'o', 'n', '-', 'v', '1',
};

typedef char dm_source_auth_domain_size_check[
    (sizeof(dm_source_auth_domain) == DM_SOURCE_AUTH_DOMAIN_BYTES) ? 1 : -1];
typedef char dm_source_auth_suite_size_check[
    (sizeof(dm_source_auth_suite) == DM_WIRE_SOURCE_SUITE_BYTES) ? 1 : -1];
typedef char dm_source_auth_relation_size_check[
    (sizeof(dm_source_auth_relation) == DM_WIRE_RELATION_ID_BYTES) ? 1 : -1];

static void dm_source_auth_wipe(void* pointer, size_t length) {
  volatile uint8_t* bytes = (volatile uint8_t*)pointer;
  if (bytes == NULL) {
    return;
  }
  while (length != 0u) {
    *bytes = 0u;
    ++bytes;
    --length;
  }
}

/* A conservative overflow result is intentional: an unrepresentable span is
 * treated as an alias so no destructive clear is attempted. */
static int dm_source_auth_spans_overlap(const void* lhs, size_t lhs_bytes,
                                        const void* rhs, size_t rhs_bytes) {
  uintptr_t lhs_start;
  uintptr_t rhs_start;
  uintptr_t lhs_end;
  uintptr_t rhs_end;

  if (lhs == NULL || rhs == NULL || lhs_bytes == 0u || rhs_bytes == 0u) {
    return 0;
  }
  lhs_start = (uintptr_t)lhs;
  rhs_start = (uintptr_t)rhs;
  if ((uintmax_t)lhs_bytes > (uintmax_t)UINTPTR_MAX - (uintmax_t)lhs_start ||
      (uintmax_t)rhs_bytes > (uintmax_t)UINTPTR_MAX - (uintmax_t)rhs_start) {
    return 1;
  }
  lhs_end = lhs_start + (uintptr_t)lhs_bytes;
  rhs_end = rhs_start + (uintptr_t)rhs_bytes;
  return lhs_start < rhs_end && rhs_start < lhs_end;
}

static size_t dm_source_auth_alias_bytes(size_t requested) {
  return requested == 0u ? 1u : requested;
}

static void dm_source_auth_wipe_signature_bounded(uint8_t* signature,
                                                  size_t signature_bytes) {
  size_t wipe_bytes = signature_bytes;
  if (signature == NULL) {
    return;
  }
  if (wipe_bytes > DM_SOURCE_AUTH_SIGNATURE_BYTES) {
    wipe_bytes = DM_SOURCE_AUTH_SIGNATURE_BYTES;
  }
  dm_source_auth_wipe(signature, wipe_bytes);
}

static void dm_source_auth_store_u64_le(uint8_t output[8], uint64_t value) {
  for (size_t index = 0; index != 8u; ++index) {
    output[index] = (uint8_t)(value & UINT64_C(0xff));
    value >>= 8;
  }
}

static int dm_source_auth_nonzero(const uint8_t* bytes, size_t length) {
  uint8_t accumulator = 0u;
  for (size_t index = 0; index != length; ++index) {
    accumulator |= bytes[index];
  }
  return accumulator != 0u;
}

static int dm_source_auth_descriptor_equal(
    const dm_wire_relation_descriptor_t* lhs,
    const dm_wire_relation_descriptor_t* rhs) {
  return lhs != NULL && rhs != NULL && lhs->field_bits == rhs->field_bits &&
         lhs->degree == rhs->degree && lhs->tau == rhs->tau &&
         lhs->w_grind == rhs->w_grind &&
         lhs->short_challenge_bits == rhs->short_challenge_bits &&
         lhs->open_budget == rhs->open_budget &&
         lhs->witness_bits == rhs->witness_bits &&
         lhs->constraints == rhs->constraints &&
         lhs->padding_bits == rhs->padding_bits &&
         lhs->mask_count == rhs->mask_count &&
         lhs->nonce_bits == rhs->nonce_bits &&
         lhs->challenge_mode == rhs->challenge_mode;
}

static void dm_source_auth_set_descriptor(dm_wire_relation_descriptor_t* descriptor) {
  memset(descriptor, 0, sizeof(*descriptor));
  descriptor->field_bits = DMV_LAMBDA;
  descriptor->degree = DMV_DEGREE;
  descriptor->tau = DMV_TAU;
  descriptor->w_grind = DMV_W_GRIND;
  descriptor->short_challenge_bits = DMV_SHORT_CHALLENGE_BITS;
  descriptor->open_budget = DMV_T_OPEN;
  descriptor->witness_bits = DMK_WITNESS_BITS;
  descriptor->constraints = DMK_CONSTRAINTS;
  descriptor->padding_bits = 0u;
  descriptor->mask_count = DMK_MASK_COUNT;
  descriptor->nonce_bits = 8u * DMV_NONCE_BYTES;
  descriptor->challenge_mode = DMV_CHALLENGE_MODE;
}

static dm_source_auth_status_t dm_source_auth_validate_canonical_x(
    const uint8_t x[DM_SOURCE_AUTH_X_BYTES]) {
  dm_wire_statement_t statement;
  uint8_t round_trip[DM_SOURCE_AUTH_X_BYTES];
  dm_wire_status_t wire_status;
  dm_source_auth_status_t result = DM_SOURCE_AUTH_ERR_CANONICAL_X;

  memset(&statement, 0, sizeof(statement));
  memset(round_trip, 0, sizeof(round_trip));
  wire_status = dm_wire_statement_decode(&statement, x, DM_SOURCE_AUTH_X_BYTES);
  if (wire_status == DM_WIRE_OK &&
      dm_wire_statement_encode(round_trip, sizeof(round_trip), &statement) == DM_WIRE_OK &&
      memcmp(round_trip, x, sizeof(round_trip)) == 0) {
    result = DM_SOURCE_AUTH_OK;
  }
  dm_source_auth_wipe(round_trip, sizeof(round_trip));
  dm_source_auth_wipe(&statement, sizeof(statement));
  return result;
}

static dm_source_auth_status_t dm_source_auth_validate_request(
    const dm_source_auth_request_t* request) {
  dm_wire_relation_descriptor_t descriptor;

  if (request == NULL) {
    return DM_SOURCE_AUTH_ERR_ARGUMENT;
  }
  dm_source_auth_set_descriptor(&descriptor);
  if (memcmp(request->expected_source_suite, dm_source_auth_suite,
             sizeof(dm_source_auth_suite)) != 0 ||
      memcmp(request->expected_relation_id, dm_source_auth_relation,
             sizeof(dm_source_auth_relation)) != 0 ||
      !dm_source_auth_descriptor_equal(&request->expected_descriptor, &descriptor)) {
    dm_source_auth_wipe(&descriptor, sizeof(descriptor));
    return DM_SOURCE_AUTH_ERR_REQUEST;
  }
  dm_source_auth_wipe(&descriptor, sizeof(descriptor));
  if (!dm_source_auth_nonzero(request->expected_U, DM_SOURCE_AUTH_U_BYTES)) {
    return DM_SOURCE_AUTH_ERR_U;
  }
  if (!dm_source_auth_nonzero(request->trusted_public_key,
                              DM_SOURCE_AUTH_PUBLIC_KEY_BYTES)) {
    return DM_SOURCE_AUTH_ERR_REQUEST;
  }
  if (request->expected_key_epoch == 0u) {
    return DM_SOURCE_AUTH_ERR_KEY_EPOCH;
  }
  return DM_SOURCE_AUTH_OK;
}

static void dm_source_auth_make_message(
    uint8_t message[DM_SOURCE_AUTH_MESSAGE_BYTES], uint64_t key_epoch,
    const uint8_t x[DM_SOURCE_AUTH_X_BYTES]) {
  memcpy(message, dm_source_auth_domain, DM_SOURCE_AUTH_DOMAIN_BYTES);
  dm_source_auth_store_u64_le(message + DM_SOURCE_AUTH_DOMAIN_BYTES, key_epoch);
  memcpy(message + DM_SOURCE_AUTH_DOMAIN_BYTES + DM_SOURCE_AUTH_KEY_EPOCH_BYTES,
         x, DM_SOURCE_AUTH_X_BYTES);
}

const char* dm_source_auth_status_name(dm_source_auth_status_t status) {
  switch (status) {
    case DM_SOURCE_AUTH_OK:
      return "ok";
    case DM_SOURCE_AUTH_ERR_ARGUMENT:
      return "argument";
    case DM_SOURCE_AUTH_ERR_SIZE:
      return "size";
    case DM_SOURCE_AUTH_ERR_CANONICAL_X:
      return "canonical-x";
    case DM_SOURCE_AUTH_ERR_REQUEST:
      return "request";
    case DM_SOURCE_AUTH_ERR_CONTEXT:
      return "context";
    case DM_SOURCE_AUTH_ERR_U:
      return "U";
    case DM_SOURCE_AUTH_ERR_KEY_EPOCH:
      return "key-epoch";
    case DM_SOURCE_AUTH_ERR_SIGNATURE:
      return "signature";
    case DM_SOURCE_AUTH_ERR_CRYPTO:
      return "crypto";
    case DM_SOURCE_AUTH_ERR_CSPRNG:
      return "csprng";
    case DM_SOURCE_AUTH_ERR_OUTPUT_ALIAS:
      return "output-alias";
    case DM_SOURCE_AUTH_ERR_INPUT_ALIAS:
      return "input-alias";
    default:
      return "unknown";
  }
}

void dm_source_auth_request_clear(dm_source_auth_request_t* request) {
  if (request != NULL) {
    dm_source_auth_wipe(request, sizeof(*request));
  }
}

void dm_source_auth_request_init(dm_source_auth_request_t* request) {
  if (request == NULL) {
    return;
  }
  dm_source_auth_request_clear(request);
  memcpy(request->expected_source_suite, dm_source_auth_suite,
         sizeof(dm_source_auth_suite));
  memcpy(request->expected_relation_id, dm_source_auth_relation,
         sizeof(dm_source_auth_relation));
  dm_source_auth_set_descriptor(&request->expected_descriptor);
}

void dm_source_auth_verified_clear(dm_source_auth_verified_t* verified) {
  if (verified != NULL) {
    dm_source_auth_wipe(verified, sizeof(*verified));
  }
}

dm_source_auth_status_t dm_source_auth_sign(
    uint8_t* signature, size_t signature_bytes, const uint8_t* secret_key,
    size_t secret_key_bytes, uint64_t key_epoch, const uint8_t* canonical_x,
    size_t canonical_x_bytes) {
  uint8_t secret_key_snapshot[DM_SOURCE_AUTH_SECRET_KEY_BYTES];
  uint8_t x_snapshot[DM_SOURCE_AUTH_X_BYTES];
  uint8_t message[DM_SOURCE_AUTH_MESSAGE_BYTES];
  uint8_t randomizer[DM_SOURCE_AUTH_RANDOMIZER_BYTES];
  dm_source_auth_status_t result = DM_SOURCE_AUTH_ERR_CRYPTO;
  blind_source_auth_mldsa87_v1_status crypto_status;

  memset(secret_key_snapshot, 0, sizeof(secret_key_snapshot));
  memset(x_snapshot, 0, sizeof(x_snapshot));
  memset(message, 0, sizeof(message));
  memset(randomizer, 0, sizeof(randomizer));

  /* Alias checks precede every destructive output operation, including
   * NULL/size validation.  A NULL argument must not provide a path around a
   * live input/output alias. */
  if ((secret_key != NULL &&
       dm_source_auth_spans_overlap(
           signature, dm_source_auth_alias_bytes(signature_bytes), secret_key,
           dm_source_auth_alias_bytes(secret_key_bytes))) ||
      (canonical_x != NULL &&
       dm_source_auth_spans_overlap(
           signature, dm_source_auth_alias_bytes(signature_bytes), canonical_x,
           dm_source_auth_alias_bytes(canonical_x_bytes)))) {
    return DM_SOURCE_AUTH_ERR_OUTPUT_ALIAS;
  }
  if (secret_key != NULL && canonical_x != NULL &&
      dm_source_auth_spans_overlap(
          secret_key, dm_source_auth_alias_bytes(secret_key_bytes), canonical_x,
          dm_source_auth_alias_bytes(canonical_x_bytes))) {
    dm_source_auth_wipe_signature_bounded(signature, signature_bytes);
    return DM_SOURCE_AUTH_ERR_INPUT_ALIAS;
  }
  if (signature == NULL || secret_key == NULL || canonical_x == NULL) {
    dm_source_auth_wipe_signature_bounded(signature, signature_bytes);
    return DM_SOURCE_AUTH_ERR_ARGUMENT;
  }
  if (signature_bytes != DM_SOURCE_AUTH_SIGNATURE_BYTES ||
      secret_key_bytes != DM_SOURCE_AUTH_SECRET_KEY_BYTES ||
      canonical_x_bytes != DM_SOURCE_AUTH_X_BYTES) {
    dm_source_auth_wipe_signature_bounded(signature, signature_bytes);
    return DM_SOURCE_AUTH_ERR_SIZE;
  }

  dm_source_auth_wipe(signature, DM_SOURCE_AUTH_SIGNATURE_BYTES);
  memcpy(secret_key_snapshot, secret_key, sizeof(secret_key_snapshot));
  memcpy(x_snapshot, canonical_x, sizeof(x_snapshot));

  if (key_epoch == 0u) {
    result = DM_SOURCE_AUTH_ERR_KEY_EPOCH;
    goto cleanup;
  }
  result = dm_source_auth_validate_canonical_x(x_snapshot);
  if (result != DM_SOURCE_AUTH_OK) {
    goto cleanup;
  }
  dm_source_auth_make_message(message, key_epoch, x_snapshot);
  if (dm_wire_os_random_bytes(NULL, randomizer, sizeof(randomizer)) != 0) {
    result = DM_SOURCE_AUTH_ERR_CSPRNG;
    goto cleanup;
  }
  crypto_status = blind_source_auth_mldsa87_v1_sign_hedged(
      signature, DM_SOURCE_AUTH_SIGNATURE_BYTES, secret_key_snapshot,
      sizeof(secret_key_snapshot), message, sizeof(message), randomizer,
      sizeof(randomizer));
  result = crypto_status == BLIND_SOURCE_AUTH_MLDSA87_V1_OK
               ? DM_SOURCE_AUTH_OK
               : DM_SOURCE_AUTH_ERR_CRYPTO;

cleanup:
  if (result != DM_SOURCE_AUTH_OK) {
    dm_source_auth_wipe(signature, DM_SOURCE_AUTH_SIGNATURE_BYTES);
  }
  dm_source_auth_wipe(randomizer, sizeof(randomizer));
  dm_source_auth_wipe(message, sizeof(message));
  dm_source_auth_wipe(x_snapshot, sizeof(x_snapshot));
  dm_source_auth_wipe(secret_key_snapshot, sizeof(secret_key_snapshot));
  return result;
}

dm_source_auth_status_t dm_source_auth_verify(
    const dm_source_auth_request_t* request, uint64_t presented_key_epoch,
    const uint8_t* canonical_x, size_t canonical_x_bytes,
    const uint8_t* signature, size_t signature_bytes,
    dm_source_auth_verified_t* verified) {
  dm_source_auth_request_t request_snapshot;
  uint8_t x_snapshot[DM_SOURCE_AUTH_X_BYTES];
  uint8_t signature_snapshot[DM_SOURCE_AUTH_SIGNATURE_BYTES];
  uint8_t message[DM_SOURCE_AUTH_MESSAGE_BYTES];
  uint8_t round_trip[DM_SOURCE_AUTH_X_BYTES];
  dm_wire_statement_t statement;
  dm_source_auth_status_t result = DM_SOURCE_AUTH_ERR_CRYPTO;
  blind_source_auth_mldsa87_v1_status crypto_status;
  int accepted = 0;

  memset(&request_snapshot, 0, sizeof(request_snapshot));
  memset(x_snapshot, 0, sizeof(x_snapshot));
  memset(signature_snapshot, 0, sizeof(signature_snapshot));
  memset(message, 0, sizeof(message));
  memset(round_trip, 0, sizeof(round_trip));
  memset(&statement, 0, sizeof(statement));

  if (verified == NULL) {
    return DM_SOURCE_AUTH_ERR_ARGUMENT;
  }
  if (dm_source_auth_spans_overlap(verified, sizeof(*verified), request,
                                   request == NULL ? 0u : sizeof(*request)) ||
      dm_source_auth_spans_overlap(verified, sizeof(*verified), canonical_x,
                                   dm_source_auth_alias_bytes(canonical_x_bytes)) ||
      dm_source_auth_spans_overlap(verified, sizeof(*verified), signature,
                                   dm_source_auth_alias_bytes(signature_bytes))) {
    return DM_SOURCE_AUTH_ERR_OUTPUT_ALIAS;
  }
  if (request != NULL &&
      (dm_source_auth_spans_overlap(request, sizeof(*request), canonical_x,
                                    dm_source_auth_alias_bytes(canonical_x_bytes)) ||
       dm_source_auth_spans_overlap(request, sizeof(*request), signature,
                                    dm_source_auth_alias_bytes(signature_bytes)) ||
       dm_source_auth_spans_overlap(canonical_x,
                                    dm_source_auth_alias_bytes(canonical_x_bytes),
                                    signature,
                                    dm_source_auth_alias_bytes(signature_bytes)))) {
    dm_source_auth_verified_clear(verified);
    return DM_SOURCE_AUTH_ERR_INPUT_ALIAS;
  }

  dm_source_auth_verified_clear(verified);
  if (request == NULL || canonical_x == NULL || signature == NULL) {
    result = DM_SOURCE_AUTH_ERR_ARGUMENT;
    goto cleanup;
  }
  if (canonical_x_bytes != DM_SOURCE_AUTH_X_BYTES ||
      signature_bytes != DM_SOURCE_AUTH_SIGNATURE_BYTES) {
    result = DM_SOURCE_AUTH_ERR_SIZE;
    goto cleanup;
  }

  memcpy(&request_snapshot, request, sizeof(request_snapshot));
  memcpy(x_snapshot, canonical_x, sizeof(x_snapshot));
  memcpy(signature_snapshot, signature, sizeof(signature_snapshot));

  result = dm_source_auth_validate_request(&request_snapshot);
  if (result != DM_SOURCE_AUTH_OK) {
    goto cleanup;
  }
  if (presented_key_epoch == 0u ||
      presented_key_epoch != request_snapshot.expected_key_epoch) {
    result = DM_SOURCE_AUTH_ERR_KEY_EPOCH;
    goto cleanup;
  }
  result = dm_source_auth_validate_canonical_x(x_snapshot);
  if (result != DM_SOURCE_AUTH_OK) {
    goto cleanup;
  }

  if (dm_wire_statement_decode(&statement, x_snapshot, sizeof(x_snapshot)) != DM_WIRE_OK) {
    result = DM_SOURCE_AUTH_ERR_CANONICAL_X;
    goto cleanup;
  }
  if (memcmp(statement.source_suite, request_snapshot.expected_source_suite,
             DM_WIRE_SOURCE_SUITE_BYTES) != 0 ||
      statement.relation_id_bytes != DM_WIRE_RELATION_ID_BYTES ||
      memcmp(statement.relation_id, request_snapshot.expected_relation_id,
             DM_WIRE_RELATION_ID_BYTES) != 0 ||
      !dm_source_auth_descriptor_equal(&statement.descriptor,
                                       &request_snapshot.expected_descriptor)) {
    result = DM_SOURCE_AUTH_ERR_REQUEST;
    goto cleanup;
  }
  if (memcmp(statement.context, request_snapshot.expected_context,
             DM_SOURCE_AUTH_CONTEXT_BYTES) != 0) {
    result = DM_SOURCE_AUTH_ERR_CONTEXT;
    goto cleanup;
  }
  if (memcmp(statement.U, request_snapshot.expected_U, DM_SOURCE_AUTH_U_BYTES) != 0) {
    result = DM_SOURCE_AUTH_ERR_U;
    goto cleanup;
  }
  if (dm_wire_statement_encode(round_trip, sizeof(round_trip), &statement) != DM_WIRE_OK ||
      memcmp(round_trip, x_snapshot, sizeof(round_trip)) != 0) {
    result = DM_SOURCE_AUTH_ERR_CANONICAL_X;
    goto cleanup;
  }

  dm_source_auth_make_message(message, presented_key_epoch, x_snapshot);
  crypto_status = blind_source_auth_mldsa87_v1_verify(
      &accepted, request_snapshot.trusted_public_key,
      sizeof(request_snapshot.trusted_public_key), message, sizeof(message),
      signature_snapshot, sizeof(signature_snapshot));
  if (crypto_status != BLIND_SOURCE_AUTH_MLDSA87_V1_OK) {
    result = DM_SOURCE_AUTH_ERR_CRYPTO;
    goto cleanup;
  }
  if (!accepted) {
    result = DM_SOURCE_AUTH_ERR_SIGNATURE;
    goto cleanup;
  }

  memcpy(verified->canonical_x, x_snapshot, sizeof(verified->canonical_x));
  verified->key_epoch = presented_key_epoch;
  verified->authentication = DM_SOURCE_AUTH_AUTHENTICATED;
  result = DM_SOURCE_AUTH_OK;

cleanup:
  if (result != DM_SOURCE_AUTH_OK) {
    dm_source_auth_verified_clear(verified);
  }
  dm_source_auth_wipe(&statement, sizeof(statement));
  dm_source_auth_wipe(round_trip, sizeof(round_trip));
  dm_source_auth_wipe(message, sizeof(message));
  dm_source_auth_wipe(signature_snapshot, sizeof(signature_snapshot));
  dm_source_auth_wipe(x_snapshot, sizeof(x_snapshot));
  dm_source_auth_wipe(&request_snapshot, sizeof(request_snapshot));
  return result;
}
