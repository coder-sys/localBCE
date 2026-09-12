/* SPDX-License-Identifier: MIT */

#include "direct_mask_source_proof.h"

#include "aes.h"
#include "direct_mask_native.h"
#include "direct_mask_vole.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#if DMN_PACKED_WITNESS_BYTES != 15631u || DMN_PACKED_WITNESS_BITS != 125048u
#error "the source producer requires the pinned 15631-byte/125048-bit witness"
#endif

static const uint8_t dm_source_proof_source_suite[DM_WIRE_SOURCE_SUITE_BYTES] = {
    'S', 'B', 'A', '1', '-', 'S', 'R', 'C', '-', 'C', 'M', 'T', '-', 'v', '1', 0,
};

static const uint8_t dm_source_proof_relation_id[] = "direct-mask-relation-v1";

static void dm_source_proof_wipe(void* pointer, size_t length) {
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
static int dm_source_proof_spans_overlap(const void* lhs, size_t lhs_bytes,
                                          const void* rhs, size_t rhs_bytes) {
  const uintptr_t lhs_start = (uintptr_t)lhs;
  const uintptr_t rhs_start = (uintptr_t)rhs;
  if (lhs == NULL || rhs == NULL || lhs_bytes == 0u || rhs_bytes == 0u) {
    return 0;
  }
  if ((uintmax_t)lhs_bytes > (uintmax_t)UINTPTR_MAX - (uintmax_t)lhs_start ||
      (uintmax_t)rhs_bytes > (uintmax_t)UINTPTR_MAX - (uintmax_t)rhs_start) {
    return 1;
  }
  return lhs_start < rhs_start + (uintptr_t)rhs_bytes &&
         rhs_start < lhs_start + (uintptr_t)lhs_bytes;
}

static size_t dm_source_proof_alias_bytes(size_t requested) {
  return requested == 0u ? 1u : requested;
}

static int dm_source_proof_output_alias(
    const dm_source_proof_output_t* output, const uint8_t* context,
    size_t context_bytes, const uint8_t* U, size_t U_bytes,
    const uint8_t* values_le, size_t values_le_bytes, const uint8_t* secret_key,
    size_t secret_key_bytes) {
  if (output == NULL) {
    return 0;
  }
  return dm_source_proof_spans_overlap(
             output, sizeof(*output), context,
             dm_source_proof_alias_bytes(context_bytes)) ||
         dm_source_proof_spans_overlap(
             output, sizeof(*output), U,
             dm_source_proof_alias_bytes(U_bytes)) ||
         dm_source_proof_spans_overlap(
             output, sizeof(*output), values_le,
             dm_source_proof_alias_bytes(values_le_bytes)) ||
         dm_source_proof_spans_overlap(
             output, sizeof(*output), secret_key,
             dm_source_proof_alias_bytes(secret_key_bytes));
}

static int dm_source_proof_input_alias(
    const uint8_t* context, size_t context_bytes, const uint8_t* U,
    size_t U_bytes, const uint8_t* values_le, size_t values_le_bytes,
    const uint8_t* secret_key, size_t secret_key_bytes) {
  const size_t context_alias_bytes = dm_source_proof_alias_bytes(context_bytes);
  const size_t U_alias_bytes = dm_source_proof_alias_bytes(U_bytes);
  const size_t values_alias_bytes = dm_source_proof_alias_bytes(values_le_bytes);
  const size_t key_alias_bytes = dm_source_proof_alias_bytes(secret_key_bytes);

  return dm_source_proof_spans_overlap(context, context_alias_bytes, U,
                                       U_alias_bytes) ||
         dm_source_proof_spans_overlap(context, context_alias_bytes, values_le,
                                       values_alias_bytes) ||
         dm_source_proof_spans_overlap(context, context_alias_bytes, secret_key,
                                       key_alias_bytes) ||
         dm_source_proof_spans_overlap(U, U_alias_bytes, values_le,
                                       values_alias_bytes) ||
         dm_source_proof_spans_overlap(U, U_alias_bytes, secret_key,
                                       key_alias_bytes) ||
         dm_source_proof_spans_overlap(values_le, values_alias_bytes, secret_key,
                                       key_alias_bytes);
}

static uint64_t dm_source_proof_load_u64_le(const uint8_t input[8]) {
  uint64_t value = 0u;
  for (size_t index = 0; index != 8u; ++index) {
    value |= (uint64_t)input[index] << (8u * index);
  }
  return value;
}

static int dm_source_proof_nonzero(const uint8_t* bytes, size_t length) {
  uint8_t accumulator = 0u;
  if (bytes == NULL) {
    return 0;
  }
  for (size_t index = 0; index != length; ++index) {
    accumulator |= bytes[index];
  }
  return accumulator != 0u;
}

static void dm_source_proof_set_descriptor(
    dm_wire_relation_descriptor_t* descriptor) {
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
  descriptor->challenge_mode = 1u;
}

static int dm_source_proof_make_instance(
    dmk_instance* instance, const uint8_t context[DM_SOURCE_PROOF_CONTEXT_BYTES],
    const uint8_t U[DM_SOURCE_PROOF_U_BYTES],
    const uint8_t values_le[DM_SOURCE_PROOF_VALUES_BYTES],
    const uint8_t root[DMN_ROOT_BYTES]) {
  uint8_t g0[DMN_G0_BYTES];
  uint8_t g1[DMN_G1_BYTES];
  uint8_t zero_iv[16];
  uint8_t iv_2pow127[16];
  bf768_t product;
  bf768_t z;
  bf256_t k;

  memset(instance, 0, sizeof(*instance));
  memset(g0, 0, sizeof(g0));
  memset(g1, 0, sizeof(g1));
  memset(zero_iv, 0, sizeof(zero_iv));
  memset(iv_2pow127, 0, sizeof(iv_2pow127));
  memset(&product, 0, sizeof(product));
  memset(&z, 0, sizeof(z));
  memset(&k, 0, sizeof(k));

  memcpy(instance->source_suite, dm_source_proof_source_suite,
         sizeof(instance->source_suite));
  memcpy(instance->context, context, sizeof(instance->context));
  memcpy(instance->U, U, sizeof(instance->U));

  iv_2pow127[15] = 0x80u;
  prg_4_lambda(root, zero_iv, 0, g0, 256);
  prg(g0, iv_2pow127, 0, g1, 256, sizeof(instance->C));

  bf768_load(&product, instance->U);
  bf256_load(&k, g0);
  bf768_mul_256_inplace(&product, &k);
  bf768_load(&z, g0 + DM_WIRE_FIELD_BYTES);
  bf768_add_inplace(&product, &z);
  bf768_store(instance->T, &product);

  for (size_t index = 0; index != sizeof(instance->C); ++index) {
    instance->C[index] = (uint8_t)(g1[index] ^ values_le[index]);
  }

  dm_source_proof_wipe(&k, sizeof(k));
  dm_source_proof_wipe(&z, sizeof(z));
  dm_source_proof_wipe(&product, sizeof(product));
  dm_source_proof_wipe(iv_2pow127, sizeof(iv_2pow127));
  dm_source_proof_wipe(zero_iv, sizeof(zero_iv));
  dm_source_proof_wipe(g1, sizeof(g1));
  dm_source_proof_wipe(g0, sizeof(g0));
  return DMN_OK;
}

static void dm_source_proof_make_statement(
    const dmk_instance* instance, dm_wire_statement_t* statement) {
  memset(statement, 0, sizeof(*statement));
  memcpy(statement->source_suite, instance->source_suite,
         DM_WIRE_SOURCE_SUITE_BYTES);
  statement->relation_id = dm_source_proof_relation_id;
  statement->relation_id_bytes = (uint32_t)(sizeof(dm_source_proof_relation_id) - 1u);
  statement->context = instance->context;
  statement->U = instance->U;
  statement->T = instance->T;
  statement->C = instance->C;
  dm_source_proof_set_descriptor(&statement->descriptor);
}

static int dm_source_proof_unpack_witness(const dmn_packed_witness* packed,
                                          uint8_t* witness_bits) {
  if (packed == NULL || witness_bits == NULL ||
      packed->byte_count != DMN_PACKED_WITNESS_BYTES ||
      packed->bit_count != DMN_PACKED_WITNESS_BITS) {
    return 0;
  }
  for (size_t bit = 0; bit != packed->bit_count; ++bit) {
    witness_bits[bit] =
        (uint8_t)((packed->bytes[bit / 8u] >> (bit % 8u)) & 1u);
  }
  return 1;
}

static dm_source_proof_status_t dm_source_proof_map_native(int status) {
  if (status == DMN_ERR_ALLOCATION) {
    return DM_SOURCE_PROOF_ERR_ALLOCATION;
  }
  if (status == DMN_ERR_RANGE) {
    return DM_SOURCE_PROOF_ERR_RANGE;
  }
  return DM_SOURCE_PROOF_ERR_WITNESS;
}

static dm_source_proof_status_t dm_source_proof_map_wire(
    dm_wire_status_t status) {
  switch (status) {
    case DM_WIRE_ERR_ALLOCATION:
      return DM_SOURCE_PROOF_ERR_ALLOCATION;
    case DM_WIRE_ERR_RETRY:
      return DM_SOURCE_PROOF_ERR_RETRY;
    case DM_WIRE_ERR_STATEMENT:
    case DM_WIRE_ERR_DESCRIPTOR:
      return DM_SOURCE_PROOF_ERR_STATEMENT;
    case DM_WIRE_ERR_ENCODING:
      return DM_SOURCE_PROOF_ERR_ENCODING;
    default:
      return DM_SOURCE_PROOF_ERR_PROOF;
  }
}

const char* dm_source_proof_status_name(dm_source_proof_status_t status) {
  switch (status) {
    case DM_SOURCE_PROOF_OK:
      return "ok";
    case DM_SOURCE_PROOF_ERR_ARGUMENT:
      return "argument";
    case DM_SOURCE_PROOF_ERR_SIZE:
      return "size";
    case DM_SOURCE_PROOF_ERR_INPUT_ALIAS:
      return "input-alias";
    case DM_SOURCE_PROOF_ERR_OUTPUT_ALIAS:
      return "output-alias";
    case DM_SOURCE_PROOF_ERR_KEY_EPOCH:
      return "key-epoch";
    case DM_SOURCE_PROOF_ERR_RETRY:
      return "retry";
    case DM_SOURCE_PROOF_ERR_RANGE:
      return "range";
    case DM_SOURCE_PROOF_ERR_CSPRNG:
      return "csprng";
    case DM_SOURCE_PROOF_ERR_WITNESS:
      return "witness";
    case DM_SOURCE_PROOF_ERR_STATEMENT:
      return "statement";
    case DM_SOURCE_PROOF_ERR_PROOF:
      return "proof";
    case DM_SOURCE_PROOF_ERR_ENCODING:
      return "encoding";
    case DM_SOURCE_PROOF_ERR_SIGNATURE:
      return "signature";
    case DM_SOURCE_PROOF_ERR_ALLOCATION:
      return "allocation";
    default:
      return "unknown";
  }
}

void dm_source_proof_output_clear(dm_source_proof_output_t* output) {
  if (output != NULL) {
    dm_source_proof_wipe(output, sizeof(*output));
  }
}

dm_source_proof_status_t dm_source_proof_generate(
    const uint8_t* context, size_t context_bytes, const uint8_t* U,
    size_t U_bytes, const uint8_t* values_le, size_t values_le_bytes,
    const uint8_t* secret_key, size_t secret_key_bytes, uint64_t key_epoch,
    uint32_t max_final_retries, dm_source_proof_output_t* output) {
  dmk_instance instance;
  dmn_packed_witness packed;
  dm_wire_statement_t statement;
  dm_wire_proof_t proof;
  uint8_t context_snapshot[DM_SOURCE_PROOF_CONTEXT_BYTES];
  uint8_t U_snapshot[DM_SOURCE_PROOF_U_BYTES];
  uint8_t values_snapshot[DM_SOURCE_PROOF_VALUES_BYTES];
  uint8_t secret_key_snapshot[DM_SOURCE_PROOF_SECRET_KEY_BYTES];
  uint8_t root[DMN_ROOT_BYTES];
  uint64_t values[DM_SOURCE_PROOF_VALUE_COUNT];
  uint8_t* witness_bits = NULL;
  size_t frame_bytes = 0u;
  size_t written = 0u;
  dm_wire_status_t wire_status;
  dm_source_auth_status_t auth_status;
  int native_status;
  dm_source_proof_status_t result = DM_SOURCE_PROOF_ERR_ARGUMENT;

  memset(&instance, 0, sizeof(instance));
  memset(&packed, 0, sizeof(packed));
  memset(&statement, 0, sizeof(statement));
  dm_wire_proof_init(&proof);
  memset(context_snapshot, 0, sizeof(context_snapshot));
  memset(U_snapshot, 0, sizeof(U_snapshot));
  memset(values_snapshot, 0, sizeof(values_snapshot));
  memset(secret_key_snapshot, 0, sizeof(secret_key_snapshot));
  memset(root, 0, sizeof(root));
  memset(values, 0, sizeof(values));

  /* These checks precede every destructive output operation. */
  if (output == NULL) {
    dm_wire_proof_clear(&proof);
    return DM_SOURCE_PROOF_ERR_ARGUMENT;
  }
  if (dm_source_proof_output_alias(output, context, context_bytes, U, U_bytes,
                                   values_le, values_le_bytes, secret_key,
                                   secret_key_bytes)) {
    dm_wire_proof_clear(&proof);
    return DM_SOURCE_PROOF_ERR_OUTPUT_ALIAS;
  }
  if (dm_source_proof_input_alias(context, context_bytes, U, U_bytes,
                                  values_le, values_le_bytes, secret_key,
                                  secret_key_bytes)) {
    dm_source_proof_output_clear(output);
    dm_wire_proof_clear(&proof);
    return DM_SOURCE_PROOF_ERR_INPUT_ALIAS;
  }

  dm_source_proof_output_clear(output);
  if (context == NULL || U == NULL || values_le == NULL || secret_key == NULL) {
    goto cleanup;
  }
  if (context_bytes != DM_SOURCE_PROOF_CONTEXT_BYTES ||
      U_bytes != DM_SOURCE_PROOF_U_BYTES ||
      values_le_bytes != DM_SOURCE_PROOF_VALUES_BYTES ||
      secret_key_bytes != DM_SOURCE_PROOF_SECRET_KEY_BYTES) {
    result = DM_SOURCE_PROOF_ERR_SIZE;
    goto cleanup;
  }
  if (key_epoch == 0u) {
    result = DM_SOURCE_PROOF_ERR_KEY_EPOCH;
    goto cleanup;
  }
  if (max_final_retries == 0u || max_final_retries > DMV_MAX_FINAL_RETRIES) {
    result = DM_SOURCE_PROOF_ERR_RETRY;
    goto cleanup;
  }

  /* Snapshot each fixed caller span exactly once before any random/proof work. */
  memcpy(context_snapshot, context, sizeof(context_snapshot));
  memcpy(U_snapshot, U, sizeof(U_snapshot));
  memcpy(values_snapshot, values_le, sizeof(values_snapshot));
  memcpy(secret_key_snapshot, secret_key, sizeof(secret_key_snapshot));

  if (!dm_source_proof_nonzero(U_snapshot, sizeof(U_snapshot))) {
    result = DM_SOURCE_PROOF_ERR_STATEMENT;
    goto cleanup;
  }
  for (size_t index = 0; index != DM_SOURCE_PROOF_VALUE_COUNT; ++index) {
    values[index] = dm_source_proof_load_u64_le(values_snapshot + 8u * index);
    if (values[index] < DMK_LOWER || values[index] > DMK_UPPER) {
      result = DM_SOURCE_PROOF_ERR_RANGE;
      goto cleanup;
    }
  }

  if (dm_wire_os_random_bytes(NULL, root, sizeof(root)) != 0) {
    result = DM_SOURCE_PROOF_ERR_CSPRNG;
    goto cleanup;
  }
  if (dm_source_proof_make_instance(&instance, context_snapshot, U_snapshot,
                                    values_snapshot, root) != DMN_OK) {
    result = DM_SOURCE_PROOF_ERR_STATEMENT;
    goto cleanup;
  }
  dm_source_proof_make_statement(&instance, &statement);

  wire_status = dm_wire_statement_encode(
      output->canonical_x, sizeof(output->canonical_x), &statement);
  if (wire_status != DM_WIRE_OK) {
    result = DM_SOURCE_PROOF_ERR_ENCODING;
    goto cleanup;
  }

  native_status = dmn_extend(&instance, root, &packed);
  if (native_status != DMN_OK || packed.byte_count != 15631u ||
      packed.bit_count != 125048u) {
    result = native_status == DMN_OK ? DM_SOURCE_PROOF_ERR_WITNESS
                                     : dm_source_proof_map_native(native_status);
    goto cleanup;
  }
  witness_bits = (uint8_t*)calloc(DMN_PACKED_WITNESS_BITS, 1u);
  if (witness_bits == NULL) {
    result = DM_SOURCE_PROOF_ERR_ALLOCATION;
    goto cleanup;
  }
  if (!dm_source_proof_unpack_witness(&packed, witness_bits)) {
    result = DM_SOURCE_PROOF_ERR_WITNESS;
    goto cleanup;
  }

  wire_status = dm_wire_prove_kernel_os(
      &proof, &statement, witness_bits, DMK_WITNESS_BITS, max_final_retries);
  if (wire_status != DM_WIRE_OK) {
    result = dm_source_proof_map_wire(wire_status);
    goto cleanup;
  }
  wire_status = dm_wire_proof_size(&proof, &statement, &frame_bytes);
  if (wire_status != DM_WIRE_OK || frame_bytes != DM_SOURCE_PROOF_FRAME_BYTES) {
    result = wire_status == DM_WIRE_OK ? DM_SOURCE_PROOF_ERR_SIZE
                                       : dm_source_proof_map_wire(wire_status);
    goto cleanup;
  }
  wire_status = dm_wire_encode(&proof, &statement, output->frame,
                               sizeof(output->frame), &written);
  if (wire_status != DM_WIRE_OK || written != DM_SOURCE_PROOF_FRAME_BYTES) {
    result = wire_status == DM_WIRE_OK ? DM_SOURCE_PROOF_ERR_ENCODING
                                       : dm_source_proof_map_wire(wire_status);
    goto cleanup;
  }

  auth_status = dm_source_auth_sign(
      output->signature, sizeof(output->signature), secret_key_snapshot,
      sizeof(secret_key_snapshot), key_epoch, output->canonical_x,
      sizeof(output->canonical_x));
  if (auth_status != DM_SOURCE_AUTH_OK) {
    result = auth_status == DM_SOURCE_AUTH_ERR_CSPRNG
                 ? DM_SOURCE_PROOF_ERR_CSPRNG
                 : DM_SOURCE_PROOF_ERR_SIGNATURE;
    goto cleanup;
  }
  output->key_epoch = key_epoch;
  result = DM_SOURCE_PROOF_OK;

cleanup:
  dm_wire_proof_clear(&proof);
  if (witness_bits != NULL) {
    dm_source_proof_wipe(witness_bits, DMN_PACKED_WITNESS_BITS);
    free(witness_bits);
  }
  dmn_clear(&packed);
  dm_source_proof_wipe(&statement, sizeof(statement));
  dm_source_proof_wipe(&instance, sizeof(instance));
  dm_source_proof_wipe(values, sizeof(values));
  dm_source_proof_wipe(root, sizeof(root));
  dm_source_proof_wipe(secret_key_snapshot, sizeof(secret_key_snapshot));
  dm_source_proof_wipe(values_snapshot, sizeof(values_snapshot));
  dm_source_proof_wipe(U_snapshot, sizeof(U_snapshot));
  dm_source_proof_wipe(context_snapshot, sizeof(context_snapshot));
  if (result != DM_SOURCE_PROOF_OK) {
    dm_source_proof_output_clear(output);
  }
  return result;
}
