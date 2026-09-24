/* SPDX-License-Identifier: MIT */

#include "direct_mask_wire.h"

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <stdlib.h>
#endif

static const uint8_t dm_source_suite[DM_WIRE_SOURCE_SUITE_BYTES] = {
    'S', 'B', 'A', '1', '-', 'S', 'R', 'C', '-', 'C', 'M', 'T', '-', 'v', '1', 0,
};
static const uint8_t dm_relation_id[] = "direct-mask-relation-v1";

static int checked_add_size(size_t lhs, size_t rhs, size_t* output) {
  if (output == NULL || rhs > SIZE_MAX - lhs) {
    return 0;
  }
  *output = lhs + rhs;
  return 1;
}

static uint32_t load_u32_le(const uint8_t* input) {
  return (uint32_t)input[0] | ((uint32_t)input[1] << 8) | ((uint32_t)input[2] << 16) |
         ((uint32_t)input[3] << 24);
}

static void store_u32_le(uint8_t* output, uint32_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8);
  output[2] = (uint8_t)(value >> 16);
  output[3] = (uint8_t)(value >> 24);
}

static int bytes_equal(const uint8_t* lhs, const uint8_t* rhs, size_t length) {
  return length == 0 || (lhs != NULL && rhs != NULL && memcmp(lhs, rhs, length) == 0);
}

static int ranges_overlap(const void* lhs, size_t lhs_bytes, const void* rhs, size_t rhs_bytes) {
  if (lhs == NULL || rhs == NULL || lhs_bytes == 0 || rhs_bytes == 0) {
    return 0;
  }
  const uintptr_t lhs_address = (uintptr_t)lhs;
  const uintptr_t rhs_address = (uintptr_t)rhs;
  if (lhs_bytes > UINTPTR_MAX || rhs_bytes > UINTPTR_MAX) {
    return 1;
  }
  if (lhs_address <= rhs_address) {
    return rhs_address - lhs_address < (uintptr_t)lhs_bytes;
  }
  return lhs_address - rhs_address < (uintptr_t)rhs_bytes;
}

static int proof_aliases_input(const dm_wire_proof_t* proof, const void* input,
                               size_t input_bytes) {
  if (proof == NULL || input == NULL || input_bytes == 0) {
    return 0;
  }
  if (ranges_overlap(input, input_bytes, proof, sizeof(*proof))) {
    return 1;
  }
  if (!proof->primitive.initialized) {
    return 0;
  }
  return ranges_overlap(input, input_bytes, proof->primitive.statement,
                        proof->primitive.statement_len) ||
         ranges_overlap(input, input_bytes, proof->primitive.m1, proof->primitive.m1_len) ||
         ranges_overlap(input, input_bytes, proof->primitive.m2, proof->primitive.m2_len) ||
         ranges_overlap(input, input_bytes, proof->primitive.m3, proof->primitive.m3_len) ||
         ranges_overlap(input, input_bytes, proof->primitive.m4, proof->primitive.m4_len);
}

static int proof_aliases_statement(const dm_wire_proof_t* proof,
                                   const dm_wire_statement_t* statement) {
  if (proof == NULL || statement == NULL) {
    return 0;
  }
  /* Check the statement object itself against every proof-owned range before dereferencing it.
   * A caller can place the borrowed descriptor inside m1 while its member pointers escape to
   * ordinary storage; checking only the outer proof struct and then reading the freed object is
   * a use-after-free during the destructive decode/prove preflight. */
  if (proof_aliases_input(proof, statement, sizeof(*statement))) {
    return 1;
  }
  return proof_aliases_input(proof, statement->relation_id, statement->relation_id_bytes) ||
         proof_aliases_input(proof, statement->context, DM_WIRE_CONTEXT_BYTES) ||
         proof_aliases_input(proof, statement->U, DM_WIRE_U_BYTES) ||
         proof_aliases_input(proof, statement->T, DM_WIRE_T_BYTES) ||
         proof_aliases_input(proof, statement->C, DM_WIRE_C_BYTES);
}

static int exact_proof_descriptor(const dmv_descriptor_t* descriptor) {
  return descriptor != NULL && descriptor->witness_bits == DMK_WITNESS_BITS &&
         descriptor->constraint_count == DMK_CONSTRAINTS && descriptor->degree == DMV_DEGREE;
}

static dmv_descriptor_t proof_descriptor_from_statement(const dm_wire_statement_t* statement) {
  dmv_descriptor_t descriptor;
  descriptor.witness_bits = statement->descriptor.witness_bits;
  descriptor.constraint_count = statement->descriptor.constraints;
  descriptor.degree = (uint8_t)statement->descriptor.degree;
  return descriptor;
}

static void instance_from_statement(const dm_wire_statement_t* statement, dmk_instance* instance) {
  memset(instance, 0, sizeof(*instance));
  memcpy(instance->source_suite, statement->source_suite, sizeof(instance->source_suite));
  memcpy(instance->context, statement->context, DM_WIRE_CONTEXT_BYTES);
  memcpy(instance->U, statement->U, DM_WIRE_U_BYTES);
  memcpy(instance->T, statement->T, DM_WIRE_T_BYTES);
  memcpy(instance->C, statement->C, DM_WIRE_C_BYTES);
}

const char* dm_wire_status_name(dm_wire_status_t status) {
  switch (status) {
    case DM_WIRE_OK:
      return "ok";
    case DM_WIRE_ERR_ARGUMENT:
      return "argument";
    case DM_WIRE_ERR_STATEMENT:
      return "statement";
    case DM_WIRE_ERR_DESCRIPTOR:
      return "descriptor";
    case DM_WIRE_ERR_SIZE:
      return "size";
    case DM_WIRE_ERR_ENCODING:
      return "encoding";
    case DM_WIRE_ERR_FRAME:
      return "frame";
    case DM_WIRE_ERR_CHALLENGE:
      return "challenge";
    case DM_WIRE_ERR_COMMITMENT:
      return "commitment";
    case DM_WIRE_ERR_RELATION:
      return "relation";
    case DM_WIRE_ERR_RETRY:
      return "retry";
    case DM_WIRE_ERR_ALLOCATION:
      return "allocation";
    case DM_WIRE_ERR_INPUT:
      return "input";
    case DM_WIRE_ERR_BACKEND:
      return "backend";
    default:
      return "unknown";
  }
}

static dm_wire_status_t validate_relation_descriptor(
    const dm_wire_relation_descriptor_t* descriptor) {
  if (descriptor == NULL) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  if (descriptor->field_bits != DMV_LAMBDA || descriptor->degree != DMV_DEGREE ||
      descriptor->tau != DMV_TAU || descriptor->w_grind != DMV_W_GRIND ||
      descriptor->short_challenge_bits != DMV_SHORT_CHALLENGE_BITS ||
      descriptor->open_budget != DMV_T_OPEN || descriptor->witness_bits != DMK_WITNESS_BITS ||
      descriptor->constraints != DMK_CONSTRAINTS || descriptor->padding_bits != 0 ||
      descriptor->mask_count != DMK_MASK_COUNT || descriptor->nonce_bits != 8u * DMV_NONCE_BYTES ||
      descriptor->challenge_mode != DMV_CHALLENGE_MODE) {
    return DM_WIRE_ERR_DESCRIPTOR;
  }
  return DM_WIRE_OK;
}

dm_wire_status_t dm_wire_statement_validate(const dm_wire_statement_t* statement) {
  if (statement == NULL || statement->relation_id == NULL || statement->context == NULL ||
      statement->U == NULL || statement->T == NULL || statement->C == NULL) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  if (!bytes_equal(statement->source_suite, dm_source_suite, sizeof(dm_source_suite)) ||
      statement->relation_id_bytes == 0 ||
      statement->relation_id_bytes > DM_WIRE_RELATION_ID_MAX ||
      statement->relation_id_bytes != sizeof(dm_relation_id) - 1u ||
      !bytes_equal(statement->relation_id, dm_relation_id, sizeof(dm_relation_id) - 1u)) {
    return DM_WIRE_ERR_STATEMENT;
  }
  dm_wire_status_t status = validate_relation_descriptor(&statement->descriptor);
  if (status != DM_WIRE_OK) {
    return status;
  }
  dmk_instance instance;
  instance_from_statement(statement, &instance);
  return dmk_instance_validate(&instance) == DMK_OK ? DM_WIRE_OK : DM_WIRE_ERR_STATEMENT;
}

dm_wire_status_t dm_wire_statement_size(const dm_wire_statement_t* statement,
                                        size_t* size_out) {
  if (size_out == NULL) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  dm_wire_status_t status = dm_wire_statement_validate(statement);
  if (status != DM_WIRE_OK) {
    return status;
  }
  if (!checked_add_size(DM_WIRE_X_FIXED_BYTES, statement->relation_id_bytes, size_out)) {
    return DM_WIRE_ERR_SIZE;
  }
  return *size_out > UINT32_MAX ? DM_WIRE_ERR_SIZE : DM_WIRE_OK;
}

dm_wire_status_t dm_wire_statement_encode(uint8_t* output, size_t output_bytes,
                                          const dm_wire_statement_t* statement) {
  size_t statement_bytes = 0;
  dm_wire_status_t status = dm_wire_statement_size(statement, &statement_bytes);
  if (status != DM_WIRE_OK) {
    return status;
  }
  if (output == NULL || output_bytes != statement_bytes) {
    return DM_WIRE_ERR_SIZE;
  }
  size_t offset = 0;
  memcpy(output + offset, statement->source_suite, DM_WIRE_SOURCE_SUITE_BYTES);
  offset += DM_WIRE_SOURCE_SUITE_BYTES;
  store_u32_le(output + offset, statement->relation_id_bytes);
  offset += 4u;
  memcpy(output + offset, statement->relation_id, statement->relation_id_bytes);
  offset += statement->relation_id_bytes;
  memcpy(output + offset, statement->context, DM_WIRE_CONTEXT_BYTES);
  offset += DM_WIRE_CONTEXT_BYTES;
  memcpy(output + offset, statement->U, DM_WIRE_U_BYTES);
  offset += DM_WIRE_U_BYTES;
  memcpy(output + offset, statement->T, DM_WIRE_T_BYTES);
  offset += DM_WIRE_T_BYTES;
  memcpy(output + offset, statement->C, DM_WIRE_C_BYTES);
  offset += DM_WIRE_C_BYTES;
  const uint32_t words[DM_WIRE_DESCRIPTOR_WORDS] = {
      statement->descriptor.field_bits,
      statement->descriptor.degree,
      statement->descriptor.tau,
      statement->descriptor.w_grind,
      statement->descriptor.short_challenge_bits,
      statement->descriptor.open_budget,
      statement->descriptor.witness_bits,
      statement->descriptor.constraints,
      statement->descriptor.padding_bits,
      statement->descriptor.mask_count,
      statement->descriptor.nonce_bits,
      statement->descriptor.challenge_mode,
  };
  for (size_t index = 0; index != DM_WIRE_DESCRIPTOR_WORDS; ++index) {
    store_u32_le(output + offset, words[index]);
    offset += 4u;
  }
  return offset == statement_bytes ? DM_WIRE_OK : DM_WIRE_ERR_ENCODING;
}

dm_wire_status_t dm_wire_statement_decode(dm_wire_statement_t* statement,
                                          const uint8_t* input, size_t input_bytes) {
  if (statement == NULL || input == NULL) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  if (input_bytes != DM_WIRE_STATEMENT_BYTES) {
    return DM_WIRE_ERR_SIZE;
  }
  memset(statement, 0, sizeof(*statement));
  size_t offset = 0;
  memcpy(statement->source_suite, input + offset, DM_WIRE_SOURCE_SUITE_BYTES);
  offset += DM_WIRE_SOURCE_SUITE_BYTES;
  statement->relation_id_bytes = load_u32_le(input + offset);
  offset += 4u;
  if (statement->relation_id_bytes != DM_WIRE_RELATION_ID_BYTES) {
    return DM_WIRE_ERR_STATEMENT;
  }
  statement->relation_id = input + offset;
  offset += DM_WIRE_RELATION_ID_BYTES;
  statement->context = input + offset;
  offset += DM_WIRE_CONTEXT_BYTES;
  statement->U = input + offset;
  offset += DM_WIRE_U_BYTES;
  statement->T = input + offset;
  offset += DM_WIRE_T_BYTES;
  statement->C = input + offset;
  offset += DM_WIRE_C_BYTES;
  uint32_t words[DM_WIRE_DESCRIPTOR_WORDS];
  for (size_t index = 0; index != DM_WIRE_DESCRIPTOR_WORDS; ++index) {
    words[index] = load_u32_le(input + offset);
    offset += 4u;
  }
  if (offset != input_bytes) {
    memset(statement, 0, sizeof(*statement));
    return DM_WIRE_ERR_ENCODING;
  }
  statement->descriptor.field_bits = words[0];
  statement->descriptor.degree = words[1];
  statement->descriptor.tau = words[2];
  statement->descriptor.w_grind = words[3];
  statement->descriptor.short_challenge_bits = words[4];
  statement->descriptor.open_budget = words[5];
  statement->descriptor.witness_bits = words[6];
  statement->descriptor.constraints = words[7];
  statement->descriptor.padding_bits = words[8];
  statement->descriptor.mask_count = words[9];
  statement->descriptor.nonce_bits = words[10];
  statement->descriptor.challenge_mode = words[11];
  const dm_wire_status_t status = dm_wire_statement_validate(statement);
  if (status != DM_WIRE_OK) {
    memset(statement, 0, sizeof(*statement));
  }
  return status;
}

static dm_wire_status_t proof_matches_statement(const dm_wire_proof_t* proof,
                                                const dm_wire_statement_t* statement,
                                                size_t* statement_bytes_out) {
  if (proof == NULL || statement == NULL || !proof->primitive.initialized) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  dm_wire_status_t status = dm_wire_statement_size(statement, statement_bytes_out);
  if (status != DM_WIRE_OK) {
    return status;
  }
  if (!exact_proof_descriptor(&proof->primitive.descriptor) ||
      proof->primitive.statement == NULL ||
      proof->primitive.statement_len != *statement_bytes_out) {
    return DM_WIRE_ERR_SIZE;
  }
  uint8_t* expected = (uint8_t*)malloc(*statement_bytes_out);
  if (expected == NULL) {
    return DM_WIRE_ERR_ALLOCATION;
  }
  status = dm_wire_statement_encode(expected, *statement_bytes_out, statement);
  const int matches = status == DM_WIRE_OK &&
                      memcmp(expected, proof->primitive.statement, *statement_bytes_out) == 0;
  memset(expected, 0, *statement_bytes_out);
  free(expected);
  if (!matches) {
    return status == DM_WIRE_OK ? DM_WIRE_ERR_STATEMENT : status;
  }
  if (proof->primitive.m1 == NULL || proof->primitive.m2 == NULL ||
      proof->primitive.m3 == NULL || proof->primitive.m4 == NULL ||
      proof->primitive.m1_len != DM_WIRE_M1_BYTES ||
      proof->primitive.m2_len != DM_WIRE_M2_BYTES ||
      proof->primitive.m3_len != DM_WIRE_M3_BYTES ||
      proof->primitive.m4_len != DM_WIRE_M4_BYTES) {
    return DM_WIRE_ERR_SIZE;
  }
  uint8_t recomputed_nu[DM_WIRE_NU_BYTES];
  if (dmv_derive_leaf_uhash(recomputed_nu, proof->primitive.m1) != DMV_OK ||
      !bytes_equal(recomputed_nu, proof->primitive.nu, DM_WIRE_NU_BYTES)) {
    memset(recomputed_nu, 0, sizeof(recomputed_nu));
    return DM_WIRE_ERR_COMMITMENT;
  }
  memset(recomputed_nu, 0, sizeof(recomputed_nu));
  return DM_WIRE_OK;
}

static dm_wire_status_t map_dmv_status(int status);

dm_wire_status_t dm_wire_proof_size(const dm_wire_proof_t* proof,
                                    const dm_wire_statement_t* statement,
                                    size_t* size_out) {
  if (size_out == NULL) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  size_t statement_bytes = 0;
  dm_wire_status_t status = proof_matches_statement(proof, statement, &statement_bytes);
  if (status != DM_WIRE_OK) {
    return status;
  }
  size_t expected_total = DM_WIRE_HEADER_BYTES;
  const size_t parts[] = {statement_bytes, DM_WIRE_NU_BYTES,
                          DM_WIRE_NONCE_COUNT * DM_WIRE_NONCE_BYTES, DM_WIRE_M1_BYTES,
                          DM_WIRE_M2_BYTES, DM_WIRE_M3_BYTES, DM_WIRE_M4_BYTES};
  for (size_t index = 0; index != sizeof(parts) / sizeof(parts[0]); ++index) {
    if (!checked_add_size(expected_total, parts[index], &expected_total)) {
      return DM_WIRE_ERR_SIZE;
    }
  }
  size_t primitive_total = 0;
  const int primitive_status = dmv_proof_wire_size(&proof->primitive, &primitive_total);
  if (primitive_status != DMV_OK) {
    return map_dmv_status(primitive_status);
  }
  if (primitive_total != expected_total || primitive_total > DM_WIRE_MAX_BYTES) {
    return DM_WIRE_ERR_SIZE;
  }
  *size_out = primitive_total;
  return DM_WIRE_OK;
}

dm_wire_status_t dm_wire_encode(const dm_wire_proof_t* proof,
                                const dm_wire_statement_t* statement,
                                uint8_t* output, size_t output_bytes,
                                size_t* written_out) {
  size_t total = 0;
  dm_wire_status_t status = dm_wire_proof_size(proof, statement, &total);
  if (status != DM_WIRE_OK) {
    return status;
  }
  if (output == NULL || output_bytes != total) {
    return DM_WIRE_ERR_SIZE;
  }
  size_t primitive_written = 0;
  const int primitive_status =
      dmv_proof_encode(&proof->primitive, output, output_bytes, &primitive_written);
  if (primitive_status != DMV_OK) {
    return map_dmv_status(primitive_status);
  }
  if (primitive_written != total) {
    return DM_WIRE_ERR_ENCODING;
  }
  if (written_out != NULL) {
    *written_out = primitive_written;
  }
  return DM_WIRE_OK;
}

static dm_wire_status_t header_matches(const uint8_t* input, size_t input_bytes,
                                       size_t statement_bytes) {
  if (input == NULL || input_bytes < DM_WIRE_HEADER_BYTES || input_bytes > DM_WIRE_MAX_BYTES) {
    return DM_WIRE_ERR_FRAME;
  }
  if (memcmp(input, "DMV3", 4u) != 0 || input[4] != DM_WIRE_VERSION || input[5] != 0 ||
      input[6] != 0 || input[7] != 0 || input[17] != 0 || input[18] != 0 || input[19] != 0) {
    return DM_WIRE_ERR_ENCODING;
  }
  if (load_u32_le(input + 8u) != DMK_WITNESS_BITS ||
      load_u32_le(input + 12u) != DMK_CONSTRAINTS || input[16] != DMV_DEGREE ||
      load_u32_le(input + 20u) != statement_bytes || load_u32_le(input + 24u) != DM_WIRE_M1_BYTES ||
      load_u32_le(input + 28u) != DM_WIRE_M2_BYTES ||
      load_u32_le(input + 32u) != DM_WIRE_M3_BYTES ||
      load_u32_le(input + 36u) != DM_WIRE_M4_BYTES) {
    return DM_WIRE_ERR_SIZE;
  }
  return DM_WIRE_OK;
}

dm_wire_status_t dm_wire_decode(dm_wire_proof_t* proof,
                                const dm_wire_statement_t* expected_statement,
                                const uint8_t* input, size_t input_bytes) {
  if (proof == NULL) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  /* Decode is destructive at the outer boundary as well as in the primitive.  Reject an input
   * or expected statement that aliases the destination before clearing it; otherwise clearing a
   * live proof could free bytes that the caller asked us to decode or authenticate. */
  const int input_alias = proof_aliases_input(proof, input, input_bytes);
  const int statement_alias = proof_aliases_statement(proof, expected_statement);
  dm_wire_proof_clear(proof);
  if (expected_statement == NULL || input == NULL || input_alias || statement_alias) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  size_t statement_bytes = 0;
  dm_wire_status_t status = dm_wire_statement_size(expected_statement, &statement_bytes);
  if (status != DM_WIRE_OK) {
    return status;
  }
  status = header_matches(input, input_bytes, statement_bytes);
  if (status != DM_WIRE_OK) {
    return status;
  }
  size_t total = DM_WIRE_HEADER_BYTES;
  const size_t parts[] = {statement_bytes, DM_WIRE_NU_BYTES,
                          DM_WIRE_NONCE_COUNT * DM_WIRE_NONCE_BYTES, DM_WIRE_M1_BYTES,
                          DM_WIRE_M2_BYTES, DM_WIRE_M3_BYTES, DM_WIRE_M4_BYTES};
  for (size_t index = 0; index != sizeof(parts) / sizeof(parts[0]); ++index) {
    if (!checked_add_size(total, parts[index], &total)) {
      return DM_WIRE_ERR_SIZE;
    }
  }
  if (total != input_bytes || total > DM_WIRE_MAX_BYTES) {
    return DM_WIRE_ERR_FRAME;
  }

  dmv_proof_t decoded;
  memset(&decoded, 0, sizeof(decoded));
  const int primitive_status = dmv_proof_decode(&decoded, input, input_bytes);
  if (primitive_status != DMV_OK) {
    return primitive_status == DMV_ERR_ALLOCATION ? DM_WIRE_ERR_ALLOCATION
                                                  : DM_WIRE_ERR_ENCODING;
  }
  uint8_t* expected = (uint8_t*)malloc(statement_bytes);
  if (expected == NULL) {
    dmv_proof_clear(&decoded);
    return DM_WIRE_ERR_ALLOCATION;
  }
  status = dm_wire_statement_encode(expected, statement_bytes, expected_statement);
  const int canonical = status == DM_WIRE_OK && decoded.statement_len == statement_bytes &&
                        bytes_equal(expected, decoded.statement, statement_bytes);
  memset(expected, 0, statement_bytes);
  free(expected);
  if (!canonical || !exact_proof_descriptor(&decoded.descriptor) ||
      decoded.m1_len != DM_WIRE_M1_BYTES || decoded.m2_len != DM_WIRE_M2_BYTES ||
      decoded.m3_len != DM_WIRE_M3_BYTES || decoded.m4_len != DM_WIRE_M4_BYTES) {
    dmv_proof_clear(&decoded);
    return canonical ? DM_WIRE_ERR_SIZE : DM_WIRE_ERR_STATEMENT;
  }
  uint8_t recomputed_nu[DM_WIRE_NU_BYTES];
  const int nu_status = dmv_derive_leaf_uhash(recomputed_nu, decoded.m1);
  const int nu_matches = nu_status == DMV_OK &&
                         bytes_equal(recomputed_nu, decoded.nu, DM_WIRE_NU_BYTES);
  memset(recomputed_nu, 0, sizeof(recomputed_nu));
  if (!nu_matches) {
    dmv_proof_clear(&decoded);
    return DM_WIRE_ERR_COMMITMENT;
  }
  if (proof->primitive.initialized) {
    dm_wire_proof_clear(proof);
  } else {
    memset(proof, 0, sizeof(*proof));
  }
  proof->primitive = decoded;
  return DM_WIRE_OK;
}

void dm_wire_proof_clear(dm_wire_proof_t* proof) {
  if (proof == NULL) {
    return;
  }
  dmv_proof_clear(&proof->primitive);
}

void dm_wire_proof_init(dm_wire_proof_t* proof) {
  if (proof != NULL) {
    memset(proof, 0, sizeof(*proof));
  }
}

static void erase_bytes(void* pointer, size_t length) {
  if (pointer == NULL) {
    return;
  }
  volatile uint8_t* bytes = (volatile uint8_t*)pointer;
  while (length-- != 0) {
    *bytes++ = 0;
  }
}

int dm_wire_os_random_bytes(void* context, uint8_t* output, size_t length) {
  (void)context;
  if (output == NULL || length == 0) {
    return -1;
  }
#if defined(_WIN32)
  if (length > ULONG_MAX ||
      BCryptGenRandom(NULL, output, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
    return -1;
  }
  return 0;
#elif defined(__linux__)
  size_t offset = 0;
  while (offset != length) {
    const ssize_t received = getrandom(output + offset, length - offset, 0);
    if (received < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (received == 0) {
      return -1;
    }
    offset += (size_t)received;
  }
  return 0;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  arc4random_buf(output, length);
  return 0;
#else
  return -1;
#endif
}

static int exact_kernel_counts(const dmk_counts* counts) {
  return counts != NULL && counts->witness_bits == DMK_WITNESS_BITS &&
         counts->constraints == DMK_CONSTRAINTS && counts->bitness == DMK_WITNESS_BITS &&
         counts->inverse == 26192u && counts->equality == 7424u && counts->tag == 768u &&
         counts->range == 12800u && counts->sboxes == 13096u && counts->aes_blocks == 58u &&
         counts->key_schedules == 2u;
}

static dm_wire_status_t map_dmv_status(int status) {
  switch (status) {
    case DMV_OK:
      return DM_WIRE_OK;
    case DMV_ERR_ARGUMENT:
      return DM_WIRE_ERR_ARGUMENT;
    case DMV_ERR_DESCRIPTOR:
      return DM_WIRE_ERR_DESCRIPTOR;
    case DMV_ERR_SIZE:
      return DM_WIRE_ERR_SIZE;
    case DMV_ERR_CHALLENGE:
      return DM_WIRE_ERR_CHALLENGE;
    case DMV_ERR_OPENING:
      return DM_WIRE_ERR_COMMITMENT;
    case DMV_ERR_COMMITMENT:
      return DM_WIRE_ERR_COMMITMENT;
    case DMV_ERR_ALLOCATION:
      return DM_WIRE_ERR_ALLOCATION;
    case DMV_ERR_RELATION:
      return DM_WIRE_ERR_RELATION;
    case DMV_ERR_RETRY:
      return DM_WIRE_ERR_RETRY;
    case DMV_ERR_ENCODING:
      return DM_WIRE_ERR_ENCODING;
    default:
      return DM_WIRE_ERR_BACKEND;
  }
}

typedef struct dm_wire_relation_context_t {
  dmk_instance instance;
} dm_wire_relation_context_t;

static int unpack_witness_bits(const uint8_t* packed, size_t packed_bytes, uint8_t* bits,
                               size_t bit_count) {
  if (packed == NULL || bits == NULL || packed_bytes != (bit_count + 7u) / 8u) {
    return 0;
  }
  for (size_t bit = 0; bit != bit_count; ++bit) {
    bits[bit] = (uint8_t)((packed[bit / 8u] >> (bit % 8u)) & 1u);
  }
  if ((bit_count & 7u) != 0 &&
      (packed[packed_bytes - 1u] & (uint8_t)~((1u << (bit_count & 7u)) - 1u)) != 0) {
    return 0;
  }
  return 1;
}

static int pack_witness_bits(const uint8_t* bits, size_t bit_count, uint8_t* packed,
                             size_t packed_bytes) {
  if (bits == NULL || packed == NULL || packed_bytes != (bit_count + 7u) / 8u) {
    return 0;
  }
  memset(packed, 0, packed_bytes);
  for (size_t bit = 0; bit != bit_count; ++bit) {
    if (bits[bit] > 1u) {
      return 0;
    }
    packed[bit / 8u] |= (uint8_t)(bits[bit] << (bit % 8u));
  }
  return 1;
}

static int dm_wire_relation_prove(
    void* context, const dmv_descriptor_t* descriptor, const bf256_t* base_rows,
    uint32_t bit_rows, const uint8_t* witness, size_t witness_bytes,
    dmv_coefficient_sink_fn coefficient_sink, void* sink_context) {
  dm_wire_relation_context_t* relation = (dm_wire_relation_context_t*)context;
  if (relation == NULL || !exact_proof_descriptor(descriptor) || base_rows == NULL ||
      bit_rows != DM_WIRE_BIT_ROWS || witness == NULL ||
      witness_bytes != DM_WIRE_WITNESS_BYTES || coefficient_sink == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  uint8_t* witness_bits = (uint8_t*)malloc(DMK_WITNESS_BITS);
  if (witness_bits == NULL) {
    return DMV_ERR_ALLOCATION;
  }
  const int unpacked =
      unpack_witness_bits(witness, witness_bytes, witness_bits, DMK_WITNESS_BITS);
  dmk_counts counts;
  memset(&counts, 0, sizeof(counts));
  int status = DMK_ERR_WITNESS;
  if (unpacked) {
    status = dmk_prover_coefficients(
        &relation->instance, witness_bits, DMK_WITNESS_BITS, base_rows, DMK_WITNESS_BITS,
        (dmk_coefficient_sink)coefficient_sink, sink_context, &counts);
  }
  erase_bytes(witness_bits, DMK_WITNESS_BITS);
  free(witness_bits);
  return status == DMK_OK && exact_kernel_counts(&counts) ? DMV_OK : DMV_ERR_RELATION;
}

static int dm_wire_relation_verify(
    void* context, const dmv_descriptor_t* descriptor, const bf256_t* q_prime_rows,
    uint32_t bit_rows, const bf256_t* mask_term, const uint8_t gamma2[DMV_FS2_BYTES],
    const bf256_t* delta, const bf256_t* expected_b) {
  dm_wire_relation_context_t* relation = (dm_wire_relation_context_t*)context;
  if (relation == NULL || !exact_proof_descriptor(descriptor) || q_prime_rows == NULL ||
      bit_rows != DM_WIRE_BIT_ROWS || mask_term == NULL || gamma2 == NULL || delta == NULL ||
      expected_b == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  dmk_eval_hash evaluation;
  memset(&evaluation, 0, sizeof(evaluation));
  if (dmk_eval_hash_init(&evaluation, gamma2, DMK_CONSTRAINTS) != DMK_OK) {
    return DMV_ERR_RELATION;
  }
  dmk_counts counts;
  memset(&counts, 0, sizeof(counts));
  const int kernel_status =
      dmk_verifier_evaluate(&relation->instance, q_prime_rows, DMK_WITNESS_BITS, delta,
                            dmk_eval_hash_update, &evaluation, &counts);
  if (kernel_status != DMK_OK || !exact_kernel_counts(&counts)) {
    dmk_eval_hash_clear(&evaluation);
    return DMV_ERR_RELATION;
  }
  const int evaluation_status = dmk_eval_hash_finish(&evaluation, mask_term, expected_b);
  dmk_eval_hash_clear(&evaluation);
  return evaluation_status == DMK_OK ? DMV_OK : DMV_ERR_RELATION;
}

static const dmv_relation_callbacks_t dm_wire_relation_callbacks = {
    dm_wire_relation_prove,
    dm_wire_relation_verify,
};

dm_wire_status_t dm_wire_prove_kernel(
    dm_wire_proof_t* proof, const dm_wire_statement_t* statement,
    const uint8_t* witness_bits, size_t witness_count,
    dmv_random_bytes_fn random_bytes, void* random_context,
    uint32_t max_final_retries) {
  if (proof == NULL) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  const int input_alias = proof_aliases_statement(proof, statement) ||
                          proof_aliases_input(proof, witness_bits, witness_count);
  dm_wire_proof_clear(proof);
  if (statement == NULL || witness_bits == NULL || witness_count != DMK_WITNESS_BITS ||
      random_bytes == NULL || input_alias) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  if (max_final_retries == 0 || max_final_retries > DMV_MAX_FINAL_RETRIES) {
    return DM_WIRE_ERR_RETRY;
  }
  dm_wire_status_t status = dm_wire_statement_validate(statement);
  if (status != DM_WIRE_OK) {
    return status;
  }
  size_t statement_bytes = 0;
  status = dm_wire_statement_size(statement, &statement_bytes);
  if (status != DM_WIRE_OK) {
    return status;
  }
  uint8_t* canonical_statement = (uint8_t*)malloc(statement_bytes);
  if (canonical_statement == NULL) {
    return DM_WIRE_ERR_ALLOCATION;
  }
  uint8_t* packed_witness = (uint8_t*)malloc(DM_WIRE_WITNESS_BYTES);
  if (packed_witness == NULL) {
    erase_bytes(canonical_statement, statement_bytes);
    free(canonical_statement);
    return DM_WIRE_ERR_ALLOCATION;
  }
  status = dm_wire_statement_encode(canonical_statement, statement_bytes, statement);
  if (status == DM_WIRE_OK &&
      !pack_witness_bits(witness_bits, witness_count, packed_witness, DM_WIRE_WITNESS_BYTES)) {
    status = DM_WIRE_ERR_RELATION;
  }
  if (status != DM_WIRE_OK) {
    erase_bytes(canonical_statement, statement_bytes);
    erase_bytes(packed_witness, DM_WIRE_WITNESS_BYTES);
    free(canonical_statement);
    free(packed_witness);
    return status;
  }

  dmv_descriptor_t descriptor = proof_descriptor_from_statement(statement);
  dm_wire_relation_context_t relation;
  memset(&relation, 0, sizeof(relation));
  instance_from_statement(statement, &relation.instance);
  const int primitive_status =
      dmv_prove(&proof->primitive, &descriptor, canonical_statement, statement_bytes,
                packed_witness, DM_WIRE_WITNESS_BYTES, random_bytes, random_context,
                &dm_wire_relation_callbacks, &relation, max_final_retries);
  erase_bytes(canonical_statement, statement_bytes);
  erase_bytes(packed_witness, DM_WIRE_WITNESS_BYTES);
  free(canonical_statement);
  free(packed_witness);
  return map_dmv_status(primitive_status);
}

dm_wire_status_t dm_wire_prove_kernel_os(
    dm_wire_proof_t* proof, const dm_wire_statement_t* statement,
    const uint8_t* witness_bits, size_t witness_count, uint32_t max_final_retries) {
  return dm_wire_prove_kernel(proof, statement, witness_bits, witness_count,
                              dm_wire_os_random_bytes, NULL, max_final_retries);
}

dm_wire_status_t dm_wire_verify_kernel(const dm_wire_proof_t* proof,
                                       const dm_wire_statement_t* expected_statement) {
  if (proof == NULL || expected_statement == NULL || !proof->primitive.initialized) {
    return DM_WIRE_ERR_ARGUMENT;
  }
  dm_wire_status_t status = dm_wire_statement_validate(expected_statement);
  if (status != DM_WIRE_OK) {
    return status;
  }
  size_t statement_bytes = 0;
  status = proof_matches_statement(proof, expected_statement, &statement_bytes);
  if (status != DM_WIRE_OK) {
    return status;
  }
  uint8_t* canonical_statement = (uint8_t*)malloc(statement_bytes);
  if (canonical_statement == NULL) {
    return DM_WIRE_ERR_ALLOCATION;
  }
  status = dm_wire_statement_encode(canonical_statement, statement_bytes, expected_statement);
  if (status != DM_WIRE_OK) {
    erase_bytes(canonical_statement, statement_bytes);
    free(canonical_statement);
    return status;
  }
  const dmv_descriptor_t descriptor = proof_descriptor_from_statement(expected_statement);
  dm_wire_relation_context_t relation;
  memset(&relation, 0, sizeof(relation));
  instance_from_statement(expected_statement, &relation.instance);
  const int primitive_status =
      dmv_verify(&proof->primitive, &descriptor, canonical_statement, statement_bytes,
                 &dm_wire_relation_callbacks, &relation);
  erase_bytes(canonical_statement, statement_bytes);
  free(canonical_statement);
  return map_dmv_status(primitive_status);
}
