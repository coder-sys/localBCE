/* SPDX-License-Identifier: MIT */

#include "direct_mask_vole.h"

#include "../direct_mask_circuit/dmc_range_constraints.h"
#include "../direct_mask_kernel/direct_mask_algebra.h"
#include "../direct_mask_kernel/direct_mask_kernel.h"
#include "direct_mask_circuit.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int g_passed;
static unsigned int g_failed;

static void fill_pattern(uint8_t* bytes, size_t length, uint8_t seed);
static bool field_is_zero(const bf256_t* value);

static void probe_secure_clear(void* pointer, size_t length) {
  volatile uint8_t* cursor = (volatile uint8_t*)pointer;
  while (length != 0) {
    *cursor++ = 0;
    --length;
  }
}

static void probe_clear_free(void* pointer, size_t length) {
  if (pointer != NULL) {
    probe_secure_clear(pointer, length);
    free(pointer);
  }
}

typedef struct actual_relation_context_t {
  dmk_instance instance;
  dmk_counts prover_counts;
  dmk_counts verifier_counts;
  unsigned int prover_calls;
  unsigned int verifier_calls;
} actual_relation_context_t;

typedef struct coefficient_bridge_t {
  dmv_coefficient_sink_fn sink;
  void* sink_context;
} coefficient_bridge_t;

static int bridge_coefficient_sink(void* context, uint32_t row,
                                  const bf256_t coefficients[4]) {
  coefficient_bridge_t* bridge = (coefficient_bridge_t*)context;
  if (bridge == NULL || bridge->sink == NULL || coefficients == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  return bridge->sink(bridge->sink_context, row, coefficients);
}

static int actual_relation_prove(void* context, const dmv_descriptor_t* descriptor,
                                 const bf256_t* base_rows, uint32_t bit_rows,
                                 const uint8_t* witness, size_t witness_bytes,
                                 dmv_coefficient_sink_fn coefficient_sink,
                                 void* sink_context) {
  actual_relation_context_t* relation = (actual_relation_context_t*)context;
  if (relation == NULL || descriptor == NULL || base_rows == NULL || witness == NULL ||
      coefficient_sink == NULL || descriptor->witness_bits != DMK_WITNESS_BITS ||
      descriptor->constraint_count != DMK_CONSTRAINTS ||
      bit_rows != DMK_WITNESS_BITS + DMV_MASK_COUNT * DMV_LAMBDA ||
      witness_bytes != DMK_WITNESS_BITS / 8u) {
    return DMV_ERR_ARGUMENT;
  }
  uint8_t* unpacked = (uint8_t*)calloc(DMK_WITNESS_BITS, 1);
  if (unpacked == NULL) {
    return DMV_ERR_ALLOCATION;
  }
  for (size_t bit = 0; bit != DMK_WITNESS_BITS; ++bit) {
    unpacked[bit] = (uint8_t)((witness[bit / 8u] >> (bit % 8u)) & 1u);
  }
  coefficient_bridge_t bridge = {coefficient_sink, sink_context};
  const int status = dmk_prover_coefficients(
      &relation->instance, unpacked, DMK_WITNESS_BITS, base_rows, DMK_WITNESS_BITS,
      bridge_coefficient_sink, &bridge, &relation->prover_counts);
  ++relation->prover_calls;
  probe_clear_free(unpacked, DMK_WITNESS_BITS);
  return status == DMK_OK ? DMV_OK : DMV_ERR_RELATION;
}

static int actual_relation_verify(void* context, const dmv_descriptor_t* descriptor,
                                  const bf256_t* q_prime_rows, uint32_t bit_rows,
                                  const bf256_t* mask_term,
                                  const uint8_t gamma2[DMV_FS2_BYTES],
                                  const bf256_t* delta, const bf256_t* expected_b) {
  actual_relation_context_t* relation = (actual_relation_context_t*)context;
  if (relation == NULL || descriptor == NULL || q_prime_rows == NULL || mask_term == NULL ||
      gamma2 == NULL || delta == NULL || expected_b == NULL ||
      descriptor->witness_bits != DMK_WITNESS_BITS ||
      descriptor->constraint_count != DMK_CONSTRAINTS ||
      bit_rows != DMK_WITNESS_BITS + DMV_MASK_COUNT * DMV_LAMBDA) {
    return DMV_ERR_ARGUMENT;
  }
  dmk_eval_hash hash;
  if (dmk_eval_hash_init(&hash, gamma2, DMK_CONSTRAINTS) != DMK_OK) {
    return DMV_ERR_RELATION;
  }
  const int evaluation_status = dmk_verifier_evaluate(
      &relation->instance, q_prime_rows, DMK_WITNESS_BITS, delta, dmk_eval_hash_update, &hash,
      &relation->verifier_counts);
  ++relation->verifier_calls;
  if (evaluation_status != DMK_OK) {
    dmk_eval_hash_clear(&hash);
    return DMV_ERR_RELATION;
  }
  const int finish_status = dmk_eval_hash_finish(&hash, mask_term, expected_b);
  dmk_eval_hash_clear(&hash);
  if (finish_status != DMK_OK) {
    return DMV_ERR_RELATION;
  }
  return DMV_OK;
}

static void set_packed_bit(uint8_t* packed, size_t bit, uint8_t value) {
  if (value != 0) {
    packed[bit / 8u] |= (uint8_t)(1u << (bit % 8u));
  } else {
    packed[bit / 8u] &= (uint8_t)~(uint8_t)(1u << (bit % 8u));
  }
}

static void copy_bytes_to_packed_bits(uint8_t* packed, size_t base, const uint8_t* bytes,
                                      size_t byte_count) {
  for (size_t byte = 0; byte != byte_count; ++byte) {
    for (unsigned int bit = 0; bit != 8u; ++bit) {
      set_packed_bit(packed, base + 8u * byte + bit, (uint8_t)((bytes[byte] >> bit) & 1u));
    }
  }
}

static uint64_t load_u64_le(const uint8_t bytes[8]) {
  uint64_t value = 0;
  for (unsigned int byte = 0; byte != 8u; ++byte) {
    value |= (uint64_t)bytes[byte] << (8u * byte);
  }
  return value;
}

static int materialize_source_fixture(dmk_instance* instance, uint8_t* packed_witness,
                                       size_t packed_witness_bytes) {
  if (instance == NULL || packed_witness == NULL ||
      packed_witness_bytes != DMK_WITNESS_BITS / 8u) {
    return DMV_ERR_ARGUMENT;
  }
  const uint8_t source_root[DMK_R_BITS / 8u] = {
      0x03u, 0x0au, 0x11u, 0x18u, 0x1fu, 0x26u, 0x2du, 0x34u,
      0x3bu, 0x42u, 0x49u, 0x50u, 0x57u, 0x5eu, 0x65u, 0x6cu,
      0x73u, 0x7au, 0x81u, 0x88u, 0x8fu, 0x96u, 0x9du, 0xa4u,
      0xabu, 0xb2u, 0xb9u, 0xc0u, 0xc7u, 0xceu, 0xd5u, 0xdcu};
  uint64_t values[DMC_VALUE_COUNT];
  for (unsigned int i = 0; i != DMC_VALUE_COUNT; ++i) {
    values[i] = (i & 1u) == 0 ? DMK_LOWER : DMK_UPPER;
  }
  dmc_public_instance_t request;
  dmc_public_instance_t public_instance;
  memset(&request, 0, sizeof(request));
  memset(&public_instance, 0, sizeof(public_instance));
  request.version = DMC_VERSION;
  memcpy(request.suite_id, DMC_SUITE_ID, DMC_SUITE_ID_BYTES);
  request.lower = DMC_LOWER;
  request.upper = DMC_UPPER;
  for (unsigned int i = 0; i != DMC_CONTEXT_BYTES; ++i) {
    request.context[i] = (uint8_t)(i + 1u);
  }
  for (unsigned int i = 0; i != DMC_U_BYTES; ++i) {
    request.U[i] = (uint8_t)(i * 11u + 5u);
  }
  if (dmc_source_prepare(&request, values, source_root, &public_instance) != DMC_OK) {
    return DMV_ERR_RELATION;
  }
  dmc_native_aes_witness_t trace;
  memset(&trace, 0, sizeof(trace));
  if (dmc_generate_native_aes_witness(source_root, &trace) != DMC_OK ||
      trace.inverse_bit_count != DMK_G0_BASE - DMK_INVERSE_BASE ||
      trace.inverse_bits == NULL || trace.sbox_count != DMK_SBOX_COUNT) {
    dmc_native_aes_witness_clear(&trace);
    return DMV_ERR_RELATION;
  }
  memset(instance, 0, sizeof(*instance));
  memcpy(instance->source_suite, public_instance.suite_id, sizeof(instance->source_suite));
  memcpy(instance->context, public_instance.context, sizeof(instance->context));
  memcpy(instance->U, public_instance.U, sizeof(instance->U));
  memcpy(instance->T, public_instance.T, sizeof(instance->T));
  memcpy(instance->C, public_instance.C, sizeof(instance->C));
  memset(packed_witness, 0, packed_witness_bytes);
  copy_bytes_to_packed_bits(packed_witness, 0, source_root, sizeof(source_root));
  for (size_t bit = 0; bit != trace.inverse_bit_count; ++bit) {
    set_packed_bit(packed_witness, DMK_INVERSE_BASE + bit, trace.inverse_bits[bit]);
  }
  copy_bytes_to_packed_bits(packed_witness, DMK_G0_BASE, trace.g0, DMC_G0_BYTES);
  uint8_t range_aux[DMC_RANGE_AUX_BITS];
  memset(range_aux, 0, sizeof(range_aux));
  uint32_t out_of_range = 0;
  for (unsigned int i = 0; i != DMC_VALUE_COUNT; ++i) {
     uint8_t value_bytes[8] = {0};
    for (unsigned int byte = 0; byte != sizeof(value_bytes); ++byte) {
      value_bytes[byte] = (uint8_t)(public_instance.C[8u * i + byte] ^
                                     trace.g1[8u * i + byte]);
    }
    values[i] = load_u64_le(value_bytes);
    copy_bytes_to_packed_bits(packed_witness, DMK_VALUE_BASE + 64u * i, value_bytes,
                              sizeof(value_bytes));
     probe_secure_clear(value_bytes, sizeof(value_bytes));
  }
  if (dmc_range_materialize_aux(values, range_aux, &out_of_range) != DMC_RANGE_OK ||
      out_of_range != 0u) {
    probe_secure_clear(range_aux, sizeof(range_aux));
    dmc_native_aes_witness_clear(&trace);
    return DMV_ERR_RELATION;
  }
  for (size_t bit = 0; bit != sizeof(range_aux); ++bit) {
    set_packed_bit(packed_witness, DMK_RANGE_BASE + bit, range_aux[bit]);
  }
  printf("SOURCE_FIXTURE ell=%u constraints=%u inverse_bits=%zu g0_bits=%u value_bits=%u "
         "range_aux_bits=%u sboxes=%zu\n",
         DMK_WITNESS_BITS, DMK_CONSTRAINTS, trace.inverse_bit_count, DMK_VALUE_BASE - DMK_G0_BASE,
         DMK_RANGE_BASE - DMK_VALUE_BASE, DMK_WITNESS_BITS - DMK_RANGE_BASE,
         trace.sbox_count);
  probe_secure_clear(range_aux, sizeof(range_aux));
  dmc_native_aes_witness_clear(&trace);
  return DMV_OK;
}

typedef struct probe_rng_t {
  unsigned int nonce_calls;
  uint8_t final_seed;
  bool duplicate_final;
  bool use_forced_final;
  uint8_t forced_final[DMV_NONCE_BYTES];
} probe_rng_t;

static int probe_random_bytes(void* context, uint8_t* out, size_t length) {
  probe_rng_t* rng = (probe_rng_t*)context;
  if (rng == NULL || out == NULL || (length != 16u && length != 32u && length != DMV_NONCE_BYTES)) {
    return -1;
  }
  uint8_t seed = 0;
  if (length == 32u) {
    seed = 0x11u;
  } else if (length == 16u) {
    seed = 0x22u;
  } else {
    const unsigned int nonce_call = rng->nonce_calls++;
    if (nonce_call == 0u) {
      seed = 0x33u;
    } else if (nonce_call == 1u) {
      seed = 0x44u;
    } else if (rng->use_forced_final) {
      memcpy(out, rng->forced_final, length);
      return 0;
    } else if (rng->duplicate_final) {
      seed = 0x33u;
    } else {
      seed = (uint8_t)(rng->final_seed + (uint8_t)(nonce_call - 2u));
    }
  }
  fill_pattern(out, length, seed);
  if (length == DMV_NONCE_BYTES && rng->nonce_calls > 2u && !rng->duplicate_final &&
      !rng->use_forced_final) {
    const uint32_t index = rng->nonce_calls - 3u;
    out[0] = (uint8_t)index;
    out[1] = (uint8_t)(index >> 8);
    out[2] = (uint8_t)(index >> 16);
    out[3] = (uint8_t)(index >> 24);
  }
  return 0;
}

static void check_result(const char* name, bool condition) {
  if (condition) {
    ++g_passed;
    printf("CHECK_PASS %s\n", name);
  } else {
    ++g_failed;
    printf("CHECK_FAIL %s\n", name);
  }
}

static bool proof_is_zeroed(const dmv_proof_t* proof) {
  if (proof == NULL) {
    return false;
  }
  dmv_proof_t zero;
  memset(&zero, 0, sizeof(zero));
  return memcmp(proof, &zero, sizeof(zero)) == 0;
}

static void print_hex(const uint8_t* bytes, size_t length) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i != length; ++i) {
    putchar(digits[bytes[i] >> 4]);
    putchar(digits[bytes[i] & 0x0fu]);
  }
}

static void fill_pattern(uint8_t* bytes, size_t length, uint8_t seed) {
  for (size_t i = 0; i != length; ++i) {
    bytes[i] = (uint8_t)(seed + (uint8_t)(i * 29u) + (uint8_t)(i >> 3));
  }
}

static bool bytes_are_zero(const uint8_t* bytes, size_t length) {
  uint8_t accumulator = 0;
  for (size_t i = 0; i != length; ++i) {
    accumulator |= bytes[i];
  }
  return accumulator == 0;
}

static bool field_equal(const bf256_t* lhs, const bf256_t* rhs) {
  uint8_t lhs_bytes[DMV_LAMBDA_BYTES];
  uint8_t rhs_bytes[DMV_LAMBDA_BYTES];
  bf256_store(lhs_bytes, lhs);
  bf256_store(rhs_bytes, rhs);
  return memcmp(lhs_bytes, rhs_bytes, sizeof(lhs_bytes)) == 0;
}

static bool field_is_zero(const bf256_t* value) {
  uint8_t bytes[DMV_LAMBDA_BYTES];
  bf256_store(bytes, value);
  return bytes_are_zero(bytes, sizeof(bytes));
}

static unsigned int challenge_index(const uint8_t raw[DMV_CHALLENGE_BYTES], unsigned int tree) {
  const unsigned int width = tree < DMV_TAU1 ? DMV_TREE_K : DMV_TREE_K - 1u;
  const unsigned int offset = tree < DMV_TAU1
                                  ? tree * DMV_TREE_K
                                  : DMV_TAU1 * DMV_TREE_K + (tree - DMV_TAU1) * (DMV_TREE_K - 1u);
  unsigned int value = 0;
  for (unsigned int bit = 0; bit != width; ++bit) {
    value |= ptr_get_bit(raw, offset + bit) << bit;
  }
  return value;
}

static bool find_correction_bit(const uint8_t raw[DMV_CHALLENGE_BYTES], unsigned int* tree_out,
                                unsigned int* level_out) {
  for (unsigned int tree = 1; tree != DMV_TAU; ++tree) {
    const unsigned int index = challenge_index(raw, tree);
    const unsigned int depth = tree < DMV_TAU1 ? DMV_TREE_K : DMV_TREE_K - 1u;
    for (unsigned int level = 0; level != depth; ++level) {
      if (((index >> level) & 1u) != 0) {
        *tree_out = tree;
        *level_out = level;
        return true;
      }
    }
  }
  return false;
}

static bool find_opening(const dmv_commitment_t* commitment, uint8_t raw[DMV_CHALLENGE_BYTES],
                         uint8_t* opening, unsigned int* attempts_out) {
  for (unsigned int attempt = 0; attempt != (1u << 20); ++attempt) {
    memset(raw, 0, DMV_CHALLENGE_BYTES);
    raw[0] = (uint8_t)attempt;
    raw[1] = (uint8_t)(attempt >> 8);
    raw[2] = (uint8_t)(attempt >> 16);
    raw[3] = (uint8_t)(attempt >> 24);
    unsigned int correction_tree = 0;
    unsigned int correction_level = 0;
    const bool has_correction_bit =
        find_correction_bit(raw, &correction_tree, &correction_level);
    (void)correction_tree;
    (void)correction_level;
    if (!has_correction_bit) {
      continue;
    }
    if (dmv_open(commitment, raw, opening, dmv_opening_bytes()) == DMV_OK) {
      *attempts_out = attempt + 1u;
      return true;
    }
  }
  *attempts_out = 1u << 20;
  return false;
}

int main(void) {
  const dmv_descriptor_t descriptor = {256u, 3u, DMV_DEGREE};
  const uint32_t expected_rows = 256u + DMV_MASK_COUNT * DMV_LAMBDA;
  const size_t expected_row_bytes = expected_rows / 8u;
  uint8_t root[DMV_LAMBDA_BYTES];
  uint8_t iv[16];
  fill_pattern(root, sizeof(root), 0x31u);
  fill_pattern(iv, sizeof(iv), 0x7bu);

  printf("DIRECT_MASK_PROBE_BEGIN\n");
  printf("PARAMETERS lambda=%u tau=%u w_grind=%u challenge_bits=%u T_open=%u rows=%u row_bytes=%zu\n",
         DMV_LAMBDA, DMV_TAU, DMV_W_GRIND, DMV_CHALLENGE_BITS, DMV_T_OPEN, expected_rows,
         expected_row_bytes);

  uint32_t actual_rows = 0;
  size_t actual_row_bytes = 0;
  check_result("descriptor_valid", dmv_descriptor_validate(&descriptor) == DMV_OK);
  check_result("descriptor_rows", dmv_descriptor_bit_rows(&descriptor, &actual_rows) == DMV_OK &&
                                  actual_rows == expected_rows);
  check_result("row_bytes", dmv_row_bytes(actual_rows, &actual_row_bytes) == DMV_OK &&
                              actual_row_bytes == expected_row_bytes);
  check_result("correction_size", dmv_correction_bytes(&descriptor) == (DMV_TAU - 1u) * expected_row_bytes);
  check_result("m1_size", dmv_m1_bytes(&descriptor) == 16u + DMV_BAVC_COMMITMENT_BYTES +
                                      (DMV_TAU - 1u) * expected_row_bytes);
  check_result("m2_size", dmv_m2_bytes(&descriptor) == 8u * DMV_LAMBDA_BYTES +
                                  descriptor.witness_bits / 8u);
  check_result("m3_size", dmv_m3_bytes() == 3u * DMV_LAMBDA_BYTES);
  check_result("m4_size", dmv_m4_bytes() == dmv_opening_bytes());

  dmv_descriptor_t bad_descriptor = descriptor;
  bad_descriptor.degree = DMV_DEGREE - 1u;
  dmv_commitment_t bad_commitment;
  memset(&bad_commitment, 0, sizeof(bad_commitment));
  check_result("bad_degree_rejected", dmv_descriptor_validate(&bad_descriptor) == DMV_ERR_DESCRIPTOR &&
                                         dmv_commit(&bad_commitment, &bad_descriptor, root, iv) ==
                                             DMV_ERR_DESCRIPTOR);
  dmv_commit_clear(&bad_commitment);

  dmv_commitment_t commitment;
  memset(&commitment, 0, sizeof(commitment));
  const int commit_status = dmv_commit(&commitment, &descriptor, root, iv);
  check_result("commit", commit_status == DMV_OK);
  if (commit_status != DMV_OK) {
    printf("DIRECT_MASK_PROBE_COUNTS passed=%u failed=%u\n", g_passed, g_failed);
    printf("DIRECT_MASK_PROBE_STATUS=FAIL\n");
    probe_secure_clear(root, sizeof(root));
    probe_secure_clear(iv, sizeof(iv));
    return 1;
  }
  check_result("commit_initialized", dmv_bavc_commitment(&commitment) != NULL &&
                                        dmv_u_bits(&commitment) != NULL &&
                                        dmv_corrections(&commitment) != NULL &&
                                        dmv_v_rows(&commitment) != NULL);

  uint8_t* opening = calloc(1, dmv_opening_bytes());
  uint8_t* opening_tampered = calloc(1, dmv_opening_bytes());
  uint8_t* corrections_tampered = calloc(1, dmv_correction_bytes(&descriptor));
  bf256_t* q_rows = calloc(actual_rows, sizeof(*q_rows));
  bf256_t* q_rows_tampered = calloc(actual_rows, sizeof(*q_rows_tampered));
  uint8_t reconstructed_commitment[DMV_BAVC_COMMITMENT_BYTES];
  bf256_t delta;
  uint8_t raw_challenge[DMV_CHALLENGE_BYTES];
  if (opening == NULL || opening_tampered == NULL || corrections_tampered == NULL ||
      q_rows == NULL || q_rows_tampered == NULL) {
    printf("CHECK_FAIL allocation\n");
    dmv_commit_clear(&commitment);
    probe_clear_free(opening, dmv_opening_bytes());
    probe_clear_free(opening_tampered, dmv_opening_bytes());
    probe_clear_free(corrections_tampered, dmv_correction_bytes(&descriptor));
    probe_clear_free(q_rows, (size_t)actual_rows * sizeof(*q_rows));
    probe_clear_free(q_rows_tampered, (size_t)actual_rows * sizeof(*q_rows_tampered));
    probe_secure_clear(root, sizeof(root));
    probe_secure_clear(iv, sizeof(iv));
    return 1;
  }

  unsigned int open_attempts = 0;
  const bool found_opening = find_opening(&commitment, raw_challenge, opening, &open_attempts);
  printf("OPENING_SEARCH attempts=%u raw_high_byte=%u\n", open_attempts,
         raw_challenge[DMV_CHALLENGE_BYTES - 1u]);
  check_result("opening_found_with_grinding", found_opening &&
                                               raw_challenge[DMV_CHALLENGE_BYTES - 1u] == 0);
  if (!found_opening) {
    dmv_commit_clear(&commitment);
    probe_clear_free(opening, dmv_opening_bytes());
    probe_clear_free(opening_tampered, dmv_opening_bytes());
    probe_clear_free(corrections_tampered, dmv_correction_bytes(&descriptor));
    probe_clear_free(q_rows, (size_t)actual_rows * sizeof(*q_rows));
    probe_clear_free(q_rows_tampered, (size_t)actual_rows * sizeof(*q_rows_tampered));
    probe_secure_clear(root, sizeof(root));
    probe_secure_clear(iv, sizeof(iv));
    printf("DIRECT_MASK_PROBE_COUNTS passed=%u failed=%u\n", g_passed, g_failed);
    printf("DIRECT_MASK_PROBE_STATUS=FAIL\n");
    return 1;
  }

  const int reconstruct_status = dmv_reconstruct(
      &descriptor, iv, raw_challenge, opening, dmv_opening_bytes(), dmv_corrections(&commitment),
      dmv_correction_bytes(&descriptor), reconstructed_commitment, q_rows, actual_rows, &delta);
  check_result("reconstruct", reconstruct_status == DMV_OK);
  check_result("reconstructed_commitment_matches",
               reconstruct_status == DMV_OK &&
                   memcmp(reconstructed_commitment, dmv_bavc_commitment(&commitment),
                          DMV_BAVC_COMMITMENT_BYTES) == 0);

  unsigned int identity_mismatches = 0;
  for (uint32_t row = 0; row != actual_rows; ++row) {
    bf256_t expected = dmv_v_rows(&commitment)[row];
    if (ptr_get_bit(dmv_u_bits(&commitment), row) != 0) {
      bf256_add_inplace(&expected, &delta);
    }
    if (!field_equal(&expected, &q_rows[row])) {
      ++identity_mismatches;
    }
  }
  printf("VOLE_IDENTITY rows=%u mismatches=%u delta_zero=%u\n", actual_rows, identity_mismatches,
         field_is_zero(&delta) ? 1u : 0u);
  check_result("q_equals_v_plus_delta_u_all_rows", reconstruct_status == DMV_OK &&
                                                       identity_mismatches == 0);

  uint8_t invalid_challenge[DMV_CHALLENGE_BYTES];
  memcpy(invalid_challenge, raw_challenge, sizeof(invalid_challenge));
  invalid_challenge[DMV_CHALLENGE_BYTES - 1u] = 1u;
  check_result("nonzero_grinding_bits_rejected",
               dmv_open(&commitment, invalid_challenge, opening, dmv_opening_bytes()) ==
                   DMV_ERR_CHALLENGE &&
                   dmv_reconstruct(&descriptor, iv, invalid_challenge, opening,
                                   dmv_opening_bytes(), dmv_corrections(&commitment),
                                   dmv_correction_bytes(&descriptor), reconstructed_commitment,
                                   q_rows, actual_rows, &delta) == DMV_ERR_CHALLENGE);
  check_result("opening_length_rejected",
               dmv_reconstruct(&descriptor, iv, raw_challenge, opening, dmv_opening_bytes() - 1u,
                               dmv_corrections(&commitment), dmv_correction_bytes(&descriptor),
                               reconstructed_commitment, q_rows, actual_rows, &delta) == DMV_ERR_SIZE);
  check_result("correction_length_rejected",
               dmv_reconstruct(&descriptor, iv, raw_challenge, opening, dmv_opening_bytes(),
                               dmv_corrections(&commitment), dmv_correction_bytes(&descriptor) - 1u,
                               reconstructed_commitment, q_rows, actual_rows, &delta) == DMV_ERR_SIZE);

  memcpy(opening_tampered, opening, dmv_opening_bytes());
  opening_tampered[0] ^= 1u;
  const int tampered_opening_status = dmv_reconstruct(
      &descriptor, iv, raw_challenge, opening_tampered, dmv_opening_bytes(),
      dmv_corrections(&commitment), dmv_correction_bytes(&descriptor), reconstructed_commitment,
      q_rows_tampered, actual_rows, &delta);
  check_result("tampered_opening_changes_commitment",
               tampered_opening_status == DMV_OK &&
                   memcmp(reconstructed_commitment, dmv_bavc_commitment(&commitment),
                          DMV_BAVC_COMMITMENT_BYTES) != 0);

  memcpy(corrections_tampered, dmv_corrections(&commitment),
         dmv_correction_bytes(&descriptor));
  unsigned int correction_tree = 0;
  unsigned int correction_level = 0;
  const bool found_correction_bit =
      find_correction_bit(raw_challenge, &correction_tree, &correction_level);
  if (found_correction_bit) {
    const size_t correction_offset = (size_t)(correction_tree - 1u) * actual_row_bytes;
    corrections_tampered[correction_offset] ^= 1u;
  }
  const int tampered_correction_status = dmv_reconstruct(
      &descriptor, iv, raw_challenge, opening, dmv_opening_bytes(), corrections_tampered,
      dmv_correction_bytes(&descriptor), reconstructed_commitment, q_rows_tampered, actual_rows,
      &delta);
  unsigned int correction_mismatches = 0;
  if (tampered_correction_status == DMV_OK && found_correction_bit) {
    for (uint32_t row = 0; row != actual_rows; ++row) {
      if (!field_equal(&q_rows[row], &q_rows_tampered[row])) {
        ++correction_mismatches;
      }
    }
  }
  printf("CORRECTION_TAMPER tree=%u level=%u mismatches=%u\n", correction_tree, correction_level,
         correction_mismatches);
  check_result("tampered_correction_changes_q", found_correction_bit &&
                                                     tampered_correction_status == DMV_OK &&
                                                     correction_mismatches != 0);

  uint8_t uhash[DMV_LEAF_UHASH_BYTES];
  uint8_t statement[37];
  uint8_t statement_changed[37];
  uint8_t nonce1[DMV_NONCE_BYTES];
  uint8_t nonce2[DMV_NONCE_BYTES];
  uint8_t nonce3[DMV_NONCE_BYTES];
  fill_pattern(statement, sizeof(statement), 0x11u);
  memcpy(statement_changed, statement, sizeof(statement));
  statement_changed[0] ^= 0x80u;
  fill_pattern(nonce1, sizeof(nonce1), 0x22u);
  fill_pattern(nonce2, sizeof(nonce2), 0x33u);
  fill_pattern(nonce3, sizeof(nonce3), 0x44u);
  check_result("leaf_uhash", dmv_derive_leaf_uhash(uhash, iv) == DMV_OK &&
                                !bytes_are_zero(uhash, sizeof(uhash)));
  fill_pattern(uhash, sizeof(uhash), 0xa2u);

  const size_t m1_len = dmv_m1_bytes(&descriptor);
  const size_t m2_len = dmv_m2_bytes(&descriptor);
  const size_t m3_len = dmv_m3_bytes();
  uint8_t* m1 = calloc(1, m1_len);
  uint8_t* m2 = calloc(1, m2_len);
  uint8_t* m3 = calloc(1, m3_len);
  uint8_t fs1[264];
  uint8_t fs1_changed[264];
  uint8_t fs2[104];
  uint8_t fs2_changed[104];
  uint8_t fs3[DMV_LAMBDA_BYTES];
  uint8_t fs3_changed[DMV_LAMBDA_BYTES];
  uint8_t gamma1[264];
  uint8_t gamma2[104];
  if (m1 == NULL || m2 == NULL || m3 == NULL) {
    printf("CHECK_FAIL transcript_allocation\n");
    ++g_failed;
  } else {
    fill_pattern(m1, m1_len, 0x51u);
    fill_pattern(m2, m2_len, 0x61u);
    fill_pattern(m3, m3_len, 0x71u);
    fill_pattern(gamma1, sizeof(gamma1), 0x81u);
    fill_pattern(gamma2, sizeof(gamma2), 0x91u);
    uint8_t nonce1_fs2_vector[sizeof(fs2)] = {0};
    uint8_t nonce1_fs3_vector[sizeof(fs3)] = {0};
    uint8_t nonce2_fs3_vector[sizeof(fs3)] = {0};
    check_result("fs1", dmv_fs1(fs1, sizeof(fs1), statement, sizeof(statement), uhash, m1, m1_len,
                                nonce1) == DMV_OK);
    check_result("fs1_wrong_output_size", dmv_fs1(fs1, sizeof(fs1) - 1u, statement,
                                                   sizeof(statement), uhash, m1, m1_len, nonce1) ==
                                                   DMV_ERR_SIZE);
    check_result("fs2", dmv_fs2(fs2, sizeof(fs2), statement, sizeof(statement), uhash, m1, m1_len,
                                 nonce1, gamma1, m2, m2_len, nonce2) == DMV_OK);
    check_result("fs3", dmv_fs3(fs3, statement, sizeof(statement), uhash, m1, m1_len, nonce1,
                                 gamma1, m2, m2_len, nonce2, gamma2, m3, m3_len, nonce3) == DMV_OK);
    printf("TRANSCRIPT_C_INPUT statement=%zu uhash=%u m1=%zu sigma1=%u gamma1=%u m2=%zu sigma2=%u "
           "gamma2=%u m3=%zu sigma3=%u\n",
           sizeof(statement), (unsigned)sizeof(uhash), m1_len, (unsigned)sizeof(nonce1),
           (unsigned)sizeof(gamma1), m2_len, (unsigned)sizeof(nonce2), (unsigned)sizeof(gamma2),
           m3_len, (unsigned)sizeof(nonce3));
    printf("TRANSCRIPT_C_KAT fs1=");
    print_hex(fs1, sizeof(fs1));
    printf(" fs2=");
    print_hex(fs2, sizeof(fs2));
    printf(" fs3=");
    print_hex(fs3, sizeof(fs3));
    putchar('\n');

    check_result("fs1_binds_full_statement",
                 dmv_fs1(fs1_changed, sizeof(fs1_changed), statement_changed, sizeof(statement_changed),
                         uhash, m1, m1_len, nonce1) == DMV_OK &&
                     memcmp(fs1, fs1_changed, sizeof(fs1)) != 0);
    check_result("fs2_binds_full_statement",
                 dmv_fs2(fs2_changed, sizeof(fs2_changed), statement_changed,
                         sizeof(statement_changed), uhash, m1, m1_len, nonce1, gamma1, m2, m2_len,
                         nonce2) ==
                         DMV_OK &&
                      memcmp(fs2, fs2_changed, sizeof(fs2)) != 0);
    check_result("fs3_binds_full_statement",
                 dmv_fs3(fs3_changed, statement_changed, sizeof(statement_changed), uhash, m1,
                         m1_len, nonce1, gamma1, m2, m2_len, nonce2, gamma2, m3, m3_len, nonce3) ==
                         DMV_OK &&
                      memcmp(fs3, fs3_changed, sizeof(fs3)) != 0);

    uint8_t nonce2_changed[DMV_NONCE_BYTES];
    memcpy(nonce2_changed, nonce2, sizeof(nonce2));
    nonce2_changed[0] ^= 1u;
    check_result("fs2_binds_nonce",
                 dmv_fs2(fs2_changed, sizeof(fs2_changed), statement, sizeof(statement), uhash, m1,
                         m1_len, nonce1, gamma1, m2, m2_len, nonce2_changed) == DMV_OK &&
                      memcmp(fs2, fs2_changed, sizeof(fs2)) != 0);

    uint8_t nonce1_changed[DMV_NONCE_BYTES];
    memcpy(nonce1_changed, nonce1, sizeof(nonce1));
    nonce1_changed[0] ^= 1u;
    check_result("fs2_binds_prior_nonce_with_fixed_gamma1",
                 dmv_fs2(fs2_changed, sizeof(fs2_changed), statement, sizeof(statement), uhash, m1,
                         m1_len, nonce1_changed, gamma1, m2, m2_len, nonce2) == DMV_OK &&
                     memcmp(fs2, fs2_changed, sizeof(fs2)) != 0);
    memcpy(nonce1_fs2_vector, fs2_changed, sizeof(nonce1_fs2_vector));
    check_result("fs3_binds_prior_nonce_with_fixed_challenges",
                 dmv_fs3(fs3_changed, statement, sizeof(statement), uhash, m1, m1_len,
                         nonce1_changed, gamma1, m2, m2_len, nonce2, gamma2, m3, m3_len, nonce3) ==
                         DMV_OK &&
                     memcmp(fs3, fs3_changed, sizeof(fs3)) != 0);
    memcpy(nonce1_fs3_vector, fs3_changed, sizeof(nonce1_fs3_vector));

    uint8_t nonce2_changed_for_fs3[DMV_NONCE_BYTES];
    memcpy(nonce2_changed_for_fs3, nonce2, sizeof(nonce2));
    nonce2_changed_for_fs3[0] ^= 1u;
    check_result("fs3_binds_prior_nonce2_with_fixed_gamma2",
                 dmv_fs3(fs3_changed, statement, sizeof(statement), uhash, m1, m1_len, nonce1,
                         gamma1, m2, m2_len, nonce2_changed_for_fs3, gamma2, m3, m3_len, nonce3) ==
                         DMV_OK &&
                     memcmp(fs3, fs3_changed, sizeof(fs3)) != 0);
    memcpy(nonce2_fs3_vector, fs3_changed, sizeof(nonce2_fs3_vector));
    printf("TRANSCRIPT_C_MUTATION nonce1_fs2=");
    print_hex(nonce1_fs2_vector, sizeof(nonce1_fs2_vector));
    printf(" nonce1_fs3=");
    print_hex(nonce1_fs3_vector, sizeof(nonce1_fs3_vector));
    printf(" nonce2_fs3=");
    print_hex(nonce2_fs3_vector, sizeof(nonce2_fs3_vector));
    putchar('\n');

    check_result("fs_domains_separated", memcmp(fs1, fs2, sizeof(fs2)) != 0);
  }

  printf("REMOVED_SYNTHETIC_CHECKS count=6 reason=obsolete_local_polynomial_and_hash_path_removed "
         "replacement=accepted_direct_mask_kernel_and_algebra_probes\n");

  dmk_instance source_instance;
  memset(&source_instance, 0, sizeof(source_instance));
  const size_t packed_witness_bytes = DMK_WITNESS_BITS / 8u;
  uint8_t* proof_witness = (uint8_t*)calloc(packed_witness_bytes, 1);
  const int source_fixture_status =
      proof_witness == NULL
          ? DMV_ERR_ALLOCATION
          : materialize_source_fixture(&source_instance, proof_witness, packed_witness_bytes);
  check_result("source_bound_witness_materialized", source_fixture_status == DMV_OK);
  actual_relation_context_t relation_context;
  memset(&relation_context, 0, sizeof(relation_context));
  relation_context.instance = source_instance;
  const dmv_relation_callbacks_t source_relation = {actual_relation_prove,
                                                    actual_relation_verify};
  const dmv_descriptor_t proof_descriptor = {DMK_WITNESS_BITS, DMK_CONSTRAINTS, DMV_DEGREE};
  uint8_t proof_statement[sizeof(source_instance)];
  memcpy(proof_statement, &source_instance, sizeof(proof_statement));
  dmv_proof_t generated_proof;
  memset(&generated_proof, 0, sizeof(generated_proof));
  bool proof_found = false;
  uint8_t invalid_final[DMV_NONCE_BYTES] = {0};
  bool invalid_final_found = false;
  if (source_fixture_status == DMV_OK) {
    probe_rng_t proof_rng = {0u, 0x60u, false};
    const int prove_status = dmv_prove(
        &generated_proof, &proof_descriptor, proof_statement, sizeof(proof_statement),
        proof_witness, packed_witness_bytes, probe_random_bytes, &proof_rng, &source_relation,
        &relation_context, 1024u);
    printf("SOURCE_PROVE_STATUS status=%d prover_calls=%u\n", prove_status,
           relation_context.prover_calls);
    proof_found = prove_status == DMV_OK;
  }
  check_result("source_bound_prove_with_bounded_retry", proof_found);
  if (proof_found) {
    size_t wire_size = 0;
    size_t wire_written = 0;
    check_result("wire_size", dmv_proof_wire_size(&generated_proof, &wire_size) == DMV_OK &&
                                  wire_size > DMV_WIRE_HEADER_BYTES);
    uint8_t* wire = malloc(wire_size);
    dmv_proof_t decoded_proof;
    memset(&decoded_proof, 0, sizeof(decoded_proof));
    const int size_status = dmv_proof_wire_size(&generated_proof, &wire_size);
    const int encode_status = wire == NULL ? DMV_ERR_ALLOCATION
                                           : dmv_proof_encode(&generated_proof, wire, wire_size,
                                                              &wire_written);
    const int decode_status = wire == NULL ? DMV_ERR_ALLOCATION
                                           : dmv_proof_decode(&decoded_proof, wire, wire_size);
    if (size_status != DMV_OK || encode_status != DMV_OK || decode_status != DMV_OK) {
      printf("E2E_WIRE_STATUS size=%d encode=%d decode=%d\n", size_status, encode_status,
             decode_status);
      check_result("canonical_wire_roundtrip", false);
    } else {
      printf("E2E_WIRE_SIZE bytes=%zu written=%zu statement=%zu nu=%u nonces=%u m1=%zu m2=%zu m3=%zu m4=%zu\n",
             wire_size, wire_written, decoded_proof.statement_len, DMV_LEAF_UHASH_BYTES,
             3u * DMV_NONCE_BYTES, decoded_proof.m1_len, decoded_proof.m2_len,
             decoded_proof.m3_len, decoded_proof.m4_len);
       const int verify_status = dmv_verify(&decoded_proof, &proof_descriptor, proof_statement,
                                           sizeof(proof_statement), &source_relation,
                                           &relation_context);
       printf("E2E_VERIFY_STATUS status=%d\n", verify_status);
       printf("SOURCE_BOUND_COUNTS ell=%u m=%u bitness=%u inverse=%u equality=%u tag=%u "
              "range=%u sboxes=%u aes_blocks=%u key_schedules=%u prover_calls=%u "
              "verifier_calls=%u counts_equal=%u\n",
              relation_context.prover_counts.witness_bits, relation_context.prover_counts.constraints,
              relation_context.prover_counts.bitness, relation_context.prover_counts.inverse,
              relation_context.prover_counts.equality, relation_context.prover_counts.tag,
              relation_context.prover_counts.range, relation_context.prover_counts.sboxes,
              relation_context.prover_counts.aes_blocks,
              relation_context.prover_counts.key_schedules, relation_context.prover_calls,
              relation_context.verifier_calls,
              memcmp(&relation_context.prover_counts, &relation_context.verifier_counts,
                     sizeof(relation_context.prover_counts)) == 0 ? 1u : 0u);
       check_result("canonical_wire_roundtrip", wire_written == wire_size &&
                                                    verify_status == DMV_OK &&
                                                    relation_context.prover_calls == 1u &&
                                                    relation_context.verifier_calls == 1u &&
                                                    memcmp(&relation_context.prover_counts,
                                                           &relation_context.verifier_counts,
                                                           sizeof(relation_context.prover_counts)) == 0);

       decoded_proof.nu[0] ^= 1u;
       check_result("explicit_nu_tamper_rejected",
                    dmv_verify(&decoded_proof, &proof_descriptor, proof_statement,
                               sizeof(proof_statement), &source_relation,
                               &relation_context) != DMV_OK);
      decoded_proof.nu[0] ^= 1u;

       decoded_proof.m2[0] ^= 1u;
       check_result("vh_tamper_rejected",
                    dmv_verify(&decoded_proof, &proof_descriptor, proof_statement,
                               sizeof(proof_statement), &source_relation,
                               &relation_context) != DMV_OK);
      decoded_proof.m2[0] ^= 1u;

       decoded_proof.m3[0] ^= 1u;
       check_result("three_coefficient_tamper_rejected",
                    dmv_verify(&decoded_proof, &proof_descriptor, proof_statement,
                               sizeof(proof_statement), &source_relation,
                               &relation_context) != DMV_OK);
      decoded_proof.m3[0] ^= 1u;

      uint8_t wrong_statement[sizeof(proof_statement)];
      memcpy(wrong_statement, proof_statement, sizeof(wrong_statement));
      wrong_statement[0] ^= 1u;
       check_result("full_statement_mismatch_rejected",
                    dmv_verify(&decoded_proof, &proof_descriptor, wrong_statement,
                               sizeof(wrong_statement), &source_relation,
                               &relation_context) != DMV_OK);

      uint8_t gamma1_for_retry[DMV_FS1_BYTES];
      uint8_t gamma2_for_retry[DMV_FS2_BYTES];
      uint8_t gamma3_for_retry[DMV_FS3_BYTES];
      if (dmv_fs1(gamma1_for_retry, sizeof(gamma1_for_retry), generated_proof.statement,
                  generated_proof.statement_len, generated_proof.nu, generated_proof.m1,
                  generated_proof.m1_len, generated_proof.sigma1) == DMV_OK &&
          dmv_fs2(gamma2_for_retry, sizeof(gamma2_for_retry), generated_proof.statement,
                  generated_proof.statement_len, generated_proof.nu, generated_proof.m1,
                  generated_proof.m1_len, generated_proof.sigma1, gamma1_for_retry,
                  generated_proof.m2, generated_proof.m2_len, generated_proof.sigma2) == DMV_OK) {
        for (unsigned int index = 0; index != 1024u && !invalid_final_found; ++index) {
          fill_pattern(invalid_final, sizeof(invalid_final), (uint8_t)(0xa0u + index));
          invalid_final[0] = (uint8_t)index;
          invalid_final[1] = (uint8_t)(index >> 8);
          invalid_final[2] = (uint8_t)(index >> 16);
          invalid_final[3] = (uint8_t)(index >> 24);
          if (dmv_fs3(gamma3_for_retry, generated_proof.statement,
                      generated_proof.statement_len, generated_proof.nu, generated_proof.m1,
                      generated_proof.m1_len, generated_proof.sigma1, gamma1_for_retry,
                      generated_proof.m2, generated_proof.m2_len, generated_proof.sigma2,
                      gamma2_for_retry, generated_proof.m3, generated_proof.m3_len,
                      invalid_final) == DMV_OK &&
              gamma3_for_retry[DMV_FS3_BYTES - 1u] != 0) {
            invalid_final_found = true;
          }
        }
      }
      printf("RETRY_NEGATIVE_SEARCH found=%u\n", invalid_final_found ? 1u : 0u);

      dmv_proof_t empty_statement_wire = generated_proof;
      empty_statement_wire.statement = NULL;
      empty_statement_wire.statement_len = 0;
      size_t empty_wire_size = 0;
      dmv_proof_t empty_decoded;
      memset(&empty_decoded, 0, sizeof(empty_decoded));
      uint8_t* empty_wire = NULL;
      bool empty_wire_ok = dmv_proof_wire_size(&empty_statement_wire, &empty_wire_size) == DMV_OK;
      if (empty_wire_ok) {
        empty_wire = malloc(empty_wire_size);
        empty_wire_ok = empty_wire != NULL &&
                        dmv_proof_encode(&empty_statement_wire, empty_wire, empty_wire_size, NULL) ==
                            DMV_OK &&
                        dmv_proof_decode(&empty_decoded, empty_wire, empty_wire_size) == DMV_OK &&
                        empty_decoded.statement == NULL && empty_decoded.statement_len == 0;
      }
      check_result("zero_length_statement_wire_safe", empty_wire_ok);
      probe_clear_free(empty_wire, empty_wire_size);
      dmv_proof_clear(&empty_decoded);

      const int failed_decode_status =
          dmv_proof_decode(&decoded_proof, wire, wire_size - 1u);
      check_result("failed_decode_clears_destination",
                   failed_decode_status == DMV_ERR_SIZE && proof_is_zeroed(&decoded_proof));
      check_result("failed_decode_cannot_verify",
                   dmv_verify(&decoded_proof, &proof_descriptor, proof_statement,
                              sizeof(proof_statement), &source_relation,
                              &relation_context) == DMV_ERR_ARGUMENT);

      const int recovered_decode_status = dmv_proof_decode(&decoded_proof, wire, wire_size);
      const int recovered_decode_verify =
          recovered_decode_status == DMV_OK
              ? dmv_verify(&decoded_proof, &proof_descriptor, proof_statement,
                           sizeof(proof_statement), &source_relation, &relation_context)
              : DMV_ERR_ARGUMENT;
      check_result("decode_valid_recovery",
                   recovered_decode_status == DMV_OK && recovered_decode_verify == DMV_OK);
      dmv_proof_clear(&decoded_proof);
      dmv_proof_clear(&decoded_proof);
      check_result("decode_double_clear_zeroes_destination", proof_is_zeroed(&decoded_proof));
    }
    probe_clear_free(wire, wire_size);
  }

  probe_rng_t lifecycle_rng = {0u, 0x60u, false, false, {0}};
  const int live_reuse_status =
      dmv_prove(&generated_proof, &proof_descriptor, proof_statement, sizeof(proof_statement),
                proof_witness, packed_witness_bytes, probe_random_bytes, &lifecycle_rng,
                &source_relation, &relation_context, 1024u);
  check_result("live_proof_reuse_succeeds",
               live_reuse_status == DMV_OK && generated_proof.initialized);

  const int failed_prove_status =
      dmv_prove(&generated_proof, &proof_descriptor, proof_statement, sizeof(proof_statement),
                proof_witness, packed_witness_bytes, probe_random_bytes, &lifecycle_rng,
                &source_relation, &relation_context, 0u);
  check_result("failed_prove_clears_destination",
               failed_prove_status == DMV_ERR_RETRY && proof_is_zeroed(&generated_proof));
  check_result("failed_prove_cannot_verify",
               dmv_verify(&generated_proof, &proof_descriptor, proof_statement,
                          sizeof(proof_statement), &source_relation,
                          &relation_context) == DMV_ERR_ARGUMENT);

  const int recovered_prove_status =
      dmv_prove(&generated_proof, &proof_descriptor, proof_statement, sizeof(proof_statement),
                proof_witness, packed_witness_bytes, probe_random_bytes, &lifecycle_rng,
                &source_relation, &relation_context, 1024u);
  check_result("prove_valid_recovery",
               recovered_prove_status == DMV_OK && generated_proof.initialized);
  dmv_proof_clear(&generated_proof);
  dmv_proof_clear(&generated_proof);
  check_result("prove_double_clear_zeroes_destination", proof_is_zeroed(&generated_proof));

  dmv_proof_t exhausted_proof;
  memset(&exhausted_proof, 0, sizeof(exhausted_proof));
  probe_rng_t exhausted_rng;
  memset(&exhausted_rng, 0, sizeof(exhausted_rng));
  exhausted_rng.final_seed = 0x90u;
  exhausted_rng.use_forced_final = invalid_final_found;
  memcpy(exhausted_rng.forced_final, invalid_final, sizeof(invalid_final));
  check_result("retry_negative_fixture_found", proof_found && invalid_final_found);
  check_result("fresh_final_nonce_exhaustion_fails_closed",
               proof_found && invalid_final_found &&
                   dmv_prove(&exhausted_proof, &proof_descriptor, proof_statement,
                              sizeof(proof_statement), proof_witness, packed_witness_bytes,
                              probe_random_bytes, &exhausted_rng, &source_relation,
                              &relation_context, 4u) ==
                       DMV_ERR_RETRY);
  dmv_proof_clear(&exhausted_proof);

  dmv_commit_clear(&commitment);
  probe_clear_free(m1, m1_len);
  probe_clear_free(m2, m2_len);
  probe_clear_free(m3, m3_len);
  probe_clear_free(proof_witness, packed_witness_bytes);
  probe_clear_free(opening, dmv_opening_bytes());
  probe_clear_free(opening_tampered, dmv_opening_bytes());
  probe_clear_free(corrections_tampered, dmv_correction_bytes(&descriptor));
  probe_clear_free(q_rows, (size_t)actual_rows * sizeof(*q_rows));
  probe_clear_free(q_rows_tampered, (size_t)actual_rows * sizeof(*q_rows_tampered));
  probe_secure_clear(root, sizeof(root));
  probe_secure_clear(iv, sizeof(iv));

  printf("DIRECT_MASK_PROBE_COUNTS passed=%u failed=%u\n", g_passed, g_failed);
  printf("DIRECT_MASK_PROBE_STATUS=%s\n", g_failed == 0 ? "PASS" : "FAIL");
  return g_failed == 0 ? 0 : 1;
}
