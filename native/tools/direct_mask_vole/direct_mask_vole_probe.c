/* SPDX-License-Identifier: MIT */

#include "direct_mask_vole.h"

#include "../direct_mask_circuit/dmc_range_constraints.h"
#include "../direct_mask_kernel/direct_mask_algebra.h"
#include "../direct_mask_kernel/direct_mask_kernel.h"
#include "direct_mask_circuit.h"
#include "utils.h"

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
  unsigned int iv_start;
  unsigned int iv_calls;
  unsigned int root_calls;
  unsigned int nonce_calls;
  bool root_pending;
  uint8_t final_seed;
  bool use_forced_final;
  unsigned int force_final_after;
  bool fail_h0;
  bool fail_nonce_at_enabled;
  unsigned int fail_nonce_at;
  uint8_t forced_final[DMV_NONCE_BYTES];
} probe_rng_t;

static uint64_t probe_clock_ticks(void) {
  const clock_t now = clock();
  return now == (clock_t)-1 ? 0u : (uint64_t)now;
}

static void fill_counter_pattern(uint8_t* out, size_t length, uint8_t seed,
                                 unsigned int counter) {
  fill_pattern(out, length, seed);
  const size_t counter_bytes = length < sizeof(counter) ? length : sizeof(counter);
  for (size_t byte = 0; byte != counter_bytes; ++byte) {
    out[byte] = (uint8_t)(counter >> (8u * byte));
  }
}

static int probe_random_bytes(void* context, uint8_t* out, size_t length) {
  probe_rng_t* rng = (probe_rng_t*)context;
  if (rng == NULL || out == NULL || (length != 16u && length != DMV_SEED_BYTES)) {
    return -1;
  }
  if (length == 16u) {
    const unsigned int iv_call = rng->iv_calls++;
    if (rng->fail_h0) {
      return -1;
    }
    fill_counter_pattern(out, length, 0x22u, rng->iv_start + iv_call);
    rng->root_pending = true;
    return 0;
  }
  if (rng->root_pending) {
    const unsigned int root_call = rng->root_calls++;
    fill_counter_pattern(out, DMV_SEED_BYTES, 0x11u, root_call);
    rng->root_pending = false;
    return 0;
  }
  const unsigned int nonce_call = rng->nonce_calls++;
  if (rng->fail_nonce_at_enabled && nonce_call == rng->fail_nonce_at) {
    return -1;
  }
  if (rng->use_forced_final && nonce_call >= rng->force_final_after) {
    memcpy(out, rng->forced_final, length);
  } else {
    const uint8_t seed = nonce_call == 0u
                             ? 0x33u
                             : (uint8_t)(rng->final_seed + (uint8_t)(nonce_call - 1u));
    fill_counter_pattern(out, length, seed, nonce_call);
  }
  return 0;
}

static uint64_t probe_elapsed_ticks(uint64_t started) {
  const uint64_t finished = probe_clock_ticks();
  return finished >= started ? finished - started : 0u;
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

static bool find_h0_vectors(uint8_t accepted_iv[16], unsigned int* accepted_index,
                            unsigned int* rejected_index) {
  bool found_accepted = false;
  bool found_rejected = false;
  uint8_t candidate[16];
  uint8_t raw[DMV_H0_SQUEEZE_BYTES];
  for (unsigned int index = 0; index != DMV_MAX_H0_RETRIES &&
                                (!found_accepted || !found_rejected);
       ++index) {
    fill_counter_pattern(candidate, sizeof(candidate), 0x22u, index);
    if (dmv_h0_raw(raw, candidate) != DMV_OK) {
      probe_secure_clear(raw, sizeof(raw));
      continue;
    }
    const bool accepted = (raw[DMV_LEAF_UHASH_BYTES - 1u] & 0x80u) == 0u &&
                          raw[DMV_LEAF_UHASH_BYTES] == 0u &&
                          (raw[DMV_LEAF_UHASH_BYTES + 1u] & 0x01u) == 0u;
    if (accepted && !found_accepted) {
      memcpy(accepted_iv, candidate, sizeof(candidate));
      *accepted_index = index;
      found_accepted = true;
    }
    if (!accepted && !found_rejected) {
      *rejected_index = index;
      found_rejected = true;
    }
    probe_secure_clear(raw, sizeof(raw));
  }
  probe_secure_clear(candidate, sizeof(candidate));
  probe_secure_clear(raw, sizeof(raw));
  return found_accepted && found_rejected;
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
  uint8_t root[DMV_SEED_BYTES];
  uint8_t iv[16];
  fill_pattern(root, sizeof(root), 0x31u);
  unsigned int accepted_iv_index = 0u;
  unsigned int rejected_iv_index = 0u;
  const bool h0_vectors_found =
      find_h0_vectors(iv, &accepted_iv_index, &rejected_iv_index);
  if (!h0_vectors_found) {
    fill_pattern(iv, sizeof(iv), 0x7bu);
  }

  uint8_t h0_raw_kat[DMV_H0_SQUEEZE_BYTES] = {0};
  uint8_t h0_nu_kat[DMV_LEAF_UHASH_BYTES] = {0};
  const int h0_kat_status = h0_vectors_found
                                ? dmv_h0_raw(h0_raw_kat, iv)
                                : DMV_ERR_ARGUMENT;
  const int h0_nu_status = h0_vectors_found
                               ? dmv_derive_leaf_uhash(h0_nu_kat, iv)
                               : DMV_ERR_ARGUMENT;
  check_result("h0_vendor_raw_matches_leaf",
               h0_kat_status == DMV_OK && h0_nu_status == DMV_OK &&
                   memcmp(h0_nu_kat, h0_raw_kat, DMV_LEAF_UHASH_BYTES) == 0 &&
                   (h0_raw_kat[DMV_LEAF_UHASH_BYTES - 1u] & 0x80u) == 0u &&
                   h0_raw_kat[DMV_LEAF_UHASH_BYTES] == 0u &&
                   (h0_raw_kat[DMV_LEAF_UHASH_BYTES + 1u] & 0x01u) == 0u);
  if (h0_kat_status == DMV_OK && h0_nu_status == DMV_OK) {
    printf("H0_KAT iv=");
    print_hex(iv, sizeof(iv));
    printf(" raw=");
    print_hex(h0_raw_kat, sizeof(h0_raw_kat));
    printf(" nu=");
    print_hex(h0_nu_kat, sizeof(h0_nu_kat));
    putchar('\n');
  }

  uint8_t commit_nu[DMV_NU_BYTES] = {0};
  const int commit_nu_status = dmv_derive_leaf_uhash(commit_nu, iv);
  check_result("commit_nu", commit_nu_status == DMV_OK);

  printf("DIRECT_MASK_PROBE_BEGIN\n");
  check_result("h0_filter_vectors_found", h0_vectors_found);
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
  check_result("m4_size", dmv_m4_bytes() == dmv_opening_bytes() &&
                               dmv_m4_bytes() == (size_t)DMV_TAU * DMV_BAVC_COM_BYTES +
                                                     (size_t)DMV_T_OPEN * DMV_SEED_BYTES);

  dmv_descriptor_t bad_descriptor = descriptor;
  bad_descriptor.degree = DMV_DEGREE - 1u;
  dmv_commitment_t bad_commitment;
  memset(&bad_commitment, 0, sizeof(bad_commitment));
  check_result("bad_degree_rejected", dmv_descriptor_validate(&bad_descriptor) == DMV_ERR_DESCRIPTOR &&
                                         dmv_commit(&bad_commitment, &bad_descriptor, root, iv,
                                                    commit_nu) == DMV_ERR_DESCRIPTOR);
  dmv_commit_clear(&bad_commitment);

  dmv_commitment_t commitment;
  memset(&commitment, 0, sizeof(commitment));
  const int commit_status = dmv_commit(&commitment, &descriptor, root, iv, commit_nu);
  check_result("commit", commit_status == DMV_OK);
  if (commit_status != DMV_OK) {
    printf("DIRECT_MASK_PROBE_COUNTS passed=%u failed=%u\n", g_passed, g_failed);
    printf("DIRECT_MASK_PROBE_STATUS=FAIL\n");
    probe_secure_clear(root, sizeof(root));
    probe_secure_clear(iv, sizeof(iv));
    probe_secure_clear(commit_nu, sizeof(commit_nu));
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
    probe_secure_clear(commit_nu, sizeof(commit_nu));
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
    probe_secure_clear(commit_nu, sizeof(commit_nu));
    printf("DIRECT_MASK_PROBE_COUNTS passed=%u failed=%u\n", g_passed, g_failed);
    printf("DIRECT_MASK_PROBE_STATUS=FAIL\n");
    return 1;
  }

  const int reconstruct_status = dmv_reconstruct(
      &descriptor, iv, commit_nu, raw_challenge, opening, dmv_opening_bytes(),
      dmv_corrections(&commitment),
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
                   dmv_reconstruct(&descriptor, iv, commit_nu, invalid_challenge, opening,
                                   dmv_opening_bytes(), dmv_corrections(&commitment),
                                   dmv_correction_bytes(&descriptor), reconstructed_commitment,
                                   q_rows, actual_rows, &delta) == DMV_ERR_CHALLENGE);
  check_result("opening_length_rejected",
               dmv_reconstruct(&descriptor, iv, commit_nu, raw_challenge, opening,
                               dmv_opening_bytes() - 1u,
                               dmv_corrections(&commitment), dmv_correction_bytes(&descriptor),
                               reconstructed_commitment, q_rows, actual_rows, &delta) == DMV_ERR_SIZE);
  check_result("correction_length_rejected",
               dmv_reconstruct(&descriptor, iv, commit_nu, raw_challenge, opening,
                               dmv_opening_bytes(),
                               dmv_corrections(&commitment), dmv_correction_bytes(&descriptor) - 1u,
                               reconstructed_commitment, q_rows, actual_rows, &delta) == DMV_ERR_SIZE);

  memcpy(opening_tampered, opening, dmv_opening_bytes());
  opening_tampered[0] ^= 1u;
  const int tampered_opening_status = dmv_reconstruct(
      &descriptor, iv, commit_nu, raw_challenge, opening_tampered, dmv_opening_bytes(),
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
      &descriptor, iv, commit_nu, raw_challenge, opening, dmv_opening_bytes(), corrections_tampered,
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
  uint8_t fs1[DMV_FS1_BYTES];
  uint8_t fs1_changed[DMV_FS1_BYTES];
  uint8_t fs2[DMV_FS2_BYTES];
  uint8_t fs2_raw[DMV_FS2_SQUEEZE_BYTES];
  uint8_t fs2_raw_changed[DMV_FS2_SQUEEZE_BYTES];
  uint8_t fs3[DMV_FS3_BYTES];
  uint8_t fs3_raw[DMV_FS3_SQUEEZE_BYTES];
  uint8_t fs3_raw_changed[DMV_FS3_SQUEEZE_BYTES];
  uint8_t gamma1[DMV_FS1_BYTES];
  uint8_t gamma2[DMV_FS2_BYTES];
  if (m1 == NULL || m2 == NULL || m3 == NULL) {
    printf("CHECK_FAIL transcript_allocation\n");
    ++g_failed;
  } else {
    fill_pattern(m1, m1_len, 0x51u);
    fill_pattern(m2, m2_len, 0x61u);
    fill_pattern(m3, m3_len, 0x71u);
    fill_pattern(gamma1, sizeof(gamma1), 0x81u);
    fill_pattern(gamma2, sizeof(gamma2), 0x91u);
    uint8_t nonce1_fs2_vector[sizeof(fs2_raw)] = {0};
    uint8_t nonce1_fs3_vector[sizeof(fs3_raw)] = {0};
    uint8_t nonce2_fs3_vector[sizeof(fs3_raw)] = {0};
    check_result("fs1", dmv_fs1(fs1, sizeof(fs1), statement, sizeof(statement), uhash, m1, m1_len,
                                nonce1) == DMV_OK);
    check_result("fs1_wrong_output_size", dmv_fs1(fs1, sizeof(fs1) - 1u, statement,
                                                   sizeof(statement), uhash, m1, m1_len, nonce1) ==
                                                   DMV_ERR_SIZE);
    const int fs2_raw_status =
        dmv_fs2_raw(fs2_raw, statement, sizeof(statement), uhash, m1, m1_len, nonce1, gamma1, m2,
                    m2_len, nonce2);
    const int fs3_raw_status =
        dmv_fs3_raw(fs3_raw, statement, sizeof(statement), uhash, m1, m1_len, nonce1, gamma1, m2,
                    m2_len, nonce2, gamma2, m3, m3_len, nonce3);
    const int fs2_status =
        dmv_fs2(fs2, sizeof(fs2), statement, sizeof(statement), uhash, m1, m1_len, nonce1, gamma1,
                m2, m2_len, nonce2);
    const int fs3_status = dmv_fs3(fs3, statement, sizeof(statement), uhash, m1, m1_len, nonce1,
                                   gamma1, m2, m2_len, nonce2, gamma2, m3, m3_len, nonce3);
    check_result("fs2_raw", fs2_raw_status == DMV_OK);
    check_result("fs3_raw", fs3_raw_status == DMV_OK);
    check_result("fs2_filter_predicate",
                 fs2_raw_status == DMV_OK &&
                     ((fs2_status == DMV_OK) == ((fs2_raw[DMV_FS2_BYTES] & 0x3fu) == 0u)) &&
                     (fs2_status != DMV_OK || memcmp(fs2, fs2_raw, DMV_FS2_BYTES) == 0) &&
                     (fs2_status == DMV_OK || bytes_are_zero(fs2, sizeof(fs2))));
    check_result("fs3_filter_predicate",
                 fs3_raw_status == DMV_OK &&
                     ((fs3_status == DMV_OK) == ((fs3_raw[DMV_FS3_BYTES] & 0x7fu) == 0u)) &&
                     (fs3_status != DMV_OK || memcmp(fs3, fs3_raw, DMV_FS3_BYTES) == 0) &&
                     (fs3_status == DMV_OK || bytes_are_zero(fs3, sizeof(fs3))));
    check_result("fs2_wrong_output_size",
                 dmv_fs2(fs2, sizeof(fs2) - 1u, statement, sizeof(statement), uhash, m1, m1_len,
                         nonce1, gamma1, m2, m2_len, nonce2) == DMV_ERR_SIZE);
    check_result("fs3_raw_output_size_is_fixed",
                 dmv_fs3_raw(fs3_raw, statement, sizeof(statement), uhash, m1, m1_len, nonce1,
                             gamma1, m2, m2_len, nonce2, gamma2, m3, m3_len, nonce3) == DMV_OK);
    printf("TRANSCRIPT_C_INPUT statement=%zu uhash=%u m1=%zu sigma1=%u gamma1=%u m2=%zu sigma2=%u "
           "gamma2=%u m3=%zu sigma3=%u\n",
           sizeof(statement), (unsigned)sizeof(uhash), m1_len, (unsigned)sizeof(nonce1),
           (unsigned)sizeof(gamma1), m2_len, (unsigned)sizeof(nonce2), (unsigned)sizeof(gamma2),
           m3_len, (unsigned)sizeof(nonce3));
    printf("TRANSCRIPT_C_KAT fs1=");
    print_hex(fs1, sizeof(fs1));
    printf(" fs2=");
    print_hex(fs2_raw, sizeof(fs2_raw));
    printf(" fs3=");
    print_hex(fs3_raw, sizeof(fs3_raw));
    putchar('\n');

    check_result("fs1_binds_full_statement",
                 dmv_fs1(fs1_changed, sizeof(fs1_changed), statement_changed, sizeof(statement_changed),
                         uhash, m1, m1_len, nonce1) == DMV_OK &&
                     memcmp(fs1, fs1_changed, sizeof(fs1)) != 0);
    check_result("fs2_binds_full_statement",
                 dmv_fs2_raw(fs2_raw_changed, statement_changed, sizeof(statement_changed), uhash,
                             m1, m1_len, nonce1, gamma1, m2, m2_len, nonce2) == DMV_OK &&
                     memcmp(fs2_raw, fs2_raw_changed, sizeof(fs2_raw)) != 0);
    check_result("fs3_binds_full_statement",
                 dmv_fs3_raw(fs3_raw_changed, statement_changed, sizeof(statement_changed), uhash,
                             m1, m1_len, nonce1, gamma1, m2, m2_len, nonce2, gamma2, m3, m3_len,
                             nonce3) == DMV_OK &&
                     memcmp(fs3_raw, fs3_raw_changed, sizeof(fs3_raw)) != 0);

    uint8_t nonce2_changed[DMV_NONCE_BYTES];
    memcpy(nonce2_changed, nonce2, sizeof(nonce2));
    nonce2_changed[0] ^= 1u;
    check_result("fs2_binds_nonce",
                 dmv_fs2_raw(fs2_raw_changed, statement, sizeof(statement), uhash, m1, m1_len,
                             nonce1, gamma1, m2, m2_len, nonce2_changed) == DMV_OK &&
                     memcmp(fs2_raw, fs2_raw_changed, sizeof(fs2_raw)) != 0);

    uint8_t nonce1_changed[DMV_NONCE_BYTES];
    memcpy(nonce1_changed, nonce1, sizeof(nonce1));
    nonce1_changed[0] ^= 1u;
    check_result("fs2_binds_prior_nonce_with_fixed_gamma1",
                 dmv_fs2_raw(fs2_raw_changed, statement, sizeof(statement), uhash, m1, m1_len,
                             nonce1_changed, gamma1, m2, m2_len, nonce2) == DMV_OK &&
                     memcmp(fs2_raw, fs2_raw_changed, sizeof(fs2_raw)) != 0);
    memcpy(nonce1_fs2_vector, fs2_raw_changed, sizeof(nonce1_fs2_vector));
    check_result("fs3_binds_prior_nonce_with_fixed_challenges",
                 dmv_fs3_raw(fs3_raw_changed, statement, sizeof(statement), uhash, m1, m1_len,
                             nonce1_changed, gamma1, m2, m2_len, nonce2, gamma2, m3, m3_len,
                             nonce3) == DMV_OK &&
                     memcmp(fs3_raw, fs3_raw_changed, sizeof(fs3_raw)) != 0);
    memcpy(nonce1_fs3_vector, fs3_raw_changed, sizeof(nonce1_fs3_vector));

    uint8_t nonce2_changed_for_fs3[DMV_NONCE_BYTES];
    memcpy(nonce2_changed_for_fs3, nonce2, sizeof(nonce2));
    nonce2_changed_for_fs3[0] ^= 1u;
    check_result("fs3_binds_prior_nonce2_with_fixed_gamma2",
                 dmv_fs3_raw(fs3_raw_changed, statement, sizeof(statement), uhash, m1, m1_len,
                             nonce1, gamma1, m2, m2_len, nonce2_changed_for_fs3, gamma2, m3,
                             m3_len, nonce3) == DMV_OK &&
                     memcmp(fs3_raw, fs3_raw_changed, sizeof(fs3_raw)) != 0);
    memcpy(nonce2_fs3_vector, fs3_raw_changed, sizeof(nonce2_fs3_vector));
    printf("TRANSCRIPT_C_MUTATION nonce1_fs2=");
    print_hex(nonce1_fs2_vector, sizeof(nonce1_fs2_vector));
    printf(" nonce1_fs3=");
    print_hex(nonce1_fs3_vector, sizeof(nonce1_fs3_vector));
    printf(" nonce2_fs3=");
    print_hex(nonce2_fs3_vector, sizeof(nonce2_fs3_vector));
    putchar('\n');

    dmv_transcript_cache_t fs2_cache = {0};
    dmv_transcript_cache_t fs3_cache = {0};
    uint8_t fs2_cached[DMV_FS2_SQUEEZE_BYTES] = {0};
    uint8_t fs2_cached_alt[DMV_FS2_SQUEEZE_BYTES] = {0};
    uint8_t fs2_cached_repeat[DMV_FS2_SQUEEZE_BYTES] = {0};
    uint8_t fs3_cached[DMV_FS3_SQUEEZE_BYTES] = {0};
    uint8_t fs3_cached_alt[DMV_FS3_SQUEEZE_BYTES] = {0};
    uint8_t fs3_cached_repeat[DMV_FS3_SQUEEZE_BYTES] = {0};
    uint8_t fs2_alt_raw[DMV_FS2_SQUEEZE_BYTES] = {0};
    uint8_t fs3_alt_raw[DMV_FS3_SQUEEZE_BYTES] = {0};
    uint8_t fs2_changed_raw[DMV_FS2_SQUEEZE_BYTES] = {0};
    uint8_t fs3_changed_raw[DMV_FS3_SQUEEZE_BYTES] = {0};
    uint8_t nonce3_changed[DMV_NONCE_BYTES];
    memcpy(nonce3_changed, nonce3, sizeof(nonce3_changed));
    nonce3_changed[0] ^= 1u;
    const int fs2_cache_init_status =
        dmv_fs2_cache_init(&fs2_cache, statement, sizeof(statement), uhash, m1, m1_len, nonce1,
                           gamma1, m2, m2_len);
    const int fs2_cache_query_status = fs2_cache_init_status == DMV_OK
                                           ? dmv_fs2_cache_query_raw(&fs2_cache, fs2_cached, nonce2)
                                           : DMV_ERR_ARGUMENT;
    const int fs2_cache_alt_query_status =
        fs2_cache_init_status == DMV_OK
            ? dmv_fs2_cache_query_raw(&fs2_cache, fs2_cached_alt, nonce2_changed)
            : DMV_ERR_ARGUMENT;
    const int fs2_cache_repeat_query_status =
        fs2_cache_init_status == DMV_OK
            ? dmv_fs2_cache_query_raw(&fs2_cache, fs2_cached_repeat, nonce2)
            : DMV_ERR_ARGUMENT;
    const int fs2_alt_raw_status =
        dmv_fs2_raw(fs2_alt_raw, statement, sizeof(statement), uhash, m1, m1_len, nonce1, gamma1,
                    m2, m2_len, nonce2_changed);
    const int fs3_cache_init_status =
        dmv_fs3_cache_init(&fs3_cache, statement, sizeof(statement), uhash, m1, m1_len, nonce1,
                           gamma1, m2, m2_len, nonce2, gamma2, m3, m3_len);
    const int fs3_cache_query_status = fs3_cache_init_status == DMV_OK
                                           ? dmv_fs3_cache_query_raw(&fs3_cache, fs3_cached, nonce3)
                                           : DMV_ERR_ARGUMENT;
    const int fs3_cache_alt_query_status =
        fs3_cache_init_status == DMV_OK
            ? dmv_fs3_cache_query_raw(&fs3_cache, fs3_cached_alt, nonce3_changed)
            : DMV_ERR_ARGUMENT;
    const int fs3_cache_repeat_query_status =
        fs3_cache_init_status == DMV_OK
            ? dmv_fs3_cache_query_raw(&fs3_cache, fs3_cached_repeat, nonce3)
            : DMV_ERR_ARGUMENT;
    const int fs3_alt_raw_status =
        dmv_fs3_raw(fs3_alt_raw, statement, sizeof(statement), uhash, m1, m1_len, nonce1, gamma1,
                    m2, m2_len, nonce2, gamma2, m3, m3_len, nonce3_changed);
    check_result("fs2_cache_full_replay_byte_equivalence",
                 fs2_cache_query_status == DMV_OK &&
                     memcmp(fs2_cached, fs2_raw, sizeof(fs2_cached)) == 0);
    check_result("fs3_cache_full_replay_byte_equivalence",
                 fs3_cache_query_status == DMV_OK &&
                     memcmp(fs3_cached, fs3_raw, sizeof(fs3_cached)) == 0);
    check_result("fs2_cache_multiple_nonces_replay_equivalence",
                 fs2_cache_alt_query_status == DMV_OK && fs2_alt_raw_status == DMV_OK &&
                     memcmp(fs2_cached_alt, fs2_alt_raw, sizeof(fs2_cached_alt)) == 0 &&
                     fs2_cache_repeat_query_status == DMV_OK &&
                     memcmp(fs2_cached_repeat, fs2_raw, sizeof(fs2_cached_repeat)) == 0);
    check_result("fs3_cache_multiple_nonces_replay_equivalence",
                 fs3_cache_alt_query_status == DMV_OK && fs3_alt_raw_status == DMV_OK &&
                     memcmp(fs3_cached_alt, fs3_alt_raw, sizeof(fs3_cached_alt)) == 0 &&
                     fs3_cache_repeat_query_status == DMV_OK &&
                     memcmp(fs3_cached_repeat, fs3_raw, sizeof(fs3_cached_repeat)) == 0);
    const size_t fs2_fixed_prefix_bytes = DMV_TRANSCRIPT_PREFIX_BYTES + 3u + 6u * sizeof(uint32_t) +
                                          sizeof(statement) + sizeof(uhash) + m1_len +
                                          sizeof(nonce1) + sizeof(gamma1) + m2_len;
    const size_t fs3_fixed_prefix_bytes = DMV_TRANSCRIPT_PREFIX_BYTES + 3u + 9u * sizeof(uint32_t) +
                                          sizeof(statement) + sizeof(uhash) + m1_len +
                                          sizeof(nonce1) + sizeof(gamma1) + m2_len + sizeof(nonce2) +
                                          sizeof(gamma2) + m3_len;
    dmv_transcript_cache_clear(&fs2_cache);
    dmv_transcript_cache_clear(&fs3_cache);
    const bool cache_zeroed_after_first_clear =
        bytes_are_zero((const uint8_t*)&fs2_cache, sizeof(fs2_cache)) &&
        bytes_are_zero((const uint8_t*)&fs3_cache, sizeof(fs3_cache));
    const int fs2_changed_init_status =
        dmv_fs2_cache_init(&fs2_cache, statement_changed, sizeof(statement_changed), uhash, m1,
                           m1_len, nonce1, gamma1, m2, m2_len);
    const int fs2_changed_query_status =
        fs2_changed_init_status == DMV_OK
            ? dmv_fs2_cache_query_raw(&fs2_cache, fs2_cached, nonce2)
            : DMV_ERR_ARGUMENT;
    const int fs2_changed_raw_status =
        dmv_fs2_raw(fs2_changed_raw, statement_changed, sizeof(statement_changed), uhash, m1,
                    m1_len, nonce1, gamma1, m2, m2_len, nonce2);
    const int fs3_changed_init_status =
        dmv_fs3_cache_init(&fs3_cache, statement_changed, sizeof(statement_changed), uhash, m1,
                           m1_len, nonce1, gamma1, m2, m2_len, nonce2, gamma2, m3, m3_len);
    const int fs3_changed_query_status =
        fs3_changed_init_status == DMV_OK
            ? dmv_fs3_cache_query_raw(&fs3_cache, fs3_cached, nonce3)
            : DMV_ERR_ARGUMENT;
    const int fs3_changed_raw_status =
        dmv_fs3_raw(fs3_changed_raw, statement_changed, sizeof(statement_changed), uhash, m1,
                    m1_len, nonce1, gamma1, m2, m2_len, nonce2, gamma2, m3, m3_len, nonce3);
    const bool reinitialized_changed_input =
        fs2_changed_init_status == DMV_OK && fs2_changed_query_status == DMV_OK &&
        fs2_changed_raw_status == DMV_OK &&
        memcmp(fs2_cached, fs2_changed_raw, sizeof(fs2_cached)) == 0 &&
        fs3_changed_init_status == DMV_OK && fs3_changed_query_status == DMV_OK &&
        fs3_changed_raw_status == DMV_OK &&
        memcmp(fs3_cached, fs3_changed_raw, sizeof(fs3_cached)) == 0;
    check_result("cache_reinitialize_changed_frozen_input", reinitialized_changed_input);
    dmv_transcript_cache_clear(&fs2_cache);
    dmv_transcript_cache_clear(&fs3_cache);
    const bool cache_zeroed_after_reinit_clear =
        bytes_are_zero((const uint8_t*)&fs2_cache, sizeof(fs2_cache)) &&
        bytes_are_zero((const uint8_t*)&fs3_cache, sizeof(fs3_cache));
    printf("TRANSCRIPT_CACHE_DERIVED fs2_fixed_prefix_bytes=%zu fs3_fixed_prefix_bytes=%zu "
           "fresh_queries_unchanged=1 final_nonce_length_word_preserved=1 fs2_multi_nonce=1 "
           "fs3_multi_nonce=1 reinit_changed_input=%u cache_clear_zeroed=%u\n",
           fs2_fixed_prefix_bytes, fs3_fixed_prefix_bytes, reinitialized_changed_input ? 1u : 0u,
           (cache_zeroed_after_first_clear && cache_zeroed_after_reinit_clear) ? 1u : 0u);
    check_result("cache_clear_zeroes_owned_contexts",
                 cache_zeroed_after_first_clear && cache_zeroed_after_reinit_clear);
    check_result("fs_domains_separated", memcmp(fs1, fs2_raw, sizeof(fs2)) != 0);
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
  dmv_proof_t h0_retry_proof;
  memset(&h0_retry_proof, 0, sizeof(h0_retry_proof));
  probe_rng_t h0_retry_rng;
  memset(&h0_retry_rng, 0, sizeof(h0_retry_rng));
  h0_retry_rng.iv_start = rejected_iv_index;
  h0_retry_rng.final_seed = 0x60u;
  h0_retry_rng.force_final_after = UINT_MAX;
  dmv_retry_counters_t h0_retry_counters;
  memset(&h0_retry_counters, 0, sizeof(h0_retry_counters));
  const unsigned int h0_retry_prover_before = relation_context.prover_calls;
  const int h0_retry_status =
      source_fixture_status == DMV_OK && h0_vectors_found
          ? dmv_prove_ex(&h0_retry_proof, &proof_descriptor, proof_statement,
                         sizeof(proof_statement), proof_witness, packed_witness_bytes,
                         probe_random_bytes, &h0_retry_rng, &source_relation, &relation_context, 1u,
                         &h0_retry_counters, NULL)
          : DMV_ERR_ARGUMENT;
  const unsigned int h0_retry_prover_delta = relation_context.prover_calls - h0_retry_prover_before;
  printf("H0_RETRY_CAP_STATUS status=%d reserved=%llu queries=%llu accepted=%llu rejected=%llu "
         "aborted=%llu rng_failures=%llu root_calls=%u prover_delta=%u zeroed=%u\n",
         h0_retry_status, (unsigned long long)h0_retry_counters.h0_reserved,
         (unsigned long long)h0_retry_counters.h0_queries,
         (unsigned long long)h0_retry_counters.h0_accepted,
         (unsigned long long)h0_retry_counters.h0_rejected,
         (unsigned long long)h0_retry_counters.h0_aborted,
         (unsigned long long)h0_retry_counters.h0_rng_failures, h0_retry_rng.root_calls,
         h0_retry_prover_delta,
         proof_is_zeroed(&h0_retry_proof) ? 1u : 0u);
  check_result("h0_retry_cap_fails_closed",
               h0_retry_status == DMV_ERR_RETRY && proof_is_zeroed(&h0_retry_proof) &&
                   h0_retry_counters.h0_reserved == 1u && h0_retry_counters.h0_queries == 1u &&
                   h0_retry_counters.h0_accepted == 0u && h0_retry_counters.h0_rejected == 1u &&
                   h0_retry_counters.h0_aborted == 0u && h0_retry_counters.h0_rng_failures == 0u &&
                   h0_retry_counters.h0_queries ==
                       h0_retry_counters.h0_accepted + h0_retry_counters.h0_rejected &&
                   h0_retry_counters.h0_reserved ==
                       h0_retry_counters.h0_queries + h0_retry_counters.h0_aborted &&
                   h0_retry_rng.root_calls == 0u && h0_retry_prover_delta == 0u);
  dmv_proof_clear(&h0_retry_proof);
  dmv_proof_t generated_proof;
  memset(&generated_proof, 0, sizeof(generated_proof));
  probe_rng_t proof_rng;
  memset(&proof_rng, 0, sizeof(proof_rng));
  proof_rng.iv_start = accepted_iv_index;
  proof_rng.final_seed = 0x60u;
  proof_rng.force_final_after = UINT_MAX;
  dmv_retry_counters_t proof_counters;
  memset(&proof_counters, 0, sizeof(proof_counters));
  dmv_stage_metrics_t proof_metrics;
  memset(&proof_metrics, 0, sizeof(proof_metrics));
  bool proof_found = false;
  uint8_t invalid_final[DMV_NONCE_BYTES] = {0};
  bool invalid_final_found = false;
  if (source_fixture_status == DMV_OK) {
    const int prove_status = dmv_prove_ex(
        &generated_proof, &proof_descriptor, proof_statement, sizeof(proof_statement),
        proof_witness, packed_witness_bytes, probe_random_bytes, &proof_rng, &source_relation,
         &relation_context, DMV_MAX_FINAL_RETRIES, &proof_counters, &proof_metrics);
    printf("SOURCE_PROVE_STATUS status=%d prover_calls=%u\n", prove_status,
           relation_context.prover_calls);
    printf("DMV_RETRY_COUNTERS h0=%llu/%llu/%llu/%llu/%llu/%llu "
           "fs2=%llu/%llu/%llu/%llu/%llu/%llu fs3=%llu/%llu/%llu/%llu/%llu/%llu\n",
           (unsigned long long)proof_counters.h0_reserved,
           (unsigned long long)proof_counters.h0_queries,
           (unsigned long long)proof_counters.h0_accepted,
           (unsigned long long)proof_counters.h0_rejected,
           (unsigned long long)proof_counters.h0_aborted,
           (unsigned long long)proof_counters.h0_rng_failures,
           (unsigned long long)proof_counters.fs2_reserved,
           (unsigned long long)proof_counters.fs2_queries,
           (unsigned long long)proof_counters.fs2_accepted,
           (unsigned long long)proof_counters.fs2_rejected,
           (unsigned long long)proof_counters.fs2_aborted,
           (unsigned long long)proof_counters.fs2_rng_failures,
           (unsigned long long)proof_counters.fs3_reserved,
           (unsigned long long)proof_counters.fs3_queries,
           (unsigned long long)proof_counters.fs3_accepted,
           (unsigned long long)proof_counters.fs3_rejected,
           (unsigned long long)proof_counters.fs3_aborted,
           (unsigned long long)proof_counters.fs3_rng_failures);
    printf("DMV_STAGE_CLOCK ticks_per_second=%llu h0=%llu commitment=%llu construction=%llu "
           "fs2=%llu relation=%llu fs3=%llu\n",
           (unsigned long long)proof_metrics.clock_ticks_per_second,
           (unsigned long long)proof_metrics.h0_clock_ticks,
           (unsigned long long)proof_metrics.commitment_clock_ticks,
           (unsigned long long)proof_metrics.construction_clock_ticks,
           (unsigned long long)proof_metrics.fs2_clock_ticks,
           (unsigned long long)proof_metrics.relation_clock_ticks,
           (unsigned long long)proof_metrics.fs3_clock_ticks);
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
       const uint64_t verify_started = probe_clock_ticks();
       const int verify_status = dmv_verify(&decoded_proof, &proof_descriptor, proof_statement,
                                           sizeof(proof_statement), &source_relation,
                                           &relation_context);
       printf("E2E_VERIFY_STATUS status=%d clock_ticks=%llu ticks_per_second=%llu\n",
              verify_status, (unsigned long long)probe_elapsed_ticks(verify_started),
              (unsigned long long)CLOCKS_PER_SEC);
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
      uint8_t raw_final_retry[DMV_FS3_SQUEEZE_BYTES];
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
          if (dmv_fs3_raw(raw_final_retry, generated_proof.statement,
                          generated_proof.statement_len, generated_proof.nu, generated_proof.m1,
                          generated_proof.m1_len, generated_proof.sigma1, gamma1_for_retry,
                          generated_proof.m2, generated_proof.m2_len, generated_proof.sigma2,
                          gamma2_for_retry, generated_proof.m3, generated_proof.m3_len,
                          invalid_final) == DMV_OK &&
              (raw_final_retry[DMV_FS3_BYTES] & 0x7fu) != 0u) {
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

  probe_rng_t lifecycle_rng;
  memset(&lifecycle_rng, 0, sizeof(lifecycle_rng));
  lifecycle_rng.iv_start = accepted_iv_index;
  lifecycle_rng.final_seed = 0x60u;
  lifecycle_rng.force_final_after = UINT_MAX;
  const int live_reuse_status =
      dmv_prove(&generated_proof, &proof_descriptor, proof_statement, sizeof(proof_statement),
                proof_witness, packed_witness_bytes, probe_random_bytes, &lifecycle_rng,
                &source_relation, &relation_context, DMV_MAX_FINAL_RETRIES);
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
                &source_relation, &relation_context, DMV_MAX_FINAL_RETRIES);
  check_result("prove_valid_recovery",
               recovered_prove_status == DMV_OK && generated_proof.initialized);
  dmv_proof_clear(&generated_proof);
  dmv_proof_clear(&generated_proof);
  check_result("prove_double_clear_zeroes_destination", proof_is_zeroed(&generated_proof));

  check_result("retry_negative_fixture_found", proof_found && invalid_final_found);
  const bool retry_stage_fixture_ready =
      proof_found && invalid_final_found && proof_counters.fs2_queries != 0u &&
      proof_counters.fs2_queries < (uint64_t)(UINT_MAX - 2u);
  const unsigned int observed_fs2_queries =
      retry_stage_fixture_ready ? (unsigned int)proof_counters.fs2_queries : 0u;
  const unsigned int fs2_cap_fixture = observed_fs2_queries > 1u
                                           ? observed_fs2_queries - 1u
                                           : 0u;
  const unsigned int fs3_cap_fixture = observed_fs2_queries + 1u;
  printf("DMV_LOCAL_RETRY_CAPS h0=%u fs2=%u fs3=%u stage_fixture_ready=%u\n",
         DMV_MAX_H0_RETRIES, DMV_MAX_FS2_RETRIES, DMV_MAX_FS3_RETRIES,
         retry_stage_fixture_ready ? 1u : 0u);

  dmv_proof_t fs2_cap_proof;
  memset(&fs2_cap_proof, 0, sizeof(fs2_cap_proof));
  probe_rng_t fs2_cap_rng;
  memset(&fs2_cap_rng, 0, sizeof(fs2_cap_rng));
  fs2_cap_rng.iv_start = accepted_iv_index;
  fs2_cap_rng.final_seed = 0x60u;
  fs2_cap_rng.force_final_after = UINT_MAX;
  dmv_retry_counters_t fs2_cap_counters;
  memset(&fs2_cap_counters, 0, sizeof(fs2_cap_counters));
  const unsigned int fs2_cap_prover_before = relation_context.prover_calls;
  const int fs2_cap_status =
      retry_stage_fixture_ready
          ? dmv_prove_ex(&fs2_cap_proof, &proof_descriptor, proof_statement,
                         sizeof(proof_statement), proof_witness, packed_witness_bytes,
                         probe_random_bytes, &fs2_cap_rng, &source_relation, &relation_context,
                         fs2_cap_fixture, &fs2_cap_counters, NULL)
          : DMV_ERR_ARGUMENT;
  const unsigned int fs2_cap_prover_delta = relation_context.prover_calls - fs2_cap_prover_before;
  printf("FS2_CAP_STATUS cap=%u status=%d reserved=%llu queries=%llu accepted=%llu rejected=%llu "
         "aborted=%llu rng_failures=%llu root_calls=%u prover_delta=%u zeroed=%u\n",
         fs2_cap_fixture, fs2_cap_status, (unsigned long long)fs2_cap_counters.fs2_reserved,
         (unsigned long long)fs2_cap_counters.fs2_queries,
         (unsigned long long)fs2_cap_counters.fs2_accepted,
         (unsigned long long)fs2_cap_counters.fs2_rejected,
         (unsigned long long)fs2_cap_counters.fs2_aborted,
         (unsigned long long)fs2_cap_counters.fs2_rng_failures, fs2_cap_rng.root_calls,
         fs2_cap_prover_delta, proof_is_zeroed(&fs2_cap_proof) ? 1u : 0u);
  check_result("fs2_cap_reaches_stage_and_fails_closed",
               retry_stage_fixture_ready && fs2_cap_fixture != 0u &&
                   fs2_cap_status == DMV_ERR_RETRY && proof_is_zeroed(&fs2_cap_proof) &&
                   fs2_cap_counters.h0_reserved == 1u && fs2_cap_counters.h0_queries == 1u &&
                   fs2_cap_counters.h0_accepted == 1u && fs2_cap_counters.fs2_reserved == fs2_cap_fixture &&
                   fs2_cap_counters.fs2_queries == fs2_cap_fixture &&
                   fs2_cap_counters.fs2_accepted == 0u &&
                   fs2_cap_counters.fs2_rejected == fs2_cap_fixture &&
                   fs2_cap_counters.fs2_aborted == 0u && fs2_cap_counters.fs2_rng_failures == 0u &&
                   fs2_cap_counters.fs2_queries ==
                       fs2_cap_counters.fs2_accepted + fs2_cap_counters.fs2_rejected &&
                   fs2_cap_counters.fs2_reserved ==
                       fs2_cap_counters.fs2_queries + fs2_cap_counters.fs2_aborted &&
                   fs2_cap_rng.root_calls == 1u && fs2_cap_prover_delta == 0u);
  dmv_proof_clear(&fs2_cap_proof);

  dmv_proof_t fs3_cap_proof;
  memset(&fs3_cap_proof, 0, sizeof(fs3_cap_proof));
  probe_rng_t fs3_cap_rng;
  memset(&fs3_cap_rng, 0, sizeof(fs3_cap_rng));
  fs3_cap_rng.iv_start = accepted_iv_index;
  fs3_cap_rng.final_seed = 0x60u;
  fs3_cap_rng.use_forced_final = retry_stage_fixture_ready;
  fs3_cap_rng.force_final_after = 1u + observed_fs2_queries;
  memcpy(fs3_cap_rng.forced_final, invalid_final, sizeof(invalid_final));
  dmv_retry_counters_t fs3_cap_counters;
  memset(&fs3_cap_counters, 0, sizeof(fs3_cap_counters));
  const unsigned int fs3_cap_prover_before = relation_context.prover_calls;
  const int fs3_cap_status =
      retry_stage_fixture_ready
          ? dmv_prove_ex(&fs3_cap_proof, &proof_descriptor, proof_statement,
                         sizeof(proof_statement), proof_witness, packed_witness_bytes,
                         probe_random_bytes, &fs3_cap_rng, &source_relation, &relation_context,
                         fs3_cap_fixture, &fs3_cap_counters, NULL)
          : DMV_ERR_ARGUMENT;
  const unsigned int fs3_cap_prover_delta = relation_context.prover_calls - fs3_cap_prover_before;
  printf("FS3_CAP_STATUS cap=%u status=%d reserved=%llu queries=%llu accepted=%llu rejected=%llu "
         "aborted=%llu rng_failures=%llu root_calls=%u prover_delta=%u zeroed=%u\n",
         fs3_cap_fixture, fs3_cap_status, (unsigned long long)fs3_cap_counters.fs3_reserved,
         (unsigned long long)fs3_cap_counters.fs3_queries,
         (unsigned long long)fs3_cap_counters.fs3_accepted,
         (unsigned long long)fs3_cap_counters.fs3_rejected,
         (unsigned long long)fs3_cap_counters.fs3_aborted,
         (unsigned long long)fs3_cap_counters.fs3_rng_failures, fs3_cap_rng.root_calls,
         fs3_cap_prover_delta, proof_is_zeroed(&fs3_cap_proof) ? 1u : 0u);
  check_result("fs3_cap_reaches_stage_and_fails_closed",
               retry_stage_fixture_ready && fs3_cap_status == DMV_ERR_RETRY &&
                   proof_is_zeroed(&fs3_cap_proof) && fs3_cap_counters.h0_accepted == 1u &&
                   fs3_cap_counters.fs2_accepted == 1u &&
                   fs3_cap_counters.fs3_reserved == fs3_cap_fixture &&
                   fs3_cap_counters.fs3_queries == fs3_cap_fixture &&
                   fs3_cap_counters.fs3_accepted == 0u &&
                   fs3_cap_counters.fs3_rejected == fs3_cap_fixture &&
                   fs3_cap_counters.fs3_aborted == 0u && fs3_cap_counters.fs3_rng_failures == 0u &&
                   fs3_cap_counters.fs3_queries ==
                       fs3_cap_counters.fs3_accepted + fs3_cap_counters.fs3_rejected &&
                   fs3_cap_counters.fs3_reserved ==
                       fs3_cap_counters.fs3_queries + fs3_cap_counters.fs3_aborted &&
                   fs3_cap_rng.root_calls == 1u && fs3_cap_prover_delta == 1u);
  dmv_proof_clear(&fs3_cap_proof);

  dmv_proof_t h0_rng_proof;
  memset(&h0_rng_proof, 0, sizeof(h0_rng_proof));
  probe_rng_t h0_rng;
  memset(&h0_rng, 0, sizeof(h0_rng));
  h0_rng.iv_start = accepted_iv_index;
  h0_rng.final_seed = 0x60u;
  h0_rng.force_final_after = UINT_MAX;
  h0_rng.fail_h0 = true;
  dmv_retry_counters_t h0_rng_counters;
  memset(&h0_rng_counters, 0, sizeof(h0_rng_counters));
  const unsigned int h0_rng_prover_before = relation_context.prover_calls;
  const int h0_rng_status =
      source_fixture_status == DMV_OK
          ? dmv_prove_ex(&h0_rng_proof, &proof_descriptor, proof_statement,
                         sizeof(proof_statement), proof_witness, packed_witness_bytes,
                         probe_random_bytes, &h0_rng, &source_relation, &relation_context,
                         DMV_MAX_H0_RETRIES, &h0_rng_counters, NULL)
          : DMV_ERR_ARGUMENT;
  const unsigned int h0_rng_prover_delta = relation_context.prover_calls - h0_rng_prover_before;
  printf("H0_RNG_STATUS cap=%u status=%d reserved=%llu queries=%llu accepted=%llu rejected=%llu "
         "aborted=%llu rng_failures=%llu root_calls=%u prover_delta=%u zeroed=%u\n",
         DMV_MAX_H0_RETRIES, h0_rng_status, (unsigned long long)h0_rng_counters.h0_reserved,
         (unsigned long long)h0_rng_counters.h0_queries,
         (unsigned long long)h0_rng_counters.h0_accepted,
         (unsigned long long)h0_rng_counters.h0_rejected,
         (unsigned long long)h0_rng_counters.h0_aborted,
         (unsigned long long)h0_rng_counters.h0_rng_failures, h0_rng.root_calls,
         h0_rng_prover_delta, proof_is_zeroed(&h0_rng_proof) ? 1u : 0u);
  check_result("h0_rng_failure_fails_closed_and_counts_abort",
               source_fixture_status == DMV_OK && h0_rng_status == DMV_ERR_RETRY &&
                   proof_is_zeroed(&h0_rng_proof) && h0_rng_counters.h0_reserved == 1u &&
                   h0_rng_counters.h0_queries == 0u && h0_rng_counters.h0_accepted == 0u &&
                   h0_rng_counters.h0_rejected == 0u && h0_rng_counters.h0_aborted == 1u &&
                   h0_rng_counters.h0_rng_failures == 1u && h0_rng.root_calls == 0u &&
                   h0_rng_prover_delta == 0u);
  dmv_proof_clear(&h0_rng_proof);

  dmv_proof_t fs2_rng_proof;
  memset(&fs2_rng_proof, 0, sizeof(fs2_rng_proof));
  probe_rng_t fs2_rng;
  memset(&fs2_rng, 0, sizeof(fs2_rng));
  fs2_rng.iv_start = accepted_iv_index;
  fs2_rng.final_seed = 0x60u;
  fs2_rng.force_final_after = UINT_MAX;
  fs2_rng.fail_nonce_at_enabled = true;
  fs2_rng.fail_nonce_at = 1u;
  dmv_retry_counters_t fs2_rng_counters;
  memset(&fs2_rng_counters, 0, sizeof(fs2_rng_counters));
  const unsigned int fs2_rng_prover_before = relation_context.prover_calls;
  const int fs2_rng_status =
      source_fixture_status == DMV_OK
          ? dmv_prove_ex(&fs2_rng_proof, &proof_descriptor, proof_statement,
                         sizeof(proof_statement), proof_witness, packed_witness_bytes,
                         probe_random_bytes, &fs2_rng, &source_relation, &relation_context,
                         DMV_MAX_FS2_RETRIES, &fs2_rng_counters, NULL)
          : DMV_ERR_ARGUMENT;
  const unsigned int fs2_rng_prover_delta = relation_context.prover_calls - fs2_rng_prover_before;
  printf("FS2_RNG_STATUS cap=%u status=%d reserved=%llu queries=%llu accepted=%llu rejected=%llu "
         "aborted=%llu rng_failures=%llu root_calls=%u prover_delta=%u zeroed=%u\n",
         DMV_MAX_FS2_RETRIES, fs2_rng_status, (unsigned long long)fs2_rng_counters.fs2_reserved,
         (unsigned long long)fs2_rng_counters.fs2_queries,
         (unsigned long long)fs2_rng_counters.fs2_accepted,
         (unsigned long long)fs2_rng_counters.fs2_rejected,
         (unsigned long long)fs2_rng_counters.fs2_aborted,
         (unsigned long long)fs2_rng_counters.fs2_rng_failures, fs2_rng.root_calls,
         fs2_rng_prover_delta, proof_is_zeroed(&fs2_rng_proof) ? 1u : 0u);
  check_result("fs2_rng_failure_fails_closed_and_counts_abort",
               source_fixture_status == DMV_OK && fs2_rng_status == DMV_ERR_RETRY &&
                   proof_is_zeroed(&fs2_rng_proof) && fs2_rng_counters.h0_accepted == 1u &&
                   fs2_rng_counters.fs2_reserved == 1u && fs2_rng_counters.fs2_queries == 0u &&
                   fs2_rng_counters.fs2_accepted == 0u && fs2_rng_counters.fs2_rejected == 0u &&
                   fs2_rng_counters.fs2_aborted == 1u && fs2_rng_counters.fs2_rng_failures == 1u &&
                   fs2_rng.root_calls == 1u && fs2_rng_prover_delta == 0u);
  dmv_proof_clear(&fs2_rng_proof);

  dmv_proof_t fs3_rng_proof;
  memset(&fs3_rng_proof, 0, sizeof(fs3_rng_proof));
  probe_rng_t fs3_rng;
  memset(&fs3_rng, 0, sizeof(fs3_rng));
  fs3_rng.iv_start = accepted_iv_index;
  fs3_rng.final_seed = 0x60u;
  fs3_rng.fail_nonce_at_enabled = retry_stage_fixture_ready;
  fs3_rng.fail_nonce_at = 1u + observed_fs2_queries;
  fs3_rng.force_final_after = UINT_MAX;
  dmv_retry_counters_t fs3_rng_counters;
  memset(&fs3_rng_counters, 0, sizeof(fs3_rng_counters));
  const unsigned int fs3_rng_prover_before = relation_context.prover_calls;
  const int fs3_rng_status =
      retry_stage_fixture_ready
          ? dmv_prove_ex(&fs3_rng_proof, &proof_descriptor, proof_statement,
                         sizeof(proof_statement), proof_witness, packed_witness_bytes,
                         probe_random_bytes, &fs3_rng, &source_relation, &relation_context,
                         DMV_MAX_FS3_RETRIES, &fs3_rng_counters, NULL)
          : DMV_ERR_ARGUMENT;
  const unsigned int fs3_rng_prover_delta = relation_context.prover_calls - fs3_rng_prover_before;
  printf("FS3_RNG_STATUS cap=%u status=%d reserved=%llu queries=%llu accepted=%llu rejected=%llu "
         "aborted=%llu rng_failures=%llu root_calls=%u prover_delta=%u zeroed=%u\n",
         DMV_MAX_FS3_RETRIES, fs3_rng_status, (unsigned long long)fs3_rng_counters.fs3_reserved,
         (unsigned long long)fs3_rng_counters.fs3_queries,
         (unsigned long long)fs3_rng_counters.fs3_accepted,
         (unsigned long long)fs3_rng_counters.fs3_rejected,
         (unsigned long long)fs3_rng_counters.fs3_aborted,
         (unsigned long long)fs3_rng_counters.fs3_rng_failures, fs3_rng.root_calls,
         fs3_rng_prover_delta, proof_is_zeroed(&fs3_rng_proof) ? 1u : 0u);
  check_result("fs3_rng_failure_fails_closed_and_counts_abort",
               retry_stage_fixture_ready && fs3_rng_status == DMV_ERR_RETRY &&
                   proof_is_zeroed(&fs3_rng_proof) && fs3_rng_counters.h0_accepted == 1u &&
                   fs3_rng_counters.fs2_accepted == 1u && fs3_rng_counters.fs3_reserved == 1u &&
                   fs3_rng_counters.fs3_queries == 0u && fs3_rng_counters.fs3_accepted == 0u &&
                   fs3_rng_counters.fs3_rejected == 0u && fs3_rng_counters.fs3_aborted == 1u &&
                   fs3_rng_counters.fs3_rng_failures == 1u && fs3_rng.root_calls == 1u &&
                   fs3_rng_prover_delta == 1u);
  dmv_proof_clear(&fs3_rng_proof);

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
  probe_secure_clear(commit_nu, sizeof(commit_nu));

  printf("DIRECT_MASK_PROBE_COUNTS passed=%u failed=%u\n", g_passed, g_failed);
  printf("DIRECT_MASK_PROBE_STATUS=%s\n", g_failed == 0 ? "PASS" : "FAIL");
  return g_failed == 0 ? 0 : 1;
}
