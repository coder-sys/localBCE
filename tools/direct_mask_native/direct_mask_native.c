/* SPDX-License-Identifier: MIT */
#include "direct_mask_native.h"

#include "aes.h"
#include "dmc_range_constraints.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Only inverse bytes are consumed by materialization.  The previous private input
 * trace was not read by any caller or verifier, so it is deliberately not allocated. */
typedef struct dmn_sbox_trace {
  uint8_t *inverses;
  size_t count;
  size_t capacity;
} dmn_sbox_trace;

static void dmn_zero(void *pointer, size_t length) {
  volatile uint8_t *cursor = (volatile uint8_t *)pointer;
  while (length != 0) {
    *cursor++ = 0;
    --length;
  }
}

static int dmn_equal(const uint8_t *left, const uint8_t *right, size_t length) {
  if (left == NULL || right == NULL) {
    return 0;
  }
  uint8_t difference = 0;
  for (size_t i = 0; i != length; ++i) {
    difference |= (uint8_t)(left[i] ^ right[i]);
  }
  const int equal = difference == 0;
  dmn_zero(&difference, sizeof(difference));
  return equal;
}

static int dmn_size_mul(size_t left, size_t right, size_t *out) {
  if (out == NULL || (left != 0 && right > SIZE_MAX / left)) {
    return DMN_ERR_ALLOCATION;
  }
  *out = left * right;
  return DMN_OK;
}

static uint64_t dmn_load_u64_le(const uint8_t input[8]) {
  uint64_t value = 0;
  for (unsigned int i = 0; i != 8; ++i) {
    value |= (uint64_t)input[i] << (8u * i);
  }
  const uint64_t output = value;
  dmn_zero(&value, sizeof(value));
  return output;
}

static uint8_t dmn_gf8_mul(uint8_t left, uint8_t right) {
  uint8_t result = 0;
  for (unsigned int i = 0; i != 8; ++i) {
    const uint8_t right_mask = (uint8_t)(0u - (uint32_t)(right & 1u));
    const uint8_t high_mask = (uint8_t)(0u - (uint32_t)(left >> 7));
    result ^= (uint8_t)(left & right_mask);
    left = (uint8_t)((uint8_t)(left << 1) ^ (uint8_t)(0x1bu & high_mask));
    right = (uint8_t)(right >> 1);
  }
  const uint8_t output = result;
  dmn_zero(&result, sizeof(result));
  dmn_zero(&left, sizeof(left));
  dmn_zero(&right, sizeof(right));
  return output;
}

static uint8_t dmn_gf8_inverse(uint8_t value) {
  uint8_t result = 1;
  uint8_t base = value;
  for (unsigned int bit = 0; bit != 8; ++bit) {
    uint8_t product = dmn_gf8_mul(result, base);
    const uint8_t select = (uint8_t)(0u - (uint32_t)((254u >> bit) & 1u));
    result = (uint8_t)((result & (uint8_t)~select) | (product & select));
    base = dmn_gf8_mul(base, base);
    dmn_zero(&product, sizeof(product));
  }
  const uint8_t output = result;
  dmn_zero(&result, sizeof(result));
  dmn_zero(&base, sizeof(base));
  return output;
}

static uint8_t dmn_aes_sbox_from_inverse(uint8_t inverse) {
  const uint8_t output =
      (uint8_t)(inverse ^ (uint8_t)((inverse << 1) | (inverse >> 7)) ^
                (uint8_t)((inverse << 2) | (inverse >> 6)) ^
                (uint8_t)((inverse << 3) | (inverse >> 5)) ^
                (uint8_t)((inverse << 4) | (inverse >> 4)) ^ 0x63u);
  dmn_zero(&inverse, sizeof(inverse));
  return output;
}

static uint8_t dmn_aes_rcon(unsigned int index) {
  uint8_t value = 1;
  for (unsigned int i = 1; i < index; ++i) {
    value = dmn_gf8_mul(value, 2);
  }
  return value;
}

static int dmn_trace_init(dmn_sbox_trace *trace) {
  if (trace == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  memset(trace, 0, sizeof(*trace));
  const size_t capacity = (size_t)DMK_SBOX_COUNT;
  size_t allocation = 0;
  if (capacity == 0 || dmn_size_mul(capacity, sizeof(*trace->inverses), &allocation) != DMN_OK) {
    return DMN_ERR_ALLOCATION;
  }
  trace->capacity = capacity;
  trace->inverses = (uint8_t *)malloc(allocation);
  if (trace->inverses == NULL) {
    dmn_zero(trace->inverses, trace->inverses == NULL ? 0 : trace->capacity);
    free(trace->inverses);
    memset(trace, 0, sizeof(*trace));
    return DMN_ERR_ALLOCATION;
  }
  return DMN_OK;
}

static void dmn_trace_clear(dmn_sbox_trace *trace) {
  if (trace == NULL) {
    return;
  }
  if (trace->inverses != NULL) {
    dmn_zero(trace->inverses, trace->capacity);
  }
  free(trace->inverses);
  memset(trace, 0, sizeof(*trace));
}

static int dmn_trace_sbox(dmn_sbox_trace *trace, uint8_t input, uint8_t *output) {
  if (trace == NULL || output == NULL || trace->inverses == NULL ||
      trace->count >= trace->capacity) {
    return DMN_ERR_ORACLE;
  }
  uint8_t inverse = dmn_gf8_inverse(input);
  trace->inverses[trace->count] = inverse;
  ++trace->count;
  *output = dmn_aes_sbox_from_inverse(inverse);
  dmn_zero(&inverse, sizeof(inverse));
  return DMN_OK;
}

static int dmn_expand_key_trace(const uint8_t key[DMN_ROOT_BYTES], uint8_t expanded[240],
                                dmn_sbox_trace *trace) {
  if (key == NULL || expanded == NULL || trace == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  memcpy(expanded, key, DMN_ROOT_BYTES);
  unsigned int generated = DMN_ROOT_BYTES;
  unsigned int rcon_index = 1;
  uint8_t temporary[4] = {0};
  int status = DMN_OK;
  while (generated < 240u) {
    memcpy(temporary, expanded + generated - 4u, sizeof(temporary));
    if (generated % 32u == 0) {
      uint8_t first = temporary[0];
      if (dmn_trace_sbox(trace, temporary[1], &temporary[0]) != DMN_OK ||
          dmn_trace_sbox(trace, temporary[2], &temporary[1]) != DMN_OK ||
           dmn_trace_sbox(trace, temporary[3], &temporary[2]) != DMN_OK ||
           dmn_trace_sbox(trace, first, &temporary[3]) != DMN_OK) {
        dmn_zero(&first, sizeof(first));
        status = DMN_ERR_ORACLE;
        goto cleanup;
      }
      temporary[0] ^= dmn_aes_rcon(rcon_index++);
      dmn_zero(&first, sizeof(first));
    } else if (generated % 32u == 16u) {
      for (unsigned int i = 0; i != 4; ++i) {
        uint8_t transformed = 0;
        if (dmn_trace_sbox(trace, temporary[i], &transformed) != DMN_OK) {
          dmn_zero(&transformed, sizeof(transformed));
          status = DMN_ERR_ORACLE;
          goto cleanup;
        }
        temporary[i] = transformed;
        dmn_zero(&transformed, sizeof(transformed));
      }
    }
    for (unsigned int i = 0; i != 4; ++i) {
      expanded[generated] = (uint8_t)(expanded[generated - 32u] ^ temporary[i]);
      ++generated;
    }
  }
cleanup:
  dmn_zero(temporary, sizeof(temporary));
  return status;
}

static void dmn_add_round_key(uint8_t state[16], const uint8_t *round_key) {
  for (unsigned int i = 0; i != 16; ++i) {
    state[i] ^= round_key[i];
  }
}

static int dmn_sub_bytes_trace(uint8_t state[16], dmn_sbox_trace *trace) {
  for (unsigned int i = 0; i != 16; ++i) {
    uint8_t transformed = 0;
    if (dmn_trace_sbox(trace, state[i], &transformed) != DMN_OK) {
      return DMN_ERR_ORACLE;
    }
    state[i] = transformed;
  }
  return DMN_OK;
}

static void dmn_shift_rows(uint8_t state[16]) {
  uint8_t shifted[16] = {0};
  for (unsigned int row = 0; row != 4; ++row) {
    for (unsigned int column = 0; column != 4; ++column) {
      shifted[4u * column + row] = state[4u * ((column + row) % 4u) + row];
    }
  }
  memcpy(state, shifted, sizeof(shifted));
  dmn_zero(shifted, sizeof(shifted));
}

static void dmn_mix_columns(uint8_t state[16]) {
  for (unsigned int column = 0; column != 4; ++column) {
    uint8_t *c = state + 4u * column;
    uint8_t a0 = c[0];
    uint8_t a1 = c[1];
    uint8_t a2 = c[2];
    uint8_t a3 = c[3];
    c[0] = (uint8_t)(dmn_gf8_mul(a0, 2) ^ dmn_gf8_mul(a1, 3) ^ a2 ^ a3);
    c[1] = (uint8_t)(a0 ^ dmn_gf8_mul(a1, 2) ^ dmn_gf8_mul(a2, 3) ^ a3);
    c[2] = (uint8_t)(a0 ^ a1 ^ dmn_gf8_mul(a2, 2) ^ dmn_gf8_mul(a3, 3));
    c[3] = (uint8_t)(dmn_gf8_mul(a0, 3) ^ a1 ^ a2 ^ dmn_gf8_mul(a3, 2));
    dmn_zero(&a0, sizeof(a0));
    dmn_zero(&a1, sizeof(a1));
    dmn_zero(&a2, sizeof(a2));
    dmn_zero(&a3, sizeof(a3));
  }
}

static int dmn_encrypt_schedule_trace(const uint8_t expanded[240], const uint8_t plaintext[16],
                                       uint8_t ciphertext[16], dmn_sbox_trace *trace) {
  if (expanded == NULL || plaintext == NULL || ciphertext == NULL || trace == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  uint8_t state[16];
  memcpy(state, plaintext, sizeof(state));
  dmn_add_round_key(state, expanded);
  for (unsigned int round = 1; round != 14; ++round) {
    if (dmn_sub_bytes_trace(state, trace) != DMN_OK) {
      dmn_zero(state, sizeof(state));
      return DMN_ERR_ORACLE;
    }
    dmn_shift_rows(state);
    dmn_mix_columns(state);
    dmn_add_round_key(state, expanded + 16u * round);
  }
  if (dmn_sub_bytes_trace(state, trace) != DMN_OK) {
    dmn_zero(state, sizeof(state));
    return DMN_ERR_ORACLE;
  }
  dmn_shift_rows(state);
  dmn_add_round_key(state, expanded + 16u * 14u);
  memcpy(ciphertext, state, sizeof(state));
  dmn_zero(state, sizeof(state));
  return DMN_OK;
}

static void dmn_counter_block(uint8_t counter[16], const uint8_t iv[16], unsigned int block) {
  memcpy(counter, iv, 16);
  uint32_t low = (uint32_t)counter[0] | ((uint32_t)counter[1] << 8) |
                 ((uint32_t)counter[2] << 16) | ((uint32_t)counter[3] << 24);
  low += block;
  counter[0] = (uint8_t)low;
  counter[1] = (uint8_t)(low >> 8);
  counter[2] = (uint8_t)(low >> 16);
  counter[3] = (uint8_t)(low >> 24);
}

static int dmn_derive_g0(const uint8_t root[DMN_ROOT_BYTES], uint8_t g0[DMN_G0_BYTES]) {
  if (root == NULL || g0 == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  const uint8_t zero_iv[16] = {0};
  prg_4_lambda(root, zero_iv, 0, g0, 256);
  return DMN_OK;
}

static int dmn_derive_g1(const uint8_t key[DMN_ROOT_BYTES], uint8_t g1[DMN_G1_BYTES]) {
  if (key == NULL || g1 == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  uint8_t iv_2pow127[16] = {0};
  iv_2pow127[15] = 0x80;
  prg(key, iv_2pow127, 0, g1, 256, DMN_G1_BYTES);
  dmn_zero(iv_2pow127, sizeof(iv_2pow127));
  return DMN_OK;
}

static int dmn_materialize_aes(const uint8_t root[DMN_ROOT_BYTES], uint8_t g0[DMN_G0_BYTES],
                               uint8_t g1[DMN_G1_BYTES], dmn_sbox_trace *trace) {
  if (root == NULL || g0 == NULL || g1 == NULL || trace == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  uint8_t expanded_root[240] = {0};
  uint8_t expanded_key[240] = {0};
  uint8_t reference_g0[DMN_G0_BYTES] = {0};
  uint8_t reference_g1[DMN_G1_BYTES] = {0};
  uint8_t counter[16] = {0};
  const uint8_t zero_iv[16] = {0};
  uint8_t iv_2pow127[16] = {0};
  iv_2pow127[15] = 0x80;
  int status = dmn_derive_g0(root, g0);
  if (status != DMN_OK || dmn_expand_key_trace(root, expanded_root, trace) != DMN_OK) {
    status = status == DMN_OK ? DMN_ERR_ORACLE : status;
    goto cleanup;
  }
  for (unsigned int block = 0; block != 8; ++block) {
    dmn_counter_block(counter, zero_iv, block);
    if (dmn_encrypt_schedule_trace(expanded_root, counter, reference_g0 + 16u * block,
                                    trace) != DMN_OK) {
      status = DMN_ERR_ORACLE;
      goto cleanup;
    }
  }
  status = dmn_derive_g1(g0, g1);
  if (status != DMN_OK || dmn_expand_key_trace(g0, expanded_key, trace) != DMN_OK) {
    status = status == DMN_OK ? DMN_ERR_ORACLE : status;
    goto cleanup;
  }
  for (unsigned int block = 0; block != 50; ++block) {
    dmn_counter_block(counter, iv_2pow127, block);
    if (dmn_encrypt_schedule_trace(expanded_key, counter, reference_g1 + 16u * block,
                                    trace) != DMN_OK) {
      status = DMN_ERR_ORACLE;
      goto cleanup;
    }
  }
  status = (dmn_equal(g0, reference_g0, sizeof(reference_g0)) &&
            dmn_equal(g1, reference_g1, sizeof(reference_g1)) &&
            trace->count == DMK_SBOX_COUNT)
               ? DMN_OK
               : DMN_ERR_ORACLE;

cleanup:
  dmn_zero(expanded_root, sizeof(expanded_root));
  dmn_zero(expanded_key, sizeof(expanded_key));
  dmn_zero(reference_g0, sizeof(reference_g0));
  dmn_zero(reference_g1, sizeof(reference_g1));
  dmn_zero(counter, sizeof(counter));
  dmn_zero(iv_2pow127, sizeof(iv_2pow127));
  return status;
}

static int dmn_tag_compute(uint8_t output[DMN_T_BYTES], const uint8_t u[DMN_T_BYTES],
                           const uint8_t g0[DMN_G0_BYTES]) {
  if (output == NULL || u == NULL || g0 == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  bf768_t product;
  bf768_t z;
  bf256_t k;
  bf768_load(&product, u);
  bf256_load(&k, g0);
  bf768_mul_256_inplace(&product, &k);
  bf768_load(&z, g0 + 32u);
  bf768_add_inplace(&product, &z);
  bf768_store(output, &product);
  dmn_zero(&product, sizeof(product));
  dmn_zero(&z, sizeof(z));
  dmn_zero(&k, sizeof(k));
  return DMN_OK;
}

static int dmn_instance_validate(const dmk_instance *instance) {
  static const uint8_t source_suite[16] = {
      'S', 'B', 'A', '1', '-', 'S', 'R', 'C', '-', 'C', 'M', 'T', '-', 'v', '1', 0};
  if (instance == NULL || memcmp(instance->source_suite, source_suite, sizeof(source_suite)) != 0) {
    return DMN_ERR_INSTANCE;
  }
  uint8_t nonzero = 0;
  for (size_t i = 0; i != 96; ++i) {
    nonzero |= instance->U[i];
  }
  const int status = nonzero == 0 ? DMN_ERR_INSTANCE : DMN_OK;
  dmn_zero(&nonzero, sizeof(nonzero));
  return status;
}

static int dmn_set_bit(uint8_t *packed, size_t bit, uint8_t value) {
  if (packed == NULL || bit >= DMN_PACKED_WITNESS_BITS) {
    return DMN_ERR_DIMENSION;
  }
  const uint8_t mask = (uint8_t)(1u << (bit % 8u));
  uint8_t value_mask = (uint8_t)(0u - (uint32_t)(value & 1u));
  packed[bit / 8u] = (uint8_t)((packed[bit / 8u] & (uint8_t)~mask) |
                                (value_mask & mask));
  uint8_t invalid = (uint8_t)(value & UINT8_C(0xfe));
  const int status = invalid == 0u ? DMN_OK : DMN_ERR_DIMENSION;
  dmn_zero(&value_mask, sizeof(value_mask));
  dmn_zero(&invalid, sizeof(invalid));
  return status;
}

static int dmn_copy_byte_bits(uint8_t *packed, size_t base, const uint8_t *bytes,
                              size_t byte_count) {
  size_t bit_count = 0;
  if (packed == NULL || bytes == NULL || dmn_size_mul(byte_count, 8u, &bit_count) != DMN_OK ||
      base > DMN_PACKED_WITNESS_BITS || bit_count > DMN_PACKED_WITNESS_BITS - base) {
    return DMN_ERR_DIMENSION;
  }
  int status = DMN_OK;
  for (size_t bit = 0; bit != bit_count; ++bit) {
    if (dmn_set_bit(packed, base + bit,
                    (uint8_t)((bytes[bit / 8u] >> (bit % 8u)) & 1u)) != DMN_OK) {
      status = DMN_ERR_DIMENSION;
    }
  }
  return status;
}

static int dmn_copy_boolean_bits(uint8_t *packed, size_t base, const uint8_t *bits,
                                 size_t bit_count) {
  if (packed == NULL || bits == NULL || base > DMN_PACKED_WITNESS_BITS ||
      bit_count > DMN_PACKED_WITNESS_BITS - base) {
    return DMN_ERR_DIMENSION;
  }
  int status = DMN_OK;
  for (size_t bit = 0; bit != bit_count; ++bit) {
    if (dmn_set_bit(packed, base + bit, bits[bit]) != DMN_OK) {
      status = DMN_ERR_DIMENSION;
    }
  }
  return status;
}

void dmn_clear(dmn_packed_witness *witness) {
  if (witness == NULL) {
    return;
  }
  dmn_zero(witness->bytes, sizeof(witness->bytes));
  memset(witness, 0, sizeof(*witness));
}

int dmn_extend(const dmk_instance *expected, const uint8_t root[DMN_ROOT_BYTES],
               dmn_packed_witness *out) {
  if (out == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  /* Reuse is safe because the caller-owned fixed buffer is cleared first. */
  dmn_clear(out);
  if (expected == NULL || root == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  const int instance_status = dmn_instance_validate(expected);
  if (instance_status != DMN_OK) {
    return instance_status;
  }
  out->byte_count = DMN_PACKED_WITNESS_BYTES;
  out->bit_count = DMN_PACKED_WITNESS_BITS;

  int status = DMN_OK;
  dmn_sbox_trace trace;
  memset(&trace, 0, sizeof(trace));
  uint8_t g0[DMN_G0_BYTES] = {0};
  uint8_t g1[DMN_G1_BYTES] = {0};
  uint8_t expected_t[DMN_T_BYTES] = {0};
  uint64_t values[DMN_VALUE_COUNT] = {0};
  uint8_t range_aux[DMN_RANGE_AUX_BITS] = {0};
  uint32_t out_of_range = 0;
  if (dmn_trace_init(&trace) != DMN_OK) {
    status = DMN_ERR_ALLOCATION;
    goto failure;
  }
  status = dmn_materialize_aes(root, g0, g1, &trace);
  if (status != DMN_OK) {
    goto failure;
  }
  status = dmn_tag_compute(expected_t, expected->U, g0);
  if (status != DMN_OK || !dmn_equal(expected_t, expected->T, sizeof(expected_t))) {
    status = DMN_ERR_ORACLE;
    goto failure;
  }
  if (dmn_copy_byte_bits(out->bytes, 0, root, DMN_ROOT_BYTES) != DMN_OK) {
    status = DMN_ERR_DIMENSION;
    goto failure;
  }
  for (size_t i = 0; i != trace.count; ++i) {
    for (unsigned int bit = 0; bit != 8; ++bit) {
      const uint8_t value = (uint8_t)((trace.inverses[i] >> bit) & 1u);
      if (dmn_set_bit(out->bytes, DMK_INVERSE_BASE + i * 8u + bit, value) != DMN_OK) {
        status = DMN_ERR_DIMENSION;
        goto failure;
      }
    }
  }
  if (dmn_copy_byte_bits(out->bytes, DMK_G0_BASE, g0, sizeof(g0)) != DMN_OK) {
    status = DMN_ERR_DIMENSION;
    goto failure;
  }
  int value_pack_status = DMN_OK;
  for (size_t i = 0; i != DMN_VALUE_COUNT; ++i) {
    uint8_t encoded[8];
    for (size_t byte = 0; byte != sizeof(encoded); ++byte) {
      encoded[byte] = (uint8_t)(expected->C[8u * i + byte] ^ g1[8u * i + byte]);
    }
    values[i] = dmn_load_u64_le(encoded);
    dmn_zero(encoded, sizeof(encoded));
    out_of_range |= (uint32_t)(values[i] < DMK_LOWER);
    out_of_range |= (uint32_t)(values[i] > DMK_UPPER);
    for (unsigned int bit = 0; bit != 64; ++bit) {
      if (dmn_set_bit(out->bytes, DMK_VALUE_BASE + i * 64u + bit,
                      (uint8_t)((values[i] >> bit) & 1u)) != DMN_OK) {
        value_pack_status = DMN_ERR_DIMENSION;
      }
    }
  }
  if (value_pack_status != DMN_OK) {
    status = value_pack_status;
    goto failure;
  }
  if (out_of_range != 0u) {
    status = DMN_ERR_RANGE;
    goto failure;
  }
  status = dmc_range_materialize_aux(values, range_aux, &out_of_range);
  if (status != DMC_RANGE_OK || out_of_range != 0 ||
      dmn_copy_boolean_bits(out->bytes, DMK_RANGE_BASE, range_aux, DMN_RANGE_AUX_BITS) != DMN_OK) {
    status = DMN_ERR_RANGE;
    goto failure;
  }
  dmn_trace_clear(&trace);
  dmn_zero(g0, sizeof(g0));
  dmn_zero(g1, sizeof(g1));
  dmn_zero(expected_t, sizeof(expected_t));
  dmn_zero(values, sizeof(values));
  dmn_zero(range_aux, sizeof(range_aux));
  dmn_zero(&out_of_range, sizeof(out_of_range));
  return DMN_OK;

failure:
  dmn_trace_clear(&trace);
  dmn_zero(g0, sizeof(g0));
  dmn_zero(g1, sizeof(g1));
  dmn_zero(expected_t, sizeof(expected_t));
  dmn_zero(values, sizeof(values));
  dmn_zero(range_aux, sizeof(range_aux));
  dmn_zero(&out_of_range, sizeof(out_of_range));
  dmn_clear(out);
  return status;
}

#ifdef DMN_NATIVE_PROBE
/* Test-only accessors are compiled into the probe implementation, never the
 * production direct_mask_native library or its public header. */
int dmn_native_probe_byte(uint8_t input, uint8_t *inverse, uint8_t *sbox) {
  if (inverse == NULL || sbox == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  *inverse = dmn_gf8_inverse(input);
  *sbox = dmn_aes_sbox_from_inverse(*inverse);
  return DMN_OK;
}

int dmn_native_probe_mul(uint8_t left, uint8_t right, uint8_t *product) {
  if (product == NULL) {
    return DMN_ERR_ARGUMENT;
  }
  *product = dmn_gf8_mul(left, right);
  return DMN_OK;
}
#endif
