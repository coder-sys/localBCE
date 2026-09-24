/* SPDX-License-Identifier: MIT */

#include "direct_mask_circuit.h"

#include "aes.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static int bytes_equal(const uint8_t* lhs, const uint8_t* rhs, size_t bytes) {
  return memcmp(lhs, rhs, bytes) == 0;
}

static int field_is_zero(const bf256_t* value) {
  uint8_t bytes[DMC_FIELD_BYTES];
  bf256_store(bytes, value);
  uint8_t accumulator = 0;
  for (size_t i = 0; i != sizeof(bytes); ++i) {
    accumulator |= bytes[i];
  }
  return accumulator == 0;
}

static void field_load(bf256_t* value, const uint8_t bytes[DMC_FIELD_BYTES]) {
  bf256_load(value, bytes);
}

static void field_store(uint8_t bytes[DMC_FIELD_BYTES], const bf256_t* value) {
  bf256_store(bytes, value);
}

static void field_add(bf256_t* output, const bf256_t* lhs, const bf256_t* rhs) {
  bf256_add(output, lhs, rhs);
}

static void field_mul(bf256_t* output, const bf256_t* lhs, const bf256_t* rhs) {
  bf256_mul(output, lhs, rhs);
}

static void field_square(bf256_t* output, const bf256_t* input) {
  bf256_square(output, input);
}

int dmc_descriptor_validate(const dmc_descriptor_t* descriptor) {
  if (descriptor == NULL) {
    return DMC_ERR_ARGUMENT;
  }
  if (descriptor->degree != DMC_RELATION_DEGREE ||
      descriptor->short_challenge_bits != DMC_SHORT_CHALLENGE_BITS) {
    return DMC_ERR_DIMENSION;
  }
  if (descriptor->witness_bits == 0 || descriptor->witness_bits % 8u != 0 ||
      descriptor->witness_bits > DMC_ADMITTED_ELL_MAX || descriptor->constraint_count == 0 ||
      descriptor->constraint_count > DMC_ADMITTED_CONSTRAINT_MAX) {
    return DMC_ERR_DIMENSION;
  }
  if ((uint64_t)descriptor->witness_bits +
          (uint64_t)DMC_DIRECT_MASK_COUNT * 8u * DMC_FIELD_BYTES > UINT32_MAX) {
    return DMC_ERR_DIMENSION;
  }
  return DMC_OK;
}

int dmc_compute_counts(const dmc_descriptor_t* descriptor, dmc_counts_t* counts) {
  if (descriptor == NULL || counts == NULL) {
    return DMC_ERR_ARGUMENT;
  }
  const int descriptor_status = dmc_descriptor_validate(descriptor);
  if (descriptor_status != DMC_OK) {
    return descriptor_status;
  }
  memset(counts, 0, sizeof(*counts));
  counts->direct_mask_rows =
      descriptor->witness_bits + DMC_DIRECT_MASK_COUNT * (8u * DMC_FIELD_BYTES);
  counts->aes_key_schedule_sboxes = 52;
  counts->aes_round_sboxes = 14u * 16u;
  counts->aes_total_sboxes = counts->aes_key_schedule_sboxes + counts->aes_round_sboxes;
  counts->inverse_constraints = counts->aes_total_sboxes * 2u;
  counts->bitness_constraints = counts->aes_total_sboxes * 16u;
  counts->correction_bytes = (uint32_t)(DMC_FAEST_256F_TAU - 1u) * DMC_DIRECT_MASK_COUNT *
                             DMC_FIELD_BYTES;
  counts->lambda = DMC_FAEST_256F_LAMBDA;
  counts->tau = DMC_FAEST_256F_TAU;
  counts->grinding_bits = DMC_FAEST_256F_W_GRIND;
  counts->opening_budget = DMC_FAEST_256F_T_OPEN;
  counts->non_em = 1;
  return DMC_OK;
}

static void counter_aes(const uint8_t key[DMC_FIELD_BYTES], const uint8_t iv[DMC_AES_BLOCK_BYTES],
                        uint8_t* output, size_t output_bytes) {
  aes_round_keys_t round_keys;
  aes256_init_round_keys(&round_keys, key);
  for (size_t block = 0; block != output_bytes / DMC_AES_BLOCK_BYTES; ++block) {
    uint8_t counter[DMC_AES_BLOCK_BYTES];
    memcpy(counter, iv, sizeof(counter));
    uint32_t low = (uint32_t)counter[0] | ((uint32_t)counter[1] << 8) |
                   ((uint32_t)counter[2] << 16) | ((uint32_t)counter[3] << 24);
    low += (uint32_t)block;
    counter[0] = (uint8_t)low;
    counter[1] = (uint8_t)(low >> 8);
    counter[2] = (uint8_t)(low >> 16);
    counter[3] = (uint8_t)(low >> 24);
    aes256_encrypt_block(&round_keys, counter, output + block * DMC_AES_BLOCK_BYTES);
  }
}

int dmc_generate_aesg(const uint8_t root_key[DMC_FIELD_BYTES],
                      uint8_t aesg0[DMC_AESG0_BYTES], uint8_t aesg1[DMC_AESG1_BYTES]) {
  if (root_key == NULL || aesg0 == NULL || aesg1 == NULL) {
    return DMC_ERR_ARGUMENT;
  }
  const uint8_t iv_zero[DMC_AES_BLOCK_BYTES] = {0};
  uint8_t iv_2pow127[DMC_AES_BLOCK_BYTES] = {0};
  iv_2pow127[15] = 0x80;
  prg_4_lambda(root_key, iv_zero, 0, aesg0, 256);
  prg(aesg0, iv_2pow127, 0, aesg1, 256, DMC_AESG1_BYTES);
  return DMC_OK;
}

int dmc_aesg_oracle_check(const uint8_t root_key[DMC_FIELD_BYTES]) {
  if (root_key == NULL) {
    return DMC_ERR_ARGUMENT;
  }
  uint8_t aesg0[DMC_AESG0_BYTES];
  uint8_t aesg1[DMC_AESG1_BYTES];
  uint8_t expected_g0[DMC_AESG0_BYTES];
  uint8_t expected_g1[DMC_AESG1_BYTES];
  if (dmc_generate_aesg(root_key, aesg0, aesg1) != DMC_OK) {
    return DMC_ERR_ORACLE;
  }
  const uint8_t iv_zero[DMC_AES_BLOCK_BYTES] = {0};
  uint8_t iv_2pow127[DMC_AES_BLOCK_BYTES] = {0};
  iv_2pow127[15] = 0x80;
  counter_aes(root_key, iv_zero, expected_g0, sizeof(expected_g0));
  counter_aes(aesg0, iv_2pow127, expected_g1, sizeof(expected_g1));
  if (!bytes_equal(aesg0, expected_g0, sizeof(aesg0)) ||
      !bytes_equal(aesg1, expected_g1, sizeof(aesg1))) {
    return DMC_ERR_ORACLE;
  }
  return DMC_OK;
}

static uint8_t gf8_mul(uint8_t lhs, uint8_t rhs) {
  uint8_t result = 0;
  for (unsigned int i = 0; i != 8; ++i) {
    if ((rhs & 1u) != 0) {
      result ^= lhs;
    }
    const uint8_t high = lhs & 0x80u;
    lhs <<= 1;
    if (high != 0) {
      lhs ^= 0x1bu;
    }
    rhs >>= 1;
  }
  return result;
}

static uint8_t gf8_pow(uint8_t base, uint8_t exponent) {
  uint8_t result = 1;
  while (exponent != 0) {
    if ((exponent & 1u) != 0) {
      result = gf8_mul(result, base);
    }
    base = gf8_mul(base, base);
    exponent >>= 1;
  }
  return result;
}

static uint8_t gf8_inverse(uint8_t value) {
  return value == 0 ? 0 : gf8_pow(value, 254);
}

static uint8_t aes_sbox(uint8_t value) {
  const uint8_t inverse = gf8_inverse(value);
  return (uint8_t)(inverse ^ (uint8_t)((inverse << 1) | (inverse >> 7)) ^
                   (uint8_t)((inverse << 2) | (inverse >> 6)) ^
                   (uint8_t)((inverse << 3) | (inverse >> 5)) ^
                   (uint8_t)((inverse << 4) | (inverse >> 4)) ^ 0x63u);
}

static uint8_t aes_rcon(unsigned int index) {
  uint8_t value = 1;
  for (unsigned int i = 1; i < index; ++i) {
    value = gf8_mul(value, 2);
  }
  return value;
}

static void aes_reference_expand_key(const uint8_t key[DMC_FIELD_BYTES], uint8_t expanded[240]) {
  memcpy(expanded, key, DMC_FIELD_BYTES);
  unsigned int generated = DMC_FIELD_BYTES;
  unsigned int rcon_index = 1;
  uint8_t temporary[4];
  while (generated < 240) {
    memcpy(temporary, expanded + generated - 4, sizeof(temporary));
    if (generated % 32u == 0) {
      const uint8_t first = temporary[0];
      temporary[0] = aes_sbox(temporary[1]);
      temporary[1] = aes_sbox(temporary[2]);
      temporary[2] = aes_sbox(temporary[3]);
      temporary[3] = aes_sbox(first);
      temporary[0] ^= aes_rcon(rcon_index++);
    } else if (generated % 32u == 16u) {
      temporary[0] = aes_sbox(temporary[0]);
      temporary[1] = aes_sbox(temporary[1]);
      temporary[2] = aes_sbox(temporary[2]);
      temporary[3] = aes_sbox(temporary[3]);
    }
    for (unsigned int i = 0; i != 4; ++i) {
      expanded[generated] = (uint8_t)(expanded[generated - 32u] ^ temporary[i]);
      ++generated;
    }
  }
}

static void aes_add_round_key(uint8_t state[16], const uint8_t* round_key) {
  for (unsigned int i = 0; i != 16; ++i) {
    state[i] ^= round_key[i];
  }
}

static void aes_sub_bytes(uint8_t state[16]) {
  for (unsigned int i = 0; i != 16; ++i) {
    state[i] = aes_sbox(state[i]);
  }
}

static void aes_shift_rows(uint8_t state[16]) {
  uint8_t shifted[16];
  for (unsigned int row = 0; row != 4; ++row) {
    for (unsigned int column = 0; column != 4; ++column) {
      shifted[4u * column + row] = state[4u * ((column + row) % 4u) + row];
    }
  }
  memcpy(state, shifted, sizeof(shifted));
}

static void aes_mix_columns(uint8_t state[16]) {
  for (unsigned int column = 0; column != 4; ++column) {
    uint8_t* c = state + 4u * column;
    const uint8_t a0 = c[0];
    const uint8_t a1 = c[1];
    const uint8_t a2 = c[2];
    const uint8_t a3 = c[3];
    c[0] = (uint8_t)(gf8_mul(a0, 2) ^ gf8_mul(a1, 3) ^ a2 ^ a3);
    c[1] = (uint8_t)(a0 ^ gf8_mul(a1, 2) ^ gf8_mul(a2, 3) ^ a3);
    c[2] = (uint8_t)(a0 ^ a1 ^ gf8_mul(a2, 2) ^ gf8_mul(a3, 3));
    c[3] = (uint8_t)(gf8_mul(a0, 3) ^ a1 ^ a2 ^ gf8_mul(a3, 2));
  }
}

void dmc_aes256_reference_encrypt(const uint8_t key[DMC_FIELD_BYTES],
                                  const uint8_t plaintext[DMC_AES_BLOCK_BYTES],
                                  uint8_t ciphertext[DMC_AES_BLOCK_BYTES]) {
  uint8_t expanded[240];
  uint8_t state[16];
  aes_reference_expand_key(key, expanded);
  memcpy(state, plaintext, sizeof(state));
  aes_add_round_key(state, expanded);
  for (unsigned int round = 1; round != 14; ++round) {
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_mix_columns(state);
    aes_add_round_key(state, expanded + 16u * round);
  }
  aes_sub_bytes(state);
  aes_shift_rows(state);
  aes_add_round_key(state, expanded + 16u * 14u);
  memcpy(ciphertext, state, sizeof(state));
}

int dmc_bitness_constraint_ok(uint8_t bit) {
  if (bit > 1u) {
    return 0;
  }
  return (uint8_t)(bit & (uint8_t)(bit ^ 1u)) == 0;
}

int dmc_inverse_constraints_ok(uint8_t input, uint8_t inverse) {
  bf256_t x;
  bf256_t y;
  bf256_t xy;
  bf256_t one = bf256_one();
  bf256_t factor;
  bf256_t first;
  bf256_t second;
  bf256_byte_combine_bits(&x, input);
  bf256_byte_combine_bits(&y, inverse);
  field_mul(&xy, &x, &y);
  field_add(&factor, &xy, &one);
  field_mul(&first, &x, &factor);
  field_mul(&second, &y, &factor);
  return field_is_zero(&first) && field_is_zero(&second);
}

int dmc_aes256_oracle_check(const uint8_t key[DMC_FIELD_BYTES],
                            const uint8_t plaintext[DMC_AES_BLOCK_BYTES],
                            const uint8_t expected[DMC_AES_BLOCK_BYTES]) {
  if (key == NULL || plaintext == NULL || expected == NULL) {
    return DMC_ERR_ARGUMENT;
  }
  aes_round_keys_t round_keys;
  uint8_t native[DMC_AES_BLOCK_BYTES];
  uint8_t reference[DMC_AES_BLOCK_BYTES];
  aes256_init_round_keys(&round_keys, key);
  aes256_encrypt_block(&round_keys, plaintext, native);
  dmc_aes256_reference_encrypt(key, plaintext, reference);
  if (!bytes_equal(native, expected, sizeof(native)) ||
      !bytes_equal(reference, expected, sizeof(reference))) {
    return DMC_ERR_ORACLE;
  }
  for (unsigned int input = 0; input != 256; ++input) {
    const uint8_t inverse = gf8_inverse((uint8_t)input);
    if (!dmc_inverse_constraints_ok((uint8_t)input, inverse)) {
      return DMC_ERR_RELATION;
    }
  }
  return DMC_OK;
}

static void inverse_coefficients(const bf256_t* x0, const bf256_t* x1, const bf256_t* y0,
                                 const bf256_t* y1, bf256_t coefficients[4]) {
  bf256_t x0_squared;
  bf256_t x1_squared;
  field_square(&x0_squared, x0);
  field_square(&x1_squared, x1);
  field_mul(&coefficients[0], &x0_squared, y0);
  field_mul(&coefficients[1], &x0_squared, y1);
  field_mul(&coefficients[2], &x1_squared, y0);
  field_add(&coefficients[2], &coefficients[2], x0);
  field_mul(&coefficients[3], &x1_squared, y1);
  field_add(&coefficients[3], &coefficients[3], x1);
}

static void inverse_y_coefficients(const bf256_t* x0, const bf256_t* x1, const bf256_t* y0,
                                   const bf256_t* y1, bf256_t coefficients[4]) {
  bf256_t y0_squared;
  bf256_t y1_squared;
  field_square(&y0_squared, y0);
  field_square(&y1_squared, y1);
  field_mul(&coefficients[0], x0, &y0_squared);
  field_mul(&coefficients[1], x1, &y0_squared);
  field_mul(&coefficients[2], x0, &y1_squared);
  field_add(&coefficients[2], &coefficients[2], y0);
  field_mul(&coefficients[3], x1, &y1_squared);
  field_add(&coefficients[3], &coefficients[3], y1);
}

static void polynomial_eval(bf256_t* output, const bf256_t coefficients[4], const bf256_t* z) {
  *output = coefficients[3];
  for (int i = 2; i >= 0; --i) {
    field_mul(output, output, z);
    field_add(output, output, &coefficients[i]);
  }
}

static void field_inverse(bf256_t* output, const bf256_t* input) {
  /* a^(2^256-2), written with the exponent's low bit zero and all other bits one. */
  bf256_t result = bf256_one();
  bf256_t base = *input;
  for (unsigned int bit = 0; bit != 256; ++bit) {
    if (bit != 0) {
      field_mul(&result, &result, &base);
    }
    field_square(&base, &base);
  }
  *output = result;
}

int dmc_homogenized_inverse_check(const uint8_t x0[DMC_FIELD_BYTES],
                                  const uint8_t x1[DMC_FIELD_BYTES],
                                  const uint8_t y0[DMC_FIELD_BYTES],
                                  const uint8_t y1[DMC_FIELD_BYTES],
                                  const uint8_t z[DMC_FIELD_BYTES], int* x_leading_zero,
                                  int* y_leading_zero) {
  if (x0 == NULL || x1 == NULL || y0 == NULL || y1 == NULL || z == NULL ||
      x_leading_zero == NULL || y_leading_zero == NULL) {
    return DMC_ERR_ARGUMENT;
  }
  bf256_t x0_field;
  bf256_t x1_field;
  bf256_t y0_field;
  bf256_t y1_field;
  bf256_t z_field;
  field_load(&x0_field, x0);
  field_load(&x1_field, x1);
  field_load(&y0_field, y0);
  field_load(&y1_field, y1);
  field_load(&z_field, z);
  if (field_is_zero(&z_field)) {
    return DMC_ERR_ARGUMENT;
  }

  bf256_t x_coefficients[4];
  bf256_t y_coefficients[4];
  inverse_coefficients(&x0_field, &x1_field, &y0_field, &y1_field, x_coefficients);
  inverse_y_coefficients(&x0_field, &x1_field, &y0_field, &y1_field, y_coefficients);
  *x_leading_zero = field_is_zero(&x_coefficients[3]);
  *y_leading_zero = field_is_zero(&y_coefficients[3]);

  bf256_t x_at_z;
  bf256_t y_at_z;
  field_mul(&x_at_z, &x1_field, &z_field);
  field_add(&x_at_z, &x_at_z, &x0_field);
  field_mul(&y_at_z, &y1_field, &z_field);
  field_add(&y_at_z, &y_at_z, &y0_field);

  bf256_t inverse_z;
  field_inverse(&inverse_z, &z_field);
  bf256_t x_scaled;
  bf256_t y_scaled;
  field_mul(&x_scaled, &x_at_z, &inverse_z);
  field_mul(&y_scaled, &y_at_z, &inverse_z);

  bf256_t xy;
  bf256_t one = bf256_one();
  bf256_t x_factor;
  bf256_t x_value;
  bf256_t y_value;
  field_mul(&xy, &x_scaled, &y_scaled);
  field_add(&x_factor, &xy, &one);
  field_mul(&x_value, &x_scaled, &x_factor);
  field_mul(&y_value, &y_scaled, &x_factor);

  bf256_t z_squared;
  bf256_t z_cubed;
  field_square(&z_squared, &z_field);
  field_mul(&z_cubed, &z_squared, &z_field);
  field_mul(&x_value, &x_value, &z_cubed);
  field_mul(&y_value, &y_value, &z_cubed);

  bf256_t x_polynomial;
  bf256_t y_polynomial;
  polynomial_eval(&x_polynomial, x_coefficients, &z_field);
  polynomial_eval(&y_polynomial, y_coefficients, &z_field);
  return field_is_zero(&x_polynomial) == field_is_zero(&x_value) &&
         field_is_zero(&y_polynomial) == field_is_zero(&y_value) &&
         bytes_equal((const uint8_t*)&x_polynomial, (const uint8_t*)&x_value, sizeof(bf256_t)) &&
         bytes_equal((const uint8_t*)&y_polynomial, (const uint8_t*)&y_value, sizeof(bf256_t))
             ? DMC_OK
             : DMC_ERR_RELATION;
}

void dmc_direct_mask_compute(const uint8_t u[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES],
                             const uint8_t v[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES],
                             const uint8_t delta[DMC_FIELD_BYTES],
                             uint8_t q[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES]) {
  bf256_t delta_field;
  field_load(&delta_field, delta);
  for (unsigned int i = 0; i != DMC_DIRECT_MASK_COUNT; ++i) {
    bf256_t u_field;
    bf256_t v_field;
    bf256_t product;
    bf256_t q_field;
    field_load(&u_field, u[i]);
    field_load(&v_field, v[i]);
    field_mul(&product, &delta_field, &u_field);
    field_add(&q_field, &v_field, &product);
    field_store(q[i], &q_field);
  }
}

int dmc_direct_mask_identity(const uint8_t u[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES],
                             const uint8_t v[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES],
                             const uint8_t delta[DMC_FIELD_BYTES],
                             const uint8_t q[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES]) {
  if (u == NULL || v == NULL || delta == NULL || q == NULL) {
    return DMC_ERR_ARGUMENT;
  }
  uint8_t expected[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES];
  dmc_direct_mask_compute(u, v, delta, expected);
  return bytes_equal((const uint8_t*)expected, (const uint8_t*)q, sizeof(expected)) ? DMC_OK
                                                                                      : DMC_ERR_RELATION;
}

static uint64_t rotate_left64(uint64_t value, unsigned int shift) {
  return shift == 0 ? value : (value << shift) | (value >> (64u - shift));
}

static void keccak_f1600(uint64_t state[25]) {
  static const uint64_t round_constants[24] = {
      UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
      UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
      UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
      UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
      UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
      UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
      UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
      UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
      UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
      UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
      UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
      UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
  };
  static const unsigned int rotations[25] = {
      0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43,
      25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
  };
  for (unsigned int round = 0; round != 24; ++round) {
    uint64_t c[5];
    uint64_t d[5];
    for (unsigned int x = 0; x != 5; ++x) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    for (unsigned int x = 0; x != 5; ++x) {
      d[x] = c[(x + 4) % 5] ^ rotate_left64(c[(x + 1) % 5], 1);
    }
    for (unsigned int y = 0; y != 5; ++y) {
      for (unsigned int x = 0; x != 5; ++x) {
        state[x + 5 * y] ^= d[x];
      }
    }

    uint64_t b[25];
    for (unsigned int y = 0; y != 5; ++y) {
      for (unsigned int x = 0; x != 5; ++x) {
        const unsigned int source = x + 5 * y;
        const unsigned int target = y + 5 * ((2 * x + 3 * y) % 5);
        b[target] = rotate_left64(state[source], rotations[source]);
      }
    }
    for (unsigned int y = 0; y != 5; ++y) {
      for (unsigned int x = 0; x != 5; ++x) {
        state[x + 5 * y] = b[x + 5 * y] ^
                           ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
      }
    }
    state[0] ^= round_constants[round];
  }
}

static uint64_t load_le64(const uint8_t* bytes) {
  uint64_t value = 0;
  for (unsigned int i = 0; i != 8; ++i) {
    value |= (uint64_t)bytes[i] << (8u * i);
  }
  return value;
}

static void shake256_reference(uint8_t* output, size_t output_bytes, const uint8_t* input,
                               size_t input_bytes) {
  enum { RATE_BYTES = 136 };
  uint64_t state[25] = {0};
  while (input_bytes >= RATE_BYTES) {
    for (unsigned int lane = 0; lane != RATE_BYTES / 8; ++lane) {
      state[lane] ^= load_le64(input + 8u * lane);
    }
    keccak_f1600(state);
    input += RATE_BYTES;
    input_bytes -= RATE_BYTES;
  }

  uint8_t block[RATE_BYTES] = {0};
  memcpy(block, input, input_bytes);
  block[input_bytes] ^= 0x1fu;
  block[RATE_BYTES - 1] ^= 0x80u;
  for (unsigned int lane = 0; lane != RATE_BYTES / 8; ++lane) {
    state[lane] ^= load_le64(block + 8u * lane);
  }
  keccak_f1600(state);

  while (output_bytes != 0) {
    const size_t take = output_bytes < RATE_BYTES ? output_bytes : RATE_BYTES;
    for (size_t byte = 0; byte != take; ++byte) {
      output[byte] = (uint8_t)(state[byte / 8] >> (8u * (byte % 8)));
    }
    output += take;
    output_bytes -= take;
    if (output_bytes != 0) {
      keccak_f1600(state);
    }
  }
}

static void write_le32(uint8_t* output, uint32_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8);
  output[2] = (uint8_t)(value >> 16);
  output[3] = (uint8_t)(value >> 24);
}

int dmc_fs_challenge(uint8_t round, const uint8_t* statement, size_t statement_bytes,
                     const uint8_t nu[DMC_FIELD_BYTES], const uint8_t* prior,
                     size_t prior_bytes, const uint8_t nonce[DMC_FS_NONCE_BYTES], uint8_t* output,
                     size_t output_bytes) {
  if (statement == NULL || nu == NULL || prior == NULL || nonce == NULL || output == NULL ||
      output_bytes == 0 || statement_bytes > UINT32_MAX || prior_bytes > UINT32_MAX) {
    return DMC_ERR_ARGUMENT;
  }
  const size_t fixed_bytes = 5u + 4u + DMC_FIELD_BYTES + 4u + DMC_FS_NONCE_BYTES;
  if (statement_bytes > SIZE_MAX - fixed_bytes || prior_bytes > SIZE_MAX - fixed_bytes - statement_bytes) {
    return DMC_ERR_ENCODING;
  }
  const size_t input_bytes = fixed_bytes + statement_bytes + prior_bytes;
  uint8_t* input = (uint8_t*)malloc(input_bytes);
  if (input == NULL) {
    return DMC_ERR_ENCODING;
  }
  size_t offset = 0;
  input[offset++] = 'D';
  input[offset++] = 'M';
  input[offset++] = 'C';
  input[offset++] = round;
  input[offset++] = 1; /* transcript encoding version */
  write_le32(input + offset, (uint32_t)statement_bytes);
  offset += 4;
  memcpy(input + offset, statement, statement_bytes);
  offset += statement_bytes;
  memcpy(input + offset, nu, DMC_FIELD_BYTES);
  offset += DMC_FIELD_BYTES;
  write_le32(input + offset, (uint32_t)prior_bytes);
  offset += 4;
  memcpy(input + offset, prior, prior_bytes);
  offset += prior_bytes;
  memcpy(input + offset, nonce, DMC_FS_NONCE_BYTES);
  shake256_reference(output, output_bytes, input, input_bytes);
  free(input);
  return DMC_OK;
}
