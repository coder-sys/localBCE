/* SPDX-License-Identifier: MIT */

#include "dmc_tag_linear.h"

#include <string.h>

enum { DMC_TAG_LINEAR_FIELD_BYTES = DMC_TAG_LINEAR_U_BYTES };

static uint8_t bit_at(const uint8_t value[DMC_TAG_LINEAR_FIELD_BYTES], unsigned int bit) {
  return (uint8_t)((value[bit / 8u] >> (bit % 8u)) & 1u);
}

/* Multiply a GF(2^768) polynomial by x and reduce by
 * x^768 + x^19 + x^17 + x^4 + 1. */
static void gf768_shift_left_one(uint8_t value[DMC_TAG_LINEAR_FIELD_BYTES]) {
  const uint8_t carry = (uint8_t)(value[DMC_TAG_LINEAR_FIELD_BYTES - 1u] >> 7);
  for (size_t byte = DMC_TAG_LINEAR_FIELD_BYTES - 1u; byte != 0; --byte) {
    value[byte] = (uint8_t)((value[byte] << 1) | (value[byte - 1u] >> 7));
  }
  value[0] = (uint8_t)(value[0] << 1);
  if (carry != 0) {
    /* Low bits 0, 4, 17, and 19, in little-endian byte order. */
    value[0] ^= UINT8_C(0x11);
    value[2] ^= UINT8_C(0x0a);
  }
}

static int validate_indices(const uint32_t* indices, size_t count, uint32_t witness_bit_count) {
  for (size_t i = 0; i != count; ++i) {
    if (indices[i] >= witness_bit_count) {
      return DMC_TAG_LINEAR_ERR_INDEX;
    }
  }
  return DMC_TAG_LINEAR_OK;
}

int dmc_tag_linear_emit_constraints(
    const uint8_t u[DMC_TAG_LINEAR_U_BYTES], const uint8_t t[DMC_TAG_LINEAR_T_BYTES],
    const uint32_t k_bit_indices[DMC_TAG_LINEAR_K_BITS],
    const uint32_t z_bit_indices[DMC_TAG_LINEAR_Z_BITS], uint32_t witness_bit_count,
    dmc_tag_linear_emit_fn emit, void* context) {
  if (u == NULL || t == NULL || k_bit_indices == NULL || z_bit_indices == NULL ||
      emit == NULL) {
    return DMC_TAG_LINEAR_ERR_ARGUMENT;
  }

  /* Preflight every caller-owned index so an invalid invocation never emits a prefix. */
  if (validate_indices(k_bit_indices, DMC_TAG_LINEAR_K_BITS, witness_bit_count) !=
          DMC_TAG_LINEAR_OK ||
      validate_indices(z_bit_indices, DMC_TAG_LINEAR_Z_BITS, witness_bit_count) !=
          DMC_TAG_LINEAR_OK) {
    return DMC_TAG_LINEAR_ERR_INDEX;
  }

  /* basis[k] is U*x^k reduced in the pinned GF(2^768) polynomial basis. */
  uint8_t basis[DMC_TAG_LINEAR_K_BITS][DMC_TAG_LINEAR_FIELD_BYTES];
  memcpy(basis[0], u, DMC_TAG_LINEAR_FIELD_BYTES);
  for (unsigned int k = 1; k != DMC_TAG_LINEAR_K_BITS; ++k) {
    memcpy(basis[k], basis[k - 1u], DMC_TAG_LINEAR_FIELD_BYTES);
    gf768_shift_left_one(basis[k]);
  }

  for (uint32_t equation = 0; equation != DMC_TAG_LINEAR_Z_BITS; ++equation) {
    uint32_t indices[DMC_TAG_LINEAR_MAX_TERMS];
    size_t index_count = 0;
    for (unsigned int k = 0; k != DMC_TAG_LINEAR_K_BITS; ++k) {
      if (bit_at(basis[k], equation) != 0) {
        if (index_count >= DMC_TAG_LINEAR_MAX_TERMS) {
          return DMC_TAG_LINEAR_ERR_OVERFLOW;
        }
        indices[index_count++] = k_bit_indices[k];
      }
    }
    if (index_count >= DMC_TAG_LINEAR_MAX_TERMS) {
      return DMC_TAG_LINEAR_ERR_OVERFLOW;
    }
    indices[index_count++] = z_bit_indices[equation];
    if (index_count > DMC_TAG_LINEAR_MAX_TERMS) {
      return DMC_TAG_LINEAR_ERR_OVERFLOW;
    }

    const int callback_status = emit(context, equation, indices, index_count,
                                     bit_at(t, equation));
    if (callback_status != 0) {
      return callback_status;
    }
  }
  return DMC_TAG_LINEAR_OK;
}
