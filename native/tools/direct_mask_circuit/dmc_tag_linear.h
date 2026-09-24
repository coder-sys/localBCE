/* SPDX-License-Identifier: MIT */

#ifndef DMC_TAG_LINEAR_H
#define DMC_TAG_LINEAR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The public tag relation is G0_r128 = k32 || z96 and
 * T96 = U96 * embed_low256(k32) + z96 in GF(2^768).  Bytes and bits are
 * little-endian polynomial coefficients, matching the pinned FAEST field API. */
#define DMC_TAG_LINEAR_U_BYTES 96u
#define DMC_TAG_LINEAR_T_BYTES 96u
#define DMC_TAG_LINEAR_K_BITS 256u
#define DMC_TAG_LINEAR_Z_BITS 768u
#define DMC_TAG_LINEAR_WITNESS_BITS (DMC_TAG_LINEAR_K_BITS + DMC_TAG_LINEAR_Z_BITS)
#define DMC_TAG_LINEAR_MAX_TERMS (DMC_TAG_LINEAR_K_BITS + 1u)

typedef enum dmc_tag_linear_status_t {
  DMC_TAG_LINEAR_OK = 0,
  DMC_TAG_LINEAR_ERR_ARGUMENT = -1,
  DMC_TAG_LINEAR_ERR_INDEX = -2,
  DMC_TAG_LINEAR_ERR_OVERFLOW = -3,
} dmc_tag_linear_status_t;

/*
 * Emit one equation in row order.  `indices` contains the selected k witness
 * indices in increasing k-bit order, followed by z_bit_indices[equation_index].
 * `constant` is the public T bit and the equation is XOR(indices) XOR constant = 0.
 * A nonzero callback return is propagated verbatim by dmc_tag_linear_emit_constraints.
 */
typedef int (*dmc_tag_linear_emit_fn)(void* context, uint32_t equation_index,
                                      const uint32_t* indices, size_t index_count,
                                      uint8_t constant);

/*
 * Emit the exact 768-row binary linear relation.  The function allocates no
 * witness bits and does not own the supplied index arrays.  All indices must
 * be strictly below witness_bit_count; validation completes before the first
 * callback is made.
 */
int dmc_tag_linear_emit_constraints(
    const uint8_t u[DMC_TAG_LINEAR_U_BYTES], const uint8_t t[DMC_TAG_LINEAR_T_BYTES],
    const uint32_t k_bit_indices[DMC_TAG_LINEAR_K_BITS],
    const uint32_t z_bit_indices[DMC_TAG_LINEAR_Z_BITS], uint32_t witness_bit_count,
    dmc_tag_linear_emit_fn emit, void* context);

#ifdef __cplusplus
}
#endif

#endif
