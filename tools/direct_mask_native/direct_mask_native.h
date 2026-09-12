/* SPDX-License-Identifier: MIT */
#ifndef DIRECT_MASK_NATIVE_H
#define DIRECT_MASK_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#include "direct_mask_kernel.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMN_ROOT_BYTES (DMK_R_BITS / 8u)
#define DMN_G0_BYTES 128u
#define DMN_G1_BYTES 800u
#define DMN_T_BYTES 96u
#define DMN_VALUE_COUNT 100u
#define DMN_RANGE_AUX_BITS 12600u
#define DMN_PACKED_WITNESS_BITS DMK_WITNESS_BITS
#define DMN_PACKED_WITNESS_BYTES (DMN_PACKED_WITNESS_BITS / 8u)

typedef enum dmn_result {
  DMN_OK = 0,
  DMN_ERR_ARGUMENT = -1,
  DMN_ERR_INSTANCE = -2,
  DMN_ERR_DIMENSION = -3,
  DMN_ERR_ALLOCATION = -4,
  DMN_ERR_ORACLE = -5,
  DMN_ERR_RANGE = -6,
} dmn_result;

/* The caller owns this fixed output buffer.  A successful result fills exactly 15631
 * bytes containing 125048 little-endian packed Boolean witness bits. */
typedef struct dmn_packed_witness {
  uint8_t bytes[DMN_PACKED_WITNESS_BYTES];
  size_t byte_count;
  size_t bit_count;
} dmn_packed_witness;

/* Materialize only a native witness.  This API has no attacker-controlled callback or
 * verification authority and never derives a secret root from context. */
int dmn_extend(const dmk_instance *expected, const uint8_t root[DMN_ROOT_BYTES],
               dmn_packed_witness *out);
void dmn_clear(dmn_packed_witness *witness);

#ifdef __cplusplus
}
#endif

#endif
