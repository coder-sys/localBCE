/* SPDX-License-Identifier: MIT */
#ifndef BL_DIRECT_MASK_KERNEL_H
#define BL_DIRECT_MASK_KERNEL_H

#include <stddef.h>
#include <stdint.h>
#include "fields.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This is the arithmetic relation only. It is not a proof verifier or a
 * production-qualified suite. All field elements use the pinned FAEST GF256. */
#define DMK_VERSION 1u
#define DMK_R_BITS 256u
#define DMK_SBOX_COUNT 13096u
#define DMK_INVERSE_BASE DMK_R_BITS
#define DMK_G0_BASE (DMK_INVERSE_BASE + 8u * DMK_SBOX_COUNT)
#define DMK_VALUE_BASE (DMK_G0_BASE + 1024u)
#define DMK_RANGE_BASE (DMK_VALUE_BASE + 6400u)
#define DMK_WITNESS_BITS (DMK_RANGE_BASE + 12600u)
#define DMK_CONSTRAINTS 172232u
#define DMK_DEGREE 3u
#define DMK_MASK_COUNT 6u
#define DMK_LOWER UINT64_C(0x1122334455667788)
#define DMK_UPPER UINT64_C(0xddeeff0011223344)

typedef struct dmk_instance {
  uint8_t source_suite[16];
  uint8_t context[64];
  uint8_t U[96];
  uint8_t T[96];
  uint8_t C[800];
} dmk_instance;

typedef struct dmk_counts {
  uint32_t witness_bits;
  uint32_t constraints;
  uint32_t bitness;
  uint32_t inverse;
  uint32_t equality;
  uint32_t tag;
  uint32_t range;
  uint32_t sboxes;
  uint32_t aes_blocks;
  uint32_t key_schedules;
} dmk_counts;

enum dmk_result {
  DMK_OK = 0,
  DMK_ERR_ARGUMENT = -1,
  DMK_ERR_INSTANCE = -2,
  DMK_ERR_DIMENSION = -3,
  DMK_ERR_ALLOCATION = -4,
  DMK_ERR_CALLBACK = -5,
  DMK_ERR_INTERNAL = -6,
  DMK_ERR_WITNESS = -7
};

/* The callback consumes the four actual coefficients of
 * Z^3 f((v+wZ)/Z), including its degree-three coefficient f(w).
 * The row/array are borrowed for this call only. Nonzero callback status is
 * propagated. No source root or witness is passed to the verifier API. */
typedef int (*dmk_coefficient_sink)(void *context, uint32_t row,
                                    const bf256_t coefficients[4]);
typedef int (*dmk_evaluation_sink)(void *context, uint32_t row,
                                   const bf256_t *value);

int dmk_instance_validate(const dmk_instance *instance);
int dmk_instance_matches(const dmk_instance *expected, const dmk_instance *actual);
int dmk_prover_coefficients(const dmk_instance *instance,
                            const uint8_t *witness_bits, size_t witness_count,
                            const bf256_t *v_rows, size_t row_count,
                            dmk_coefficient_sink sink, void *context,
                            dmk_counts *counts);
int dmk_verifier_evaluate(const dmk_instance *expected,
                          const bf256_t *q_prime_rows, size_t row_count,
                          const bf256_t *delta,
                          dmk_evaluation_sink sink, void *context,
                          dmk_counts *counts);

#ifdef __cplusplus
}
#endif
#endif
