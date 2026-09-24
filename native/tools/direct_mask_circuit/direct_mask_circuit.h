/* SPDX-License-Identifier: MIT */

#ifndef DIRECT_MASK_CIRCUIT_H
#define DIRECT_MASK_CIRCUIT_H

#include <stddef.h>
#include <stdint.h>

#include "fields.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMC_FIELD_BYTES 32u
#define DMC_AES_BLOCK_BYTES 16u
#define DMC_AESG0_BYTES 128u
#define DMC_AESG1_BYTES 6144u
#define DMC_DIRECT_MASK_COUNT 6u
#define DMC_SHORT_CHALLENGE_BITS 64u
#define DMC_FS1_BYTES 264u /* 8 * 256 + 64 bits */
#define DMC_FS2_BYTES 104u /* 3 * 256 + 64 bits */
#define DMC_FS3_BYTES 32u  /* 256 bits */
#define DMC_FS_NONCE_BYTES 64u
#define DMC_RELATION_DEGREE 3u
#define DMC_ADMITTED_ELL_MAX (1u << 17)
#define DMC_ADMITTED_CONSTRAINT_MAX (1u << 18)

/* Exact FAEST-256F values copied from the pinned vendor meson.build.  The fixture does not
 * compile instances.c because that file requires Meson-generated parameters.h and table headers. */
#define DMC_FAEST_256F_LAMBDA 256u
#define DMC_FAEST_256F_TAU 33u
#define DMC_FAEST_256F_W_GRIND 8u
#define DMC_FAEST_256F_T_OPEN 229u
#define DMC_FAEST_256F_ELL 2208u

typedef enum dmc_status_t {
  DMC_OK = 0,
  DMC_ERR_ARGUMENT = -1,
  DMC_ERR_DIMENSION = -2,
  DMC_ERR_ENCODING = -3,
  DMC_ERR_ORACLE = -4,
  DMC_ERR_RELATION = -5,
  DMC_ERR_TRANSCRIPT = -6,
} dmc_status_t;

/* Generic dimensions are deliberately wider than faest_paramset_t's uint16_t fields. */
typedef struct dmc_descriptor_t {
  uint32_t witness_bits;
  uint32_t constraint_count;
  uint8_t degree;
  uint8_t short_challenge_bits;
} dmc_descriptor_t;

typedef struct dmc_counts_t {
  uint32_t direct_mask_rows;
  uint32_t aes_key_schedule_sboxes;
  uint32_t aes_round_sboxes;
  uint32_t aes_total_sboxes;
  uint32_t inverse_constraints;
  uint32_t bitness_constraints;
  uint32_t correction_bytes;
  uint16_t lambda;
  uint8_t tau;
  uint8_t grinding_bits;
  uint16_t opening_budget;
  uint8_t non_em;
} dmc_counts_t;

int dmc_descriptor_validate(const dmc_descriptor_t* descriptor);
int dmc_compute_counts(const dmc_descriptor_t* descriptor, dmc_counts_t* counts);

/* AESG0/AESG1 are the pinned FAEST AES-256 counter-generator fixtures. */
int dmc_generate_aesg(const uint8_t root_key[DMC_FIELD_BYTES],
                      uint8_t aesg0[DMC_AESG0_BYTES], uint8_t aesg1[DMC_AESG1_BYTES]);
int dmc_aesg_oracle_check(const uint8_t root_key[DMC_FIELD_BYTES]);

/* Independent scalar AES-256 reference, used only to cross-check the pinned native oracle. */
void dmc_aes256_reference_encrypt(const uint8_t key[DMC_FIELD_BYTES],
                                  const uint8_t plaintext[DMC_AES_BLOCK_BYTES],
                                  uint8_t ciphertext[DMC_AES_BLOCK_BYTES]);
int dmc_aes256_oracle_check(const uint8_t key[DMC_FIELD_BYTES],
                            const uint8_t plaintext[DMC_AES_BLOCK_BYTES],
                            const uint8_t expected[DMC_AES_BLOCK_BYTES]);

/* GF(2^8) embedding and the two degree-three inverse constraints. */
int dmc_bitness_constraint_ok(uint8_t bit);
int dmc_inverse_constraints_ok(uint8_t input, uint8_t inverse);

/* Check F(Z)=Z^3 f((v+wZ)/Z) for both inverse constraints. */
int dmc_homogenized_inverse_check(const uint8_t x0[DMC_FIELD_BYTES],
                                  const uint8_t x1[DMC_FIELD_BYTES],
                                  const uint8_t y0[DMC_FIELD_BYTES],
                                  const uint8_t y1[DMC_FIELD_BYTES],
                                  const uint8_t z[DMC_FIELD_BYTES],
                                  int* x_leading_zero, int* y_leading_zero);

/* Compute and verify the six direct field-mask identities q = v + Delta*u. */
void dmc_direct_mask_compute(const uint8_t u[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES],
                             const uint8_t v[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES],
                             const uint8_t delta[DMC_FIELD_BYTES],
                             uint8_t q[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES]);
int dmc_direct_mask_identity(const uint8_t u[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES],
                             const uint8_t v[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES],
                             const uint8_t delta[DMC_FIELD_BYTES],
                             const uint8_t q[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES]);

/* Canonical nonce-bearing full-statement transcript hash. */
int dmc_fs_challenge(uint8_t round, const uint8_t* statement, size_t statement_bytes,
                     const uint8_t nu[DMC_FIELD_BYTES], const uint8_t* prior,
                     size_t prior_bytes, const uint8_t nonce[DMC_FS_NONCE_BYTES], uint8_t* output,
                     size_t output_bytes);

#ifdef __cplusplus
}
#endif

#endif
