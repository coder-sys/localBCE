/* SPDX-License-Identifier: MIT */
#ifndef BL_DIRECT_MASK_ALGEBRA_H
#define BL_DIRECT_MASK_ALGEBRA_H
#include "direct_mask_kernel.h"
#include "universal_hashing.h"
#ifdef __cplusplus
extern "C" {
#endif

#define DMK_VH_CHALLENGE_BYTES 264u
#define DMK_ZK_CHALLENGE_BYTES 104u
#define DMK_MASK_ROWS (DMK_MASK_COUNT * 256u)
#define DMK_MASK_BYTES (DMK_MASK_COUNT * 32u)

/* Pack each consecutive 256-row block with the proof polynomial basis X^i.
 * This is not the AES subfield embedding and is not XOR/parity packing. */
int dmk_pack_mask_rows(const bf256_t *rows, size_t row_count, bf256_t masks[6]);
int dmk_pack_mask_bits(const uint8_t *packed, size_t byte_count, bf256_t masks[6]);

/* Exact pinned VOLEHash on (rows[0..ell),mask0,mask1 ; mask2..mask5),
 * retaining the 64-bit short challenge and all four additive mask lanes. */
int dmk_vh(const uint8_t gamma1[DMK_VH_CHALLENGE_BYTES], const bf256_t *rows,
           size_t row_count, const bf256_t masks[6], bf256_t output[4]);

typedef struct dmk_poly_hash {
  uint8_t gamma2[DMK_ZK_CHALLENGE_BYTES];
  zk_hash_256_ctx coefficient[3];
  uint32_t next_row, expected_rows;
  int error;
} dmk_poly_hash;
/* Clear on caller abort too, including a relation failure before the first sink
 * call. Terminal errors erase the context except for their sticky error code. */
void dmk_poly_hash_clear(dmk_poly_hash *hash);
int dmk_poly_hash_init(dmk_poly_hash *hash, const uint8_t gamma2[DMK_ZK_CHALLENGE_BYTES],
                       uint32_t expected_rows);
/* Direct dmk_coefficient_sink callback. Rejects a nonzero degree-three coefficient. */
int dmk_poly_hash_update(void *hash, uint32_t row, const bf256_t coefficients[4]);
/* a0=H(F0)+vbar0; a1=H(F1)+ubar0+vbar1; a2=H(F2)+ubar1.
 * Every coefficient uses the same raw gamma2, with no additional hash derivation. */
int dmk_poly_hash_finish(dmk_poly_hash *hash, const bf256_t ubar[6],
                         const bf256_t vbar[6], bf256_t a[3]);

typedef struct dmk_eval_hash {
  uint8_t gamma2[DMK_ZK_CHALLENGE_BYTES];
  zk_hash_256_ctx evaluation;
  uint32_t next_row, expected_rows;
  int error;
} dmk_eval_hash;
void dmk_eval_hash_clear(dmk_eval_hash *hash);
int dmk_eval_hash_init(dmk_eval_hash *hash, const uint8_t gamma2[DMK_ZK_CHALLENGE_BYTES],
                       uint32_t expected_rows);
/* Direct dmk_evaluation_sink callback. */
int dmk_eval_hash_update(void *hash, uint32_t row, const bf256_t *value);
/* Checks H(F(Delta))+qbar0+Delta*qbar1 against a0+Delta*a1+Delta^2*a2. */
int dmk_eval_hash_finish(dmk_eval_hash *hash, const bf256_t *mask_term,
                         const bf256_t *expected_b);
#ifdef __cplusplus
}
#endif
#endif
