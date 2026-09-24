/*
 * Child-local arithmetic acceleration boundary for the pinned FAEST field API.
 *
 * The public bf256_mul/bf256_mul_inplace symbols are defined by the companion
 * implementation.  The two portable names are supplied by the pinned vendor
 * fields.c translation unit after a per-source symbol rename in CMake; they
 * intentionally remain available as an independently linked reference.
 */

#ifndef DIRECT_MASK_BF256_ACCEL_H
#define DIRECT_MASK_BF256_ACCEL_H

#include "fields.h"

#ifdef __cplusplus
extern "C" {
#endif

void direct_mask_bf256_mul_portable(bf256_t* dst, const bf256_t* lhs, const bf256_t* rhs);
void direct_mask_bf256_mul_inplace_portable(bf256_t* lhs, const bf256_t* rhs);

int direct_mask_bf256_pclmul_available(void);
const char* direct_mask_bf256_backend_name(void);

#ifdef __cplusplus
}
#endif

#endif
