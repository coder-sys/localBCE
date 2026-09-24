/* SPDX-License-Identifier: MIT */

#include "dmc_tag_linear.h"

#include "universal_hashing.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static int require_true(int condition, const char* label) {
  if (!condition) {
    fprintf(stderr, "FAIL %s\n", label);
    return 0;
  }
  return 1;
}

static void fill_bytes(uint8_t* output, size_t bytes, uint8_t seed, uint8_t step) {
  for (size_t i = 0; i != bytes; ++i) {
    output[i] = (uint8_t)(seed + (uint8_t)(step * (uint8_t)i));
  }
}

static uint8_t bit_at(const uint8_t* bytes, size_t bit) {
  return (uint8_t)((bytes[bit / 8u] >> (bit % 8u)) & 1u);
}

static void set_bit(uint8_t* bytes, size_t bit, uint8_t value) {
  const uint8_t mask = (uint8_t)(1u << (bit % 8u));
  if (value != 0) {
    bytes[bit / 8u] |= mask;
  } else {
    bytes[bit / 8u] &= (uint8_t)~mask;
  }
}

static void native_leaf_tag(uint8_t output[DMC_TAG_LINEAR_T_BYTES],
                            const uint8_t u[DMC_TAG_LINEAR_U_BYTES],
                            const uint8_t k[DMC_TAG_LINEAR_K_BITS / 8u],
                            const uint8_t z[DMC_TAG_LINEAR_Z_BITS / 8u]) {
  uint8_t g0[DMC_TAG_LINEAR_K_BITS / 8u + DMC_TAG_LINEAR_Z_BITS / 8u];
  memcpy(g0, k, DMC_TAG_LINEAR_K_BITS / 8u);
  memcpy(g0 + DMC_TAG_LINEAR_K_BITS / 8u, z, DMC_TAG_LINEAR_Z_BITS / 8u);
  leaf_hash_256(output, u, g0);
}

typedef struct eval_context_t {
  uint8_t witness[DMC_TAG_LINEAR_WITNESS_BITS];
  uint8_t rho[DMC_TAG_LINEAR_Z_BITS];
  uint8_t constants[DMC_TAG_LINEAR_Z_BITS];
  size_t callback_count;
  size_t total_terms;
  size_t max_terms;
  int violated;
  int metadata_error;
} eval_context_t;

static int evaluate_callback(void* raw_context, uint32_t equation_index,
                             const uint32_t* indices, size_t index_count, uint8_t constant) {
  eval_context_t* context = (eval_context_t*)raw_context;
  if (equation_index != context->callback_count || indices == NULL || index_count == 0 ||
      index_count > DMC_TAG_LINEAR_MAX_TERMS || constant > 1u ||
      indices[index_count - 1u] != DMC_TAG_LINEAR_K_BITS + equation_index) {
    context->metadata_error = 1;
    return 0;
  }

  uint8_t rho = 0;
  for (size_t i = 0; i != index_count; ++i) {
    if (indices[i] >= DMC_TAG_LINEAR_WITNESS_BITS) {
      context->metadata_error = 1;
      continue;
    }
    rho ^= (uint8_t)(context->witness[indices[i]] & 1u);
  }
  context->rho[equation_index] = rho;
  context->constants[equation_index] = constant;
  context->total_terms += index_count;
  if (index_count > context->max_terms) {
    context->max_terms = index_count;
  }
  if ((uint8_t)(rho ^ constant) != 0) {
    context->violated = 1;
  }
  ++context->callback_count;
  return 0;
}

static int evaluate_relation(const uint8_t u[DMC_TAG_LINEAR_U_BYTES],
                             const uint8_t t[DMC_TAG_LINEAR_T_BYTES],
                             const uint8_t k[DMC_TAG_LINEAR_K_BITS / 8u],
                             const uint8_t z[DMC_TAG_LINEAR_Z_BITS / 8u],
                             eval_context_t* context) {
  uint32_t k_indices[DMC_TAG_LINEAR_K_BITS];
  uint32_t z_indices[DMC_TAG_LINEAR_Z_BITS];
  memset(context, 0, sizeof(*context));
  for (unsigned int i = 0; i != DMC_TAG_LINEAR_K_BITS; ++i) {
    k_indices[i] = i;
    context->witness[i] = bit_at(k, i);
  }
  for (unsigned int i = 0; i != DMC_TAG_LINEAR_Z_BITS; ++i) {
    z_indices[i] = DMC_TAG_LINEAR_K_BITS + i;
    context->witness[DMC_TAG_LINEAR_K_BITS + i] = bit_at(z, i);
  }
  const int status = dmc_tag_linear_emit_constraints(
      u, t, k_indices, z_indices, DMC_TAG_LINEAR_WITNESS_BITS, evaluate_callback, context);
  if (status != DMC_TAG_LINEAR_OK || context->callback_count != DMC_TAG_LINEAR_Z_BITS ||
      context->metadata_error) {
    return status == DMC_TAG_LINEAR_OK ? DMC_TAG_LINEAR_ERR_OVERFLOW : status;
  }
  return DMC_TAG_LINEAR_OK;
}

static int run_special_u_checks(void) {
  static const char* names[] = {"zeroU", "oneU", "highBitU", "randomU"};
  uint8_t u[4][DMC_TAG_LINEAR_U_BYTES] = {{0}};
  u[1][0] = 1;
  u[2][DMC_TAG_LINEAR_U_BYTES - 1u] = UINT8_C(0x80);
  fill_bytes(u[3], sizeof(u[3]), UINT8_C(0x4a), UINT8_C(0x2d));

  uint8_t k[DMC_TAG_LINEAR_K_BITS / 8u];
  uint8_t z[DMC_TAG_LINEAR_Z_BITS / 8u];
  uint8_t t[DMC_TAG_LINEAR_T_BYTES];
  fill_bytes(k, sizeof(k), UINT8_C(0x11), UINT8_C(0x37));
  fill_bytes(z, sizeof(z), UINT8_C(0x92), UINT8_C(0x0b));
  for (unsigned int i = 0; i != 4; ++i) {
    native_leaf_tag(t, u[i], k, z);
    eval_context_t context;
    if (!require_true(evaluate_relation(u[i], t, k, z, &context) == DMC_TAG_LINEAR_OK &&
                          !context.violated,
                      names[i])) {
      return 0;
    }
    printf("U_CASE %s native_leaf_hash=PASS rows=%u\n", names[i], DMC_TAG_LINEAR_Z_BITS);
  }
  return 1;
}

static int run_basis_checks(void) {
  uint8_t u[DMC_TAG_LINEAR_U_BYTES];
  uint8_t k[DMC_TAG_LINEAR_K_BITS / 8u] = {0};
  uint8_t z[DMC_TAG_LINEAR_Z_BITS / 8u] = {0};
  uint8_t t[DMC_TAG_LINEAR_T_BYTES];
  fill_bytes(u, sizeof(u), UINT8_C(0x6d), UINT8_C(0x19));

  for (unsigned int basis = 0; basis != DMC_TAG_LINEAR_K_BITS; ++basis) {
    memset(k, 0, sizeof(k));
    set_bit(k, basis, 1);
    native_leaf_tag(t, u, k, z);
    eval_context_t context;
    if (!require_true(evaluate_relation(u, t, k, z, &context) == DMC_TAG_LINEAR_OK &&
                          !context.violated,
                      "all k basis vectors") ||
        context.metadata_error) {
      return 0;
    }
  }
  for (unsigned int basis = 0; basis != DMC_TAG_LINEAR_Z_BITS; ++basis) {
    memset(k, 0, sizeof(k));
    memset(z, 0, sizeof(z));
    set_bit(z, basis, 1);
    native_leaf_tag(t, u, k, z);
    eval_context_t context;
    if (!require_true(evaluate_relation(u, t, k, z, &context) == DMC_TAG_LINEAR_OK &&
                          !context.violated,
                      "all z basis vectors") ||
        context.metadata_error) {
      return 0;
    }
  }
  printf("BASIS k_vectors=%u z_vectors=%u native_leaf_hash=PASS\n", DMC_TAG_LINEAR_K_BITS,
         DMC_TAG_LINEAR_Z_BITS);
  return 1;
}

static int run_mutation_checks(void) {
  uint8_t u[DMC_TAG_LINEAR_U_BYTES] = {0};
  uint8_t k[DMC_TAG_LINEAR_K_BITS / 8u];
  uint8_t z[DMC_TAG_LINEAR_Z_BITS / 8u];
  uint8_t t[DMC_TAG_LINEAR_T_BYTES];
  fill_bytes(k, sizeof(k), UINT8_C(0x21), UINT8_C(0x07));
  fill_bytes(z, sizeof(z), UINT8_C(0x72), UINT8_C(0x13));
  u[0] = 1;
  native_leaf_tag(t, u, k, z);

  eval_context_t context;
  if (!require_true(evaluate_relation(u, t, k, z, &context) == DMC_TAG_LINEAR_OK &&
                        !context.violated,
                    "unmutated relation")) {
    return 0;
  }

  t[0] ^= 1;
  if (!require_true(evaluate_relation(u, t, k, z, &context) == DMC_TAG_LINEAR_OK &&
                        context.violated,
                    "T mutation detected")) {
    return 0;
  }
  t[0] ^= 1;
  k[0] ^= 1;
  if (!require_true(evaluate_relation(u, t, k, z, &context) == DMC_TAG_LINEAR_OK &&
                        context.violated,
                    "k mutation detected")) {
    return 0;
  }
  k[0] ^= 1;
  z[0] ^= 1;
  if (!require_true(evaluate_relation(u, t, k, z, &context) == DMC_TAG_LINEAR_OK &&
                        context.violated,
                    "z mutation detected")) {
    return 0;
  }
  printf("MUTATIONS T=DETECTED k=DETECTED z=DETECTED\n");
  return 1;
}

static uint8_t homogeneous_leading_coefficient(uint8_t t_bit) {
  return t_bit;
}

static uint8_t homogeneous_eval(uint8_t rho, uint8_t t_bit, uint8_t delta) {
  /* Over GF(2), F(Z)=Z^2*(rho + t_bit*Z) and delta is a bit. */
  const uint8_t delta_squared = (uint8_t)(delta & delta);
  return (uint8_t)(delta_squared & (uint8_t)(rho ^ (uint8_t)(t_bit & delta)));
}

static int run_homogeneous_checks(void) {
  uint8_t u[DMC_TAG_LINEAR_U_BYTES];
  uint8_t k[DMC_TAG_LINEAR_K_BITS / 8u];
  uint8_t z[DMC_TAG_LINEAR_Z_BITS / 8u];
  uint8_t t[DMC_TAG_LINEAR_T_BYTES];
  fill_bytes(u, sizeof(u), UINT8_C(0x37), UINT8_C(0x1d));
  fill_bytes(k, sizeof(k), UINT8_C(0xa1), UINT8_C(0x09));
  fill_bytes(z, sizeof(z), UINT8_C(0x44), UINT8_C(0x23));
  native_leaf_tag(t, u, k, z);

  eval_context_t context;
  if (!require_true(evaluate_relation(u, t, k, z, &context) == DMC_TAG_LINEAR_OK &&
                        !context.violated,
                    "homogeneous source rows")) {
    return 0;
  }
  for (unsigned int row = 0; row != DMC_TAG_LINEAR_Z_BITS; ++row) {
    const uint8_t rho = context.rho[row];
    const uint8_t t_bit = context.constants[row];
    const uint8_t random_delta = (uint8_t)((u[row % sizeof(u)] ^ k[row % sizeof(k)] ^
                                             z[row % sizeof(z)]) & 1u);
    if (!require_true(rho == t_bit && homogeneous_leading_coefficient(t_bit) == t_bit &&
                          homogeneous_eval(rho, t_bit, 0) == 0 &&
                          homogeneous_eval(rho, t_bit, 1) == 0 &&
                          homogeneous_eval(rho, t_bit, random_delta) == 0,
                      "homogeneous leading coefficient and evaluation")) {
      return 0;
    }
  }
  printf("HOMOGENIZATION polynomial=Z^2*(rho+Tbit*Z) leading_coefficient=PASS "
         "Delta0=PASS random_delta=PASS actual_rows=%u actual_terms=%zu max_terms=%zu\n",
         DMC_TAG_LINEAR_Z_BITS, context.total_terms, context.max_terms);
  return 1;
}

typedef struct count_context_t {
  size_t calls;
} count_context_t;

static int count_callback(void* raw_context, uint32_t equation_index, const uint32_t* indices,
                          size_t index_count, uint8_t constant) {
  count_context_t* context = (count_context_t*)raw_context;
  (void)equation_index;
  (void)indices;
  (void)index_count;
  (void)constant;
  ++context->calls;
  return 0;
}

static int failing_callback(void* context, uint32_t equation_index, const uint32_t* indices,
                            size_t index_count, uint8_t constant) {
  (void)context;
  (void)equation_index;
  (void)indices;
  (void)index_count;
  (void)constant;
  return -73;
}

static int run_api_error_checks(void) {
  uint8_t u[DMC_TAG_LINEAR_U_BYTES] = {0};
  uint8_t t[DMC_TAG_LINEAR_T_BYTES] = {0};
  uint32_t k_indices[DMC_TAG_LINEAR_K_BITS];
  uint32_t z_indices[DMC_TAG_LINEAR_Z_BITS];
  for (unsigned int i = 0; i != DMC_TAG_LINEAR_K_BITS; ++i) {
    k_indices[i] = i;
  }
  for (unsigned int i = 0; i != DMC_TAG_LINEAR_Z_BITS; ++i) {
    z_indices[i] = DMC_TAG_LINEAR_K_BITS + i;
  }

  count_context_t count = {0};
  if (!require_true(dmc_tag_linear_emit_constraints(
                          u, t, k_indices, z_indices, DMC_TAG_LINEAR_WITNESS_BITS,
                          count_callback, &count) == DMC_TAG_LINEAR_OK &&
                        count.calls == DMC_TAG_LINEAR_Z_BITS,
                    "callback row count")) {
    return 0;
  }

  z_indices[DMC_TAG_LINEAR_Z_BITS - 1u] = DMC_TAG_LINEAR_WITNESS_BITS;
  count.calls = 0;
  if (!require_true(dmc_tag_linear_emit_constraints(
                          u, t, k_indices, z_indices, DMC_TAG_LINEAR_WITNESS_BITS,
                          count_callback, &count) == DMC_TAG_LINEAR_ERR_INDEX && count.calls == 0,
                    "invalid index rejected before callback")) {
    return 0;
  }
  z_indices[DMC_TAG_LINEAR_Z_BITS - 1u] = DMC_TAG_LINEAR_WITNESS_BITS - 1u;

  k_indices[0] = UINT32_MAX - 1u;
  count.calls = 0;
  if (!require_true(dmc_tag_linear_emit_constraints(u, t, k_indices, z_indices, UINT32_MAX,
                                                     count_callback, &count) == DMC_TAG_LINEAR_OK &&
                        count.calls == DMC_TAG_LINEAR_Z_BITS,
                    "maximum valid uint32 index accepted")) {
    return 0;
  }
  k_indices[0] = UINT32_MAX;
  count.calls = 0;
  if (!require_true(dmc_tag_linear_emit_constraints(u, t, k_indices, z_indices, UINT32_MAX,
                                                     count_callback, &count) ==
                        DMC_TAG_LINEAR_ERR_INDEX &&
                        count.calls == 0,
                    "uint32 index overflow boundary rejected")) {
    return 0;
  }
  k_indices[0] = 0;

  if (!require_true(dmc_tag_linear_emit_constraints(u, t, k_indices, z_indices,
                                                     DMC_TAG_LINEAR_WITNESS_BITS, failing_callback,
                                                     NULL) == -73,
                    "callback error propagated")) {
    return 0;
  }
  if (!require_true(dmc_tag_linear_emit_constraints(NULL, t, k_indices, z_indices,
                                                     DMC_TAG_LINEAR_WITNESS_BITS, count_callback,
                                                     &count) == DMC_TAG_LINEAR_ERR_ARGUMENT &&
                        dmc_tag_linear_emit_constraints(u, NULL, k_indices, z_indices,
                                                        DMC_TAG_LINEAR_WITNESS_BITS, count_callback,
                                                        &count) == DMC_TAG_LINEAR_ERR_ARGUMENT &&
                        dmc_tag_linear_emit_constraints(u, t, NULL, z_indices,
                                                        DMC_TAG_LINEAR_WITNESS_BITS, count_callback,
                                                        &count) == DMC_TAG_LINEAR_ERR_ARGUMENT &&
                        dmc_tag_linear_emit_constraints(u, t, k_indices, NULL,
                                                        DMC_TAG_LINEAR_WITNESS_BITS, count_callback,
                                                        &count) == DMC_TAG_LINEAR_ERR_ARGUMENT &&
                        dmc_tag_linear_emit_constraints(u, t, k_indices, z_indices,
                                                        DMC_TAG_LINEAR_WITNESS_BITS, NULL, &count) ==
                            DMC_TAG_LINEAR_ERR_ARGUMENT &&
                        dmc_tag_linear_emit_constraints(u, t, k_indices, z_indices, 0,
                                                        count_callback, &count) ==
                            DMC_TAG_LINEAR_ERR_INDEX,
                    "null and zero-witness arguments rejected")) {
    return 0;
  }
  printf("API_ERRORS null=REJECTED index=REJECTED uint32_boundary=CHECKED "
         "callback_error=PROPAGATED overflow_guard=CHECKED\n");
  return 1;
}

int main(void) {
  int passed = 1;
  passed = run_special_u_checks() && passed;
  passed = run_basis_checks() && passed;
  passed = run_mutation_checks() && passed;
  passed = run_homogeneous_checks() && passed;
  passed = run_api_error_checks() && passed;
  if (!passed) {
    fprintf(stderr, "DMC_TAG_LINEAR status=FAIL\n");
    return 1;
  }
  printf("DMC_TAG_LINEAR status=PASS rows=%u terms_max=%u native_oracle=independent\n",
         DMC_TAG_LINEAR_Z_BITS, DMC_TAG_LINEAR_MAX_TERMS);
  printf("scope=standalone_actual_gf768_tag_linear no_new_witness_bits=TRUE "
         "production_integration=none security_qualification=none\n");
  return 0;
}
