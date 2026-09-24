/* SPDX-License-Identifier: MIT */

#ifndef DMC_RANGE_CONSTRAINTS_H
#define DMC_RANGE_CONSTRAINTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is a small translation boundary for the range relation.  It does not own the parent
 * circuit IR or field arithmetic.  The parent supplies the 640 value-wire indices and translates
 * each record into its native degree-three row representation.
 */
#define DMC_RANGE_VALUE_COUNT 100u
#define DMC_RANGE_VALUE_BITS 64u
#define DMC_RANGE_AUX_BITS_PER_DIRECTION 63u
#define DMC_RANGE_DIRECTIONS 2u
#define DMC_RANGE_AUX_BITS_PER_VALUE \
  (DMC_RANGE_DIRECTIONS * DMC_RANGE_AUX_BITS_PER_DIRECTION)
#define DMC_RANGE_AUX_BITS \
  (DMC_RANGE_VALUE_COUNT * DMC_RANGE_AUX_BITS_PER_VALUE)
#define DMC_RANGE_RECURRENCE_ROWS_PER_DIRECTION \
  (DMC_RANGE_VALUE_COUNT * DMC_RANGE_VALUE_BITS)
#define DMC_RANGE_RECURRENCE_ROWS DMC_RANGE_RECURRENCE_ROWS_PER_DIRECTION
#define DMC_RANGE_RECURSION_ROWS DMC_RANGE_RECURRENCE_ROWS
#define DMC_RANGE_AUX_BITNESS_ROWS DMC_RANGE_AUX_BITS
#define DMC_RANGE_BORROW_ROWS (DMC_RANGE_DIRECTIONS * DMC_RANGE_RECURSION_ROWS)
#define DMC_RANGE_TOTAL_ROWS (DMC_RANGE_AUX_BITNESS_ROWS + DMC_RANGE_BORROW_ROWS)
#define DMC_RANGE_MAX_LINEAR_TERMS 3u
#define DMC_RANGE_NO_INDEX UINT32_MAX

/* Inclusive unsigned 64-bit bounds, encoded here as the circuit constants' LE64 values. */
#define DMC_RANGE_LOWER UINT64_C(0x1122334455667788)
#define DMC_RANGE_UPPER UINT64_C(0xDDEEFF0011223344)

/* Value-wire bitness is a parent-circuit obligation; this module emits only auxiliary bitness. */
#define DMC_RANGE_VALUE_BITNESS_PARENT_OWNED 1u
#define DMC_RANGE_FULL_CIRCUIT_BITS_BOUND 0u

typedef enum dmc_range_direction_t {
  DMC_RANGE_LOWER_BORROW = 0,
  DMC_RANGE_UPPER_BORROW = 1,
} dmc_range_direction_t;

typedef enum dmc_range_result_t {
  DMC_RANGE_OK = 0,
  DMC_RANGE_VALUES_OUT_OF_RANGE = 1,
  DMC_RANGE_ERR_ARGUMENT = -1,
  DMC_RANGE_ERR_DIMENSION = -2,
  DMC_RANGE_ERR_INDEX = -3,
  DMC_RANGE_ERR_CALLBACK = -4,
} dmc_range_result_t;

/*
 * A row is f(w) = constant + sum(linear_indices) + w[monomial_left] * w[monomial_right].
 * The parent evaluates this over its Boolean field.  Both monomial indices are NO_INDEX when the
 * row has no quadratic term.  A row has at most one quadratic term and at most three linear terms.
 * The record is deliberately independent of any larger circuit IR.
 *
 * Degree-three homogenization owned by the parent is exact:
 *   H(rho,Z) = constant*Z^3 + sum(rho[i]*Z^2) + rho[a]*rho[b]*Z.
 * For rho[i] = Z*w[i], H(rho,Z) = Z^3*f(w), including Z=0.  This module does not perform field
 * operations or treat a caller's host comparison as a circuit check.
 */
typedef struct dmc_range_constraint_record_t {
  uint8_t constant;
  uint8_t linear_count;
  uint32_t linear_indices[DMC_RANGE_MAX_LINEAR_TERMS];
  uint32_t monomial_left;
  uint32_t monomial_right;
} dmc_range_constraint_record_t;

typedef int (*dmc_range_emit_fn)(void* context, uint32_t row,
                                 const dmc_range_constraint_record_t* record);

/* Return the contiguous auxiliary index for an internal borrow b_(internal_bit + 1). */
uint32_t dmc_range_aux_index(uint32_t value_slot, dmc_range_direction_t direction,
                             uint32_t internal_bit);

/*
 * Emit rows in the fixed order:
 *   0 .. DMC_RANGE_AUX_BITNESS_ROWS-1: auxiliary bitness, aux index ascending;
 *   then lower-borrow recurrences, value slot ascending and bit l=0..63;
 *   then upper-borrow recurrences, value slot ascending and bit l=0..63.
 *
 * b0 and b64 are fixed zero constants and therefore have no witness index.  The caller's value
 * indices must be distinct, in range, and disjoint from [aux_start, aux_start + DMC_RANGE_AUX_BITS).
 * aux_start + DMC_RANGE_AUX_BITS must fit inside witness_bit_count.  emitted_rows is required and
 * receives the number of callback calls, including a partial prefix when the callback fails.
 */
int dmc_range_emit_constraints(
    const uint32_t value_indices[DMC_RANGE_VALUE_COUNT][DMC_RANGE_VALUE_BITS],
    uint32_t aux_start, uint32_t witness_bit_count, dmc_range_emit_fn emit, void* context,
    uint32_t* emitted_rows);

/*
 * Materialize the 63 internal borrows for both exact inclusive comparisons for every value.  The
 * aux layout is value-major, then lower 63 bits, then upper 63 bits.  The return value is explicit:
 * DMC_RANGE_OK means every value is in range; DMC_RANGE_VALUES_OUT_OF_RANGE means one or more final
 * borrows is nonzero.  An out_of_range_count is required and counts slots with either final borrow.
 * No native unsigned comparison is used by this function.
 */
int dmc_range_materialize_aux(const uint64_t values[DMC_RANGE_VALUE_COUNT],
                              uint8_t aux_bits[DMC_RANGE_AUX_BITS],
                              uint32_t* out_of_range_count);

#ifdef __cplusplus
}
#endif

#endif
