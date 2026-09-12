/* SPDX-License-Identifier: MIT */

#include "dmc_range_constraints.h"

#include <stddef.h>
#include <string.h>

static uint8_t lower_borrow_step(uint8_t value_bit, uint8_t constant_bit, uint8_t borrow) {
  /* b' = (1 + v)b for L_l=0, and b' = 1 + v + vb for L_l=1, in characteristic two. */
  if (constant_bit == 0u) {
    return (uint8_t)(((uint8_t)(1u ^ value_bit)) & borrow);
  }
  return (uint8_t)(1u ^ value_bit ^ (uint8_t)(value_bit & borrow));
}

static uint8_t upper_borrow_step(uint8_t value_bit, uint8_t constant_bit, uint8_t borrow) {
  /* b' = v + b + vb for U_l=0, and b' = vb for U_l=1, in characteristic two. */
  if (constant_bit == 0u) {
    return (uint8_t)(value_bit ^ borrow ^ (uint8_t)(value_bit & borrow));
  }
  return (uint8_t)(value_bit & borrow);
}

static uint8_t bound_bit(uint64_t bound, uint32_t bit) {
  return (uint8_t)((bound >> bit) & UINT64_C(1));
}

static uint8_t value_bit(uint64_t value, uint32_t bit) {
  return (uint8_t)((value >> bit) & UINT64_C(1));
}

uint32_t dmc_range_aux_index(uint32_t value_slot, dmc_range_direction_t direction,
                             uint32_t internal_bit) {
  if (value_slot >= DMC_RANGE_VALUE_COUNT || direction >= DMC_RANGE_DIRECTIONS ||
      internal_bit >= DMC_RANGE_AUX_BITS_PER_DIRECTION) {
    return DMC_RANGE_NO_INDEX;
  }
  return value_slot * DMC_RANGE_AUX_BITS_PER_VALUE +
         (uint32_t)direction * DMC_RANGE_AUX_BITS_PER_DIRECTION + internal_bit;
}

static int index_is_in_aux_range(uint32_t index, uint32_t aux_start, uint64_t aux_end) {
  return (uint64_t)index >= (uint64_t)aux_start && (uint64_t)index < aux_end;
}

static int validate_layout(
    const uint32_t value_indices[DMC_RANGE_VALUE_COUNT][DMC_RANGE_VALUE_BITS],
    uint32_t aux_start, uint32_t witness_bit_count) {
  if (value_indices == NULL) {
    return DMC_RANGE_ERR_ARGUMENT;
  }
  /* Guard the subtraction before use to distinguish a bad start from an end overflow. */
  if (aux_start > witness_bit_count) {
    return DMC_RANGE_ERR_INDEX;
  }
  if ((uint64_t)DMC_RANGE_AUX_BITS >
      (uint64_t)witness_bit_count - (uint64_t)aux_start) {
    return DMC_RANGE_ERR_DIMENSION;
  }

  const uint64_t aux_end = (uint64_t)aux_start + (uint64_t)DMC_RANGE_AUX_BITS;
  uint32_t seen[DMC_RANGE_VALUE_COUNT * DMC_RANGE_VALUE_BITS];
  size_t seen_count = 0;
  for (uint32_t slot = 0; slot != DMC_RANGE_VALUE_COUNT; ++slot) {
    for (uint32_t bit = 0; bit != DMC_RANGE_VALUE_BITS; ++bit) {
      const uint32_t index = value_indices[slot][bit];
      if (index >= witness_bit_count || index_is_in_aux_range(index, aux_start, aux_end)) {
        return DMC_RANGE_ERR_INDEX;
      }
      for (size_t prior = 0; prior != seen_count; ++prior) {
        if (seen[prior] == index) {
          return DMC_RANGE_ERR_INDEX;
        }
      }
      seen[seen_count++] = index;
    }
  }
  return DMC_RANGE_OK;
}

static void record_init(dmc_range_constraint_record_t* record) {
  memset(record, 0, sizeof(*record));
  record->monomial_left = DMC_RANGE_NO_INDEX;
  record->monomial_right = DMC_RANGE_NO_INDEX;
}

static int record_add_linear(dmc_range_constraint_record_t* record, uint32_t index) {
  if (index == DMC_RANGE_NO_INDEX) {
    return DMC_RANGE_OK;
  }
  if (record->linear_count >= DMC_RANGE_MAX_LINEAR_TERMS) {
    return DMC_RANGE_ERR_DIMENSION;
  }
  record->linear_indices[record->linear_count++] = index;
  return DMC_RANGE_OK;
}

static int record_add_monomial(dmc_range_constraint_record_t* record, uint32_t left,
                               uint32_t right) {
  if (left == DMC_RANGE_NO_INDEX || right == DMC_RANGE_NO_INDEX) {
    return DMC_RANGE_OK;
  }
  record->monomial_left = left;
  record->monomial_right = right;
  return DMC_RANGE_OK;
}

static uint32_t borrow_index(uint32_t aux_start, uint32_t slot,
                              dmc_range_direction_t direction, int32_t borrow_number) {
  if (borrow_number <= 0 || borrow_number >= (int32_t)DMC_RANGE_VALUE_BITS) {
    return DMC_RANGE_NO_INDEX;
  }
  const uint32_t internal_bit = (uint32_t)borrow_number - 1u;
  return aux_start + dmc_range_aux_index(slot, direction, internal_bit);
}

static int build_borrow_record(
    const uint32_t value_indices[DMC_RANGE_VALUE_COUNT][DMC_RANGE_VALUE_BITS], uint32_t aux_start,
    uint32_t slot, dmc_range_direction_t direction, uint32_t bit,
    dmc_range_constraint_record_t* record) {
  const uint64_t bound = direction == DMC_RANGE_LOWER_BORROW ? DMC_RANGE_LOWER : DMC_RANGE_UPPER;
  const uint32_t value_index = value_indices[slot][bit];
  const uint32_t borrow_in = borrow_index(aux_start, slot, direction, (int32_t)bit);
  const uint32_t borrow_out = borrow_index(aux_start, slot, direction, (int32_t)bit + 1);
  const uint8_t constant_bit = bound_bit(bound, bit);

  record_init(record);
  if (direction == DMC_RANGE_LOWER_BORROW) {
    if (constant_bit == 0u) {
      if (record_add_linear(record, borrow_out) != DMC_RANGE_OK ||
          record_add_linear(record, borrow_in) != DMC_RANGE_OK ||
          record_add_monomial(record, value_index, borrow_in) != DMC_RANGE_OK) {
        return DMC_RANGE_ERR_DIMENSION;
      }
    } else {
      record->constant = 1u;
      if (record_add_linear(record, borrow_out) != DMC_RANGE_OK ||
          record_add_linear(record, value_index) != DMC_RANGE_OK ||
          record_add_monomial(record, value_index, borrow_in) != DMC_RANGE_OK) {
        return DMC_RANGE_ERR_DIMENSION;
      }
    }
  } else if (constant_bit == 0u) {
    if (record_add_linear(record, borrow_out) != DMC_RANGE_OK ||
        record_add_linear(record, value_index) != DMC_RANGE_OK ||
        record_add_linear(record, borrow_in) != DMC_RANGE_OK ||
        record_add_monomial(record, value_index, borrow_in) != DMC_RANGE_OK) {
      return DMC_RANGE_ERR_DIMENSION;
    }
  } else {
    if (record_add_linear(record, borrow_out) != DMC_RANGE_OK ||
        record_add_monomial(record, value_index, borrow_in) != DMC_RANGE_OK) {
      return DMC_RANGE_ERR_DIMENSION;
    }
  }
  return DMC_RANGE_OK;
}

static int emit_one(dmc_range_emit_fn emit, void* context, uint32_t* row,
                    const dmc_range_constraint_record_t* record) {
  if (emit(context, *row, record) != 0) {
    return DMC_RANGE_ERR_CALLBACK;
  }
  ++*row;
  return DMC_RANGE_OK;
}

int dmc_range_emit_constraints(
    const uint32_t value_indices[DMC_RANGE_VALUE_COUNT][DMC_RANGE_VALUE_BITS],
    uint32_t aux_start, uint32_t witness_bit_count, dmc_range_emit_fn emit, void* context,
    uint32_t* emitted_rows) {
  if (emitted_rows == NULL || emit == NULL) {
    return DMC_RANGE_ERR_ARGUMENT;
  }
  *emitted_rows = 0;
  const int layout_status = validate_layout(value_indices, aux_start, witness_bit_count);
  if (layout_status != DMC_RANGE_OK) {
    return layout_status;
  }

  dmc_range_constraint_record_t record;
  uint32_t row = 0;
  for (uint32_t aux = 0; aux != DMC_RANGE_AUX_BITS; ++aux) {
    record_init(&record);
    if (record_add_linear(&record, aux_start + aux) != DMC_RANGE_OK ||
        record_add_monomial(&record, aux_start + aux, aux_start + aux) != DMC_RANGE_OK) {
      return DMC_RANGE_ERR_DIMENSION;
    }
    const int status = emit_one(emit, context, &row, &record);
    if (status != DMC_RANGE_OK) {
      *emitted_rows = row;
      return status;
    }
  }

  for (dmc_range_direction_t direction = DMC_RANGE_LOWER_BORROW;
       direction <= DMC_RANGE_UPPER_BORROW; ++direction) {
    for (uint32_t slot = 0; slot != DMC_RANGE_VALUE_COUNT; ++slot) {
      for (uint32_t bit = 0; bit != DMC_RANGE_VALUE_BITS; ++bit) {
        if (build_borrow_record(value_indices, aux_start, slot, direction, bit, &record) !=
            DMC_RANGE_OK) {
          return DMC_RANGE_ERR_DIMENSION;
        }
        const int status = emit_one(emit, context, &row, &record);
        if (status != DMC_RANGE_OK) {
          *emitted_rows = row;
          return status;
        }
      }
    }
  }
  *emitted_rows = row;
  return row == DMC_RANGE_TOTAL_ROWS ? DMC_RANGE_OK : DMC_RANGE_ERR_DIMENSION;
}

int dmc_range_materialize_aux(const uint64_t values[DMC_RANGE_VALUE_COUNT],
                              uint8_t aux_bits[DMC_RANGE_AUX_BITS],
                              uint32_t* out_of_range_count) {
  if (values == NULL || aux_bits == NULL || out_of_range_count == NULL) {
    return DMC_RANGE_ERR_ARGUMENT;
  }
  *out_of_range_count = 0;
  for (uint32_t slot = 0; slot != DMC_RANGE_VALUE_COUNT; ++slot) {
    const uint32_t base = slot * DMC_RANGE_AUX_BITS_PER_VALUE;
    uint8_t lower_borrow = 0;
    uint8_t upper_borrow = 0;
    for (uint32_t bit = 0; bit != DMC_RANGE_VALUE_BITS; ++bit) {
      const uint8_t current = value_bit(values[slot], bit);
      lower_borrow = lower_borrow_step(current, bound_bit(DMC_RANGE_LOWER, bit), lower_borrow);
      upper_borrow = upper_borrow_step(current, bound_bit(DMC_RANGE_UPPER, bit), upper_borrow);
      if (bit < DMC_RANGE_AUX_BITS_PER_DIRECTION) {
        aux_bits[base + bit] = lower_borrow;
        aux_bits[base + DMC_RANGE_AUX_BITS_PER_DIRECTION + bit] = upper_borrow;
      }
    }
    if (lower_borrow != 0u || upper_borrow != 0u) {
      ++*out_of_range_count;
    }
  }
  return *out_of_range_count == 0 ? DMC_RANGE_OK : DMC_RANGE_VALUES_OUT_OF_RANGE;
}
