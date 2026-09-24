/* SPDX-License-Identifier: MIT */
#include "direct_mask_kernel.h"
#include "../direct_mask_circuit/dmc_tag_linear.h"
#include "../direct_mask_circuit/dmc_range_constraints.h"

#include <stdlib.h>
#include <string.h>

/* Every AES wire is an affine polynomial a+bZ in prover mode. In verifier
 * mode a is its value at Delta and b is unused. Nonlinear constraints are
 * emitted at the S-box boundary; the S-box output uses authenticated inverse
 * witness bits. Thus AES is never evaluated on a reconstructed secret root. */
typedef struct linear_wire { bf256_t a, b; } linear_wire;
typedef struct aes_byte { linear_wire bits[8]; } aes_byte;
typedef struct kernel_state {
  const dmk_instance *instance;
  const uint8_t *w;
  const bf256_t *v_or_q;
  int verifier;
  bf256_t delta, delta2, delta3;
  uint32_t next_inverse;
  int error;
  dmk_coefficient_sink coefficient_sink;
  dmk_evaluation_sink evaluation_sink;
  void *sink_context;
  dmk_counts counts;
  bf256_t byte_basis[8];
  aes_byte round_key[240];
  aes_byte state[16];
} kernel_state;

static void erase(void *pointer, size_t length) {
  volatile uint8_t *p = (volatile uint8_t *)pointer;
  while (length--) *p++ = 0;
}
static bf256_t add(bf256_t x, bf256_t y) {
  bf256_t r; bf256_add(&r, &x, &y); return r;
}
static bf256_t mul(bf256_t x, bf256_t y) {
  bf256_t r; bf256_mul(&r, &x, &y); return r;
}
static bf256_t square(bf256_t x) {
  bf256_t r; bf256_square(&r, &x); return r;
}
static linear_wire linear_zero(void) {
  linear_wire r; r.a = bf256_zero(); r.b = bf256_zero(); return r;
}
static linear_wire linear_add(linear_wire x, linear_wire y) {
  linear_wire r; r.a = add(x.a, y.a); r.b = add(x.b, y.b); return r;
}
static linear_wire constant_wire(const kernel_state *s, uint8_t bit) {
  linear_wire r = linear_zero();
  if (s->verifier) {
    if (bit) r.a = s->delta;
  } else {
    r.b = bf256_from_bit(bit);
  }
  return r;
}
static linear_wire witness_wire(kernel_state *s, uint32_t index) {
  linear_wire r = linear_zero();
  if (index >= DMK_WITNESS_BITS) {
    s->error = DMK_ERR_INTERNAL;
    return r;
  }
  r.a = s->v_or_q[index];
  if (!s->verifier) r.b = bf256_from_bit(s->w[index]);
  return r;
}

static int emit(kernel_state *s, const bf256_t f[4], uint32_t *category) {
  if (s->error) return s->error;
  if (s->counts.constraints >= DMK_CONSTRAINTS) {
    s->error = DMK_ERR_INTERNAL; return s->error;
  }
  const uint32_t row = s->counts.constraints++;
  ++*category;
  int result = s->verifier
      ? s->evaluation_sink(s->sink_context, row, &f[0])
      : s->coefficient_sink(s->sink_context, row, f);
  if (result) s->error = result;
  return result;
}

/* Emit Z^2*l(Z), where l already includes each public constant times Z. */
static int emit_linear(kernel_state *s, linear_wire l, uint32_t *category) {
  bf256_t f[4] = {bf256_zero(), bf256_zero(), bf256_zero(), bf256_zero()};
  if (s->verifier) f[0] = mul(s->delta2, l.a);
  else { f[2] = l.a; f[3] = l.b; }
  int result = emit(s, f, category);
  erase(f, sizeof(f));
  return result;
}

/* Emit Z*x(Z)*y(Z)+Z^2*l(Z), the general quadratic range row. */
static int emit_quadratic(kernel_state *s, linear_wire x, linear_wire y,
                          linear_wire l, uint32_t *category) {
  bf256_t f[4] = {bf256_zero(), bf256_zero(), bf256_zero(), bf256_zero()};
  if (s->verifier) {
    f[0] = add(mul(s->delta, mul(x.a, y.a)), mul(s->delta2, l.a));
  } else {
    f[1] = mul(x.a, y.a);
    f[2] = add(add(mul(x.a, y.b), mul(x.b, y.a)), l.a);
    f[3] = add(mul(x.b, y.b), l.b);
  }
  int result = emit(s, f, category);
  erase(f, sizeof(f));
  return result;
}

static int emit_bitness(kernel_state *s, uint32_t index) {
  linear_wire x = witness_wire(s, index);
  /* x(x+1)=0 homogenizes to Z*x(Z)^2+Z^2*x(Z). */
  bf256_t f[4] = {bf256_zero(), bf256_zero(), bf256_zero(), bf256_zero()};
  if (s->verifier) {
    f[0] = add(mul(s->delta, square(x.a)), mul(s->delta2, x.a));
  } else {
    f[1] = square(x.a); f[2] = x.a;
    f[3] = add(square(x.b), x.b);
  }
  int result = emit(s, f, &s->counts.bitness);
  erase(f, sizeof(f));
  return result;
}

static void initialize_byte_embedding_basis(bf256_t basis[8]) {
  for (unsigned i = 0; i < 8; ++i)
    bf256_byte_combine_bits(&basis[i], (uint8_t)(1u << i));
}
static linear_wire embed_byte(const aes_byte *byte, const bf256_t basis[8]) {
  linear_wire result;
  result.a = byte->bits[0].a;
  result.b = byte->bits[0].b;
  bf256_t product;
  for (unsigned i = 1; i < 8; ++i) {
    bf256_mul(&product, &byte->bits[i].a, &basis[i]);
    bf256_add_inplace(&result.a, &product);
    bf256_mul(&product, &byte->bits[i].b, &basis[i]);
    bf256_add_inplace(&result.b, &product);
  }
  erase(&product, sizeof(product));
  return result;
}

/* x*(x*y+1)=0, including x=y=0. Both equations are mandatory. */
static int emit_inverse(kernel_state *s, linear_wire x, linear_wire y) {
  bf256_t f[4] = {bf256_zero(), bf256_zero(), bf256_zero(), bf256_zero()};
  if (s->verifier) {
    f[0] = add(mul(square(x.a), y.a), mul(x.a, s->delta2));
  } else {
    bf256_t aa = square(x.a), bb = square(x.b);
    f[0] = mul(aa, y.a);
    f[1] = mul(aa, y.b);
    f[2] = add(mul(bb, y.a), x.a);
    f[3] = add(mul(bb, y.b), x.b);
  }
  int result = emit(s, f, &s->counts.inverse);
  if (!result) {
    if (s->verifier) {
      f[0] = add(mul(square(y.a), x.a), mul(y.a, s->delta2));
    } else {
      bf256_t aa = square(y.a), bb = square(y.b);
      f[0] = mul(aa, x.a);
      f[1] = mul(aa, x.b);
      f[2] = add(mul(bb, x.a), y.a);
      f[3] = add(mul(bb, x.b), y.b);
    }
    result = emit(s, f, &s->counts.inverse);
  }
  erase(f, sizeof(f));
  return result;
}

static aes_byte byte_from_witness(kernel_state *s, uint32_t base) {
  aes_byte result;
  for (unsigned i = 0; i < 8; ++i) result.bits[i] = witness_wire(s, base + i);
  return result;
}
static aes_byte byte_constant(kernel_state *s, uint8_t value) {
  aes_byte result;
  for (unsigned i = 0; i < 8; ++i) result.bits[i] = constant_wire(s, (value >> i) & 1u);
  return result;
}
static aes_byte byte_add(aes_byte x, aes_byte y) {
  aes_byte r;
  for (unsigned i = 0; i < 8; ++i) r.bits[i] = linear_add(x.bits[i], y.bits[i]);
  return r;
}
static aes_byte xtime(aes_byte x) {
  aes_byte r;
  r.bits[0] = x.bits[7];
  for (unsigned i = 1; i < 8; ++i) {
    r.bits[i] = x.bits[i-1];
    if ((0x1bu >> i) & 1u) r.bits[i] = linear_add(r.bits[i], x.bits[7]);
  }
  return r;
}
static int sub_byte(kernel_state *s, aes_byte input, aes_byte *output) {
  if (s->next_inverse >= DMK_SBOX_COUNT) return DMK_ERR_INTERNAL;
  aes_byte y = byte_from_witness(s, DMK_INVERSE_BASE + 8u * s->next_inverse++);
  ++s->counts.sboxes;
  int result = emit_inverse(s, embed_byte(&input, s->byte_basis),
                            embed_byte(&y, s->byte_basis));
  if (result) return result;
  for (unsigned i = 0; i < 8; ++i) {
    linear_wire r = y.bits[i];
    for (unsigned offset = 4; offset <= 7; ++offset)
      r = linear_add(r, y.bits[(i + offset) & 7u]);
    output->bits[i] = linear_add(r, constant_wire(s, (0x63u >> i) & 1u));
  }
  erase(&y, sizeof(y));
  return DMK_OK;
}

static int expand_key(kernel_state *s, uint32_t key_base) {
  for (unsigned i = 0; i < 32; ++i)
    s->round_key[i] = byte_from_witness(s, key_base + 8u*i);
  uint8_t rcon = 1;
  for (unsigned i = 32; i < 240; i += 4) {
    aes_byte temp[4];
    for (unsigned j = 0; j < 4; ++j) temp[j] = s->round_key[i-4+j];
    if (i % 32u == 0) {
      aes_byte first = temp[0];
      temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = first;
      for (unsigned j = 0; j < 4; ++j) {
        int result = sub_byte(s, temp[j], &temp[j]);
        if (result) { erase(temp, sizeof(temp)); return result; }
      }
      temp[0] = byte_add(temp[0], byte_constant(s, rcon));
      rcon = (uint8_t)((rcon << 1) ^ ((rcon >> 7) ? 0x1bu : 0u));
    } else if (i % 32u == 16u) {
      for (unsigned j = 0; j < 4; ++j) {
        int result = sub_byte(s, temp[j], &temp[j]);
        if (result) { erase(temp, sizeof(temp)); return result; }
      }
    }
    for (unsigned j = 0; j < 4; ++j)
      s->round_key[i+j] = byte_add(s->round_key[i-32+j], temp[j]);
    erase(temp, sizeof(temp));
  }
  ++s->counts.key_schedules;
  return DMK_OK;
}

static void add_round_key(kernel_state *s, unsigned round) {
  for (unsigned i = 0; i < 16; ++i)
    s->state[i] = byte_add(s->state[i], s->round_key[16u*round+i]);
}
static void shift_rows(kernel_state *s) {
  aes_byte old[16]; memcpy(old, s->state, sizeof(old));
  for (unsigned col = 0; col < 4; ++col)
    for (unsigned row = 0; row < 4; ++row)
      s->state[4u*col+row] = old[4u*((col+row)&3u)+row];
  erase(old, sizeof(old));
}
static void mix_columns(kernel_state *s) {
  for (unsigned col = 0; col < 4; ++col) {
    aes_byte a[4];
    for (unsigned row = 0; row < 4; ++row) a[row] = s->state[4u*col+row];
    aes_byte all = byte_add(byte_add(a[0],a[1]),byte_add(a[2],a[3]));
    for (unsigned row = 0; row < 4; ++row)
      s->state[4u*col+row] = byte_add(byte_add(a[row],all),
                                    xtime(byte_add(a[row],a[(row+1u)&3u])));
    erase(a, sizeof(a)); erase(&all, sizeof(all));
  }
}
static int encrypt_counter(kernel_state *s, unsigned block, int g1) {
  /* Exact LE128(j) for G0, LE128(2^127+j) for G1; at most 50 blocks. */
  for (unsigned i = 0; i < 16; ++i)
    s->state[i] = byte_constant(s, i == 0 ? (uint8_t)block :
                                  (i == 15 && g1 ? UINT8_C(0x80) : 0));
  add_round_key(s, 0);
  for (unsigned round = 1; round <= 14; ++round) {
    for (unsigned i = 0; i < 16; ++i) {
      int result = sub_byte(s, s->state[i], &s->state[i]);
      if (result) return result;
    }
    shift_rows(s);
    if (round != 14) mix_columns(s);
    add_round_key(s, round);
  }
  ++s->counts.aes_blocks;
  return DMK_OK;
}

static int tag_row(void *context, uint32_t row, const uint32_t *indices,
                   size_t count, uint8_t constant) {
  kernel_state *s = (kernel_state *)context;
  if (row != s->counts.tag || count > DMC_TAG_LINEAR_MAX_TERMS || constant > 1)
    return DMK_ERR_INTERNAL;
  linear_wire l = constant_wire(s, constant);
  for (size_t i = 0; i < count; ++i) l = linear_add(l, witness_wire(s, indices[i]));
  return emit_linear(s, l, &s->counts.tag);
}
static int range_row(void *context, uint32_t row,
                      const dmc_range_constraint_record_t *record) {
  kernel_state *s = (kernel_state *)context;
  if (row >= DMC_RANGE_TOTAL_ROWS || record->linear_count > 3 || record->constant > 1)
    return DMK_ERR_INTERNAL;
  linear_wire l = constant_wire(s, record->constant);
  for (unsigned i = 0; i < record->linear_count; ++i)
    l = linear_add(l, witness_wire(s, record->linear_indices[i]));
  uint32_t *category = row < DMC_RANGE_AUX_BITNESS_ROWS ? &s->counts.bitness : &s->counts.range;
  if (record->monomial_left == DMC_RANGE_NO_INDEX &&
      record->monomial_right == DMC_RANGE_NO_INDEX)
    return emit_linear(s, l, category);
  if (record->monomial_left == DMC_RANGE_NO_INDEX ||
      record->monomial_right == DMC_RANGE_NO_INDEX) return DMK_ERR_INTERNAL;
  return emit_quadratic(s, witness_wire(s, record->monomial_left),
                         witness_wire(s, record->monomial_right), l, category);
}

static int walk_relation(kernel_state *s) {
  /* The range module emits bitness for its own 12600 auxiliary coordinates.
   * This prefix emits all other bits, so no bitness row is omitted or duplicated. */
  for (uint32_t i = 0; i < DMK_RANGE_BASE; ++i) {
    int result = emit_bitness(s, i); if (result) return result;
  }
  int result = expand_key(s, 0); if (result) return result;
  for (unsigned block = 0; block < 8; ++block) {
    result = encrypt_counter(s, block, 0); if (result) return result;
    for (unsigned byte = 0; byte < 16; ++byte) for (unsigned bit = 0; bit < 8; ++bit) {
      uint32_t index = DMK_G0_BASE + block*128u + byte*8u + bit;
      linear_wire l = linear_add(s->state[byte].bits[bit], witness_wire(s,index));
      result = emit_linear(s, l, &s->counts.equality); if (result) return result;
    }
  }
  result = expand_key(s, DMK_G0_BASE); if (result) return result;
  for (unsigned block = 0; block < 50; ++block) {
    result = encrypt_counter(s, block, 1); if (result) return result;
    for (unsigned byte = 0; byte < 16; ++byte) for (unsigned bit = 0; bit < 8; ++bit) {
      uint32_t cbyte = 16u*block+byte;
      linear_wire l = linear_add(s->state[byte].bits[bit],
                                 witness_wire(s,DMK_VALUE_BASE+8u*cbyte+bit));
      l = linear_add(l,constant_wire(s,(s->instance->C[cbyte] >> bit)&1u));
      result = emit_linear(s,l,&s->counts.equality); if (result) return result;
    }
  }
  uint32_t k[256], z[768], values[100][64];
  for (unsigned i = 0; i < 256; ++i) k[i] = DMK_G0_BASE+i;
  for (unsigned i = 0; i < 768; ++i) z[i] = DMK_G0_BASE+256u+i;
  result = dmc_tag_linear_emit_constraints(s->instance->U,s->instance->T,k,z,
                                            DMK_WITNESS_BITS,tag_row,s);
  if (result) return result;
  for (unsigned i = 0; i < 100; ++i) for (unsigned j = 0; j < 64; ++j)
    values[i][j] = DMK_VALUE_BASE+64u*i+j;
  uint32_t range_rows = 0;
  result = dmc_range_emit_constraints(values,DMK_RANGE_BASE,DMK_WITNESS_BITS,
                                       range_row,s,&range_rows);
  if (result) return s->error ? s->error : result;
  if (range_rows != DMC_RANGE_TOTAL_ROWS || s->next_inverse != DMK_SBOX_COUNT ||
      s->counts.constraints != DMK_CONSTRAINTS || s->counts.bitness != DMK_WITNESS_BITS ||
      s->counts.inverse != 2u*DMK_SBOX_COUNT || s->counts.equality != 7424u ||
      s->counts.tag != 768u || s->counts.range != 12800u ||
      s->counts.sboxes != DMK_SBOX_COUNT || s->counts.aes_blocks != 58u ||
      s->counts.key_schedules != 2u) return DMK_ERR_INTERNAL;
  return s->error;
}

int dmk_instance_validate(const dmk_instance *instance) {
  static const uint8_t source_suite[16] = {'S','B','A','1','-','S','R','C','-','C','M','T','-','v','1',0};
  if (!instance) return DMK_ERR_ARGUMENT;
  if (memcmp(instance->source_suite, source_suite, sizeof(source_suite))) return DMK_ERR_INSTANCE;
  uint8_t nonzero = 0;
  for (unsigned i = 0; i < 96; ++i) nonzero |= instance->U[i];
  return nonzero ? DMK_OK : DMK_ERR_INSTANCE;
}
int dmk_instance_matches(const dmk_instance *expected, const dmk_instance *actual) {
  if (dmk_instance_validate(expected) || dmk_instance_validate(actual)) return DMK_ERR_INSTANCE;
  /* Explicit fields, independent of any C structure padding. */
  if (memcmp(expected->source_suite,actual->source_suite,16) ||
      memcmp(expected->context,actual->context,64) || memcmp(expected->U,actual->U,96) ||
      memcmp(expected->T,actual->T,96) || memcmp(expected->C,actual->C,800)) return DMK_ERR_INSTANCE;
  return DMK_OK;
}
static int run_kernel(const dmk_instance *instance, const uint8_t *w,
                       const bf256_t *v_or_q, const bf256_t *delta,
                       dmk_coefficient_sink csink, dmk_evaluation_sink esink,
                       void *context, dmk_counts *counts) {
  kernel_state *s = (kernel_state *)calloc(1,sizeof(*s));
  if (!s) return DMK_ERR_ALLOCATION;
  s->instance = instance; s->w = w; s->v_or_q = v_or_q;
  s->verifier = delta != NULL;
  s->coefficient_sink = csink; s->evaluation_sink = esink; s->sink_context = context;
  s->counts.witness_bits = DMK_WITNESS_BITS;
  initialize_byte_embedding_basis(s->byte_basis);
  if (delta) { s->delta = *delta; s->delta2 = square(*delta); s->delta3 = mul(s->delta2,*delta); }
  int result = walk_relation(s);
  *counts = s->counts;
  erase(s,sizeof(*s)); free(s);
  return result;
}
int dmk_prover_coefficients(const dmk_instance *instance,
                            const uint8_t *witness_bits, size_t witness_count,
                            const bf256_t *v_rows, size_t row_count,
                            dmk_coefficient_sink sink, void *context,
                            dmk_counts *counts) {
  if (counts) memset(counts,0,sizeof(*counts));
  if (!counts || !witness_bits || !v_rows || !sink) return DMK_ERR_ARGUMENT;
  int result = dmk_instance_validate(instance); if (result) return result;
  if (witness_count != DMK_WITNESS_BITS || row_count != DMK_WITNESS_BITS) return DMK_ERR_DIMENSION;
  for (size_t i = 0; i < witness_count; ++i) if (witness_bits[i] > 1) return DMK_ERR_WITNESS;
  return run_kernel(instance,witness_bits,v_rows,NULL,sink,NULL,context,counts);
}
int dmk_verifier_evaluate(const dmk_instance *expected,
                          const bf256_t *q_prime_rows, size_t row_count,
                          const bf256_t *delta,
                          dmk_evaluation_sink sink, void *context,
                          dmk_counts *counts) {
  if (counts) memset(counts,0,sizeof(*counts));
  if (!counts || !q_prime_rows || !delta || !sink) return DMK_ERR_ARGUMENT;
  int result = dmk_instance_validate(expected); if (result) return result;
  if (row_count != DMK_WITNESS_BITS) return DMK_ERR_DIMENSION;
  return run_kernel(expected,NULL,q_prime_rows,delta,NULL,sink,context,counts);
}
