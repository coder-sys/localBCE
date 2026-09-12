/* SPDX-License-Identifier: MIT */
#include "direct_mask_kernel.h"
#include "direct_mask_circuit.h"
#include "../direct_mask_vole/direct_mask_bf256_accel.h"
#include "../direct_mask_circuit/dmc_range_constraints.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct probe_state {
  bf256_t delta;
  bf256_t *evaluations;
  uint32_t rows, nonzero_leading, mismatches;
  int record;
} probe_state;

static int equal(bf256_t x, bf256_t y) {
  uint8_t a[32],b[32]; bf256_store(a,&x); bf256_store(b,&y);
  return memcmp(a,b,32)==0;
}

#if defined(DIRECT_MASK_BF256_TEST_SEAM)
extern void direct_mask_bf256_test_portable_dispatch(
    bf256_t* dst, const bf256_t* lhs, const bf256_t* rhs);
extern void direct_mask_bf256_test_portable_dispatch_inplace(
    bf256_t* lhs, const bf256_t* rhs);
#endif

static void set_words(bf256_t *value, uint64_t w0, uint64_t w1,
                      uint64_t w2, uint64_t w3) {
  *value = bf256_zero();
  BF_VALUE(*value, 0) = w0;
  BF_VALUE(*value, 1) = w1;
  BF_VALUE(*value, 2) = w2;
  BF_VALUE(*value, 3) = w3;
}

static bf256_t basis_element(unsigned int bit) {
  bf256_t value = bf256_zero();
  BF_VALUE(value, bit / 64u) = UINT64_C(1) << (bit % 64u);
  return value;
}

static void print_arithmetic_mismatch(const char *suite, unsigned int lhs_index,
                                      unsigned int rhs_index, const char *case_name,
                                      const bf256_t *expected, const bf256_t *actual) {
  printf("BF256_ARITHMETIC_MISMATCH suite=%s lhs=%u rhs=%u case=%s "
         "expected=%016llx:%016llx:%016llx:%016llx "
         "actual=%016llx:%016llx:%016llx:%016llx\n",
         suite, lhs_index, rhs_index, case_name,
         (unsigned long long)BF_VALUE(*expected, 3),
         (unsigned long long)BF_VALUE(*expected, 2),
         (unsigned long long)BF_VALUE(*expected, 1),
         (unsigned long long)BF_VALUE(*expected, 0),
         (unsigned long long)BF_VALUE(*actual, 3),
         (unsigned long long)BF_VALUE(*actual, 2),
         (unsigned long long)BF_VALUE(*actual, 1),
         (unsigned long long)BF_VALUE(*actual, 0));
}

static int check_arithmetic_result(const char *suite, unsigned int lhs_index,
                                   unsigned int rhs_index, const char *case_name,
                                   const bf256_t *expected, const bf256_t *actual,
                                   unsigned long long *checks, unsigned int *mismatches) {
  ++*checks;
  if (equal(*expected, *actual)) return 1;
  ++*mismatches;
  print_arithmetic_mismatch(suite, lhs_index, rhs_index, case_name, expected, actual);
  return 0;
}

static int check_arithmetic_pair(const char *suite, unsigned int lhs_index,
                                 unsigned int rhs_index, const bf256_t *lhs,
                                 const bf256_t *rhs, unsigned long long *checks,
                                 unsigned int *mismatches) {
  int ok = 1;
  bf256_t expected, actual;
  direct_mask_bf256_mul_portable(&expected, lhs, rhs);

  bf256_mul(&actual, lhs, rhs);
  if (!check_arithmetic_result(suite, lhs_index, rhs_index, "public_out_of_place",
                               &expected, &actual, checks, mismatches)) ok = 0;

#if defined(DIRECT_MASK_BF256_TEST_SEAM)
  direct_mask_bf256_test_portable_dispatch(&actual, lhs, rhs);
  if (!check_arithmetic_result(suite, lhs_index, rhs_index, "forced_portable_dispatch",
                               &expected, &actual, checks, mismatches)) ok = 0;
#endif

  bf256_t lhs_alias = *lhs;
  bf256_mul(&lhs_alias, &lhs_alias, rhs);
  if (!check_arithmetic_result(suite, lhs_index, rhs_index, "public_dst_lhs_alias",
                               &expected, &lhs_alias, checks, mismatches)) ok = 0;

  bf256_t rhs_alias = *rhs;
  bf256_mul(&rhs_alias, lhs, &rhs_alias);
  if (!check_arithmetic_result(suite, lhs_index, rhs_index, "public_dst_rhs_alias",
                               &expected, &rhs_alias, checks, mismatches)) ok = 0;

  bf256_t lhs_inplace = *lhs;
  bf256_mul_inplace(&lhs_inplace, rhs);
  if (!check_arithmetic_result(suite, lhs_index, rhs_index, "public_inplace_lhs",
                               &expected, &lhs_inplace, checks, mismatches)) ok = 0;

  bf256_t expected_rhs, rhs_inplace;
  direct_mask_bf256_mul_portable(&expected_rhs, rhs, lhs);
  rhs_inplace = *rhs;
  bf256_mul_inplace(&rhs_inplace, lhs);
  if (!check_arithmetic_result(suite, lhs_index, rhs_index, "public_inplace_rhs",
                               &expected_rhs, &rhs_inplace, checks, mismatches)) ok = 0;

  bf256_t expected_self, self_alias, self_inplace;
  direct_mask_bf256_mul_portable(&expected_self, lhs, lhs);
  self_alias = *lhs;
  bf256_mul(&self_alias, &self_alias, &self_alias);
  if (!check_arithmetic_result(suite, lhs_index, rhs_index, "public_self_alias",
                               &expected_self, &self_alias, checks, mismatches)) ok = 0;
  self_inplace = *lhs;
  bf256_mul_inplace(&self_inplace, &self_inplace);
  if (!check_arithmetic_result(suite, lhs_index, rhs_index, "public_self_inplace",
                               &expected_self, &self_inplace, checks, mismatches)) ok = 0;

#if defined(DIRECT_MASK_BF256_TEST_SEAM)
  bf256_t forced_portable_inplace = *lhs;
  direct_mask_bf256_test_portable_dispatch_inplace(&forced_portable_inplace, rhs);
  if (!check_arithmetic_result(suite, lhs_index, rhs_index, "forced_portable_inplace",
                               &expected, &forced_portable_inplace, checks, mismatches)) ok = 0;
#endif
  return ok;
}

static int run_bf256_arithmetic_checks(void) {
  enum { BOUNDARY_VECTOR_COUNT = 17 };
  const uint64_t boundary_words[BOUNDARY_VECTOR_COUNT][4] = {
      {UINT64_C(0), UINT64_C(0), UINT64_C(0), UINT64_C(0)},
      {UINT64_C(1), UINT64_C(0), UINT64_C(0), UINT64_C(0)},
      {UINT64_MAX, UINT64_MAX, UINT64_MAX, UINT64_MAX},
      {UINT64_MAX, UINT64_C(0), UINT64_C(0), UINT64_C(0)},
      {UINT64_C(0), UINT64_MAX, UINT64_C(0), UINT64_C(0)},
      {UINT64_C(0), UINT64_C(0), UINT64_MAX, UINT64_C(0)},
      {UINT64_C(0), UINT64_C(0), UINT64_C(0), UINT64_MAX},
      {UINT64_C(1) << 63, UINT64_C(0), UINT64_C(0), UINT64_C(0)},
      {UINT64_C(0), UINT64_C(1), UINT64_C(0), UINT64_C(0)},
      {UINT64_C(0), UINT64_C(0), UINT64_C(1) << 63, UINT64_C(0)},
      {UINT64_C(0), UINT64_C(0), UINT64_C(1), UINT64_C(0)},
      {UINT64_C(0), UINT64_C(0), UINT64_C(0), UINT64_C(1) << 63},
      {UINT64_C(0), UINT64_C(0), UINT64_C(0), UINT64_C(1)},
      {UINT64_MAX, UINT64_C(1), UINT64_C(0), UINT64_C(0)},
      {UINT64_C(0), UINT64_MAX, UINT64_C(1), UINT64_C(0)},
      {UINT64_C(0), UINT64_C(0), UINT64_MAX, UINT64_C(1)},
      {UINT64_C(1), UINT64_MAX, UINT64_MAX, UINT64_C(1)},
  };
  bf256_t basis[256], boundary[BOUNDARY_VECTOR_COUNT];
  unsigned long long checks = 0;
  unsigned int mismatches = 0;
  int ok = 1;

  printf("BF256_ARITHMETIC_BEGIN\n");
  printf("BF256_ARITHMETIC_BACKEND=%s PCLMUL_AVAILABLE=%d "
         "FORCED_PORTABLE_SEAM=compiled\n",
         direct_mask_bf256_backend_name(), direct_mask_bf256_pclmul_available());
  for (unsigned int i = 0; i != 256u; ++i) basis[i] = basis_element(i);
  for (unsigned int i = 0; i != BOUNDARY_VECTOR_COUNT; ++i) {
    set_words(&boundary[i], boundary_words[i][0], boundary_words[i][1],
              boundary_words[i][2], boundary_words[i][3]);
  }

  for (unsigned int i = 0; i != 256u; ++i) {
    for (unsigned int j = 0; j != 256u; ++j) {
      if (!check_arithmetic_pair("basis", i, j, &basis[i], &basis[j],
                                 &checks, &mismatches)) ok = 0;
    }
  }
  for (unsigned int i = 0; i != BOUNDARY_VECTOR_COUNT; ++i) {
    for (unsigned int j = 0; j != BOUNDARY_VECTOR_COUNT; ++j) {
      if (!check_arithmetic_pair("boundary", i, j, &boundary[i], &boundary[j],
                                 &checks, &mismatches)) ok = 0;
    }
  }
  printf("BF256_ARITHMETIC_BASIS_PAIRS=65536 BOUNDARY_VECTORS=%u "
         "BOUNDARY_PAIRS=%u CHECKS=%llu MISMATCHES=%u\n",
         BOUNDARY_VECTOR_COUNT,
         BOUNDARY_VECTOR_COUNT * BOUNDARY_VECTOR_COUNT,
         checks, mismatches);
  printf("BF256_ARITHMETIC_STATUS=%s\n", ok ? "PASS" : "FAIL");
  return ok;
}

static bf256_t add(bf256_t a,bf256_t b) { bf256_t r; bf256_add(&r,&a,&b); return r; }
static bf256_t mul(bf256_t a,bf256_t b) { bf256_t r; bf256_mul(&r,&a,&b); return r; }
static uint64_t rng_state=UINT64_C(0xb3204829fe125618);
static uint64_t fixture_random(void) {
  rng_state^=rng_state<<13; rng_state^=rng_state>>7; rng_state^=rng_state<<17;
  return rng_state;
}
static bf256_t random_field(void) {
  uint8_t bytes[32];
  for(unsigned i=0;i<32;i+=8) {
    uint64_t x=fixture_random();
    for(unsigned j=0;j<8;++j) bytes[i+j]=(uint8_t)(x>>(8u*j));
  }
  bf256_t r; bf256_load(&r,bytes); return r;
}
static int coefficients(void *context,uint32_t row,const bf256_t f[4]) {
  probe_state *s=(probe_state*)context;
  if(row!=s->rows++) return -80;
  s->nonzero_leading+=(uint32_t)!equal(f[3],bf256_zero());
  if(s->record) {
    bf256_t y=f[3];
    for(int i=2;i>=0;--i) y=add(mul(y,s->delta),f[i]);
    s->evaluations[row]=y;
  }
  return 0;
}
static int evaluations(void *context,uint32_t row,const bf256_t *value) {
  probe_state *s=(probe_state*)context;
  if(row!=s->rows++) return -81;
  if(!equal(s->evaluations[row],*value)) {
    if(s->mismatches==0) printf("FIRST_MISMATCH row=%u\n",row);
    ++s->mismatches;
  }
  return 0;
}
static int fail_callback(void *context,uint32_t row,const bf256_t f[4]) {
  (void)context;(void)f; return row==123u ? -91 : 0;
}
static void unpack(uint8_t *out,const uint8_t *in,size_t n) {
  for(size_t i=0;i<n*8u;++i) out[i]=(uint8_t)((in[i/8u]>>(i%8u))&1u);
}
static void set_values(dmk_instance *x,uint8_t *w,const uint8_t g1[800],
                       const uint64_t values[100]) {
  for(unsigned i=0;i<100;++i) for(unsigned j=0;j<8;++j) {
    uint8_t b=(uint8_t)(values[i]>>(8u*j));
    x->C[8u*i+j]=(uint8_t)(g1[8u*i+j]^b);
    for(unsigned k=0;k<8;++k) w[DMK_VALUE_BASE+64u*i+8u*j+k]=(uint8_t)((b>>k)&1u);
  }
}
static int check_negative(const char *name,const dmk_instance *x,const uint8_t *w,
                           const bf256_t *v) {
  probe_state s={0}; dmk_counts c;
  int status=dmk_prover_coefficients(x,w,DMK_WITNESS_BITS,v,DMK_WITNESS_BITS,
                                    coefficients,&s,&c);
  printf("NEGATIVE name=%s status=%d rows=%u nonzero_leading=%u\n",
         name,status,s.rows,s.nonzero_leading);
  return status==0 && s.rows==DMK_CONSTRAINTS && s.nonzero_leading>0;
}
int main(void) {
  const clock_t start=clock();
  int ok=run_bf256_arithmetic_checks();
  uint8_t root[32]; for(unsigned i=0;i<32;++i) root[i]=(uint8_t)(i*7u+3u);
  uint64_t values[100];
  for(unsigned i=0;i<100;++i) values[i]=(i%2u) ? DMK_LOWER : DMK_UPPER;
  dmc_public_instance_t request={0}, native_public;
  request.version=DMC_VERSION; request.lower=DMC_LOWER;request.upper=DMC_UPPER;
  memcpy(request.suite_id,DMC_SUITE_ID,16);
  for(unsigned i=0;i<96;++i) request.U[i]=(uint8_t)(i*11u+5u);
  for(unsigned i=0;i<64;++i) request.context[i]=(uint8_t)(i+1u);
  if(dmc_source_prepare(&request,values,root,&native_public)!=DMC_OK) return 1;
  dmc_native_aes_witness_t trace;
  if(dmc_generate_native_aes_witness(root,&trace)!=DMC_OK) return 2;
  dmk_instance x;
  memcpy(x.source_suite,native_public.suite_id,16);memcpy(x.context,native_public.context,64);
  memcpy(x.U,native_public.U,96);memcpy(x.T,native_public.T,96);memcpy(x.C,native_public.C,800);
  uint8_t *w=(uint8_t*)calloc(DMK_WITNESS_BITS,1);
  bf256_t *v=(bf256_t*)malloc(DMK_WITNESS_BITS*sizeof(*v));
  bf256_t *q=(bf256_t*)malloc(DMK_WITNESS_BITS*sizeof(*q));
  bf256_t *expected=(bf256_t*)malloc(DMK_CONSTRAINTS*sizeof(*expected));
  if(!w||!v||!q||!expected) { free(w);free(v);free(q);free(expected);dmc_native_aes_witness_clear(&trace);return 3; }
  unpack(w,root,32);memcpy(w+DMK_INVERSE_BASE,trace.inverse_bits,trace.inverse_bit_count);
  unpack(w+DMK_G0_BASE,trace.g0,128);
  set_values(&x,w,trace.g1,values);
  uint32_t out_of_range=0;
  if(dmc_range_materialize_aux(values,w+DMK_RANGE_BASE,&out_of_range)!=0) ok=0;
  for(uint32_t i=0;i<DMK_WITNESS_BITS;++i) v[i]=random_field();
  for(unsigned test=0;test<4;++test) {
    probe_state s={0}; dmk_counts pc,vc;
    s.delta=test==0?bf256_zero():(test==1?bf256_from_bit(1):random_field());
    s.record=1;s.evaluations=expected;
    for(uint32_t i=0;i<DMK_WITNESS_BITS;++i) q[i]=add(v[i],mul(s.delta,bf256_from_bit(w[i])));
    int ps=dmk_prover_coefficients(&x,w,DMK_WITNESS_BITS,v,DMK_WITNESS_BITS,coefficients,&s,&pc);
    uint32_t leading=s.nonzero_leading;s.rows=0;
    int vs=dmk_verifier_evaluate(&x,q,DMK_WITNESS_BITS,&s.delta,evaluations,&s,&vc);
    printf("FIELD_IDENTITY delta_case=%u prover=%d verifier=%d rows=%u nonzero_leading=%u mismatches=%u\n",test,ps,vs,s.rows,leading,s.mismatches);
    ok=ok&&ps==0&&vs==0&&leading==0&&s.mismatches==0&&s.rows==DMK_CONSTRAINTS&&memcmp(&pc,&vc,sizeof(pc))==0;
    if(test==0) printf("ACTUAL_COUNTS ell=%u m=%u bitness=%u inverse=%u equality=%u tag=%u range=%u sboxes=%u aes_blocks=%u key_schedules=%u\n",pc.witness_bits,pc.constraints,pc.bitness,pc.inverse,pc.equality,pc.tag,pc.range,pc.sboxes,pc.aes_blocks,pc.key_schedules);
  }
  const uint32_t locations[]={0,DMK_INVERSE_BASE,DMK_G0_BASE,DMK_VALUE_BASE,DMK_RANGE_BASE,DMK_WITNESS_BITS-1u};
  const char *names[]={"root","inverse","g0","value","borrow_first","borrow_last"};
  for(unsigned i=0;i<6;++i) {
    w[locations[i]]^=1u;ok=check_negative(names[i],&x,w,v)&&ok;w[locations[i]]^=1u;
  }
  x.T[0]^=1u;ok=check_negative("tag_T",&x,w,v)&&ok;x.T[0]^=1u;
  x.U[0]^=1u;ok=check_negative("tag_U",&x,w,v)&&ok;x.U[0]^=1u;
  x.C[799]^=1u;ok=check_negative("ciphertext_C",&x,w,v)&&ok;x.C[799]^=1u;
  for(unsigned i=0;i<2;++i) {
    values[0]=i?DMK_UPPER+1u:DMK_LOWER-1u;
    set_values(&x,w,trace.g1,values);
    int status=dmc_range_materialize_aux(values,w+DMK_RANGE_BASE,&out_of_range);
    printf("RANGE_NATIVE boundary=%u status=%d out_of_range=%u\n",i,status,out_of_range);
    ok=ok&&status==DMC_RANGE_VALUES_OUT_OF_RANGE&&out_of_range==1;
    ok=check_negative(i?"upper_plus_one":"lower_minus_one",&x,w,v)&&ok;
  }
  probe_state s={0}; dmk_counts c;
  int callback=dmk_prover_coefficients(&x,w,DMK_WITNESS_BITS,v,DMK_WITNESS_BITS,fail_callback,&s,&c);
  ok=ok&&callback==-91&&c.constraints==124;
  w[0]=2;
  int nonbit=dmk_prover_coefficients(&x,w,DMK_WITNESS_BITS,v,DMK_WITNESS_BITS,coefficients,&s,&c);
  ok=ok&&nonbit==DMK_ERR_WITNESS&&c.constraints==0;w[0]=0;
  int dimension=dmk_verifier_evaluate(&x,q,DMK_WITNESS_BITS-1u,&s.delta,evaluations,&s,&c);
  ok=ok&&dimension==DMK_ERR_DIMENSION&&c.constraints==0;
  dmk_instance changed=x;changed.context[0]^=1u;
  int context=dmk_instance_matches(&x,&changed);ok=ok&&context==DMK_ERR_INSTANCE;
  memset(changed.U,0,96);int zero_u=dmk_instance_validate(&changed);ok=ok&&zero_u==DMK_ERR_INSTANCE;
  printf("API_REJECTIONS callback=%d non_boolean=%d dimension=%d context=%d zero_U=%d\n",callback,nonbit,dimension,context,zero_u);
  printf("DIRECT_MASK_KERNEL status=%s skips=0 fixture_rng=deterministic cpu_seconds=%.3f\n",ok?"PASS":"FAIL",(double)(clock()-start)/CLOCKS_PER_SEC);
  memset(w,0,DMK_WITNESS_BITS);memset(v,0,DMK_WITNESS_BITS*sizeof(*v));memset(q,0,DMK_WITNESS_BITS*sizeof(*q));
  free(w);free(v);free(q);free(expected);dmc_native_aes_witness_clear(&trace);
  return ok?0:1;
}
