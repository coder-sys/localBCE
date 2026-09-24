/* SPDX-License-Identifier: MIT */
#include "direct_mask_algebra.h"
#include <string.h>

static void erase(void *pointer, size_t length) {
  volatile uint8_t *p=(volatile uint8_t*)pointer;
  while(length--) *p++=0;
}
static bf256_t add(bf256_t a,bf256_t b) { bf256_t r;bf256_add(&r,&a,&b);return r; }
static bf256_t mul(bf256_t a,bf256_t b) { bf256_t r;bf256_mul(&r,&a,&b);return r; }
static int equal(bf256_t a,bf256_t b) {
  uint8_t x[32],y[32],difference=0;
  bf256_store(x,&a);bf256_store(y,&b);
  for(unsigned i=0;i<32;++i) difference|=(uint8_t)(x[i]^y[i]);
  erase(x,sizeof(x));erase(y,sizeof(y));return difference==0;
}
int dmk_pack_mask_rows(const bf256_t *rows,size_t row_count,bf256_t masks[6]) {
  if(!rows||!masks) return DMK_ERR_ARGUMENT;
  if(row_count!=DMK_MASK_ROWS) return DMK_ERR_DIMENSION;
  uint8_t two_bytes[32]={2};bf256_t x;bf256_load(&x,two_bytes);
  for(unsigned block=0;block<6;++block) {
    bf256_t packed=bf256_zero();
    for(unsigned i=256;i>0;--i) packed=add(mul(packed,x),rows[256u*block+i-1u]);
    masks[block]=packed;
  }
  return DMK_OK;
}
int dmk_pack_mask_bits(const uint8_t *packed,size_t byte_count,bf256_t masks[6]) {
  if(!packed||!masks) return DMK_ERR_ARGUMENT;
  if(byte_count!=DMK_MASK_BYTES) return DMK_ERR_DIMENSION;
  for(unsigned i=0;i<6;++i) bf256_load(&masks[i],packed+32u*i);
  return DMK_OK;
}
static void vh_update(bf256_t y[5],const bf256_t s[5],bf256_t value) {
  for(unsigned j=0;j<5;++j) y[j]=add(mul(y[j],s[j]),value);
}
int dmk_vh(const uint8_t gamma1[DMK_VH_CHALLENGE_BYTES],const bf256_t *rows,
           size_t row_count,const bf256_t masks[6],bf256_t output[4]) {
  if(!gamma1||!rows||!masks||!output) return DMK_ERR_ARGUMENT;
  if(row_count==0||row_count>(1u<<17)) return DMK_ERR_DIMENSION;
  bf256_t s[5],y[5];uint8_t t[32]={0};
  for(unsigned i=0;i<4;++i) bf256_load(&s[i],gamma1+128u+32u*i);
  memcpy(t,gamma1+256u,8);bf256_load(&s[4],t);
  for(unsigned i=0;i<5;++i) y[i]=bf256_zero();
  for(size_t i=0;i<row_count;++i) vh_update(y,s,rows[i]);
  vh_update(y,s,masks[0]);vh_update(y,s,masks[1]);
  for(unsigned i=0;i<4;++i) {
    bf256_t r;bf256_load(&r,gamma1+32u*i);
    output[i]=add(add(mul(r,y[0]),y[i+1u]),masks[i+2u]);
  }
  erase(s,sizeof(s));erase(y,sizeof(y));erase(t,sizeof(t));return DMK_OK;
}
void dmk_poly_hash_clear(dmk_poly_hash *hash) { if(hash) erase(hash,sizeof(*hash)); }
static int poly_fail(dmk_poly_hash *hash,int error) {
  dmk_poly_hash_clear(hash);hash->error=error;return error;
}
int dmk_poly_hash_init(dmk_poly_hash *hash,const uint8_t gamma2[DMK_ZK_CHALLENGE_BYTES],
                       uint32_t expected_rows) {
  if(!hash) return DMK_ERR_ARGUMENT;
  if(!gamma2) return poly_fail(hash,DMK_ERR_ARGUMENT);
  dmk_poly_hash_clear(hash);
  if(expected_rows==0||expected_rows>(1u<<18)) return poly_fail(hash,DMK_ERR_DIMENSION);
  memcpy(hash->gamma2,gamma2,DMK_ZK_CHALLENGE_BYTES);hash->expected_rows=expected_rows;
  for(unsigned i=0;i<3;++i) zk_hash_256_init(&hash->coefficient[i],hash->gamma2);
  return DMK_OK;
}
int dmk_poly_hash_update(void *context,uint32_t row,const bf256_t f[4]) {
  dmk_poly_hash *hash=(dmk_poly_hash*)context;
  if(!hash) return DMK_ERR_ARGUMENT;
  if(!f) return poly_fail(hash,DMK_ERR_ARGUMENT);
  if(hash->error) return hash->error;
  if(row!=hash->next_row||row>=hash->expected_rows) return poly_fail(hash,DMK_ERR_DIMENSION);
  if(!equal(f[3],bf256_zero())) return poly_fail(hash,DMK_ERR_WITNESS);
  for(unsigned i=0;i<3;++i) zk_hash_256_update(&hash->coefficient[i],&f[i]);
  ++hash->next_row;return DMK_OK;
}
int dmk_poly_hash_finish(dmk_poly_hash *hash,const bf256_t ubar[6],
                         const bf256_t vbar[6],bf256_t a[3]) {
  if(!hash) return DMK_ERR_ARGUMENT;
  if(!ubar||!vbar||!a) return poly_fail(hash,DMK_ERR_ARGUMENT);
  if(hash->error) return hash->error;
  if(hash->expected_rows==0||hash->next_row!=hash->expected_rows)
    return poly_fail(hash,DMK_ERR_DIMENSION);
  bf256_t masks[3]={vbar[0],add(ubar[0],vbar[1]),ubar[1]};
  for(unsigned i=0;i<3;++i) {
    uint8_t bytes[32];hash->coefficient[i].sd=hash->gamma2;
    zk_hash_256_finalize(bytes,&hash->coefficient[i],&masks[i]);bf256_load(&a[i],bytes);
    erase(bytes,sizeof(bytes));
  }
  erase(masks,sizeof(masks));dmk_poly_hash_clear(hash);return DMK_OK;
}
void dmk_eval_hash_clear(dmk_eval_hash *hash) { if(hash) erase(hash,sizeof(*hash)); }
static int eval_fail(dmk_eval_hash *hash,int error) {
  dmk_eval_hash_clear(hash);hash->error=error;return error;
}
int dmk_eval_hash_init(dmk_eval_hash *hash,const uint8_t gamma2[DMK_ZK_CHALLENGE_BYTES],
                       uint32_t expected_rows) {
  if(!hash) return DMK_ERR_ARGUMENT;
  if(!gamma2) return eval_fail(hash,DMK_ERR_ARGUMENT);
  dmk_eval_hash_clear(hash);
  if(expected_rows==0||expected_rows>(1u<<18)) return eval_fail(hash,DMK_ERR_DIMENSION);
  memcpy(hash->gamma2,gamma2,DMK_ZK_CHALLENGE_BYTES);hash->expected_rows=expected_rows;
  zk_hash_256_init(&hash->evaluation,hash->gamma2);return DMK_OK;
}
int dmk_eval_hash_update(void *context,uint32_t row,const bf256_t *value) {
  dmk_eval_hash *hash=(dmk_eval_hash*)context;
  if(!hash) return DMK_ERR_ARGUMENT;
  if(!value) return eval_fail(hash,DMK_ERR_ARGUMENT);
  if(hash->error) return hash->error;
  if(row!=hash->next_row||row>=hash->expected_rows) return eval_fail(hash,DMK_ERR_DIMENSION);
  zk_hash_256_update(&hash->evaluation,value);++hash->next_row;return DMK_OK;
}
int dmk_eval_hash_finish(dmk_eval_hash *hash,const bf256_t *mask_term,
                         const bf256_t *expected_b) {
  if(!hash) return DMK_ERR_ARGUMENT;
  if(!mask_term||!expected_b) return eval_fail(hash,DMK_ERR_ARGUMENT);
  if(hash->error) return hash->error;
  if(hash->expected_rows==0||hash->next_row!=hash->expected_rows)
    return eval_fail(hash,DMK_ERR_DIMENSION);
  uint8_t bytes[32];bf256_t actual;hash->evaluation.sd=hash->gamma2;
  zk_hash_256_finalize(bytes,&hash->evaluation,mask_term);bf256_load(&actual,bytes);
  int result=equal(actual,*expected_b)?DMK_OK:DMK_ERR_WITNESS;
  erase(bytes,sizeof(bytes));erase(&actual,sizeof(actual));dmk_eval_hash_clear(hash);return result;
}
