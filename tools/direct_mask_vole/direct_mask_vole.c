/* SPDX-License-Identifier: MIT */

#include "direct_mask_vole.h"

#include "aes.h"
#include "../direct_mask_kernel/direct_mask_algebra.h"
#include "hash_shake.h"
#include "parameters.h"
#include "random_oracle.h"
#include "tables/pregenerated/tables_256f.h"
#include "utils.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static const faest_paramset_t DMV_TREE_PARAMS = {
    DMV_LAMBDA,
    DMV_TAU,
    DMV_W_GRIND,
    DMV_T_OPEN,
    0,
    DMV_TREE_K,
    DMV_TAU0,
    DMV_TAU1,
    DMV_TREE_LEAVES,
    4,
    52,
    14,
    672,
    768,
    20856,
    16,
    32,
    704,
    NULL,
    NULL,
    NULL,
    NULL,
    &FAEST_256F_W_CRT[0][0],
    NULL,
    NULL,
    0,
    0,
    0,
    0,
    FAEST_256F_W_CRT_WORDS,
};

static int checked_mul_size(size_t lhs, size_t rhs, size_t* out) {
  if (out == NULL || (lhs != 0 && rhs > SIZE_MAX / lhs)) {
    return DMV_ERR_SIZE;
  }
  *out = lhs * rhs;
  return DMV_OK;
}

static void secure_clear(void* pointer, size_t length) {
  volatile uint8_t* cursor = (volatile uint8_t*)pointer;
  while (length != 0) {
    *cursor++ = 0;
    --length;
  }
}

static void clear_free(void* pointer, size_t length);

static void clear_pointer_array(uint8_t*** pointer_array, size_t rows, size_t columns) {
  if (pointer_array == NULL || *pointer_array == NULL) {
    return;
  }
  if ((*pointer_array)[0] != NULL) {
    secure_clear((*pointer_array)[0], rows * columns);
  }
  free_pointer_array(pointer_array);
}

static void xor_bytes(uint8_t* destination, const uint8_t* source, size_t length) {
  for (size_t i = 0; i != length; ++i) {
    destination[i] ^= source[i];
  }
}

static void transpose_rows_to_fields(bf256_t* fields, uint32_t bit_rows,
                                     uint8_t* const* bit_columns) {
  for (uint32_t row = 0; row != bit_rows; ++row) {
    uint8_t encoded[DMV_LAMBDA_BYTES] = {0};
    for (unsigned int column = 0; column != DMV_CHALLENGE_BITS; ++column) {
      ptr_set_bit(encoded, column, ptr_get_bit(bit_columns[column], row));
    }
    uint8_t mapped[DMV_LAMBDA_BYTES] = {0};
    bf2_matrix_mul_tbl(mapped, encoded, DMV_TREE_PARAMS.W_CRT, DMV_CHALLENGE_BITS,
                       DMV_LAMBDA, DMV_TREE_PARAMS.w_crt_words);
    bf256_load(&fields[row], mapped);
    secure_clear(encoded, sizeof(encoded));
    secure_clear(mapped, sizeof(mapped));
  }
}

static void transpose_rows_to_fields_from_bytes(bf256_t* fields, uint32_t bit_rows,
                                                uint8_t* const* bit_columns) {
  transpose_rows_to_fields(fields, bit_rows, bit_columns);
}

static int valid_descriptor_and_rows(const dmv_descriptor_t* descriptor, uint32_t* bit_rows,
                                     size_t* row_bytes) {
  int status = dmv_descriptor_validate(descriptor);
  if (status != DMV_OK) {
    return status;
  }
  status = dmv_descriptor_bit_rows(descriptor, bit_rows);
  if (status != DMV_OK) {
    return status;
  }
  return dmv_row_bytes(*bit_rows, row_bytes);
}

/* This is the ordinary bit-row conversion from the pinned FAEST implementation.  It is kept
 * here as a generic helper so the direct-mask path never calls the specialized vole.c path. */
static unsigned int direct_convert_to_vole(const uint8_t* iv, const uint8_t* sd, bool sd0_bot,
                                           unsigned int tree, size_t row_bytes, uint8_t* u,
                                           uint8_t* v) {
  const unsigned int num_instances =
      bavc_max_node_index(tree, DMV_TREE_PARAMS.tau1, DMV_TREE_PARAMS.k);
  const unsigned int depth =
      bavc_max_node_depth(tree, DMV_TREE_PARAMS.tau1, DMV_TREE_PARAMS.k);
  const unsigned int lambda_bytes = DMV_LAMBDA_BYTES;
  const size_t r_bytes = (size_t)2u * num_instances * row_bytes;
  uint8_t* r = calloc(1, r_bytes);
  if (r == NULL) {
    return 0;
  }

#define DMV_R(row, column) (r + ((((row) & 1u) * num_instances + (column)) * row_bytes))
#define DMV_V(index) (v + ((size_t)(index) * row_bytes))

  const uint32_t tweak = tree ^ UINT32_C(0x80000000);
  if (!sd0_bot) {
    prg(sd, iv, tweak, DMV_R(0, 0), DMV_LAMBDA, row_bytes);
  }
  for (unsigned int j = 1; j != num_instances; ++j) {
    prg(sd + (size_t)lambda_bytes * j, iv, tweak, DMV_R(0, j), DMV_LAMBDA, row_bytes);
  }

  memset(v, 0, (size_t)depth * row_bytes);
  for (unsigned int level = 0; level != depth; ++level) {
    const unsigned int level_instances = num_instances >> (level + 1u);
    for (unsigned int index = 0; index != level_instances; ++index) {
      xor_bytes(DMV_V(level), DMV_R(level, 2u * index + 1u), row_bytes);
      for (size_t byte = 0; byte != row_bytes; ++byte) {
        DMV_R(level + 1u, index)[byte] =
            DMV_R(level, 2u * index)[byte] ^ DMV_R(level, 2u * index + 1u)[byte];
      }
    }
  }
  if (!sd0_bot && u != NULL) {
    memcpy(u, DMV_R(depth, 0), row_bytes);
  }

#undef DMV_R
#undef DMV_V
  clear_free(r, r_bytes);
  return depth;
}

static bool valid_raw_challenge(const uint8_t raw[DMV_CHALLENGE_BYTES]) {
  if (raw == NULL) {
    return false;
  }
  /* The high w_grind bits are the required zero-grinding check. */
  const unsigned int preceding_bits = (DMV_CHALLENGE_BYTES - 1u) * 8u;
  const unsigned int used_bits = DMV_CHALLENGE_BITS > preceding_bits
                                     ? DMV_CHALLENGE_BITS - preceding_bits
                                     : 0u;
  const unsigned int unused_bits = 8u - used_bits;
  const uint8_t high_bit_mask = (uint8_t)~(uint8_t)(0xffu >> unused_bits);
  return (raw[DMV_CHALLENGE_BYTES - 1u] & high_bit_mask) == 0;
}

static void clear_padding_bits(uint8_t* bytes, uint32_t bits) {
  if (bits % 8u != 0) {
    bytes[bits / 8u] &= (uint8_t)((1u << (bits % 8u)) - 1u);
  }
}

int dmv_descriptor_validate(const dmv_descriptor_t* descriptor) {
  if (descriptor == NULL || descriptor->degree != DMV_DEGREE || descriptor->witness_bits == 0 ||
      descriptor->witness_bits > DMV_MAX_WITNESS_BITS ||
      descriptor->constraint_count == 0 || descriptor->constraint_count > DMV_MAX_CONSTRAINTS ||
      descriptor->witness_bits % 8u != 0) {
    return DMV_ERR_DESCRIPTOR;
  }
  return DMV_OK;
}

int dmv_descriptor_bit_rows(const dmv_descriptor_t* descriptor, uint32_t* bit_rows_out) {
  if (bit_rows_out == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  int status = dmv_descriptor_validate(descriptor);
  if (status != DMV_OK) {
    return status;
  }
  if (descriptor->witness_bits > UINT32_MAX - DMV_MASK_COUNT * DMV_LAMBDA) {
    return DMV_ERR_SIZE;
  }
  *bit_rows_out = descriptor->witness_bits + DMV_MASK_COUNT * DMV_LAMBDA;
  return DMV_OK;
}

int dmv_row_bytes(uint32_t bit_rows, size_t* row_bytes_out) {
  if (row_bytes_out == NULL || bit_rows == 0) {
    return DMV_ERR_ARGUMENT;
  }
  *row_bytes_out = ((size_t)bit_rows + 7u) / 8u;
  return DMV_OK;
}

size_t dmv_correction_bytes(const dmv_descriptor_t* descriptor) {
  uint32_t rows = 0;
  size_t row_bytes = 0;
  if (valid_descriptor_and_rows(descriptor, &rows, &row_bytes) != DMV_OK ||
      row_bytes > SIZE_MAX / (DMV_TAU - 1u)) {
    return 0;
  }
  return row_bytes * (DMV_TAU - 1u);
}

size_t dmv_m1_bytes(const dmv_descriptor_t* descriptor) {
  const size_t corrections = dmv_correction_bytes(descriptor);
  if (corrections == 0 || corrections > SIZE_MAX - 16u - DMV_BAVC_COMMITMENT_BYTES) {
    return 0;
  }
  return 16u + DMV_BAVC_COMMITMENT_BYTES + corrections;
}

size_t dmv_m2_bytes(const dmv_descriptor_t* descriptor) {
  if (dmv_descriptor_validate(descriptor) != DMV_OK ||
      descriptor->witness_bits / 8u > SIZE_MAX - 8u * DMV_LAMBDA_BYTES) {
    return 0;
  }
  /* m2 is tilde_u[4], D[4], and the ordinary witness correction d_w only. */
  return 8u * DMV_LAMBDA_BYTES + descriptor->witness_bits / 8u;
}

size_t dmv_m3_bytes(void) { return 3u * DMV_LAMBDA_BYTES; }

size_t dmv_opening_bytes(void) {
  return (size_t)DMV_TAU * DMV_BAVC_COM_BYTES + (size_t)DMV_T_OPEN * DMV_LAMBDA_BYTES;
}

size_t dmv_m4_bytes(void) { return dmv_opening_bytes(); }

static int allocate_commitment_buffers(dmv_commitment_t* commitment) {
  const size_t correction_bytes = dmv_correction_bytes(&commitment->descriptor);
  size_t v_bytes = 0;
  if (correction_bytes == 0 ||
      checked_mul_size(commitment->bit_rows, sizeof(*commitment->v_rows), &v_bytes) != DMV_OK) {
    return DMV_ERR_SIZE;
  }
  commitment->u_bits = calloc(commitment->row_bytes, 1);
  commitment->corrections = calloc(correction_bytes, 1);
  commitment->v_rows = calloc(1, v_bytes);
  if (commitment->u_bits == NULL || commitment->corrections == NULL || commitment->v_rows == NULL) {
    return DMV_ERR_ALLOCATION;
  }
  return DMV_OK;
}

int dmv_commit(dmv_commitment_t* commitment, const dmv_descriptor_t* descriptor,
               const uint8_t root[DMV_LAMBDA_BYTES], const uint8_t iv[16]) {
  if (commitment == NULL || descriptor == NULL || root == NULL || iv == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  if (commitment->initialized) {
    dmv_commit_clear(commitment);
  } else {
    memset(commitment, 0, sizeof(*commitment));
  }
  int status = valid_descriptor_and_rows(descriptor, &commitment->bit_rows, &commitment->row_bytes);
  if (status != DMV_OK) {
    return status;
  }
  commitment->descriptor = *descriptor;
  memcpy(commitment->iv, iv, sizeof(commitment->iv));
  status = allocate_commitment_buffers(commitment);
  if (status != DMV_OK) {
    dmv_commit_clear(commitment);
    return status;
  }

  bavc_commit(&commitment->bavc, root, iv, &DMV_TREE_PARAMS);
  commitment->initialized = true;

  uint8_t** v_columns = alloc_pointer_array(DMV_CHALLENGE_BITS, commitment->row_bytes);
  uint8_t* ui = calloc(DMV_TAU, commitment->row_bytes);
  if (v_columns == NULL || ui == NULL) {
    clear_pointer_array(&v_columns, DMV_CHALLENGE_BITS, commitment->row_bytes);
    clear_free(ui, (size_t)DMV_TAU * commitment->row_bytes);
    dmv_commit_clear(commitment);
    return DMV_ERR_ALLOCATION;
  }

  unsigned int v_index = 0;
  uint8_t* sd_i = commitment->bavc.sd;
  for (unsigned int tree = 0; tree != DMV_TAU; ++tree) {
    const unsigned int depth = direct_convert_to_vole(
        iv, sd_i, false, tree, commitment->row_bytes, ui + (size_t)tree * commitment->row_bytes,
        v_columns[v_index]);
    if (depth == 0 || v_index + depth > DMV_CHALLENGE_BITS) {
      clear_pointer_array(&v_columns, DMV_CHALLENGE_BITS, commitment->row_bytes);
      clear_free(ui, (size_t)DMV_TAU * commitment->row_bytes);
      dmv_commit_clear(commitment);
      return DMV_ERR_ALLOCATION;
    }
    v_index += depth;
    sd_i += (size_t)DMV_LAMBDA_BYTES * bavc_max_node_index(
                              tree, DMV_TREE_PARAMS.tau1, DMV_TREE_PARAMS.k);
  }
  memcpy(commitment->u_bits, ui, commitment->row_bytes);
  for (unsigned int tree = 1; tree != DMV_TAU; ++tree) {
    for (size_t byte = 0; byte != commitment->row_bytes; ++byte) {
      commitment->corrections[(size_t)(tree - 1u) * commitment->row_bytes + byte] =
          ui[byte] ^ ui[(size_t)tree * commitment->row_bytes + byte];
    }
  }
  clear_padding_bits(commitment->u_bits, commitment->bit_rows);
  for (unsigned int tree = 1; tree != DMV_TAU; ++tree) {
    clear_padding_bits(commitment->corrections + (size_t)(tree - 1u) * commitment->row_bytes,
                       commitment->bit_rows);
  }

  transpose_rows_to_fields_from_bytes(commitment->v_rows, commitment->bit_rows, v_columns);
  clear_pointer_array(&v_columns, DMV_CHALLENGE_BITS, commitment->row_bytes);
  clear_free(ui, (size_t)DMV_TAU * commitment->row_bytes);
  commitment->initialized = true;
  return DMV_OK;
}

void dmv_commit_clear(dmv_commitment_t* commitment) {
  if (commitment == NULL) {
    return;
  }
  if (commitment->initialized) {
    secure_clear(commitment->bavc.k,
                 ((size_t)2u * DMV_TREE_PARAMS.L - 1u) * DMV_LAMBDA_BYTES);
    secure_clear(commitment->bavc.sd, (size_t)DMV_TREE_PARAMS.L * DMV_LAMBDA_BYTES);
    secure_clear(commitment->bavc.com,
                 (size_t)DMV_TREE_PARAMS.L * 3u * DMV_LAMBDA_BYTES);
    secure_clear(commitment->bavc.h, 2u * DMV_LAMBDA_BYTES);
    bavc_clear(&commitment->bavc);
  }
  clear_free(commitment->u_bits, commitment->row_bytes);
  clear_free(commitment->corrections, dmv_correction_bytes(&commitment->descriptor));
  clear_free(commitment->v_rows, (size_t)commitment->bit_rows * sizeof(*commitment->v_rows));
  memset(commitment, 0, sizeof(*commitment));
}

const uint8_t* dmv_bavc_commitment(const dmv_commitment_t* commitment) {
  return commitment == NULL || !commitment->initialized ? NULL : commitment->bavc.h;
}

const uint8_t* dmv_u_bits(const dmv_commitment_t* commitment) {
  return commitment == NULL || !commitment->initialized ? NULL : commitment->u_bits;
}

const uint8_t* dmv_corrections(const dmv_commitment_t* commitment) {
  return commitment == NULL || !commitment->initialized ? NULL : commitment->corrections;
}

const bf256_t* dmv_v_rows(const dmv_commitment_t* commitment) {
  return commitment == NULL || !commitment->initialized ? NULL : commitment->v_rows;
}

static int decode_challenge(uint16_t i_delta[DMV_TAU],
                            const uint8_t raw_challenge[DMV_CHALLENGE_BYTES]) {
  if (!valid_raw_challenge(raw_challenge) || !decode_all_chall_3(i_delta, raw_challenge,
                                                                  &DMV_TREE_PARAMS)) {
    return DMV_ERR_CHALLENGE;
  }
  return DMV_OK;
}

int dmv_open(const dmv_commitment_t* commitment, const uint8_t raw_challenge[DMV_CHALLENGE_BYTES],
             uint8_t* opening, size_t opening_len) {
  if (commitment == NULL || !commitment->initialized || raw_challenge == NULL || opening == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  if (opening_len != dmv_opening_bytes()) {
    return DMV_ERR_SIZE;
  }
  uint16_t i_delta[DMV_TAU];
  int status = decode_challenge(i_delta, raw_challenge);
  if (status != DMV_OK) {
    return status;
  }
  return bavc_open(opening, &commitment->bavc, i_delta, &DMV_TREE_PARAMS) ? DMV_OK
                                                                            : DMV_ERR_OPENING;
}

static void fill_tree_sd(uint8_t* sd, const uint8_t* reconstructed_sd, unsigned int tree,
                         uint16_t challenge_index) {
  const unsigned int instances =
      bavc_max_node_index(tree, DMV_TREE_PARAMS.tau1, DMV_TREE_PARAMS.k);
  const uint8_t* source = reconstructed_sd;
  memset(sd, 0, ((size_t)1u << DMV_TREE_PARAMS.k) * DMV_LAMBDA_BYTES);
  for (unsigned int j = 0; j != instances; ++j) {
    if (j < challenge_index) {
      memcpy(sd + (size_t)(j ^ challenge_index) * DMV_LAMBDA_BYTES, source,
             DMV_LAMBDA_BYTES);
      source += DMV_LAMBDA_BYTES;
    } else if (j > challenge_index) {
      memcpy(sd + (size_t)(j ^ challenge_index) * DMV_LAMBDA_BYTES, source,
             DMV_LAMBDA_BYTES);
      source += DMV_LAMBDA_BYTES;
    }
  }
}

int dmv_reconstruct(const dmv_descriptor_t* descriptor, const uint8_t iv[16],
                    const uint8_t raw_challenge[DMV_CHALLENGE_BYTES], const uint8_t* opening,
                    size_t opening_len, const uint8_t* corrections, size_t corrections_len,
                    uint8_t reconstructed_commitment[DMV_BAVC_COMMITMENT_BYTES], bf256_t* q_rows,
                    size_t q_rows_count, bf256_t* delta_out) {
  if (descriptor == NULL || iv == NULL || raw_challenge == NULL || opening == NULL ||
      reconstructed_commitment == NULL || q_rows == NULL || delta_out == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  uint32_t bit_rows = 0;
  size_t row_bytes = 0;
  int status = valid_descriptor_and_rows(descriptor, &bit_rows, &row_bytes);
  if (status != DMV_OK) {
    return status;
  }
  if (opening_len != dmv_opening_bytes() || q_rows_count != bit_rows ||
      corrections == NULL || corrections_len != dmv_correction_bytes(descriptor)) {
    return DMV_ERR_SIZE;
  }
  uint16_t i_delta[DMV_TAU];
  status = decode_challenge(i_delta, raw_challenge);
  if (status != DMV_OK) {
    return status;
  }

  bavc_rec_t reconstructed = {
      .h = reconstructed_commitment,
      .s = malloc((DMV_TREE_LEAVES - DMV_TAU) * DMV_LAMBDA_BYTES),
  };
  if (reconstructed.s == NULL ||
      !bavc_reconstruct(&reconstructed, opening, i_delta, iv, &DMV_TREE_PARAMS)) {
    clear_free(reconstructed.s, (DMV_TREE_LEAVES - DMV_TAU) * DMV_LAMBDA_BYTES);
    return DMV_ERR_OPENING;
  }

  uint8_t** q_columns = alloc_pointer_array(DMV_CHALLENGE_BITS, row_bytes);
  uint8_t* sd = calloc((size_t)1u << DMV_TREE_PARAMS.k, DMV_LAMBDA_BYTES);
  uint8_t* qtmp = calloc(DMV_TREE_PARAMS.k, row_bytes);
  if (q_columns == NULL || sd == NULL || qtmp == NULL) {
    clear_pointer_array(&q_columns, DMV_CHALLENGE_BITS, row_bytes);
    clear_free(sd, ((size_t)1u << DMV_TREE_PARAMS.k) * DMV_LAMBDA_BYTES);
    clear_free(qtmp, (size_t)DMV_TREE_PARAMS.k * row_bytes);
    clear_free(reconstructed.s, (DMV_TREE_LEAVES - DMV_TAU) * DMV_LAMBDA_BYTES);
    return DMV_ERR_ALLOCATION;
  }

  unsigned int q_index = 0;
  const uint8_t* reconstructed_sd = reconstructed.s;
  for (unsigned int tree = 0; tree != DMV_TAU; ++tree) {
    fill_tree_sd(sd, reconstructed_sd, tree, i_delta[tree]);
    const unsigned int depth =
        direct_convert_to_vole(iv, sd, true, tree, row_bytes, NULL, qtmp);
    if (depth == 0 || q_index + depth > DMV_CHALLENGE_BITS) {
      clear_pointer_array(&q_columns, DMV_CHALLENGE_BITS, row_bytes);
      clear_free(sd, ((size_t)1u << DMV_TREE_PARAMS.k) * DMV_LAMBDA_BYTES);
      clear_free(qtmp, (size_t)DMV_TREE_PARAMS.k * row_bytes);
      clear_free(reconstructed.s, (DMV_TREE_LEAVES - DMV_TAU) * DMV_LAMBDA_BYTES);
      return DMV_ERR_OPENING;
    }
    for (unsigned int level = 0; level != depth; ++level, ++q_index) {
      memcpy(q_columns[q_index], qtmp + (size_t)level * row_bytes, row_bytes);
      if (tree != 0 && ((i_delta[tree] >> level) & 1u) != 0) {
        xor_bytes(q_columns[q_index], corrections + (size_t)(tree - 1u) * row_bytes, row_bytes);
      }
    }
    reconstructed_sd += (size_t)(bavc_max_node_index(tree, DMV_TREE_PARAMS.tau1,
                                                       DMV_TREE_PARAMS.k) - 1u) *
                        DMV_LAMBDA_BYTES;
  }

  transpose_rows_to_fields(q_rows, bit_rows, q_columns);
  uint8_t delta_bytes[DMV_LAMBDA_BYTES] = {0};
  bf2_matrix_mul_tbl(delta_bytes, raw_challenge, DMV_TREE_PARAMS.W_CRT, DMV_CHALLENGE_BITS,
                     DMV_LAMBDA, DMV_TREE_PARAMS.w_crt_words);
  bf256_load(delta_out, delta_bytes);

  secure_clear(delta_bytes, sizeof(delta_bytes));
  clear_pointer_array(&q_columns, DMV_CHALLENGE_BITS, row_bytes);
  clear_free(sd, ((size_t)1u << DMV_TREE_PARAMS.k) * DMV_LAMBDA_BYTES);
  clear_free(qtmp, (size_t)DMV_TREE_PARAMS.k * row_bytes);
  clear_free(reconstructed.s, (DMV_TREE_LEAVES - DMV_TAU) * DMV_LAMBDA_BYTES);
  return DMV_OK;
}

int dmv_derive_leaf_uhash(uint8_t uhash[DMV_LEAF_UHASH_BYTES], const uint8_t iv[16]) {
  if (uhash == NULL || iv == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  H0_context_t context;
  H0_init(&context, DMV_LAMBDA);
  H0_update(&context, iv, 16);
  H0_final(&context, uhash, DMV_LEAF_UHASH_BYTES);
  return DMV_OK;
}

static int fs_part(hash_context* context, const uint8_t* data, size_t length) {
  if (length > UINT32_MAX) {
    return DMV_ERR_SIZE;
  }
  hash_update_uint32_le(context, (uint32_t)length);
  if (length != 0 && data == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  hash_update(context, data, length);
  return DMV_OK;
}

static int fs_hash(uint8_t* out, size_t out_len, const uint8_t* domain, size_t domain_len,
                   const uint8_t* const* parts, const size_t* part_lengths, size_t part_count) {
  if (out == NULL || domain == NULL || parts == NULL || part_lengths == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  hash_context context;
  hash_init(&context, DMV_LAMBDA);
  static const uint8_t transcript_prefix[] = "BL/DMV/FAEST-256F/v1";
  hash_update(&context, transcript_prefix, sizeof(transcript_prefix) - 1u);
  hash_update(&context, domain, domain_len);
  for (size_t i = 0; i != part_count; ++i) {
    int status = fs_part(&context, parts[i], part_lengths[i]);
    if (status != DMV_OK) {
      hash_clear(&context);
      return status;
    }
  }
  hash_final(&context);
  hash_squeeze(&context, out, out_len);
  hash_clear(&context);
  return DMV_OK;
}

int dmv_fs1(uint8_t* out, size_t out_len, const uint8_t* statement, size_t statement_len,
            const uint8_t uhash[DMV_LEAF_UHASH_BYTES], const uint8_t* m1, size_t m1_len,
            const uint8_t nonce1[DMV_NONCE_BYTES]) {
  if (out_len != 264u || uhash == NULL || nonce1 == NULL) {
    return DMV_ERR_SIZE;
  }
  const uint8_t* parts[] = {statement, uhash, m1, nonce1};
  const size_t lengths[] = {statement_len, DMV_LEAF_UHASH_BYTES, m1_len, DMV_NONCE_BYTES};
  return fs_hash(out, out_len, (const uint8_t*)"FS1", 3, parts, lengths, 4);
}

int dmv_fs2(uint8_t* out, size_t out_len, const uint8_t* statement, size_t statement_len,
            const uint8_t uhash[DMV_LEAF_UHASH_BYTES], const uint8_t* m1, size_t m1_len,
            const uint8_t nonce1[DMV_NONCE_BYTES], const uint8_t gamma1[DMV_FS1_BYTES],
            const uint8_t* m2, size_t m2_len,
            const uint8_t nonce2[DMV_NONCE_BYTES]) {
  if (out_len != DMV_FS2_BYTES || uhash == NULL || nonce1 == NULL || gamma1 == NULL ||
      nonce2 == NULL) {
    return DMV_ERR_SIZE;
  }
  const uint8_t* parts[] = {statement, uhash, m1, nonce1, gamma1, m2, nonce2};
  const size_t lengths[] = {statement_len, DMV_LEAF_UHASH_BYTES, m1_len, DMV_NONCE_BYTES,
                            DMV_FS1_BYTES, m2_len, DMV_NONCE_BYTES};
  return fs_hash(out, out_len, (const uint8_t*)"FS2", 3, parts, lengths, 7);
}

int dmv_fs3(uint8_t out[DMV_LAMBDA_BYTES], const uint8_t* statement, size_t statement_len,
            const uint8_t uhash[DMV_LEAF_UHASH_BYTES], const uint8_t* m1, size_t m1_len,
            const uint8_t nonce1[DMV_NONCE_BYTES], const uint8_t gamma1[DMV_FS1_BYTES],
            const uint8_t* m2, size_t m2_len, const uint8_t nonce2[DMV_NONCE_BYTES],
            const uint8_t gamma2[DMV_FS2_BYTES], const uint8_t* m3, size_t m3_len,
            const uint8_t nonce3[DMV_NONCE_BYTES]) {
  if (out == NULL || uhash == NULL || nonce1 == NULL || gamma1 == NULL || nonce2 == NULL ||
      gamma2 == NULL || nonce3 == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  const uint8_t* parts[] = {statement, uhash, m1, nonce1, gamma1, m2, nonce2, gamma2, m3, nonce3};
  const size_t lengths[] = {statement_len, DMV_LEAF_UHASH_BYTES, m1_len, DMV_NONCE_BYTES,
                            DMV_FS1_BYTES, m2_len, DMV_NONCE_BYTES, DMV_FS2_BYTES, m3_len,
                            DMV_NONCE_BYTES};
  return fs_hash(out, DMV_LAMBDA_BYTES, (const uint8_t*)"FS3", 3, parts, lengths, 10);
}

static int checked_add_size(size_t lhs, size_t rhs, size_t* out) {
  if (out == NULL || rhs > SIZE_MAX - lhs) {
    return DMV_ERR_SIZE;
  }
  *out = lhs + rhs;
  return DMV_OK;
}

static int random_fill(dmv_random_bytes_fn random_bytes, void* random_context, uint8_t* out,
                       size_t length) {
  if (random_bytes == NULL || out == NULL ||
      random_bytes(random_context, out, length) != 0) {
    return DMV_ERR_RETRY;
  }
  return DMV_OK;
}

static void load_field(const uint8_t* source, bf256_t* destination) {
  bf256_load(destination, source);
}

static void store_field(uint8_t* destination, const bf256_t* source) {
  bf256_store(destination, source);
}

static void add_delta_bit(bf256_t* value, const bf256_t* delta, unsigned int bit) {
  if (bit != 0) {
    bf256_add_inplace(value, delta);
  }
}

static int map_dmk_status(int status) {
  if (status == DMK_OK) {
    return DMV_OK;
  }
  if (status == DMK_ERR_ARGUMENT) {
    return DMV_ERR_ARGUMENT;
  }
  if (status == DMK_ERR_DIMENSION) {
    return DMV_ERR_SIZE;
  }
  return DMV_ERR_RELATION;
}

static int get_commitment_masks(const dmv_commitment_t* commitment,
                                bf256_t masks[DMV_MASK_COUNT]) {
  if (commitment == NULL || masks == NULL || !commitment->initialized) {
    return DMV_ERR_ARGUMENT;
  }
  return map_dmk_status(dmk_pack_mask_rows(
      commitment->v_rows + commitment->descriptor.witness_bits,
      DMV_MASK_COUNT * DMV_LAMBDA, masks));
}

static int get_u_masks(const dmv_commitment_t* commitment, bf256_t masks[DMV_MASK_COUNT]) {
  if (commitment == NULL || masks == NULL || !commitment->initialized) {
    return DMV_ERR_ARGUMENT;
  }
  const uint32_t offset = commitment->descriptor.witness_bits;
  return map_dmk_status(dmk_pack_mask_bits(
      commitment->u_bits + offset / 8u, DMV_MASK_COUNT * DMV_LAMBDA / 8u, masks));
}

static int get_row_masks(const bf256_t* rows, uint32_t offset,
                         bf256_t masks[DMV_MASK_COUNT]) {
  if (rows == NULL || masks == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  return map_dmk_status(dmk_pack_mask_rows(rows + offset, DMV_MASK_COUNT * DMV_LAMBDA, masks));
}

/* Exact pinned FAEST VOLEHash-256.  It includes the short 64-bit challenge and all
 * six packed mask blocks: blocks 0 and 1 are the recurrence coordinates and blocks
 * 2 through 5 are the additive output coordinates. */
int dmv_vh_eval(const uint8_t gamma1[DMV_FS1_BYTES], const bf256_t* rows, uint32_t row_count,
                const bf256_t masks[DMV_MASK_COUNT], bf256_t out[4]) {
  if (gamma1 == NULL || rows == NULL || masks == NULL || out == NULL || row_count == 0) {
    return DMV_ERR_ARGUMENT;
  }
  return map_dmk_status(dmk_vh(gamma1, rows, row_count, masks, out));
}

static int proof_lengths_valid(const dmv_proof_t* proof) {
  if (proof == NULL || dmv_descriptor_validate(&proof->descriptor) != DMV_OK ||
      proof->statement_len > UINT32_MAX ||
      (proof->statement_len != 0 && proof->statement == NULL)) {
    return DMV_ERR_ARGUMENT;
  }
  if (proof->m1_len != dmv_m1_bytes(&proof->descriptor) ||
      proof->m2_len != dmv_m2_bytes(&proof->descriptor) || proof->m3_len != dmv_m3_bytes() ||
      proof->m4_len != dmv_m4_bytes() || proof->m1 == NULL || proof->m2 == NULL ||
      proof->m3 == NULL || proof->m4 == NULL) {
    return DMV_ERR_SIZE;
  }
  return DMV_OK;
}

void dmv_proof_clear(dmv_proof_t* proof) {
  if (proof == NULL) {
    return;
  }
  clear_free(proof->statement, proof->statement_len);
  clear_free(proof->m1, proof->m1_len);
  clear_free(proof->m2, proof->m2_len);
  clear_free(proof->m3, proof->m3_len);
  clear_free(proof->m4, proof->m4_len);
  secure_clear(proof->nu, sizeof(proof->nu));
  secure_clear(proof->sigma1, sizeof(proof->sigma1));
  secure_clear(proof->sigma2, sizeof(proof->sigma2));
  secure_clear(proof->sigma3, sizeof(proof->sigma3));
  memset(proof, 0, sizeof(*proof));
}

static void put_u32_le(uint8_t* destination, uint32_t value) {
  destination[0] = (uint8_t)value;
  destination[1] = (uint8_t)(value >> 8);
  destination[2] = (uint8_t)(value >> 16);
  destination[3] = (uint8_t)(value >> 24);
}

static uint32_t get_u32_le(const uint8_t* source) {
  return (uint32_t)source[0] | ((uint32_t)source[1] << 8) | ((uint32_t)source[2] << 16) |
         ((uint32_t)source[3] << 24);
}

static void copy_if_nonzero(void* destination, const void* source, size_t length) {
  if (length != 0) {
    memcpy(destination, source, length);
  }
}

static void clear_free(void* pointer, size_t length) {
  if (pointer != NULL) {
    secure_clear(pointer, length);
    free(pointer);
  }
}

static int proof_wire_size_internal(const dmv_proof_t* proof, size_t* size_out) {
  if (proof_lengths_valid(proof) != DMV_OK || size_out == NULL) {
    return proof == NULL || size_out == NULL ? DMV_ERR_ARGUMENT : DMV_ERR_SIZE;
  }
  size_t total = DMV_WIRE_HEADER_BYTES;
  const size_t parts[] = {proof->statement_len, DMV_LEAF_UHASH_BYTES,
                          3u * DMV_NONCE_BYTES, proof->m1_len, proof->m2_len, proof->m3_len,
                          proof->m4_len};
  for (size_t i = 0; i != sizeof(parts) / sizeof(parts[0]); ++i) {
    if (checked_add_size(total, parts[i], &total) != DMV_OK) {
      return DMV_ERR_SIZE;
    }
  }
  *size_out = total;
  return DMV_OK;
}

int dmv_proof_wire_size(const dmv_proof_t* proof, size_t* size_out) {
  return proof_wire_size_internal(proof, size_out);
}

int dmv_proof_encode(const dmv_proof_t* proof, uint8_t* wire, size_t wire_len,
                     size_t* written_out) {
  size_t expected = 0;
  int status = proof_wire_size_internal(proof, &expected);
  if (status != DMV_OK) {
    return status;
  }
  if (wire == NULL || wire_len != expected) {
    return DMV_ERR_SIZE;
  }
  memset(wire, 0, DMV_WIRE_HEADER_BYTES);
  memcpy(wire, "DMV1", 4);
  wire[4] = DMV_WIRE_VERSION;
  put_u32_le(wire + 8, proof->descriptor.witness_bits);
  put_u32_le(wire + 12, proof->descriptor.constraint_count);
  wire[16] = proof->descriptor.degree;
  put_u32_le(wire + 20, (uint32_t)proof->statement_len);
  put_u32_le(wire + 24, (uint32_t)proof->m1_len);
  put_u32_le(wire + 28, (uint32_t)proof->m2_len);
  put_u32_le(wire + 32, (uint32_t)proof->m3_len);
  put_u32_le(wire + 36, (uint32_t)proof->m4_len);
  size_t offset = DMV_WIRE_HEADER_BYTES;
#define DMV_WIRE_COPY(ptr, len)                                                                    \
  do {                                                                                             \
    copy_if_nonzero(wire + offset, (ptr), (len));                                                  \
    offset += (len);                                                                               \
  } while (0)
  DMV_WIRE_COPY(proof->statement, proof->statement_len);
  DMV_WIRE_COPY(proof->nu, DMV_LEAF_UHASH_BYTES);
  DMV_WIRE_COPY(proof->sigma1, DMV_NONCE_BYTES);
  DMV_WIRE_COPY(proof->sigma2, DMV_NONCE_BYTES);
  DMV_WIRE_COPY(proof->sigma3, DMV_NONCE_BYTES);
  DMV_WIRE_COPY(proof->m1, proof->m1_len);
  DMV_WIRE_COPY(proof->m2, proof->m2_len);
  DMV_WIRE_COPY(proof->m3, proof->m3_len);
  DMV_WIRE_COPY(proof->m4, proof->m4_len);
#undef DMV_WIRE_COPY
  if (offset != expected) {
    return DMV_ERR_ENCODING;
  }
  if (written_out != NULL) {
    *written_out = offset;
  }
  return DMV_OK;
}

int dmv_proof_decode(dmv_proof_t* proof, const uint8_t* wire, size_t wire_len) {
  if (proof == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  /* Decode is a destructive destination operation: every failure leaves a zeroed proof. */
  dmv_proof_clear(proof);
  if (wire == NULL || wire_len < DMV_WIRE_HEADER_BYTES) {
    return DMV_ERR_ARGUMENT;
  }
  if (memcmp(wire, "DMV1", 4) != 0 || wire[4] != DMV_WIRE_VERSION || wire[5] != 0 || wire[6] != 0 ||
      wire[7] != 0 || wire[17] != 0 || wire[18] != 0 || wire[19] != 0) {
    return DMV_ERR_ENCODING;
  }
  dmv_descriptor_t descriptor = {get_u32_le(wire + 8), get_u32_le(wire + 12), wire[16]};
  if (dmv_descriptor_validate(&descriptor) != DMV_OK) {
    return DMV_ERR_DESCRIPTOR;
  }
  dmv_proof_t decoded;
  memset(&decoded, 0, sizeof(decoded));
  decoded.descriptor = descriptor;
  decoded.statement_len = get_u32_le(wire + 20);
  decoded.m1_len = get_u32_le(wire + 24);
  decoded.m2_len = get_u32_le(wire + 28);
  decoded.m3_len = get_u32_le(wire + 32);
  decoded.m4_len = get_u32_le(wire + 36);
  if (decoded.m1_len != dmv_m1_bytes(&descriptor) || decoded.m2_len != dmv_m2_bytes(&descriptor) ||
      decoded.m3_len != dmv_m3_bytes() || decoded.m4_len != dmv_m4_bytes()) {
    return DMV_ERR_SIZE;
  }
  size_t expected = DMV_WIRE_HEADER_BYTES;
  const size_t wire_parts[] = {decoded.statement_len, DMV_LEAF_UHASH_BYTES,
                               3u * DMV_NONCE_BYTES, decoded.m1_len, decoded.m2_len,
                               decoded.m3_len, decoded.m4_len};
  for (size_t i = 0; i != sizeof(wire_parts) / sizeof(wire_parts[0]); ++i) {
    if (checked_add_size(expected, wire_parts[i], &expected) != DMV_OK) {
      return DMV_ERR_SIZE;
    }
  }
  if (expected != wire_len) {
    return DMV_ERR_SIZE;
  }
  size_t offset = DMV_WIRE_HEADER_BYTES;
  if (decoded.statement_len != 0) {
    decoded.statement = malloc(decoded.statement_len);
  }
  decoded.m1 = malloc(decoded.m1_len);
  decoded.m2 = malloc(decoded.m2_len);
  decoded.m3 = malloc(decoded.m3_len);
  decoded.m4 = malloc(decoded.m4_len);
  if ((decoded.statement_len != 0 && decoded.statement == NULL) || decoded.m1 == NULL ||
      decoded.m2 == NULL || decoded.m3 == NULL || decoded.m4 == NULL) {
    dmv_proof_clear(&decoded);
    return DMV_ERR_ALLOCATION;
  }
#define DMV_WIRE_READ(ptr, len)                                                                    \
  do {                                                                                             \
    copy_if_nonzero((ptr), wire + offset, (len));                                                  \
    offset += (len);                                                                               \
  } while (0)
  DMV_WIRE_READ(decoded.statement, decoded.statement_len);
  DMV_WIRE_READ(decoded.nu, DMV_LEAF_UHASH_BYTES);
  DMV_WIRE_READ(decoded.sigma1, DMV_NONCE_BYTES);
  DMV_WIRE_READ(decoded.sigma2, DMV_NONCE_BYTES);
  DMV_WIRE_READ(decoded.sigma3, DMV_NONCE_BYTES);
  DMV_WIRE_READ(decoded.m1, decoded.m1_len);
  DMV_WIRE_READ(decoded.m2, decoded.m2_len);
  DMV_WIRE_READ(decoded.m3, decoded.m3_len);
  DMV_WIRE_READ(decoded.m4, decoded.m4_len);
#undef DMV_WIRE_READ
  if (offset != expected) {
    dmv_proof_clear(&decoded);
    return DMV_ERR_ENCODING;
  }
  decoded.initialized = true;
  *proof = decoded;
  return DMV_OK;
}

static int make_witness_correction(uint8_t* correction, const uint8_t* witness,
                                   const dmv_commitment_t* commitment) {
  if (correction == NULL || witness == NULL || commitment == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  const size_t witness_bytes = commitment->descriptor.witness_bits / 8u;
  for (size_t i = 0; i != witness_bytes; ++i) {
    correction[i] = witness[i] ^ commitment->u_bits[i];
  }
  clear_padding_bits(correction, commitment->descriptor.witness_bits);
  return DMV_OK;
}

static int parse_m2(const dmv_descriptor_t* descriptor, const uint8_t* m2, size_t m2_len,
                    bf256_t tilde_u[4], bf256_t difference[4], const uint8_t** correction_out) {
  if (descriptor == NULL || m2 == NULL || tilde_u == NULL || difference == NULL ||
      correction_out == NULL || m2_len != dmv_m2_bytes(descriptor)) {
    return DMV_ERR_SIZE;
  }
  for (unsigned int lane = 0; lane != 4; ++lane) {
    load_field(m2 + lane * DMV_LAMBDA_BYTES, &tilde_u[lane]);
    load_field(m2 + (4u + lane) * DMV_LAMBDA_BYTES, &difference[lane]);
  }
  *correction_out = m2 + 8u * DMV_LAMBDA_BYTES;
  return DMV_OK;
}

static void evaluate_three_coefficient(const uint8_t m3[DMV_LAMBDA_BYTES * 3u],
                                       const bf256_t* delta, bf256_t* value) {
  bf256_t a0;
  bf256_t a1;
  bf256_t a2;
  load_field(m3, &a0);
  load_field(m3 + DMV_LAMBDA_BYTES, &a1);
  load_field(m3 + 2u * DMV_LAMBDA_BYTES, &a2);
  *value = a2;
  bf256_mul_inplace(value, delta);
  bf256_add_inplace(value, &a1);
  bf256_mul_inplace(value, delta);
  bf256_add_inplace(value, &a0);
}

static int validate_expected_statement(const dmv_proof_t* proof,
                                       const dmv_descriptor_t* expected_descriptor,
                                       const uint8_t* expected_statement,
                                       size_t expected_statement_len) {
  if (proof == NULL || !proof->initialized || expected_descriptor == NULL ||
      dmv_descriptor_validate(expected_descriptor) != DMV_OK ||
      proof->descriptor.witness_bits != expected_descriptor->witness_bits ||
      proof->descriptor.constraint_count != expected_descriptor->constraint_count ||
      proof->descriptor.degree != expected_descriptor->degree ||
      proof->statement_len != expected_statement_len ||
      (expected_statement_len != 0 && (expected_statement == NULL || proof->statement == NULL)) ||
      (expected_statement_len != 0 &&
       memcmp(proof->statement, expected_statement, expected_statement_len) != 0)) {
    return DMV_ERR_ARGUMENT;
  }
  return proof_lengths_valid(proof);
}

static int dmv_poly_hash_coefficient_sink(void* context, uint32_t row,
                                          const bf256_t coefficients[DMV_DEGREE + 1u]) {
  return map_dmk_status(dmk_poly_hash_update(context, row, coefficients));
}

int dmv_prove(dmv_proof_t* proof, const dmv_descriptor_t* descriptor, const uint8_t* statement,
              size_t statement_len, const uint8_t* witness, size_t witness_bytes,
              dmv_random_bytes_fn random_bytes, void* random_context,
              const dmv_relation_callbacks_t* relation, void* relation_context,
              uint32_t max_final_retries) {
  /* The transcript implements q = v + Delta*u, d_w = w + u, and hence
   * q' = q + Delta*d_w = v + Delta*w.  D and tilde_u are the corresponding
   * affine pieces of the linear VH hash.  The relation adapter supplies the
   * four coefficients of each F_j(Z)=Z^3*f_j(rho_j/Z); the three ZK-hash
   * outputs become a0,a1,a2 and are evaluated only after Delta is known. */
  if (proof == NULL) {
    return DMV_ERR_ARGUMENT;
  }
  /* Prove is a destructive destination operation: every failure leaves a zeroed proof. */
  dmv_proof_clear(proof);
  if (descriptor == NULL ||
      dmv_descriptor_validate(descriptor) != DMV_OK ||
      (statement_len != 0 && statement == NULL) || witness == NULL ||
      witness_bytes != descriptor->witness_bits / 8u || random_bytes == NULL || relation == NULL ||
      relation->prove == NULL || relation->verify == NULL || max_final_retries == 0 ||
      max_final_retries > DMV_MAX_FINAL_RETRIES) {
    return (max_final_retries == 0 || max_final_retries > DMV_MAX_FINAL_RETRIES) ? DMV_ERR_RETRY
                                                                                  : DMV_ERR_ARGUMENT;
  }
  dmv_commitment_t commitment;
  memset(&commitment, 0, sizeof(commitment));
  uint8_t root[DMV_LAMBDA_BYTES];
  uint8_t iv[16];
  int status = random_fill(random_bytes, random_context, root, sizeof(root));
  if (status == DMV_OK) {
    status = random_fill(random_bytes, random_context, iv, sizeof(iv));
  }
  if (status != DMV_OK || dmv_commit(&commitment, descriptor, root, iv) != DMV_OK) {
    secure_clear(root, sizeof(root));
    secure_clear(iv, sizeof(iv));
    dmv_commit_clear(&commitment);
    return status == DMV_OK ? DMV_ERR_COMMITMENT : status;
  }

  const size_t m1_len = dmv_m1_bytes(descriptor);
  const size_t m2_len = dmv_m2_bytes(descriptor);
  const size_t m3_len = dmv_m3_bytes();
  const size_t m4_len = dmv_m4_bytes();
  uint8_t* m1 = malloc(m1_len);
  uint8_t* m2 = malloc(m2_len);
  uint8_t* m3 = malloc(m3_len);
  uint8_t* m4 = malloc(m4_len);
  uint8_t* witness_correction = malloc(witness_bytes);
  size_t statement_copy_len = statement_len;
  uint8_t* statement_copy = statement_copy_len == 0 ? NULL : malloc(statement_copy_len);
  if (m1 == NULL || m2 == NULL || m3 == NULL || m4 == NULL || witness_correction == NULL ||
      (statement_copy_len != 0 && statement_copy == NULL)) {
    clear_free(m1, m1_len);
    clear_free(m2, m2_len);
    clear_free(m3, m3_len);
    clear_free(m4, m4_len);
    clear_free(witness_correction, witness_bytes);
    clear_free(statement_copy, statement_copy_len);
    secure_clear(root, sizeof(root));
    secure_clear(iv, sizeof(iv));
    secure_clear(proof->nu, sizeof(proof->nu));
    secure_clear(proof->sigma1, sizeof(proof->sigma1));
    secure_clear(proof->sigma2, sizeof(proof->sigma2));
    secure_clear(proof->sigma3, sizeof(proof->sigma3));
    dmv_commit_clear(&commitment);
    return DMV_ERR_ALLOCATION;
  }
  memcpy(m1, iv, 16);
  memcpy(m1 + 16, dmv_bavc_commitment(&commitment), DMV_BAVC_COMMITMENT_BYTES);
  memcpy(m1 + 16u + DMV_BAVC_COMMITMENT_BYTES, dmv_corrections(&commitment),
         dmv_correction_bytes(descriptor));
  if (statement_copy_len != 0) {
    memcpy(statement_copy, statement, statement_copy_len);
  }
  status = dmv_derive_leaf_uhash(proof->nu, iv);
  secure_clear(root, sizeof(root));
  secure_clear(iv, sizeof(iv));
  if (status != DMV_OK || make_witness_correction(witness_correction, witness, &commitment) != DMV_OK ||
      random_fill(random_bytes, random_context, proof->sigma1, sizeof(proof->sigma1)) != DMV_OK) {
    clear_free(m1, m1_len);
    clear_free(m2, m2_len);
    clear_free(m3, m3_len);
    clear_free(m4, m4_len);
    clear_free(witness_correction, witness_bytes);
    clear_free(statement_copy, statement_copy_len);
    secure_clear(proof->nu, sizeof(proof->nu));
    secure_clear(proof->sigma1, sizeof(proof->sigma1));
    secure_clear(proof->sigma2, sizeof(proof->sigma2));
    secure_clear(proof->sigma3, sizeof(proof->sigma3));
    dmv_commit_clear(&commitment);
    return DMV_ERR_RETRY;
  }

  uint8_t gamma1[DMV_FS1_BYTES] = {0};
  uint8_t gamma2[DMV_FS2_BYTES] = {0};
  bf256_t v_masks[DMV_MASK_COUNT] = {0};
  bf256_t u_masks[DMV_MASK_COUNT] = {0};
  status = dmv_fs1(gamma1, sizeof(gamma1), statement, statement_len, proof->nu, m1, m1_len,
                   proof->sigma1);
  if (status == DMV_OK) {
    bf256_t* u_field_rows = malloc((size_t)descriptor->witness_bits * sizeof(*u_field_rows));
    if (u_field_rows == NULL) {
      status = DMV_ERR_ALLOCATION;
    } else {
      bf256_t tilde_u[4];
      bf256_t difference[4];
      status = get_commitment_masks(&commitment, v_masks);
      if (status == DMV_OK) {
        status = get_u_masks(&commitment, u_masks);
      }
      if (status == DMV_OK) {
        for (uint32_t row = 0; row != descriptor->witness_bits; ++row) {
          u_field_rows[row] = bf256_from_bit(ptr_get_bit(dmv_u_bits(&commitment), row));
        }
        status = dmv_vh_eval(gamma1, dmv_v_rows(&commitment), descriptor->witness_bits, v_masks,
                             difference);
      }
      if (status == DMV_OK) {
        status = dmv_vh_eval(gamma1, u_field_rows, descriptor->witness_bits, u_masks, tilde_u);
      }
      if (status == DMV_OK) {
        for (unsigned int lane = 0; lane != 4; ++lane) {
          store_field(m2 + lane * DMV_LAMBDA_BYTES, &tilde_u[lane]);
          store_field(m2 + (4u + lane) * DMV_LAMBDA_BYTES, &difference[lane]);
        }
        memcpy(m2 + 8u * DMV_LAMBDA_BYTES, witness_correction, witness_bytes);
        if (random_fill(random_bytes, random_context, proof->sigma2, sizeof(proof->sigma2)) !=
            DMV_OK) {
          status = DMV_ERR_RETRY;
        } else {
          status = dmv_fs2(gamma2, sizeof(gamma2), statement, statement_len, proof->nu, m1,
                           m1_len, proof->sigma1, gamma1, m2, m2_len, proof->sigma2);
        }
      }
      clear_free(u_field_rows, (size_t)descriptor->witness_bits * sizeof(*u_field_rows));
      secure_clear(tilde_u, sizeof(tilde_u));
      secure_clear(difference, sizeof(difference));
    }
  }
  if (status == DMV_OK) {
    dmk_poly_hash hash = {0};
    bf256_t coefficients[DMV_DEGREE] = {0};
    if (dmk_poly_hash_init(&hash, gamma2, descriptor->constraint_count) != DMK_OK) {
      status = DMV_ERR_RELATION;
    } else {
      const int relation_status =
          relation->prove(relation_context, descriptor, dmv_v_rows(&commitment),
                          commitment.bit_rows, witness, witness_bytes,
                          dmv_poly_hash_coefficient_sink, &hash);
      if (relation_status != DMV_OK ||
          dmk_poly_hash_finish(&hash, u_masks, v_masks, coefficients) != DMK_OK) {
        status = DMV_ERR_RELATION;
      } else {
        for (unsigned int coefficient = 0; coefficient != DMV_DEGREE; ++coefficient) {
          store_field(m3 + coefficient * DMV_LAMBDA_BYTES, &coefficients[coefficient]);
        }
      }
      /* dmk_poly_hash_finish clears on success and terminal error; this also
       * covers an adapter failure before the first coefficient reaches it. */
      dmk_poly_hash_clear(&hash);
      secure_clear(coefficients, sizeof(coefficients));
    }
  }
  bool final_found = false;
  if (status == DMV_OK) {
    uint8_t gamma3[DMV_FS3_BYTES] = {0};
    for (uint32_t attempt = 0; attempt != max_final_retries; ++attempt) {
      if (random_fill(random_bytes, random_context, proof->sigma3, sizeof(proof->sigma3)) != DMV_OK) {
        continue;
      }
      if (dmv_fs3(gamma3, statement, statement_len, proof->nu, m1, m1_len, proof->sigma1,
                  gamma1, m2, m2_len, proof->sigma2, gamma2, m3, m3_len, proof->sigma3) !=
              DMV_OK ||
          !valid_raw_challenge(gamma3) ||
          dmv_open(&commitment, gamma3, m4, m4_len) != DMV_OK) {
        continue;
      }
      final_found = true;
      break;
    }
    secure_clear(gamma3, sizeof(gamma3));
  }
  if (!final_found) {
    clear_free(m1, m1_len);
    clear_free(m2, m2_len);
    clear_free(m3, m3_len);
    clear_free(m4, m4_len);
    clear_free(witness_correction, witness_bytes);
    clear_free(statement_copy, statement_copy_len);
    secure_clear(gamma1, sizeof(gamma1));
    secure_clear(gamma2, sizeof(gamma2));
    secure_clear(v_masks, sizeof(v_masks));
    secure_clear(u_masks, sizeof(u_masks));
    secure_clear(proof->nu, sizeof(proof->nu));
    secure_clear(proof->sigma1, sizeof(proof->sigma1));
    secure_clear(proof->sigma2, sizeof(proof->sigma2));
    secure_clear(proof->sigma3, sizeof(proof->sigma3));
    dmv_commit_clear(&commitment);
    return status == DMV_OK ? DMV_ERR_RETRY : status;
  }
  proof->descriptor = *descriptor;
  proof->statement = statement_copy;
  proof->statement_len = statement_copy_len;
  proof->m1 = m1;
  proof->m2 = m2;
  proof->m3 = m3;
  proof->m4 = m4;
  proof->m1_len = m1_len;
  proof->m2_len = m2_len;
  proof->m3_len = m3_len;
  proof->m4_len = m4_len;
  proof->initialized = true;
  clear_free(witness_correction, witness_bytes);
  secure_clear(gamma1, sizeof(gamma1));
  secure_clear(gamma2, sizeof(gamma2));
  secure_clear(v_masks, sizeof(v_masks));
  secure_clear(u_masks, sizeof(u_masks));
  dmv_commit_clear(&commitment);
  return DMV_OK;
}

int dmv_verify(const dmv_proof_t* proof, const dmv_descriptor_t* expected_descriptor,
               const uint8_t* expected_statement, size_t expected_statement_len,
               const dmv_relation_callbacks_t* relation, void* relation_context) {
  /* The opening is checked before relation evaluation.  This ensures the
   * relation callback receives authenticated q' and the explicit mask term
   * bar_q0 + Delta*bar_q1, rather than caller-controlled field rows. */
  int status = validate_expected_statement(proof, expected_descriptor, expected_statement,
                                            expected_statement_len);
  if (status != DMV_OK || relation == NULL || relation->verify == NULL) {
    return status == DMV_OK ? DMV_ERR_ARGUMENT : status;
  }

  const uint8_t* iv = proof->m1;
  uint8_t recomputed_nu[DMV_LEAF_UHASH_BYTES] = {0};
  uint8_t gamma1[DMV_FS1_BYTES] = {0};
  uint8_t gamma2[DMV_FS2_BYTES] = {0};
  uint8_t gamma3[DMV_FS3_BYTES] = {0};
  uint8_t reconstructed_commitment[DMV_BAVC_COMMITMENT_BYTES] = {0};
  bf256_t delta = {0};
  bf256_t tilde_u[4] = {0};
  bf256_t difference[4] = {0};
  bf256_t masks[DMV_MASK_COUNT] = {0};
  bf256_t vh[4] = {0};
  bf256_t mask_term = {0};
  bf256_t mask_delta = {0};
  bf256_t expected_b = {0};
  const uint8_t* witness_correction = NULL;
  bf256_t* q_rows = NULL;
  bf256_t* q_prime = NULL;
  size_t q_rows_bytes = 0;
  int result = DMV_OK;

  if (dmv_derive_leaf_uhash(recomputed_nu, iv) != DMV_OK ||
      memcmp(recomputed_nu, proof->nu, sizeof(recomputed_nu)) != 0) {
    result = DMV_ERR_COMMITMENT;
    goto verify_cleanup;
  }

  if (dmv_fs1(gamma1, sizeof(gamma1), proof->statement, proof->statement_len, proof->nu,
              proof->m1, proof->m1_len, proof->sigma1) != DMV_OK ||
      dmv_fs2(gamma2, sizeof(gamma2), proof->statement, proof->statement_len, proof->nu,
              proof->m1, proof->m1_len, proof->sigma1, gamma1, proof->m2, proof->m2_len,
              proof->sigma2) != DMV_OK ||
      dmv_fs3(gamma3, proof->statement, proof->statement_len, proof->nu, proof->m1, proof->m1_len,
              proof->sigma1, gamma1, proof->m2, proof->m2_len, proof->sigma2, gamma2, proof->m3,
              proof->m3_len, proof->sigma3) != DMV_OK ||
      !valid_raw_challenge(gamma3)) {
    result = DMV_ERR_CHALLENGE;
    goto verify_cleanup;
  }

  const size_t correction_bytes = dmv_correction_bytes(&proof->descriptor);
  if (proof->m1_len != 16u + DMV_BAVC_COMMITMENT_BYTES + correction_bytes) {
    result = DMV_ERR_SIZE;
    goto verify_cleanup;
  }
  const size_t bit_rows = (size_t)proof->descriptor.witness_bits + DMV_MASK_COUNT * DMV_LAMBDA;
  if (checked_mul_size(bit_rows, sizeof(bf256_t), &q_rows_bytes) != DMV_OK) {
    result = DMV_ERR_SIZE;
    goto verify_cleanup;
  }
  q_rows = calloc(bit_rows, sizeof(*q_rows));
  if (q_rows == NULL) {
    result = DMV_ERR_ALLOCATION;
    goto verify_cleanup;
  }
  status = dmv_reconstruct(&proof->descriptor, iv, gamma3, proof->m4, proof->m4_len,
                           proof->m1 + 16u + DMV_BAVC_COMMITMENT_BYTES, correction_bytes,
                           reconstructed_commitment, q_rows, bit_rows, &delta);
  if (status != DMV_OK) {
    result = status;
    goto verify_cleanup;
  }
  if (memcmp(reconstructed_commitment, proof->m1 + 16u, DMV_BAVC_COMMITMENT_BYTES) != 0) {
    result = DMV_ERR_COMMITMENT;
    goto verify_cleanup;
  }

  status = parse_m2(&proof->descriptor, proof->m2, proof->m2_len, tilde_u, difference,
                    &witness_correction);
  if (status != DMV_OK) {
    result = status;
    goto verify_cleanup;
  }
  status = get_row_masks(q_rows, proof->descriptor.witness_bits, masks);
  if (status != DMV_OK) {
    result = status;
    goto verify_cleanup;
  }
  status = dmv_vh_eval(gamma1, q_rows, proof->descriptor.witness_bits, masks, vh);
  if (status != DMV_OK) {
    result = status;
    goto verify_cleanup;
  }
  for (unsigned int lane = 0; lane != 4; ++lane) {
    bf256_t expected = tilde_u[lane];
    bf256_mul_inplace(&expected, &delta);
    bf256_add_inplace(&expected, &difference[lane]);
    if (memcmp(&expected, &vh[lane], sizeof(expected)) != 0) {
      secure_clear(&expected, sizeof(expected));
      result = DMV_ERR_COMMITMENT;
      goto verify_cleanup;
    }
    secure_clear(&expected, sizeof(expected));
  }

  q_prime = malloc(q_rows_bytes);
  if (q_prime == NULL) {
    result = DMV_ERR_ALLOCATION;
    goto verify_cleanup;
  }
  memcpy(q_prime, q_rows, q_rows_bytes);
  for (uint32_t row = 0; row != proof->descriptor.witness_bits; ++row) {
    add_delta_bit(&q_prime[row], &delta, ptr_get_bit(witness_correction, row));
  }
  mask_term = masks[0];
  bf256_mul(&mask_delta, &delta, &masks[1]);
  bf256_add_inplace(&mask_term, &mask_delta);
  evaluate_three_coefficient(proof->m3, &delta, &expected_b);
  status = relation->verify(relation_context, &proof->descriptor, q_prime, (uint32_t)bit_rows,
                            &mask_term, gamma2, &delta, &expected_b);
  result = status == DMV_OK ? DMV_OK : DMV_ERR_RELATION;

verify_cleanup:
  clear_free(q_prime, q_rows_bytes);
  clear_free(q_rows, q_rows_bytes);
  secure_clear(recomputed_nu, sizeof(recomputed_nu));
  secure_clear(gamma1, sizeof(gamma1));
  secure_clear(gamma2, sizeof(gamma2));
  secure_clear(gamma3, sizeof(gamma3));
  secure_clear(reconstructed_commitment, sizeof(reconstructed_commitment));
  secure_clear(&delta, sizeof(delta));
  secure_clear(tilde_u, sizeof(tilde_u));
  secure_clear(difference, sizeof(difference));
  secure_clear(masks, sizeof(masks));
  secure_clear(vh, sizeof(vh));
  secure_clear(&mask_term, sizeof(mask_term));
  secure_clear(&mask_delta, sizeof(mask_delta));
  secure_clear(&expected_b, sizeof(expected_b));
  return result;
}
