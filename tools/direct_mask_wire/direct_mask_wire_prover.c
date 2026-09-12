/* SPDX-License-Identifier: MIT */

/*
 * Non-activating process prover.  The synthetic source fixture and native witness are private to
 * this process; only the independently framed statement and proof are written to stdout for the
 * bounded in-memory process harness.  This is a lower-bound integration fixture, not a security
 * qualification or production protocol endpoint.
 */

#include "direct_mask_wire.h"
#include "direct_mask_native.h"
#include "aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

static void secure_clear(void* pointer, size_t bytes) {
  if (pointer == NULL) {
    return;
  }
  volatile uint8_t* cursor = (volatile uint8_t*)pointer;
  while (bytes-- != 0) {
    *cursor++ = 0;
  }
}

static void compute_tag(uint8_t output[DM_WIRE_T_BYTES], const uint8_t input[DM_WIRE_U_BYTES],
                        const uint8_t g0[DMN_G0_BYTES]) {
  bf768_t product;
  bf768_t z;
  bf256_t k;
  bf768_load(&product, input);
  bf256_load(&k, g0);
  bf768_mul_256_inplace(&product, &k);
  bf768_load(&z, g0 + DM_WIRE_FIELD_BYTES);
  bf768_add_inplace(&product, &z);
  bf768_store(output, &product);
  secure_clear(&product, sizeof(product));
  secure_clear(&z, sizeof(z));
  secure_clear(&k, sizeof(k));
}

static void make_instance(dmk_instance* instance, const uint8_t root[DMN_ROOT_BYTES]) {
  static const uint8_t source_suite[DM_WIRE_SOURCE_SUITE_BYTES] = {
      'S', 'B', 'A', '1', '-', 'S', 'R', 'C', '-', 'C', 'M', 'T', '-', 'v', '1', 0,
  };
  uint8_t g0[DMN_G0_BYTES];
  uint8_t g1[DMN_G1_BYTES];
  const uint8_t zero_iv[16] = {0};
  uint8_t iv_2pow127[16] = {0};
  iv_2pow127[15] = 0x80u;
  memset(instance, 0, sizeof(*instance));
  memcpy(instance->source_suite, source_suite, sizeof(source_suite));
  for (unsigned int index = 0; index != sizeof(instance->context); ++index) {
    instance->context[index] = (uint8_t)(index + 1u);
  }
  for (unsigned int index = 0; index != sizeof(instance->U); ++index) {
    instance->U[index] = (uint8_t)(index * 11u + 5u);
  }
  prg_4_lambda(root, zero_iv, 0, g0, 256);
  prg(g0, iv_2pow127, 0, g1, 256, sizeof(instance->C));
  compute_tag(instance->T, instance->U, g0);
  for (unsigned int index = 0; index != sizeof(instance->C); ++index) {
    const uint64_t value = (index / 8u) & 1u ? DMK_UPPER : DMK_LOWER;
    instance->C[index] = (uint8_t)(g1[index] ^ (uint8_t)(value >> (8u * (index % 8u))));
  }
  secure_clear(g0, sizeof(g0));
  secure_clear(g1, sizeof(g1));
  secure_clear(iv_2pow127, sizeof(iv_2pow127));
}

static void make_statement(const dmk_instance* instance, dm_wire_statement_t* statement) {
  static const uint8_t relation_id[] = "direct-mask-relation-v1";
  memset(statement, 0, sizeof(*statement));
  memcpy(statement->source_suite, instance->source_suite, DM_WIRE_SOURCE_SUITE_BYTES);
  statement->relation_id = relation_id;
  statement->relation_id_bytes = (uint32_t)(sizeof(relation_id) - 1u);
  statement->context = instance->context;
  statement->U = instance->U;
  statement->T = instance->T;
  statement->C = instance->C;
  statement->descriptor.field_bits = DMV_LAMBDA;
  statement->descriptor.degree = DMV_DEGREE;
  statement->descriptor.tau = DMV_TAU;
  statement->descriptor.w_grind = DMV_W_GRIND;
  statement->descriptor.short_challenge_bits = DMV_SHORT_CHALLENGE_BITS;
  statement->descriptor.open_budget = DMV_T_OPEN;
  statement->descriptor.witness_bits = DMK_WITNESS_BITS;
  statement->descriptor.constraints = DMK_CONSTRAINTS;
  statement->descriptor.padding_bits = 0;
  statement->descriptor.mask_count = DMK_MASK_COUNT;
  statement->descriptor.nonce_bits = 8u * DMV_NONCE_BYTES;
  statement->descriptor.challenge_mode = 1u;
}

static void unpack_witness(const dmn_packed_witness* packed, uint8_t* bits) {
  for (size_t bit = 0; bit != packed->bit_count; ++bit) {
    bits[bit] = (uint8_t)((packed->bytes[bit / 8u] >> (bit % 8u)) & 1u);
  }
}

static int write_all_stdout(const uint8_t* bytes, size_t length) {
  if (bytes == NULL || length == 0) {
    return -1;
  }
  while (length != 0) {
    const size_t written = fwrite(bytes, 1, length, stdout);
    if (written == 0) {
      return -1;
    }
    bytes += written;
    length -= written;
  }
  return fflush(stdout) == 0 ? 0 : -1;
}

static int run_retry_failure(void) {
  static const uint8_t root[DMN_ROOT_BYTES] = {
      0x03u, 0x0au, 0x11u, 0x18u, 0x1fu, 0x26u, 0x2du, 0x34u,
      0x3bu, 0x42u, 0x49u, 0x50u, 0x57u, 0x5eu, 0x65u, 0x6cu,
      0x73u, 0x7au, 0x81u, 0x88u, 0x8fu, 0x96u, 0x9du, 0xa4u,
      0xabu, 0xb2u, 0xb9u, 0xc0u, 0xc7u, 0xceu, 0xd5u, 0xdcu,
  };
  dmk_instance instance;
  dm_wire_statement_t statement;
  uint8_t witness[DMK_WITNESS_BITS] = {0};
  dm_wire_proof_t proof;
  make_instance(&instance, root);
  make_statement(&instance, &statement);
  dm_wire_proof_init(&proof);
  const dm_wire_status_t status = dm_wire_prove_kernel_os(
      &proof, &statement, witness, DMK_WITNESS_BITS, 0);
  dm_wire_proof_clear(&proof);
  secure_clear(witness, sizeof(witness));
  return status == DM_WIRE_ERR_RETRY ? 41 : 42;
}

static int run_prover(void) {
  static const uint8_t root[DMN_ROOT_BYTES] = {
      0x03u, 0x0au, 0x11u, 0x18u, 0x1fu, 0x26u, 0x2du, 0x34u,
      0x3bu, 0x42u, 0x49u, 0x50u, 0x57u, 0x5eu, 0x65u, 0x6cu,
      0x73u, 0x7au, 0x81u, 0x88u, 0x8fu, 0x96u, 0x9du, 0xa4u,
      0xabu, 0xb2u, 0xb9u, 0xc0u, 0xc7u, 0xceu, 0xd5u, 0xdcu,
  };
  dmk_instance instance;
  dm_wire_statement_t statement;
  dmn_packed_witness packed = {0};
  uint8_t* witness_bits = NULL;
  uint8_t statement_wire[DM_WIRE_STATEMENT_BYTES] = {0};
  uint8_t* frame = NULL;
  size_t frame_bytes = 0;
  size_t written = 0;
  dm_wire_proof_t proof;
  dm_wire_proof_init(&proof);
  make_instance(&instance, root);
  if (dmn_extend(&instance, root, &packed) != DMN_OK ||
      packed.byte_count != DM_WIRE_WITNESS_BYTES || packed.bit_count != DMK_WITNESS_BITS) {
    dmn_clear(&packed);
    return 10;
  }
  witness_bits = (uint8_t*)calloc(DMK_WITNESS_BITS, 1);
  if (witness_bits == NULL) {
    dmn_clear(&packed);
    return 11;
  }
  unpack_witness(&packed, witness_bits);
  make_statement(&instance, &statement);
  if (dm_wire_statement_encode(statement_wire, sizeof(statement_wire), &statement) != DM_WIRE_OK) {
    secure_clear(witness_bits, DMK_WITNESS_BITS);
    free(witness_bits);
    dmn_clear(&packed);
    return 12;
  }
  const dm_wire_status_t prove_status = dm_wire_prove_kernel_os(
      &proof, &statement, witness_bits, DMK_WITNESS_BITS, DMV_MAX_FINAL_RETRIES);
  if (prove_status != DM_WIRE_OK ||
      dm_wire_proof_size(&proof, &statement, &frame_bytes) != DM_WIRE_OK ||
      frame_bytes != DM_WIRE_FRAME_BYTES) {
    dm_wire_proof_clear(&proof);
    secure_clear(witness_bits, DMK_WITNESS_BITS);
    free(witness_bits);
    dmn_clear(&packed);
    return 13;
  }
  frame = (uint8_t*)malloc(frame_bytes);
  if (frame == NULL) {
    dm_wire_proof_clear(&proof);
    secure_clear(witness_bits, DMK_WITNESS_BITS);
    free(witness_bits);
    dmn_clear(&packed);
    return 14;
  }
  const dm_wire_status_t encode_status =
      dm_wire_encode(&proof, &statement, frame, frame_bytes, &written);
  const int output_status = encode_status == DM_WIRE_OK && written == frame_bytes &&
                            write_all_stdout(statement_wire, sizeof(statement_wire)) == 0 &&
                            write_all_stdout(frame, frame_bytes) == 0;
  secure_clear(frame, frame_bytes);
  free(frame);
  dm_wire_proof_clear(&proof);
  secure_clear(witness_bits, DMK_WITNESS_BITS);
  free(witness_bits);
  dmn_clear(&packed);
  return output_status ? 0 : 15;
}

int main(int argc, char** argv) {
#if defined(_WIN32)
  if (_setmode(_fileno(stdout), _O_BINARY) == -1) {
    return 2;
  }
#endif
  if (argc == 2 && strcmp(argv[1], "--retry-failure") == 0) {
    return run_retry_failure();
  }
  if (argc != 1) {
    return 3;
  }
  return run_prover();
}
