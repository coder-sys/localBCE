/* SPDX-License-Identifier: MIT */

/* Non-activating native-to-wire integration probe. */

#include "direct_mask_wire.h"

#include "direct_mask_native.h"
#include "aes.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void secure_clear(void* pointer, size_t bytes) {
  if (pointer == NULL) {
    return;
  }
  volatile uint8_t* cursor = (volatile uint8_t*)pointer;
  while (bytes != 0) {
    *cursor++ = 0;
    --bytes;
  }
}

static bool proof_is_zero(const dm_wire_proof_t* proof) {
  if (proof == NULL) {
    return false;
  }
  dm_wire_proof_t zero;
  memset(&zero, 0, sizeof(zero));
  return memcmp(proof, &zero, sizeof(zero)) == 0;
}

static void fill_pattern(uint8_t* bytes, size_t length, uint8_t seed) {
  for (size_t index = 0; index != length; ++index) {
    bytes[index] = (uint8_t)(seed + (uint8_t)(index * 29u) + (uint8_t)(index >> 3));
  }
}

static void fill_counter_pattern(uint8_t* bytes, size_t length, uint8_t seed,
                                 uint32_t counter) {
  fill_pattern(bytes, length, seed);
  const size_t counter_bytes = length < sizeof(counter) ? length : sizeof(counter);
  for (size_t index = 0; index != counter_bytes; ++index) {
    bytes[index] = (uint8_t)(counter >> (8u * index));
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
  const uint8_t zero_iv[DM_WIRE_NONCE_BYTES / 4u] = {0};
  uint8_t iv_2pow127[DM_WIRE_NONCE_BYTES / 4u] = {0};
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
  statement->descriptor.challenge_mode = DMV_CHALLENGE_MODE;
}

static void unpack_witness(const dmn_packed_witness* packed, uint8_t* bits) {
  for (size_t bit = 0; bit != packed->bit_count; ++bit) {
    bits[bit] = (uint8_t)((packed->bytes[bit / 8u] >> (bit % 8u)) & 1u);
  }
}

typedef struct count_sink_state_t {
  uint32_t next_row;
} count_sink_state_t;

static int count_sink(void* context, uint32_t row, const bf256_t coefficients[4]) {
  count_sink_state_t* state = (count_sink_state_t*)context;
  if (state == NULL || coefficients == NULL || row != state->next_row) {
    return DMK_ERR_CALLBACK;
  }
  ++state->next_row;
  return DMK_OK;
}

typedef struct probe_rng_t {
  uint32_t iv_calls;
  uint32_t nonce_calls;
  bool root_pending;
} probe_rng_t;

static int probe_random_bytes(void* context, uint8_t* output, size_t length) {
  probe_rng_t* rng = (probe_rng_t*)context;
  if (rng == NULL || output == NULL) {
    return -1;
  }
  if (length == 16u) {
    fill_counter_pattern(output, length, 0x22u, rng->iv_calls++);
    rng->root_pending = true;
    return 0;
  }
  if (length != DMV_SEED_BYTES) {
    return -1;
  }
  if (rng->root_pending) {
    fill_counter_pattern(output, length, 0x11u, 0u);
    rng->root_pending = false;
    return 0;
  }
  const uint32_t call = rng->nonce_calls++;
  fill_pattern(output, length, call < 2u ? (uint8_t)(0x33u + 0x11u * call)
                                        : (uint8_t)(0x60u + call));
  if (call >= 2u) {
    const uint32_t index = call - 2u;
    output[0] = (uint8_t)index;
    output[1] = (uint8_t)(index >> 8);
    output[2] = (uint8_t)(index >> 16);
    output[3] = (uint8_t)(index >> 24);
  }
  return 0;
}

static void print_status(const char* label, dm_wire_status_t status) {
  printf("%s status=%d name=%s\n", label, status, dm_wire_status_name(status));
}

static int run_probe(void) {
  static const uint8_t root[DMN_ROOT_BYTES] = {
      0x03u, 0x0au, 0x11u, 0x18u, 0x1fu, 0x26u, 0x2du, 0x34u,
      0x3bu, 0x42u, 0x49u, 0x50u, 0x57u, 0x5eu, 0x65u, 0x6cu,
      0x73u, 0x7au, 0x81u, 0x88u, 0x8fu, 0x96u, 0x9du, 0xa4u,
      0xabu, 0xb2u, 0xb9u, 0xc0u, 0xc7u, 0xceu, 0xd5u, 0xdcu,
  };
  dmk_instance instance;
  make_instance(&instance, root);
  dmn_packed_witness packed = {0};
  const int native_status = dmn_extend(&instance, root, &packed);
  printf("NATIVE_MATERIALIZER status=%d byte_count=%zu bit_count=%zu expected_bytes=%u\n",
         native_status, packed.byte_count, packed.bit_count, DMN_PACKED_WITNESS_BYTES);
  if (native_status != DMN_OK || packed.byte_count != DMN_PACKED_WITNESS_BYTES ||
      packed.bit_count != DMN_PACKED_WITNESS_BITS) {
    dmn_clear(&packed);
    printf("DIRECT_MASK_WIRE_PROBE status=FAIL reason=native_materializer\n");
    return 1;
  }

  uint8_t* witness_bits = (uint8_t*)calloc(DMK_WITNESS_BITS, 1);
  bf256_t* zero_rows = (bf256_t*)calloc(DMK_WITNESS_BITS, sizeof(*zero_rows));
  if (witness_bits == NULL || zero_rows == NULL) {
    secure_clear(witness_bits, DMK_WITNESS_BITS);
    free(witness_bits);
    secure_clear(zero_rows, DMK_WITNESS_BITS * sizeof(*zero_rows));
    free(zero_rows);
    dmn_clear(&packed);
    printf("DIRECT_MASK_WIRE_PROBE status=FAIL reason=allocation\n");
    return 1;
  }
  unpack_witness(&packed, witness_bits);

  count_sink_state_t count_state = {0};
  dmk_counts counts;
  memset(&counts, 0, sizeof(counts));
  const int count_status = dmk_prover_coefficients(
      &instance, witness_bits, DMK_WITNESS_BITS, zero_rows, DMK_WITNESS_BITS, count_sink,
      &count_state, &counts);
  printf("KERNEL_COUNTS status=%d rows=%u ell=%u m=%u bitness=%u inverse=%u equality=%u tag=%u "
         "range=%u sboxes=%u aes_blocks=%u key_schedules=%u\n",
         count_status, count_state.next_row, counts.witness_bits, counts.constraints, counts.bitness,
         counts.inverse, counts.equality, counts.tag, counts.range, counts.sboxes,
         counts.aes_blocks, counts.key_schedules);
  const bool counts_ok = count_status == DMK_OK && count_state.next_row == DMK_CONSTRAINTS &&
                         counts.witness_bits == DMK_WITNESS_BITS &&
                         counts.constraints == DMK_CONSTRAINTS &&
                         counts.bitness == DMK_WITNESS_BITS && counts.inverse == 26192u &&
                         counts.equality == 7424u && counts.tag == 768u && counts.range == 12800u &&
                         counts.sboxes == DMK_SBOX_COUNT && counts.aes_blocks == 58u &&
                         counts.key_schedules == 2u;

  dm_wire_statement_t statement;
  make_statement(&instance, &statement);
  const dm_wire_status_t statement_status = dm_wire_statement_validate(&statement);
  print_status("STATEMENT_VALIDATE", statement_status);
  probe_rng_t rng = {0};
  dm_wire_proof_t proof;
  dm_wire_proof_init(&proof);
  const bool proof_init_zero = proof_is_zero(&proof);
  const dm_wire_status_t prove_status =
      dm_wire_prove_kernel(&proof, &statement, witness_bits, DMK_WITNESS_BITS,
                           probe_random_bytes, &rng, DMV_MAX_FINAL_RETRIES);
  printf("WIRE_PROVE_STATUS status=%d name=%s final_nonce_calls=%u\n", prove_status,
         dm_wire_status_name(prove_status), rng.nonce_calls);
  int passed = counts_ok && statement_status == DM_WIRE_OK && prove_status == DM_WIRE_OK;
  if (prove_status != DM_WIRE_OK) {
    dm_wire_proof_clear(&proof);
    secure_clear(witness_bits, DMK_WITNESS_BITS);
    free(witness_bits);
    secure_clear(zero_rows, DMK_WITNESS_BITS * sizeof(*zero_rows));
    free(zero_rows);
    dmn_clear(&packed);
    printf("DIRECT_MASK_WIRE_PROBE status=FAIL reason=prove\n");
    return 1;
  }

  size_t statement_bytes = 0;
  size_t frame_bytes = 0;
  const dm_wire_status_t statement_size_status =
      dm_wire_statement_size(&statement, &statement_bytes);
  const dm_wire_status_t size_status = dm_wire_proof_size(&proof, &statement, &frame_bytes);
  print_status("STATEMENT_SIZE", statement_size_status);
  print_status("WIRE_SIZE", size_status);
  uint8_t* wire = frame_bytes == 0 ? NULL : (uint8_t*)malloc(frame_bytes);
  size_t written = 0;
  const dm_wire_status_t encode_status =
      wire == NULL ? DM_WIRE_ERR_ALLOCATION
                   : dm_wire_encode(&proof, &statement, wire, frame_bytes, &written);
  print_status("WIRE_ENCODE", encode_status);
  printf("WIRE_FRAME bytes=%zu written=%zu statement=%zu nu=%u nonces=%u m1=%u m2=%u m3=%u m4=%u\n",
         frame_bytes, written, statement_bytes, DM_WIRE_NU_BYTES,
         DM_WIRE_NONCE_COUNT * DM_WIRE_NONCE_BYTES, DM_WIRE_M1_BYTES, DM_WIRE_M2_BYTES,
         DM_WIRE_M3_BYTES, DM_WIRE_M4_BYTES);
  passed = passed && statement_size_status == DM_WIRE_OK && size_status == DM_WIRE_OK &&
           encode_status == DM_WIRE_OK && written == frame_bytes;

  dm_wire_proof_t decoded;
  memset(&decoded, 0, sizeof(decoded));
  const dm_wire_status_t decode_status =
      wire == NULL ? DM_WIRE_ERR_ALLOCATION : dm_wire_decode(&decoded, &statement, wire, frame_bytes);
  print_status("WIRE_DECODE", decode_status);
  const dm_wire_status_t verify_status =
      decode_status == DM_WIRE_OK ? dm_wire_verify_kernel(&decoded, &statement)
                                  : DM_WIRE_ERR_INPUT;
  print_status("WIRE_VERIFY", verify_status);
  passed = passed && decode_status == DM_WIRE_OK && verify_status == DM_WIRE_OK;

  uint8_t* reencoded = frame_bytes == 0 ? NULL : (uint8_t*)malloc(frame_bytes);
  size_t reencoded_bytes = 0;
  const dm_wire_status_t reencode_status =
      reencoded == NULL ? DM_WIRE_ERR_ALLOCATION
                        : dm_wire_encode(&decoded, &statement, reencoded, frame_bytes,
                                         &reencoded_bytes);
  const bool canonical = reencode_status == DM_WIRE_OK && reencoded_bytes == frame_bytes &&
                         memcmp(wire, reencoded, frame_bytes) == 0;
  printf("WIRE_CANONICAL_REENCODE status=%d name=%s bytes_equal=%u\n", reencode_status,
         dm_wire_status_name(reencode_status), canonical ? 1u : 0u);
  passed = passed && canonical;

  int lifecycle_pass = proof_init_zero && proof.primitive.initialized;
  printf("PROOF_CONTRACT init_zero=%s live_after_prove=%s\n", proof_init_zero ? "true" : "false",
         proof.primitive.initialized ? "true" : "false");

  uint8_t wrong_context[DM_WIRE_CONTEXT_BYTES];
  memcpy(wrong_context, statement.context, sizeof(wrong_context));
  wrong_context[0] ^= 1u;
  dm_wire_statement_t wrong_statement = statement;
  wrong_statement.context = wrong_context;
  const dm_wire_status_t wrong_context_status = dm_wire_verify_kernel(&decoded, &wrong_statement);
  print_status("NEG_EXPECTED_CONTEXT", wrong_context_status);
  passed = passed && wrong_context_status == DM_WIRE_ERR_STATEMENT;

  if (wire != NULL) {
    uint8_t* mutated = (uint8_t*)malloc(frame_bytes);
    if (mutated == NULL) {
      lifecycle_pass = 0;
      passed = 0;
      printf("PROOF_CONTRACT status=FAIL reason=allocation\n");
      printf("NEG_EXPLICIT_NU status=%d name=allocation\n", DM_WIRE_ERR_ALLOCATION);
      printf("NEG_BODY_DECODE status=%d name=allocation\n", DM_WIRE_ERR_ALLOCATION);
      printf("NEG_BODY_VERIFY status=%d name=not_run\n", DM_WIRE_ERR_INPUT);
    } else {
      const size_t nu_offset = DM_WIRE_HEADER_BYTES + statement_bytes;

      const dm_wire_status_t reuse_status = dm_wire_decode(&proof, &statement, wire, frame_bytes);
      const bool reuse_live = proof.primitive.initialized && !proof_is_zero(&proof);

      memcpy(mutated, wire, frame_bytes);
      mutated[nu_offset] ^= 1u;
      const dm_wire_status_t failed_decode =
          dm_wire_decode(&proof, &statement, mutated, frame_bytes);
      const bool failed_decode_zero = proof_is_zero(&proof);

      const dm_wire_status_t restore_status =
          dm_wire_decode(&proof, &statement, wire, frame_bytes);
      const bool restored_live = proof.primitive.initialized && !proof_is_zero(&proof);
      const uint8_t* aliased_input = proof.primitive.m1;
      const size_t aliased_bytes = proof.primitive.m1_len;
      const dm_wire_status_t alias_status =
          dm_wire_decode(&proof, &statement, aliased_input, aliased_bytes);
      const bool alias_zero = proof_is_zero(&proof);

      const dm_wire_status_t restore_after_alias =
          dm_wire_decode(&proof, &statement, wire, frame_bytes);
      const bool live_before_clear = proof.primitive.initialized && !proof_is_zero(&proof);
      dm_wire_proof_clear(&proof);
      const bool clear_zero = proof_is_zero(&proof);

      const dm_wire_status_t restore_after_clear =
          dm_wire_decode(&proof, &statement, wire, frame_bytes);
      const dm_wire_status_t failed_prove =
          dm_wire_prove_kernel(&proof, &statement, witness_bits, DMK_WITNESS_BITS, NULL, NULL,
                               DMV_MAX_FINAL_RETRIES);
      const bool failed_prove_zero = proof_is_zero(&proof);
      printf("PROOF_CONTRACT reuse_status=%d reuse_live=%s failed_decode=%d failed_decode_zero=%s "
             "restore_status=%d restored_live=%s alias_status=%d alias_zero=%s "
             "restore_after_alias=%d live_before_clear=%s clear_zero=%s restore_after_clear=%d "
             "failed_prove=%d failed_prove_zero=%s\n",
             reuse_status, reuse_live ? "true" : "false", failed_decode,
             failed_decode_zero ? "true" : "false", restore_status, restored_live ? "true" : "false",
             alias_status, alias_zero ? "true" : "false", restore_after_alias,
             live_before_clear ? "true" : "false", clear_zero ? "true" : "false",
             restore_after_clear, failed_prove, failed_prove_zero ? "true" : "false");
      lifecycle_pass = lifecycle_pass && reuse_status == DM_WIRE_OK && reuse_live &&
                       failed_decode == DM_WIRE_ERR_COMMITMENT && failed_decode_zero &&
                       restore_status == DM_WIRE_OK && restored_live &&
                       alias_status == DM_WIRE_ERR_ARGUMENT && alias_zero &&
                       restore_after_alias == DM_WIRE_OK && live_before_clear && clear_zero &&
                       restore_after_clear == DM_WIRE_OK && failed_prove == DM_WIRE_ERR_ARGUMENT &&
                       failed_prove_zero;

      memcpy(mutated, wire, frame_bytes);
      mutated[nu_offset] ^= 1u;
      dm_wire_proof_t nu_mutation;
      memset(&nu_mutation, 0, sizeof(nu_mutation));
      const dm_wire_status_t nu_status = dm_wire_decode(&nu_mutation, &statement, mutated, frame_bytes);
      print_status("NEG_EXPLICIT_NU", nu_status);
      passed = passed && nu_status == DM_WIRE_ERR_COMMITMENT;
      dm_wire_proof_clear(&nu_mutation);

      const size_t m2_offset = nu_offset + DM_WIRE_NU_BYTES +
                               DM_WIRE_NONCE_COUNT * DM_WIRE_NONCE_BYTES + DM_WIRE_M1_BYTES;
      memcpy(mutated, wire, frame_bytes);
      mutated[m2_offset] ^= 1u;
      dm_wire_proof_t body_mutation;
      memset(&body_mutation, 0, sizeof(body_mutation));
      const dm_wire_status_t body_decode = dm_wire_decode(&body_mutation, &statement, mutated, frame_bytes);
      const dm_wire_status_t body_verify =
          body_decode == DM_WIRE_OK ? dm_wire_verify_kernel(&body_mutation, &statement)
                                    : DM_WIRE_ERR_INPUT;
      print_status("NEG_BODY_DECODE", body_decode);
      print_status("NEG_BODY_VERIFY", body_verify);
      passed = passed && body_decode == DM_WIRE_OK && body_verify != DM_WIRE_OK;
      dm_wire_proof_clear(&body_mutation);
      secure_clear(mutated, frame_bytes);
      free(mutated);
    }
  } else {
    lifecycle_pass = 0;
    printf("PROOF_CONTRACT status=FAIL reason=wire_unavailable\n");
  }
  passed = passed && lifecycle_pass;

  printf("DIRECT_MASK_WIRE_PROBE status=%s proof_verification=%s skips=0\n",
         passed ? "PASS" : "FAIL", verify_status == DM_WIRE_OK ? "PASS" : "FAIL");
  dm_wire_proof_clear(&decoded);
  dm_wire_proof_clear(&proof);
  secure_clear(reencoded, frame_bytes);
  secure_clear(wire, frame_bytes);
  free(reencoded);
  free(wire);
  secure_clear(witness_bits, DMK_WITNESS_BITS);
  free(witness_bits);
  secure_clear(zero_rows, DMK_WITNESS_BITS * sizeof(*zero_rows));
  free(zero_rows);
  dmn_clear(&packed);
  return passed ? 0 : 1;
}

int main(int argc, char** argv) {
  if (argc > 2 || (argc == 2 && strcmp(argv[1], "--child-fixture") != 0)) {
    fprintf(stderr, "usage: direct_mask_wire_probe [--child-fixture]\n");
    return 2;
  }
  const int result = run_probe();
  if (argc == 2) {
    printf("DM_CHILD phase=direct_mask_wire_e2e status=%s\n", result == 0 ? "PASS" : "FAIL");
  }
  return result;
}
