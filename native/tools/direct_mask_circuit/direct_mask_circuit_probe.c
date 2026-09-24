/* SPDX-License-Identifier: MIT */

#include "direct_mask_circuit.h"

#include "aes.h"
#include "fields.h"

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

static void print_hex_prefix(const char* label, const uint8_t* bytes, size_t count) {
  printf("%s=", label);
  for (size_t i = 0; i != count; ++i) {
    printf("%02x", bytes[i]);
  }
  putchar('\n');
}

static int run_parameter_checks(void) {
  const dmc_descriptor_t descriptor = {
      .witness_bits = 117328,
      .constraint_count = 156788,
      .degree = DMC_RELATION_DEGREE,
      .short_challenge_bits = DMC_SHORT_CHALLENGE_BITS,
  };
  dmc_counts_t counts;
  if (!require_true(dmc_descriptor_validate(&descriptor) == DMC_OK, "descriptor accepted")) {
    return 0;
  }
  if (!require_true(dmc_compute_counts(&descriptor, &counts) == DMC_OK, "counts computed")) {
    return 0;
  }
  printf("PARAMETERS lambda=%u tau=%u grinding_bits=%u T_open=%u non_em=%u\n", counts.lambda,
         counts.tau, counts.grinding_bits, counts.opening_budget, counts.non_em);
  printf("DIMENSIONS witness_bits=%u constraints=%u degree=%u short_challenge_bits=%u\n",
         descriptor.witness_bits, descriptor.constraint_count, descriptor.degree,
         descriptor.short_challenge_bits);
  printf("COUNTS direct_mask_rows=%u correction_bytes=%u aes_key_sboxes=%u aes_round_sboxes=%u "
         "aes_total_sboxes=%u inverse_constraints=%u bitness_constraints=%u upstream_ell=%u\n",
         counts.direct_mask_rows, counts.correction_bytes, counts.aes_key_schedule_sboxes,
         counts.aes_round_sboxes, counts.aes_total_sboxes, counts.inverse_constraints,
         counts.bitness_constraints, DMC_FAEST_256F_ELL);
  if (!require_true(counts.direct_mask_rows == 118864u, "direct mask rows exact")) {
    return 0;
  }
  if (!require_true(counts.correction_bytes == 6144u, "direct correction bytes exact")) {
    return 0;
  }

  const dmc_descriptor_t bad_degree = {117328, 156788, 2, DMC_SHORT_CHALLENGE_BITS};
  const dmc_descriptor_t bad_alignment = {117329, 156788, DMC_RELATION_DEGREE,
                                          DMC_SHORT_CHALLENGE_BITS};
  const dmc_descriptor_t bad_challenge = {117328, 156788, DMC_RELATION_DEGREE, 128};
  if (!require_true(dmc_descriptor_validate(&bad_degree) != DMC_OK, "wrong degree rejected")) {
    return 0;
  }
  if (!require_true(dmc_descriptor_validate(&bad_alignment) != DMC_OK,
                    "non-byte witness dimension rejected")) {
    return 0;
  }
  if (!require_true(dmc_descriptor_validate(&bad_challenge) != DMC_OK,
                    "wrong short challenge width rejected")) {
    return 0;
  }
  printf("NEG descriptor_wrong_degree=REJECTED\n");
  printf("NEG descriptor_non_byte_dimension=REJECTED\n");
  printf("NEG descriptor_wrong_challenge_width=REJECTED\n");
  return 1;
}

static int run_aes_checks(uint8_t aesg0[DMC_AESG0_BYTES], uint8_t aesg1[DMC_AESG1_BYTES]) {
  static const uint8_t key[DMC_FIELD_BYTES] = {
      0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
      0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
      0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
  };
  static const uint8_t plaintext[DMC_AES_BLOCK_BYTES] = {
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  };
  static const uint8_t expected[DMC_AES_BLOCK_BYTES] = {
      0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
      0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
  };
  uint8_t reference[DMC_AES_BLOCK_BYTES];
  dmc_aes256_reference_encrypt(key, plaintext, reference);
  if (!require_true(memcmp(reference, expected, sizeof(reference)) == 0,
                    "independent AES-256 reference vector")) {
    return 0;
  }
  if (!require_true(dmc_aes256_oracle_check(key, plaintext, expected) == DMC_OK,
                    "pinned/native AES-256 oracle")) {
    return 0;
  }
  uint8_t wrong_expected[DMC_AES_BLOCK_BYTES];
  memcpy(wrong_expected, expected, sizeof(wrong_expected));
  wrong_expected[0] ^= 1;
  if (!require_true(dmc_aes256_oracle_check(key, plaintext, wrong_expected) != DMC_OK,
                    "wrong AES output rejected")) {
    return 0;
  }
  printf("AES256 native_reference=PASS inverse_table=256/256\n");
  printf("NEG aes_wrong_output=REJECTED\n");

  if (!require_true(dmc_generate_aesg(key, aesg0, aesg1) == DMC_OK, "AESG generation")) {
    return 0;
  }
  if (!require_true(dmc_aesg_oracle_check(key) == DMC_OK, "AESG0/AESG1 counter oracle")) {
    return 0;
  }
  print_hex_prefix("AESG0_prefix", aesg0, 16);
  print_hex_prefix("AESG1_prefix", aesg1, 16);
  printf("AESG0_bytes=%u AESG1_bytes=%u native_counter_oracle=PASS\n", DMC_AESG0_BYTES,
         DMC_AESG1_BYTES);
  return 1;
}

static int run_inverse_and_homogenization_checks(void) {
  uint8_t inverse_of_53 = 0;
  for (unsigned int candidate = 0; candidate != 256; ++candidate) {
    if (dmc_inverse_constraints_ok(0x53, (uint8_t)candidate)) {
      inverse_of_53 = (uint8_t)candidate;
      break;
    }
  }
  if (!require_true(inverse_of_53 == 0xcau, "embedded AES inverse lookup")) {
    return 0;
  }
  if (!require_true(dmc_inverse_constraints_ok(0, 0), "zero inverse case accepted")) {
    return 0;
  }
  if (!require_true(!dmc_inverse_constraints_ok(0, 1), "zero inverse mutation rejected")) {
    return 0;
  }
  if (!require_true(!dmc_inverse_constraints_ok(0x53, 0), "wrong nonzero inverse rejected")) {
    return 0;
  }
  if (!require_true(dmc_bitness_constraint_ok(0) && dmc_bitness_constraint_ok(1) &&
                        !dmc_bitness_constraint_ok(2),
                    "bitness predicate")) {
    return 0;
  }
  printf("INVERSE_CONSTRAINTS zero_case=PASS nonzero_case=PASS bitness=PASS\n");
  printf("NEG inverse_zero_output=REJECTED\n");
  printf("NEG inverse_wrong_nonzero_output=REJECTED\n");
  printf("NEG bitness_nonboolean=REJECTED\n");

  bf256_t x1_field;
  bf256_t y1_field;
  bf256_byte_combine_bits(&x1_field, 0x53);
  bf256_byte_combine_bits(&y1_field, inverse_of_53);
  uint8_t x1[DMC_FIELD_BYTES];
  uint8_t y1[DMC_FIELD_BYTES];
  bf256_store(x1, &x1_field);
  bf256_store(y1, &y1_field);
  uint8_t x0[DMC_FIELD_BYTES];
  uint8_t y0[DMC_FIELD_BYTES];
  uint8_t z[DMC_FIELD_BYTES];
  fill_bytes(x0, sizeof(x0), 0x11, 0x17);
  fill_bytes(y0, sizeof(y0), 0x92, 0x0b);
  fill_bytes(z, sizeof(z), 0x37, 0x19);
  int x_leading_zero = 0;
  int y_leading_zero = 0;
  if (!require_true(dmc_homogenized_inverse_check(x0, x1, y0, y1, z, &x_leading_zero,
                                                   &y_leading_zero) == DMC_OK,
                    "homogenized evaluation identity")) {
    return 0;
  }
  if (!require_true(x_leading_zero && y_leading_zero, "valid slope leading coefficients zero")) {
    return 0;
  }
  uint8_t wrong_y1[DMC_FIELD_BYTES];
  memcpy(wrong_y1, y1, sizeof(wrong_y1));
  wrong_y1[0] ^= 1;
  int wrong_x_leading_zero = 1;
  int wrong_y_leading_zero = 1;
  if (!require_true(dmc_homogenized_inverse_check(x0, x1, y0, wrong_y1, z,
                                                   &wrong_x_leading_zero,
                                                   &wrong_y_leading_zero) == DMC_OK,
                    "homogenized identity remains algebraically checked")) {
    return 0;
  }
  if (!require_true(!wrong_y_leading_zero, "wrong slope leading coefficient exposed")) {
    return 0;
  }
  printf("HOMOGENIZATION degree=3 evaluation=PASS leading_coefficients=PASS\n");
  printf("NEG homogenized_wrong_slope_leading_coefficient=DETECTED\n");
  return 1;
}

static int run_direct_mask_checks(const uint8_t aesg0[DMC_AESG0_BYTES],
                                  const uint8_t aesg1[DMC_AESG1_BYTES]) {
  uint8_t u[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES];
  uint8_t v[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES];
  uint8_t q[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES];
  uint8_t delta[DMC_FIELD_BYTES];
  for (unsigned int mask = 0; mask != DMC_DIRECT_MASK_COUNT; ++mask) {
    memcpy(u[mask], aesg1 + mask * DMC_FIELD_BYTES, DMC_FIELD_BYTES);
    memcpy(v[mask], aesg1 + (DMC_DIRECT_MASK_COUNT + mask) * DMC_FIELD_BYTES, DMC_FIELD_BYTES);
    for (unsigned int byte = 0; byte != DMC_FIELD_BYTES; ++byte) {
      u[mask][byte] ^= aesg0[(mask * DMC_FIELD_BYTES + byte) % DMC_AESG0_BYTES];
    }
  }
  fill_bytes(delta, sizeof(delta), 0xa7, 0x13);
  dmc_direct_mask_compute(u, v, delta, q);
  if (!require_true(dmc_direct_mask_identity(u, v, delta, q) == DMC_OK,
                    "six direct field-mask identities")) {
    return 0;
  }
  uint8_t wrong_q[DMC_DIRECT_MASK_COUNT][DMC_FIELD_BYTES];
  memcpy(wrong_q, q, sizeof(wrong_q));
  wrong_q[2][7] ^= 1;
  if (!require_true(dmc_direct_mask_identity(u, v, delta, wrong_q) != DMC_OK,
                    "wrong direct-mask output rejected")) {
    return 0;
  }
  uint8_t wrong_delta[DMC_FIELD_BYTES];
  memcpy(wrong_delta, delta, sizeof(wrong_delta));
  wrong_delta[0] ^= 1;
  if (!require_true(dmc_direct_mask_identity(u, v, wrong_delta, q) != DMC_OK,
                    "wrong Delta rejected")) {
    return 0;
  }
  printf("DIRECT_MASKS count=%u identity=PASS correction_bytes=%u\n", DMC_DIRECT_MASK_COUNT,
         (DMC_FAEST_256F_TAU - 1u) * DMC_DIRECT_MASK_COUNT * DMC_FIELD_BYTES);
  printf("NEG direct_mask_wrong_q=REJECTED\n");
  printf("NEG direct_mask_wrong_delta=REJECTED\n");
  return 1;
}

static int run_transcript_checks(void) {
  uint8_t statement[96];
  uint8_t nu[DMC_FIELD_BYTES];
  uint8_t prior[48];
  uint8_t nonce1[DMC_FS_NONCE_BYTES];
  uint8_t nonce2[DMC_FS_NONCE_BYTES];
  uint8_t fs1[DMC_FS1_BYTES];
  uint8_t fs2[DMC_FS2_BYTES];
  uint8_t fs3[DMC_FS3_BYTES];
  fill_bytes(statement, sizeof(statement), 0x21, 0x09);
  fill_bytes(nu, sizeof(nu), 0x72, 0x07);
  fill_bytes(prior, sizeof(prior), 0x45, 0x1d);
  fill_bytes(nonce1, sizeof(nonce1), 0x90, 0x03);
  fill_bytes(nonce2, sizeof(nonce2), 0x91, 0x03);
  if (!require_true(dmc_fs_challenge(1, statement, sizeof(statement), nu, prior, sizeof(prior),
                                     nonce1, fs1, sizeof(fs1)) == DMC_OK,
                    "FS1 challenge encoding")) {
    return 0;
  }
  if (!require_true(dmc_fs_challenge(2, statement, sizeof(statement), nu, fs1, sizeof(fs1),
                                     nonce1, fs2, sizeof(fs2)) == DMC_OK,
                    "FS2 challenge encoding")) {
    return 0;
  }
  if (!require_true(dmc_fs_challenge(3, statement, sizeof(statement), nu, fs2, sizeof(fs2),
                                     nonce1, fs3, sizeof(fs3)) == DMC_OK,
                    "FS3 challenge encoding")) {
    return 0;
  }
  uint8_t changed_statement[sizeof(statement)];
  uint8_t changed_fs1[sizeof(fs1)];
  memcpy(changed_statement, statement, sizeof(changed_statement));
  changed_statement[17] ^= 1;
  if (!require_true(dmc_fs_challenge(1, changed_statement, sizeof(changed_statement), nu, prior,
                                     sizeof(prior), nonce1, changed_fs1, sizeof(changed_fs1)) ==
                        DMC_OK &&
                        memcmp(changed_fs1, fs1, sizeof(fs1)) != 0,
                    "full statement binding")) {
    return 0;
  }
  if (!require_true(dmc_fs_challenge(1, statement, sizeof(statement), nu, prior, sizeof(prior),
                                     nonce2, changed_fs1, sizeof(changed_fs1)) == DMC_OK &&
                        memcmp(changed_fs1, fs1, sizeof(fs1)) != 0,
                    "fresh nonce binding")) {
    return 0;
  }
  printf("TRANSCRIPT fs1_bytes=%u fs2_bytes=%u fs3_bytes=%u statement_binding=PASS nonce_binding=PASS\n",
         DMC_FS1_BYTES, DMC_FS2_BYTES, DMC_FS3_BYTES);
  printf("NEG transcript_wrong_statement=REJECTED\n");
  printf("NEG transcript_nonce_reuse_mutation=REJECTED\n");
  return 1;
}

int main(void) {
  uint8_t aesg0[DMC_AESG0_BYTES];
  uint8_t aesg1[DMC_AESG1_BYTES];
  int passed = 1;
  passed = run_parameter_checks() && passed;
  passed = run_aes_checks(aesg0, aesg1) && passed;
  passed = run_inverse_and_homogenization_checks() && passed;
  passed = run_direct_mask_checks(aesg0, aesg1) && passed;
  passed = run_transcript_checks() && passed;
  if (!passed) {
    fprintf(stderr, "DIRECT_MASK_CIRCUIT status=FAIL\n");
    return 1;
  }
  printf("DIRECT_MASK_CIRCUIT status=PASS\n");
  printf("scope=nonactivating_reference_fixture production_integration=none security_qualification=none\n");
  return 0;
}
