/* SPDX-License-Identifier: MIT */

#include "blind_source_auth_mldsa87_v1.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static const uint8_t k_fixture_seed[BLIND_SOURCE_AUTH_MLDSA87_V1_SEED_BYTES] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu,
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu,
};

static void fixture_secure_clear(void* pointer, size_t bytes) {
  volatile uint8_t* cursor = (volatile uint8_t*)pointer;
  if (cursor == NULL) {
    return;
  }
  while (bytes != 0u) {
    *cursor++ = 0u;
    --bytes;
  }
}

int main(int argc, char** argv) {
  uint8_t public_key[BLIND_SOURCE_AUTH_MLDSA87_V1_PUBLIC_KEY_BYTES];
  uint8_t secret_key[BLIND_SOURCE_AUTH_MLDSA87_V1_SECRET_KEY_BYTES];
  int result = 1;

  (void)argv;
  memset(public_key, 0, sizeof(public_key));
  memset(secret_key, 0, sizeof(secret_key));
  if (argc != 1) {
    goto cleanup;
  }
  if (blind_source_auth_mldsa87_v1_keypair_from_seed(
          public_key, sizeof(public_key), secret_key, sizeof(secret_key),
          k_fixture_seed, sizeof(k_fixture_seed)) !=
      BLIND_SOURCE_AUTH_MLDSA87_V1_OK) {
    goto cleanup;
  }
  if (fputs("PK_HEX=", stdout) == EOF) {
    goto cleanup;
  }
  for (size_t index = 0u; index != sizeof(public_key); ++index) {
    if (fprintf(stdout, "%02x", (unsigned)public_key[index]) < 0) {
      goto cleanup;
    }
  }
  if (fputc('\n', stdout) == EOF || fflush(stdout) != 0) {
    goto cleanup;
  }
  result = 0;

cleanup:
  fixture_secure_clear(secret_key, sizeof(secret_key));
  fixture_secure_clear(public_key, sizeof(public_key));
  fixture_secure_clear((void*)k_fixture_seed, 0u);
  if (fclose(stdout) != 0) {
    result = 1;
  }
  return result;
}
