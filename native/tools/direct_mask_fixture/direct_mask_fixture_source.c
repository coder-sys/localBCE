/* SPDX-License-Identifier: MIT */

#include "direct_mask_fixture.h"
#include "fixture_public_key.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static int dm_fixture_set_binary_mode(void) {
#ifdef _WIN32
  if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
      _setmode(_fileno(stdout), _O_BINARY) == -1) {
    return 0;
  }
#endif
  return 1;
}

/* 0 = exact EOF, 1 = malformed short/extra input, -1 = I/O failure. */
static int dm_fixture_read_exact(uint8_t* buffer, size_t bytes) {
  const size_t read_bytes = fread(buffer, 1u, bytes, stdin);
  int trailing;

  if (read_bytes != bytes) {
    return ferror(stdin) != 0 ? -1 : 1;
  }
  trailing = fgetc(stdin);
  if (trailing != EOF) {
    return 1;
  }
  return ferror(stdin) != 0 ? -1 : 0;
}

int main(int argc, char** argv) {
  uint8_t request_bytes[DM_FIXTURE_REQUEST_BYTES];
  uint8_t seed[DM_FIXTURE_SEED_BYTES];
  uint8_t public_key[DM_FIXTURE_PUBLIC_KEY_BYTES];
  uint8_t secret_key[DM_FIXTURE_SECRET_KEY_BYTES];
  uint8_t capsule[DM_PIPELINE_CAPSULE_BYTES];
  dm_fixture_request_view_t request;
  dm_pipeline_status_t result = DM_PIPELINE_INTERNAL;
  int read_result;
  int stdin_closed = 0;
  int stdout_closed = 0;
  int close_status;

  (void)argv;

  memset(request_bytes, 0, sizeof(request_bytes));
  memset(seed, 0, sizeof(seed));
  memset(public_key, 0, sizeof(public_key));
  memset(secret_key, 0, sizeof(secret_key));
  memset(capsule, 0, sizeof(capsule));
  memset(&request, 0, sizeof(request));

  if (!dm_fixture_cli_args_valid(argc)) {
    result = DM_PIPELINE_MALFORMED;
    goto cleanup;
  }
  if (!dm_fixture_set_binary_mode()) {
    goto cleanup;
  }
  read_result = dm_fixture_read_exact(request_bytes, sizeof(request_bytes));
  if (fclose(stdin) != 0) {
    stdin_closed = 1;
    result = DM_PIPELINE_INTERNAL;
    goto cleanup;
  }
  stdin_closed = 1;
  if (read_result != 0) {
    result = read_result > 0 ? DM_PIPELINE_MALFORMED : DM_PIPELINE_INTERNAL;
    goto cleanup;
  }
  if (!dm_fixture_request_parse(request_bytes, sizeof(request_bytes), &request)) {
    result = DM_PIPELINE_MALFORMED;
    goto cleanup;
  }

  dm_fixture_fill_seed(seed);
  if (blind_source_auth_mldsa87_v1_keypair_from_seed(
          public_key, sizeof(public_key), secret_key, sizeof(secret_key), seed,
          sizeof(seed)) != BLIND_SOURCE_AUTH_MLDSA87_V1_OK) {
    result = DM_PIPELINE_INTERNAL;
    goto cleanup;
  }
  if (!dm_fixture_public_key_matches(public_key)) {
    result = DM_PIPELINE_INTERNAL;
    goto cleanup;
  }
  result = dm_fixture_run_bound_source(
      &request, secret_key, sizeof(secret_key), public_key,
      dm_fixture_frozen_public_key, capsule, sizeof(capsule),
      dm_pipeline_source_process);
  if (result == DM_PIPELINE_ACCEPT &&
      (fwrite(capsule, 1u, sizeof(capsule), stdout) != sizeof(capsule) ||
       fflush(stdout) != 0)) {
    result = DM_PIPELINE_INTERNAL;
  }

cleanup:
  dm_fixture_secure_clear(&request, sizeof(request));
  dm_fixture_secure_clear(capsule, sizeof(capsule));
  dm_fixture_secure_clear(secret_key, sizeof(secret_key));
  dm_fixture_secure_clear(public_key, sizeof(public_key));
  dm_fixture_secure_clear(seed, sizeof(seed));
  dm_fixture_secure_clear(request_bytes, sizeof(request_bytes));
  if (!stdin_closed) {
    close_status = fclose(stdin);
    stdin_closed = 1;
    if (close_status != 0) {
      result = DM_PIPELINE_INTERNAL;
    }
  }
  if (!stdout_closed) {
    close_status = fclose(stdout);
    stdout_closed = 1;
    if (close_status != 0) {
      result = DM_PIPELINE_INTERNAL;
    }
  }
  return (int)result;
}
