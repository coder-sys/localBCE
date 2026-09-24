/* SPDX-License-Identifier: MIT */

#include "direct_mask_pipeline.h"

#include <stdio.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static int dm_pipeline_set_binary_mode(void) {
#ifdef _WIN32
  if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
      _setmode(_fileno(stdout), _O_BINARY) == -1) {
    return 0;
  }
#endif
  return 1;
}

/* 0 = exact EOF, 1 = malformed short/extra input, -1 = I/O failure. */
static int dm_pipeline_read_exact(uint8_t* buffer, size_t bytes) {
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
  static uint8_t input[DM_PIPELINE_SOURCE_INPUT_BYTES];
  static uint8_t capsule[DM_PIPELINE_CAPSULE_BYTES];
  dm_pipeline_status_t result = DM_PIPELINE_INTERNAL;
  int read_result;

  (void)argv;
  if (!dm_pipeline_cli_args_valid(argc)) {
    return DM_PIPELINE_MALFORMED;
  }
  if (!dm_pipeline_set_binary_mode()) {
    goto cleanup;
  }
  read_result = dm_pipeline_read_exact(input, sizeof(input));
  if (read_result != 0) {
    result = read_result > 0 ? DM_PIPELINE_MALFORMED : DM_PIPELINE_INTERNAL;
    goto cleanup;
  }

  result = dm_pipeline_source_process(input, sizeof(input), capsule,
                                      sizeof(capsule));
  if (result == DM_PIPELINE_ACCEPT &&
      (fwrite(capsule, 1u, sizeof(capsule), stdout) != sizeof(capsule) ||
       fflush(stdout) != 0)) {
    result = DM_PIPELINE_INTERNAL;
  }

cleanup:
  dm_pipeline_secure_clear(capsule, sizeof(capsule));
  dm_pipeline_secure_clear(input, sizeof(input));
  return (int)result;
}
