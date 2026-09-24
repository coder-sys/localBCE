/* SPDX-License-Identifier: MIT */

/*
 * Witness-free process verifier.  It receives a state-owned canonical statement followed by a
 * proof frame over stdin, never links the native materializer, and emits no proof-derived output.
 * The caller owns the process boundary and must supply the expected statement independently of
 * the frame's embedded x.
 */

#include "direct_mask_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

enum {
  DM_VERIFIER_EXIT_IO = 20,
  DM_VERIFIER_EXIT_EXTRA = 21,
  DM_VERIFIER_EXIT_STATEMENT = 22,
  DM_VERIFIER_EXIT_DECODE = 23,
  DM_VERIFIER_EXIT_VERIFY = 24,
};

static void secure_clear(void* pointer, size_t bytes) {
  if (pointer == NULL) {
    return;
  }
  volatile uint8_t* cursor = (volatile uint8_t*)pointer;
  while (bytes-- != 0) {
    *cursor++ = 0;
  }
}

static int read_exact(FILE* input, uint8_t* output, size_t length) {
  if (input == NULL || output == NULL || length == 0) {
    return 0;
  }
  size_t offset = 0;
  while (offset != length) {
    const size_t received = fread(output + offset, 1, length - offset, input);
    if (received == 0) {
      return 0;
    }
    offset += received;
  }
  return 1;
}

int main(void) {
#if defined(_WIN32)
  if (_setmode(_fileno(stdin), _O_BINARY) == -1) {
    return DM_VERIFIER_EXIT_IO;
  }
#endif
  uint8_t* expected_wire = (uint8_t*)malloc(DM_WIRE_STATEMENT_BYTES);
  uint8_t* frame = (uint8_t*)malloc(DM_WIRE_FRAME_BYTES);
  dm_wire_statement_t expected_statement;
  dm_wire_proof_t proof;
  dm_wire_proof_init(&proof);
  memset(&expected_statement, 0, sizeof(expected_statement));
  int result = DM_VERIFIER_EXIT_IO;
  if (expected_wire == NULL || frame == NULL) {
    goto cleanup;
  }
  if (!read_exact(stdin, expected_wire, DM_WIRE_STATEMENT_BYTES) ||
      !read_exact(stdin, frame, DM_WIRE_FRAME_BYTES)) {
    result = DM_VERIFIER_EXIT_IO;
    goto cleanup;
  }
  const int trailing = fgetc(stdin);
  if (trailing != EOF) {
    result = DM_VERIFIER_EXIT_EXTRA;
    goto cleanup;
  }
  if (ferror(stdin)) {
    result = DM_VERIFIER_EXIT_IO;
    goto cleanup;
  }
  if (dm_wire_statement_decode(&expected_statement, expected_wire,
                               DM_WIRE_STATEMENT_BYTES) != DM_WIRE_OK) {
    result = DM_VERIFIER_EXIT_STATEMENT;
    goto cleanup;
  }
  const dm_wire_status_t decode_status =
      dm_wire_decode(&proof, &expected_statement, frame, DM_WIRE_FRAME_BYTES);
  if (decode_status != DM_WIRE_OK) {
    result = DM_VERIFIER_EXIT_DECODE;
    goto cleanup;
  }
  result = dm_wire_verify_kernel(&proof, &expected_statement) == DM_WIRE_OK
               ? 0
               : DM_VERIFIER_EXIT_VERIFY;

cleanup:
  dm_wire_proof_clear(&proof);
  secure_clear(&expected_statement, sizeof(expected_statement));
  secure_clear(frame, DM_WIRE_FRAME_BYTES);
  secure_clear(expected_wire, DM_WIRE_STATEMENT_BYTES);
  free(frame);
  free(expected_wire);
  return result;
}
