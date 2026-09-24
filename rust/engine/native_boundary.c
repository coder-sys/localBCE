#include <lean/lean.h>

#include <stddef.h>
#include <stdint.h>

extern void *malloc(size_t size);
extern void free(void *pointer);

static void blind_ledger_copy_bytes(uint8_t *destination, const uint8_t *source,
                                    size_t size) {
  for (size_t index = 0; index < size; ++index) {
    destination[index] = source[index];
  }
}

#define BLIND_LEDGER_MAX_INPUT_BYTES ((size_t)1000000)
#define BLIND_LEDGER_MAX_OUTPUT_BYTES ((size_t)(64 * 1024))

enum {
  BLIND_LEDGER_NATIVE_OK = 0,
  BLIND_LEDGER_NATIVE_INVALID_ARGUMENT = 1,
  BLIND_LEDGER_NATIVE_INITIALIZATION = 2,
  BLIND_LEDGER_NATIVE_OUTPUT_TOO_LARGE = 3,
  BLIND_LEDGER_NATIVE_ALLOCATION = 4,
  BLIND_LEDGER_NATIVE_RESULT_INVALID = 5,
};

extern void lean_initialize_runtime_module(void);
extern lean_object *initialize_blind__ledger__semantic__kernel_BlindLedger_SemanticExecutable(
    uint8_t builtin);
extern lean_object *blind_ledger_run_bytes(lean_object *data);

/* The adapter is intentionally one-shot: the outer State runner starts one
   process per request.  Runtime initialization/finalization is global Lean
   runtime state, not durable authority or per-request semantic state. */
static int blind_ledger_runtime_state = 0;

int blind_ledger_native_initialize(void) {
  if (blind_ledger_runtime_state == 1) {
    return BLIND_LEDGER_NATIVE_OK;
  }
  if (blind_ledger_runtime_state != 0) {
    return BLIND_LEDGER_NATIVE_INITIALIZATION;
  }

  lean_initialize_runtime_module();
  lean_object *result =
      initialize_blind__ledger__semantic__kernel_BlindLedger_SemanticExecutable(1);
  if (result == NULL || !lean_io_result_is_ok(result)) {
    if (result != NULL) {
      lean_dec_ref(result);
    }
    blind_ledger_runtime_state = -1;
    return BLIND_LEDGER_NATIVE_INITIALIZATION;
  }
  lean_dec_ref(result);
  lean_io_mark_end_initialization();
  lean_init_task_manager();
  blind_ledger_runtime_state = 1;
  return BLIND_LEDGER_NATIVE_OK;
}

int blind_ledger_native_run(const uint8_t *input, size_t input_len,
                            uint8_t **output, size_t *output_len) {
  if (output == NULL || output_len == NULL || input_len > BLIND_LEDGER_MAX_INPUT_BYTES ||
      (input_len != 0 && input == NULL)) {
    return BLIND_LEDGER_NATIVE_INVALID_ARGUMENT;
  }
  *output = NULL;
  *output_len = 0;

  int initialization = blind_ledger_native_initialize();
  if (initialization != BLIND_LEDGER_NATIVE_OK) {
    return initialization;
  }

  /* The input bound is checked before Lean allocates the ByteArray. */
  lean_object *data = lean_mk_empty_byte_array(lean_box(input_len));
  if (data == NULL) {
    return BLIND_LEDGER_NATIVE_ALLOCATION;
  }
  lean_sarray_set_size(data, input_len);
  if (input_len != 0) {
    blind_ledger_copy_bytes(lean_sarray_cptr(data), input, input_len);
  }

  /* This call owns/consumes `data` according to Lean's generated object ABI. */
  lean_object *line = blind_ledger_run_bytes(data);
  if (line == NULL || !lean_is_string(line)) {
    if (line != NULL) {
      lean_dec_ref(line);
    }
    return BLIND_LEDGER_NATIVE_RESULT_INVALID;
  }

  /* Lean strings reserve one byte for the terminating NUL in m_size. */
  size_t line_size = lean_string_size(line);
  if (line_size == 0) {
    lean_dec_ref(line);
    return BLIND_LEDGER_NATIVE_RESULT_INVALID;
  }
  size_t line_len = line_size - 1;
  if (line_len > BLIND_LEDGER_MAX_OUTPUT_BYTES) {
    lean_dec_ref(line);
    return BLIND_LEDGER_NATIVE_OUTPUT_TOO_LARGE;
  }

  /* The copied buffer is the only cross-language allocation and is bounded
     before malloc.  Rust must return it through blind_ledger_native_free. */
  uint8_t *copy = (uint8_t *)malloc(line_len + 1);
  if (copy == NULL) {
    lean_dec_ref(line);
    return BLIND_LEDGER_NATIVE_ALLOCATION;
  }
  blind_ledger_copy_bytes(copy, (const uint8_t *)lean_string_cstr(line), line_len);
  copy[line_len] = 0;
  lean_dec_ref(line);
  *output = copy;
  *output_len = line_len;
  return BLIND_LEDGER_NATIVE_OK;
}

void blind_ledger_native_free(uint8_t *output, size_t output_len) {
  (void)output_len;
  free(output);
}

void blind_ledger_native_shutdown(void) {
  if (blind_ledger_runtime_state == 1) {
    lean_finalize_task_manager();
    blind_ledger_runtime_state = 2;
  }
}
