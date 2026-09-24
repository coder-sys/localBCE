#include "lean/lean.h"

void *memcpy(void *destination, const void *source, size_t count);

extern lean_object *initialize_blind__ledger__admission__kernel_Admission_Library(uint8_t builtin);
extern lean_object *blind_ledger_admission_run_bytes(lean_object *data);
extern void lean_initialize_runtime_module(void);

static int g_runtime_state = 0;

static void wipe_bytes(uint8_t *data, size_t length) {
    volatile uint8_t *cursor = data;
    while (length-- != 0) {
        *cursor++ = 0;
    }
}

int blind_ledger_native_initialize(void) {
    if (g_runtime_state == 1) {
        return 0;
    }
    if (g_runtime_state == -1) {
        return -1;
    }
    lean_initialize_runtime_module();
    lean_object *initialization =
        initialize_blind__ledger__admission__kernel_Admission_Library(1);
    if (initialization == NULL || !lean_io_result_is_ok(initialization)) {
        if (initialization != NULL) {
            lean_dec_ref(initialization);
        }
        g_runtime_state = -1;
        return -1;
    }
    lean_dec_ref(initialization);
    lean_io_mark_end_initialization();
    lean_init_task_manager();
    g_runtime_state = 1;
    return 0;
}

int blind_ledger_native_run(
    const uint8_t *input,
    size_t input_length,
    uint8_t **output,
    size_t *output_length) {
    if (output == NULL || output_length == NULL ||
        (input == NULL && input_length != 0) || input_length > 1000000 ||
        g_runtime_state != 1) {
        return -1;
    }
    *output = NULL;
    *output_length = 0;

    lean_object *input_array = lean_alloc_sarray(1, 0, input_length);
    if (input_array == NULL) {
        return -2;
    }
    if (input_length != 0) {
        memcpy(lean_sarray_cptr(input_array), input, input_length);
    }
    lean_sarray_set_size(input_array, input_length);

    lean_object *result = blind_ledger_admission_run_bytes(input_array);
    if (result == NULL || !lean_is_sarray(result) ||
        lean_sarray_elem_size(result) != 1 || lean_sarray_size(result) > 216) {
        if (result != NULL) {
            lean_dec_ref(result);
        }
        return -3;
    }

    size_t result_length = lean_sarray_size(result);
    uint8_t *copy = (uint8_t *)malloc(result_length == 0 ? 1 : result_length);
    if (copy == NULL) {
        lean_dec_ref(result);
        return -4;
    }
    if (result_length != 0) {
        memcpy(copy, lean_sarray_cptr(result), result_length);
    }
    lean_dec_ref(result);
    *output = copy;
    *output_length = result_length;
    return 0;
}

void blind_ledger_native_free(uint8_t *output, size_t output_length) {
    if (output != NULL) {
        wipe_bytes(output, output_length);
        free(output);
    }
}

void blind_ledger_native_shutdown(void) {
    if (g_runtime_state == 1) {
        lean_finalize_task_manager();
        g_runtime_state = 2;
    }
}
