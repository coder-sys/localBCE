/* SPDX-License-Identifier: MIT */
#ifndef BLIND_LEDGER_DIRECT_MASK_WIRE_H
#define BLIND_LEDGER_DIRECT_MASK_WIRE_H

/*
 * This is the concrete, non-activating wire boundary for the direct-mask
 * degree-three candidate.  The BAVC/VOLE implementation is supplied by the
 * separately pinned direct-mask primitive checkout; the relation arithmetic
 * is supplied by direct_mask_kernel in this checkout.
 */

#include <stddef.h>
#include <stdint.h>

#include "direct_mask_kernel.h"
#include "direct_mask_algebra.h"
#include "direct_mask_vole.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DM_WIRE_VERSION DMV_WIRE_VERSION
#define DM_WIRE_HEADER_BYTES DMV_WIRE_HEADER_BYTES
#define DM_WIRE_NONCE_COUNT 3u
#define DM_WIRE_DESCRIPTOR_WORDS 12u
#define DM_WIRE_SOURCE_SUITE_BYTES 16u
#define DM_WIRE_RELATION_ID_BYTES 23u
#define DM_WIRE_RELATION_ID_MAX DM_WIRE_RELATION_ID_BYTES
#define DM_WIRE_CONTEXT_BYTES 64u
#define DM_WIRE_U_BYTES 96u
#define DM_WIRE_T_BYTES 96u
#define DM_WIRE_C_BYTES 800u
#define DM_WIRE_FIELD_BYTES 32u
#define DM_WIRE_NONCE_BYTES DMV_NONCE_BYTES
#define DM_WIRE_NU_BYTES DMV_LEAF_UHASH_BYTES
#define DM_WIRE_WITNESS_BYTES (DMK_WITNESS_BITS / 8u)
#define DM_WIRE_BIT_ROWS (DMK_WITNESS_BITS + DMK_MASK_COUNT * DMV_LAMBDA)
#define DM_WIRE_ROW_BYTES ((DM_WIRE_BIT_ROWS + 7u) / 8u)
#define DM_WIRE_CORRECTION_BYTES ((DMV_TAU - 1u) * DM_WIRE_ROW_BYTES)
#define DM_WIRE_M1_BYTES (16u + DMV_BAVC_COMMITMENT_BYTES + DM_WIRE_CORRECTION_BYTES)
#define DM_WIRE_M2_BYTES (8u * DM_WIRE_FIELD_BYTES + DM_WIRE_WITNESS_BYTES)
#define DM_WIRE_M3_BYTES (3u * DM_WIRE_FIELD_BYTES)
#define DM_WIRE_M4_BYTES (DMV_TAU * DMV_BAVC_COM_BYTES + DMV_T_OPEN * DMV_SEED_BYTES)
#define DM_WIRE_X_FIXED_BYTES \
  (DM_WIRE_SOURCE_SUITE_BYTES + 4u + DM_WIRE_CONTEXT_BYTES + DM_WIRE_U_BYTES + \
   DM_WIRE_T_BYTES + DM_WIRE_C_BYTES + DM_WIRE_DESCRIPTOR_WORDS * 4u)
#define DM_WIRE_STATEMENT_BYTES (DM_WIRE_X_FIXED_BYTES + DM_WIRE_RELATION_ID_BYTES)
#define DM_WIRE_FRAME_BYTES \
  (DM_WIRE_HEADER_BYTES + DM_WIRE_STATEMENT_BYTES + DM_WIRE_NU_BYTES + \
   DM_WIRE_NONCE_COUNT * DM_WIRE_NONCE_BYTES + DM_WIRE_M1_BYTES + DM_WIRE_M2_BYTES + \
   DM_WIRE_M3_BYTES + DM_WIRE_M4_BYTES)
#define DM_WIRE_MAX_BYTES DM_WIRE_FRAME_BYTES

typedef enum dm_wire_status_t {
  DM_WIRE_OK = 0,
  DM_WIRE_ERR_ARGUMENT = -1,
  DM_WIRE_ERR_STATEMENT = -2,
  DM_WIRE_ERR_DESCRIPTOR = -3,
  DM_WIRE_ERR_SIZE = -4,
  DM_WIRE_ERR_ENCODING = -5,
  DM_WIRE_ERR_FRAME = -6,
  DM_WIRE_ERR_CHALLENGE = -7,
  DM_WIRE_ERR_COMMITMENT = -8,
  DM_WIRE_ERR_RELATION = -9,
  DM_WIRE_ERR_RETRY = -10,
  DM_WIRE_ERR_ALLOCATION = -11,
  DM_WIRE_ERR_INPUT = -12,
  DM_WIRE_ERR_BACKEND = -13,
} dm_wire_status_t;

/* The twelve words are serialized in this order, with no host structure padding. */
typedef struct dm_wire_relation_descriptor_t {
  uint32_t field_bits;
  uint32_t degree;
  uint32_t tau;
  uint32_t w_grind;
  uint32_t short_challenge_bits;
  uint32_t open_budget;
  uint32_t witness_bits;
  uint32_t constraints;
  uint32_t padding_bits;
  uint32_t mask_count;
  uint32_t nonce_bits;
  uint32_t challenge_mode;
} dm_wire_relation_descriptor_t;

/* All pointers are borrowed.  The receiver supplies this independently of an untrusted proof. */
typedef struct dm_wire_statement_t {
  uint8_t source_suite[DM_WIRE_SOURCE_SUITE_BYTES];
  const uint8_t* relation_id;
  uint32_t relation_id_bytes;
  const uint8_t* context;
  const uint8_t* U;
  const uint8_t* T;
  const uint8_t* C;
  dm_wire_relation_descriptor_t descriptor;
} dm_wire_statement_t;

typedef struct dm_wire_proof_t {
  dmv_proof_t primitive;
} dm_wire_proof_t;

const char* dm_wire_status_name(dm_wire_status_t status);

dm_wire_status_t dm_wire_statement_validate(const dm_wire_statement_t* statement);
dm_wire_status_t dm_wire_statement_size(const dm_wire_statement_t* statement,
                                        size_t* size_out);
dm_wire_status_t dm_wire_statement_encode(uint8_t* output, size_t output_bytes,
                                          const dm_wire_statement_t* statement);
/* Decode a fixed-size canonical x into borrowed pointers owned by input. */
dm_wire_status_t dm_wire_statement_decode(dm_wire_statement_t* statement,
                                          const uint8_t* input, size_t input_bytes);

dm_wire_status_t dm_wire_proof_size(const dm_wire_proof_t* proof,
                                    const dm_wire_statement_t* statement,
                                    size_t* size_out);
dm_wire_status_t dm_wire_encode(const dm_wire_proof_t* proof,
                                const dm_wire_statement_t* statement,
                                uint8_t* output, size_t output_bytes,
                                size_t* written_out);
dm_wire_status_t dm_wire_decode(dm_wire_proof_t* proof,
                                const dm_wire_statement_t* expected_statement,
                                const uint8_t* input, size_t input_bytes);
void dm_wire_proof_clear(dm_wire_proof_t* proof);

/*
 * Proof lifecycle: initialize with this function or all-zero storage only for fresh or already
 * cleared storage.  Never call init over a live object without clearing it first.  A live proof
 * may be passed to prove/decode for replacement; both operations are destructive and leave the
 * destination zeroed on every failure, including argument, size, and allocation failures.  Clear
 * accepts NULL, zero, or live objects and leaves the object zeroed.  Proof-owned buffers must not
 * alias caller input buffers or the borrowed statement object; the adapter rejects such an alias
 * before dereferencing or clearing the destination.  Statement pointers are borrowed and are
 * never freed.
 */
void dm_wire_proof_init(dm_wire_proof_t* proof);

/*
 * Build and verify the concrete profile from the supplied one-byte-per-bit kernel witness.  The
 * callback is an injectable random-byte source for tests or an application-owned CSPRNG.  Use
 * dm_wire_prove_kernel_os for the production-shaped OS-CSPRNG path; a deterministic callback is
 * test-only and must not be used for production proof generation.
 */
dm_wire_status_t dm_wire_prove_kernel(
    dm_wire_proof_t* proof, const dm_wire_statement_t* statement,
    const uint8_t* witness_bits, size_t witness_count,
    dmv_random_bytes_fn random_bytes, void* random_context,
    uint32_t max_final_retries);
dm_wire_status_t dm_wire_prove_kernel_os(
    dm_wire_proof_t* proof, const dm_wire_statement_t* statement,
    const uint8_t* witness_bits, size_t witness_count, uint32_t max_final_retries);
dm_wire_status_t dm_wire_verify_kernel(const dm_wire_proof_t* proof,
                                       const dm_wire_statement_t* expected_statement);

/* Uses the platform OS CSPRNG.  Returns 0 on success, nonzero on failure. */
int dm_wire_os_random_bytes(void* context, uint8_t* output, size_t length);

#ifdef __cplusplus
}
#endif

#endif
