/* SPDX-License-Identifier: MIT */

#ifndef BLIND_LEDGER_DIRECT_MASK_VOLE_H
#define BLIND_LEDGER_DIRECT_MASK_VOLE_H

/* Experimental, non-activating DMV3 candidate; not a production FAEST implementation. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fields.h"
#include "hash_shake.h"

#define DMV_LAMBDA 256u
#define DMV_LAMBDA_BYTES (DMV_LAMBDA / 8u)
#define DMV_SEED_BITS 512u
#define DMV_SEED_BYTES (DMV_SEED_BITS / 8u)
#define DMV_TAU 33u
#define DMV_W_GRIND 8u
#define DMV_CHALLENGE_BITS (DMV_LAMBDA - DMV_W_GRIND)
#define DMV_CHALLENGE_BYTES DMV_LAMBDA_BYTES
#define DMV_TAU1 17u
#define DMV_TAU0 16u
#define DMV_TREE_K 8u
#define DMV_TREE_LEAVES 6400u
#define DMV_T_OPEN 229u
#define DMV_DEGREE 3u
#define DMV_SHORT_CHALLENGE_BITS 64u
#define DMV_MASK_COUNT 6u
#define DMV_NONCE_BYTES 64u
#define DMV_CHALLENGE_MODE 3u
#define DMV_TAIL_BITS (2u * DMV_SEED_BITS + 288u)
#define DMV_TAIL_BYTES (DMV_TAIL_BITS / 8u)
#define DMV_NU_BITS (3u * DMV_SEED_BITS + 287u)
#define DMV_NU_BYTES ((DMV_NU_BITS + 7u) / 8u)
#define DMV_FULL_GENERATOR_BITS 2112u
#define DMV_FULL_GENERATOR_BYTES (DMV_FULL_GENERATOR_BITS / 8u)
#define DMV_H0_ACTIVE_BITS (DMV_NU_BITS + 10u)
#define DMV_H0_SQUEEZE_BYTES ((DMV_H0_ACTIVE_BITS + 7u) / 8u)
#define DMV_FS1_BYTES 264u
#define DMV_FS2_BYTES 104u
#define DMV_FS2_SQUEEZE_BYTES 105u
#define DMV_FS3_BYTES DMV_LAMBDA_BYTES
#define DMV_FS3_SQUEEZE_BYTES 33u
#define DMV_LEAF_UHASH_BYTES DMV_NU_BYTES
#define DMV_BAVC_COMMITMENT_BYTES (2u * DMV_LAMBDA_BYTES)
#define DMV_BAVC_COM_BYTES DMV_TAIL_BYTES
#define DMV_TREE_INTERNAL_NODES (DMV_TREE_LEAVES - 1u)
#define DMV_TREE_HEAP_NODES (2u * DMV_TREE_LEAVES - 1u)
#define DMV_TREE_MAX_INSTANCES (1u << DMV_TREE_K)
#define DMV_ROW_STREAM_BLOCK_BYTES DMV_SEED_BYTES
#define DMV_MAX_WITNESS_BITS (1u << 17)
#define DMV_MAX_CONSTRAINTS (1u << 18)
#define DMV_MAX_H0_RETRIES (1u << 16)
#define DMV_MAX_FS2_RETRIES (1u << 12)
#define DMV_MAX_FS3_RETRIES (1u << 22)
/* The outer request carries one caller-supplied upper bound.  Each local stage
 * takes the minimum of that bound and its own fixed cap. */
#define DMV_MAX_FINAL_RETRIES DMV_MAX_FS3_RETRIES
#define DMV_WIRE_HEADER_BYTES 40u
#define DMV_WIRE_VERSION 3u
#define DMV_TRANSCRIPT_PREFIX "BL/DMV/FAEST-256F/v3"
#define DMV_TRANSCRIPT_PREFIX_BYTES (sizeof(DMV_TRANSCRIPT_PREFIX) - 1u)
#define DMV_GENERATOR_VERSION "DMV-RO-WIDE-SEED-v3"
#define DMV_GENERATOR_VERSION_BYTES (sizeof(DMV_GENERATOR_VERSION) - 1u)

typedef enum dmv_status_t {
  DMV_OK = 0,
  DMV_ERR_ARGUMENT = -1,
  DMV_ERR_DESCRIPTOR = -2,
  DMV_ERR_SIZE = -3,
  DMV_ERR_CHALLENGE = -4,
  DMV_ERR_OPENING = -5,
  DMV_ERR_COMMITMENT = -6,
  DMV_ERR_ALLOCATION = -7,
  DMV_ERR_RELATION = -8,
  DMV_ERR_RETRY = -9,
  DMV_ERR_ENCODING = -10,
} dmv_status_t;

/* Dimensions are deliberately independent of faest_paramset_t's uint16_t ell field. */
typedef struct dmv_descriptor_t {
  uint32_t witness_bits;       /* byte-padded, including constrained padding */
  uint32_t constraint_count;   /* admitted generic relation size */
  uint8_t degree;              /* exactly DMV_DEGREE for this suite */
} dmv_descriptor_t;

typedef struct dmv_commitment_t {
  dmv_descriptor_t descriptor;
  uint32_t bit_rows;
  size_t row_bytes;
  uint8_t iv[16];
  /* Opaque child-local DMV3 wide-seed tree; never a wire or mathematical table. */
  void* backend;
  uint8_t* u_bits;
  uint8_t* corrections;
  bf256_t* v_rows;
  bool initialized;
} dmv_commitment_t;

typedef int (*dmv_random_bytes_fn)(void* context, uint8_t* out, size_t length);

/* The relation adapter owns the circuit-specific semantics.  The prover callback streams the four
 * coefficients of each degree-three homogenized polynomial F_j to the sink in row order.  The
 * verifier callback checks the same relation at q' and the supplied mask term, including the
 * value B supplied by this backend.  Both callbacks are required so the generic proof body
 * remains independent of PQ's circuit layout while keeping the proof/verifier boundary explicit. */
typedef int (*dmv_coefficient_sink_fn)(void* context, uint32_t row,
                                       const bf256_t coefficients[DMV_DEGREE + 1u]);
typedef int (*dmv_relation_prove_fn)(
    void* context, const dmv_descriptor_t* descriptor, const bf256_t* base_rows,
    uint32_t bit_rows, const uint8_t* witness, size_t witness_bytes,
    dmv_coefficient_sink_fn coefficient_sink, void* sink_context);
typedef int (*dmv_relation_verify_fn)(
    void* context, const dmv_descriptor_t* descriptor, const bf256_t* q_prime_rows,
    uint32_t bit_rows, const bf256_t* mask_term, const uint8_t gamma2[DMV_FS2_BYTES],
    const bf256_t* delta, const bf256_t* expected_b);

typedef struct dmv_relation_callbacks_t {
  dmv_relation_prove_fn prove;
  dmv_relation_verify_fn verify;
} dmv_relation_callbacks_t;

typedef struct dmv_proof_t {
  dmv_descriptor_t descriptor;
  uint8_t* statement;
  size_t statement_len;
  uint8_t nu[DMV_LEAF_UHASH_BYTES];
  uint8_t sigma1[DMV_NONCE_BYTES];
  uint8_t sigma2[DMV_NONCE_BYTES];
  uint8_t sigma3[DMV_NONCE_BYTES];
  uint8_t* m1;
  uint8_t* m2;
  uint8_t* m3;
  uint8_t* m4;
  size_t m1_len;
  size_t m2_len;
  size_t m3_len;
  size_t m4_len;
  bool initialized;
} dmv_proof_t;

/* Local diagnostics are deliberately separate from the proof/wire grammar.  A
 * reservation is charged before its RNG/query work; RNG failures are counted
 * as aborted reservations and never masquerade as oracle queries. */
typedef struct dmv_retry_counters_t {
  uint64_t h0_reserved;
  uint64_t h0_queries;
  uint64_t h0_accepted;
  uint64_t h0_rejected;
  uint64_t h0_aborted;
  uint64_t h0_rng_failures;
  uint64_t fs2_reserved;
  uint64_t fs2_queries;
  uint64_t fs2_accepted;
  uint64_t fs2_rejected;
  uint64_t fs2_aborted;
  uint64_t fs2_rng_failures;
  uint64_t fs3_reserved;
  uint64_t fs3_queries;
  uint64_t fs3_accepted;
  uint64_t fs3_rejected;
  uint64_t fs3_aborted;
  uint64_t fs3_rng_failures;
} dmv_retry_counters_t;

/* Optional construction-stage clock evidence.  These are process-local CPU-clock
 * ticks from the native candidate and do not alter the proof or wire contract. */
typedef struct dmv_stage_metrics_t {
  uint64_t clock_ticks_per_second;
  uint64_t h0_clock_ticks;
  uint64_t commitment_clock_ticks;
  uint64_t construction_clock_ticks;
  uint64_t fs2_clock_ticks;
  uint64_t relation_clock_ticks;
  uint64_t fs3_clock_ticks;
} dmv_stage_metrics_t;

/* A frozen transcript prefix is queried only through hash_copy into a fresh
 * live context.  The vendor hash_context is included intentionally: this is
 * a native, pinned candidate API, not a portable wire type. */
typedef struct dmv_transcript_cache_t {
  hash_context prefix;
  uint8_t domain[3];
  bool initialized;
} dmv_transcript_cache_t;

int dmv_descriptor_validate(const dmv_descriptor_t* descriptor);
int dmv_descriptor_bit_rows(const dmv_descriptor_t* descriptor, uint32_t* bit_rows_out);
int dmv_row_bytes(uint32_t bit_rows, size_t* row_bytes_out);

size_t dmv_correction_bytes(const dmv_descriptor_t* descriptor);
size_t dmv_m1_bytes(const dmv_descriptor_t* descriptor);
size_t dmv_m2_bytes(const dmv_descriptor_t* descriptor);
size_t dmv_m3_bytes(void);
size_t dmv_m4_bytes(void);
size_t dmv_opening_bytes(void);

/* The first dmv_commit call requires a zero-initialized object.  A live object may be
 * passed to dmv_commit again; it is cleared before reuse.  dmv_commit_clear is also
 * required for every completed or failed initialization to release and wipe state. */
/* Commit the ordinary bit-VOLE rows and six additional lambda-row mask blocks. */
int dmv_commit(dmv_commitment_t* commitment, const dmv_descriptor_t* descriptor,
               const uint8_t root[DMV_SEED_BYTES], const uint8_t iv[16],
               const uint8_t nu[DMV_NU_BYTES]);
void dmv_commit_clear(dmv_commitment_t* commitment);

const uint8_t* dmv_bavc_commitment(const dmv_commitment_t* commitment);
const uint8_t* dmv_u_bits(const dmv_commitment_t* commitment);
const uint8_t* dmv_corrections(const dmv_commitment_t* commitment);
const bf256_t* dmv_v_rows(const dmv_commitment_t* commitment);

/* m4 opening selected by the low 248 challenge bits and the fixed opening budget. */
int dmv_open(const dmv_commitment_t* commitment, const uint8_t raw_challenge[DMV_CHALLENGE_BYTES],
             uint8_t* opening, size_t opening_len);

/* Reconstruct q rows and Delta from m1/m4. q rows are the native 248-bit FAEST projection. */
int dmv_reconstruct(const dmv_descriptor_t* descriptor, const uint8_t iv[16],
                    const uint8_t nu[DMV_NU_BYTES],
                    const uint8_t raw_challenge[DMV_CHALLENGE_BYTES], const uint8_t* opening,
                    size_t opening_len, const uint8_t* corrections, size_t corrections_len,
                    uint8_t reconstructed_commitment[DMV_BAVC_COMMITMENT_BYTES], bf256_t* q_rows,
                    size_t q_rows_count, bf256_t* delta_out);

/* H0(iv), the DMV3 filtered wide-seed universal-hash key bound into FS1. */
int dmv_derive_leaf_uhash(uint8_t uhash[DMV_LEAF_UHASH_BYTES], const uint8_t iv[16]);

/* Full fixed-output transcript paths.  The final filter suffix is returned so
 * tests can compare filtered and payload bytes without forcing acceptance. */
int dmv_h0_raw(uint8_t out[DMV_H0_SQUEEZE_BYTES], const uint8_t iv[16]);
int dmv_fs2_raw(uint8_t out[DMV_FS2_SQUEEZE_BYTES], const uint8_t* statement,
                size_t statement_len, const uint8_t uhash[DMV_LEAF_UHASH_BYTES],
                const uint8_t* m1, size_t m1_len, const uint8_t nonce1[DMV_NONCE_BYTES],
                const uint8_t gamma1[DMV_FS1_BYTES], const uint8_t* m2, size_t m2_len,
                const uint8_t nonce2[DMV_NONCE_BYTES]);
int dmv_fs3_raw(uint8_t out[DMV_FS3_SQUEEZE_BYTES], const uint8_t* statement,
                size_t statement_len, const uint8_t uhash[DMV_LEAF_UHASH_BYTES],
                const uint8_t* m1, size_t m1_len, const uint8_t nonce1[DMV_NONCE_BYTES],
                const uint8_t gamma1[DMV_FS1_BYTES], const uint8_t* m2, size_t m2_len,
                const uint8_t nonce2[DMV_NONCE_BYTES], const uint8_t gamma2[DMV_FS2_BYTES],
                const uint8_t* m3, size_t m3_len, const uint8_t nonce3[DMV_NONCE_BYTES]);

int dmv_fs2_cache_init(dmv_transcript_cache_t* cache, const uint8_t* statement,
                       size_t statement_len, const uint8_t uhash[DMV_LEAF_UHASH_BYTES],
                       const uint8_t* m1, size_t m1_len, const uint8_t nonce1[DMV_NONCE_BYTES],
                       const uint8_t gamma1[DMV_FS1_BYTES], const uint8_t* m2, size_t m2_len);
int dmv_fs3_cache_init(dmv_transcript_cache_t* cache, const uint8_t* statement,
                       size_t statement_len, const uint8_t uhash[DMV_LEAF_UHASH_BYTES],
                       const uint8_t* m1, size_t m1_len, const uint8_t nonce1[DMV_NONCE_BYTES],
                       const uint8_t gamma1[DMV_FS1_BYTES], const uint8_t* m2, size_t m2_len,
                       const uint8_t nonce2[DMV_NONCE_BYTES], const uint8_t gamma2[DMV_FS2_BYTES],
                       const uint8_t* m3, size_t m3_len);
int dmv_fs2_cache_query_raw(const dmv_transcript_cache_t* cache,
                             uint8_t out[DMV_FS2_SQUEEZE_BYTES],
                             const uint8_t nonce2[DMV_NONCE_BYTES]);
int dmv_fs3_cache_query_raw(const dmv_transcript_cache_t* cache,
                             uint8_t out[DMV_FS3_SQUEEZE_BYTES],
                             const uint8_t nonce3[DMV_NONCE_BYTES]);
void dmv_transcript_cache_clear(dmv_transcript_cache_t* cache);

/* Length-delimited, domain-separated FS encodings. */
int dmv_fs1(uint8_t* out, size_t out_len, const uint8_t* statement, size_t statement_len,
            const uint8_t uhash[DMV_LEAF_UHASH_BYTES], const uint8_t* m1, size_t m1_len,
            const uint8_t nonce1[DMV_NONCE_BYTES]);
int dmv_fs2(uint8_t* out, size_t out_len, const uint8_t* statement, size_t statement_len,
            const uint8_t uhash[DMV_LEAF_UHASH_BYTES], const uint8_t* m1, size_t m1_len,
            const uint8_t nonce1[DMV_NONCE_BYTES], const uint8_t gamma1[DMV_FS1_BYTES],
            const uint8_t* m2, size_t m2_len,
            const uint8_t nonce2[DMV_NONCE_BYTES]);
int dmv_fs3(uint8_t out[DMV_LAMBDA_BYTES], const uint8_t* statement, size_t statement_len,
            const uint8_t uhash[DMV_LEAF_UHASH_BYTES], const uint8_t* m1, size_t m1_len,
            const uint8_t nonce1[DMV_NONCE_BYTES], const uint8_t gamma1[DMV_FS1_BYTES],
            const uint8_t* m2, size_t m2_len, const uint8_t nonce2[DMV_NONCE_BYTES],
            const uint8_t gamma2[DMV_FS2_BYTES], const uint8_t* m3, size_t m3_len,
            const uint8_t nonce3[DMV_NONCE_BYTES]);

/* Generic direct-mask degree-three proof and canonical E2E wire.
 *
 * Lifecycle contract for dmv_proof_t:
 * - Before the first dmv_prove, dmv_proof_decode, or dmv_proof_clear call, the object must be
 *   zero-initialized (for example, dmv_proof_t proof = {0}).
 * - A successful dmv_prove or dmv_proof_decode returns an initialized live object.  Both
 *   functions clear a live destination before doing any work, so live reuse is supported.
 * - A failed dmv_prove or dmv_proof_decode leaves the destination zeroed and invalid; callers
 *   must not verify, size, or encode that destination and may call dmv_proof_clear again.
 * - dmv_proof_clear is idempotent for zeroed and live objects and leaves the object zeroed.
 * - The dmv_prove output object and its owned storage must not overlap descriptor, statement,
 *   witness, or storage used by the relation callback.  A dmv_proof_decode destination must
 *   not overlap the input wire storage.  dmv_proof_encode's output wire must not overlap the
 *   proof object or any storage owned by it.
 *
 * Wire bytes are: fixed DMV3 header, x, explicit nu, sigma1, sigma2, sigma3, m1, m2, m3, m4.
 * The header stores the descriptor and every variable payload length in little-endian uint32.
 * FS challenges are recomputed; they are intentionally not wire fields. */
/* Exact pinned VOLEHash over the ordinary rows, mask blocks 0..1 as the two
 * recurrence coordinates, and mask blocks 2..5 as the four additive lanes. */
int dmv_vh_eval(const uint8_t gamma1[DMV_FS1_BYTES], const bf256_t* rows, uint32_t row_count,
                const bf256_t masks[DMV_MASK_COUNT], bf256_t out[4]);
int dmv_prove(dmv_proof_t* proof, const dmv_descriptor_t* descriptor, const uint8_t* statement,
              size_t statement_len, const uint8_t* witness, size_t witness_bytes,
              dmv_random_bytes_fn random_bytes, void* random_context,
              const dmv_relation_callbacks_t* relation, void* relation_context,
              uint32_t max_final_retries);
int dmv_prove_ex(dmv_proof_t* proof, const dmv_descriptor_t* descriptor,
                 const uint8_t* statement, size_t statement_len,
                 const uint8_t* witness, size_t witness_bytes,
                 dmv_random_bytes_fn random_bytes, void* random_context,
                 const dmv_relation_callbacks_t* relation, void* relation_context,
                 uint32_t max_final_retries, dmv_retry_counters_t* counters,
                 dmv_stage_metrics_t* metrics);
int dmv_verify(const dmv_proof_t* proof, const dmv_descriptor_t* expected_descriptor,
               const uint8_t* expected_statement, size_t expected_statement_len,
               const dmv_relation_callbacks_t* relation, void* relation_context);
void dmv_proof_clear(dmv_proof_t* proof);
int dmv_proof_wire_size(const dmv_proof_t* proof, size_t* size_out);
int dmv_proof_encode(const dmv_proof_t* proof, uint8_t* wire, size_t wire_len,
                     size_t* written_out);
int dmv_proof_decode(dmv_proof_t* proof, const uint8_t* wire, size_t wire_len);

#endif
