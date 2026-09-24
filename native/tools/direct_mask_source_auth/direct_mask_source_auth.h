/* SPDX-License-Identifier: MIT */
#ifndef BLIND_LEDGER_DIRECT_MASK_SOURCE_AUTH_H
#define BLIND_LEDGER_DIRECT_MASK_SOURCE_AUTH_H

/*
 * Detached source-authentication binding for the direct-mask canonical public
 * commitment x.  This module authenticates provenance, scope, and key epoch;
 * it has no proof, policy, disposition, or state-transition authority.
 */

#include <stddef.h>
#include <stdint.h>

#include "direct_mask_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DM_SOURCE_AUTH_DOMAIN "BL/DM/SOURCE-AUTH/v1"
#define DM_SOURCE_AUTH_DOMAIN_BYTES 20u
#define DM_SOURCE_AUTH_KEY_EPOCH_BYTES 8u
#define DM_SOURCE_AUTH_X_BYTES 1147u
#define DM_SOURCE_AUTH_MESSAGE_BYTES \
  (DM_SOURCE_AUTH_DOMAIN_BYTES + DM_SOURCE_AUTH_KEY_EPOCH_BYTES + DM_SOURCE_AUTH_X_BYTES)
#define DM_SOURCE_AUTH_CONTEXT_BYTES DM_WIRE_CONTEXT_BYTES
#define DM_SOURCE_AUTH_U_BYTES DM_WIRE_U_BYTES
#define DM_SOURCE_AUTH_PUBLIC_KEY_BYTES 2592u
#define DM_SOURCE_AUTH_SECRET_KEY_BYTES 4896u
#define DM_SOURCE_AUTH_SIGNATURE_BYTES 4627u
#define DM_SOURCE_AUTH_RANDOMIZER_BYTES 32u

typedef enum dm_source_auth_status_t {
  DM_SOURCE_AUTH_OK = 0,
  DM_SOURCE_AUTH_ERR_ARGUMENT = -1,
  DM_SOURCE_AUTH_ERR_SIZE = -2,
  DM_SOURCE_AUTH_ERR_CANONICAL_X = -3,
  DM_SOURCE_AUTH_ERR_REQUEST = -4,
  DM_SOURCE_AUTH_ERR_CONTEXT = -5,
  DM_SOURCE_AUTH_ERR_U = -6,
  DM_SOURCE_AUTH_ERR_KEY_EPOCH = -7,
  DM_SOURCE_AUTH_ERR_SIGNATURE = -8,
  DM_SOURCE_AUTH_ERR_CRYPTO = -9,
  DM_SOURCE_AUTH_ERR_CSPRNG = -10,
  DM_SOURCE_AUTH_ERR_OUTPUT_ALIAS = -11,
  DM_SOURCE_AUTH_ERR_INPUT_ALIAS = -12,
} dm_source_auth_status_t;

typedef enum dm_source_auth_authentication_t {
  DM_SOURCE_AUTH_UNAUTHENTICATED = 0,
  DM_SOURCE_AUTH_AUTHENTICATED = 1,
} dm_source_auth_authentication_t;

/*
 * Verifier-owned expected request.  The fixed suite, relation, and descriptor
 * are carried for explicit binding but are accepted only when they equal this
 * module's compile-time constants.  All arrays are caller-owned storage and
 * are snapshotted once by dm_source_auth_verify.
 */
typedef struct dm_source_auth_request_t {
  uint8_t expected_source_suite[DM_WIRE_SOURCE_SUITE_BYTES];
  uint8_t expected_relation_id[DM_WIRE_RELATION_ID_BYTES];
  uint8_t expected_context[DM_SOURCE_AUTH_CONTEXT_BYTES];
  uint8_t expected_U[DM_SOURCE_AUTH_U_BYTES];
  dm_wire_relation_descriptor_t expected_descriptor;
  uint8_t trusted_public_key[DM_SOURCE_AUTH_PUBLIC_KEY_BYTES];
  uint64_t expected_key_epoch;
} dm_source_auth_request_t;

/*
 * Owned verifier output.  canonical_x is the exact x snapshot authenticated by
 * the signature.  No proof, source record, root, private value, directive, or
 * state result is returned.
 */
typedef struct dm_source_auth_verified_t {
  uint8_t canonical_x[DM_SOURCE_AUTH_X_BYTES];
  uint64_t key_epoch;
  dm_source_auth_authentication_t authentication;
} dm_source_auth_verified_t;

const char* dm_source_auth_status_name(dm_source_auth_status_t status);

/* Initializes fixed request fields and clears all other fields. */
void dm_source_auth_request_init(dm_source_auth_request_t* request);
void dm_source_auth_request_clear(dm_source_auth_request_t* request);
void dm_source_auth_verified_clear(dm_source_auth_verified_t* verified);

/*
 * Source-owned signing seam.  secret_key and canonical_x are borrowed only for
 * this synchronous call; the caller must keep each advertised input span valid
 * and unmodified until the call returns.  The module copies them once, retains
 * nothing, obtains a fresh
 * 32-byte OS-CSPRNG hedging randomizer, and wipes all local sensitive buffers.
 * The randomizer is intentionally not caller-configurable.  key_epoch is
 * encoded as positive uint64 little-endian bytes after the 20-byte ASCII
 * domain and before the exact canonical x bytes.
 *
 * On ordinary failure, a disjoint signature output is wiped through the
 * bounded span min(signature_bytes, DM_SOURCE_AUTH_SIGNATURE_BYTES); a valid
 * full-capacity output is therefore always zeroed, while an invalid advertised
 * span is never overrun.  If an input/output alias is detected, the function
 * returns before clearing the output so a live input is never destroyed;
 * callers must discard that output because the status is non-OK.  Inputs must
 * not alias each other.
 */
dm_source_auth_status_t dm_source_auth_sign(
    uint8_t* signature, size_t signature_bytes, const uint8_t* secret_key,
    size_t secret_key_bytes, uint64_t key_epoch, const uint8_t* canonical_x,
    size_t canonical_x_bytes);

/*
 * Verifier seam.  request, canonical_x, and signature are borrowed for this
 * synchronous call; the caller must keep each advertised input span valid and
 * unmodified until the call returns.  The verifier snapshots all of them
 * before validation and cryptographic checking,
 * validates the canonical x through the existing direct-mask wire codec,
 * compares the full expected request bindings, checks the separately presented
 * epoch, and returns only an owned authenticated x snapshot.
 *
 * On ordinary failure verified is zeroed and unauthenticated.  An input-input
 * alias also clears the disjoint verified output.  Only an illegal
 * input/output alias returns before clearing verified to avoid destroying the
 * aliased input; callers must discard the output on that error.
 */
dm_source_auth_status_t dm_source_auth_verify(
    const dm_source_auth_request_t* request, uint64_t presented_key_epoch,
    const uint8_t* canonical_x, size_t canonical_x_bytes,
    const uint8_t* signature, size_t signature_bytes,
    dm_source_auth_verified_t* verified);

#ifdef __cplusplus
}
#endif

#endif /* BLIND_LEDGER_DIRECT_MASK_SOURCE_AUTH_H */
