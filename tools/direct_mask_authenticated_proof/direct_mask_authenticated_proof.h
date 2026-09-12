/* SPDX-License-Identifier: MIT */
#ifndef BLIND_LEDGER_DIRECT_MASK_AUTHENTICATED_PROOF_H
#define BLIND_LEDGER_DIRECT_MASK_AUTHENTICATED_PROOF_H

/*
 * Non-activating composition seam for one source-authenticated direct-mask
 * statement and one independently verified wire proof.  Source authentication
 * remains provenance/scope evidence; proof acceptance remains the wire/kernel
 * boundary.  This seam owns only their checked binding and never authorizes a
 * directive, policy decision, state transition, or source-truth claim.
 */

#include <stddef.h>
#include <stdint.h>

#include "../direct_mask_source_auth/direct_mask_source_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DM_AUTHENTICATED_PROOF_FRAME_BYTES 534370u

#if DM_WIRE_FRAME_BYTES != DM_AUTHENTICATED_PROOF_FRAME_BYTES
#error "the authenticated-proof seam requires the pinned 534370-byte frame"
#endif

typedef enum dm_authenticated_proof_status_t {
  DM_AUTHENTICATED_PROOF_OK = 0,
  DM_AUTHENTICATED_PROOF_ERR_ARGUMENT = -1,
  DM_AUTHENTICATED_PROOF_ERR_SIZE = -2,
  DM_AUTHENTICATED_PROOF_ERR_INPUT_ALIAS = -3,
  DM_AUTHENTICATED_PROOF_ERR_OUTPUT_ALIAS = -4,
  DM_AUTHENTICATED_PROOF_ERR_SOURCE_AUTH = -5,
  DM_AUTHENTICATED_PROOF_ERR_STATEMENT = -6,
  DM_AUTHENTICATED_PROOF_ERR_DECODE = -7,
  DM_AUTHENTICATED_PROOF_ERR_PROOF = -8,
  DM_AUTHENTICATED_PROOF_ERR_ALLOCATION = -9,
} dm_authenticated_proof_status_t;

/*
 * Owned result.  A successful result means only that the supplied source
 * signature and the supplied wire proof were both accepted for the same exact
 * canonical x under the verifier-owned request and epoch.  It is not a proof
 * object and carries no policy, directive, source-truth, or state authority.
 */
typedef struct dm_authenticated_proof_verified_t {
  uint8_t canonical_x[DM_SOURCE_AUTH_X_BYTES];
  uint64_t key_epoch;
} dm_authenticated_proof_verified_t;

const char* dm_authenticated_proof_status_name(
    dm_authenticated_proof_status_t status);

void dm_authenticated_proof_verified_clear(
    dm_authenticated_proof_verified_t* verified);

/*
 * All inputs are borrowed for this synchronous call and must remain valid and
 * unchanged until it returns.  The frame is bounded before any wire parser or
 * proof allocation runs, and its size must be exactly 534370 bytes.  The
 * output owns a copy of the source-authenticated canonical x and is cleared on
 * every ordinary failure.  Illegal output aliases return before clearing so a
 * live input is never destroyed; input-input aliases clear a disjoint output
 * and return an error.  The owned x is volatile verifier evidence only: it must
 * not enter State, WAL, receipts, logs, backups, or any other durable or
 * downstream authority, and callers must clear it when its bounded use ends.
 */
dm_authenticated_proof_status_t dm_authenticated_proof_verify(
    const dm_source_auth_request_t* request, uint64_t presented_key_epoch,
    const uint8_t* canonical_x, size_t canonical_x_bytes,
    const uint8_t* signature, size_t signature_bytes,
    const uint8_t* frame, size_t frame_bytes,
    dm_authenticated_proof_verified_t* verified);

#ifdef __cplusplus
}
#endif

#endif /* BLIND_LEDGER_DIRECT_MASK_AUTHENTICATED_PROOF_H */
