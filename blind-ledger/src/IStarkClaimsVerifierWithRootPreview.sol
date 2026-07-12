// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @notice Root-aware interface preview for a future STARK claim verifier.
/// @dev This is not wired into ClaimsRegistry and is not a production ABI.
interface IStarkClaimsVerifierWithRootPreview {
    function verifyClaimWithPublicInputRoot(
        bytes32 claimHash,
        uint8 decision,
        uint32 failureCode,
        bytes32 publicInputRoot,
        bytes calldata proofCommitment
    ) external view returns (bool);
}
