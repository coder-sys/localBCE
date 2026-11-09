// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @notice Interface-only preview for a future STARK claim verifier.
/// @dev This is not wired into ClaimsRegistry and is not a production ABI.
interface IStarkClaimsVerifierPreview {
    function verifyClaim(
        bytes32 claimHash,
        uint8 decision,
        uint32 failureCode,
        bytes calldata proofCommitment
    ) external view returns (bool);
}
