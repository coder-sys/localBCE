// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @notice Interface-only preview for a future STARK ClaimsRegistry adapter.
/// @dev This is not wired into the active Groth16 ClaimsRegistry.
interface IStarkClaimsRegistryAdapterPreview {
    function submitStarkClaim(
        bytes32 claimHash,
        uint8 decision,
        uint32 failureCode,
        bytes32 publicInputRoot,
        bytes calldata proofCommitment,
        uint256 claimAmount
    ) external payable;
}
