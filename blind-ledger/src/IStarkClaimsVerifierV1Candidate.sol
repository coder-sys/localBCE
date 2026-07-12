// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// @notice Candidate ABI for a future production STARK claims verifier.
/// @dev Preview only. This is not wired into ClaimsRegistry and is not audited.
interface IStarkClaimsVerifierV1Candidate {
    struct PublicInputs {
        bytes32 claimHash;
        uint8 decision;
        uint32 failureCode;
        bytes32 publicInputRoot;
        bytes32 claimSourceRoot;
        bytes32 oracleFactsRoot;
        bytes32 feeScheduleRoot;
        bytes32 nullifierRootBefore;
        bytes32 nullifierRootAfter;
        bytes32 batchRoot;
    }

    function verifyStarkClaim(
        PublicInputs calldata publicInputs,
        bytes calldata proof
    ) external view returns (bool);
}
