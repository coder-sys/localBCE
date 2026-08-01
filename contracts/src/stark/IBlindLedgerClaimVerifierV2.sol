// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBlindLedgerClaimVerifierV2 {
    function verifyClaimProof(bytes calldata proof, bytes32[12] calldata publicOutputs) external view returns (bool);
    function verifierArtifactHash() external view returns (bytes32);
    function statementSchemaHash() external view returns (bytes32);
    function isTestVerifier() external view returns (bool);
}
