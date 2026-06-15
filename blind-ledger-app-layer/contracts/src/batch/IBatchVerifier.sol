// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBatchVerifier {
    function verifyBatch(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
    function isBatchVerifier() external view returns (bool);
    function batchPublicInputLength() external view returns (uint256);
    function isTestVerifier() external view returns (bool);
}
