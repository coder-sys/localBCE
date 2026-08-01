// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface INativeStarkVerifier {
    function verifyStark(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
    function verifierArtifactHash() external view returns (bytes32);
    function isLegacyProofWrapper() external view returns (bool);
}
