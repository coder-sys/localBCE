// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IBatchVerifier.sol";

contract BatchStubVerifier is IBatchVerifier {
    string public constant STATUS = "FAIL-CLOSED STUB / PENDING REAL PROOF + CRYPTO AUDIT";

    function verifyBatch(bytes calldata proof, bytes32[] calldata publicInputs) external pure returns (bool) {
        proof;
        publicInputs;
        return false;
    }

    function isBatchVerifier() external pure returns (bool) {
        return true;
    }

    function batchPublicInputLength() external pure returns (uint256) {
        return 11;
    }

    function isTestVerifier() external pure returns (bool) {
        return true;
    }
}
