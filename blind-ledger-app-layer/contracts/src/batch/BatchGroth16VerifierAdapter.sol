// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../ClaimVerifierAdapter.sol";
import "../GeneratedClaimVerifier.sol";
import "./IBatchVerifier.sol";

contract BatchGroth16VerifierAdapter is IBatchVerifier {
    string public constant STATUS = "REAL SINGLE-CLAIM GROTH16 ADAPTER; BATCH STATEMENT FAILS CLOSED";

    ClaimVerifierAdapter public immutable claimAdapter;

    constructor(Groth16Verifier verifier) {
        claimAdapter = new ClaimVerifierAdapter(verifier);
    }

    function verifyBatch(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        if (publicInputs.length != 4) {
            return false;
        }
        try claimAdapter.verify(proof, publicInputs) returns (bool accepted) {
            return accepted;
        } catch {
            return false;
        }
    }

    function isBatchVerifier() external pure returns (bool) {
        return false;
    }

    function batchPublicInputLength() external pure returns (uint256) {
        return 4;
    }

    function isTestVerifier() external pure returns (bool) {
        return false;
    }
}
