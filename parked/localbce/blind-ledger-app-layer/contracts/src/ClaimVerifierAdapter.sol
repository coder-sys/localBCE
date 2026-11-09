// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./GeneratedClaimVerifier.sol";
import "./IVerifier.sol";

contract ClaimVerifierAdapter is IVerifier {
    Groth16Verifier public immutable verifier;

    constructor(Groth16Verifier _verifier) {
        verifier = _verifier;
    }

    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        require(publicInputs.length == 4, "invalid public inputs");
        (uint[2] memory pA, uint[2][2] memory pB, uint[2] memory pC) =
            abi.decode(proof, (uint[2], uint[2][2], uint[2]));

        uint[4] memory inputs;
        for (uint256 i = 0; i < 4; i++) {
            inputs[i] = uint256(publicInputs[i]);
        }

        return verifier.verifyProof(pA, pB, pC, inputs);
    }
}
