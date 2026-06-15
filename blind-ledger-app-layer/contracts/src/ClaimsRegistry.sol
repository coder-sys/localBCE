// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IVerifier.sol";

contract ClaimsRegistry {
    struct ClaimResult {
        bool exists;
        bool approved;
        string denialReason;
        bytes32 contextHash;
        address submitter;
        uint256 timestamp;
    }

    IVerifier public verifier;
    mapping(bytes32 => ClaimResult) public claims;

    event ClaimRecorded(bytes32 indexed claimId, bool approved, string denialReason, bytes32 contextHash, address indexed submitter);

    constructor(IVerifier _verifier) {
        verifier = _verifier;
    }

    function recordClaim(
        bytes32 claimId,
        bool approved,
        string calldata denialReason,
        bytes32 contextHash,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        require(!claims[claimId].exists, "claim exists");
        require(verifier.verify(proof, publicInputs), "invalid proof");
        claims[claimId] = ClaimResult(true, approved, denialReason, contextHash, msg.sender, block.timestamp);
        emit ClaimRecorded(claimId, approved, denialReason, contextHash, msg.sender);
    }
}

