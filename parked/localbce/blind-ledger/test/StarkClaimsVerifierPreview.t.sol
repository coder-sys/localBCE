// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IStarkClaimsVerifierPreview} from "../src/IStarkClaimsVerifierPreview.sol";

contract MockStarkClaimsVerifierPreview is IStarkClaimsVerifierPreview {
    bytes32 public expectedClaimHash;
    uint8 public expectedDecision;
    uint32 public expectedFailureCode;
    bytes32 public expectedProofCommitmentHash;

    constructor(
        bytes32 _expectedClaimHash,
        uint8 _expectedDecision,
        uint32 _expectedFailureCode,
        bytes memory _expectedProofCommitment
    ) {
        expectedClaimHash = _expectedClaimHash;
        expectedDecision = _expectedDecision;
        expectedFailureCode = _expectedFailureCode;
        expectedProofCommitmentHash = keccak256(_expectedProofCommitment);
    }

    function verifyClaim(
        bytes32 claimHash,
        uint8 decision,
        uint32 failureCode,
        bytes calldata proofCommitment
    ) external view returns (bool) {
        if (decision > 1) {
            return false;
        }

        if (decision == 1 && failureCode != 0) {
            return false;
        }

        if (decision == 0 && failureCode == 0) {
            return false;
        }

        return claimHash == expectedClaimHash
            && decision == expectedDecision
            && failureCode == expectedFailureCode
            && keccak256(proofCommitment) == expectedProofCommitmentHash;
    }
}

contract StarkClaimsVerifierPreviewTest is Test {
    bytes32 private constant CLAIM_HASH =
        0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607;

    bytes private proofCommitment = hex"535441524b5f50524f4f465f50524556494557";

    function test_InterfacePreviewAcceptsExpectedApprovedInputs() public {
        IStarkClaimsVerifierPreview verifier =
            new MockStarkClaimsVerifierPreview(CLAIM_HASH, 1, 0, proofCommitment);

        assertTrue(verifier.verifyClaim(CLAIM_HASH, 1, 0, proofCommitment));
    }

    function test_InterfacePreviewRejectsMismatchedClaimHash() public {
        IStarkClaimsVerifierPreview verifier =
            new MockStarkClaimsVerifierPreview(CLAIM_HASH, 1, 0, proofCommitment);

        assertFalse(verifier.verifyClaim(keccak256("wrong-claim"), 1, 0, proofCommitment));
    }

    function test_InterfacePreviewRejectsInvalidDecision() public {
        IStarkClaimsVerifierPreview verifier =
            new MockStarkClaimsVerifierPreview(CLAIM_HASH, 1, 0, proofCommitment);

        assertFalse(verifier.verifyClaim(CLAIM_HASH, 2, 0, proofCommitment));
    }

    function test_InterfacePreviewRejectsApprovedClaimWithFailureCode() public {
        IStarkClaimsVerifierPreview verifier =
            new MockStarkClaimsVerifierPreview(CLAIM_HASH, 1, 0, proofCommitment);

        assertFalse(verifier.verifyClaim(CLAIM_HASH, 1, 7, proofCommitment));
    }

    function test_InterfacePreviewAcceptsExpectedDeniedInputs() public {
        IStarkClaimsVerifierPreview verifier =
            new MockStarkClaimsVerifierPreview(CLAIM_HASH, 0, 7, proofCommitment);

        assertTrue(verifier.verifyClaim(CLAIM_HASH, 0, 7, proofCommitment));
    }

    function test_InterfacePreviewRejectsDeniedClaimWithoutFailureCode() public {
        IStarkClaimsVerifierPreview verifier =
            new MockStarkClaimsVerifierPreview(CLAIM_HASH, 0, 7, proofCommitment);

        assertFalse(verifier.verifyClaim(CLAIM_HASH, 0, 0, proofCommitment));
    }

    function test_InterfacePreviewRejectsMismatchedProofCommitment() public {
        IStarkClaimsVerifierPreview verifier =
            new MockStarkClaimsVerifierPreview(CLAIM_HASH, 1, 0, proofCommitment);

        assertFalse(verifier.verifyClaim(CLAIM_HASH, 1, 0, hex"00"));
    }
}
