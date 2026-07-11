// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IStarkClaimsVerifierPreview} from "../src/IStarkClaimsVerifierPreview.sol";

contract StarkVerifierHarness is IStarkClaimsVerifierPreview {
    struct PublicInputs {
        bytes32 claimHash;
        uint8 decision;
        uint32 failureCode;
        bytes32 publicInputRoot;
    }

    PublicInputs public expectedInputs;
    bytes32 public expectedProofCommitmentHash;
    bool public verifierEnabled = true;

    constructor(PublicInputs memory _expectedInputs, bytes memory expectedProofCommitment) {
        expectedInputs = _expectedInputs;
        expectedProofCommitmentHash = keccak256(expectedProofCommitment);
    }

    function setVerifierEnabled(bool enabled) external {
        verifierEnabled = enabled;
    }

    function verifyClaim(
        bytes32 claimHash,
        uint8 decision,
        uint32 failureCode,
        bytes calldata proofCommitment
    ) external view returns (bool) {
        if (!verifierEnabled) {
            return false;
        }

        if (!_decisionAndFailureCodeAreConsistent(decision, failureCode)) {
            return false;
        }

        if (claimHash != expectedInputs.claimHash) {
            return false;
        }

        if (decision != expectedInputs.decision || failureCode != expectedInputs.failureCode) {
            return false;
        }

        return keccak256(proofCommitment) == expectedProofCommitmentHash;
    }

    function verifyClaimWithPublicInputRoot(
        bytes32 claimHash,
        uint8 decision,
        uint32 failureCode,
        bytes32 publicInputRoot,
        bytes calldata proofCommitment
    ) external view returns (bool) {
        if (publicInputRoot != expectedInputs.publicInputRoot) {
            return false;
        }

        return this.verifyClaim(claimHash, decision, failureCode, proofCommitment);
    }

    function _decisionAndFailureCodeAreConsistent(
        uint8 decision,
        uint32 failureCode
    ) private pure returns (bool) {
        if (decision > 1) {
            return false;
        }

        if (decision == 1) {
            return failureCode == 0;
        }

        return failureCode != 0;
    }
}

contract StarkVerifierHarnessTest is Test {
    bytes32 private constant CLAIM_HASH =
        0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607;
    bytes32 private constant PUBLIC_INPUT_ROOT =
        0x822ed70b5249ff98a4bdd99c16ef5c6ba14c9aa568a8fa8ad0b8befec06c1be9;

    bytes private proofCommitment = hex"535441524b5f50524f4f465f50524556494557";

    function test_HarnessAcceptsExpectedApprovedPublicInputs() public {
        StarkVerifierHarness verifier = approvedHarness();

        assertTrue(
            verifier.verifyClaimWithPublicInputRoot(
                CLAIM_HASH,
                1,
                0,
                PUBLIC_INPUT_ROOT,
                proofCommitment
            )
        );
    }

    function test_HarnessRejectsWrongPublicInputRoot() public {
        StarkVerifierHarness verifier = approvedHarness();

        assertFalse(
            verifier.verifyClaimWithPublicInputRoot(
                CLAIM_HASH,
                1,
                0,
                keccak256("wrong-root"),
                proofCommitment
            )
        );
    }

    function test_HarnessRejectsWrongProofCommitment() public {
        StarkVerifierHarness verifier = approvedHarness();

        assertFalse(
            verifier.verifyClaimWithPublicInputRoot(CLAIM_HASH, 1, 0, PUBLIC_INPUT_ROOT, hex"00")
        );
    }

    function test_HarnessRejectsDisabledVerifier() public {
        StarkVerifierHarness verifier = approvedHarness();
        verifier.setVerifierEnabled(false);

        assertFalse(
            verifier.verifyClaimWithPublicInputRoot(
                CLAIM_HASH,
                1,
                0,
                PUBLIC_INPUT_ROOT,
                proofCommitment
            )
        );
    }

    function test_HarnessRejectsInvalidDecision() public {
        StarkVerifierHarness verifier = approvedHarness();

        assertFalse(
            verifier.verifyClaimWithPublicInputRoot(
                CLAIM_HASH,
                2,
                0,
                PUBLIC_INPUT_ROOT,
                proofCommitment
            )
        );
    }

    function test_HarnessRejectsApprovedClaimWithFailureCode() public {
        StarkVerifierHarness verifier = approvedHarness();

        assertFalse(
            verifier.verifyClaimWithPublicInputRoot(
                CLAIM_HASH,
                1,
                7,
                PUBLIC_INPUT_ROOT,
                proofCommitment
            )
        );
    }

    function test_HarnessAcceptsExpectedDeniedPublicInputs() public {
        StarkVerifierHarness verifier = deniedHarness();

        assertTrue(
            verifier.verifyClaimWithPublicInputRoot(
                CLAIM_HASH,
                0,
                7,
                PUBLIC_INPUT_ROOT,
                proofCommitment
            )
        );
    }

    function test_HarnessRejectsDeniedClaimWithoutFailureCode() public {
        StarkVerifierHarness verifier = deniedHarness();

        assertFalse(
            verifier.verifyClaimWithPublicInputRoot(
                CLAIM_HASH,
                0,
                0,
                PUBLIC_INPUT_ROOT,
                proofCommitment
            )
        );
    }

    function approvedHarness() private returns (StarkVerifierHarness) {
        return new StarkVerifierHarness(
            StarkVerifierHarness.PublicInputs({
                claimHash: CLAIM_HASH,
                decision: 1,
                failureCode: 0,
                publicInputRoot: PUBLIC_INPUT_ROOT
            }),
            proofCommitment
        );
    }

    function deniedHarness() private returns (StarkVerifierHarness) {
        return new StarkVerifierHarness(
            StarkVerifierHarness.PublicInputs({
                claimHash: CLAIM_HASH,
                decision: 0,
                failureCode: 7,
                publicInputRoot: PUBLIC_INPUT_ROOT
            }),
            proofCommitment
        );
    }
}
