// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IStarkClaimsVerifierV1Candidate} from "../src/IStarkClaimsVerifierV1Candidate.sol";

contract MockStarkClaimsVerifierV1Candidate is IStarkClaimsVerifierV1Candidate {
    PublicInputs private expectedInputs;
    bytes32 private expectedProofHash;
    bool public verifierEnabled = true;

    constructor(PublicInputs memory _expectedInputs, bytes memory expectedProof) {
        expectedInputs = _expectedInputs;
        expectedProofHash = keccak256(expectedProof);
    }

    function setVerifierEnabled(bool enabled) external {
        verifierEnabled = enabled;
    }

    function verifyStarkClaim(
        PublicInputs calldata publicInputs,
        bytes calldata proof
    ) external view returns (bool) {
        if (!verifierEnabled) {
            return false;
        }

        if (!_decisionAndFailureCodeAreConsistent(publicInputs.decision, publicInputs.failureCode)) {
            return false;
        }

        if (!_requiredRootsArePresent(publicInputs)) {
            return false;
        }

        return publicInputs.claimHash == expectedInputs.claimHash
            && publicInputs.decision == expectedInputs.decision
            && publicInputs.failureCode == expectedInputs.failureCode
            && publicInputs.publicInputRoot == expectedInputs.publicInputRoot
            && publicInputs.claimSourceRoot == expectedInputs.claimSourceRoot
            && publicInputs.oracleFactsRoot == expectedInputs.oracleFactsRoot
            && publicInputs.feeScheduleRoot == expectedInputs.feeScheduleRoot
            && publicInputs.nullifierRootBefore == expectedInputs.nullifierRootBefore
            && publicInputs.nullifierRootAfter == expectedInputs.nullifierRootAfter
            && publicInputs.batchRoot == expectedInputs.batchRoot
            && keccak256(proof) == expectedProofHash;
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

    function _requiredRootsArePresent(
        PublicInputs calldata publicInputs
    ) private pure returns (bool) {
        return publicInputs.publicInputRoot != bytes32(0)
            && publicInputs.claimSourceRoot != bytes32(0)
            && publicInputs.oracleFactsRoot != bytes32(0)
            && publicInputs.feeScheduleRoot != bytes32(0)
            && publicInputs.nullifierRootBefore != bytes32(0)
            && publicInputs.nullifierRootAfter != bytes32(0)
            && publicInputs.batchRoot != bytes32(0);
    }
}

contract StarkClaimsVerifierV1CandidateTest is Test {
    bytes32 private constant CLAIM_HASH =
        0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607;
    bytes32 private constant PUBLIC_INPUT_ROOT =
        0x822ed70b5249ff98a4bdd99c16ef5c6ba14c9aa568a8fa8ad0b8befec06c1be9;
    bytes32 private constant CLAIM_SOURCE_ROOT =
        0xe6218358708a664711e285e5262eff75f9a58f5d9a7c7480f1e339f4987b52a1;
    bytes32 private constant ORACLE_FACTS_ROOT =
        0x3b73e6f89123ebfef62f8d8922ccebbe1677e40d7442059de8f4f54f9d5f28c0;
    bytes32 private constant FEE_SCHEDULE_ROOT =
        0xbb39998f9fdb5cb88cbd9c77e660e6dc8e3480297ac930e9651ab8a31b6f2a56;
    bytes32 private constant NULLIFIER_ROOT_BEFORE =
        0x18e77544af57f8b9aaf943d9972f6d555eb9654cdb12ddacde4df5e8a433e000;
    bytes32 private constant NULLIFIER_ROOT_AFTER =
        0x8a67b4cb676636e4baad10b713a91dfd742fd38cf9f0e261c8ef9d3ef810d678;
    bytes32 private constant BATCH_ROOT =
        0x782e1b6f6609aa4e7c385c39e52736801fae471a4f671e92d706c0487beca6a4;

    bytes private proof = hex"535441524b5f50524f44554354494f4e5f4142495f5631";

    function test_CandidateAcceptsApprovedPublicInputs() public {
        IStarkClaimsVerifierV1Candidate verifier =
            new MockStarkClaimsVerifierV1Candidate(approvedInputs(), proof);

        assertTrue(verifier.verifyStarkClaim(approvedInputs(), proof));
    }

    function test_CandidateAcceptsDeniedPublicInputs() public {
        IStarkClaimsVerifierV1Candidate verifier =
            new MockStarkClaimsVerifierV1Candidate(deniedInputs(), proof);

        assertTrue(verifier.verifyStarkClaim(deniedInputs(), proof));
    }

    function test_CandidateRejectsApprovedClaimWithFailureCode() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = approvedInputs();
        inputs.failureCode = 7;
        IStarkClaimsVerifierV1Candidate verifier =
            new MockStarkClaimsVerifierV1Candidate(approvedInputs(), proof);

        assertFalse(verifier.verifyStarkClaim(inputs, proof));
    }

    function test_CandidateRejectsDeniedClaimWithoutFailureCode() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = deniedInputs();
        inputs.failureCode = 0;
        IStarkClaimsVerifierV1Candidate verifier =
            new MockStarkClaimsVerifierV1Candidate(deniedInputs(), proof);

        assertFalse(verifier.verifyStarkClaim(inputs, proof));
    }

    function test_CandidateRejectsInvalidDecision() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = approvedInputs();
        inputs.decision = 2;
        IStarkClaimsVerifierV1Candidate verifier =
            new MockStarkClaimsVerifierV1Candidate(approvedInputs(), proof);

        assertFalse(verifier.verifyStarkClaim(inputs, proof));
    }

    function test_CandidateRejectsMissingRequiredRoot() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = approvedInputs();
        inputs.oracleFactsRoot = bytes32(0);
        IStarkClaimsVerifierV1Candidate verifier =
            new MockStarkClaimsVerifierV1Candidate(approvedInputs(), proof);

        assertFalse(verifier.verifyStarkClaim(inputs, proof));
    }

    function test_CandidateRejectsMismatchedPublicInputRoot() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = approvedInputs();
        inputs.publicInputRoot = keccak256("wrong-public-input-root");
        IStarkClaimsVerifierV1Candidate verifier =
            new MockStarkClaimsVerifierV1Candidate(approvedInputs(), proof);

        assertFalse(verifier.verifyStarkClaim(inputs, proof));
    }

    function test_CandidateRejectsMismatchedProof() public {
        IStarkClaimsVerifierV1Candidate verifier =
            new MockStarkClaimsVerifierV1Candidate(approvedInputs(), proof);

        assertFalse(verifier.verifyStarkClaim(approvedInputs(), hex"00"));
    }

    function test_CandidateRejectsDisabledVerifier() public {
        MockStarkClaimsVerifierV1Candidate verifier =
            new MockStarkClaimsVerifierV1Candidate(approvedInputs(), proof);
        verifier.setVerifierEnabled(false);

        assertFalse(verifier.verifyStarkClaim(approvedInputs(), proof));
    }

    function approvedInputs()
        private
        pure
        returns (IStarkClaimsVerifierV1Candidate.PublicInputs memory)
    {
        return baseInputs(1, 0);
    }

    function deniedInputs()
        private
        pure
        returns (IStarkClaimsVerifierV1Candidate.PublicInputs memory)
    {
        return baseInputs(0, 7);
    }

    function baseInputs(
        uint8 decision,
        uint32 failureCode
    ) private pure returns (IStarkClaimsVerifierV1Candidate.PublicInputs memory) {
        return IStarkClaimsVerifierV1Candidate.PublicInputs({
            claimHash: CLAIM_HASH,
            decision: decision,
            failureCode: failureCode,
            publicInputRoot: PUBLIC_INPUT_ROOT,
            claimSourceRoot: CLAIM_SOURCE_ROOT,
            oracleFactsRoot: ORACLE_FACTS_ROOT,
            feeScheduleRoot: FEE_SCHEDULE_ROOT,
            nullifierRootBefore: NULLIFIER_ROOT_BEFORE,
            nullifierRootAfter: NULLIFIER_ROOT_AFTER,
            batchRoot: BATCH_ROOT
        });
    }
}
