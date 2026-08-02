// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IStarkClaimsVerifierV1Candidate} from "../src/IStarkClaimsVerifierV1Candidate.sol";
import {StarkAttestationVerifier} from "../src/StarkAttestationVerifier.sol";
import {StarkClaimsRegistry} from "../src/StarkClaimsRegistry.sol";

contract StarkAttestationSettlementTest is Test {
    uint256 private constant ATTESTOR_KEY = 0xA11CE;
    uint256 private constant WRONG_KEY = 0xBAD;
    address private constant TREASURY = address(0xBEEF);
    address private constant SUBMITTER = address(0xCAFE);

    bytes32 private constant CLAIM_HASH = 0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607;
    bytes32 private constant PUBLIC_INPUT_ROOT = keccak256("public-input-root");
    bytes32 private constant CLAIM_SOURCE_ROOT = keccak256("claim-source-root");
    bytes32 private constant ORACLE_FACTS_ROOT = keccak256("oracle-facts-root");
    bytes32 private constant FEE_SCHEDULE_ROOT = keccak256("fee-schedule-root");
    bytes32 private constant NULLIFIER_ROOT_BEFORE = keccak256("nullifier-root-before");
    bytes32 private constant NULLIFIER_ROOT_AFTER = keccak256("nullifier-root-after");
    bytes32 private constant BATCH_ROOT = keccak256("batch-root");

    StarkAttestationVerifier private verifier;
    StarkClaimsRegistry private registry;

    function setUp() public {
        verifier = new StarkAttestationVerifier(address(this), vm.addr(ATTESTOR_KEY));
        registry = new StarkClaimsRegistry(TREASURY, address(verifier), NULLIFIER_ROOT_BEFORE);
        verifier.setRegistry(address(registry));
        vm.deal(SUBMITTER, 10 ether);
    }

    function test_ApprovedAttestationSettlesAndAdvancesNullifierRoot() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = approvedInputs();
        bytes memory envelope = signedEnvelope(inputs, 50_000, ATTESTOR_KEY);

        vm.prank(SUBMITTER);
        registry.submitStarkClaim{value: 0.01 ether}(inputs, envelope, 50_000);

        assertEq(registry.approvedClaims(), 1);
        assertEq(registry.rejectedProofs(), 0);
        assertEq(registry.currentNullifierRoot(), NULLIFIER_ROOT_AFTER);
        assertTrue(registry.consumedBatchRoots(BATCH_ROOT));
        assertEq(registry.baseFeesCollected(), 0.01 ether);
        (
            bool recorded,
            bool approved,
            uint256 claimAmount,
            uint256 baseFeePaid,
            uint256 denialFeeAccrued,
            uint32 failureCode,
            bytes32 publicInputRoot,
            bytes32 batchRoot,
            bytes32 proofEnvelopeHash
        ) = registry.claims(CLAIM_HASH);
        assertTrue(recorded);
        assertTrue(approved);
        assertEq(claimAmount, 50_000);
        assertEq(baseFeePaid, 0.01 ether);
        assertEq(denialFeeAccrued, 0);
        assertEq(failureCode, 0);
        assertEq(publicInputRoot, PUBLIC_INPUT_ROOT);
        assertEq(batchRoot, BATCH_ROOT);
        assertEq(proofEnvelopeHash, keccak256(envelope));
    }

    function test_DeniedAttestationRecordsNoOpNullifierTransitionWithoutFee() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = deniedInputs();
        bytes memory envelope = signedEnvelope(inputs, 10_000, ATTESTOR_KEY);

        registry.submitStarkClaim(inputs, envelope, 10_000);

        assertEq(registry.deniedClaims(), 1);
        assertEq(registry.denialFeesAccrued(), 2_000);
        assertEq(registry.currentNullifierRoot(), NULLIFIER_ROOT_BEFORE);
        (bool recorded, bool approved,,, uint256 denialFee, uint32 failureCode,,,) = registry.claims(CLAIM_HASH);
        assertTrue(recorded);
        assertFalse(approved);
        assertEq(denialFee, 2_000);
        assertEq(failureCode, 7);
    }

    function test_InvalidSignatureIsRejectedWithoutRecordingOrAdvancingState() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = approvedInputs();
        bytes memory envelope = signedEnvelope(inputs, 50_000, WRONG_KEY);

        registry.submitStarkClaim(inputs, envelope, 50_000);

        assertEq(registry.rejectedProofs(), 1);
        assertEq(registry.currentNullifierRoot(), NULLIFIER_ROOT_BEFORE);
        (bool recorded,,,,,,,,) = registry.claims(CLAIM_HASH);
        assertFalse(recorded);
    }

    function test_TamperedPublicInputIsRejectedByAttestation() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory signedInputs = approvedInputs();
        bytes memory envelope = signedEnvelope(signedInputs, 50_000, ATTESTOR_KEY);
        signedInputs.claimSourceRoot = keccak256("tampered");

        vm.prank(address(registry));
        assertFalse(verifier.verifyStarkClaim(signedInputs, envelope));
    }

    function test_BatchReplayAndStaleNullifierRootAreRejected() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory first = approvedInputs();
        bytes memory firstEnvelope = signedEnvelope(first, 100, ATTESTOR_KEY);
        vm.prank(SUBMITTER);
        registry.submitStarkClaim{value: 1}(first, firstEnvelope, 100);

        IStarkClaimsVerifierV1Candidate.PublicInputs memory replay = approvedInputs();
        replay.claimHash = keccak256("second-claim");
        replay.nullifierRootBefore = NULLIFIER_ROOT_AFTER;
        replay.nullifierRootAfter = keccak256("third-root");
        bytes memory replayEnvelope = signedEnvelope(replay, 100, ATTESTOR_KEY);
        vm.prank(SUBMITTER);
        registry.submitStarkClaim{value: 1}(replay, replayEnvelope, 100);

        assertEq(registry.approvedClaims(), 1);
        assertEq(registry.rejectedProofs(), 1);
        (bool recorded,,,,,,,,) = registry.claims(replay.claimHash);
        assertFalse(recorded);
    }

    function test_DuplicateRecordedClaimIsRejected() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = deniedInputs();
        bytes memory envelope = signedEnvelope(inputs, 100, ATTESTOR_KEY);
        registry.submitStarkClaim(inputs, envelope, 100);

        vm.expectRevert("STARK claim already recorded");
        registry.submitStarkClaim(inputs, envelope, 100);
    }

    function test_ApprovedClaimRequiresFee() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = approvedInputs();
        bytes memory envelope = signedEnvelope(inputs, 100, ATTESTOR_KEY);
        vm.expectRevert("Fee required");
        registry.submitStarkClaim(inputs, envelope, 100);
    }

    function test_OnlyGovernanceCanRotateAttestorAndVerifier() public {
        vm.prank(address(0x1234));
        vm.expectRevert("Not owner");
        verifier.setAttestor(address(0x9999));

        vm.prank(address(0x1234));
        vm.expectRevert("Not authorized");
        registry.setVerifier(address(0x9999));

        vm.prank(address(0x1234));
        vm.expectRevert("Not owner");
        verifier.setRegistry(address(0x9999));

        vm.prank(TREASURY);
        registry.setVerifier(address(0x9999));
        assertEq(address(registry.verifier()), address(0x9999));
    }

    function test_ClaimAmountMustMatchSignedEnvelope() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = approvedInputs();
        bytes memory envelope = signedEnvelope(inputs, 50_000, ATTESTOR_KEY);
        uint256 balanceBefore = SUBMITTER.balance;

        vm.prank(SUBMITTER);
        registry.submitStarkClaim{value: 0.01 ether}(inputs, envelope, 50_001);

        assertEq(registry.rejectedProofs(), 1);
        assertEq(SUBMITTER.balance, balanceBefore);
        assertEq(address(registry).balance, 0);
        (bool recorded,,,,,,,,) = registry.claims(CLAIM_HASH);
        assertFalse(recorded);
    }

    function test_RejectedProofRefundsAttachedValue() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = approvedInputs();
        bytes memory envelope = signedEnvelope(inputs, 50_000, WRONG_KEY);
        uint256 balanceBefore = SUBMITTER.balance;

        vm.prank(SUBMITTER);
        registry.submitStarkClaim{value: 1 ether}(inputs, envelope, 50_000);

        assertEq(registry.rejectedProofs(), 1);
        assertEq(SUBMITTER.balance, balanceBefore);
        assertEq(address(registry).balance, 0);
    }

    function test_DeniedClaimRejectsAttachedValue() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = deniedInputs();
        bytes memory envelope = signedEnvelope(inputs, 10_000, ATTESTOR_KEY);

        vm.expectRevert("Denied claim cannot carry value");
        registry.submitStarkClaim{value: 1}(inputs, envelope, 10_000);
    }

    function test_AttestationCannotReplayThroughAnotherRegistry() public {
        StarkClaimsRegistry otherRegistry = new StarkClaimsRegistry(TREASURY, address(verifier), NULLIFIER_ROOT_BEFORE);
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = approvedInputs();
        bytes memory envelope = signedEnvelope(inputs, 100, ATTESTOR_KEY);

        vm.prank(SUBMITTER);
        otherRegistry.submitStarkClaim{value: 1}(inputs, envelope, 100);

        assertEq(otherRegistry.rejectedProofs(), 1);
        (bool recorded,,,,,,,,) = otherRegistry.claims(CLAIM_HASH);
        assertFalse(recorded);
    }

    function approvedInputs() private pure returns (IStarkClaimsVerifierV1Candidate.PublicInputs memory) {
        return IStarkClaimsVerifierV1Candidate.PublicInputs({
            claimHash: CLAIM_HASH,
            decision: 1,
            failureCode: 0,
            publicInputRoot: PUBLIC_INPUT_ROOT,
            claimSourceRoot: CLAIM_SOURCE_ROOT,
            oracleFactsRoot: ORACLE_FACTS_ROOT,
            feeScheduleRoot: FEE_SCHEDULE_ROOT,
            nullifierRootBefore: NULLIFIER_ROOT_BEFORE,
            nullifierRootAfter: NULLIFIER_ROOT_AFTER,
            batchRoot: BATCH_ROOT
        });
    }

    function deniedInputs() private pure returns (IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs) {
        inputs = approvedInputs();
        inputs.decision = 0;
        inputs.failureCode = 7;
        inputs.nullifierRootAfter = inputs.nullifierRootBefore;
    }

    function signedEnvelope(
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs,
        uint256 claimAmount,
        uint256 privateKey
    ) private view returns (bytes memory) {
        bytes32 winterfellProofCommitment = keccak256("winterfell-proof-fixture-v1");
        bytes32 digest = verifier.attestationDigest(inputs, winterfellProofCommitment, claimAmount);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v, winterfellProofCommitment, claimAmount);
    }
}
