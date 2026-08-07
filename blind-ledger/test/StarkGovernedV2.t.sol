// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "openzeppelin-contracts/contracts/governance/TimelockController.sol";

import {IStarkClaimsVerifierV1Candidate} from "../src/IStarkClaimsVerifierV1Candidate.sol";
import {StarkAttestationVerifierV2} from "../src/StarkAttestationVerifierV2.sol";
import {StarkClaimsRegistryV2} from "../src/StarkClaimsRegistryV2.sol";

contract StarkGovernedV2Test is Test {
    uint256 private constant TIMELOCK_DELAY = 3 days;
    uint256 private constant ATTESTOR_KEY = 0xA11CE;
    uint256 private constant WRONG_KEY = 0xBAD;
    address private constant GOVERNANCE_SAFE = address(0x7001);
    address private constant EMERGENCY_SAFE = address(0x7002);
    address private constant TREASURY = address(0x7003);
    address private constant SUBMITTER = address(0x7004);

    bytes32 private constant POLICY_HASH = keccak256("policy-manifest-v1");
    bytes32 private constant CLAIM_HASH = keccak256("v2-claim");
    bytes32 private constant PUBLIC_INPUT_ROOT = keccak256("public-input-root");
    bytes32 private constant CLAIM_SOURCE_ROOT = keccak256("claim-source-root");
    bytes32 private constant ORACLE_FACTS_ROOT = keccak256("oracle-facts-root");
    bytes32 private constant FEE_SCHEDULE_ROOT = keccak256("fee-schedule-root");
    bytes32 private constant NULLIFIER_ROOT_BEFORE = keccak256("nullifier-root-before");
    bytes32 private constant NULLIFIER_ROOT_AFTER = keccak256("nullifier-root-after");
    bytes32 private constant BATCH_ROOT = keccak256("batch-root");

    TimelockController private timelock;
    StarkAttestationVerifierV2 private verifier;
    StarkClaimsRegistryV2 private registry;
    uint256 private operationNonce;

    function setUp() public {
        address[] memory proposers = new address[](1);
        proposers[0] = GOVERNANCE_SAFE;
        address[] memory executors = new address[](1);
        executors[0] = GOVERNANCE_SAFE;
        timelock = new TimelockController(TIMELOCK_DELAY, proposers, executors, address(0));

        verifier = new StarkAttestationVerifierV2(address(timelock), EMERGENCY_SAFE, vm.addr(ATTESTOR_KEY), POLICY_HASH);
        registry = new StarkClaimsRegistryV2(
            address(timelock), EMERGENCY_SAFE, TREASURY, address(verifier), NULLIFIER_ROOT_BEFORE
        );
        _timelockedCall(
            address(verifier),
            abi.encodeCall(StarkAttestationVerifierV2.setRegistryAuthorization, (address(registry), true))
        );
        vm.deal(SUBMITTER, 10 ether);
    }

    function test_ApprovedAndDeniedClaimsPreserveV1SettlementSemantics() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory approved = _approvedInputs();
        bytes memory approvedEnvelope = _signedEnvelope(approved, 50_000, ATTESTOR_KEY);
        vm.prank(SUBMITTER);
        registry.submitStarkClaim{value: 0.01 ether}(approved, approvedEnvelope, 50_000);

        assertEq(registry.approvedClaims(), 1);
        assertEq(registry.currentNullifierRoot(), NULLIFIER_ROOT_AFTER);
        assertTrue(registry.consumedBatchRoots(BATCH_ROOT));
        assertEq(registry.baseFeesCollected(), 0.01 ether);

        IStarkClaimsVerifierV1Candidate.PublicInputs memory denied = _deniedInputs();
        denied.claimHash = keccak256("denied-v2-claim");
        denied.batchRoot = keccak256("denied-v2-batch");
        denied.nullifierRootBefore = NULLIFIER_ROOT_AFTER;
        denied.nullifierRootAfter = NULLIFIER_ROOT_AFTER;
        bytes memory deniedEnvelope = _signedEnvelope(denied, 10_000, ATTESTOR_KEY);
        registry.submitStarkClaim(denied, deniedEnvelope, 10_000);

        assertEq(registry.deniedClaims(), 1);
        assertEq(registry.denialFeesAccrued(), 2_000);
        assertEq(registry.currentNullifierRoot(), NULLIFIER_ROOT_AFTER);
    }

    function test_RejectedProofRecordsMetricAndRefundsValue() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = _approvedInputs();
        bytes memory envelope = _signedEnvelope(inputs, 50_000, WRONG_KEY);
        uint256 beforeBalance = SUBMITTER.balance;

        vm.prank(SUBMITTER);
        registry.submitStarkClaim{value: 1 ether}(inputs, envelope, 50_000);

        assertEq(registry.rejectedProofs(), 1);
        assertEq(SUBMITTER.balance, beforeBalance);
        (bool recorded,,,,,,,,) = registry.claims(CLAIM_HASH);
        assertFalse(recorded);
    }

    function test_DuplicateBatchAndClaimProtectionsRemainActive() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory first = _deniedInputs();
        bytes memory firstEnvelope = _signedEnvelope(first, 100, ATTESTOR_KEY);
        registry.submitStarkClaim(first, firstEnvelope, 100);

        vm.expectRevert("STARK claim already recorded");
        registry.submitStarkClaim(first, firstEnvelope, 100);

        IStarkClaimsVerifierV1Candidate.PublicInputs memory replay = _deniedInputs();
        replay.claimHash = keccak256("other-claim");
        bytes memory replayEnvelope = _signedEnvelope(replay, 100, ATTESTOR_KEY);
        registry.submitStarkClaim(replay, replayEnvelope, 100);
        assertEq(registry.rejectedProofs(), 1);
    }

    function test_EmergencyPauseIsImmediateButUnpauseIsTimelocked() public {
        vm.prank(EMERGENCY_SAFE);
        verifier.pause();
        vm.prank(EMERGENCY_SAFE);
        registry.pause();
        assertTrue(verifier.paused());
        assertTrue(registry.paused());

        vm.prank(EMERGENCY_SAFE);
        vm.expectRevert();
        registry.unpause();

        _timelockedCall(address(verifier), abi.encodeCall(StarkAttestationVerifierV2.unpause, ()));
        _timelockedCall(address(registry), abi.encodeCall(StarkClaimsRegistryV2.unpause, ()));
        assertFalse(verifier.paused());
        assertFalse(registry.paused());
    }

    function test_AttestorPolicyVerifierAndAllowlistChangesAreTimelocked() public {
        address newAttestor = vm.addr(0xB0B);
        bytes32 newPolicyHash = keccak256("policy-manifest-v2");

        vm.expectRevert();
        verifier.setAttestor(newAttestor);
        vm.expectRevert();
        verifier.setPolicyManifestHash(newPolicyHash);
        vm.expectRevert();
        registry.setVerifier(address(0x9999));

        _timelockedCall(address(verifier), abi.encodeCall(StarkAttestationVerifierV2.setAttestor, (newAttestor)));
        _timelockedCall(
            address(verifier), abi.encodeCall(StarkAttestationVerifierV2.setPolicyManifestHash, (newPolicyHash))
        );
        _timelockedCall(
            address(verifier),
            abi.encodeCall(StarkAttestationVerifierV2.setRegistryAuthorization, (address(registry), false))
        );
        _timelockedCall(address(registry), abi.encodeCall(StarkClaimsRegistryV2.setVerifier, (address(verifier))));

        assertEq(verifier.attestor(), newAttestor);
        assertEq(verifier.policyManifestHash(), newPolicyHash);
        assertFalse(verifier.authorizedRegistries(address(registry)));
    }

    function test_TreasuryTransferIsTimelockedAndTwoStep() public {
        address newTreasury = address(0x7010);
        vm.expectRevert();
        registry.proposeTreasury(newTreasury);

        _timelockedCall(address(registry), abi.encodeCall(StarkClaimsRegistryV2.proposeTreasury, (newTreasury)));
        assertEq(registry.pendingTreasury(), newTreasury);

        vm.prank(address(0xDEAD));
        vm.expectRevert("Not pending treasury");
        registry.acceptTreasury();
        vm.prank(newTreasury);
        registry.acceptTreasury();

        assertEq(registry.treasury(), newTreasury);
        assertTrue(registry.hasRole(registry.TREASURY_ROLE(), newTreasury));
        assertFalse(registry.hasRole(registry.TREASURY_ROLE(), TREASURY));
    }

    function test_PolicyHashAndRegistryAddressAreBoundIntoDigest() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = _approvedInputs();
        bytes32 commitment = keccak256("winterfell-proof-fixture-v2");
        bytes32 digest = verifier.attestationDigest(address(registry), inputs, commitment, 1);

        _timelockedCall(
            address(verifier),
            abi.encodeCall(StarkAttestationVerifierV2.setPolicyManifestHash, (keccak256("different-policy")))
        );
        bytes32 changed = verifier.attestationDigest(address(registry), inputs, commitment, 1);
        assertNotEq(digest, changed);
    }

    function test_EnvelopeClaimAmountMismatchFailsClosedWithoutConsumingState() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = _approvedInputs();
        bytes memory envelope = _signedEnvelope(inputs, 50_000, ATTESTOR_KEY);
        uint256 beforeBalance = SUBMITTER.balance;

        vm.prank(SUBMITTER);
        registry.submitStarkClaim{value: 1 ether}(inputs, envelope, 50_001);

        assertEq(registry.rejectedProofs(), 1);
        assertEq(SUBMITTER.balance, beforeBalance);
        assertEq(registry.currentNullifierRoot(), NULLIFIER_ROOT_BEFORE);
        assertFalse(registry.consumedBatchRoots(BATCH_ROOT));
        (bool recorded,,,,,,,,) = registry.claims(CLAIM_HASH);
        assertFalse(recorded);
    }

    function test_PausedVerifierFailsClosedWithoutRecordingClaim() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = _approvedInputs();
        bytes memory envelope = _signedEnvelope(inputs, 50_000, ATTESTOR_KEY);
        vm.prank(EMERGENCY_SAFE);
        verifier.pause();

        vm.prank(SUBMITTER);
        registry.submitStarkClaim{value: 1 ether}(inputs, envelope, 50_000);

        assertEq(registry.rejectedProofs(), 1);
        assertFalse(registry.consumedBatchRoots(BATCH_ROOT));
        (bool recorded,,,,,,,,) = registry.claims(CLAIM_HASH);
        assertFalse(recorded);
    }

    function test_UnauthorizedRegistryAndDeniedValueFailClosed() public {
        IStarkClaimsVerifierV1Candidate.PublicInputs memory approved = _approvedInputs();
        bytes memory approvedEnvelope = _signedEnvelope(approved, 50_000, ATTESTOR_KEY);
        assertFalse(verifier.verifyStarkClaim(approved, approvedEnvelope));

        IStarkClaimsVerifierV1Candidate.PublicInputs memory denied = _deniedInputs();
        bytes memory deniedEnvelope = _signedEnvelope(denied, 10_000, ATTESTOR_KEY);
        vm.prank(SUBMITTER);
        vm.expectRevert("Denied claim cannot carry value");
        registry.submitStarkClaim{value: 1}(denied, deniedEnvelope, 10_000);
    }

    function testFuzz_AttestationDigestBindsClaimAmount(uint96 firstAmount, uint96 secondAmount) public view {
        if (firstAmount == secondAmount) secondAmount = firstAmount == type(uint96).max ? 0 : firstAmount + 1;
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = _approvedInputs();
        bytes32 commitment = keccak256("winterfell-proof-fixture-v2");

        bytes32 first = verifier.attestationDigest(address(registry), inputs, commitment, firstAmount);
        bytes32 second = verifier.attestationDigest(address(registry), inputs, commitment, secondAmount);

        assertNotEq(first, second);
    }

    function _timelockedCall(address target, bytes memory data) private {
        bytes32 salt = bytes32(++operationNonce);
        vm.prank(GOVERNANCE_SAFE);
        timelock.schedule(target, 0, data, bytes32(0), salt, TIMELOCK_DELAY);
        vm.warp(block.timestamp + TIMELOCK_DELAY);
        vm.prank(GOVERNANCE_SAFE);
        timelock.execute(target, 0, data, bytes32(0), salt);
    }

    function _approvedInputs() private pure returns (IStarkClaimsVerifierV1Candidate.PublicInputs memory) {
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

    function _deniedInputs() private pure returns (IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs) {
        inputs = _approvedInputs();
        inputs.decision = 0;
        inputs.failureCode = 7;
        inputs.nullifierRootAfter = inputs.nullifierRootBefore;
    }

    function _signedEnvelope(
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs,
        uint256 claimAmount,
        uint256 privateKey
    ) private view returns (bytes memory) {
        bytes32 commitment = keccak256("winterfell-proof-fixture-v2");
        bytes32 digest = verifier.attestationDigest(address(registry), inputs, commitment, claimAmount);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v, commitment, claimAmount);
    }
}
