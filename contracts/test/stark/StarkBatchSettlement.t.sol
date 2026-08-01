// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../src/stark/INativeStarkVerifier.sol";
import "../../src/stark/StarkBatchSettlement.sol";

contract TestNativeStarkVerifier is INativeStarkVerifier {
    bytes32 public immutable override verifierArtifactHash;
    bool public immutable override isLegacyProofWrapper;
    bool public accepted = true;

    constructor(bytes32 artifactHash, bool legacyProofWrapper) {
        verifierArtifactHash = artifactHash;
        isLegacyProofWrapper = legacyProofWrapper;
    }

    function setAccepted(bool value) external {
        accepted = value;
    }

    function verifyStark(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return accepted;
    }
}

    contract StarkBatchSettlementTest is Test {
        bytes32 internal constant ARTIFACT = keccak256("native-stark-artifact-v1");
        address internal constant SIGNER_ONE = address(0x1001);
        address internal constant SIGNER_TWO = address(0x1002);
        address internal constant SIGNER_THREE = address(0x1003);
        uint256 internal constant TIMELOCK = 259200;

        TestNativeStarkVerifier internal verifier;
        StarkBatchSettlement internal settlement;

        function setUp() public {
            verifier = new TestNativeStarkVerifier(ARTIFACT, false);
            settlement = new StarkBatchSettlement(verifier, ARTIFACT, _governedRoots(), _signers(), 2, TIMELOCK);
        }

        function _signers() internal pure returns (address[] memory signers) {
            signers = new address[](3);
            signers[0] = SIGNER_ONE;
            signers[1] = SIGNER_TWO;
            signers[2] = SIGNER_THREE;
        }

        function _governedRoots() internal pure returns (StarkBatchSettlement.GovernedRootConfig memory roots) {
            roots = StarkBatchSettlement.GovernedRootConfig({
                rulesetRoot: keccak256("ruleset-root"),
                policyRoot: keccak256("policy-root"),
                claimSourceRoot: keccak256("claim-source-root"),
                oracleFactsRoot: keccak256("oracle-facts-root")
            });
        }

        function _submission()
            internal
            view
            returns (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload, bytes32[] memory inputs)
        {
            payload = abi.encodePacked("encrypted-claim-payload");
            s = StarkBatchSettlement.StarkBatchSubmission({
                batchId: keccak256("batch-1"),
                nullifierRootBefore: settlement.liveNullifierRoot(),
                nullifierRootAfter: keccak256("root-after-1"),
                claimRoot: keccak256("claim-root"),
                resultRoot: keccak256("result-root"),
                paymentRoot: keccak256("payment-root"),
                batchNullifierCommitment: keccak256("batch-nullifier"),
                rulesetRoot: keccak256("ruleset-root"),
                claimSourceRoot: keccak256("claim-source-root"),
                oracleFactsRoot: keccak256("oracle-facts-root"),
                oracleSignerRoot: keccak256("oracle-signer-root"),
                policyRoot: keccak256("policy-root"),
                addressBookRoot: keccak256("address-book-root"),
                dataAvailabilityRoot: keccak256("da-root"),
                encryptedClaimDataRoot: sha256(payload),
                combinedBatchCommitment: keccak256("combined-batch"),
                accumulatorRootBefore: keccak256("accumulator-before"),
                accumulatorRootAfter: keccak256("accumulator-after"),
                valueConservationCommitment: keccak256("value-conservation"),
                approvedAmountCents: 12500,
                paymentAmountCents: 12500
            });
            inputs = new bytes32[](21);
            inputs[0] = s.batchId;
            inputs[1] = s.nullifierRootBefore;
            inputs[2] = s.nullifierRootAfter;
            inputs[3] = s.claimRoot;
            inputs[4] = s.resultRoot;
            inputs[5] = s.paymentRoot;
            inputs[6] = s.batchNullifierCommitment;
            inputs[7] = s.rulesetRoot;
            inputs[8] = s.claimSourceRoot;
            inputs[9] = s.oracleFactsRoot;
            inputs[10] = s.oracleSignerRoot;
            inputs[11] = s.policyRoot;
            inputs[12] = s.addressBookRoot;
            inputs[13] = s.dataAvailabilityRoot;
            inputs[14] = s.encryptedClaimDataRoot;
            inputs[15] = s.combinedBatchCommitment;
            inputs[16] = s.accumulatorRootBefore;
            inputs[17] = s.accumulatorRootAfter;
            inputs[18] = s.valueConservationCommitment;
            inputs[19] = bytes32(s.approvedAmountCents);
            inputs[20] = bytes32(s.paymentAmountCents);
        }

        function _syncInputs(StarkBatchSettlement.StarkBatchSubmission memory s)
            internal
            pure
            returns (bytes32[] memory inputs)
        {
            inputs = new bytes32[](21);
            inputs[0] = s.batchId;
            inputs[1] = s.nullifierRootBefore;
            inputs[2] = s.nullifierRootAfter;
            inputs[3] = s.claimRoot;
            inputs[4] = s.resultRoot;
            inputs[5] = s.paymentRoot;
            inputs[6] = s.batchNullifierCommitment;
            inputs[7] = s.rulesetRoot;
            inputs[8] = s.claimSourceRoot;
            inputs[9] = s.oracleFactsRoot;
            inputs[10] = s.oracleSignerRoot;
            inputs[11] = s.policyRoot;
            inputs[12] = s.addressBookRoot;
            inputs[13] = s.dataAvailabilityRoot;
            inputs[14] = s.encryptedClaimDataRoot;
            inputs[15] = s.combinedBatchCommitment;
            inputs[16] = s.accumulatorRootBefore;
            inputs[17] = s.accumulatorRootAfter;
            inputs[18] = s.valueConservationCommitment;
            inputs[19] = bytes32(s.approvedAmountCents);
            inputs[20] = bytes32(s.paymentAmountCents);
        }

        function _submitAsGovernedSigner(
            StarkBatchSettlement.StarkBatchSubmission memory s,
            bytes32[] memory inputs,
            bytes memory payload
        ) internal {
            vm.prank(SIGNER_ONE);
            settlement.submitBatch(s, "test-stark-proof", inputs, payload);
        }

        function _propose(bytes32 rootId, bytes32 newRoot) internal returns (bytes32 proposalId) {
            vm.prank(SIGNER_ONE);
            proposalId = settlement.proposeRootUpdate(rootId, newRoot, keccak256("reason"));
        }

        function _approveTwo(bytes32 proposalId) internal {
            vm.prank(SIGNER_ONE);
            settlement.approve(proposalId);
            vm.prank(SIGNER_TWO);
            settlement.approve(proposalId);
        }

        function _activate(bytes32 proposalId) internal {
            vm.warp(block.timestamp + TIMELOCK);
            settlement.activate(proposalId);
        }

        function testSubmitNativeStarkBatchAdvancesRootAndStoresEncryptedRoot() public {
            (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload, bytes32[] memory inputs) =
                _submission();

            _submitAsGovernedSigner(s, inputs, payload);

            assertEq(settlement.liveNullifierRoot(), s.nullifierRootAfter);
            assertEq(settlement.encryptedClaimDataHash(s.batchId), s.encryptedClaimDataRoot);
        }

        function testUnauthorizedSubmitterCannotAdvanceRootEvenWithValidProof() public {
            (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload, bytes32[] memory inputs) =
                _submission();
            bytes32 beforeRoot = settlement.liveNullifierRoot();

            vm.expectRevert("not governance signer");
            settlement.submitBatch(s, "test-stark-proof", inputs, payload);

            assertEq(settlement.liveNullifierRoot(), beforeRoot);

            _submitAsGovernedSigner(s, inputs, payload);

            assertEq(settlement.liveNullifierRoot(), s.nullifierRootAfter);
        }

        function testRejectsStaleNullifierRoot() public {
            (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload, bytes32[] memory inputs) =
                _submission();
            _submitAsGovernedSigner(s, inputs, payload);

            s.batchId = keccak256("batch-2");
            vm.expectRevert("stale nullifier root");
            _submitAsGovernedSigner(s, inputs, payload);
        }

        function testRejectsPaymentAboveApprovedAmount() public {
            (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload, bytes32[] memory inputs) =
                _submission();
            s.paymentAmountCents = 12501;
            inputs[20] = bytes32(s.paymentAmountCents);

            vm.expectRevert("value conservation");
            _submitAsGovernedSigner(s, inputs, payload);
        }

        function testRejectsVerifierArtifactMismatch() public {
            TestNativeStarkVerifier wrong = new TestNativeStarkVerifier(keccak256("wrong"), false);
            vm.expectRevert("artifact mismatch");
            new StarkBatchSettlement(wrong, ARTIFACT, _governedRoots(), _signers(), 2, TIMELOCK);
        }

        function testRejectsLegacyProofWrapperVerifier() public {
            TestNativeStarkVerifier wrapper = new TestNativeStarkVerifier(ARTIFACT, true);
            vm.expectRevert("legacy proof wrapper forbidden");
            new StarkBatchSettlement(wrapper, ARTIFACT, _governedRoots(), _signers(), 2, TIMELOCK);
        }

        function testRejectsNonGovernedRulesetRoot() public {
            (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload,) = _submission();
            s.rulesetRoot = keccak256("evil-ruleset-root");
            vm.expectRevert("ruleset root not governed");
            _submitAsGovernedSigner(s, _syncInputs(s), payload);
        }

        function testRejectsNonGovernedPolicyRoot() public {
            (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload,) = _submission();
            s.policyRoot = keccak256("evil-policy-root");
            vm.expectRevert("policy root not governed");
            _submitAsGovernedSigner(s, _syncInputs(s), payload);
        }

        function testRejectsNonGovernedClaimSourceRoot() public {
            (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload,) = _submission();
            s.claimSourceRoot = keccak256("evil-claim-source-root");
            vm.expectRevert("claim source root not governed");
            _submitAsGovernedSigner(s, _syncInputs(s), payload);
        }

        function testRejectsNonGovernedOracleFactsRoot() public {
            (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload,) = _submission();
            s.oracleFactsRoot = keccak256("evil-oracle-facts-root");
            vm.expectRevert("oracle facts root not governed");
            _submitAsGovernedSigner(s, _syncInputs(s), payload);
        }

        function testGovernedRootUpdateActivatesAfterThresholdAndTimelock() public {
            bytes32 newRoot = keccak256("ruleset-root-v2");
            bytes32 proposalId = _propose(settlement.RULESET_ROOT_ID(), newRoot);
            _approveTwo(proposalId);
            _activate(proposalId);
            assertEq(settlement.governedRulesetRoot(), newRoot);
        }

        function testNonSignerCannotProposeOrApprove() public {
            bytes32 rootId = settlement.RULESET_ROOT_ID();
            vm.expectRevert("not governance signer");
            settlement.proposeRootUpdate(rootId, keccak256("ruleset-root-v2"), keccak256("reason"));

            bytes32 proposalId = _propose(rootId, keccak256("ruleset-root-v2"));
            vm.expectRevert("not governance signer");
            settlement.approve(proposalId);
        }

        function testSignerCannotApproveTwice() public {
            bytes32 proposalId = _propose(settlement.RULESET_ROOT_ID(), keccak256("ruleset-root-v2"));
            vm.startPrank(SIGNER_ONE);
            settlement.approve(proposalId);
            vm.expectRevert("already approved");
            settlement.approve(proposalId);
            vm.stopPrank();
        }

        function testActivateBeforeTimelockReverts() public {
            bytes32 proposalId = _propose(settlement.RULESET_ROOT_ID(), keccak256("ruleset-root-v2"));
            _approveTwo(proposalId);
            vm.expectRevert("timelock not elapsed");
            settlement.activate(proposalId);
        }

        function testActivateBelowThresholdReverts() public {
            bytes32 proposalId = _propose(settlement.RULESET_ROOT_ID(), keccak256("ruleset-root-v2"));
            vm.prank(SIGNER_ONE);
            settlement.approve(proposalId);
            vm.warp(block.timestamp + TIMELOCK);
            vm.expectRevert("threshold not met");
            settlement.activate(proposalId);
        }

        function testZeroNewRootRejected() public {
            bytes32 rootId = settlement.RULESET_ROOT_ID();
            vm.prank(SIGNER_ONE);
            vm.expectRevert("new root zero");
            settlement.proposeRootUpdate(rootId, bytes32(0), keccak256("reason"));
        }

        function testInFlightBatchWithSupersededRootRejected() public {
            (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload, bytes32[] memory inputs) =
                _submission();
            bytes32 proposalId = _propose(settlement.RULESET_ROOT_ID(), keccak256("ruleset-root-v2"));
            _approveTwo(proposalId);
            _activate(proposalId);
            vm.expectRevert("ruleset root not governed");
            _submitAsGovernedSigner(s, inputs, payload);
        }
    }
