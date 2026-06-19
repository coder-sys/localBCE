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

    TestNativeStarkVerifier internal verifier;
    StarkBatchSettlement internal settlement;

    function setUp() public {
        verifier = new TestNativeStarkVerifier(ARTIFACT, false);
        settlement = new StarkBatchSettlement(verifier, ARTIFACT);
    }

    function _submission() internal view returns (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload, bytes32[] memory inputs) {
        payload = abi.encodePacked("encrypted-claim-payload");
        s = StarkBatchSettlement.StarkBatchSubmission({
            batchId: keccak256("batch-1"),
            nullifierRootBefore: settlement.liveNullifierRoot(),
            nullifierRootAfter: keccak256("root-after-1"),
            claimRoot: keccak256("claim-root"),
            resultRoot: keccak256("result-root"),
            paymentRoot: keccak256("payment-root"),
            dataAvailabilityRoot: keccak256("da-root"),
            encryptedClaimDataRoot: sha256(payload),
            valueConservationCommitment: keccak256("value-conservation"),
            approvedAmountCents: 12500,
            paymentAmountCents: 12500
        });
        inputs = new bytes32[](9);
        inputs[0] = s.nullifierRootBefore;
        inputs[1] = s.nullifierRootAfter;
        inputs[2] = s.claimRoot;
        inputs[3] = s.resultRoot;
        inputs[4] = s.paymentRoot;
        inputs[5] = s.dataAvailabilityRoot;
        inputs[6] = s.encryptedClaimDataRoot;
        inputs[7] = s.valueConservationCommitment;
        inputs[8] = bytes32(s.paymentAmountCents);
    }

    function testSubmitNativeStarkBatchAdvancesRootAndStoresEncryptedRoot() public {
        (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload, bytes32[] memory inputs) = _submission();

        settlement.submitBatch(s, "test-stark-proof", inputs, payload);

        assertEq(settlement.liveNullifierRoot(), s.nullifierRootAfter);
        assertEq(settlement.encryptedClaimDataHash(s.batchId), s.encryptedClaimDataRoot);
    }

    function testRejectsStaleNullifierRoot() public {
        (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload, bytes32[] memory inputs) = _submission();
        settlement.submitBatch(s, "test-stark-proof", inputs, payload);

        s.batchId = keccak256("batch-2");
        vm.expectRevert("stale nullifier root");
        settlement.submitBatch(s, "test-stark-proof", inputs, payload);
    }

    function testRejectsPaymentAboveApprovedAmount() public {
        (StarkBatchSettlement.StarkBatchSubmission memory s, bytes memory payload, bytes32[] memory inputs) = _submission();
        s.paymentAmountCents = 12501;
        inputs[8] = bytes32(s.paymentAmountCents);

        vm.expectRevert("value conservation");
        settlement.submitBatch(s, "test-stark-proof", inputs, payload);
    }

    function testRejectsVerifierArtifactMismatch() public {
        TestNativeStarkVerifier wrong = new TestNativeStarkVerifier(keccak256("wrong"), false);
        vm.expectRevert("artifact mismatch");
        new StarkBatchSettlement(wrong, ARTIFACT);
    }

    function testRejectsLegacyProofWrapperVerifier() public {
        TestNativeStarkVerifier wrapper = new TestNativeStarkVerifier(ARTIFACT, true);
        vm.expectRevert("legacy proof wrapper forbidden");
        new StarkBatchSettlement(wrapper, ARTIFACT);
    }
}
