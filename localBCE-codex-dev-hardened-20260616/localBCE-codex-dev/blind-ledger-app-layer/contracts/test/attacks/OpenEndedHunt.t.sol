// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../src/batch/BatchClaimsRegistry.sol";
import "../../src/batch/BatchPaymentTrigger.sol";
import "../../src/batch/IBatchVerifier.sol";

contract OpenEndedAcceptingVerifier is IBatchVerifier {
    function verifyBatch(bytes calldata proof, bytes32[] calldata publicInputs) external pure returns (bool) {
        return proof.length > 0 && publicInputs.length == 20;
    }

    function isBatchVerifier() external pure returns (bool) {
        return true;
    }

    function batchPublicInputLength() external pure returns (uint256) {
        return 20;
    }
}

contract OpenEndedSettlementBridge is ISettlementBridge {
    event ProviderPaymentPrepared(bytes32 indexed batchId, address indexed recipient, bytes32 indexed paymentRecord, bytes32 settlementRef);

    function submitProviderPayment(
        bytes32 batchId,
        address recipient,
        bytes32 paymentRecord
    ) external returns (bytes32 settlementRef) {
        settlementRef = keccak256(abi.encodePacked("TEST_SETTLEMENT_BRIDGE", batchId, recipient, paymentRecord));
        emit ProviderPaymentPrepared(batchId, recipient, paymentRecord, settlementRef);
    }
}

contract OpenEndedHuntTest {
    bytes32 internal constant CHECKER_ID = keccak256("NATIVE_STARK_SETTLEMENT_V1");
    bytes32 internal constant GENESIS = 0x111df93687d686f128495834e87222c67d3ec42ae5d128db3ad65e8123b11f2c;

    function _id(string memory value) internal pure returns (bytes32) {
        return keccak256(bytes(value));
    }

    function _pair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(left, right));
    }

    function _zeroAt(uint256 level) internal pure returns (bytes32 zero) {
        zero = bytes32(0);
        for (uint256 i = 0; i < level; i++) {
            zero = _pair(zero, zero);
        }
    }

    function _rootWithSingleRealLeaf(bytes32 firstLeaf) internal pure returns (bytes32 root) {
        root = _pair(firstLeaf, bytes32(0));
        for (uint256 level = 1; level < 10; level++) {
            root = _pair(root, _zeroAt(level));
        }
    }

    function _pathForSecondLeaf(bytes32 firstLeaf) internal pure returns (bytes32[] memory path) {
        path = new bytes32[](10);
        path[0] = firstLeaf;
        for (uint256 level = 1; level < 10; level++) {
            path[level] = _zeroAt(level);
        }
    }

    function _pathForFirstLeaf() internal pure returns (bytes32[] memory path) {
        path = new bytes32[](10);
        for (uint256 level = 0; level < 10; level++) {
            path[level] = _zeroAt(level);
        }
    }

    function _combined(BatchClaimsRegistry.BatchSubmission memory submission) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                submission.batchId,
                submission.claimRoot,
                submission.resultRoot,
                submission.paymentRoot,
                submission.nullifierRootBefore,
                submission.nullifierRootAfter,
                submission.batchNullifierCommitment,
                submission.rulesetRoot,
                submission.claimSourceRoot,
                submission.oracleFactsRoot,
                submission.oracleSignerRoot,
                submission.feeScheduleRoot,
                submission.addressBookRoot,
                submission.dataAvailabilityRoot,
                submission.denialAttestationRoot,
                submission.forcedInclusionRoot,
                submission.valueConservationCommitment,
                submission.verifierKeyId,
                submission.claimCount,
                submission.paymentCount
            )
        );
    }

    function _submission(bytes32 batchId, bytes32 resultRoot, bytes32 verifierKeyId)
        internal
        pure
        returns (BatchClaimsRegistry.BatchSubmission memory submission)
    {
        submission.batchId = batchId;
        submission.claimRoot = _id("claim-root");
        submission.resultRoot = resultRoot;
        submission.paymentRoot = _id("payment-root");
        submission.nullifierRootBefore = GENESIS;
        submission.nullifierRootAfter = _id("nullifier-root-after");
        submission.batchNullifierCommitment = _id("batch-nullifier-commitment");
        submission.rulesetRoot = _id("ruleset-root");
        submission.claimSourceRoot = _id("claim-source-root");
        submission.oracleFactsRoot = _id("oracle-facts-root");
        submission.oracleSignerRoot = _id("oracle-signer-root");
        submission.feeScheduleRoot = _id("fee-schedule-root");
        submission.addressBookRoot = _id("address-book-root");
        submission.dataAvailabilityRoot = _id("data-availability-root");
        submission.denialAttestationRoot = _id("denial-attestation-root");
        submission.forcedInclusionRoot = _id("forced-inclusion-root");
        submission.valueConservationCommitment = _id("value-conservation-commitment");
        submission.verifierKeyId = verifierKeyId;
        submission.claimCount = 1;
        submission.paymentCount = 1;
        submission.combinedBatchCommitment = _combined(submission);
    }

    function _inputs(BatchClaimsRegistry.BatchSubmission memory submission) internal pure returns (bytes32[] memory inputs) {
        inputs = new bytes32[](20);
        inputs[0] = submission.claimRoot;
        inputs[1] = submission.resultRoot;
        inputs[2] = submission.paymentRoot;
        inputs[3] = submission.nullifierRootBefore;
        inputs[4] = submission.nullifierRootAfter;
        inputs[5] = submission.batchNullifierCommitment;
        inputs[6] = submission.rulesetRoot;
        inputs[7] = submission.combinedBatchCommitment;
        inputs[8] = submission.verifierKeyId;
        inputs[9] = bytes32(submission.claimCount);
        inputs[10] = bytes32(submission.paymentCount);
        inputs[11] = submission.claimSourceRoot;
        inputs[12] = submission.oracleFactsRoot;
        inputs[13] = submission.oracleSignerRoot;
        inputs[14] = submission.feeScheduleRoot;
        inputs[15] = submission.addressBookRoot;
        inputs[16] = submission.dataAvailabilityRoot;
        inputs[17] = submission.denialAttestationRoot;
        inputs[18] = submission.forcedInclusionRoot;
        inputs[19] = submission.valueConservationCommitment;
    }

    function _approveSubmissionRoots(BatchClaimsRegistry registry, BatchClaimsRegistry.BatchSubmission memory submission) internal {
        registry.setRulesetApproved(submission.rulesetRoot, true);
        registry.setRootApproved(registry.CLAIM_SOURCE_ROOT_KEY(), submission.claimSourceRoot, true);
        registry.setRootApproved(registry.ORACLE_FACTS_ROOT_KEY(), submission.oracleFactsRoot, true);
        registry.setRootApproved(registry.ORACLE_SIGNER_ROOT_KEY(), submission.oracleSignerRoot, true);
        registry.setRootApproved(registry.FEE_SCHEDULE_ROOT_KEY(), submission.feeScheduleRoot, true);
        registry.setRootApproved(registry.ADDRESS_BOOK_ROOT_KEY(), submission.addressBookRoot, true);
    }

    function testRegistryRejectsRevokingLastAdmin() public {
        BatchClaimsRegistry registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new OpenEndedAcceptingVerifier());

        try registry.revokeRole(registry.ADMIN_ROLE(), address(this)) {
            revert("last admin revoke accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("last admin")), "wrong last-admin reason");
        }
        registry.setRulesetApproved(_id("future-ruleset"), true);
        require(registry.adminCount() == 1, "admin count changed");
    }

    function testRegistryGrantSecondAdminThenRevokeWorks() public {
        BatchClaimsRegistry registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new OpenEndedAcceptingVerifier());
        address secondAdmin = address(0xA11CE);
        registry.grantRole(registry.ADMIN_ROLE(), secondAdmin);
        require(registry.adminCount() == 2, "admin grant did not count");
        registry.revokeRole(registry.ADMIN_ROLE(), secondAdmin);
        require(registry.adminCount() == 1, "admin revoke did not count");
    }

    function testPaymentTriggerGrantThenRevokeOperatorWorks() public {
        BatchClaimsRegistry registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new OpenEndedAcceptingVerifier());
        BatchPaymentTrigger trigger = new BatchPaymentTrigger(address(this), new OpenEndedSettlementBridge(), registry);
        OpenEndedPaymentCaller caller = new OpenEndedPaymentCaller();
        bytes32[] memory path = new bytes32[](10);

        trigger.grantRole(trigger.OPERATOR_ROLE(), address(caller));
        try caller.trigger(trigger, _id("missingBatch"), _id("paymentRecord"), path) {
            revert("authorized missing payment unexpectedly accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment not in batch")), "operator was not granted");
        }

        trigger.revokeRole(trigger.OPERATOR_ROLE(), address(caller));
        try caller.trigger(trigger, _id("missingBatch"), _id("paymentRecord"), path) {
            revert("revoked operator accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("not authorized")), "wrong revoked operator reason");
        }
    }

    function testPaymentTriggerRejectsRevokingLastAdmin() public {
        BatchClaimsRegistry registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new OpenEndedAcceptingVerifier());
        BatchPaymentTrigger trigger = new BatchPaymentTrigger(address(this), new OpenEndedSettlementBridge(), registry);

        try trigger.revokeRole(trigger.ADMIN_ROLE(), address(this)) {
            revert("payment trigger last admin revoke accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("last admin")), "wrong payment trigger last-admin reason");
        }
        require(trigger.adminCount() == 1, "payment admin count changed");
    }

    function testPaddingZeroResultLeafPastClaimCountBlocked() public {
        BatchClaimsRegistry registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new OpenEndedAcceptingVerifier());
        bytes32 realResultLeaf = _id("only-real-result-leaf");
        BatchClaimsRegistry.BatchSubmission memory submission =
            _submission(_id("padding-zero-leaf-batch"), _rootWithSingleRealLeaf(realResultLeaf), CHECKER_ID);
        _approveSubmissionRoots(registry, submission);
        registry.submitBatch(submission, hex"01", _inputs(submission));

        bool paddingLeafAccepted =
            registry.verifyClaimInBatch(submission.batchId, bytes32(0), _pathForSecondLeaf(realResultLeaf), 1);
        require(!paddingLeafAccepted, "padding zero leaf verified past claim count");
        require(registry.submittedBatchCount() == 1, "wrong test setup");
    }

    function testMerkleIndexHighBitsBlocked() public {
        BatchClaimsRegistry registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new OpenEndedAcceptingVerifier());
        bytes32 realResultLeaf = _id("only-real-result-leaf");
        BatchClaimsRegistry.BatchSubmission memory submission =
            _submission(_id("high-bit-index-alias-batch"), _rootWithSingleRealLeaf(realResultLeaf), CHECKER_ID);
        _approveSubmissionRoots(registry, submission);
        registry.submitBatch(submission, hex"01", _inputs(submission));

        bool lowIndexAccepted =
            registry.verifyClaimInBatch(submission.batchId, realResultLeaf, _pathForFirstLeaf(), 0);
        bool highIndexAccepted =
            registry.verifyClaimInBatch(submission.batchId, realResultLeaf, _pathForFirstLeaf(), 1024);
        require(lowIndexAccepted, "valid low index rejected");
        require(!highIndexAccepted, "high-bit index alias verified");
    }

    function testClaimCountAboveMerkleCapacityBlocked() public {
        BatchClaimsRegistry registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new OpenEndedAcceptingVerifier());
        BatchClaimsRegistry.BatchSubmission memory submission =
            _submission(_id("over-capacity-count-batch"), _id("result-root"), CHECKER_ID);
        submission.claimCount = 1025;
        submission.combinedBatchCommitment = _combined(submission);
        _approveSubmissionRoots(registry, submission);

        try registry.submitBatch(submission, hex"01", _inputs(submission)) {
            revert("over-capacity claim count accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("claim count exceeds capacity")), "wrong capacity reason");
        }
        require(registry.submittedBatchCount() == 0, "over-capacity batch was stored");
    }

    function testShortPublicInputLengthMisconfigBlockedCleanly() public {
        bytes32 shortCheckerId = keccak256("SHORT_INPUT_CHECKER");
        BatchClaimsRegistry registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new OpenEndedAcceptingVerifier());

        try registry.setBatchCheckerWithInputLength(shortCheckerId, new OpenEndedAcceptingVerifier(), 1) {
            revert("short public input length accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("input length too short")), "wrong input-length reason");
        }
    }
}

contract OpenEndedPaymentCaller {
    function trigger(BatchPaymentTrigger triggerContract, bytes32 batchId, bytes32 paymentRecord, bytes32[] memory path) external {
        triggerContract.triggerBatchSettlement(batchId, paymentRecord, path, 0);
    }
}
