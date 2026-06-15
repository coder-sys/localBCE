// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../src/batch/BatchClaimsRegistry.sol";
import "../../src/batch/BatchPaymentTrigger.sol";
import "../../src/batch/BatchStubVerifier.sol";
import "../../src/batch/IBatchVerifier.sol";

contract AcceptingAttackVerifier is IBatchVerifier {
    function verifyBatch(bytes calldata proof, bytes32[] calldata publicInputs) external pure returns (bool) {
        return proof.length > 0 && publicInputs.length == 11;
    }

    function isBatchVerifier() external pure returns (bool) {
        return true;
    }

    function batchPublicInputLength() external pure returns (uint256) {
        return 11;
    }

    function isTestVerifier() external pure returns (bool) {
        return true;
    }
}

contract RegistryCaller {
    function submit(BatchClaimsRegistry registry, BatchClaimsRegistry.BatchSubmission memory submission, bytes32[] memory inputs) external {
        registry.submitBatch(submission, hex"1234", inputs);
    }

    function grantSelfAdmin(BatchClaimsRegistry registry) external {
        registry.grantRole(registry.ADMIN_ROLE(), address(this));
    }
}

contract PaymentCaller {
    function submit(BatchPaymentTrigger trigger, bytes32 batchId, address recipient, bytes32 paymentRecord, bytes32[] memory path) external {
        trigger.triggerProviderNetSettlement(batchId, recipient, paymentRecord, path, 0);
    }
}

contract BatchAttackTest {
    bytes32 internal constant CHECKER_ID = keccak256("RISC_ZERO_WRAPPED_STUB_V1");
    bytes32 internal constant GENESIS = 0x111df93687d686f128495834e87222c67d3ec42ae5d128db3ad65e8123b11f2c;

    function _id(string memory value) internal pure returns (bytes32) {
        return keccak256(bytes(value));
    }

    function _pair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(left, right));
    }

    function _payee(address recipient, bytes32 paymentRecord) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(recipient, paymentRecord));
    }

    function _combined(
        bytes32 batchId,
        bytes32 claimRoot,
        bytes32 resultRoot,
        bytes32 paymentRoot,
        bytes32 duplicateBefore,
        bytes32 duplicateAfter,
        bytes32 batchNullifierCommitment,
        bytes32 rulesetRoot,
        bytes32 verifierKeyId,
        uint256 claimCount,
        uint256 paymentCount
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(batchId, claimRoot, resultRoot, paymentRoot, duplicateBefore, duplicateAfter, batchNullifierCommitment, rulesetRoot, verifierKeyId, claimCount, paymentCount));
    }

    function _zeroAt(uint256 level) internal pure returns (bytes32 zeroHash) {
        zeroHash = bytes32(0);
        for (uint256 i = 0; i < level; i++) {
            zeroHash = _pair(zeroHash, zeroHash);
        }
    }

    function _pathForFirst(bytes32 sibling) internal pure returns (bytes32[] memory path) {
        path = new bytes32[](10);
        path[0] = sibling;
        for (uint256 i = 1; i < 10; i++) {
            path[i] = _zeroAt(i);
        }
    }

    function _pathForSecond(bytes32 sibling) internal pure returns (bytes32[] memory path) {
        path = new bytes32[](10);
        path[0] = sibling;
        for (uint256 i = 1; i < 10; i++) {
            path[i] = _zeroAt(i);
        }
    }

    function _rootForFirst(bytes32 leaf, bytes32 sibling) internal pure returns (bytes32 root) {
        root = _pair(leaf, sibling);
        for (uint256 i = 1; i < 10; i++) {
            root = _pair(root, _zeroAt(i));
        }
    }

    function _registry() internal returns (BatchClaimsRegistry registry) {
        registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new AcceptingAttackVerifier(), true);
        registry.setRulesetApproved(_id("rulesetRoot"), true);
    }

    function _failClosedRegistry() internal returns (BatchClaimsRegistry registry) {
        registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new BatchStubVerifier(), true);
        registry.setRulesetApproved(_id("rulesetRoot"), true);
    }

    function _submission(
        bytes32 batchId,
        bytes32 resultRoot,
        bytes32 duplicateAfter
    ) internal pure returns (BatchClaimsRegistry.BatchSubmission memory) {
        return _submissionWithPayment(batchId, resultRoot, GENESIS, duplicateAfter, _id("paymentRoot"));
    }

    function _submissionWithPayment(
        bytes32 batchId,
        bytes32 resultRoot,
        bytes32 duplicateBefore,
        bytes32 duplicateAfter,
        bytes32 paymentRoot
    ) internal pure returns (BatchClaimsRegistry.BatchSubmission memory) {
        bytes32 claimRoot = _id("claimRoot");
        bytes32 rulesetRoot = _id("rulesetRoot");
        bytes32 batchNullifierCommitment = _id("batchNullifierCommitment");
        return BatchClaimsRegistry.BatchSubmission(
            batchId,
            claimRoot,
            resultRoot,
            duplicateBefore,
            duplicateAfter,
            batchNullifierCommitment,
            _combined(batchId, claimRoot, resultRoot, paymentRoot, duplicateBefore, duplicateAfter, batchNullifierCommitment, rulesetRoot, CHECKER_ID, 1, 1),
            paymentRoot,
            rulesetRoot,
            CHECKER_ID,
            1,
            1
        );
    }

    function _inputs(BatchClaimsRegistry.BatchSubmission memory submission) internal pure returns (bytes32[] memory inputs) {
        inputs = new bytes32[](11);
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
    }

    function _submit(BatchClaimsRegistry registry, BatchClaimsRegistry.BatchSubmission memory submission) internal {
        registry.submitBatch(submission, hex"1234", _inputs(submission));
    }

    function _paymentFixture() internal returns (BatchPaymentTrigger trigger, bytes32 batchId, address recipient, bytes32 payment0, bytes32[] memory path) {
        batchId = _id("payBatch");
        recipient = address(0xBEEF);
        payment0 = _id("payment-1");
        bytes32 payment1 = _id("payment-2");
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            batchId,
            _id("result"),
            registry.currentNullifierRoot(),
            _id("dupPay"),
            _rootForFirst(_payee(recipient, payment0), _payee(address(0xCAFE), payment1))
        );
        _submit(registry, submission);
        trigger = new BatchPaymentTrigger(address(this), new CPNAdapterStub(), registry);
        path = _pathForFirst(_payee(address(0xCAFE), payment1));
    }

    function testA1DoublePayBlocked() public {
        (BatchPaymentTrigger trigger, bytes32 batchId, address recipient, bytes32 payment0, bytes32[] memory path) = _paymentFixture();
        trigger.triggerProviderNetSettlement(batchId, recipient, payment0, path, 0);
        try trigger.triggerProviderNetSettlement(batchId, recipient, payment0, path, 0) {
            revert("double payment accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment already submitted")), "wrong double-pay reason");
        }
    }

    function testA2InflatedPayoutRecordBlocked() public {
        (BatchPaymentTrigger trigger, bytes32 batchId, address recipient,, bytes32[] memory path) = _paymentFixture();
        try trigger.triggerProviderNetSettlement(batchId, recipient, _id("inflated-payment"), path, 0) {
            revert("inflated payment accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment not in batch")), "wrong inflated reason");
        }
    }

    function testA3DeniedClaimPaymentBlocked() public {
        (BatchPaymentTrigger trigger, bytes32 batchId, address recipient,, bytes32[] memory path) = _paymentFixture();
        try trigger.triggerProviderNetSettlement(batchId, recipient, _id("denied-result"), path, 0) {
            revert("denied payment accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment not in batch")), "wrong denied reason");
        }
    }

    function testA4QuarantinedClaimPaymentBlocked() public {
        (BatchPaymentTrigger trigger, bytes32 batchId, address recipient,, bytes32[] memory path) = _paymentFixture();
        try trigger.triggerProviderNetSettlement(batchId, recipient, _id("quarantined-payment"), path, 0) {
            revert("quarantined payment accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment not in batch")), "wrong quarantine reason");
        }
    }

    function testA6PhantomProviderBlocked() public {
        (BatchPaymentTrigger trigger, bytes32 batchId,, bytes32 payment0, bytes32[] memory path) = _paymentFixture();
        try trigger.triggerProviderNetSettlement(batchId, address(0xF00D), payment0, path, 0) {
            revert("phantom provider accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment not in batch")), "wrong phantom reason");
        }
    }

    function testB2ReplayRecordedBatchBlocked() public {
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchB2"), _id("resultB2"), _id("dupB2"));
        _submit(registry, submission);
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("batch replay accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("batch exists")), "wrong replay reason");
        }
    }

    function testB3ReuseStaleNullifierRootBlocked() public {
        BatchClaimsRegistry registry = _registry();
        _submit(registry, _submission(_id("batchB3a"), _id("resultB3a"), _id("spentDup")));
        BatchClaimsRegistry.BatchSubmission memory second = _submissionWithPayment(
            _id("batchB3b"),
            _id("resultB3b"),
            bytes32(0),
            _id("freshButBuiltFromOldRoot"),
            _id("paymentRoot")
        );
        try registry.submitBatch(second, hex"1234", _inputs(second)) {
            revert("stale duplicate root accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("stale nullifier root")), "wrong stale-root reason");
        }
    }

    function testB4CompetingWorkersSameRootSecondRevertsStaleRoot() public {
        BatchClaimsRegistry registry = _registry();
        bytes32 rootBefore = registry.currentNullifierRoot();
        BatchClaimsRegistry.BatchSubmission memory first = _submissionWithPayment(
            _id("raceFirst"),
            _id("raceResultA"),
            rootBefore,
            _id("raceAfterA"),
            _id("paymentRoot")
        );
        BatchClaimsRegistry.BatchSubmission memory second = _submissionWithPayment(
            _id("raceSecond"),
            _id("raceResultB"),
            rootBefore,
            _id("raceAfterB"),
            _id("paymentRoot")
        );
        _submit(registry, first);
        try registry.submitBatch(second, hex"1234", _inputs(second)) {
            revert("stale root accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("stale nullifier root")), "wrong stale-root reason");
        }
    }

    function testB1AndF4FailClosedStubBlocksOverlappingClaims() public {
        BatchClaimsRegistry registry = _failClosedRegistry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchOverlap"), _id("sameClaimResult"), _id("dupVariant"));
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("fail-closed duplicate surface accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("batch check failed")), "wrong fail-closed reason");
        }
    }

    function testC1ForgeInclusionForAbsentClaimBlocked() public {
        BatchClaimsRegistry registry = _registry();
        bytes32 leaf0 = _id("real0");
        bytes32 leaf1 = _id("real1");
        _submit(registry, _submission(_id("batchC1"), _rootForFirst(leaf0, leaf1), _id("dupC1")));
        bytes32[] memory path = _pathForFirst(leaf1);
        require(!registry.verifyClaimInBatch(_id("batchC1"), _id("fake"), path, 0), "fake inclusion accepted");
    }

    function testC2DifferentResultLeafBlockedAgainstFixedRoot() public {
        BatchClaimsRegistry registry = _registry();
        bytes32 approved = _id("approved");
        bytes32 denied = _id("denied");
        _submit(registry, _submission(_id("batchC2"), _rootForFirst(approved, _id("sibling")), _id("dupC2")));
        bytes32[] memory path = _pathForFirst(_id("sibling"));
        require(!registry.verifyClaimInBatch(_id("batchC2"), denied, path, 0), "swapped result accepted");
    }

    function testC5EmptyMalformedBatchAttestationBlocked() public {
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchC5"), _id("resultC5"), _id("dupC5"));
        bytes32[] memory emptyInputs = new bytes32[](0);
        try registry.submitBatch(submission, hex"", emptyInputs) {
            revert("empty attestation accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("batch inputs mismatch")), "wrong empty-proof reason");
        }
    }

    function testD1UnauthorizedBatchSubmitBlocked() public {
        BatchClaimsRegistry registry = _registry();
        RegistryCaller caller = new RegistryCaller();
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchD1"), _id("resultD1"), _id("dupD1"));
        try caller.submit(registry, submission, _inputs(submission)) {
            revert("unauthorized submit accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("not authorized")), "wrong unauthorized reason");
        }
    }

    function testD2AuditorCannotSubmitOrTriggerPayment() public {
        BatchClaimsRegistry registry = _registry();
        RegistryCaller caller = new RegistryCaller();
        registry.grantRole(registry.AUDITOR_ROLE(), address(caller));
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchD2"), _id("resultD2"), _id("dupD2"));
        try caller.submit(registry, submission, _inputs(submission)) {
            revert("auditor submit accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("not authorized")), "wrong auditor submit reason");
        }

        (BatchPaymentTrigger trigger, bytes32 batchId, address recipient, bytes32 payment0, bytes32[] memory path) = _paymentFixture();
        PaymentCaller payCaller = new PaymentCaller();
        try payCaller.submit(trigger, batchId, recipient, payment0, path) {
            revert("auditor-like payment accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("not authorized")), "wrong payment auth reason");
        }
    }

    function testD3LowerRoleCannotGrantItselfAdmin() public {
        BatchClaimsRegistry registry = _registry();
        RegistryCaller caller = new RegistryCaller();
        registry.grantRole(registry.OPERATOR_ROLE(), address(caller));
        try caller.grantSelfAdmin(registry) {
            revert("role escalation accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("not admin")), "wrong escalation reason");
        }
    }

    function testD4SettlementBypassesBatchSubmissionBlocked() public {
        BatchClaimsRegistry registry = _registry();
        BatchPaymentTrigger trigger = new BatchPaymentTrigger(address(this), new CPNAdapterStub(), registry);
        bytes32[] memory path = _pathForFirst(_id("sibling"));
        try trigger.triggerBatchSettlement(_id("neverSubmittedBatch"), _id("paymentRecord"), path, 0) {
            revert("unsubmitted batch settlement accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment not in batch")), "wrong bypass reason");
        }
    }

    function testF1InconsistentRootsFailClosedStubBlocked() public {
        BatchClaimsRegistry registry = _failClosedRegistry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchF1"), _id("not-derived-from-claims"), _id("dupF1"));
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("inconsistent roots accepted by stub");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("batch check failed")), "wrong inconsistent-root reason");
        }
    }

    function testP1ForgedRulesetRootBlocked() public {
        BatchClaimsRegistry registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new AcceptingAttackVerifier(), true);
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchRulesetForged"), _id("resultRuleset"), _id("dupRuleset"));
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("forged ruleset accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("ruleset not approved")), "wrong ruleset reason");
        }
    }

    function testP1PublicInputsMismatchBlocked() public {
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchMismatchedInputs"), _id("honestResultRoot"), _id("dupMismatch"));
        bytes32[] memory badInputs = new bytes32[](11);
        badInputs[0] = _id("badClaimRoot");
        badInputs[1] = _id("badResultRoot");
        badInputs[2] = _id("badPaymentRoot");
        badInputs[3] = _id("badBefore");
        badInputs[4] = _id("badAfter");
        badInputs[5] = _id("badBatchNullifier");
        badInputs[6] = _id("badRuleset");
        badInputs[7] = _id("badCombined");
        badInputs[8] = CHECKER_ID;
        badInputs[9] = bytes32(uint256(1));
        badInputs[10] = bytes32(uint256(1));
        try registry.submitBatch(submission, hex"1234", badInputs) {
            revert("mismatched public inputs accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("batch inputs mismatch")), "wrong mismatch reason");
        }
    }

    function testP1MissingBatchZeroLeafInclusionBlocked() public {
        bytes32[] memory emptyPath = new bytes32[](0);
        BatchClaimsRegistry registry = _registry();
        require(!registry.verifyClaimInBatch(_id("missingBatch"), bytes32(0), emptyPath, 0), "missing batch zero leaf accepted");
    }
}
