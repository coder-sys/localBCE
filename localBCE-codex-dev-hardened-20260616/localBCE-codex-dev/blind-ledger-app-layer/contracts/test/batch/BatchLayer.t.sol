// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../src/batch/BatchClaimsRegistry.sol";
import "../../src/batch/BatchPaymentTrigger.sol";
import "../../src/batch/IBatchVerifier.sol";

contract AcceptingBatchVerifier is IBatchVerifier {
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

contract RejectingBatchVerifier is IBatchVerifier {
    function verifyBatch(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return false;
    }

    function isBatchVerifier() external pure returns (bool) {
        return true;
    }

    function batchPublicInputLength() external pure returns (uint256) {
        return 20;
    }
}

contract RecordingSettlementBridge is ISettlementBridge {
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

contract BatchRegistryAttacker {
    function submit(
        BatchClaimsRegistry registry,
        BatchClaimsRegistry.BatchSubmission memory submission,
        bytes memory batchAttestation,
        bytes32[] memory batchInputs
    ) external {
        registry.submitBatch(submission, batchAttestation, batchInputs);
    }
}

contract BatchLayerTest {
    bytes32 internal constant CHECKER_ID = keccak256("NATIVE_STARK_SETTLEMENT_V1");
    bytes32 internal constant GENESIS = 0x111df93687d686f128495834e87222c67d3ec42ae5d128db3ad65e8123b11f2c;

    function _id(string memory value) internal pure returns (bytes32) {
        return keccak256(bytes(value));
    }

    function _pair(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(left, right));
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
        bytes32 claimSourceRoot,
        bytes32 oracleFactsRoot,
        bytes32 oracleSignerRoot,
        bytes32 feeScheduleRoot,
        bytes32 addressBookRoot,
        bytes32 verifierKeyId,
        uint256 claimCount,
        uint256 paymentCount
    ) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                batchId,
                claimRoot,
                resultRoot,
                paymentRoot,
                duplicateBefore,
                duplicateAfter,
                batchNullifierCommitment,
                rulesetRoot,
                claimSourceRoot,
                oracleFactsRoot,
                oracleSignerRoot,
                feeScheduleRoot,
                addressBookRoot,
                _id("dataAvailabilityRoot"),
                _id("denialAttestationRoot"),
                _id("forcedInclusionRoot"),
                _id("valueConservationCommitment"),
                verifierKeyId,
                claimCount,
                paymentCount
            )
        );
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

    function _registry() internal returns (BatchClaimsRegistry registry) {
        registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new AcceptingBatchVerifier());
        registry.setRulesetApproved(_id("rulesetRoot"), true);
        registry.setRootApproved(registry.CLAIM_SOURCE_ROOT_KEY(), _id("claimSourceRoot"), true);
        registry.setRootApproved(registry.ORACLE_FACTS_ROOT_KEY(), _id("oracleFactsRoot"), true);
        registry.setRootApproved(registry.ORACLE_SIGNER_ROOT_KEY(), _id("oracleSignerRoot"), true);
        registry.setRootApproved(registry.FEE_SCHEDULE_ROOT_KEY(), _id("feeScheduleRoot"), true);
        registry.setRootApproved(registry.ADDRESS_BOOK_ROOT_KEY(), _id("addressBookRoot"), true);
    }

    function _failClosedRegistry() internal returns (BatchClaimsRegistry registry) {
        registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new RejectingBatchVerifier());
        registry.setRulesetApproved(_id("rulesetRoot"), true);
        registry.setRootApproved(registry.CLAIM_SOURCE_ROOT_KEY(), _id("claimSourceRoot"), true);
        registry.setRootApproved(registry.ORACLE_FACTS_ROOT_KEY(), _id("oracleFactsRoot"), true);
        registry.setRootApproved(registry.ORACLE_SIGNER_ROOT_KEY(), _id("oracleSignerRoot"), true);
        registry.setRootApproved(registry.FEE_SCHEDULE_ROOT_KEY(), _id("feeScheduleRoot"), true);
        registry.setRootApproved(registry.ADDRESS_BOOK_ROOT_KEY(), _id("addressBookRoot"), true);
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
        bytes32 claimSourceRoot = _id("claimSourceRoot");
        bytes32 oracleFactsRoot = _id("oracleFactsRoot");
        bytes32 oracleSignerRoot = _id("oracleSignerRoot");
        bytes32 feeScheduleRoot = _id("feeScheduleRoot");
        bytes32 addressBookRoot = _id("addressBookRoot");
        bytes32 dataAvailabilityRoot = _id("dataAvailabilityRoot");
        bytes32 denialAttestationRoot = _id("denialAttestationRoot");
        bytes32 forcedInclusionRoot = _id("forcedInclusionRoot");
        bytes32 valueConservationCommitment = _id("valueConservationCommitment");
        bytes32 batchNullifierCommitment = _id("batchNullifierCommitment");
        return BatchClaimsRegistry.BatchSubmission(
            batchId,
            claimRoot,
            resultRoot,
            duplicateBefore,
            duplicateAfter,
            batchNullifierCommitment,
            _combined(batchId, claimRoot, resultRoot, paymentRoot, duplicateBefore, duplicateAfter, batchNullifierCommitment, rulesetRoot, claimSourceRoot, oracleFactsRoot, oracleSignerRoot, feeScheduleRoot, addressBookRoot, CHECKER_ID, 2, 2),
            paymentRoot,
            rulesetRoot,
            claimSourceRoot,
            oracleFactsRoot,
            oracleSignerRoot,
            feeScheduleRoot,
            addressBookRoot,
            dataAvailabilityRoot,
            denialAttestationRoot,
            forcedInclusionRoot,
            valueConservationCommitment,
            CHECKER_ID,
            2,
            2
        );
    }

    function _submitDefault(BatchClaimsRegistry registry, bytes32 batchId, bytes32 resultRoot, bytes32 duplicateAfter) internal {
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            batchId,
            resultRoot,
            registry.currentNullifierRoot(),
            duplicateAfter,
            _id("paymentRoot")
        );
        registry.submitBatch(submission, hex"1234", _inputs(submission));
    }

    function testRejectingVerifierRejectsByDefault() public {
        BatchClaimsRegistry registry = _failClosedRegistry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchReject"), _id("resultReject"), _id("dupReject"));
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("fail-closed verifier accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("batch check failed")), "wrong verifier rejection");
        }
    }

    function testArbitraryNullifierBootstrapRejected() public {
        BatchClaimsRegistry registry = _registry();
        try registry.bootstrapNullifierRoot(_id("evil-root")) {
            revert("arbitrary genesis accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("noncanonical genesis")), "wrong genesis rejection");
        }
        registry.bootstrapNullifierRoot(GENESIS);
        require(registry.currentNullifierRoot() == GENESIS, "canonical genesis changed");
    }

    function testBatchRecordStoresRootOnlyHeader() public {
        BatchClaimsRegistry registry = _registry();
        bytes32 resultRoot = _id("resultRootA");
        bytes32 duplicateAfter = _id("duplicateAfterA");
        _submitDefault(registry, _id("batchA"), resultRoot, duplicateAfter);

        (
            bool exists,
            bytes32 claimRoot,
            bytes32 storedResultRoot,
            ,
            bytes32 storedDuplicateAfter,
            bytes32 batchNullifierCommitment,
            bytes32 combinedBatchCommitment,
            bytes32 paymentRoot,
            bytes32 rulesetRoot,
            bytes32 claimSourceRoot,
            bytes32 oracleFactsRoot,
            bytes32 oracleSignerRoot,
            bytes32 feeScheduleRoot,
            bytes32 addressBookRoot,
            bytes32 dataAvailabilityRoot,
            bytes32 denialAttestationRoot,
            bytes32 forcedInclusionRoot,
            bytes32 valueConservationCommitment,
            bytes32 verifierKeyId,
            uint256 claimCount,
            uint256 paymentCount,
            address submitter,
            uint256 timestamp
        ) = registry.batches(_id("batchA"));

        require(exists, "missing batch");
        require(claimRoot == _id("claimRoot"), "claim record mismatch");
        require(storedResultRoot == resultRoot, "adjudication record mismatch");
        require(storedDuplicateAfter == duplicateAfter, "duplicate record mismatch");
        require(batchNullifierCommitment == _id("batchNullifierCommitment"), "batch nullifier mismatch");
        require(combinedBatchCommitment == _combined(_id("batchA"), _id("claimRoot"), resultRoot, _id("paymentRoot"), GENESIS, duplicateAfter, _id("batchNullifierCommitment"), _id("rulesetRoot"), _id("claimSourceRoot"), _id("oracleFactsRoot"), _id("oracleSignerRoot"), _id("feeScheduleRoot"), _id("addressBookRoot"), CHECKER_ID, 2, 2), "combined mismatch");
        require(paymentRoot == _id("paymentRoot"), "payment record mismatch");
        require(rulesetRoot == _id("rulesetRoot"), "ruleset mismatch");
        require(claimSourceRoot == _id("claimSourceRoot"), "claim source root mismatch");
        require(oracleFactsRoot == _id("oracleFactsRoot"), "oracle facts root mismatch");
        require(oracleSignerRoot == _id("oracleSignerRoot"), "oracle signer root mismatch");
        require(feeScheduleRoot == _id("feeScheduleRoot"), "fee schedule root mismatch");
        require(addressBookRoot == _id("addressBookRoot"), "address book root mismatch");
        require(dataAvailabilityRoot == _id("dataAvailabilityRoot"), "data availability root mismatch");
        require(denialAttestationRoot == _id("denialAttestationRoot"), "denial attestation root mismatch");
        require(forcedInclusionRoot == _id("forcedInclusionRoot"), "forced inclusion root mismatch");
        require(valueConservationCommitment == _id("valueConservationCommitment"), "value conservation mismatch");
        require(verifierKeyId == CHECKER_ID, "checker mismatch");
        require(claimCount == 2, "claim count mismatch");
        require(paymentCount == 2, "payment count mismatch");
        require(submitter == address(this), "submitter mismatch");
        require(timestamp > 0, "timestamp missing");
    }

    function testInclusionAcceptsRecordedClaim() public {
        BatchClaimsRegistry registry = _registry();
        bytes32 leaf0 = _id("claim-result-0");
        bytes32 leaf1 = _id("claim-result-1");
        bytes32 root = _rootForFirst(leaf0, leaf1);
        _submitDefault(registry, _id("batchB"), root, _id("duplicateAfterB"));

        bytes32[] memory path = _pathForFirst(leaf1);
        require(registry.verifyClaimInBatch(_id("batchB"), leaf0, path, 0), "inclusion rejected");
        require(registry.checkClaimInBatch(_id("batchB"), leaf0, path, 0), "plain inclusion rejected");
    }

    function testTamperedInclusionRejects() public {
        BatchClaimsRegistry registry = _registry();
        bytes32 leaf0 = _id("claim-result-0");
        bytes32 leaf1 = _id("claim-result-1");
        bytes32 root = _rootForFirst(leaf0, leaf1);
        _submitDefault(registry, _id("batchC"), root, _id("duplicateAfterC"));

        bytes32[] memory path = _pathForFirst(_id("tampered"));
        require(!registry.verifyClaimInBatch(_id("batchC"), leaf0, path, 0), "tampered inclusion accepted");
    }

    function testStaleNullifierRootRejects() public {
        BatchClaimsRegistry registry = _registry();
        bytes32 duplicateAfter = _id("duplicateAfterD");
        _submitDefault(registry, _id("batchD1"), _id("resultRootD1"), duplicateAfter);
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("batchD2"),
            _id("resultRootD2"),
            bytes32(0),
            _id("duplicateAfterD2"),
            _id("paymentRoot")
        );
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("expected stale root rejection");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("stale nullifier root")), "wrong stale-root reason");
        }
    }

    function testAuthoritativeNullifierRootRejectsStaleCompetingBatch() public {
        BatchClaimsRegistry registry = _registry();
        bytes32 rootBefore = registry.currentNullifierRoot();
        BatchClaimsRegistry.BatchSubmission memory first = _submissionWithPayment(
            _id("batchRaceA"),
            _id("resultRaceA"),
            rootBefore,
            _id("rootRaceA"),
            _id("paymentRoot")
        );
        BatchClaimsRegistry.BatchSubmission memory second = _submissionWithPayment(
            _id("batchRaceB"),
            _id("resultRaceB"),
            rootBefore,
            _id("rootRaceB"),
            _id("paymentRoot")
        );
        registry.submitBatch(first, hex"1234", _inputs(first));
        require(registry.currentNullifierRoot() == _id("rootRaceA"), "root did not advance");
        try registry.submitBatch(second, hex"1234", _inputs(second)) {
            revert("stale competing batch accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("stale nullifier root")), "wrong stale-root reason");
        }
    }

    function testReusingPaymentRootUnderFreshBatchRejected() public {
        BatchClaimsRegistry registry = _registry();
        bytes32 firstAfter = _id("paymentReplayAfter1");
        BatchClaimsRegistry.BatchSubmission memory first = _submissionWithPayment(
            _id("paymentReplayA"),
            _id("paymentReplayResultA"),
            registry.currentNullifierRoot(),
            firstAfter,
            _id("samePaymentRoot")
        );
        registry.submitBatch(first, hex"1234", _inputs(first));

        BatchClaimsRegistry.BatchSubmission memory second = _submissionWithPayment(
            _id("paymentReplayB"),
            _id("paymentReplayResultB"),
            registry.currentNullifierRoot(),
            _id("paymentReplayAfter2"),
            _id("samePaymentRoot")
        );
        try registry.submitBatch(second, hex"1234", _inputs(second)) {
            revert("reused payment root accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment root used")), "wrong payment replay reason");
        }
    }

    function testPaymentRequiresNullifierRootAdvance() public {
        BatchClaimsRegistry registry = _registry();
        bytes32 root = registry.currentNullifierRoot();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("paymentNoNullifierDelta"),
            _id("paymentNoDeltaResult"),
            root,
            root,
            _id("paymentNoDeltaRoot")
        );
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("payment with zero nullifier delta accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment requires nullifier advance")), "wrong nullifier-delta reason");
        }
    }

    function testCombinedCommitmentRejectsSwappedClaimRoot() public {
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("batchBindClaim"),
            _id("resultBind"),
            registry.currentNullifierRoot(),
            _id("dupBind"),
            _id("paymentRoot")
        );
        submission.claimRoot = _id("evilClaimRoot");
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("swapped claim root accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("combined commitment mismatch")), "wrong claim-root bind reason");
        }
    }

    function testCombinedCommitmentRejectsSwappedPaymentRoot() public {
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("batchBindPayment"),
            _id("resultBind"),
            registry.currentNullifierRoot(),
            _id("dupBindPayment"),
            _id("paymentRoot")
        );
        submission.paymentRoot = _id("evilPaymentRoot");
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("swapped payment root accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("combined commitment mismatch")), "wrong payment-root bind reason");
        }
    }

    function testCombinedCommitmentRejectsSwappedResultRoot() public {
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("batchBindResult"),
            _id("resultBind"),
            registry.currentNullifierRoot(),
            _id("dupBindResult"),
            _id("paymentRoot")
        );
        submission.resultRoot = _id("evilResultRoot");
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("swapped result root accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("combined commitment mismatch")), "wrong result-root bind reason");
        }
    }

    function testCombinedCommitmentRejectsSwappedVerifierKeyId() public {
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("batchBindVerifier"),
            _id("resultBind"),
            registry.currentNullifierRoot(),
            _id("dupBindVerifier"),
            _id("paymentRoot")
        );
        submission.verifierKeyId = keccak256("EVIL_VERIFIER_KEY");
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("swapped verifier key accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("combined commitment mismatch")), "wrong verifier bind reason");
        }
    }

    function testExactPublicInputLengthRejectsTrailingData() public {
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("batchExactLength"),
            _id("resultExact"),
            registry.currentNullifierRoot(),
            _id("dupExact"),
            _id("paymentRoot")
        );
        bytes32[] memory tooLong = new bytes32[](21);
        bytes32[] memory honest = _inputs(submission);
        for (uint256 i = 0; i < honest.length; i++) {
            tooLong[i] = honest[i];
        }
        tooLong[20] = _id("ignored-before-fix");
        try registry.submitBatch(submission, hex"1234", tooLong) {
            revert("wrong-length public inputs accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("batch inputs mismatch")), "wrong length reason");
        }
        registry.submitBatch(submission, hex"1234", honest);
    }

    function testClaimCountMismatchAgainstPublicInputsRejected() public {
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("batchClaimCountBind"),
            _id("resultCountBind"),
            registry.currentNullifierRoot(),
            _id("dupCountBind"),
            _id("paymentRoot")
        );
        bytes32[] memory staleInputs = _inputs(submission);
        submission.claimCount = 3;
        submission.combinedBatchCommitment = _combined(
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
            submission.verifierKeyId,
            submission.claimCount,
            submission.paymentCount
        );
        try registry.submitBatch(submission, hex"1234", staleInputs) {
            revert("claim-count mismatch accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("batch inputs mismatch")), "wrong count mismatch reason");
        }
    }

    function testCombinedCommitmentBindsBatchId() public {
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("batchBindIdA"),
            _id("resultBindId"),
            registry.currentNullifierRoot(),
            _id("dupBindId"),
            _id("paymentRoot")
        );
        bytes32 originalCommitment = submission.combinedBatchCommitment;
        bytes32[] memory originalInputs = _inputs(submission);
        submission.batchId = _id("batchBindIdB");
        require(registry.computeCombinedBatchCommitment(submission) != originalCommitment, "batch id not bound");
        try registry.submitBatch(submission, hex"1234", originalInputs) {
            revert("swapped batch id accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("combined commitment mismatch")), "wrong batch-id bind reason");
        }
    }

    function testUnauthorizedSubmitterRejects() public {
        BatchClaimsRegistry registry = _registry();
        BatchRegistryAttacker attacker = new BatchRegistryAttacker();
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchE"), _id("resultRoot"), _id("after"));
        try attacker.submit(registry, submission, hex"1234", _inputs(submission)) {
            revert("expected unauthorized rejection");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("not authorized")), "wrong auth reason");
        }
    }

    function testBatchPaymentNetSettlementCorrect() public {
        bytes32 payment0 = _id("payment-1");
        bytes32 payment1 = _id("payment-2");
        address[] memory recipients = new address[](2);
        recipients[0] = address(0xBEEF);
        recipients[1] = address(0xCAFE);
        bytes32 paymentRoot = _rootForFirst(_payee(recipients[0], payment0), _payee(recipients[1], payment1));
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(_id("payBatchA"), _id("result"), registry.currentNullifierRoot(), _id("dupPayA"), paymentRoot);
        registry.submitBatch(submission, hex"1234", _inputs(submission));
        BatchPaymentTrigger trigger = new BatchPaymentTrigger(address(this), new RecordingSettlementBridge(), registry);

        bytes32[] memory records = new bytes32[](2);
        records[0] = payment0;
        records[1] = payment1;
        bytes32[][] memory paths = new bytes32[][](2);
        paths[0] = _pathForFirst(_payee(recipients[1], payment1));
        paths[1] = _pathForSecond(_payee(recipients[0], payment0));
        uint256[] memory indexes = new uint256[](2);
        indexes[0] = 0;
        indexes[1] = 1;

        bytes32[] memory refs = trigger.submitBatchForPayment(_id("payBatchA"), recipients, records, paths, indexes);
        require(refs[0] != bytes32(0), "missing first ref");
        require(refs[1] != bytes32(0), "missing second ref");
        require(refs[0] != refs[1], "refs should differ");
    }

    function testPaymentIndexPastPaymentCountRejectsPadding() public {
        bytes32 payment0 = _id("payment-1");
        address recipient = address(0xBEEF);
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("payBatchPadding"),
            _id("result"),
            registry.currentNullifierRoot(),
            _id("dupPayPadding"),
            _rootForFirst(_payee(recipient, payment0), bytes32(0))
        );
        submission.paymentCount = 1;
        submission.combinedBatchCommitment = _combined(
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
            submission.verifierKeyId,
            submission.claimCount,
            submission.paymentCount
        );
        registry.submitBatch(submission, hex"1234", _inputs(submission));
        require(
            !registry.checkPaymentInBatch(_id("payBatchPadding"), bytes32(0), _pathForSecond(_payee(recipient, payment0)), 1),
            "padding payment leaf verified past payment count"
        );
    }

    function testPaymentRecordNotInBatchRejects() public {
        bytes32 payment0 = _id("payment-1");
        bytes32 payment1 = _id("payment-2");
        address authorized = address(0xBEEF);
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("payBatchB"),
            _id("result"),
            registry.currentNullifierRoot(),
            _id("dupPayB"),
            _rootForFirst(_payee(authorized, payment0), _payee(address(0xCAFE), payment1))
        );
        registry.submitBatch(submission, hex"1234", _inputs(submission));
        BatchPaymentTrigger trigger = new BatchPaymentTrigger(address(this), new RecordingSettlementBridge(), registry);

        address[] memory recipients = new address[](1);
        recipients[0] = address(0xBAD);
        bytes32[] memory records = new bytes32[](1);
        records[0] = _id("payment-quarantine");
        bytes32[][] memory paths = new bytes32[][](1);
        paths[0] = _pathForFirst(_payee(address(0xCAFE), payment1));
        uint256[] memory indexes = new uint256[](1);

        try trigger.submitBatchForPayment(_id("payBatchB"), recipients, records, paths, indexes) {
            revert("expected payment-root rejection");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment not in batch")), "wrong payment rejection");
        }
    }

    function testDoublePaymentRejects() public {
        bytes32 payment0 = _id("payment-1");
        bytes32 payment1 = _id("payment-2");
        address recipient = address(0xBEEF);
        BatchClaimsRegistry registry = _registry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submissionWithPayment(
            _id("payBatchC"),
            _id("result"),
            registry.currentNullifierRoot(),
            _id("dupPayC"),
            _rootForFirst(_payee(recipient, payment0), _payee(address(0xCAFE), payment1))
        );
        registry.submitBatch(submission, hex"1234", _inputs(submission));
        BatchPaymentTrigger trigger = new BatchPaymentTrigger(address(this), new RecordingSettlementBridge(), registry);
        bytes32[] memory path = _pathForFirst(_payee(address(0xCAFE), payment1));
        trigger.triggerProviderNetSettlement(_id("payBatchC"), recipient, payment0, path, 0);
        try trigger.triggerProviderNetSettlement(_id("payBatchC"), recipient, payment0, path, 0) {
            revert("expected duplicate payment rejection");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment already submitted")), "wrong duplicate payment reason");
        }
    }
}
