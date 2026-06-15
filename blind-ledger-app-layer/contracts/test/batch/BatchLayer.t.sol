// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../src/batch/BatchClaimsRegistry.sol";
import "../../src/batch/BatchGroth16VerifierAdapter.sol";
import "../../src/batch/BatchPaymentTrigger.sol";
import "../../src/batch/BatchStubVerifier.sol";
import "../../src/batch/IBatchVerifier.sol";
import "../../src/GeneratedClaimVerifier.sol";

contract AcceptingBatchVerifier is IBatchVerifier {
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
    bytes32 internal constant CHECKER_ID = keccak256("RISC_ZERO_WRAPPED_STUB_V1");
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
        bytes32 verifierKeyId,
        uint256 claimCount,
        uint256 paymentCount
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(batchId, claimRoot, resultRoot, paymentRoot, duplicateBefore, duplicateAfter, batchNullifierCommitment, rulesetRoot, verifierKeyId, claimCount, paymentCount));
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

    function _approvedGroth16Proof() internal pure returns (bytes memory proof, bytes32[] memory publicInputs) {
        uint[2] memory pA;
        pA[0] = 0x06bd47dd43d8cbd711ca21fd7a98295a90af307e814fc19494939b68d9faef95;
        pA[1] = 0x2f34f3e3be84942f4c4af58113d628745497e843a6f8aa5799840af08c749425;

        uint[2][2] memory pB;
        pB[0][0] = 0x05f16ec6bc6fea20446486066afdcfdd32f29d4f575254eea8fe5172ea066742;
        pB[0][1] = 0x30083f0389bf3cbc9ca2231562ef120432cc405c8ad2bb15e83037c6866d48ce;
        pB[1][0] = 0x2bdd7b210e33166ca08569c4ed1bb8c66e74bfcd34497e072f8f6cb0a93d4d41;
        pB[1][1] = 0x156e2a6d1478b3a05b93707fa62f644239b0aa863f2b59c01ae61f196d4384f5;

        uint[2] memory pC;
        pC[0] = 0x04260819665f1301ec59b9b5b6da58854a6e9a8d1f36d1337e7a8ea932e178a6;
        pC[1] = 0x1842833093348c1aef9268bdf99d1f9727dbdb0f16aa306cf38b119c49686af7;

        proof = abi.encode(pA, pB, pC);
        publicInputs = new bytes32[](4);
        publicInputs[0] = 0x0476a2c5d0927d475d96528c6e5b72fc431c33d5c4e4fdc5c261d0460082abfa;
        publicInputs[1] = 0x1b3ec387939908d04d426b54d4abe3b055ff935ae37802d9d81cc552d03cd51d;
        publicInputs[2] = bytes32(uint256(1));
        publicInputs[3] = bytes32(uint256(0));
    }

    function _registry() internal returns (BatchClaimsRegistry registry) {
        registry = new BatchClaimsRegistry(address(this), CHECKER_ID, new AcceptingBatchVerifier(), true);
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
            _combined(batchId, claimRoot, resultRoot, paymentRoot, duplicateBefore, duplicateAfter, batchNullifierCommitment, rulesetRoot, CHECKER_ID, 2, 2),
            paymentRoot,
            rulesetRoot,
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

    function testStubVerifierRejectsByDefault() public {
        BatchClaimsRegistry registry = _failClosedRegistry();
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchStub"), _id("resultStub"), _id("dupStub"));
        try registry.submitBatch(submission, hex"1234", _inputs(submission)) {
            revert("fail-closed stub accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("batch check failed")), "wrong stub rejection");
        }
    }

    function testRealGroth16BatchAdapterRejectsGarbageAndBatchStatement() public {
        BatchGroth16VerifierAdapter adapter = new BatchGroth16VerifierAdapter(new Groth16Verifier());
        BatchClaimsRegistry.BatchSubmission memory submission = _submission(_id("batchRealReject"), _id("resultRealReject"), _id("dupRealReject"));
        require(!adapter.verifyBatch(hex"1234", _inputs(submission)), "garbage batch proof accepted");

        (bytes memory proof, bytes32[] memory publicInputs) = _approvedGroth16Proof();
        require(adapter.verifyBatch(proof, publicInputs), "known single-claim proof fixture should verify directly");
        publicInputs[2] = bytes32(uint256(0));
        require(!adapter.verifyBatch(proof, publicInputs), "tampered single-claim fixture accepted");
    }

    function testSingleClaimAdapterCannotBeRegisteredAsBatchChecker() public {
        BatchClaimsRegistry registry = _registry();
        BatchGroth16VerifierAdapter adapter = new BatchGroth16VerifierAdapter(new Groth16Verifier());
        try registry.setBatchChecker(keccak256("SINGLE_CLAIM_ADAPTER"), adapter) {
            revert("single-claim adapter registered as batch checker");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("not batch verifier")), "wrong adapter rejection");
        }
    }

    function testStubVerifierRejectedWithoutExplicitTestFlag() public {
        try new BatchClaimsRegistry(address(this), CHECKER_ID, new BatchStubVerifier(), false) {
            revert("test stub accepted without test flag");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("test verifier disabled")), "wrong stub-prod rejection");
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
        require(combinedBatchCommitment == _combined(_id("batchA"), _id("claimRoot"), resultRoot, _id("paymentRoot"), GENESIS, duplicateAfter, _id("batchNullifierCommitment"), _id("rulesetRoot"), CHECKER_ID, 2, 2), "combined mismatch");
        require(paymentRoot == _id("paymentRoot"), "payment record mismatch");
        require(rulesetRoot == _id("rulesetRoot"), "ruleset mismatch");
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
        bytes32[] memory tooLong = new bytes32[](12);
        bytes32[] memory honest = _inputs(submission);
        for (uint256 i = 0; i < honest.length; i++) {
            tooLong[i] = honest[i];
        }
        tooLong[11] = _id("ignored-before-fix");
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
        BatchPaymentTrigger trigger = new BatchPaymentTrigger(address(this), new CPNAdapterStub(), registry);

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
        BatchPaymentTrigger trigger = new BatchPaymentTrigger(address(this), new CPNAdapterStub(), registry);

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
        BatchPaymentTrigger trigger = new BatchPaymentTrigger(address(this), new CPNAdapterStub(), registry);
        bytes32[] memory path = _pathForFirst(_payee(address(0xCAFE), payment1));
        trigger.triggerProviderNetSettlement(_id("payBatchC"), recipient, payment0, path, 0);
        try trigger.triggerProviderNetSettlement(_id("payBatchC"), recipient, payment0, path, 0) {
            revert("expected duplicate payment rejection");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("payment already submitted")), "wrong duplicate payment reason");
        }
    }
}
