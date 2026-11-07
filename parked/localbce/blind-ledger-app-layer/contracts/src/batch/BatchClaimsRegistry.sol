// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IBatchVerifier.sol";

contract BatchClaimsRegistry {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    uint256 public constant MERKLE_DEPTH = 10;
    uint256 public constant MERKLE_CAPACITY = 1 << MERKLE_DEPTH;
    uint256 public constant DEFAULT_BATCH_PUBLIC_INPUT_LENGTH = 11;
    bytes32 public constant CANONICAL_NULLIFIER_GENESIS = 0x111df93687d686f128495834e87222c67d3ec42ae5d128db3ad65e8123b11f2c;

    struct BatchResult {
        bool exists;
        bytes32 claimRoot;
        bytes32 resultRoot;
        bytes32 nullifierRootBefore;
        bytes32 nullifierRootAfter;
        bytes32 batchNullifierCommitment;
        bytes32 combinedBatchCommitment;
        bytes32 paymentRoot;
        bytes32 rulesetRoot;
        bytes32 verifierKeyId;
        uint256 claimCount;
        uint256 paymentCount;
        address submitter;
        uint256 timestamp;
    }

    struct BatchSubmission {
        bytes32 batchId;
        bytes32 claimRoot;
        bytes32 resultRoot;
        bytes32 nullifierRootBefore;
        bytes32 nullifierRootAfter;
        bytes32 batchNullifierCommitment;
        bytes32 combinedBatchCommitment;
        bytes32 paymentRoot;
        bytes32 rulesetRoot;
        bytes32 verifierKeyId;
        uint256 claimCount;
        uint256 paymentCount;
    }

    mapping(bytes32 => BatchResult) public batches;
    mapping(bytes32 => bool) public usedNullifierRoots;
    mapping(bytes32 => bool) public usedCombinedCommitments;
    mapping(bytes32 => bool) public usedPaymentRoots;
    mapping(bytes32 => bool) public approvedRulesetRoots;
    bytes32 public currentNullifierRoot;
    bytes32 public immutable productionVerifierKeyId;
    bool public immutable allowTestVerifiers;
    uint256 public submittedBatchCount;
    uint256 public adminCount;

    mapping(bytes32 => IBatchVerifier) internal batchCheckers;
    mapping(bytes32 => uint256) public publicInputLengths;
    mapping(bytes32 => mapping(address => bool)) internal roles;

    event BatchSubmitted(
        bytes32 indexed batchId,
        bytes32 claimRoot,
        bytes32 resultRoot,
        bytes32 nullifierRootAfter,
        bytes32 paymentRoot,
        uint256 claimCount,
        uint256 paymentCount,
        address indexed submitter
    );
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    event BatchCheckerSet(bytes32 indexed verifierKeyId, address indexed checker);
    event RulesetRootApproved(bytes32 indexed rulesetRoot, bool approved);
    event NullifierRootBootstrapped(bytes32 indexed nullifierRoot);
    event NullifierRootAdvanced(bytes32 indexed batchId, bytes32 indexed rootBefore, bytes32 indexed rootAfter);

    constructor(address initialAdmin, bytes32 defaultVerifierKeyId, IBatchVerifier defaultChecker, bool allowTestVerifiers_) {
        require(initialAdmin != address(0), "admin zero");
        require(address(defaultChecker) != address(0), "checker zero");
        roles[ADMIN_ROLE][initialAdmin] = true;
        roles[OPERATOR_ROLE][initialAdmin] = true;
        roles[AUDITOR_ROLE][initialAdmin] = true;
        adminCount = 1;
        productionVerifierKeyId = defaultVerifierKeyId;
        allowTestVerifiers = allowTestVerifiers_;
        currentNullifierRoot = CANONICAL_NULLIFIER_GENESIS;
        usedNullifierRoots[CANONICAL_NULLIFIER_GENESIS] = true;
        _setBatchChecker(defaultVerifierKeyId, defaultChecker, DEFAULT_BATCH_PUBLIC_INPUT_LENGTH);
        emit RoleGranted(ADMIN_ROLE, initialAdmin);
        emit RoleGranted(OPERATOR_ROLE, initialAdmin);
        emit RoleGranted(AUDITOR_ROLE, initialAdmin);
        emit NullifierRootBootstrapped(CANONICAL_NULLIFIER_GENESIS);
    }

    modifier onlyAdmin() {
        require(roles[ADMIN_ROLE][msg.sender], "not admin");
        _;
    }

    modifier onlyBatchSubmitter() {
        require(canSubmitBatch(msg.sender), "not authorized");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyAdmin {
        require(role == ADMIN_ROLE || role == OPERATOR_ROLE || role == AUDITOR_ROLE, "unknown role");
        require(account != address(0), "account zero");
        if (role == ADMIN_ROLE && !roles[ADMIN_ROLE][account]) {
            adminCount += 1;
        }
        roles[role][account] = true;
        emit RoleGranted(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyAdmin {
        require(role == ADMIN_ROLE || role == OPERATOR_ROLE || role == AUDITOR_ROLE, "unknown role");
        if (role == ADMIN_ROLE && roles[ADMIN_ROLE][account]) {
            require(adminCount > 1, "last admin");
            adminCount -= 1;
        }
        roles[role][account] = false;
        emit RoleRevoked(role, account);
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return roles[role][account];
    }

    function canSubmitBatch(address account) public view returns (bool) {
        return roles[ADMIN_ROLE][account] || roles[OPERATOR_ROLE][account];
    }

    function canReadAppeals(address account) external view returns (bool) {
        return canSubmitBatch(account) || roles[AUDITOR_ROLE][account];
    }

    function setBatchChecker(bytes32 verifierKeyId, IBatchVerifier checker) external onlyAdmin {
        _setBatchChecker(verifierKeyId, checker, DEFAULT_BATCH_PUBLIC_INPUT_LENGTH);
    }

    function setBatchCheckerWithInputLength(bytes32 verifierKeyId, IBatchVerifier checker, uint256 publicInputLength) external onlyAdmin {
        _setBatchChecker(verifierKeyId, checker, publicInputLength);
    }

    function _setBatchChecker(bytes32 verifierKeyId, IBatchVerifier checker, uint256 publicInputLength) internal {
        require(verifierKeyId != bytes32(0), "checker id zero");
        require(address(checker) != address(0), "checker zero");
        require(address(batchCheckers[verifierKeyId]) == address(0), "checker exists");
        require(checker.isBatchVerifier(), "not batch verifier");
        require(!checker.isTestVerifier() || allowTestVerifiers, "test verifier disabled");
        require(publicInputLength > 0, "input length zero");
        require(publicInputLength >= DEFAULT_BATCH_PUBLIC_INPUT_LENGTH, "input length too short");
        uint256 expectedLength = checker.batchPublicInputLength();
        require(expectedLength > 0, "input length zero");
        require(expectedLength >= DEFAULT_BATCH_PUBLIC_INPUT_LENGTH, "input length too short");
        require(publicInputLength == expectedLength, "input length mismatch");
        batchCheckers[verifierKeyId] = checker;
        publicInputLengths[verifierKeyId] = expectedLength;
        emit BatchCheckerSet(verifierKeyId, address(checker));
    }

    function setRulesetApproved(bytes32 rulesetRoot, bool approved) external onlyAdmin {
        require(rulesetRoot != bytes32(0), "ruleset zero");
        approvedRulesetRoots[rulesetRoot] = approved;
        emit RulesetRootApproved(rulesetRoot, approved);
    }

    function bootstrapNullifierRoot(bytes32 initialRoot) external onlyAdmin {
        require(submittedBatchCount == 0, "batches exist");
        require(initialRoot == CANONICAL_NULLIFIER_GENESIS, "noncanonical genesis");
        require(currentNullifierRoot == CANONICAL_NULLIFIER_GENESIS, "genesis locked");
        emit NullifierRootBootstrapped(CANONICAL_NULLIFIER_GENESIS);
    }

    function submitBatch(
        BatchSubmission calldata submission,
        bytes calldata batchAttestation,
        bytes32[] calldata batchInputs
    ) external onlyBatchSubmitter {
        require(!batches[submission.batchId].exists, "batch exists");
        require(submission.nullifierRootBefore == currentNullifierRoot, "stale nullifier root");
        require(!usedCombinedCommitments[submission.combinedBatchCommitment], "combined commitment used");
        if (submission.paymentCount > 0) {
            require(submission.nullifierRootAfter != submission.nullifierRootBefore, "payment requires nullifier advance");
            require(submission.paymentRoot != bytes32(0), "payment root zero");
            require(!usedPaymentRoots[submission.paymentRoot], "payment root used");
        }
        if (submission.nullifierRootAfter != submission.nullifierRootBefore) {
            require(!usedNullifierRoots[submission.nullifierRootAfter], "duplicate check record used");
        }
        require(submission.claimCount > 0, "empty batch");
        require(submission.claimCount <= MERKLE_CAPACITY, "claim count exceeds capacity");
        require(submission.paymentCount <= submission.claimCount, "payment count exceeds claim count");
        require(approvedRulesetRoots[submission.rulesetRoot], "ruleset not approved");
        require(submission.combinedBatchCommitment == computeCombinedBatchCommitment(submission), "combined commitment mismatch");
        require(_batchInputsMatch(submission, batchInputs), "batch inputs mismatch");
        require(address(batchCheckers[submission.verifierKeyId]) != address(0), "checker missing");
        require(batchCheckers[submission.verifierKeyId].verifyBatch(batchAttestation, batchInputs), "batch check failed");

        BatchResult storage stored = batches[submission.batchId];
        stored.exists = true;
        stored.claimRoot = submission.claimRoot;
        stored.resultRoot = submission.resultRoot;
        stored.nullifierRootBefore = submission.nullifierRootBefore;
        stored.nullifierRootAfter = submission.nullifierRootAfter;
        stored.batchNullifierCommitment = submission.batchNullifierCommitment;
        stored.combinedBatchCommitment = submission.combinedBatchCommitment;
        stored.paymentRoot = submission.paymentRoot;
        stored.rulesetRoot = submission.rulesetRoot;
        stored.verifierKeyId = submission.verifierKeyId;
        stored.claimCount = submission.claimCount;
        stored.paymentCount = submission.paymentCount;
        stored.submitter = msg.sender;
        stored.timestamp = block.timestamp;
        if (submission.nullifierRootAfter != submission.nullifierRootBefore) {
            usedNullifierRoots[submission.nullifierRootAfter] = true;
        }
        usedCombinedCommitments[submission.combinedBatchCommitment] = true;
        if (submission.paymentCount > 0) {
            usedPaymentRoots[submission.paymentRoot] = true;
        }
        currentNullifierRoot = submission.nullifierRootAfter;
        submittedBatchCount += 1;
        emit NullifierRootAdvanced(submission.batchId, submission.nullifierRootBefore, submission.nullifierRootAfter);
        emit BatchSubmitted(
            submission.batchId,
            submission.claimRoot,
            submission.resultRoot,
            submission.nullifierRootAfter,
            submission.paymentRoot,
            submission.claimCount,
            submission.paymentCount,
            msg.sender
        );
    }

    function checkClaimInBatch(
        bytes32 batchId,
        bytes32 adjudicationRecord,
        bytes32[] calldata recordPath,
        uint256 recordIndex
    ) external view returns (bool) {
        if (!batches[batchId].exists) {
            return false;
        }
        BatchResult storage batch = batches[batchId];
        if (recordIndex >= batch.claimCount) {
            return false;
        }
        return _verifyRecord(batch.resultRoot, adjudicationRecord, recordPath, recordIndex);
    }

    function verifyClaimInBatch(
        bytes32 batchId,
        bytes32 resultLeaf,
        bytes32[] calldata merklePath,
        uint256 leafIndex
    ) external view returns (bool) {
        if (!batches[batchId].exists) {
            return false;
        }
        BatchResult storage batch = batches[batchId];
        if (leafIndex >= batch.claimCount) {
            return false;
        }
        return _verifyRecord(batch.resultRoot, resultLeaf, merklePath, leafIndex);
    }

    function checkPaymentInBatch(
        bytes32 batchId,
        bytes32 paymentRecord,
        bytes32[] calldata recordPath,
        uint256 recordIndex
    ) external view returns (bool) {
        if (!batches[batchId].exists) {
            return false;
        }
        BatchResult storage batch = batches[batchId];
        if (recordIndex >= batch.paymentCount) {
            return false;
        }
        return _verifyRecord(batch.paymentRoot, paymentRecord, recordPath, recordIndex);
    }

    function computeCombinedBatchCommitment(BatchSubmission calldata submission) public pure returns (bytes32) {
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
                submission.verifierKeyId,
                submission.claimCount,
                submission.paymentCount
            )
        );
    }

    function _batchInputsMatch(BatchSubmission calldata submission, bytes32[] calldata batchInputs) internal view returns (bool) {
        if (batchInputs.length < DEFAULT_BATCH_PUBLIC_INPUT_LENGTH) {
            return false;
        }
        return batchInputs.length == publicInputLengths[submission.verifierKeyId]
            && batchInputs[0] == submission.claimRoot
            && batchInputs[1] == submission.resultRoot
            && batchInputs[2] == submission.paymentRoot
            && batchInputs[3] == submission.nullifierRootBefore
            && batchInputs[4] == submission.nullifierRootAfter
            && batchInputs[5] == submission.batchNullifierCommitment
            && batchInputs[6] == submission.rulesetRoot
            && batchInputs[7] == submission.combinedBatchCommitment
            && batchInputs[8] == submission.verifierKeyId
            && batchInputs[9] == bytes32(submission.claimCount)
            && batchInputs[10] == bytes32(submission.paymentCount);
    }

    function _verifyRecord(
        bytes32 expectedRoot,
        bytes32 leaf,
        bytes32[] calldata path,
        uint256 index
    ) internal pure returns (bool) {
        if (path.length != MERKLE_DEPTH || index >= MERKLE_CAPACITY) {
            return false;
        }
        bytes32 computed = leaf;
        for (uint256 i = 0; i < path.length; i++) {
            if (index % 2 == 0) {
                computed = sha256(abi.encodePacked(computed, path[i]));
            } else {
                computed = sha256(abi.encodePacked(path[i], computed));
            }
            index = index / 2;
        }
        return computed == expectedRoot;
    }
}
