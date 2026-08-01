// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IBlindLedgerClaimVerifierV2.sol";

contract StarkBatchSettlementV2 {
    bytes32 public constant PROTOCOL_VERSION = bytes32(uint256(2));
    uint256 public constant STARK_FIELD_MODULUS = 0x0800000000000011000000000000000000000000000000000000000000000001;

    struct GovernedRoots {
        bytes32 claimSourceRoot;
        bytes32 oracleFactsRoot;
        bytes32 policyRoot;
        bytes32 rulesetRoot;
    }

    struct Submission {
        bytes32 protocolVersion;
        bytes32 settlementDomain;
        bytes32 batchNonce;
        bytes32 nullifierRootBefore;
        bytes32 nullifierRootAfter;
        bytes32 claimSourceRoot;
        bytes32 oracleFactsRoot;
        bytes32 policyRoot;
        bytes32 rulesetRoot;
        bytes32 opaqueBatchCommitment;
        bytes32 valueConservationCommitment;
        bytes32 settlementCommitment;
    }

    struct StoredBatch {
        bool exists;
        bytes32 nullifierRootBefore;
        bytes32 nullifierRootAfter;
        bytes32 opaqueBatchCommitment;
        bytes32 valueConservationCommitment;
        address submitter;
    }

    IBlindLedgerClaimVerifierV2 public immutable verifier;
    bytes32 public immutable pinnedVerifierArtifactHash;
    bytes32 public immutable pinnedStatementSchemaHash;
    bytes32 public immutable settlementDomain;
    bytes32 public liveNullifierRoot;
    GovernedRoots public governedRoots;
    mapping(address => bool) public authorizedSubmitters;
    mapping(bytes32 => bool) public consumedBatchNonces;
    mapping(bytes32 => StoredBatch) public batches;

    event PrivateBatchSettled(
        bytes32 indexed settlementCommitment, bytes32 indexed batchNonce, bytes32 indexed nullifierRootAfter
    );

    constructor(
        IBlindLedgerClaimVerifierV2 verifier_,
        bytes32 verifierArtifactHash_,
        bytes32 statementSchemaHash_,
        bytes32 settlementDomain_,
        bytes32 initialNullifierRoot_,
        GovernedRoots memory governedRoots_,
        address[] memory submitters_
    ) {
        require(address(verifier_) != address(0), "verifier zero");
        require(!verifier_.isTestVerifier(), "test verifier forbidden");
        require(verifierArtifactHash_ != bytes32(0), "artifact zero");
        require(statementSchemaHash_ != bytes32(0), "schema zero");
        require(verifier_.verifierArtifactHash() == verifierArtifactHash_, "artifact mismatch");
        require(verifier_.statementSchemaHash() == statementSchemaHash_, "schema mismatch");
        require(settlementDomain_ != bytes32(0), "domain zero");
        require(initialNullifierRoot_ != bytes32(0), "initial root zero");
        require(governedRoots_.claimSourceRoot != bytes32(0), "claim source zero");
        require(governedRoots_.oracleFactsRoot != bytes32(0), "oracle facts zero");
        require(governedRoots_.policyRoot != bytes32(0), "policy zero");
        require(governedRoots_.rulesetRoot != bytes32(0), "ruleset zero");
        require(submitters_.length != 0, "submitters empty");
        verifier = verifier_;
        pinnedVerifierArtifactHash = verifierArtifactHash_;
        pinnedStatementSchemaHash = statementSchemaHash_;
        settlementDomain = settlementDomain_;
        liveNullifierRoot = initialNullifierRoot_;
        governedRoots = governedRoots_;
        for (uint256 i = 0; i < submitters_.length; i++) {
            address submitter = submitters_[i];
            require(submitter != address(0), "submitter zero");
            require(!authorizedSubmitters[submitter], "duplicate submitter");
            authorizedSubmitters[submitter] = true;
        }
    }

    function submitPrivateBatch(Submission calldata submission, bytes calldata proof) external {
        require(authorizedSubmitters[msg.sender], "not authorized");
        require(submission.protocolVersion == PROTOCOL_VERSION, "protocol version");
        require(submission.settlementDomain == settlementDomain, "settlement domain");
        require(submission.batchNonce != bytes32(0), "batch nonce zero");
        require(!consumedBatchNonces[submission.batchNonce], "batch nonce consumed");
        require(!batches[submission.settlementCommitment].exists, "batch exists");
        require(submission.nullifierRootBefore == liveNullifierRoot, "stale nullifier root");
        require(submission.nullifierRootAfter != bytes32(0), "nullifier root zero");
        require(submission.nullifierRootAfter != submission.nullifierRootBefore, "nullifier root unchanged");
        require(submission.claimSourceRoot == governedRoots.claimSourceRoot, "claim source root");
        require(submission.oracleFactsRoot == governedRoots.oracleFactsRoot, "oracle facts root");
        require(submission.policyRoot == governedRoots.policyRoot, "policy root");
        require(submission.rulesetRoot == governedRoots.rulesetRoot, "ruleset root");
        require(submission.opaqueBatchCommitment != bytes32(0), "opaque batch zero");
        require(submission.valueConservationCommitment != bytes32(0), "value commitment zero");
        require(submission.settlementCommitment != bytes32(0), "settlement commitment zero");
        require(verifier.verifierArtifactHash() == pinnedVerifierArtifactHash, "artifact changed");
        require(verifier.statementSchemaHash() == pinnedStatementSchemaHash, "schema changed");

        bytes32[12] memory outputs = _publicOutputs(submission);
        _requireCanonicalFields(outputs);
        require(verifier.verifyClaimProof(proof, outputs), "claim proof rejected");

        consumedBatchNonces[submission.batchNonce] = true;
        batches[submission.settlementCommitment] = StoredBatch({
            exists: true,
            nullifierRootBefore: submission.nullifierRootBefore,
            nullifierRootAfter: submission.nullifierRootAfter,
            opaqueBatchCommitment: submission.opaqueBatchCommitment,
            valueConservationCommitment: submission.valueConservationCommitment,
            submitter: msg.sender
        });
        liveNullifierRoot = submission.nullifierRootAfter;
        emit PrivateBatchSettled(submission.settlementCommitment, submission.batchNonce, submission.nullifierRootAfter);
    }

    function publicOutputs(Submission calldata submission) external pure returns (bytes32[12] memory) {
        return _publicOutputs(submission);
    }

    function _publicOutputs(Submission calldata submission) internal pure returns (bytes32[12] memory outputs) {
        outputs[0] = submission.protocolVersion;
        outputs[1] = submission.settlementDomain;
        outputs[2] = submission.batchNonce;
        outputs[3] = submission.nullifierRootBefore;
        outputs[4] = submission.nullifierRootAfter;
        outputs[5] = submission.claimSourceRoot;
        outputs[6] = submission.oracleFactsRoot;
        outputs[7] = submission.policyRoot;
        outputs[8] = submission.rulesetRoot;
        outputs[9] = submission.opaqueBatchCommitment;
        outputs[10] = submission.valueConservationCommitment;
        outputs[11] = submission.settlementCommitment;
    }

    function _requireCanonicalFields(bytes32[12] memory outputs) internal pure {
        for (uint256 i = 0; i < outputs.length; i++) {
            require(uint256(outputs[i]) < STARK_FIELD_MODULUS, "noncanonical Stark field");
        }
    }
}
