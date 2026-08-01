// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./INativeStarkVerifier.sol";

contract StarkBatchSettlement {
    // Poseidon empty root of the depth-32 two-sentinel indexed nullifier tree
    // produced by app.batch.nullifier.IndexedNullifierTree().
    bytes32 public constant CANONICAL_NULLIFIER_GENESIS =
        0x05a71994342ca7f0dd4c33697abd6455bd77822b175cb0b42fe7ba9f8f4a528f;
    bytes32 public constant RULESET_ROOT_ID = keccak256("rulesetRoot");
    bytes32 public constant POLICY_ROOT_ID = keccak256("policyRoot");
    bytes32 public constant CLAIM_SOURCE_ROOT_ID = keccak256("claimSourceRoot");
    bytes32 public constant ORACLE_FACTS_ROOT_ID = keccak256("oracleFactsRoot");
    uint256 public constant MINIMUM_TIMELOCK_SECONDS = 259200;

    struct StarkBatchSubmission {
        bytes32 batchId;
        bytes32 nullifierRootBefore;
        bytes32 nullifierRootAfter;
        bytes32 claimRoot;
        bytes32 resultRoot;
        bytes32 paymentRoot;
        bytes32 batchNullifierCommitment;
        bytes32 rulesetRoot;
        bytes32 claimSourceRoot;
        bytes32 oracleFactsRoot;
        bytes32 oracleSignerRoot;
        bytes32 policyRoot;
        bytes32 addressBookRoot;
        bytes32 dataAvailabilityRoot;
        bytes32 encryptedClaimDataRoot;
        bytes32 combinedBatchCommitment;
        bytes32 accumulatorRootBefore;
        bytes32 accumulatorRootAfter;
        bytes32 valueConservationCommitment;
        uint256 approvedAmountCents;
        uint256 paymentAmountCents;
    }

    struct StoredBatch {
        bool exists;
        bytes32 nullifierRootBefore;
        bytes32 nullifierRootAfter;
        bytes32 rulesetRoot;
        bytes32 oracleFactsRoot;
        bytes32 policyRoot;
        bytes32 combinedBatchCommitment;
        bytes32 accumulatorRootBefore;
        bytes32 accumulatorRootAfter;
        bytes32 dataAvailabilityRoot;
        bytes32 encryptedClaimDataRoot;
        uint256 approvedAmountCents;
        uint256 paymentAmountCents;
        address submitter;
    }

    struct GovernedRootConfig {
        bytes32 rulesetRoot;
        bytes32 policyRoot;
        bytes32 claimSourceRoot;
        bytes32 oracleFactsRoot;
    }

    struct RootUpdateProposal {
        bytes32 rootId;
        bytes32 oldRoot;
        bytes32 newRoot;
        bytes32 reasonHash;
        uint256 proposalTime;
        uint256 effectiveTime;
        uint256 approvalCount;
        bool exists;
        bool activated;
    }

    INativeStarkVerifier public immutable verifier;
    bytes32 public immutable pinnedVerifierArtifactHash;
    uint256 public immutable governanceThreshold;
    uint256 public immutable governanceTimelockSeconds;
    bytes32 public liveNullifierRoot;
    bytes32 public governedRulesetRoot;
    bytes32 public governedPolicyRoot;
    bytes32 public governedClaimSourceRoot;
    bytes32 public governedOracleFactsRoot;
    uint256 public rootProposalNonce;
    mapping(bytes32 => StoredBatch) public batches;
    mapping(bytes32 => bytes) internal encryptedClaimData;
    mapping(address => bool) public governanceSigners;
    mapping(bytes32 => RootUpdateProposal) public rootUpdateProposals;
    mapping(bytes32 => mapping(address => bool)) public rootUpdateApprovals;

    event StarkBatchSubmitted(
        bytes32 indexed batchId,
        bytes32 indexed nullifierRootBefore,
        bytes32 indexed nullifierRootAfter,
        bytes32 dataAvailabilityRoot,
        bytes32 encryptedClaimDataRoot,
        uint256 approvedAmountCents,
        uint256 paymentAmountCents
    );
    event RootUpdateProposed(
        bytes32 indexed proposalId,
        bytes32 indexed rootId,
        bytes32 oldRoot,
        bytes32 newRoot,
        bytes32 reasonHash,
        uint256 effectiveTime,
        address indexed proposer
    );
    event RootUpdateApproved(bytes32 indexed proposalId, address indexed signer, uint256 approvalCount);
    event RootUpdateActivated(
        bytes32 indexed proposalId,
        bytes32 indexed rootId,
        bytes32 oldRoot,
        bytes32 newRoot,
        bytes32 reasonHash,
        address indexed activator
    );

    constructor(
        INativeStarkVerifier verifier_,
        bytes32 pinnedVerifierArtifactHash_,
        GovernedRootConfig memory governedRoots_,
        address[] memory governanceSigners_,
        uint256 governanceThreshold_,
        uint256 governanceTimelockSeconds_
    ) {
        require(address(verifier_) != address(0), "verifier zero");
        require(pinnedVerifierArtifactHash_ != bytes32(0), "artifact zero");
        require(!verifier_.isLegacyProofWrapper(), "legacy proof wrapper forbidden");
        require(verifier_.verifierArtifactHash() == pinnedVerifierArtifactHash_, "artifact mismatch");
        require(governedRoots_.rulesetRoot != bytes32(0), "governed ruleset zero");
        require(governedRoots_.policyRoot != bytes32(0), "governed policy zero");
        require(governedRoots_.claimSourceRoot != bytes32(0), "governed claim source zero");
        require(governedRoots_.oracleFactsRoot != bytes32(0), "governed oracle facts zero");
        require(governanceThreshold_ != 0, "threshold zero");
        require(governanceThreshold_ <= governanceSigners_.length, "threshold above signer count");
        require(governanceTimelockSeconds_ >= MINIMUM_TIMELOCK_SECONDS, "timelock below minimum");
        verifier = verifier_;
        pinnedVerifierArtifactHash = pinnedVerifierArtifactHash_;
        governedRulesetRoot = governedRoots_.rulesetRoot;
        governedPolicyRoot = governedRoots_.policyRoot;
        governedClaimSourceRoot = governedRoots_.claimSourceRoot;
        governedOracleFactsRoot = governedRoots_.oracleFactsRoot;
        governanceThreshold = governanceThreshold_;
        governanceTimelockSeconds = governanceTimelockSeconds_;
        for (uint256 i = 0; i < governanceSigners_.length; i++) {
            address signer = governanceSigners_[i];
            require(signer != address(0), "signer zero");
            require(!governanceSigners[signer], "duplicate signer");
            governanceSigners[signer] = true;
        }
        liveNullifierRoot = CANONICAL_NULLIFIER_GENESIS;
    }

    function proposeRootUpdate(bytes32 rootId, bytes32 newRoot, bytes32 reasonHash)
        external
        returns (bytes32 proposalId)
    {
        require(governanceSigners[msg.sender], "not governance signer");
        require(newRoot != bytes32(0), "new root zero");
        bytes32 oldRoot = _activeRoot(rootId);
        uint256 effectiveTime = block.timestamp + governanceTimelockSeconds;
        proposalId = keccak256(abi.encode(rootId, oldRoot, newRoot, reasonHash, block.timestamp, rootProposalNonce));
        rootProposalNonce++;
        rootUpdateProposals[proposalId] = RootUpdateProposal({
            rootId: rootId,
            oldRoot: oldRoot,
            newRoot: newRoot,
            reasonHash: reasonHash,
            proposalTime: block.timestamp,
            effectiveTime: effectiveTime,
            approvalCount: 0,
            exists: true,
            activated: false
        });
        emit RootUpdateProposed(proposalId, rootId, oldRoot, newRoot, reasonHash, effectiveTime, msg.sender);
    }

    function approve(bytes32 proposalId) external {
        require(governanceSigners[msg.sender], "not governance signer");
        RootUpdateProposal storage proposal = rootUpdateProposals[proposalId];
        require(proposal.exists, "proposal missing");
        require(!proposal.activated, "proposal activated");
        require(!rootUpdateApprovals[proposalId][msg.sender], "already approved");
        rootUpdateApprovals[proposalId][msg.sender] = true;
        proposal.approvalCount++;
        emit RootUpdateApproved(proposalId, msg.sender, proposal.approvalCount);
    }

    function activate(bytes32 proposalId) external {
        RootUpdateProposal storage proposal = rootUpdateProposals[proposalId];
        require(proposal.exists, "proposal missing");
        require(!proposal.activated, "proposal activated");
        require(proposal.approvalCount >= governanceThreshold, "threshold not met");
        require(block.timestamp >= proposal.effectiveTime, "timelock not elapsed");
        require(_activeRoot(proposal.rootId) == proposal.oldRoot, "proposal root stale");
        proposal.activated = true;
        _setActiveRoot(proposal.rootId, proposal.newRoot);
        emit RootUpdateActivated(
            proposalId, proposal.rootId, proposal.oldRoot, proposal.newRoot, proposal.reasonHash, msg.sender
        );
    }

    function submitBatch(
        StarkBatchSubmission calldata submission,
        bytes calldata starkProof,
        bytes32[] calldata publicInputs,
        bytes calldata encryptedPayload
    ) external {
        require(governanceSigners[msg.sender], "not governance signer");
        require(!batches[submission.batchId].exists, "batch exists");
        require(submission.nullifierRootBefore == liveNullifierRoot, "stale nullifier root");
        require(submission.nullifierRootAfter != bytes32(0), "nullifier root zero");
        require(submission.nullifierRootAfter != submission.nullifierRootBefore, "nullifier root unchanged");
        require(submission.batchNullifierCommitment != bytes32(0), "batch nullifier zero");
        require(submission.rulesetRoot != bytes32(0), "ruleset root zero");
        require(submission.oracleFactsRoot != bytes32(0), "oracle facts root zero");
        require(submission.oracleSignerRoot != bytes32(0), "oracle signer root zero");
        require(submission.policyRoot != bytes32(0), "policy root zero");
        require(submission.addressBookRoot != bytes32(0), "address book zero");
        require(submission.combinedBatchCommitment != bytes32(0), "combined zero");
        require(submission.accumulatorRootBefore != bytes32(0), "accumulator before zero");
        require(submission.accumulatorRootAfter != bytes32(0), "accumulator after zero");
        require(submission.dataAvailabilityRoot != bytes32(0), "DA root zero");
        require(submission.encryptedClaimDataRoot != bytes32(0), "encrypted root zero");
        require(submission.valueConservationCommitment != bytes32(0), "value conservation zero");
        require(submission.paymentAmountCents <= submission.approvedAmountCents, "value conservation");
        require(submission.rulesetRoot == governedRulesetRoot, "ruleset root not governed");
        require(submission.policyRoot == governedPolicyRoot, "policy root not governed");
        require(submission.claimSourceRoot == governedClaimSourceRoot, "claim source root not governed");
        require(submission.oracleFactsRoot == governedOracleFactsRoot, "oracle facts root not governed");
        require(encryptedPayload.length > 0, "encrypted payload empty");
        require(sha256(encryptedPayload) == submission.encryptedClaimDataRoot, "encrypted root mismatch");
        require(_publicInputsMatch(submission, publicInputs), "public inputs mismatch");
        require(verifier.verifierArtifactHash() == pinnedVerifierArtifactHash, "artifact changed");
        require(!verifier.isLegacyProofWrapper(), "legacy proof wrapper forbidden");
        require(verifier.verifyStark(starkProof, publicInputs), "STARK verify failed");

        batches[submission.batchId] = StoredBatch({
            exists: true,
            nullifierRootBefore: submission.nullifierRootBefore,
            nullifierRootAfter: submission.nullifierRootAfter,
            rulesetRoot: submission.rulesetRoot,
            oracleFactsRoot: submission.oracleFactsRoot,
            policyRoot: submission.policyRoot,
            combinedBatchCommitment: submission.combinedBatchCommitment,
            accumulatorRootBefore: submission.accumulatorRootBefore,
            accumulatorRootAfter: submission.accumulatorRootAfter,
            dataAvailabilityRoot: submission.dataAvailabilityRoot,
            encryptedClaimDataRoot: submission.encryptedClaimDataRoot,
            approvedAmountCents: submission.approvedAmountCents,
            paymentAmountCents: submission.paymentAmountCents,
            submitter: msg.sender
        });
        encryptedClaimData[submission.batchId] = encryptedPayload;
        liveNullifierRoot = submission.nullifierRootAfter;
        emit StarkBatchSubmitted(
            submission.batchId,
            submission.nullifierRootBefore,
            submission.nullifierRootAfter,
            submission.dataAvailabilityRoot,
            submission.encryptedClaimDataRoot,
            submission.approvedAmountCents,
            submission.paymentAmountCents
        );
    }

    function encryptedClaimDataHash(bytes32 batchId) external view returns (bytes32) {
        require(batches[batchId].exists, "batch missing");
        return sha256(encryptedClaimData[batchId]);
    }

    function _activeRoot(bytes32 rootId) internal view returns (bytes32) {
        if (rootId == RULESET_ROOT_ID) {
            return governedRulesetRoot;
        }
        if (rootId == POLICY_ROOT_ID) {
            return governedPolicyRoot;
        }
        if (rootId == CLAIM_SOURCE_ROOT_ID) {
            return governedClaimSourceRoot;
        }
        if (rootId == ORACLE_FACTS_ROOT_ID) {
            return governedOracleFactsRoot;
        }
        revert("unknown root id");
    }

    function _setActiveRoot(bytes32 rootId, bytes32 newRoot) internal {
        if (rootId == RULESET_ROOT_ID) {
            governedRulesetRoot = newRoot;
            return;
        }
        if (rootId == POLICY_ROOT_ID) {
            governedPolicyRoot = newRoot;
            return;
        }
        if (rootId == CLAIM_SOURCE_ROOT_ID) {
            governedClaimSourceRoot = newRoot;
            return;
        }
        if (rootId == ORACLE_FACTS_ROOT_ID) {
            governedOracleFactsRoot = newRoot;
            return;
        }
        revert("unknown root id");
    }

    function _publicInputsMatch(StarkBatchSubmission calldata submission, bytes32[] calldata publicInputs)
        internal
        pure
        returns (bool)
    {
        return publicInputs.length == 21 && publicInputs[0] == submission.batchId
            && publicInputs[1] == submission.nullifierRootBefore && publicInputs[2] == submission.nullifierRootAfter
            && publicInputs[3] == submission.claimRoot && publicInputs[4] == submission.resultRoot
            && publicInputs[5] == submission.paymentRoot && publicInputs[6] == submission.batchNullifierCommitment
            && publicInputs[7] == submission.rulesetRoot && publicInputs[8] == submission.claimSourceRoot
            && publicInputs[9] == submission.oracleFactsRoot && publicInputs[10] == submission.oracleSignerRoot
            && publicInputs[11] == submission.policyRoot && publicInputs[12] == submission.addressBookRoot
            && publicInputs[13] == submission.dataAvailabilityRoot
            && publicInputs[14] == submission.encryptedClaimDataRoot
            && publicInputs[15] == submission.combinedBatchCommitment
            && publicInputs[16] == submission.accumulatorRootBefore
            && publicInputs[17] == submission.accumulatorRootAfter
            && publicInputs[18] == submission.valueConservationCommitment
            && publicInputs[19] == bytes32(submission.approvedAmountCents)
            && publicInputs[20] == bytes32(submission.paymentAmountCents);
    }
}
