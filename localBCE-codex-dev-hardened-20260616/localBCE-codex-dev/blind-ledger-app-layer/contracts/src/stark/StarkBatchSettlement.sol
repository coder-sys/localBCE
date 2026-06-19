// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./INativeStarkVerifier.sol";

contract StarkBatchSettlement {
    bytes32 public constant CANONICAL_NULLIFIER_GENESIS =
        0x111df93687d686f128495834e87222c67d3ec42ae5d128db3ad65e8123b11f2c;

    struct StarkBatchSubmission {
        bytes32 batchId;
        bytes32 nullifierRootBefore;
        bytes32 nullifierRootAfter;
        bytes32 claimRoot;
        bytes32 resultRoot;
        bytes32 paymentRoot;
        bytes32 dataAvailabilityRoot;
        bytes32 encryptedClaimDataRoot;
        bytes32 valueConservationCommitment;
        uint256 approvedAmountCents;
        uint256 paymentAmountCents;
    }

    struct StoredBatch {
        bool exists;
        bytes32 nullifierRootBefore;
        bytes32 nullifierRootAfter;
        bytes32 dataAvailabilityRoot;
        bytes32 encryptedClaimDataRoot;
        uint256 approvedAmountCents;
        uint256 paymentAmountCents;
        address submitter;
    }

    INativeStarkVerifier public immutable verifier;
    bytes32 public immutable pinnedVerifierArtifactHash;
    bytes32 public liveNullifierRoot;
    mapping(bytes32 => StoredBatch) public batches;
    mapping(bytes32 => bytes) internal encryptedClaimData;

    event StarkBatchSubmitted(
        bytes32 indexed batchId,
        bytes32 indexed nullifierRootBefore,
        bytes32 indexed nullifierRootAfter,
        bytes32 dataAvailabilityRoot,
        bytes32 encryptedClaimDataRoot,
        uint256 approvedAmountCents,
        uint256 paymentAmountCents
    );

    constructor(INativeStarkVerifier verifier_, bytes32 pinnedVerifierArtifactHash_) {
        require(address(verifier_) != address(0), "verifier zero");
        require(pinnedVerifierArtifactHash_ != bytes32(0), "artifact zero");
        require(!verifier_.isLegacyProofWrapper(), "legacy proof wrapper forbidden");
        require(verifier_.verifierArtifactHash() == pinnedVerifierArtifactHash_, "artifact mismatch");
        verifier = verifier_;
        pinnedVerifierArtifactHash = pinnedVerifierArtifactHash_;
        liveNullifierRoot = CANONICAL_NULLIFIER_GENESIS;
    }

    function submitBatch(
        StarkBatchSubmission calldata submission,
        bytes calldata starkProof,
        bytes32[] calldata publicInputs,
        bytes calldata encryptedPayload
    ) external {
        require(!batches[submission.batchId].exists, "batch exists");
        require(submission.nullifierRootBefore == liveNullifierRoot, "stale nullifier root");
        require(submission.nullifierRootAfter != bytes32(0), "nullifier root zero");
        require(submission.nullifierRootAfter != submission.nullifierRootBefore, "nullifier root unchanged");
        require(submission.dataAvailabilityRoot != bytes32(0), "DA root zero");
        require(submission.encryptedClaimDataRoot != bytes32(0), "encrypted root zero");
        require(submission.valueConservationCommitment != bytes32(0), "value conservation zero");
        require(submission.paymentAmountCents <= submission.approvedAmountCents, "value conservation");
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

    function _publicInputsMatch(
        StarkBatchSubmission calldata submission,
        bytes32[] calldata publicInputs
    ) internal pure returns (bool) {
        return publicInputs.length >= 9
            && publicInputs[0] == submission.nullifierRootBefore
            && publicInputs[1] == submission.nullifierRootAfter
            && publicInputs[2] == submission.claimRoot
            && publicInputs[3] == submission.resultRoot
            && publicInputs[4] == submission.paymentRoot
            && publicInputs[5] == submission.dataAvailabilityRoot
            && publicInputs[6] == submission.encryptedClaimDataRoot
            && publicInputs[7] == submission.valueConservationCommitment
            && publicInputs[8] == bytes32(submission.paymentAmountCents);
    }
}
