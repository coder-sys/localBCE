// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IStarkClaimsVerifierV1Candidate} from "./IStarkClaimsVerifierV1Candidate.sol";

/// @notice Parallel STARK settlement registry. The active Groth16 ClaimsRegistry is unchanged.
contract StarkClaimsRegistry {
    uint256 private unlocked = 1;

    struct StarkClaimRecord {
        bool recorded;
        bool approved;
        uint256 claimAmount;
        uint256 baseFeePaid;
        uint256 denialFeeAccrued;
        uint32 failureCode;
        bytes32 publicInputRoot;
        bytes32 batchRoot;
        bytes32 proofEnvelopeHash;
    }

    mapping(bytes32 => StarkClaimRecord) public claims;
    mapping(bytes32 => bool) public consumedBatchRoots;

    IStarkClaimsVerifierV1Candidate public verifier;
    address public treasury;
    bytes32 public currentNullifierRoot;

    uint256 public approvedClaims;
    uint256 public deniedClaims;
    uint256 public rejectedProofs;
    uint256 public baseFeesCollected;
    uint256 public denialFeesAccrued;
    uint256 public totalValueReviewed;
    uint256 public denialFeeBps = 2000;

    event StarkClaimApproved(bytes32 indexed claimHash, bytes32 indexed batchRoot);
    event StarkClaimDenied(bytes32 indexed claimHash, uint32 failureCode, bytes32 indexed batchRoot);
    event StarkProofRejected(bytes32 indexed claimHash, bytes32 indexed batchRoot);
    event NullifierRootAdvanced(bytes32 indexed rootBefore, bytes32 indexed rootAfter);
    event VerifierUpdated(address indexed previousVerifier, address indexed newVerifier);
    event FeesWithdrawn(address indexed treasury, uint256 amount);

    constructor(address initialTreasury, address initialVerifier, bytes32 initialNullifierRoot) {
        require(initialTreasury != address(0), "Treasury required");
        require(initialVerifier != address(0), "Verifier required");
        require(initialNullifierRoot != bytes32(0), "Nullifier root required");
        treasury = initialTreasury;
        verifier = IStarkClaimsVerifierV1Candidate(initialVerifier);
        currentNullifierRoot = initialNullifierRoot;
    }

    modifier nonReentrant() {
        require(unlocked == 1, "Reentrant call");
        unlocked = 2;
        _;
        unlocked = 1;
    }

    function submitStarkClaim(
        IStarkClaimsVerifierV1Candidate.PublicInputs calldata publicInputs,
        bytes calldata proofEnvelope,
        uint256 claimAmount
    ) external payable nonReentrant {
        require(!claims[publicInputs.claimHash].recorded, "STARK claim already recorded");

        bool proofValid = _claimAmountMatchesEnvelope(proofEnvelope, claimAmount);
        if (proofValid) {
            try verifier.verifyStarkClaim(publicInputs, proofEnvelope) returns (bool valid) {
                proofValid = valid;
            } catch {
                proofValid = false;
            }
        }
        proofValid = proofValid && publicInputs.nullifierRootBefore == currentNullifierRoot
            && !consumedBatchRoots[publicInputs.batchRoot];

        if (!proofValid) {
            rejectedProofs++;
            emit StarkProofRejected(publicInputs.claimHash, publicInputs.batchRoot);
            _refundRejectedValue();
            return;
        }

        if (publicInputs.decision == 1) {
            require(msg.value > 0, "Fee required");
        } else {
            require(msg.value == 0, "Denied claim cannot carry value");
        }

        totalValueReviewed += claimAmount;
        consumedBatchRoots[publicInputs.batchRoot] = true;
        bytes32 proofEnvelopeHash = keccak256(proofEnvelope);

        if (publicInputs.decision == 1) {
            approvedClaims++;
            baseFeesCollected += msg.value;
            claims[publicInputs.claimHash] = StarkClaimRecord({
                recorded: true,
                approved: true,
                claimAmount: claimAmount,
                baseFeePaid: msg.value,
                denialFeeAccrued: 0,
                failureCode: 0,
                publicInputRoot: publicInputs.publicInputRoot,
                batchRoot: publicInputs.batchRoot,
                proofEnvelopeHash: proofEnvelopeHash
            });
            bytes32 rootBefore = currentNullifierRoot;
            currentNullifierRoot = publicInputs.nullifierRootAfter;
            emit NullifierRootAdvanced(rootBefore, currentNullifierRoot);
            emit StarkClaimApproved(publicInputs.claimHash, publicInputs.batchRoot);
            return;
        }

        uint256 denialFee = (claimAmount * denialFeeBps) / 10_000;
        deniedClaims++;
        denialFeesAccrued += denialFee;
        claims[publicInputs.claimHash] = StarkClaimRecord({
            recorded: true,
            approved: false,
            claimAmount: claimAmount,
            baseFeePaid: 0,
            denialFeeAccrued: denialFee,
            failureCode: publicInputs.failureCode,
            publicInputRoot: publicInputs.publicInputRoot,
            batchRoot: publicInputs.batchRoot,
            proofEnvelopeHash: proofEnvelopeHash
        });
        emit StarkClaimDenied(publicInputs.claimHash, publicInputs.failureCode, publicInputs.batchRoot);
    }

    function setVerifier(address newVerifier) external {
        require(msg.sender == treasury, "Not authorized");
        require(newVerifier != address(0), "Verifier required");
        emit VerifierUpdated(address(verifier), newVerifier);
        verifier = IStarkClaimsVerifierV1Candidate(newVerifier);
    }

    function realizeDenialFees(uint256 amount) external {
        require(msg.sender == treasury, "Not authorized");
        require(amount <= denialFeesAccrued, "Exceeds accrued");
        denialFeesAccrued -= amount;
        baseFeesCollected += amount;
    }

    function withdrawFees() external nonReentrant {
        require(msg.sender == treasury, "Not authorized");
        uint256 amount = address(this).balance;
        require(amount > 0, "No funds");
        (bool sent,) = payable(treasury).call{value: amount}("");
        require(sent, "Fee withdrawal failed");
        emit FeesWithdrawn(treasury, amount);
    }

    function _claimAmountMatchesEnvelope(bytes calldata proofEnvelope, uint256 claimAmount)
        private
        pure
        returns (bool)
    {
        if (proofEnvelope.length != 129) return false;
        uint256 signedClaimAmount;
        assembly ("memory-safe") {
            signedClaimAmount := calldataload(add(proofEnvelope.offset, 97))
        }
        return signedClaimAmount == claimAmount;
    }

    function _refundRejectedValue() private {
        if (msg.value == 0) return;
        (bool refunded,) = payable(msg.sender).call{value: msg.value}("");
        require(refunded, "Rejected value refund failed");
    }
}
