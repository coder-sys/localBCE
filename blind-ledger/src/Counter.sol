// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Verifier.sol";

contract ClaimsRegistry {
    mapping(bytes32 => bool) public verifiedClaims;

    struct ClaimRecord {
        bool verified;
        uint256 claimAmount;
        uint256 baseFeePaid;
        uint256 performanceFeeAccrued;
    }

    mapping(bytes32 => ClaimRecord) public claims;

    Groth16Verifier public verifier;
    address public treasury;

    uint256 public successfulClaims;
    uint256 public rejectedProofs;
    uint256 public baseFeesCollected;
    uint256 public performanceFeesAccrued;
    uint256 public fraudulentTransactionsBlocked;
    uint256 public totalValueSecured;
    uint256 public performanceFeeBps = 2000; // 20%

    event ClaimVerified(bytes32 claimHash);
    event ProofRejected(bytes32 claimHash);
    event ClaimRecorded(bytes32 claimHash, bool verified, uint256 claimAmount, uint256 fee);
    event FeesWithdrawn(address treasury, uint256 amount);

    constructor(address _treasury, address _verifier) {
        treasury = _treasury;
        verifier = Groth16Verifier(_verifier);
    }

    function submitVerifiedClaim(
        bytes32 claimHash,
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[1] memory input,
        uint256 claimAmount
    ) external payable {
        require(claims[claimHash].claimAmount == 0, "Claim already recorded");

        bool proofValid = verifier.verifyProof(a, b, c, input);

        if (!proofValid) {
            rejectedProofs++;
            fraudulentTransactionsBlocked++;
            totalValueSecured += claimAmount;

            uint256 fee = (claimAmount * performanceFeeBps) / 10_000;
            performanceFeesAccrued += fee;

            claims[claimHash] = ClaimRecord(false, claimAmount, 0, fee);

            emit ProofRejected(claimHash);
            emit ClaimRecorded(claimHash, false, claimAmount, fee);
            return;
        }

        require(msg.value > 0, "Fee required");

        verifiedClaims[claimHash] = true;
        successfulClaims++;
        baseFeesCollected += msg.value;

        claims[claimHash] = ClaimRecord(true, claimAmount, msg.value, 0);

        emit ClaimVerified(claimHash);
        emit ClaimRecorded(claimHash, true, claimAmount, msg.value);
    }

    function performanceFeeOwed() external view returns (uint256) {
        return performanceFeesAccrued;
    }

    function realizePerformanceFees(uint256 amount) external {
        require(msg.sender == treasury, "Not authorized");
        require(amount <= performanceFeesAccrued, "Exceeds accrued");

        performanceFeesAccrued -= amount;
        baseFeesCollected += amount;
    }

    function withdrawFees() external {
        require(msg.sender == treasury, "Not authorized");

        uint256 amount = address(this).balance;
        require(amount > 0, "No funds");

        payable(treasury).transfer(amount);
        emit FeesWithdrawn(treasury, amount);
    }
}