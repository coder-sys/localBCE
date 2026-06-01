// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ClaimsRegistry} from "../src/ClaimsRegistry.sol";

contract MockGroth16Verifier {
    bool public proofValid;

    function setProofValid(bool _proofValid) external {
        proofValid = _proofValid;
    }

    function verifyProof(
        uint[2] calldata,
        uint[2][2] calldata,
        uint[2] calldata,
        uint[1] calldata
    ) external view returns (bool) {
        return proofValid;
    }
}

contract ClaimsRegistryTest is Test {
    ClaimsRegistry private registry;
    MockGroth16Verifier private verifier;
    address private treasury = address(0xBEEF);

    uint[2] private a;
    uint[2][2] private b;
    uint[2] private c;
    uint[1] private input;

    function setUp() public {
        verifier = new MockGroth16Verifier();
        registry = new ClaimsRegistry(treasury, address(verifier));
    }

    function test_ConstructorStoresTreasuryAndVerifier() public {
        assertEq(registry.treasury(), treasury);
        assertEq(address(registry.verifier()), address(verifier));
    }

    function test_SubmitVerifiedClaimRecordsApprovedClaim() public {
        verifier.setProofValid(true);
        bytes32 claimHash = keccak256("approved-claim");

        registry.submitVerifiedClaim{value: 0.001 ether}(claimHash, a, b, c, input, 1000);

        assertTrue(registry.verifiedClaims(claimHash));
        assertEq(registry.successfulClaims(), 1);
        assertEq(registry.baseFeesCollected(), 0.001 ether);

        (
            bool recordVerified,
            uint256 claimAmount,
            uint256 baseFeePaid,
            uint256 performanceFeeAccrued
        ) = registry.claims(claimHash);

        assertTrue(recordVerified);
        assertEq(claimAmount, 1000);
        assertEq(baseFeePaid, 0.001 ether);
        assertEq(performanceFeeAccrued, 0);
    }

    function test_SubmitVerifiedClaimRejectsMissingFeeWhenProofIsValid() public {
        verifier.setProofValid(true);

        vm.expectRevert("Fee required");
        registry.submitVerifiedClaim(keccak256("missing-fee"), a, b, c, input, 1000);
    }

    function test_SubmitVerifiedClaimRecordsRejectedProof() public {
        verifier.setProofValid(false);
        bytes32 claimHash = keccak256("rejected-proof");

        registry.submitVerifiedClaim(claimHash, a, b, c, input, 5000);

        assertFalse(registry.verifiedClaims(claimHash));
        assertEq(registry.rejectedProofs(), 1);
        assertEq(registry.fraudulentTransactionsBlocked(), 1);
        assertEq(registry.totalValueSecured(), 5000);
        assertEq(registry.performanceFeesAccrued(), 1000);
        assertEq(registry.performanceFeeOwed(), 1000);

        (
            bool recordVerified,
            uint256 claimAmount,
            uint256 baseFeePaid,
            uint256 performanceFeeAccrued
        ) = registry.claims(claimHash);

        assertFalse(recordVerified);
        assertEq(claimAmount, 5000);
        assertEq(baseFeePaid, 0);
        assertEq(performanceFeeAccrued, 1000);
    }

    function test_SubmitVerifiedClaimRejectsDuplicateClaimHash() public {
        verifier.setProofValid(true);
        bytes32 claimHash = keccak256("duplicate-claim");

        registry.submitVerifiedClaim{value: 0.001 ether}(claimHash, a, b, c, input, 1000);

        vm.expectRevert("Claim already recorded");
        registry.submitVerifiedClaim{value: 0.001 ether}(claimHash, a, b, c, input, 1000);
    }

    function test_SubmitRejectedProofRejectsDuplicateClaimHash() public {
        verifier.setProofValid(false);
        bytes32 claimHash = keccak256("duplicate-rejected-proof");

        registry.submitVerifiedClaim(claimHash, a, b, c, input, 1000);

        vm.expectRevert("Claim already recorded");
        registry.submitVerifiedClaim(claimHash, a, b, c, input, 1000);
    }

    function test_RealizePerformanceFeesRequiresTreasury() public {
        verifier.setProofValid(false);
        registry.submitVerifiedClaim(keccak256("performance-fee"), a, b, c, input, 5000);

        vm.expectRevert("Not authorized");
        registry.realizePerformanceFees(1000);

        vm.prank(treasury);
        registry.realizePerformanceFees(1000);

        assertEq(registry.performanceFeesAccrued(), 0);
        assertEq(registry.baseFeesCollected(), 1000);
    }

    function test_RealizePerformanceFeesRejectsAmountAboveAccrued() public {
        verifier.setProofValid(false);
        registry.submitVerifiedClaim(keccak256("excess-performance-fee"), a, b, c, input, 5000);

        vm.expectRevert("Exceeds accrued");
        vm.prank(treasury);
        registry.realizePerformanceFees(1001);
    }

    function test_WithdrawFeesRejectsWhenNoFunds() public {
        vm.expectRevert("No funds");
        vm.prank(treasury);
        registry.withdrawFees();
    }

    function test_WithdrawFeesRequiresTreasury() public {
        verifier.setProofValid(true);
        registry.submitVerifiedClaim{value: 1 ether}(keccak256("withdraw-fee"), a, b, c, input, 1000);

        vm.expectRevert("Not authorized");
        registry.withdrawFees();

        uint256 beforeBalance = treasury.balance;

        vm.prank(treasury);
        registry.withdrawFees();

        assertEq(treasury.balance, beforeBalance + 1 ether);
        assertEq(address(registry).balance, 0);
    }
}
