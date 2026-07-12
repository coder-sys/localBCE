// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IStarkClaimsRegistryAdapterPreview} from "../src/IStarkClaimsRegistryAdapterPreview.sol";
import {IStarkClaimsVerifierWithRootPreview} from "../src/IStarkClaimsVerifierWithRootPreview.sol";

contract MockStarkClaimsVerifierWithRoot is IStarkClaimsVerifierWithRootPreview {
    bytes32 public expectedClaimHash;
    uint8 public expectedDecision;
    uint32 public expectedFailureCode;
    bytes32 public expectedPublicInputRoot;
    bytes32 public expectedProofCommitmentHash;
    bool public verifierEnabled = true;

    constructor(
        bytes32 _expectedClaimHash,
        uint8 _expectedDecision,
        uint32 _expectedFailureCode,
        bytes32 _expectedPublicInputRoot,
        bytes memory _expectedProofCommitment
    ) {
        expectedClaimHash = _expectedClaimHash;
        expectedDecision = _expectedDecision;
        expectedFailureCode = _expectedFailureCode;
        expectedPublicInputRoot = _expectedPublicInputRoot;
        expectedProofCommitmentHash = keccak256(_expectedProofCommitment);
    }

    function setVerifierEnabled(bool enabled) external {
        verifierEnabled = enabled;
    }

    function verifyClaimWithPublicInputRoot(
        bytes32 claimHash,
        uint8 decision,
        uint32 failureCode,
        bytes32 publicInputRoot,
        bytes calldata proofCommitment
    ) external view returns (bool) {
        if (!verifierEnabled) {
            return false;
        }

        if (decision > 1) {
            return false;
        }

        if (decision == 1 && failureCode != 0) {
            return false;
        }

        if (decision == 0 && failureCode == 0) {
            return false;
        }

        return claimHash == expectedClaimHash && decision == expectedDecision
            && failureCode == expectedFailureCode && publicInputRoot == expectedPublicInputRoot
            && keccak256(proofCommitment) == expectedProofCommitmentHash;
    }
}

contract StarkClaimsRegistryAdapterPreview is IStarkClaimsRegistryAdapterPreview {
    struct StarkClaimRecord {
        bool recorded;
        bool approved;
        uint256 claimAmount;
        uint256 baseFeePaid;
        uint256 denialFeeAccrued;
        uint32 failureCode;
        bytes32 publicInputRoot;
        bytes32 proofCommitmentHash;
    }

    mapping(bytes32 => StarkClaimRecord) public starkClaims;

    IStarkClaimsVerifierWithRootPreview public verifier;
    address public treasury;

    uint256 public approvedStarkClaims;
    uint256 public deniedStarkClaims;
    uint256 public invalidStarkProofs;
    uint256 public baseFeesCollected;
    uint256 public denialFeesAccrued;
    uint256 public totalValueReviewed;
    uint256 public denialFeeBps = 2000;

    constructor(address _treasury, address _verifier) {
        treasury = _treasury;
        verifier = IStarkClaimsVerifierWithRootPreview(_verifier);
    }

    function submitStarkClaim(
        bytes32 claimHash,
        uint8 decision,
        uint32 failureCode,
        bytes32 publicInputRoot,
        bytes calldata proofCommitment,
        uint256 claimAmount
    ) external payable {
        require(!starkClaims[claimHash].recorded, "STARK claim already recorded");

        bool proofValid = verifier.verifyClaimWithPublicInputRoot(
            claimHash, decision, failureCode, publicInputRoot, proofCommitment
        );

        if (!proofValid) {
            invalidStarkProofs++;
            emit StarkProofRejected(claimHash);
            return;
        }

        totalValueReviewed += claimAmount;

        if (decision == 1) {
            require(msg.value > 0, "Fee required");

            approvedStarkClaims++;
            baseFeesCollected += msg.value;

            starkClaims[claimHash] = StarkClaimRecord({
                recorded: true,
                approved: true,
                claimAmount: claimAmount,
                baseFeePaid: msg.value,
                denialFeeAccrued: 0,
                failureCode: 0,
                publicInputRoot: publicInputRoot,
                proofCommitmentHash: keccak256(proofCommitment)
            });

            emit StarkClaimApproved(claimHash, publicInputRoot);
            emit StarkClaimRecorded(claimHash, true, claimAmount, msg.value);
            return;
        }

        uint256 denialFee = (claimAmount * denialFeeBps) / 10_000;

        deniedStarkClaims++;
        denialFeesAccrued += denialFee;

        starkClaims[claimHash] = StarkClaimRecord({
            recorded: true,
            approved: false,
            claimAmount: claimAmount,
            baseFeePaid: 0,
            denialFeeAccrued: denialFee,
            failureCode: failureCode,
            publicInputRoot: publicInputRoot,
            proofCommitmentHash: keccak256(proofCommitment)
        });

        emit StarkClaimDenied(claimHash, failureCode, publicInputRoot);
        emit StarkClaimRecorded(claimHash, false, claimAmount, denialFee);
    }
}

contract StarkClaimsRegistryAdapterPreviewTest is Test {
    bytes32 private constant CLAIM_HASH =
        0x1c1b60223d4f3ffd351887f834b31a4260508b1602a5a9e16a447ea40e386607;
    bytes32 private constant PUBLIC_INPUT_ROOT =
        0x822ed70b5249ff98a4bdd99c16ef5c6ba14c9aa568a8fa8ad0b8befec06c1be9;

    address private treasury = address(0xBEEF);
    bytes private proofCommitment = hex"535441524b5f50524f4f465f50524556494557";

    function test_AdapterRecordsApprovedStarkClaimWithFee() public {
        StarkClaimsRegistryAdapterPreview adapter = approvedAdapter(CLAIM_HASH);

        adapter.submitStarkClaim{value: 0.001 ether}(
            CLAIM_HASH, 1, 0, PUBLIC_INPUT_ROOT, proofCommitment, 1000
        );

        assertEq(adapter.approvedStarkClaims(), 1);
        assertEq(adapter.deniedStarkClaims(), 0);
        assertEq(adapter.invalidStarkProofs(), 0);
        assertEq(adapter.baseFeesCollected(), 0.001 ether);
        assertEq(adapter.totalValueReviewed(), 1000);

        (
            bool recorded,
            bool approved,
            uint256 claimAmount,
            uint256 baseFeePaid,
            uint256 denialFeeAccrued,
            uint32 failureCode,
            bytes32 publicInputRoot,
            bytes32 proofCommitmentHash
        ) = adapter.starkClaims(CLAIM_HASH);

        assertTrue(recorded);
        assertTrue(approved);
        assertEq(claimAmount, 1000);
        assertEq(baseFeePaid, 0.001 ether);
        assertEq(denialFeeAccrued, 0);
        assertEq(failureCode, 0);
        assertEq(publicInputRoot, PUBLIC_INPUT_ROOT);
        assertEq(proofCommitmentHash, keccak256(proofCommitment));
    }

    function test_AdapterCanBeCalledThroughPreviewInterface() public {
        IStarkClaimsRegistryAdapterPreview adapter = approvedAdapter(CLAIM_HASH);

        adapter.submitStarkClaim{value: 0.001 ether}(
            CLAIM_HASH, 1, 0, PUBLIC_INPUT_ROOT, proofCommitment, 1000
        );

        assertEq(StarkClaimsRegistryAdapterPreview(address(adapter)).approvedStarkClaims(), 1);
    }

    function test_AdapterEmitsApprovedSettlementEvents() public {
        StarkClaimsRegistryAdapterPreview adapter = approvedAdapter(CLAIM_HASH);

        vm.expectEmit(false, false, false, true, address(adapter));
        emit IStarkClaimsRegistryAdapterPreview.StarkClaimApproved(CLAIM_HASH, PUBLIC_INPUT_ROOT);
        vm.expectEmit(false, false, false, true, address(adapter));
        emit IStarkClaimsRegistryAdapterPreview.StarkClaimRecorded(
            CLAIM_HASH, true, 1000, 0.001 ether
        );

        adapter.submitStarkClaim{value: 0.001 ether}(
            CLAIM_HASH, 1, 0, PUBLIC_INPUT_ROOT, proofCommitment, 1000
        );
    }

    function test_AdapterRequiresFeeForApprovedStarkClaim() public {
        StarkClaimsRegistryAdapterPreview adapter = approvedAdapter(CLAIM_HASH);

        vm.expectRevert("Fee required");
        adapter.submitStarkClaim(CLAIM_HASH, 1, 0, PUBLIC_INPUT_ROOT, proofCommitment, 1000);
    }

    function test_AdapterRecordsDeniedStarkClaimWithoutFee() public {
        StarkClaimsRegistryAdapterPreview adapter = deniedAdapter(CLAIM_HASH);

        adapter.submitStarkClaim(CLAIM_HASH, 0, 7, PUBLIC_INPUT_ROOT, proofCommitment, 5000);

        assertEq(adapter.approvedStarkClaims(), 0);
        assertEq(adapter.deniedStarkClaims(), 1);
        assertEq(adapter.invalidStarkProofs(), 0);
        assertEq(adapter.denialFeesAccrued(), 1000);
        assertEq(adapter.totalValueReviewed(), 5000);

        (
            bool recorded,
            bool approved,
            uint256 claimAmount,
            uint256 baseFeePaid,
            uint256 denialFeeAccrued,
            uint32 failureCode,
            bytes32 publicInputRoot,
            bytes32 proofCommitmentHash
        ) = adapter.starkClaims(CLAIM_HASH);

        assertTrue(recorded);
        assertFalse(approved);
        assertEq(claimAmount, 5000);
        assertEq(baseFeePaid, 0);
        assertEq(denialFeeAccrued, 1000);
        assertEq(failureCode, 7);
        assertEq(publicInputRoot, PUBLIC_INPUT_ROOT);
        assertEq(proofCommitmentHash, keccak256(proofCommitment));
    }

    function test_AdapterEmitsDeniedSettlementEvents() public {
        StarkClaimsRegistryAdapterPreview adapter = deniedAdapter(CLAIM_HASH);

        vm.expectEmit(false, false, false, true, address(adapter));
        emit IStarkClaimsRegistryAdapterPreview.StarkClaimDenied(CLAIM_HASH, 7, PUBLIC_INPUT_ROOT);
        vm.expectEmit(false, false, false, true, address(adapter));
        emit IStarkClaimsRegistryAdapterPreview.StarkClaimRecorded(CLAIM_HASH, false, 5000, 1000);

        adapter.submitStarkClaim(CLAIM_HASH, 0, 7, PUBLIC_INPUT_ROOT, proofCommitment, 5000);
    }

    function test_AdapterRejectsDuplicateRecordedStarkClaim() public {
        StarkClaimsRegistryAdapterPreview adapter = approvedAdapter(CLAIM_HASH);

        adapter.submitStarkClaim{value: 0.001 ether}(
            CLAIM_HASH, 1, 0, PUBLIC_INPUT_ROOT, proofCommitment, 1000
        );

        vm.expectRevert("STARK claim already recorded");
        adapter.submitStarkClaim{value: 0.001 ether}(
            CLAIM_HASH, 1, 0, PUBLIC_INPUT_ROOT, proofCommitment, 1000
        );
    }

    function test_AdapterRejectsInvalidProofWithoutRecordingClaim() public {
        StarkClaimsRegistryAdapterPreview adapter = approvedAdapter(CLAIM_HASH);

        vm.expectEmit(false, false, false, true, address(adapter));
        emit IStarkClaimsRegistryAdapterPreview.StarkProofRejected(CLAIM_HASH);

        adapter.submitStarkClaim(CLAIM_HASH, 1, 0, keccak256("wrong-root"), proofCommitment, 1000);

        assertEq(adapter.invalidStarkProofs(), 1);
        assertEq(adapter.approvedStarkClaims(), 0);
        assertEq(adapter.deniedStarkClaims(), 0);
        assertEq(adapter.totalValueReviewed(), 0);

        (bool recorded,,,,,,,) = adapter.starkClaims(CLAIM_HASH);
        assertFalse(recorded);
    }

    function test_AdapterDoesNotBlockRetryAfterInvalidProof() public {
        StarkClaimsRegistryAdapterPreview adapter = approvedAdapter(CLAIM_HASH);

        adapter.submitStarkClaim(CLAIM_HASH, 1, 0, keccak256("wrong-root"), proofCommitment, 1000);
        adapter.submitStarkClaim{value: 0.001 ether}(
            CLAIM_HASH, 1, 0, PUBLIC_INPUT_ROOT, proofCommitment, 1000
        );

        assertEq(adapter.invalidStarkProofs(), 1);
        assertEq(adapter.approvedStarkClaims(), 1);
        (bool recorded, bool approved,,,,,,) = adapter.starkClaims(CLAIM_HASH);
        assertTrue(recorded);
        assertTrue(approved);
    }

    function test_AdapterRejectsDisabledVerifierWithoutRecordingClaim() public {
        MockStarkClaimsVerifierWithRoot verifier =
            new MockStarkClaimsVerifierWithRoot(CLAIM_HASH, 1, 0, PUBLIC_INPUT_ROOT, proofCommitment);
        verifier.setVerifierEnabled(false);
        StarkClaimsRegistryAdapterPreview adapter =
            new StarkClaimsRegistryAdapterPreview(treasury, address(verifier));

        adapter.submitStarkClaim(CLAIM_HASH, 1, 0, PUBLIC_INPUT_ROOT, proofCommitment, 1000);

        assertEq(adapter.invalidStarkProofs(), 1);
        (bool recorded,,,,,,,) = adapter.starkClaims(CLAIM_HASH);
        assertFalse(recorded);
    }

    function approvedAdapter(bytes32 claimHash) private returns (StarkClaimsRegistryAdapterPreview) {
        MockStarkClaimsVerifierWithRoot verifier =
            new MockStarkClaimsVerifierWithRoot(claimHash, 1, 0, PUBLIC_INPUT_ROOT, proofCommitment);
        return new StarkClaimsRegistryAdapterPreview(treasury, address(verifier));
    }

    function deniedAdapter(bytes32 claimHash) private returns (StarkClaimsRegistryAdapterPreview) {
        MockStarkClaimsVerifierWithRoot verifier =
            new MockStarkClaimsVerifierWithRoot(claimHash, 0, 7, PUBLIC_INPUT_ROOT, proofCommitment);
        return new StarkClaimsRegistryAdapterPreview(treasury, address(verifier));
    }
}
