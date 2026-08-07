// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Test} from "forge-std/Test.sol";
import {TimelockController} from "openzeppelin-contracts/contracts/governance/TimelockController.sol";

import {IStarkClaimsVerifierV1Candidate} from "../src/IStarkClaimsVerifierV1Candidate.sol";
import {StarkAttestationVerifierV2} from "../src/StarkAttestationVerifierV2.sol";
import {StarkClaimsRegistryV2} from "../src/StarkClaimsRegistryV2.sol";

contract StarkGovernedV2Handler is Test {
    uint256 private constant ATTESTOR_KEY = 0xA11CE;
    bytes32 private constant PUBLIC_INPUT_ROOT = keccak256("invariant-public-input-root");
    bytes32 private constant CLAIM_SOURCE_ROOT = keccak256("invariant-claim-source-root");
    bytes32 private constant ORACLE_FACTS_ROOT = keccak256("invariant-oracle-facts-root");
    bytes32 private constant FEE_SCHEDULE_ROOT = keccak256("invariant-fee-schedule-root");
    bytes32 private constant PROOF_COMMITMENT = keccak256("invariant-winterfell-proof");

    StarkAttestationVerifierV2 public immutable verifier;
    StarkClaimsRegistryV2 public immutable registry;

    uint256 public approvedSubmissions;
    uint256 public deniedSubmissions;
    uint256 public expectedBaseFees;
    uint256 public expectedDenialFees;
    uint256 public expectedReviewedValue;
    bytes32 public expectedNullifierRoot;
    uint256 private nonce;

    constructor(StarkAttestationVerifierV2 verifier_, StarkClaimsRegistryV2 registry_) {
        verifier = verifier_;
        registry = registry_;
        expectedNullifierRoot = registry_.currentNullifierRoot();
        vm.deal(address(this), 1_000_000 ether);
    }

    function submitApproved(uint96 rawClaimAmount, uint96 rawFee) external {
        uint256 claimAmount = bound(uint256(rawClaimAmount), 1, 1e24);
        uint256 fee = bound(uint256(rawFee), 1, 1 ether);
        uint256 id = ++nonce;
        bytes32 nextRoot = keccak256(abi.encode("approved-root", id, expectedNullifierRoot));
        if (nextRoot == bytes32(0)) nextRoot = bytes32(uint256(1));
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = _inputs(id);
        inputs.nullifierRootAfter = nextRoot;
        bytes memory envelope = _signedEnvelope(inputs, claimAmount);

        registry.submitStarkClaim{value: fee}(inputs, envelope, claimAmount);

        approvedSubmissions++;
        expectedBaseFees += fee;
        expectedReviewedValue += claimAmount;
        expectedNullifierRoot = nextRoot;
    }

    function submitDenied(uint96 rawClaimAmount, uint32 rawFailureCode) external {
        uint256 claimAmount = bound(uint256(rawClaimAmount), 1, 1e24);
        uint32 failureCode = uint32(bound(uint256(rawFailureCode), 1, type(uint32).max));
        uint256 id = ++nonce;
        IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs = _inputs(id);
        inputs.decision = 0;
        inputs.failureCode = failureCode;
        bytes memory envelope = _signedEnvelope(inputs, claimAmount);

        registry.submitStarkClaim(inputs, envelope, claimAmount);

        deniedSubmissions++;
        expectedDenialFees += (claimAmount * 2_000) / 10_000;
        expectedReviewedValue += claimAmount;
    }

    function _inputs(uint256 id) private view returns (IStarkClaimsVerifierV1Candidate.PublicInputs memory) {
        return IStarkClaimsVerifierV1Candidate.PublicInputs({
            claimHash: keccak256(abi.encode("invariant-claim", id)),
            decision: 1,
            failureCode: 0,
            publicInputRoot: PUBLIC_INPUT_ROOT,
            claimSourceRoot: CLAIM_SOURCE_ROOT,
            oracleFactsRoot: ORACLE_FACTS_ROOT,
            feeScheduleRoot: FEE_SCHEDULE_ROOT,
            nullifierRootBefore: expectedNullifierRoot,
            nullifierRootAfter: expectedNullifierRoot,
            batchRoot: keccak256(abi.encode("invariant-batch", id))
        });
    }

    function _signedEnvelope(IStarkClaimsVerifierV1Candidate.PublicInputs memory inputs, uint256 claimAmount)
        private
        view
        returns (bytes memory)
    {
        bytes32 digest = verifier.attestationDigest(address(registry), inputs, PROOF_COMMITMENT, claimAmount);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTESTOR_KEY, digest);
        return abi.encodePacked(r, s, v, PROOF_COMMITMENT, claimAmount);
    }
}

contract StarkGovernedV2InvariantTest is StdInvariant, Test {
    uint256 private constant TIMELOCK_DELAY = 3 days;
    uint256 private constant ATTESTOR_KEY = 0xA11CE;
    address private constant GOVERNANCE_SAFE = address(0x7101);
    address private constant EMERGENCY_SAFE = address(0x7102);
    address private constant TREASURY = address(0x7103);

    StarkClaimsRegistryV2 private registry;
    StarkGovernedV2Handler private handler;

    function setUp() public {
        address[] memory proposers = new address[](1);
        proposers[0] = GOVERNANCE_SAFE;
        address[] memory executors = new address[](1);
        executors[0] = GOVERNANCE_SAFE;
        TimelockController timelock = new TimelockController(TIMELOCK_DELAY, proposers, executors, address(0));
        StarkAttestationVerifierV2 verifier = new StarkAttestationVerifierV2(
            address(timelock), EMERGENCY_SAFE, vm.addr(ATTESTOR_KEY), keccak256("invariant-policy")
        );
        registry = new StarkClaimsRegistryV2(
            address(timelock), EMERGENCY_SAFE, TREASURY, address(verifier), keccak256("invariant-initial-root")
        );

        bytes memory data =
            abi.encodeCall(StarkAttestationVerifierV2.setRegistryAuthorization, (address(registry), true));
        bytes32 salt = keccak256("invariant-authorize");
        vm.prank(GOVERNANCE_SAFE);
        timelock.schedule(address(verifier), 0, data, bytes32(0), salt, TIMELOCK_DELAY);
        vm.warp(block.timestamp + TIMELOCK_DELAY);
        vm.prank(GOVERNANCE_SAFE);
        timelock.execute(address(verifier), 0, data, bytes32(0), salt);

        handler = new StarkGovernedV2Handler(verifier, registry);
        targetContract(address(handler));
    }

    function invariant_CountersFeesAndRootsStayConsistent() public view {
        assertEq(registry.approvedClaims(), handler.approvedSubmissions());
        assertEq(registry.deniedClaims(), handler.deniedSubmissions());
        assertEq(registry.rejectedProofs(), 0);
        assertEq(registry.baseFeesCollected(), handler.expectedBaseFees());
        assertEq(registry.denialFeesAccrued(), handler.expectedDenialFees());
        assertEq(registry.totalValueReviewed(), handler.expectedReviewedValue());
        assertEq(registry.currentNullifierRoot(), handler.expectedNullifierRoot());
    }
}
