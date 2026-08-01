// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../src/stark/IBlindLedgerClaimVerifierV2.sol";
import "../../src/stark/StarkBatchSettlementV2.sol";

contract BindingVerifierV2 is IBlindLedgerClaimVerifierV2 {
    bytes32 public immutable override verifierArtifactHash;
    bytes32 public immutable override statementSchemaHash;
    bool public immutable override isTestVerifier;

    constructor(bytes32 artifact, bytes32 schema, bool testVerifier) {
        verifierArtifactHash = artifact;
        statementSchemaHash = schema;
        isTestVerifier = testVerifier;
    }

    function verifyClaimProof(bytes calldata proof, bytes32[12] calldata publicOutputs)
        external
        pure
        override
        returns (bool)
    {
        return keccak256(proof) == keccak256(abi.encode(publicOutputs));
    }
}

    contract StarkBatchSettlementV2Test is Test {
        bytes32 constant ARTIFACT = keccak256("v2-artifact");
        bytes32 constant SCHEMA = keccak256("native-stark-public-inputs-v2");
        bytes32 constant DOMAIN = bytes32(uint256(7001));
        bytes32 constant INITIAL_ROOT = bytes32(uint256(8001));
        address constant SUBMITTER = address(0xB1);

        BindingVerifierV2 verifier;
        StarkBatchSettlementV2 settlement;

        function setUp() public {
            verifier = new BindingVerifierV2(ARTIFACT, SCHEMA, false);
            address[] memory submitters = new address[](1);
            submitters[0] = SUBMITTER;
            settlement = new StarkBatchSettlementV2(
                verifier, ARTIFACT, SCHEMA, DOMAIN, INITIAL_ROOT, _roots(), submitters
            );
        }

        function _roots() internal pure returns (StarkBatchSettlementV2.GovernedRoots memory roots) {
            roots = StarkBatchSettlementV2.GovernedRoots({
                claimSourceRoot: bytes32(uint256(101)),
                oracleFactsRoot: bytes32(uint256(102)),
                policyRoot: bytes32(uint256(103)),
                rulesetRoot: bytes32(uint256(104))
            });
        }

        function _submission() internal pure returns (StarkBatchSettlementV2.Submission memory submission) {
            submission = StarkBatchSettlementV2.Submission({
                protocolVersion: bytes32(uint256(2)),
                settlementDomain: DOMAIN,
                batchNonce: bytes32(uint256(1)),
                nullifierRootBefore: INITIAL_ROOT,
                nullifierRootAfter: bytes32(uint256(8002)),
                claimSourceRoot: bytes32(uint256(101)),
                oracleFactsRoot: bytes32(uint256(102)),
                policyRoot: bytes32(uint256(103)),
                rulesetRoot: bytes32(uint256(104)),
                opaqueBatchCommitment: bytes32(uint256(201)),
                valueConservationCommitment: bytes32(uint256(202)),
                settlementCommitment: bytes32(uint256(203))
            });
        }

        function _proof(StarkBatchSettlementV2.Submission memory submission) internal view returns (bytes memory) {
            return abi.encode(settlement.publicOutputs(submission));
        }

        function testExactTwelveFieldProofAdvancesStateWithoutAmountsOrPayload() public {
            StarkBatchSettlementV2.Submission memory submission = _submission();
            bytes memory proof = _proof(submission);
            vm.prank(SUBMITTER);
            settlement.submitPrivateBatch(submission, proof);
            assertEq(settlement.liveNullifierRoot(), submission.nullifierRootAfter);
            assertTrue(settlement.consumedBatchNonces(submission.batchNonce));
        }

        function testChangedOutputWithOldProofIsRejected() public {
            StarkBatchSettlementV2.Submission memory submission = _submission();
            bytes memory proof = _proof(submission);
            submission.opaqueBatchCommitment = bytes32(uint256(999));
            vm.prank(SUBMITTER);
            vm.expectRevert("claim proof rejected");
            settlement.submitPrivateBatch(submission, proof);
        }

        function testNonceReplayAndUnauthorizedSubmissionAreRejected() public {
            StarkBatchSettlementV2.Submission memory submission = _submission();
            bytes memory proof = _proof(submission);
            vm.expectRevert("not authorized");
            settlement.submitPrivateBatch(submission, proof);
            vm.prank(SUBMITTER);
            settlement.submitPrivateBatch(submission, proof);
            vm.prank(SUBMITTER);
            vm.expectRevert("batch nonce consumed");
            settlement.submitPrivateBatch(submission, proof);
        }

        function testUnchangedNullifierRootIsRejectedWithoutStateMutation() public {
            StarkBatchSettlementV2.Submission memory submission = _submission();
            submission.nullifierRootAfter = submission.nullifierRootBefore;
            bytes memory proof = _proof(submission);
            vm.prank(SUBMITTER);
            vm.expectRevert("nullifier root unchanged");
            settlement.submitPrivateBatch(submission, proof);
            assertEq(settlement.liveNullifierRoot(), INITIAL_ROOT);
            assertFalse(settlement.consumedBatchNonces(submission.batchNonce));
            (bool exists,,,,,) = settlement.batches(submission.settlementCommitment);
            assertFalse(exists);
        }

        function testNoncanonicalStarkFieldIsRejectedBeforeVerification() public {
            StarkBatchSettlementV2.Submission memory submission = _submission();
            submission.opaqueBatchCommitment = bytes32(settlement.STARK_FIELD_MODULUS());
            bytes memory proof = _proof(submission);
            vm.prank(SUBMITTER);
            vm.expectRevert("noncanonical Stark field");
            settlement.submitPrivateBatch(submission, proof);
        }

        function testDeploymentRejectsVerifierMarkedAsTestOnly() public {
            BindingVerifierV2 testVerifier = new BindingVerifierV2(ARTIFACT, SCHEMA, true);
            address[] memory submitters = new address[](1);
            submitters[0] = SUBMITTER;
            vm.expectRevert("test verifier forbidden");
            new StarkBatchSettlementV2(testVerifier, ARTIFACT, SCHEMA, DOMAIN, INITIAL_ROOT, _roots(), submitters);
        }
    }
