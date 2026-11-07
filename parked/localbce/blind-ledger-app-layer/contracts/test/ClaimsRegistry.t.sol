// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/ClaimsRegistry.sol";
import "../src/ClaimVerifierAdapter.sol";
import "../src/GeneratedClaimVerifier.sol";
import "../src/StubVerifier.sol";
import "../src/PaymentTrigger.sol";
import "../src/IBridge.sol";
import "../src/GovernanceRegistry.sol";

contract GovernanceAttacker {
    function setRoot(GovernanceRegistry registry, bytes32 key, bytes32 root) external {
        registry.setRoot(key, root);
    }
}

contract GovernanceSigner {
    function approveRoot(GovernanceRegistry registry, bytes32 proposalId) external {
        registry.approveRoot(proposalId);
    }
}

contract ClaimsRegistryTest {
    function _id(string memory value) internal pure returns (bytes32) {
        return keccak256(bytes(value));
    }

    function _inputs() internal pure returns (bytes32[] memory inputs) {
        inputs = new bytes32[](1);
        inputs[0] = keccak256(bytes("input-1"));
    }

    function _registry() internal returns (ClaimsRegistry registry) {
        StubVerifier verifier = new StubVerifier();
        registry = new ClaimsRegistry(verifier);
    }

    function _approvedGroth16Proof() internal pure returns (bytes memory proof, bytes32[] memory publicInputs) {
        uint[2] memory pA;
        pA[0] = 0x06bd47dd43d8cbd711ca21fd7a98295a90af307e814fc19494939b68d9faef95;
        pA[1] = 0x2f34f3e3be84942f4c4af58113d628745497e843a6f8aa5799840af08c749425;

        uint[2][2] memory pB;
        pB[0][0] = 0x05f16ec6bc6fea20446486066afdcfdd32f29d4f575254eea8fe5172ea066742;
        pB[0][1] = 0x30083f0389bf3cbc9ca2231562ef120432cc405c8ad2bb15e83037c6866d48ce;
        pB[1][0] = 0x2bdd7b210e33166ca08569c4ed1bb8c66e74bfcd34497e072f8f6cb0a93d4d41;
        pB[1][1] = 0x156e2a6d1478b3a05b93707fa62f644239b0aa863f2b59c01ae61f196d4384f5;

        uint[2] memory pC;
        pC[0] = 0x04260819665f1301ec59b9b5b6da58854a6e9a8d1f36d1337e7a8ea932e178a6;
        pC[1] = 0x1842833093348c1aef9268bdf99d1f9727dbdb0f16aa306cf38b119c49686af7;

        proof = abi.encode(pA, pB, pC);
        publicInputs = new bytes32[](4);
        publicInputs[0] = 0x0476a2c5d0927d475d96528c6e5b72fc431c33d5c4e4fdc5c261d0460082abfa;
        publicInputs[1] = 0x1b3ec387939908d04d426b54d4abe3b055ff935ae37802d9d81cc552d03cd51d;
        publicInputs[2] = bytes32(uint256(1));
        publicInputs[3] = bytes32(uint256(0));
    }

    function _assertRevertString(bytes memory data, string memory expected) internal pure {
        require(data.length >= 4, "missing revert data");
        bytes memory payload = new bytes(data.length - 4);
        for (uint256 i = 4; i < data.length; i++) {
            payload[i - 4] = data[i];
        }
        string memory reason = abi.decode(payload, (string));
        require(keccak256(bytes(reason)) == keccak256(bytes(expected)), "wrong revert reason");
    }

    function testRecordApprovedClaimStoresFields() public {
        ClaimsRegistry registry = _registry();
        registry.recordClaim(_id("CLAIM1"), true, "", _id("CTX"), hex"1234", _inputs());
        (bool exists, bool approved, string memory denialReason, bytes32 contextHash, address submitter,) = registry.claims(_id("CLAIM1"));
        require(exists, "missing claim");
        require(approved, "not approved");
        require(bytes(denialReason).length == 0, "unexpected denial");
        require(contextHash == _id("CTX"), "context mismatch");
        require(submitter == address(this), "submitter mismatch");
    }

    function testRecordDeniedClaimStoresReason() public {
        ClaimsRegistry registry = _registry();
        registry.recordClaim(_id("CLAIM2"), false, "eligibility_inactive", _id("CTX2"), hex"1234", _inputs());
        (bool exists, bool approved, string memory denialReason,,,) = registry.claims(_id("CLAIM2"));
        require(exists, "missing claim");
        require(!approved, "approved");
        require(keccak256(bytes(denialReason)) == keccak256(bytes("eligibility_inactive")), "denial mismatch");
    }

    function testRejectsDuplicateClaim() public {
        ClaimsRegistry registry = _registry();
        registry.recordClaim(_id("CLAIM3"), true, "", _id("CTX"), hex"1234", _inputs());
        try registry.recordClaim(_id("CLAIM3"), true, "", _id("CTX"), hex"1234", _inputs()) {
            revert("expected duplicate rejection");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("claim exists")), "wrong duplicate reason");
        }
    }

    function testRejectsInvalidProof() public {
        ClaimsRegistry registry = _registry();
        bytes32[] memory emptyInputs = new bytes32[](0);
        try registry.recordClaim(_id("CLAIM4"), true, "", _id("CTX"), hex"", emptyInputs) {
            revert("expected invalid proof rejection");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("invalid proof")), "wrong proof reason");
        }
    }

    function testRealGroth16ProofRecordsClaim() public {
        Groth16Verifier verifier = new Groth16Verifier();
        ClaimVerifierAdapter adapter = new ClaimVerifierAdapter(verifier);
        ClaimsRegistry registry = new ClaimsRegistry(adapter);
        (bytes memory proof, bytes32[] memory publicInputs) = _approvedGroth16Proof();

        require(adapter.verify(proof, publicInputs), "proof should verify");
        registry.recordClaim(_id("CLAIM-ZK"), true, "", publicInputs[0], proof, publicInputs);

        (bool exists, bool approved,, bytes32 contextHash,,) = registry.claims(_id("CLAIM-ZK"));
        require(exists, "missing zk claim");
        require(approved, "zk claim not approved");
        require(contextHash == publicInputs[0], "context mismatch");
    }

    function testRealGroth16ProofRejectsTamperedPublicInput() public {
        Groth16Verifier verifier = new Groth16Verifier();
        ClaimVerifierAdapter adapter = new ClaimVerifierAdapter(verifier);
        ClaimsRegistry registry = new ClaimsRegistry(adapter);
        (bytes memory proof, bytes32[] memory publicInputs) = _approvedGroth16Proof();
        publicInputs[2] = bytes32(uint256(0));

        require(!adapter.verify(proof, publicInputs), "tampered proof should fail");
        try registry.recordClaim(_id("CLAIM-ZK-BAD"), true, "", publicInputs[0], proof, publicInputs) {
            revert("expected invalid proof rejection");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("invalid proof")), "wrong real proof reason");
        }
    }

    function testPaymentTriggerOnApprovedClaim() public {
        ClaimsRegistry registry = _registry();
        registry.recordClaim(_id("CLAIM5"), true, "", _id("CTX"), hex"1234", _inputs());
        (, bool approved,,,,) = registry.claims(_id("CLAIM5"));
        require(approved, "claim not approved");

        CircleBridgeStub bridge = new CircleBridgeStub();
        PaymentTrigger trigger = new PaymentTrigger(bridge);
        bytes32 ref = trigger.triggerApprovedClaim(_id("CLAIM5"), address(0xBEEF), 100);
        require(ref != bytes32(0), "missing settlement ref");
    }

    function testPaymentTriggerRejectsZeroAmount() public {
        CircleBridgeStub bridge = new CircleBridgeStub();
        PaymentTrigger trigger = new PaymentTrigger(bridge);
        try trigger.triggerApprovedClaim(_id("CLAIM6"), address(0xBEEF), 0) {
            revert("expected zero amount rejection");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("amount zero")), "wrong amount reason");
        }
    }

    function testGovernanceRootStorage() public {
        GovernanceRegistry registry = new GovernanceRegistry();
        registry.setRoot(_id("rules"), _id("root"));
        require(registry.roots(_id("rules")) == _id("root"), "root mismatch");
    }

    function testGovernanceOnlyOwnerCanSetRoot() public {
        GovernanceRegistry registry = new GovernanceRegistry();
        GovernanceAttacker attacker = new GovernanceAttacker();
        try attacker.setRoot(registry, _id("rules"), _id("bad-root")) {
            revert("expected owner rejection");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("not owner")), "wrong owner reason");
        }
        registry.setRoot(_id("rules"), _id("good-root"));
        require(registry.roots(_id("rules")) == _id("good-root"), "owner update failed");
    }

    function testGovernanceMultisigRootUpdateRequiresThreshold() public {
        GovernanceRegistry registry = new GovernanceRegistry();
        GovernanceSigner signer = new GovernanceSigner();
        address[] memory signers = new address[](2);
        signers[0] = address(this);
        signers[1] = address(signer);
        registry.configureGovernance(signers, 2, 0);

        bytes32 key = _id("rules");
        bytes32 root = _id("root-v2");
        bytes32 proposalId = registry.proposeRoot(key, root);

        try registry.setRoot(key, root) {
            revert("immediate governance update accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("timelock required")), "wrong immediate reason");
        }

        try registry.executeRoot(proposalId) {
            revert("single signer update accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("insufficient approvals")), "wrong threshold reason");
        }

        signer.approveRoot(registry, proposalId);
        registry.executeRoot(proposalId);
        require(registry.roots(key) == root, "multisig root update failed");
    }

    function testGovernanceRootUpdateHonorsTimelock() public {
        GovernanceRegistry registry = new GovernanceRegistry();
        address[] memory signers = new address[](1);
        signers[0] = address(this);
        registry.configureGovernance(signers, 1, 1 days);

        bytes32 proposalId = registry.proposeRoot(_id("rules"), _id("root-v2"));

        try registry.executeRoot(proposalId) {
            revert("timelock bypass accepted");
        } catch Error(string memory reason) {
            require(keccak256(bytes(reason)) == keccak256(bytes("timelock active")), "wrong timelock reason");
        }
    }
}
