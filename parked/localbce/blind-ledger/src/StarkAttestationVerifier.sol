// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IStarkClaimsVerifierV1Candidate} from "./IStarkClaimsVerifierV1Candidate.sol";

/// @notice Controlled attestation anchor for locally verified Winterfell proofs.
/// @dev This is not a native on-chain Winterfell verifier. The proof envelope contains an
///      authorized signature, proof commitment, and signed claim amount.
contract StarkAttestationVerifier is IStarkClaimsVerifierV1Candidate {
    bytes32 public constant ATTESTATION_DOMAIN = keccak256("localBCE.stark.attestation.v1");
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public owner;
    address public attestor;
    address public registry;

    event AttestorUpdated(address indexed previousAttestor, address indexed newAttestor);
    event RegistryUpdated(address indexed previousRegistry, address indexed newRegistry);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(address initialOwner, address initialAttestor) {
        require(initialOwner != address(0), "Owner required");
        require(initialAttestor != address(0), "Attestor required");
        owner = initialOwner;
        attestor = initialAttestor;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function setAttestor(address newAttestor) external onlyOwner {
        require(newAttestor != address(0), "Attestor required");
        emit AttestorUpdated(attestor, newAttestor);
        attestor = newAttestor;
    }

    function setRegistry(address newRegistry) external onlyOwner {
        require(newRegistry != address(0), "Registry required");
        emit RegistryUpdated(registry, newRegistry);
        registry = newRegistry;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Owner required");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function verifyStarkClaim(PublicInputs calldata publicInputs, bytes calldata proofEnvelope)
        external
        view
        returns (bool)
    {
        if (msg.sender != registry || !_validPublicInputs(publicInputs) || proofEnvelope.length != 129) {
            return false;
        }

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(proofEnvelope.offset)
            s := calldataload(add(proofEnvelope.offset, 32))
            v := byte(0, calldataload(add(proofEnvelope.offset, 64)))
        }
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) {
            return false;
        }

        bytes32 proofCommitment;
        uint256 claimAmount;
        assembly ("memory-safe") {
            proofCommitment := calldataload(add(proofEnvelope.offset, 65))
            claimAmount := calldataload(add(proofEnvelope.offset, 97))
        }
        bytes32 digest = attestationDigest(publicInputs, proofCommitment, claimAmount);
        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == attestor;
    }

    function attestationDigest(
        PublicInputs calldata publicInputs,
        bytes32 winterfellProofCommitment,
        uint256 claimAmount
    ) public view returns (bytes32) {
        bytes32 publicInputsHash = keccak256(abi.encode(publicInputs));
        bytes32 payloadHash = keccak256(
            abi.encode(
                ATTESTATION_DOMAIN,
                block.chainid,
                address(this),
                registry,
                publicInputsHash,
                winterfellProofCommitment,
                claimAmount
            )
        );
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
    }

    function _validPublicInputs(PublicInputs calldata value) private pure returns (bool) {
        if (value.claimHash == bytes32(0) || value.publicInputRoot == bytes32(0)) return false;
        if (
            value.claimSourceRoot == bytes32(0) || value.oracleFactsRoot == bytes32(0)
                || value.feeScheduleRoot == bytes32(0) || value.nullifierRootBefore == bytes32(0)
                || value.nullifierRootAfter == bytes32(0) || value.batchRoot == bytes32(0)
        ) return false;
        if (value.decision > 1) return false;
        if (value.decision == 1) {
            return value.failureCode == 0 && value.nullifierRootBefore != value.nullifierRootAfter;
        }
        return value.failureCode != 0 && value.nullifierRootBefore == value.nullifierRootAfter;
    }
}
