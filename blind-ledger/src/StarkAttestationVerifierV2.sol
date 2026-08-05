// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

import {IStarkClaimsVerifierV1Candidate} from "./IStarkClaimsVerifierV1Candidate.sol";

/// @notice Governed controlled-attestation verifier for the Sepolia STARK pilot.
/// @dev The 129-byte proof envelope is unchanged. Winterfell proof verification remains off-chain.
contract StarkAttestationVerifierV2 is IStarkClaimsVerifierV1Candidate, AccessControl, Pausable {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant ATTESTATION_DOMAIN = keccak256("localBCE.stark.attestation.v2");
    uint256 private constant SECP256K1_HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public attestor;
    bytes32 public policyManifestHash;
    mapping(address => bool) public authorizedRegistries;

    event GovernanceAuthorityConfigured(address indexed timelock);
    event EmergencyPauserConfigured(address indexed pauser);
    event AttestorUpdated(address indexed previousAttestor, address indexed newAttestor);
    event PolicyManifestHashUpdated(bytes32 indexed previousHash, bytes32 indexed newHash);
    event RegistryAuthorizationUpdated(address indexed registry, bool authorized);

    constructor(address timelock, address emergencyPauser, address initialAttestor, bytes32 initialPolicyManifestHash) {
        require(timelock != address(0), "Timelock required");
        require(emergencyPauser != address(0), "Pauser required");
        require(initialAttestor != address(0), "Attestor required");
        require(initialPolicyManifestHash != bytes32(0), "Policy hash required");

        attestor = initialAttestor;
        policyManifestHash = initialPolicyManifestHash;
        _grantRole(DEFAULT_ADMIN_ROLE, timelock);
        _grantRole(PAUSER_ROLE, emergencyPauser);
        emit GovernanceAuthorityConfigured(timelock);
        emit EmergencyPauserConfigured(emergencyPauser);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function setAttestor(address newAttestor) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newAttestor != address(0), "Attestor required");
        emit AttestorUpdated(attestor, newAttestor);
        attestor = newAttestor;
    }

    function setPolicyManifestHash(bytes32 newPolicyManifestHash) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newPolicyManifestHash != bytes32(0), "Policy hash required");
        emit PolicyManifestHashUpdated(policyManifestHash, newPolicyManifestHash);
        policyManifestHash = newPolicyManifestHash;
    }

    function setRegistryAuthorization(address registry, bool authorized) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(registry != address(0), "Registry required");
        authorizedRegistries[registry] = authorized;
        emit RegistryAuthorizationUpdated(registry, authorized);
    }

    function verifyStarkClaim(PublicInputs calldata publicInputs, bytes calldata proofEnvelope)
        external
        view
        returns (bool)
    {
        if (
            paused() || !authorizedRegistries[msg.sender] || !_validPublicInputs(publicInputs)
                || proofEnvelope.length != 129
        ) {
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
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) return false;

        bytes32 proofCommitment;
        uint256 claimAmount;
        assembly ("memory-safe") {
            proofCommitment := calldataload(add(proofEnvelope.offset, 65))
            claimAmount := calldataload(add(proofEnvelope.offset, 97))
        }
        bytes32 digest = _attestationDigest(msg.sender, publicInputs, proofCommitment, claimAmount);
        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == attestor;
    }

    function attestationDigest(
        address registry,
        PublicInputs calldata publicInputs,
        bytes32 winterfellProofCommitment,
        uint256 claimAmount
    ) public view returns (bytes32) {
        require(authorizedRegistries[registry], "Registry not authorized");
        return _attestationDigest(registry, publicInputs, winterfellProofCommitment, claimAmount);
    }

    function _attestationDigest(
        address registry,
        PublicInputs calldata publicInputs,
        bytes32 winterfellProofCommitment,
        uint256 claimAmount
    ) private view returns (bytes32) {
        bytes32 publicInputsHash = keccak256(abi.encode(publicInputs));
        bytes32 payloadHash = keccak256(
            abi.encode(
                ATTESTATION_DOMAIN,
                block.chainid,
                address(this),
                registry,
                publicInputsHash,
                winterfellProofCommitment,
                policyManifestHash,
                claimAmount
            )
        );
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
    }

    function verificationMode() external pure returns (string memory) {
        return "controlled_attestation_v2";
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
