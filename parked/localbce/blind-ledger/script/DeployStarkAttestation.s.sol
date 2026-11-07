// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {StarkAttestationVerifier} from "../src/StarkAttestationVerifier.sol";
import {StarkClaimsRegistry} from "../src/StarkClaimsRegistry.sol";

contract DeployStarkAttestation is Script {
    StarkAttestationVerifier public verifier;
    StarkClaimsRegistry public registry;

    function run() public {
        address owner = vm.envAddress("STARK_OWNER");
        address treasury = vm.envAddress("STARK_TREASURY");
        address attestor = vm.envAddress("STARK_ATTESTOR");
        bytes32 initialNullifierRoot = vm.envBytes32("STARK_INITIAL_NULLIFIER_ROOT");

        vm.startBroadcast();
        verifier = new StarkAttestationVerifier(owner, attestor);
        registry = new StarkClaimsRegistry(treasury, address(verifier), initialNullifierRoot);
        verifier.setRegistry(address(registry));
        vm.stopBroadcast();

        writeStarkDeploymentJson(address(registry), address(verifier), owner, treasury, attestor, initialNullifierRoot);
    }

    function writeStarkDeploymentJson(
        address registryAddress,
        address verifierAddress,
        address ownerAddress,
        address treasuryAddress,
        address attestorAddress,
        bytes32 initialNullifierRoot
    ) public {
        string memory deployment = "starkDeployment";
        vm.serializeAddress(deployment, "starkClaimsRegistry", registryAddress);
        vm.serializeAddress(deployment, "starkAttestationVerifier", verifierAddress);
        vm.serializeAddress(deployment, "owner", ownerAddress);
        vm.serializeAddress(deployment, "treasury", treasuryAddress);
        vm.serializeAddress(deployment, "attestor", attestorAddress);
        vm.serializeBytes32(deployment, "initialNullifierRoot", initialNullifierRoot);
        vm.serializeString(deployment, "trustModel", "authorized_attestor_after_local_winterfell_verification");
        vm.serializeBool(deployment, "nativeOnChainStarkVerification", false);
        vm.serializeUint(deployment, "chainId", block.chainid);
        string memory finalJson = vm.serializeUint(deployment, "deployedAtBlock", block.number);
        vm.writeJson(finalJson, "./stark_deployment.json");
    }
}
