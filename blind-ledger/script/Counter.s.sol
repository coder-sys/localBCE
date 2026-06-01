// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {ClaimsRegistry} from "../src/ClaimsRegistry.sol";
import {Groth16Verifier} from "../src/Verifier.sol";

contract DeployClaimsRegistry is Script {
    ClaimsRegistry public registry;
    Groth16Verifier public verifier;

    function run() public {
        vm.startBroadcast();

        verifier = new Groth16Verifier();
        registry = new ClaimsRegistry(msg.sender, address(verifier));

        vm.stopBroadcast();

        writeDeploymentJson(address(registry), address(verifier), msg.sender);
    }

    function writeDeploymentJson(
        address registryAddress,
        address verifierAddress,
        address treasuryAddress
    ) public {
        string memory deployment = "deployment";
        vm.serializeAddress(deployment, "claimsRegistry", registryAddress);
        vm.serializeAddress(deployment, "verifier", verifierAddress);
        vm.serializeAddress(deployment, "treasury", treasuryAddress);
        vm.serializeUint(deployment, "chainId", block.chainid);
        string memory finalJson = vm.serializeUint(deployment, "deployedAtBlock", block.number);
        vm.writeJson(finalJson, "./deployment.json");
    }
}
