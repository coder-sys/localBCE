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

        string memory deployment = "deployment";
        vm.serializeAddress(deployment, "claimsRegistry", address(registry));
        vm.serializeAddress(deployment, "verifier", address(verifier));
        vm.serializeAddress(deployment, "treasury", msg.sender);
        vm.serializeUint(deployment, "chainId", block.chainid);
        string memory finalJson = vm.serializeUint(deployment, "deployedAtBlock", block.number);
        vm.writeJson(finalJson, "./deployment.json");
    }
}
