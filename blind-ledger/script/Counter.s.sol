// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {ClaimsRegistry} from "../src/Counter.sol";
import {Groth16Verifier} from "../src/Verifier.sol";

contract DeployClaimsRegistry is Script {
    ClaimsRegistry public registry;
    Groth16Verifier public verifier;

    function run() public {
        vm.startBroadcast();

        verifier = new Groth16Verifier();
        registry = new ClaimsRegistry(msg.sender, address(verifier));

        vm.stopBroadcast();
    }
}