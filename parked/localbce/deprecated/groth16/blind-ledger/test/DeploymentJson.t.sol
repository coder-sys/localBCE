// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployClaimsRegistry} from "../script/Counter.s.sol";
import {ClaimsRegistry} from "../src/ClaimsRegistry.sol";
import {Groth16Verifier} from "../src/Verifier.sol";

contract DeploymentJsonTest is Test {
    string private constant DEPLOYMENT_PATH = "./deployment.json";

    function setUp() public {
        if (vm.exists(DEPLOYMENT_PATH)) {
            vm.removeFile(DEPLOYMENT_PATH);
        }
    }

    function tearDown() public {
        if (vm.exists(DEPLOYMENT_PATH)) {
            vm.removeFile(DEPLOYMENT_PATH);
        }
    }

    function test_WriteDeploymentJsonCreatesExpectedDeploymentFile() public {
        address treasury = address(0xBEEF);
        Groth16Verifier verifier = new Groth16Verifier();
        ClaimsRegistry registry = new ClaimsRegistry(treasury, address(verifier));
        DeployClaimsRegistry deployScript = new DeployClaimsRegistry();

        deployScript.writeDeploymentJson(address(registry), address(verifier), treasury);

        assertTrue(vm.exists(DEPLOYMENT_PATH));

        string memory deploymentJson = vm.readFile(DEPLOYMENT_PATH);

        assertEq(vm.parseJsonAddress(deploymentJson, ".claimsRegistry"), address(registry));
        assertEq(vm.parseJsonAddress(deploymentJson, ".verifier"), address(verifier));
        assertEq(vm.parseJsonAddress(deploymentJson, ".treasury"), treasury);
        assertEq(vm.parseJsonUint(deploymentJson, ".chainId"), block.chainid);
        assertEq(vm.parseJsonUint(deploymentJson, ".deployedAtBlock"), block.number);
    }
}
