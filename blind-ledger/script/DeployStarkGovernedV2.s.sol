// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {TimelockController} from "openzeppelin-contracts/contracts/governance/TimelockController.sol";

import {StarkAttestationVerifierV2} from "../src/StarkAttestationVerifierV2.sol";
import {StarkClaimsRegistryV2} from "../src/StarkClaimsRegistryV2.sol";

contract DeployStarkGovernedV2 is Script {
    uint256 private constant SEPOLIA_CHAIN_ID = 11_155_111;
    uint256 private constant REQUIRED_DELAY = 3 days;

    function run() public {
        bool allowLocalTestChain = vm.envOr("STARK_ALLOW_LOCAL_TEST_CHAIN", false);
        require(
            block.chainid == SEPOLIA_CHAIN_ID || (block.chainid == 31337 && allowLocalTestChain),
            "Sepolia only; local chain requires explicit test flag"
        );
        address governanceSafe = vm.envAddress("STARK_GOVERNANCE_SAFE");
        address emergencySafe = vm.envAddress("STARK_EMERGENCY_SAFE");
        address treasury = vm.envAddress("STARK_TREASURY");
        address attestor = vm.envAddress("STARK_ATTESTOR");
        bytes32 policyManifestHash = vm.envBytes32("STARK_POLICY_MANIFEST_HASH");
        bytes32 initialNullifierRoot = vm.envBytes32("STARK_INITIAL_NULLIFIER_ROOT");
        uint256 deployerPrivateKey = vm.envUint("STARK_DEPLOYER_PRIVATE_KEY");
        require(deployerPrivateKey != 0, "STARK_DEPLOYER_PRIVATE_KEY must be nonzero");

        address[] memory proposers = new address[](1);
        proposers[0] = governanceSafe;
        address[] memory executors = new address[](1);
        executors[0] = governanceSafe;

        vm.startBroadcast(deployerPrivateKey);
        TimelockController timelock = new TimelockController(REQUIRED_DELAY, proposers, executors, address(0));
        StarkAttestationVerifierV2 verifier =
            new StarkAttestationVerifierV2(address(timelock), emergencySafe, attestor, policyManifestHash);
        StarkClaimsRegistryV2 registry = new StarkClaimsRegistryV2(
            address(timelock), emergencySafe, treasury, address(verifier), initialNullifierRoot
        );
        vm.stopBroadcast();

        _writeDeployment(
            address(timelock),
            address(verifier),
            address(registry),
            governanceSafe,
            emergencySafe,
            treasury,
            attestor,
            policyManifestHash,
            initialNullifierRoot
        );
    }

    function _writeDeployment(
        address timelock,
        address verifier,
        address registry,
        address governanceSafe,
        address emergencySafe,
        address treasury,
        address attestor,
        bytes32 policyManifestHash,
        bytes32 initialNullifierRoot
    ) private {
        string memory deployment = "starkGovernedV2Deployment";
        vm.serializeUint(deployment, "chainId", block.chainid);
        vm.serializeAddress(deployment, "governanceSafe", governanceSafe);
        vm.serializeAddress(deployment, "emergencySafe", emergencySafe);
        vm.serializeAddress(deployment, "timelock", timelock);
        vm.serializeUint(deployment, "timelockDelaySeconds", REQUIRED_DELAY);
        vm.serializeAddress(deployment, "treasury", treasury);
        vm.serializeAddress(deployment, "attestor", attestor);
        vm.serializeAddress(deployment, "starkAttestationVerifierV2", verifier);
        vm.serializeAddress(deployment, "starkClaimsRegistryV2", registry);
        vm.serializeBytes32(deployment, "policyManifestHash", policyManifestHash);
        vm.serializeBytes32(deployment, "initialNullifierRoot", initialNullifierRoot);
        vm.serializeBool(deployment, "registryAuthorized", false);
        vm.serializeString(
            deployment,
            "requiredPostDeploymentAction",
            "Safe must schedule and execute verifier.setRegistryAuthorization(registry,true) through the timelock"
        );
        vm.serializeBool(deployment, "nativeOnChainStarkVerification", false);
        vm.serializeString(deployment, "releaseProfile", "governed_stark_attested_pilot");
        string memory json = vm.serializeUint(deployment, "deployedAtBlock", block.number);
        vm.writeJson(json, "./stark_v2_deployment.json");
    }
}
