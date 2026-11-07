// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WinterfellNativeVerifierCandidate} from "../src/WinterfellNativeVerifierCandidate.sol";

contract WinterfellNativeVerifierCandidateTest is Test {
    function test_CandidateCannotBeMistakenForProofCommitmentVerification() public {
        WinterfellNativeVerifierCandidate candidate = new WinterfellNativeVerifierCandidate();
        uint64[38] memory publicInputs;
        vm.expectRevert(WinterfellNativeVerifierCandidate.NativeVerifierInactive.selector);
        candidate.verify(hex"01", publicInputs);
        assertFalse(candidate.activationAllowed());
    }
}
