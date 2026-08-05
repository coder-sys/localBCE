// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Inactive ABI boundary for a future audited native Winterfell verifier.
/// @dev This contract deliberately does not compare proof commitments or return a placeholder true.
contract WinterfellNativeVerifierCandidate {
    error NativeVerifierInactive();

    string public constant PROOF_SYSTEM = "winterfell-0.13.1";
    string public constant STATUS = "inactive_transcript_fri_gas_and_audits_required";

    function verify(bytes calldata, uint64[38] calldata) external pure returns (bool) {
        revert NativeVerifierInactive();
    }

    function activationAllowed() external pure returns (bool) {
        return false;
    }
}
