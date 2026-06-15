// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IBridge.sol";

contract PaymentTrigger {
    IBridge public bridge;

    event PaymentTriggered(bytes32 indexed claimId, address indexed recipient, uint256 amount, bytes32 settlementRef);

    constructor(IBridge _bridge) {
        bridge = _bridge;
    }

    function triggerApprovedClaim(bytes32 claimId, address recipient, uint256 amount) external returns (bytes32 settlementRef) {
        require(amount > 0, "amount zero");
        settlementRef = bridge.triggerPayment(claimId, recipient, amount);
        emit PaymentTriggered(claimId, recipient, amount, settlementRef);
    }
}

